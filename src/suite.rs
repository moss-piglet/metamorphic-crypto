//! CNSA 2.0 **suite axis** — shared scaffolding for the post-quantum suites
//! added in v0.7.0 (additive, non-breaking).
//!
//! The [`Suite`] axis is **orthogonal** to [`crate::hybrid::SecurityLevel`] /
//! [`crate::sign::SignatureLevel`]: `SecurityLevel` selects the ML-* parameter
//! set (Cat-1/3/5), while `Suite` selects the *composition posture* (classical
//! hybrid vs. matched-strength hybrid vs. pure post-quantum). Both the KEM /
//! seal layer ([`crate::hybrid`]) and the signature layer ([`crate::sign`])
//! consume the same axis, so a developer flips between postures with a single
//! one-argument change while the rest of the API surface stays identical.
//!
//! ## Suites
//!
//! - [`Suite::Hybrid`] — **default & recommended.** The existing strict-AND
//!   classical+PQ construction. Byte-for-byte unchanged; the new wire formats
//!   in this module are never produced for `Hybrid`.
//! - [`Suite::HybridMatched`] — opt-in. The classical partner is chosen *by the
//!   PQ category* so it is never the weak link (KEM: Cat-3→X448, Cat-5→P-521
//!   ECDH; signatures: Cat-3→Ed448, Cat-5→ECDSA-P-521). At the lowest shared
//!   rung it is identical to `Hybrid` (no new format), so nothing breaks.
//! - [`Suite::PureCnsa2`] — opt-in. The NSA CNSA-2.0 box: pure ML-KEM-1024 /
//!   AES-256-GCM (KEM) and pure ML-DSA-87 (signatures), with no classical half.
//!   Standards-compliant but, until the lattice implementation is independently
//!   audited, it lacks the classical backstop the default `Hybrid` keeps — this
//!   is documented plainly rather than hidden.
//!
//! ## Seal envelope (KEM, new suites only)
//!
//! The matched / pure KEM suites do **not** reuse the legacy `combineKEMS`
//! (SHA3-256) + XSalsa20-Poly1305 construction (that stays byte-identical for
//! `Suite::Hybrid`). Instead they use a CNSA-correct envelope built only from
//! standardized pieces:
//!
//! ```text
//! KEM encapsulate -> ss(s)
//!   ikm  = ss_mlkem (PureCnsa2)  |  ss_mlkem || ss_ecc (HybridMatched)
//!   key  = HKDF-SHA512(ikm, info = suite_tag || context_label) -> 32-byte AES-256 key
//!   out  = AES-256-GCM(key, 96-bit random nonce, AAD = suite_tag || context_label)
//!   wire = tag(1) || kem_ct || [ecc_eph_pk] || nonce(12) || ct || gcm_tag(16)
//! ```
//!
//! Because every encapsulation yields a fresh KEM secret, the derived AES-256
//! key is single-use, so the 96-bit random nonce can never repeat — SIV-grade
//! misuse resistance without leaving the CNSA-approved set (no AES-GCM-SIV).
//! HKDF-SHA512 is the SP 800-56C-approved KDF for KEM-derived keys and is
//! byte-identical across RustCrypto, WebCrypto, and `@noble/hashes`.
//!
//! Note the deliberate hash split: HKDF-**SHA512** for *key derivation* here;
//! SHA3-512 stays the choice for *leaf/transcript* hashing elsewhere
//! ([`crate::hash`]). Different roles, both standardized.

use aes_gcm::aead::array::Array;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::CryptoError;

// === Suite axis ===

/// Composition posture for the post-quantum suites (orthogonal to the ML-*
/// parameter set chosen by `SecurityLevel` / `SignatureLevel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Suite {
    /// Default & recommended: existing classical+PQ strict-AND construction.
    /// Byte-for-byte unchanged; never emits the new envelope formats.
    #[default]
    Hybrid,
    /// Opt-in: classical partner matched to the PQ category (Cat-3 / Cat-5
    /// diverge from `Hybrid`; the lowest shared rung is identical to `Hybrid`).
    HybridMatched,
    /// Opt-in: pure post-quantum, no classical half (the NSA CNSA-2.0 box).
    PureCnsa2,
}

// === Context labels ===

/// Default versioned context label for sealing (KEM envelope).
///
/// Grammar: `"<namespace>/<purpose>/v<major>"`. The **namespace** is the one
/// per-tenant knob — Mosslet / Metamorphic / mosskeys pass their own (e.g.
/// `"mosslet/seal/v1"`) while the protocol shape stays fixed. Bound into both
/// the HKDF `info` and the GCM AAD.
pub const SEAL_CONTEXT_V1: &str = "metamorphic/seal/v1";

// === Wire-format tags (new KEM/seal suites) ===

/// `0x10` — PureCnsa2 seal (ML-KEM-1024 + AES-256-GCM). Headline CNSA-5 box.
pub const TAG_KEM_PURE_CNSA2: u8 = 0x10;
/// `0x13` — HybridMatched Cat-3 seal (ML-KEM-768 + X448, AES-256-GCM).
pub const TAG_KEM_MATCHED_CAT3: u8 = 0x13;
/// `0x14` — HybridMatched Cat-5 seal (ML-KEM-1024 + P-521 ECDH, AES-256-GCM).
pub const TAG_KEM_MATCHED_CAT5: u8 = 0x14;

/// AES-256-GCM nonce length (96-bit, per SP 800-38D).
pub const GCM_NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length (full 128-bit).
pub const GCM_TAG_LEN: usize = 16;
/// Derived AES-256 key length.
pub const AES256_KEY_LEN: usize = 32;

// === Domain-separation bytes ===

/// Build the domain-separation bytes bound into both the HKDF `info` and the
/// GCM AAD: `suite_tag || context_label_utf8`.
pub(crate) fn domain_bytes(tag: u8, context_label: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + context_label.len());
    v.push(tag);
    v.extend_from_slice(context_label.as_bytes());
    v
}

// === HKDF-SHA512 ===

/// Derive a single-use 32-byte AES-256 key from KEM-derived `ikm` using
/// HKDF-SHA512 (RFC 5869) with no salt and `info = suite_tag || context_label`.
pub(crate) fn derive_aes256_key(
    ikm: &[u8],
    info: &[u8],
) -> Result<[u8; AES256_KEY_LEN], CryptoError> {
    let hk = Hkdf::<Sha512>::new(None, ikm);
    let mut okm = [0u8; AES256_KEY_LEN];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::Hybrid("HKDF-SHA512 expand failed".into()))?;
    Ok(okm)
}

// === AES-256-GCM ===

/// AES-256-GCM seal. Returns the combined `ciphertext || tag(16)` (the AEAD
/// output); the caller supplies the 96-bit `nonce` and the `aad`.
pub(crate) fn aes256gcm_seal(
    key: &[u8; AES256_KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(&Array(*key));
    let nonce_arr: Array<u8, _> = Array(*nonce);
    cipher
        .encrypt(
            &nonce_arr,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Hybrid("AES-256-GCM encrypt failed".into()))
}

/// AES-256-GCM open. `ciphertext` is the combined `ciphertext || tag(16)`.
pub(crate) fn aes256gcm_open(
    key: &[u8; AES256_KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(&Array(*key));
    let nonce_arr: Array<u8, _> = Array(*nonce);
    cipher
        .decrypt(
            &nonce_arr,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decryption)
}

/// Convenience: seal `plaintext` for the new envelope. Derives the single-use
/// AES key from `ikm` + domain bytes, encrypts under a caller-provided 96-bit
/// `nonce`, and zeroizes the derived key. Returns `ciphertext || tag(16)`.
pub(crate) fn envelope_seal(
    ikm: &[u8],
    tag: u8,
    context_label: &str,
    nonce: &[u8; GCM_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let domain = domain_bytes(tag, context_label);
    let mut key = derive_aes256_key(ikm, &domain)?;
    let out = aes256gcm_seal(&key, nonce, &domain, plaintext);
    key.zeroize();
    out
}

/// Convenience: open a new-envelope `ciphertext || tag(16)` produced by
/// [`envelope_seal`] with the same `ikm`, `tag`, `context_label`, and `nonce`.
pub(crate) fn envelope_open(
    ikm: &[u8],
    tag: u8,
    context_label: &str,
    nonce: &[u8; GCM_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let domain = domain_bytes(tag, context_label);
    let mut key = derive_aes256_key(ikm, &domain)?;
    let out = aes256gcm_open(&key, nonce, &domain, ciphertext);
    key.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // --- Known-answer tests (KATs) ---

    /// AES-256-GCM NIST CAVP vectors (all-zero key + 96-bit zero IV). Pins the
    /// AEAD output (`ciphertext || tag`) for cross-language parity.
    #[test]
    fn aes256gcm_nist_kat() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        // Empty plaintext / empty AAD => 16-byte tag only.
        let out = aes256gcm_seal(&key, &nonce, &[], &[]).unwrap();
        assert_eq!(hex(&out), "530f8afbc74536b9a963b4f1c4cb738b");
        // 16 zero bytes plaintext => ct(16) || tag(16).
        let out16 = aes256gcm_seal(&key, &nonce, &[], &[0u8; 16]).unwrap();
        assert_eq!(
            hex(&out16),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
        // Round-trips.
        assert_eq!(aes256gcm_open(&key, &nonce, &[], &out).unwrap(), b"");
        assert_eq!(
            aes256gcm_open(&key, &nonce, &[], &out16).unwrap(),
            [0u8; 16]
        );
    }

    /// HKDF-SHA512 known-answer vector (RFC 5869 Test Case 1 inputs computed
    /// with SHA-512, L=42). Pins the HKDF-SHA512 primitive used for the seal
    /// envelope's key derivation; byte-identical to `@noble/hashes` and
    /// WebCrypto.
    #[test]
    fn hkdf_sha512_kat() {
        use hkdf::Hkdf;
        use sha2::Sha512;
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let hk = Hkdf::<Sha512>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
        );
    }

    #[test]
    fn hkdf_sha512_deterministic_and_domain_separated() {
        let ikm = [7u8; 32];
        let k1 =
            derive_aes256_key(&ikm, &domain_bytes(TAG_KEM_PURE_CNSA2, SEAL_CONTEXT_V1)).unwrap();
        let k2 =
            derive_aes256_key(&ikm, &domain_bytes(TAG_KEM_PURE_CNSA2, SEAL_CONTEXT_V1)).unwrap();
        assert_eq!(k1, k2);
        // Different tag => different key.
        let k3 =
            derive_aes256_key(&ikm, &domain_bytes(TAG_KEM_MATCHED_CAT5, SEAL_CONTEXT_V1)).unwrap();
        assert_ne!(k1, k3);
        // Different context label => different key.
        let k4 =
            derive_aes256_key(&ikm, &domain_bytes(TAG_KEM_PURE_CNSA2, "mosslet/seal/v1")).unwrap();
        assert_ne!(k1, k4);
    }

    #[test]
    fn aes256gcm_roundtrip_and_aad_binding() {
        let key = [9u8; 32];
        let nonce = [3u8; 12];
        let aad = b"metamorphic/seal/v1";
        let ct = aes256gcm_seal(&key, &nonce, aad, b"hello cnsa").unwrap();
        // ct includes the 16-byte tag.
        assert_eq!(ct.len(), "hello cnsa".len() + GCM_TAG_LEN);
        assert_eq!(
            aes256gcm_open(&key, &nonce, aad, &ct).unwrap(),
            b"hello cnsa"
        );
        // Wrong AAD fails.
        assert!(aes256gcm_open(&key, &nonce, b"other", &ct).is_err());
        // Tampered ciphertext fails.
        let mut bad = ct.clone();
        bad[0] ^= 0xFF;
        assert!(aes256gcm_open(&key, &nonce, aad, &bad).is_err());
    }

    #[test]
    fn envelope_roundtrip() {
        let ikm = [1u8; 64];
        let nonce = [5u8; 12];
        let ct = envelope_seal(
            &ikm,
            TAG_KEM_PURE_CNSA2,
            SEAL_CONTEXT_V1,
            &nonce,
            b"key material",
        )
        .unwrap();
        let pt = envelope_open(&ikm, TAG_KEM_PURE_CNSA2, SEAL_CONTEXT_V1, &nonce, &ct).unwrap();
        assert_eq!(pt, b"key material");
        // Different ikm fails to open.
        let other = [2u8; 64];
        assert!(envelope_open(&other, TAG_KEM_PURE_CNSA2, SEAL_CONTEXT_V1, &nonce, &ct).is_err());
    }
}
