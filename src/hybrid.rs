//! Hybrid post-quantum KEM: ML-KEM-512 + X25519 (Cat-1), ML-KEM-768 + X25519
//! (Cat-3, default), and ML-KEM-1024 + X25519 (Cat-5).
//!
//! This module implements hybrid KEMs combining ML-KEM with X25519, ensuring
//! byte-level compatibility with existing production ciphertext. The three tiers
//! span the **full standardized ML-KEM range** — NIST (FIPS 203) defines ML-KEM
//! only at categories 1, 3, and 5 (512 / 768 / 1024). There is **no** category-2
//! or category-4 ML-KEM parameter set, so none is offered here.
//!
//! ## Security Levels
//!
//! | Level | ML-KEM | NIST Category | Equivalent | Version Tag |
//! |-------|--------|---------------|------------|-------------|
//! | Cat-1 | 512    | 1             | ~AES-128   | `0x01`      |
//! | Cat-3 | 768    | 3             | ~AES-192   | `0x02`      |
//! | Cat-5 | 1024   | 5             | ~AES-256   | `0x03`      |
//!
//! ### About the version tags
//!
//! The version tag is a **per-artifact-type wire-format version**, *not* a
//! global NIST-category code. A KEM tag only ever appears as the first byte of a
//! hybrid-KEM ciphertext produced by this module and is parsed only by
//! [`hybrid_open`] / [`is_hybrid_ciphertext`]; it is never handed to the
//! signature code. The KEM tags form a dense ordered sequence — Cat-1 = `0x01`,
//! Cat-3 = `0x02`, Cat-5 = `0x03`.
//!
//! By design these tags **agree with the signature tags in [`crate::sign`] on
//! every level the two families share**: Cat-3 = `0x02` and Cat-5 = `0x03` in
//! both. The single divergence is at `0x01`, which here denotes Cat-1
//! (ML-KEM-512) while on the signature side `0x01` denotes Cat-2 (ML-DSA-44).
//! This is unavoidable: NIST standardizes ML-KEM at categories {1, 3, 5} but
//! ML-DSA at {2, 3, 5}, so the two families have different lowest rungs and
//! "tag == category" cannot hold for both.
//!
//! These bytes are **not legacy sentinels**, either. The pre-PQ `box_seal`
//! ciphertext format is *unversioned* — its output is `ephemeral_pk (32) ||
//! box_ct`, so its first byte is a random X25519 public-key byte, not a reserved
//! tag — so there is no `0x00`/`0x01` legacy marker anywhere for these values to
//! clash with. Both [`is_hybrid_ciphertext`] and [`hybrid_open`] additionally
//! enforce a minimum-length gate per tier, so a legacy ciphertext whose random
//! first byte happens to be `0x01` cannot be mis-routed as a Cat-1 hybrid
//! ciphertext; [`crate::seal::unseal_from_user`] also falls back to the legacy
//! opener if a hybrid open fails, closing the residual length-collision case.
//!
//! ## Construction (from noble source)
//!
//! ```text
//! combineKEMS(
//!   seedLen = 32,
//!   outputLen = 32,
//!   expandSeed = SHAKE256(seed, dkLen=96),
//!   combiner = SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || b"\\.//^\\"),
//!   ml_kem{512|768|1024},
//!   ecdhKem(x25519)
//! )
//! ```
//!
//! ## Key layout (Cat-1 / Cat-3 / Cat-5)
//!
//! | Component | Cat-1 (512) | Cat-3 (768) | Cat-5 (1024) | Description |
//! |-----------|-------------|-------------|--------------|-------------|
//! | Secret key (seed) | 32 bytes | 32 bytes | 32 bytes | Root seed expanded via SHAKE256 |
//! | Public key | 832 bytes | 1216 bytes | 1600 bytes | ML-KEM ek ‖ X25519 pk (32) |
//! | Ciphertext | 800 bytes | 1120 bytes | 1600 bytes | ML-KEM ct ‖ X25519 ephemeral pk (32) |
//! | Shared secret | 32 bytes | 32 bytes | 32 bytes | SHA3-256 combiner output |
//!
//! ## Classical partner caveat
//!
//! The classical half is **X25519 (~Cat-1 classical) at every tier** — it does
//! not scale up with the ML-KEM parameter set. At Cat-3 and Cat-5 the
//! post-quantum half dominates and X25519 is the classical floor; this is
//! standard hybrid-KEM practice (the hybrid is at least as strong as its
//! strongest component, and a break requires defeating *both* halves). If you
//! need a higher classical margin, that is a separate (currently non-standard
//! for X25519) concern.
//!
//! ## Sealed-box ciphertext format
//!
//! ```text
//! v1: 0x01 || hybrid_ciphertext_512  (800 B)  || nonce (24 B) || secretbox_ct
//! v2: 0x02 || hybrid_ciphertext_768  (1120 B) || nonce (24 B) || secretbox_ct
//! v3: 0x03 || hybrid_ciphertext_1024 (1600 B) || nonce (24 B) || secretbox_ct
//! ```

use ml_kem::{Decapsulate, MlKem512, MlKem768, MlKem1024};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crypto_secretbox::aead::Aead;
use crypto_secretbox::aead::generic_array::GenericArray;
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};

use crate::CryptoError;
use crate::b64;
use crate::ecc;
use crate::suite::{
    self, GCM_NONCE_LEN, GCM_TAG_LEN, SEAL_CONTEXT_V1, Suite, TAG_KEM_MATCHED_CAT3,
    TAG_KEM_MATCHED_CAT5, TAG_KEM_PURE_CNSA2,
};

// === Constants ===

/// Version tag for Cat-1 hybrid ciphertext (ML-KEM-512).
const VERSION_HYBRID_512: u8 = 0x01;
/// Version tag for Cat-3 hybrid ciphertext (ML-KEM-768).
const VERSION_HYBRID_768: u8 = 0x02;
/// Version tag for Cat-5 hybrid ciphertext (ML-KEM-1024).
const VERSION_HYBRID_1024: u8 = 0x03;
/// XSalsa20 nonce length.
const NONCE_LEN: usize = 24;
/// X25519 key size.
const X25519_LEN: usize = 32;
/// Root seed length.
const SEED_LEN: usize = 32;
/// Poly1305 MAC.
const MAC_LEN: usize = 16;
/// Noble's domain-separation label.
const LABEL: &[u8] = b"\\.//^\\";

// ML-KEM-512 (Cat-1)
/// ML-KEM-512 encapsulation key size.
const MLKEM512_EK_LEN: usize = 800;
/// ML-KEM-512 ciphertext size.
const MLKEM512_CT_LEN: usize = 768;
/// ML-KEM-512 seed portion (64 bytes).
const MLKEM512_SEED_LEN: usize = 64;
/// Expanded seed for Cat-1: ML-KEM seed (64) + X25519 secret (32).
const EXPANDED_SEED_512_LEN: usize = 96;
/// Combined public key for Cat-1: ML-KEM ek (800) + X25519 pk (32).
const COMBINED_PK_512_LEN: usize = MLKEM512_EK_LEN + X25519_LEN;
/// Combined ciphertext for Cat-1: ML-KEM ct (768) + X25519 ephemeral pk (32).
const COMBINED_CT_512_LEN: usize = MLKEM512_CT_LEN + X25519_LEN;
/// Minimum sealed-box length for a Cat-1 hybrid ciphertext (empty plaintext:
/// version tag + combined ct + nonce + Poly1305 MAC). Single source of truth
/// shared by the routing check ([`is_hybrid_ciphertext`]) and the open gate
/// ([`hybrid_open_512`]); keeping them in lockstep is what prevents a legacy
/// ciphertext from being mis-routed.
const MIN_HYBRID_512_LEN: usize = 1 + COMBINED_CT_512_LEN + NONCE_LEN + MAC_LEN;

// ML-KEM-768 (Cat-3)
/// ML-KEM-768 encapsulation key size.
const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext size.
const MLKEM768_CT_LEN: usize = 1088;
/// ML-KEM-768 seed portion (64 bytes).
const MLKEM768_SEED_LEN: usize = 64;
/// Expanded seed for Cat-3: ML-KEM seed (64) + X25519 secret (32).
const EXPANDED_SEED_768_LEN: usize = 96;
/// Combined public key for Cat-3: ML-KEM ek (1184) + X25519 pk (32).
const COMBINED_PK_768_LEN: usize = MLKEM768_EK_LEN + X25519_LEN;
/// Combined ciphertext for Cat-3: ML-KEM ct (1088) + X25519 ephemeral pk (32).
const COMBINED_CT_768_LEN: usize = MLKEM768_CT_LEN + X25519_LEN;
/// Minimum sealed-box length for a Cat-3 hybrid ciphertext (empty plaintext).
/// Shared by [`is_hybrid_ciphertext`] and [`hybrid_open_768`].
const MIN_HYBRID_768_LEN: usize = 1 + COMBINED_CT_768_LEN + NONCE_LEN + MAC_LEN;

// ML-KEM-1024 (Cat-5)
/// ML-KEM-1024 encapsulation key size.
const MLKEM1024_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext size.
const MLKEM1024_CT_LEN: usize = 1568;
/// ML-KEM-1024 seed portion (64 bytes).
const MLKEM1024_SEED_LEN: usize = 64;
/// Expanded seed for Cat-5: ML-KEM seed (64) + X25519 secret (32).
const EXPANDED_SEED_1024_LEN: usize = 96;
/// Combined public key for Cat-5: ML-KEM ek (1568) + X25519 pk (32).
const COMBINED_PK_1024_LEN: usize = MLKEM1024_EK_LEN + X25519_LEN;
/// Combined ciphertext for Cat-5: ML-KEM ct (1568) + X25519 ephemeral pk (32).
const COMBINED_CT_1024_LEN: usize = MLKEM1024_CT_LEN + X25519_LEN;
/// Minimum sealed-box length for a Cat-5 hybrid ciphertext (empty plaintext).
/// Shared by [`is_hybrid_ciphertext`] and [`hybrid_open_1024`].
const MIN_HYBRID_1024_LEN: usize = 1 + COMBINED_CT_1024_LEN + NONCE_LEN + MAC_LEN;

// === CNSA 2.0 suites (v0.7.0): AES-256-GCM envelope layouts ===
//
// These layouts are produced only by the new `Suite::PureCnsa2` /
// `Suite::HybridMatched` paths. Layout: `tag(1) || mlkem_ct || [ecc_eph_pk] ||
// nonce(12) || aes_gcm_ct || gcm_tag(16)`. The `aes_gcm_ct || gcm_tag` portion
// is the combined AEAD output, so an empty-plaintext minimum is
// `header || nonce(12) || tag(16)`.

/// Minimum sealed-box length for a PureCnsa2 (`0x10`) ciphertext:
/// `tag(1) || ML-KEM-1024 ct (1568) || nonce(12) || gcm_tag(16)`.
const MIN_PURE_CNSA2_LEN: usize = 1 + MLKEM1024_CT_LEN + GCM_NONCE_LEN + GCM_TAG_LEN;
/// Minimum sealed-box length for a HybridMatched Cat-3 (`0x13`) ciphertext:
/// `tag(1) || ML-KEM-768 ct (1088) || X448 eph pk (56) || nonce(12) || gcm_tag(16)`.
const MIN_MATCHED_CAT3_LEN: usize =
    1 + MLKEM768_CT_LEN + ecc::X448_LEN + GCM_NONCE_LEN + GCM_TAG_LEN;
/// Minimum sealed-box length for a HybridMatched Cat-5 (`0x14`) ciphertext:
/// `tag(1) || ML-KEM-1024 ct (1568) || P-521 eph pk (133) || nonce(12) || gcm_tag(16)`.
const MIN_MATCHED_CAT5_LEN: usize =
    1 + MLKEM1024_CT_LEN + ecc::P521_PK_LEN + GCM_NONCE_LEN + GCM_TAG_LEN;

/// PureCnsa2 combined public key length (ML-KEM-1024 ek only).
const PURE_CNSA2_PK_LEN: usize = MLKEM1024_EK_LEN;
/// HybridMatched Cat-3 combined public key length (ML-KEM-768 ek + X448 pk).
const MATCHED_CAT3_PK_LEN: usize = MLKEM768_EK_LEN + ecc::X448_LEN;
/// HybridMatched Cat-5 combined public key length (ML-KEM-1024 ek + P-521 pk).
const MATCHED_CAT5_PK_LEN: usize = MLKEM1024_EK_LEN + ecc::P521_PK_LEN;

/// Expanded-seed length for HybridMatched Cat-3 (ML-KEM-768 seed + X448 secret).
const EXPANDED_SEED_MATCHED_CAT3_LEN: usize = MLKEM768_SEED_LEN + ecc::X448_LEN;
/// Expanded-seed length for HybridMatched Cat-5 (ML-KEM-1024 seed + P-521 secret).
const EXPANDED_SEED_MATCHED_CAT5_LEN: usize = MLKEM1024_SEED_LEN + ecc::P521_SK_LEN;

// === Types ===

/// A hybrid ML-KEM + X25519 keypair (base64-encoded).
#[derive(Debug, Clone)]
pub struct HybridKeyPair {
    /// Combined public key: ML-KEM ek ‖ X25519 pk. Base64.
    pub public_key: String,
    /// Root seed (32 bytes). Base64.
    pub secret_key: String,
}

/// Security level for hybrid PQ operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityLevel {
    /// NIST Category 1: ML-KEM-512 + X25519 (~AES-128).
    Cat1,
    /// NIST Category 3: ML-KEM-768 + X25519 (~AES-192). Default.
    #[default]
    Cat3,
    /// NIST Category 5: ML-KEM-1024 + X25519 (~AES-256).
    Cat5,
}

// === Helpers ===

/// Fill buffer with OS random bytes.
#[inline]
fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Expand a 32-byte seed using SHAKE256.
fn expand_seed(seed: &[u8; SEED_LEN], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; output_len];
    reader.read(&mut out);
    out
}

/// SHA3-256 combiner: `SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || label)`
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8],
    ct_x25519: &[u8; X25519_LEN],
    pk_x25519: &[u8; X25519_LEN],
) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    Digest::update(&mut hasher, ss_mlkem);
    Digest::update(&mut hasher, ss_x25519);
    Digest::update(&mut hasher, ct_x25519);
    Digest::update(&mut hasher, pk_x25519);
    Digest::update(&mut hasher, LABEL);
    hasher.finalize().into()
}

/// Encrypt plaintext with a 32-byte shared secret using XSalsa20-Poly1305.
fn secretbox_encrypt(
    shared_secret: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_LEN]), CryptoError> {
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(shared_secret));
    let mut nonce_buf = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_buf);
    let nonce = GenericArray::from_slice(&nonce_buf);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Hybrid("secretbox encrypt failed".into()))?;
    Ok((ct, nonce_buf))
}

/// Decrypt ciphertext with a 32-byte shared secret using XSalsa20-Poly1305.
fn secretbox_decrypt(
    shared_secret: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(shared_secret));
    let nonce = GenericArray::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decryption)
}

// === Public API: Cat-1 (ML-KEM-512) ===

/// Generate a hybrid ML-KEM-512 + X25519 keypair (Cat-1).
pub fn generate_hybrid_keypair_512() -> HybridKeyPair {
    generate_hybrid_keypair_with_level(SecurityLevel::Cat1)
}

/// Seal `plaintext` to a Cat-1 hybrid public key (ML-KEM-512).
///
/// Returns base64: `0x01 || hybrid_ct (800 B) || nonce (24 B) || secretbox_ct`.
pub fn hybrid_seal_512(plaintext: &[u8], combined_pk_b64: &str) -> Result<String, CryptoError> {
    hybrid_seal_with_level(plaintext, combined_pk_b64, SecurityLevel::Cat1)
}

// === Public API: Cat-3 (ML-KEM-768, default) ===

/// Generate a hybrid ML-KEM-768 + X25519 keypair (Cat-3, default).
pub fn generate_hybrid_keypair() -> HybridKeyPair {
    generate_hybrid_keypair_with_level(SecurityLevel::Cat3)
}

/// Seal `plaintext` to a Cat-3 hybrid public key (ML-KEM-768).
///
/// Returns base64: `0x02 || hybrid_ct (1120 B) || nonce (24 B) || secretbox_ct`.
pub fn hybrid_seal(plaintext: &[u8], combined_pk_b64: &str) -> Result<String, CryptoError> {
    hybrid_seal_with_level(plaintext, combined_pk_b64, SecurityLevel::Cat3)
}

/// Open a hybrid-sealed ciphertext. Auto-detects the suite + level from the
/// version tag.
///
/// - `0x01/0x02/0x03` → legacy `Suite::Hybrid` (ML-KEM + X25519, combineKEMS).
/// - `0x10` → `Suite::PureCnsa2` Cat-5 (ML-KEM-1024 + AES-256-GCM).
/// - `0x13` → `Suite::HybridMatched` Cat-3 (ML-KEM-768 + X448 + AES-256-GCM).
/// - `0x14` → `Suite::HybridMatched` Cat-5 (ML-KEM-1024 + P-521 + AES-256-GCM).
///
/// The new (`0x10/0x13/0x14`) suites bind the **default** context label
/// [`SEAL_CONTEXT_V1`]; use [`hybrid_open_with_context`] to supply a custom
/// per-tenant label.
pub fn hybrid_open(ct_b64: &str, seed_b64: &str) -> Result<Vec<u8>, CryptoError> {
    hybrid_open_with_context(ct_b64, seed_b64, SEAL_CONTEXT_V1)
}

/// Open a hybrid-sealed ciphertext, supplying the context label used at seal
/// time for the new CNSA-2.0 suites. The label is ignored for the legacy
/// `0x01/0x02/0x03` tags (which never bind a context).
pub fn hybrid_open_with_context(
    ct_b64: &str,
    seed_b64: &str,
    context_label: &str,
) -> Result<Vec<u8>, CryptoError> {
    let combined = b64::decode(ct_b64)?;
    match combined.first() {
        Some(&VERSION_HYBRID_512) => hybrid_open_512(&combined, seed_b64),
        Some(&VERSION_HYBRID_768) => hybrid_open_768(&combined, seed_b64),
        Some(&VERSION_HYBRID_1024) => hybrid_open_1024(&combined, seed_b64),
        Some(&TAG_KEM_PURE_CNSA2) => open_pure_cnsa2(&combined, seed_b64, context_label),
        Some(&TAG_KEM_MATCHED_CAT3) => open_matched_cat3(&combined, seed_b64, context_label),
        Some(&TAG_KEM_MATCHED_CAT5) => open_matched_cat5(&combined, seed_b64, context_label),
        _ => Err(CryptoError::Hybrid(
            "not a hybrid ciphertext (bad version tag)".into(),
        )),
    }
}

/// Returns `true` if the base64 blob is a hybrid ciphertext: its first byte is a
/// known version tag (`0x01`, `0x02`, or `0x03`) **and** its total length is at
/// least the minimum for that tier.
///
/// The length check (matching the exact minimum-length gate enforced by
/// [`hybrid_open`]) is what definitively distinguishes a hybrid ciphertext from a
/// legacy `box_seal` ciphertext whose random first byte happens to collide with a
/// tag value: a real hybrid ciphertext is always `>=` its tier minimum, while a
/// short legacy ciphertext below that bound is correctly rejected here. (A legacy
/// ciphertext that collides on *both* the first byte *and* a hybrid-matching
/// length is still handled safely by the fallback in
/// [`crate::seal::unseal_from_user`].)
pub fn is_hybrid_ciphertext(ct_b64: &str) -> bool {
    let Ok(bytes) = b64::decode(ct_b64) else {
        return false;
    };
    match bytes.first() {
        Some(&VERSION_HYBRID_512) => bytes.len() >= MIN_HYBRID_512_LEN,
        Some(&VERSION_HYBRID_768) => bytes.len() >= MIN_HYBRID_768_LEN,
        Some(&VERSION_HYBRID_1024) => bytes.len() >= MIN_HYBRID_1024_LEN,
        Some(&TAG_KEM_PURE_CNSA2) => bytes.len() >= MIN_PURE_CNSA2_LEN,
        Some(&TAG_KEM_MATCHED_CAT3) => bytes.len() >= MIN_MATCHED_CAT3_LEN,
        Some(&TAG_KEM_MATCHED_CAT5) => bytes.len() >= MIN_MATCHED_CAT5_LEN,
        _ => false,
    }
}

// === Public API: Cat-5 (ML-KEM-1024) ===

/// Generate a hybrid ML-KEM-1024 + X25519 keypair (Cat-5).
pub fn generate_hybrid_keypair_1024() -> HybridKeyPair {
    generate_hybrid_keypair_with_level(SecurityLevel::Cat5)
}

/// Seal `plaintext` to a Cat-5 hybrid public key (ML-KEM-1024).
///
/// Returns base64: `0x03 || hybrid_ct (1600 B) || nonce (24 B) || secretbox_ct`.
pub fn hybrid_seal_1024(plaintext: &[u8], combined_pk_b64: &str) -> Result<String, CryptoError> {
    hybrid_seal_with_level(plaintext, combined_pk_b64, SecurityLevel::Cat5)
}

// === Public API: Level-parametric ===

/// Generate a hybrid keypair at the specified security level.
pub fn generate_hybrid_keypair_with_level(level: SecurityLevel) -> HybridKeyPair {
    let mut seed = [0u8; SEED_LEN];
    random_bytes(&mut seed);

    let expanded_len = match level {
        SecurityLevel::Cat1 => EXPANDED_SEED_512_LEN,
        SecurityLevel::Cat3 => EXPANDED_SEED_768_LEN,
        SecurityLevel::Cat5 => EXPANDED_SEED_1024_LEN,
    };
    let mlkem_seed_len = match level {
        SecurityLevel::Cat1 => MLKEM512_SEED_LEN,
        SecurityLevel::Cat3 => MLKEM768_SEED_LEN,
        SecurityLevel::Cat5 => MLKEM1024_SEED_LEN,
    };

    let mut expanded = expand_seed(&seed, expanded_len);
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[mlkem_seed_len..].try_into().unwrap();

    // X25519 keypair
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    let combined_pk = match level {
        SecurityLevel::Cat1 => {
            let mlkem_seed: [u8; MLKEM512_SEED_LEN] =
                expanded[..MLKEM512_SEED_LEN].try_into().unwrap();
            let dk = DecapsulationKey::<MlKem512>::from_seed(mlkem_seed.into());
            let ek = dk.encapsulation_key();
            let ek_bytes = ek.to_bytes();
            let mut pk = Vec::with_capacity(COMBINED_PK_512_LEN);
            pk.extend_from_slice(&ek_bytes);
            pk.extend_from_slice(x25519_pk.as_bytes());
            pk
        }
        SecurityLevel::Cat3 => {
            let mlkem_seed: [u8; MLKEM768_SEED_LEN] =
                expanded[..MLKEM768_SEED_LEN].try_into().unwrap();
            let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed.into());
            let ek = dk.encapsulation_key();
            let ek_bytes = ek.to_bytes();
            let mut pk = Vec::with_capacity(COMBINED_PK_768_LEN);
            pk.extend_from_slice(&ek_bytes);
            pk.extend_from_slice(x25519_pk.as_bytes());
            pk
        }
        SecurityLevel::Cat5 => {
            let mlkem_seed: [u8; MLKEM1024_SEED_LEN] =
                expanded[..MLKEM1024_SEED_LEN].try_into().unwrap();
            let dk = DecapsulationKey::<MlKem1024>::from_seed(mlkem_seed.into());
            let ek = dk.encapsulation_key();
            let ek_bytes = ek.to_bytes();
            let mut pk = Vec::with_capacity(COMBINED_PK_1024_LEN);
            pk.extend_from_slice(&ek_bytes);
            pk.extend_from_slice(x25519_pk.as_bytes());
            pk
        }
    };

    let pair = HybridKeyPair {
        public_key: b64::encode(&combined_pk),
        secret_key: b64::encode(&seed),
    };

    seed.zeroize();
    expanded.zeroize();
    pair
}

/// Seal plaintext at the specified security level.
pub fn hybrid_seal_with_level(
    plaintext: &[u8],
    combined_pk_b64: &str,
    level: SecurityLevel,
) -> Result<String, CryptoError> {
    let pk_bytes = b64::decode(combined_pk_b64)?;

    let (expected_pk_len, mlkem_ek_len, version_tag) = match level {
        SecurityLevel::Cat1 => (COMBINED_PK_512_LEN, MLKEM512_EK_LEN, VERSION_HYBRID_512),
        SecurityLevel::Cat3 => (COMBINED_PK_768_LEN, MLKEM768_EK_LEN, VERSION_HYBRID_768),
        SecurityLevel::Cat5 => (COMBINED_PK_1024_LEN, MLKEM1024_EK_LEN, VERSION_HYBRID_1024),
    };

    if pk_bytes.len() != expected_pk_len {
        return Err(CryptoError::InvalidLength {
            expected: expected_pk_len,
            got: pk_bytes.len(),
        });
    }

    // Split combined public key
    let mlkem_ek_bytes = &pk_bytes[..mlkem_ek_len];
    let x25519_pk_bytes: [u8; X25519_LEN] = pk_bytes[mlkem_ek_len..].try_into().unwrap();

    // ML-KEM encapsulate
    let mut mlkem_coins = [0u8; 32];
    random_bytes(&mut mlkem_coins);

    let (mlkem_ct_bytes, ss_mlkem_bytes) = match level {
        SecurityLevel::Cat1 => {
            let ek = EncapsulationKey::<MlKem512>::new(
                mlkem_ek_bytes
                    .try_into()
                    .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-512 ek".into()))?,
            )
            .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-512 encapsulation key".into()))?;
            let (ct, ss) = ek.encapsulate_deterministic(&mlkem_coins.into());
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        SecurityLevel::Cat3 => {
            let ek = EncapsulationKey::<MlKem768>::new(
                mlkem_ek_bytes
                    .try_into()
                    .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 ek".into()))?,
            )
            .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 encapsulation key".into()))?;
            let (ct, ss) = ek.encapsulate_deterministic(&mlkem_coins.into());
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        SecurityLevel::Cat5 => {
            let ek = EncapsulationKey::<MlKem1024>::new(
                mlkem_ek_bytes
                    .try_into()
                    .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 ek".into()))?,
            )
            .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 encapsulation key".into()))?;
            let (ct, ss) = ek.encapsulate_deterministic(&mlkem_coins.into());
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
    };
    mlkem_coins.zeroize();

    // X25519 encapsulate (ephemeral DH)
    let mut x25519_eph_bytes = [0u8; X25519_LEN];
    random_bytes(&mut x25519_eph_bytes);
    let x25519_eph_sk = X25519StaticSecret::from(x25519_eph_bytes);
    let x25519_eph_pk = X25519PublicKey::from(&x25519_eph_sk);
    let x25519_recipient_pk = X25519PublicKey::from(x25519_pk_bytes);
    let ss_x25519 = x25519_eph_sk.diffie_hellman(&x25519_recipient_pk);
    x25519_eph_bytes.zeroize();

    // Combine shared secrets
    let ct_x25519: [u8; X25519_LEN] = *x25519_eph_pk.as_bytes();
    let mut shared_secret = combine(
        &ss_mlkem_bytes,
        ss_x25519.as_bytes(),
        &ct_x25519,
        &x25519_pk_bytes,
    );

    // Encrypt plaintext
    let (secretbox_ct, nonce_buf) = secretbox_encrypt(&shared_secret, plaintext)?;
    shared_secret.zeroize();

    // Assemble: version || mlkem_ct || x25519_eph_pk || nonce || secretbox_ct
    let combined_ct_len = mlkem_ct_bytes.len() + X25519_LEN;
    let mut out = Vec::with_capacity(1 + combined_ct_len + NONCE_LEN + secretbox_ct.len());
    out.push(version_tag);
    out.extend_from_slice(&mlkem_ct_bytes);
    out.extend_from_slice(&ct_x25519);
    out.extend_from_slice(&nonce_buf);
    out.extend_from_slice(&secretbox_ct);

    Ok(b64::encode(&out))
}

// === Internal: Cat-1 open ===

fn hybrid_open_512(combined: &[u8], seed_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let seed_bytes = b64::decode(seed_b64)?;
    if seed_bytes.len() != SEED_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SEED_LEN,
            got: seed_bytes.len(),
        });
    }
    if combined.len() < MIN_HYBRID_512_LEN {
        return Err(CryptoError::TooShort);
    }

    let seed: [u8; SEED_LEN] = seed_bytes.try_into().unwrap();
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_512_LEN);
    let mlkem_seed: [u8; MLKEM512_SEED_LEN] = expanded[..MLKEM512_SEED_LEN].try_into().unwrap();
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[MLKEM512_SEED_LEN..].try_into().unwrap();
    expanded.zeroize();

    // Parse ciphertext
    let mlkem_ct = &combined[1..1 + MLKEM512_CT_LEN];
    let x25519_eph_pk_bytes: [u8; X25519_LEN] = combined
        [1 + MLKEM512_CT_LEN..1 + COMBINED_CT_512_LEN]
        .try_into()
        .unwrap();
    let nonce_slice = &combined[1 + COMBINED_CT_512_LEN..1 + COMBINED_CT_512_LEN + NONCE_LEN];
    let encrypted = &combined[1 + COMBINED_CT_512_LEN + NONCE_LEN..];

    // ML-KEM-512 decapsulate
    let dk = DecapsulationKey::<MlKem512>::from_seed(mlkem_seed.into());
    let kem_ct = mlkem_ct
        .try_into()
        .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-512 ciphertext".into()))?;
    let ss_mlkem = dk.decapsulate(kem_ct);

    // X25519 decapsulate
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_eph_pk = X25519PublicKey::from(x25519_eph_pk_bytes);
    let ss_x25519 = x25519_sk.diffie_hellman(&x25519_eph_pk);

    let x25519_pk = X25519PublicKey::from(&x25519_sk);
    let pk_x25519: [u8; X25519_LEN] = *x25519_pk.as_bytes();

    let mut shared_secret = combine(
        ss_mlkem.as_slice(),
        ss_x25519.as_bytes(),
        &x25519_eph_pk_bytes,
        &pk_x25519,
    );

    let result = secretbox_decrypt(&shared_secret, nonce_slice, encrypted);
    shared_secret.zeroize();
    result
}

// === Internal: Cat-3 open ===

fn hybrid_open_768(combined: &[u8], seed_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let seed_bytes = b64::decode(seed_b64)?;
    if seed_bytes.len() != SEED_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SEED_LEN,
            got: seed_bytes.len(),
        });
    }
    if combined.len() < MIN_HYBRID_768_LEN {
        return Err(CryptoError::TooShort);
    }

    let seed: [u8; SEED_LEN] = seed_bytes.try_into().unwrap();
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_768_LEN);
    let mlkem_seed: [u8; MLKEM768_SEED_LEN] = expanded[..MLKEM768_SEED_LEN].try_into().unwrap();
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[MLKEM768_SEED_LEN..].try_into().unwrap();
    expanded.zeroize();

    // Parse ciphertext
    let mlkem_ct = &combined[1..1 + MLKEM768_CT_LEN];
    let x25519_eph_pk_bytes: [u8; X25519_LEN] = combined
        [1 + MLKEM768_CT_LEN..1 + COMBINED_CT_768_LEN]
        .try_into()
        .unwrap();
    let nonce_slice = &combined[1 + COMBINED_CT_768_LEN..1 + COMBINED_CT_768_LEN + NONCE_LEN];
    let encrypted = &combined[1 + COMBINED_CT_768_LEN + NONCE_LEN..];

    // ML-KEM-768 decapsulate
    let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed.into());
    let kem_ct = mlkem_ct
        .try_into()
        .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 ciphertext".into()))?;
    let ss_mlkem = dk.decapsulate(kem_ct);

    // X25519 decapsulate
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_eph_pk = X25519PublicKey::from(x25519_eph_pk_bytes);
    let ss_x25519 = x25519_sk.diffie_hellman(&x25519_eph_pk);

    let x25519_pk = X25519PublicKey::from(&x25519_sk);
    let pk_x25519: [u8; X25519_LEN] = *x25519_pk.as_bytes();

    let mut shared_secret = combine(
        ss_mlkem.as_slice(),
        ss_x25519.as_bytes(),
        &x25519_eph_pk_bytes,
        &pk_x25519,
    );

    let result = secretbox_decrypt(&shared_secret, nonce_slice, encrypted);
    shared_secret.zeroize();
    result
}

// === Internal: Cat-5 open ===

fn hybrid_open_1024(combined: &[u8], seed_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let seed_bytes = b64::decode(seed_b64)?;
    if seed_bytes.len() != SEED_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SEED_LEN,
            got: seed_bytes.len(),
        });
    }
    if combined.len() < MIN_HYBRID_1024_LEN {
        return Err(CryptoError::TooShort);
    }

    let seed: [u8; SEED_LEN] = seed_bytes.try_into().unwrap();
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_1024_LEN);
    let mlkem_seed: [u8; MLKEM1024_SEED_LEN] = expanded[..MLKEM1024_SEED_LEN].try_into().unwrap();
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[MLKEM1024_SEED_LEN..].try_into().unwrap();
    expanded.zeroize();

    // Parse ciphertext
    let mlkem_ct = &combined[1..1 + MLKEM1024_CT_LEN];
    let x25519_eph_pk_bytes: [u8; X25519_LEN] = combined
        [1 + MLKEM1024_CT_LEN..1 + COMBINED_CT_1024_LEN]
        .try_into()
        .unwrap();
    let nonce_slice = &combined[1 + COMBINED_CT_1024_LEN..1 + COMBINED_CT_1024_LEN + NONCE_LEN];
    let encrypted = &combined[1 + COMBINED_CT_1024_LEN + NONCE_LEN..];

    // ML-KEM-1024 decapsulate
    let dk = DecapsulationKey::<MlKem1024>::from_seed(mlkem_seed.into());
    let kem_ct = mlkem_ct
        .try_into()
        .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 ciphertext".into()))?;
    let ss_mlkem = dk.decapsulate(kem_ct);

    // X25519 decapsulate
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_eph_pk = X25519PublicKey::from(x25519_eph_pk_bytes);
    let ss_x25519 = x25519_sk.diffie_hellman(&x25519_eph_pk);

    let x25519_pk = X25519PublicKey::from(&x25519_sk);
    let pk_x25519: [u8; X25519_LEN] = *x25519_pk.as_bytes();

    let mut shared_secret = combine(
        ss_mlkem.as_slice(),
        ss_x25519.as_bytes(),
        &x25519_eph_pk_bytes,
        &pk_x25519,
    );

    let result = secretbox_decrypt(&shared_secret, nonce_slice, encrypted);
    shared_secret.zeroize();
    result
}

// === CNSA 2.0 suites: ML-KEM helpers ===

/// ML-KEM-768 encapsulate against `ek_bytes`. Returns `(ct, ss(32))`.
fn mlkem768_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
    let ek = EncapsulationKey::<MlKem768>::new(
        ek_bytes
            .try_into()
            .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 ek".into()))?,
    )
    .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 encapsulation key".into()))?;
    let mut coins = [0u8; 32];
    random_bytes(&mut coins);
    let (ct, ss) = ek.encapsulate_deterministic(&coins.into());
    coins.zeroize();
    let ss32: [u8; 32] = ss
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Hybrid("unexpected ML-KEM shared-secret length".into()))?;
    Ok((ct.as_slice().to_vec(), ss32))
}

/// ML-KEM-1024 encapsulate against `ek_bytes`. Returns `(ct, ss(32))`.
fn mlkem1024_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
    let ek = EncapsulationKey::<MlKem1024>::new(
        ek_bytes
            .try_into()
            .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 ek".into()))?,
    )
    .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 encapsulation key".into()))?;
    let mut coins = [0u8; 32];
    random_bytes(&mut coins);
    let (ct, ss) = ek.encapsulate_deterministic(&coins.into());
    coins.zeroize();
    let ss32: [u8; 32] = ss
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Hybrid("unexpected ML-KEM shared-secret length".into()))?;
    Ok((ct.as_slice().to_vec(), ss32))
}

/// ML-KEM-768 decapsulate `ct` with a 64-byte seed. Returns `ss(32)`.
fn mlkem768_decapsulate(
    seed64: &[u8; MLKEM768_SEED_LEN],
    ct: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let dk = DecapsulationKey::<MlKem768>::from_seed((*seed64).into());
    let kem_ct = ct
        .try_into()
        .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 ciphertext".into()))?;
    let ss = dk.decapsulate(kem_ct);
    ss.as_slice()
        .try_into()
        .map_err(|_| CryptoError::Hybrid("unexpected ML-KEM shared-secret length".into()))
}

/// ML-KEM-1024 decapsulate `ct` with a 64-byte seed. Returns `ss(32)`.
fn mlkem1024_decapsulate(
    seed64: &[u8; MLKEM1024_SEED_LEN],
    ct: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let dk = DecapsulationKey::<MlKem1024>::from_seed((*seed64).into());
    let kem_ct = ct
        .try_into()
        .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 ciphertext".into()))?;
    let ss = dk.decapsulate(kem_ct);
    ss.as_slice()
        .try_into()
        .map_err(|_| CryptoError::Hybrid("unexpected ML-KEM shared-secret length".into()))
}

/// Derive the ML-KEM-1024 encapsulation key bytes (1568 B) from a 64-byte seed.
fn mlkem1024_ek_from_seed(seed64: &[u8; MLKEM1024_SEED_LEN]) -> Vec<u8> {
    let dk = DecapsulationKey::<MlKem1024>::from_seed((*seed64).into());
    dk.encapsulation_key().to_bytes().as_slice().to_vec()
}

/// Derive the ML-KEM-768 encapsulation key bytes (1184 B) from a 64-byte seed.
fn mlkem768_ek_from_seed(seed64: &[u8; MLKEM768_SEED_LEN]) -> Vec<u8> {
    let dk = DecapsulationKey::<MlKem768>::from_seed((*seed64).into());
    dk.encapsulation_key().to_bytes().as_slice().to_vec()
}

// === CNSA 2.0 suites: keygen ===

/// Generate a keypair for the given [`Suite`] + [`SecurityLevel`].
///
/// - `Suite::Hybrid` (any level) and `Suite::HybridMatched` at Cat-1 delegate to
///   the existing [`generate_hybrid_keypair_with_level`] (identical bytes).
/// - `Suite::HybridMatched` at Cat-3/Cat-5 and `Suite::PureCnsa2` at Cat-5
///   produce the new combined-key layouts (ML-KEM ek `||` matched ECC pk, or
///   ML-KEM-1024 ek alone). The `secret_key` stays a single 32-byte root seed.
///
/// Returns an error for unsupported combinations (PureCnsa2 below Cat-5).
pub fn generate_hybrid_keypair_suite(
    suite: Suite,
    level: SecurityLevel,
) -> Result<HybridKeyPair, CryptoError> {
    match (suite, level) {
        (Suite::Hybrid, _) | (Suite::HybridMatched, SecurityLevel::Cat1) => {
            Ok(generate_hybrid_keypair_with_level(level))
        }
        (Suite::HybridMatched, SecurityLevel::Cat3) => Ok(generate_matched_cat3_keypair()),
        (Suite::HybridMatched, SecurityLevel::Cat5) => Ok(generate_matched_cat5_keypair()),
        (Suite::PureCnsa2, SecurityLevel::Cat5) => Ok(generate_pure_cnsa2_keypair()),
        (Suite::PureCnsa2, _) => Err(CryptoError::Hybrid(
            "PureCnsa2 is Cat-5 only in v0.7.0".into(),
        )),
    }
}

fn generate_pure_cnsa2_keypair() -> HybridKeyPair {
    let mut seed = [0u8; SEED_LEN];
    random_bytes(&mut seed);
    let mut expanded = expand_seed(&seed, MLKEM1024_SEED_LEN);
    let mlkem_seed: [u8; MLKEM1024_SEED_LEN] = expanded[..].try_into().unwrap();
    let pk = mlkem1024_ek_from_seed(&mlkem_seed);
    let pair = HybridKeyPair {
        public_key: b64::encode(&pk),
        secret_key: b64::encode(&seed),
    };
    seed.zeroize();
    expanded.zeroize();
    pair
}

fn generate_matched_cat3_keypair() -> HybridKeyPair {
    let mut seed = [0u8; SEED_LEN];
    random_bytes(&mut seed);
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_MATCHED_CAT3_LEN);
    let mlkem_seed: [u8; MLKEM768_SEED_LEN] = expanded[..MLKEM768_SEED_LEN].try_into().unwrap();
    let x448_secret: [u8; ecc::X448_LEN] = expanded[MLKEM768_SEED_LEN..].try_into().unwrap();
    let mut pk = mlkem768_ek_from_seed(&mlkem_seed);
    pk.extend_from_slice(&ecc::x448_public_from_secret(&x448_secret));
    let pair = HybridKeyPair {
        public_key: b64::encode(&pk),
        secret_key: b64::encode(&seed),
    };
    seed.zeroize();
    expanded.zeroize();
    pair
}

fn generate_matched_cat5_keypair() -> HybridKeyPair {
    let mut seed = [0u8; SEED_LEN];
    random_bytes(&mut seed);
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_MATCHED_CAT5_LEN);
    let mlkem_seed: [u8; MLKEM1024_SEED_LEN] = expanded[..MLKEM1024_SEED_LEN].try_into().unwrap();
    let p521_secret: [u8; ecc::P521_SK_LEN] = expanded[MLKEM1024_SEED_LEN..].try_into().unwrap();
    let mut pk = mlkem1024_ek_from_seed(&mlkem_seed);
    pk.extend_from_slice(
        &ecc::p521_public_from_secret(&p521_secret)
            .expect("deterministic P-521 public-key derivation"),
    );
    let pair = HybridKeyPair {
        public_key: b64::encode(&pk),
        secret_key: b64::encode(&seed),
    };
    seed.zeroize();
    expanded.zeroize();
    pair
}

// === CNSA 2.0 suites: seal ===

/// Seal `plaintext` to a recipient public key under the given [`Suite`] +
/// [`SecurityLevel`], binding the **default** context label [`SEAL_CONTEXT_V1`].
///
/// See [`hybrid_seal_suite_with_context`] for a custom per-tenant label.
pub fn hybrid_seal_suite(
    plaintext: &[u8],
    combined_pk_b64: &str,
    suite: Suite,
    level: SecurityLevel,
) -> Result<String, CryptoError> {
    hybrid_seal_suite_with_context(plaintext, combined_pk_b64, suite, level, SEAL_CONTEXT_V1)
}

/// Seal `plaintext` under the given [`Suite`] + [`SecurityLevel`] + context label.
///
/// `Suite::Hybrid` (and `HybridMatched` at Cat-1) delegate to the legacy
/// combineKEMS path and ignore `context_label` (that format binds no context).
/// The new suites build the HKDF-SHA512 + AES-256-GCM envelope described in
/// [`crate::suite`], binding `context_label` into both the HKDF `info` and the
/// GCM AAD.
pub fn hybrid_seal_suite_with_context(
    plaintext: &[u8],
    combined_pk_b64: &str,
    suite: Suite,
    level: SecurityLevel,
    context_label: &str,
) -> Result<String, CryptoError> {
    match (suite, level) {
        (Suite::Hybrid, _) => hybrid_seal_with_level(plaintext, combined_pk_b64, level),
        (Suite::HybridMatched, SecurityLevel::Cat1) => {
            hybrid_seal_with_level(plaintext, combined_pk_b64, SecurityLevel::Cat1)
        }
        (Suite::HybridMatched, SecurityLevel::Cat3) => {
            seal_matched_cat3(plaintext, combined_pk_b64, context_label)
        }
        (Suite::HybridMatched, SecurityLevel::Cat5) => {
            seal_matched_cat5(plaintext, combined_pk_b64, context_label)
        }
        (Suite::PureCnsa2, SecurityLevel::Cat5) => {
            seal_pure_cnsa2(plaintext, combined_pk_b64, context_label)
        }
        (Suite::PureCnsa2, _) => Err(CryptoError::Hybrid(
            "PureCnsa2 is Cat-5 only in v0.7.0".into(),
        )),
    }
}

fn check_pk_len(pk: &[u8], expected: usize) -> Result<(), CryptoError> {
    if pk.len() != expected {
        return Err(CryptoError::InvalidLength {
            expected,
            got: pk.len(),
        });
    }
    Ok(())
}

fn assemble_envelope(
    tag: u8,
    kem_ct: &[u8],
    ecc_eph_pk: Option<&[u8]>,
    nonce: &[u8; GCM_NONCE_LEN],
    aead_ct: &[u8],
) -> String {
    let ecc_len = ecc_eph_pk.map_or(0, |p| p.len());
    let mut out = Vec::with_capacity(1 + kem_ct.len() + ecc_len + GCM_NONCE_LEN + aead_ct.len());
    out.push(tag);
    out.extend_from_slice(kem_ct);
    if let Some(p) = ecc_eph_pk {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(nonce);
    out.extend_from_slice(aead_ct);
    b64::encode(&out)
}

fn random_nonce() -> [u8; GCM_NONCE_LEN] {
    let mut nonce = [0u8; GCM_NONCE_LEN];
    random_bytes(&mut nonce);
    nonce
}

fn seal_pure_cnsa2(
    plaintext: &[u8],
    combined_pk_b64: &str,
    context_label: &str,
) -> Result<String, CryptoError> {
    let pk = b64::decode(combined_pk_b64)?;
    check_pk_len(&pk, PURE_CNSA2_PK_LEN)?;
    let (kem_ct, ss_mlkem) = mlkem1024_encapsulate(&pk)?;
    let nonce = random_nonce();
    let aead_ct = suite::envelope_seal(
        &ss_mlkem,
        TAG_KEM_PURE_CNSA2,
        context_label,
        &nonce,
        plaintext,
    )?;
    Ok(assemble_envelope(
        TAG_KEM_PURE_CNSA2,
        &kem_ct,
        None,
        &nonce,
        &aead_ct,
    ))
}

fn seal_matched_cat3(
    plaintext: &[u8],
    combined_pk_b64: &str,
    context_label: &str,
) -> Result<String, CryptoError> {
    let pk = b64::decode(combined_pk_b64)?;
    check_pk_len(&pk, MATCHED_CAT3_PK_LEN)?;
    let (mlkem_ek, x448_pk) = pk.split_at(MLKEM768_EK_LEN);
    let (kem_ct, ss_mlkem) = mlkem768_encapsulate(mlkem_ek)?;
    let (x448_eph_pk, ss_x448) = ecc::x448_encapsulate(x448_pk)?;
    let mut ikm = Vec::with_capacity(32 + ecc::X448_LEN);
    ikm.extend_from_slice(&ss_mlkem);
    ikm.extend_from_slice(&ss_x448);
    let nonce = random_nonce();
    let aead_ct =
        suite::envelope_seal(&ikm, TAG_KEM_MATCHED_CAT3, context_label, &nonce, plaintext)?;
    ikm.zeroize();
    Ok(assemble_envelope(
        TAG_KEM_MATCHED_CAT3,
        &kem_ct,
        Some(&x448_eph_pk),
        &nonce,
        &aead_ct,
    ))
}

fn seal_matched_cat5(
    plaintext: &[u8],
    combined_pk_b64: &str,
    context_label: &str,
) -> Result<String, CryptoError> {
    let pk = b64::decode(combined_pk_b64)?;
    check_pk_len(&pk, MATCHED_CAT5_PK_LEN)?;
    let (mlkem_ek, p521_pk) = pk.split_at(MLKEM1024_EK_LEN);
    let (kem_ct, ss_mlkem) = mlkem1024_encapsulate(mlkem_ek)?;
    let (p521_eph_pk, ss_p521) = ecc::p521_encapsulate(p521_pk)?;
    let mut ikm = Vec::with_capacity(32 + ecc::P521_SS_LEN);
    ikm.extend_from_slice(&ss_mlkem);
    ikm.extend_from_slice(&ss_p521);
    let nonce = random_nonce();
    let aead_ct =
        suite::envelope_seal(&ikm, TAG_KEM_MATCHED_CAT5, context_label, &nonce, plaintext)?;
    ikm.zeroize();
    Ok(assemble_envelope(
        TAG_KEM_MATCHED_CAT5,
        &kem_ct,
        Some(&p521_eph_pk),
        &nonce,
        &aead_ct,
    ))
}

// === CNSA 2.0 suites: open ===

fn load_seed(seed_b64: &str) -> Result<[u8; SEED_LEN], CryptoError> {
    let seed_bytes = b64::decode(seed_b64)?;
    if seed_bytes.len() != SEED_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SEED_LEN,
            got: seed_bytes.len(),
        });
    }
    Ok(seed_bytes.try_into().unwrap())
}

fn open_pure_cnsa2(
    combined: &[u8],
    seed_b64: &str,
    context_label: &str,
) -> Result<Vec<u8>, CryptoError> {
    if combined.len() < MIN_PURE_CNSA2_LEN {
        return Err(CryptoError::TooShort);
    }
    let seed = load_seed(seed_b64)?;
    let mut expanded = expand_seed(&seed, MLKEM1024_SEED_LEN);
    let mlkem_seed: [u8; MLKEM1024_SEED_LEN] = expanded[..].try_into().unwrap();

    let kem_ct = &combined[1..1 + MLKEM1024_CT_LEN];
    let nonce: [u8; GCM_NONCE_LEN] = combined
        [1 + MLKEM1024_CT_LEN..1 + MLKEM1024_CT_LEN + GCM_NONCE_LEN]
        .try_into()
        .unwrap();
    let aead_ct = &combined[1 + MLKEM1024_CT_LEN + GCM_NONCE_LEN..];

    let ss_mlkem = mlkem1024_decapsulate(&mlkem_seed, kem_ct)?;
    expanded.zeroize();
    suite::envelope_open(
        &ss_mlkem,
        TAG_KEM_PURE_CNSA2,
        context_label,
        &nonce,
        aead_ct,
    )
}

fn open_matched_cat3(
    combined: &[u8],
    seed_b64: &str,
    context_label: &str,
) -> Result<Vec<u8>, CryptoError> {
    if combined.len() < MIN_MATCHED_CAT3_LEN {
        return Err(CryptoError::TooShort);
    }
    let seed = load_seed(seed_b64)?;
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_MATCHED_CAT3_LEN);
    let mlkem_seed: [u8; MLKEM768_SEED_LEN] = expanded[..MLKEM768_SEED_LEN].try_into().unwrap();
    let x448_secret: [u8; ecc::X448_LEN] = expanded[MLKEM768_SEED_LEN..].try_into().unwrap();

    let kem_ct = &combined[1..1 + MLKEM768_CT_LEN];
    let ecc_start = 1 + MLKEM768_CT_LEN;
    let x448_eph_pk = &combined[ecc_start..ecc_start + ecc::X448_LEN];
    let nonce_start = ecc_start + ecc::X448_LEN;
    let nonce: [u8; GCM_NONCE_LEN] = combined[nonce_start..nonce_start + GCM_NONCE_LEN]
        .try_into()
        .unwrap();
    let aead_ct = &combined[nonce_start + GCM_NONCE_LEN..];

    let ss_mlkem = mlkem768_decapsulate(&mlkem_seed, kem_ct)?;
    let ss_x448 = ecc::x448_decapsulate(&x448_secret, x448_eph_pk)?;
    expanded.zeroize();
    let mut ikm = Vec::with_capacity(32 + ecc::X448_LEN);
    ikm.extend_from_slice(&ss_mlkem);
    ikm.extend_from_slice(&ss_x448);
    let out = suite::envelope_open(&ikm, TAG_KEM_MATCHED_CAT3, context_label, &nonce, aead_ct);
    ikm.zeroize();
    out
}

fn open_matched_cat5(
    combined: &[u8],
    seed_b64: &str,
    context_label: &str,
) -> Result<Vec<u8>, CryptoError> {
    if combined.len() < MIN_MATCHED_CAT5_LEN {
        return Err(CryptoError::TooShort);
    }
    let seed = load_seed(seed_b64)?;
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_MATCHED_CAT5_LEN);
    let mlkem_seed: [u8; MLKEM1024_SEED_LEN] = expanded[..MLKEM1024_SEED_LEN].try_into().unwrap();
    let p521_secret: [u8; ecc::P521_SK_LEN] = expanded[MLKEM1024_SEED_LEN..].try_into().unwrap();

    let kem_ct = &combined[1..1 + MLKEM1024_CT_LEN];
    let ecc_start = 1 + MLKEM1024_CT_LEN;
    let p521_eph_pk = &combined[ecc_start..ecc_start + ecc::P521_PK_LEN];
    let nonce_start = ecc_start + ecc::P521_PK_LEN;
    let nonce: [u8; GCM_NONCE_LEN] = combined[nonce_start..nonce_start + GCM_NONCE_LEN]
        .try_into()
        .unwrap();
    let aead_ct = &combined[nonce_start + GCM_NONCE_LEN..];

    let ss_mlkem = mlkem1024_decapsulate(&mlkem_seed, kem_ct)?;
    let ss_p521 = ecc::p521_decapsulate(&p521_secret, p521_eph_pk)?;
    expanded.zeroize();
    let mut ikm = Vec::with_capacity(32 + ecc::P521_SS_LEN);
    ikm.extend_from_slice(&ss_mlkem);
    ikm.extend_from_slice(&ss_p521);
    let out = suite::envelope_open(&ikm, TAG_KEM_MATCHED_CAT5, context_label, &nonce, aead_ct);
    ikm.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Cat-3 (existing behavior) ===

    #[test]
    fn cat3_roundtrip() {
        let kp = generate_hybrid_keypair();
        let pt = b"32-byte symmetric context key!!!";
        let ct = hybrid_seal(pt, &kp.public_key).unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        let opened = hybrid_open(&ct, &kp.secret_key).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn cat3_wrong_key_fails() {
        let kp1 = generate_hybrid_keypair();
        let kp2 = generate_hybrid_keypair();
        let ct = hybrid_seal(b"x", &kp1.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp2.secret_key).is_err());
    }

    #[test]
    fn cat3_version_tag() {
        let kp = generate_hybrid_keypair();
        let raw = b64::decode(&hybrid_seal(b"x", &kp.public_key).unwrap()).unwrap();
        assert_eq!(raw[0], VERSION_HYBRID_768);
    }

    #[test]
    fn cat3_nondeterministic() {
        let kp = generate_hybrid_keypair();
        let c1 = hybrid_seal(b"x", &kp.public_key).unwrap();
        let c2 = hybrid_seal(b"x", &kp.public_key).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn cat3_empty_plaintext() {
        let kp = generate_hybrid_keypair();
        let ct = hybrid_seal(b"", &kp.public_key).unwrap();
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"");
    }

    #[test]
    fn cat3_key_sizes() {
        let kp = generate_hybrid_keypair();
        let pk = b64::decode(&kp.public_key).unwrap();
        let sk = b64::decode(&kp.secret_key).unwrap();
        assert_eq!(pk.len(), COMBINED_PK_768_LEN); // 1216
        assert_eq!(sk.len(), SEED_LEN); // 32
    }

    #[test]
    fn cat3_ciphertext_size() {
        let kp = generate_hybrid_keypair();
        let pt = b"exactly 32 bytes of key material";
        let raw = b64::decode(&hybrid_seal(pt, &kp.public_key).unwrap()).unwrap();
        // 1 + 1120 + 24 + 32 + 16 = 1193
        assert_eq!(
            raw.len(),
            1 + COMBINED_CT_768_LEN + NONCE_LEN + 32 + MAC_LEN
        );
    }

    // === Cat-1 (new) ===

    #[test]
    fn cat1_roundtrip() {
        let kp = generate_hybrid_keypair_512();
        let pt = b"32-byte symmetric context key!!!";
        let ct = hybrid_seal_512(pt, &kp.public_key).unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        let opened = hybrid_open(&ct, &kp.secret_key).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn cat1_version_tag() {
        let kp = generate_hybrid_keypair_512();
        let raw = b64::decode(&hybrid_seal_512(b"x", &kp.public_key).unwrap()).unwrap();
        assert_eq!(raw[0], VERSION_HYBRID_512);
    }

    #[test]
    fn cat1_wrong_key_fails() {
        let kp1 = generate_hybrid_keypair_512();
        let kp2 = generate_hybrid_keypair_512();
        let ct = hybrid_seal_512(b"x", &kp1.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp2.secret_key).is_err());
    }

    #[test]
    fn cat1_key_sizes() {
        let kp = generate_hybrid_keypair_512();
        let pk = b64::decode(&kp.public_key).unwrap();
        let sk = b64::decode(&kp.secret_key).unwrap();
        assert_eq!(pk.len(), COMBINED_PK_512_LEN); // 832
        assert_eq!(sk.len(), SEED_LEN); // 32
    }

    #[test]
    fn cat1_ciphertext_size() {
        let kp = generate_hybrid_keypair_512();
        let pt = b"exactly 32 bytes of key material";
        let raw = b64::decode(&hybrid_seal_512(pt, &kp.public_key).unwrap()).unwrap();
        // 1 + 800 + 24 + 32 + 16 = 873
        assert_eq!(
            raw.len(),
            1 + COMBINED_CT_512_LEN + NONCE_LEN + 32 + MAC_LEN
        );
    }

    #[test]
    fn cat1_nondeterministic() {
        let kp = generate_hybrid_keypair_512();
        let c1 = hybrid_seal_512(b"x", &kp.public_key).unwrap();
        let c2 = hybrid_seal_512(b"x", &kp.public_key).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn cat1_empty_plaintext() {
        let kp = generate_hybrid_keypair_512();
        let ct = hybrid_seal_512(b"", &kp.public_key).unwrap();
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"");
    }

    // === Cat-5 (new) ===

    #[test]
    fn cat5_roundtrip() {
        let kp = generate_hybrid_keypair_1024();
        let pt = b"32-byte symmetric context key!!!";
        let ct = hybrid_seal_1024(pt, &kp.public_key).unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        let opened = hybrid_open(&ct, &kp.secret_key).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn cat5_version_tag() {
        let kp = generate_hybrid_keypair_1024();
        let raw = b64::decode(&hybrid_seal_1024(b"x", &kp.public_key).unwrap()).unwrap();
        assert_eq!(raw[0], VERSION_HYBRID_1024);
    }

    #[test]
    fn cat5_wrong_key_fails() {
        let kp1 = generate_hybrid_keypair_1024();
        let kp2 = generate_hybrid_keypair_1024();
        let ct = hybrid_seal_1024(b"x", &kp1.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp2.secret_key).is_err());
    }

    #[test]
    fn cat5_key_sizes() {
        let kp = generate_hybrid_keypair_1024();
        let pk = b64::decode(&kp.public_key).unwrap();
        let sk = b64::decode(&kp.secret_key).unwrap();
        assert_eq!(pk.len(), COMBINED_PK_1024_LEN); // 1600
        assert_eq!(sk.len(), SEED_LEN); // 32
    }

    #[test]
    fn cat5_ciphertext_size() {
        let kp = generate_hybrid_keypair_1024();
        let pt = b"exactly 32 bytes of key material";
        let raw = b64::decode(&hybrid_seal_1024(pt, &kp.public_key).unwrap()).unwrap();
        // 1 + 1600 + 24 + 32 + 16 = 1673
        assert_eq!(
            raw.len(),
            1 + COMBINED_CT_1024_LEN + NONCE_LEN + 32 + MAC_LEN
        );
    }

    #[test]
    fn cat5_nondeterministic() {
        let kp = generate_hybrid_keypair_1024();
        let c1 = hybrid_seal_1024(b"x", &kp.public_key).unwrap();
        let c2 = hybrid_seal_1024(b"x", &kp.public_key).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn cat5_empty_plaintext() {
        let kp = generate_hybrid_keypair_1024();
        let ct = hybrid_seal_1024(b"", &kp.public_key).unwrap();
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"");
    }

    // === Cross-level ===

    #[test]
    fn cat3_ct_cannot_open_with_cat5_key() {
        let kp3 = generate_hybrid_keypair();
        let kp5 = generate_hybrid_keypair_1024();
        let ct = hybrid_seal(b"test", &kp3.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp5.secret_key).is_err());
    }

    #[test]
    fn cat5_ct_cannot_open_with_cat3_key() {
        let kp3 = generate_hybrid_keypair();
        let kp5 = generate_hybrid_keypair_1024();
        let ct = hybrid_seal_1024(b"test", &kp5.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp3.secret_key).is_err());
    }

    #[test]
    fn cat1_ct_cannot_open_with_cat3_key() {
        let kp1 = generate_hybrid_keypair_512();
        let kp3 = generate_hybrid_keypair();
        let ct = hybrid_seal_512(b"test", &kp1.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp3.secret_key).is_err());
    }

    #[test]
    fn cat1_ct_cannot_open_with_cat5_key() {
        let kp1 = generate_hybrid_keypair_512();
        let kp5 = generate_hybrid_keypair_1024();
        let ct = hybrid_seal_512(b"test", &kp1.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp5.secret_key).is_err());
    }

    #[test]
    fn legacy_not_hybrid() {
        // A short blob whose first byte is not any hybrid tag.
        let legacy = b64::encode(&[0x42, 0x02, 0x03]);
        assert!(!is_hybrid_ciphertext(&legacy));
    }

    #[test]
    fn legacy_starting_with_0x01_not_misdetected_as_cat1() {
        // `is_hybrid_ciphertext` is length-aware: a legacy-sized (~80B) blob whose
        // first byte collides with the Cat-1 tag (0x01) is NOT classified as
        // hybrid, because it is far below the Cat-1 minimum length
        // (1 + 768 + 32 + 24 + 16 = 841B). In practice Mosslet legacy cts (~80B
        // sealing a 32B key) can never reach a hybrid length.
        let mut legacy = vec![0x01u8]; // collides with the Cat-1 tag
        legacy.extend_from_slice(&[0u8; 79]); // total 80 bytes, legacy-sized
        let legacy_b64 = b64::encode(&legacy);
        assert!(!is_hybrid_ciphertext(&legacy_b64));
        // And `hybrid_open`'s own length gate independently rejects it.
        let kp = generate_hybrid_keypair_512();
        let err = hybrid_open(&legacy_b64, &kp.secret_key).unwrap_err();
        assert!(matches!(err, CryptoError::TooShort));
    }

    #[test]
    fn long_0x01_blob_below_cat1_min_not_hybrid() {
        // A 0x01-leading blob just under the Cat-1 minimum is still not hybrid.
        let min_cat1 = MIN_HYBRID_512_LEN; // 841
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&vec![0u8; min_cat1 - 2]); // total = min - 1
        assert!(!is_hybrid_ciphertext(&b64::encode(&blob)));
        // At exactly the minimum, the tag+length check classifies it as hybrid
        // (disambiguation past this point is handled by unseal_from_user's
        // fallback to the legacy opener).
        let mut at_min = vec![0x01u8];
        at_min.extend_from_slice(&vec![0u8; min_cat1 - 1]); // total = min
        assert!(is_hybrid_ciphertext(&b64::encode(&at_min)));
    }

    #[test]
    fn seed_expansion_deterministic() {
        let seed = [0x42u8; SEED_LEN];
        let expanded = expand_seed(&seed, 96);
        let expanded2 = expand_seed(&seed, 96);
        assert_eq!(expanded, expanded2);
    }

    #[test]
    fn combiner_uses_label() {
        let ss_mlkem = [0xAAu8; 32];
        let ss_x25519 = [0xBBu8; 32];
        let ct_x25519 = [0xCCu8; 32];
        let pk_x25519 = [0xDDu8; 32];
        let result = combine(&ss_mlkem, &ss_x25519, &ct_x25519, &pk_x25519);
        assert_eq!(result.len(), 32);

        let ss_mlkem2 = [0xEEu8; 32];
        let result2 = combine(&ss_mlkem2, &ss_x25519, &ct_x25519, &pk_x25519);
        assert_ne!(result, result2);
    }

    // === CNSA 2.0 suites (v0.7.0) ===

    #[test]
    fn pure_cnsa2_roundtrip() {
        let kp = generate_hybrid_keypair_suite(Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
        let pt = b"32-byte symmetric context key!!!";
        let ct =
            hybrid_seal_suite(pt, &kp.public_key, Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        assert_eq!(b64::decode(&ct).unwrap()[0], TAG_KEM_PURE_CNSA2);
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), pt);
    }

    #[test]
    fn pure_cnsa2_pk_len_and_no_classical_half() {
        let kp = generate_hybrid_keypair_suite(Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
        assert_eq!(
            b64::decode(&kp.public_key).unwrap().len(),
            PURE_CNSA2_PK_LEN
        );
        assert_eq!(b64::decode(&kp.secret_key).unwrap().len(), SEED_LEN);
    }

    #[test]
    fn pure_cnsa2_only_cat5() {
        assert!(generate_hybrid_keypair_suite(Suite::PureCnsa2, SecurityLevel::Cat3).is_err());
        assert!(generate_hybrid_keypair_suite(Suite::PureCnsa2, SecurityLevel::Cat1).is_err());
    }

    #[test]
    fn matched_cat3_roundtrip() {
        let kp = generate_hybrid_keypair_suite(Suite::HybridMatched, SecurityLevel::Cat3).unwrap();
        assert_eq!(
            b64::decode(&kp.public_key).unwrap().len(),
            MATCHED_CAT3_PK_LEN
        );
        let pt = b"matched cat-3 (ML-KEM-768 + X448)";
        let ct = hybrid_seal_suite(
            pt,
            &kp.public_key,
            Suite::HybridMatched,
            SecurityLevel::Cat3,
        )
        .unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        assert_eq!(b64::decode(&ct).unwrap()[0], TAG_KEM_MATCHED_CAT3);
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), pt);
    }

    #[test]
    fn matched_cat5_roundtrip() {
        let kp = generate_hybrid_keypair_suite(Suite::HybridMatched, SecurityLevel::Cat5).unwrap();
        assert_eq!(
            b64::decode(&kp.public_key).unwrap().len(),
            MATCHED_CAT5_PK_LEN
        );
        let pt = b"matched cat-5 (ML-KEM-1024 + P-521)";
        let ct = hybrid_seal_suite(
            pt,
            &kp.public_key,
            Suite::HybridMatched,
            SecurityLevel::Cat5,
        )
        .unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        assert_eq!(b64::decode(&ct).unwrap()[0], TAG_KEM_MATCHED_CAT5);
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), pt);
    }

    #[test]
    fn matched_cat1_is_plain_hybrid() {
        // HybridMatched at Cat-1 must be byte-format-identical to Hybrid Cat-1
        // (X25519, tag 0x01) — no new format at the lowest rung.
        let kp = generate_hybrid_keypair_suite(Suite::HybridMatched, SecurityLevel::Cat1).unwrap();
        let ct = hybrid_seal_suite(
            b"x",
            &kp.public_key,
            Suite::HybridMatched,
            SecurityLevel::Cat1,
        )
        .unwrap();
        assert_eq!(b64::decode(&ct).unwrap()[0], VERSION_HYBRID_512);
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"x");
    }

    #[test]
    fn hybrid_suite_is_unchanged_legacy_format() {
        // Suite::Hybrid must keep emitting the legacy tags/bytes at every level.
        for (level, tag) in [
            (SecurityLevel::Cat1, VERSION_HYBRID_512),
            (SecurityLevel::Cat3, VERSION_HYBRID_768),
            (SecurityLevel::Cat5, VERSION_HYBRID_1024),
        ] {
            let kp = generate_hybrid_keypair_suite(Suite::Hybrid, level).unwrap();
            let ct = hybrid_seal_suite(b"x", &kp.public_key, Suite::Hybrid, level).unwrap();
            assert_eq!(b64::decode(&ct).unwrap()[0], tag);
            assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"x");
        }
    }

    #[test]
    fn new_suites_empty_plaintext() {
        for (suite, level) in [
            (Suite::PureCnsa2, SecurityLevel::Cat5),
            (Suite::HybridMatched, SecurityLevel::Cat3),
            (Suite::HybridMatched, SecurityLevel::Cat5),
        ] {
            let kp = generate_hybrid_keypair_suite(suite, level).unwrap();
            let ct = hybrid_seal_suite(b"", &kp.public_key, suite, level).unwrap();
            assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"");
        }
    }

    #[test]
    fn new_suites_nondeterministic_and_wrong_key_fails() {
        for (suite, level) in [
            (Suite::PureCnsa2, SecurityLevel::Cat5),
            (Suite::HybridMatched, SecurityLevel::Cat3),
            (Suite::HybridMatched, SecurityLevel::Cat5),
        ] {
            let kp = generate_hybrid_keypair_suite(suite, level).unwrap();
            let kp2 = generate_hybrid_keypair_suite(suite, level).unwrap();
            let c1 = hybrid_seal_suite(b"x", &kp.public_key, suite, level).unwrap();
            let c2 = hybrid_seal_suite(b"x", &kp.public_key, suite, level).unwrap();
            assert_ne!(c1, c2, "fresh nonce + KEM => non-deterministic");
            assert!(
                hybrid_open(&c1, &kp2.secret_key).is_err(),
                "wrong key fails"
            );
        }
    }

    #[test]
    fn context_label_is_bound() {
        let kp = generate_hybrid_keypair_suite(Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
        let ct = hybrid_seal_suite_with_context(
            b"secret",
            &kp.public_key,
            Suite::PureCnsa2,
            SecurityLevel::Cat5,
            "mosslet/seal/v1",
        )
        .unwrap();
        // Opening with the wrong context label fails (AAD + HKDF info mismatch).
        assert!(hybrid_open_with_context(&ct, &kp.secret_key, "metamorphic/seal/v1").is_err());
        // Opening with the correct label succeeds.
        assert_eq!(
            hybrid_open_with_context(&ct, &kp.secret_key, "mosslet/seal/v1").unwrap(),
            b"secret"
        );
    }

    #[test]
    fn new_suite_tampered_ciphertext_fails() {
        let kp = generate_hybrid_keypair_suite(Suite::HybridMatched, SecurityLevel::Cat5).unwrap();
        let ct = hybrid_seal_suite(
            b"data",
            &kp.public_key,
            Suite::HybridMatched,
            SecurityLevel::Cat5,
        )
        .unwrap();
        let mut raw = b64::decode(&ct).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF; // corrupt the GCM tag
        assert!(hybrid_open(&b64::encode(&raw), &kp.secret_key).is_err());
    }

    /// ML-KEM-1024 deterministic known-answer test (fixed seed + fixed coins).
    /// The `ml-kem` crate is validated against the NIST FIPS-203 KATs, so these
    /// pinned digests anchor byte-equality of the raw ML-KEM-1024 encapsulation
    /// key / ciphertext / shared secret with `@noble/post-quantum` (ml_kem1024)
    /// and any other FIPS-203 implementation, across Rust / WASM / NIF.
    #[test]
    fn mlkem1024_fips203_kat() {
        use crate::hash::sha3_512;
        fn hx(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        let seed = [0x07u8; MLKEM1024_SEED_LEN];
        let dk = DecapsulationKey::<MlKem1024>::from_seed(seed.into());
        let ek = dk.encapsulation_key();
        let ek_bytes = ek.to_bytes();
        assert_eq!(ek_bytes.len(), MLKEM1024_EK_LEN);
        assert_eq!(
            hx(&sha3_512(ek_bytes.as_slice())),
            "21d44f22f8467cde9040b3e6161c9353f9dd48e6854d3125c2690826a06ad707\
             8fa79245d715430afcca6bbd94a352e95081bd0b65aa210661f4deafdfc2fee4"
        );
        let coins = [0x09u8; 32];
        let (ct, ss) = ek.encapsulate_deterministic(&coins.into());
        assert_eq!(ct.as_slice().len(), MLKEM1024_CT_LEN);
        assert_eq!(
            hx(&sha3_512(ct.as_slice())),
            "79ca73f654930548ecedd30019fcd19f4ca6b653aef0bc647df8389945d04f81\
             47d5c45c8c8b93b679f3c15a4424c6c38c57e23d3383fd1e72964e98c1f19475"
        );
        assert_eq!(
            hx(ss.as_slice()),
            "a6b0741c68de147722d30abc60415c846f7130a51611c0de65cfe019cd9913f4"
        );
    }
}
