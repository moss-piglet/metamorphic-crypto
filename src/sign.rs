//! Hybrid post-quantum signatures: ML-DSA (FIPS 204) + Ed25519 composite.
//!
//! This module implements a *composite* digital signature: every message is
//! signed by **both** a post-quantum algorithm (ML-DSA, FIPS 204) **and** a
//! classical algorithm (Ed25519, RFC 8032), and verification requires **both**
//! component signatures to be valid (strict AND). An attacker therefore has to
//! break *both* a lattice scheme *and* an elliptic-curve scheme to forge a
//! signature, and cannot strip one algorithm off to downgrade the other
//! (signature-stripping / cross-protocol mix-and-match are rejected by the
//! length-framed, version-tagged wire format).
//!
//! It is the signing counterpart to this crate's hybrid KEM ([`crate::hybrid`]):
//! the KEM combines ML-KEM + X25519 for *confidentiality*, this combines
//! ML-DSA + Ed25519 for *authenticity / integrity*. It is the foundational
//! primitive for transparency logs and key-transparency work, where entries
//! must be signed once and verified byte-identically across native Rust, WASM,
//! and the Elixir NIF.
//!
//! ## Security levels
//!
//! ML-DSA is standardized by NIST at three parameter sets only — categories 2,
//! 3, and 5 — and each is paired here with Ed25519:
//!
//! | Level | ML-DSA   | NIST Category | Equivalent | Version Tag | Default |
//! |-------|----------|---------------|------------|-------------|---------|
//! | Cat-2 | ML-DSA-44| 2             | ~AES-128   | `0x01`      | No      |
//! | Cat-3 | ML-DSA-65| 3             | ~AES-192   | `0x02`      | Yes     |
//! | Cat-5 | ML-DSA-87| 5             | ~AES-256   | `0x03`      | No      |
//!
//! Cat-3 is the default, mirroring this crate's KEM default posture.
//!
//! ### About the version tags
//!
//! The version tag is a **per-artifact-type wire-format version**, *not* a
//! global NIST-category code. A signature tag only ever appears as the first
//! byte of a signature / key blob produced by this module, is parsed only by
//! [`verify`] / [`derive_public_key`], and is never handed to the KEM / seal
//! code. Signatures and ciphertexts are distinct artifacts processed by
//! distinct functions, so a signature tag can never be confused with a
//! sealed-box or hybrid-KEM byte — regardless of its value.
//!
//! By design these tags **agree with the KEM tags in [`crate::hybrid`] on every
//! level the two families share**: Cat-3 = `0x02` and Cat-5 = `0x03` in both.
//! The single divergence is at `0x01`, which here denotes Cat-2 (ML-DSA-44)
//! while on the KEM side `0x01` denotes Cat-1 (ML-KEM-512). This is unavoidable:
//! NIST standardizes ML-KEM at categories {1, 3, 5} but ML-DSA at {2, 3, 5}, so
//! the two families have different lowest rungs and "tag == category" cannot
//! hold for both.
//!
//! These bytes are **not legacy sentinels**, either. The pre-PQ `box_seal`
//! ciphertext format is *unversioned* — its first byte is a random ephemeral
//! public-key byte, not a reserved tag — so there is no `0x00`/`0x01` legacy
//! marker anywhere for these values to clash with.
//!
//! ## Signing mode (hedged / randomized ML-DSA)
//!
//! ML-DSA signatures are produced with the **hedged (randomized)** variant from
//! FIPS 204 — the standard's default and most conservative mode. Hedging mixes
//! fresh OS randomness into each signature, which (a) is resilient to RNG
//! failure (it still degrades gracefully toward the deterministic variant) and
//! (b) hardens lattice signing against fault and side-channel attacks that
//! deterministic signing is known to invite. Ed25519 is deterministic by design
//! (RFC 8032), which is the standard, audited behavior and is left unchanged.
//!
//! As a result the **signature bytes are not reproducible** (two signatures over
//! the same message differ) — but the **wire format is fully deterministic and
//! pinnable**: the layout, version tags, public-key derivation, and the
//! domain-separation framing are all fixed, so any client can reproduce keys and
//! verify signatures byte-identically.
//!
//! ## Domain separation (stable wire format — reproduce exactly)
//!
//! Both algorithms sign the *same* domain-separated message, framed **exactly**
//! like [`crate::hash::sha3_512_with_context`] (a length-prefixed context):
//!
//! ```text
//! signed_msg = I2OSP(len(context_utf8), 8) || context_utf8 || message
//! ```
//!
//! where `I2OSP(len, 8)` is the byte length of `context` (UTF-8) as a
//! **big-endian unsigned 64-bit integer**. Each algorithm signs `signed_msg`
//! directly: Ed25519 hashes it internally per RFC 8032; ML-DSA takes it as the
//! message with an **empty** native context string (the domain separation lives
//! entirely in `signed_msg`, so the framing is identical for both algorithms and
//! across every language binding). The 8-byte length prefix makes the
//! `(context, message)` boundary unambiguous. `context` is a UTF-8 label,
//! conventionally a versioned namespace — see [`SIGN_CONTEXT_V1`].
//!
//! ## Byte layout
//!
//! Ed25519 components are fixed-size and placed first, so the variable-length
//! ML-DSA tail needs no length prefix. `tag` is the 1-byte version tag above.
//!
//! ```text
//! signature  = tag || ed25519_sig (64 B) || ml_dsa_sig (2420 / 3309 / 4627 B)
//! public_key = tag || ed25519_pk  (32 B) || ml_dsa_pk  (1312 / 1952 / 2592 B)
//! secret_key = tag || ed25519_seed(32 B) || ml_dsa_seed(32 B)              = 65 B
//! ```
//!
//! Both algorithms are seeded from independent 32-byte seeds; the ML-DSA seed is
//! the FIPS 204 `Seed` (`ξ`), which is the canonical 32-byte signing-key
//! serialization across all three parameter sets.
//!
//! ## Encoding
//!
//! Native Rust takes raw bytes (`&[u8]`) and returns base64 strings for the
//! key/signature artifacts (consistent with [`crate::hybrid`]). The WASM
//! bindings (see [`crate::wasm`]) take and return base64 throughout. The Elixir
//! NIF mirrors the native bytes. Secret key material is zeroized on drop (see
//! [`HybridSignatureKeyPair`]).
//!
//! ## Dependency audit posture
//!
//! | Dependency      | Version | Audited            | Notes |
//! |-----------------|---------|--------------------|-------|
//! | `ed25519-dalek` | 2.x     | Yes (mature)       | Widely deployed RFC 8032 implementation. |
//! | `ml-dsa`        | 0.1.x   | **No** (RustCrypto)| FIPS 204 (final). New crate, not yet independently audited. Pinned; tracked for FIPS-mode roadmap. |
//!
//! ML-DSA support is provided as defense-in-depth on top of the mature,
//! independently-strong Ed25519 signature: even if a flaw were found in the
//! young `ml-dsa` implementation, the composite remains at least as strong as
//! Ed25519. This is called out honestly so integrators can make an informed
//! choice while the post-quantum implementation matures toward audit / FIPS
//! validation.

use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey, Verifier,
    VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::signature::{Keypair, Verifier as MlVerifier};
use ml_dsa::{
    B32, ExpandedSigningKey, KeyInit, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature,
    SigningKey, VerifyingKey,
};
use std::convert::Infallible;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;
use crate::b64;

// === Constants ===

/// Recommended versioned context label for general-purpose signing.
///
/// Pass this (or another versioned `"namespace/purpose/vN"` label) as the
/// `context` argument to [`sign`] / [`verify`] to bind signatures to a purpose.
pub const SIGN_CONTEXT_V1: &str = "metamorphic/sign/v1";

/// Version tag for Cat-2 (ML-DSA-44 + Ed25519). Local to this module.
const VERSION_CAT2: u8 = 0x01;
/// Version tag for Cat-3 (ML-DSA-65 + Ed25519, default). Local to this module.
const VERSION_CAT3: u8 = 0x02;
/// Version tag for Cat-5 (ML-DSA-87 + Ed25519). Local to this module.
const VERSION_CAT5: u8 = 0x03;

/// Ed25519 seed (secret key) length.
const ED25519_SEED_LEN: usize = 32;
/// Ed25519 public key length.
const ED25519_PK_LEN: usize = 32;
/// Ed25519 signature length.
const ED25519_SIG_LEN: usize = 64;
/// ML-DSA seed (`ξ`) length — identical across all parameter sets.
const MLDSA_SEED_LEN: usize = 32;

/// Combined secret key length: `tag || ed25519_seed || ml_dsa_seed`.
const SECRET_KEY_LEN: usize = 1 + ED25519_SEED_LEN + MLDSA_SEED_LEN;

// ML-DSA-44 (Cat-2)
/// ML-DSA-44 public key length.
const MLDSA44_PK_LEN: usize = 1312;
/// ML-DSA-44 signature length.
const MLDSA44_SIG_LEN: usize = 2420;
// ML-DSA-65 (Cat-3)
/// ML-DSA-65 public key length.
const MLDSA65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature length.
const MLDSA65_SIG_LEN: usize = 3309;
// ML-DSA-87 (Cat-5)
/// ML-DSA-87 public key length.
const MLDSA87_PK_LEN: usize = 2592;
/// ML-DSA-87 signature length.
const MLDSA87_SIG_LEN: usize = 4627;

// === Types ===

/// A hybrid ML-DSA + Ed25519 signing keypair (base64-encoded).
///
/// The `secret_key` is zeroized on drop. Both fields are base64 strings using
/// the byte layout documented at the [module level](crate::sign).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSignatureKeyPair {
    /// Combined public key: `tag || ed25519_pk || ml_dsa_pk`. Base64. Public.
    #[zeroize(skip)]
    pub public_key: String,
    /// Combined secret key: `tag || ed25519_seed || ml_dsa_seed`. Base64. Secret.
    pub secret_key: String,
}

impl std::fmt::Debug for HybridSignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSignatureKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// Security level for hybrid PQ signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureLevel {
    /// NIST Category 2: ML-DSA-44 + Ed25519 (~AES-128).
    Cat2,
    /// NIST Category 3: ML-DSA-65 + Ed25519 (~AES-192). Default.
    #[default]
    Cat3,
    /// NIST Category 5: ML-DSA-87 + Ed25519 (~AES-256).
    Cat5,
}

impl SignatureLevel {
    /// The 1-byte version tag for this level.
    fn version_tag(self) -> u8 {
        match self {
            SignatureLevel::Cat2 => VERSION_CAT2,
            SignatureLevel::Cat3 => VERSION_CAT3,
            SignatureLevel::Cat5 => VERSION_CAT5,
        }
    }

    /// The ML-DSA public-key length for this level.
    fn mldsa_pk_len(self) -> usize {
        match self {
            SignatureLevel::Cat2 => MLDSA44_PK_LEN,
            SignatureLevel::Cat3 => MLDSA65_PK_LEN,
            SignatureLevel::Cat5 => MLDSA87_PK_LEN,
        }
    }

    /// The ML-DSA signature length for this level.
    fn mldsa_sig_len(self) -> usize {
        match self {
            SignatureLevel::Cat2 => MLDSA44_SIG_LEN,
            SignatureLevel::Cat3 => MLDSA65_SIG_LEN,
            SignatureLevel::Cat5 => MLDSA87_SIG_LEN,
        }
    }
}

// === Helpers ===

/// Fill buffer with OS random bytes.
#[inline]
fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// An infallible, OS-backed CSPRNG adapter for `ml-dsa`'s randomized signer.
///
/// `ml-dsa`'s hedged signing path is generic over a `rand_core` RNG. This thin
/// adapter sources every byte from the OS CSPRNG via [`getrandom`], exactly like
/// the rest of this crate, so no userspace PRNG is introduced.
struct OsCsprng;

impl TryRng for OsCsprng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        random_bytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        random_bytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        random_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for OsCsprng {}

/// Build the domain-separated message: `u64_be(len(context)) || context || message`.
fn frame(context: &str, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len() + message.len());
    out.extend_from_slice(&(context.len() as u64).to_be_bytes());
    out.extend_from_slice(context.as_bytes());
    out.extend_from_slice(message);
    out
}

/// Map a leading version-tag byte to a [`SignatureLevel`].
fn level_from_tag(tag: Option<&u8>) -> Result<SignatureLevel, CryptoError> {
    match tag {
        Some(&VERSION_CAT2) => Ok(SignatureLevel::Cat2),
        Some(&VERSION_CAT3) => Ok(SignatureLevel::Cat3),
        Some(&VERSION_CAT5) => Ok(SignatureLevel::Cat5),
        _ => Err(CryptoError::Signature(
            "unknown or missing signature version tag".into(),
        )),
    }
}

/// Derive the ML-DSA public key bytes from a 32-byte seed.
fn mldsa_public_key<P: MlDsaParams>(seed: &B32) -> Vec<u8> {
    let vk = SigningKey::<P>::from_seed(seed).verifying_key().encode();
    AsRef::<[u8]>::as_ref(&vk).to_vec()
}

/// Produce a hedged (randomized) ML-DSA signature over `framed` (empty native ctx).
fn mldsa_sign<P: MlDsaParams>(seed: &B32, framed: &[u8]) -> Vec<u8> {
    let sig = ExpandedSigningKey::<P>::from_seed(seed)
        .sign_randomized(framed, &[], &mut OsCsprng)
        .expect("ML-DSA randomized signing (empty context, infallible RNG)")
        .encode();
    AsRef::<[u8]>::as_ref(&sig).to_vec()
}

/// Verify an ML-DSA signature; returns `false` on any malformed input.
fn mldsa_verify<P: MlDsaParams>(pk: &[u8], framed: &[u8], sig: &[u8]) -> bool {
    match (
        VerifyingKey::<P>::new_from_slice(pk),
        Signature::<P>::try_from(sig),
    ) {
        (Ok(vk), Ok(s)) => MlVerifier::verify(&vk, framed, &s).is_ok(),
        _ => false,
    }
}

// === Public API: keygen ===

/// Generate a hybrid ML-DSA-65 + Ed25519 signing keypair (Cat-3, default).
pub fn generate_signing_keypair() -> HybridSignatureKeyPair {
    generate_signing_keypair_with_level(SignatureLevel::Cat3)
}

/// Generate a hybrid ML-DSA-44 + Ed25519 signing keypair (Cat-2).
pub fn generate_signing_keypair_44() -> HybridSignatureKeyPair {
    generate_signing_keypair_with_level(SignatureLevel::Cat2)
}

/// Generate a hybrid ML-DSA-87 + Ed25519 signing keypair (Cat-5).
pub fn generate_signing_keypair_87() -> HybridSignatureKeyPair {
    generate_signing_keypair_with_level(SignatureLevel::Cat5)
}

/// Generate a hybrid signing keypair at the specified security level.
///
/// Returns base64 `public_key` and `secret_key` using the documented byte
/// layout. The two algorithms are seeded from independent OS randomness.
pub fn generate_signing_keypair_with_level(level: SignatureLevel) -> HybridSignatureKeyPair {
    let mut ed_seed = [0u8; ED25519_SEED_LEN];
    random_bytes(&mut ed_seed);
    let mut ml_seed_bytes = [0u8; MLDSA_SEED_LEN];
    random_bytes(&mut ml_seed_bytes);

    let ed_sk = EdSigningKey::from_bytes(&ed_seed);
    let ed_pk = ed_sk.verifying_key().to_bytes();

    let ml_seed: B32 = ml_seed_bytes.into();
    let ml_pk = match level {
        SignatureLevel::Cat2 => mldsa_public_key::<MlDsa44>(&ml_seed),
        SignatureLevel::Cat3 => mldsa_public_key::<MlDsa65>(&ml_seed),
        SignatureLevel::Cat5 => mldsa_public_key::<MlDsa87>(&ml_seed),
    };

    let tag = level.version_tag();

    let mut public_key = Vec::with_capacity(1 + ED25519_PK_LEN + ml_pk.len());
    public_key.push(tag);
    public_key.extend_from_slice(&ed_pk);
    public_key.extend_from_slice(&ml_pk);

    let mut secret_key = Vec::with_capacity(SECRET_KEY_LEN);
    secret_key.push(tag);
    secret_key.extend_from_slice(&ed_seed);
    secret_key.extend_from_slice(&ml_seed_bytes);

    let pair = HybridSignatureKeyPair {
        public_key: b64::encode(&public_key),
        secret_key: b64::encode(&secret_key),
    };

    ed_seed.zeroize();
    ml_seed_bytes.zeroize();
    secret_key.zeroize();
    pair
}

// === Public API: sign / verify ===

/// Re-derive the base64 public key from a base64 hybrid secret key.
///
/// Both component public keys are a deterministic function of the secret seeds,
/// so this reproduces exactly the `public_key` returned by keygen. Useful for
/// recovering a public key from a backed-up secret, or for verifying that a
/// secret/public pair belong together. The security level is read from the
/// secret key's version tag.
pub fn derive_public_key(secret_key_b64: &str) -> Result<String, CryptoError> {
    let mut sk_bytes = b64::decode(secret_key_b64)?;
    let level = level_from_tag(sk_bytes.first())?;

    if sk_bytes.len() != SECRET_KEY_LEN {
        sk_bytes.zeroize();
        return Err(CryptoError::InvalidLength {
            expected: SECRET_KEY_LEN,
            got: sk_bytes.len(),
        });
    }

    let mut ed_seed = [0u8; ED25519_SEED_LEN];
    ed_seed.copy_from_slice(&sk_bytes[1..1 + ED25519_SEED_LEN]);
    let mut ml_seed_bytes = [0u8; MLDSA_SEED_LEN];
    ml_seed_bytes.copy_from_slice(&sk_bytes[1 + ED25519_SEED_LEN..SECRET_KEY_LEN]);
    sk_bytes.zeroize();

    let ed_pk = EdSigningKey::from_bytes(&ed_seed)
        .verifying_key()
        .to_bytes();
    ed_seed.zeroize();

    let ml_seed: B32 = ml_seed_bytes.into();
    let ml_pk = match level {
        SignatureLevel::Cat2 => mldsa_public_key::<MlDsa44>(&ml_seed),
        SignatureLevel::Cat3 => mldsa_public_key::<MlDsa65>(&ml_seed),
        SignatureLevel::Cat5 => mldsa_public_key::<MlDsa87>(&ml_seed),
    };
    ml_seed_bytes.zeroize();

    let mut public_key = Vec::with_capacity(1 + ED25519_PK_LEN + ml_pk.len());
    public_key.push(level.version_tag());
    public_key.extend_from_slice(&ed_pk);
    public_key.extend_from_slice(&ml_pk);

    Ok(b64::encode(&public_key))
}
/// Sign `message` under `context` with a base64 hybrid `secret_key`.
///
/// Produces a composite signature: a hedged (randomized) ML-DSA signature and a
/// deterministic Ed25519 signature, both over the domain-separated
/// `frame(context, message)`. The security level is read from the secret key's
/// version tag. Returns the base64 signature `tag || ed25519_sig || ml_dsa_sig`.
///
/// Because ML-DSA signing is randomized, signing the same message twice yields
/// different (both-valid) signatures. Use [`SIGN_CONTEXT_V1`] (or another
/// versioned label) for `context`.
pub fn sign(message: &[u8], context: &str, secret_key_b64: &str) -> Result<String, CryptoError> {
    let mut sk_bytes = b64::decode(secret_key_b64)?;
    let level = level_from_tag(sk_bytes.first())?;

    if sk_bytes.len() != SECRET_KEY_LEN {
        sk_bytes.zeroize();
        return Err(CryptoError::InvalidLength {
            expected: SECRET_KEY_LEN,
            got: sk_bytes.len(),
        });
    }

    let mut ed_seed = [0u8; ED25519_SEED_LEN];
    ed_seed.copy_from_slice(&sk_bytes[1..1 + ED25519_SEED_LEN]);
    let mut ml_seed_bytes = [0u8; MLDSA_SEED_LEN];
    ml_seed_bytes.copy_from_slice(&sk_bytes[1 + ED25519_SEED_LEN..SECRET_KEY_LEN]);
    sk_bytes.zeroize();

    let framed = frame(context, message);

    let ed_sk = EdSigningKey::from_bytes(&ed_seed);
    let ed_sig = ed_sk.sign(&framed).to_bytes();
    ed_seed.zeroize();

    let ml_seed: B32 = ml_seed_bytes.into();
    let ml_sig = match level {
        SignatureLevel::Cat2 => mldsa_sign::<MlDsa44>(&ml_seed, &framed),
        SignatureLevel::Cat3 => mldsa_sign::<MlDsa65>(&ml_seed, &framed),
        SignatureLevel::Cat5 => mldsa_sign::<MlDsa87>(&ml_seed, &framed),
    };
    ml_seed_bytes.zeroize();

    let mut out = Vec::with_capacity(1 + ED25519_SIG_LEN + ml_sig.len());
    out.push(level.version_tag());
    out.extend_from_slice(&ed_sig);
    out.extend_from_slice(&ml_sig);

    Ok(b64::encode(&out))
}

/// Verify a composite `signature_b64` over `message`/`context` against `public_key_b64`.
///
/// Returns `Ok(true)` **only if both** the Ed25519 and ML-DSA component
/// signatures verify (strict AND). Returns `Ok(false)` for any cryptographic
/// failure, including a tampered message/context, a wrong key, a tampered
/// half-signature, or a signature/public-key whose version tags or lengths do
/// not match (cross-level or stripped). Returns `Err` only when an input cannot
/// be decoded as base64 or carries an unknown version tag.
pub fn verify(
    message: &[u8],
    context: &str,
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<bool, CryptoError> {
    let sig = b64::decode(signature_b64)?;
    let pk = b64::decode(public_key_b64)?;

    let sig_level = level_from_tag(sig.first())?;
    let pk_level = level_from_tag(pk.first())?;
    // Mismatched levels => verification fails (no cross-level confusion).
    if sig_level != pk_level {
        return Ok(false);
    }
    let level = sig_level;

    if sig.len() != 1 + ED25519_SIG_LEN + level.mldsa_sig_len()
        || pk.len() != 1 + ED25519_PK_LEN + level.mldsa_pk_len()
    {
        return Ok(false);
    }

    let framed = frame(context, message);

    let ed_pk_bytes: [u8; ED25519_PK_LEN] = pk[1..1 + ED25519_PK_LEN].try_into().unwrap();
    let ed_sig_bytes: [u8; ED25519_SIG_LEN] = sig[1..1 + ED25519_SIG_LEN].try_into().unwrap();
    let ml_pk = &pk[1 + ED25519_PK_LEN..];
    let ml_sig = &sig[1 + ED25519_SIG_LEN..];

    let ed_ok = match EdVerifyingKey::from_bytes(&ed_pk_bytes) {
        Ok(vk) => vk
            .verify(&framed, &EdSignature::from_bytes(&ed_sig_bytes))
            .is_ok(),
        Err(_) => false,
    };

    let ml_ok = match level {
        SignatureLevel::Cat2 => mldsa_verify::<MlDsa44>(ml_pk, &framed, ml_sig),
        SignatureLevel::Cat3 => mldsa_verify::<MlDsa65>(ml_pk, &framed, ml_sig),
        SignatureLevel::Cat5 => mldsa_verify::<MlDsa87>(ml_pk, &framed, ml_sig),
    };

    // Strict AND: both component signatures must verify.
    Ok(ed_ok && ml_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(level: SignatureLevel) {
        let kp = generate_signing_keypair_with_level(level);
        let sig = sign(b"hello transparency log", SIGN_CONTEXT_V1, &kp.secret_key).unwrap();
        assert!(
            verify(
                b"hello transparency log",
                SIGN_CONTEXT_V1,
                &sig,
                &kp.public_key
            )
            .unwrap()
        );
    }

    #[test]
    fn cat2_roundtrip() {
        roundtrip(SignatureLevel::Cat2);
    }

    #[test]
    fn cat3_roundtrip() {
        roundtrip(SignatureLevel::Cat3);
    }

    #[test]
    fn cat5_roundtrip() {
        roundtrip(SignatureLevel::Cat5);
    }

    #[test]
    fn default_is_cat3() {
        assert_eq!(SignatureLevel::default(), SignatureLevel::Cat3);
        let kp = generate_signing_keypair();
        let raw = b64::decode(&kp.public_key).unwrap();
        assert_eq!(raw[0], VERSION_CAT3);
    }

    #[test]
    fn version_tags() {
        for (level, tag) in [
            (SignatureLevel::Cat2, VERSION_CAT2),
            (SignatureLevel::Cat3, VERSION_CAT3),
            (SignatureLevel::Cat5, VERSION_CAT5),
        ] {
            let kp = generate_signing_keypair_with_level(level);
            let sig = sign(b"x", SIGN_CONTEXT_V1, &kp.secret_key).unwrap();
            assert_eq!(b64::decode(&kp.public_key).unwrap()[0], tag);
            assert_eq!(b64::decode(&kp.secret_key).unwrap()[0], tag);
            assert_eq!(b64::decode(&sig).unwrap()[0], tag);
        }
    }

    #[test]
    fn key_and_signature_sizes() {
        for (level, pk_len, sig_len) in [
            (SignatureLevel::Cat2, MLDSA44_PK_LEN, MLDSA44_SIG_LEN),
            (SignatureLevel::Cat3, MLDSA65_PK_LEN, MLDSA65_SIG_LEN),
            (SignatureLevel::Cat5, MLDSA87_PK_LEN, MLDSA87_SIG_LEN),
        ] {
            let kp = generate_signing_keypair_with_level(level);
            let pk = b64::decode(&kp.public_key).unwrap();
            let sk = b64::decode(&kp.secret_key).unwrap();
            let sig = b64::decode(&sign(b"x", SIGN_CONTEXT_V1, &kp.secret_key).unwrap()).unwrap();
            assert_eq!(pk.len(), 1 + ED25519_PK_LEN + pk_len);
            assert_eq!(sk.len(), SECRET_KEY_LEN);
            assert_eq!(sig.len(), 1 + ED25519_SIG_LEN + sig_len);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = generate_signing_keypair();
        let kp2 = generate_signing_keypair();
        let sig = sign(b"msg", SIGN_CONTEXT_V1, &kp1.secret_key).unwrap();
        assert!(!verify(b"msg", SIGN_CONTEXT_V1, &sig, &kp2.public_key).unwrap());
    }

    #[test]
    fn tampered_message_fails() {
        let kp = generate_signing_keypair();
        let sig = sign(b"original", SIGN_CONTEXT_V1, &kp.secret_key).unwrap();
        assert!(!verify(b"tampered", SIGN_CONTEXT_V1, &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn context_separation() {
        let kp = generate_signing_keypair();
        let sig = sign(b"msg", "metamorphic/sign/v1", &kp.secret_key).unwrap();
        // Same message, different verification context => fails.
        assert!(!verify(b"msg", "metamorphic/other/v1", &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn empty_message_and_context() {
        let kp = generate_signing_keypair();
        let sig = sign(b"", "", &kp.secret_key).unwrap();
        assert!(verify(b"", "", &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn nondeterministic_but_both_valid() {
        let kp = generate_signing_keypair();
        let s1 = sign(b"msg", SIGN_CONTEXT_V1, &kp.secret_key).unwrap();
        let s2 = sign(b"msg", SIGN_CONTEXT_V1, &kp.secret_key).unwrap();
        // Hedged ML-DSA => signatures differ, but both verify.
        assert_ne!(s1, s2);
        assert!(verify(b"msg", SIGN_CONTEXT_V1, &s1, &kp.public_key).unwrap());
        assert!(verify(b"msg", SIGN_CONTEXT_V1, &s2, &kp.public_key).unwrap());
    }

    /// Strict AND: tampering with *either* component signature must fail
    /// verification, proving neither algorithm can be stripped or forged alone.
    #[test]
    fn strict_and_requires_both() {
        let kp = generate_signing_keypair();
        let good = b64::decode(&sign(b"msg", SIGN_CONTEXT_V1, &kp.secret_key).unwrap()).unwrap();

        // Corrupt a byte inside the Ed25519 component (ML-DSA still valid).
        let mut bad_ed = good.clone();
        bad_ed[1] ^= 0xFF;
        assert!(
            !verify(
                b"msg",
                SIGN_CONTEXT_V1,
                &b64::encode(&bad_ed),
                &kp.public_key
            )
            .unwrap()
        );

        // Corrupt a byte inside the ML-DSA component (Ed25519 still valid).
        let mut bad_ml = good.clone();
        let i = 1 + ED25519_SIG_LEN + 10;
        bad_ml[i] ^= 0xFF;
        assert!(
            !verify(
                b"msg",
                SIGN_CONTEXT_V1,
                &b64::encode(&bad_ml),
                &kp.public_key
            )
            .unwrap()
        );
    }

    #[test]
    fn cross_level_fails() {
        let kp3 = generate_signing_keypair_with_level(SignatureLevel::Cat3);
        let kp5 = generate_signing_keypair_with_level(SignatureLevel::Cat5);
        let sig3 = sign(b"msg", SIGN_CONTEXT_V1, &kp3.secret_key).unwrap();
        // Cat-3 signature against a Cat-5 public key => fails (tag mismatch).
        assert!(!verify(b"msg", SIGN_CONTEXT_V1, &sig3, &kp5.public_key).unwrap());
    }

    #[test]
    fn unknown_tag_errors() {
        let bad = b64::encode(&[0x09u8; SECRET_KEY_LEN]);
        assert!(sign(b"x", SIGN_CONTEXT_V1, &bad).is_err());
        let pk = b64::encode(&[0x09u8; 100]);
        let sig = b64::encode(&[0x09u8; 100]);
        assert!(verify(b"x", SIGN_CONTEXT_V1, &sig, &pk).is_err());
    }

    #[test]
    fn bad_base64_errors() {
        assert!(sign(b"x", SIGN_CONTEXT_V1, "not!base64!").is_err());
        assert!(verify(b"x", SIGN_CONTEXT_V1, "not!base64!", "also!bad!").is_err());
    }

    #[test]
    fn frame_matches_manual() {
        let ctx = "metamorphic/sign/v1";
        let msg = b"payload";
        let mut expected = Vec::new();
        expected.extend_from_slice(&(ctx.len() as u64).to_be_bytes());
        expected.extend_from_slice(ctx.as_bytes());
        expected.extend_from_slice(msg);
        assert_eq!(frame(ctx, msg), expected);
    }

    #[test]
    fn frame_no_boundary_confusion() {
        assert_ne!(frame("ab", b"c"), frame("a", b"bc"));
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let kp = generate_signing_keypair();
        let shown = format!("{kp:?}");
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains(&kp.secret_key));
    }

    #[test]
    fn keygen_public_key_matches_derived() {
        for level in [
            SignatureLevel::Cat2,
            SignatureLevel::Cat3,
            SignatureLevel::Cat5,
        ] {
            let kp = generate_signing_keypair_with_level(level);
            assert_eq!(derive_public_key(&kp.secret_key).unwrap(), kp.public_key);
        }
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_arbitrary_message(msg: Vec<u8>, ctx in "[a-z/]{0,32}") {
            let kp = generate_signing_keypair();
            let sig = sign(&msg, &ctx, &kp.secret_key).unwrap();
            prop_assert!(verify(&msg, &ctx, &sig, &kp.public_key).unwrap());
        }
    }
}
