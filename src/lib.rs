//! # metamorphic-crypto
//!
//! Zero-knowledge end-to-end encryption core for the Metamorphic platform.
//!
//! This library implements the cryptographic operations required by all Metamorphic
//! clients (web/WASM, iOS/UniFFI, Android/UniFFI). It produces byte-compatible
//! ciphertext with the existing JavaScript implementation so that data encrypted
//! by one client can be decrypted by any other.
//!
//! ## Security guarantees
//!
//! - All secret key material is [`Zeroize`]-on-drop
//! - No `unsafe` code
//! - Constant-time comparisons via the underlying RustCrypto crates
//! - Randomness sourced directly from the OS CSPRNG ([`getrandom`])
//!
//! ## Ciphertext formats
//!
//! The legacy `Suite::Hybrid` (default) formats are byte-for-byte unchanged. The
//! opt-in CNSA 2.0 suites use an AES-256-GCM envelope keyed by
//! `HKDF-SHA512(info = suite_tag || context_label)` (see [`suite`]); the
//! `nonce (12B) || ct || gcm_tag (16B)` portion is the AEAD output.
//!
//! | Format | Layout |
//! |--------|--------|
//! | Secretbox | `nonce (24B) \|\| ciphertext (len + 16B MAC)` |
//! | box_seal | `ephemeral_pk (32B) \|\| box ciphertext` |
//! | Hybrid v1 (Cat-1) | `0x01 \|\| ML-KEM-512 ct (768B) \|\| X25519 eph pk (32B) \|\| nonce (24B) \|\| secretbox ct` |
//! | Hybrid v2 (Cat-3) | `0x02 \|\| ML-KEM-768 ct (1088B) \|\| X25519 eph pk (32B) \|\| nonce (24B) \|\| secretbox ct` |
//! | Hybrid v3 (Cat-5) | `0x03 \|\| ML-KEM-1024 ct (1568B) \|\| X25519 eph pk (32B) \|\| nonce (24B) \|\| secretbox ct` |
//! | PureCnsa2 (Cat-5) | `0x10 \|\| ML-KEM-1024 ct (1568B) \|\| nonce (12B) \|\| ct \|\| gcm_tag (16B)` |
//! | HybridMatched (Cat-3) | `0x13 \|\| ML-KEM-768 ct (1088B) \|\| X448 eph pk (56B) \|\| nonce (12B) \|\| ct \|\| gcm_tag (16B)` |
//! | HybridMatched (Cat-5) | `0x14 \|\| ML-KEM-1024 ct (1568B) \|\| P-521 eph pk (133B) \|\| nonce (12B) \|\| ct \|\| gcm_tag (16B)` |
//!
//! ## Signature formats
//!
//! The default `Suite::Hybrid` is a composite ML-DSA + Ed25519 signature with
//! strict-AND verification. The opt-in CNSA 2.0 suites place the fixed-size
//! classical component first (so the variable ML-DSA tail needs no length
//! prefix) and reuse the same I2OSP domain-separation framing. `PureCnsa2` has
//! no classical component. All are strict-AND verified.
//!
//! | Suite (level) | signature | public_key | secret_key |
//! |---------------|-----------|------------|------------|
//! | Hybrid (Cat-2/3/5) | `tag \|\| ed25519_sig (64B) \|\| ml_dsa_sig` | `tag \|\| ed25519_pk (32B) \|\| ml_dsa_pk` | `tag \|\| ed25519_seed (32B) \|\| ml_dsa_seed (32B)` |
//! | HybridMatched (Cat-3) | `0x13 \|\| ed448_sig (114B) \|\| ml_dsa65_sig` | `0x13 \|\| ed448_pk (57B) \|\| ml_dsa65_pk` | `0x13 \|\| ed448_seed (57B) \|\| ml_dsa_seed (32B)` |
//! | HybridMatched (Cat-5) | `0x14 \|\| ecdsa_p521_sig (132B) \|\| ml_dsa87_sig` | `0x14 \|\| p521_pk (133B) \|\| ml_dsa87_pk` | `0x14 \|\| p521_seed (66B) \|\| ml_dsa_seed (32B)` |
//! | PureCnsa2 (Cat-5) | `0x10 \|\| ml_dsa87_sig` | `0x10 \|\| ml_dsa87_pk` | `0x10 \|\| ml_dsa_seed (32B)` |
//!
//! Separately, the [`ed25519`] module exposes **bare RFC 8032 Ed25519**
//! (sign/verify, no framing, no PQ component). It exists *only* for byte-level
//! interoperability with the deployed C2SP transparency-log witness ecosystem
//! (Go `sumdb/note`, sigsum, transparency-dev, Tessera), which co-signs
//! checkpoints with raw Ed25519. It is **not** a general-purpose signing API —
//! use the hybrid PQ [`sign`] for Metamorphic authenticity.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod b64;
pub mod box_seal;
mod ecc;
pub mod ed25519;
pub mod error;
pub mod hash;
pub mod hkdf;
pub mod hybrid;
pub mod kdf;
pub mod keys;
pub mod mac;
pub mod mldsa;
pub mod recovery;
pub mod seal;
pub mod secretbox;
pub mod sign;
#[cfg(not(target_arch = "wasm32"))]
pub mod stack;
pub mod suite;
pub mod vrf;
pub mod vrf_p256;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::CryptoError;

// Re-export the primary public API
pub use b64::parse_salt_from_key_hash;
pub use box_seal::{box_seal, box_seal_open};
pub use ed25519::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SEED_LEN, ED25519_SIGNATURE_LEN, ed25519_generate_keypair,
    ed25519_public_key, ed25519_sign, ed25519_verify,
};
pub use hash::{sha3_256, sha3_512, sha3_512_with_context, sha256, sha512};
pub use hkdf::{HASH_LEN as HKDF_SHA512_HASH_LEN, hkdf_sha512};
pub use hybrid::{
    HybridKeyPair, SecurityLevel, generate_hybrid_keypair, generate_hybrid_keypair_512,
    generate_hybrid_keypair_1024, generate_hybrid_keypair_suite,
    generate_hybrid_keypair_with_level, hybrid_open, hybrid_open_with_context, hybrid_seal,
    hybrid_seal_512, hybrid_seal_1024, hybrid_seal_suite, hybrid_seal_suite_with_context,
    hybrid_seal_with_level, is_hybrid_ciphertext,
};
pub use kdf::derive_session_key;
pub use keys::{
    KeyPair, decrypt_private_key, encrypt_private_key, generate_key, generate_keypair,
    generate_salt,
};
pub use mac::{HMAC_SHA256_LEN, hmac_sha256};
pub use mldsa::{
    MLDSA44_PUBLIC_KEY_LEN, MLDSA44_SEED_LEN, MLDSA44_SIGNATURE_LEN, ml_dsa_44_generate_keypair,
    ml_dsa_44_public_key, ml_dsa_44_sign, ml_dsa_44_verify,
};
pub use recovery::{
    RecoveryKey, decrypt_private_key_with_recovery, encrypt_private_key_for_recovery,
    generate_recovery_key, recovery_key_to_secret,
};
pub use seal::{
    seal_for_user, seal_for_user_with_level, seal_for_user_with_suite, unseal_from_user,
};
pub use secretbox::{
    decrypt_secretbox, decrypt_secretbox_to_string, encrypt_secretbox, encrypt_secretbox_string,
};
pub use sign::{
    HybridSignatureKeyPair, SIGN_CONTEXT_V1, SignatureLevel, derive_public_key,
    generate_signing_keypair, generate_signing_keypair_44, generate_signing_keypair_87,
    generate_signing_keypair_suite, generate_signing_keypair_with_level, sign, signature_posture,
    signature_posture_from_signature, verify,
};
#[cfg(not(target_arch = "wasm32"))]
pub use stack::{RECOMMENDED_SIGNING_STACK_BYTES, on_signing_stack};
pub use suite::{SEAL_CONTEXT_V1, Suite};
pub use vrf::{
    ECVRF_EDWARDS25519_SHA512_TAI_SUITE, ECVRF_OUTPUT_LEN, ECVRF_PROOF_LEN, ECVRF_PUBLIC_KEY_LEN,
    ECVRF_SECRET_KEY_LEN, ecvrf_generate_keypair, ecvrf_proof_to_hash, ecvrf_prove,
    ecvrf_public_key, ecvrf_verify,
};
pub use vrf_p256::{
    ECVRF_P256_OUTPUT_LEN, ECVRF_P256_PROOF_LEN, ECVRF_P256_PUBLIC_KEY_LEN,
    ECVRF_P256_SECRET_KEY_LEN, ECVRF_P256_SHA256_TAI_SUITE, ecvrf_p256_generate_keypair,
    ecvrf_p256_proof_to_hash, ecvrf_p256_prove, ecvrf_p256_public_key, ecvrf_p256_verify,
};
