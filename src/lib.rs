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
//! | Format | Layout |
//! |--------|--------|
//! | Secretbox | `nonce (24B) \|\| ciphertext (len + 16B MAC)` |
//! | box_seal | `ephemeral_pk (32B) \|\| box ciphertext` |
//! | Hybrid v1 (Cat-1) | `0x01 \|\| ML-KEM-512 ct (768B) \|\| X25519 eph pk (32B) \|\| nonce (24B) \|\| secretbox ct` |
//! | Hybrid v2 (Cat-3) | `0x02 \|\| ML-KEM-768 ct (1088B) \|\| X25519 eph pk (32B) \|\| nonce (24B) \|\| secretbox ct` |
//! | Hybrid v3 (Cat-5) | `0x03 \|\| ML-KEM-1024 ct (1568B) \|\| X25519 eph pk (32B) \|\| nonce (24B) \|\| secretbox ct` |
//!
//! ## Signature format
//!
//! Composite ML-DSA + Ed25519 signatures (see [`sign`]); strict-AND verification.
//!
//! | Component  | Layout |
//! |------------|--------|
//! | signature  | `tag \|\| ed25519_sig (64B) \|\| ml_dsa_sig` |
//! | public_key | `tag \|\| ed25519_pk (32B) \|\| ml_dsa_pk` |
//! | secret_key | `tag \|\| ed25519_seed (32B) \|\| ml_dsa_seed (32B)` |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod b64;
pub mod box_seal;
pub mod error;
pub mod hash;
pub mod hybrid;
pub mod kdf;
pub mod keys;
pub mod recovery;
pub mod seal;
pub mod secretbox;
pub mod sign;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::CryptoError;

// Re-export the primary public API
pub use b64::parse_salt_from_key_hash;
pub use box_seal::{box_seal, box_seal_open};
pub use hash::{sha3_256, sha3_512, sha3_512_with_context, sha256, sha512};
pub use hybrid::{
    HybridKeyPair, SecurityLevel, generate_hybrid_keypair, generate_hybrid_keypair_512,
    generate_hybrid_keypair_1024, generate_hybrid_keypair_with_level, hybrid_open, hybrid_seal,
    hybrid_seal_512, hybrid_seal_1024, hybrid_seal_with_level, is_hybrid_ciphertext,
};
pub use kdf::derive_session_key;
pub use keys::{
    KeyPair, decrypt_private_key, encrypt_private_key, generate_key, generate_keypair,
    generate_salt,
};
pub use recovery::{
    RecoveryKey, decrypt_private_key_with_recovery, encrypt_private_key_for_recovery,
    generate_recovery_key, recovery_key_to_secret,
};
pub use seal::{seal_for_user, seal_for_user_with_level, unseal_from_user};
pub use secretbox::{
    decrypt_secretbox, decrypt_secretbox_to_string, encrypt_secretbox, encrypt_secretbox_string,
};
pub use sign::{
    HybridSignatureKeyPair, SIGN_CONTEXT_V1, SignatureLevel, derive_public_key,
    generate_signing_keypair, generate_signing_keypair_44, generate_signing_keypair_87,
    generate_signing_keypair_with_level, sign, verify,
};
