//! Error types for the crypto library.

use thiserror::Error;

/// All possible errors from cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Base64 decoding failed.
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Decryption failed (wrong key, corrupted ciphertext, or MAC mismatch).
    #[error("decryption failed: invalid ciphertext or wrong key")]
    Decryption,

    /// A key or salt has the wrong byte length.
    #[error("invalid length: expected {expected} bytes, got {got}")]
    InvalidLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        got: usize,
    },

    /// Ciphertext is too short to contain the expected components.
    #[error("ciphertext too short to be valid")]
    TooShort,

    /// The key_hash string is not in the expected `{salt}$argon2id` format.
    #[error("invalid key_hash format (expected `salt$argon2id`)")]
    InvalidKeyHash,

    /// A recovery key contains characters outside the allowed base32 alphabet.
    #[error("invalid recovery key character")]
    InvalidRecoveryKey,

    /// The Argon2id key derivation failed.
    #[error("key derivation failed: {0}")]
    Kdf(String),

    /// An HKDF (RFC 5869) extract/expand operation failed — in practice only
    /// when the requested output length exceeds `255 * HashLen`.
    #[error("hkdf: {0}")]
    Hkdf(String),

    /// An error in the hybrid PQ KEM layer.
    #[error("hybrid KEM: {0}")]
    Hybrid(String),

    /// An error in the hybrid PQ signature layer.
    #[error("signature: {0}")]
    Signature(String),

    /// An error in the verifiable random function (ECVRF) layer that is not a
    /// plain length mismatch — e.g. a proof component that is not a valid curve
    /// point, or hash-to-curve exhausting its counter budget. A *verification*
    /// failure of an otherwise well-formed proof is reported as `Ok(None)` from
    /// `ecvrf_verify`, not as this error.
    #[error("vrf: {0}")]
    Vrf(String),

    /// An error in the partially oblivious PRF (POPRF, RFC 9497) layer that is
    /// not a plain length mismatch — e.g. a non-canonical scalar, an invalid or
    /// identity element, or a zero tweaked key (`InverseError`, which per the
    /// RFC signals a likely key compromise and should trigger rotation). A
    /// *verification* failure of an otherwise well-formed DLEQ proof is
    /// reported as `Ok(None)` from `poprf_finalize`, not as this error.
    #[error("poprf: {0}")]
    Poprf(String),

    /// Decrypted bytes are not valid UTF-8.
    #[error("UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}
