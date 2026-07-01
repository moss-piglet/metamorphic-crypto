//! HKDF (HMAC-based Key Derivation Function, RFC 5869) — SHA-512.
//!
//! A thin, one-shot wrapper over the already-audited [`hkdf`] RustCrypto crate,
//! using SHA-512 as the underlying hash (matching this crate's Cat-5 posture and
//! the HKDF-SHA512 already used internally by the hybrid-seal envelope, see
//! [`crate::suite`]). It exposes no new or novel cryptography — it makes the
//! extract-then-expand KDF the rest of the stack needs available as public API.
//!
//! ## Why this exists
//!
//! Unlike the bare hashes in [`crate::hash`], HKDF is the *correct* construction
//! for combining and diversifying **secret** key material. Its motivating
//! consumer is Mosslet's WebAuthn-PRF device-bound `user_key` wrap (board #362):
//! a single wrapping key must be derived from two secrets — the password-derived
//! key and the authenticator's PRF output — with auditable domain separation.
//! That is exactly HKDF: `salt` + `IKM` in Extract, versioned `info` in Expand.
//!
//! ```text
//! wrapping_key = HKDF-SHA512(
//!     salt = wrap_salt,
//!     ikm  = password_key ‖ prf_output,
//!     info = "mosslet/user_key-wrap/v1",   // domain separation (Expand)
//!     len  = 32,                           // XSalsa20-Poly1305 secretbox key
//! )
//! ```
//!
//! ## Encoding
//!
//! The native [`hkdf_sha512`] takes raw bytes and returns a `Vec<u8>`. The WASM
//! binding (see [`crate::wasm`]) and the Elixir NIF operate on base64 strings to
//! match the rest of the API, so an OKM derived in the browser is byte-for-byte
//! identical to one derived in native Rust or the NIF (pinned by a parity
//! vector). This cross-language determinism is what lets a wrap produced in the
//! browser be re-derived anywhere without the server ever seeing the inputs.
//!
//! ## Salt semantics (RFC 5869 §2.2)
//!
//! An **empty** `salt` is treated as "not provided", i.e. HKDF uses a string of
//! `HashLen` (64) zero bytes as the salt. Pass a non-empty salt to bind the
//! derivation to a per-wrap value (recommended). Callers who need the distinct
//! "salt is the empty string" behaviour should not use this wrapper.

use hkdf::Hkdf;
use sha2::Sha512;

use crate::CryptoError;

/// The underlying hash's output length in bytes (SHA-512 ⇒ 64). The maximum
/// permitted HKDF output is `255 * HASH_LEN` bytes.
pub const HASH_LEN: usize = 64;

/// Derive `length` bytes of output keying material via HKDF-SHA512 (RFC 5869).
///
/// Performs Extract-then-Expand in one call:
///
/// * `salt` — non-secret; bound into Extract. An empty slice means "not
///   provided" (RFC 5869 §2.2), i.e. `HashLen` zero bytes.
/// * `ikm` — the input keying material (may be secret; e.g.
///   `password_key ‖ prf_output`).
/// * `info` — optional, non-secret, application-specific context bound into
///   Expand. Use a versioned label like `b"mosslet/user_key-wrap/v1"` for
///   domain separation.
/// * `length` — desired output length in bytes; must be `<= 255 * 64 = 16320`.
///
/// Returns `CryptoError::Hkdf` only when `length` exceeds the RFC maximum.
///
/// ```
/// use metamorphic_crypto::hkdf::hkdf_sha512;
///
/// // RFC 5869 Test Case 1, recomputed with SHA-512 (L = 42).
/// let ikm = [0x0bu8; 22];
/// let salt: Vec<u8> = (0u8..=0x0c).collect();
/// let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
/// let okm = hkdf_sha512(&salt, &ikm, &info, 42).unwrap();
/// assert_eq!(okm.len(), 42);
/// ```
pub fn hkdf_sha512(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha512>::new(salt_opt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).map_err(|_| {
        CryptoError::Hkdf(format!(
            "invalid output length {length} (max {})",
            255 * HASH_LEN
        ))
    })?;
    Ok(okm)
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

    /// RFC 5869 Test Case 1 inputs, recomputed with SHA-512 (L = 42). This is
    /// the exact vector already pinned for the internal seal HKDF in
    /// `crate::suite`, so the public API is provably the same primitive. It is
    /// also byte-identical to `@noble/hashes` and WebCrypto HKDF-SHA-512.
    #[test]
    fn rfc5869_sha512_kat() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf_sha512(&salt, &ikm, &info, 42).unwrap();
        assert_eq!(
            hex(&okm),
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
        );
    }

    #[test]
    fn deterministic() {
        let okm1 = hkdf_sha512(b"salt", b"ikm-bytes", b"info", 32).unwrap();
        let okm2 = hkdf_sha512(b"salt", b"ikm-bytes", b"info", 32).unwrap();
        assert_eq!(okm1, okm2);
        assert_eq!(okm1.len(), 32);
    }

    #[test]
    fn domain_separated_by_info() {
        let a = hkdf_sha512(b"salt", b"ikm", b"mosslet/user_key-wrap/v1", 32).unwrap();
        let b = hkdf_sha512(b"salt", b"ikm", b"mosslet/user_key-wrap/v2", 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn distinct_salt_ikm_produce_distinct_output() {
        let base = hkdf_sha512(b"salt", b"ikm", b"info", 32).unwrap();
        assert_ne!(base, hkdf_sha512(b"salt2", b"ikm", b"info", 32).unwrap());
        assert_ne!(base, hkdf_sha512(b"salt", b"ikm2", b"info", 32).unwrap());
    }

    #[test]
    fn empty_salt_is_none_semantics() {
        // Empty salt ⇒ "not provided" ⇒ HashLen zero bytes (RFC 5869 §2.2),
        // which differs from a salt that is genuinely 64 explicit zero bytes...
        // actually equals it by construction, but must NOT equal a short salt.
        let empty = hkdf_sha512(b"", b"ikm", b"info", 32).unwrap();
        let zeros = hkdf_sha512(&[0u8; HASH_LEN], b"ikm", b"info", 32).unwrap();
        assert_eq!(empty, zeros);
    }

    #[test]
    fn rejects_too_long_output() {
        assert!(hkdf_sha512(b"salt", b"ikm", b"info", 255 * HASH_LEN + 1).is_err());
        assert!(hkdf_sha512(b"salt", b"ikm", b"info", 255 * HASH_LEN).is_ok());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hkdf_is_deterministic(salt: Vec<u8>, ikm: Vec<u8>, info: Vec<u8>) {
            prop_assert_eq!(
                hkdf_sha512(&salt, &ikm, &info, 32).unwrap(),
                hkdf_sha512(&salt, &ikm, &info, 32).unwrap()
            );
        }
    }
}
