//! Unified seal/unseal that auto-detects hybrid (v2/v3) vs legacy (v1) format.
//!
//! These are the primary interface for wrapping/unwrapping per-context symmetric
//! keys for distribution to users.

use crate::CryptoError;
use crate::b64;
use crate::box_seal;
use crate::hybrid;
use crate::hybrid::SecurityLevel;

/// Seal `plaintext` bytes to a user's public key(s).
///
/// - If `pq_public_key_b64` is provided (non-empty), uses hybrid ML-KEM-768 (Cat-3).
/// - Otherwise, falls back to legacy X25519 `box_seal`.
///
/// To choose Cat-5 (ML-KEM-1024), use [`seal_for_user_with_level`] instead.
pub fn seal_for_user(
    plaintext: &[u8],
    public_key_b64: &str,
    pq_public_key_b64: Option<&str>,
) -> Result<String, CryptoError> {
    match pq_public_key_b64 {
        Some(pq) if !pq.is_empty() => hybrid::hybrid_seal(plaintext, pq),
        _ => box_seal::box_seal(plaintext, public_key_b64),
    }
}

/// Seal `plaintext` bytes to a user's public key(s) at a specific security level.
///
/// - If `pq_public_key_b64` is provided (non-empty), uses hybrid KEM at the
///   specified [`SecurityLevel`] (Cat-3 = ML-KEM-768, Cat-5 = ML-KEM-1024).
/// - Otherwise, falls back to legacy X25519 `box_seal`.
pub fn seal_for_user_with_level(
    plaintext: &[u8],
    public_key_b64: &str,
    pq_public_key_b64: Option<&str>,
    level: SecurityLevel,
) -> Result<String, CryptoError> {
    match pq_public_key_b64 {
        Some(pq) if !pq.is_empty() => hybrid::hybrid_seal_with_level(plaintext, pq, level),
        _ => box_seal::box_seal(plaintext, public_key_b64),
    }
}

/// Unseal a ciphertext using the user's private key(s).
///
/// Auto-detects the format:
/// - `0x02` → Cat-3 hybrid (ML-KEM-768)
/// - `0x03` → Cat-5 hybrid (ML-KEM-1024)
/// - Otherwise → legacy X25519 `box_seal_open`
///
/// Returns base64-encoded plaintext (matching the JS `boxSealOpen` convention).
pub fn unseal_from_user(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
    pq_secret_key_b64: Option<&str>,
) -> Result<String, CryptoError> {
    if let Some(pq_sk) = pq_secret_key_b64 {
        if !pq_sk.is_empty() && hybrid::is_hybrid_ciphertext(ciphertext_b64) {
            let pt = hybrid::hybrid_open(ciphertext_b64, pq_sk)?;
            return Ok(b64::encode(&pt));
        }
    }
    box_seal::box_seal_open(ciphertext_b64, public_key_b64, private_key_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::{generate_hybrid_keypair, generate_hybrid_keypair_1024};
    use crate::keys::generate_keypair;

    #[test]
    fn legacy_roundtrip() {
        let kp = generate_keypair();
        let pt = b"context key material";
        let ct = seal_for_user(pt, &kp.public_key, None).unwrap();
        assert!(!hybrid::is_hybrid_ciphertext(&ct));
        let opened = unseal_from_user(&ct, &kp.public_key, &kp.private_key, None).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn hybrid_roundtrip() {
        let kp = generate_keypair();
        let hkp = generate_hybrid_keypair();
        let pt = b"context key material";
        let ct = seal_for_user(pt, &kp.public_key, Some(&hkp.public_key)).unwrap();
        assert!(hybrid::is_hybrid_ciphertext(&ct));
        let opened =
            unseal_from_user(&ct, &kp.public_key, &kp.private_key, Some(&hkp.secret_key)).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn empty_pq_key_falls_back_to_legacy() {
        let kp = generate_keypair();
        let pt = b"context key";
        let ct = seal_for_user(pt, &kp.public_key, Some("")).unwrap();
        assert!(!hybrid::is_hybrid_ciphertext(&ct));
        let opened = unseal_from_user(&ct, &kp.public_key, &kp.private_key, None).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn legacy_ct_with_pq_key_available() {
        let kp = generate_keypair();
        let hkp = generate_hybrid_keypair();
        let pt = b"old pre-migration key";
        // Seal with legacy
        let ct = seal_for_user(pt, &kp.public_key, None).unwrap();
        // Open with PQ key available — detects legacy format
        let opened =
            unseal_from_user(&ct, &kp.public_key, &kp.private_key, Some(&hkp.secret_key)).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    // --- Cat-5 tests ---

    #[test]
    fn cat5_seal_with_level_roundtrip() {
        let kp = generate_keypair();
        let hkp = generate_hybrid_keypair_1024();
        let pt = b"cat5 context key material";
        let ct = seal_for_user_with_level(
            pt,
            &kp.public_key,
            Some(&hkp.public_key),
            SecurityLevel::Cat5,
        )
        .unwrap();
        assert!(hybrid::is_hybrid_ciphertext(&ct));
        // unseal_from_user auto-detects v3
        let opened =
            unseal_from_user(&ct, &kp.public_key, &kp.private_key, Some(&hkp.secret_key)).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn cat3_seal_with_level_roundtrip() {
        let kp = generate_keypair();
        let hkp = generate_hybrid_keypair();
        let pt = b"cat3 via with_level";
        let ct = seal_for_user_with_level(
            pt,
            &kp.public_key,
            Some(&hkp.public_key),
            SecurityLevel::Cat3,
        )
        .unwrap();
        assert!(hybrid::is_hybrid_ciphertext(&ct));
        let opened =
            unseal_from_user(&ct, &kp.public_key, &kp.private_key, Some(&hkp.secret_key)).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn with_level_no_pq_key_falls_back_to_legacy() {
        let kp = generate_keypair();
        let pt = b"no pq key";
        // Even with Cat5 level, no PQ key → legacy
        let ct = seal_for_user_with_level(pt, &kp.public_key, None, SecurityLevel::Cat5).unwrap();
        assert!(!hybrid::is_hybrid_ciphertext(&ct));
        let opened = unseal_from_user(&ct, &kp.public_key, &kp.private_key, None).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }
}
