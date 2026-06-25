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
/// - `0x01` → Cat-1 hybrid (ML-KEM-512)
/// - `0x02` → Cat-3 hybrid (ML-KEM-768)
/// - `0x03` → Cat-5 hybrid (ML-KEM-1024)
/// - Otherwise → legacy X25519 `box_seal_open`
///
/// If hybrid detection matches but the hybrid open fails, this falls back to the
/// legacy `box_seal_open`. This closes a narrow data-*availability* edge case: a
/// legacy (unversioned) `box_seal` ciphertext whose random leading byte happens
/// to collide with a hybrid tag *and* whose total length matches a hybrid
/// ciphertext would otherwise fail to open. The fallback is safe — a genuinely
/// failed hybrid open of a *real* hybrid ciphertext will also fail the legacy
/// attempt, so an error is still returned in that case.
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
            if let Ok(pt) = hybrid::hybrid_open(ciphertext_b64, pq_sk) {
                return Ok(b64::encode(&pt));
            }
            // Hybrid open failed despite hybrid detection. Fall through to the
            // legacy opener to rescue a misdetected legacy ciphertext; a real
            // hybrid ciphertext will fail this too and still surface an error.
        }
    }
    box_seal::box_seal_open(ciphertext_b64, public_key_b64, private_key_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::{
        generate_hybrid_keypair, generate_hybrid_keypair_512, generate_hybrid_keypair_1024,
    };
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

    // --- #308: legacy/hybrid first-byte collision hardening ---

    #[test]
    fn legacy_colliding_with_hybrid_tag_and_length_falls_back() {
        use crate::box_seal;
        let kp = generate_keypair();
        let hkp = generate_hybrid_keypair_512();
        // A 900-byte plaintext yields a legacy box_seal ct of 32 + 900 + 16 = 948
        // bytes — comfortably above the Cat-1 hybrid minimum (841B). Loop until a
        // freshly-generated legacy ct's random leading byte collides with the
        // Cat-1 tag (0x01); ~1/256 per attempt.
        let pt = vec![7u8; 900];
        let mut sealed = None;
        for _ in 0..200_000 {
            let ct = box_seal::box_seal(&pt, &kp.public_key).unwrap();
            if b64::decode(&ct).unwrap().first() == Some(&0x01) {
                sealed = Some(ct);
                break;
            }
        }
        let ct = sealed.expect("should find a 0x01-leading legacy ct");
        // Misdetected as hybrid by the tag+length check ...
        assert!(hybrid::is_hybrid_ciphertext(&ct));
        // ... but unseal_from_user's fallback rescues it via the legacy opener.
        let opened =
            unseal_from_user(&ct, &kp.public_key, &kp.private_key, Some(&hkp.secret_key)).unwrap();
        assert_eq!(b64::decode(&opened).unwrap(), pt);
    }

    #[test]
    fn real_hybrid_wrong_key_still_errors_with_fallback() {
        let kp = generate_keypair();
        let hkp1 = generate_hybrid_keypair();
        let hkp2 = generate_hybrid_keypair();
        let pt = b"real hybrid ciphertext";
        let ct = seal_for_user(pt, &kp.public_key, Some(&hkp1.public_key)).unwrap();
        // Wrong PQ key: hybrid_open fails, and the legacy fallback also fails
        // (it is not a legacy ct) → still an error, no silent wrong plaintext.
        assert!(
            unseal_from_user(&ct, &kp.public_key, &kp.private_key, Some(&hkp2.secret_key)).is_err()
        );
    }
}
