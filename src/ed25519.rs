//! Raw RFC 8032 Ed25519 — exposed strictly for **transparency-log witness
//! interoperability** (C2SP `signed-note` / `tlog-witness`).
//!
//! ## Why this exists (and why it is *not* the default)
//!
//! The default authenticity primitive in this crate is the **hybrid PQ
//! composite** ([`crate::sign`]): an ML-DSA + Ed25519 signature over a
//! context-framed message. That is what Metamorphic uses for its own
//! authenticity guarantees, and new code should keep using it.
//!
//! This module deliberately exposes **bare, classical RFC 8032 Ed25519** —
//! a raw signature over the *exact* message bytes, with **no context framing
//! and no post-quantum component**. It is provided for one reason only:
//! **byte-level interoperability with the deployed C2SP transparency-log
//! witness ecosystem** (Go's `golang.org/x/mod/sumdb/note`, sigsum,
//! transparency-dev, Tessera). Those witnesses co-sign checkpoints using a
//! `signed-note` signature line whose algorithm identity is fixed to raw
//! Ed25519 over the note text:
//!
//! ```text
//! signature line = "— " <key-name> " " base64( key_id[4] || ed25519_sig[64] )
//! verification   = Ed25519.verify(public_key, note_text_bytes, ed25519_sig)
//! ```
//!
//! A C2SP witness will never emit our hybrid composite (it does not know our
//! format), and for an external witness to recompute and co-sign *our*
//! checkpoint it must be verifiable by its stock `note` library. So verifying
//! (and producing) that classical line requires bare Ed25519 — which we surface
//! here rather than pulling a second, parallel Ed25519 dependency into
//! downstream crates (e.g. `metamorphic-log`). This keeps `metamorphic-crypto`
//! the single source of truth for every primitive.
//!
//! Forward security for our own checkpoints is layered **additively** on top
//! of this classical line via a separate hybrid-PQ signature line (built on
//! [`crate::sign`]); it does not replace the classical line that the witness
//! network needs.
//!
//! ## Verification strictness
//!
//! [`ed25519_verify`] uses `ed25519-dalek`'s `verify_strict` (rejecting
//! non-canonical encodings and small-order / mixed-order public keys). Honestly
//! generated witness signatures over canonical keys verify identically under
//! the strict and permissive equations, so this is fully interoperable with the
//! ecosystem while rejecting malleable / edge-case forgeries.

use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey as EdSigningKey, VerifyingKey};

use crate::CryptoError;

/// Ed25519 seed (private scalar seed) length, in bytes (RFC 8032).
pub const ED25519_SEED_LEN: usize = 32;
/// Ed25519 public-key length, in bytes (RFC 8032).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature length, in bytes (RFC 8032).
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Verify a **raw RFC 8032 Ed25519** signature over `message`.
///
/// This is the primitive a transparency-log verifier uses to check a C2SP
/// `signed-note` witness co-signature line: `message` is the exact note text
/// (no context framing), `public_key` is the witness's 32-byte Ed25519 key, and
/// `signature` is the 64-byte signature carried (after the 4-byte key id) in the
/// note's signature line.
///
/// Verification uses `verify_strict` (see the module docs): canonical witness
/// signatures verify, while non-canonical / small-order edge cases are rejected.
///
/// Returns:
/// - `Ok(true)` if the signature is valid for `(public_key, message)`.
/// - `Ok(false)` for any *cryptographic* failure — wrong key, tampered message,
///   tampered signature, or a non-canonical / small-order public key.
/// - `Err(CryptoError::InvalidLength)` if `public_key` or `signature` is not the
///   exact RFC 8032 length (a *structural*, not cryptographic, failure).
pub fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let pk: [u8; ED25519_PUBLIC_KEY_LEN] =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                got: public_key.len(),
            })?;
    let sig: [u8; ED25519_SIGNATURE_LEN] =
        signature
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: ED25519_SIGNATURE_LEN,
                got: signature.len(),
            })?;

    // A non-canonical / small-order public key is a cryptographic reject, not a
    // structural error: the bytes are the right length but do not decode to a
    // valid point.
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return Ok(false);
    };
    let ed_sig = EdSignature::from_bytes(&sig);
    Ok(vk.verify_strict(message, &ed_sig).is_ok())
}

/// Sign `message` with a **raw RFC 8032 Ed25519** seed, returning the 64-byte
/// signature.
///
/// Provided for completeness and for generating known-answer test vectors /
/// emitting our own classical witness-compatible signature line. For general
/// Metamorphic authenticity, prefer the hybrid PQ [`crate::sign::sign`].
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `seed` is not exactly
/// [`ED25519_SEED_LEN`] bytes.
pub fn ed25519_sign(
    seed: &[u8],
    message: &[u8],
) -> Result<[u8; ED25519_SIGNATURE_LEN], CryptoError> {
    let seed: [u8; ED25519_SEED_LEN] = seed.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: ED25519_SEED_LEN,
        got: seed.len(),
    })?;
    let sk = EdSigningKey::from_bytes(&seed);
    Ok(sk.sign(message).to_bytes())
}

/// Derive the 32-byte Ed25519 public key for a given seed.
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `seed` is not exactly
/// [`ED25519_SEED_LEN`] bytes.
pub fn ed25519_public_key(seed: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], CryptoError> {
    let seed: [u8; ED25519_SEED_LEN] = seed.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: ED25519_SEED_LEN,
        got: seed.len(),
    })?;
    let sk = EdSigningKey::from_bytes(&seed);
    Ok(sk.verifying_key().to_bytes())
}

/// Generate a fresh Ed25519 keypair from the OS CSPRNG, returning
/// `(seed, public_key)`.
///
/// Intended for tests, tooling, and witness-key provisioning. The seed is the
/// private key material; handle it as a secret.
#[must_use]
pub fn ed25519_generate_keypair() -> ([u8; ED25519_SEED_LEN], [u8; ED25519_PUBLIC_KEY_LEN]) {
    let mut seed = [0u8; ED25519_SEED_LEN];
    getrandom::getrandom(&mut seed).expect("OS CSPRNG unavailable");
    let sk = EdSigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    (seed, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (seed, pk) = ed25519_generate_keypair();
        let msg = b"transparency-log checkpoint witness line";
        let sig = ed25519_sign(&seed, msg).unwrap();
        assert!(ed25519_verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn derived_public_key_matches_keygen() {
        let (seed, pk) = ed25519_generate_keypair();
        assert_eq!(ed25519_public_key(&seed).unwrap(), pk);
    }

    #[test]
    fn tampered_message_fails() {
        let (seed, pk) = ed25519_generate_keypair();
        let sig = ed25519_sign(&seed, b"original").unwrap();
        assert!(!ed25519_verify(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let (seed, _pk) = ed25519_generate_keypair();
        let (_other_seed, other_pk) = ed25519_generate_keypair();
        let sig = ed25519_sign(&seed, b"msg").unwrap();
        assert!(!ed25519_verify(&other_pk, b"msg", &sig).unwrap());
    }

    #[test]
    fn bad_lengths_are_structural_errors() {
        assert!(matches!(
            ed25519_verify(&[0u8; 31], b"m", &[0u8; 64]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ed25519_verify(&[0u8; 32], b"m", &[0u8; 63]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ed25519_sign(&[0u8; 31], b"m"),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ed25519_public_key(&[0u8; 33]),
            Err(CryptoError::InvalidLength { .. })
        ));
    }

    #[test]
    fn empty_message_signs_and_verifies() {
        // Edge case relevant to checkpoints: a zero-length message body.
        let (seed, pk) = ed25519_generate_keypair();
        let sig = ed25519_sign(&seed, b"").unwrap();
        assert!(ed25519_verify(&pk, b"", &sig).unwrap());
    }

    #[test]
    fn all_zero_public_key_is_rejected_not_errored() {
        // 32 zero bytes is a small-order point: structurally valid length, but a
        // cryptographic reject under verify_strict (Ok(false), not Err).
        assert!(matches!(
            ed25519_verify(
                &[0u8; ED25519_PUBLIC_KEY_LEN],
                b"m",
                &[0u8; ED25519_SIGNATURE_LEN]
            ),
            Ok(false)
        ));
    }

    /// RFC 8032 §7.1 known-answer vectors. Locking these proves byte-for-byte
    /// agreement with the deployed Ed25519 ecosystem the witness network uses.
    fn rfc8032_kat(secret: &str, public: &str, message: &str, signature: &str) {
        let seed = hex(secret);
        let pk = hex(public);
        let msg = hex(message);
        let sig = hex(signature);

        assert_eq!(ed25519_public_key(&seed).unwrap().as_slice(), &pk[..]);
        assert_eq!(ed25519_sign(&seed, &msg).unwrap().as_slice(), &sig[..]);
        assert!(ed25519_verify(&pk, &msg, &sig).unwrap());
    }

    #[test]
    fn rfc8032_test_1_empty_message() {
        rfc8032_kat(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
    }

    #[test]
    fn rfc8032_test_2_one_byte() {
        rfc8032_kat(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
    }

    /// Decode a hex string into bytes (test helper).
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd-length hex");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
}
