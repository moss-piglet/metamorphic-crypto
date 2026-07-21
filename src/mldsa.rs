//! Raw FIPS 204 ML-DSA-44 — exposed strictly for **transparency-log
//! cosignature interoperability** (C2SP `tlog-cosignature` v1, the ML-DSA-44
//! type).
//!
//! ## Why this exists (and why it is *not* the default)
//!
//! The default authenticity primitive in this crate is the **hybrid PQ
//! composite** ([`crate::sign`]): an ML-DSA + classical signature over a
//! context-framed message. That is what Metamorphic uses for its own
//! authenticity guarantees, and new code should keep using it.
//!
//! This module deliberately exposes **bare, single-algorithm ML-DSA-44** —
//! a raw FIPS 204 signature over the *exact* message bytes, with **no context
//! framing and no classical component**. It is provided for one reason only:
//! **byte-level interoperability with the C2SP transparency-log cosignature
//! ecosystem**. The `tlog-cosignature` spec (<https://c2sp.org/tlog-cosignature>)
//! defines two cosignature types: a classical Ed25519 one (see
//! [`crate::ed25519`]) and a post-quantum **ML-DSA-44** one that a witness can
//! emit so log clients get quantum-resistant split-view protection. Producing
//! and verifying that ML-DSA-44 cosignature line requires bare ML-DSA-44 — which
//! we surface here rather than pulling a second, parallel ML-DSA dependency into
//! downstream crates (e.g. `metamorphic-log`). This keeps `metamorphic-crypto`
//! the single source of truth for every primitive.
//!
//! The signed message for a v1 ML-DSA-44 cosignature is the spec's
//! `cosigned_message` TLS-style struct (a `subtree/v1` label, the cosigner name,
//! a timestamp, the log origin, the subtree bounds, and the root hash); the
//! framing of that struct lives in `metamorphic-log`. This module only signs and
//! verifies the resulting bytes.
//!
//! ## Signing mode (hedged / randomized ML-DSA)
//!
//! Like the composite, signatures use the **hedged (randomized)** variant, so
//! signature *bytes* are not reproducible, but verification is fully
//! deterministic. The native ML-DSA context is empty (the domain separation is
//! carried by the `cosignature/v1` message framing, not the FIPS 204 context).

use ml_dsa::{B32, MlDsa44};

use crate::CryptoError;
use crate::sign::{mldsa_public_key, mldsa_sign, mldsa_verify};

/// ML-DSA-44 seed (`ξ`) length, in bytes (FIPS 204).
pub const MLDSA44_SEED_LEN: usize = 32;
/// ML-DSA-44 public-key length, in bytes (FIPS 204).
pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;
/// ML-DSA-44 signature length, in bytes (FIPS 204).
pub const MLDSA44_SIGNATURE_LEN: usize = 2420;

/// Verify a **raw FIPS 204 ML-DSA-44** signature over `message`.
///
/// This is the primitive a transparency-log verifier uses to check a C2SP
/// `tlog-cosignature` v1 **ML-DSA-44** witness cosignature: `message` is the
/// spec's `cosigned_message` struct bytes (built by the caller), `public_key` is
/// the witness's 1312-byte ML-DSA-44 key, and `signature` is the 2420-byte
/// ML-DSA-44 signature carried (after the timestamp prefix) in the note's
/// signature line.
///
/// Returns:
/// - `Ok(true)` if the signature is valid for `(public_key, message)`.
/// - `Ok(false)` for any *cryptographic* failure — wrong key, tampered message,
///   or a malformed/undecodable signature or key of the right length.
/// - `Err(CryptoError::InvalidLength)` if `public_key` or `signature` is not the
///   exact FIPS 204 ML-DSA-44 length (a *structural*, not cryptographic,
///   failure).
pub fn ml_dsa_44_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    if public_key.len() != MLDSA44_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: MLDSA44_PUBLIC_KEY_LEN,
            got: public_key.len(),
        });
    }
    if signature.len() != MLDSA44_SIGNATURE_LEN {
        return Err(CryptoError::InvalidLength {
            expected: MLDSA44_SIGNATURE_LEN,
            got: signature.len(),
        });
    }
    Ok(mldsa_verify::<MlDsa44>(public_key, message, signature))
}

/// Sign `message` with a **raw FIPS 204 ML-DSA-44** seed, returning the
/// 2420-byte hedged signature.
///
/// Provided for emitting our own ML-DSA-44 witness cosignature line and for
/// tests. For general Metamorphic authenticity, prefer the hybrid PQ
/// [`crate::sign::sign`]. Because ML-DSA signing is hedged, the bytes are not
/// reproducible, but they verify deterministically under [`ml_dsa_44_verify`].
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `seed` is not exactly
/// [`MLDSA44_SEED_LEN`] bytes.
pub fn ml_dsa_44_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed = mldsa44_seed(seed)?;
    Ok(mldsa_sign::<MlDsa44>(&seed, message))
}

/// Derive the 1312-byte ML-DSA-44 public key for a given seed.
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `seed` is not exactly
/// [`MLDSA44_SEED_LEN`] bytes.
pub fn ml_dsa_44_public_key(seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let seed = mldsa44_seed(seed)?;
    Ok(mldsa_public_key::<MlDsa44>(&seed))
}

/// Generate a fresh ML-DSA-44 keypair from the OS CSPRNG, returning
/// `(seed, public_key)`.
///
/// Intended for tests, tooling, and witness-key provisioning. The seed is the
/// private key material; handle it as a secret.
#[must_use]
pub fn ml_dsa_44_generate_keypair() -> ([u8; MLDSA44_SEED_LEN], Vec<u8>) {
    let mut seed_bytes = [0u8; MLDSA44_SEED_LEN];
    getrandom::getrandom(&mut seed_bytes).expect("OS CSPRNG unavailable");
    let seed: B32 = seed_bytes.into();
    let pk = mldsa_public_key::<MlDsa44>(&seed);
    (seed_bytes, pk)
}

/// Convert a byte slice into the ML-DSA `B32` seed type, enforcing the exact
/// FIPS 204 seed length.
fn mldsa44_seed(seed: &[u8]) -> Result<B32, CryptoError> {
    let seed: [u8; MLDSA44_SEED_LEN] = seed.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: MLDSA44_SEED_LEN,
        got: seed.len(),
    })?;
    Ok(seed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (seed, pk) = ml_dsa_44_generate_keypair();
        let msg = b"transparency-log checkpoint ML-DSA-44 cosignature";
        let sig = ml_dsa_44_sign(&seed, msg).unwrap();
        assert_eq!(pk.len(), MLDSA44_PUBLIC_KEY_LEN);
        assert_eq!(sig.len(), MLDSA44_SIGNATURE_LEN);
        assert!(ml_dsa_44_verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn derived_public_key_matches_keygen() {
        let (seed, pk) = ml_dsa_44_generate_keypair();
        assert_eq!(ml_dsa_44_public_key(&seed).unwrap(), pk);
    }

    #[test]
    fn tampered_message_fails() {
        let (seed, pk) = ml_dsa_44_generate_keypair();
        let sig = ml_dsa_44_sign(&seed, b"original").unwrap();
        assert!(!ml_dsa_44_verify(&pk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let (seed, _pk) = ml_dsa_44_generate_keypair();
        let (_other_seed, other_pk) = ml_dsa_44_generate_keypair();
        let sig = ml_dsa_44_sign(&seed, b"msg").unwrap();
        assert!(!ml_dsa_44_verify(&other_pk, b"msg", &sig).unwrap());
    }

    #[test]
    fn bad_lengths_are_structural_errors() {
        assert!(matches!(
            ml_dsa_44_verify(&[0u8; 1311], b"m", &[0u8; MLDSA44_SIGNATURE_LEN]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ml_dsa_44_verify(&[0u8; MLDSA44_PUBLIC_KEY_LEN], b"m", &[0u8; 2419]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ml_dsa_44_sign(&[0u8; 31], b"m"),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ml_dsa_44_public_key(&[0u8; 33]),
            Err(CryptoError::InvalidLength { .. })
        ));
    }

    #[test]
    fn empty_message_signs_and_verifies() {
        let (seed, pk) = ml_dsa_44_generate_keypair();
        let sig = ml_dsa_44_sign(&seed, b"").unwrap();
        assert!(ml_dsa_44_verify(&pk, b"", &sig).unwrap());
    }
}
