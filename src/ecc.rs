//! Matched classical ECDH partners for [`Suite::HybridMatched`] KEM.
//!
//! These are used **only** by the matched-strength KEM suites
//! ([`crate::suite::Suite::HybridMatched`]) so that the classical half scales
//! with the post-quantum category and is never the weak link:
//!
//! - **Cat-3 → X448** (~224-bit classical), RFC 7748.
//! - **Cat-5 → P-521 ECDH** (~256-bit classical), SP 800-56A / SEC1.
//!
//! `Suite::Hybrid` (the default) keeps X25519 at every level and never touches
//! this module; `Suite::PureCnsa2` has no classical half. The shared-secret
//! bytes produced here are concatenated after the ML-KEM shared secret to form
//! the HKDF-SHA512 IKM (see [`crate::suite`]).
//!
//! Both recipient long-term secrets are derived deterministically from the
//! crate's 32-byte root seed (SHAKE256-expanded, mirroring [`crate::hybrid`]),
//! so the public key is reproducible and the secret key stays a single 32-byte
//! seed. Ephemeral secrets are sourced from the OS CSPRNG.

use x448::{PublicKey as X448PublicKey, StaticSecret as X448StaticSecret};

use p521::NistP521;
use p521::elliptic_curve::FieldBytes;
use p521::elliptic_curve::ops::Reduce;
use p521::elliptic_curve::sec1::ToSec1Point;
use p521::{NonZeroScalar, PublicKey as P521PublicKey, Scalar, SecretKey as P521SecretKey};

use crate::CryptoError;

// === X448 (Cat-3 matched) ===

/// X448 public key / secret / shared-secret length (all 56 bytes, RFC 7748).
pub(crate) const X448_LEN: usize = 56;

/// Fill buffer with OS random bytes.
#[inline]
fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Derive the X448 public key (56 B) for a deterministic 56-byte secret.
pub(crate) fn x448_public_from_secret(secret: &[u8; X448_LEN]) -> [u8; X448_LEN] {
    let sk = X448StaticSecret::from(*secret);
    *X448PublicKey::from(&sk).as_bytes()
}

/// Ephemeral X448 encapsulation against a recipient public key.
/// Returns `(ephemeral_pk (56 B), shared_secret (56 B))`.
pub(crate) fn x448_encapsulate(
    recipient_pk: &[u8],
) -> Result<([u8; X448_LEN], [u8; X448_LEN]), CryptoError> {
    let recipient = X448PublicKey::from_bytes(recipient_pk)
        .ok_or_else(|| CryptoError::Hybrid("invalid X448 recipient public key".into()))?;
    let mut eph_bytes = [0u8; X448_LEN];
    random_bytes(&mut eph_bytes);
    let eph_sk = X448StaticSecret::from(eph_bytes);
    let eph_pk = *X448PublicKey::from(&eph_sk).as_bytes();
    let ss = *eph_sk.diffie_hellman(&recipient).as_bytes();
    Ok((eph_pk, ss))
}

/// X448 decapsulation: recompute the shared secret from the recipient's
/// deterministic 56-byte secret and the ephemeral public key.
pub(crate) fn x448_decapsulate(
    recipient_secret: &[u8; X448_LEN],
    eph_pk: &[u8],
) -> Result<[u8; X448_LEN], CryptoError> {
    let eph = X448PublicKey::from_bytes(eph_pk)
        .ok_or_else(|| CryptoError::Hybrid("invalid X448 ephemeral public key".into()))?;
    let sk = X448StaticSecret::from(*recipient_secret);
    Ok(*sk.diffie_hellman(&eph).as_bytes())
}

// === P-521 ECDH (Cat-5 matched) ===

/// P-521 uncompressed SEC1 public-key length (`0x04 || X(66) || Y(66)`).
pub(crate) const P521_PK_LEN: usize = 133;
/// P-521 secret seed material length (wide bytes reduced mod n).
pub(crate) const P521_SK_LEN: usize = 66;
/// P-521 ECDH shared-secret length (the x-coordinate, a field element).
pub(crate) const P521_SS_LEN: usize = 66;

/// Reduce 66 seed bytes to a non-zero P-521 scalar and wrap it as a secret key.
fn p521_secret_from_bytes(bytes: &[u8; P521_SK_LEN]) -> P521SecretKey {
    let fb: FieldBytes<NistP521> = (*bytes).into();
    let scalar = <Scalar as Reduce<FieldBytes<NistP521>>>::reduce(&fb);
    // A zero scalar here is cryptographically impossible (prob. ~2^-521); the
    // expect mirrors the crate's existing `getrandom` expects.
    let nz: NonZeroScalar =
        Option::from(NonZeroScalar::new(scalar)).expect("P-521 scalar reduced to zero");
    P521SecretKey::from(nz)
}

/// Derive the uncompressed SEC1 P-521 public key (133 B) for a 66-byte secret.
pub(crate) fn p521_public_from_secret(
    secret: &[u8; P521_SK_LEN],
) -> Result<[u8; P521_PK_LEN], CryptoError> {
    let sk = p521_secret_from_bytes(secret);
    let ep = sk.public_key().to_sec1_point(false);
    let bytes = ep.as_bytes();
    bytes
        .try_into()
        .map_err(|_| CryptoError::Hybrid("unexpected P-521 public-key length".into()))
}

/// Ephemeral P-521 ECDH encapsulation against a recipient public key.
/// Returns `(ephemeral_pk (133 B uncompressed), shared_secret (66 B))`.
pub(crate) fn p521_encapsulate(
    recipient_pk: &[u8],
) -> Result<([u8; P521_PK_LEN], [u8; P521_SS_LEN]), CryptoError> {
    let recipient = P521PublicKey::from_sec1_bytes(recipient_pk)
        .map_err(|_| CryptoError::Hybrid("invalid P-521 recipient public key".into()))?;
    let mut eph_bytes = [0u8; P521_SK_LEN];
    random_bytes(&mut eph_bytes);
    let eph_sk = p521_secret_from_bytes(&eph_bytes);
    let eph_pk: [u8; P521_PK_LEN] = eph_sk
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::Hybrid("unexpected P-521 public-key length".into()))?;
    let ss: [u8; P521_SS_LEN] = (*eph_sk.diffie_hellman(&recipient).raw_secret_bytes()).into();
    Ok((eph_pk, ss))
}

/// P-521 ECDH decapsulation: recompute the shared secret from the recipient's
/// deterministic 66-byte secret and the ephemeral public key.
pub(crate) fn p521_decapsulate(
    recipient_secret: &[u8; P521_SK_LEN],
    eph_pk: &[u8],
) -> Result<[u8; P521_SS_LEN], CryptoError> {
    let eph = P521PublicKey::from_sec1_bytes(eph_pk)
        .map_err(|_| CryptoError::Hybrid("invalid P-521 ephemeral public key".into()))?;
    let sk = p521_secret_from_bytes(recipient_secret);
    Ok((*sk.diffie_hellman(&eph).raw_secret_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x448_ecdh_agrees() {
        let mut a = [0u8; X448_LEN];
        let mut b = [0u8; X448_LEN];
        random_bytes(&mut a);
        random_bytes(&mut b);
        // `a` is the recipient long-term secret; encapsulate to its public key.
        let a_pk = x448_public_from_secret(&a);
        let (eph_pk, ss_sender) = x448_encapsulate(&a_pk).unwrap();
        let ss_recipient = x448_decapsulate(&a, &eph_pk).unwrap();
        assert_eq!(ss_sender, ss_recipient);
        let _ = b;
    }

    #[test]
    fn p521_ecdh_agrees() {
        let mut a = [0u8; P521_SK_LEN];
        random_bytes(&mut a);
        let a_pk = p521_public_from_secret(&a).unwrap();
        let (eph_pk, ss_sender) = p521_encapsulate(&a_pk).unwrap();
        let ss_recipient = p521_decapsulate(&a, &eph_pk).unwrap();
        assert_eq!(ss_sender, ss_recipient);
    }

    #[test]
    fn x448_public_is_deterministic() {
        let s = [42u8; X448_LEN];
        assert_eq!(x448_public_from_secret(&s), x448_public_from_secret(&s));
    }

    #[test]
    fn p521_public_is_deterministic() {
        let s = [42u8; P521_SK_LEN];
        assert_eq!(
            p521_public_from_secret(&s).unwrap(),
            p521_public_from_secret(&s).unwrap()
        );
    }
}
