//! Verifiable Random Function (VRF) — ECVRF-P256-SHA256-TAI (RFC 9381).
//!
//! This is the NIST P-256 sibling of the Edwards25519 ECVRF in [`crate::vrf`].
//! It implements RFC 9381 ciphersuite octet [`ECVRF_P256_SHA256_TAI_SUITE`]
//! (`0x01`): the P-256 curve, SHA-256, and the *try-and-increment* (TAI)
//! hash-to-curve. It exists so that [`metamorphic-log`]'s KEYTRANS layer can
//! offer the **on-spec IETF `KT_128_SHA256_P256` cipher suite**
//! (`draft-ietf-keytrans-protocol`), whose VRF is defined as
//! ECVRF-P256-SHA256-TAI.
//!
//! ## Why a second curve
//!
//! The Edwards25519 ECVRF ([`crate::vrf`]) backs the experimental private
//! KEYTRANS suite and the `KT_128_SHA256_Ed25519` standard suite. The standard
//! `KT_128_SHA256_P256` suite instead mandates P-256, so full on-spec support
//! requires this construction. It is built on the `p256` RustCrypto crate (the
//! same `elliptic-curve` 0.14 generation as the crate's existing P-521 stack)
//! plus SHA-256 and RFC 6979 deterministic nonces — no novel cryptography.
//! Correctness is pinned byte-for-byte by RFC 9381 Appendix B.1's known-answer
//! vectors (see the module tests), so independent implementations interoperate
//! exactly.
//!
//! ## Post-quantum posture (honest framing)
//!
//! Like [`crate::vrf`], this VRF is **classical** (elliptic-curve discrete log)
//! and protects exactly one property: KEYTRANS *index privacy*. Integrity,
//! authenticity, and the hash-based commitments are post-quantum and do not rely
//! on this VRF. These primitives are not FIPS-validated, and this crate makes no
//! such claim.
//!
//! ## Wire formats (stable — reproduce exactly for cross-language parity)
//!
//! ```text
//! secret key  (SK) : 32 bytes   (the VRF secret scalar x, big-endian; x = SK)
//! public key  (Y)  : 33 bytes   (SEC1 point compression on; Y = x*B)
//! proof       (pi) : 81 bytes   = point_to_string(Gamma) (33)
//!                                || int_to_string(c, 16)  (16, big-endian)
//!                                || int_to_string(s, 32)  (32, big-endian)
//! output      (beta): 32 bytes  = SHA-256(0x01 || 0x03 || point_to_string(
//!                                            Gamma) || 0x00)   [cofactor = 1]
//! ```
//!
//! Points use SEC1 §2.3.3 compressed encoding (33 bytes); scalars are 32-byte
//! big-endian (I2OSP / OS2IP), exactly as RFC 9381's P-256 ciphersuite requires.
//!
//! [`metamorphic-log`]: https://github.com/moss-piglet/metamorphic-log

use hmac::digest::consts::U32;
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::ff::Field;
use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, Sec1Point, U256};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::CryptoError;

/// VRF secret-key length, in bytes (the big-endian secret scalar `x`).
pub const ECVRF_P256_SECRET_KEY_LEN: usize = 32;
/// VRF public-key length, in bytes (SEC1 compressed point, `ptLen`).
pub const ECVRF_P256_PUBLIC_KEY_LEN: usize = 33;
/// VRF proof (`pi`) length, in bytes: `Gamma(33) || c(16) || s(32)`.
pub const ECVRF_P256_PROOF_LEN: usize = 81;
/// VRF output (`beta`) length, in bytes (a SHA-256 digest).
pub const ECVRF_P256_OUTPUT_LEN: usize = 32;

/// RFC 9381 ciphersuite octet for **ECVRF-P256-SHA256-TAI**.
///
/// Mixed into every hash in the construction (hash-to-curve, challenge, and
/// output), so proofs are bound to this specific ciphersuite.
pub const ECVRF_P256_SHA256_TAI_SUITE: u8 = 0x01;

// RFC 9381 per-step domain-separation octets (the "front"/"back" framing bytes
// that surround each hashed payload).
const DOM_HASH_TO_CURVE: u8 = 0x01;
const DOM_CHALLENGE: u8 = 0x02;
const DOM_PROOF_TO_HASH: u8 = 0x03;
const DOM_BACK: u8 = 0x00;

/// Challenge length in bytes (`cLen` in RFC 9381 for this suite).
const CHALLENGE_LEN: usize = 16;

/// The NIST P-256 group order `q` (big-endian), used by RFC 6979 nonce
/// generation and to reduce the message hash into the scalar field.
const P256_ORDER_Q: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Decode a 32-byte big-endian secret key into the VRF secret scalar `x`.
///
/// Per the ciphersuite, `x = SK`. Rejects a scalar that is zero or not in
/// `[1, q-1]` (a non-canonical / out-of-range key).
fn secret_scalar(secret_key: &[u8]) -> Result<Scalar, CryptoError> {
    let sk: [u8; ECVRF_P256_SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: ECVRF_P256_SECRET_KEY_LEN,
                got: secret_key.len(),
            })?;
    let fb = FieldBytes::from(sk);
    let x = Option::<Scalar>::from(Scalar::from_repr(fb))
        .ok_or_else(|| CryptoError::Vrf("secret key is not a canonical P-256 scalar".into()))?;
    if bool::from(Field::is_zero(&x)) {
        return Err(CryptoError::Vrf("secret key scalar is zero".into()));
    }
    Ok(x)
}

/// `point_to_string`: SEC1 §2.3.3 compressed encoding (33 bytes). The input must
/// not be the identity (which has no compressed encoding and never arises here).
fn point_to_string(p: &ProjectivePoint) -> [u8; ECVRF_P256_PUBLIC_KEY_LEN] {
    let affine = p.to_affine();
    let encoded = affine.to_sec1_point(true);
    let mut out = [0u8; ECVRF_P256_PUBLIC_KEY_LEN];
    out.copy_from_slice(encoded.as_bytes());
    out
}

/// `string_to_point`: decode a SEC1 point encoding, returning `None`
/// ("INVALID") if the bytes do not decode to a valid curve point.
fn string_to_point(bytes: &[u8]) -> Option<ProjectivePoint> {
    let encoded = Sec1Point::from_bytes(bytes).ok()?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_sec1_point(&encoded))?;
    Some(ProjectivePoint::from(affine))
}

/// ECVRF_encode_to_curve, try-and-increment (RFC 9381 §5.4.1.1) with
/// `interpret_hash_value_as_a_point(s) = string_to_point(0x02 || s)`.
///
/// `salt` is the prover's compressed public key (`encode_to_curve_salt =
/// PK_string`). Returns `None` only if no candidate succeeds within the 256-step
/// counter budget — a ~2^-256 event.
fn hash_to_curve_tai(
    salt: &[u8; ECVRF_P256_PUBLIC_KEY_LEN],
    alpha: &[u8],
) -> Option<ProjectivePoint> {
    for ctr in 0u8..=u8::MAX {
        let mut h = Sha256::new();
        h.update([ECVRF_P256_SHA256_TAI_SUITE, DOM_HASH_TO_CURVE]);
        h.update(salt);
        h.update(alpha);
        h.update([ctr, DOM_BACK]);
        let digest = h.finalize();

        // interpret_hash_value_as_a_point: prepend the 0x02 even-y compression
        // prefix and decode as a 33-byte SEC1 compressed point.
        let mut candidate = [0u8; ECVRF_P256_PUBLIC_KEY_LEN];
        candidate[0] = 0x02;
        candidate[1..].copy_from_slice(&digest);
        if let Some(point) = string_to_point(&candidate) {
            // cofactor = 1, so no cofactor clearing; reject the identity.
            if bool::from(point.is_identity()) {
                continue;
            }
            return Some(point);
        }
    }
    None
}

/// ECVRF_challenge_generation (RFC 9381 §5.4.3): hash the five compressed points
/// under the challenge domain separator and take the low `CHALLENGE_LEN` bytes
/// as a scalar.
fn challenge(points: [&ProjectivePoint; 5]) -> Scalar {
    let mut h = Sha256::new();
    h.update([ECVRF_P256_SHA256_TAI_SUITE, DOM_CHALLENGE]);
    for p in points {
        h.update(point_to_string(p));
    }
    h.update([DOM_BACK]);
    let digest = h.finalize();
    scalar_from_challenge(&digest[..CHALLENGE_LEN])
}

/// Build a scalar from a `CHALLENGE_LEN`-byte big-endian challenge value. The
/// value is < 2^128 < q, so it is always canonical.
fn scalar_from_challenge(c_bytes: &[u8]) -> Scalar {
    let mut wide = [0u8; 32];
    wide[32 - CHALLENGE_LEN..].copy_from_slice(c_bytes);
    Scalar::from_repr(FieldBytes::from(wide))
        .expect("a 16-byte big-endian value is always a canonical P-256 scalar")
}

/// ECVRF_proof_to_hash (RFC 9381 §5.2): derive the 32-byte output `beta` from
/// `Gamma`. cofactor = 1, so `cofactor * Gamma = Gamma`.
fn gamma_to_hash(gamma: &ProjectivePoint) -> [u8; ECVRF_P256_OUTPUT_LEN] {
    let mut h = Sha256::new();
    h.update([ECVRF_P256_SHA256_TAI_SUITE, DOM_PROOF_TO_HASH]);
    h.update(point_to_string(gamma));
    h.update([DOM_BACK]);
    h.finalize().into()
}

/// ECVRF_nonce_generation_RFC6979 (RFC 9381 §5.4.2.1): `k = generate_k(x,
/// h_string)` with `m = h_string`, `H = SHA-256`. `h_string` is the compressed
/// `H` point. The message digest is reduced mod `q` (RFC 6979 `bits2octets`)
/// before being fed to the HMAC_DRBG.
fn nonce_rfc6979(x: &Scalar, h_string: &[u8]) -> Scalar {
    let h1 = Sha256::digest(h_string);
    // bits2octets: since hLen == qLen == 256 bits and the digest is < 2q, this
    // reduction modulo q matches RFC 6979's bits2octets exactly.
    let h_reduced = <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(&h1));
    let x_bytes = x.to_repr();
    let k_bytes = rfc6979::generate_k::<Sha256, U32>(
        &x_bytes,
        &FieldBytes::from(P256_ORDER_Q),
        &h_reduced.to_repr(),
        b"",
    );
    Scalar::from_repr(k_bytes).expect("RFC 6979 generate_k yields a scalar in [1, q-1]")
}

/// Generate a fresh VRF keypair from the OS CSPRNG, returning
/// `(secret_key, public_key)`. The secret key is a 32-byte big-endian scalar;
/// handle it as secret material.
#[must_use]
pub fn ecvrf_p256_generate_keypair() -> (
    [u8; ECVRF_P256_SECRET_KEY_LEN],
    [u8; ECVRF_P256_PUBLIC_KEY_LEN],
) {
    loop {
        let mut sk = [0u8; ECVRF_P256_SECRET_KEY_LEN];
        getrandom::getrandom(&mut sk).expect("OS CSPRNG unavailable");
        // Reject the ~2^-224 fraction of 32-byte strings that are not a valid
        // in-range, non-zero scalar, and re-sample. On success the caller owns
        // the secret, so it is returned (not wiped) here.
        match ecvrf_p256_public_key(&sk) {
            Ok(pk) => return (sk, pk),
            Err(_) => sk.zeroize(),
        }
    }
}

/// Derive the 33-byte compressed VRF public key for a secret-key scalar.
///
/// # Errors
/// [`CryptoError::InvalidLength`] if `secret_key` is not
/// [`ECVRF_P256_SECRET_KEY_LEN`] bytes, or [`CryptoError::Vrf`] if it is not a
/// canonical non-zero P-256 scalar.
pub fn ecvrf_p256_public_key(
    secret_key: &[u8],
) -> Result<[u8; ECVRF_P256_PUBLIC_KEY_LEN], CryptoError> {
    let x = secret_scalar(secret_key)?;
    let y = ProjectivePoint::GENERATOR * x;
    Ok(point_to_string(&y))
}

/// Produce a VRF proof `pi` (81 bytes) for `alpha` under `secret_key`.
///
/// # Errors
/// - [`CryptoError::InvalidLength`] if `secret_key` is not
///   [`ECVRF_P256_SECRET_KEY_LEN`] bytes.
/// - [`CryptoError::Vrf`] for a non-canonical/zero key or the negligible
///   (~2^-256) hash-to-curve counter exhaustion.
pub fn ecvrf_p256_prove(
    secret_key: &[u8],
    alpha: &[u8],
) -> Result<[u8; ECVRF_P256_PROOF_LEN], CryptoError> {
    let x = secret_scalar(secret_key)?;
    let y = ProjectivePoint::GENERATOR * x;
    let pk = point_to_string(&y);

    let Some(h) = hash_to_curve_tai(&pk, alpha) else {
        return Err(CryptoError::Vrf(
            "hash-to-curve found no candidate point within the counter budget".into(),
        ));
    };
    let h_string = point_to_string(&h);
    let gamma = h * x;

    let k = nonce_rfc6979(&x, &h_string);
    let c = challenge([&y, &h, &gamma, &(ProjectivePoint::GENERATOR * k), &(h * k)]);
    let s = k + c * x;

    let mut pi = [0u8; ECVRF_P256_PROOF_LEN];
    pi[..33].copy_from_slice(&point_to_string(&gamma));
    pi[33..33 + CHALLENGE_LEN].copy_from_slice(&c.to_repr()[32 - CHALLENGE_LEN..]);
    pi[33 + CHALLENGE_LEN..].copy_from_slice(&s.to_repr());
    Ok(pi)
}

/// Verify a VRF proof `pi` for `alpha` under `public_key`, with full key
/// validation (RFC 9381 `validate_key = TRUE`).
///
/// Returns:
/// - `Ok(Some(beta))` — the 32-byte output — if the proof is valid.
/// - `Ok(None)` for any *cryptographic* rejection: an invalid public key or
///   `Gamma`, a non-canonical `s`, an identity public key, or a challenge
///   mismatch.
/// - `Err(CryptoError::InvalidLength)` if `public_key` or `proof` is the wrong
///   length (a *structural* failure).
pub fn ecvrf_p256_verify(
    public_key: &[u8],
    alpha: &[u8],
    proof: &[u8],
) -> Result<Option<[u8; ECVRF_P256_OUTPUT_LEN]>, CryptoError> {
    if public_key.len() != ECVRF_P256_PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: ECVRF_P256_PUBLIC_KEY_LEN,
            got: public_key.len(),
        });
    }
    let pk: [u8; ECVRF_P256_PUBLIC_KEY_LEN] = public_key.try_into().expect("length checked");
    if proof.len() != ECVRF_P256_PROOF_LEN {
        return Err(CryptoError::InvalidLength {
            expected: ECVRF_P256_PROOF_LEN,
            got: proof.len(),
        });
    }

    // Step 1-2: Y = string_to_point(PK); INVALID -> reject.
    let Some(y) = string_to_point(&pk) else {
        return Ok(None);
    };
    // Step 3: validate_key = TRUE. cofactor = 1, so reject only the identity.
    if bool::from(y.is_identity()) {
        return Ok(None);
    }

    // Step 4-6: decode pi = Gamma(33) || c(16) || s(32).
    let Some(gamma) = string_to_point(&proof[..33]) else {
        return Ok(None);
    };
    let c = scalar_from_challenge(&proof[33..33 + CHALLENGE_LEN]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&proof[33 + CHALLENGE_LEN..]);
    // Reject a non-canonical s (>= q): a strict, malleability-free decode.
    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(s_bytes))) else {
        return Ok(None);
    };

    // Step 7: H = encode_to_curve(PK, alpha).
    let Some(h) = hash_to_curve_tai(&pk, alpha) else {
        return Ok(None);
    };

    // Step 8-10: U = s*B - c*Y ; V = s*H - c*Gamma ; c' = challenge(...).
    let u = ProjectivePoint::GENERATOR * s - y * c;
    let v = h * s - gamma * c;
    let c_prime = challenge([&y, &h, &gamma, &u, &v]);

    // Step 11: accept iff the recomputed challenge matches. Both are public.
    if c_prime == c {
        Ok(Some(gamma_to_hash(&gamma)))
    } else {
        Ok(None)
    }
}

/// Recover the 32-byte VRF output `beta` directly from a proof `pi`, **without**
/// verifying it. Use only on a proof already verified with
/// [`ecvrf_p256_verify`], or whose provenance you independently trust.
///
/// # Errors
/// - [`CryptoError::InvalidLength`] if `proof` is not [`ECVRF_P256_PROOF_LEN`]
///   bytes.
/// - [`CryptoError::Vrf`] if the `Gamma` component is not a valid curve point.
pub fn ecvrf_p256_proof_to_hash(proof: &[u8]) -> Result<[u8; ECVRF_P256_OUTPUT_LEN], CryptoError> {
    if proof.len() != ECVRF_P256_PROOF_LEN {
        return Err(CryptoError::InvalidLength {
            expected: ECVRF_P256_PROOF_LEN,
            got: proof.len(),
        });
    }
    let gamma = string_to_point(&proof[..33])
        .ok_or_else(|| CryptoError::Vrf("proof Gamma is not a valid curve point".into()))?;
    Ok(gamma_to_hash(&gamma))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hex-decode a string literal into a `Vec<u8>` (test helper).
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd-length hex");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9381 Appendix B.1 known-answer vectors for ECVRF-P256-SHA256-TAI.
    /// Locking `(PK, pi, beta)` for each `(SK, alpha)` proves byte-for-byte
    /// agreement with the standard, so any independent verifier interoperates.
    fn rfc9381_p256_kat(sk: &str, pk: &str, alpha: &str, pi: &str, beta: &str) {
        let sk = hex(sk);
        let pk = hex(pk);
        let alpha = hex(alpha);
        let pi = hex(pi);
        let beta = hex(beta);

        assert_eq!(
            ecvrf_p256_public_key(&sk).unwrap().as_slice(),
            &pk[..],
            "PK"
        );
        assert_eq!(
            ecvrf_p256_prove(&sk, &alpha).unwrap().as_slice(),
            &pi[..],
            "pi"
        );
        assert_eq!(
            ecvrf_p256_proof_to_hash(&pi).unwrap().as_slice(),
            &beta[..],
            "beta"
        );
        assert_eq!(
            ecvrf_p256_verify(&pk, &alpha, &pi)
                .unwrap()
                .map(|b| b.to_vec()),
            Some(beta),
            "verify"
        );
    }

    #[test]
    fn rfc9381_example_10_sample() {
        rfc9381_p256_kat(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            "73616d706c65",
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4\
             a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376\
             b33edf7de17c6ea056d4d82de6bc02f",
            "a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e",
        );
    }

    #[test]
    fn rfc9381_example_11_test() {
        rfc9381_p256_kat(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            "74657374",
            "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56\
             c19e067b15a8a8174905b13617804534214f935b94c2287f797e393eb0816969d\
             864f37625b443f30f1a5a33f2b3c854",
            "a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d",
        );
    }

    #[test]
    fn rfc9381_example_12_ansi() {
        rfc9381_p256_kat(
            "2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8",
            "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d",
            "4578616d706c65207573696e67204543445341206b65792066726f6d20417070656e646978204c2e342e32206f6620414e53492e58392d36322d32303035",
            "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667d\
             091c00b0f5c3619d10ecea44363b5a599cadc5b2957e223fec62e81f7b4825fc79\
             9a771a3d7334b9186bdbee87316b1",
            "90871e06da5caa39a3c61578ebb844de8635e27ac0b13e829997d0d95dd98c19",
        );
    }

    #[test]
    fn prove_verify_roundtrip() {
        let (sk, pk) = ecvrf_p256_generate_keypair();
        let alpha = b"directory identity index";
        let pi = ecvrf_p256_prove(&sk, alpha).unwrap();
        let beta = ecvrf_p256_verify(&pk, alpha, &pi).unwrap();
        assert_eq!(beta, Some(ecvrf_p256_proof_to_hash(&pi).unwrap()));
    }

    #[test]
    fn derived_public_key_matches_keygen() {
        let (sk, pk) = ecvrf_p256_generate_keypair();
        assert_eq!(ecvrf_p256_public_key(&sk).unwrap(), pk);
    }

    #[test]
    fn output_is_deterministic_for_same_input() {
        let (sk, _pk) = ecvrf_p256_generate_keypair();
        assert_eq!(
            ecvrf_p256_prove(&sk, b"x").unwrap(),
            ecvrf_p256_prove(&sk, b"x").unwrap()
        );
    }

    #[test]
    fn distinct_inputs_give_distinct_outputs() {
        let (sk, _pk) = ecvrf_p256_generate_keypair();
        let b1 = ecvrf_p256_proof_to_hash(&ecvrf_p256_prove(&sk, b"a").unwrap()).unwrap();
        let b2 = ecvrf_p256_proof_to_hash(&ecvrf_p256_prove(&sk, b"b").unwrap()).unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn tampered_alpha_is_rejected() {
        let (sk, pk) = ecvrf_p256_generate_keypair();
        let pi = ecvrf_p256_prove(&sk, b"original").unwrap();
        assert_eq!(ecvrf_p256_verify(&pk, b"tampered", &pi).unwrap(), None);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (sk, _pk) = ecvrf_p256_generate_keypair();
        let (_other_sk, other_pk) = ecvrf_p256_generate_keypair();
        let pi = ecvrf_p256_prove(&sk, b"msg").unwrap();
        assert_eq!(ecvrf_p256_verify(&other_pk, b"msg", &pi).unwrap(), None);
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (sk, pk) = ecvrf_p256_generate_keypair();
        let pi = ecvrf_p256_prove(&sk, b"msg").unwrap();
        // Flip a bit in each component (Gamma, c, s) and confirm each rejects.
        for idx in [1usize, 34, 80] {
            let mut bad = pi;
            bad[idx] ^= 0x01;
            let r = ecvrf_p256_verify(&pk, b"msg", &bad).unwrap();
            assert!(r.is_none(), "idx {idx} should reject");
        }
        assert!(ecvrf_p256_verify(&pk, b"msg", &pi).unwrap().is_some());
    }

    #[test]
    fn bad_lengths_are_structural_errors() {
        let (sk, pk) = ecvrf_p256_generate_keypair();
        let pi = ecvrf_p256_prove(&sk, b"m").unwrap();
        assert!(matches!(
            ecvrf_p256_public_key(&[0u8; 31]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ecvrf_p256_verify(&[0u8; 32], b"m", &pi),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ecvrf_p256_verify(&pk, b"m", &[0u8; 80]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ecvrf_p256_proof_to_hash(&[0u8; 82]),
            Err(CryptoError::InvalidLength { .. })
        ));
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prove_then_verify_always_accepts(seed: [u8; 32], alpha: Vec<u8>) {
            // Only proceed for seeds that are valid in-range scalars.
            if let Ok(pk) = ecvrf_p256_public_key(&seed) {
                let pi = ecvrf_p256_prove(&seed, &alpha).unwrap();
                let beta = ecvrf_p256_verify(&pk, &alpha, &pi).unwrap();
                prop_assert_eq!(beta, Some(ecvrf_p256_proof_to_hash(&pi).unwrap()));
            }
        }

        #[test]
        fn verify_rejects_under_a_different_input(
            seed: [u8; 32],
            alpha: Vec<u8>,
            other: Vec<u8>,
        ) {
            prop_assume!(alpha != other);
            if let Ok(pk) = ecvrf_p256_public_key(&seed) {
                let pi = ecvrf_p256_prove(&seed, &alpha).unwrap();
                prop_assert_eq!(ecvrf_p256_verify(&pk, &other, &pi).unwrap(), None);
            }
        }
    }
}
