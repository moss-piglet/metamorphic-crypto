//! Verifiable Random Function (VRF) — ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381).
//!
//! A VRF is a keyed function whose owner can compute, for any input
//! `alpha`, a pseudorandom output `beta` **and** a proof `pi` that `beta` was
//! computed correctly under their public key. Anyone with the public key can
//! verify `pi`, but cannot compute `beta` for a new input themselves, and
//! cannot learn `alpha` from `(pi, beta)` alone. This crate exposes the VRF so
//! that [`metamorphic-log`]'s CONIKS-style key-transparency layer can map a
//! (private) identity index to a pseudorandom tree position — giving
//! *index privacy* (the directory never reveals which identities it holds)
//! together with a verifiable, non-equivocable mapping.
//!
//! ## Which construction, and why this one
//!
//! This is **ECVRF-EDWARDS25519-SHA512-TAI** — RFC 9381 ciphersuite octet
//! [`ECVRF_EDWARDS25519_SHA512_TAI_SUITE`] (`0x03`): the Edwards25519 curve,
//! SHA-512, and the *try-and-increment* (TAI) hash-to-curve. It is built
//! **entirely on the curve arithmetic this crate already depends on**
//! (`curve25519-dalek`, the same backend behind [`crate::ed25519`]) plus
//! SHA-512 — no new curve stack, no parallel crypto. The construction is
//! standardized and pinned byte-for-byte by RFC 9381's own test vectors (see
//! the module tests), so independent implementations interoperate exactly.
//!
//! RFC 9381 also defines a sibling ciphersuite, `ECVRF-EDWARDS25519-SHA512-ELL2`
//! (`0x04`), which differs **only** in the hash-to-curve step (the constant-time
//! Elligator2 map instead of try-and-increment). A conformant Elligator2
//! hash-to-curve is not exposed by the released `curve25519-dalek` 4.x backend
//! this crate pins (its only public Edwards map is the `#[deprecated]`,
//! explicitly non-conformant `nonspec_map_to_curve`). ELL2 is therefore a
//! deliberate, documented future addition that lands when the curve backend
//! ships a conformant `encode_to_curve` (curve25519-dalek 5.x). Because the
//! suite octet is mixed into every hash in the construction, a TAI proof and an
//! ELL2 proof are distinct, self-describing artifacts: adding ELL2 later is
//! purely additive and never invalidates a TAI proof. (Index privacy as
//! observed by a verifier is identical for both suites; they differ only in
//! whether the *prover's* hash-to-curve is constant-time, which matters only
//! when an adversary can time a prover hashing a secret input — not the case
//! for a directory that already holds its identities in plaintext.)
//!
//! ## Post-quantum posture (honest framing)
//!
//! This VRF is **classical** (elliptic-curve discrete log). It is the one place
//! in the Metamorphic transparency stack whose security is not post-quantum,
//! and it protects exactly one property: *index privacy*. A future quantum
//! adversary able to break Curve25519 could, in principle, learn which indices
//! a recorded proof transcript corresponds to. Integrity, authenticity,
//! confidentiality, and the hash-based commitments built on
//! [`crate::hash::sha3_512`] are post-quantum from day one and do not rely on
//! this VRF. A designed-in hybrid path (a post-quantum VRF combined with this
//! classical one, with output mixed via SHA3-512 and uniqueness anchored on the
//! audited classical half) is intended for when an audited, production-grade
//! lattice VRF exists; none does today, so it is not built here. These
//! primitives are not FIPS-validated, and this crate makes no such claim.
//!
//! ## Wire formats (stable — reproduce exactly for cross-language parity)
//!
//! ```text
//! secret key  (SK) : 32 bytes   (an Ed25519-style seed; secret scalar + nonce
//!                                 prefix are derived as SHA-512(SK))
//! public key  (Y)  : 32 bytes   (compressed Edwards point Y = x*B)
//! proof       (pi) : 80 bytes   = point_to_string(Gamma) (32)
//!                                || int_to_string(c, 16)  (16, the truncated
//!                                                              challenge)
//!                                || int_to_string(s, 32)  (32, little-endian)
//! output      (beta): 64 bytes  = SHA-512(0x03 || 0x03 || point_to_string(
//!                                            cofactor*Gamma) || 0x00)
//! ```
//!
//! All point encodings are the 32-byte compressed Edwards Y form; scalars are
//! the canonical 32-byte little-endian form, exactly as in RFC 8032 / RFC 9381.
//!
//! [`metamorphic-log`]: https://github.com/moss-piglet/metamorphic-log

use curve25519_dalek::{EdwardsPoint, Scalar, edwards::CompressedEdwardsY, scalar::clamp_integer};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::CryptoError;

/// VRF secret-key length, in bytes (an Ed25519-style 32-byte seed).
pub const ECVRF_SECRET_KEY_LEN: usize = 32;
/// VRF public-key length, in bytes (compressed Edwards point).
pub const ECVRF_PUBLIC_KEY_LEN: usize = 32;
/// VRF proof (`pi`) length, in bytes: `Gamma(32) || c(16) || s(32)`.
pub const ECVRF_PROOF_LEN: usize = 80;
/// VRF output (`beta`) length, in bytes (a SHA-512 digest).
pub const ECVRF_OUTPUT_LEN: usize = 64;

/// RFC 9381 ciphersuite octet for **ECVRF-EDWARDS25519-SHA512-TAI**.
///
/// Mixed into every hash in the construction (hash-to-curve, challenge, and
/// output), so proofs are bound to this specific ciphersuite and cannot be
/// reinterpreted under another (e.g. the future `0x04` Elligator2 suite).
pub const ECVRF_EDWARDS25519_SHA512_TAI_SUITE: u8 = 0x03;

// RFC 9381 per-step domain-separation octets (the "front"/"back" framing bytes
// that surround each hashed payload). Kept here as named constants so the
// framing is auditable against the spec at a glance.
const DOM_HASH_TO_CURVE: u8 = 0x01;
const DOM_CHALLENGE: u8 = 0x02;
const DOM_PROOF_TO_HASH: u8 = 0x03;
const DOM_BACK: u8 = 0x00;

/// Truncated-challenge length in bytes (`cLen` in RFC 9381 for this suite).
const CHALLENGE_LEN: usize = 16;

/// Derive the secret scalar `x` and the 32-byte nonce prefix from a secret-key
/// seed, exactly as RFC 8032 / RFC 9381 specify: `SHA-512(SK)`, clamp the low
/// 32 bytes into the secret scalar, keep the high 32 bytes as the nonce prefix.
fn expand_secret(sk: &[u8; ECVRF_SECRET_KEY_LEN]) -> (Scalar, [u8; 32]) {
    let mut hashed: [u8; 64] = Sha512::digest(sk).into();
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&hashed[..32]);
    let x = Scalar::from_bytes_mod_order(clamp_integer(x_bytes));
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&hashed[32..]);
    x_bytes.zeroize();
    hashed.zeroize();
    (x, prefix)
}

/// ECVRF_encode_to_curve, try-and-increment variant (RFC 9381 §5.4.1.1).
///
/// Hashes `suite || 0x01 || salt || alpha || ctr || 0x00` for `ctr = 0, 1, …`,
/// interpreting the first 32 bytes of each digest as a compressed Edwards point,
/// until one decodes to a valid, non-small-order point; that point is then
/// cleared of its cofactor. `salt` is the prover's compressed public key.
///
/// Returns `None` only if no candidate succeeds within the 256-step counter
/// budget — a ~2^-256 event that never occurs for honest inputs.
fn hash_to_curve_tai(salt: &[u8; 32], alpha: &[u8]) -> Option<EdwardsPoint> {
    for ctr in 0u8..=u8::MAX {
        let mut h = Sha512::new();
        h.update([ECVRF_EDWARDS25519_SHA512_TAI_SUITE, DOM_HASH_TO_CURVE]);
        h.update(salt);
        h.update(alpha);
        h.update([ctr, DOM_BACK]);
        let digest = h.finalize();

        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&digest[..32]);
        if let Some(point) = CompressedEdwardsY(candidate).decompress() {
            // A small-order candidate becomes the identity after cofactor
            // clearing (RFC 9381 rejects an identity H), so skip it directly.
            if point.is_small_order() {
                continue;
            }
            return Some(point.mul_by_cofactor());
        }
    }
    None
}

/// ECVRF_challenge_generation (RFC 9381 §5.4.3): hash the five compressed points
/// under the challenge domain separator and take the low `CHALLENGE_LEN` bytes
/// as a scalar.
fn challenge(points: [&EdwardsPoint; 5]) -> Scalar {
    let mut h = Sha512::new();
    h.update([ECVRF_EDWARDS25519_SHA512_TAI_SUITE, DOM_CHALLENGE]);
    for p in points {
        h.update(p.compress().as_bytes());
    }
    h.update([DOM_BACK]);
    let digest = h.finalize();

    let mut c_bytes = [0u8; 32];
    c_bytes[..CHALLENGE_LEN].copy_from_slice(&digest[..CHALLENGE_LEN]);
    Scalar::from_bytes_mod_order(c_bytes)
}

/// ECVRF_proof_to_hash (RFC 9381 §5.2): derive the 64-byte output `beta` from
/// `Gamma`. Defined over `cofactor*Gamma` so the output is invariant under the
/// small-subgroup component of `Gamma`.
fn gamma_to_hash(gamma: &EdwardsPoint) -> [u8; ECVRF_OUTPUT_LEN] {
    let mut h = Sha512::new();
    h.update([ECVRF_EDWARDS25519_SHA512_TAI_SUITE, DOM_PROOF_TO_HASH]);
    h.update(gamma.mul_by_cofactor().compress().as_bytes());
    h.update([DOM_BACK]);
    h.finalize().into()
}

/// Generate a fresh VRF keypair from the OS CSPRNG, returning
/// `(secret_key, public_key)`.
///
/// The secret key is a 32-byte seed (the private scalar and nonce prefix are
/// derived from it); handle it as secret material. Intended for tests, tooling,
/// and per-namespace VRF-key provisioning.
#[must_use]
pub fn ecvrf_generate_keypair() -> ([u8; ECVRF_SECRET_KEY_LEN], [u8; ECVRF_PUBLIC_KEY_LEN]) {
    let mut sk = [0u8; ECVRF_SECRET_KEY_LEN];
    getrandom::getrandom(&mut sk).expect("OS CSPRNG unavailable");
    let pk = ecvrf_public_key(&sk).expect("freshly generated 32-byte seed is valid");
    (sk, pk)
}

/// Derive the 32-byte VRF public key for a secret-key seed.
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `secret_key` is not exactly
/// [`ECVRF_SECRET_KEY_LEN`] bytes.
pub fn ecvrf_public_key(secret_key: &[u8]) -> Result<[u8; ECVRF_PUBLIC_KEY_LEN], CryptoError> {
    let sk: [u8; ECVRF_SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: ECVRF_SECRET_KEY_LEN,
                got: secret_key.len(),
            })?;
    let (mut x, mut prefix) = expand_secret(&sk);
    let pk = EdwardsPoint::mul_base(&x).compress().to_bytes();
    x.zeroize();
    prefix.zeroize();
    Ok(pk)
}

/// Produce a VRF proof `pi` (80 bytes) for `alpha` under `secret_key`.
///
/// The proof both authenticates the output and lets any verifier recompute it;
/// recover the output with [`ecvrf_proof_to_hash`], or verify and recover in one
/// step with [`ecvrf_verify`].
///
/// # Errors
/// - [`CryptoError::InvalidLength`] if `secret_key` is not
///   [`ECVRF_SECRET_KEY_LEN`] bytes.
/// - [`CryptoError::Vrf`] in the cryptographically negligible (~2^-256) event
///   that hash-to-curve finds no candidate within the counter budget.
pub fn ecvrf_prove(secret_key: &[u8], alpha: &[u8]) -> Result<[u8; ECVRF_PROOF_LEN], CryptoError> {
    let sk: [u8; ECVRF_SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: ECVRF_SECRET_KEY_LEN,
                got: secret_key.len(),
            })?;
    let (mut x, mut prefix) = expand_secret(&sk);

    let y = EdwardsPoint::mul_base(&x);
    let pk = y.compress();
    let Some(h) = hash_to_curve_tai(pk.as_bytes(), alpha) else {
        x.zeroize();
        prefix.zeroize();
        return Err(CryptoError::Vrf(
            "hash-to-curve found no candidate point within the counter budget".into(),
        ));
    };
    let gamma = x * h;

    // ECVRF_nonce_generation_RFC8032 (RFC 9381 §5.4.2.2): k = SHA-512(nonce
    // prefix || H), reduced into a scalar.
    let mut nonce_input = Sha512::new();
    nonce_input.update(prefix);
    nonce_input.update(h.compress().as_bytes());
    let k_wide: [u8; 64] = nonce_input.finalize().into();
    let mut k = Scalar::from_bytes_mod_order_wide(&k_wide);

    let c = challenge([&y, &h, &gamma, &EdwardsPoint::mul_base(&k), &(k * h)]);
    let s = k + c * x;

    let mut pi = [0u8; ECVRF_PROOF_LEN];
    pi[..32].copy_from_slice(gamma.compress().as_bytes());
    pi[32..32 + CHALLENGE_LEN].copy_from_slice(&c.as_bytes()[..CHALLENGE_LEN]);
    pi[32 + CHALLENGE_LEN..].copy_from_slice(s.as_bytes());

    x.zeroize();
    k.zeroize();
    prefix.zeroize();
    Ok(pi)
}

/// Verify a VRF proof `pi` for `alpha` under `public_key`.
///
/// Returns:
/// - `Ok(Some(beta))` — the 64-byte output — if the proof is valid.
/// - `Ok(None)` for any *cryptographic* rejection: a public key or `Gamma` that
///   is not a valid/canonical point, a non-canonical `s`, or a challenge
///   mismatch (wrong key, tampered input, or forged proof).
/// - `Err(CryptoError::InvalidLength)` if `public_key` or `proof` is not the
///   exact expected length (a *structural*, not cryptographic, failure).
pub fn ecvrf_verify(
    public_key: &[u8],
    alpha: &[u8],
    proof: &[u8],
) -> Result<Option<[u8; ECVRF_OUTPUT_LEN]>, CryptoError> {
    let pk_bytes: [u8; ECVRF_PUBLIC_KEY_LEN] =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: ECVRF_PUBLIC_KEY_LEN,
                got: public_key.len(),
            })?;
    let pi: [u8; ECVRF_PROOF_LEN] = proof.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: ECVRF_PROOF_LEN,
        got: proof.len(),
    })?;

    let Some(y) = CompressedEdwardsY(pk_bytes).decompress() else {
        return Ok(None);
    };
    // Reject small-order / mixed-order public keys (no honest key is small
    // order); this rules out degenerate keys before any further work.
    if y.is_small_order() {
        return Ok(None);
    }

    // Decode pi = Gamma(32) || c(16) || s(32).
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&pi[..32]);
    let Some(gamma) = CompressedEdwardsY(gamma_bytes).decompress() else {
        return Ok(None);
    };
    let mut c_bytes = [0u8; 32];
    c_bytes[..CHALLENGE_LEN].copy_from_slice(&pi[32..32 + CHALLENGE_LEN]);
    let c = Scalar::from_bytes_mod_order(c_bytes);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&pi[32 + CHALLENGE_LEN..]);
    // Reject a non-canonical s (>= group order): a strict, malleability-free
    // decode, stronger than a silent reduction.
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return Ok(None);
    };

    let Some(h) = hash_to_curve_tai(&pk_bytes, alpha) else {
        return Ok(None);
    };

    // U = s*B - c*Y ; V = s*H - c*Gamma ; accept iff the recomputed challenge
    // matches the one carried in the proof.
    let u = EdwardsPoint::mul_base(&s) - c * y;
    let v = s * h - c * gamma;
    let c_prime = challenge([&y, &h, &gamma, &u, &v]);

    if c_prime == c {
        Ok(Some(gamma_to_hash(&gamma)))
    } else {
        Ok(None)
    }
}

/// Recover the 64-byte VRF output `beta` directly from a proof `pi`, **without**
/// verifying it.
///
/// This is only the `Gamma -> beta` mapping; it does **not** check that `pi` is
/// a valid proof for any `(public_key, alpha)`. Use it only on a proof you have
/// already verified with [`ecvrf_verify`] (which returns `beta` on success), or
/// when you independently trust the proof's provenance.
///
/// # Errors
/// - [`CryptoError::InvalidLength`] if `proof` is not [`ECVRF_PROOF_LEN`] bytes.
/// - [`CryptoError::Vrf`] if the `Gamma` component is not a valid curve point.
pub fn ecvrf_proof_to_hash(proof: &[u8]) -> Result<[u8; ECVRF_OUTPUT_LEN], CryptoError> {
    let pi: [u8; ECVRF_PROOF_LEN] = proof.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: ECVRF_PROOF_LEN,
        got: proof.len(),
    })?;
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&pi[..32]);
    let gamma = CompressedEdwardsY(gamma_bytes)
        .decompress()
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

    /// RFC 9381 Appendix B.3 known-answer vectors for
    /// ECVRF-EDWARDS25519-SHA512-TAI. Locking `(PK, pi, beta)` for each `(SK,
    /// alpha)` proves byte-for-byte agreement with the standard, so any
    /// independent verifier (or a future cross-language SDK) interoperates.
    fn rfc9381_tai_kat(sk: &str, pk: &str, alpha: &str, pi: &str, beta: &str) {
        let sk = hex(sk);
        let pk = hex(pk);
        let alpha = hex(alpha);
        let pi = hex(pi);
        let beta = hex(beta);

        assert_eq!(ecvrf_public_key(&sk).unwrap().as_slice(), &pk[..], "PK");
        assert_eq!(ecvrf_prove(&sk, &alpha).unwrap().as_slice(), &pi[..], "pi");
        assert_eq!(
            ecvrf_proof_to_hash(&pi).unwrap().as_slice(),
            &beta[..],
            "beta"
        );

        // Verification accepts and returns the same beta.
        assert_eq!(
            ecvrf_verify(&pk, &alpha, &pi).unwrap().map(|b| b.to_vec()),
            Some(beta),
            "verify"
        );
    }

    #[test]
    fn rfc9381_example_16_empty_alpha() {
        rfc9381_tai_kat(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
             26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab126\
             8a1b0db10836d9826a528ca76567805",
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff\
             66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        );
    }

    #[test]
    fn rfc9381_example_17_one_byte_alpha() {
        rfc9381_tai_kat(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593\
             3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da\
             3ef39226bbc355bdc9850112c8f4b02",
            "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb\
             5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        );
    }

    #[test]
    fn rfc9381_example_18_two_byte_alpha() {
        rfc9381_tai_kat(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80\
             96bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2\
             d41b00b05081ed0f58ee5e31b3a970e",
            "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45\
             2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        );
    }

    #[test]
    fn prove_verify_roundtrip() {
        let (sk, pk) = ecvrf_generate_keypair();
        let alpha = b"directory identity index";
        let pi = ecvrf_prove(&sk, alpha).unwrap();
        let beta = ecvrf_verify(&pk, alpha, &pi).unwrap();
        assert_eq!(beta, Some(ecvrf_proof_to_hash(&pi).unwrap()));
    }

    #[test]
    fn derived_public_key_matches_keygen() {
        let (sk, pk) = ecvrf_generate_keypair();
        assert_eq!(ecvrf_public_key(&sk).unwrap(), pk);
    }

    #[test]
    fn output_is_deterministic_for_same_input() {
        let (sk, _pk) = ecvrf_generate_keypair();
        let pi1 = ecvrf_prove(&sk, b"x").unwrap();
        let pi2 = ecvrf_prove(&sk, b"x").unwrap();
        // TAI ECVRF is fully deterministic: same key + input => same proof.
        assert_eq!(pi1, pi2);
    }

    #[test]
    fn distinct_inputs_give_distinct_outputs() {
        let (sk, _pk) = ecvrf_generate_keypair();
        let b1 = ecvrf_proof_to_hash(&ecvrf_prove(&sk, b"a").unwrap()).unwrap();
        let b2 = ecvrf_proof_to_hash(&ecvrf_prove(&sk, b"b").unwrap()).unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn tampered_alpha_is_rejected() {
        let (sk, pk) = ecvrf_generate_keypair();
        let pi = ecvrf_prove(&sk, b"original").unwrap();
        assert_eq!(ecvrf_verify(&pk, b"tampered", &pi).unwrap(), None);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (sk, _pk) = ecvrf_generate_keypair();
        let (_other_sk, other_pk) = ecvrf_generate_keypair();
        let pi = ecvrf_prove(&sk, b"msg").unwrap();
        assert_eq!(ecvrf_verify(&other_pk, b"msg", &pi).unwrap(), None);
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (sk, pk) = ecvrf_generate_keypair();
        let pi = ecvrf_prove(&sk, b"msg").unwrap();
        // Flip a bit in each component (Gamma, c, s) and confirm each rejects.
        for idx in [0usize, 33, 79] {
            let mut bad = pi;
            bad[idx] ^= 0x01;
            assert_eq!(ecvrf_verify(&pk, b"msg", &bad).unwrap(), None, "idx {idx}");
        }
        // Sanity: the untouched proof still verifies.
        assert!(ecvrf_verify(&pk, b"msg", &pi).unwrap().is_some());
    }

    #[test]
    fn bad_lengths_are_structural_errors() {
        let (sk, pk) = ecvrf_generate_keypair();
        let pi = ecvrf_prove(&sk, b"m").unwrap();
        assert!(matches!(
            ecvrf_public_key(&[0u8; 31]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ecvrf_prove(&[0u8; 33], b"m"),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ecvrf_verify(&[0u8; 31], b"m", &pi),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ecvrf_verify(&pk, b"m", &[0u8; 79]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            ecvrf_proof_to_hash(&[0u8; 81]),
            Err(CryptoError::InvalidLength { .. })
        ));
    }

    #[test]
    fn small_order_public_key_is_rejected_not_errored() {
        let (sk, _pk) = ecvrf_generate_keypair();
        let pi = ecvrf_prove(&sk, b"m").unwrap();
        // 32 zero bytes is the identity (small order): a cryptographic reject.
        assert_eq!(ecvrf_verify(&[0u8; 32], b"m", &pi).unwrap(), None);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prove_then_verify_always_accepts(seed: [u8; 32], alpha: Vec<u8>) {
            let pk = ecvrf_public_key(&seed).unwrap();
            let pi = ecvrf_prove(&seed, &alpha).unwrap();
            let beta = ecvrf_verify(&pk, &alpha, &pi).unwrap();
            prop_assert_eq!(beta, Some(ecvrf_proof_to_hash(&pi).unwrap()));
        }

        #[test]
        fn verify_rejects_under_a_different_input(
            seed: [u8; 32],
            alpha: Vec<u8>,
            other: Vec<u8>,
        ) {
            prop_assume!(alpha != other);
            let pk = ecvrf_public_key(&seed).unwrap();
            let pi = ecvrf_prove(&seed, &alpha).unwrap();
            prop_assert_eq!(ecvrf_verify(&pk, &other, &pi).unwrap(), None);
        }
    }
}
