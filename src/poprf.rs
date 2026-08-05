//! Partially Oblivious Pseudorandom Function (POPRF) — RFC 9497,
//! **OPRF(ristretto255, SHA-512)** suite.
//!
//! A POPRF lets a client compute a keyed, deterministic pseudorandom value over
//! its private input **without the server ever seeing that input**: the client
//! blinds its input, the server evaluates the blinded element under its secret
//! key and returns a DLEQ proof, and the client unblinds and verifies. Both
//! parties additionally bind a *public* `info` string (the "partially" in
//! partially oblivious) — the server never learns the private input, and the
//! client cannot evaluate without the server's key.
//!
//! ## Why this lives here
//!
//! [`metamorphic-log`]'s CONIKS-style key-transparency layer derives a private
//! tree index from a (private) identity. With the classical VRF
//! ([`crate::vrf`]) the server must see the cleartext identity at query time to
//! produce its proof. With this POPRF the same deterministic index is derived
//! **obliviously**: the query-time cleartext-label exposure disappears while
//! the tree, proofs, and log format stay unchanged. This is the construction
//! deployed at scale by WhatsApp Key Transparency, pinned byte-for-byte by
//! RFC 9497's own test vectors (see the module tests).
//!
//! ## Which construction, and why this one
//!
//! This is **RFC 9497 modePOPRF (`0x02`), suite OPRF(ristretto255, SHA-512)**
//! (suite identifier `"ristretto255-SHA512"`): the ristretto255 prime-order
//! group ([RFC 9496]) over Curve25519, SHA-512, and RFC 9380
//! `hash_to_ristretto255` (XMD expand). It is built **entirely on the curve
//! arithmetic this crate already depends on** (`curve25519-dalek`, the same
//! backend behind [`crate::ed25519`] and [`crate::vrf`]) plus SHA-512 — no new
//! curve stack, no parallel crypto. Only the POPRF mode is implemented (the
//! OPRF/VOPRF modes share the same machinery and are a deliberate future
//! addition if a consumer needs them); the mode octet is bound into every
//! domain separator, so a POPRF transcript can never be reinterpreted under
//! another mode.
//!
//! ## Post-quantum posture (honest framing)
//!
//! 2HashDH blinding is **classical** (elliptic-curve discrete log): recorded
//! evaluation transcripts are not post-quantum private — a future quantum
//! adversary could unblind them (harvest-now/unblind-later). This protects
//! exactly one property, *query-time index privacy against the operator today*,
//! and it does so completely: the server provably never sees the cleartext
//! label. Authenticity, integrity, and confidentiality elsewhere in the stack
//! are post-quantum from day one (ML-DSA hybrid signatures, SHA3-512
//! commitments) and do not rely on this primitive. The post-quantum-privacy
//! research track (a lattice VRF/POPRF) is followed separately; none exists in
//! audited production form today. These primitives are not FIPS-validated, and
//! this crate makes no such claim.
//!
//! ## Wire formats (stable — reproduce exactly for cross-language parity)
//!
//! ```text
//! secret key  (skS): 32 bytes   (canonical little-endian scalar, top 3 bits 0)
//! public key  (pkS): 32 bytes   (ristretto255 encoding of skS * B)
//! blind            : 32 bytes   (canonical scalar — client-side state, secret)
//! blinded element  : 32 bytes   (ristretto255 encoding)
//! evaluated element: 32 bytes   (ristretto255 encoding)
//! tweaked key      : 32 bytes   (ristretto255 encoding of (skS + m) * B,
//!                                m = HashToScalar("Info" || len16(info) || info))
//! DLEQ proof       : 64 bytes   = c (32, canonical scalar) || s (32)
//! output           : 64 bytes   = SHA-512(len16(input) || input ||
//!                                  len16(info) || info ||
//!                                  len16(unblinded) || unblinded || "Finalize")
//! ```
//!
//! All element encodings are the 32-byte ristretto255 canonical form; scalars
//! are the canonical 32-byte little-endian form, exactly as in RFC 9496 /
//! RFC 9497. `len16(x)` is `I2OSP(len(x), 2)` (big-endian u16 length prefix).
//!
//! [RFC 9496]: https://www.rfc-editor.org/rfc/rfc9496.html
//! [`metamorphic-log`]: https://github.com/moss-piglet/metamorphic-log

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto, traits::Identity};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::CryptoError;

/// POPRF secret-key length, in bytes (a canonical ristretto255 scalar).
pub const POPRF_SECRET_KEY_LEN: usize = 32;
/// POPRF public-key length, in bytes (a ristretto255-encoded element).
pub const POPRF_PUBLIC_KEY_LEN: usize = 32;
/// Blinded / evaluated element length, in bytes (ristretto255 encoding).
pub const POPRF_ELEMENT_LEN: usize = 32;
/// Client blind length, in bytes (a canonical scalar; client-side state).
pub const POPRF_BLIND_LEN: usize = 32;
/// Scalar length, in bytes (canonical little-endian ristretto255 scalar) —
/// blinds and DLEQ nonces alike.
const POPRF_SCALAR_LEN: usize = 32;
/// DLEQ proof length, in bytes: `c (32) || s (32)`.
pub const POPRF_PROOF_LEN: usize = 64;
/// POPRF output length, in bytes (a SHA-512 digest).
pub const POPRF_OUTPUT_LEN: usize = 64;
/// [`poprf_derive_key_pair`] seed length, in bytes (RFC 9497 §3.2.1).
pub const POPRF_SEED_LEN: usize = 32;

/// The metamorphic CONIKS index-derivation binding identifier for this
/// construction, mixed into the CONIKS leaf hash exactly as the RFC 9381 VRF
/// suite octets are (`metamorphic_log::coniks`).
///
/// This is **not** an RFC 9497 identifier — RFC 9497 names this suite with the
/// ASCII string `"ristretto255-SHA512"` — and it is **not** an RFC 9381 suite
/// octet. It is a private allocation (`0x80`, above the RFC 9381 registered
/// range `0x01–0x04`) so a POPRF-derived tree can never be confused with a
/// VRF-derived one at the byte level.
pub const POPRF_RISTRETTO255_SHA512_SUITE: u8 = 0x80;

// RFC 9497 §3.1: contextString = "OPRFV1-" || I2OSP(modePOPRF, 1) || "-" ||
// identifier, with modePOPRF = 0x02 and identifier = "ristretto255-SHA512"
// (i.e. "OPRFV1-\x02-ristretto255-SHA512", embedded in every DST below and
// pinned by the `dsts_embed_the_poprf_context_string` test). RFC 9497 §4.1
// domain-separation tags: `DeriveKeyPair` is concatenated with the context
// string *without* a dash (§3.2.1); the others carry the dash as specified.
const HASH_TO_GROUP_DST: &[u8] = b"HashToGroup-OPRFV1-\x02-ristretto255-SHA512";
const HASH_TO_SCALAR_DST: &[u8] = b"HashToScalar-OPRFV1-\x02-ristretto255-SHA512";
const DERIVE_KEY_PAIR_DST: &[u8] = b"DeriveKeyPairOPRFV1-\x02-ristretto255-SHA512";
const SEED_DST: &[u8] = b"Seed-OPRFV1-\x02-ristretto255-SHA512";

/// The result of [`poprf_blind`]: the client's secret `blind` (kept local),
/// the `blinded_element` (sent to the server), and the `tweaked_key` (kept
/// local; binds the evaluation to `info` and the server's public key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoprfBlindState {
    /// The client's secret blind scalar (canonical encoding). Handle as secret
    /// material for the life of one evaluation; it is what unblinds the
    /// server's response.
    pub blind: [u8; POPRF_BLIND_LEN],
    /// The blinded element to send to the server (ristretto255 encoding).
    pub blinded_element: [u8; POPRF_ELEMENT_LEN],
    /// The tweaked public key `HashToScalar("Info" || len16(info) || info) * B
    /// + pkS` the server's DLEQ proof verifies against (ristretto255 encoding).
    pub tweaked_key: [u8; POPRF_PUBLIC_KEY_LEN],
}

/// `I2OSP(len(x), 2) || x` — the RFC 9497 two-byte big-endian length framing.
fn push_len16(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice((x.len() as u16).to_be_bytes().as_slice());
    out.extend_from_slice(x);
}

/// RFC 9380 §5.3.1 `expand_message_xmd` over SHA-512.
///
/// `DST` values used here are all well under the 255-byte `DST_prime` limit.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 64; // SHA-512 output length
    const S_IN_BYTES: usize = 128; // SHA-512 input block length
    debug_assert!(dst.len() <= 255, "DST too long for DST_prime framing");

    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    // DST_prime = DST || I2OSP(len(DST), 1) — the length byte is a SUFFIX
    // (RFC 9380 §5.3.1 step 3; a late change from the draft, easy to invert).
    let mut dst_prime = Vec::with_capacity(1 + dst.len());
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut h = Sha512::new();
    h.update([0u8; S_IN_BYTES]);
    h.update(msg);
    h.update((len_in_bytes as u16).to_be_bytes());
    h.update([0u8]);
    h.update(&dst_prime);
    let b_0: [u8; B_IN_BYTES] = h.finalize().into();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h = Sha512::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut b_prev: [u8; B_IN_BYTES] = h.finalize().into();

    let mut uniform = Vec::with_capacity(ell * B_IN_BYTES);
    uniform.extend_from_slice(&b_prev);
    for i in 2..=ell {
        // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime)
        let mut xored = [0u8; B_IN_BYTES];
        for (x, (a, b)) in xored.iter_mut().zip(b_0.iter().zip(b_prev.iter())) {
            *x = a ^ b;
        }
        let mut h = Sha512::new();
        h.update(xored);
        h.update([i as u8]);
        h.update(&dst_prime);
        b_prev = h.finalize().into();
        uniform.extend_from_slice(&b_prev);
    }
    uniform.truncate(len_in_bytes);
    uniform
}

/// RFC 9497 §4.1 `HashToGroup`: RFC 9380 `hash_to_ristretto255` —
/// `expand_message_xmd(SHA-512, input, "HashToGroup-" || contextString, 64)`
/// fed to the ristretto255 map ([`RistrettoPoint::from_uniform_bytes`]).
fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let uniform = expand_message_xmd(input, HASH_TO_GROUP_DST, 64);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&uniform);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// RFC 9497 §4.1 `HashToScalar` under an explicit DST:
/// `expand_message_xmd(SHA-512, msg, DST, 64)` interpreted as a 512-bit
/// little-endian integer reduced modulo the group order.
fn hash_to_scalar_with_dst(dst: &[u8], msg: &[u8]) -> Scalar {
    let uniform = expand_message_xmd(msg, dst, 64);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&uniform);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// RFC 9497 §4.1 `HashToScalar` under the suite DST.
fn hash_to_scalar(msg: &[u8]) -> Scalar {
    hash_to_scalar_with_dst(HASH_TO_SCALAR_DST, msg)
}

/// Serialize an element (ristretto255 canonical encoding).
fn serialize_element(p: &RistrettoPoint) -> [u8; POPRF_ELEMENT_LEN] {
    p.compress().to_bytes()
}

/// RFC 9497 §4.1 `DeserializeElement`: ristretto255 decode, rejecting the
/// identity element (and any non-canonical encoding, which the ristretto255
/// decode already rejects).
fn deserialize_element(bytes: &[u8; POPRF_ELEMENT_LEN]) -> Option<RistrettoPoint> {
    let point = CompressedRistretto(*bytes).decompress()?;
    if point == RistrettoPoint::identity() {
        None
    } else {
        Some(point)
    }
}

/// RFC 9497 §4.1 `DeserializeScalar`: canonical little-endian scalar (the top
/// three bits must be zero — a strict, malleability-free decode).
fn deserialize_scalar(bytes: &[u8; POPRF_SCALAR_LEN]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
}

/// The public-input tweak scalar: `m = HashToScalar("Info" || len16(info) ||
/// info)` (RFC 9497 §3.3.3).
fn tweak_scalar(info: &[u8]) -> Scalar {
    let mut framed = Vec::with_capacity(4 + 2 + info.len());
    framed.extend_from_slice(b"Info");
    push_len16(&mut framed, info);
    hash_to_scalar(&framed)
}

/// A uniformly random nonzero scalar from the OS CSPRNG (RFC 9497 §2.1
/// `RandomScalar`, rejection-sampling the measure-zero case).
fn random_scalar() -> Scalar {
    loop {
        let mut wide = [0u8; 64];
        getrandom::getrandom(&mut wide).expect("OS CSPRNG unavailable");
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        if scalar != Scalar::ZERO {
            return scalar;
        }
    }
}

/// RFC 9497 §2.2.1 `ComputeCompositesFast` (the server-side composite
/// optimization): `M = Σ d_i * C[i]`, `Z = k * M` with
/// `d_i = HashToScalar(len16(seed) || seed || I2OSP(i, 2) || len16(C_i) ||
/// C_i || len16(D_i) || D_i || "Composite")` and
/// `seed = SHA-512(len16(Bm) || Bm || len16(seedDST) || seedDST)`.
fn compute_composites_fast(
    k: &Scalar,
    b: &RistrettoPoint,
    c: &[RistrettoPoint],
    d: &[RistrettoPoint],
) -> (RistrettoPoint, RistrettoPoint) {
    let bm = serialize_element(b);
    let mut seed_transcript = Vec::with_capacity(2 + 32 + 2 + SEED_DST.len());
    push_len16(&mut seed_transcript, &bm);
    push_len16(&mut seed_transcript, SEED_DST);
    let seed: [u8; 64] = Sha512::digest(&seed_transcript).into();

    let mut m = RistrettoPoint::identity();
    for (i, (c_i, d_i)) in c.iter().zip(d.iter()).enumerate() {
        let ci = serialize_element(c_i);
        let di_bytes = serialize_element(d_i);
        let mut transcript = Vec::with_capacity(2 + 64 + 2 + 2 + 32 + 2 + 32 + 9);
        push_len16(&mut transcript, &seed);
        transcript.extend_from_slice((i as u16).to_be_bytes().as_slice());
        push_len16(&mut transcript, &ci);
        push_len16(&mut transcript, &di_bytes);
        transcript.extend_from_slice(b"Composite");
        let di = hash_to_scalar(&transcript);
        m = di * c_i + m;
    }
    (m, k * m)
}

/// RFC 9497 §2.2.2 `ComputeComposites` (the verifier side): identical to the
/// fast path except `Z = Σ d_i * D[i]` (no secret key required).
fn compute_composites(
    b: &RistrettoPoint,
    c: &[RistrettoPoint],
    d: &[RistrettoPoint],
) -> (RistrettoPoint, RistrettoPoint) {
    let bm = serialize_element(b);
    let mut seed_transcript = Vec::with_capacity(2 + 32 + 2 + SEED_DST.len());
    push_len16(&mut seed_transcript, &bm);
    push_len16(&mut seed_transcript, SEED_DST);
    let seed: [u8; 64] = Sha512::digest(&seed_transcript).into();

    let mut m = RistrettoPoint::identity();
    let mut z = RistrettoPoint::identity();
    for (i, (c_i, d_i)) in c.iter().zip(d.iter()).enumerate() {
        let ci = serialize_element(c_i);
        let di_bytes = serialize_element(d_i);
        let mut transcript = Vec::with_capacity(2 + 64 + 2 + 2 + 32 + 2 + 32 + 9);
        push_len16(&mut transcript, &seed);
        transcript.extend_from_slice((i as u16).to_be_bytes().as_slice());
        push_len16(&mut transcript, &ci);
        push_len16(&mut transcript, &di_bytes);
        transcript.extend_from_slice(b"Composite");
        let di = hash_to_scalar(&transcript);
        m = di * c_i + m;
        z = di * d_i + z;
    }
    (m, z)
}

/// The shared DLEQ challenge transcript (RFC 9497 §2.2):
/// `HashToScalar(len16(Bm) || Bm || len16(M) || M || len16(Z) || Z ||
/// len16(t2) || t2 || len16(t3) || t3 || "Challenge")`.
fn dleq_challenge(
    b: &RistrettoPoint,
    m: &RistrettoPoint,
    z: &RistrettoPoint,
    t2: &RistrettoPoint,
    t3: &RistrettoPoint,
) -> Scalar {
    let mut transcript = Vec::with_capacity(5 * (2 + 32) + 9);
    push_len16(&mut transcript, &serialize_element(b));
    push_len16(&mut transcript, &serialize_element(m));
    push_len16(&mut transcript, &serialize_element(z));
    push_len16(&mut transcript, &serialize_element(t2));
    push_len16(&mut transcript, &serialize_element(t3));
    transcript.extend_from_slice(b"Challenge");
    hash_to_scalar(&transcript)
}

/// RFC 9497 §2.2.1 `GenerateProof` with an explicit random nonce `r` (the
/// KAT-deterministic core of [`poprf_blind_evaluate`]): proves
/// `k * A == B` and `k * C[i] == D[i]` as `c || s` with `s = r - c * k`.
fn generate_proof_with_random(
    k: &Scalar,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    c: &[RistrettoPoint],
    d: &[RistrettoPoint],
    mut r: Scalar,
) -> [u8; POPRF_PROOF_LEN] {
    let (m, z) = compute_composites_fast(k, b, c, d);
    let t2 = r * a;
    let t3 = r * m;
    let challenge = dleq_challenge(b, &m, &z, &t2, &t3);
    let s = r - challenge * k;
    r.zeroize();

    let mut proof = [0u8; POPRF_PROOF_LEN];
    proof[..32].copy_from_slice(challenge.as_bytes());
    proof[32..].copy_from_slice(s.as_bytes());
    proof
}

/// RFC 9497 §2.2.2 `VerifyProof`: recompute the challenge from public inputs
/// and accept iff it matches the one carried in the proof.
fn verify_proof(
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    c: &[RistrettoPoint],
    d: &[RistrettoPoint],
    proof: &[u8; POPRF_PROOF_LEN],
) -> bool {
    let Some(challenge) = deserialize_scalar(proof[..32].try_into().expect("32-byte slice")) else {
        return false;
    };
    let Some(s) = deserialize_scalar(proof[32..].try_into().expect("32-byte slice")) else {
        return false;
    };

    let (m, z) = compute_composites(b, c, d);
    let t2 = s * a + challenge * b;
    let t3 = s * m + challenge * z;
    let expected = dleq_challenge(b, &m, &z, &t2, &t3);
    expected == challenge
}

/// Generate a fresh POPRF keypair from the OS CSPRNG, returning
/// `(secret_key, public_key)` (RFC 9497 §3.2 `GenerateKeyPair`).
///
/// Intended for tests, tooling, and first-time operator provisioning; a
/// deployment that needs a stable, re-derivable key uses
/// [`poprf_derive_key_pair`] instead.
#[must_use]
pub fn poprf_generate_keypair() -> ([u8; POPRF_SECRET_KEY_LEN], [u8; POPRF_PUBLIC_KEY_LEN]) {
    let mut sk = random_scalar();
    let pk = serialize_element(&RistrettoPoint::mul_base(&sk));
    let mut sk_bytes = [0u8; POPRF_SECRET_KEY_LEN];
    sk_bytes.copy_from_slice(sk.as_bytes());
    sk.zeroize();
    (sk_bytes, pk)
}

/// Derive a POPRF keypair deterministically from a 32-byte `seed` and a public
/// `info` string (RFC 9497 §3.2.1 `DeriveKeyPair`). This is how an operator
/// re-derives a stable deployment key from a managed master secret.
///
/// # Errors
/// - [`CryptoError::InvalidLength`] if `seed` is not exactly
///   [`POPRF_SEED_LEN`] bytes.
/// - [`CryptoError::Poprf`] in the cryptographically negligible event that all
///   256 counter candidates map to the zero scalar (RFC 9497
///   `DeriveKeyPairError`).
pub fn poprf_derive_key_pair(
    seed: &[u8],
    info: &[u8],
) -> Result<([u8; POPRF_SECRET_KEY_LEN], [u8; POPRF_PUBLIC_KEY_LEN]), CryptoError> {
    if seed.len() != POPRF_SEED_LEN {
        return Err(CryptoError::InvalidLength {
            expected: POPRF_SEED_LEN,
            got: seed.len(),
        });
    }
    let mut derive_input = Vec::with_capacity(POPRF_SEED_LEN + 2 + info.len() + 1);
    derive_input.extend_from_slice(seed);
    push_len16(&mut derive_input, info);

    for counter in 0u8..=u8::MAX {
        derive_input.truncate(POPRF_SEED_LEN + 2 + info.len());
        derive_input.push(counter);
        let mut sk = hash_to_scalar_with_dst(DERIVE_KEY_PAIR_DST, &derive_input);
        if sk != Scalar::ZERO {
            let pk = serialize_element(&RistrettoPoint::mul_base(&sk));
            let mut sk_bytes = [0u8; POPRF_SECRET_KEY_LEN];
            sk_bytes.copy_from_slice(sk.as_bytes());
            sk.zeroize();
            return Ok((sk_bytes, pk));
        }
        sk.zeroize();
    }
    Err(CryptoError::Poprf(
        "DeriveKeyPair found no nonzero scalar within the counter budget".into(),
    ))
}

/// Derive the 32-byte POPRF public key for a secret key: `pkS = skS * B`.
///
/// # Errors
/// Returns [`CryptoError::InvalidLength`] if `secret_key` is not exactly
/// [`POPRF_SECRET_KEY_LEN`] bytes, or [`CryptoError::Poprf`] if it is not a
/// canonical scalar.
pub fn poprf_public_key(secret_key: &[u8]) -> Result<[u8; POPRF_PUBLIC_KEY_LEN], CryptoError> {
    let sk_bytes: [u8; POPRF_SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: POPRF_SECRET_KEY_LEN,
                got: secret_key.len(),
            })?;
    let mut sk = deserialize_scalar(&sk_bytes)
        .ok_or_else(|| CryptoError::Poprf("secret key is not a canonical scalar".into()))?;
    let pk = serialize_element(&RistrettoPoint::mul_base(&sk));
    sk.zeroize();
    Ok(pk)
}

/// The POPRF blinding step (RFC 9497 §3.3.3 `Blind`) with an explicit blind
/// scalar — the KAT-deterministic core of [`poprf_blind`].
///
/// # Errors
/// - [`CryptoError::InvalidLength`] if `public_key` or `blind` is not the exact
///   expected length.
/// - [`CryptoError::Poprf`] if `public_key` is not a valid non-identity
///   element, `blind` is not a canonical scalar, or the input/info map to a
///   degenerate element (RFC 9497 `InvalidInputError`, a ~2^-252 event).
#[doc(hidden)]
pub fn poprf_blind_with_scalar(
    input: &[u8],
    info: &[u8],
    public_key: &[u8],
    blind: &[u8],
) -> Result<PoprfBlindState, CryptoError> {
    let pk_bytes: [u8; POPRF_PUBLIC_KEY_LEN] =
        public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: POPRF_PUBLIC_KEY_LEN,
                got: public_key.len(),
            })?;
    let blind_bytes: [u8; POPRF_BLIND_LEN] =
        blind.try_into().map_err(|_| CryptoError::InvalidLength {
            expected: POPRF_BLIND_LEN,
            got: blind.len(),
        })?;
    let pk = deserialize_element(&pk_bytes)
        .ok_or_else(|| CryptoError::Poprf("public key is not a valid element".into()))?;
    let mut blind_scalar = deserialize_scalar(&blind_bytes)
        .ok_or_else(|| CryptoError::Poprf("blind is not a canonical scalar".into()))?;

    let mut m = tweak_scalar(info);
    let tweaked_key = RistrettoPoint::mul_base(&m) + pk;
    m.zeroize();
    if tweaked_key == RistrettoPoint::identity() {
        blind_scalar.zeroize();
        return Err(CryptoError::Poprf(
            "tweaked key is the identity element (InvalidInputError)".into(),
        ));
    }

    let input_element = hash_to_group(input);
    if input_element == RistrettoPoint::identity() {
        blind_scalar.zeroize();
        return Err(CryptoError::Poprf(
            "input maps to the identity element (InvalidInputError)".into(),
        ));
    }
    let blinded_element = blind_scalar * input_element;

    let state = PoprfBlindState {
        blind: blind_bytes,
        blinded_element: serialize_element(&blinded_element),
        tweaked_key: serialize_element(&tweaked_key),
    };
    blind_scalar.zeroize();
    Ok(state)
}

/// The POPRF blinding step (RFC 9497 §3.3.3 `Blind`) with a fresh OS-CSPRNG
/// blind.
///
/// The client keeps `blind` and `tweaked_key` local and sends only
/// `blinded_element` to the server — the server never sees `input`.
///
/// # Errors
/// Same as [`poprf_blind_with_scalar`].
pub fn poprf_blind(
    input: &[u8],
    info: &[u8],
    public_key: &[u8],
) -> Result<PoprfBlindState, CryptoError> {
    let mut blind = random_scalar();
    let mut blind_bytes = [0u8; POPRF_BLIND_LEN];
    blind_bytes.copy_from_slice(blind.as_bytes());
    blind.zeroize();
    poprf_blind_with_scalar(input, info, public_key, &blind_bytes)
}

/// The server-side blind evaluation (RFC 9497 §3.3.3 `BlindEvaluate`) with an
/// explicit DLEQ nonce — the KAT-deterministic core of
/// [`poprf_blind_evaluate`].
///
/// Computes `t = skS + HashToScalar("Info" || len16(info) || info)`,
/// `evaluatedElement = t⁻¹ * blindedElement`, and a DLEQ proof that
/// `log_G(tweakedKey) == log_{evaluatedElement}(blindedElement)` for
/// `tweakedKey = t * B`.
///
/// # Errors
/// - [`CryptoError::InvalidLength`] if any fixed-size input is the wrong
///   length.
/// - [`CryptoError::Poprf`] if the secret key or nonce is not a canonical
///   scalar, the blinded element is not a valid non-identity element, or
///   `t == 0` (RFC 9497 `InverseError` — per the RFC this signals the client
///   likely knows the server key; treat as a key-rotation trigger).
#[doc(hidden)]
pub fn poprf_blind_evaluate_with_random(
    secret_key: &[u8],
    blinded_element: &[u8],
    info: &[u8],
    random: &[u8],
) -> Result<([u8; POPRF_ELEMENT_LEN], [u8; POPRF_PROOF_LEN]), CryptoError> {
    let sk_bytes: [u8; POPRF_SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: POPRF_SECRET_KEY_LEN,
                got: secret_key.len(),
            })?;
    let blinded_bytes: [u8; POPRF_ELEMENT_LEN] =
        blinded_element
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: POPRF_ELEMENT_LEN,
                got: blinded_element.len(),
            })?;
    let random_bytes: [u8; POPRF_SCALAR_LEN] =
        random.try_into().map_err(|_| CryptoError::InvalidLength {
            expected: POPRF_SCALAR_LEN,
            got: random.len(),
        })?;

    let mut sk = deserialize_scalar(&sk_bytes)
        .ok_or_else(|| CryptoError::Poprf("secret key is not a canonical scalar".into()))?;
    let blinded = deserialize_element(&blinded_bytes)
        .ok_or_else(|| CryptoError::Poprf("blinded element is not a valid element".into()))?;
    let r = deserialize_scalar(&random_bytes)
        .ok_or_else(|| CryptoError::Poprf("DLEQ nonce is not a canonical scalar".into()))?;

    let mut m = tweak_scalar(info);
    let mut t = sk + m;
    sk.zeroize();
    m.zeroize();
    if t == Scalar::ZERO {
        t.zeroize();
        return Err(CryptoError::Poprf(
            "tweaked secret key is zero (InverseError): rotate the server key".into(),
        ));
    }

    let evaluated = t.invert() * blinded;
    let tweaked_key = RistrettoPoint::mul_base(&t);
    let proof = generate_proof_with_random(
        &t,
        &RistrettoPoint::mul_base(&Scalar::ONE),
        &tweaked_key,
        &[evaluated],
        &[blinded],
        r,
    );
    t.zeroize();
    Ok((serialize_element(&evaluated), proof))
}

/// The server-side blind evaluation (RFC 9497 §3.3.3 `BlindEvaluate`) with a
/// fresh OS-CSPRNG DLEQ nonce. Returns `(evaluated_element, dleq_proof)`.
///
/// The server learns nothing about the client's input: `blinded_element` is a
/// uniformly random-looking group element.
///
/// # Errors
/// Same as [`poprf_blind_evaluate_with_random`].
pub fn poprf_blind_evaluate(
    secret_key: &[u8],
    blinded_element: &[u8],
    info: &[u8],
) -> Result<([u8; POPRF_ELEMENT_LEN], [u8; POPRF_PROOF_LEN]), CryptoError> {
    let mut r = random_scalar();
    let mut r_bytes = [0u8; POPRF_SCALAR_LEN];
    r_bytes.copy_from_slice(r.as_bytes());
    r.zeroize();
    poprf_blind_evaluate_with_random(secret_key, blinded_element, info, &r_bytes)
}

/// The client-side completion (RFC 9497 §3.3.3 `Finalize`): verify the server's
/// DLEQ proof against `tweaked_key`, unblind, and hash to the 64-byte output.
///
/// Returns:
/// - `Ok(Some(output))` — the 64-byte PRF output — if the proof is valid.
/// - `Ok(None)` for any *cryptographic* rejection: a proof that does not
///   verify (wrong key, wrong `info`, tampered evaluation, or forgery), or a
///   non-canonical proof scalar.
/// - `Err(CryptoError::InvalidLength)` / `Err(CryptoError::Poprf)` for
///   *structural* failures (wrong lengths, invalid elements or blind).
#[allow(clippy::too_many_arguments)] // Mirrors the RFC 9497 Finalize signature one-to-one.
pub fn poprf_finalize(
    input: &[u8],
    blind: &[u8],
    evaluated_element: &[u8],
    blinded_element: &[u8],
    proof: &[u8],
    info: &[u8],
    tweaked_key: &[u8],
) -> Result<Option<[u8; POPRF_OUTPUT_LEN]>, CryptoError> {
    let blind_bytes: [u8; POPRF_BLIND_LEN] =
        blind.try_into().map_err(|_| CryptoError::InvalidLength {
            expected: POPRF_BLIND_LEN,
            got: blind.len(),
        })?;
    let evaluated_bytes: [u8; POPRF_ELEMENT_LEN] =
        evaluated_element
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: POPRF_ELEMENT_LEN,
                got: evaluated_element.len(),
            })?;
    let blinded_bytes: [u8; POPRF_ELEMENT_LEN] =
        blinded_element
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: POPRF_ELEMENT_LEN,
                got: blinded_element.len(),
            })?;
    let proof_bytes: [u8; POPRF_PROOF_LEN] =
        proof.try_into().map_err(|_| CryptoError::InvalidLength {
            expected: POPRF_PROOF_LEN,
            got: proof.len(),
        })?;
    let tweaked_bytes: [u8; POPRF_PUBLIC_KEY_LEN] =
        tweaked_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: POPRF_PUBLIC_KEY_LEN,
                got: tweaked_key.len(),
            })?;

    let mut blind_scalar = deserialize_scalar(&blind_bytes)
        .ok_or_else(|| CryptoError::Poprf("blind is not a canonical scalar".into()))?;
    let evaluated = deserialize_element(&evaluated_bytes)
        .ok_or_else(|| CryptoError::Poprf("evaluated element is not a valid element".into()))?;
    let blinded = deserialize_element(&blinded_bytes)
        .ok_or_else(|| CryptoError::Poprf("blinded element is not a valid element".into()))?;
    let tweaked = deserialize_element(&tweaked_bytes)
        .ok_or_else(|| CryptoError::Poprf("tweaked key is not a valid element".into()))?;

    if !verify_proof(
        &RistrettoPoint::mul_base(&Scalar::ONE),
        &tweaked,
        &[evaluated],
        &[blinded],
        &proof_bytes,
    ) {
        blind_scalar.zeroize();
        return Ok(None);
    }

    let unblinded = blind_scalar.invert() * evaluated;
    blind_scalar.zeroize();
    let unblinded_bytes = serialize_element(&unblinded);

    let mut hash_input =
        Vec::with_capacity(2 + input.len() + 2 + info.len() + 2 + POPRF_ELEMENT_LEN + 8);
    push_len16(&mut hash_input, input);
    push_len16(&mut hash_input, info);
    push_len16(&mut hash_input, &unblinded_bytes);
    hash_input.extend_from_slice(b"Finalize");
    Ok(Some(Sha512::digest(&hash_input).into()))
}

/// The non-oblivious server-side evaluation (RFC 9497 §3.3.3 `Evaluate`):
/// compute the PRF output directly from the secret key and the cleartext
/// `input`. An operator uses this to derive the same index the client derives
/// obliviously — e.g. when (re)constructing a directory from labels it already
/// holds.
///
/// # Errors
/// - [`CryptoError::InvalidLength`] if `secret_key` is not
///   [`POPRF_SECRET_KEY_LEN`] bytes.
/// - [`CryptoError::Poprf`] if the secret key is not a canonical scalar, the
///   input maps to the identity element, or `t == 0` (RFC 9497
///   `InverseError`).
pub fn poprf_evaluate(
    secret_key: &[u8],
    input: &[u8],
    info: &[u8],
) -> Result<[u8; POPRF_OUTPUT_LEN], CryptoError> {
    let sk_bytes: [u8; POPRF_SECRET_KEY_LEN] =
        secret_key
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                expected: POPRF_SECRET_KEY_LEN,
                got: secret_key.len(),
            })?;
    let mut sk = deserialize_scalar(&sk_bytes)
        .ok_or_else(|| CryptoError::Poprf("secret key is not a canonical scalar".into()))?;

    let input_element = hash_to_group(input);
    if input_element == RistrettoPoint::identity() {
        sk.zeroize();
        return Err(CryptoError::Poprf(
            "input maps to the identity element (InvalidInputError)".into(),
        ));
    }

    let mut m = tweak_scalar(info);
    let mut t = sk + m;
    sk.zeroize();
    m.zeroize();
    if t == Scalar::ZERO {
        t.zeroize();
        return Err(CryptoError::Poprf(
            "tweaked secret key is zero (InverseError): rotate the server key".into(),
        ));
    }
    let evaluated = t.invert() * input_element;
    t.zeroize();
    let issued = serialize_element(&evaluated);

    let mut hash_input =
        Vec::with_capacity(2 + input.len() + 2 + info.len() + 2 + POPRF_ELEMENT_LEN + 8);
    push_len16(&mut hash_input, input);
    push_len16(&mut hash_input, info);
    push_len16(&mut hash_input, &issued);
    hash_input.extend_from_slice(b"Finalize");
    Ok(Sha512::digest(&hash_input).into())
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

    // RFC 9497 Appendix A.1.3 (POPRF mode, ristretto255-SHA512) shared key
    // material: DeriveKeyPair(seed, KeyInfo) under the POPRF context string.
    const SEED: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
    const KEY_INFO: &str = "74657374206b6579"; // "test key"
    const SK_SM: &str = "145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07";
    const PK_SM: &str = "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631";
    const INFO: &str = "7465737420696e666f"; // "test info"
    const BLIND: &str = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706";
    const PROOF_RANDOM: &str = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e";

    #[test]
    fn rfc9497_derive_key_pair_matches_a1_3() {
        let (sk, pk) = poprf_derive_key_pair(&hex(SEED), &hex(KEY_INFO)).unwrap();
        assert_eq!(sk.as_slice(), &hex(SK_SM)[..], "skSm");
        assert_eq!(pk.as_slice(), &hex(PK_SM)[..], "pkSm");
        assert_eq!(poprf_public_key(&sk).unwrap().as_slice(), &hex(PK_SM)[..]);
    }

    /// One RFC 9497 A.1.3 POPRF vector, batch size 1: blind (fixed scalar),
    /// blind-evaluate (fixed DLEQ nonce), and finalize must reproduce the
    /// published BlindedElement, EvaluationElement, Proof, and Output.
    fn rfc9497_poprf_kat(input: &str, blinded: &str, evaluated: &str, proof: &str, output: &str) {
        let sk = hex(SK_SM);
        let pk = hex(PK_SM);
        let info = hex(INFO);
        let input = hex(input);
        let blind = hex(BLIND);
        let random = hex(PROOF_RANDOM);

        let state = poprf_blind_with_scalar(&input, &info, &pk, &blind).unwrap();
        assert_eq!(
            state.blinded_element.as_slice(),
            &hex(blinded)[..],
            "BlindedElement"
        );

        let (eval, pi) =
            poprf_blind_evaluate_with_random(&sk, &state.blinded_element, &info, &random).unwrap();
        assert_eq!(eval.as_slice(), &hex(evaluated)[..], "EvaluationElement");
        assert_eq!(pi.as_slice(), &hex(proof)[..], "Proof");

        let out = poprf_finalize(
            &input,
            &state.blind,
            &eval,
            &state.blinded_element,
            &pi,
            &info,
            &state.tweaked_key,
        )
        .unwrap();
        assert_eq!(out.map(|o| o.to_vec()), Some(hex(output)), "Output");

        // The non-oblivious server path derives the identical output.
        assert_eq!(
            poprf_evaluate(&sk, &input, &info).unwrap().as_slice(),
            &hex(output)[..],
            "Evaluate"
        );
    }

    #[test]
    fn rfc9497_a1_3_1_batch_1() {
        rfc9497_poprf_kat(
            "00",
            "c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715",
            "1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874",
            "41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100d\
             e32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206",
            "ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d\
             38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221",
        );
    }

    #[test]
    fn rfc9497_a1_3_2_batch_1() {
        rfc9497_poprf_kat(
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d",
            "8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540",
            "4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de7701\
             8bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908",
            "7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52\
             de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507",
        );
    }

    #[test]
    fn rfc9497_a1_3_3_batch_2() {
        // The batched DLEQ vector: one proof over two (evaluated, blinded)
        // pairs. Exercises the multi-element composites path directly.
        let sk = hex(SK_SM);
        let pk = hex(PK_SM);
        let info = hex(INFO);
        let inputs = [hex("00"), hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")];
        let blinds = [
            hex("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
            hex("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
        ];
        let expected_blinded = [
            hex("c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"),
            hex("423a01c072e06eb1cce96d23acce06e1ea64a609d7ec9e9023f3049f2d64e50c"),
        ];
        let expected_evaluated = [
            hex("1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874"),
            hex("aa1f16e903841036e38075da8a46655c94fc92341887eb5819f46312adfc0504"),
        ];
        let expected_proof = hex(
            "43fdb53be399cbd3561186ae480320caa2b9f36cca0e5b160c4a677b8bbf4301\
             b28f12c36aa8e11e5a7ef551da0781e863a6dc8c0b2bf5a149c9e00621f02006",
        );
        let random = hex("419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c");
        let expected_outputs = [
            hex(
                "ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d\
                 38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221",
            ),
            hex(
                "7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52\
                 de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507",
            ),
        ];

        // Blind both inputs with the fixed blinds.
        let states: Vec<PoprfBlindState> = inputs
            .iter()
            .zip(blinds.iter())
            .map(|(input, blind)| poprf_blind_with_scalar(input, &info, &pk, blind).unwrap())
            .collect();
        for (state, expected) in states.iter().zip(expected_blinded.iter()) {
            assert_eq!(&state.blinded_element.as_slice(), &expected.as_slice());
        }

        // Batch blind-evaluate through the internal slice-based DLEQ path.
        let sk_scalar = deserialize_scalar(&sk.clone().try_into().unwrap()).unwrap();
        let m = tweak_scalar(&info);
        let t = sk_scalar + m;
        let blinded: Vec<RistrettoPoint> = states
            .iter()
            .map(|s| deserialize_element(&s.blinded_element).unwrap())
            .collect();
        let evaluated: Vec<RistrettoPoint> = blinded.iter().map(|b| t.invert() * b).collect();
        for (ev, expected) in evaluated.iter().zip(expected_evaluated.iter()) {
            assert_eq!(&serialize_element(ev).as_slice(), &expected.as_slice());
        }
        let tweaked_key = RistrettoPoint::mul_base(&t);
        let r = deserialize_scalar(&random.clone().try_into().unwrap()).unwrap();
        let proof = generate_proof_with_random(
            &t,
            &RistrettoPoint::mul_base(&Scalar::ONE),
            &tweaked_key,
            &evaluated,
            &blinded,
            r,
        );
        assert_eq!(proof.as_slice(), &expected_proof[..], "batched Proof");

        // The batched proof verifies for the full pair list. A single-element
        // finalize recomputes a *single-element* composite, which differs from
        // the batched composite, so it must reject the batched proof; the
        // published per-input Outputs are reproduced through poprf_evaluate.
        assert!(verify_proof(
            &RistrettoPoint::mul_base(&Scalar::ONE),
            &tweaked_key,
            &evaluated,
            &blinded,
            &proof,
        ));
        for (i, state) in states.iter().enumerate() {
            assert_eq!(
                poprf_finalize(
                    &inputs[i],
                    &state.blind,
                    &serialize_element(&evaluated[i]),
                    &state.blinded_element,
                    &proof,
                    &info,
                    &state.tweaked_key,
                )
                .unwrap(),
                None,
                "single-element finalize must reject the batched proof"
            );
            assert_eq!(
                poprf_evaluate(&sk, &inputs[i], &info).unwrap().as_slice(),
                &expected_outputs[i][..],
                "Output[{i}]"
            );
        }
    }

    #[test]
    fn blind_evaluate_finalize_roundtrip() {
        let (sk, pk) = poprf_generate_keypair();
        let input = b"alice@example.com";
        let info = b"mosskeys/directory/v1:test-namespace";
        let state = poprf_blind(input, info, &pk).unwrap();
        let (eval, proof) = poprf_blind_evaluate(&sk, &state.blinded_element, info).unwrap();
        let out = poprf_finalize(
            input,
            &state.blind,
            &eval,
            &state.blinded_element,
            &proof,
            info,
            &state.tweaked_key,
        )
        .unwrap();
        assert_eq!(out, Some(poprf_evaluate(&sk, input, info).unwrap()));
    }

    #[test]
    fn derived_public_key_matches_keygen() {
        let (sk, pk) = poprf_generate_keypair();
        assert_eq!(poprf_public_key(&sk).unwrap(), pk);
    }

    #[test]
    fn output_is_deterministic_and_info_bound() {
        let (sk, _pk) = poprf_generate_keypair();
        let a = poprf_evaluate(&sk, b"label", b"info-1").unwrap();
        assert_eq!(a, poprf_evaluate(&sk, b"label", b"info-1").unwrap());
        // The public info string is cryptographically bound: a different info
        // yields an independent PRF instance.
        assert_ne!(a, poprf_evaluate(&sk, b"label", b"info-2").unwrap());
        assert_ne!(a, poprf_evaluate(&sk, b"other", b"info-1").unwrap());
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let (sk, pk) = poprf_generate_keypair();
        let info = b"info";
        let state = poprf_blind(b"msg", info, &pk).unwrap();
        let (eval, proof) = poprf_blind_evaluate(&sk, &state.blinded_element, info).unwrap();
        for idx in [0usize, 33, 63] {
            let mut bad = proof;
            bad[idx] ^= 0x01;
            assert_eq!(
                poprf_finalize(
                    b"msg",
                    &state.blind,
                    &eval,
                    &state.blinded_element,
                    &bad,
                    info,
                    &state.tweaked_key,
                )
                .unwrap(),
                None,
                "idx {idx}"
            );
        }
    }

    #[test]
    fn wrong_info_or_key_is_rejected() {
        let (sk, pk) = poprf_generate_keypair();
        let (_sk2, pk2) = poprf_generate_keypair();
        let info = b"info";
        let state = poprf_blind(b"msg", info, &pk).unwrap();
        let (eval, proof) = poprf_blind_evaluate(&sk, &state.blinded_element, info).unwrap();

        // A client that blinded under a different info (different tweaked key)
        // must reject the evaluation.
        let other = poprf_blind(b"msg", b"other-info", &pk).unwrap();
        assert_eq!(
            poprf_finalize(
                b"msg",
                &state.blind,
                &eval,
                &state.blinded_element,
                &proof,
                info,
                &other.tweaked_key,
            )
            .unwrap(),
            None
        );

        // A client that blinded under a different server key must reject.
        let other_key = poprf_blind(b"msg", info, &pk2).unwrap();
        assert_eq!(
            poprf_finalize(
                b"msg",
                &state.blind,
                &eval,
                &state.blinded_element,
                &proof,
                info,
                &other_key.tweaked_key,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn bad_lengths_are_structural_errors() {
        let (sk, pk) = poprf_generate_keypair();
        assert!(matches!(
            poprf_derive_key_pair(&[0u8; 31], b""),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            poprf_public_key(&[0u8; 33]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            poprf_blind(b"m", b"i", &pk[..31]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            poprf_blind_evaluate(&sk, &[0u8; 31], b"i"),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            poprf_finalize(
                b"m", &[0u8; 31], &[0u8; 32], &[0u8; 32], &[0u8; 64], b"i", &pk
            ),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            poprf_evaluate(&sk[..31], b"m", b"i"),
            Err(CryptoError::InvalidLength { .. })
        ));
    }

    #[test]
    fn identity_and_noncanonical_inputs_are_rejected() {
        let (sk, pk) = poprf_generate_keypair();
        // 32 zero bytes is the ristretto255 identity encoding: rejected as an
        // element everywhere (structural error server-side, None client-side).
        assert!(poprf_blind_evaluate(&sk, &[0u8; 32], b"i").is_err());
        let state = poprf_blind(b"m", b"i", &pk).unwrap();
        let (eval, proof) = poprf_blind_evaluate(&sk, &state.blinded_element, b"i").unwrap();
        assert!(
            poprf_finalize(
                b"m",
                &state.blind,
                &[0u8; 32],
                &state.blinded_element,
                &proof,
                b"i",
                &state.tweaked_key,
            )
            .is_err()
        );
        let _ = eval;
    }

    #[test]
    fn dsts_embed_the_poprf_context_string() {
        // Guards against a fat-fingered DST: every domain separator must embed
        // the exact RFC 9497 §3.1 POPRF context string
        // ("OPRFV1-" || 0x02 || "-" || "ristretto255-SHA512"), and the
        // DeriveKeyPair DST must concatenate it WITHOUT a dash (§3.2.1).
        let ctx = b"OPRFV1-\x02-ristretto255-SHA512";
        for dst in [
            HASH_TO_GROUP_DST,
            HASH_TO_SCALAR_DST,
            DERIVE_KEY_PAIR_DST,
            SEED_DST,
        ] {
            assert!(
                dst.windows(ctx.len()).any(|w| w == ctx),
                "DST {dst:?} does not embed the context string"
            );
        }
        assert!(DERIVE_KEY_PAIR_DST.starts_with(b"DeriveKeyPairOPRFV1-"));
        assert!(SEED_DST.starts_with(b"Seed-OPRFV1-"));
    }

    use proptest::prelude::*;

    #[test]
    fn rfc9380_k3_expand_message_xmd_sha512() {
        // RFC 9380 Appendix K.3, msg = "" / len 0x20.
        let dst = b"QUUX-V01-CS02-with-expander-SHA512-256";
        let out = expand_message_xmd(b"", dst, 32);
        assert_eq!(
            out,
            hex("6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba")
        );
        let out = expand_message_xmd(b"abc", dst, 32);
        assert_eq!(
            out,
            hex("0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc")
        );
    }

    proptest! {
        #[test]
        fn blind_evaluate_finalize_always_matches_evaluate(
            seed: [u8; 32],
            input: Vec<u8>,
            info: Vec<u8>,
        ) {
            let (sk, pk) = poprf_derive_key_pair(&seed, b"proptest").unwrap();
            let state = poprf_blind(&input, &info, &pk).unwrap();
            let (eval, proof) = poprf_blind_evaluate(&sk, &state.blinded_element, &info).unwrap();
            let out = poprf_finalize(
                &input,
                &state.blind,
                &eval,
                &state.blinded_element,
                &proof,
                &info,
                &state.tweaked_key,
            )
            .unwrap();
            prop_assert_eq!(out, Some(poprf_evaluate(&sk, &input, &info).unwrap()));
        }
    }
}
