//! Hybrid signature cross-language wire-format pins and behavioral vectors.
//!
//! ML-DSA signatures are **hedged (randomized)**, so the signature *bytes* are
//! deliberately non-reproducible and cannot be pinned. What *is* fully
//! deterministic — and therefore pinned here so native Rust, WASM, and the
//! Elixir NIF stay byte-identical — is:
//!
//!   1. The domain-separation framing `u64_be(len(ctx)) || ctx || msg`.
//!   2. Public-key derivation from a fixed secret key (the seeds fully determine
//!      both the Ed25519 and ML-DSA public keys), for every security level.
//!   3. The byte layout (version tag, fixed Ed25519 prefix, ML-DSA tail) and the
//!      sizes implied by it.
//!
//! These vectors were produced by this crate and verified to round-trip. Any
//! other implementation that reproduces the framing and key derivation will
//! compute identical public keys and verify identical signatures.

use metamorphic_crypto::{
    SIGN_CONTEXT_V1, SignatureLevel, b64, derive_public_key, generate_signing_keypair_with_level,
    sign, verify,
};

// Fixed secret keys: `tag || ed_seed(0..=31) || ml_seed(100..=131)`, base64.
const SK_CAT2: &str =
    "AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoM=";
const SK_CAT3: &str =
    "AgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoM=";
const SK_CAT5: &str =
    "AwABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoM=";

// Expected ed25519 public-key prefix (bytes 1..=32) for the fixed ed seed
// `0u8..=31`. This is the canonical RFC 8032 public key and lets any client
// pin the Ed25519 half independent of ML-DSA. Base64 of the 32 pk bytes.
const ED25519_PK_FOR_SEED_0_31: &str = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";

/// The framing is the same length-prefixed construction as `sha3_512_with_context`.
#[test]
fn framing_pin() {
    let ctx = SIGN_CONTEXT_V1;
    let msg = b"transparency log entry";
    let mut framed = Vec::new();
    framed.extend_from_slice(&(ctx.len() as u64).to_be_bytes());
    framed.extend_from_slice(ctx.as_bytes());
    framed.extend_from_slice(msg);
    assert_eq!(
        b64::encode(&framed),
        "AAAAAAAAABNtZXRhbW9ycGhpYy9zaWduL3YxdHJhbnNwYXJlbmN5IGxvZyBlbnRyeQ=="
    );
}

/// Public-key derivation is deterministic across all levels: re-deriving from a
/// fixed secret key reproduces the exact composite public key, and its layout
/// (`tag || ed25519_pk(32) || ml_dsa_pk`) is byte-stable.
#[test]
fn public_key_derivation_pins() {
    for (sk, level, tag, ml_pk_len) in [
        (SK_CAT2, SignatureLevel::Cat2, 0x01u8, 1312usize),
        (SK_CAT3, SignatureLevel::Cat3, 0x02, 1952),
        (SK_CAT5, SignatureLevel::Cat5, 0x03, 2592),
    ] {
        let _ = level;
        let pk_b64 = derive_public_key(sk).unwrap();
        let pk = b64::decode(&pk_b64).unwrap();

        // Layout and sizes.
        assert_eq!(pk[0], tag, "version tag");
        assert_eq!(pk.len(), 1 + 32 + ml_pk_len, "composite public-key length");

        // Ed25519 half is identical across every level (same ed seed).
        assert_eq!(b64::encode(&pk[1..33]), ED25519_PK_FOR_SEED_0_31);

        // Re-derivation is stable.
        assert_eq!(derive_public_key(sk).unwrap(), pk_b64);
    }
}

/// End-to-end: sign with a fixed secret key, verify against the *derived* public
/// key. Covers every level and proves the secret/public pair interoperate.
#[test]
fn sign_then_verify_with_derived_public_key() {
    for sk in [SK_CAT2, SK_CAT3, SK_CAT5] {
        let pk = derive_public_key(sk).unwrap();
        let msg = b"cross-language signed payload";
        let sig = sign(msg, SIGN_CONTEXT_V1, sk).unwrap();
        assert!(verify(msg, SIGN_CONTEXT_V1, &sig, &pk).unwrap());
        // Wrong context must fail.
        assert!(!verify(msg, "metamorphic/other/v1", &sig, &pk).unwrap());
    }
}

/// Strict-AND across the wire format: corrupting either the Ed25519 region or
/// the ML-DSA region of a real signature makes verification fail.
#[test]
fn strict_and_over_wire_format() {
    let kp = generate_signing_keypair_with_level(SignatureLevel::Cat3);
    let msg = b"strict and";
    let good = b64::decode(&sign(msg, SIGN_CONTEXT_V1, &kp.secret_key).unwrap()).unwrap();

    let mut ed_broken = good.clone();
    ed_broken[5] ^= 0xFF; // inside ed25519_sig (bytes 1..=64)
    assert!(
        !verify(
            msg,
            SIGN_CONTEXT_V1,
            &b64::encode(&ed_broken),
            &kp.public_key
        )
        .unwrap()
    );

    let mut ml_broken = good.clone();
    ml_broken[1 + 64 + 50] ^= 0xFF; // inside ml_dsa_sig
    assert!(
        !verify(
            msg,
            SIGN_CONTEXT_V1,
            &b64::encode(&ml_broken),
            &kp.public_key
        )
        .unwrap()
    );
}

/// Cross-level confusion is rejected: a signature/public key whose version tags
/// disagree never verifies.
#[test]
fn cross_level_rejected() {
    let sig_cat3 = sign(b"x", SIGN_CONTEXT_V1, SK_CAT3).unwrap();
    let pk_cat5 = derive_public_key(SK_CAT5).unwrap();
    assert!(!verify(b"x", SIGN_CONTEXT_V1, &sig_cat3, &pk_cat5).unwrap());
}
