//! CNSA 2.0 suite cross-language wire-format pins (v0.7.0).
//!
//! These public-API vectors lock down the byte-level contract of the new
//! `Suite::PureCnsa2` and `Suite::HybridMatched` paths so that native Rust,
//! WASM, and the Elixir NIF stay byte-identical.
//!
//! What is pinned here is everything **deterministic**:
//!
//!   * the version tags (`0x10` PureCnsa2, `0x13` matched Cat-3,
//!     `0x14` matched Cat-5) on keys / ciphertexts / signatures,
//!   * the FIPS-determined sizes (ML-KEM-1024 / ML-DSA-87 artifacts,
//!     Ed448 / ECDSA-P-521 / X448 partners),
//!   * the signature **public keys derived from fixed secret keys**
//!     (key derivation is fully deterministic; pinned via SHA3-512 digest).
//!
//! KEM/seal ciphertexts and ML-DSA / hedged-ECDSA signatures are
//! non-reproducible by design (fresh KEM secret + random GCM nonce; hedged
//! signing), so only their structure + round-trip behaviour is asserted. The
//! raw ML-KEM-1024 byte-equality with `@noble/post-quantum` is anchored by the
//! FIPS-203 KAT in `src/hybrid.rs` (`mlkem1024_fips203_kat`).

use metamorphic_crypto::{
    SEAL_CONTEXT_V1, SIGN_CONTEXT_V1, SecurityLevel, Suite, b64, derive_public_key,
    generate_hybrid_keypair_suite, hash, hybrid_open, hybrid_seal_suite, sign, verify,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ============================================================================
// KEM / seal (#311)
// ============================================================================

#[test]
fn pure_cnsa2_seal_structure_and_roundtrip() {
    let kp = generate_hybrid_keypair_suite(Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
    // Combined public key = ML-KEM-1024 ek only (no classical half).
    assert_eq!(b64::decode(&kp.public_key).unwrap().len(), 1568);

    let pt = b"32-byte symmetric context key!!!";
    let ct = hybrid_seal_suite(pt, &kp.public_key, Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
    let raw = b64::decode(&ct).unwrap();
    assert_eq!(raw[0], 0x10, "PureCnsa2 tag");
    // tag(1) || ML-KEM-1024 ct(1568) || nonce(12) || aes_gcm(pt + 16-byte tag)
    assert_eq!(raw.len(), 1 + 1568 + 12 + pt.len() + 16);
    assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), pt);
}

#[test]
fn matched_cat3_seal_structure_and_roundtrip() {
    let kp = generate_hybrid_keypair_suite(Suite::HybridMatched, SecurityLevel::Cat3).unwrap();
    // ML-KEM-768 ek(1184) || X448 pk(56)
    assert_eq!(b64::decode(&kp.public_key).unwrap().len(), 1184 + 56);

    let pt = b"matched cat-3 key material......!";
    let ct = hybrid_seal_suite(
        pt,
        &kp.public_key,
        Suite::HybridMatched,
        SecurityLevel::Cat3,
    )
    .unwrap();
    let raw = b64::decode(&ct).unwrap();
    assert_eq!(raw[0], 0x13, "matched Cat-3 tag");
    // tag(1) || ML-KEM-768 ct(1088) || X448 eph pk(56) || nonce(12) || aead(pt+16)
    assert_eq!(raw.len(), 1 + 1088 + 56 + 12 + pt.len() + 16);
    assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), pt);
}

#[test]
fn matched_cat5_seal_structure_and_roundtrip() {
    let kp = generate_hybrid_keypair_suite(Suite::HybridMatched, SecurityLevel::Cat5).unwrap();
    // ML-KEM-1024 ek(1568) || P-521 uncompressed pk(133)
    assert_eq!(b64::decode(&kp.public_key).unwrap().len(), 1568 + 133);

    let pt = b"matched cat-5 key material......!";
    let ct = hybrid_seal_suite(
        pt,
        &kp.public_key,
        Suite::HybridMatched,
        SecurityLevel::Cat5,
    )
    .unwrap();
    let raw = b64::decode(&ct).unwrap();
    assert_eq!(raw[0], 0x14, "matched Cat-5 tag");
    // tag(1) || ML-KEM-1024 ct(1568) || P-521 eph pk(133) || nonce(12) || aead(pt+16)
    assert_eq!(raw.len(), 1 + 1568 + 133 + 12 + pt.len() + 16);
    assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), pt);
}

#[test]
fn seal_context_default_label_is_metamorphic_seal_v1() {
    // Documents the library default label; seal with it, open with it.
    assert_eq!(SEAL_CONTEXT_V1, "metamorphic/seal/v1");
    let kp = generate_hybrid_keypair_suite(Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
    let ct =
        hybrid_seal_suite(b"x", &kp.public_key, Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
    assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"x");
}

// ============================================================================
// Signatures (#312) — derived public keys are deterministic and pinned
// ============================================================================

// PureCnsa2 sk = 0x10 || ml_dsa87_seed(32 = 0x20..=0x3f), base64.
const SIG_SK_PURE: &str = "ECAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/";
// HybridMatched Cat-3 sk = 0x13 || ed448_seed(0..=56) || ml_dsa65_seed(100..=131).
const SIG_SK_MATCHED_CAT3: &str = "EwABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3OGRlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKD";
// HybridMatched Cat-5 sk = 0x14 || p521_seed(0..=65) || ml_dsa87_seed(200..=231).
const SIG_SK_MATCHED_CAT5: &str = "FAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQcjJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn";

#[test]
fn pure_cnsa2_signature_pubkey_pin() {
    let pk = derive_public_key(SIG_SK_PURE).unwrap();
    let raw = b64::decode(&pk).unwrap();
    assert_eq!(raw[0], 0x10);
    assert_eq!(raw.len(), 1 + 2592, "tag || ML-DSA-87 pk");
    assert_eq!(
        hex(&hash::sha3_512(&raw)),
        "af6062b6adbb5f4bf8bee855a358673a3b5d414204f0242b1f570b05dc803927\
         ecaaff019c83e41fc54571b7c84ccc75ba68635c5a65102d20f08316cb853177"
    );
}

#[test]
fn matched_cat3_signature_pubkey_pin() {
    let pk = derive_public_key(SIG_SK_MATCHED_CAT3).unwrap();
    let raw = b64::decode(&pk).unwrap();
    assert_eq!(raw[0], 0x13);
    assert_eq!(raw.len(), 1 + 57 + 1952, "tag || Ed448 pk || ML-DSA-65 pk");
    assert_eq!(
        hex(&hash::sha3_512(&raw)),
        "f0bc0effd7668196467f0eeeccd376c5337797bfdc1203f5a1e13ff6017fbbe3\
         550ed662ee7c8c9e26607410cb46e3ed19e1c52295d5863c234a5991618119d4"
    );
}

#[test]
fn matched_cat5_signature_pubkey_pin() {
    let pk = derive_public_key(SIG_SK_MATCHED_CAT5).unwrap();
    let raw = b64::decode(&pk).unwrap();
    assert_eq!(raw[0], 0x14);
    assert_eq!(
        raw.len(),
        1 + 133 + 2592,
        "tag || ECDSA-P-521 pk || ML-DSA-87 pk"
    );
    assert_eq!(
        hex(&hash::sha3_512(&raw)),
        "0d9125727b3ff64a9d305130e440e89d3b915c4b4738ac1a94e4348bad0d572b\
         516bead707d14abf18d07991801aaa29c756f8c0a92a6635e729fa6ff78519f3"
    );
}

#[test]
fn signature_suites_sign_verify_and_sizes() {
    for (sk, sig_len) in [
        (SIG_SK_PURE, 1 + 4627),               // tag || ML-DSA-87 sig
        (SIG_SK_MATCHED_CAT3, 1 + 114 + 3309), // tag || Ed448 sig || ML-DSA-65 sig
        (SIG_SK_MATCHED_CAT5, 1 + 132 + 4627), // tag || ECDSA-P-521 sig || ML-DSA-87 sig
    ] {
        let pk = derive_public_key(sk).unwrap();
        let sig = sign(b"checkpoint", SIGN_CONTEXT_V1, sk).unwrap();
        assert_eq!(b64::decode(&sig).unwrap().len(), sig_len);
        assert!(verify(b"checkpoint", SIGN_CONTEXT_V1, &sig, &pk).unwrap());
        assert!(!verify(b"tampered", SIGN_CONTEXT_V1, &sig, &pk).unwrap());
    }
}
