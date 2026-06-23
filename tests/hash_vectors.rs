//! Hash known-answer vectors and cross-target (native ⇄ WASM) parity vectors.
//!
//! The native functions return raw bytes; the WASM bindings return the same
//! digest base64-encoded. These shared vectors lock down both the raw digests
//! and their base64 form, so any divergence between the two targets is caught.
//!
//! The base64 values below were produced by the WASM build
//! (`wasm-pack build --target nodejs --release`) and verified to equal the
//! native digests for identical input. To regenerate, hash the input with the
//! WASM `sha3_512`/etc. exports (which take base64 input, return base64 output).

use metamorphic_crypto::{b64, hash};

/// `SHA3-512("abc")` as base64 — the exact string the WASM `sha3_512("YWJj")`
/// export returns. Proves the native path agrees with the WASM path.
const SHA3_512_ABC_B64: &str =
    "t1GFCxpXFopWk82SS2sJbgj2IYJ0RPcNiE9dAkDScS4Q4RbpGSrzyRp+xXZH45NAVzQLTPQI1aVlkvgnTuxT8A==";

#[test]
fn sha3_512_native_matches_wasm_base64() {
    let digest = hash::sha3_512(b"abc");
    assert_eq!(b64::encode(&digest), SHA3_512_ABC_B64);
}

#[test]
fn sha3_256_native_matches_wasm_base64() {
    // WASM: sha3_256("YWJj")
    let digest = hash::sha3_256(b"abc");
    assert_eq!(
        b64::encode(&digest),
        "Ophdp0/iJbIEXBcta9OQvYVfCG4+nVJbRr/iRRFDFTI="
    );
}

#[test]
fn sha256_native_matches_wasm_base64() {
    // WASM: sha256("YWJj")
    let digest = hash::sha256(b"abc");
    assert_eq!(
        b64::encode(&digest),
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
}

#[test]
fn sha512_native_matches_wasm_base64() {
    // WASM: sha512("YWJj")
    let digest = hash::sha512(b"abc");
    assert_eq!(
        b64::encode(&digest),
        "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="
    );
}

#[test]
fn distinct_inputs_distinct_digests() {
    assert_ne!(hash::sha3_512(b"key-a"), hash::sha3_512(b"key-b"));
}

/// Domain-separated SHA3-512 parity vector.
///
/// `sha3_512_with_context("mosslet/key-fingerprint/v1", "public key bytes")`,
/// computed independently (Python: `sha3_512(u64_be(len(ctx)) || ctx || data)`)
/// and verified to equal the WASM `sha3_512WithContext("mosslet/key-fingerprint/v1", btoa("public key bytes"))`.
/// Locks the cross-language wire format so native, WASM, and the Elixir NIF stay byte-identical.
#[test]
fn sha3_512_with_context_parity_vector() {
    let digest = hash::sha3_512_with_context("mosslet/key-fingerprint/v1", b"public key bytes");
    assert_eq!(
        b64::encode(&digest),
        "y/pbnlfUE85DjRUSFYNCJR1B19NFtpK8eJvoO6Ig2tsKOaknFLYbmUg5KWjtaiQn98nBDCI7X2Su8xFT0xQJng=="
    );
}
