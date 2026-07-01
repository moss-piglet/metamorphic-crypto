//! WASM bindings via `wasm-bindgen`.
//!
//! Exposes the same async-style API that `assets/js/crypto/nacl.js` provides,
//! so existing hooks can call into the WASM module as a drop-in replacement.
//!
//! Every function accepts and returns base64 strings (matching the JS convention).
//! Errors are returned as JavaScript exceptions via `JsValue`.

use wasm_bindgen::prelude::*;

use crate::hybrid::SecurityLevel;
use crate::suite::Suite;
use crate::{
    b64, box_seal, hash, hybrid, kdf, keys, mac, recovery, seal, secretbox, sign, vrf, vrf_p256,
};
// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte session key from password + base64-encoded salt.
/// Returns base64-encoded key.
#[wasm_bindgen(js_name = "deriveSessionKey")]
pub fn derive_session_key(password: &str, salt_b64: &str) -> Result<String, JsValue> {
    kdf::derive_session_key(password, salt_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// Secretbox (symmetric encryption)
// ---------------------------------------------------------------------------

/// Encrypt a UTF-8 string with a base64 key. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "encryptSecretboxString")]
pub fn encrypt_secretbox_string(plaintext: &str, key_b64: &str) -> Result<String, JsValue> {
    secretbox::encrypt_secretbox_string(plaintext, key_b64).map_err(to_js)
}

/// Decrypt base64 ciphertext to a UTF-8 string.
#[wasm_bindgen(js_name = "decryptSecretboxToString")]
pub fn decrypt_secretbox_to_string(ciphertext_b64: &str, key_b64: &str) -> Result<String, JsValue> {
    secretbox::decrypt_secretbox_to_string(ciphertext_b64, key_b64).map_err(to_js)
}

/// Encrypt raw bytes (as base64) with a base64 key. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "encryptSecretbox")]
pub fn encrypt_secretbox(plaintext_b64: &str, key_b64: &str) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    secretbox::encrypt_secretbox(&pt, key_b64).map_err(to_js)
}

/// Decrypt base64 ciphertext, returning plaintext as base64.
#[wasm_bindgen(js_name = "decryptSecretbox")]
pub fn decrypt_secretbox(ciphertext_b64: &str, key_b64: &str) -> Result<String, JsValue> {
    let pt = secretbox::decrypt_secretbox(ciphertext_b64, key_b64).map_err(to_js)?;
    Ok(b64::encode(&pt))
}

// ---------------------------------------------------------------------------
// Box seal (anonymous public-key encryption)
// ---------------------------------------------------------------------------

/// Seal plaintext (base64) to a recipient's public key. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "boxSeal")]
pub fn box_seal_wasm(plaintext_b64: &str, public_key_b64: &str) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    box_seal::box_seal(&pt, public_key_b64).map_err(to_js)
}

/// Open a sealed box. Returns base64-encoded plaintext.
#[wasm_bindgen(js_name = "boxSealOpen")]
pub fn box_seal_open(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
) -> Result<String, JsValue> {
    box_seal::box_seal_open(ciphertext_b64, public_key_b64, private_key_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// Unified seal/unseal (auto-detects hybrid vs legacy)
// ---------------------------------------------------------------------------

/// Seal plaintext bytes (base64) to a user's key(s). Uses hybrid PQ if pq_pk is provided.
#[wasm_bindgen(js_name = "sealForUser")]
pub fn seal_for_user(
    plaintext_b64: &str,
    public_key_b64: &str,
    pq_public_key_b64: Option<String>,
) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    seal::seal_for_user(&pt, public_key_b64, pq_public_key_b64.as_deref()).map_err(to_js)
}

/// Unseal ciphertext using the user's keys. Auto-detects format.
/// Returns base64-encoded plaintext.
#[wasm_bindgen(js_name = "unsealFromUser")]
pub fn unseal_from_user(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
    pq_secret_key_b64: Option<String>,
) -> Result<String, JsValue> {
    seal::unseal_from_user(
        ciphertext_b64,
        public_key_b64,
        private_key_b64,
        pq_secret_key_b64.as_deref(),
    )
    .map_err(to_js)
}

/// Seal plaintext bytes (base64) to a user's key(s) at a specific security level.
///
/// `level` must be `"cat1"` (ML-KEM-512), `"cat3"` (ML-KEM-768, default), or
/// `"cat5"` (ML-KEM-1024).
/// If `pq_public_key_b64` is absent or empty, falls back to legacy X25519.
#[wasm_bindgen(js_name = "sealForUserWithLevel")]
pub fn seal_for_user_with_level(
    plaintext_b64: &str,
    public_key_b64: &str,
    pq_public_key_b64: Option<String>,
    level: &str,
) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    let sec_level = parse_security_level(level)?;
    seal::seal_for_user_with_level(&pt, public_key_b64, pq_public_key_b64.as_deref(), sec_level)
        .map_err(to_js)
}

// ---------------------------------------------------------------------------
// Hybrid PQ KEM
// ---------------------------------------------------------------------------
/// Generate a ML-KEM-512 + X25519 keypair (Cat-1). Returns JSON: `{ publicKey, secretKey }`.
#[wasm_bindgen(js_name = "generateHybridKeyPair512")]
pub fn generate_hybrid_keypair_512() -> JsValue {
    let kp = hybrid::generate_hybrid_keypair_512();
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.into()).unwrap();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &kp.secret_key.into()).unwrap();
    obj.into()
}

/// Generate a ML-KEM-768 keypair. Returns JSON: `{ publicKey, secretKey }`.
#[wasm_bindgen(js_name = "generateHybridKeyPair")]
pub fn generate_hybrid_keypair() -> JsValue {
    let kp = hybrid::generate_hybrid_keypair();
    // Return as a plain JS object
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.into()).unwrap();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &kp.secret_key.into()).unwrap();
    obj.into()
}

/// Generate a ML-KEM-1024 + X25519 keypair (Cat-5). Returns JSON: `{ publicKey, secretKey }`.
#[wasm_bindgen(js_name = "generateHybridKeyPair1024")]
pub fn generate_hybrid_keypair_1024() -> JsValue {
    let kp = hybrid::generate_hybrid_keypair_1024();
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.into()).unwrap();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &kp.secret_key.into()).unwrap();
    obj.into()
}

/// Check if a base64 ciphertext is hybrid (v2/v3) format.
#[wasm_bindgen(js_name = "isHybridCiphertext")]
pub fn is_hybrid_ciphertext(ciphertext_b64: &str) -> bool {
    hybrid::is_hybrid_ciphertext(ciphertext_b64)
}

// ---------------------------------------------------------------------------
// CNSA 2.0 suites (v0.7.0): Suite × SecurityLevel KEM/seal
// ---------------------------------------------------------------------------
//
// `suite` is `"hybrid"` (default/legacy), `"hybridMatched"`, or `"pureCnsa2"`
// (case-insensitive; `_`/`-` separators tolerated). `level` is `"cat1"`,
// `"cat3"`, or `"cat5"`. PureCnsa2 requires Cat-5. The new suites bind a
// versioned context label (`"<namespace>/<purpose>/v<major>"`); the default is
// `"metamorphic/seal/v1"`.

/// Generate a keypair for `(suite, level)`. Returns JSON: `{ publicKey, secretKey }`.
#[wasm_bindgen(js_name = "generateHybridKeyPairSuite")]
pub fn generate_hybrid_keypair_suite(suite: &str, level: &str) -> Result<JsValue, JsValue> {
    let suite = parse_suite(suite)?;
    let lvl = parse_security_level(level)?;
    let kp = hybrid::generate_hybrid_keypair_suite(suite, lvl).map_err(to_js)?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.into()).unwrap();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &kp.secret_key.into()).unwrap();
    Ok(obj.into())
}

/// Seal plaintext (base64) to a `(suite, level)` combined public key, binding
/// the default `"metamorphic/seal/v1"` context label. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "hybridSealSuite")]
pub fn hybrid_seal_suite(
    plaintext_b64: &str,
    combined_pk_b64: &str,
    suite: &str,
    level: &str,
) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    let suite = parse_suite(suite)?;
    let lvl = parse_security_level(level)?;
    hybrid::hybrid_seal_suite(&pt, combined_pk_b64, suite, lvl).map_err(to_js)
}

/// Seal plaintext (base64) to a `(suite, level)` combined public key, binding a
/// custom `context_label`. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "hybridSealSuiteWithContext")]
pub fn hybrid_seal_suite_with_context(
    plaintext_b64: &str,
    combined_pk_b64: &str,
    suite: &str,
    level: &str,
    context_label: &str,
) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    let suite = parse_suite(suite)?;
    let lvl = parse_security_level(level)?;
    hybrid::hybrid_seal_suite_with_context(&pt, combined_pk_b64, suite, lvl, context_label)
        .map_err(to_js)
}

/// Open a CNSA-2.0 (or legacy) hybrid ciphertext, supplying the context label
/// used at seal time for the new suites. Returns base64-encoded plaintext.
#[wasm_bindgen(js_name = "hybridOpenWithContext")]
pub fn hybrid_open_with_context(
    ciphertext_b64: &str,
    seed_b64: &str,
    context_label: &str,
) -> Result<String, JsValue> {
    let pt =
        hybrid::hybrid_open_with_context(ciphertext_b64, seed_b64, context_label).map_err(to_js)?;
    Ok(b64::encode(&pt))
}

/// Seal plaintext (base64) to a user's key(s) under a full `(suite, level)`.
/// Falls back to legacy X25519 if `pq_public_key_b64` is absent/empty.
#[wasm_bindgen(js_name = "sealForUserWithSuite")]
pub fn seal_for_user_with_suite(
    plaintext_b64: &str,
    public_key_b64: &str,
    pq_public_key_b64: Option<String>,
    suite: &str,
    level: &str,
) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    let suite = parse_suite(suite)?;
    let lvl = parse_security_level(level)?;
    seal::seal_for_user_with_suite(
        &pt,
        public_key_b64,
        pq_public_key_b64.as_deref(),
        suite,
        lvl,
    )
    .map_err(to_js)
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a random 32-byte symmetric key (base64).
#[wasm_bindgen(js_name = "generateKey")]
pub fn generate_key() -> String {
    keys::generate_key()
}

/// Generate a random X25519 keypair. Returns JSON: `{ publicKey, privateKey }`.
#[wasm_bindgen(js_name = "generateKeyPair")]
pub fn generate_keypair() -> JsValue {
    let kp = keys::generate_keypair();
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.into()).unwrap();
    js_sys::Reflect::set(&obj, &"privateKey".into(), &kp.private_key.into()).unwrap();
    obj.into()
}

/// Generate a random 16-byte salt (base64).
#[wasm_bindgen(js_name = "generateSalt")]
pub fn generate_salt() -> String {
    keys::generate_salt()
}

// ---------------------------------------------------------------------------
// Private key encrypt/decrypt
// ---------------------------------------------------------------------------

/// Encrypt a base64 private key with a session key. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "encryptPrivateKey")]
pub fn encrypt_private_key(
    private_key_b64: &str,
    session_key_b64: &str,
) -> Result<String, JsValue> {
    keys::encrypt_private_key(private_key_b64, session_key_b64).map_err(to_js)
}

/// Decrypt an encrypted private key with a session key. Returns base64 private key.
#[wasm_bindgen(js_name = "decryptPrivateKey")]
pub fn decrypt_private_key(ciphertext_b64: &str, session_key_b64: &str) -> Result<String, JsValue> {
    keys::decrypt_private_key(ciphertext_b64, session_key_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// Recovery key
// ---------------------------------------------------------------------------

/// Generate a recovery key. Returns JSON: `{ recoveryKey, recoverySecretBase64 }`.
#[wasm_bindgen(js_name = "generateRecoveryKey")]
pub fn generate_recovery_key() -> Result<JsValue, JsValue> {
    let rk = recovery::generate_recovery_key().map_err(to_js)?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"recoveryKey".into(), &rk.recovery_key.into()).unwrap();
    js_sys::Reflect::set(
        &obj,
        &"recoverySecretBase64".into(),
        &rk.recovery_secret_b64.into(),
    )
    .unwrap();
    Ok(obj.into())
}

/// Derive the 32-byte secret (base64) from a human-readable recovery key.
#[wasm_bindgen(js_name = "recoveryKeyToSecret")]
pub fn recovery_key_to_secret(recovery_key: &str) -> Result<String, JsValue> {
    recovery::recovery_key_to_secret(recovery_key).map_err(to_js)
}

/// Encrypt private key for recovery backup. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "encryptPrivateKeyForRecovery")]
pub fn encrypt_private_key_for_recovery(
    private_key_b64: &str,
    recovery_secret_b64: &str,
) -> Result<String, JsValue> {
    recovery::encrypt_private_key_for_recovery(private_key_b64, recovery_secret_b64).map_err(to_js)
}

/// Decrypt private key from recovery backup. Returns base64 private key.
#[wasm_bindgen(js_name = "decryptPrivateKeyWithRecovery")]
pub fn decrypt_private_key_with_recovery(
    ciphertext_b64: &str,
    recovery_secret_b64: &str,
) -> Result<String, JsValue> {
    recovery::decrypt_private_key_with_recovery(ciphertext_b64, recovery_secret_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Parse the salt (base64) from a key_hash string (`salt$argon2id`).
#[wasm_bindgen(js_name = "parseSaltFromKeyHash")]
pub fn parse_salt_from_key_hash(key_hash: &str) -> Result<String, JsValue> {
    b64::parse_salt_from_key_hash(key_hash)
        .map(|s| s.to_string())
        .map_err(to_js)
}

// ---------------------------------------------------------------------------
// Hashing (SHA-3 / SHA-2)
// ---------------------------------------------------------------------------
//
// Encoding: like the rest of this WASM API, inputs and outputs are base64
// strings (standard alphabet, with padding — matching JS `btoa`/`atob`). The
// caller passes the data to hash as base64 and receives the digest as base64.
// Base64 (not hex) is used purely for consistency with the sibling exports;
// decode with `atob` or re-encode to hex on the JS side if a hex fingerprint
// is required.

/// SHA3-512 digest of base64-encoded `data`. Returns the 64-byte digest as base64.
///
/// This is the recommended default hash (NIST Cat-5).
#[wasm_bindgen(js_name = "sha3_512")]
pub fn sha3_512(data_b64: &str) -> Result<String, JsValue> {
    let data = b64::decode(data_b64).map_err(to_js)?;
    Ok(b64::encode(&hash::sha3_512(&data)))
}

/// Domain-separated SHA3-512: binds the digest to a UTF-8 `context` label.
///
/// `data` is base64; returns the 64-byte digest as base64. Prefer this over
/// `sha3_512` for fingerprints / safety numbers / key-transparency entries.
///
/// Wire format (reproduce exactly for parity with native/Elixir):
/// `SHA3-512( u64_be(len(context_utf8)) || context_utf8 || data )`.
#[wasm_bindgen(js_name = "sha3_512WithContext")]
pub fn sha3_512_with_context(context: &str, data_b64: &str) -> Result<String, JsValue> {
    let data = b64::decode(data_b64).map_err(to_js)?;
    Ok(b64::encode(&hash::sha3_512_with_context(context, &data)))
}

/// SHA3-256 digest of base64-encoded `data`. Returns the 32-byte digest as base64.
#[wasm_bindgen(js_name = "sha3_256")]
pub fn sha3_256(data_b64: &str) -> Result<String, JsValue> {
    let data = b64::decode(data_b64).map_err(to_js)?;
    Ok(b64::encode(&hash::sha3_256(&data)))
}

/// SHA-256 (SHA-2) digest of base64-encoded `data`. Returns the 32-byte digest as base64.
#[wasm_bindgen(js_name = "sha256")]
pub fn sha256(data_b64: &str) -> Result<String, JsValue> {
    let data = b64::decode(data_b64).map_err(to_js)?;
    Ok(b64::encode(&hash::sha256(&data)))
}

/// SHA-512 (SHA-2) digest of base64-encoded `data`. Returns the 64-byte digest as base64.
#[wasm_bindgen(js_name = "sha512")]
pub fn sha512(data_b64: &str) -> Result<String, JsValue> {
    let data = b64::decode(data_b64).map_err(to_js)?;
    Ok(b64::encode(&hash::sha512(&data)))
}

// ---------------------------------------------------------------------------
// Hybrid PQ signatures (ML-DSA + Ed25519 composite)
// ---------------------------------------------------------------------------
//
// Keys and signatures are base64 strings using the wire format documented in
// `crate::sign`. The message to sign/verify is passed as base64 (consistent
// with the rest of this WASM API); `context` is a plain UTF-8 string.

/// Generate a hybrid signing keypair. Returns JSON: `{ publicKey, secretKey }`.
///
/// `level` is `"cat2"` (ML-DSA-44), `"cat3"` (ML-DSA-65, default), or `"cat5"`
/// (ML-DSA-87). Empty/null defaults to Cat-3.
#[wasm_bindgen(js_name = "generateSigningKeyPair")]
pub fn generate_signing_keypair(level: &str) -> Result<JsValue, JsValue> {
    let lvl = parse_signature_level(level)?;
    let kp = sign::generate_signing_keypair_with_level(lvl);
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.clone().into()).unwrap();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &kp.secret_key.clone().into()).unwrap();
    Ok(obj.into())
}

/// Generate a signing keypair for a full CNSA-2.0 `(suite, level)`.
///
/// `suite` is `"hybrid"` (default), `"hybridMatched"` (Cat-3→Ed448,
/// Cat-5→ECDSA-P-521), or `"pureCnsa2"` (ML-DSA-87 only, Cat-5). `level` is
/// `"cat2"`/`"cat3"`/`"cat5"`. `sign` / `verify` / `deriveSigningPublicKey`
/// auto-detect the suite from the key/signature version tag, so no suite
/// argument is needed there. Returns JSON: `{ publicKey, secretKey }`.
#[wasm_bindgen(js_name = "generateSigningKeyPairSuite")]
pub fn generate_signing_keypair_suite(suite: &str, level: &str) -> Result<JsValue, JsValue> {
    let suite = parse_suite(suite)?;
    let lvl = parse_signature_level(level)?;
    let kp = sign::generate_signing_keypair_suite(suite, lvl).map_err(to_js)?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.clone().into()).unwrap();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &kp.secret_key.clone().into()).unwrap();
    Ok(obj.into())
}

/// Re-derive the base64 public key from a base64 hybrid secret key.
#[wasm_bindgen(js_name = "deriveSigningPublicKey")]
pub fn derive_signing_public_key(secret_key_b64: &str) -> Result<String, JsValue> {
    sign::derive_public_key(secret_key_b64).map_err(to_js)
}

/// Sign base64 `message` under `context` with a base64 hybrid `secret_key`.
/// Returns the composite signature as base64.
#[wasm_bindgen(js_name = "sign")]
pub fn sign_message(
    message_b64: &str,
    context: &str,
    secret_key_b64: &str,
) -> Result<String, JsValue> {
    let msg = b64::decode(message_b64).map_err(to_js)?;
    sign::sign(&msg, context, secret_key_b64).map_err(to_js)
}

/// Verify a base64 composite `signature` over base64 `message`/`context`
/// against a base64 `public_key`. Returns `true` only if **both** the Ed25519
/// and ML-DSA components verify (strict AND).
#[wasm_bindgen(js_name = "verify")]
pub fn verify(
    message_b64: &str,
    context: &str,
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<bool, JsValue> {
    let msg = b64::decode(message_b64).map_err(to_js)?;
    sign::verify(&msg, context, signature_b64, public_key_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// MAC (HMAC-SHA256)
// ---------------------------------------------------------------------------
//
// The generic keyed-MAC primitive. Its headline use is the on-spec IETF
// KEYTRANS commitment (`HMAC(Kc, CommitmentValue)`); the KEYTRANS-specific
// framing lives in the transparency-log layer, not here. `key`/`msg` are
// base64; the 32-byte tag is returned as base64.

/// HMAC-SHA256 of base64 `msg` under base64 `key`. Returns the 32-byte tag as
/// base64. Any key length is accepted (RFC 2104).
#[wasm_bindgen(js_name = "hmacSha256")]
pub fn hmac_sha256(key_b64: &str, msg_b64: &str) -> Result<String, JsValue> {
    let key = b64::decode(key_b64).map_err(to_js)?;
    let msg = b64::decode(msg_b64).map_err(to_js)?;
    Ok(b64::encode(&mac::hmac_sha256(&key, &msg)))
}

// ---------------------------------------------------------------------------
// Verifiable Random Functions (ECVRF, RFC 9381)
// ---------------------------------------------------------------------------
//
// Two RFC 9381 ciphersuites, mirroring the native API exactly:
//   * `ecvrfEd25519*` — ECVRF-EDWARDS25519-SHA512-TAI (suite 0x03)
//   * `ecvrfP256*`    — ECVRF-P256-SHA256-TAI          (suite 0x01)
// They back the KEYTRANS index-privacy VRF (Ed25519 for the private/experimental
// and `KT_128_SHA256_Ed25519` suites; P-256 for `KT_128_SHA256_P256`). Keys,
// proofs, inputs (`alpha`), and outputs cross as base64. `verify` returns the
// base64 output on success or `undefined` (JS `null`) on a cryptographic reject.

/// Generate an ECVRF-Edwards25519 keypair. Returns JSON: `{ secretKey, publicKey }`.
#[wasm_bindgen(js_name = "ecvrfEd25519GenerateKeyPair")]
pub fn ecvrf_ed25519_generate_keypair() -> JsValue {
    let (sk, pk) = vrf::ecvrf_generate_keypair();
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &b64::encode(&sk).into()).unwrap();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &b64::encode(&pk).into()).unwrap();
    obj.into()
}

/// Derive the base64 ECVRF-Edwards25519 public key from a base64 secret key.
#[wasm_bindgen(js_name = "ecvrfEd25519PublicKey")]
pub fn ecvrf_ed25519_public_key(secret_key_b64: &str) -> Result<String, JsValue> {
    let sk = b64::decode(secret_key_b64).map_err(to_js)?;
    Ok(b64::encode(&vrf::ecvrf_public_key(&sk).map_err(to_js)?))
}

/// Produce an ECVRF-Edwards25519 proof (base64) for base64 `alpha`.
#[wasm_bindgen(js_name = "ecvrfEd25519Prove")]
pub fn ecvrf_ed25519_prove(secret_key_b64: &str, alpha_b64: &str) -> Result<String, JsValue> {
    let sk = b64::decode(secret_key_b64).map_err(to_js)?;
    let alpha = b64::decode(alpha_b64).map_err(to_js)?;
    Ok(b64::encode(&vrf::ecvrf_prove(&sk, &alpha).map_err(to_js)?))
}

/// Verify an ECVRF-Edwards25519 proof. Returns the base64 output on success, or
/// `null` on a cryptographic rejection.
#[wasm_bindgen(js_name = "ecvrfEd25519Verify")]
pub fn ecvrf_ed25519_verify(
    public_key_b64: &str,
    alpha_b64: &str,
    proof_b64: &str,
) -> Result<Option<String>, JsValue> {
    let pk = b64::decode(public_key_b64).map_err(to_js)?;
    let alpha = b64::decode(alpha_b64).map_err(to_js)?;
    let proof = b64::decode(proof_b64).map_err(to_js)?;
    Ok(vrf::ecvrf_verify(&pk, &alpha, &proof)
        .map_err(to_js)?
        .map(|beta| b64::encode(&beta)))
}

/// Recover the base64 ECVRF-Edwards25519 output from a proof, without verifying.
#[wasm_bindgen(js_name = "ecvrfEd25519ProofToHash")]
pub fn ecvrf_ed25519_proof_to_hash(proof_b64: &str) -> Result<String, JsValue> {
    let proof = b64::decode(proof_b64).map_err(to_js)?;
    Ok(b64::encode(
        &vrf::ecvrf_proof_to_hash(&proof).map_err(to_js)?,
    ))
}

/// Generate an ECVRF-P256 keypair. Returns JSON: `{ secretKey, publicKey }`.
#[wasm_bindgen(js_name = "ecvrfP256GenerateKeyPair")]
pub fn ecvrf_p256_generate_keypair() -> JsValue {
    let (sk, pk) = vrf_p256::ecvrf_p256_generate_keypair();
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &b64::encode(&sk).into()).unwrap();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &b64::encode(&pk).into()).unwrap();
    obj.into()
}

/// Derive the base64 ECVRF-P256 public key from a base64 secret key.
#[wasm_bindgen(js_name = "ecvrfP256PublicKey")]
pub fn ecvrf_p256_public_key(secret_key_b64: &str) -> Result<String, JsValue> {
    let sk = b64::decode(secret_key_b64).map_err(to_js)?;
    Ok(b64::encode(
        &vrf_p256::ecvrf_p256_public_key(&sk).map_err(to_js)?,
    ))
}

/// Produce an ECVRF-P256 proof (base64) for base64 `alpha`.
#[wasm_bindgen(js_name = "ecvrfP256Prove")]
pub fn ecvrf_p256_prove(secret_key_b64: &str, alpha_b64: &str) -> Result<String, JsValue> {
    let sk = b64::decode(secret_key_b64).map_err(to_js)?;
    let alpha = b64::decode(alpha_b64).map_err(to_js)?;
    Ok(b64::encode(
        &vrf_p256::ecvrf_p256_prove(&sk, &alpha).map_err(to_js)?,
    ))
}

/// Verify an ECVRF-P256 proof. Returns the base64 output on success, or `null`
/// on a cryptographic rejection.
#[wasm_bindgen(js_name = "ecvrfP256Verify")]
pub fn ecvrf_p256_verify(
    public_key_b64: &str,
    alpha_b64: &str,
    proof_b64: &str,
) -> Result<Option<String>, JsValue> {
    let pk = b64::decode(public_key_b64).map_err(to_js)?;
    let alpha = b64::decode(alpha_b64).map_err(to_js)?;
    let proof = b64::decode(proof_b64).map_err(to_js)?;
    Ok(vrf_p256::ecvrf_p256_verify(&pk, &alpha, &proof)
        .map_err(to_js)?
        .map(|beta| b64::encode(&beta)))
}

/// Recover the base64 ECVRF-P256 output from a proof, without verifying.
#[wasm_bindgen(js_name = "ecvrfP256ProofToHash")]
pub fn ecvrf_p256_proof_to_hash(proof_b64: &str) -> Result<String, JsValue> {
    let proof = b64::decode(proof_b64).map_err(to_js)?;
    Ok(b64::encode(
        &vrf_p256::ecvrf_p256_proof_to_hash(&proof).map_err(to_js)?,
    ))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
/// Parse a JS string into a `SecurityLevel`.
///
/// Accepts `"cat1"`, `"cat3"`, `"cat5"` (case-insensitive). Defaults to Cat-3 on empty/null.
fn parse_security_level(level: &str) -> Result<SecurityLevel, JsValue> {
    match level.to_ascii_lowercase().as_str() {
        "cat1" => Ok(SecurityLevel::Cat1),
        "" | "cat3" => Ok(SecurityLevel::Cat3),
        "cat5" => Ok(SecurityLevel::Cat5),
        other => Err(JsValue::from_str(&format!(
            "invalid security level \"{other}\": expected \"cat1\", \"cat3\", or \"cat5\""
        ))),
    }
}

/// Convert a CryptoError into a JsValue (thrown as a JS Error).
fn to_js(e: crate::CryptoError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Parse a JS string into a [`Suite`].
///
/// Accepts `"hybrid"` (default), `"hybridMatched"` / `"matched"`, and
/// `"pureCnsa2"` / `"pure"` (case-insensitive; `_`/`-`/space separators
/// tolerated). Empty/null defaults to `Hybrid`.
fn parse_suite(suite: &str) -> Result<Suite, JsValue> {
    let normalized: String = suite
        .chars()
        .filter(|c| *c != '_' && *c != '-' && *c != ' ')
        .collect::<String>()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "" | "hybrid" => Ok(Suite::Hybrid),
        "hybridmatched" | "matched" => Ok(Suite::HybridMatched),
        "purecnsa2" | "pure" | "cnsa2" => Ok(Suite::PureCnsa2),
        other => Err(JsValue::from_str(&format!(
            "invalid suite \"{other}\": expected \"hybrid\", \"hybridMatched\", or \"pureCnsa2\""
        ))),
    }
}

/// Parse a JS string into a `SignatureLevel`.
///
/// Accepts `"cat2"`, `"cat3"`, `"cat5"` (case-insensitive). Defaults to Cat-3
/// on empty/null.
fn parse_signature_level(level: &str) -> Result<sign::SignatureLevel, JsValue> {
    match level.to_ascii_lowercase().as_str() {
        "cat2" => Ok(sign::SignatureLevel::Cat2),
        "" | "cat3" => Ok(sign::SignatureLevel::Cat3),
        "cat5" => Ok(sign::SignatureLevel::Cat5),
        other => Err(JsValue::from_str(&format!(
            "invalid signature level \"{other}\": expected \"cat2\", \"cat3\", or \"cat5\""
        ))),
    }
}
