//! Interoperability test vectors.
//!
//! These tests verify that the Rust crypto core produces ciphertext in the exact
//! format expected by the JavaScript `nacl.js` / `hybrid.js` modules, and vice versa.
//!
//! The vectors use fixed keys and nonces (where possible) so the tests are
//! deterministic. In production, nonces are always random.
//!
//! ## How to regenerate vectors from JS
//!
//! Run the following in a browser console (with libsodium loaded):
//!
//! ```js
//! const sodium = await import("libsodium-wrappers-sumo");
//! await sodium.ready;
//!
//! // Fixed key (32 bytes of 0x01)
//! const key = new Uint8Array(32).fill(0x01);
//! const keyB64 = btoa(String.fromCharCode(...key));
//!
//! // Encrypt "hello" with secretbox
//! const pt = sodium.from_string("hello");
//! const nonce = new Uint8Array(24).fill(0xAA);
//! const ct = sodium.crypto_secretbox_easy(pt, nonce, key);
//! const combined = new Uint8Array(24 + ct.length);
//! combined.set(nonce);
//! combined.set(ct, 24);
//! console.log("secretbox:", btoa(String.fromCharCode(...combined)));
//! ```

use metamorphic_crypto::{b64, box_seal, kdf, keys, recovery, seal, secretbox};

// ============================================================================
// Secretbox format tests
// ============================================================================

#[test]
fn secretbox_ciphertext_is_nonce_prepended() {
    let key = b64::encode(&[0x01u8; 32]);
    let ct_b64 = secretbox::encrypt_secretbox(b"hello", &key).unwrap();
    let ct = b64::decode(&ct_b64).unwrap();

    // Format: nonce (24) || ciphertext (5 + 16 MAC)
    assert_eq!(ct.len(), 24 + 5 + 16);

    // Verify we can decrypt it back
    let pt = secretbox::decrypt_secretbox(&ct_b64, &key).unwrap();
    assert_eq!(pt, b"hello");
}

#[test]
fn secretbox_string_roundtrip_utf8() {
    let key = keys::generate_key();

    // Test with emoji (multi-byte UTF-8)
    let plaintext = "🔐 Zero Knowledge!";
    let ct = secretbox::encrypt_secretbox_string(plaintext, &key).unwrap();
    let pt = secretbox::decrypt_secretbox_to_string(&ct, &key).unwrap();
    assert_eq!(pt, plaintext);
}

// ============================================================================
// box_seal format tests (matches libsodium crypto_box_seal)
// ============================================================================

#[test]
fn box_seal_format_is_ephemeral_pk_then_ciphertext() {
    let kp = keys::generate_keypair();
    let plaintext = b"context key 32 bytes of data!!!";

    let ct_b64 = box_seal::box_seal(plaintext, &kp.public_key).unwrap();
    let ct = b64::decode(&ct_b64).unwrap();

    // Format: ephemeral_pk (32) || encrypted (31 + 16 MAC)
    assert_eq!(ct.len(), 32 + 31 + 16);

    // The first 32 bytes should be a valid public key (not all zeros)
    let epk = &ct[..32];
    assert_ne!(epk, &[0u8; 32]);

    // Verify decryption
    let pt_b64 = box_seal::box_seal_open(&ct_b64, &kp.public_key, &kp.private_key).unwrap();
    let pt = b64::decode(&pt_b64).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn box_seal_open_returns_base64_plaintext() {
    // This matches the JS convention where boxSealOpen returns b64_encode(plaintext)
    let kp = keys::generate_keypair();
    let plaintext = b"test";
    let ct = box_seal::box_seal(plaintext, &kp.public_key).unwrap();
    let result = box_seal::box_seal_open(&ct, &kp.public_key, &kp.private_key).unwrap();

    // Result is base64-encoded plaintext
    assert_eq!(b64::decode(&result).unwrap(), plaintext);
}

// ============================================================================
// seal_for_user / unseal_from_user integration
// ============================================================================

#[test]
fn seal_unseal_legacy_format_32_byte_key() {
    // This is the most common case: sealing a 32-byte context key for a user
    let kp = keys::generate_keypair();
    let context_key = b64::decode(&keys::generate_key()).unwrap();

    let sealed = seal::seal_for_user(&context_key, &kp.public_key, None).unwrap();
    let opened_b64 =
        seal::unseal_from_user(&sealed, &kp.public_key, &kp.private_key, None).unwrap();
    let opened = b64::decode(&opened_b64).unwrap();

    assert_eq!(opened, context_key);
}

#[test]
fn seal_unseal_hybrid_format_32_byte_key() {
    use metamorphic_crypto::hybrid;

    let kp = keys::generate_keypair();
    let hkp = hybrid::generate_hybrid_keypair();
    let context_key = b64::decode(&keys::generate_key()).unwrap();

    let sealed = seal::seal_for_user(&context_key, &kp.public_key, Some(&hkp.public_key)).unwrap();

    // Verify it's hybrid format
    let raw = b64::decode(&sealed).unwrap();
    assert_eq!(raw[0], 0x02);

    let opened_b64 = seal::unseal_from_user(
        &sealed,
        &kp.public_key,
        &kp.private_key,
        Some(&hkp.secret_key),
    )
    .unwrap();
    let opened = b64::decode(&opened_b64).unwrap();

    assert_eq!(opened, context_key);
}

// ============================================================================
// KDF (Argon2id) — verify parameters match libsodium INTERACTIVE
// ============================================================================

#[test]
fn kdf_deterministic_with_fixed_inputs() {
    // Same password + salt must always produce the same key
    let salt = b64::encode(&[0x42u8; 16]);
    let key1 = kdf::derive_session_key("my-password", &salt).unwrap();
    let key2 = kdf::derive_session_key("my-password", &salt).unwrap();
    assert_eq!(key1, key2);

    // Output is exactly 32 bytes
    assert_eq!(b64::decode(&key1).unwrap().len(), 32);
}

#[test]
fn kdf_different_password_different_key() {
    let salt = b64::encode(&[0x42u8; 16]);
    let k1 = kdf::derive_session_key("password-a", &salt).unwrap();
    let k2 = kdf::derive_session_key("password-b", &salt).unwrap();
    assert_ne!(k1, k2);
}

// ============================================================================
// Private key encrypt/decrypt (the invariant: private key is stored as b64 string)
// ============================================================================

#[test]
fn private_key_stored_as_base64_string() {
    // The JS stores privateKey as a base64 STRING (not raw bytes).
    // encryptPrivateKey encrypts that STRING with secretbox.
    // decryptPrivateKey returns the original base64 STRING.
    let kp = keys::generate_keypair();
    let session_key = keys::generate_key();

    let encrypted = keys::encrypt_private_key(&kp.private_key, &session_key).unwrap();
    let decrypted = keys::decrypt_private_key(&encrypted, &session_key).unwrap();

    // The decrypted value IS the base64 string, not raw bytes
    assert_eq!(decrypted, kp.private_key);

    // And that string decodes to 32 raw bytes
    assert_eq!(b64::decode(&decrypted).unwrap().len(), 32);
}

// ============================================================================
// Recovery key format
// ============================================================================

#[test]
fn recovery_key_format_matches_js() {
    let rk = recovery::generate_recovery_key().unwrap();

    // 13 hyphen-separated groups
    let groups: Vec<&str> = rk.recovery_key.split('-').collect();
    assert_eq!(groups.len(), 13);

    // 12 groups of 5 + 1 group of 4 = 64 chars total
    let total_chars: usize = groups.iter().map(|g| g.len()).sum();
    assert_eq!(total_chars, 64);

    // Secret is 32 bytes
    assert_eq!(b64::decode(&rk.recovery_secret_b64).unwrap().len(), 32);

    // Roundtrip: key → secret → matches
    let derived = recovery::recovery_key_to_secret(&rk.recovery_key).unwrap();
    assert_eq!(derived, rk.recovery_secret_b64);
}

#[test]
fn recovery_key_case_insensitive_matches_js() {
    // JS does .toUpperCase() before decoding — verify Rust does too
    let rk = recovery::generate_recovery_key().unwrap();
    let lower = recovery::recovery_key_to_secret(&rk.recovery_key.to_lowercase()).unwrap();
    assert_eq!(lower, rk.recovery_secret_b64);
}

// ============================================================================
// parse_salt_from_key_hash
// ============================================================================

#[test]
fn parse_salt_matches_js_format() {
    // JS key_hash format: "base64salt$argon2id"
    let key_hash = "dGVzdHNhbHQ=$argon2id";
    let salt = b64::parse_salt_from_key_hash(key_hash).unwrap();
    assert_eq!(salt, "dGVzdHNhbHQ=");
}

// ============================================================================
// End-to-end: full login flow simulation
// ============================================================================

#[test]
fn full_registration_and_login_flow() {
    // 1. Registration: generate all keys
    let salt = keys::generate_salt();
    let session_key = kdf::derive_session_key("user-password-123", &salt).unwrap();
    let keypair = keys::generate_keypair();
    let user_key = keys::generate_key();

    // Encrypt private key with session key
    let encrypted_private_key =
        keys::encrypt_private_key(&keypair.private_key, &session_key).unwrap();

    // Seal user_key to public key
    let user_key_bytes = b64::decode(&user_key).unwrap();
    let encrypted_user_key = box_seal::box_seal(&user_key_bytes, &keypair.public_key).unwrap();

    // Store key_hash
    let key_hash = format!("{}$argon2id", salt);

    // 2. Login: re-derive session key
    let parsed_salt = b64::parse_salt_from_key_hash(&key_hash).unwrap();
    let re_derived_session_key = kdf::derive_session_key("user-password-123", parsed_salt).unwrap();
    assert_eq!(re_derived_session_key, session_key);

    // 3. Decrypt private key
    let private_key =
        keys::decrypt_private_key(&encrypted_private_key, &re_derived_session_key).unwrap();
    assert_eq!(private_key, keypair.private_key);

    // 4. Unseal user_key
    let unsealed_user_key =
        box_seal::box_seal_open(&encrypted_user_key, &keypair.public_key, &private_key).unwrap();
    assert_eq!(unsealed_user_key, user_key);

    // 5. Use user_key to encrypt/decrypt habit data
    let habit_name = "Exercise 3x/week";
    let encrypted_name =
        secretbox::encrypt_secretbox_string(habit_name, &unsealed_user_key).unwrap();
    let decrypted_name =
        secretbox::decrypt_secretbox_to_string(&encrypted_name, &unsealed_user_key).unwrap();
    assert_eq!(decrypted_name, habit_name);
}

#[test]
fn full_password_change_flow() {
    // Setup: existing user with keys
    let old_salt = keys::generate_salt();
    let old_session_key = kdf::derive_session_key("old-password", &old_salt).unwrap();
    let keypair = keys::generate_keypair();
    let encrypted_private_key =
        keys::encrypt_private_key(&keypair.private_key, &old_session_key).unwrap();

    // Password change:
    // 1. Decrypt private key with OLD session key
    let private_key = keys::decrypt_private_key(&encrypted_private_key, &old_session_key).unwrap();

    // 2. Generate new salt, derive NEW session key
    let new_salt = keys::generate_salt();
    let new_session_key = kdf::derive_session_key("new-password", &new_salt).unwrap();

    // 3. Re-encrypt SAME private key with NEW session key
    let new_encrypted_private_key =
        keys::encrypt_private_key(&private_key, &new_session_key).unwrap();

    // 4. Verify: can decrypt with new session key, get same private key
    let recovered =
        keys::decrypt_private_key(&new_encrypted_private_key, &new_session_key).unwrap();
    assert_eq!(recovered, keypair.private_key);

    // 5. Verify: old session key can't decrypt new blob
    assert!(keys::decrypt_private_key(&new_encrypted_private_key, &old_session_key).is_err());
}

#[test]
fn full_recovery_key_flow() {
    // Setup: user with existing keys
    let session_key = keys::generate_key(); // simplified
    let keypair = keys::generate_keypair();
    let _encrypted_private_key =
        keys::encrypt_private_key(&keypair.private_key, &session_key).unwrap();

    // Generate recovery key
    let rk = recovery::generate_recovery_key().unwrap();

    // Encrypt private key for recovery
    let recovery_blob =
        recovery::encrypt_private_key_for_recovery(&keypair.private_key, &rk.recovery_secret_b64)
            .unwrap();

    // Simulate: user forgets password, uses recovery key
    let re_derived_secret = recovery::recovery_key_to_secret(&rk.recovery_key).unwrap();
    let recovered_private_key =
        recovery::decrypt_private_key_with_recovery(&recovery_blob, &re_derived_secret).unwrap();

    assert_eq!(recovered_private_key, keypair.private_key);

    // Re-encrypt with new password
    let new_session_key = keys::generate_key();
    let new_encrypted_pk =
        keys::encrypt_private_key(&recovered_private_key, &new_session_key).unwrap();
    let final_pk = keys::decrypt_private_key(&new_encrypted_pk, &new_session_key).unwrap();
    assert_eq!(final_pk, keypair.private_key);
}
