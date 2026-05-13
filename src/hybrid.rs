//! Hybrid post-quantum KEM: ML-KEM-768 + X25519 (Cat-3) and ML-KEM-1024 + X25519 (Cat-5).
//!
//! This module implements hybrid KEMs combining ML-KEM with X25519, ensuring
//! byte-level compatibility with existing production ciphertext.
//!
//! ## Security Levels
//!
//! | Level | ML-KEM | NIST Category | Equivalent | Version Tag |
//! |-------|--------|---------------|------------|-------------|
//! | Cat-3 | 768    | 3             | ~AES-192   | `0x02`      |
//! | Cat-5 | 1024   | 5             | ~AES-256   | `0x03`      |
//!
//! ## Construction (from noble source)
//!
//! ```text
//! combineKEMS(
//!   seedLen = 32,
//!   outputLen = 32,
//!   expandSeed = SHAKE256(seed, dkLen=96 | 128),
//!   combiner = SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || b"\\.//^\\"),
//!   ml_kem{768|1024},
//!   ecdhKem(x25519)
//! )
//! ```
//!
//! ## Key layout (Cat-3 / Cat-5)
//!
//! | Component | Cat-3 (768) | Cat-5 (1024) | Description |
//! |-----------|-------------|--------------|-------------|
//! | Secret key (seed) | 32 bytes | 32 bytes | Root seed expanded via SHAKE256 |
//! | Public key | 1216 bytes | 1600 bytes | ML-KEM ek ‖ X25519 pk (32) |
//! | Ciphertext | 1120 bytes | 1600 bytes | ML-KEM ct ‖ X25519 ephemeral pk (32) |
//! | Shared secret | 32 bytes | 32 bytes | SHA3-256 combiner output |
//!
//! ## Sealed-box ciphertext format
//!
//! ```text
//! v2: 0x02 || hybrid_ciphertext_768 (1120 B) || nonce (24 B) || secretbox_ct
//! v3: 0x03 || hybrid_ciphertext_1024 (1600 B) || nonce (24 B) || secretbox_ct
//! ```

use ml_kem::{Decapsulate, MlKem768, MlKem1024};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crypto_secretbox::aead::Aead;
use crypto_secretbox::aead::generic_array::GenericArray;
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};

use crate::CryptoError;
use crate::b64;

// === Constants ===

/// Version tag for Cat-3 hybrid ciphertext (ML-KEM-768).
const VERSION_HYBRID_768: u8 = 0x02;
/// Version tag for Cat-5 hybrid ciphertext (ML-KEM-1024).
const VERSION_HYBRID_1024: u8 = 0x03;
/// XSalsa20 nonce length.
const NONCE_LEN: usize = 24;
/// X25519 key size.
const X25519_LEN: usize = 32;
/// Root seed length.
const SEED_LEN: usize = 32;
/// Poly1305 MAC.
const MAC_LEN: usize = 16;
/// Noble's domain-separation label.
const LABEL: &[u8] = b"\\.//^\\";

// ML-KEM-768 (Cat-3)
/// ML-KEM-768 encapsulation key size.
const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext size.
const MLKEM768_CT_LEN: usize = 1088;
/// ML-KEM-768 seed portion (64 bytes).
const MLKEM768_SEED_LEN: usize = 64;
/// Expanded seed for Cat-3: ML-KEM seed (64) + X25519 secret (32).
const EXPANDED_SEED_768_LEN: usize = 96;
/// Combined public key for Cat-3: ML-KEM ek (1184) + X25519 pk (32).
const COMBINED_PK_768_LEN: usize = MLKEM768_EK_LEN + X25519_LEN;
/// Combined ciphertext for Cat-3: ML-KEM ct (1088) + X25519 ephemeral pk (32).
const COMBINED_CT_768_LEN: usize = MLKEM768_CT_LEN + X25519_LEN;

// ML-KEM-1024 (Cat-5)
/// ML-KEM-1024 encapsulation key size.
const MLKEM1024_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext size.
const MLKEM1024_CT_LEN: usize = 1568;
/// ML-KEM-1024 seed portion (64 bytes).
const MLKEM1024_SEED_LEN: usize = 64;
/// Expanded seed for Cat-5: ML-KEM seed (64) + X25519 secret (32).
const EXPANDED_SEED_1024_LEN: usize = 96;
/// Combined public key for Cat-5: ML-KEM ek (1568) + X25519 pk (32).
const COMBINED_PK_1024_LEN: usize = MLKEM1024_EK_LEN + X25519_LEN;
/// Combined ciphertext for Cat-5: ML-KEM ct (1568) + X25519 ephemeral pk (32).
const COMBINED_CT_1024_LEN: usize = MLKEM1024_CT_LEN + X25519_LEN;

// === Types ===

/// A hybrid ML-KEM + X25519 keypair (base64-encoded).
#[derive(Debug, Clone)]
pub struct HybridKeyPair {
    /// Combined public key: ML-KEM ek ‖ X25519 pk. Base64.
    pub public_key: String,
    /// Root seed (32 bytes). Base64.
    pub secret_key: String,
}

/// Security level for hybrid PQ operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityLevel {
    /// NIST Category 3: ML-KEM-768 + X25519 (~AES-192). Default.
    #[default]
    Cat3,
    /// NIST Category 5: ML-KEM-1024 + X25519 (~AES-256).
    Cat5,
}

// === Helpers ===

/// Fill buffer with OS random bytes.
#[inline]
fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Expand a 32-byte seed using SHAKE256.
fn expand_seed(seed: &[u8; SEED_LEN], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; output_len];
    reader.read(&mut out);
    out
}

/// SHA3-256 combiner: `SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || label)`
fn combine(
    ss_mlkem: &[u8],
    ss_x25519: &[u8],
    ct_x25519: &[u8; X25519_LEN],
    pk_x25519: &[u8; X25519_LEN],
) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    Digest::update(&mut hasher, ss_mlkem);
    Digest::update(&mut hasher, ss_x25519);
    Digest::update(&mut hasher, ct_x25519);
    Digest::update(&mut hasher, pk_x25519);
    Digest::update(&mut hasher, LABEL);
    hasher.finalize().into()
}

/// Encrypt plaintext with a 32-byte shared secret using XSalsa20-Poly1305.
fn secretbox_encrypt(
    shared_secret: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_LEN]), CryptoError> {
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(shared_secret));
    let mut nonce_buf = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_buf);
    let nonce = GenericArray::from_slice(&nonce_buf);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Hybrid("secretbox encrypt failed".into()))?;
    Ok((ct, nonce_buf))
}

/// Decrypt ciphertext with a 32-byte shared secret using XSalsa20-Poly1305.
fn secretbox_decrypt(
    shared_secret: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(shared_secret));
    let nonce = GenericArray::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decryption)
}

// === Public API: Cat-3 (ML-KEM-768, default) ===

/// Generate a hybrid ML-KEM-768 + X25519 keypair (Cat-3, default).
pub fn generate_hybrid_keypair() -> HybridKeyPair {
    generate_hybrid_keypair_with_level(SecurityLevel::Cat3)
}

/// Seal `plaintext` to a Cat-3 hybrid public key (ML-KEM-768).
///
/// Returns base64: `0x02 || hybrid_ct (1120 B) || nonce (24 B) || secretbox_ct`.
pub fn hybrid_seal(plaintext: &[u8], combined_pk_b64: &str) -> Result<String, CryptoError> {
    hybrid_seal_with_level(plaintext, combined_pk_b64, SecurityLevel::Cat3)
}

/// Open a Cat-3 or Cat-5 hybrid-sealed ciphertext. Auto-detects from version tag.
pub fn hybrid_open(ct_b64: &str, seed_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let combined = b64::decode(ct_b64)?;
    match combined.first() {
        Some(&VERSION_HYBRID_768) => hybrid_open_768(&combined, seed_b64),
        Some(&VERSION_HYBRID_1024) => hybrid_open_1024(&combined, seed_b64),
        _ => Err(CryptoError::Hybrid(
            "not a hybrid ciphertext (bad version tag)".into(),
        )),
    }
}

/// Returns `true` if the base64 blob starts with a hybrid version tag (0x02 or 0x03).
pub fn is_hybrid_ciphertext(ct_b64: &str) -> bool {
    b64::decode(ct_b64)
        .map(|bytes| {
            matches!(
                bytes.first(),
                Some(&VERSION_HYBRID_768) | Some(&VERSION_HYBRID_1024)
            )
        })
        .unwrap_or(false)
}

// === Public API: Cat-5 (ML-KEM-1024) ===

/// Generate a hybrid ML-KEM-1024 + X25519 keypair (Cat-5).
pub fn generate_hybrid_keypair_1024() -> HybridKeyPair {
    generate_hybrid_keypair_with_level(SecurityLevel::Cat5)
}

/// Seal `plaintext` to a Cat-5 hybrid public key (ML-KEM-1024).
///
/// Returns base64: `0x03 || hybrid_ct (1600 B) || nonce (24 B) || secretbox_ct`.
pub fn hybrid_seal_1024(plaintext: &[u8], combined_pk_b64: &str) -> Result<String, CryptoError> {
    hybrid_seal_with_level(plaintext, combined_pk_b64, SecurityLevel::Cat5)
}

// === Public API: Level-parametric ===

/// Generate a hybrid keypair at the specified security level.
pub fn generate_hybrid_keypair_with_level(level: SecurityLevel) -> HybridKeyPair {
    let mut seed = [0u8; SEED_LEN];
    random_bytes(&mut seed);

    let expanded_len = match level {
        SecurityLevel::Cat3 => EXPANDED_SEED_768_LEN,
        SecurityLevel::Cat5 => EXPANDED_SEED_1024_LEN,
    };
    let mlkem_seed_len = match level {
        SecurityLevel::Cat3 => MLKEM768_SEED_LEN,
        SecurityLevel::Cat5 => MLKEM1024_SEED_LEN,
    };

    let mut expanded = expand_seed(&seed, expanded_len);
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[mlkem_seed_len..].try_into().unwrap();

    // X25519 keypair
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    let combined_pk = match level {
        SecurityLevel::Cat3 => {
            let mlkem_seed: [u8; MLKEM768_SEED_LEN] =
                expanded[..MLKEM768_SEED_LEN].try_into().unwrap();
            let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed.into());
            let ek = dk.encapsulation_key();
            let ek_bytes = ek.to_bytes();
            let mut pk = Vec::with_capacity(COMBINED_PK_768_LEN);
            pk.extend_from_slice(&ek_bytes);
            pk.extend_from_slice(x25519_pk.as_bytes());
            pk
        }
        SecurityLevel::Cat5 => {
            let mlkem_seed: [u8; MLKEM1024_SEED_LEN] =
                expanded[..MLKEM1024_SEED_LEN].try_into().unwrap();
            let dk = DecapsulationKey::<MlKem1024>::from_seed(mlkem_seed.into());
            let ek = dk.encapsulation_key();
            let ek_bytes = ek.to_bytes();
            let mut pk = Vec::with_capacity(COMBINED_PK_1024_LEN);
            pk.extend_from_slice(&ek_bytes);
            pk.extend_from_slice(x25519_pk.as_bytes());
            pk
        }
    };

    let pair = HybridKeyPair {
        public_key: b64::encode(&combined_pk),
        secret_key: b64::encode(&seed),
    };

    seed.zeroize();
    expanded.zeroize();
    pair
}

/// Seal plaintext at the specified security level.
pub fn hybrid_seal_with_level(
    plaintext: &[u8],
    combined_pk_b64: &str,
    level: SecurityLevel,
) -> Result<String, CryptoError> {
    let pk_bytes = b64::decode(combined_pk_b64)?;

    let (expected_pk_len, mlkem_ek_len, version_tag) = match level {
        SecurityLevel::Cat3 => (COMBINED_PK_768_LEN, MLKEM768_EK_LEN, VERSION_HYBRID_768),
        SecurityLevel::Cat5 => (COMBINED_PK_1024_LEN, MLKEM1024_EK_LEN, VERSION_HYBRID_1024),
    };

    if pk_bytes.len() != expected_pk_len {
        return Err(CryptoError::InvalidLength {
            expected: expected_pk_len,
            got: pk_bytes.len(),
        });
    }

    // Split combined public key
    let mlkem_ek_bytes = &pk_bytes[..mlkem_ek_len];
    let x25519_pk_bytes: [u8; X25519_LEN] = pk_bytes[mlkem_ek_len..].try_into().unwrap();

    // ML-KEM encapsulate
    let mut mlkem_coins = [0u8; 32];
    random_bytes(&mut mlkem_coins);

    let (mlkem_ct_bytes, ss_mlkem_bytes) = match level {
        SecurityLevel::Cat3 => {
            let ek = EncapsulationKey::<MlKem768>::new(
                mlkem_ek_bytes
                    .try_into()
                    .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 ek".into()))?,
            )
            .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 encapsulation key".into()))?;
            let (ct, ss) = ek.encapsulate_deterministic(&mlkem_coins.into());
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        SecurityLevel::Cat5 => {
            let ek = EncapsulationKey::<MlKem1024>::new(
                mlkem_ek_bytes
                    .try_into()
                    .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 ek".into()))?,
            )
            .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 encapsulation key".into()))?;
            let (ct, ss) = ek.encapsulate_deterministic(&mlkem_coins.into());
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
    };
    mlkem_coins.zeroize();

    // X25519 encapsulate (ephemeral DH)
    let mut x25519_eph_bytes = [0u8; X25519_LEN];
    random_bytes(&mut x25519_eph_bytes);
    let x25519_eph_sk = X25519StaticSecret::from(x25519_eph_bytes);
    let x25519_eph_pk = X25519PublicKey::from(&x25519_eph_sk);
    let x25519_recipient_pk = X25519PublicKey::from(x25519_pk_bytes);
    let ss_x25519 = x25519_eph_sk.diffie_hellman(&x25519_recipient_pk);
    x25519_eph_bytes.zeroize();

    // Combine shared secrets
    let ct_x25519: [u8; X25519_LEN] = *x25519_eph_pk.as_bytes();
    let mut shared_secret = combine(
        &ss_mlkem_bytes,
        ss_x25519.as_bytes(),
        &ct_x25519,
        &x25519_pk_bytes,
    );

    // Encrypt plaintext
    let (secretbox_ct, nonce_buf) = secretbox_encrypt(&shared_secret, plaintext)?;
    shared_secret.zeroize();

    // Assemble: version || mlkem_ct || x25519_eph_pk || nonce || secretbox_ct
    let combined_ct_len = mlkem_ct_bytes.len() + X25519_LEN;
    let mut out = Vec::with_capacity(1 + combined_ct_len + NONCE_LEN + secretbox_ct.len());
    out.push(version_tag);
    out.extend_from_slice(&mlkem_ct_bytes);
    out.extend_from_slice(&ct_x25519);
    out.extend_from_slice(&nonce_buf);
    out.extend_from_slice(&secretbox_ct);

    Ok(b64::encode(&out))
}

// === Internal: Cat-3 open ===

fn hybrid_open_768(combined: &[u8], seed_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let seed_bytes = b64::decode(seed_b64)?;
    if seed_bytes.len() != SEED_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SEED_LEN,
            got: seed_bytes.len(),
        });
    }
    if combined.len() < 1 + COMBINED_CT_768_LEN + NONCE_LEN + MAC_LEN {
        return Err(CryptoError::TooShort);
    }

    let seed: [u8; SEED_LEN] = seed_bytes.try_into().unwrap();
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_768_LEN);
    let mlkem_seed: [u8; MLKEM768_SEED_LEN] = expanded[..MLKEM768_SEED_LEN].try_into().unwrap();
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[MLKEM768_SEED_LEN..].try_into().unwrap();
    expanded.zeroize();

    // Parse ciphertext
    let mlkem_ct = &combined[1..1 + MLKEM768_CT_LEN];
    let x25519_eph_pk_bytes: [u8; X25519_LEN] = combined
        [1 + MLKEM768_CT_LEN..1 + COMBINED_CT_768_LEN]
        .try_into()
        .unwrap();
    let nonce_slice = &combined[1 + COMBINED_CT_768_LEN..1 + COMBINED_CT_768_LEN + NONCE_LEN];
    let encrypted = &combined[1 + COMBINED_CT_768_LEN + NONCE_LEN..];

    // ML-KEM-768 decapsulate
    let dk = DecapsulationKey::<MlKem768>::from_seed(mlkem_seed.into());
    let kem_ct = mlkem_ct
        .try_into()
        .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-768 ciphertext".into()))?;
    let ss_mlkem = dk.decapsulate(kem_ct);

    // X25519 decapsulate
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_eph_pk = X25519PublicKey::from(x25519_eph_pk_bytes);
    let ss_x25519 = x25519_sk.diffie_hellman(&x25519_eph_pk);

    let x25519_pk = X25519PublicKey::from(&x25519_sk);
    let pk_x25519: [u8; X25519_LEN] = *x25519_pk.as_bytes();

    let mut shared_secret = combine(
        ss_mlkem.as_slice(),
        ss_x25519.as_bytes(),
        &x25519_eph_pk_bytes,
        &pk_x25519,
    );

    let result = secretbox_decrypt(&shared_secret, nonce_slice, encrypted);
    shared_secret.zeroize();
    result
}

// === Internal: Cat-5 open ===

fn hybrid_open_1024(combined: &[u8], seed_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let seed_bytes = b64::decode(seed_b64)?;
    if seed_bytes.len() != SEED_LEN {
        return Err(CryptoError::InvalidLength {
            expected: SEED_LEN,
            got: seed_bytes.len(),
        });
    }
    if combined.len() < 1 + COMBINED_CT_1024_LEN + NONCE_LEN + MAC_LEN {
        return Err(CryptoError::TooShort);
    }

    let seed: [u8; SEED_LEN] = seed_bytes.try_into().unwrap();
    let mut expanded = expand_seed(&seed, EXPANDED_SEED_1024_LEN);
    let mlkem_seed: [u8; MLKEM1024_SEED_LEN] = expanded[..MLKEM1024_SEED_LEN].try_into().unwrap();
    let x25519_sk_bytes: [u8; X25519_LEN] = expanded[MLKEM1024_SEED_LEN..].try_into().unwrap();
    expanded.zeroize();

    // Parse ciphertext
    let mlkem_ct = &combined[1..1 + MLKEM1024_CT_LEN];
    let x25519_eph_pk_bytes: [u8; X25519_LEN] = combined
        [1 + MLKEM1024_CT_LEN..1 + COMBINED_CT_1024_LEN]
        .try_into()
        .unwrap();
    let nonce_slice = &combined[1 + COMBINED_CT_1024_LEN..1 + COMBINED_CT_1024_LEN + NONCE_LEN];
    let encrypted = &combined[1 + COMBINED_CT_1024_LEN + NONCE_LEN..];

    // ML-KEM-1024 decapsulate
    let dk = DecapsulationKey::<MlKem1024>::from_seed(mlkem_seed.into());
    let kem_ct = mlkem_ct
        .try_into()
        .map_err(|_| CryptoError::Hybrid("invalid ML-KEM-1024 ciphertext".into()))?;
    let ss_mlkem = dk.decapsulate(kem_ct);

    // X25519 decapsulate
    let x25519_sk = X25519StaticSecret::from(x25519_sk_bytes);
    let x25519_eph_pk = X25519PublicKey::from(x25519_eph_pk_bytes);
    let ss_x25519 = x25519_sk.diffie_hellman(&x25519_eph_pk);

    let x25519_pk = X25519PublicKey::from(&x25519_sk);
    let pk_x25519: [u8; X25519_LEN] = *x25519_pk.as_bytes();

    let mut shared_secret = combine(
        ss_mlkem.as_slice(),
        ss_x25519.as_bytes(),
        &x25519_eph_pk_bytes,
        &pk_x25519,
    );

    let result = secretbox_decrypt(&shared_secret, nonce_slice, encrypted);
    shared_secret.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Cat-3 (existing behavior) ===

    #[test]
    fn cat3_roundtrip() {
        let kp = generate_hybrid_keypair();
        let pt = b"32-byte symmetric context key!!!";
        let ct = hybrid_seal(pt, &kp.public_key).unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        let opened = hybrid_open(&ct, &kp.secret_key).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn cat3_wrong_key_fails() {
        let kp1 = generate_hybrid_keypair();
        let kp2 = generate_hybrid_keypair();
        let ct = hybrid_seal(b"x", &kp1.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp2.secret_key).is_err());
    }

    #[test]
    fn cat3_version_tag() {
        let kp = generate_hybrid_keypair();
        let raw = b64::decode(&hybrid_seal(b"x", &kp.public_key).unwrap()).unwrap();
        assert_eq!(raw[0], VERSION_HYBRID_768);
    }

    #[test]
    fn cat3_nondeterministic() {
        let kp = generate_hybrid_keypair();
        let c1 = hybrid_seal(b"x", &kp.public_key).unwrap();
        let c2 = hybrid_seal(b"x", &kp.public_key).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn cat3_empty_plaintext() {
        let kp = generate_hybrid_keypair();
        let ct = hybrid_seal(b"", &kp.public_key).unwrap();
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"");
    }

    #[test]
    fn cat3_key_sizes() {
        let kp = generate_hybrid_keypair();
        let pk = b64::decode(&kp.public_key).unwrap();
        let sk = b64::decode(&kp.secret_key).unwrap();
        assert_eq!(pk.len(), COMBINED_PK_768_LEN); // 1216
        assert_eq!(sk.len(), SEED_LEN); // 32
    }

    #[test]
    fn cat3_ciphertext_size() {
        let kp = generate_hybrid_keypair();
        let pt = b"exactly 32 bytes of key material";
        let raw = b64::decode(&hybrid_seal(pt, &kp.public_key).unwrap()).unwrap();
        // 1 + 1120 + 24 + 32 + 16 = 1193
        assert_eq!(
            raw.len(),
            1 + COMBINED_CT_768_LEN + NONCE_LEN + 32 + MAC_LEN
        );
    }

    // === Cat-5 (new) ===

    #[test]
    fn cat5_roundtrip() {
        let kp = generate_hybrid_keypair_1024();
        let pt = b"32-byte symmetric context key!!!";
        let ct = hybrid_seal_1024(pt, &kp.public_key).unwrap();
        assert!(is_hybrid_ciphertext(&ct));
        let opened = hybrid_open(&ct, &kp.secret_key).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn cat5_version_tag() {
        let kp = generate_hybrid_keypair_1024();
        let raw = b64::decode(&hybrid_seal_1024(b"x", &kp.public_key).unwrap()).unwrap();
        assert_eq!(raw[0], VERSION_HYBRID_1024);
    }

    #[test]
    fn cat5_wrong_key_fails() {
        let kp1 = generate_hybrid_keypair_1024();
        let kp2 = generate_hybrid_keypair_1024();
        let ct = hybrid_seal_1024(b"x", &kp1.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp2.secret_key).is_err());
    }

    #[test]
    fn cat5_key_sizes() {
        let kp = generate_hybrid_keypair_1024();
        let pk = b64::decode(&kp.public_key).unwrap();
        let sk = b64::decode(&kp.secret_key).unwrap();
        assert_eq!(pk.len(), COMBINED_PK_1024_LEN); // 1600
        assert_eq!(sk.len(), SEED_LEN); // 32
    }

    #[test]
    fn cat5_ciphertext_size() {
        let kp = generate_hybrid_keypair_1024();
        let pt = b"exactly 32 bytes of key material";
        let raw = b64::decode(&hybrid_seal_1024(pt, &kp.public_key).unwrap()).unwrap();
        // 1 + 1600 + 24 + 32 + 16 = 1673
        assert_eq!(
            raw.len(),
            1 + COMBINED_CT_1024_LEN + NONCE_LEN + 32 + MAC_LEN
        );
    }

    #[test]
    fn cat5_nondeterministic() {
        let kp = generate_hybrid_keypair_1024();
        let c1 = hybrid_seal_1024(b"x", &kp.public_key).unwrap();
        let c2 = hybrid_seal_1024(b"x", &kp.public_key).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn cat5_empty_plaintext() {
        let kp = generate_hybrid_keypair_1024();
        let ct = hybrid_seal_1024(b"", &kp.public_key).unwrap();
        assert_eq!(hybrid_open(&ct, &kp.secret_key).unwrap(), b"");
    }

    // === Cross-level ===

    #[test]
    fn cat3_ct_cannot_open_with_cat5_key() {
        let kp3 = generate_hybrid_keypair();
        let kp5 = generate_hybrid_keypair_1024();
        let ct = hybrid_seal(b"test", &kp3.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp5.secret_key).is_err());
    }

    #[test]
    fn cat5_ct_cannot_open_with_cat3_key() {
        let kp3 = generate_hybrid_keypair();
        let kp5 = generate_hybrid_keypair_1024();
        let ct = hybrid_seal_1024(b"test", &kp5.public_key).unwrap();
        assert!(hybrid_open(&ct, &kp3.secret_key).is_err());
    }

    #[test]
    fn legacy_not_hybrid() {
        let legacy = b64::encode(&[0x01, 0x02, 0x03]);
        assert!(!is_hybrid_ciphertext(&legacy));
    }

    #[test]
    fn seed_expansion_deterministic() {
        let seed = [0x42u8; SEED_LEN];
        let expanded = expand_seed(&seed, 96);
        let expanded2 = expand_seed(&seed, 96);
        assert_eq!(expanded, expanded2);
    }

    #[test]
    fn combiner_uses_label() {
        let ss_mlkem = [0xAAu8; 32];
        let ss_x25519 = [0xBBu8; 32];
        let ct_x25519 = [0xCCu8; 32];
        let pk_x25519 = [0xDDu8; 32];
        let result = combine(&ss_mlkem, &ss_x25519, &ct_x25519, &pk_x25519);
        assert_eq!(result.len(), 32);

        let ss_mlkem2 = [0xEEu8; 32];
        let result2 = combine(&ss_mlkem2, &ss_x25519, &ct_x25519, &pk_x25519);
        assert_ne!(result, result2);
    }
}
