//! Message authentication codes (HMAC).
//!
//! A thin, one-shot wrapper over the audited [`hmac`] RustCrypto crate. It
//! exposes no new or novel cryptography — it makes the keyed-MAC primitive the
//! rest of the Metamorphic stack needs available as public API.
//!
//! ## Why this exists
//!
//! The IETF KEYTRANS protocol (`draft-ietf-keytrans-protocol`) specifies that
//! commitments in its **standard** cipher suites are computed as
//! `HMAC(Kc, CommitmentValue)` using the suite hash (SHA-256 for both currently
//! defined suites). [`metamorphic-log`] owns the KEYTRANS-specific framing (the
//! fixed key `Kc` and the `CommitmentValue` TLS encoding); this module supplies
//! only the generic HMAC-SHA256 primitive, keeping `metamorphic-crypto` the
//! single source of truth for cryptographic primitives.
//!
//! ## Security note
//!
//! HMAC's security rests on the key being secret *when used as an
//! authenticator*. In the KEYTRANS commitment construction the "key" is a
//! **fixed, public** per-suite constant and hiding comes from the random
//! `opening` inside the message — HMAC is used there as a committing PRF, not as
//! an authenticator. This primitive is generic; callers are responsible for
//! using it in a construction whose security properties they understand.
//!
//! [`metamorphic-log`]: https://github.com/moss-piglet/metamorphic-log

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// HMAC-SHA256 output length, in bytes (a SHA-256 digest).
pub const HMAC_SHA256_LEN: usize = 32;

/// Compute `HMAC-SHA256(key, msg)`, returning 32 bytes (RFC 2104 + FIPS 198-1).
///
/// The key may be any length: HMAC internally hashes an over-long key and
/// zero-pads a short one, so no length validation is required or performed.
///
/// ## Encoding (stable — reproduce exactly for cross-language parity)
///
/// This is standard HMAC-SHA256; any conformant implementation (native Rust,
/// WASM, the Elixir NIF, or hand-rolled JS) computes an identical tag for the
/// same `(key, msg)`.
///
/// ```
/// use metamorphic_crypto::mac::hmac_sha256;
///
/// // RFC 4231 Test Case 2.
/// let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
/// assert_eq!(
///     &tag[..4],
///     &[0x5b, 0xdc, 0xc1, 0x46],
/// );
/// ```
#[inline]
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; HMAC_SHA256_LEN] {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts a key of any length (RFC 2104)");
    mac.update(msg);
    mac.finalize().into_bytes().into()
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

    // === RFC 4231 known-answer vectors for HMAC-SHA-256 ===

    #[test]
    fn rfc4231_case_1() {
        let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hmac_sha256(&key, data).to_vec(), expected);
    }

    #[test]
    fn rfc4231_case_2() {
        // Key shorter than the block size; ASCII key and message.
        let expected = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
            expected
        );
    }

    #[test]
    fn rfc4231_case_3() {
        let key = vec![0xaau8; 20];
        let data = vec![0xddu8; 50];
        let expected = hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        assert_eq!(hmac_sha256(&key, &data).to_vec(), expected);
    }

    #[test]
    fn rfc4231_case_6_over_long_key() {
        // Test Case 6: key longer than the block size is hashed first.
        let key = vec![0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        assert_eq!(hmac_sha256(&key, data).to_vec(), expected);
    }

    #[test]
    fn distinct_keys_distinct_tags() {
        assert_ne!(hmac_sha256(b"k1", b"msg"), hmac_sha256(b"k2", b"msg"));
    }

    #[test]
    fn distinct_messages_distinct_tags() {
        assert_ne!(hmac_sha256(b"k", b"a"), hmac_sha256(b"k", b"b"));
    }

    #[test]
    fn empty_key_and_message_is_defined() {
        // HMAC is defined for any key/message length, including empty.
        assert_eq!(hmac_sha256(b"", b"").len(), HMAC_SHA256_LEN);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hmac_sha256_is_deterministic(key: Vec<u8>, msg: Vec<u8>) {
            prop_assert_eq!(hmac_sha256(&key, &msg), hmac_sha256(&key, &msg));
        }

        #[test]
        fn hmac_sha256_output_is_always_32_bytes(key: Vec<u8>, msg: Vec<u8>) {
            prop_assert_eq!(hmac_sha256(&key, &msg).len(), HMAC_SHA256_LEN);
        }
    }
}
