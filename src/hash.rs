//! Cryptographic hash functions (SHA-3 and SHA-2 families).
//!
//! These are thin, one-shot wrappers over the already-audited [`sha3`] and
//! [`sha2`] RustCrypto crates. They expose no new or novel cryptography — they
//! simply make the digest primitives the rest of the crate already depends on
//! available as public API.
//!
//! ## Which one should I use?
//!
//! [`sha3_512`] is the recommended default for new code. It is the highest-assurance
//! option here (~256-bit collision resistance, NIST Category 5) and keeps callers
//! consistent with this crate's Keccak-based hybrid combiner. The other functions
//! are provided so integrators can pick a level that matches an existing format or
//! interoperability requirement.
//!
//! | Function     | Algorithm  | Output | Notes                              |
//! |--------------|------------|--------|------------------------------------|
//! | [`sha3_512`] | SHA3-512   | 64 B   | Recommended default (Cat-5).       |
//! | [`sha3_256`] | SHA3-256   | 32 B   | Same family as the hybrid combiner.|
//! | [`sha256`]   | SHA-256    | 32 B   | SHA-2; for SHA-2 interop.          |
//! | [`sha512`]   | SHA-512    | 64 B   | SHA-2; for SHA-2 interop.          |
//!
//! ## Encoding
//!
//! The native functions take raw bytes (`&[u8]`) and return fixed-size byte
//! arrays. Encode the result yourself when needed, e.g. with [`crate::b64::encode`]
//! for base64. The WASM bindings (see [`crate::wasm`]) operate on base64 strings to
//! match the rest of the WASM API.
//!
//! ## Security note
//!
//! These digests are intended for **public** data only — specifically key
//! fingerprints / safety numbers and key-transparency-log entries, where both
//! the input (e.g. a public key) and the output digest are meant to be public.
//!
//! Because the input is public, the zeroize-on-drop and constant-time concerns
//! that apply to the encryption APIs in this crate do not apply here, and no
//! such ceremony is added. This is deliberate, not an oversight: a bare hash
//! makes **no** guarantees about its inputs, and wiping a transient copy of
//! already-public data would add cost without adding protection (the underlying
//! RustCrypto `sha2`/`sha3` primitives do not zeroize their internal state
//! either, and callers routinely hold the input elsewhere).
//!
//! **Do not feed secret material (passwords, private keys, shared secrets) to a
//! bare hash here.** If you need to process secrets, use the right construction
//! instead — this crate's Argon2id [`crate::kdf::derive_session_key`] for
//! password-based derivation, or a dedicated KDF/MAC. The encryption APIs that
//! *do* handle secrets already zeroize that material on drop.

use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

/// Compute the SHA3-512 digest of `data`, returning 64 bytes.
///
/// This is the recommended default hash for new code (NIST Category 5,
/// ~256-bit collision resistance).
///
/// ```
/// use metamorphic_crypto::hash::sha3_512;
///
/// let digest = sha3_512(b"hello, metamorphic!");
/// assert_eq!(digest.len(), 64);
/// // The empty-input digest is a well-known SHA3-512 test vector.
/// assert_eq!(
///     &sha3_512(b"")[..4],
///     &[0xa6, 0x9f, 0x73, 0xcc]
/// );
/// ```
#[inline]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data).into()
}

/// Compute a **domain-separated** SHA3-512 digest of `data` under `context`.
///
/// This binds the digest to a caller-chosen context label, so the same `data`
/// hashed under two different contexts yields unrelated digests. Prefer this
/// over bare [`sha3_512`] for fingerprints, safety numbers, and
/// key-transparency-log entries: it guarantees a digest computed for one
/// purpose can never be reinterpreted as a digest for another (cross-protocol /
/// cross-context collision resistance), and it makes the intent explicit at the
/// call site.
///
/// It is exactly as collision- and preimage-resistant as [`sha3_512`] — it *is*
/// SHA3-512, just over an unambiguously framed message.
///
/// ## Encoding (stable wire format — reproduce exactly for cross-language parity)
///
/// ```text
/// digest = SHA3-512( I2OSP(len(context), 8) || context_utf8 || data )
/// ```
///
/// where `I2OSP(len, 8)` is the byte length of `context` (its UTF-8 encoding)
/// as a **big-endian unsigned 64-bit integer**. The length prefix makes the
/// `(context, data)` boundary unambiguous, so distinct `(context, data)` pairs
/// cannot collide by boundary confusion. Any client (native Rust, WASM, the
/// Elixir NIF, or hand-rolled JS) that reproduces this framing computes an
/// identical digest.
///
/// `context` is a UTF-8 label, conventionally a versioned namespace such as
/// `"mosslet/key-fingerprint/v1"`. An empty context is permitted (it still
/// differs from `sha3_512(data)` because of the length prefix) but is
/// discouraged — pick an explicit label.
///
/// ```
/// use metamorphic_crypto::hash::sha3_512_with_context;
///
/// let fp = sha3_512_with_context("mosslet/key-fingerprint/v1", b"public key bytes");
/// assert_eq!(fp.len(), 64);
///
/// // Same bytes under a different context produce an unrelated digest.
/// let log = sha3_512_with_context("mosslet/log-entry/v1", b"public key bytes");
/// assert_ne!(fp, log);
/// ```
#[inline]
pub fn sha3_512_with_context(context: &str, data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update((context.len() as u64).to_be_bytes());
    hasher.update(context.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the SHA3-256 digest of `data`, returning 32 bytes.
///
/// This is the same primitive used by the crate's hybrid KEM combiner.
///
/// ```
/// use metamorphic_crypto::hash::sha3_256;
///
/// let digest = sha3_256(b"hello, metamorphic!");
/// assert_eq!(digest.len(), 32);
/// ```
#[inline]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

/// Compute the SHA-256 (SHA-2 family) digest of `data`, returning 32 bytes.
///
/// Provided for interoperability with systems standardized on SHA-2. Prefer
/// [`sha3_512`] for new code.
///
/// ```
/// use metamorphic_crypto::hash::sha256;
///
/// let digest = sha256(b"hello, metamorphic!");
/// assert_eq!(digest.len(), 32);
/// ```
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Compute the SHA-512 (SHA-2 family) digest of `data`, returning 64 bytes.
///
/// Provided for interoperability with systems standardized on SHA-2. Prefer
/// [`sha3_512`] for new code.
///
/// ```
/// use metamorphic_crypto::hash::sha512;
///
/// let digest = sha512(b"hello, metamorphic!");
/// assert_eq!(digest.len(), 64);
/// ```
#[inline]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
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

    // === Known-answer tests (NIST / standard vectors) ===

    #[test]
    fn sha3_512_kat_empty() {
        // SHA3-512("")
        let expected = hex(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        );
        assert_eq!(sha3_512(b"").to_vec(), expected);
    }

    #[test]
    fn sha3_512_kat_abc() {
        // SHA3-512("abc")
        let expected = hex(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        );
        assert_eq!(sha3_512(b"abc").to_vec(), expected);
    }

    #[test]
    fn sha3_256_kat_empty() {
        // SHA3-256("")
        let expected = hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(sha3_256(b"").to_vec(), expected);
    }

    #[test]
    fn sha3_256_kat_abc() {
        // SHA3-256("abc")
        let expected = hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        assert_eq!(sha3_256(b"abc").to_vec(), expected);
    }

    #[test]
    fn sha256_kat_abc() {
        // SHA-256("abc")
        let expected = hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256(b"abc").to_vec(), expected);
    }

    #[test]
    fn sha512_kat_abc() {
        // SHA-512("abc")
        let expected = hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        assert_eq!(sha512(b"abc").to_vec(), expected);
    }

    #[test]
    fn distinct_inputs_distinct_digests() {
        assert_ne!(sha3_512(b"a"), sha3_512(b"b"));
    }

    #[test]
    fn deterministic() {
        assert_eq!(sha3_512(b"metamorphic"), sha3_512(b"metamorphic"));
    }

    // === Domain-separated SHA3-512 ===

    /// The documented framing is exactly `SHA3-512(u64_be(len(ctx)) || ctx || data)`.
    /// Prove it in terms of the already-KAT-verified `sha3_512`, so the wire
    /// format other languages must reproduce is pinned.
    #[test]
    fn with_context_matches_manual_framing() {
        let ctx = "mosslet/key-fingerprint/v1";
        let data = b"public key bytes";

        let mut framed = Vec::new();
        framed.extend_from_slice(&(ctx.len() as u64).to_be_bytes());
        framed.extend_from_slice(ctx.as_bytes());
        framed.extend_from_slice(data);

        assert_eq!(sha3_512_with_context(ctx, data), sha3_512(&framed));
    }

    #[test]
    fn with_context_separates_domains() {
        let data = b"public key bytes";
        assert_ne!(
            sha3_512_with_context("mosslet/key-fingerprint/v1", data),
            sha3_512_with_context("mosslet/log-entry/v1", data),
        );
    }

    #[test]
    fn with_context_differs_from_bare_hash() {
        // The length prefix guarantees this even for an empty context.
        assert_ne!(sha3_512_with_context("", b"data"), sha3_512(b"data"));
    }

    #[test]
    fn with_context_no_boundary_confusion() {
        // ("ab", "c") and ("a", "bc") must NOT collide — the length prefix
        // disambiguates where the context ends.
        assert_ne!(
            sha3_512_with_context("ab", b"c"),
            sha3_512_with_context("a", b"bc"),
        );
    }

    #[test]
    fn with_context_deterministic() {
        let a = sha3_512_with_context("ctx", b"data");
        let b = sha3_512_with_context("ctx", b"data");
        assert_eq!(a, b);
    }

    // === Property tests (matches the repo's existing use of proptest) ===

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn sha3_512_is_deterministic(data: Vec<u8>) {
            prop_assert_eq!(sha3_512(&data), sha3_512(&data));
        }

        #[test]
        fn sha3_512_output_is_always_64_bytes(data: Vec<u8>) {
            prop_assert_eq!(sha3_512(&data).len(), 64);
        }

        #[test]
        fn sha3_256_output_is_always_32_bytes(data: Vec<u8>) {
            prop_assert_eq!(sha3_256(&data).len(), 32);
        }
    }
}
