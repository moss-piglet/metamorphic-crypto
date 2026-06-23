# Changelog

## v0.4.0 (unreleased)

- Add a public hashing API (additive, non-breaking). Thin one-shot wrappers over
  the already-present, audited `sha3` dependency and a new `sha2` dependency.
  - New Rust module `hash`, re-exported at the crate root:
    `sha3_512` (recommended default, NIST Cat-5), `sha3_256`, `sha256`, `sha512`.
    Each takes `&[u8]` and returns a fixed-size byte array (`[u8; 64]` / `[u8; 32]`).
  - New domain-separated variant `sha3_512_with_context(context, data)` —
    recommended for key fingerprints, safety numbers, and key-transparency-log
    entries. Binds the digest to a versioned context label so the same bytes
    hashed for different purposes cannot collide or be cross-interpreted. Wire
    format: `SHA3-512( u64_be(len(context_utf8)) || context_utf8 || data )` (an
    8-byte big-endian length prefix removes boundary ambiguity). As strong as
    `sha3_512`; it *is* SHA3-512 over a framed message.
  - New WASM exports: `sha3_512`, `sha3_256`, `sha256`, `sha512`, and
    `sha3_512WithContext` — take base64-encoded input, return the digest as
    base64 (consistent with the rest of the WASM API).
  - Intended for public, non-secret digests (e.g. key fingerprints / safety
    numbers). A digest is not secret-bearing, so no zeroize/constant-time
    ceremony is added; this is called out explicitly in the docs.
  - Tests: NIST known-answer vectors for all four functions, native⇄WASM base64
    parity vectors, and proptest determinism/length properties.
  - Dependencies: add `sha2` 0.11 (RustCrypto, shares `digest` 0.11 with the
    existing `sha3` 0.11 — no second `digest`/`keccak` version, SBOM stays clean).
- All existing APIs unchanged — fully backward compatible.

## v0.3.7 (2026-06-10)

- No functional changes to the crate; output is byte-identical to v0.3.6.
- Dependencies: `sha3` 0.10 → 0.11. This unifies on a single `sha3`/`keccak`
  version with `ml-kem` (previously the tree carried both 0.10 and 0.11),
  shrinking the dependency graph and producing a cleaner SBOM and slightly
  smaller WASM. `js-sys` 0.3.99 → 0.3.100.
- CI: release-pipeline actions updated to current major versions
  (cosign-installer v4, attest-build-provenance v4, action-gh-release v3,
  setup-node v6, checkout v6).

## v0.3.6 (2026-06-10)

- No functional changes to the crate.
- Documentation: explain the `wasm-bindgen` "network access" pattern that
  security scanners (e.g. Socket) surface — the loader's single `fetch()` only
  loads the package's own `.wasm`; documents `initSync` for no-network init.
- Group Dependabot updates to reduce PR noise.

## v0.3.5 (2026-06-10)

- No functional changes to the crate.
- Supply-chain hardening of the release pipeline:
  - OIDC trusted publishing to crates.io and npm (no stored registry tokens),
    scoped to a protected `release` GitHub Actions environment
  - npm publish now attaches build provenance
  - CycloneDX SBOM generated, checksummed, and attested with each release
  - Release-time `cargo audit` gate
  - All GitHub Actions pinned to commit SHAs; Dependabot added
  - `wasm-pack` installed from locked source instead of an unverified tarball

## v0.3.0 (2026-05-15)

- Expose Cat-5 (ML-KEM-1024) in WASM bindings for browser opt-in
  - New WASM export: `generateHybridKeyPair1024` — Cat-5 keypair generation
  - New WASM export: `sealForUserWithLevel` — seal with explicit `"cat3"` / `"cat5"` level
  - `isHybridCiphertext` now documents v2 (Cat-3) and v3 (Cat-5) detection
- New Rust API: `seal_for_user_with_level` — level-parametric unified seal
- `unsealFromUser` / `unseal_from_user` unchanged — already auto-detects Cat-3/Cat-5
- All existing APIs unchanged — fully backward compatible

## v0.2.0 (2026-05-13)

- Add ML-KEM-1024 + X25519 hybrid (NIST Category 5) as opt-in security level
  - New functions: `generate_hybrid_keypair_1024`, `hybrid_seal_1024`, `hybrid_seal_with_level`
  - New `SecurityLevel` enum (`Cat3` / `Cat5`) for parametric API
  - Version tag `0x03` for Cat-5 ciphertext
- `hybrid_open` now auto-detects Cat-3 (v2) and Cat-5 (v3) from version byte
- `is_hybrid_ciphertext` recognizes both `0x02` and `0x03`
- Extracted shared secretbox helpers for DRY internal code
- `expand_seed` now flexible over output length
- All existing APIs unchanged — fully backward compatible

## v0.1.0 (2026-05-11)

- Initial release
- XSalsa20-Poly1305 symmetric encryption (secretbox)
- X25519 sealed box (anonymous public-key encryption)
- ML-KEM-768 + X25519 hybrid post-quantum KEM (Cat-3)
- Argon2id key derivation (libsodium INTERACTIVE parameters)
- Unified seal/unseal with auto-format-detection
- Human-readable recovery keys (base32)
- WASM bindings via `wasm-bindgen`
- `#![forbid(unsafe_code)]`, zeroize-on-drop for all secrets
