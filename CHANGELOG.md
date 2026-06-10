# Changelog

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
