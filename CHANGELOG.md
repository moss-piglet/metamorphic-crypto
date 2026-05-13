# Changelog

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
