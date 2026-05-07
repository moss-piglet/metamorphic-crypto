# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this crate, **do not open a public issue**.

Please report it privately via one of:

- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/metamorphic/metamorphic-crypto/security/advisories/new)
- **Email**: security@metamorphic.app

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

This policy covers the `metamorphic-crypto` Rust crate, including:

- All cryptographic operations (secretbox, box_seal, hybrid KEM, KDF)
- WASM bindings
- Key generation and management
- Recovery key encoding

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Design

- `#![forbid(unsafe_code)]` — no unsafe Rust
- All dependencies are from the audited [RustCrypto](https://github.com/RustCrypto) project
- ML-KEM-768 implementation via the `ml-kem` crate (FIPS 203)
- Secret key material zeroized after use via `zeroize`
- OS CSPRNG only (no userspace PRNG)
- Constant-time operations for all MAC comparisons
