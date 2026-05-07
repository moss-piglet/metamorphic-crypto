# metamorphic-crypto

Zero-knowledge end-to-end encryption library with post-quantum hybrid KEM.

Built for [Metamorphic](https://metamorphic.app) — a privacy-first habit tracker where all user data is encrypted client-side and the server only stores opaque ciphertext.

## What this provides

- **Secretbox** (XSalsa20-Poly1305) — symmetric authenticated encryption
- **Sealed box** (X25519) — anonymous public-key encryption (libsodium-compatible)
- **Hybrid PQ KEM** (ML-KEM-768 + X25519) — post-quantum key encapsulation with SHA3-256 combiner
- **Argon2id KDF** — password-based key derivation (libsodium INTERACTIVE parameters)
- **WASM bindings** — browser-ready via `wasm-pack`
- **Recovery keys** — human-readable base32 encoding for key backup

## Security properties

- `#![forbid(unsafe_code)]` — no unsafe anywhere in the crate
- All secret key material zeroized after use
- Constant-time MAC comparison via RustCrypto
- OS CSPRNG via `getrandom` (no userspace PRNG)
- Hybrid construction: both ML-KEM-768 AND X25519 must be broken to compromise a sealed key

## Hybrid KEM construction

The hybrid combiner matches the format used by [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)'s `ml_kem768_x25519`:

```
Seed expansion:  SHAKE256(seed_32) → 96 bytes [ML-KEM seed (64) || X25519 sk (32)]
Public key:      ML-KEM-768 ek (1184 B) || X25519 pk (32 B) = 1216 bytes
Ciphertext:      ML-KEM-768 ct (1088 B) || X25519 eph pk (32 B) = 1120 bytes
Shared secret:   SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || label)
```

## Targets

| Target | Build | Use case |
|--------|-------|----------|
| Native | `cargo build` | Tests, CLI tools |
| WASM | `wasm-pack build --target web` | Browser (Phoenix LiveView, any SPA) |
| iOS | UniFFI (planned) | Native Swift apps |
| Android | UniFFI (planned) | Native Kotlin apps |

## Usage

```rust
use metamorphic_crypto::{generate_key, encrypt_secretbox_string, decrypt_secretbox_to_string};

let key = generate_key();
let ciphertext = encrypt_secretbox_string("sensitive data", &key).unwrap();
let plaintext = decrypt_secretbox_to_string(&ciphertext, &key).unwrap();
assert_eq!(plaintext, "sensitive data");
```

## WASM (browser)

```bash
wasm-pack build --target web --release
```

```js
import init, { deriveSessionKey, encryptSecretboxString } from './pkg/metamorphic_crypto.js';

await init('/path/to/metamorphic_crypto_bg.wasm');

const key = deriveSessionKey(password, saltBase64);
const ciphertext = encryptSecretboxString("hello", key);
```

## Tests

```bash
cargo test          # 66 tests (unit + integration + cross-language vectors)
cargo clippy        # zero warnings
cargo fmt --check   # formatted
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
