# metamorphic-crypto

Zero-knowledge end-to-end encryption library with post-quantum hybrid KEM.

Built for [Metamorphic](https://metamorphic.app) and [Mosslet](https://mosslet.app) — privacy-first apps by [Moss Piglet Corporation](https://mosspiglet.dev) where all user data is encrypted client-side and the server only stores opaque ciphertext.

## What this provides

- **Secretbox** (XSalsa20-Poly1305) — symmetric authenticated encryption
- **Sealed box** (X25519) — anonymous public-key encryption (libsodium-compatible)
- **Hybrid PQ KEM** (ML-KEM-768 + X25519) — NIST Cat-3 post-quantum key encapsulation (default)
- **Hybrid PQ KEM** (ML-KEM-1024 + X25519) — NIST Cat-5 post-quantum key encapsulation (opt-in)
- **Argon2id KDF** — password-based key derivation (libsodium INTERACTIVE parameters)
- **WASM bindings** — browser-ready via `wasm-pack`
- **Recovery keys** — human-readable base32 encoding for key backup

## Security levels

| Level | ML-KEM | NIST Category | Equivalent | Version Tag | Default |
|-------|--------|---------------|------------|-------------|---------|
| Cat-3 | 768    | 3             | ~AES-192   | `0x02`      | Yes     |
| Cat-5 | 1024   | 5             | ~AES-256   | `0x03`      | No      |

Both levels use the same combiner construction and X25519 classical fallback. `hybrid_open` auto-detects the level from the version tag byte — old and new ciphertext coexist seamlessly.

## Security properties

- `#![forbid(unsafe_code)]` — no unsafe anywhere in the crate
- All secret key material zeroized after use
- Constant-time MAC comparison via RustCrypto
- OS CSPRNG via `getrandom` (no userspace PRNG)
- Hybrid construction: both ML-KEM AND X25519 must be broken to compromise a sealed key

## Hybrid KEM construction

The hybrid combiner matches the format used by [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)'s `ml_kem768_x25519`:

```
Seed expansion:  SHAKE256(seed_32) → 96 bytes [ML-KEM seed (64) || X25519 sk (32)]
Combiner:        SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || label)
```

### Cat-3 (ML-KEM-768, default)
```
Public key:   ML-KEM-768 ek (1184 B) || X25519 pk (32 B) = 1216 bytes
Ciphertext:   0x02 || ML-KEM-768 ct (1088 B) || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct
```

### Cat-5 (ML-KEM-1024, opt-in)
```
Public key:   ML-KEM-1024 ek (1568 B) || X25519 pk (32 B) = 1600 bytes
Ciphertext:   0x03 || ML-KEM-1024 ct (1568 B) || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct
```

## Targets

| Target | Build | Use case |
|--------|-------|----------|
| Native | `cargo build` | Tests, CLI tools, Elixir NIF (`metamorphic_crypto` Hex package) |
| WASM | `wasm-pack build --target web` | Browser (Phoenix LiveView, any SPA) |
| iOS | UniFFI (planned) | Native Swift apps |
| Android | UniFFI (planned) | Native Kotlin apps |

## Usage

```rust
use metamorphic_crypto::{generate_key, encrypt_secretbox_string, decrypt_secretbox_to_string};
use metamorphic_crypto::{generate_hybrid_keypair, hybrid_seal, hybrid_open};
use metamorphic_crypto::{generate_hybrid_keypair_1024, hybrid_seal_1024};

// Symmetric encryption
let key = generate_key();
let ciphertext = encrypt_secretbox_string("sensitive data", &key).unwrap();
let plaintext = decrypt_secretbox_to_string(&ciphertext, &key).unwrap();
assert_eq!(plaintext, "sensitive data");

// Hybrid PQ seal (Cat-3, default)
let kp = generate_hybrid_keypair();
let sealed = hybrid_seal(b"context_key_bytes", &kp.public_key).unwrap();
let opened = hybrid_open(&sealed, &kp.secret_key).unwrap();

// Hybrid PQ seal (Cat-5)
let kp5 = generate_hybrid_keypair_1024();
let sealed5 = hybrid_seal_1024(b"context_key_bytes", &kp5.public_key).unwrap();
let opened5 = hybrid_open(&sealed5, &kp5.secret_key).unwrap(); // auto-detects level
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
cargo test          # unit + integration + cross-level compatibility
cargo clippy        # zero warnings
cargo fmt --check   # formatted
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
