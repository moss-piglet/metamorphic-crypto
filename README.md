# metamorphic-crypto

Zero-knowledge end-to-end encryption library with post-quantum hybrid KEM.

Built for [Metamorphic](https://metamorphic.app) and [Mosslet](https://mosslet.com) — privacy-first apps by [Moss Piglet Corporation](https://mosspiglet.dev) where all user data is encrypted client-side and the server only stores opaque ciphertext.

## What this provides

- **Secretbox** (XSalsa20-Poly1305) — symmetric authenticated encryption
- **Sealed box** (X25519) — anonymous public-key encryption (libsodium-compatible)
- **Hybrid PQ KEM** (ML-KEM-768 + X25519) — NIST Cat-3 post-quantum key encapsulation (default)
- **Hybrid PQ KEM** (ML-KEM-1024 + X25519) — NIST Cat-5 post-quantum key encapsulation (opt-in)
- **Argon2id KDF** — password-based key derivation (libsodium INTERACTIVE parameters)
- **Hybrid PQ signatures** (ML-DSA + Ed25519) — NIST Cat-2/3/5 composite digital signatures (strict AND)
- **Hashing** (SHA3-512/256, SHA-256/512) — public, one-shot digest functions (e.g. for key fingerprints / safety numbers)
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

## Hashing

Public, one-shot digest functions over the already-present, audited `sha3` and
`sha2` dependencies. These are intended for **public** data only — key
fingerprints / safety numbers and key-transparency-log entries — where both the
input (e.g. a public key) and the output digest are meant to be public.

`sha3_512` is the recommended default (NIST Cat-5, ~256-bit collision
resistance, consistent with the crate's Keccak-based combiner). `sha3_256`,
`sha256`, and `sha512` are provided so integrators can match an existing format.

```rust
use metamorphic_crypto::{sha3_512, sha3_256, sha256, sha512};

// Take raw bytes, return fixed-size byte arrays.
let digest: [u8; 64] = sha3_512(b"public key bytes"); // recommended default
let d256:   [u8; 32] = sha3_256(b"...");
let s256:   [u8; 32] = sha256(b"...");   // SHA-2 interop
let s512:   [u8; 64] = sha512(b"...");   // SHA-2 interop

// Encode the digest yourself when needed:
use metamorphic_crypto::b64;
let fingerprint_b64 = b64::encode(&digest);
```

### Domain separation (recommended for fingerprints / transparency logs)

For key fingerprints, safety numbers, and key-transparency-log entries, prefer
`sha3_512_with_context`, which binds the digest to a versioned context label so
the same bytes hashed for different purposes can never collide or be
reinterpreted across contexts. It is exactly as strong as `sha3_512` — it *is*
SHA3-512, over an unambiguously framed message — and makes intent explicit:

```rust
use metamorphic_crypto::sha3_512_with_context;

let fp  = sha3_512_with_context("mosslet/key-fingerprint/v1", pubkey_bytes);
let log = sha3_512_with_context("mosslet/log-entry/v1", entry_bytes);
// fp and log are unrelated even if the byte inputs coincide.
```

Stable wire format (reproduce exactly for cross-language parity):

```text
SHA3-512( u64_be(len(context_utf8)) || context_utf8 || data )
```

The 8-byte big-endian length prefix makes the `(context, data)` boundary
unambiguous (no boundary-confusion collisions). Use a versioned namespace label.

Encoding: the native functions take `&[u8]` and return raw byte arrays — encode
to base64 or hex at the call site. The WASM bindings take/return base64 to match
the rest of the WASM API (see below).

**Do not hash secrets with these.** A bare hash makes no guarantees about its
inputs, and (consistent with the rest of the crate) the hashing path adds no
zeroize/constant-time ceremony — wiping a transient copy of already-public data
would add cost without protection. If you need to process secret material
(passwords, private keys), use the right construction instead — this crate's
Argon2id `derive_session_key` for password-based derivation, or a dedicated
KDF/MAC. The encryption APIs that handle secrets already zeroize on drop.

## Hybrid PQ signatures

Composite digital signatures: every message is signed by **both** ML-DSA
(FIPS 204) **and** Ed25519 (RFC 8032), and verification requires **both** to be
valid (strict AND). An attacker has to break both a lattice scheme and an
elliptic-curve scheme to forge, and cannot strip one algorithm to downgrade the
other. This is the signing counterpart to the hybrid KEM above.

```rust
use metamorphic_crypto::{generate_signing_keypair, sign, verify, SIGN_CONTEXT_V1};

let kp = generate_signing_keypair(); // Cat-3 (ML-DSA-65 + Ed25519), default
let sig = sign(b"transparency log entry", SIGN_CONTEXT_V1, &kp.secret_key).unwrap();
assert!(verify(b"transparency log entry", SIGN_CONTEXT_V1, &sig, &kp.public_key).unwrap());

// Re-derive the public key from a backed-up secret key:
use metamorphic_crypto::derive_public_key;
assert_eq!(derive_public_key(&kp.secret_key).unwrap(), kp.public_key);
```

Cat-2 (`generate_signing_keypair_44`) and Cat-5 (`generate_signing_keypair_87`)
are also available; `verify` auto-detects the level from the signature's version
tag. The `secret_key` field is zeroized on drop.

### Signing levels and mode

| Level | ML-DSA    | NIST Category | Equivalent | Version Tag | Default |
|-------|-----------|---------------|------------|-------------|---------|
| Cat-2 | ML-DSA-44 | 2             | ~AES-128   | `0x01`      | No      |
| Cat-3 | ML-DSA-65 | 3             | ~AES-192   | `0x02`      | Yes     |
| Cat-5 | ML-DSA-87 | 5             | ~AES-256   | `0x03`      | No      |

ML-DSA is signed with the **hedged (randomized)** variant — FIPS 204's default
and most conservative mode (resilient to RNG failure, hardened against fault /
side-channel attacks that deterministic lattice signing invites). Ed25519 is
deterministic per RFC 8032. As a result signature **bytes are non-reproducible**,
but the **wire format is deterministic and pinned**.

### Domain separation and wire format

Both algorithms sign the same domain-separated message, framed exactly like
`sha3_512_with_context` (a length-prefixed context):

```text
signed_msg = I2OSP(len(context_utf8), 8) || context_utf8 || message
```

ML-DSA signs `signed_msg` with an empty native context, so the framing is
identical for both algorithms and across every language binding. Byte layout
(Ed25519 first, fixed-size, so the ML-DSA tail needs no length prefix):

```text
signature  = tag || ed25519_sig (64 B) || ml_dsa_sig (2420 / 3309 / 4627 B)
public_key = tag || ed25519_pk  (32 B) || ml_dsa_pk  (1312 / 1952 / 2592 B)
secret_key = tag || ed25519_seed(32 B) || ml_dsa_seed(32 B)              = 65 B
```

### Dependency audit posture

| Dependency      | Version | Audited             | Notes |
|-----------------|---------|---------------------|-------|
| `ed25519-dalek` | 2.x     | Yes (mature)        | Widely deployed RFC 8032 implementation. |
| `ml-dsa`        | 0.1.x   | **No** (RustCrypto) | FIPS 204 (final). New crate, not yet independently audited. Pinned; tracked for the FIPS-mode roadmap. |

ML-DSA is defense-in-depth on top of the independently-strong Ed25519: even if a
flaw were found in the young `ml-dsa` implementation, the composite remains at
least as strong as Ed25519. This is stated honestly so integrators can choose
while the post-quantum implementation matures toward audit / FIPS validation.

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

### Hashing (WASM)

Digest exports take base64-encoded input and return the digest as base64. Decode
or re-encode to hex on the JS side if a hex fingerprint is required.

```js
import init, { sha3_512, sha3_512WithContext } from './pkg/metamorphic_crypto.js';
await init();

const dataB64 = btoa("public key bytes");
const digestB64 = sha3_512(dataB64); // also: sha3_256, sha256, sha512

// Domain-separated (recommended for fingerprints / transparency logs):
const fp = sha3_512WithContext("mosslet/key-fingerprint/v1", dataB64);
```

### Signatures (WASM)

Keys and signatures are base64; the message is base64 and `context` is a UTF-8
string. `verify` returns `true` only if both component signatures are valid.

```js
import init, { generateSigningKeyPair, sign, verify } from './pkg/metamorphic_crypto.js';
await init();

const kp = generateSigningKeyPair("cat3"); // { publicKey, secretKey }
const msg = btoa("transparency log entry");
const sig = sign(msg, "metamorphic/sign/v1", kp.secretKey);
const ok = verify(msg, "metamorphic/sign/v1", sig, kp.publicKey); // true
```

## Tests

```bash
cargo test          # unit + integration + cross-level compatibility
cargo clippy        # zero warnings
cargo fmt --check   # formatted
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
