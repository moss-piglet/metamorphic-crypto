# @f0rest8/metamorphic-crypto

Zero-knowledge end-to-end encryption with post-quantum hybrid KEM (ML-KEM-512/768/1024 + X25519).

Built for [Metamorphic](https://metamorphic.app) and [Mosslet](https://mosslet.com) — privacy-first apps by [Moss Piglet Corporation](https://mosspiglet.dev) where all user data is encrypted client-side and the server only stores opaque ciphertext.

This package is a WebAssembly build of the [metamorphic-crypto](https://github.com/moss-piglet/metamorphic-crypto) Rust crate.

## Install

```bash
npm install @f0rest8/metamorphic-crypto
```

## Quick start

```js
import init, {
  generateKey,
  encryptSecretboxString,
  decryptSecretboxToString,
} from "@f0rest8/metamorphic-crypto";

// Initialize the WASM module (required once before calling any function)
await init();

// All functions are synchronous after init() and throw on error
const key = generateKey();
const ciphertext = encryptSecretboxString("sensitive data", key);
const plaintext = decryptSecretboxToString(ciphertext, key);
// plaintext === "sensitive data"
```

## API overview

All values are base64-encoded strings unless noted otherwise.

### Key derivation (Argon2id)

```js
import { deriveSessionKey, generateSalt, parseSaltFromKeyHash } from "@f0rest8/metamorphic-crypto";

const salt = generateSalt();                          // random 16-byte salt (base64)
const sessionKey = deriveSessionKey(password, salt);   // 32-byte derived key (base64)
const salt2 = parseSaltFromKeyHash("base64salt$argon2id..."); // extract salt from stored hash
```

### Symmetric encryption (XSalsa20-Poly1305)

```js
import {
  generateKey,
  encryptSecretboxString, decryptSecretboxToString,
  encryptSecretbox, decryptSecretbox,
} from "@f0rest8/metamorphic-crypto";

const key = generateKey();

// String plaintext
const ct = encryptSecretboxString("hello", key);
const pt = decryptSecretboxToString(ct, key); // "hello"

// Binary plaintext (base64 in, base64 out)
const ctBin = encryptSecretbox(plaintextBase64, key);
const ptBin = decryptSecretbox(ctBin, key); // base64
```

### Public-key encryption (X25519 sealed box)

```js
import { generateKeyPair, boxSeal, boxSealOpen } from "@f0rest8/metamorphic-crypto";

const kp = generateKeyPair(); // { publicKey, privateKey }
const sealed = boxSeal(plaintextBase64, kp.publicKey);
const opened = boxSealOpen(sealed, kp.publicKey, kp.privateKey); // base64
```

### Hybrid PQ seal/unseal (ML-KEM + X25519)

The recommended API for encrypting data to a user. Uses post-quantum hybrid encryption when a PQ public key is available, falls back to legacy X25519 sealed box otherwise. Decryption auto-detects the format.

```js
import {
  generateKeyPair, generateHybridKeyPair,
  sealForUser, unsealFromUser,
} from "@f0rest8/metamorphic-crypto";

// Generate keys
const x25519 = generateKeyPair();          // { publicKey, privateKey }
const pq = generateHybridKeyPair();         // { publicKey, secretKey } (ML-KEM-768)

// Seal (encrypt) — pass both public keys
const sealed = sealForUser(plaintextBase64, x25519.publicKey, pq.publicKey);

// Unseal (decrypt) — pass both secret keys, auto-detects format
const opened = unsealFromUser(sealed, x25519.publicKey, x25519.privateKey, pq.secretKey);
```

### Cat-5 (ML-KEM-1024, opt-in)

```js
import { generateHybridKeyPair1024, sealForUserWithLevel } from "@f0rest8/metamorphic-crypto";

const pq5 = generateHybridKeyPair1024();  // { publicKey, secretKey } (ML-KEM-1024)
const sealed = sealForUserWithLevel(plaintextBase64, x25519.publicKey, pq5.publicKey, "cat5");
// unsealFromUser auto-detects Cat-1 vs Cat-3 vs Cat-5, no level param needed
```

### Cat-1 (ML-KEM-512, opt-in)

```js
import { generateHybridKeyPair512, sealForUserWithLevel } from "@f0rest8/metamorphic-crypto";

const pq1 = generateHybridKeyPair512();  // { publicKey, secretKey } (ML-KEM-512)
const sealed = sealForUserWithLevel(plaintextBase64, x25519.publicKey, pq1.publicKey, "cat1");
// unsealFromUser auto-detects the level from the version tag, no level param needed
```

### Private key management

```js
import { encryptPrivateKey, decryptPrivateKey } from "@f0rest8/metamorphic-crypto";

const encrypted = encryptPrivateKey(privateKeyBase64, sessionKeyBase64);
const decrypted = decryptPrivateKey(encrypted, sessionKeyBase64);
```

### Recovery keys

```js
import {
  generateRecoveryKey, recoveryKeyToSecret,
  encryptPrivateKeyForRecovery, decryptPrivateKeyWithRecovery,
} from "@f0rest8/metamorphic-crypto";

const rk = generateRecoveryKey(); // { recoveryKey, recoverySecretBase64 }
// recoveryKey is a human-readable string like "ABCD-EFGH-..." for the user to write down

const backup = encryptPrivateKeyForRecovery(privateKeyBase64, rk.recoverySecretBase64);
const restored = decryptPrivateKeyWithRecovery(backup, rk.recoverySecretBase64);

// Or recover from the human-readable key:
const secret = recoveryKeyToSecret("ABCD-EFGH-...");
const restored2 = decryptPrivateKeyWithRecovery(backup, secret);
```

### Hashing (SHA-3 / SHA-2)

Public, one-shot digest functions — intended for **public** data only, such as
key fingerprints, safety numbers, and key-transparency-log entries. Each takes
**base64-encoded input** and returns the digest as **base64**. Decode with
`atob`, or re-encode to hex, if you need a hex fingerprint.

`sha3_512` is the recommended default (highest assurance, NIST Cat-5). The
others let you match an existing format.

```js
import { sha3_512, sha3_256, sha256, sha512 } from "@f0rest8/metamorphic-crypto";

const dataBase64 = btoa("public key bytes");
const digestBase64 = sha3_512(dataBase64); // 64-byte digest, base64

// Need hex? decode the base64 digest:
const hex = [...atob(digestBase64)].map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
```

**Domain separation (recommended for fingerprints / transparency logs).** Use
`sha3_512WithContext` to bind a digest to a versioned context label, so the same
bytes hashed for different purposes can never collide or be reinterpreted across
contexts. It is exactly as strong as `sha3_512`:

```js
import { sha3_512WithContext } from "@f0rest8/metamorphic-crypto";

const dataBase64 = btoa("public key bytes");
const fingerprint = sha3_512WithContext("mosslet/key-fingerprint/v1", dataBase64);
```

Stable wire format (reproduce exactly to match native/Elixir):
`SHA3-512( u64_be(len(context_utf8)) || context_utf8 || data )`.

> **Do not hash secrets with these.** A bare hash makes no guarantees about its
> inputs, and the hashing path intentionally adds no zeroize/constant-time
> ceremony — wiping a transient copy of already-public data adds cost without
> protection. To process secret material (passwords, private keys), use the
> right construction instead: this package's Argon2id `deriveSessionKey` for
> password-based derivation, or a dedicated KDF/MAC.

### Hybrid PQ signatures (ML-DSA + Ed25519)

Composite digital signatures: every message is signed by **both** ML-DSA
(FIPS 204) and Ed25519 (RFC 8032), and `verify` returns `true` only if **both**
component signatures are valid (strict AND). Keys and signatures are base64; the
message is **base64** and `context` is a UTF-8 string.

```js
import { generateSigningKeyPair, sign, verify, deriveSigningPublicKey } from "@f0rest8/metamorphic-crypto";

const kp = generateSigningKeyPair("cat3"); // { publicKey, secretKey } — Cat-3 default
const msg = btoa("transparency log entry");
const sig = sign(msg, "metamorphic/sign/v1", kp.secretKey);
const ok = verify(msg, "metamorphic/sign/v1", sig, kp.publicKey); // true

// Re-derive the public key from a backed-up secret key:
const pk = deriveSigningPublicKey(kp.secretKey); // === kp.publicKey
```

Levels are `"cat2"` (ML-DSA-44), `"cat3"` (ML-DSA-65, default), and `"cat5"`
(ML-DSA-87); `verify` auto-detects the level from the signature. ML-DSA uses the
hedged/randomized FIPS 204 mode, so signature **bytes are non-reproducible**,
but key derivation and the domain-separation framing
(`u64_be(len(context)) || context || message`) are deterministic and identical
across native Rust, WASM, and the Elixir NIF.

> **Audit posture.** `ed25519-dalek` (2.x) is mature and widely deployed.
> `ml-dsa` (0.1.x, RustCrypto FIPS 204) is new and **not yet independently
> audited** — it is included as defense-in-depth on top of Ed25519, so the
> composite remains at least as strong as Ed25519 even if a flaw is found in the
> young post-quantum implementation. Pinned and tracked for the FIPS-mode roadmap.

## Security levels

| Level | ML-KEM | NIST Category | Equivalent | Default |
|-------|--------|---------------|------------|---------|
| Cat-1 | 512    | 1             | ~AES-128   | No      |
| Cat-3 | 768    | 3             | ~AES-192   | Yes     |
| Cat-5 | 1024   | 5             | ~AES-256   | No      |

Decryption always auto-detects the level from the ciphertext version tag. NIST (FIPS 203) standardizes ML-KEM only at categories 1/3/5 — there is no category-2/4 set. The classical half is X25519 (~Cat-1 classical) at every tier; at Cat-3/Cat-5 the post-quantum half dominates and X25519 is the classical floor (standard hybrid-KEM practice).

## Security properties

- `#![forbid(unsafe_code)]` — no unsafe anywhere in the Rust source
- All secret key material zeroized after use
- Constant-time MAC comparison via RustCrypto
- OS CSPRNG via `getrandom` (no userspace PRNG)
- Hybrid construction: both ML-KEM AND X25519 must be broken to compromise a sealed key

## Network access

Security scanners (e.g. Socket) may flag this package for "network access."
This is the standard `wasm-bindgen` loader, which calls `fetch()` for a **single**
purpose: to load the package's own `.wasm` binary when you call the default
`init()` export. There are no other network calls — no telemetry, no remote
code, no install scripts.

The fetched URL is whatever **you** pass to `init()`. With no argument it
defaults to the `.wasm` file shipped alongside the JS (`new URL('metamorphic_crypto_bg.wasm', import.meta.url)`),
i.e. a same-origin asset you control.

If you want zero network capability, use the synchronous initializer with bytes
you load yourself — it never calls `fetch`:

```js
import { initSync } from "@f0rest8/metamorphic-crypto";

// e.g. bytes from your bundler, a same-origin path, or an embedded buffer
initSync({ module: wasmBytes });
```

## Integrity verification

Every release includes SHA-512 checksums and [cosign](https://docs.sigstore.dev/cosign/overview/) signatures for supply chain verification:

```bash
cosign verify-blob \
  --bundle metamorphic_crypto_bg.wasm.cosign.bundle \
  metamorphic_crypto_bg.wasm
```

## License

Dual-licensed under [MIT](https://github.com/moss-piglet/metamorphic-crypto/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/moss-piglet/metamorphic-crypto/blob/main/LICENSE-APACHE) at your option.
