# @f0rest8/metamorphic-crypto

Zero-knowledge end-to-end encryption with post-quantum hybrid KEM (ML-KEM-768/1024 + X25519).

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
// unsealFromUser auto-detects Cat-3 vs Cat-5, no level param needed
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

## Security levels

| Level | ML-KEM | NIST Category | Equivalent | Default |
|-------|--------|---------------|------------|---------|
| Cat-3 | 768    | 3             | ~AES-192   | Yes     |
| Cat-5 | 1024   | 5             | ~AES-256   | No      |

Decryption always auto-detects the level from the ciphertext version tag.

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
