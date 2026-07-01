# metamorphic-crypto

Zero-knowledge end-to-end encryption library with post-quantum hybrid KEM, hybrid
PQ signatures, and an opt-in **CNSA 2.0** suite axis (matched-strength hybrid +
pure ML-KEM-1024 / ML-DSA-87 / AES-256-GCM).

Built for [Metamorphic](https://metamorphic.app) and [Mosslet](https://mosslet.com) — privacy-first apps by [Moss Piglet Corporation](https://mosspiglet.dev) where all user data is encrypted client-side and the server only stores opaque ciphertext.

## What this provides

- **Secretbox** (XSalsa20-Poly1305) — symmetric authenticated encryption
- **Sealed box** (X25519) — anonymous public-key encryption (libsodium-compatible)
- **Hybrid PQ KEM** (ML-KEM-512 + X25519) — NIST Cat-1 post-quantum key encapsulation (opt-in)
- **Hybrid PQ KEM** (ML-KEM-768 + X25519) — NIST Cat-3 post-quantum key encapsulation (default)
- **Hybrid PQ KEM** (ML-KEM-1024 + X25519) — NIST Cat-5 post-quantum key encapsulation (opt-in)
- **Argon2id KDF** — password-based key derivation (libsodium INTERACTIVE parameters)
- **Hybrid PQ signatures** (ML-DSA + Ed25519) — NIST Cat-2/3/5 composite digital signatures (strict AND)
- **CNSA 2.0 suite axis** (opt-in) — matched-strength hybrid (X448 / P-521 / Ed448 / ECDSA-P-521) and pure post-quantum (ML-KEM-1024, ML-DSA-87, AES-256-GCM)
- **Hashing** (SHA3-512/256, SHA-256/512) — public, one-shot digest functions (e.g. for key fingerprints / safety numbers)
- **HMAC-SHA256** (RFC 2104) — keyed MAC primitive (e.g. the on-spec KEYTRANS commitment)
- **HKDF-SHA512** (RFC 5869) — extract-then-expand KDF for combining/diversifying secret key material
- **Verifiable random functions** (ECVRF, RFC 9381) — Edwards25519 (`0x03`) and NIST P-256 (`0x01`), classical VRFs for transparency-log *index privacy* (CONIKS / KEYTRANS)
- **WASM bindings** — browser-ready via `wasm-pack`
- **Recovery keys** — human-readable base32 encoding for key backup

## Security levels

| Level | ML-KEM | NIST Category | Equivalent | Version Tag | Default |
|-------|--------|---------------|------------|-------------|---------|
| Cat-1 | 512    | 1             | ~AES-128   | `0x01`      | No      |
| Cat-3 | 768    | 3             | ~AES-192   | `0x02`      | Yes     |
| Cat-5 | 1024   | 5             | ~AES-256   | `0x03`      | No      |

NIST (FIPS 203) standardizes ML-KEM only at categories 1/3/5 — there is no category-2/4 parameter set, so none is offered. All levels use the same combiner construction. The classical half is **X25519 (~Cat-1 classical) at every tier** — it does not scale up with the ML-KEM parameter set; at Cat-3/Cat-5 the post-quantum half dominates and X25519 is the classical floor (standard hybrid-KEM practice: a break requires defeating *both* halves). `hybrid_open` auto-detects the level from the version tag byte — old and new ciphertext coexist seamlessly.

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

### Cat-1 (ML-KEM-512, opt-in)
```
Public key:   ML-KEM-512 ek (800 B) || X25519 pk (32 B) = 832 bytes
Ciphertext:   0x01 || ML-KEM-512 ct (768 B) || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct
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
use metamorphic_crypto::{generate_hybrid_keypair_512, hybrid_seal_512};
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

// Hybrid PQ seal (Cat-1)
let kp1 = generate_hybrid_keypair_512();
let sealed1 = hybrid_seal_512(b"context_key_bytes", &kp1.public_key).unwrap();
let opened1 = hybrid_open(&sealed1, &kp1.secret_key).unwrap(); // auto-detects level
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

## Message authentication (HMAC-SHA256)

`hmac_sha256(key, msg)` is a thin wrapper over the audited RustCrypto `hmac`
crate — the generic keyed-MAC primitive, no novel cryptography. Its headline use
is the **on-spec IETF KEYTRANS commitment** (`HMAC(Kc, CommitmentValue)`); the
KEYTRANS-specific framing lives in `metamorphic-log`, so this crate stays the
single source of truth for primitives.

```rust
use metamorphic_crypto::hmac_sha256;

let tag: [u8; 32] = hmac_sha256(key_bytes, message_bytes);
```

Any key length is accepted (RFC 2104). Validated against RFC 4231 test vectors.
WASM: `hmacSha256(keyB64, msgB64) -> tagB64`.

> **Not an authenticator by default here.** In the KEYTRANS commitment the "key"
> is a fixed, public per-suite constant and hiding comes from a random opening in
> the message — HMAC is used as a committing PRF, not a secret-keyed
> authenticator. Use it in a construction whose properties you understand.

## Key derivation from secrets (HKDF-SHA512, RFC 5869)

For **password-based** derivation use Argon2id (`derive_session_key`). To
**combine or diversify already-high-entropy secret key material** — deriving one
key from two, or several subkeys from one — use HKDF-SHA512.

`hkdf_sha512(salt, ikm, info, length)` performs RFC 5869 Extract-then-Expand in a
single call over the same audited `Hkdf::<Sha512>` the hybrid-seal envelope
already uses internally. No novel cryptography — it promotes that internal HKDF
to a public, cross-language primitive.

```rust
use metamorphic_crypto::hkdf_sha512;

// Combine two secrets into one 32-byte wrapping key with domain separation.
let wrapping_key = hkdf_sha512(
    wrap_salt,                          // salt  → Extract (non-secret)
    &[password_key, prf_output].concat(), // ikm → Extract (secret)
    b"mosslet/user_key-wrap/v1",        // info → Expand (domain separation)
    32,                                 // output length in bytes
)?;
```

- **`salt`** is bound into Extract; an **empty** salt means "not provided"
  (RFC 5869 §2.2 — `HashLen` zero bytes). Prefer a per-derivation salt.
- **`info`** is the versioned domain-separation label, bound into Expand — the
  *correct* place for context (not Extract).
- **`length`** must be `<= 255 * 64 = 16320` bytes; otherwise `CryptoError::Hkdf`.

Its headline use is Mosslet's WebAuthn-PRF device-bound `user_key` wrap
(board #362): one wrapping key derived from the password-derived key **and** an
authenticator's PRF output, so a stolen password alone cannot unlock. The
combine runs entirely in the browser (the server never sees the inputs); the
NIF/native functions exist for parity and general use.

Byte-identical across native Rust, WASM, and the Elixir NIF — and to
`@noble/hashes` / WebCrypto HKDF-SHA-512 — pinned by the RFC 5869 SHA-512 vector.
WASM: `hkdfSha512(saltB64, ikmB64, info, length) -> okmB64` (`info` a UTF-8
label).

> **Secrets welcome here.** Unlike the bare hashes above, HKDF is the right
> construction for secret input keying material. Do **not** reach for a plain
> hash to combine secrets — use this.

## Verifiable random functions (ECVRF, RFC 9381)

The crate exposes **two** RFC 9381 ECVRF ciphersuites, sharing an identical
prove/verify/proof-to-hash shape:

| Module | Ciphersuite | Suite octet | Curve + hash | Used by |
|--------|-------------|-------------|--------------|---------|
| `vrf` | ECVRF-EDWARDS25519-SHA512-TAI | `0x03` | Edwards25519 + SHA-512 | KEYTRANS private/experimental + `KT_128_SHA256_Ed25519` |
| `vrf_p256` | ECVRF-P256-SHA256-TAI | `0x01` | NIST P-256 + SHA-256 | on-spec `KT_128_SHA256_P256` |

A VRF lets the key owner compute, for any input `alpha`, a pseudorandom output
`beta` plus a proof `pi` that `beta` is correct under their public key. Anyone
with the public key can verify `pi`, but cannot compute `beta` for a new input
and cannot learn `alpha` from `(pi, beta)`. This is the primitive behind
**transparency-log index privacy** (CONIKS / KEYTRANS): a directory maps a
private identity index to a verifiable, pseudorandom tree position without
revealing which identities it holds.

Both are built on curve backends already in-tree (`curve25519-dalek` for
Edwards25519; `p256` for P-256 — the same `elliptic-curve` generation as the
crate's P-521 stack) — no parallel crypto — and are pinned byte-for-byte by
RFC 9381's own test vectors.

```rust
// Edwards25519 (suite 0x03)
use metamorphic_crypto::{ecvrf_generate_keypair, ecvrf_prove, ecvrf_verify};

let (sk, pk) = ecvrf_generate_keypair();
let alpha = b"identity index";
let pi = ecvrf_prove(&sk, alpha)?;         // 80-byte proof
let beta = ecvrf_verify(&pk, alpha, &pi)?; // Ok(Some(beta)) if valid
assert!(beta.is_some());

// NIST P-256 (suite 0x01) — identical shape
use metamorphic_crypto::{ecvrf_p256_generate_keypair, ecvrf_p256_prove, ecvrf_p256_verify};

let (sk, pk) = ecvrf_p256_generate_keypair();
let pi = ecvrf_p256_prove(&sk, alpha)?;         // 81-byte proof
let beta = ecvrf_p256_verify(&pk, alpha, &pi)?; // Ok(Some(beta)) if valid
```

| Item | Edwards25519 (`vrf`) | P-256 (`vrf_p256`) |
|------|----------------------|--------------------|
| secret key | 32 B (seed) | 32 B (big-endian scalar `x`) |
| public key | 32 B (compressed Edwards `Y`) | 33 B (SEC1 compressed `Y`) |
| proof `pi` | 80 B: `Gamma(32) \|\| c(16) \|\| s(32)` | 81 B: `Gamma(33) \|\| c(16) \|\| s(32)` |
| output `beta` | 64 B (SHA-512) | 32 B (SHA-256) |

WASM: `ecvrfEd25519{GenerateKeyPair,PublicKey,Prove,Verify,ProofToHash}` and
`ecvrfP256{...}` (base64 in/out; `verify` returns the output or `null`).

**Honest posture.** Both VRFs are **classical** (elliptic-curve discrete log).
They protect exactly one property — *index privacy* — and are the one
non-post-quantum piece in the transparency stack; integrity, authenticity,
confidentiality, and hash-based commitments are post-quantum independently of
them. RFC 9381's Elligator2 / SSWU siblings are designed-in future additions
that never invalidate a TAI proof (the suite octet is bound into every hash). A
hybrid (post-quantum + classical) VRF is intended for when an audited lattice
VRF exists; none does today, so it is not built. These primitives are not
FIPS-validated.

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

## CNSA 2.0 suite axis (opt-in)

By default everything above is **`Suite::Hybrid`** — the classical+PQ strict-AND
constructions (ML-KEM + X25519; ML-DSA + Ed25519). If you have no specific
mandate, that is the recommended choice and you can ignore this section.

For deployments that must follow the NSA's **Commercial National Security
Algorithm Suite 2.0** (CNSA 2.0 / NIST IR 8547), a `Suite` axis lets you raise
the posture with a *single extra argument*. It is **orthogonal** to the
`SecurityLevel` (Cat-1/3/5) you already know, so you really have two independent
knobs:

```
            posture (Suite)                  ×   parameter set (SecurityLevel)
  ┌──────────────────────────────┐               ┌───────────────────────┐
  │ Hybrid         (default)      │               │ Cat-1 / Cat-3 / Cat-5 │
  │ HybridMatched  (opt-in)       │               └───────────────────────┘
  │ PureCnsa2      (opt-in)       │
  └──────────────────────────────┘
```

| Suite | What it is | Classical partner | Status |
|-------|------------|-------------------|--------|
| `Hybrid` | Existing strict-AND classical+PQ. **Byte-for-byte unchanged.** | X25519 / Ed25519 (every tier) | **Default, recommended** |
| `HybridMatched` | Classical partner matched to the PQ category so it is never the weak link | KEM: Cat-3→X448, Cat-5→P-521 ECDH · Sign: Cat-3→Ed448, Cat-5→ECDSA-P-521 | Opt-in |
| `PureCnsa2` | Pure post-quantum, no classical half (the CNSA-2.0 box) | none | Opt-in, **Cat-5 only** |

`HybridMatched` at the lowest rung (KEM Cat-1 / sign Cat-2) is identical to
`Hybrid` — no new format is produced there, so nothing breaks.

### New wire formats (new suites only)

The `Hybrid` suite (and `HybridMatched` at the lowest rung) keep their existing
`0x01/0x02/0x03` ciphertext tags and byte layout untouched. The matched / pure
suites use new tags and a CNSA-correct seal envelope:

| Suite + level | KEM | Tag |
|---------------|-----|-----|
| `PureCnsa2` Cat-5 | ML-KEM-1024 + AES-256-GCM | `0x10` |
| `HybridMatched` Cat-3 | ML-KEM-768 + X448 + AES-256-GCM | `0x13` |
| `HybridMatched` Cat-5 | ML-KEM-1024 + P-521 ECDH + AES-256-GCM | `0x14` |

```text
ikm  = ss_mlkem (PureCnsa2)  |  ss_mlkem || ss_ecc (HybridMatched)
key  = HKDF-SHA512(ikm, info = suite_tag || context_label)   -> 32-byte AES-256 key
out  = AES-256-GCM(key, 96-bit random nonce, AAD = suite_tag || context_label)
wire = tag(1) || kem_ct || [ecc_eph_pk] || nonce(12) || ct || gcm_tag(16)
```

Each encapsulation yields a fresh KEM secret, so the derived AES-256 key is
single-use and the random 96-bit nonce can never repeat — SIV-grade misuse
resistance without leaving the CNSA-approved set (no AES-GCM-SIV). Note the
deliberate hash split: **HKDF-SHA512** for *key derivation* here; **SHA3-512**
stays the choice for *leaf/transcript* hashing (`sha3_512_with_context`).

### Context labels

The new suites bind a versioned context label into both the HKDF `info` and the
GCM AAD (and, for signatures, the I2OSP-framed message). Grammar:
`"<namespace>/<purpose>/v<major>"`. The **namespace** is the one per-tenant knob;
the protocol shape stays fixed. Library defaults are `SEAL_CONTEXT_V1`
(`"metamorphic/seal/v1"`) and `SIGN_CONTEXT_V1` (`"metamorphic/sign/v1"`); pass
your own (e.g. `"mosslet/seal/v1"`) to namespace your deployment.

### Usage (Rust)

```rust
use metamorphic_crypto::{
    Suite, SecurityLevel, SignatureLevel, SEAL_CONTEXT_V1, SIGN_CONTEXT_V1,
    generate_hybrid_keypair_suite, hybrid_seal_suite, hybrid_open_with_context,
    generate_signing_keypair_suite, sign, verify,
};

// --- KEM / seal: the pure CNSA-2.0 box (ML-KEM-1024 + AES-256-GCM) ---
let kp = generate_hybrid_keypair_suite(Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
let sealed = hybrid_seal_suite(b"context_key_bytes", &kp.public_key,
                               Suite::PureCnsa2, SecurityLevel::Cat5).unwrap();
// `hybrid_open` auto-detects the tag using the DEFAULT context label; if you
// sealed with a custom label, open with it explicitly:
let opened = hybrid_open_with_context(&sealed, &kp.secret_key, SEAL_CONTEXT_V1).unwrap();

// --- Signatures: ML-DSA-87 only (Cat-5 pure) ---
let sk = generate_signing_keypair_suite(Suite::PureCnsa2, SignatureLevel::Cat5).unwrap();
let sig = sign(b"checkpoint", SIGN_CONTEXT_V1, &sk.secret_key).unwrap();
assert!(verify(b"checkpoint", SIGN_CONTEXT_V1, &sig, &sk.public_key).unwrap());
// `sign` / `verify` / `derive_public_key` auto-detect the suite from the version
// tag — no suite argument is needed once the key exists.
```

`seal_for_user_with_suite` is the user-facing seal that falls back to legacy
X25519 when no PQ key is present, mirroring `seal_for_user_with_level`.

### Honest claims

Claim: **"CNSA 2.0 algorithm suite, NCC-audited components, pure-Rust,
memory-safe (`forbid-unsafe`)."** **Not** "FIPS 140-3 validated." `PureCnsa2` is
more standards-compliant but leans entirely on the (not-yet-independently-audited
at our layer) lattice implementation, which is exactly why the strict-AND
`Hybrid` default stays recommended: it keeps the classical backstop until the PQ
implementations are audited / validated.

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

### HMAC & VRF (WASM)

Base64 in/out throughout. VRF `verify` returns the base64 output on success or
`null` on a cryptographic rejection, mirroring the native `Option`.

```js
import init, {
  hmacSha256,
  hkdfSha512,
  ecvrfEd25519GenerateKeyPair, ecvrfEd25519Prove, ecvrfEd25519Verify,
  ecvrfP256GenerateKeyPair, ecvrfP256Prove, ecvrfP256Verify,
} from './pkg/metamorphic_crypto.js';
await init();

// HMAC-SHA256
const tag = hmacSha256(btoa("key bytes"), btoa("message")); // base64 tag

// HKDF-SHA512 (RFC 5869) — combine two secrets into one 32-byte key.
// info is a UTF-8 domain-separation label; empty salt ⇒ "not provided".
const wrappingKey = hkdfSha512(wrapSaltB64, ikmB64, "mosslet/user_key-wrap/v1", 32);

// ECVRF-Edwards25519 (suite 0x03)
const ed = ecvrfEd25519GenerateKeyPair();     // { secretKey, publicKey }
const alpha = btoa("identity index");
const piEd = ecvrfEd25519Prove(ed.secretKey, alpha);
const betaEd = ecvrfEd25519Verify(ed.publicKey, alpha, piEd); // base64 or null

// ECVRF-P256 (suite 0x01) — identical shape
const p = ecvrfP256GenerateKeyPair();
const piP = ecvrfP256Prove(p.secretKey, alpha);
const betaP = ecvrfP256Verify(p.publicKey, alpha, piP);       // base64 or null
```

### CNSA 2.0 suites (WASM)

The `Suite` axis is exposed as a string argument (`"hybrid"` (default),
`"hybridMatched"`, or `"pureCnsa2"`) alongside the usual `"cat1"`/`"cat3"`/`"cat5"`
level. Decryption / verification auto-detect the suite from the version tag.

```js
import init, {
  generateHybridKeyPairSuite, hybridSealSuite, hybridOpenWithContext,
  generateSigningKeyPairSuite, sign, verify,
} from './pkg/metamorphic_crypto.js';
await init();

// Pure CNSA-2.0 KEM box (ML-KEM-1024 + AES-256-GCM)
const kp = generateHybridKeyPairSuite("pureCnsa2", "cat5"); // { publicKey, secretKey }
const sealed = hybridSealSuite(btoa("key material"), kp.publicKey, "pureCnsa2", "cat5");
// Open with the context label used at seal time (default "metamorphic/seal/v1"):
const opened = hybridOpenWithContext(sealed, kp.secretKey, "metamorphic/seal/v1"); // base64

// Pure ML-DSA-87 signatures
const sk = generateSigningKeyPairSuite("pureCnsa2", "cat5");
const sig = sign(btoa("checkpoint"), "metamorphic/sign/v1", sk.secretKey);
const ok = verify(btoa("checkpoint"), "metamorphic/sign/v1", sig, sk.publicKey); // true
```

For a custom per-tenant namespace, use `hybridSealSuiteWithContext(...,
"mosslet/seal/v1")` and open with the same label. `sealForUserWithSuite` mirrors
`sealForUser` with the suite/level appended.

## Tests

```bash
cargo test          # unit + integration + cross-level compatibility
cargo clippy        # zero warnings
cargo fmt --check   # formatted
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
