# Changelog

## v0.7.2 (2026-06-26)

Adds a small, **additive** raw-Ed25519 interop API. Fully non-breaking: every
existing artifact, tag, function, and byte path is untouched, and the hybrid PQ
composite remains the default authenticity primitive.

### New `ed25519` module — bare RFC 8032 Ed25519 (witness interop)

- New public module `ed25519` exposing `ed25519_verify`, `ed25519_sign`,
  `ed25519_public_key`, and `ed25519_generate_keypair`, plus the
  `ED25519_SEED_LEN` / `ED25519_PUBLIC_KEY_LEN` / `ED25519_SIGNATURE_LEN`
  constants. Re-exported at the crate root.
- **Purpose: byte-level interoperability with the deployed C2SP
  transparency-log witness ecosystem** (Go `sumdb/note`, sigsum,
  transparency-dev, Tessera), which co-signs `checkpoint` / `signed-note`
  artifacts with **raw** Ed25519 over the exact note text — no context framing
  and no post-quantum component. `metamorphic-log` consumes this to verify
  external witness co-signature lines (and emit its own classical line) without
  pulling a second, parallel Ed25519 dependency, keeping `metamorphic-crypto`
  the single source of truth for primitives.
- This is **not** a general-purpose signing API. For Metamorphic authenticity,
  keep using the hybrid PQ composite [`sign`] / [`verify`]. Verification uses
  `verify_strict` (rejects non-canonical / small-order keys) while remaining
  interoperable with honestly generated witness signatures.
- Locked against RFC 8032 §7.1 known-answer vectors (Test 1 + Test 2).
- No new dependencies (`ed25519-dalek` was already in-tree); no wire-format or
  public-API changes to any existing function.

## v0.7.1 (2026-06-25)

Docs + dependency/CI maintenance. **No functional or wire-format changes** — the
crate's source, public API, version tags, and byte layout are byte-for-byte
identical to v0.7.0.

- **Docs:** document the v0.7.0 **CNSA 2.0 suite axis** in `README.md` and
  `npm-README.md` (the orthogonal `Suite` × `SecurityLevel` model;
  `Hybrid` / `HybridMatched` / `PureCnsa2`; the HKDF-SHA512 + AES-256-GCM seal
  envelope and `0x10/0x13/0x14` tags; context labels; Rust + WASM usage; honest
  "CNSA 2.0 suite, not FIPS-validated" claims). Newcomers can now discover the
  `generate_*_suite` / `*Suite` APIs without reading the source.
- **Dependencies** (Cargo.lock only; within existing semver ranges — the pinned
  CNSA-2.0 rc/pre deps are untouched): `zeroize` 1.8.2 → 1.9.0, `zeroize_derive`
  1.4.3 → 1.5.0, `js-sys` 0.3.100 → 0.3.103, `wasm-bindgen` 0.2.123 → 0.2.126.
- **CI / release** (GitHub Actions, SHA-pinned): `actions/checkout` v6 → v7,
  `rust-lang/crates-io-auth-action` v1.0.4 → v1.0.5,
  `softprops/action-gh-release` v3.0.0 → v3.0.1.

## v0.7.0 (2026-06-25)

Adds an **opt-in CNSA 2.0 suite axis** to both the KEM/seal and signature
layers — fully additive and **non-breaking**: every existing artifact, tag,
function, and byte path is untouched, and `Suite::Hybrid` stays the default.

### New `Suite` axis (orthogonal to `SecurityLevel`)

A new `Suite` enum composes with the existing `SecurityLevel` (Cat-1/3/5), so a
developer chooses posture with a single extra argument while the rest of the API
surface stays identical:

- **`Suite::Hybrid`** — default & recommended. The existing classical+PQ
  strict-AND constructions (ML-KEM + X25519 KEM; ML-DSA + Ed25519 signatures).
  Byte-for-byte unchanged.
- **`Suite::HybridMatched`** — opt-in. The classical partner is matched to the
  PQ category. The lowest shared rung is identical
  to `Hybrid` (no new format), so nothing breaks.
- **`Suite::PureCnsa2`** — opt-in. Pure post-quantum, no classical half (the NSA
  CNSA-2.0 box). Cat-5 only in this release.

### KEM / seal (target of #311)

- **PureCnsa2 (Cat-5):** ML-KEM-1024 + AES-256-GCM. Tag `0x10`. Public key =
  ML-KEM-1024 ek (1568 B).
- **HybridMatched Cat-3:** ML-KEM-768 + **X448** + AES-256-GCM. Tag `0x13`.
- **HybridMatched Cat-5:** ML-KEM-1024 + **P-521 ECDH** + AES-256-GCM. Tag `0x14`.
- **HybridMatched Cat-1** reuses the existing `0x01` X25519 construction (no
  duplicate format).
- **Seal envelope** (new suites only): KEM shared secret(s) →
  `HKDF-SHA512(info = suite_tag ‖ context_label)` → single-use AES-256 key →
  `AES-256-GCM(96-bit random nonce, AAD = suite_tag ‖ context_label, full
128-bit tag)`. Layout: `tag(1) ‖ kem_ct ‖ [ecc_eph_pk] ‖ nonce(12) ‖ ct ‖
gcm_tag(16)`. Because each encapsulation yields a fresh KEM secret, the AES key
  is single-use, so the random nonce can never repeat — SIV-grade misuse
  resistance without leaving the CNSA-approved set (no AES-GCM-SIV).
- The legacy `combineKEMS` (SHA3-256) + XSalsa20-Poly1305 path and all
  `0x01/0x02/0x03` bytes are **byte-for-byte untouched**. Deliberate hash split:
  HKDF-SHA512 for _key derivation_; SHA3-512 remains for _leaf/transcript_
  hashing.
- New Rust fns (crate root): `generate_hybrid_keypair_suite`,
  `hybrid_seal_suite`, `hybrid_seal_suite_with_context`, `hybrid_open_with_context`,
  `seal_for_user_with_suite`, plus the `Suite` enum and `SEAL_CONTEXT_V1`.
  `hybrid_open` / `unseal_from_user` auto-detect the new tags (using the default
  context label).
- New WASM exports: `generateHybridKeyPairSuite`, `hybridSealSuite`,
  `hybridSealSuiteWithContext`, `hybridOpenWithContext`, `sealForUserWithSuite`.

### Signatures (target of #312)

- **PureCnsa2 (Cat-5):** ML-DSA-87 only. Tag `0x10`.
- **HybridMatched Cat-3:** ML-DSA-65 + **Ed448** (deterministic, RFC 8032).
  Tag `0x13`.
- **HybridMatched Cat-5:** ML-DSA-87 + **ECDSA-P-521**, **hedged RFC 6979**
  (deterministic nonce + added OS entropy via RustCrypto `RandomizedSigner`,
  consistent with the existing hedged-ML-DSA posture). Tag `0x14`.
- **HybridMatched Cat-2** reuses the existing `0x01` Ed25519 construction.
- Layouts (fixed-size classical first, so the variable ML-DSA tail needs no
  length prefix): `sig = tag ‖ [classical_sig] ‖ ml_dsa_sig`;
  `pk = tag ‖ [classical_pk] ‖ ml_dsa_pk`; `sk = tag ‖ [classical_seed] ‖
ml_dsa_seed`. The same I2OSP length-prefixed domain-separation framing is
  reused for all suites. `sign` / `verify` / `derive_public_key` auto-detect the
  suite from the version tag (no suite argument needed).
- New fns: `generate_signing_keypair_suite` (Rust) and
  `generateSigningKeyPairSuite` (WASM). Existing `sign`/`verify` byte paths
  unchanged.

### Context labels (RESOLVED)

Versioned grammar `"<namespace>/<purpose>/v<major>"`. Library defaults
`"metamorphic/seal/v1"` (`SEAL_CONTEXT_V1`) and `"metamorphic/sign/v1"`
(`SIGN_CONTEXT_V1`). The namespace is the one per-tenant knob; it is bound into
the HKDF `info` + GCM AAD (seal) and the I2OSP-framed signed message (sign).

### Dependencies (single pure-Rust stack; `#![forbid(unsafe_code)]` preserved)

All RustCrypto, no `aws-lc-rs` (which would break WASM + forbid-unsafe). Pinned
to the same rc/pre generation as the existing `sha3 0.11` / `ml-kem 0.3` /
`ml-dsa 0.1` (digest 0.11 / crypto-common 0.2) stack — no mixed generations:
`aes-gcm 0.11.0-rc.4` (NCC-audited 2023), `hkdf 0.13`, `x448 0.14.0-pre.12`,
`p521 0.14.0-rc.14` (ecdh + ecdsa), `ed448-goldilocks 0.14.0-pre.15`. The CNSA-2.0
deps pull in getrandom 0.4, whose wasm32 backend is opted into via the `wasm_js`
feature (renamed `getrandom_v04`) so it coexists with the 0.2 instance — exactly
the WASM-friendliness that staying pure-Rust buys.

### Honesty / claims discipline

Claim: "CNSA 2.0 algorithm suite, NCC-audited components, pure-Rust,
memory-safe (`forbid-unsafe`)." **Not** "FIPS 140-3 validated." `PureCnsa2` is
more standards-compliant but leans entirely on the (not-yet-independently-
audited at our layer) lattice implementation, so the strict-AND `Hybrid` default
keeps the classical backstop until the PQ impls are audited/validated.

### Tests / KATs

- AES-256-GCM NIST CAVP vectors; HKDF-SHA512 known-answer vector; ML-KEM-1024
  FIPS-203 deterministic KAT (anchors raw byte-equality with `@noble/post-quantum`
  and any FIPS-203 impl).
- Full PureCnsa2 + HybridMatched seal round-trips, context-label binding, tamper
  rejection; PureCnsa2 + matched sign/verify round-trips with strict-AND
  corruption tests; cross-suite/-key rejection.
- New `tests/cnsa2_vectors.rs` pins the wire structure (tags, FIPS sizes) and the
  deterministic signature public keys (via SHA3-512 digest) for cross-language
  (Rust / WASM / NIF) parity.

## v0.6.0 (2026-06-24)

- Extend the hybrid post-quantum **KEM** to the full standardized ML-KEM range
  (additive, non-breaking). ML-KEM coverage now spans every NIST (FIPS 203)
  parameter set: **Cat-1 (512)**, Cat-3 (768, default), Cat-5 (1024). Together
  with the ML-DSA 44/65/87 signatures from v0.5.0 (Cat-2/3/5), the crate now
  covers **all** standardized FIPS 203 / 204 parameter sets — no rolled or
  invented parameters.
  - New tier: **Cat-1 = ML-KEM-512 + X25519** (~AES-128), version tag `0x01`.
    NIST defines ML-KEM only at categories 1/3/5; there is no category-2/4
    ML-KEM set, so none is offered.
  - New Rust fns, re-exported at the crate root: `generate_hybrid_keypair_512`
    and `hybrid_seal_512`, plus the `SecurityLevel::Cat1` variant wired into
    `generate_hybrid_keypair_with_level` / `hybrid_seal_with_level`.
  - `hybrid_open` now auto-detects Cat-1 (`0x01`), Cat-3 (`0x02`), and Cat-5
    (`0x03`) from the version byte; `is_hybrid_ciphertext` recognizes all three.
    The KEM tags form a dense ordered sequence (Cat-1=`0x01`, Cat-3=`0x02`,
    Cat-5=`0x03`).
  - Wire format (Cat-1): `0x01 || ML-KEM-512 ct (768 B) || X25519 eph pk (32 B)
|| nonce (24 B) || secretbox ct`. Public key = ML-KEM-512 ek (800 B) ||
    X25519 pk (32 B) = 832 bytes; secret key = 32-byte root seed.
  - Version-tag note: tags are **per-artifact-type wire-format versions**, not
    global category codes. KEM and signature tags agree on the shared Cat-3
    (`0x02`) / Cat-5 (`0x03`) rungs; they intentionally diverge at `0x01`
    (KEM = Cat-1 ML-KEM-512, signatures = Cat-2 ML-DSA-44) because NIST
    standardizes ML-KEM at {1,3,5} and ML-DSA at {2,3,5}. `box_seal` is
    unversioned (its first byte is a random X25519 pubkey byte), so `0x01` is
    not a legacy sentinel. `hybrid_open`'s exact minimum-length gate prevents a
    legacy ciphertext whose random first byte happens to be `0x01` from being
    mis-routed as Cat-1 (covered by a regression test).
  - Classical-partner caveat (documented honestly): the classical half is
    X25519 (~Cat-1 classical) at every tier and does not scale up; at Cat-3/Cat-5
    the PQ half dominates and X25519 is the classical floor — standard hybrid
    practice.
  - New WASM export: `generateHybridKeyPair512` (Cat-1 keypair generation);
    `parse_security_level` now accepts `"cat1"`. `unsealFromUser` /
    `unseal_from_user` unchanged — already auto-detects from the version byte.
  - Tests mirroring Cat-3/Cat-5: roundtrip, version tag, wrong-key, key sizes,
    ciphertext size, cross-level rejection, nondeterministic, empty plaintext,
    plus a legacy-not-misdetected-as-Cat-1 guard.
- Harden the unified unseal path against legacy/hybrid first-byte collisions
  (data-availability only; not a security fix; no wire-format change). The
  unversioned legacy `box_seal` format has a random leading byte, so a legacy
  ciphertext could in principle collide with a hybrid tag — a surface widened
  from two tag values to three by the new Cat-1 `0x01`.
  - `is_hybrid_ciphertext` is now **length-aware**: it returns `true` only when
    the leading byte is a known tag **and** the total length is at least that
    tier's minimum (the same bound `hybrid_open` enforces). This is a minor,
    more-correct behavior change to a public function — a short legacy
    ciphertext that merely collides on the first byte is no longer classified as
    hybrid. Real hybrid ciphertexts are always above the minimum, so they are
    unaffected.
  - `unseal_from_user` now **falls back** to the legacy `box_seal_open` if hybrid
    detection matched but the hybrid open failed. This rescues a misdetected
    legacy ciphertext that collides on _both_ the tag byte and a hybrid-matching
    length; a genuinely failed hybrid open of a real hybrid ciphertext still
    fails the legacy attempt and returns an error (no silent wrong plaintext).
    Internal only — no API or wire-format change. (The explicitly rejected
    alternative — adding a version prefix to the unversioned legacy `box_seal`
    format — would be a breaking wire-format change requiring a client-side
    re-seal of all existing data, disproportionate for an availability-only
    edge case.)
  - Internal hardening: the per-tier minimum sealed-box length is now a single
    source of truth (`MIN_HYBRID_512_LEN` / `_768_` / `_1024_` consts) shared by
    the routing check (`is_hybrid_ciphertext`) and the decapsulation gate
    (`hybrid_open_*`), so the detection bound and the open gate cannot drift
    apart. No behavior change.
- All existing APIs unchanged — fully backward compatible.

## v0.5.0 (2026-06-24)

- Add a hybrid post-quantum **signature** API (additive, non-breaking). This is
  the signing counterpart to the existing hybrid KEM: a _composite_ signature
  that signs every message with **both** ML-DSA (FIPS 204) **and** Ed25519
  (RFC 8032), and verifies only if **both** components are valid (strict AND).
  An attacker must break both a lattice scheme and an elliptic-curve scheme, and
  cannot strip one algorithm to downgrade the other.
  - New Rust module `sign`, re-exported at the crate root:
    `generate_signing_keypair` (Cat-3 default), `generate_signing_keypair_44`
    (Cat-2), `generate_signing_keypair_87` (Cat-5),
    `generate_signing_keypair_with_level`, `derive_public_key`, `sign`,
    `verify`, plus `HybridSignatureKeyPair`, `SignatureLevel`, and the
    `SIGN_CONTEXT_V1` convention label.
  - Security levels (the full standardized ML-DSA range, each + Ed25519):
    Cat-2 = ML-DSA-44 (`0x01`), Cat-3 = ML-DSA-65 (`0x02`, default),
    Cat-5 = ML-DSA-87 (`0x03`). NIST standardizes ML-DSA only at categories
    2/3/5. No SLH-DSA (FIPS 205) yet.
  - Signing mode is **hedged/randomized** ML-DSA (FIPS 204 default and most
    conservative; resilient to RNG failure and side-channel/fault-hardened).
    Ed25519 is deterministic per RFC 8032. Signature _bytes_ are therefore
    non-reproducible, but the wire format (layout, tags, key derivation,
    framing) is fully deterministic and pinned.
  - Domain separation reuses the exact `sha3_512_with_context` framing:
    `signed_msg = I2OSP(len(context), 8) || context_utf8 || message`, signed
    directly by both algorithms (ML-DSA with an empty native context).
  - Wire format:
    `signature  = tag || ed25519_sig (64 B) || ml_dsa_sig`;
    `public_key = tag || ed25519_pk  (32 B) || ml_dsa_pk`;
    `secret_key = tag || ed25519_seed (32 B) || ml_dsa_seed (32 B)` (65 B), base64.
    The `HybridSignatureKeyPair` secret is zeroized on drop.
  - New WASM exports: `generateSigningKeyPair`, `deriveSigningPublicKey`,
    `sign`, `verify` — base64 in/out (message base64, `context` a UTF-8 string),
    consistent with the rest of the WASM API.
  - Tests: per-level roundtrips, strict-AND tamper checks (both halves),
    wrong-key / tampered-message / context-separation / cross-level failures,
    version-tag and size pins, randomized-but-both-valid, framing pins, and a
    `tests/sign_vectors.rs` cross-language pin file (deterministic public-key
    derivation + framing). Plus a proptest roundtrip over arbitrary messages.
  - Dependencies: add `ed25519-dalek` 2.x (mature, audited) and `ml-dsa` 0.1.x
    (RustCrypto FIPS 204; **not yet independently audited** — pinned and tracked
    for the FIPS-mode roadmap; documented honestly in `README`/module docs).
    `ml-dsa` shares `sha3` 0.11 with the existing tree (no new keccak version).
- All existing APIs unchanged — fully backward compatible. Encryption
  (KEM / secretbox / Argon2id) is untouched.

## v0.4.0 (2026-06-22)

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
    `sha3_512`; it _is_ SHA3-512 over a framed message.
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
