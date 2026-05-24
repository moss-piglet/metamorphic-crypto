#!/usr/bin/env bash
#
# update-wasm.sh — Download and verify WASM artifacts from a metamorphic-crypto release.
#
# Usage:
#   ./update-wasm.sh v0.3.0 /path/to/project
#
# This script:
#   1. Downloads the WASM artifacts and SHA512SUMS from a GitHub Release
#   2. Verifies SHA-512 checksums
#   3. Patches the JS glue to use /wasm/ serving path (for Phoenix)
#   4. Copies artifacts into the project's vendor directory
#   5. Copies the .wasm file into priv/static/wasm/ for serving
#
# Requirements: curl, sha512sum (or shasum on macOS)

set -euo pipefail

REPO="moss-piglet/metamorphic-crypto"
VENDOR_DIR="assets/vendor/metamorphic-crypto"
STATIC_WASM_DIR="priv/static/wasm"

# --- Argument parsing ---

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <version-tag> [project-root]"
  echo "  e.g. $0 v0.3.0 /path/to/mosslet"
  exit 1
fi

TAG="$1"
PROJECT_ROOT="${2:-.}"

# Resolve absolute path
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"

echo "==> Updating metamorphic-crypto WASM to ${TAG}"
echo "    Project: ${PROJECT_ROOT}"

# --- Download ---

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

for file in metamorphic_crypto.js metamorphic_crypto_bg.wasm SHA512SUMS; do
  echo "    Downloading ${file}..."
  curl -fsSL "${BASE_URL}/${file}" -o "${TMPDIR}/${file}"
done

# --- Verify checksums ---

echo "==> Verifying SHA-512 checksums..."

# macOS uses shasum, Linux uses sha512sum
if command -v sha512sum &>/dev/null; then
  SHA_CMD="sha512sum"
elif command -v shasum &>/dev/null; then
  SHA_CMD="shasum -a 512"
else
  echo "ERROR: Neither sha512sum nor shasum found." >&2
  exit 1
fi

(cd "$TMPDIR" && $SHA_CMD -c SHA512SUMS)
echo "    Checksums OK"

# --- Patch JS glue for Phoenix /wasm/ serving ---

echo "==> Patching JS glue for Phoenix static serving..."

# wasm-pack generates: new URL('metamorphic_crypto_bg.wasm', import.meta.url)
# We replace with the absolute path where Phoenix serves the file.
sed -i.bak \
  "s|new URL('metamorphic_crypto_bg.wasm', import.meta.url)|\"/wasm/metamorphic_crypto_bg.wasm\"|g" \
  "${TMPDIR}/metamorphic_crypto.js"
rm -f "${TMPDIR}/metamorphic_crypto.js.bak"

# --- Copy to project ---

echo "==> Copying to vendor directory..."

DEST="${PROJECT_ROOT}/${VENDOR_DIR}"
mkdir -p "$DEST"
cp "${TMPDIR}/metamorphic_crypto.js" "$DEST/"
cp "${TMPDIR}/metamorphic_crypto_bg.wasm" "$DEST/"
cp "${TMPDIR}/SHA512SUMS" "$DEST/"

# Keep license files if they exist
for license in LICENSE-APACHE LICENSE-MIT; do
  if [[ -f "${DEST}/${license}" ]]; then
    echo "    Keeping existing ${license}"
  fi
done

echo "==> Copying WASM binary to priv/static/wasm/..."

WASM_DEST="${PROJECT_ROOT}/${STATIC_WASM_DIR}"
mkdir -p "$WASM_DEST"
cp "${TMPDIR}/metamorphic_crypto_bg.wasm" "$WASM_DEST/"

# Clean up Phoenix digest cache (force re-digest on next compile)
rm -f "${WASM_DEST}/metamorphic_crypto_bg-"*.wasm
echo "    Cleared old digest-hashed copies"

echo ""
echo "==> Done! metamorphic-crypto WASM updated to ${TAG}"
echo "    Vendor:  ${DEST}"
echo "    Static:  ${WASM_DEST}"
echo ""
echo "    Next steps:"
echo "      1. Review changes: git diff"
echo "      2. Test your app: mix test"
echo "      3. Commit: git add -A && git commit -m 'Update metamorphic-crypto WASM to ${TAG}'"
