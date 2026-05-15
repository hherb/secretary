#!/usr/bin/env bash
# macOS-host Swift conformance KAT replay runner.
#
# Parallels tests/swift/run.sh (smoke runner) but compiles a different
# binary (secretary_conformance) and points it at the conformance KAT
# JSON via SECRETARY_CONFORMANCE_KAT.
#
# Run from anywhere — the script resolves paths relative to itself.
# Exits 0 if every vector passes, non-zero (with diagnostics) otherwise.
set -euo pipefail

# --- Path resolution (script-relative so callers can invoke from anywhere) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
BINDINGS_DIR="$CRATE_DIR/bindings/swift"
TARGET_DIR="$REPO_ROOT/target/release"
CDYLIB="$TARGET_DIR/libsecretary_ffi_uniffi.dylib"
BIN_OUT="$SCRIPT_DIR/secretary_conformance"

export SECRETARY_GOLDEN_VAULT_DIR="$REPO_ROOT/core/tests/data"
export SECRETARY_CONFORMANCE_KAT="$REPO_ROOT/core/tests/data/conformance_kat.json"

# --- Sanity: macOS + swiftc available ---
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: this conformance runner targets macOS hosts (got $(uname -s))" >&2
    exit 2
fi
if ! command -v swiftc >/dev/null 2>&1; then
    echo "ERROR: swiftc not found in PATH (install Xcode or the Swift toolchain)" >&2
    exit 2
fi

# --- Step 1: cargo build the cdylib ---
echo "==> cargo build --release -p secretary-ffi-uniffi"
(cd "$REPO_ROOT" && cargo build --release -p secretary-ffi-uniffi)

if [[ ! -f "$CDYLIB" ]]; then
    echo "ERROR: cdylib not produced at $CDYLIB" >&2
    exit 3
fi

# --- Step 2: regenerate Swift bindings (idempotent — safe on every run) ---
# `--features cli` enables the in-crate uniffi-bindgen binary (gated by
# `required-features = ["cli"]` so it stays out of default cdylib builds).
# `--release` matches step 1's profile so cargo reuses the compiled
# uniffi + transitive deps instead of recompiling them under the dev
# profile — bindgen itself doesn't need optimization, but profile parity
# saves a multi-minute second compile of the dependency tree.
echo "==> uniffi-bindgen generate (Swift)"
mkdir -p "$BINDINGS_DIR"
(cd "$REPO_ROOT" && cargo run --release --features cli -p secretary-ffi-uniffi \
    --bin uniffi-bindgen -- generate \
    --library "$CDYLIB" \
    --language swift \
    --out-dir "$BINDINGS_DIR")

# --- Step 3: swiftc the bindings + conformance runner ---
# - `-fmodule-map-file` registers the generated modulemap as a Clang
#   module so `import secretaryFFI` in the bindings resolves.
# - `-L`/`-lsecretary_ffi_uniffi` links the cdylib at compile time.
echo "==> swiftc conformance runner"
swiftc \
    -O \
    -I "$BINDINGS_DIR" \
    -L "$TARGET_DIR" \
    -lsecretary_ffi_uniffi \
    -Xcc -fmodule-map-file="$BINDINGS_DIR/secretaryFFI.modulemap" \
    "$BINDINGS_DIR/secretary.swift" \
    "$SCRIPT_DIR/conformance.swift" \
    -o "$BIN_OUT"

# --- Step 4: execute ---
echo "==> running $BIN_OUT"
DYLD_LIBRARY_PATH="$TARGET_DIR" "$BIN_OUT"
