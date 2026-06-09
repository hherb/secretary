#!/usr/bin/env bash
# Build the Secretary.xcframework for iOS (device + simulator) from the
# secretary-ffi-uniffi crate, generate the Swift bindings, and stage the
# golden-vault test fixture into the SPM test target's resources.
#
# Produces these build artifacts (excluded from git via ios/.gitignore):
#   ios/Secretary.xcframework/
#   ios/SecretaryKit/Sources/SecretaryKit/secretary.swift
#   ios/SecretaryKit/Tests/SecretaryKitTests/Resources/{golden_vault_001, golden_vault_001_inputs.json}
#
# Run from anywhere — paths resolve relative to this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$IOS_DIR/.." && pwd)"

CRATE="secretary-ffi-uniffi"
LIB="libsecretary_ffi_uniffi.a"
XCFRAMEWORK="$IOS_DIR/Secretary.xcframework"
PKG_SRC="$IOS_DIR/SecretaryKit/Sources/SecretaryKit"
RES_DIR="$IOS_DIR/SecretaryKit/Tests/SecretaryKitTests/Resources"
STAGING="$IOS_DIR/.build-staging"

# --- Preflight: macOS + required tools ---
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: iOS builds require macOS (got $(uname -s))" >&2; exit 2
fi
for tool in xcodebuild lipo rustup cargo; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not found in PATH" >&2; exit 2; }
done

DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")

# --- Step 1: iOS targets ---
echo "==> rustup target add (iOS)"
rustup target add "$DEVICE_TARGET" "${SIM_TARGETS[@]}"

# --- Step 2: cross-compile the staticlib for each triple ---
echo "==> cargo build staticlib (device + simulators)"
for t in "$DEVICE_TARGET" "${SIM_TARGETS[@]}"; do
    (cd "$REPO_ROOT" && cargo build --release -p "$CRATE" --target "$t")
done

# --- Step 3: lipo the two simulator archives into one fat archive ---
echo "==> lipo simulator archives"
rm -rf "$STAGING"; mkdir -p "$STAGING"
SIM_FAT="$STAGING/sim/$LIB"; mkdir -p "$STAGING/sim"
lipo -create \
    "$REPO_ROOT/target/aarch64-apple-ios-sim/release/$LIB" \
    "$REPO_ROOT/target/x86_64-apple-ios/release/$LIB" \
    -output "$SIM_FAT"
DEVICE_LIB="$REPO_ROOT/target/$DEVICE_TARGET/release/$LIB"

# --- Step 4: generate Swift bindings (uniffi-bindgen) ---
# Why a host cdylib for bindgen: uniffi 0.31's `--library` mode reads the
# crate's component metadata out of the binary's symbol table. The iOS
# *staticlib* slices are cross-compiled archives whose metadata uniffi-bindgen
# (a host tool) cannot read on this host, so we generate the bindings from the
# HOST cdylib instead. The generated Swift + the C header/modulemap are pure
# source artifacts — identical regardless of which slice they're read from —
# so packaging the iOS `.a` slices into the XCFramework below remains correct.
# This mirrors the desktop tests/swift/run.sh, which also reads the cdylib.
echo "==> cargo build host cdylib (for bindgen metadata)"
(cd "$REPO_ROOT" && cargo build --release -p "$CRATE")
HOST_CDYLIB="$REPO_ROOT/target/release/${LIB%.a}.dylib"
if [[ ! -f "$HOST_CDYLIB" ]]; then
    echo "ERROR: host cdylib not produced at $HOST_CDYLIB" >&2; exit 3
fi

echo "==> uniffi-bindgen generate (Swift)"
BIND_OUT="$STAGING/bindings"; mkdir -p "$BIND_OUT"
# --release here matches the cdylib build above: reusing the release profile
# reuses the already-compiled dependency tree, avoiding a multi-minute
# dev-profile recompile (same rationale as ffi/secretary-ffi-uniffi/tests/swift/run.sh).
(cd "$REPO_ROOT" && cargo run --release --features cli -p "$CRATE" \
    --bin uniffi-bindgen -- generate \
    --library "$HOST_CDYLIB" \
    --language swift \
    --out-dir "$BIND_OUT")

# Copy the high-level Swift API into the SPM lib target.
mkdir -p "$PKG_SRC"
cp "$BIND_OUT/secretary.swift" "$PKG_SRC/secretary.swift"

# Assemble the XCFramework headers dir: the FFI header + a module.modulemap
# (Clang requires the file be named module.modulemap inside an xcframework's
# Headers dir). uniffi emits <name>.h and <name>.modulemap; copy by glob so a
# uniffi rename surfaces as a build error here, not silently.
HDRS="$STAGING/headers"; mkdir -p "$HDRS"
cp "$BIND_OUT"/*.h "$HDRS/"
cp "$BIND_OUT"/*.modulemap "$HDRS/module.modulemap"

# --- Step 5: assemble the XCFramework (clean-rebuild; -create refuses overwrite) ---
echo "==> xcodebuild -create-xcframework"
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" -headers "$HDRS" \
    -library "$SIM_FAT" -headers "$HDRS" \
    -output "$XCFRAMEWORK"

# --- Step 6: stage the golden-vault fixture as an SPM test resource ---
echo "==> stage golden_vault_001 fixture"
rm -rf "$RES_DIR"; mkdir -p "$RES_DIR"
cp -R "$REPO_ROOT/core/tests/data/golden_vault_001" "$RES_DIR/golden_vault_001"
cp "$REPO_ROOT/core/tests/data/golden_vault_001_inputs.json" "$RES_DIR/golden_vault_001_inputs.json"

echo "==> done: $XCFRAMEWORK"
