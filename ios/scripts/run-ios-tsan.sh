#!/usr/bin/env bash
# TSan acceptance entry point (#300 follow-up): build the Secretary.xcframework,
# then run the full SecretaryKit XCTest suite under ThreadSanitizer on an iOS
# simulator. The SessionConcurrencyIntegrationTests are the teeth — they drive
# UniffiVaultSession's readBlock/wipe/writes concurrently, so TSan flags any
# unsynchronized access to its mutable state (the #300 lock).
#
# Run from anywhere — paths resolve relative to this script.
# Override the simulator with IOS_SIM, e.g.  IOS_SIM='iPhone 15' run-ios-tsan.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$IOS_DIR/SecretaryKit"
SIM_NAME="${IOS_SIM:-iPhone 16}"

# --- Step 1: build the framework + stage fixtures (golden_vault_001) ---
echo "==> build-xcframework.sh"
bash "$SCRIPT_DIR/build-xcframework.sh"

# --- Step 2: resolve the simulator name to a concrete UDID ---
echo "==> resolving simulator: $SIM_NAME"
# shellcheck source=lib/resolve-simulator.sh
source "$SCRIPT_DIR/lib/resolve-simulator.sh"
SIM_ID="$(resolve_simulator "$SIM_NAME")"
echo "    -> $SIM_ID"

# --- Step 3: run the whole suite under ThreadSanitizer ---
# -enableThreadSanitizer YES instruments the Swift build. The uniffi Rust dylib is
# opaque to TSan (calls into it carry no happens-before), which is fine: the races
# #300 guards are on Swift-side mutable stored properties (currentBlock / wiped /
# cachedDeviceUuid), which NSLock (TSan-aware) synchronizes. xcodebuild's exit
# status is the acceptance result; it is the last command, so `set -e` propagates a
# non-zero test/TSan failure as this script's exit code.
echo "==> xcodebuild test -enableThreadSanitizer YES (simulator: $SIM_NAME / $SIM_ID)"
cd "$PKG_DIR"
xcodebuild test -scheme SecretaryKit \
    -destination "platform=iOS Simulator,id=$SIM_ID" \
    -enableThreadSanitizer YES
