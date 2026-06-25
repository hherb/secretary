#!/usr/bin/env bash
# Acceptance entry point for D.3 slice 1: build the Secretary.xcframework, then
# run the SecretaryKit XCTest on an iOS simulator. Exits non-zero on any failure.
#
# Run from anywhere — paths resolve relative to this script.
#
# Override the simulator with IOS_SIM, e.g.  IOS_SIM='iPhone 15' run-ios-tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$IOS_DIR/SecretaryKit"
SIM_NAME="${IOS_SIM:-iPhone 16}"

# --- Step 1: host-run the pure SecretaryDeviceUnlock package (fast, no simulator) ---
# Runs FIRST: the pure package has no XCFramework dependency, so a logic
# regression fails here in milliseconds, before the multi-minute framework build.
echo "==> swift test (pure SecretaryDeviceUnlock — host)"
( cd "$IOS_DIR/SecretaryDeviceUnlock" && swift test )

# Same rationale: the pure vault-access package (unlock + browse view models)
# has no XCFramework dependency, so a logic regression fails here in
# milliseconds, before the multi-minute framework build.
echo "==> swift test (pure SecretaryVaultAccess — host)"
( cd "$IOS_DIR/SecretaryVaultAccess" && swift test )

# --- Step 2: build the framework + stage fixtures ---
echo "==> build-xcframework.sh"
bash "$SCRIPT_DIR/build-xcframework.sh"

# --- Step 3: resolve the simulator name to a concrete UDID ---
echo "==> resolving simulator: $SIM_NAME"
# shellcheck source=lib/resolve-simulator.sh
source "$SCRIPT_DIR/lib/resolve-simulator.sh"
SIM_ID="$(resolve_simulator "$SIM_NAME")"
echo "    -> $SIM_ID"

# --- Step 4: run the XCTest on the simulator ---
# xcodebuild's exit status is the acceptance result; it is the last command, so
# `set -e` propagates a non-zero test failure as this script's exit code. (We do
# NOT pipe it through tail/tee, which would mask the real status.)
echo "==> xcodebuild test (simulator: $SIM_NAME / $SIM_ID)"
cd "$PKG_DIR"
xcodebuild test -scheme SecretaryKit \
    -destination "platform=iOS Simulator,id=$SIM_ID"

# --- Step 5: build the SwiftUI walking-skeleton app ---
echo "==> build the Secretary app (XcodeGen + simulator compile proof)"
bash "$SCRIPT_DIR/build-app.sh"
