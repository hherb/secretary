#!/usr/bin/env bash
# Acceptance entry point for D.5.1: host-test the pure packages, build the
# Secretary.xcframework (incl. the macOS slice), host-test SecretaryKit on macOS,
# and compile-prove the SecretaryMac app. Exits non-zero on any failure.
#
# Real Touch ID / Secure-Enclave release is a manual proof — see
# ios/SecretaryMacApp/MANUAL-PROOF.md. Run from anywhere.
#
# This runner is manual/local for now; wiring it into CI as a macos-host job is
# tracked in https://github.com/hherb/secretary/issues/437 (the pure host packages
# are already covered by the ios-host job).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: macOS builds require macOS (got $(uname -s))" >&2; exit 2
fi

# --- Step 1: host-run the pure packages (fast, no framework) ---
echo "==> swift test (pure SecretaryDeviceUnlock — host)"
( cd "$IOS_DIR/SecretaryDeviceUnlock" && swift test )
echo "==> swift test (pure SecretaryVaultAccess — host)"
( cd "$IOS_DIR/SecretaryVaultAccess" && swift test )

# --- Step 2: build the framework (incl. the macOS slice) + stage fixtures ---
# build-xcframework.sh is a multi-minute silent build with no interim output;
# an agent runner should background it and poll the log instead of blocking
# on it (avoids tripping the harness's watchdog timeout).
echo "==> build-xcframework.sh"
bash "$SCRIPT_DIR/build-xcframework.sh"

# --- Step 3: host-test SecretaryKit on macOS (no simulator — the D.5.1 win) ---
echo "==> swift test (SecretaryKit — macOS host)"
( cd "$IOS_DIR/SecretaryKit" && swift test )

# --- Step 4: compile-prove the SecretaryMac app ---
echo "==> build the SecretaryMac app (XcodeGen + macOS compile proof)"
bash "$SCRIPT_DIR/build-macos-app.sh"

echo "==> D.5.1 automated acceptance: PASS"
