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

# --- Step 1: build the framework + stage fixtures ---
echo "==> build-xcframework.sh"
bash "$SCRIPT_DIR/build-xcframework.sh"

# --- Step 2: resolve the simulator name to a concrete UDID ---
# The bare `name=` destination is ambiguous when multiple runtimes/arches share
# a device name (xcodebuild errors with "Unable to find a device matching the
# provided destination specifier"), so we resolve to a UDID and target by id=.
# Anchor the match to "<name> (" so an exact name like "iPhone 16" does not also
# match "iPhone 16 Pro" / "iPhone 16 Plus" / "iPhone 16e".
echo "==> resolving simulator: $SIM_NAME"
# Capture the device list ONCE: a genuine `simctl` failure aborts here under
# `set -e` (rather than being swallowed by the `|| true` below and misreported
# as a missing device). The `|| true` then guards ONLY the grep pipeline, where
# a no-match is legitimately empty.
# NB: $SIM_NAME is interpolated into an ERE, so a device name containing regex
# metacharacters (. + ( etc.) could mis-match — fine for real device names
# ("iPhone 16", "iPhone 15"), which contain none.
# `head -1` takes the FIRST matching device regardless of which iOS runtime it
# is paired with. `simctl` lists devices grouped by runtime, so this is whatever
# runtime simctl emits first; it assumes every installed runtime is >= the
# Package.swift deployment floor (iOS 17). If a sub-floor runtime is ever
# installed and emitted first, pin the runtime via IOS_SIM or extend this match.
DEVICES="$(xcrun simctl list devices available)"
SIM_ID="$(printf '%s\n' "$DEVICES" \
    | grep -E "^[[:space:]]*${SIM_NAME} \(" \
    | head -1 \
    | grep -oE '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' || true)"
if [[ -z "$SIM_ID" ]]; then
    echo "ERROR: no available simulator named '$SIM_NAME'. Available devices:" >&2
    printf '%s\n' "$DEVICES" >&2
    echo "Set IOS_SIM to one of the device names listed above." >&2
    exit 2
fi
echo "    -> $SIM_ID"

# --- Step 3: run the XCTest on the simulator ---
# xcodebuild's exit status is the acceptance result; it is the last command, so
# `set -e` propagates a non-zero test failure as this script's exit code. (We do
# NOT pipe it through tail/tee, which would mask the real status.)
echo "==> xcodebuild test (simulator: $SIM_NAME / $SIM_ID)"
cd "$PKG_DIR"
xcodebuild test -scheme SecretaryKit \
    -destination "platform=iOS Simulator,id=$SIM_ID"
