#!/usr/bin/env bash
# Convenience launcher for the manual macOS smoke (D.5.x): build the framework,
# stage the demo vault, generate the Xcode project, compile-prove, then OPEN the
# project in Xcode so you can select your signing team and Run (⌘R).
#
# Why Xcode and not a headless launch: running from Xcode with a real Developer
# team is what makes Touch ID / Secure Enclave key release work. The
# CODE_SIGNING_ALLOWED=NO compile proof (build-macos-app.sh / CI) cannot — an
# unsigned run fails enroll with errSecMissingEntitlement (-34018). See
# ios/SecretaryMacApp/MANUAL-PROOF.md for the on-hardware proof steps.
#
# Optionally pass your team so the generated project pre-fills it (you can also
# pick it in Xcode's Signing & Capabilities tab):
#   DEVELOPMENT_TEAM=<YOUR_TEAM_ID> bash ios/scripts/run-macos-app.sh
#
# Xcode's own build on ⌘R is incremental — it reuses the compile proof's object
# files from the shared DerivedData, so it only re-links + re-signs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: the macOS app runs on macOS only (got $(uname -s))" >&2; exit 2
fi

# Reuse the single source of truth for xcframework build + demo-vault staging +
# project generation + compile proof (DRY — do not duplicate that logic here).
bash "$SCRIPT_DIR/build-macos-app.sh"

PROJECT="$IOS_DIR/SecretaryMacApp/SecretaryMac.xcodeproj"
echo "==> opening $PROJECT in Xcode"
echo "    In Xcode: scheme SecretaryMac · destination My Mac · Signing & Capabilities → your team · Run (⌘R)."
open "$PROJECT"
