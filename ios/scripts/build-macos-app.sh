#!/usr/bin/env bash
# Stage the demo vault, generate the Xcode project with XcodeGen, and build the
# SecretaryMac app for macOS (a signing-free compile proof for CI). Real Touch ID
# release is the manual proof in ios/SecretaryMacApp/MANUAL-PROOF.md (D.5.1).
#
# Secretary.xcframework is a prerequisite — build it (with its macOS slice) first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_DIR="$REPO_ROOT/ios/SecretaryMacApp"
RES_DIR="$APP_DIR/Fixtures"
XCFRAMEWORK="$REPO_ROOT/ios/Secretary.xcframework"

command -v xcodegen >/dev/null || { echo "ERROR: xcodegen not found — 'brew install xcodegen'"; exit 1; }

if [[ ! -d "$XCFRAMEWORK" ]]; then
    echo "==> Secretary.xcframework not found — running build-xcframework.sh first"
    bash "$SCRIPT_DIR/build-xcframework.sh"
fi

echo "==> stage golden_vault_001 fixture into the app bundle (Fixtures/)"
rm -rf "$RES_DIR"; mkdir -p "$RES_DIR"
cp -R "$REPO_ROOT/core/tests/data/golden_vault_001" "$RES_DIR/golden_vault_001"
cp "$REPO_ROOT/core/tests/data/golden_vault_001_inputs.json" "$RES_DIR/golden_vault_001_inputs.json"

echo "==> generate SecretaryMac.xcodeproj"
( cd "$APP_DIR" && xcodegen generate )

echo "==> build for macOS (no signing — compile proof)"
xcodebuild build \
  -project "$APP_DIR/SecretaryMac.xcodeproj" \
  -scheme SecretaryMac \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO
