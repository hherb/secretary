#!/usr/bin/env bash
# install-dev.sh — one-shot DEV install of the Secretary browser-autofill
# native-messaging host manifest, so the manual browser smoke is copy-paste.
#
# It builds the host binary, then writes the native-messaging manifest
# (com.secretary.browser_host.json) — with the absolute binary path and the
# extension ID filled in — into the right NativeMessagingHosts directory for
# your browser + OS (macOS / Linux). Chromium/Chrome/Edge only; Windows +
# Firefox/Safari are D.4.6.
#
# Usage:
#   install-dev.sh --ext-id <EXTENSION_ID> [--browser chrome|chromium|edge]
#                  [--skip-build] [--dry-run] [--uninstall]
#
# The EXTENSION_ID is the 32-char id shown on the extension's card at
# chrome://extensions after you "Load unpacked" browser/extension/.
#
# Override the install directory (for testing) with $SECRETARY_NM_DIR.
set -euo pipefail

BROWSER="chrome"
EXT_ID=""
SKIP_BUILD=0
DRY_RUN=0
UNINSTALL=0
MANIFEST_NAME="com.secretary.browser_host.json"

die() { echo "install-dev.sh: $*" >&2; exit 1; }

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ext-id)    EXT_ID="${2:-}"; shift 2 ;;
    --browser)   BROWSER="${2:-}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)   usage 0 ;;
    *) die "unexpected argument: $1 (try --help)" ;;
  esac
done

# Repo root = two levels up from this script (browser/host-manifest/).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Resolve the per-OS + per-browser NativeMessagingHosts directory.
nm_dir() {
  if [ -n "${SECRETARY_NM_DIR:-}" ]; then
    printf '%s' "$SECRETARY_NM_DIR"
    return
  fi
  local os; os="$(uname -s)"
  case "$os" in
    Darwin)
      local base="$HOME/Library/Application Support"
      case "$BROWSER" in
        chrome)   printf '%s' "$base/Google/Chrome/NativeMessagingHosts" ;;
        chromium) printf '%s' "$base/Chromium/NativeMessagingHosts" ;;
        edge)     printf '%s' "$base/Microsoft Edge/NativeMessagingHosts" ;;
        *) die "unknown --browser '$BROWSER' (chrome|chromium|edge)" ;;
      esac ;;
    Linux)
      local base="$HOME/.config"
      case "$BROWSER" in
        chrome)   printf '%s' "$base/google-chrome/NativeMessagingHosts" ;;
        chromium) printf '%s' "$base/chromium/NativeMessagingHosts" ;;
        edge)     printf '%s' "$base/microsoft-edge/NativeMessagingHosts" ;;
        *) die "unknown --browser '$BROWSER' (chrome|chromium|edge)" ;;
      esac ;;
    *) die "unsupported OS '$os' (macOS/Linux only; Windows is D.4.6)" ;;
  esac
}

DEST_DIR="$(nm_dir)"
DEST="$DEST_DIR/$MANIFEST_NAME"

if [ "$UNINSTALL" -eq 1 ]; then
  if [ -f "$DEST" ]; then
    [ "$DRY_RUN" -eq 1 ] && { echo "[dry-run] would remove $DEST"; exit 0; }
    rm -f "$DEST"
    echo "removed $DEST"
  else
    echo "nothing to remove at $DEST"
  fi
  exit 0
fi

# Validate the extension ID (Chrome ids are 32 chars, a–p).
[ -n "$EXT_ID" ] || die "missing required --ext-id <EXTENSION_ID> (see chrome://extensions)"
if ! printf '%s' "$EXT_ID" | grep -Eq '^[a-p]{32}$'; then
  echo "install-dev.sh: warning: '$EXT_ID' does not look like a 32-char Chrome extension id" >&2
fi

# Build the host binary unless skipped.
HOST_BIN="$REPO_ROOT/target/release/secretary-browser-host"
if [ "$SKIP_BUILD" -eq 0 ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] would run: cargo build --release -p secretary-browser-host"
  else
    ( cd "$REPO_ROOT" && cargo build --release -p secretary-browser-host )
  fi
fi
if [ "$DRY_RUN" -eq 0 ] && [ ! -x "$HOST_BIN" ]; then
  die "host binary not found at $HOST_BIN (drop --skip-build, or build it first)"
fi

# Render the manifest with the absolute path + bound extension id.
read -r -d '' MANIFEST <<JSON || true
{
  "name": "com.secretary.browser_host",
  "description": "Secretary native-messaging host (dev install)",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
JSON

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[dry-run] would write to: $DEST"
  echo "[dry-run] manifest contents:"
  printf '%s\n' "$MANIFEST"
  exit 0
fi

mkdir -p "$DEST_DIR"
printf '%s\n' "$MANIFEST" > "$DEST"

echo "installed native-messaging host manifest:"
echo "  $DEST"
echo "  -> path: $HOST_BIN"
echo "  -> allowed_origins: chrome-extension://$EXT_ID/"
echo
echo "Next:"
echo "  1. (optional) enroll a casual vault so the count is non-zero:"
echo "       SECRETARY_VAULT_PASSWORD=… target/release/secretary-browser-enroll \\"
echo "         --vault /path/to/casual-vault --config ~/.config/secretary/browser-host.json"
echo "       (then the host reads that config by default; see browser/README.md)"
echo "  2. In your browser: chrome://extensions → Developer mode → Load unpacked → browser/extension/"
echo "  3. Visit https://example.com/ and open the extension's service-worker console;"
echo "     you should see: [secretary] available reply: { …, count: N }"
