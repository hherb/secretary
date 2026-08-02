#!/usr/bin/env bash
#
# check-public-log-hygiene.sh — assert no `privacy: .public` log line renders an
# error by hand (#467).
#
# WHY THIS EXISTS
# ---------------
# `privacy: .public` disables the unified log's default redaction so a diagnostic
# survives into a sysdiagnose (#456). `SecretFreeError` + `diagnosticDetail` make
# the RENDERING fail-closed — an unreviewed error type is never described. But
# nothing in the type system forces a NEW log site to call `diagnosticDetail`
# instead of hand-rolling `String(describing:)` or `.localizedDescription`. This
# script is that tripwire; without it #467's acceptance criterion does not hold.
#
# THE ONE DELIBERATE EXCEPTION
# ----------------------------
# `BookmarkVaultLocationStore` logs `location.displayName` at `.public`. That is
# the vault FOLDER name from the system picker — not an error, and not a secret:
# anyone able to read the unified log can read the filesystem. It matches neither
# forbidden pattern, so it needs no allowlist entry; the reasoning is recorded at
# the call site.
#
# USAGE
# -----
#   bash ios/scripts/check-public-log-hygiene.sh              # guard ios/**/*.swift
#   bash ios/scripts/check-public-log-hygiene.sh --self-test  # prove the matcher works
#
# LIMITS (stated, not hidden)
# ---------------------------
# The matcher is LINE-BASED: a `.public` interpolation split across two source
# lines would evade it. Every current site is single-line and swift-format keeps
# them that way; parsing Swift to close that gap is far out of proportion. The
# `--self-test` controls document exactly what does and does not trip it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly SCAN_ROOT="$REPO_ROOT/ios"

# A line that emits at `privacy: .public` …
readonly PUBLIC_RE='privacy: \.public'
# … must not ALSO render an error by hand. `diagnosticDetail` is the only
# sanctioned renderer (see SecretFreeError.swift).
readonly FORBIDDEN_RE='String\(describing:|\.localizedDescription'

# Print every offending `<file>:<line>:<text>`; empty output means clean.
scan() {
  grep -rn --include='*.swift' -E "$PUBLIC_RE" "$1" 2>/dev/null \
    | grep -E "$FORBIDDEN_RE" || true
}

# Two-sided control: the matcher must fire on a known-positive AND stay silent on
# a known-negative. A check never observed failing is indistinguishable from a
# no-op; a check that fires on everything is worse than none.
#
# `SELF_TEST_TMP` is deliberately script-scoped, NOT `local`: the `EXIT` trap runs
# after the function's frame is gone, so a `local` would be unset by then and
# `set -u` would turn the cleanup itself into a non-zero exit — which looked
# exactly like a self-test failure while the matcher was in fact fine.
SELF_TEST_TMP=""
cleanup_self_test() { [[ -n "$SELF_TEST_TMP" ]] && rm -rf "$SELF_TEST_TMP"; }

self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap cleanup_self_test EXIT

  printf '%s\n' 'log.error("boom: \(String(describing: error), privacy: .public)")' \
    > "$SELF_TEST_TMP/Positive.swift"
  printf '%s\n' 'log.error("boom: \(diagnosticDetail(error), privacy: .public)")' \
    > "$SELF_TEST_TMP/Negative.swift"

  local hits
  hits="$(scan "$SELF_TEST_TMP")"

  if ! grep -q 'Positive\.swift' <<<"$hits"; then
    echo "SELF-TEST FAILED: matcher did NOT fire on the known-positive control" >&2
    return 1
  fi
  if grep -q 'Negative\.swift' <<<"$hits"; then
    echo "SELF-TEST FAILED: matcher fired on the known-negative control" >&2
    return 1
  fi
  echo "self-test OK — matcher fires on the positive control, not on the negative"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

hits="$(scan "$SCAN_ROOT")"
if [[ -n "$hits" ]]; then
  echo "ERROR: an Error is rendered into a 'privacy: .public' log line without diagnosticDetail (#467):" >&2
  echo "$hits" >&2
  echo >&2
  echo "Fix: render via diagnosticDetail(error). If the type should keep its detail," >&2
  echo "conform it to SecretFreeError (redacting at source if any case can carry a secret)." >&2
  exit 1
fi
echo "OK — no hand-rolled error rendering at a 'privacy: .public' site"
