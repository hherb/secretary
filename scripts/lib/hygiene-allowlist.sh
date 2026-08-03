#!/usr/bin/env bash
# hygiene-allowlist.sh — shared exact-line allowlist matcher for the
# `privacy: .public` log-hygiene guards (#467 iOS, #472 Android).
#
# WHAT THIS IS
# ------------
# `allowlisted()` is the exact-trimmed-line matcher that decides whether a
# would-be violation is a reviewed, recorded exception rather than a bypass.
# Its substring predecessor was demonstrably exploitable: an allowlist entry
# chosen to exempt ONE line silently exempted every FUTURE line in the same
# file that happened to contain the same needle (fixed only in #467's third
# review round). Two copies of this function could drift — a fix applied to
# one would silently not apply to the other — so it lives here ONCE and every
# platform's guard sources this file rather than reimplementing it.
#
# WHO SOURCES THIS
# ----------------
# ios/scripts/check-public-log-hygiene.sh (#467) and, from #472 onward,
# android's equivalent guard. Source it via the `SCRIPT_DIR` idiom already used
# at ios/scripts/run-ios-tests.sh:35, e.g. from a script at `<platform>/scripts/`:
#
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=../../scripts/lib/hygiene-allowlist.sh
#   source "$SCRIPT_DIR/../../scripts/lib/hygiene-allowlist.sh"
#
# THE $ALLOWLIST / $REPO_ROOT CONTRACT
# -------------------------------------
# `allowlisted()` does NOT take the allowlist path or repo root as arguments —
# it reads `$ALLOWLIST` and `$REPO_ROOT` from the SOURCING SCRIPT's scope. Both
# must be set (non-empty) before `allowlisted` is called:
#   - `$REPO_ROOT` relativizes the hit's path so allowlist entries are portable.
#   - `$ALLOWLIST` is the tab-separated `<path>\t<rule>\t<exact line>\t<reason>`
#     file to match against.
# `$ALLOWLIST` must NOT be declared `readonly` in the sourcing script: a
# `--self-test` mode legitimately retargets it at a synthetic allowlist so the
# exact-line matching is itself covered by a positive/negative control pair
# (see the `A.swift` fixture in ios/scripts/check-public-log-hygiene.sh's
# `self_test`), and `readonly` would turn that deliberate test seam into a
# hard failure instead.
#
# This file has no `set -euo pipefail` of its own — it inherits the sourcing
# script's shell options, matching the existing lib/resolve-simulator.sh
# pattern.
#
# CHANGING `allowlisted()` CHANGES A SECURITY CONTROL ON EVERY PLATFORM THAT
# SOURCES THIS FILE, ALL AT ONCE. Review accordingly.

# Strip leading/trailing whitespace so an allowlist entry survives re-indentation
# but not a content edit.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# Does rule $1's hit $2 (`<file>:<line>:<text>`) have an allowlist entry?
#
# CONTRACT: reads `$ALLOWLIST` and `$REPO_ROOT` from the sourcing script's
# scope — see the file header above. Neither is passed as an argument.
#
# The entry must match the file AND the EXACT trimmed source line. An earlier
# version matched any substring, which meant the entry chosen for
# BookmarkVaultLocationStore (`location.displayName`) exempted any FUTURE
# `.public` line in that file that happened to mention the same identifier —
# demonstrably including one rendering `err.localizedDescription` raw. Exact-line
# matching costs a re-review whenever an exempted line is edited, which is the
# correct price for a line that bypasses the only mechanism keeping secrets out
# of the log store.
allowlisted() {
  local rule="$1" hit="$2" path text a_path a_rule a_line _reason
  path="${hit%%:*}"
  path="${path#"$REPO_ROOT"/}"
  text="${hit#*:}"; text="${text#*:}"
  text="$(trim "$text")"
  [[ -f "$ALLOWLIST" ]] || return 1
  while IFS=$'\t' read -r a_path a_rule a_line _reason; do
    [[ -z "${a_path// }" || "$a_path" == \#* ]] && continue
    [[ "$a_rule" == "$rule" && "$path" == "$a_path" && "$text" == "$a_line" ]] && return 0
  done < "$ALLOWLIST"
  return 1
}

# `SELF_TEST_TMP` is deliberately script-scoped, NOT `local`: the `EXIT` trap runs
# after the function's frame is gone, so a `local` would be unset by then and
# `set -u` would turn the cleanup itself into a non-zero exit — which looked
# exactly like a self-test failure while the matchers were in fact fine.
SELF_TEST_TMP=""
# shellcheck disable=SC2329  # invoked indirectly, via `trap cleanup_self_test EXIT`
cleanup_self_test() { [[ -n "$SELF_TEST_TMP" ]] && rm -rf "$SELF_TEST_TMP"; }
