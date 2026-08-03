#!/usr/bin/env bash
#
# check-public-log-hygiene.sh — keep secrets out of the unified log store (#467).
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
# THREE RULES
# -----------
# The first version of this script was a two-item DENYLIST ("a `.public` line must
# not contain `String(describing:` or `.localizedDescription`"). An adversarial
# review defeated it eight ways, including `privacy:.public` with no space — the
# same construct as the self-test's positive control, differing only in whitespace.
# A SECOND review then showed rule 2 was still a denylist wearing an allowlist's
# label: it matched one function name applied to five hard-coded identifier names,
# so `String(describing: caught)`, `error.localizedDescription`, `"\(error)"` and
# `String(reflecting: error)` all walked through. Both rules below now deny by
# default and are opened only by an exact-line entry in the allowlist file.
#
#   RULE 1 (public-render): on any line, the number of `privacy:<space?>.public`
#     interpolations must not exceed the number of `diagnosticDetail(` renders.
#     Counting rather than "does the line mention diagnosticDetail anywhere"
#     closes the two-interpolations-one-line bypass (one gated, one raw).
#
#   RULE 2 (no-launder): `String(describing:`, `String(reflecting:` and
#     `.localizedDescription` may not appear at all in the guarded scope.
#     `diagnosticDetail` denies unreviewed TYPES, not unreviewed CONTENT — so
#     pre-rendering ANY value into a String and stashing it in a CONFORMED error's
#     payload launders it straight through the gate. Naming the identifier was not
#     a workable filter (a `catch let caught` binding defeats it), so the rule is
#     construct-based and every legitimate use is a recorded allowlist entry.
#
#   RULE 3 (no-interpolate, BEST EFFORT — see LIMITS): `"\(error)"` launders
#     exactly like RULE 2, because Swift string interpolation of a non-
#     `CustomStringConvertible` value IS `String(describing:)`. Unlike rules 1
#     and 2 this one CANNOT be construct-based: `\(x)` is the most common
#     construct in Swift, so matching it wholesale is unusable. It therefore
#     matches a fixed list of identifier names conventionally bound in a `catch`.
#     That is a denylist, and it is labelled as one rather than dressed up.
#
# A `privacy:` whose value is not a bare `.public` / `.private` / `.sensitive` /
# `.auto` literal also fails, so hiding `.public` behind a variable does not work.
#
# USAGE
# -----
#   bash ios/scripts/check-public-log-hygiene.sh              # guard ios/**/*.swift
#   bash ios/scripts/check-public-log-hygiene.sh --self-test  # prove the matchers work
#
# LIMITS (stated, not hidden)
# ---------------------------
# The matchers are LINE-BASED, so a `privacy:` interpolation split across two
# source lines evades RULE 1. Every current site is single-line, but nothing
# ENFORCES that — this repo has no swift-format config and no formatter in CI, so
# do not read the single-line status quo as a guarantee. Parsing Swift to close
# the gap is out of proportion; the `--self-test` controls document exactly what
# does and does not trip each rule.
#
# RULE 3 is BEST EFFORT and must not be read as coverage of its class. `catch let
# problem { … "\(problem)" }` is invisible to it, and no line-based matcher can
# fix that without either parsing Swift or firing on every interpolation in the
# tree. It raises the cost of the accident — `"\(error)"` is what a developer
# reaches for by reflex — without closing the class. RULES 1 and 2 are the
# load-bearing ones: rule 1 because every log line must pass it whatever the
# value is named, rule 2 because it is construct-based and therefore name-blind.
#
# RULE 2 does not scan the SwiftUI app targets (see `is_app_ui_path`). Their
# `.localizedDescription` renders are the CORRECT #454 pattern (friendly
# `LocalizedError` copy into `Text(…)`), and allowlisting all eighteen would bury
# the five that are genuine #454 violations under thirteen that are not. STATED
# LIMIT: laundering that happens IN an app target and is later logged elsewhere is
# not caught. Closing it needs those five sites cleaned up first — a separate issue.
#
# Scope is `ios/` only. Android logs raw `Throwable`s to logcat with no equivalent
# gate — a separate, real exposure, not covered here.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT
readonly SCAN_ROOT="$REPO_ROOT/ios"
# NOT readonly: `--self-test` retargets it at a synthetic allowlist so the
# exact-line matching is itself covered by a control pair (A1/A2 below).
ALLOWLIST="$REPO_ROOT/ios/scripts/public-log-hygiene-allowlist.txt"

# Tolerant of whitespace: `privacy:.public`, `privacy:  .public`, etc.
readonly PUBLIC_RE='privacy:[[:space:]]*\.public'
# Any `privacy:` whose value is not one of the four bare literals.
readonly PRIVACY_ANY_RE='privacy:[[:space:]]*'
readonly PRIVACY_LITERAL_RE='privacy:[[:space:]]*\.(public|private|sensitive|auto)\b'
# The one sanctioned renderer.
readonly SANCTIONED_RE='diagnosticDetail\('
# RULE 2: hand-rendering ANY value into a String. Deliberately NOT scoped to
# identifiers named like errors — that filter was the bypass.
readonly LAUNDER_RE='String\(describing:|String\(reflecting:|\.localizedDescription'
# RULE 3: bare interpolation of a value bound under one of the conventional
# `catch` names. Name-based BY NECESSITY — see the LIMITS block.
readonly INTERP_RE='\\\((error|e|err|nsError|underlying|caught|failure)\)'

# Test sources legitimately construct sentinel errors and assert on their
# descriptions; they never write to the unified log.
is_test_path() { [[ "$1" == *"/Tests/"* ]]; }

# Generated + build-artifact Swift. `secretary.swift` is uniffi-bindgen output
# (regenerated by build-xcframework.sh, gitignored); `.build*` is SwiftPM/Xcode
# scratch. Neither is hand-written, so neither is reviewable or fixable here.
is_generated_path() {
  [[ "$1" == *"/secretary.swift" || "$1" == *"/.build"*"/"* || "$1" == *"/.build-staging/"* ]]
}

# A `//`-comment line is prose, not a log call. Without this, the doc comments
# that EXPLAIN this rule trip it.
is_comment_line() { [[ "$1" =~ ^[[:space:]]*(///?|\*) ]]; }

# RULES 2 AND 3 ONLY — see the LIMITS block above for why the app targets are out
# of scope and what that leaves open. RULE 1 still covers these files in full, so
# an actual `.public` log line here is gated.
is_app_ui_path() {
  [[ "$1" == *"/SecretaryApp/Sources/"* || "$1" == *"/SecretaryMacApp/Sources/"* ]]
}

# Strip leading/trailing whitespace so an allowlist entry survives re-indentation
# but not a content edit.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# Count non-overlapping matches of ERE $1 in text $2. `|| true` keeps `pipefail`
# from turning "zero matches" into a script abort.
count_matches() {
  local n
  n="$( { grep -oE "$1" <<<"$2" || true; } | wc -l)"
  printf '%s' "${n//[[:space:]]/}"
}

# Does rule $1's hit $2 (`<file>:<line>:<text>`) have an allowlist entry?
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

# RULE 1 + the privacy-literal check. Prints offending hits.
scan_public() {
  local root="$1" hit text n_public n_gated
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    is_test_path "${hit%%:*}" && continue
    is_generated_path "${hit%%:*}" && continue
    text="${hit#*:}"; text="${text#*:}"
    is_comment_line "$text" && continue
    # A non-literal `privacy:` value is a fail regardless of RULE 1.
    if ! grep -Eq "$PRIVACY_LITERAL_RE" <<<"$text"; then
      echo "$hit"; continue
    fi
    n_public="$(count_matches "$PUBLIC_RE" "$text")"
    (( n_public == 0 )) && continue
    # Per-INTERPOLATION, not per-line: a line carrying one gated and one raw
    # `.public` render must fail even though `diagnosticDetail(` is present.
    n_gated="$(count_matches "$SANCTIONED_RE" "$text")"
    (( n_gated >= n_public )) && continue
    allowlisted 1 "$hit" && continue
    echo "$hit"
  done < <(grep -rn --include='*.swift' -E "$PRIVACY_ANY_RE" "$root" 2>/dev/null || true)
}

# RULES 2 and 3 — same scope and same filters, different matcher and different
# allowlist rule id. Args: <root> <rule-id> <ERE>. Prints offending hits.
scan_launder() {
  local root="$1" rule="$2" re="$3" hit path text
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    path="${hit%%:*}"; text="${hit#*:}"; text="${text#*:}"
    is_test_path "$path" && continue
    is_generated_path "$path" && continue
    is_comment_line "$text" && continue
    is_app_ui_path "$path" && continue
    allowlisted "$rule" "$hit" && continue
    echo "$hit"
  done < <(grep -rn --include='*.swift' -E "$re" "$root" 2>/dev/null || true)
}

# `SELF_TEST_TMP` is deliberately script-scoped, NOT `local`: the `EXIT` trap runs
# after the function's frame is gone, so a `local` would be unset by then and
# `set -u` would turn the cleanup itself into a non-zero exit — which looked
# exactly like a self-test failure while the matchers were in fact fine.
SELF_TEST_TMP=""
# shellcheck disable=SC2329  # invoked indirectly, via `trap cleanup_self_test EXIT`
cleanup_self_test() { [[ -n "$SELF_TEST_TMP" ]] && rm -rf "$SELF_TEST_TMP"; }

# Every control BOTH adversarial reviews used to defeat an earlier version, so a
# regression to default-allow cannot pass. A check never observed failing is
# indistinguishable from a no-op; a check that fires on everything is worse.
self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap cleanup_self_test EXIT
  local d="$SELF_TEST_TMP" fails=0

  write_case() { printf '%s\n' "$2" > "$d/$1.swift"; }

  # --- RULE 1 positives (must all be caught) ---
  write_case P1  'log.error("x: \(String(describing: error), privacy: .public)")'
  write_case P2  'log.error("x: \(String(describing: error), privacy:.public)")'
  write_case P3  'log.error("x: \(String(describing:error), privacy:  .public)")'
  write_case P4  'log.error("x: \(String(reflecting: error), privacy: .public)")'
  write_case P5  'log.error("x: \(error as NSError, privacy: .public)")'
  write_case P6  'log.error("x: \((error as? LocalizedError)?.errorDescription ?? "", privacy: .public)")'
  write_case P7  'log.error("x: \((error as NSError).localizedFailureReason ?? "", privacy: .public)")'
  write_case P8  'log.error("x: \(describe(error), privacy: .public)")'
  write_case P9  'log.error("x: \(err.localizedDescription, privacy: .public)")'
  write_case P10 'log.error("x: \(thing, privacy: p)")'
  # Two interpolations, one gated and one raw. Defeated the "mentions
  # diagnosticDetail anywhere on the line" form of RULE 1.
  write_case P11 'log.error("a: \(diagnosticDetail(error), privacy: .public) b: \(raw, privacy: .public)")'
  # --- RULE 2 positives (must all be caught) ---
  write_case P12 'return .other(String(describing: e))'
  # The four that defeated the identifier-named form of RULE 2.
  write_case P13 'return .other(String(describing: caught))'
  write_case P14 'return .other(error.localizedDescription)'
  write_case P15 'return .other(String(reflecting: error))'
  write_case P16 'errorText = someValue.localizedDescription'
  # --- RULE 3 positives (must all be caught) ---
  # Bare interpolation IS String(describing:) — the fifth bypass of the
  # identifier-named RULE 2, and the one construct RULE 2 cannot see.
  write_case P17 'return .other("boom: \(error)")'
  write_case P18 'return .other("boom: \(caught)")'
  # --- negatives (must all pass) ---
  write_case N1  'log.error("x: \(diagnosticDetail(error), privacy: .public)")'
  write_case N2  'log.error("x: \(diagnosticDetail(error), privacy:.public)")'
  write_case N3  'log.debug("x: \(thing, privacy: .private)")'
  write_case N4  'let s = diagnosticDetail(error)'
  # Both `.public` renders gated — the counting rule must not over-fire.
  write_case N5  'log.error("a: \(diagnosticDetail(a), privacy: .public) b: \(diagnosticDetail(b), privacy: .public)")'
  # RULE 3 must anchor on the WHOLE identifier: `\(errorCount)` is not `\(error)`.
  write_case N6  'label = "\(errorCount) failures, \(errors) total"'
  # --- allowlist control: exact-line matching, NOT substring ---
  # ONE file, TWO lines. Line 1 is the allowlist entry verbatim; line 2 is a
  # DIFFERENT line in the SAME file sharing the entry's distinctive substring
  # (`location.displayName`). They must be one file: with two files the paths
  # differ and the entry never applies to the second either way, which makes the
  # control vacuous — an earlier version of this self-test had exactly that bug
  # and passed happily with substring matching restored.
  #
  # Line 2 must trip RULE 1 and ONLY rule 1 — an ungated `.public` render whose
  # value is named so rules 2 and 3 stay silent. If it also tripped rule 2 it
  # would be caught no matter what the allowlist did.
  local a_keep='Self.log.notice("Refreshed for \(location.displayName, privacy: .public)")'
  local a_catch='Self.log.error("failed for \(location.displayName): \(reason, privacy: .public)")'
  printf '%s\n%s\n' "$a_keep" "$a_catch" > "$d/A.swift"

  # TWO entries. The first is the real, exact-line exemption for line 1. The
  # second is a deliberately SHORT needle of the kind the pre-fix allowlist used
  # — it must be INERT. Under exact-line matching a short needle can never equal
  # a full source line, so it exempts nothing; under the old substring matching
  # it exempted every `.public` line in the file that mentioned it, line 2
  # included. That is what makes this pair detect the regression rather than
  # merely describe it.
  ALLOWLIST="$d/allowlist.txt"
  {
    printf '%s\t%s\t%s\t%s\n' "$d/A.swift" 1 "$a_keep" 'self-test fixture: legitimate exact-line exemption'
    printf '%s\t%s\t%s\t%s\n' "$d/A.swift" 1 'location.displayName' 'self-test fixture: short needle, MUST be inert'
  } > "$ALLOWLIST"

  local hits
  hits="$(scan_public "$d"; scan_launder "$d" 2 "$LAUNDER_RE"; scan_launder "$d" 3 "$INTERP_RE")"

  local p
  for p in P1 P2 P3 P4 P5 P6 P7 P8 P9 P10 P11 P12 P13 P14 P15 P16 P17 P18; do
    grep -q "/$p\.swift:" <<<"$hits" || { echo "SELF-TEST FAILED: no hit on positive control $p" >&2; fails=1; }
  done
  local n
  for n in N1 N2 N3 N4 N5 N6; do
    grep -q "/$n\.swift:" <<<"$hits" && { echo "SELF-TEST FAILED: fired on negative control $n" >&2; fails=1; }
  done
  # The allowlist pair, asserted BY LINE NUMBER — this is what fails if exact-line
  # matching ever regresses to substring.
  grep -q "/A\.swift:1:" <<<"$hits" &&
    { echo "SELF-TEST FAILED: allowlisted line A.swift:1 was reported" >&2; fails=1; }
  grep -q "/A\.swift:2:" <<<"$hits" ||
    { echo "SELF-TEST FAILED: A.swift:2 escaped via its file's allowlist entry (substring match?)" >&2; fails=1; }
  [[ $fails -eq 0 ]] || return 1
  echo "self-test OK — 19 positive controls caught, 7 negative controls clean"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

public_hits="$(scan_public "$SCAN_ROOT")"
launder_hits="$(scan_launder "$SCAN_ROOT" 2 "$LAUNDER_RE")"
interp_hits="$(scan_launder "$SCAN_ROOT" 3 "$INTERP_RE")"
status=0

if [[ -n "$public_hits" ]]; then
  echo "ERROR (#467 rule 1): a 'privacy: .public' interpolation does not render via" >&2
  echo "diagnosticDetail, or the line uses a non-literal privacy value:" >&2
  echo "$public_hits" >&2
  echo >&2
  echo "Fix: render via diagnosticDetail(error). If the line is legitimately exempt," >&2
  echo "add a reviewed entry to ios/scripts/public-log-hygiene-allowlist.txt." >&2
  status=1
fi

if [[ -n "$launder_hits" ]]; then
  echo "ERROR (#467 rule 2): a value is hand-rendered into a String — this LAUNDERS" >&2
  echo "unreviewed content past the gate if the result is stored in a conformed error:" >&2
  echo "$launder_hits" >&2
  echo >&2
  echo "Fix: use diagnosticDetail(error) instead. It denies unreviewed types; a raw" >&2
  echo "String(describing:) / String(reflecting:) / .localizedDescription does not, and" >&2
  echo "a conformed error's default rendering will then print it in full at .public." >&2
  echo "If the use is legitimate, add a reviewed entry to" >&2
  echo "ios/scripts/public-log-hygiene-allowlist.txt." >&2
  status=1
fi

if [[ -n "$interp_hits" ]]; then
  echo "ERROR (#467 rule 3): a value bound under a conventional catch name is bare-" >&2
  echo "interpolated. Swift interpolation of a non-CustomStringConvertible value IS" >&2
  echo "String(describing:), so this launders exactly like rule 2:" >&2
  echo "$interp_hits" >&2
  echo >&2
  echo "Fix: use diagnosticDetail(error) instead. If the string is user-facing copy" >&2
  echo "rather than a log, add a reviewed entry to" >&2
  echo "ios/scripts/public-log-hygiene-allowlist.txt." >&2
  status=1
fi

[[ $status -eq 0 ]] && echo "OK — .public renders are gated and no value is hand-rendered into a String"
exit $status
