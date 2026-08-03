#!/usr/bin/env bash
# This file writes literal Kotlin `$e` / `${e}` source into single-quoted bash
# strings throughout (the ERE constants and the self-test's write_case
# fixtures) — that `$` is Kotlin template syntax being matched / emulated,
# never intended for shell expansion, so shellcheck's SC2016 ("use double
# quotes for expansion") does not apply here; disabled file-wide rather than
# repeated at every one of the dozen call sites below.
# shellcheck disable=SC2016
#
# check-log-hygiene.sh — keep secrets out of Android logcat (#472).
#
# WHY THIS EXISTS
# ---------------
# Android's `android.util.Log` has no redaction layer at all — anything handed
# to it is plaintext in logcat, and logcat routinely ends up in bug-report
# dumps and crash aggregators. #467 gave iOS a structural gate
# (`SecretFreeError` / `diagnosticDetail`) plus this repo's first hygiene
# tripwire (`ios/scripts/check-public-log-hygiene.sh`). Android's equivalent
# structural gate (`SecretFreeThrowable`, a `SecretaryLog` façade at
# `SANCTIONED_LOG_FILE`) is built in later tasks of this same plan; this
# script is the enforcement half — the tripwire that keeps every future log
# site honest once the façade exists, and that proves, by failing red today,
# that the cleanup it demands is real rather than assumed.
#
# FOUR RULES
# ----------
#   RULE A (sink): any reference to `android.util.Log` — the import (which
#     also catches `import android.util.Log as L`) or a fully-qualified call —
#     outside the one sanctioned file is a hit. Logging AT ALL outside the
#     façade is the violation; there is nothing to allowlist here, so rule A
#     does not consult the allowlist file at all.
#
#   RULE B1 (throwable-shaped launder): `.message`, `.localizedMessage`,
#     `.stackTraceToString(` and `.printStackTrace(` all render a `Throwable`
#     (or something throwable-shaped) into text that may carry a carried
#     diagnostic. Name-blind and precise — it matches the CONSTRUCT, not an
#     identifier named like an error, so a `catch (problem: Exception)`
#     binding is caught exactly the same as a `catch (e: Exception)` one.
#
#   RULE B2 (explicit render): `.toString()`. Name-blind by design: the
#     iOS review found that a name-based version of this rule (matching only
#     `error.toString()` / `e.toString()`) was defeated simply by naming the
#     catch binding something else, so this one matches the construct with no
#     receiver filter at all. That is over-inclusive on purpose — plenty of
#     `.toString()` calls in this tree are not throwable-shaped at all — and
#     every legitimate one is a recorded allowlist entry rather than a
#     silent exclusion.
#
#   RULE C (bare interpolation, BEST EFFORT — see LIMITS): `"$e"` / `"${e}"`
#     for a fixed list of conventional catch-binding names. Like iOS rule 3,
#     this CANNOT be construct-based — `$x` / `${x}` is ordinary Kotlin string
#     templating, so matching it wholesale is unusable. It is a denylist by
#     necessity and is labelled as one. It deliberately does NOT match a named
#     typed-field render such as `${e.detail}` or `${error::class.simpleName}`
#     — those are reviewable, user-facing copy choices, and matching them
#     would produce a pile of allowlist entries that assert nothing and drown
#     the rule. See the `N3`/`N4` self-test controls for the exact boundary.
#
# There is no `is_app_ui_path`-style path exclusion (contrast iOS rule 2/3):
# the spec chose to allowlist individual Compose sites instead of excluding a
# whole app-UI directory, since Android's Compose screens and the FFI/port
# layer are not as cleanly separated as iOS's SwiftUI app targets.
#
# USAGE
# -----
#   bash android/scripts/check-log-hygiene.sh              # guard android/**/*.kt
#   bash android/scripts/check-log-hygiene.sh --self-test   # prove the matchers work
#
# LIMITS (stated, not hidden)
# ---------------------------
# The matchers are LINE-BASED. A `.message` access or `Log.w(...)` call split
# across two source lines evades detection; every current site is single-line
# but nothing enforces that. Rule C is BEST EFFORT and must not be read as
# coverage of its class — `catch (problem: Exception) { "boom: $problem" }`
# is invisible to it, exactly like iOS rule 3's `catch let problem` gap.
#
# Scope is `android/` only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/lib/hygiene-allowlist.sh
source "$SCRIPT_DIR/../../scripts/lib/hygiene-allowlist.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly REPO_ROOT
readonly SCAN_ROOT="$REPO_ROOT/android"
# NOT readonly: `--self-test` retargets it at a synthetic allowlist so the
# exact-line matching is itself covered by a control pair (X1/X2 below).
ALLOWLIST="$REPO_ROOT/android/scripts/log-hygiene-allowlist.txt"

# The one file permitted to reach logcat. This is the MECHANISM, not an
# exception, so it is a constant rather than an allowlist entry. It does not
# exist yet (a later task in this plan creates it) — until then rule A simply
# never has anything to exempt.
readonly SANCTIONED_LOG_FILE="android/kit/src/main/kotlin/org/secretary/diagnostics/SecretaryLog.kt"

# RULE A: any reference to android.util.Log — the import (which also catches
# `import android.util.Log as L`) or a fully-qualified call.
readonly LOG_RE='android\.util\.Log|(^|[^A-Za-z0-9_.])Log\.[a-z]+\('

# RULE B1: throwable-shaped constructs. Name-blind and precise.
readonly LAUNDER_RE='\.message\b|\.localizedMessage\b|\.stackTraceToString\(|\.printStackTrace\('

# RULE B2: the explicit render. Name-blind by design; the name-based form was
# the demonstrated bypass on iOS.
readonly TOSTRING_RE='\.toString\(\)'

# RULE C: BARE interpolation only. `${e.detail}` is a named typed field — a
# reviewable choice — and is deliberately NOT matched; matching it would fire
# on seven legitimate user-facing copy sites and drown the rule. iOS rule 3
# draws the same line by requiring the closing paren immediately.
readonly INTERP_RE='\$\{(e|err|error|caught|failure|ex|t)\}|\$(e|err|error|caught|failure|ex|t)([^A-Za-z0-9_.]|$)'

# Test sources legitimately construct/assert on Throwable text; they never
# write to logcat.
is_test_path() { [[ "$1" == *"/src/test/"* || "$1" == *"/src/androidTest/"* ]]; }

# Gradle build output — generated Kotlin (e.g. BuildConfig, resource
# accessors) and compiled/intermediate artifacts. Neither is hand-written.
is_generated_path() {
  [[ "$1" == *"/build/generated/"* || "$1" == *"/build/"* ]]
}

# A `//` or KDoc `*` / `/**` line is prose, not a log call. Without this, the
# doc comments that EXPLAIN this rule (or mention `android.util.Log` by name,
# as several do in this tree) would trip it.
is_comment_line() { [[ "$1" =~ ^[[:space:]]*(//|\*|/\*) ]]; }

# `trim()` and `allowlisted()` live in scripts/lib/hygiene-allowlist.sh,
# sourced above — shared with the iOS guard so the exact-line matcher has
# exactly one copy. See that file's header for the $ALLOWLIST/$REPO_ROOT
# contract `allowlisted()` depends on. `count_matches()` is NOT ported: it
# exists for iOS rule 1's per-interpolation counting, and no rule here counts.

# RULE A. Any android.util.Log reference outside the sanctioned file is a
# hit. Does NOT consult the allowlist — logging at all outside the façade is
# the violation, not a renderable value that could be reviewed as safe.
scan_sink() {
  local root="$1" hit path text
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    path="${hit%%:*}"; text="${hit#*:}"; text="${text#*:}"
    is_test_path "$path" && continue
    is_generated_path "$path" && continue
    is_comment_line "$text" && continue
    [[ "${path#"$REPO_ROOT"/}" == "$SANCTIONED_LOG_FILE" ]] && continue
    echo "$hit"
  done < <(grep -rn --include='*.kt' -E "$LOG_RE" "$root" 2>/dev/null || true)
}

# RULES B1, B2 and C — same scope and same filters, different matcher and
# different allowlist rule id. Args: <root> <rule-id> <ERE>. Prints offending
# hits not covered by a reviewed allowlist entry.
scan_launder() {
  local root="$1" rule="$2" re="$3" hit path text
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    path="${hit%%:*}"; text="${hit#*:}"; text="${text#*:}"
    is_test_path "$path" && continue
    is_generated_path "$path" && continue
    is_comment_line "$text" && continue
    allowlisted "$rule" "$hit" && continue
    echo "$hit"
  done < <(grep -rn --include='*.kt' -E "$re" "$root" 2>/dev/null || true)
}

# `SELF_TEST_TMP` and `cleanup_self_test` live in
# scripts/lib/hygiene-allowlist.sh, sourced above (same script-scoped-not-local
# rationale as documented there).

# Every control here is either a demonstrated iOS bypass ported to its Kotlin
# equivalent or a boundary the brief for this rule set explicitly calls out
# (the bare-vs-typed-field line for rule C, the whole-identifier anchor). A
# check never observed failing is indistinguishable from a no-op.
self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap cleanup_self_test EXIT
  local d="$SELF_TEST_TMP" fails=0

  write_case() { printf '%s\n' "$2" > "$d/$1.kt"; }

  # --- RULE A positives (must all be caught) ---
  write_case A1 'import android.util.Log'
  write_case A2 'import android.util.Log as L'
  write_case A3 '        android.util.Log.w(TAG, "x", e)'
  write_case A4 '        Log.w(TAG, "x", e)'
  write_case A5 '        Log.i(TAG, msg)'
  # --- RULE B1 positives (must all be caught) ---
  write_case B1a 'throw CloudFolderException("op failed: ${e.message}")'
  write_case B1b 'val s = problem.localizedMessage'
  write_case B1c 'val s = e.stackTraceToString()'
  write_case B1d 'e.printStackTrace()'
  # --- RULE B2 positives (must all be caught) ---
  # B2b is the name-based bypass that motivated making rule B2 name-blind.
  write_case B2a 'else -> VaultBrowseError.Failed(e.toString())'
  write_case B2b 'else -> VaultBrowseError.Failed(problem.toString())'
  # --- RULE C positives (bare only, must all be caught) ---
  write_case C1 'return Failed("boom: $e")'
  write_case C2 'return Failed("boom: ${e}")'
  # --- negatives (must all stay silent) ---
  write_case N1 'else -> VaultBrowseError.Failed(diagnosticDetail(e))'
  write_case N2 'SecretaryLog.warn(TAG, "unlock failed", e)'
  write_case N3 'val s = "Couldn'"'"'t authorize the change: ${error.detail}"'   # typed field, not bare
  write_case N4 'val s = "failed: ${error::class.simpleName}"'                    # typed field
  write_case N5 'label = "$errorCount failures"'                                  # whole-identifier anchor
  write_case N6 'val n = counter.toInt()'                                         # not toString

  # --- allowlist control: exact-line matching, NOT substring ---
  # ONE file, TWO lines. Line 1 is the allowlist entry verbatim; line 2 is a
  # DIFFERENT line in the SAME file sharing line 1's distinctive substring
  # (`cloudLabel`). They must be one file: with two files the paths differ and
  # the control is vacuous regardless of matching semantics — a prior version
  # of the iOS self-test had exactly that bug and passed happily with
  # substring matching restored.
  #
  # Line 2 must trip rule B2 and ONLY rule B2 — a `.toString()` render whose
  # receiver is named so rules B1/C stay silent. If it also tripped another
  # rule it would be caught no matter what the allowlist did.
  local x_keep='Text(cloudLabel.toString())'
  local x_catch='Text(other.cloudLabel.toString())'
  printf '%s\n%s\n' "$x_keep" "$x_catch" > "$d/X.kt"

  # TWO entries. The first is the real, exact-line exemption for line 1. The
  # second is a deliberately SHORT needle of the kind the pre-fix iOS
  # allowlist used — it must be INERT. Under exact-line matching a short
  # needle can never equal a full source line, so it exempts nothing; under
  # substring matching it would exempt every rule-B2 line in the file that
  # mentions it, line 2 included. That is what makes this pair detect the
  # regression rather than merely describe it.
  ALLOWLIST="$d/allowlist.txt"
  {
    printf '%s\t%s\t%s\t%s\n' "$d/X.kt" B2 "$x_keep" 'self-test fixture: legitimate exact-line exemption'
    printf '%s\t%s\t%s\t%s\n' "$d/X.kt" B2 'cloudLabel' 'self-test fixture: short needle, MUST be inert'
  } > "$ALLOWLIST"

  local hits
  hits="$(scan_sink "$d"; scan_launder "$d" B1 "$LAUNDER_RE"; scan_launder "$d" B2 "$TOSTRING_RE"; scan_launder "$d" C "$INTERP_RE")"

  local p
  for p in A1 A2 A3 A4 A5 B1a B1b B1c B1d B2a B2b C1 C2; do
    grep -q "/$p\.kt:" <<<"$hits" || { echo "SELF-TEST FAILED: no hit on positive control $p" >&2; fails=1; }
  done
  local n
  for n in N1 N2 N3 N4 N5 N6; do
    grep -q "/$n\.kt:" <<<"$hits" && { echo "SELF-TEST FAILED: fired on negative control $n" >&2; fails=1; }
  done
  # The allowlist pair, asserted BY LINE NUMBER — this is what fails if
  # exact-line matching ever regresses to substring.
  grep -q "/X\.kt:1:" <<<"$hits" &&
    { echo "SELF-TEST FAILED: allowlisted line X.kt:1 was reported" >&2; fails=1; }
  grep -q "/X\.kt:2:" <<<"$hits" ||
    { echo "SELF-TEST FAILED: X.kt:2 escaped via its file's allowlist entry (substring match?)" >&2; fails=1; }
  [[ $fails -eq 0 ]] || return 1
  echo "self-test OK — 13 positive controls caught, 6 negative controls clean"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

sink_hits="$(scan_sink "$SCAN_ROOT")"
b1_hits="$(scan_launder "$SCAN_ROOT" B1 "$LAUNDER_RE")"
b2_hits="$(scan_launder "$SCAN_ROOT" B2 "$TOSTRING_RE")"
c_hits="$(scan_launder "$SCAN_ROOT" C "$INTERP_RE")"
status=0

if [[ -n "$sink_hits" ]]; then
  echo "ERROR (#472 rule A): android.util.Log is referenced outside the sanctioned" >&2
  echo "façade ($SANCTIONED_LOG_FILE):" >&2
  echo "$sink_hits" >&2
  echo >&2
  echo "Fix: route through SecretaryLog instead of android.util.Log directly." >&2
  status=1
fi

if [[ -n "$b1_hits" ]]; then
  echo "ERROR (#472 rule B1): a throwable-shaped construct (.message, .localizedMessage," >&2
  echo ".stackTraceToString(), .printStackTrace()) renders a value that may carry a" >&2
  echo "carried diagnostic:" >&2
  echo "$b1_hits" >&2
  echo >&2
  echo "Fix: render via the sanctioned diagnostic path instead. If the use is" >&2
  echo "legitimate (on-screen copy, not a log), add a reviewed entry to" >&2
  echo "android/scripts/log-hygiene-allowlist.txt." >&2
  status=1
fi

if [[ -n "$b2_hits" ]]; then
  echo "ERROR (#472 rule B2): a value is hand-rendered via .toString() — this LAUNDERS" >&2
  echo "unreviewed content past the gate if the result is stored in a carried error:" >&2
  echo "$b2_hits" >&2
  echo >&2
  echo "Fix: use the sanctioned diagnostic path instead. If the use is legitimate" >&2
  echo "(not throwable-shaped, or on-screen copy rather than a log), add a reviewed" >&2
  echo "entry to android/scripts/log-hygiene-allowlist.txt." >&2
  status=1
fi

if [[ -n "$c_hits" ]]; then
  echo "ERROR (#472 rule C): a value bound under a conventional catch name is bare-" >&2
  echo "interpolated. Kotlin template interpolation of a Throwable calls its" >&2
  echo "toString(), so this launders exactly like rule B2:" >&2
  echo "$c_hits" >&2
  echo >&2
  echo "Fix: render via the sanctioned diagnostic path instead. If the string is" >&2
  echo "user-facing copy rather than a log, add a reviewed entry to" >&2
  echo "android/scripts/log-hygiene-allowlist.txt." >&2
  status=1
fi

[[ $status -eq 0 ]] && echo "OK — android.util.Log is confined to the façade and no value is hand-rendered"
exit $status
