#!/usr/bin/env bash
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
# structural gate is `SecretFreeThrowable` (the default-deny rendering policy
# in `:vault-access`) plus the `SecretaryLog` façade at `SANCTIONED_LOG_FILE`,
# whose signatures make the unsafe `Log.w(tag, msg, throwable)` form
# unrepresentable at call sites. This script is the enforcement half — the
# tripwire that keeps every future log site honest now that the façade exists.
#
# FIVE RULES
# ----------
#   RULE A (sink): any reference to a logcat sink outside the one sanctioned
#     file is a hit — `android.util.Log` via the import (which also catches
#     `import android.util.Log as L`), a fully-qualified call, or a bare
#     `Log.<member>(` where `<member>` may be camelCase (e.g.
#     `Log.getStackTraceString(`, a real Android API that renders a Throwable
#     to text — an all-lowercase-only member pattern missed it) — AND the
#     stdlib sinks `println(` / `System.out.` / `System.err.`, because the
#     Android runtime redirects stdout and stderr into logcat under the
#     `System.out` / `System.err` tags. `println(e)` is therefore a raw
#     Throwable in logcat that names no `Log` symbol at all, and it evaded
#     every other rule (#475 review). Logging AT ALL outside the façade is the
#     violation; there is nothing to allowlist here, so rule A does not
#     consult the allowlist file at all.
#
#   RULE B1 (throwable-shaped launder): `.message`, `.localizedMessage`,
#     `stackTraceToString(` and `printStackTrace(` (word-boundary anchored,
#     not dot-anchored, so a no-receiver call under implicit `this` — e.g.
#     inside a `Throwable.toString()` override — is caught exactly like the
#     dotted form) all render a `Throwable` (or something throwable-shaped)
#     into text that may carry a carried diagnostic. Name-blind and precise —
#     it matches the CONSTRUCT, not an identifier named like an error, so a
#     `catch (problem: Exception)` binding is caught exactly the same as a
#     `catch (e: Exception)` one.
#
#   RULE B2 (explicit render, dotted): `.toString()`. Name-blind by design:
#     the iOS review found that a name-based version of this rule (matching
#     only `error.toString()` / `e.toString()`) was defeated simply by naming
#     the catch binding something else, so this one matches the construct with
#     no receiver filter at all. That is over-inclusive on purpose — plenty of
#     `.toString()` calls in this tree are not throwable-shaped at all — and
#     every legitimate one is a recorded allowlist entry rather than a
#     silent exclusion.
#
#   RULE B3 (explicit render, no receiver): a bare `toString()` under implicit
#     `this`. Rule B2 is `\.`-anchored, so it never saw this form — the exact
#     asymmetry rule B1 was fixed for in round 1, left unfixed for B2 (#475
#     review). It matters because the receiver under implicit `this` is a
#     `Throwable` precisely when the laundering code sits inside one, e.g. a
#     `diagnosticDescription` override reaching for its own `toString()`.
#     B3 cannot simply be folded into B2 by relaxing the anchor: `\btoString\(\)`
#     also matches every `override fun toString()` DECLARATION. So B3 skips
#     lines that declare the function — and the dotted rule B2 stays
#     unconditional, which is what keeps the one line that is both
#     (`override fun toString() = e.toString()`) caught. See the `B3a`-`B3c`
#     positives and `N12` negative.
#
#   RULE C (bare interpolation + concatenation, BEST EFFORT — see LIMITS):
#     `"$e"` / `"${e}"` for a fixed list of conventional catch-binding names,
#     PLUS `"..." + e` string concatenation of the same names. In Kotlin
#     `"str" + throwable` also calls `toString()` — `SecretaryLog.warn(TAG,
#     "unlock failed: " + e)` passed this rule with exit 0 before the
#     concatenation clause was added (final whole-branch review, finding 1).
#     Like iOS rule 3, this CANNOT be construct-based — `$x` / `${x}` is
#     ordinary Kotlin string templating and `a + b` is ordinary
#     arithmetic/concatenation, so matching either wholesale is unusable. It
#     is a denylist by necessity and is labelled as one. It deliberately does
#     NOT match a named typed-field render such as `${e.detail}` or
#     `${error::class.simpleName}` — those are reviewable, user-facing copy
#     choices, and matching them would produce a pile of allowlist entries
#     that assert nothing and drown the rule (see LIMITS for why this also
#     means a typed-field render passed straight to the log sink is not
#     caught). See the `N3`/`N4` self-test controls for the bare-vs-typed-
#     field boundary, and `C3`/`N10`/`N11` for the concatenation boundary — a
#     trailing non-identifier character after the name keeps `+ errorCount`
#     from matching `+ error`.
#
# There is no `is_app_ui_path`-style path exclusion (contrast iOS rule 2/3):
# the spec chose to allowlist individual Compose sites instead of excluding a
# whole app-UI directory, since Android's Compose screens and the FFI/port
# layer are not as cleanly separated as iOS's SwiftUI app targets.
#
# FIX ROUND 1 (adversarial review; brief-specified regexes were wrong)
# ---------------------------------------------------------------------
# Three bypasses were found, all traceable to the ORIGINAL BRIEF's regexes,
# not to an implementation slip — the human ruled the findings govern over
# the brief:
#   1. CRITICAL — `is_comment_line` treated ANY line opening with `/*` as
#      pure prose, never checking whether the comment closed on the same
#      line. `/* */ Log.w(TAG, secretValue.toString())` is a complete no-op
#      Kotlin comment followed by live code, and it was silently unscanned
#      against all four rules. Fixed: a `/*`-opening line is prose only if
#      no non-whitespace follows its `*/`.
#   2. Rule A's member pattern (`Log\.[a-z]+\(`) required all-lowercase, so
#      `Log.getStackTraceString(e)` — a real Android API — was invisible.
#      Fixed: `Log\.[A-Za-z_][A-Za-z0-9_]*\(`.
#   3. Rule B1 required a leading dot, so a no-receiver
#      `stackTraceToString()` / `printStackTrace()` (implicit `this`) evaded
#      it. Fixed: `\b`-anchored instead of `\.`-anchored (still matches the
#      dotted forms).
# See the `A6`/`B1e`/`CM1`/`CM2` self-test positives and the `N7`-`N9`
# negatives for the controls that pin these.
#
# FIX ROUND 2 (#475 whole-branch review; three of the four were the SAME
# asymmetry — a hole closed on one side and left open on the other)
# ---------------------------------------------------------------------
#   1. CRITICAL, and the exact mirror of round 1's finding 1 — round 1 fixed
#      the block-comment OPENING side and left the CLOSING side untouched, so
#      `*/ android.util.Log.w(TAG, "x", e)` (real code, second line of a
#      two-line `/*` … `*/` comment) was still prose to `is_comment_line` and
#      still unscanned against all four rules. Proven by execution: a file of
#      that shape passed with exit 0. Fixed in the now-SHARED
#      `is_comment_line` (scripts/lib/hygiene-allowlist.sh), which also closes
#      the same hole in the iOS guard. Controls `CM3`-`CM5` here, `P19`/`P20`
#      there — both mutation-proven by restoring the old matcher.
#   2. Rule B2 was left `\.`-anchored after round 1 `\b`-anchored rule B1 for
#      the identical reason. Fixed by adding rule B3 rather than relaxing B2
#      — see rule B3's own note. Controls `B3a`-`B3c`, `N12`.
#   3. Rule A guarded `android.util.Log` only, but Android redirects
#      stdout/stderr into logcat, so `println(e)` reached the log while
#      naming no `Log` symbol. Fixed by widening rule A. Controls `A7`-`A9`.
#   4. Three internally-authored wrapper exception types
#      (`CloudFolderException`, `VaultMirrorException`, `DeviceUuidException`)
#      had not been declared `SecretFreeThrowable`, so every nested wrap
#      rendered `<undisclosed …>` and discarded the message it was built to
#      carry. Not a guard change — see their declarations.
#
# USAGE
# -----
#   bash android/scripts/check-log-hygiene.sh              # guard android/**/*.{kt,java}
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
# Rule B3 closes the no-receiver `toString()` form but is line-based like
# everything else: it skips a line that DECLARES `fun toString(`, so a
# declaration and a bare laundering call sharing one line hide the call. The
# dotted rule B2 is unconditional and catches the realistic shape of that
# (`override fun toString() = e.toString()`); a bare `override fun toString() =
# toString()` is infinite recursion, not a bypass.
#
# A typed-field render passed straight to the sanctioned sink is NOT caught by
# any rule here: `SecretaryLog.warn(TAG, "failed: ${e.detail}")` passes clean.
# Rule C deliberately excludes named typed-field access (`${e.detail}`,
# `${error::class.simpleName}`) because matching it would fire on seven
# legitimate user-facing `Text(...)` copy sites — that boundary is correct for
# on-screen copy. It is NOT correct inside a log call: on VaultBrowseError's
# one remaining redacted arm (InvalidArgument — #474 made CorruptVault /
# SaveCryptoFailure data-free by construction, so they no longer need this),
# `.detail` carries exactly the plaintext `diagnosticDescription`'s redaction
# exists to remove, and `${e.detail}` walks straight around it. Nothing but
# review closes this gap.
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
# exception, so it is a constant rather than an allowlist entry.
readonly SANCTIONED_LOG_FILE="android/kit/src/main/kotlin/org/secretary/diagnostics/SecretaryLog.kt"

# RULE A: any reference to a logcat sink — `android.util.Log` via the import
# (which also catches `import android.util.Log as L`) or a fully-qualified
# call, plus the stdlib sinks. The `Log.` member pattern allows camelCase
# (`[A-Za-z_][A-Za-z0-9_]*`, not `[a-z]+`): an all-lowercase requirement missed
# `Log.getStackTraceString(e)`, a real Android API that renders a Throwable to
# text (adversarial review, round 1).
#
# `println(` / `System.out.` / `System.err.` are here because the Android
# runtime redirects stdout and stderr into logcat — `println(e)` is a raw
# Throwable in the log that names no `Log` symbol, and it passed every rule
# (#475 review). The leading `(^|[^A-Za-z0-9_.])` on `println` is what keeps
# `foo.println(` (a Writer/PrintStream method, not the stdlib sink) from being
# swept up by the same alternative; the tree has no such call today, and if one
# appears the fix is to name the real sink, not to widen the rule.
readonly LOG_RE='android\.util\.Log|(^|[^A-Za-z0-9_.])Log\.[A-Za-z_][A-Za-z0-9_]*\(|(^|[^A-Za-z0-9_.])println\(|System\.(out|err)\.'

# RULE B1: throwable-shaped constructs. Name-blind and precise. Word-boundary
# anchored (`\b`), not dot-anchored: a leading-dot requirement missed a
# no-receiver call (implicit `this`), e.g. inside a `Throwable.toString()`
# override calling bare `stackTraceToString()` / `printStackTrace()`
# (adversarial review, round 1). `\b` still matches the dotted forms.
readonly LAUNDER_RE='\.message\b|\.localizedMessage\b|\bstackTraceToString\(|\bprintStackTrace\('

# RULE B2: the explicit render, DOTTED form. Name-blind by design; the
# name-based form was the demonstrated bypass on iOS. Deliberately kept
# `\.`-anchored and unconditional so that a line which both declares
# `fun toString()` and launders (`override fun toString() = e.toString()`) is
# still caught even though rule B3 skips declaration lines.
readonly TOSTRING_RE='\.toString\(\)'

# RULE B3: the explicit render, NO-RECEIVER form (implicit `this`). Same
# asymmetry rule B1 was fixed for in round 1; B2 kept the leading dot until
# #475. Relaxing B2's anchor to `\b` was not an option — that also matches
# every `override fun toString()` declaration — so this is a separate rule
# whose scan skips lines declaring the function (DECL_TOSTRING_RE below).
readonly BARE_TOSTRING_RE='(^|[^A-Za-z0-9_.])toString\(\)'

# Lines rule B3 skips: a `fun toString(` declaration is not a call. Narrow on
# purpose — it is the ONLY exclusion any rule here applies beyond the shared
# path/comment filters, and rule B2 still covers such a line's dotted calls.
readonly DECL_TOSTRING_RE='\bfun[[:space:]]+toString[[:space:]]*\('

# RULE C: BARE interpolation, plus bare concatenation (`+ e`). `${e.detail}`
# is a named typed field — a reviewable choice — and is deliberately NOT
# matched; matching it would fire on seven legitimate user-facing copy sites
# and drown the rule (see LIMITS for the one place that boundary does NOT
# hold: a typed-field render passed straight to the log sink). iOS rule 3
# draws the same interpolation line by requiring the closing paren
# immediately. The concatenation alternative catches `"str" + e` — Kotlin's
# `+` on a `String` and a `Throwable` also calls `toString()`, so it launders
# exactly like interpolation does but was not covered by either the
# interpolation alternatives above or rule B2 (no `.toString()` appears at the
# call site). The trailing `([^A-Za-z0-9_.(]|$)` class is what keeps
# `+ errorCount` from matching `+ error` — see the `C3`/`N10`/`N11` self-test
# controls.
# shellcheck disable=SC2016  # single-quoted ERE: the literal `$`/`+` are the Kotlin patterns being matched, not shell expansion
readonly INTERP_RE='\$\{(e|err|error|caught|failure|ex|t)\}|\$(e|err|error|caught|failure|ex|t)([^A-Za-z0-9_.]|$)|\+[[:space:]]*(e|err|error|caught|failure|ex|t)([^A-Za-z0-9_.(]|$)'

# Test sources legitimately construct/assert on Throwable text; they never
# write to logcat.
is_test_path() { [[ "$1" == *"/src/test/"* || "$1" == *"/src/androidTest/"* ]]; }

# Gradle build output — generated Kotlin (e.g. BuildConfig, resource
# accessors) and compiled/intermediate artifacts. Neither is hand-written.
is_generated_path() {
  [[ "$1" == *"/build/generated/"* || "$1" == *"/build/"* ]]
}

# `trim()`, `allowlisted()` and `is_comment_line()` live in
# scripts/lib/hygiene-allowlist.sh, sourced above — shared with the iOS guard so
# the two security-critical matchers have exactly one copy each. See that file's
# header for the $ALLOWLIST/$REPO_ROOT contract `allowlisted()` depends on, and
# for the two block-comment bypasses `is_comment_line()` closes.
# `count_matches()` is NOT shared: it exists for iOS rule 1's per-interpolation
# counting, and no rule here counts.

# RULE A. Any logcat-sink reference outside the sanctioned file is a hit —
# `android.util.Log` plus the stdout/stderr the runtime redirects into logcat.
# Does NOT consult the allowlist — logging at all outside the façade is the
# violation, not a renderable value that could be reviewed as safe.
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
  done < <(grep -rn --include='*.kt' --include='*.java' -E "$LOG_RE" "$root" 2>/dev/null || true)
}

# RULES B1, B2, B3 and C — same scope and same filters, different matcher and
# different allowlist rule id. Args: <root> <rule-id> <ERE> [<skip-ERE>].
# Prints offending hits not covered by a reviewed allowlist entry.
#
# <skip-ERE> is optional and used ONLY by rule B3, to drop `fun toString(`
# declarations. It is a per-rule exclusion, not a general escape hatch: adding
# one to another rule widens that rule's blind spot by a whole line-shape, so
# do it only with a control pinning what stays caught (see `N12` vs `B3c`).
scan_launder() {
  local root="$1" rule="$2" re="$3" skip_re="${4:-}" hit path text
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    path="${hit%%:*}"; text="${hit#*:}"; text="${text#*:}"
    is_test_path "$path" && continue
    is_generated_path "$path" && continue
    is_comment_line "$text" && continue
    [[ -n "$skip_re" ]] && grep -qE "$skip_re" <<<"$text" && continue
    allowlisted "$rule" "$hit" && continue
    echo "$hit"
  done < <(grep -rn --include='*.kt' --include='*.java' -E "$re" "$root" 2>/dev/null || true)
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
  # A6: camelCase member. A `[a-z]+`-only member pattern missed this real
  # Android API (adversarial review, round 1).
  write_case A6 'Log.getStackTraceString(e)'
  # A7-A9: the stdlib sinks. Android redirects stdout/stderr into logcat, so
  # these reach the log while naming no `Log` symbol — they passed all four
  # rules before rule A was widened (#475 review). Each pins ONE alternative
  # and trips NO other rule, so removing that alternative fails this control
  # rather than being masked: `System.out.println("x: " + e)` would have been
  # caught by rule C's concatenation clause regardless and proves nothing.
  write_case A7 '        println(e)'
  write_case A8 '        System.out.flush()'
  write_case A9 '        val sink = System.err.bufferedWriter()'
  # --- RULE B1 positives (must all be caught) ---
  # shellcheck disable=SC2016  # literal Kotlin `${e.message}`, not shell expansion
  write_case B1a 'throw CloudFolderException("op failed: ${e.message}")'
  write_case B1b 'val s = problem.localizedMessage'
  write_case B1c 'val s = e.stackTraceToString()'
  write_case B1d 'e.printStackTrace()'
  # B1e: no-receiver (implicit `this`) call, e.g. inside a Throwable.toString()
  # override. A leading-dot-only pattern missed this (adversarial review, round 1).
  write_case B1e 'val s = stackTraceToString()'
  # --- RULE B2 positives (must all be caught) ---
  # B2b is the name-based bypass that motivated making rule B2 name-blind.
  write_case B2a 'else -> VaultBrowseError.Failed(e.toString())'
  write_case B2b 'else -> VaultBrowseError.Failed(problem.toString())'
  # --- RULE B3 positives (no-receiver render, must all be caught) ---
  # B3a/B3b: bare `toString()` under implicit `this` — inside a Throwable that
  # is exactly a self-render of a secret-bearing message. Rule B2's leading dot
  # never saw these (#475 review).
  write_case B3a 'val s = toString()'
  write_case B3b 'SecretaryLog.warn(TAG, "failed: " + toString())'
  # B3c: a line that BOTH declares toString() and launders. Rule B3 skips it as
  # a declaration; the dotted rule B2 must still catch it. This is the control
  # that keeps B3's declaration exclusion from becoming a bypass.
  write_case B3c 'override fun toString() = e.toString()'
  # --- COMMENT-HOLE positives (must all be caught) ---
  # `/* */` is a complete Kotlin no-op comment; treating any `/*`-opening line
  # as pure prose (an earlier version of is_comment_line did) silently
  # unscanned real code hiding behind it against every rule. CM1 is the
  # Critical finding's exact shape (rule A); CM2 shows the same hole reaches
  # rule B2.
  write_case CM1 '/* */ Log.w(TAG, "x", e)'
  write_case CM2 '/* */ val s = e.toString()'
  # CM3-CM5: the CLOSING side of the same hole, which round 1's fix did not
  # cover — `*/ <code>` is line 2 of a two-line `/*` … `*/` comment, i.e. real
  # code, and the `*`-prefix branch called it prose. A file of exactly this
  # shape passed the whole guard with exit 0 (#475 review). CM4 uses the
  # fully-qualified sink so it needs no import to be a working leak.
  write_case CM3 '*/ Log.w(TAG, "x", e)'
  write_case CM4 '*/ android.util.Log.w(TAG, "x", e)'
  write_case CM5 '*/ val s = e.toString()'
  # --- RULE C positives (bare only, must all be caught) ---
  # shellcheck disable=SC2016  # literal Kotlin `$e`, not shell expansion
  write_case C1 'return Failed("boom: $e")'
  # shellcheck disable=SC2016  # literal Kotlin `${e}`, not shell expansion
  write_case C2 'return Failed("boom: ${e}")'
  # C3: string concatenation. `"str" + throwable` also calls toString() in
  # Kotlin, and this passed rule B2 (no `.toString()` at the call site) and
  # every interpolation alternative before the concatenation clause was added
  # (final whole-branch review, finding 1).
  write_case C3 'SecretaryLog.warn(TAG, "failed: " + e)'
  # --- negatives (must all stay silent) ---
  write_case N1 'else -> VaultBrowseError.Failed(diagnosticDetail(e))'
  write_case N2 'SecretaryLog.warn(TAG, "unlock failed", e)'
  # shellcheck disable=SC2016  # literal Kotlin `${error.detail}`, not shell expansion
  write_case N3 'val s = "Couldn'"'"'t authorize the change: ${error.detail}"'   # typed field, not bare
  # shellcheck disable=SC2016  # literal Kotlin `${error::class.simpleName}`, not shell expansion
  write_case N4 'val s = "failed: ${error::class.simpleName}"'                    # typed field
  # shellcheck disable=SC2016  # literal Kotlin `$errorCount`, not shell expansion
  write_case N5 'label = "$errorCount failures"'                                  # whole-identifier anchor
  write_case N6 'val n = counter.toInt()'                                         # not toString
  # N7-N9: genuine comments that mention a construct the rules would
  # otherwise catch, proving is_comment_line's fix did not over-correct into
  # treating live code as a comment.
  write_case N7 '/** Explains why Log.w(TAG, e) is never called directly. */'   # genuine KDoc one-liner
  write_case N8 ' * still mentions Log.w(TAG, e) from the bullet above'          # block-comment continuation
  write_case N9 '// Log.w(TAG, e) is what NOT to do'                             # //-only comment line
  # N10/N11: the concatenation clause's tail character class must not fire on
  # ordinary arithmetic or string concatenation that merely starts with one of
  # the denylisted names. Proves `([^A-Za-z0-9_.(]|$)` — not trusting it.
  write_case N10 'val total = count + errorCount'                                # arithmetic, not throwable concat
  write_case N11 'val s = prefix + "text"'                                       # string concat, not throwable
  # N12: a plain `toString()` DECLARATION is not a call. Without the exclusion
  # rule B3 would fire on every override in the tree; with it, B3c above proves
  # a declaration line that also launders is still caught by rule B2.
  # shellcheck disable=SC2016  # literal Kotlin `$bar`, not shell expansion
  write_case N12 'override fun toString() = "Foo(bar=$bar)"'
  # N14: `println` as a METHOD on some other receiver (a PrintWriter over a
  # file, say) is not the stdlib logcat sink. Pins the `(^|[^A-Za-z0-9_.])`
  # prefix on rule A's println alternative.
  write_case N14 'writer.println(line)'
  # N13: the CLOSING line of a genuine block comment — mentions a construct
  # rule A would catch, and closes with nothing after the `*/`. Non-vacuous by
  # construction: it fires if the CM3-CM5 fix over-corrects into treating every
  # `*/` line as code. (A bare ` */` would be vacuous — no rule matches it.)
  write_case N13 ' * @throws when Log.w(TAG, e) would have been called */'

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
  hits="$(scan_sink "$d"
          scan_launder "$d" B1 "$LAUNDER_RE"
          scan_launder "$d" B2 "$TOSTRING_RE"
          scan_launder "$d" B3 "$BARE_TOSTRING_RE" "$DECL_TOSTRING_RE"
          scan_launder "$d" C "$INTERP_RE")"

  local p
  for p in A1 A2 A3 A4 A5 A6 A7 A8 A9 B1a B1b B1c B1d B1e B2a B2b B3a B3b B3c \
           CM1 CM2 CM3 CM4 CM5 C1 C2 C3; do
    grep -q "/$p\.kt:" <<<"$hits" || { echo "SELF-TEST FAILED: no hit on positive control $p" >&2; fails=1; }
  done
  local n
  for n in N1 N2 N3 N4 N5 N6 N7 N8 N9 N10 N11 N12 N13 N14; do
    grep -q "/$n\.kt:" <<<"$hits" && { echo "SELF-TEST FAILED: fired on negative control $n" >&2; fails=1; }
  done
  # The allowlist pair, asserted BY LINE NUMBER — this is what fails if
  # exact-line matching ever regresses to substring.
  grep -q "/X\.kt:1:" <<<"$hits" &&
    { echo "SELF-TEST FAILED: allowlisted line X.kt:1 was reported" >&2; fails=1; }
  grep -q "/X\.kt:2:" <<<"$hits" ||
    { echo "SELF-TEST FAILED: X.kt:2 escaped via its file's allowlist entry (substring match?)" >&2; fails=1; }
  [[ $fails -eq 0 ]] || return 1
  echo "self-test OK — 27 positive controls caught, 14 negative controls clean"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

sink_hits="$(scan_sink "$SCAN_ROOT")"
b1_hits="$(scan_launder "$SCAN_ROOT" B1 "$LAUNDER_RE")"
b2_hits="$(scan_launder "$SCAN_ROOT" B2 "$TOSTRING_RE")"
b3_hits="$(scan_launder "$SCAN_ROOT" B3 "$BARE_TOSTRING_RE" "$DECL_TOSTRING_RE")"
c_hits="$(scan_launder "$SCAN_ROOT" C "$INTERP_RE")"
status=0

if [[ -n "$sink_hits" ]]; then
  echo "ERROR (#472 rule A): a logcat sink (android.util.Log, or println/System.out/" >&2
  echo "System.err — the Android runtime redirects both into logcat) is referenced" >&2
  echo "outside the sanctioned façade ($SANCTIONED_LOG_FILE):" >&2
  echo "$sink_hits" >&2
  echo >&2
  echo "Fix: route through SecretaryLog instead of logging directly." >&2
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

if [[ -n "$b3_hits" ]]; then
  echo "ERROR (#472 rule B3): a value is hand-rendered via a no-receiver toString()" >&2
  echo "— under implicit \`this\`, which inside a Throwable is a self-render of the" >&2
  echo "very message the gate exists to withhold:" >&2
  echo "$b3_hits" >&2
  echo >&2
  echo "Fix: use the sanctioned diagnostic path instead. If the use is legitimate" >&2
  echo "(the enclosing type is not throwable-shaped, or this IS the sanctioned" >&2
  echo "rendering), add a reviewed entry to" >&2
  echo "android/scripts/log-hygiene-allowlist.txt." >&2
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
