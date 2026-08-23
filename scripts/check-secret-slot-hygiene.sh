#!/usr/bin/env bash
#
# check-secret-slot-hygiene.sh — deny the move-out family around the secret
# wrappers in core/src/crypto/secret.rs (#521).
#
# WHY THIS EXISTS
# ---------------
# `Sensitive::build` / `try_build` hand their fill closure a `&mut T`. The
# doc comment on `build` names the residual hole honestly:
#
#   A closure that moves the secret out — e.g. via `std::mem::swap` or
#   `std::mem::replace` — defeats the wipe, because the wrapper would then
#   zeroize whatever was swapped in. […] every closure written here is a
#   review point.
#
# "Every closure written here is a review point" is convention. This repo's
# standard is CI enforcement — #467, #472, #474, #486, #500, #504 and #515
# were each spent converting exactly that sentence into a pinned sink. This
# script is that conversion for the one remaining unenforced capability on a
# security-critical type.
#
# The swap family is uniquely bad because it does not merely leak: it makes
# the wrapper's own wipe VACUOUS, so the code looks protected and is not.
# `mem::forget` / `ManuallyDrop` are a superset — they defeat `ZeroizeOnDrop`
# on EVERY wrapper in secret.rs, not just `Sensitive`.
#
# SCOPE: TREE-WIDE, NOT CLOSURE-SCOPED
# ------------------------------------
# The rules deny these identifiers anywhere in the scanned roots rather than
# only inside a `build`/`try_build` closure body. Closure-scoping would need
# brace matching in bash AND would miss the `mem::forget` / `ManuallyDrop`
# class, which is not confined to a closure. Tree-wide is simpler and
# strictly stronger, and it costs nothing: the census is empty.
#
# TEST CODE IS SCANNED
# --------------------
# There is deliberately NO `#[cfg(test)]` carve-out. #496 found the
# error-payload guard's permissive `#[cfg(...test...)]` matcher was used as a
# SKIP LIST, where an over-match is fail-OPEN — `#[cfg(not(test))]` or any
# `#[cfg_attr(test, ...)]` silenced a violation in one line. A test that
# genuinely needs one of these identifiers becomes a reviewed allowlist entry
# with a visible key, which is the outcome we want.
#
# USAGE
# -----
#   bash scripts/check-secret-slot-hygiene.sh              # guard the tree
#   bash scripts/check-secret-slot-hygiene.sh --self-test  # prove the matchers fire
#
# Exit 0 when no unallowlisted hit remains; exit non-zero (printing each
# offending line) otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/hygiene-allowlist.sh
source "$SCRIPT_DIR/lib/hygiene-allowlist.sh"

# NOT `readonly`: `self_test()` legitimately retargets this at the probe
# directory for the duration of the self-test (`allowlisted` relativizes
# hits against it), the same seam the shared lib's own header comment
# documents for `$ALLOWLIST` — `readonly` here would turn that deliberate
# test seam into a hard failure instead.
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ALLOWLIST="$REPO_ROOT/scripts/secret-slot-hygiene-allowlist.txt"

# RULE S1 — the move-out family. `\b` before `mem` so `xmem::take` does not
# match; `\b` after the verb so `mem::taken` does not either.
readonly S1_RE='\bmem::(swap|replace|take|forget)\b'

# RULE S2 — `ManuallyDrop` defeats `ZeroizeOnDrop` on every wrapper, not just
# `Sensitive`. `\b` after the name so `ManuallyDropGuard` does not match.
readonly S2_RE='\bManuallyDrop\b'

# Roots holding secret-bearing code, per #521. Repo-relative.
readonly SCAN_ROOTS=(
  core/src
  ffi/secretary-ffi-bridge/src
  ffi/secretary-ffi-py/src
  ffi/secretary-ffi-uniffi/src
  desktop/src-tauri/src
  cli/src
)

# Print offending hits for one rule under one root. Args: <root> <rule> <ERE>.
scan_rule() {
  local root="$1" rule="$2" re="$3" hit text
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    # `grep -rn` emits `<path>:<line>:<text>`; strip both leading fields.
    text="${hit#*:}"; text="${text#*:}"
    is_comment_line "$text" && continue
    allowlisted "$rule" "$hit" && continue
    echo "$hit"
  done < <(grep -rn --include='*.rs' -E "$re" "$root" 2>/dev/null || true)
}

scan_all() {
  local base="$1" root
  for root in "${SCAN_ROOTS[@]}"; do
    [[ -d "$base/$root" ]] || continue
    scan_rule "$base/$root" S1 "$S1_RE"
    scan_rule "$base/$root" S2 "$S2_RE"
  done
}

run_guard() {
  local hits
  hits="$(scan_all "$REPO_ROOT")"
  if [[ -n "$hits" ]]; then
    echo "check-secret-slot-hygiene: FORBIDDEN move-out construct(s) found:" >&2
    echo "$hits" >&2
    cat >&2 <<'EOF'

`mem::swap` / `mem::replace` / `mem::take` / `mem::forget` / `ManuallyDrop`
move a secret out of, or suppress the Drop on, a zeroize-on-drop wrapper —
so the wipe silently becomes a no-op while the code still LOOKS protected.

If a hit is a reviewed exception, add it to
scripts/secret-slot-hygiene-allowlist.txt as four TAB-separated fields:
  <repo-relative path>\t<S1|S2>\t<exact trimmed source line>\t<justification>
Adding an entry is a SECURITY DECISION. The allowlist ships empty.
EOF
    return 1
  fi
  echo "check-secret-slot-hygiene: OK (${#SCAN_ROOTS[@]} roots, 2 rules, no findings)"
}

# Two-sided self-test. A guard never observed failing is indistinguishable
# from a no-op; a guard that fires on everything is worse. Probes are written
# to `mktemp -d`, NEVER into the source tree — the payload guard writes its
# probes into the live tree and races parallel sessions, which is #516.
self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap cleanup_self_test EXIT
  local d="$SELF_TEST_TMP" fails=0
  mkdir -p "$d/core/src"

  write_case() { printf '%s\n' "$2" > "$d/core/src/$1.rs"; }

  # --- S1/S2 positives (must ALL be caught) ---
  write_case P1  '    std::mem::swap(slot, &mut plain);'
  write_case P2  '    mem::swap(slot, &mut plain);'
  write_case P3  '    let old = mem::replace(slot, [0u8; 32]);'
  write_case P4  '    let stolen = mem::take(slot);'
  write_case P5  '    mem::forget(secret);'
  write_case P6  '    std::mem::forget(secret);'
  write_case P7  '    let kept = ManuallyDrop::new(secret);'
  write_case P8  '    use std::mem::ManuallyDrop;'
  # The shape the guard exists for: a move-out INSIDE a build closure.
  write_case P9  '    let s = Sensitive::build([0u8; 32], |slot| { std::mem::swap(slot, &mut plain); });'
  # Test code is NOT carved out. This is the decision that differs from the
  # other guards in this repo (#496: a test carve-out is fail-OPEN).
  printf '%s\n%s\n%s\n%s\n' '#[cfg(test)]' 'mod tests {' '    fn t() { mem::swap(a, b); }' '}' \
    > "$d/core/src/P10.rs"
  # The two comment-hole shapes. Both are REAL CODE and must be caught; both
  # defeated an earlier `is_comment_line` (round 1, and #475).
  write_case P11 '    /* set up */ std::mem::swap(a, b);'
  printf '%s\n%s\n' '    /* two-line' '    */ std::mem::swap(a, b);' > "$d/core/src/P12.rs"

  # --- negatives (must ALL stay silent) ---
  # N1 is the REAL line at core/src/crypto/secret.rs:196 — the doc comment
  # that names the family in prose. If this ever fires, the guard would
  # demand an allowlist entry for its own rationale.
  # shellcheck disable=SC2016  # backticks are LITERAL content (the real
  # secret.rs doc-comment text), deliberately single-quoted so they don't expand
  write_case N1 '    /// `std::mem::swap` or `std::mem::replace` — defeats the wipe, because'
  write_case N2 '    // mem::forget(x) would defeat ZeroizeOnDrop here.'
  write_case N3 '    /* ManuallyDrop is not permitted in this module. */'
  write_case N4 '    let s = Sensitive::new(buf);'
  # Word-boundary controls: substring matches that must NOT fire.
  write_case N5 '    xmem::take(&mut v);'
  write_case N6 '    let guard = ManuallyDropGuard::new(x);'

  # --- allowlist control: exact-line matching, NOT substring ---
  # ONE file, TWO lines. Line 1 is the allowlist entry verbatim; line 2 is a
  # DIFFERENT line in the SAME file sharing the entry's distinctive substring.
  # They must be one file — with two files the paths differ and the entry
  # never applies to the second either way, making the control vacuous.
  local a_keep='    let taken = mem::take(&mut self.pending);'
  local a_catch='    let other = mem::take(&mut self.buffered);'
  printf '%s\n%s\n' "$a_keep" "$a_catch" > "$d/core/src/A.rs"

  ALLOWLIST="$d/allowlist.txt"
  {
    # The real, exact-line exemption for line 1.
    printf '%s\t%s\t%s\t%s\n' "core/src/A.rs" S1 "$(trim "$a_keep")" 'self-test fixture: legitimate exact-line exemption'
    # A deliberately SHORT needle of the kind a substring allowlist would use.
    # Under exact-line matching it can never equal a full source line, so it
    # exempts nothing. Under substring matching it would exempt line 2 too —
    # which is what makes this pair DETECT the regression, not merely describe it.
    printf '%s\t%s\t%s\t%s\n' "core/src/A.rs" S1 'mem::take' 'self-test fixture: short needle, MUST be inert'
  } > "$ALLOWLIST"

  # `allowlisted` relativizes hits against $REPO_ROOT, so point it at the
  # probe dir for the duration of the self-test.
  local saved_root="$REPO_ROOT"
  REPO_ROOT="$d"

  local hits p n
  hits="$(scan_all "$d")"

  REPO_ROOT="$saved_root"

  for p in P1 P2 P3 P4 P5 P6 P7 P8 P9 P10 P11 P12; do
    grep -q "/$p\.rs:" <<<"$hits" || { echo "SELF-TEST FAILED: no hit on positive control $p" >&2; fails=1; }
  done
  for n in N1 N2 N3 N4 N5 N6; do
    grep -q "/$n\.rs:" <<<"$hits" && { echo "SELF-TEST FAILED: fired on negative control $n" >&2; fails=1; }
  done
  # The allowlist pair, asserted BY LINE NUMBER — this is what fails if
  # exact-line matching ever regresses to substring.
  grep -q "/A\.rs:1:" <<<"$hits" &&
    { echo "SELF-TEST FAILED: allowlisted line A.rs:1 was reported" >&2; fails=1; }
  grep -q "/A\.rs:2:" <<<"$hits" ||
    { echo "SELF-TEST FAILED: A.rs:2 escaped via its file's allowlist entry (substring match?)" >&2; fails=1; }

  if [[ $fails -eq 0 ]]; then
    echo "check-secret-slot-hygiene --self-test: OK (12 positive, 6 negative, 2 allowlist controls)"
    return 0
  fi
  return 1
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  run_guard
fi
