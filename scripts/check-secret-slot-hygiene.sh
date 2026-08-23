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
# strictly stronger.
#
# It does NOT cost nothing, and an earlier version of this comment said it did
# — a claim that held only of the six roots that version happened to list. The
# census across the roots below is three: `secret.rs`'s own doc comment (prose,
# caught by `is_comment_line`) plus the two `scrub_string` sites in
# `browser/secretary-browser-host`, which are reviewed allowlist entries. That
# is the intended outcome, not a cost to be avoided by narrowing scope.
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
#
# LIMITS
# ------
# Both rules match by SPELLING; neither resolves a Rust name. Three blind
# spots, named rather than left implicit — the standard every sibling guard
# in this repo (see CLAUDE.md's "Rust error payloads" section, and its own
# LIMITS block in scripts/check-error-payload-hygiene.py) is held to:
#
#   1. MODULE/ITEM ALIASING — and the two rules are NOT equally exposed, so
#      do not flatten this into one claim:
#        - S1 is evaded ENTIRELY by `use std::mem as m;` followed by
#          `m::swap(slot, &mut plain)`: neither the `use` line nor the call
#          site contains a `mem::<verb>` substring, so nothing fires.
#          Verified by execution against a planted probe.
#        - S2 is exposed to the SAME attack shape, but only partially, by
#          accident rather than design: `use std::mem::ManuallyDrop as MD;`
#          still writes the literal identifier `ManuallyDrop` once, on the
#          `use` line, and S2 matches that line (though not the later
#          `MD::new(...)` call site). An S2 evasion needs the name to never
#          appear at all, which is a narrower attack than S1's.
#      Zero live producers of either shape exist in the tree today. Tracked
#      as #545 — same root cause as #512 (a renaming import defeats the
#      `Detail` newtype's E2 credit) and #517 (E6 / `SHADOWABLE_PARAM_IDENTS`
#      carry E4's alias/macro blind spots): text-based identifier matching,
#      matched by spelling, resolving nothing. Do NOT close this by widening
#      S1_RE/S2_RE here — #545 owns that fix deliberately, so this comment
#      and the guard's actual behaviour stay in sync.
#   2. MACRO-GENERATED CODE — every rule here reads TEXT, not expanded
#      macros: a `macro_rules!`-generated `mem::swap` or `ManuallyDrop::new`
#      is invisible to either rule. Inherent to a text-based guard.
#   3. SCOPE — only `*.rs` files under the SCAN_ROOTS below are read. The list
#      is still hand-written, but it is no longer merely trusted: a workspace
#      member with a `src/` that appears in neither SCAN_ROOTS nor
#      UNSCANNED_MEMBERS is a hard failure (`check_roots_cover_workspace`),
#      which is the treatment #505 gave the payload guard's `DEFAULT_ROOTS`.
#      What that does NOT cover, stated rather than glossed: a tree that is not
#      a workspace member at all (`core/fuzz` is `exclude`d outright), and any
#      non-`src/` directory inside a member. An earlier version of this block
#      named six roots and listed only `core/tests/**` and `test-utils/` as the
#      out-of-scope trees — omitting two workspace MEMBERS, one of them
#      (`browser/secretary-browser-host`) secret-bearing and holding two live
#      S1 producers. Both are now scanned. What remains outside every root, in
#      full: `core/tests/**`, `cli/tests/**`, `ffi/*/tests/**`,
#      `desktop/src-tauri/tests/**`, `browser/*/tests/**`, `core/examples/`,
#      `test-utils/` (a workspace member, dev-only by construction), and
#      `core/fuzz/` (excluded from the workspace entirely). A move-out
#      construct in any of those is unscanned regardless of what it contains.
#      Unlike the two blind spots above, a MISSING or EMPTY declared root is
#      no longer silent — `check_roots` makes it fatal.

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
#
# This list must stay in step with the root manifest's `[workspace] members`
# for every member that can hold a secret. The first version of this guard
# named six roots and omitted `browser/secretary-browser-host` — a workspace
# member that handles the device secret and the master password through
# `SecretBytes`, and which contains two live S1 producers (its `scrub_string`
# idiom, allowlisted below). `desktop/secretary-desktop-presence` was likewise
# absent. Both were invisible to the guard AND unnamed in the LIMITS block, so
# the "census is empty" claim was true only of the roots that happened to be
# listed. `check_roots_cover_workspace` below now makes that omission a hard
# failure rather than a silent one: adding a workspace member without adding
# it here (or to UNSCANNED_MEMBERS, with a reason) reds the guard.
readonly SCAN_ROOTS=(
  core/src
  ffi/secretary-ffi-bridge/src
  ffi/secretary-ffi-py/src
  ffi/secretary-ffi-uniffi/src
  desktop/src-tauri/src
  desktop/secretary-desktop-presence/src
  browser/secretary-browser-host/src
  cli/src
)

# Workspace members deliberately NOT scanned. Each needs a reason, because
# every name here is a crate this guard does not police.
#
#   test-utils — dev-only by construction (`secretary-test-utils` is consumed
#   exclusively via [dev-dependencies]; CLAUDE.md forbids making it a runtime
#   dep). It ships in no artifact, so a vacuous wipe there cannot reach a user.
readonly UNSCANNED_MEMBERS=(
  test-utils
)

# Extract `[workspace] members` from the root manifest.
#
# Deliberately a narrow parse, not a TOML implementation: it reads the quoted
# strings of the `members = [...]` array inside `[workspace]`. If it returns
# nothing, the caller treats that as a hard failure rather than as "no members"
# — a parse that silently yields zero would disable the coverage check that
# depends on it, which is the same fail-open shape as a missing scan root.
workspace_members() {
  awk '
    /^[[:space:]]*\[workspace\][[:space:]]*$/ { in_ws = 1; next }
    /^[[:space:]]*\[/                         { in_ws = 0 }
    in_ws && /^[[:space:]]*members[[:space:]]*=/ { in_arr = 1 }
    in_arr { print; if (/\]/) in_arr = 0 }
  ' "$1" 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"'
}

# Fail hard when a workspace member holding Rust sources is scanned by neither
# SCAN_ROOTS nor UNSCANNED_MEMBERS.
#
# THIS IS THE CHECK THAT WOULD HAVE CAUGHT THIS GUARD'S OWN FIRST VERSION.
# That version hand-listed six roots and omitted `browser/secretary-browser-host`
# — a member that handles the device secret and the master password — so its
# two live S1 producers were invisible while the guard printed OK and its
# allowlist advertised an empty tree-wide census.
#
# A self-test cannot catch a root being dropped from SCAN_ROOTS, because any
# assertion written over SCAN_ROOTS disappears along with the entry (learned by
# mutation while writing this). The manifest is the independent source of truth,
# which is exactly what #505 did for the payload guard's `DEFAULT_ROOTS`.
check_roots_cover_workspace() {
  local base="$1" m root x found problems=0 count=0
  while IFS= read -r m; do
    [[ -z "$m" ]] && continue
    count=$((count + 1))
    for x in "${UNSCANNED_MEMBERS[@]}"; do
      [[ "$m" == "$x" ]] && continue 2
    done
    # A member with no `src/` has no Rust sources for this guard to read.
    [[ -d "$base/$m/src" ]] || continue
    found=0
    for root in "${SCAN_ROOTS[@]}"; do
      [[ "$root" == "$m/src" ]] && { found=1; break; }
    done
    if (( ! found )); then
      echo "check-secret-slot-hygiene: UNSCANNED WORKSPACE MEMBER: $m" >&2
      echo "  $m/src holds Rust sources but is in neither SCAN_ROOTS nor" >&2
      echo "  UNSCANNED_MEMBERS. Add it to one — the second only with a reason." >&2
      problems=1
    fi
  done < <(workspace_members "$base/Cargo.toml")
  if (( count == 0 )); then
    echo "check-secret-slot-hygiene: could not read [workspace] members from" >&2
    echo "  $base/Cargo.toml — refusing to run with an unverifiable root list." >&2
    return 1
  fi
  return $problems
}

# Fail hard when a declared root cannot be scanned.
#
# NOT a finding, and deliberately not allowlistable: this is the guard being
# unable to do its job, which must never be reported as "no findings". The
# previous `[[ -d ]] || continue` made a moved or renamed root contribute zero
# files SILENTLY — verified by execution, a tree containing none of the roots
# printed `OK (6 roots, 2 rules, no findings)` and exited 0. That is #496's
# fail-open (`Path.rglob` does not raise) restated in bash; the sibling guard
# already fails closed here, see `scripts/payload_guard/scan.py`'s
# `_check_roots_resolve`.
#
# The EMPTY case matters independently of the MISSING one: a root that exists
# but holds no `*.rs` (a build reshuffle, a submodule not checked out) exempts
# a whole crate with nothing to notice.
check_roots() {
  local base="$1" root problems=0
  for root in "${SCAN_ROOTS[@]}"; do
    if [[ ! -d "$base/$root" ]]; then
      echo "check-secret-slot-hygiene: SCAN ROOT MISSING: $root" >&2
      echo "  Not a directory under $base. If the tree moved, update SCAN_ROOTS —" >&2
      echo "  this guard will NOT silently skip a root it was told to scan." >&2
      problems=1
    elif [[ -z "$(find "$base/$root" -name '*.rs' -print -quit 2>/dev/null)" ]]; then
      echo "check-secret-slot-hygiene: SCAN ROOT EMPTY: $root" >&2
      echo "  Contains no *.rs files. A root contributing zero files exempts a whole" >&2
      echo "  crate; if that is intended, remove it from SCAN_ROOTS deliberately." >&2
      problems=1
    fi
  done
  return $problems
}

# Print offending hits for one rule under one root. Args: <root> <rule> <ERE>.
scan_rule() {
  local root="$1" rule="$2" re="$3" hit text out rc=0
  # `grep` exits 0 on match, 1 on no-match, and >=1... specifically >=2 on a
  # REAL error (unreadable file or directory, malformed ERE, I/O failure). The
  # previous `2>/dev/null || true` collapsed all three into "no findings" and
  # discarded the diagnostic — verified by execution, `chmod 000` on a root
  # holding a genuine violation printed OK and exited 0. Exit 1 stays quiet;
  # anything above it is fatal.
  out="$(grep -rn --include='*.rs' -E "$re" "$root")" || rc=$?
  if (( rc > 1 )); then
    echo "check-secret-slot-hygiene: grep failed (exit $rc) on $root for rule $rule" >&2
    exit 2
  fi
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    # `grep -rn` emits `<path>:<line>:<text>`; strip both leading fields.
    text="${hit#*:}"; text="${text#*:}"
    is_comment_line "$text" && continue
    allowlisted "$rule" "$hit" && continue
    echo "$hit"
  done <<<"$out"
}

scan_all() {
  local base="$1" root
  for root in "${SCAN_ROOTS[@]}"; do
    scan_rule "$base/$root" S1 "$S1_RE"
    scan_rule "$base/$root" S2 "$S2_RE"
  done
}

run_guard() {
  local hits
  # Before scanning anything: prove every declared root is actually readable
  # and non-empty. A guard that reports OK having read nothing is worse than
  # no guard, so this is fatal rather than a finding.
  # Both run unconditionally rather than short-circuiting on the first: they
  # diagnose different mistakes (a root that moved vs. a member nobody added),
  # and someone fixing one wants to see the other in the same run.
  local roots_bad=0 cover_bad=0
  check_roots "$REPO_ROOT" || roots_bad=1
  check_roots_cover_workspace "$REPO_ROOT" || cover_bad=1
  if (( roots_bad || cover_bad )); then
    echo "check-secret-slot-hygiene: refusing to report OK — see above." >&2
    return 1
  fi
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
  # `check_roots` above proved every declared root exists and holds at least
  # one `*.rs`, so this count is now what was actually READ. Before that check
  # it was the DECLARED count, which is how a run that scanned nothing could
  # still print a reassuring "6 roots".
  echo "check-secret-slot-hygiene: OK (${#SCAN_ROOTS[@]} roots scanned, 2 rules, no findings)"
}

# Two-sided self-test. A guard never observed failing is indistinguishable
# from a no-op; a guard that fires on everything is worse. Probes are written
# to `mktemp -d`, NEVER into the source tree — the payload guard writes its
# probes into the live tree and races parallel sessions, which is #516.
self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap cleanup_self_test EXIT
  local d="$SELF_TEST_TMP" fails=0 root
  # EVERY declared root gets a directory AND a probe. Two reasons, both of
  # which were live gaps in the first version:
  #   - `check_roots` now fails on a missing or `.rs`-empty root, so a probe
  #     tree containing only `core/src` would abort the self-test.
  #   - all 12 matcher probes used to live in `core/src`, so SCAN_ROOTS could
  #     be truncated to that one entry with the self-test still green
  #     (verified by mutation). The per-root probe below is what detects a
  #     dropped root.
  for root in "${SCAN_ROOTS[@]}"; do
    mkdir -p "$d/$root"
    # Distinctive per-root filename so the assertion loop can name the root
    # that stopped being scanned rather than just "something is missing".
    printf '%s\n' '    std::mem::swap(slot, &mut plain);' \
      > "$d/$root/ROOT_$(printf '%s' "$root" | tr '/-' '__').rs"
  done

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
  # N1 is the REAL line at core/src/crypto/secret.rs:231 — the doc comment
  # that names the family in prose. If this ever fires, the guard would
  # demand an allowlist entry for its own rationale. (The citation read :196
  # when this guard landed, which was already stale: `SecretBytes::concat`,
  # added earlier in the SAME branch, had pushed it down by 35 lines. Line
  # citations in comments rot silently — grep the text, don't trust the
  # number.)
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

  # --- allowlist control: the RULE FIELD is load-bearing ---
  # `B.rs` holds an S2 hit. Its allowlist entry names rule S1 with the same
  # path and the same exact line, so it matches on every field EXCEPT the
  # rule. If `allowlisted` ever stopped comparing `$a_rule` to `$rule`, this
  # S2 hit would be silently exempted by an S1 entry — a whole rule
  # disarmable from another rule's allowlist section. Nothing in the tree
  # pinned that until now: this guard, the iOS guard and the Android guard
  # all share `lib/hygiene-allowlist.sh`, and every existing control in all
  # three uses a single rule id, so the comparison was free to be deleted
  # (verified by mutation: dropping it left every self-test green).
  local b_line='    let kept = ManuallyDrop::new(secret);'
  printf '%s\n' "$b_line" > "$d/core/src/B.rs"

  ALLOWLIST="$d/allowlist.txt"
  {
    # The real, exact-line exemption for line 1.
    printf '%s\t%s\t%s\t%s\n' "core/src/A.rs" S1 "$(trim "$a_keep")" 'self-test fixture: legitimate exact-line exemption'
    # A deliberately SHORT needle of the kind a substring allowlist would use.
    # Under exact-line matching it can never equal a full source line, so it
    # exempts nothing. Under substring matching it would exempt line 2 too —
    # which is what makes this pair DETECT the regression, not merely describe it.
    printf '%s\t%s\t%s\t%s\n' "core/src/A.rs" S1 'mem::take' 'self-test fixture: short needle, MUST be inert'
    # Right path, right line, WRONG rule. Must exempt nothing.
    printf '%s\t%s\t%s\t%s\n' "core/src/B.rs" S1 "$(trim "$b_line")" 'self-test fixture: wrong rule id, MUST be inert'
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
  grep -q "/B\.rs:1:" <<<"$hits" ||
    { echo "SELF-TEST FAILED: B.rs:1 (S2) was exempted by an S1 allowlist entry — is allowlisted() still comparing the rule field?" >&2; fails=1; }

  # Every declared root carries its own probe, so `scan_all` must report a hit
  # from each. This catches a root that is declared but never actually READ —
  # a broken loop, a bad path join. It deliberately does NOT claim to catch a
  # root DELETED from SCAN_ROOTS: this loop iterates SCAN_ROOTS, so the
  # assertion vanishes along with the entry (learned by mutation — truncating
  # SCAN_ROOTS to `core/src` left an earlier version of this loop green). That
  # case is caught by `check_roots_cover_workspace` against the manifest, and
  # by control E5 below.
  for root in "${SCAN_ROOTS[@]}"; do
    grep -q "/$root/ROOT_" <<<"$hits" ||
      { echo "SELF-TEST FAILED: declared scan root was not read: $root" >&2; fails=1; }
  done

  # --- entry-point controls: does a hit actually become a non-zero EXIT? ---
  # Everything above asserts on the TEXT `scan_all` returns. None of it runs
  # `run_guard`, so `return 1` could become `return 0` with both CI steps
  # green (verified by mutation) — the guard reduced to a no-op by the one
  # line that makes it a gate. These four run the real entry point.
  local gd="$d/entrypoint" saved_allowlist="$ALLOWLIST" rc
  mkdir -p "$gd"
  for root in "${SCAN_ROOTS[@]}"; do
    mkdir -p "$gd/$root"
    printf '%s\n' '    let s = Sensitive::new(buf);' > "$gd/$root/clean.rs"
  done
  # Synthetic manifest DERIVED from SCAN_ROOTS, so E1-E4 stay green whatever
  # the real root list is and only E5 exercises the coverage rule.
  write_manifest() {
    local extra="${1:-}" r
    {
      printf '[workspace]\nresolver = "2"\nmembers = [\n'
      for r in "${SCAN_ROOTS[@]}"; do printf '    "%s",\n' "${r%/src}"; done
      [[ -n "$extra" ]] && printf '    "%s",\n' "$extra"
      printf ']\n'
    } > "$gd/Cargo.toml"
  }
  write_manifest
  : > "$gd/allowlist.txt"
  ALLOWLIST="$gd/allowlist.txt"
  REPO_ROOT="$gd"

  # E1 — clean tree must exit 0.
  rc=0; run_guard >/dev/null 2>&1 || rc=$?
  [[ $rc -eq 0 ]] || { echo "SELF-TEST FAILED: run_guard exited $rc on a clean tree (expected 0)" >&2; fails=1; }

  # E2 — a planted violation must exit non-zero.
  printf '%s\n' '    std::mem::swap(slot, &mut plain);' > "$gd/core/src/violation.rs"
  rc=0; run_guard >/dev/null 2>&1 || rc=$?
  [[ $rc -ne 0 ]] || { echo "SELF-TEST FAILED: run_guard exited 0 despite a planted violation" >&2; fails=1; }
  rm -f "$gd/core/src/violation.rs"

  # E3 — a MISSING declared root must exit non-zero, not be skipped. This is
  # the fail-open the first version shipped: `[[ -d ]] || continue` made a
  # moved root contribute zero files and still print OK.
  mv "$gd/cli/src" "$gd/cli/src-renamed"
  rc=0; run_guard >/dev/null 2>&1 || rc=$?
  [[ $rc -ne 0 ]] || { echo "SELF-TEST FAILED: run_guard exited 0 with a MISSING scan root" >&2; fails=1; }
  mv "$gd/cli/src-renamed" "$gd/cli/src"

  # E4 — a root that EXISTS but holds no *.rs is the same silent exemption
  # without a rename, so it is fatal too.
  rm -f "$gd/cli/src/clean.rs"
  rc=0; run_guard >/dev/null 2>&1 || rc=$?
  [[ $rc -ne 0 ]] || { echo "SELF-TEST FAILED: run_guard exited 0 with an EMPTY scan root" >&2; fails=1; }
  printf '%s\n' '    let s = Sensitive::new(buf);' > "$gd/cli/src/clean.rs"

  # E5 — a workspace MEMBER with Rust sources that no scan root covers must
  # exit non-zero. This is the control for the defect that shipped in this
  # guard's first version, and unlike the per-root loop above it is NOT
  # derived from SCAN_ROOTS, so deleting a root cannot delete the check.
  mkdir -p "$gd/browser/unwatched-crate/src"
  printf '%s\n' '    let s = Sensitive::new(buf);' > "$gd/browser/unwatched-crate/src/lib.rs"
  write_manifest "browser/unwatched-crate"
  rc=0; run_guard >/dev/null 2>&1 || rc=$?
  [[ $rc -ne 0 ]] || { echo "SELF-TEST FAILED: run_guard exited 0 with an UNSCANNED workspace member" >&2; fails=1; }
  write_manifest

  # E6 — an unreadable or unparseable manifest must be fatal, not "zero
  # members, therefore full coverage". A parse that silently yields nothing
  # would disable E5 entirely.
  rm -f "$gd/Cargo.toml"
  rc=0; run_guard >/dev/null 2>&1 || rc=$?
  [[ $rc -ne 0 ]] || { echo "SELF-TEST FAILED: run_guard exited 0 with an UNPARSEABLE manifest" >&2; fails=1; }
  write_manifest

  # E7 — a `grep` that fails with exit >= 2 must be FATAL, not "no findings".
  # Provoked with a malformed ERE rather than an unreadable file, deliberately:
  # `chmod 000` is the natural probe but is a no-op for uid 0, and CI
  # containers routinely run as root, so a permissions-based control would
  # pass locally and be vacuous in the place it matters. A bad regex reaches
  # the same `rc > 1` branch on every uid. Subshell because the branch exits.
  rc=0; ( scan_rule "$gd/core/src" S1 '[' ) >/dev/null 2>&1 || rc=$?
  [[ $rc -eq 2 ]] ||
    { echo "SELF-TEST FAILED: a grep error (exit >=2) did not abort; got $rc" >&2; fails=1; }

  REPO_ROOT="$saved_root"
  ALLOWLIST="$saved_allowlist"

  if [[ $fails -eq 0 ]]; then
    echo "check-secret-slot-hygiene --self-test: OK (12 positive, 6 negative, 3 allowlist controls, ${#SCAN_ROOTS[@]} root probes, 7 entry-point controls)"
    return 0
  fi
  return 1
}

# An UNRECOGNISED argument must not fall through to the full guard. On a clean
# tree that prints an OK line and exits 0, so a typo in the CI wiring
# (`--self-tets`) reads exactly like a passing self-test — the distinguishing
# evidence is one word of output nobody reads. Same class as #496's typo'd
# `ControlExpectation` key silently degrading a control.
case "${1:-}" in
  --self-test) self_test ;;
  "")          run_guard ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
