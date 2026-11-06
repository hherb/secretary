# NEXT_SESSION.md — token-compared membership is derived, not only declared (#700)

Branch `test/pin-token-compared-membership`, worktree
`.worktrees/pin-token-compared`, base `86ee00c1` (`main`, after #714 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| `26060369` | Rust: `differential_replay_full_corpus` derives which targets must be token-compared; new `TOKEN_COMPARISON_BLOCKED` (`manifest_file`, #640); new pure module `differential_replay_helpers/token_coverage.rs` + 6 unit tests |
| `ccd7c2f6` | Python: Section VT's copy of `TOKEN_COMPARED_TARGETS` lacked `contact_card` (stale since #698); card rows now pin `wrong_type`; check 1 flags a token-less row whose decoder names a rule |
| `3bf5dc7c` | ROADMAP entry + three CLAUDE.md passages |
| (this commit) | This handoff + symlink retarget |

**How it works.** For each target the corpus loop counts reject-vs-reject
pairs and how many carried a rule token on BOTH sides. If every pair was
tokened (and there was at least one), the target must be in
`TOKEN_COMPARED_TARGETS` or in `TOKEN_COMPARISON_BLOCKED`, or the test reds.
This is derived from capability, not a pinned literal list, so a new target
does not red until it can actually be compared. The reverse direction
(a compared target rejecting without a token) was already a harness failure
in `agreement::judge`.

**Measured, per target, committed corpus** (Python side; Rust agrees on the
four compared ones, or the replay would fail):
`record` 40/40 rejects tokened, `contact_card` 22/22, `manifest_body` 43/43,
`block_file` 23/23, `vault_toml` 0/7, `bundle_file` and `manifest_file` have
no committed rejection at all.

**Mutation evidence (`scripts/mutate.py`, every row RED_AS_EXPECTED, tree
restored, exit 0):**
- `M_contact_card`, `M_record`, `M_block_file`: move the target from the
  compared list to the NOT list → `differential_replay_full_corpus` reds.
  Committed corpus only, i.e. CI conditions.
- `M_unblock_manifest_file`: empty `TOKEN_COMPARISON_BLOCKED` with `main`'s
  fuzz corpus symlinked in → reds. So the #640 entry is load-bearing on a
  fuzzed checkout. Without the runtime corpus it is not exercised (see (3)).
- `P_pre700_state`: restore the pre-fix Python (mirror without
  `contact_card`, card rows `token=None`) → Section VT reds. It was green on
  `main`.

**Gates run:** `differential_replay` 52/52 (46 before + 6 new);
`conformance.py` exit 0, all 35 sections pass; `cargo fmt --check`;
`cargo clippy --release --workspace --tests -D warnings`; clippy with
`--features differential-replay --tests`; rustdoc `-D warnings` on
`secretary-core`; `mutate.py --self-test` 20/20. The full
`cargo test --workspace` was NOT run locally: the change touches only the
feature-gated `differential_replay` test crate and one conformance section,
so CI covers it.

**Housekeeping, before the code:**
- `main` would not pull: an untracked `.vscode/settings.json` (identical to
  #714's) blocked the fast-forward. Removed; `main` at `86ee00c1`.
- Dependabot alerts 82, 87, 89 dismissed as `tolerable_risk` with the
  rationale from the #714 handoff. No open npm alerts remain.
- Closed #709, #707, #659 with comments naming their fixes.
- Removed 10 merged worktrees and 12 merged local branches (remotes untouched).
- `main`'s Tests run for #713 failed on an apt timeout (Tauri deps), not a
  test; failed job re-run.

## (2) What is next

1. **Merge this PR.** Acceptance: CI green, including `cargo test
   (ubuntu-latest)` (the replay step) and `clean-room conformance`. Then
   close #700 with a comment pointing here.
2. **#657: nothing pins the CI step that runs the replay.** This PR's guard
   only works if the step runs. Acceptance: deleting or renaming the
   `differential_replay` step in `.github/workflows/test.yml` reds a check
   (e.g. a small script that parses the workflow YAML, `--self-test` first,
   wired into `test.yml`).
3. **#658: floor strict token comparisons, not just inputs replayed.**
   Acceptance: on `manifest_body`, routing more inputs onto tolerated pairs
   reds a named test. The `TokenCoverage` counters added here are a natural
   place to count strict comparisons too.
4. **#641 (`bundle_file`, `vault_toml`)**: needs Rust taxonomies.
   `differential_replay_full_corpus` will now tell you when a target is ready:
   as soon as every rejection carries tokens on both sides it reds until the
   target is moved into `TOKEN_COMPARED_TARGETS`.
5. Card review residuals #699, #701–#705 and the #693 spec question are
   unchanged (see `docs/handoffs/2026-09-22-token-compare-contact-card-shipped.md`
   §6).

## (3) Open decisions / risks

- **The `manifest_file` blocked entry is invisible to CI.** CI replays only
  the committed corpus, which holds no `manifest_file` rejection, so CI can
  delete that entry without red. It only matters on a fuzzed checkout, where
  it was measured to be needed. Adding a committed `manifest_file` reject
  seed would make CI see it, but #640's own granularity problem means the
  seed's tokens would differ by design. Left as is and documented in
  `targets.rs`.
- **The rule is "every pair tokened".** A target that is partly tokened
  (mid-migration) is not flagged, which is deliberate. A single stray
  untokened rejection on a fully-migrated target therefore silences the
  check for that target. For a compared target that case is already a
  harness failure, so the gap only affects a target that is not compared yet.
- `sections/value_type_discipline.py` is still over the 500-line threshold
  (net +14 here). Splitting it is unchanged backlog, not new debt.
- `.worktrees/` still holds two unregistered folders,
  `d5-macos-mutation` and `d5-macos-trash-settings` (not git worktrees, not
  touched). Also left: branch `backup-pre-reword-1787543234` and two detached
  checkouts under `.claude/worktrees/`. Ask before deleting.
- First scheduled `audit.yml` on `main` is Mon 2026-11-09 06:00 UTC, still
  the only live evidence for #707's `schedule` arm.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/pin-token-compared
pwd && git branch --show-current     # test/pin-token-compared-membership
git fetch origin && git log --oneline HEAD..origin/main
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py
# mutation specs used here live in the session scratchpad; rebuild from (1)
```

For #657 / #658 start a fresh worktree from `origin/main` once this merges.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it,
retargeted in the same commit as this file's creation.
