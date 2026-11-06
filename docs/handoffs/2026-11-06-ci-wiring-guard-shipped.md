# NEXT_SESSION.md — CI gates pinned as steps (#657)

Branch `test/ci-wiring-guard`, worktree `.worktrees/ci-wiring`, base
`be94ca79` (`main`, after #715 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| `ba632943` | `scripts/check-ci-wiring.py` + new `ci wiring` job in `test.yml`; the replay step's "#657 unpinned" comment updated |
| `4d3db42d` | CLAUDE.md (Commands block + the replay bullet), ROADMAP entry |
| `a858fe97` | This handoff + symlink retarget |
| (fix wave) | PR #716 review fixes, below |

**How it works.** `REQUIRED_STEPS` is a 23-row table of (workflow, job id,
command, env). The guard parses `test.yml` and `rust-lint.yml` with PyYAML
(exact-pinned `6.0.3` in the PEP 723 header) and, per row, requires: a
`pull_request` trigger with no branch/path filter; the job present with no
job-level `if:` or `continue-on-error`; a Linux runner (`ubuntu-*` label or
`${{ matrix.os }}` over a plain list holding one, anything else fails closed);
a `run:` step whose whitespace-collapsed command equals the row exactly; that
step not `continue-on-error` and its `if:` absent or `runner.os == 'Linux'`;
and any env pair the row names (only `RUSTDOCFLAGS` on `doc`). Findings carry a
reason token (`no_step`, `step_condition`, ...).

`--self-test` edits an in-memory fixture (no file writes), 21 controls (3
negative, 18 positive), checks every reason token has a positive control, and
an edit that matches the fixture zero or 2+ times is a broken control.

**Mutation evidence (`scripts/mutate.py`, all RED_AS_EXPECTED, exit 0, tree
restored):**
- Real workflows, gate `uv run scripts/check-ci-wiring.py`: W1 delete the
  replay step (`no_step`), W2 rename its `--test` target (`no_step`), W3
  `if: false` (`step_condition`), W4 `rust-test` matrix drops `ubuntu-latest`
  (`no_linux_runner`), W5 `RUSTDOCFLAGS: ''` (`env`).
- The guard itself, gate `--self-test`: G1 step-condition check off (P5 reds),
  G2 exact match weakened to substring (P4 reds), G3 trigger check off
  (P12, P13 red).

**PR #716 review fix wave.** Four reviewers found the guard fail-open in
three ways and its docs overclaiming in three more; all fixed in this PR:
- `shell: 'true {0}'` (step, job or workflow `defaults.run`) and
  `working-directory:` turned a pinned step into a green no-op with the guard
  printing OK. New reason `run_override`.
- A row's job behind `needs:` on a skipped job is skipped green. New reason
  `needs` (fail closed on any `needs:`; no row's job has one).
- `runner.os == 'Linux'` was allowed on every row, so adding it to a matrixed
  `doc`/`clippy`/`test` step silently dropped the macOS leg. Now allowed only
  on rows marked `linux_only` (the replay test and its clippy twin).
- `--self-test` never drove `run_real_check`/`main`: `if findings:` ->
  `if False:`, an empty table and `main([])` dispatching elsewhere all stayed
  green. End-to-end checks E1-E5 now run `run_check` on a mktemp tree and the
  CLI dispatch; the OK line counts rows that RAN, not the table size.
- `pull_request: types:` added to `SKIPPING_TRIGGER_KEYS`; a non-mapping
  `env:` is an `env` finding, not a traceback; `Finding` refuses a reason not
  in `ALL_REASONS`; controls for list/str `on:`, every skipping key (spelled
  out, so dropping one from the set reds), expression `continue-on-error`,
  `if: false` jobs, workflow-level env, `|` blocks, missing `jobs:`.
- Docs: "renaming the step reds" was false (`name:` is never read); "is a
  required status check" was false (`ci wiring` is not in `protect_main`);
  LIMITS now name the two-workflow scope, the unpinned table, and the real
  platform job ids.
- 561 lines after the fixes, so split: `scripts/check-ci-wiring.py` (header
  + entrypoint), `scripts/ci_wiring/rules.py` (290), `selftest.py` (~210).
- Evidence: `scripts/mutate.py` (launched `uv run --with pyyaml==6.0.3`), 9
  rows M1-M9 over `rules.py`, gate `--self-test`, all RED_AS_EXPECTED, exit 0:
  needs check off (P11), run-override off (P22-P25), `linux_only` ignored
  (P6), `if findings:` off (E2), ran-floor off (E3), `types` dropped (P18),
  non-mapping env guard off (P21), `main([])` -> self-test (E5),
  `is_set_true` -> `is True` (P7). On copies of the real workflows, the
  `shell:`, `needs:` and Linux-gate-on-`fmt` attacks each red with the named
  reason. `--self-test`: 44/44 checks.

**Gates run (first pass):** `check-ci-wiring.py --self-test` and real (OK, 23 rows / 2
workflows); `actionlint` on `test.yml`; `mutate.py --self-test` 20/20. No Rust
or conformance code changed, so cargo/conformance were not re-run.

## (2) What is next

1. **Merge this PR**, then **add `ci wiring` to `main`'s `protect_main`
   ruleset required contexts** (asked of the user; not done yet). Without it,
   deleting the `ci-wiring` job itself reds nothing. Acceptance:
   `gh api repos/hherb/secretary/rules/branches/main` lists `ci wiring`. Then
   close #657 with a comment pointing here.
2. **#658: floor strict token comparisons, not just inputs replayed.**
   Acceptance: on `manifest_body`, routing more inputs onto tolerated pairs
   reds a named test. The `TokenCoverage` counters from #700 are the natural
   place to count strict comparisons.
3. **#641 (`bundle_file`, `vault_toml`)**: needs Rust taxonomies;
   `differential_replay_full_corpus` reds when a target becomes ready.
4. Card review residuals #699, #701-#705 and the #693 spec question are
   unchanged (see `docs/handoffs/2026-09-22-token-compare-contact-card-shipped.md` §6).

## (3) Open decisions / risks

- **Self-pinning.** The guard cannot see its own deletion. The ruleset entry
  in (2).1 is the only thing that closes that; a ruleset change is outward-
  facing, so it waits for the user.
- **Scope.** Linux reachability only; a dropped macOS matrix leg is caught
  only by its required context never reporting. Platform jobs
  (`desktop-test`, `swift-conformance`, `kotlin-conformance`, `ios-host`,
  `android-host`) are not rows; they are required contexts, so deleting the
  job is caught but emptying its steps is not. `codeql.yml`, `audit.yml`,
  `macos-host.yml`, `ios-tsan.yml` are not covered.
- **A new CI gate needs a new row.** The table is hand-maintained; forgetting
  a row leaves that gate exactly as unpinned as #657 was. Noted in CLAUDE.md's
  Commands block.
- `sections/value_type_discipline.py` (849 lines) still over the 500-line
  threshold; unchanged backlog.
- `.worktrees/` still holds `d5-macos-mutation`, `d5-macos-trash-settings`
  (unregistered folders), the merged `pin-token-compared` worktree, branch
  `backup-pre-reword-1787543234`, two detached `.claude/worktrees/` checkouts.
  Ask before deleting.
- First scheduled `audit.yml` run on `main` is Mon 2026-11-09 06:00 UTC, still
  the only live evidence for #707's `schedule` arm.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/ci-wiring
pwd && git branch --show-current     # test/ci-wiring-guard
git fetch origin && git log --oneline HEAD..origin/main
uv run scripts/check-ci-wiring.py --self-test
uv run scripts/check-ci-wiring.py
# mutation specs used here lived in the session scratchpad; rebuild from (1)
```

For #658 start a fresh worktree from `origin/main` once this merges.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit as this file's creation.
