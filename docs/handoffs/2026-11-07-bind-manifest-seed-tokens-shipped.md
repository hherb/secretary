# NEXT_SESSION.md: single-fault manifest_body seeds bound to their token (#721)

Branch `test/bind-manifest-seed-tokens`, worktree
`.worktrees/strict-seeds`, base `ab87c729` (`main`, after #722 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| (no commit) | #722 confirmed merged as `ab87c729`. Its post-merge CI on `main` was still running at session start. |
| `06f98759` | #721: label binding, `judge_bound`, strict floor 26 → 43, docs |
| (this commit) | This handoff + symlink retarget |

**Code** (all under `core/tests/differential_replay_helpers/`):
- `seed_binding.rs` (new). `SeedBindings::load()` reads
  `manifest_canonicality_kat.json` and `manifest_uniqueness_kat.json`. Each
  REJECTING row binds its seed file (`<label>.bin`, or `uniq__<label>.bin`
  for uniqueness rows) to one token. For canonicality rows the token comes
  from `expect_cause`: `null` → `rule4_tag_or_float`, and an unknown cause
  name panics. Uniqueness rows bind to `repeated_array_value`. Only committed
  `manifest_body` inputs are bound, so the `diff_regressions/` multi-fault
  witnesses stay on the §4.2 pair relation.
- `agreement::judge_bound`. This is `judge`, plus one rule for a bound
  seed: an `Agree` becomes `Disagree` unless both sides named the bound
  token.
- `token_coverage::counts_toward_strict_floor` gains an `expected`
  argument. A bound seed counts as strict when both sides named its token,
  even a re-encode-visible one.
- `targets.rs`: `MIN_STRICT_COMPARISONS["manifest_body"]` 26 → **43**.
- `differential_replay.rs` loads the bindings once and calls the two new
  functions. A comment was shortened, so the file is still under the
  threshold at **499** lines.

**Tests added**: 5 in `seed_binding.rs`, including a census over the real
fixtures (all 24 bound names exist as seed files, 17 of them
re-encode-visible), 1 in `agreement.rs` and 1 in `token_coverage.rs`. The
replay binary runs 68 tests.

**Mutation evidence** (`scripts/mutate.py`, `--self-test` 20/20 first, exit
0, tree clean afterwards; spec in the session scratchpad as `m721.toml`):

| # | Mutation | Gate | Outcome | Reds |
|---|---|---|---|---|
| B1 | binding switched off (`if true \|\| ...`) | `--test differential_replay` | RED_AS_EXPECTED | `differential_replay_full_corpus` |
| R1 | Rust `ArraySortOrder` cause → `Rule2IndefiniteLength` token | same | RED_AS_EXPECTED | same |
| P1 | Python `ArraySortOrderViolation.token` → `repeated_array_value` | same | RED_AS_EXPECTED | same |

§4.2 frees both of the pairs R1 and P1 create, so `tokens_agree` excuses
them. That is why they would have stayed green before this slice. That
"before" was **not** measured on `main`. It follows from the pair-set test,
which pins both pairs as tolerated.

**Docs updated**: CLAUDE.md (the #646 tolerance bullet and the strict-count
passage), `RuleToken::is_phase_dependent` doc (`core/src/vault/manifest/token.rs`),
`differential-replay-protocol.md` and ROADMAP (new ✅ entry). README is
untouched, since it does not mention the replay tolerance.

**Gates run, all exit 0:**
- `cargo test --release --locked -p secretary-core` (56 binaries, 0 failed)
- the replay test (68 passed; `manifest_body: 61 of 61 ... 43 committed strict`)
- clippy `-p secretary-core --features differential-replay --tests -D warnings`
- rustdoc `-D warnings -p secretary-core`; `cargo fmt --all --check`
- `conformance.py` (35/35)

**Not run locally:** full-workspace test, clippy and rustdoc. Only
`core/tests/**`, one `core/src` doc comment and docs changed. CI runs the
rest.

## (2) What is next

1. **Merge this PR.** CI's replay step must print
   `manifest_body: 61 of 61 ... 43 committed strict token comparison(s)`.
2. **#649**: `differential_replay.rs` is at **499** lines. The next addition
   to it must split it. The tests stay in the entry file because their names
   are cited, so move loop logic into helpers instead.
3. **#677**: `bundle_file` / `manifest_file` value-type sweep. The first step
   is deciding what a sweep means for a binary envelope.
4. **#668 / #693**: report-order spec questions (block envelope + record;
   contact card). These are spec decisions, so ask the user.
5. **#699, #701-#705**: card review residuals.
6. **#723**: Python's non-map `manifest_body` rejection carries no token.

## (3) Open decisions / risks

- **The binding is Rust-test-side only.** Python's own section suite does
  not check a bound seed's token. The CI replay step checks both sides
  against the binding, so CI does cover it. Section RTV still checks the
  corpus token SET.
- Other single-fault `manifest_body` seeds are **not** label-bound:
  `valuetype__`, `wellformed__` and `nesting__`. Each is already strict (its
  token is not re-encode-visible) and is pinned by its own generator's Rust
  test. Binding them would need one table per generator, and nothing is
  excused today.
- §4.2 leaves the order among interpretation-time checks unstated. The
  harness compares those strictly, as parity rather than spec. This is
  unchanged.
- No tolerance witness's Rust token is pinned by a direct decode test. This
  is unchanged since #646 (see that handoff).
- `sections/value_type_discipline.py` is still 849 lines (#683).
- Worktrees: `.worktrees/block-seeds` (#720, merged),
  `.worktrees/pairwise-tolerance` (#722, merged), the two detached
  `.claude/worktrees/` checkouts, and branch `backup-pre-reword-1787543234`.
  All left alone; ask before deleting.
- The first scheduled `audit.yml` run on `main` is Mon 2026-11-09 06:00 UTC.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/strict-seeds
pwd && git branch --show-current     # test/bind-manifest-seed-tokens
git fetch origin && git log --oneline HEAD..origin/main
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
