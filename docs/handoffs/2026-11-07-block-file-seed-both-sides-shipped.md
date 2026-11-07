# NEXT_SESSION.md — `block_file` equality checks seeded on both sides (#719)

Branch `test/block-file-seed-both-sides`, worktree `.worktrees/block-seeds`,
base `37283d29` (`main`, after #718 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| (no commit) | #718 confirmed merged; its CI replay step printed `bundle_file: 14 of 14 ... 13 committed strict token comparison(s)`. Post-merge `Tests` on `main` sat queued for ~10 h, then finished green. |
| (no commit) | #641 **closed without `vault_toml`** (user decision). Reasoning is in the issue comment: the target is cleartext and never re-encoded, accept-versus-reject is already compared, and Section VT already requires each rejection to name the position. A token would add only a both-reject which-rule check. |
| (no commit) | Removed the merged worktrees `pin-token-compared`, `ci-wiring`, `strict-floor` and `bundle-tokens`, plus their four local branches (user OK'd merged ones only). |
| `268535ff` | #719: 5 twin seeds, RTS class table + floor, replay floors, CLAUDE.md + ROADMAP |
| `02d2cbb1` | This handoff + symlink retarget |
| `e06ccf4f` | CLAUDE.md top-six re-rank |
| (review fix) | `/finalcheck` review fixes, below |

**The gap.** Every `block_file` seed planted `file_kind`, `format_version`
and `suite_id` at `+ 1` and the two signature lengths at `- 1`. Both decoders
check equality, so a check loosened toward the unseeded side accepted every
value there, with every gate green.

**The fix** (`core/tests/rule_token_seeds_helpers/block_file.rs`): add
`wrong_file_kind_below`, `format_version_below`, `suite_id_below`,
`wrong_sig_ed_len_above` and `wrong_sig_pq_len_above`, generated with
`generate_rule_token_seeds`. The 23 existing seeds came out byte-identical.
Section RTS's `_BLOCK_FILE_CLASSES` pins each new seed's Python class, and its
`_TARGETS` floor goes 23 → 28. `targets.rs` goes to `MIN_CORPUS_INPUTS` 29 and
`MIN_STRICT_COMPARISONS` 28. The committed replay corpus goes 173 → 178
(re-measured with the `ls | wc -l` recipe in CLAUDE.md).

**Mutation evidence** (`scripts/mutate.py`; `--self-test` 20/20 first; exit
0, all `RED_AS_EXPECTED`, tree clean afterwards). Each check was loosened
toward the side only its new seed covers (`!=` → `>` for the header fields,
`!=` → `<` for the signature lengths):

| # | Check | Python gate (`conformance.py`) | Rust gate (`--test rule_token_seeds`) |
|---|---|---|---|
| FV | `format_version` | Section RTS | `rule_token_seeds_are_committed_and_label_bound` |
| SU | `suite_id` | Section RTS | same |
| FK | `file_kind` | Section RTS | same |
| SE | `sig_ed_len` | Section RTS | same |
| SP | `sig_pq_len` | Section RTS | same |

These mutations were **not** re-run on the base to show they were green
there. #719 states the gap from reading the seeds, and #718 measured the
identical shape for `bundle_file`.

**Review fixes (`/finalcheck`, PR #720).** Two reviewers (code, test
coverage). Findings and what was done:

- **`magic` was a sixth one-sided equality check**, on `bundle_file` too
  (#718 missed it). `bad_magic` XORs the first byte, giving `0xAC454352`,
  which is above `MAGIC`, so `!=` → `>` stayed green. Added
  `container_malformed__bad_magic_below` on both targets.
- **Nothing bound a twin's name to its side.** New test
  `every_equality_check_is_seeded_on_both_sides` (`rule_token_seeds.rs`).
  Each helper module's `equality_check` reads `found` and the v1 value off
  the decoder's own error. The test reds a check seeded on one side only, a
  missing check from the `EQUALITY_CHECKS` census, or a `_below`/`_above` row
  on the wrong side.
- **No `block_file` seed reached `decode_aead_section`'s past-end check.**
  Added `container_malformed__aead_ct_len_exceeds_file` (`Truncated` /
  Python `ParseError`).
- **A stale class row (no seed file) was silently ignored.** Section RTS now
  reports it.
- **`rule_token_seeds.py` would have crossed 500 lines.** Its class tables
  moved to `sections/rule_token_seed_classes.py` (133 lines;
  `rule_token_seeds.py` is now 382). The package is 81 files.
- **CLAUDE.md's lead ranking omitted `rule_token_seeds.py`.** This is moot
  after the split, which took that file out of the top six. Both rankings
  now read 849 / 550 / 498 / 492 / 491 / 479 (`scanner.py` back in).

Floors: `block_file` 31 inputs / 30 strict and RTS 30; `bundle_file` 15 / 14
and RTS 14. The committed corpus is 181. All existing seeds came out
byte-identical.

Review mutations (`scripts/mutate.py`, `--self-test` 20/20, exit 0, all
`RED_AS_EXPECTED`, tree clean): P-MB/R-MB (block `magic` `!=` → `>`, Python /
Rust), P-MU/R-MU (the same on bundle), T-DIR (`bad_magic_below` planting
`MAGIC + 1` reds the new both-sides test), P-STALE (a class row with no seed
reds RTS). The `magic` rows were not run on the base. The gap was read off
the seed bytes (`xxd`: `ac454352`).

**Gates run, all exit 0:**
- `cargo test --release --locked -p secretary-core` (56 binaries, all ok)
- the replay test (60 passed; `block_file: 29 of 29 ... 28 committed strict`)
- clippy `-p secretary-core --features differential-replay --tests -D warnings`
- `cargo fmt --all --check`
- `conformance.py` (35/35 registered; RTS `block_file: 28 labelled seeds ... 28 classes checked`)

**Not run locally:** full-workspace test/clippy and rustdoc. Only
`core/tests/**`, Python and docs changed; CI runs them.

## (2) What is next

1. **Merge this PR.** CI's `cargo test (ubuntu-latest)` replay step must
   print `block_file: 31 of 31 ... 30 committed strict token comparison(s)`
   and `bundle_file: 15 of 15 ... 14`.
2. **#646**: narrowing the per-token tolerance on `manifest_body`.
   Acceptance: the §4.2 decisions it needs are written into `docs/` first,
   then `tokens_agree` is narrowed to match, and the `manifest_body` strict
   floor rises above 25. Biggest open item in this area.
3. **#677**: `bundle_file` / `manifest_file` value-type sweep. The
   substitution method doesn't fit a binary envelope, so the first step is
   deciding what a sweep even means there.
4. **#668 / #693**: spec questions on report order (block envelope + record;
   contact card). Spec decisions, so ask the user.
5. **#699, #701-#705**: card review residuals, unchanged.
6. **#649**: `core/tests/differential_replay.rs` is past 500 lines. A small
   split slice.

## (3) Open decisions / risks

- **`vault_toml` stays loose by decision**, not by omission. It remains in
  `NOT_TOKEN_COMPARED_TARGETS`. #700's derived-membership check would red if
  both decoders ever became fully tokened without moving it.
- `sections/rule_token_seeds.py` was split in the review (class tables now
  in `sections/rule_token_seed_classes.py`). It is 382 lines, out of the top
  six. Re-measure at merge.
- `sections/value_type_discipline.py` is still 849 lines (backlog, #683).
- Remaining worktrees: the two detached `.claude/worktrees/` checkouts and
  branch `backup-pre-reword-1787543234`. Left alone; ask before deleting.
- The first scheduled `audit.yml` run on `main` is Mon 2026-11-09 06:00 UTC,
  still the only live evidence for #707's `schedule` arm.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/block-seeds
pwd && git branch --show-current     # test/block-file-seed-both-sides
git fetch origin && git log --oneline HEAD..origin/main
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py
# mutation spec: the session scratchpad's m719.toml; rebuild from the table in (1)
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
