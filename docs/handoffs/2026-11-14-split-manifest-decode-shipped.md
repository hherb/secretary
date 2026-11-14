# NEXT_SESSION.md: `codec/manifest_decode.py` split under 500 lines (#725)

Branch `refactor/split-manifest-decode`, worktree
`.worktrees/split-manifest-decode`, base `0ac76da6` (`main`, after #726
merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| (no commit) | #726 (#723) confirmed merged as `0ac76da6`; post-merge CI on `main` green. |
| `c58f7237` | #725: verbatim move of the manifest shape checks, floor re-measure, docs |
| (this commit) | This handoff + symlink retarget |

**The move.** `_check_uint`, `_check_fixed_bytes` and
`_validate_manifest_shape` (origin/main `manifest_decode.py` lines 335-460)
moved to the new `core/tests/python/conformance_lib/codec/manifest_shape.py`
(152 lines). `manifest_decode.py` went from 501 to 371 lines and imports the
function back. The call stays where it was, between the required-key check
and the sort checks, so no check is reordered. Nothing outside the file
imported the three names.

**Evidence that nothing changed:**
- The moved block `cmp`s byte-identical against `git show origin/main:` lines 335-460.
- A scratchpad script ran `diff_replay.replay_bytes` over all 185 committed
  inputs (`core/fuzz/seeds/*/*`, `core/tests/data/diff_regressions/*/*`).
  The before and after JSONL files are byte-identical, with 0 `error` verdicts.
- `conformance.py` stdout before and after differs in two lines only:
  DET's `20 -> 21 codec/ module(s)` and VT's `19 -> 20 codec/ modules scanned`.
- The Rust replay (`--features differential-replay --test differential_replay`)
  passed 70 tests and printed `manifest_body: 62 of 62 ... 44 committed strict`.

**Side edits:**
- Section VT's `MIN_SCANNED_CODEC_MODULES` went from 18 to 20, the measured
  count. It was already one behind before this slice: #698 added
  `codec/card_rules.py` without bumping it.
- RTV's docstring cited `manifest_decode.py:17` for the `manifest_encode`
  import. A one-line docstring addition moved that import to line 18, so the
  citation now says 18.
- CLAUDE.md: the package file count is now 82 (both places). The ranking now
  shows TWO files past 500 lines; `manifest_decode.py` is out of the top six,
  and `required_key_determinism.py` (390) is back in at sixth.
- ROADMAP has a new ✅ entry. README is untouched, since it does not
  describe the verifier's internals.

**Not run:** the mutation harness, which has nothing to mutate in a pure
move. Also not run: cargo clippy, rustdoc, the full workspace, since no Rust
changed. CI runs them.

## (2) What is next

1. **Merge this PR.** CI's replay step must still print
   `manifest_body: 62 of 62 ... 44 committed strict token comparison(s)`,
   and `clean-room conformance` must be green.
2. **#649**: `differential_replay.rs` is at 500 lines. The next addition to
   it must split it first. Acceptance: same test name set, same 70 tests.
3. **#683**: `sections/value_type_discipline.py` (849) and
   `sections/value_type_structure.py` (550) are the two remaining files over
   500 lines. Acceptance: the same verbatim-move discipline and byte-identical
   `conformance.py` output, apart from any counts that move.
4. **Nested non-map sweep** (carried over from #723): `codec/manifest_schema.py`
   still has untokened `ValueError` sites at nested positions. Measure them by
   planting a non-map or non-array at each nested known position and running
   both decoders. File an issue with the count.
5. **#677**: the `bundle_file` / `manifest_file` envelope sweep.
6. **#668 / #693**: report-order spec questions. These are spec decisions,
   so ask the user.
7. **#699, #701-#705**: card review residuals.

## (3) Open decisions / risks

- `MIN_SCANNED_CODEC_MODULES` is a floor, not an equality, so a new `codec/`
  module that nobody re-measures leaves it lax again. That is how it drifted
  to 18 while 19 modules were scanned.
- Carried over, unchanged: the nested non-map positions above, the
  label binding being Rust-test-side only, and §4.2 stating no order among
  interpretation-time checks.
- Worktrees: `.worktrees/block-seeds`, `.worktrees/not-a-map`,
  `.worktrees/pairwise-tolerance` and `.worktrees/strict-seeds` are all
  merged. There are also two detached `.claude/worktrees/` checkouts and the
  branch `backup-pre-reword-1787543234`. All were left alone; ask before
  deleting.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/split-manifest-decode
pwd && git branch --show-current     # refactor/split-manifest-decode
git fetch origin && git log --oneline HEAD..origin/main
uv run core/tests/python/conformance.py
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
