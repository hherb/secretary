# NEXT_SESSION.md: a sync commit writes the merged block whole (#759)

Branch `feature/merge-plaintext-clock`, worktree
`.worktrees/merge-plaintext-clock`, base `5e9add4d` (`main`, the #758
merge). The PR is open; see `gh pr list --head feature/merge-plaintext-clock`.

At session start: #758 (the previous baton's PR) had merged. Its worktree
`.worktrees/nway-merge-tick-once` and branch were removed.

## (1) What shipped

| SHA | What |
|---|---|
| `2d0e5a5b` | **Spec + code + tests.** crypto-design §11.2 gains a "Writing a merge" paragraph. `DraftMerge` gains `per_block_meta` (`MergedBlockMeta`: merged `block_name`, merged `unknown`, `adopted_copy_clock`). `prepare_merge` now advances `block_name` through the fold. `commit_with_decisions` writes the merged name and `unknown`, sets the manifest `BlockEntry.block_name`, and computes each written block clock in `written_block_clocks` before any file write. |
| `0aaae449` | ROADMAP entry and README clause. |
| (this commit) | This handoff and the symlink retarget. |

**The bug, as fixed.** The commit rebuilt each merged block with an empty
`unknown` map and the canonical `block_name`, so a v2 client's block-level
keys were lost on the first v1 sync merge. When the fold adopted one copy
whole (no tick), a `KeepLocal` decision also wrote changed records under
that copy's untouched clock, so two devices held different plaintexts
under one clock. The rule now is:
- a `KeepLocal` on a block whose fold adopted a copy ticks the merging
  device once;
- `AcceptTombstone` on that block does not tick;
- a fold that already ticked gets no second tick.

**Tests** (`core/tests/sync_merge_write.rs`, new):
- `the_merged_block_name_and_unknown_keys_are_written`: a third copy with
  a new name and an `unknown` key, once dominating (adopted, clock
  untouched) and once concurrent (ticked once). Disk plaintext name,
  `unknown` and manifest name are all asserted. It was red on the old code
  (`left: {}`).
- `a_keep_local_ticks_the_merging_device_once_per_block`: three cases.
  Adopted + KeepLocal ticks, adopted + AcceptTombstone does not, and
  concurrent + KeepLocal ticks exactly once. It was red on the old code
  (no `MERGING_DEVICE` entry).
- New fixture step: `sync_helpers::add_block_sibling_with_meta`.
  `add_concurrent_block_sibling` now delegates to it, and the
  block-encrypt helper takes an `unknown` map.

**Mutations** (`scripts/mutate.py`, self-test 20/20; the spec is in the
session scratchpad, not committed). The gate is `cargo test --release
--locked -p secretary-core --no-fail-fast --test sync_merge_write --test
sync_merge_tick --test sync_merge_vetoes --test sync_kat --test
convergence`:

| Mutation | Outcome |
|---|---|
| W1: keep-local tick → `if false` | `RED_AS_EXPECTED` |
| W2: drop the `adopted_copy_clock` guard | **`UNEXPECTED_GREEN`** on the first run. The concurrent + KeepLocal case was then added, and a re-run (`--test sync_merge_write`) went `RED_AS_EXPECTED` |
| W3: tick every adopted block, decision or not | `RED_AS_EXPECTED` |
| W4: write an empty `unknown` | `RED_AS_EXPECTED` |
| W5: drop the manifest `block_name` update | `RED_AS_EXPECTED` |
| W6: drop `acc_block_name` advancing in the fold | `RED_AS_EXPECTED` |

**KAT and conformance:** every existing `KeepLocal` vector (`sync_kat.json`,
`convergence.rs`) is a concurrent fold, so its clock is unchanged and
nothing was regenerated. `conformance_lib` does not model the commit, so the
new §11.2 paragraph is checked only by the Rust tests.

**Gates run, each exit 0:**
- `cargo test --release --workspace` (109 binaries, before the third
  keep-local case; `sync_merge_write` re-run after it)
- `cargo clippy --release --workspace --tests -- -D warnings` (after the
  last edit)
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`
- `cargo fmt --all --check`
- `uv run core/tests/python/conformance.py`: PASS

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green.
2. **#761 (new, needs a ruling)**: the commit still writes
   `block_version` / `schema_version` as 1, and the fold never advances
   them, though §11.2 says max and the decoder accepts any `u32`. The issue
   names two options. Either the writer may emit the merged max, so it is
   carried on `MergedBlockMeta` and written. Or it may not, so the merge
   refuses with a typed error. Acceptance: a test with a
   `block_version: 2` copy that pins whichever is chosen.
3. **Manual GUI pass** (needs the user at the devices; carried over from
   #752). Poison a device: sync once, restore an older
   `manifest.cbor.enc`, then unlock. The reset prompt should appear, and
   "Reset and open" should open the vault. Desktop and Android have also
   never had the #745 pass.
4. **#737 / #95: size caps.** `core/src/sync/prepare.rs` is 1011 lines.
   Acceptance: move its in-file test modules to `prepare/tests.rs` with an
   unchanged test-name set. `core/tests/sync_helpers/mod.rs` is 1292 lines
   (#95). Both issues have the new counts.
5. **Carried over:** #753, #754, #755, #756, #736, #734, #740 / #741 /
   #742, #747 / #748, #738, #731, #649, #683, #677, #668 / #693 (spec
   questions) and #699 / #701-#705.

## (3) Open decisions and risks

- **Any `KeepLocal` on an adopted block ticks, whether or not the record
  changed.** A spurious tick is safe: the invariant only needs "no tick ⇒
  identical plaintext". On an adopted block the veto's record is always
  the copy's tombstoned one, so the restore always changes it.
- **A crash between block and manifest writes, followed by a retry with a
  different decision, rewrites a fold-ticked block under the same clock.**
  The first write never committed (the manifest is the commit point), so
  it is residue, not a second committed plaintext. This predates #759.
- **#761**: the version downgrade above.
- **#751 / #759 are closed in code.** Their issues stay open until a human
  closes them.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/merge-plaintext-clock
pwd && git branch --show-current     # feature/merge-plaintext-clock
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/merge-plaintext-clock --json number -q '.[0].number')"
cargo test --release -p secretary-core --test sync_merge_write --test sync_merge_tick
```

If the PR has merged, remove the worktree and branch, then start the next
item from `main`.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
