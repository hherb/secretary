# NEXT_SESSION.md: an N-way merge ticks once (#751)

Branch `feature/nway-merge-tick-once`, worktree
`.worktrees/nway-merge-tick-once`, base `4c84d21b` (`main`, the #757
merge). The PR is open; see `gh pr list --head feature/nway-merge-tick-once`.

At session start: #757 (the previous baton's PR) had merged. Its worktree
`.worktrees/sync-device-uuid-tests` and branch were removed.

## (1) What shipped

| SHA | What |
|---|---|
| `9e964873` | **Spec.** crypto-design §11.2 gets an "N-way merge" paragraph. A merge that folds three or more copies is one merge event: take the max over every folded copy, then add `+1` once for the merging device, only if some fold step was concurrent. Each step's relation is taken against the unticked running max. The manifest is likewise ticked once. |
| `11f5f55a` | **Code + tests.** `prepare_merge` (`core/src/sync/prepare.rs`) keeps the unticked running max as its accumulator and ticks once after the fold. `merge_block` is unchanged, and `prepare_merge` is its only production caller. The new `merge_error` helper replaces the inline error closure, so the post-fold tick maps a clock overflow the same way the fold does. Two tests are added in `core/tests/sync_merge_tick.rs`, plus `sync_helpers::add_concurrent_block_sibling` and `BLOCK_NONCE_G`. |
| (this commit) | ROADMAP entry, README clause, this handoff, and the symlink retarget. |

**Tests:**
- `a_three_way_block_merge_ticks_the_merging_device_once`: a canonical
  copy and two concurrent siblings. It was red on the old code with
  `MERGING_DEVICE: 2`; it now expects 1 on both the block and the
  manifest clock.
- `a_dominated_block_fold_adopts_the_dominating_clock_untouched`: the
  sibling block strictly dominates the canonical one, so the block clock
  is the sibling's unchanged and gets no tick. The manifest still gets
  its one tick.

**Mutations** (`scripts/mutate.py`, self-test 20/20; the specs are in the
session scratchpad, not committed):

| Mutation | Gate | Outcome |
|---|---|---|
| M1: delete the post-fold tick | `cargo test --release -p secretary-core --no-fail-fast` | `RED_AS_EXPECTED` (the 2-way and 3-way block tests) |
| M2: `if any_concurrent` → `if true` | same, whole `secretary-core` | **`UNEXPECTED_GREEN`**: nothing pinned the guard |
| M2, re-run after the dominated-fold test was added | `--test sync_merge_tick` | `RED_AS_EXPECTED` (the new test alone) |

**KAT and conformance:** all 12 `conflict_kat.json` vectors and
`conformance_lib/merge/` are 2-way (`local`/`remote`). None of them models
`prepare_merge`'s N-way fold, so no regeneration was needed.

**Gates run, each exit 0:**
- `cargo test --release --workspace`: 108 binaries, before the second test
  was added. After it was added, `sync_merge_tick`, `sync_merge`,
  `sync_merge_vetoes`, `sync_kat` and `convergence` were re-run, all green.
- `cargo fmt --all --check`
- `cargo clippy --release --workspace --tests -- -D warnings` (after the
  last edit)
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`
- `uv run core/tests/python/conformance.py`: 35/35 sections

**Not clean, and not caused by this branch:**
`spec_test_name_freshness.py` exits 1 with 102 unresolved citations on
`main` too. That is tracked by #642; I commented the new count there. No
workflow runs it.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green.
2. **Manual GUI pass** (needs the user at the devices; carried over from
   #752):
   - Poison a device: sync a vault copy once, restore an older
     `manifest.cbor.enc`, then unlock.
   - The reset prompt should appear, and "Reset and open" should open the
     vault.
   - Desktop and Android have also never had the #745 pass.
3. **#737 / #729: size caps.** #737 now also lists `core/src/sync/prepare.rs`
   (964 → 984 here). Acceptance: move its two in-file test modules to
   `prepare/tests.rs` with an unchanged test-name set. #95 tracks
   `core/tests/sync_helpers/mod.rs` (now 1248 lines).
4. **Carried over:** #753, #754, #755, #756, #736, #734, #740 / #741 /
   #742, #747 / #748, #738, #731, #649, #683, #677, #668 / #693 (spec
   questions) and #699 / #701-#705.

## (3) Open decisions and risks

- **The fold's step relations changed, not only the tick count.** Before,
  step k compared against the *ticked* accumulator. A later copy that
  dominated every earlier copy was still Concurrent, because of the
  merging device's synthetic tick, and was merged record by record. Now it
  is `IncomingDominates`, and its plaintext is adopted, which is what the
  2-way rule already does. This is causally right: a copy dominating all
  the others has observed them. But no test pins the plaintext in that
  case. §11.2 now states the rule normatively.
- **Fold-order independence is not established.** For more than two copies,
  nothing tests that the merged plaintext and clock are the same in every
  copy order. The clock is (max plus a guarded tick). The plaintext is
  likely order-independent through the record CRDT, but that is unproven
  once dominance adoption mixes with concurrent merges.
- **The clean-room verifier does not model the N-way fold.** The new
  §11.2 paragraph is checked only by the Rust tests above.
- **#751 is closed in code.** The issue stays open until a human closes
  it.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/nway-merge-tick-once
pwd && git branch --show-current     # feature/nway-merge-tick-once
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/nway-merge-tick-once --json number -q '.[0].number')"
cargo test --release -p secretary-core --test sync_merge_tick
```

If the PR has merged, remove the worktree and branch, then start the next
item from `main`.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
