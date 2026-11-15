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
| `d637b36f` | ROADMAP entry, README clause, this handoff, and the symlink retarget. |
| (review fix commit) | **PR #758 review.** The tick rule was fold-order dependent: keyed on "some step was concurrent", a copy dominating all the others got ticked when it folded after a concurrent pair and not when it folded first (traced by two reviewers, then measured as mutation T4 below). The tick now fires iff the final max is no single folded copy's clock, a function of the set of copies. The §11.2 paragraph says so, and the §11.2 `vector_clock` row now states the 2-way rule the paragraph leaned on (concurrent: max then `+1`; equal or dominated: adopt that side whole, no tick), which matches `merge_block` and Python's `py_merge_block`. Two tests are added, record sets are asserted, and the helper docs are corrected. CLAUDE.md and README now say 12 conflict KATs, not 11. Issue #759 was filed (below). |

**Tests:**
- `a_three_way_block_merge_ticks_the_merging_device_once`: a canonical
  copy and two concurrent siblings. It was red on the old code with
  `MERGING_DEVICE: 2`; it now expects 1 on both the block and the
  manifest clock.
- `a_dominated_block_fold_adopts_the_dominating_clock_untouched`: the
  sibling block strictly dominates the canonical one, so the block clock
  is the sibling's unchanged and gets no tick. The manifest still gets
  its one tick.
- `a_dominating_copy_is_adopted_untouched_in_either_fold_order` (review):
  canonical `{C1}`, one concurrent copy `{S1}`, and one copy `{C1,S1,E1}`
  dominating both, folded both ways round. The block clock is exactly
  `{C1,S1,E1}` and the records are the dominating copy's (0xAA keeps its
  older `last_mod` 50, which per-field LWW would have overridden).
- `a_merge_tick_that_overflows_is_a_typed_clock_overflow` (review): a
  merging-device counter at `u64::MAX` surfaces as
  `SyncError::Vault(VaultError::ClockOverflow)`, not `InvalidArgument`.
- The three-way test now also asserts all three records survive.

**Mutations** (`scripts/mutate.py`, self-test 20/20; the specs are in the
session scratchpad, not committed):

| Mutation | Gate | Outcome |
|---|---|---|
| M1: delete the post-fold tick | `cargo test --release -p secretary-core --no-fail-fast` | `RED_AS_EXPECTED` (the 2-way and 3-way block tests) |
| M2: `if any_concurrent` → `if true` | same, whole `secretary-core` | **`UNEXPECTED_GREEN`**: nothing pinned the guard |
| M2, re-run after the dominated-fold test was added | `--test sync_merge_tick` | `RED_AS_EXPECTED` (the new test alone) |

Review round, all gated on `cargo test --release --locked -p secretary-core --test sync_merge_tick`:

| Mutation | Outcome |
|---|---|
| T1: `if !adopted_one_copy` → `if true` | `RED_AS_EXPECTED`: the both-orders and dominated-fold tests |
| T2: `if !adopted_one_copy` → `if false` | `RED_AS_EXPECTED`: the 2-way and 3-way tick tests |
| T3: overflow mapped to `InvalidArgument` | `RED_AS_EXPECTED`: the overflow test |
| T4: the pre-review rule, emulated (a concurrent step clears `folded_clocks` and stops it refilling) | `RED_AS_EXPECTED`: the both-orders test |

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
2. **#759**: carry the merged `unknown`/`block_name` through `DraftMerge` and tick a block whose written plaintext differs from the adopted copy's. It is a frozen-spec-adjacent sync fix; start from the issue's reproduction sketch.
3. **Manual GUI pass** (needs the user at the devices; carried over from
   #752):
   - Poison a device: sync a vault copy once, restore an older
     `manifest.cbor.enc`, then unlock.
   - The reset prompt should appear, and "Reset and open" should open the
     vault.
   - Desktop and Android have also never had the #745 pass.
4. **#737 / #729: size caps.** #737 now also lists `core/src/sync/prepare.rs`
   (964 → 1000 after the review round; it said 984 at the docs commit, and 987 was the HEAD the review measured). Acceptance: move its two in-file test modules to
   `prepare/tests.rs` with an unchanged test-name set. #95 tracks
   `core/tests/sync_helpers/mod.rs` (now 1251 lines).
5. **Carried over:** #753, #754, #755, #756, #736, #734, #740 / #741 /
   #742, #747 / #748, #738, #731, #649, #683, #677, #668 / #693 (spec
   questions) and #699 / #701-#705.

## (3) Open decisions and risks

- **The fold's step relations changed, not only the tick count.** Before,
  step k compared against the *ticked* accumulator. A later copy that
  dominated every earlier copy was still Concurrent, because of the
  merging device's synthetic tick, and was merged record by record. Now it
  is `IncomingDominates`, and its plaintext is adopted, which is what the
  2-way rule already does. This is causally right: a copy dominating all
  the others has observed them. The both-orders test pins the plaintext
  in that case.
- **Fold-order independence is pinned for the dominating-copy case only.**
  The tick is now a function of the set of copies. The plaintext is the
  dominating copy's in every order when one exists. With no dominating
  copy, the records go through the record CRDT, which the proptests show
  is commutative and associative, but no N-way test permutes such a fold.
- **The overflow error is still order-dependent in one corner.**
  `merge_block` ticks (and the fold discards the result) on every
  concurrent step, so a merging-device counter at `u64::MAX` can fail
  closed in one fold order and succeed in another. It needs a counter no
  honest device reaches. A `shortcut:` comment in `prepare_merge` records
  it.
- **#759 (filed in the review, predates this slice).**
  `commit/write.rs::rewrite_one_block` writes the block with
  `unknown: BTreeMap::new()`, the canonical `block_name` and any
  `KeepLocal` restore, under the adopted copy's untouched clock. That
  drops block-level forward-compat keys and can put two plaintexts under
  one clock. Its fix will need to revisit
  `a_dominated_block_fold_adopts_the_dominating_clock_untouched`.
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
