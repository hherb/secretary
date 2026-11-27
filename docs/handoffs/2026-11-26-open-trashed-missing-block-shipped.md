# NEXT_SESSION.md: open a vault whose missing block a conflict copy trashed (#788)

Branch `fix/788-open-tolerates-trashed-missing-block`, in the main checkout
(no worktree), base `ab05409b` (`main`, the #793 merge for #790). See
`gh pr list --head fix/788-open-tolerates-trashed-missing-block` for the PR.

At session start #793 had merged. Its local branch was deleted and #790 got
its "closed in code" comment.

## (1) What shipped

| SHA | What |
|---|---|
| `90660c44` | The rule in code and vault-format §4.3, tests, ROADMAP, README. |
| `a4df3acb`, `0b8dfe3c` | This handoff. |
| (this commit) | PR #794 review fixes, below. |

**The problem (#788), measured worse than the issue said.** Device A
trashes block X (manifest write, `blocks/X -> trash/`). Device B, which has
not seen that, writes the canonical manifest, which still lists X.
`verify_vault_state` (open, the bridge's refresh and session sync, the
merge commit) failed with `BlockFileMissing`, shown to the user as
`CorruptVault`. I measured that on `open_vault`. The issue assumed a
password sync would recover, but the bridge's `sync_vault` also starts
with a full `open_vault` (`sync/orchestration.rs::open_identity`), and all
three apps open before they sync. So **no app on any device** could leave
the state. Only the CLI, which unlocks the identity alone, could.

**The decisions (yours, two question dialogs):**

1. Excuse the absence at open (core only), not a sync-before-open flow in
   each app (a new FFI error and UI on three platforms) and not only a
   clearer error.
2. Keep the block listed in the opened manifest, not hidden (no partial
   merge at open).
3. Excuse it for **any** authenticated trash entry for that uuid, not only
   one with the listed fingerprint. With exact matching, "edit X, then
   trash it" on A stayed unopenable, because B's entry lists X's older
   fingerprint.

**The rule** (vault-format §4.3, new paragraph "Block files at open"; it
also states the open-time fingerprint check, which no spec text did
before):

- Each listed block needs a file whose BLAKE3 fingerprint matches, as
  before. One exception: an absent file is excused when a conflict-copy
  manifest that passes §4.3 steps 1-5 and 7-9 under the owner's keys, with
  the same `vault_uuid`, and that crypto-design §11.7 counts (not
  superseded), has a `trash` entry for that `block_uuid`.
- Open and refresh only. The merge commit excuses nothing beyond its own
  merged trash, and `trash_block` refuses a block whose file is absent.
- The opened manifest is unchanged. Reading the block fails (the bridge
  says `CorruptVault`) until a merge by a device concurrent with the
  canonical manifest, such as the trashing device, trashes it
  (crypto-design §11.6). No bytes of the block are trusted.

**Code.**

- `orchestrators.rs::verify_block_fingerprints` takes an
  `excuse_missing: impl FnMut(&[u8; 16]) -> bool`, asked only on a
  `NotFound`. Its three unit-test callers pass `|_| false`.
- `vault/trashed_elsewhere.rs` (new): pure `blocks_trashed_in` and I/O
  `blocks_trashed_by_conflict_copies`, which reuses
  `sync::ingest::ingest_manifest_copies` (the merge's authentication
  checks) and `sync::trash_collision::merged_trash` (the merge's §11.7
  supersession rule; the module is now `pub(crate)`). Best-effort: a scan
  that fails excuses nothing and logs at debug.
- `session_state.rs::verify_vault_state_with_toml` takes
  `trashed_by_merge: Option<&BTreeSet>`: `None` (open, refresh) builds the
  predicate, scanning the folder once and only on the first miss; `Some`
  (merge commit) skips the merged trash and excuses nothing else.
- `trash_block` refuses with `BlockFileMissing` when `blocks/<uuid>` is
  absent, before staging.
- Test helper `apply_trash_move` moved from `sync_trash_vs_live.rs` into
  `convergence_helpers/reconcile.rs` (now takes the block uuid), so both
  binaries share it. `sync_trash_vs_live.rs` went 532 -> 517 lines; the
  review fixes moved its `prepare_as` into `convergence_helpers/sync_drive.rs`
  too (now taking `now_ms`), 517 -> 491.
- I checked that all three apps read a block only when it is selected
  (iOS `VaultBrowseViewModel`, Android `VaultBrowseModel.selectBlock`,
  desktop `RecordList.svelte`) and catch the error per block.

**Tests.** `core/tests/open_trashed_missing_block.rs` (new, 7 tests):
opens and then merges to trashed, with and without an edit before the
trash; a missing file no copy trashed is still refused, with and without a
copy; a tampered copy is not credited; wrong bytes at X, a directory at X
and a missing Y are each still refused; the session refuses to trash X; a
superseded copy does not excuse; the merge commit refuses a live block
whose file vanished after `prepare_merge`. `trashed_elsewhere` has 3 unit
tests. Hand-run mutations, each restored: never excusing reds the first
test; excusing every absence reds the next two; and (PR #794 review)
counting superseded copies, excusing on the merge path and dropping
`trash_block`'s refusal each red exactly their own test.

**Gates** (judged by exit code):

- `cargo test --release --locked --workspace --no-fail-fast`: exit 0, 114
  binaries, 2450 passed, 0 failed after the review fixes (2445 at
  `90660c44`, 2435 before it: the new binary's 8, including the 5 shared
  `sync_helpers` tests, plus 2 unit tests; the review added 1 unit and 4
  integration tests). The differential-replay test also exits 0.
- clippy `-D warnings` (workspace, `--tests`), rustdoc `-D warnings`,
  `cargo fmt --check`: clean. Payload, secret-slot, ci-wiring and
  lean-binding guards pass.
- `spec_test_name_freshness.py` exits 1 with 102 unresolved citations,
  unchanged (#642).
- Not run: `conformance.py` and the Swift/Kotlin conformance scripts (no
  Python, KAT or FFI change).

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks are green. Then
   comment on #788 that it is closed in code.
2. **Manual GUI pass** (needs you at the devices; carried over, plus one
   new check):
   - Trash a block on A while B edits another block, and open B's app
     before syncing. The vault opens, the trashed block shows a read
     error when selected, and after A syncs it is trashed on both. (New,
     #788.)
   - Trash a block on A while B edits *that* block. It stays live, with
     both devices' edits.
   - Restore a block and edit it. The old `trash/` file stays (the 90-day
     sweep is covered by `trash_orphan_sweep.rs`).
3. **Splits:** #777 (`prepare.rs` 726), #784 (`ingest.rs` 603), and
   `commit/write.rs` (519; noted on #777). Acceptance: a verbatim move and
   an unchanged test-name set.
4. **#728:** make the conformance scripts survive the new `ld`.
5. **Carried over:** #791, #792, #786, #787 part 1, #780, #782,
   #768-#771, #753-#756, #736, #734, #740-#742, #747 / #748, #738, #731,
   #649, #683, #677, #668 / #693, #699 / #701-#705, #763.

## (3) Open decisions and risks

- **Closed in the PR #794 review: superseded copies, the merge commit and
  `trash_block`.** The first version credited any authenticated copy, so an
  old copy that trashed X excused a missing `blocks/X` after a restore,
  and the merge commit used the same excuse and could sign a manifest
  listing X with no file. The excuse now counts only copies crypto-design
  §11.7 counts (`trash_collision::merged_trash`), applies on open and
  refresh only, and `trash_block` refuses a block whose file is absent
  (its newer trash entry would strand the trashing device's file).
- **Only a concurrent device finishes the trash.** On B, whose manifest is
  canonical, `sync_once` finds nothing to do; X stays listed and
  unreadable (the bridge says `CorruptVault`) until A, or another device
  that has not merged, syncs. The UI does not say "sync to finish".
- **Filed from the review:** #796 (an excused block reads back as
  `CorruptVault`, "damaged", with no hint to sync) and #797 (conflict-copy
  discovery is not stated normatively in `docs/`).
- **Not covered by a bridge-level test.** The bridge's open and password
  sync reach the fix through `core::open_vault`, which the core tests
  drive; no test builds this folder through the FFI (filed as #795). The
  PR is #794.
- Carried over from #790: a very stale copy can wedge sync once its trashed
  file has been swept; the sweep window ignores the user's retention
  setting; the repair orchestration's sweep calls do not include the
  unreferenced-file sweep.
- Carried over: a concurrent restore is undone (it goes back to the trash);
  a live-won block whose edited file exists only as a conflict sibling is
  refused on every retry; #791 (three devices, VL-2); a restore made by an
  older client that renamed the file can still refuse for good; #786; v1
  keeps `block_version` values it does not understand; `UnknownValue` is
  not zeroize-typed.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary
pwd && git branch --show-current     # fix/788-open-tolerates-trashed-missing-block, or main once merged
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head fix/788-open-tolerates-trashed-missing-block --json number -q '.[0].number')"
cargo test --release --locked -p secretary-core --no-fail-fast --test open_trashed_missing_block --test sync_trash_vs_live
cargo test --release --locked -p secretary-core --lib trashed_elsewhere
```

If the PR has merged, switch to `main`, pull, delete the branch, then start
the next item.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
