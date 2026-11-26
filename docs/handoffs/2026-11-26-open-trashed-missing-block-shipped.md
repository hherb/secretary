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
| (this commit) | This handoff. |

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
  manifest that passes §4.3 steps 1-9 under the owner's keys, with the same
  `vault_uuid`, has a `trash` entry for that `block_uuid`.
- The opened manifest is unchanged. Reading the block fails as missing
  until the next sync's merge trashes it (crypto-design §11.6). No bytes of
  the block are trusted.

**Code.**

- `orchestrators.rs::verify_block_fingerprints` takes an
  `excuse_missing: impl FnMut(&[u8; 16]) -> bool`, asked only on a
  `NotFound`. Its three unit-test callers pass `|_| false`.
- `vault/trashed_elsewhere.rs` (new): pure `blocks_trashed_in` and I/O
  `blocks_trashed_by_conflict_copies`, which reuses
  `sync::ingest::ingest_manifest_copies` (the merge's five authentication
  checks). Best-effort: a scan that fails excuses nothing.
- `session_state.rs::verify_vault_state_with_toml` builds the predicate,
  scanning the folder once and only on the first miss.
- Test helper `apply_trash_move` moved from `sync_trash_vs_live.rs` into
  `convergence_helpers/reconcile.rs` (now takes the block uuid), so both
  binaries share it. `sync_trash_vs_live.rs` went 532 -> 517 lines.
- I checked that all three apps read a block only when it is selected
  (iOS `VaultBrowseViewModel`, Android `VaultBrowseModel.selectBlock`,
  desktop `RecordList.svelte`) and catch the error per block.

**Tests.** `core/tests/open_trashed_missing_block.rs` (new, 3 tests):
opens and then merges to trashed, with and without an edit before the
trash; a missing file no copy trashed is still refused, with and without a
copy; a tampered copy is not credited. `trashed_elsewhere` has 2 unit
tests. Hand-run mutations, each restored and `cmp`-checked: never excusing
reds the first test; excusing every absence reds the other two.

**Gates** (judged by exit code):

- `cargo test --release --locked --workspace --no-fail-fast`: exit 0, 114
  binaries, 2445 passed, 0 failed (2435 before: the new binary's 8,
  including the 5 shared `sync_helpers` tests, plus 2 unit tests).
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
     before syncing. The vault opens, the trashed block shows a missing
     error when selected, and after a sync it is trashed on both. (New,
     #788.)
   - Trash a block on A while B edits *that* block. It stays live, with
     both devices' edits.
   - Restore a block and edit it. The old `trash/` file stays (the 90-day
     sweep is covered by `trash_orphan_sweep.rs`).
3. **Splits:** #777 (`prepare.rs` 726), #784 (`ingest.rs` 603), and
   `commit/write.rs` (514; noted on #777). Acceptance: a verbatim move and
   an unchanged test-name set.
4. **#728:** make the conformance scripts survive the new `ld`.
5. **Carried over:** #791, #792, #786, #787 part 1, #780, #782,
   #768-#771, #753-#756, #736, #734, #740-#742, #747 / #748, #738, #731,
   #649, #683, #677, #668 / #693, #699 / #701-#705, #763.

## (3) Open decisions and risks

- **New: an old conflict copy can excuse a missing file the merge does not
  trash.** Sync tools leave old copies in place. If one of them trashed X
  and X was later restored, a missing `blocks/X` (a torn sync) is excused
  at open; the merge then keeps X live and its commit still refuses with
  `BlockFileMissing`, as before. Open is no worse than before (it used to
  refuse too), but the error moves from open to sync.
- **Not covered by a bridge-level test.** The bridge's open and password
  sync reach the fix through `core::open_vault`, which the core tests
  drive; no test builds this folder through the FFI.
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
