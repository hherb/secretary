# NEXT_SESSION.md: open removes trash files no entry names (#790)

Branch `fix/790-orphan-trash-cleanup`, in the main checkout (no worktree),
base `d620687b` (`main`, the #789 merge for #783). See
`gh pr list --head fix/790-orphan-trash-cleanup` for the PR.

At session start #789 had merged. Its local branch was deleted, #783 got its
"closed in code" comment, and #787 a "part 2 merged" comment.

## (1) What shipped

| SHA | What |
|---|---|
| `d689b429` | The rule in code and vault-format §7, with tests. |
| (this commit) | ROADMAP, README, this handoff. |

**The problem (#790).** Since #783 a restore keeps its
`trash/<uuid>.cbor.enc.<ts>` file, because crypto-design §11.6 needs its
signed header clock. It drops the `TrashEntry` that named the file, though,
and every cleanup is keyed on entries. Once the block was edited, the old
version's ciphertext stayed in `trash/` for good.

**The decisions (yours, two question dialogs):**

1. Remove such a file once its `<ts>` suffix is past a window. The
   alternatives were also waiting for the block's last edit (which never
   cleans a block edited regularly), or cleaning only non-live orphans
   (which leaves #790's main case unfixed).
2. Run it as an **open-time sweep**, not inside `auto_purge_expired`. I had
   first built it into retention, then found that desktop
   (`RetentionDialog.svelte`'s `hasExpired`), iOS (`TrashScreen.swift:113`)
   and Android (`TrashScreen.kt:166`) only commit retention when the
   *entry* preview is non-empty. After a restore there usually is no
   expired entry, so the cleanup was unreachable in practice.

**One refinement I made without asking** (please check you agree): "now"
is the verified manifest header's `last_mod_ms`, the signed time of the
latest write, not a clock read at open. `core` reads no clock anywhere, and
this keeps it that way and makes the sweep testable. The edit after a
restore is itself a write, so the countdown runs exactly in the case #790
is about. A vault never written again keeps the file, which is harmless,
since that copy is identical to the live block.

**The rule** (vault-format §7, "Open-time unreferenced-file sweep"):

- On every `verify_vault_state` (open, and the merge commit's
  verification), next to the purged-file sweep, remove each `trash/` file
  in §7's grammar (canonical lowercase UUID, canonical `<unix-millis>`)
  that no `manifest.trash` entry names (same `block_uuid` and
  `tombstoned_at_ms`, purged or not), once
  `last_mod_ms − ts > 90 days`. The test is saturating with an exclusive
  boundary.
- The window is the fixed `DEFAULT_RETENTION_WINDOW_MS`, not the user's
  retention setting. An unnamed file cannot be restored; the window only
  gives devices time to merge (§11.3).
- No manifest write, best-effort, names outside the grammar left alone.
- Accepted risk: a copy that has not merged for longer than the window
  after the trash, and still lists the block as trashed, then refuses
  every merge (#786's class). The window counts from the trash.

**Code.**

- `core/src/vault/trash_orphans.rs` (new): pure `parse_trash_file_name`
  and `expired_unreferenced`, the I/O `remove_expired_unreferenced`, and
  `UNREFERENCED_TRASH_WINDOW_MS`.
- `session_state.rs::verify_vault_state_with_toml` calls it after
  `sweep_purged_trash_files`.
- `unlock/vault_toml.rs::parse_uuid_canonical` is now `pub(crate)` for
  reuse.
- `retention.rs`, `purge.rs` and the FFI are unchanged.

**Tests.** `trash_orphans` has 7 unit tests (grammar, boundary, future
suffix, named purged or not, an entry for another stamp).
`core/tests/trash_orphan_sweep.rs` (new) has 3: removed past the window
(and the block stays live and opens), kept at exactly the window, and named
and out-of-grammar files kept.

Hand-run mutations, each restored and sha-checked, went red: no sweep call,
ignoring a naming entry (lib and integration), and an inclusive boundary
(lib and integration). One early run was vacuous, because a
`--lib trash_orphans` filter also filtered the integration binary down to 0
tests; it was rerun with `--test` alone.

**Gates** (judged by exit code):

- `cargo test --release --locked --workspace --no-fail-fast`: 113 binaries,
  2432 passed, 0 failed.
- clippy `-D warnings` (workspace, `--tests`): clean. Rustdoc
  `-D warnings` and `cargo fmt` are clean. The payload, secret-slot and
  ci-wiring guards pass. The lean-binding guard passes.
- `spec_test_name_freshness.py` exits 1 with 102 unresolved citations. The
  count is unchanged (#642), so the new citations resolve.
- Not run: `conformance.py` and the Swift/Kotlin conformance scripts (no
  Python, KAT or FFI change).

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks are green. Then
   comment on #790 that it is closed in code.
2. **#788** (open fails until a merge commits). Acceptance: decide in docs
   what open does when a listed block's file is missing and an
   authenticated conflict copy trashed exactly that fingerprint, or show
   that every platform's open path runs a password sync first. Add a test
   that opens such a folder.
3. **Manual GUI pass** (needs you at the devices; carried over). Add these
   checks:
   - Trash a block on A while B edits another block. After both sync, the
     block is trashed on both, and the vault opens on both.
   - Trash a block on A while B edits *that* block. It stays live, with
     both devices' edits.
   - Restore a block and edit it. The old `trash/` file stays (90 days is
     too long to test by hand; the integration test covers it).
4. **Splits:** #777 (`prepare.rs` 726), #784 (`ingest.rs` 603), and
   `commit/write.rs` (514; noted on #777). Acceptance: a verbatim move and
   an unchanged test-name set.
5. **#728:** make the conformance scripts survive the new `ld`.
6. **Carried over:** #791, #792, #786, #787 part 1, #780, #782, #768-#771,
   #753-#756, #736, #734, #740-#742, #747 / #748, #738, #731, #649, #683,
   #677, #668 / #693, #699 / #701-#705, #763.

## (3) Open decisions and risks

- **New with this PR: a very stale copy can wedge sync** once its trashed
  file has been cleaned up (see the rule above). You accepted this. A
  clock on trash entries would remove it, but that needs a format change.
- **The window ignores the user's retention setting** (fixed 90 days). A
  user who set a 10-year retention still loses a restored block's old file
  after 90 days. It cannot be restored either way.
- **The retention UIs still gate on entries only.** That is now harmless
  for #790, but "Run retention now" is unavailable while only entries
  younger than the window exist, which is the intended behaviour.
- **Not yet in the repair orchestration's own sweep calls**
  (`repair/orchestration.rs:293/327` call the other two sweeps directly).
  The file goes at the next open instead.
- Carried over: a concurrent restore is undone (it goes back to the trash);
  #788 (the vault does not open until the merge commits); a live-won block
  whose edited file exists only as a conflict sibling is refused on every
  retry; #791 (three devices, VL-2); a restore made by an older client that
  renamed the file can still refuse for good; #786; v1 keeps
  `block_version` values it does not understand; `UnknownValue` is not
  zeroize-typed.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary
pwd && git branch --show-current     # fix/790-orphan-trash-cleanup, or main once merged
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head fix/790-orphan-trash-cleanup --json number -q '.[0].number')"
cargo test --release --locked -p secretary-core --test trash_orphan_sweep --test retention
cargo test --release --locked -p secretary-core --lib trash_orphans
```

If the PR has merged, switch to `main`, pull, delete the branch, then start
the next item.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
