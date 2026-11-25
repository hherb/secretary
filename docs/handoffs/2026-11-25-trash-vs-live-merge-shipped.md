# NEXT_SESSION.md: a trashed-vs-live block merges the same in both orders (#783)

Branch `fix/783-trash-vs-live-merge`, in the main checkout (no worktree),
base `6e6d0928` (`main`, the #785 merge). The PR is open; see
`gh pr list --head fix/783-trash-vs-live-merge`.

At session start #785 (the previous baton's PR) had merged. Its local branch
was deleted, and #781 got its "closed in code by #785" comment.

## (1) What shipped

| SHA | What |
|---|---|
| `185347f1` | crypto-design §11.6 rewritten (and §11.7's trash parenthetical, vault-format §7's #401 note). |
| `313f2c52` | The rule in code, with tests. |
| (this commit) | ROADMAP, README, this handoff. |

**The bug, measured with a probe.** Device A trashes block X; device B,
which has not seen the trash, edits block Y. The old commit applied "live
wins" against the canonical manifest's `blocks` only:

- A's manifest canonical: X stayed trashed.
- B's manifest canonical: B's entry for X names the file A had moved to
  `trash/`, so `verify_vault_state` failed with `BlockFileMissing` on every
  commit. Sync stayed stuck for good. `open_vault` shares that check, so it
  fails too (filed as #788, see risks).

**The decision (yours, via the question dialog):** *trash wins unless a
copy is newer*, and when live wins, *fold the trashed version in*.

- A live version is **covered** if it is the trashed version (same
  fingerprint), or the trashed file's signed header clock equals or
  dominates it. Covered everywhere: the trash wins. Otherwise live wins and
  the trashed version is merged by §11.2, so edits made before the trash
  are kept.
- Purge still wins. A legacy entry with no fingerprint loses to live.
- Accepted cost: a trash entry has no clock, so a restore made concurrently
  with another write looks like a stale device. The block goes back to the
  trash and can be restored again (tested).

**Code.**

- `vault/trash_merge.rs`: pure `resolve_trash_collision` +
  `needs_trashed_clock` + `TrashCollision`. These replace
  `resolve_live_vs_trash`, whose only caller was the commit.
- `sync/trash_collision.rs` (new): applies the rule once, so ingest (which
  files to read) and `prepare_merge` (what to refuse, fold and write) agree.
- `sync/ingest/trashed.rs` (new): reads the trashed file into the new
  `VaultBundle::trashed_envelopes`. It looks in `trash/<uuid>.cbor.enc.<ts>`,
  the block's own path and its siblings, matching by fingerprint.
- `prepare_merge`:
  - refuses an undecidable collision with `BlockCopyUnavailable`;
  - folds the trashed version with its header clock;
  - writes `merged_trash` with only the entries that won.
- A block that live wins for, and that the canonical manifest trashed, is
  carried as a §11.7 new block (`blocks_new_to_canonical` now keys on the
  collision outcome instead of the old fingerprint filter).
- Commit: drops every block still in `merged_trash` from `blocks`, skips
  their fingerprint check (`verify_vault_state_for_merge`), and refuses a
  draft that rewrites one of them.

No new error variant, no FFI, KAT or wire-format change.

**Tests.** `sync_trash_vs_live.rs` (new, 5 tests):

- three merge one pair in **both** canonical orders: stale device (with
  and without an edit before the trash), concurrent edit, concurrent restore;
- one waits for a trashed file that has not arrived;
- one is the commit's rewrite refusal.

Unit tests were added in `trash_merge.rs` (7), `trash_collision.rs` (7),
`ingest/new_blocks.rs` (6, reworked) and `prepare/completeness.rs` (+2).

Five mutations each went red, then were restored and sha-checked: never
trash on a dominating clock, no trashed fold, no fingerprint skip, no
undecided refusal, no rewrite refusal.

**Gates**, each exit 0 unless noted:

- `cargo test --release --locked --workspace`: 112 binaries, 2407 passed,
  0 failed. This ran before the last test was added; afterwards `--lib`
  (725) and `sync_trash_vs_live` (10, including the harness tests) passed.
- clippy `-D warnings` (workspace, and `-p secretary-core --features
  differential-replay`); rustdoc `-D warnings`; `cargo fmt --check`.
- Payload, secret-slot and lean-binding guards.
- `spec_test_name_freshness.py` exits 1 with 102 unresolved citations. The
  count is unchanged (#642), and none come from the edited lines.
- Not run: `conformance.py` (no Python or KAT change) and the Swift/Kotlin
  conformance scripts (no FFI change).

**Issues:** filed #788. Commented on #787 (its part 2 is addressed in code
by this rule, with no dedicated end-to-end test) and re-measured #777 and
#784.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks are green. Then
   comment on #783 that it is closed in code, and on #787 that part 2
   merged.
2. **#788** (open fails until a merge commits). Acceptance: decide in docs
   what open does when a listed block's file is missing and an
   authenticated conflict copy trashed exactly that fingerprint, or show
   that every platform's open path runs a password sync first. Add a test
   that opens such a folder.
3. **Manual GUI pass** (needs you at the devices; carried over). Add two
   checks:
   - Trash a block on A while B edits another block. After both sync, the
     block is trashed on both, and the vault opens on both.
   - Trash a block on A while B edits *that* block. It stays live, with
     both devices' edits.
4. **Splits:** #777 (`prepare.rs` 726), #784 (`ingest.rs` 603), and
   `commit/write.rs` (514; noted on #777). Acceptance: a verbatim move and
   an unchanged test-name set.
5. **#728:** make the conformance scripts survive the new `ld`.
6. **Carried over:** #786, #787 part 1, #780, #782, #768-#771, #753-#756,
   #736, #734, #740-#742, #747 / #748, #738, #731, #649, #683, #677,
   #668 / #693, #699 / #701-#705, #763.

## (3) Open decisions and risks

- **A concurrent restore is undone** (it goes back to the trash). This was
  chosen over letting every stale device resurrect trashed blocks.
  Restoring again works. A clock on trash entries would remove the
  trade-off but needs a format change.
- **#788: the vault does not open until the merge commits.** The state
  arises when the stale side's manifest is canonical. The password sync
  path now resolves it. An app that opens before it syncs cannot.
- **A live-won block whose edited file exists only as a sync-tool conflict
  sibling** (not at `blocks/<uuid>`) is refused on every retry. That is the
  same wedge class as #786. Sync tools normally keep a modified file over
  a delete, so it should be rare.
- **Three devices:** a canonical entry whose own file another device has
  overwritten still fails VL-2 (`BlockFingerprintMismatch`). This predates
  #783.
- Unchanged: a copy whose file never arrives blocks sync for good (#786);
  v1 keeps `block_version` values it does not understand; `UnknownValue`
  is not zeroize-typed.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary
pwd && git branch --show-current     # fix/783-trash-vs-live-merge, or main once merged
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head fix/783-trash-vs-live-merge --json number -q '.[0].number')"
cargo test --release --locked -p secretary-core --test sync_trash_vs_live --test sync_trash_merge --test sync_merge_new_block
```

If the PR has merged, switch to `main`, pull, delete the branch, then start
the next item.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
