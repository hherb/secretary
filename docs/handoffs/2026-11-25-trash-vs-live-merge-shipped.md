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
| `8001a45a` | ROADMAP, README, this handoff. |
| (this commit) | `/finalcheck` review fixes (below), with docs and this handoff. |

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

**Tests (before the review round).** `sync_trash_vs_live.rs` (new, 5
tests, 10 after the review round):

- three merge one pair in **both** canonical orders: stale device (with
  and without an edit before the trash), concurrent edit, concurrent restore;
- one waits for a trashed file that has not arrived;
- one is the commit's rewrite refusal.

Unit tests were added in `trash_merge.rs` (7), `trash_collision.rs` (7),
`ingest/new_blocks.rs` (6, reworked) and `prepare/completeness.rs` (+2).

Five mutations each went red, then were restored and sha-checked: never
trash on a dominating clock, no trashed fold, no fingerprint skip, no
undecided refusal, no rewrite refusal.

**Gates after the review round** (judged by cargo's exit code):

- `cargo test --release --locked --workspace --no-fail-fast`: 112 binaries,
  2420 passed, 2 failed. Both failures are in `cli/tests/notify_quirk.rs`,
  the FSEvents flake #616; that binary passed 3 runs out of 3 on its own,
  and no code from this PR is on its path.
- `--lib` 726 passed. `sync_trash_vs_live` has 10 tests.
- clippy `-D warnings`, rustdoc `-D warnings` and `cargo fmt --check` are
  clean. The payload, secret-slot, lean-binding and ci-wiring guards pass.
- Not run: the Swift/Kotlin conformance scripts. The FFI surface and KAT
  are unchanged, but restore's on-disk effect changed.

**Gates before the review round**, each exit 0 unless noted:

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

**Review round (`/finalcheck`).** Four read-only review agents ran. You
signed off on two behaviour changes; everything else was a test or doc fix:

- **Restore keeps its trash file** (vault-format §7.1 step 5). A restore
  followed by an edit, concurrent with another device's write, used to
  refuse every merge for good: the rename plus the edit destroyed the only
  copy of the trashed version, whose clock §11.6 needs. Leftover files are
  #790.
- **Superseded manifests are not counted** (§11.7). Sync tools never delete
  conflict copies, so an old copy's trash entry trashed a restored block
  again in every later merge. A manifest whose clock another one's equals
  or dominates is now skipped for the trash union and the live versions,
  and a block only such a copy lists is not carried back
  (`trash_collision::trash_removes`).
- A trashed version found as a block's sibling is paired with its header
  clock, not reported as an orphan sibling.
- Tests: an `Equal`-clock unit test (a re-key), plus five integration tests:
  restore then edit in both orders, an old copy after a restore, an old
  copy after a trash, a trashed file found as a sibling, and a live-won
  block whose own file has not arrived.
- Four more mutations go red (superseded manifests counted, restore
  renaming, no sibling pairing, new blocks ignoring `trash_removes`), nine
  in total. All are hand-run with a sha-checked restore, not
  `scripts/mutate.py`.
- About 18 doc and comment fixes. They include stale `resolve_live_vs_trash`
  references in `sync_trash_merge.rs`, the README overclaiming that open
  was fixed, and §11.6's "manifests alone".

**Issues:** filed #788, #790 (a restore's leftover trash file is never
retention-purged), #791 (three-device VL-2 failure, predates this PR) and
#792 (the refusal's log does not say why a file was unusable). Commented on #787 (its part 2 is addressed in code
by this rule, with no dedicated end-to-end test) and re-measured #777 and
#784.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks are green. Then
   comment on #783 that it is closed in code, and on #787 that part 2
   merged.
2. **#790** (a restore's leftover trash file holds an old version's
   ciphertext forever). Acceptance: vault-format §7 says when an
   entry-less trash file is removed, and a test pins it.
3. **#788** (open fails until a merge commits). Acceptance: decide in docs
   what open does when a listed block's file is missing and an
   authenticated conflict copy trashed exactly that fingerprint, or show
   that every platform's open path runs a password sync first. Add a test
   that opens such a folder.
4. **Manual GUI pass** (needs you at the devices; carried over). Add two
   checks:
   - Trash a block on A while B edits another block. After both sync, the
     block is trashed on both, and the vault opens on both.
   - Trash a block on A while B edits *that* block. It stays live, with
     both devices' edits.
5. **Splits:** #777 (`prepare.rs` 726), #784 (`ingest.rs` 603), and
   `commit/write.rs` (514; noted on #777). Acceptance: a verbatim move and
   an unchanged test-name set.
6. **#728:** make the conformance scripts survive the new `ld`.
7. **Carried over:** #791, #792, #786, #787 part 1, #780, #782, #768-#771, #753-#756,
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
  #783 and is now #791.
- **Leftover trash files (#790).** After a restore the old trash file
  stays until the next restore or purge of that block. Once the block is
  edited, it holds an older version's ciphertext.
- **A restore made by an older client** (one that renamed the file),
  followed by an edit and a concurrent merge with a copy that still holds
  the trash entry, still refuses for good.
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
