# NEXT_SESSION.md: a merge leaves out no copy content (#781)

Branch `fix/781-merge-completeness`, in the main checkout (no worktree), base
`65c18735` (`main`, the #779 merge). The PR is open; see
`gh pr list --head fix/781-merge-completeness`.

At session start #779 (the previous baton's PR) had merged. The local branch
head matched the merged PR head, so the branch was deleted, and #764 got its
"closed in code by #779" comment.

## (1) What shipped

| SHA | What |
|---|---|
| `f5fbb61a` | `prepare_merge` refuses a diverging block whose copy version has no readable block file: new `SyncError::BlockCopyUnavailable`. |
| `bb20460d` | `ingest.rs`'s unit tests moved verbatim to `ingest/tests.rs` (15 test names unchanged). |
| `e26c6a6a` | crypto-design §11.7; a block only a copy holds is carried into the merge. |
| `593a9bc0` | `SyncBlockCopyUnavailable` across the bridge, uniffi, pyo3, desktop, iOS and Android, with "Some vault files are still syncing" copy. |
| `8cde53bb` | Review fixes: a new block's seed clock is its file's signed header clock; a version that a read version dominates needs no file. |
| (this commit) | ROADMAP, README, this handoff. |

**Two measured data-loss bugs, one root cause.** The merged manifest clock
covers every folded copy. On the next sync the persisted clock equals the
disk clock, so `sync_once` returns `NothingToDo` and never reads a copy
again. Anything a merge leaves out is therefore lost:

1. **#781.** A copy manifest claimed a diverging block version whose sibling
   file was missing or failed to authenticate (cloud sync can deliver the
   manifest first). The fold merged the canonical copy alone. A probe
   showed the late sibling never merged: second sync `NothingToDo`, the
   copy's record absent.
2. **Found this session.** A block that only a copy lists (another device
   created it) was dropped. `commit_with_decisions` built the merged
   manifest from `verified.manifest.clone()`. A probe showed the merged
   manifest without the block.

**The fix.** With your sign-off: fail closed with a new typed error, and
fix both in this PR. The spec came first: crypto-design **§11.7** says a
merge carries a block new to the merging device (listed by a copy, in
neither the local `blocks` nor `trash`), and must not commit while any
version it covers is unreadable.

- `prepare/completeness.rs` (new, pure, 6 unit tests) holds two checks.
  Every copy version must be covered: by the canonical clock, or by the
  clock of a version the fold reads (an envelope, matched by fingerprint).
  Every new block must be planned. The
  "uncovered" predicate is `ingest::copy_version_is_uncovered`, shared with
  ingest's own divergence test.
- `ingest/new_blocks.rs` ingests a new block with its own authenticated
  file as the canonical envelope and its siblings as copies.
  `ingest/block_files.rs` holds the read+authenticate helpers that both
  ingest paths now share.
- In `prepare_merge` (`prepare/new_block.rs`), a new block's seed clock is
  its own file's owner-signed header clock, and its `BlockEntry` is the
  first copy entry listing it. It raises no veto, because there is no local
  record to protect. `MergedBlockMeta::added_entry` carries the entry.
- `commit_with_decisions` builds `base_manifest` = verified + added entries,
  then rewrites the blocks as before.

**Tests.** `sync_merge_write.rs::a_diverging_copy_whose_block_file_is_missing_refuses_the_merge_until_it_arrives`
replaces the test that pinned the lossy behaviour. `sync_merge_new_block.rs`
(new, 4 tests) covers a new block carried, a new block refused until its
file arrives, no veto, and a new block whose file is newer than every
manifest. Mutations, each red then restored by sha-checked backup: the
covered-version filter, the commit's entry carry, the planned-block check,
the new-block ingest, and the veto skip.

**Review round.** An independent read-only review found two defects in the
new code. Both were confirmed by a red test before the fix (`8cde53bb`):

- A new block's own file holding a version no manifest names failed every
  retry as an "orphan". That happens after a commit that crashed between
  the block write and the manifest write, or a re-edit whose file landed
  first.
- A missing file for a version another readable copy supersedes blocked
  the merge.

**Final review round (`/finalcheck`).** Five read-only review agents; the
fixes, each pinned by a test:

- A block the local manifest lists, which a copy diverges from and whose
  own file had not landed, was left out of the plan with no refusal. If the
  file landed before the commit's fingerprint check, the commit covered the
  copy without folding it (#781's loss). `ensure_divergent_blocks_are_planned`
  now requires every block whose manifests diverge, via the shared
  `ingest::listed_block_diverges`. Mutation: dropping that half reds
  `an_unplanned_diverging_listed_block_is_refused` and
  `a_listed_diverging_block_whose_file_is_missing_is_refused`.
- A copy version whose exact file another copy's trash entry records no
  longer counts as new (`blocks_new_to_canonical`); it had refused every
  retry, since trashing moves the file out of `blocks/`. crypto-design §11.7
  says so.
- A listed block's own file must match its manifest fingerprint in
  `prepare_merge` (VL-2): `BlockFingerprintMismatch`, a repair case.
- The commit refuses an `added_entry` the verified manifest already holds,
  or one for an unplanned block, before any write (pinned by
  `a_commit_refuses_an_added_entry_the_manifest_already_lists`, red
  without the check).
- `secretary-sync` exits 15 for `BlockCopyUnavailable` (was generic 1); the
  C.2 design spec's table has the row.
- The refusal logs a `warn!` naming the block.
- New tests: a newer missing version over a readable older one; a new
  block's own file older than its copy entry (refused, then adopted once
  the newer file lands; red with the copy-clock seed); its own file failing
  authentication; the header naming another block (unit test, golden block
  file); two new blocks with one unplanned; the trash exclusions.
- Docs: `new_block_seed` claimed the commit overwrites every differing
  field (it keeps `recipients`, `suite_id`, `unknown`); `prepare_merge`'s
  `# Errors`, `BlockCopyUnavailable`'s doc and the platform docs named
  sibling files or "not arrived" only.
- Filed: #786 (one variant for "in flight" and "never will authenticate"),
  #787 (copy-order-dependent `recipients`/`unknown` for a new block; a
  concurrently trashed version can still wedge one).

**Gates**, each exit 0:
- After the final review: `cargo test --release --workspace` (111 binaries,
  0 failed); clippy `-D warnings` (workspace, and `-p secretary-core
  --features differential-replay`); rustdoc `-D warnings`; `cargo fmt`; the
  payload guard. FFI surface unchanged in that round (doc comments only).
- On `8cde53bb`: `cargo test --release --locked --workspace` (111 binaries, 2376 passed, 0 failed: the 2374 plus the two review tests);
  `-p secretary-core` 61 binaries / 1242 passed; clippy `-D warnings`;
  rustdoc `-D warnings`; `cargo fmt --check`.
- On `593a9bc0` (FFI): the workspace was 111 / 2374, and the payload,
  secret-slot, ci-wiring and lean-binding guards passed. Swift and Kotlin
  conformance were 38/38 each (with `CARGO_PROFILE_RELEASE_STRIP=none`, see
  risks). Desktop vitest was 83 files / 797 tests, with `svelte-check` at 0
  errors. Swift `SyncErrorMessageTests` was 4/4. Android `:kit`,
  `:vault-access` and `:sync-ui` unit tests plus `:app:assembleDebug` built
  successfully. `conformance.py` passed.

**Issues filed or updated:** #783 (trash-vs-live merge depends on which
side is canonical), #784 (`ingest.rs` 581 production lines), #777
re-measured (`prepare.rs` 678), #728 (cause found: the release `strip`),
#642 re-measured (102), #786, #787.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks are green. Then
   comment on #781 that it is closed in code.
2. **#783** (a semantics question; decide it in `docs/` first). A trash entry
   has no clock, so "live wins" cannot tell an edit made after the trash
   from a stale copy. Acceptance: a §11.6 rule that gives one result for
   both canonical orders, and a test that merges one pair both ways.
3. **Manual GUI pass** (needs you at the devices; carried over from #752 /
   #766). Add one check: on device B, create a block, and before B's
   manifest syncs, edit another block on A. After A syncs, the new block
   must appear on both. Desktop and Android have never had the #745
   pass.
4. **Splits:** #777 (`prepare.rs` 697) and #784 (`ingest.rs` 582).
   Acceptance: a verbatim move and an unchanged test-name set.
5. **#728:** make the conformance scripts survive the new `ld`. The cheapest
   option is to export the strip override into their own target dir.
6. **Carried over:** #780, #782, #768-#771, #753-#756, #736, #734,
   #740-#742, #747 / #748, #738, #731, #649, #683, #677, #668 / #693,
   #699 / #701-#705, #763.

## (3) Open decisions and risks

- **A copy whose block file never arrives blocks sync for good.** That is
  the fail-closed choice. Retrying is right for a file in flight, but a
  sync tool that deleted the sibling leaves `BlockCopyUnavailable` on every
  pass until the user removes the stale conflict-copy manifest. No UI
  explains that yet. A copy that fails authentication behaves the same
  (a hostile host can therefore stall sync, which it could already do by
  deleting files); #786 tracks telling the two apart.
- **Seed choice for a new block.** Its own file stands in for the local
  side, and siblings fold onto it. The §11.2 fold is order-independent for
  the tick and the records, so the choice should not matter. Only a
  two-version proptest would prove it, and none exists.
- **The header clock is trusted for new blocks.** It is owner-signed, and a
  replayed old version only makes the copy's own version "uncovered", which
  fails closed. Normal writers keep the header clock equal to the manifest
  summary, so the two sources agree.
- **#728 workaround cost.** `CARGO_PROFILE_RELEASE_STRIP=none` changes the
  release fingerprint, so the next plain `cargo test --release` rebuilds
  everything.
- Unchanged from earlier batons: v1 keeps `block_version` values it does
  not understand, and `UnknownValue` is not zeroize-typed.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary
pwd && git branch --show-current     # fix/781-merge-completeness, or main once merged
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head fix/781-merge-completeness --json number -q '.[0].number')"
cargo test --release --locked -p secretary-core --test sync_merge_new_block --test sync_merge_write
```

If the PR has merged, switch to `main`, pull, delete the branch, then start
the next item.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
