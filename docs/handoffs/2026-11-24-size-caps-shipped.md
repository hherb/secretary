# NEXT_SESSION.md: two over-cap sync files split (#95, prepare.rs)

Branch `feature/size-caps`, worktree `.worktrees/size-caps`, base
`6c0103f9` (`main`, the #776 merge). The PR is open; see
`gh pr list --head feature/size-caps`.

At session start, #767 (the previous baton's PR) and #776 had merged. Both
worktrees (`save-block-preserve`, `ios-app-icon-sync-badge`) were clean, and
each branch head matched its merged PR head, so both were removed along with
their branches.

## (1) What shipped

| SHA | What |
|---|---|
| `7980e835` | `core/src/sync/prepare.rs` 1015 -> 624: its `mod tests` and `mod parent_block_clock_tests` moved to `prepare/tests.rs` (186) and `prepare/parent_block_clock_tests.rs` (203). |
| `9f1c554a` | `core/tests/sync_helpers/mod.rs` 1335 -> 59: seven submodules re-exported by glob, plus `helper_tests.rs` (#95). |
| (this commit) | This handoff and the symlink retarget. |

Both are behaviour-preserving moves by exact line range, and each was
verified two ways:

- **Content.** A script compared the whitespace-stripped old file with the
  new files. It reported identical, apart from one `use super::*;` per
  submodule and `pub(super)` on the three private items two submodules share
  (`SYNC_HELPERS_UUID_LEN`, `encrypt_block_bytes_for_uuid`,
  `write_manifest_with_block_entry`). The one-line `//!` headers were added
  after that check.
- **Test names.** The lib set was 696 before and after. The full
  `secretary-core --tests` multiset was 1233 before (listed from a detached
  `origin/main` checkout) and 1233 after, with an empty diff.
  `sync_helpers::helper_tests` keeps its module path in all 14 binaries that
  declare `mod sync_helpers`.

`sync_helpers` layout: `mod.rs` (shared constants; re-exports), `nonces`
60, `manifests` 110, `block` 191, `block_encrypt` 134, `block_manifest` 123,
`concurrent_blocks` 211, `block_siblings` 171, `helper_tests` 317. #95 asked
for submodules of at most 300 lines. `helper_tests.rs` is 317 because it is
the three helper tests moved whole. It is under the repo's 500 threshold, and
splitting it would rename test paths.

**Gates, each exit 0, after the last edit:** `cargo test --release --locked
--workspace` (109 binaries, 2353 passed, 0 failed); `cargo clippy --release
--workspace --tests -- -D warnings`; `RUSTDOCFLAGS="-D warnings" cargo doc
--no-deps --workspace`; `cargo fmt --all --check`;
`check-error-payload-hygiene.py`; `check-secret-slot-hygiene.sh`;
`check-ci-wiring.py`.

**Docs:** README and ROADMAP were not changed; this is a test-layout move
with no behaviour or user-visible change. Doc citations of `prepare.rs:NNN`
all point into lines 1-619, which did not move.

Filed: **#777** (`prepare.rs` is still 624 lines of production code; the
issue proposes a split).

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green. Then comment
   on #95 that it is closed in code (the `(#N)`, not `Closes #N`, convention).
2. **Manual GUI pass** (needs the user at the devices; carried over from
   #752 / #766). To poison a device: sync once, restore an older
   `manifest.cbor.enc`, then unlock. Acceptance: the reset prompt appears,
   and "Reset and open" opens the vault. Desktop and Android have never had
   the #745 pass. Also change one setting on each of two devices before
   syncing; both changes should survive (#766).
3. **#764**: an Equal-arm fold step can keep a concurrent step's merged
   plaintext under a real copy's clock with no tick. Theoretical, but in the
   same family as #759 / #761 / #766. Acceptance: a failing test that builds
   the fold sequence, then the fix, with the equal-clock invariant
   (vault-format §6.5.1) stated in the test.
4. **#777**: split `prepare.rs`'s production code. Acceptance as in the
   issue: a verbatim move and an unchanged lib test-name set.
5. **Still over 500 and tracked:** #737's four files (bridge
   `vault/manifest.rs`, uniffi `errors/vault.rs` and `namespace/mod.rs`,
   desktop `ipc_integration.rs`; re-measure, as the issue's counts are older),
   #772 (`tests/save_block.rs`), #729, #686, #688. `core/tests/sync_merge_write.rs`
   is exactly 500 lines, so one more line puts it over.
6. **Carried over:** #768-#771, #753-#756, #736, #734, #740-#742, #747 /
   #748, #738, #731, #649, #683, #677, #668 / #693 (spec questions),
   #699 / #701-#705 and #763.

## (3) Open decisions and risks

- **Glob re-exports widen what `sync_helpers` exports.** Each `pub use
  sub::*;` re-exports everything `pub` in that file. Nothing new is `pub`;
  the three shared private items are `pub(super)`, so they stay inside
  `sync_helpers`. A new `pub` item in a submodule now reaches every test
  binary automatically, which is the intent.
- Standing risks from the #766 baton are unchanged: v1 keeps
  `block_version` values it does not understand, and `UnknownValue` is not
  zeroize-typed.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/size-caps
pwd && git branch --show-current     # feature/size-caps
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/size-caps --json number -q '.[0].number')"
cargo test --release --locked -p secretary-core --test sync_merge
```

If the PR has merged, remove this worktree and branch, then start the next
item from `main`.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
