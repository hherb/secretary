# NEXT_SESSION.md: a whole-block save keeps what the caller cannot see (#766)

Branch `feature/save-block-preserve`, worktree
`.worktrees/save-block-preserve`, base `c81883a5` (`main`, the #765
merge). The PR is open; see `gh pr list --head feature/save-block-preserve`.

At session start #765 (the previous baton's PR) had merged. Its worktree and
the older `merge-plaintext-clock` one were removed, with their branches.

## (1) What shipped

| SHA | What |
|---|---|
| `cad43617` | **Code + tests + ROADMAP/README.** One pure `edit/rebuild.rs::rebuild_record(prior, ..)` now builds every record from caller content. `edit_record`, `append_record` and the bridge's whole-block `save_block` share it, and the three copies are gone (`build_new_record`, `RecordInput::into_core_record`). On an update `save_block` decrypts the block's current copy and keeps what the caller cannot see. |
| (this commit) | This handoff and the symlink retarget. |

**Owner ruling (this session):** the whole-block save gets the edit
primitives' semantics, not just the versions and `unknown` maps #766 named.
On an update, `BlockInput::into_block_plaintext(prior, ..)` keeps:

- the block's `block_version`, `schema_version` and block-level `unknown`;
- per record matched by `record_uuid`: `created_at_ms`, `tombstoned_at_ms`
  (a resurrection keeps its death clock, as `resurrect_record` does), the
  record-level `unknown`, and per field matched by name the field `unknown`;
- the `last_mod` / `device_uuid` of every field whose value did not change.
  Before this, `write_settings` rewrote all four settings fields at `now`, so
  a settings change on one device could overwrite another device's
  concurrent change to a different setting (field merge is last-write-wins).

A new block is still written at v1 with empty maps. A record left out of the
input is still removed (whole-block replace, unchanged).

**Behaviour change:** an update over a block that cannot be read and verified
(decrypt failure, fingerprint mismatch, missing file) now fails with
`CorruptVault` and leaves the file alone. It used to overwrite the block with
a fresh v1 copy. `read_settings` already failed on such a block, so no app
flow that worked before now breaks, but a corrupt settings block can no longer
be "repaired" by saving settings over it.

**Tests** (`ffi/secretary-ffi-bridge`, lib target):

- `save/tests.rs::an_update_carries_forward_what_the_caller_cannot_see`: a
  later client's block at `(2, 3)` with `unknown` at all three levels, a live
  record (one unchanged field, one changed), a tombstoned record the save
  resurrects, and a record new to the block. It was red at `(1, 1)` on the
  old code.
- `save/tests.rs::an_update_over_an_unreadable_block_is_refused`: one byte of
  the block file flipped. Expects `CorruptVault` and the file unchanged.
- `edit/rebuild.rs`: `without_a_prior_copy_the_record_is_fresh` and
  `with_a_prior_copy_the_hidden_state_is_carried_forward` (pure, no vault).
- The two removed `into_core_record` unit tests are covered by these; the
  duplicate-field-name test now runs through `into_block_plaintext(None, ..)`.

**Mutations** (`scripts/mutate.py`, self-test 20/20; the spec is in the
session scratchpad, not committed). Gate: `cargo test --release --locked
-p secretary-ffi-bridge --lib --no-fail-fast`.

Every row was `RED_AS_EXPECTED`, live by artifact, harness exit 0:

| Mutation | Reds |
|---|---|
| S1: new-or-update block writes `BLOCK_VERSION_V1` | `an_update_carries_forward…` |
| S2: writes `SCHEMA_VERSION_V1` | `an_update_carries_forward…` |
| S3: block `unknown` dropped | `an_update_carries_forward…` |
| S4: no prior record matched (`and_then(\|_\| None)`) | `an_update_carries_forward…` |
| S5: orchestration ignores the decrypted prior (`Ok(_) => None`) | `an_update_carries_forward…` |
| S6: read error swallowed as an insert (`Err(_) => None`) | `an_update_over_an_unreadable_block_is_refused` |
| R1: unchanged-field gate off | save test, rebuild test, `edit_record_preserves_field_clock_for_unchanged_value` |
| R2: `created_at_ms` reset | save test, rebuild test, `edit_record_preserves_unknown_at_all_three_levels` |
| R3: `tombstoned_at_ms` reset | save test, rebuild test |
| R4: record `unknown` dropped | save test, rebuild test, edit keystone |
| R5: changed field's `unknown` dropped | save test, rebuild test, edit keystone |
| R6: unchanged field's `unknown` dropped | save test, rebuild test |

**Gates run, each exit 0, after the last code edit:**

- `cargo test --release --workspace` (109 binaries)
- `cargo clippy --release --workspace --tests -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` (it first
  failed on a private intra-doc link this slice wrote; fixed, re-run green)
- `cargo fmt --all --check`
- `uv run scripts/check-error-payload-hygiene.py`
- `bash scripts/check-secret-slot-hygiene.sh`
- `uv run core/tests/python/conformance.py`: PASS

`edit/mod.rs` went from 558 to 479 lines (under the cap). `save/input.rs` is
252 lines; the new `save/tests.rs` is 243.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green.
2. **Manual GUI pass** (needs the user at the devices; carried over from
   #752). To poison a device, sync once, restore an older
   `manifest.cbor.enc`, then unlock. Acceptance: the reset prompt
   appears, and "Reset and open" opens the vault. Desktop and Android
   have also never had the #745 pass. While there, change one setting on
   each of two devices before syncing; both changes should survive (#766).
3. **#737 / #95: size caps.** `core/src/sync/prepare.rs` is **1015** lines.
   Acceptance: move its in-file test modules to `prepare/tests.rs` with an
   unchanged test-name set. `core/tests/sync_helpers/mod.rs` is **1335**
   lines and `core/tests/sync_merge_write.rs` exactly **500**. Both issues
   carry older counts, so update them when you start.
4. **#764**: an Equal-arm fold step can keep a concurrent step's merged
   plaintext under a real copy's clock with no tick. Theoretical, but in the
   same family as #759 / #761 / #766.
5. **Carried over:** #753, #754, #755, #756, #736, #734, #740 / #741 /
   #742, #747 / #748, #738, #731, #649, #683, #677, #668 / #693 (spec
   questions), #699 / #701-#705 and #763.

## (3) Open decisions and risks

- **#766 is closed in code.** The issue stays open until a human closes it
  (the `(#N)`, not `Closes #N`, convention).
- **A v1 client keeps versions it does not understand.** Same standing risk
  the #761 baton recorded, now on the save path too: before any future format
  revision bumps `block_version` for a body v1 cannot round-trip, it must
  decide whether v1 may edit such a block at all (sync commit, edit paths and
  `save_block` alike).
- **`UnknownValue` is still not zeroize-typed** (memory-hygiene memo's open
  list). The update path now clones `unknown` maps from a decrypted block,
  the same as `edit_record` always did; nothing new, but the clone count on
  this path went from zero to one.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/save-block-preserve
pwd && git branch --show-current     # feature/save-block-preserve
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/save-block-preserve --json number -q '.[0].number')"
cargo test --release -p secretary-ffi-bridge --lib save::tests
```

If the PR has merged, remove this worktree and branch, then start the next
item from `main`.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
