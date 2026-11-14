# Session Sync + Stale-Write Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Any unlocked session syncs with no password, and no session on any
platform can write a manifest over a vault that changed on disk under it.

**Architecture:** Core gains one shared post-unlock re-verification
(`verify_vault_state`) used by `open_vault`, by the merge commit (which now
takes the session's `UnlockedIdentity` instead of a password) and by a new
bridge `refresh_manifest`. Every core manifest writer first checks that the
on-disk envelope is byte-identical to the one the session holds
(`ensure_manifest_unchanged_on_disk`), refusing with a new typed error. The
bridge adds session-sync calls that refresh the handle after a pass. iOS
switches to them; desktop/Android refresh after their password pass; the Mac
app gets a Reload action.

**Tech Stack:** Rust (core, cli, bridge, uniffi 0.31, pyo3 0.28), Swift
(SwiftPM packages + XcodeGen apps), Kotlin (Gradle), Tauri 2 + Svelte.

**Spec:** `docs/superpowers/specs/2026-11-14-session-sync-design.md` (approved
2026-11-14). Read it before any task.

## Global Constraints

- Worktree: `/Users/hherb/src/secretary/.worktrees/session-sync`, branch
  `feature/session-sync`. Use absolute worktree paths with Edit/Write.
- Cargo always `--release`. Gates: `cargo test --release --workspace`,
  `cargo clippy --release --workspace --tests -- -D warnings`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`, `cargo fmt --all`,
  `uv run scripts/check-error-payload-hygiene.py`,
  `bash ffi/scripts/check-lean-binding.sh`.
- Judge every gate by its exit code; never pipe a test command into `grep`/`tail`
  without `set -o pipefail`.
- No weaker re-verification anywhere: manifest hybrid signature (both halves),
  VL-1 owner-card key binding, and every block fingerprint are checked before a
  commit writes.
- No new held secret. No on-disk format, crypto or merge change. If a `docs/`
  normative edit seems needed, stop and ask.
- Existing password sync calls keep their signatures and return values.
- Every new error detail is a literal or a sanctioned `detail::*` constructor.
- 500-line cap: do not grow `core/src/vault/orchestrators.rs` (2999 lines) or
  `core/src/sync/state.rs` beyond a few lines; new logic goes in new files.
  `ffi/secretary-ffi-bridge/src/sync/orchestration.rs` (545) must not grow.
- One commit per task minimum; every commit compiles and passes its gates.
  End commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Python via `uv` only.

## Review Focus

1. **Cloud delivered the manifest before the block files.** A session sync pass
   succeeds, then the refresh fails with `BlockFileMissing`. Expect: the call
   returns that error, the handle is unchanged, and a retry once the files
   arrive succeeds. Test: Task 5 `session_sync_refresh_failure_leaves_handle_and_retry_succeeds`.
2. **A session that only made its own writes is never refused.** A chain like
   save, trash, restore, purge, empty-trash through one handle must all
   succeed. Test: Task 2 `own_write_chain_is_never_refused`.
3. **Envelope byte round-trip.** If `encode_manifest_file(decode(bytes)) != bytes`
   for some vault, every write on that vault is refused forever. Test: Task 2
   `manifest_envelope_round_trips_byte_identically` on golden vaults 001 and 002.
4. **Lock screen mid-sync (handle wiped).** Expect a typed error, no write, and
   no panic. Test: Task 5 `session_sync_on_wiped_identity_writes_nothing`.
5. **Writes after a detected rollback.** The session handle stays on the newer
   state and the disk holds the older one. Expect: session sync returns
   `RollbackRejected` and does not refresh, and the next write is refused with
   `VaultChangedOnDisk`. Test: Task 5 `rollback_rejected_does_not_refresh_and_writes_stay_refused`.

---

### Task 1: `FfiVaultError::VaultChangedOnDisk` across every binding and platform

The variant lands first with no producer, so each later task compiles with
no interim fold.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (variant + doc)
- Modify: `ffi/secretary-ffi-uniffi/src/errors/vault.rs`, `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Modify: `ffi/secretary-ffi-py/src/errors.rs`, `ffi/secretary-ffi-py/src/lib.rs`
- Modify: `core/tests/conformance_kat_helpers/errors.rs`
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`, `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt`
- Modify: `desktop/src-tauri/src/errors/{types,mapping,tests}.rs`, `desktop/src/lib/errors.ts`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift`, `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultErrorMapping.swift` (+ any `SecretFreeError` conformance file that switches over `VaultAccessError`)
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt`, the `VaultBrowseError` sealed type in `:vault-access`, and every exhaustive `when` over it in `:browse-ui` / `:app`

**Interfaces:**
- Produces: `FfiVaultError::VaultChangedOnDisk` (fieldless),
  `#[error("the vault changed on disk since it was opened; sync, then retry")]`.
  uniffi `VaultError.VaultChangedOnDisk`; pyo3 exception `VaultChangedOnDisk`
  (mirror `SyncEvidenceStale`'s class and registration); desktop
  `AppError::VaultChangedOnDisk`; iOS `VaultAccessError.vaultChangedOnDisk`;
  Android `VaultBrowseError.VaultChangedOnDisk`.

- [ ] **Step 1: Write the failing desktop mapping test** in `desktop/src-tauri/src/errors/tests.rs`, mirroring the `SyncDecisionsIncomplete` pair: `map_ffi_error(FfiVaultError::VaultChangedOnDisk)` matches `AppError::VaultChangedOnDisk`, and its serde value has the new kind string. Add the iOS case `XCTAssertEqual(mapVaultError(.VaultChangedOnDisk), .vaultChangedOnDisk)` to the existing VaultErrorMapping test file, and a Kotlin `BrowseMapping` test asserting `VaultBrowseError.VaultChangedOnDisk`.
- [ ] **Step 2: Run `cargo test --release -p secretary-desktop errors`** (use the crate's real package name). Expected: compile FAIL, no `VaultChangedOnDisk`.
- [ ] **Step 3: Add the variant and an explicit arm at every site in Files.** User-facing copy (iOS `errorDescription`, desktop `errors.ts`, Android message): "This vault changed on another device since you opened it. Sync, then try again." The iOS and Android mappers have a `default`/`else`, so the new arm must be explicit and placed above them.
- [ ] **Step 4: Run the gates:**
  - `cargo test --release --workspace`
  - clippy
  - `uv run scripts/check-error-payload-hygiene.py`
  - `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh`
  - `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh`
  - `cd android && ./gradlew :kit:testDebugUnitTest :app:assembleDebug`
  - `cd desktop && pnpm test`
  - `cd ios/SecretaryVaultAccess && swift test`
  - `cd ios/SecretaryKit && swift test`

  Expected: all exit 0.
- [ ] **Step 5: Commit** `Add FfiVaultError::VaultChangedOnDisk across bindings and platforms (#101)`.

### Task 2: Core stale-base guard on every manifest writer

**Files:**
- Create: `core/src/vault/session_state.rs`. It holds the guard now and gains
  `verify_vault_state` in Task 3. Declare it in `core/src/vault/mod.rs`.
- Modify: `core/src/vault/mod.rs` (new `VaultError::ManifestChangedOnDisk`)
- Modify: `core/src/vault/orchestrators.rs` (`save_block`, `share_block`, `revoke_block_recipient`, `trash_block`, `restore_block`: one guard call each as the first filesystem-touching statement)
- Modify: `core/src/vault/purge.rs` (`purge_block`: before its first file op, including the idempotent re-purge branch's `remove_trash_files`; `purge_batch_commit`: first statement, which covers `empty_trash` and `retention::auto_purge_expired`)
- Modify: `core/src/vault/repair/orchestration.rs` (`repair_vault`: guard against the `manifest_file` it just read, immediately before `resign_and_write_manifest`)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (`VE::ManifestChangedOnDisk => FfiVaultError::VaultChangedOnDisk`)
- Test: `core/tests/stale_session_guard.rs` (new)

**Interfaces:**
- Produces:
  - `pub(crate) fn ensure_manifest_unchanged_on_disk(folder: &Path, expected: &ManifestFile) -> Result<(), VaultError>`: reads `manifest.cbor.enc` and compares it to `encode_manifest_file(expected)?`. If they differ it returns `ManifestChangedOnDisk`; a read failure is `VaultError::Io` with a static context. Its doc comment states the accepted check-then-write TOCTOU residual (spec §5.2).
  - `VaultError::ManifestChangedOnDisk` (fieldless), `#[error("the vault manifest changed on disk since this session loaded it")]`.

- [ ] **Step 1: Census the writers.** Run `grep -rn "resign_and_write_manifest(\|join(MANIFEST_FILENAME)\|&mut OpenVault" core/src` and confirm the list in Files is complete: every production fn that takes an `OpenVault` and writes or deletes any vault file. Also grep the bridge for core writer calls (`grep -rn "secretary_core::vault::\(save_block\|share_block\|revoke\|trash_block\|restore_block\|purge\|empty_trash\|auto_purge\)" ffi/secretary-ffi-bridge/src`) and confirm each bridge write reaches one of them. Record any addition in the commit message.
- [ ] **Step 2: Write the red reproduction** in `core/tests/stale_session_guard.rs`, plus a `snapshot_tree(folder) -> BTreeMap<PathBuf, Vec<u8>>` helper that covers every file under the vault folder:

```rust
#[test]
fn stale_handle_save_block_is_refused_and_disk_untouched() {
    let tmp = copy_dir_to_tempdir(&core_test_data_dir().join("golden_vault_001"));
    let pw = SecretBytes::new(golden_vault_001_password().to_vec());
    let mut stale = open_vault(tmp.path(), Unlocker::Password(&pw), None).unwrap();
    let mut fresh = open_vault(tmp.path(), Unlocker::Password(&pw), None).unwrap();
    save_block(tmp.path(), &mut fresh, /* new block */ .., device_b, 2_000, &mut rng).unwrap();
    let before = snapshot_tree(tmp.path());
    let err = save_block(tmp.path(), &mut stale, /* other new block */ .., device_a, 3_000, &mut rng)
        .unwrap_err();
    assert!(matches!(err, VaultError::ManifestChangedOnDisk));
    assert_eq!(snapshot_tree(tmp.path()), before);
    open_vault(tmp.path(), Unlocker::Password(&pw), None).expect("vault still opens");
}
```

- [ ] **Step 3: Run `cargo test --release -p secretary-core --test stale_session_guard`.** Expected: compile FAIL, no `ManifestChangedOnDisk`. After a temporary stub variant it would fail by succeeding, which is the bug.
- [ ] **Step 4: Implement the guard and the variant, map the variant in the bridge, and call the guard in `save_block`.** Then run Step 3's command. Expected: PASS.
- [ ] **Step 5: Add one refusal test per remaining writer**, each with the same shape: a stale handle, a fresh handle writes, the stale writer gets `Err(ManifestChangedOnDisk)`, and `snapshot_tree` is unchanged:
  - `stale_share_block_is_refused`
  - `stale_revoke_is_refused`
  - `stale_trash_block_is_refused`
  - `stale_restore_block_is_refused`
  - `stale_purge_block_is_refused`
  - `stale_repurge_branch_deletes_nothing` (the trash entry is already purged in the stale handle)
  - `stale_empty_trash_is_refused`
  - `stale_auto_purge_is_refused`
  - `stale_repair_vault_is_refused` (another process rewrites the manifest between repair's read and its write; use the narrowest seam that exists, and if none does, note the gap in the commit message)

  Borrow fixture helpers from `share_block.rs`, `trash_restore.rs` and `purge.rs` (copy the few lines you need; integration-test files cannot share private fns except via `common/`). Run each new test, confirm it fails, add the guard call, and confirm it passes.
- [ ] **Step 6: Add the Review-Focus tests:**
  - `own_write_chain_is_never_refused`: one handle runs save, trash, restore, then trash and purge, then empty-trash, and every call is `Ok`.
  - `manifest_envelope_round_trips_byte_identically`: for `golden_vault_001` and `golden_vault_002`, `encode_manifest_file(&decode_manifest_file(&bytes)?)? == bytes`.
- [ ] **Step 7: Run the full gates** (workspace test, clippy, doc, fmt, payload guard). Expected: exit 0. The pre-existing suites must stay green, which proves no false positive on normal write paths.
- [ ] **Step 8: Commit** `Refuse manifest writes over a vault that changed on disk (#101)`.

### Task 3: Extract `verify_vault_state`; `open_vault` uses it

**Files:**
- Modify: `core/src/vault/session_state.rs`
- Modify: `core/src/vault/orchestrators.rs` (`open_vault` body becomes unlock plus `verify_vault_state_with_toml`; the net line count must not grow)
- Modify: `core/src/vault/mod.rs` (re-export `verify_vault_state`, `VerifiedVaultState`)
- Test: `core/tests/stale_session_guard.rs` (or `open_vault.rs` if it fits under 500 lines)

**Interfaces:**
- Produces:
  - `pub struct VerifiedVaultState { pub owner_card: ContactCard, pub manifest: Manifest, pub manifest_file: ManifestFile }` (`Debug`)
  - `pub fn verify_vault_state(folder: &Path, identity: &UnlockedIdentity, local_highest_clock: Option<&[VectorClockEntry]>) -> Result<VerifiedVaultState, VaultError>`: reads `vault.toml`, then delegates.
  - `pub(crate) fn verify_vault_state_with_toml(folder: &Path, vault_toml_bytes: &[u8], identity: &UnlockedIdentity, local_highest_clock: Option<&[VectorClockEntry]>) -> Result<VerifiedVaultState, VaultError>`. It runs, in today's `open_vault` order: `read_and_verify_manifest`, `verify_block_fingerprints`, `complete_pending_trash_renames`, `sweep_purged_trash_files`. `open_vault` passes the `vault_toml_bytes` it unlocked with, so the toml is not read twice.
  - `pub` rather than the spec's crate-private, because the bridge's `refresh_manifest` (Task 5) consumes it.

- [ ] **Step 1: Write the tests:**
  - `verify_vault_state_matches_open_vault`: on golden_vault_001, `open_vault(..)` and `verify_vault_state(folder, &open_with_password(..), None)` yield equal `manifest`, `manifest_file` (compare encoded bytes) and owner-card canonical bytes.
  - `verify_vault_state_rejects_tampered_block_fingerprint`: flip one byte of a block file and expect `BlockFingerprintMismatch`.
  - `verify_vault_state_refuses_rollback`: a `local_highest_clock` that strictly dominates the manifest clock gives `VaultError::Rollback`.
- [ ] **Step 2: Run them.** Expected: compile FAIL.
- [ ] **Step 3: Implement**, moving the existing step comments from `open_vault` with the code.
- [ ] **Step 4: Run the full workspace test and clippy.** Expected: exit 0. All `open_vault*` suites must be unchanged.
- [ ] **Step 5: Commit** `Extract verify_vault_state shared by open and commit (#101)`.

### Task 4: Merge commit from an unlocked identity; CLI drops the password

**Files:**
- Modify: `core/src/sync/commit/write.rs`
- Modify: `cli/src/pipeline/passes.rs` (4 fns), `cli/src/pipeline/outcomes.rs` (if it calls them), `cli/src/daemon.rs` (`run_against_vault`), `cli/src/main.rs`
- Modify: `ffi/secretary-ffi-bridge/src/sync/orchestration.rs` (drop `&password` from the two pass calls only; the public signatures are unchanged)
- Modify tests: `core/tests/{sync_merge,sync_merge_crash,sync_merge_toctou,sync_merge_vetoes,sync_merge_proptest,sync_kat}.rs`, `core/tests/convergence_helpers/sync_drive.rs`, `cli/tests/{pipeline_integration,sync_pass_integration}.rs` (21 core call sites; each already has an `UnlockedIdentity` in scope)

**Interfaces:**
- Consumes: `verify_vault_state` (Task 3).
- Produces:
  - `pub fn commit_with_decisions(vault_folder: &Path, identity: &UnlockedIdentity, draft: DraftMerge, decisions: Vec<VetoDecision>, now_ms: u64) -> Result<SyncState, SyncError>`. Step 1 becomes `verify_vault_state(vault_folder, identity, None).map_err(SyncError::Vault)?`. The IBK comes from `identity.identity_block_key`.
  - `OwnerKeyBag::derive(bundle: &IdentityBundle, owner_card: &ContactCard)`.
  - `rewrite_one_block` takes `manifest: &Manifest` in place of `open: &OpenVault`.
  - CLI:
    - `run_one(vault_folder, identity, state, veto_ux, now_ms)`
    - `sync_pass_pause_on_conflict(vault_folder, identity, state, now_ms)`
    - `sync_pass_inspect(vault_folder, identity, state, now_ms)`
    - `sync_pass_commit_decisions(vault_folder, identity, state, expected, decisions, now_ms)`
    - `run_against_vault` loses `password`.

    In each case, only the `password` parameter is removed; the order is otherwise unchanged.

- [ ] **Step 1: Write the failing test** `identity_commit_aborts_on_tampered_block_fingerprint` in `core/tests/sync_merge_crash.rs`. Build a diverging draft as that file already does, flip a byte in a block file listed in the manifest, and call `commit_with_decisions(&folder, &identity, draft, vec![], now)`. Expect `Err(SyncError::Vault(VaultError::BlockFingerprintMismatch { .. }))`, with the manifest bytes unchanged.
- [ ] **Step 2: Run `cargo test --release -p secretary-core --test sync_merge_crash`.** Expected: compile FAIL (type mismatch).
- [ ] **Step 3: Change the signature and update every call site.** `cli/src/main.rs` must drop the password right after `open_with_password` succeeds: let it go out of scope, and do not hand it to the daemon. Update the module and fn docs that say "re-opens the vault" or name the password.
- [ ] **Step 4: Run the full workspace test, clippy and doc.** Expected: exit 0, and the sync merge, veto, TOCTOU and crash suites pass unchanged. Confirm with `grep -rn "password" core/src/sync/commit cli/src/pipeline` that no stale password reference is left.
- [ ] **Step 5: Commit** `Commit merges from the unlocked identity; drop the sync password from the CLI (#101)`.

### Task 5: Bridge `refresh_manifest` and session sync; uniffi + pyo3 projection

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/sync/session.rs` (session fns + refresh)
- Modify: `ffi/secretary-ffi-bridge/src/sync/orchestration.rs`. Move the body shared by the password and session variants (lockfile, state load, pass, persist) into one private helper that both call; the file must shrink.
- Modify: `ffi/secretary-ffi-bridge/src/sync/mod.rs`, `ffi/secretary-ffi-bridge/src/lib.rs` (exports)
- Modify: `ffi/secretary-ffi-bridge/src/identity.rs` (`with_core`), `ffi/secretary-ffi-bridge/src/vault/manifest.rs` (`replace_verified_state`)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/sync.rs`, `ffi/secretary-ffi-uniffi/src/secretary.udl`, `ffi/secretary-ffi-py/src/sync.rs`, `ffi/secretary-ffi-py/src/lib.rs`
- Test: `ffi/secretary-ffi-bridge/src/sync/session/tests.rs` (or `session_tests.rs`, following the crate's sibling-tests pattern)

**Interfaces:**
- Consumes: `verify_vault_state`, identity-based CLI passes (Tasks 3–4).
- Produces (bridge, public):
  - `pub fn refresh_manifest_in(state_dir: &Path, identity: &UnlockedIdentity, manifest: &OpenVaultManifest) -> Result<(), FfiVaultError>`. It loads `highest_vector_clock_seen` via `secretary_cli::state::load(state_dir, vault_uuid)`. An unreadable state means no baseline, mirroring `enforce_rollback_resistance_in`. It then calls `verify_vault_state(folder, core_identity, Some(clock))` and, only on `Ok`, `manifest.replace_verified_state(..)`. On any `Err` the handle is unchanged.
  - `pub fn refresh_manifest(identity, manifest)`: the default-dir wrapper, like `sync_vault`.
  - `pub fn sync_vault_with_session_in(state_dir: &Path, identity: &UnlockedIdentity, manifest: &OpenVaultManifest, now_ms: u64) -> Result<SyncOutcomeDto, FfiVaultError>`
  - `pub fn sync_commit_decisions_with_session_in(state_dir: &Path, identity: &UnlockedIdentity, manifest: &OpenVaultManifest, decisions: Vec<VetoDecisionDto>, manifest_hash: Vec<u8>, now_ms: u64) -> Result<SyncOutcomeDto, FfiVaultError>`

  Both session fns: the folder and `vault_uuid` come from the manifest handle. They run the shared helper with the session's core identity, and while still holding the lockfile they refresh on `AppliedAutomatically | SilentMerge | MergedClean | NothingToDo`, passing the in-memory `state.highest_vector_clock_seen` as the baseline. They never refresh on `RollbackRejected | ConflictsPending`. A refresh error is returned as the call's `Err`. Doc comments say that a retry is safe.
- Produces (bridge, crate-private):
  - `UnlockedIdentity::with_core<R>(&self, f: impl FnOnce(&secretary_core::unlock::UnlockedIdentity) -> R) -> Option<R>`: runs `f` under the handle's lock and returns `None` if the handle is wiped. No copy of the secrets is made.
  - `OpenVaultManifest::replace_verified_state(&self, s: VerifiedVaultState) -> Result<(), ReplaceManifestError>`: replaces manifest, manifest_file and owner_card under one lock.

  A wiped identity or manifest gives `FfiVaultError::CorruptVault { detail: detail::literal("vault handle has been closed") }`.
- Produces (bindings): uniffi and pyo3 `refresh_manifest(state_dir, identity, manifest)`, `sync_vault_with_session(state_dir, identity, manifest, now_ms)` and `sync_commit_decisions_with_session(state_dir, identity, manifest, decisions, manifest_hash, now_ms)`. Swift will see `refreshManifest(stateDir:identity:manifest:)` and the matching camelCase forms.

- [ ] **Step 1: Write the bridge tests**, all on a writable golden_vault_001 copy, opened via `open_vault_with_password` into bridge handles:
  - `session_sync_then_write_succeeds`: a second core open writes a block, then `sync_vault_with_session_in` returns `AppliedAutomatically`, then a bridge `save_block` through the session handles is `Ok` and `block_summaries()` contains the other writer's block.
  - `password_sync_then_refresh_then_write_succeeds`: `sync_vault_in`, then `refresh_manifest_in`, then a bridge write is `Ok`. Without the refresh, the same write is `Err(VaultChangedOnDisk)`.
  - `refresh_refuses_rollback_and_keeps_handle`: seed state with a clock that dominates the disk manifest, and expect `refresh_manifest_in` to be `Err(CorruptVault{..})` with `block_summaries()` unchanged.
  - `rollback_rejected_does_not_refresh_and_writes_stay_refused` (Review Focus 5).
  - `session_sync_refresh_failure_leaves_handle_and_retry_succeeds` (Review Focus 1): after the other writer's pass, delete one of its block files and expect `Err`, with the handle's block count unchanged. Restore the file, retry, and expect `Ok`.
  - `session_sync_on_wiped_identity_writes_nothing` (Review Focus 4): call `identity.wipe()`, then the session sync, and expect `CorruptVault`, with the manifest bytes unchanged.
  - `conflicts_pending_does_not_refresh`: drive a veto fixture as the existing orchestration tests do. The pass returns `ConflictsPending` and the handle is unchanged. `sync_commit_decisions_with_session_in` then gives `MergedClean`, and the handle reflects the commit (a write succeeds).
- [ ] **Step 2: Run `cargo test --release -p secretary-ffi-bridge sync::session`.** Expected: compile FAIL.
- [ ] **Step 3: Implement the bridge**, then project it to uniffi (UDL plus `namespace/sync.rs`) and pyo3, mirroring how `trash_block` takes the two handles (`Arc<UnlockedIdentity>`, `Arc<OpenVaultManifest>` on uniffi).
- [ ] **Step 4: Run the gates:**
  - workspace test, clippy, doc
  - payload guard
  - `bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh`
  - both `run_conformance.sh`

  Expected: exit 0.
- [ ] **Step 5: Commit** `Bridge: sync through the open session and refresh it from disk (#101)`.

### Task 6: Desktop and Android refresh after a password sync

**Files:**
- Modify: `desktop/src-tauri/src/commands/sync.rs` (`sync_now_impl`, `sync_commit_decisions_impl`)
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultOpenPort.kt` (`UniffiVaultSession.refreshFromDisk(stateDir: String)`, lock-guarded like its other handle accesses)
- Modify: `android/kit/src/main/kotlin/org/secretary/sync/UniffiVaultSyncPort.kt`, `android/kit/src/main/kotlin/org/secretary/sync/VaultSyncFactory.kt`, and the `makeVaultSync` caller in `:app`
- Test: `desktop/src-tauri/src/commands/` sync tests (where `sync_now_impl` is tested today); `android/kit/src/test/kotlin/org/secretary/sync/UniffiVaultSyncPortTest.kt` (create if absent)

**Interfaces:**
- Consumes: bridge `refresh_manifest` (desktop, default dir, matching `bridge_sync_vault`), uniffi `refreshManifest` (Android).
- Produces:
  - Android `UniffiVaultSyncPort(refreshSession: ((stateDir: String) -> Unit)? = null, …existing seams)`. After `sync`/`commitDecisions` return an outcome other than `RollbackRejected`/`ConflictsPending`, it calls `refreshSession(stateDir)`. A refresh exception goes through `callMappingErrors`.
  - `makeVaultSync(folder, stateDir, vaultUuid, session: UniffiVaultSession? = null, wallClock)` wires `session::refreshFromDisk`.

- [ ] **Step 1: Write the failing tests:**
  - Desktop: `sync_now_refreshes_session_so_next_write_succeeds`, on a temp vault. Another core open writes, then `sync_now_impl` runs, then a write command is `Ok`.
  - Kotlin: `refreshSession` is called after a `MergedClean` fake outcome and not after `RollbackRejected` or `ConflictsPending`, using the existing injectable `syncFn`/`commitFn` seams.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.** On desktop, refresh inside the same `with_unlocked` closure on the same outcome rule as the Android port.
- [ ] **Step 4: Run** `cd desktop && pnpm test`, the desktop cargo tests, and `cd android && ./gradlew :kit:testDebugUnitTest :app:assembleDebug`. Expected: exit 0.
- [ ] **Step 5: Commit** `Desktop and Android: refresh the session after a password sync (#101)`.

### Task 7: iOS session sync behind the re-auth gate

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultSyncPort.swift`, `SyncCoordinator.swift`, `VaultSyncError.swift`, `VaultSession.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/VaultSyncViewModel.swift`, `VaultBrowseViewModel.swift`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultSyncPort.swift` and the fake `VaultSession`(s) in that target
- Create: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession+Sync.swift`
- Delete: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSyncPort.swift`, `ios/SecretaryApp/Sources/SyncPasswordSheet.swift`
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/VaultSyncFactory.swift`, `ios/SecretaryApp/Sources/{SecretaryApp,VaultBrowseScreen,ConflictResolutionSheet}.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/VaultSyncViewModelTests.swift`, `.../SecretaryVaultAccessTests/SyncCoordinatorTests.swift`, `ios/SecretaryKit/Tests/SecretaryKitTests/UniffiVaultSyncPortOffMainActorTests.swift` (adapt or replace)

**Interfaces:**
- Consumes: uniffi `syncVaultWithSession`, `syncCommitDecisionsWithSession`, `refreshManifest`, `syncStatus`.
- Produces:
  - `VaultSyncPort`: `status(stateDir:vaultUuid:)`, `sync(stateDir:nowMs:)`, `commitDecisions(stateDir:decisions:manifestHash:nowMs:)`, with no password and no folder.
  - `SyncCoordinator(port:stateDir:)`, `runPass(nowMs:)`, `resolve(decisions:nowMs:)`.
  - `VaultSyncError.reauthFailed(String)`.
  - `VaultSyncViewModel.init(coordinator:wallClock:gate: WriteReauthGate, vaultUuid:monitor:onVaultChanged: (@MainActor () -> Void)? = nil)`:
    - `syncAtUnlock()`: no gate.
    - `syncNow()`: `gate.authorizeWrite(reason: "Confirm syncing this vault")` first; a refusal sets `lastError = .reauthFailed(..)` and runs no pass.
    - `resolve(decisions:)`: gated the same way.
    - `onVaultChanged` is called after every successful pass or commit whose outcome is not `.rollbackRejected` or `.conflictsPending`.
    - Removed: `passwordSheetPresented`, `beginInteractiveSync`, `runInteractivePass`, `dismissPasswordSheet`.
  - `VaultSession.refreshFromDisk(stateDir: String) throws` (used by Task 8).
  - `VaultBrowseViewModel.reloadFromDisk(stateDir: String)`: calls `session.refreshFromDisk`, then `loadBlocks()` and `refresh()`, and maps errors into `error`.
  - `extension UniffiVaultSession: VaultSyncPort`: it uses its own handles through a lock-guarded helper (the `+Trash.swift` pattern, never the raw handles outside `lock.withLock`), and its `sync`/`commitDecisions` run in `runOffMainActor`.
  - `makeVaultSync(session: VaultSession, folder: URL, stateDir: URL, gate: WriteReauthGate, onVaultChanged: @escaping @MainActor () -> Void)`: casts `session as? VaultSyncPort`, and a non-conforming session is a `preconditionFailure("production sessions conform to VaultSyncPort")`.

- [ ] **Step 1: Rewrite the VM and coordinator tests to the new API**, and add:
  - `testSyncNowAsksGateThenRunsPass`: the gate spy is called once, then one port call.
  - `testSyncNowGateRefusalRunsNoPass`: zero port calls and `lastError == .reauthFailed(_)`.
  - `testSyncAtUnlockDoesNotAskGate`.
  - `testResolveIsGated`.
  - `testOnVaultChangedFiresAfterMergedCleanNotAfterRollbackOrConflict`.
  - `testReloadFromDiskReloadsBlocks`: a fake session whose `blockSummaries` changes after `refreshFromDisk`.
  - `testVaultChangedOnDiskErrorSurfacesOnWrite`: a fake session write throws `.vaultChangedOnDisk`, and `vm.error == .vaultChangedOnDisk`.
- [ ] **Step 2: Run `cd ios/SecretaryVaultAccess && swift test`.** Expected: compile FAIL.
- [ ] **Step 3: Implement the packages and the app wiring:**
  - Pass the same gate the browse VM gets to `makeVaultSync` on both the password and the device path.
  - Set `onVaultChanged` to reload the browse VM (`loadBlocks()` + `refresh()`).
  - Make sync-at-unlock run on both paths.
  - The badge tap and "Sync now" call `syncNow()`.
  - `ConflictResolutionSheet` loses its password field.
  - On `.vaultChangedOnDisk`, `VaultBrowseScreen` shows the message with a "Sync now" button that calls `syncModel.syncNow()`.
- [ ] **Step 4: Run the gates:**
  - `swift test` in `ios/SecretaryVaultAccess` and `ios/SecretaryKit` (warm the xcframework build at controller level first; see memory note)
  - `bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh`
  - an XcodeGen + `xcodebuild` simulator build of `ios/SecretaryApp`

  Expected: exit 0. If `VaultBrowseScreen.body` hits the type-check limit, extract into a `@ViewBuilder`.
- [ ] **Step 5: Commit** `iOS: sync through the open session behind the re-auth gate (#101)`.

### Task 8: macOS interim "Reload" on `VaultChangedOnDisk`

**Files:**
- Modify: `ios/SecretaryMacApp/Sources/MacBrowseView.swift` (error display at ~line 250), and wherever the Mac app resolves its state dir (`defaultSyncStateDir()` from SecretaryKit)
- Test: covered by Task 7's `testReloadFromDiskReloadsBlocks`; this task is view wiring only

**Interfaces:**
- Consumes: `VaultBrowseViewModel.reloadFromDisk(stateDir:)` (Task 7).

- [ ] **Step 1: When `viewModel.error == .vaultChangedOnDisk`, show its message plus a "Reload" button** that calls `reloadFromDisk(stateDir: try defaultSyncStateDir().path)`; the refused edit is not kept. Add a one-line comment saying it is removed when the Mac sync slice lands.
- [ ] **Step 2: Build the Mac app** with its XcodeGen + `xcodebuild` scheme. Expected: exit 0.
- [ ] **Step 3: Manual check, recorded in the commit message.** Copy a vault to a temp dir, open it in the Mac app, write to it from the CLI or a second open, then edit in the app. The message and Reload appear, and Reload shows the other change.
- [ ] **Step 4: Commit** `macOS: Reload action for a vault that changed on disk (#101)`.

### Task 9: Docs, issues, final gate

**Files:**
- Modify: `ROADMAP.md`, `README.md` (status rows; brief, per the README style memory), the `CLAUDE.md` "Commands"/sync lines that say the commit re-opens with a password, and `docs/manual/contributors/memory-hygiene-audit-internal.md` only if a secret-handling site changed (the CLI password lifetime shrank, so note it there)

- [ ] **Step 1: Update the docs** and grep for stale claims: `grep -rn "re-opens the vault\|re-prompt\|sync password" core/src cli/src ffi ios android desktop docs/manual ROADMAP.md README.md CLAUDE.md`.
- [ ] **Step 2: File the three follow-up issues:** auto-sync on folder change, desktop onto session sync, and Android onto session sync. Also file: the bridge folds `Rollback` into `CorruptVault`, so a refused refresh cannot show a rollback-specific message.
- [ ] **Step 3: Run every gate from Global Constraints and the platform gates from Tasks 1, 5, 6 and 7 once more on the final tree.** Expected: all exit 0.
- [ ] **Step 4: Commit** `Docs: session sync and the stale-write guard (#101)`.
