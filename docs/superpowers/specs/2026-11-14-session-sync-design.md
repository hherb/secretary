# Design: sync through the open session, and refuse writes over a changed vault

Status: approved and shipped, 2026-11-14 (PR #739). Branch
`feature/session-sync`, base `13ce2ef8`. Closes the substance of **#101**.

**As shipped, the code differs from this draft in four places.** The draft
text below is left as written; the code is authoritative.

- §5.1: `verify_vault_state` is `pub` and re-exported from
  `core::vault`, not crate-private, because the bridge calls it.
- §5.3: the two `*_with_session` calls do not go through `refresh_manifest`.
  `run_session_pass` calls `verify_vault_state` itself, against the pre-pass
  clock on `SilentMerge` and the post-pass clock on the other refreshing arms,
  not the clock loaded from `state_dir`.
- §5.3: "a repeat pass is `NothingToDo`" is not true after a `SilentMerge`,
  whose persisted clock dominates the disk, so the repeat pass is
  `RollbackRejected` and does not refresh (#730).
- §5.4: no app shows "this vault is older than this device has seen". The
  bridge folds `Rollback` into `CorruptVault` (#734). iOS shows a neutral
  notice on a `RollbackRejected` pass instead.

## 1. Why

The user keeps one vault in iCloud Drive and uses it from a Mac, an iPhone and
an iPad. Two things stand between that and working sync:

1. **Sync needs the master password every time.** Core's merge-commit step
   (`core/src/sync/commit/write.rs::commit_with_decisions`) re-opens the vault
   from the password so it can re-verify the disk before writing. So every
   sync pass re-prompts, runs Argon2id twice, and a Face ID / Touch ID session
   cannot sync at all (`ios/SecretaryApp/Sources/SecretaryApp.swift`, "no sync
   password on the device path"). This blocks native-Mac sync, which is the
   next slice and will reuse the shared Swift sync view model.
2. **An open session overwrites changes made on disk after it opened** (found
   while designing this; by reading, not yet reproduced). Every vault write
   rebuilds the manifest from the session's in-memory copy
   (`OpenVault.manifest` / `.manifest_file`) and writes it back with no
   check that the on-disk manifest is still the one the session loaded
   (`orchestrators.rs::resign_and_write_manifest` and the share/revoke
   re-key path at `orchestrators.rs:~1590`). The in-memory copy goes stale
   when (a) this device runs a sync pass, which writes through a separate
   open, or (b) the cloud client delivers another device's manifest while
   the vault is open. The next local write then reverts the manifest, which
   loses the other device's index entries and very likely leaves block files
   whose fingerprints no longer match, so the next open fails with
   `BlockFingerprintMismatch`. This affects iOS, Android and the Tauri
   desktop alike.

Success: on iOS, any unlocked session (password, recovery, or Face ID) syncs
with no password prompt; no session on any platform can write over a vault
that changed under it; and a session's own sync leaves it able to keep
writing.

## 2. Goals, non-goals, anti-goals

**Goals**
- G1. Core merge commit works from an already-unlocked identity, keeping
  every disk re-verification it does today.
- G2. A bridge "sync with the open session" pair (pass + commit-decisions),
  projected onto uniffi and pyo3, that refreshes the session's manifest
  handle after a successful pass.
- G3. Every manifest-writing vault operation refuses, with a new typed error,
  when the on-disk manifest is not the one the session last loaded or wrote.
- G4. A bridge "refresh the session from disk" primitive, so the password-
  based sync callers (desktop, Android) can bring their session up to date
  after a pass, and so G3 does not turn their post-sync writes into
  permanent refusals.
- G5. iOS uses session sync for every session kind, behind the existing write
  re-auth gate, and handles the new refusal with a clear message plus a
  one-tap sync.

**Non-goals (this slice)**
- Native macOS sync UI (next slice; it reuses the shared view model changed
  here).
- iCloud download-state awareness (`NSMetadataQuery`), slice after that.
- Automatic sync on folder change. Possible once sync needs no credential;
  deferred because a sync is a write and would raise surprise biometric
  prompts. File an issue.
- Moving desktop or Android onto session sync. They keep the password pass
  and gain only the refresh and the new error handling. File an issue each.
- Auto-retrying a refused write after syncing. The user syncs and retries.

**Anti-goals (would make this a failure even if it works)**
- Any weaker re-verification than today: the commit must still verify the
  manifest signature against the owner identity (incl. the VL-1 owner-card
  key binding) and every block fingerprint before writing.
- Holding the master password or any new secret longer than today. The
  session already holds the unlocked identity; nothing else is added.
- Any on-disk format, crypto or merge-semantics change. No `docs/` normative
  edit is expected; if one turns out to be needed, stop and ask.
- Changing what an existing password-based sync call returns or writes.

## 3. Constraints

- Core is security-critical; the CLAUDE.md "verify before decrypt" and
  "both halves" properties apply to every changed path.
- `FfiVaultError` gains a variant: that is a workspace-wide exhaustive-match
  obligation, including the Swift and Kotlin conformance harnesses cargo
  cannot see (run both `run_conformance.sh` scripts), and the Android `:kit`
  + `:app` build.
- The bridge error-payload guard: any new error detail must come from a
  literal or a sanctioned `detail::*` constructor.
- Memory hygiene: no new copy of identity secrets beyond what the existing
  `clone_inner_bundle` save path already makes.
- 500-line split threshold for new and grown files (`core/src/sync/state.rs`
  is already over, #626 — do not grow it).

## 4. Approaches considered

- **A. Sync through the open session (chosen by the user).** Core commit
  takes the unlocked identity; bridge adds session-sync calls; apps gate
  them with the write re-auth gate. Removes the prompt for every session
  kind, removes the double Argon2id, and makes auto-sync possible later.
  Cost: the largest core change, on a security path.
- **B. Sync with any credential.** Generalise the password parameter to
  `Unlocker` (password, recovery, device secret). Smaller core change, but
  password users still type, every sync is a biometric prompt, and no
  auto-sync. Rejected.
- **C. Cache the password in the app.** Keeps the master password in memory
  for the session. Rejected outright.

The stale-write fix (G3) was chosen over "refresh after own sync only"
because only a write-time check also covers changes the cloud client
delivers by itself.

## 5. Decided design

### 5.1 Core: one shared re-verification, used by open and by commit

Extract the part of `open_vault` after the identity unlock into one
crate-private function — working name `verify_vault_state(folder, &UnlockedIdentity, local_highest_clock)`
— returning the owner card, manifest body and manifest envelope. It does what
`open_vault` steps 3-8 do today, in the same order: `read_and_verify_manifest`,
`verify_block_fingerprints`, and the two best-effort trash sweeps.
`open_vault` becomes "unlock, then `verify_vault_state`". One implementation
means the two cannot drift.

`commit_with_decisions` takes `identity: &UnlockedIdentity` instead of
`password: &SecretBytes` and calls `verify_vault_state(folder, identity, None)`
in place of `open_vault(.., Unlocker::Password(password), None)`. Everything
after that is unchanged, except that keys come from `identity` (IBK, bundle)
and public material from the verified state. `OwnerKeyBag::derive` takes the
bundle and the owner card instead of an `OpenVault`.

`cli/src/pipeline/passes.rs`: the four pass functions drop their `password`
parameter. The CLI daemon then no longer needs to keep the password after its
initial unlock; drop it there.

### 5.2 Core: stale-base guard on every manifest write

One crate-private helper, working name
`ensure_manifest_unchanged_on_disk(folder, expected: &ManifestFile)`: read
`manifest.cbor.enc` and require it to be byte-identical to the encoding of
`expected` (the envelope the session last loaded or wrote). On mismatch return
a new `VaultError::ManifestChangedOnDisk` (fieldless).

**Placement (my call, from the builder check):** the guard runs at the START
of each manifest-writing operation, before ANY file write. It must not live
inside `resign_and_write_manifest`: `save_block` writes its block file before
calling that, so a refusal there would leave an overwritten block and a
`BlockFingerprintMismatch` on the next open, which is the corruption this
slice exists to prevent. The builder censuses every core writer that takes an
`OpenVault` (`save_block`, `share_block`, `revoke_block_recipient`,
`trash_block`, `restore_block`, purge / empty-trash, `repair_vault` — which
passes the envelope it has just read — plus anything the census finds) and
calls the guard first in each. `commit_with_decisions` keeps its own
hash-based freshness check and is not routed through it. Purge's file-delete
ordering against its manifest write must be checked so the guard precedes
both.

The check is not atomic with the write: a cloud delivery landing between the
check and the rename is still lost. That residual is accepted and must be
stated in the helper's doc comment.

### 5.3 Bridge

- `sync_vault_with_session(state_dir, identity, manifest, now_ms)` and
  `sync_commit_decisions_with_session(state_dir, identity, manifest, decisions, manifest_hash, now_ms)`.
  Folder comes from the manifest handle. They run the same pass as the
  password variants (lockfile, state load, persist only on advancing arms)
  using the session's identity, then refresh the manifest handle in place
  on the outcomes `AppliedAutomatically`, `SilentMerge`, `MergedClean` and
  `NothingToDo`. They do NOT refresh on `RollbackRejected` (that would adopt
  the rolled-back manifest) or on `ConflictsPending` (nothing was written;
  the commit call refreshes).
- `refresh_manifest(state_dir, identity, manifest)`: re-run
  `verify_vault_state` with the session identity **and with this device's
  highest-seen clock loaded from the sync state in `state_dir`**, so the §10
  rollback check runs; a dominated manifest is refused (`Rollback`, which the
  bridge already maps) and the handle is left unchanged. Otherwise replace
  the handle's manifest, envelope and owner card. Used by the two calls above,
  by desktop/Android after a password pass, and by the macOS "Reload" action
  (§5.4a). (My call, from the builder check: without the clock, a refresh
  would adopt a rolled-back manifest, the guard would then pass, and the next
  write would re-sign the old state as current, the VL-2 class of hole.)
- **Pass succeeded, refresh failed** (my call): the session call returns the
  refresh's `Err` (typically `BlockFileMissing` / `BlockFingerprintMismatch`
  while iCloud is still delivering block files) and leaves the handle
  unchanged. Retrying is safe: a repeat pass is `NothingToDo` and then
  refreshes. Doc comments must say so.
- The existing password calls keep their signatures; internally they now call
  the identity-based pipeline after their own unlock.
- New `FfiVaultError::VaultChangedOnDisk` mapped from
  `VaultError::ManifestChangedOnDisk`, message along the lines of "the vault
  changed on disk since it was opened; sync, then retry".
- Project all three functions and the variant onto uniffi and pyo3.

### 5.4 iOS

- `VaultSyncPort` / `SyncCoordinator` / `VaultSyncViewModel` (shared
  `SecretaryVaultAccess` packages) switch to session sync. The sync password
  sheet goes away; "Sync now" and the conflict sheet's Apply call the
  re-auth gate's `authorizeWrite` and then the session call.
- Sync-at-unlock runs for every session kind, including Face ID, and is
  NOT routed through `authorizeWrite` (my call): the user authenticated at
  that instant, and gating it would raise a Face ID prompt right after a
  typed password, since the password path does not seed the grace window.
- After a pass that changed anything, the browse view model reloads its block
  list and any open block, so the UI shows the merged data.
- `VaultChangedOnDisk` from any write surfaces as a clear message with a
  "Sync now" action. A refused refresh (`Rollback`) surfaces as "this vault
  is older than this device has seen", and writes stay refused; there is no
  in-app override.

### 5.4a Native macOS app (interim, until its sync slice)

Decided by the user: the Mac app (`ios/SecretaryMacApp/`, which shares
`VaultBrowseViewModel`) gets no sync in this slice. When a write fails with
`VaultChangedOnDisk` it shows the message with a **"Reload"** action that
calls `refresh_manifest` and reloads the block list. The refused edit is not
kept; the user redoes it. This is removed again when the Mac sync slice
lands.

### 5.5 Desktop (Tauri) and Android

- After each successful password sync pass / commit, call `refresh_manifest`
  on the session.
- Map `VaultChangedOnDisk` to a user-facing error (desktop: an `AppError`
  code, classified in `writeCommands.ts` if a new command appears; Android:
  the sealed error type, built through `:app` in the same task).

### 5.6 Tests (the minimum that proves it)

- **First, a red reproduction** in core: open a vault, let a second open
  write a newer manifest, then write through the first handle — today it
  succeeds and corrupts; after the fix it returns `ManifestChangedOnDisk`
  and the disk is untouched.
- Guard coverage: one refusal test per core manifest writer, each asserting
  the disk is byte-identical afterwards (block files included, not only the
  manifest).
- Refresh refuses a rolled-back manifest and leaves the handle unchanged;
  session sync does not refresh on `RollbackRejected`.
- Commit with identity: the existing sync merge/veto/TOCTOU/crash suites pass
  with the new signature; one test that a tampered block fingerprint still
  aborts the identity-based commit (the D6 gate survived).
- Bridge: session sync refreshes the handle, so a write right after it
  succeeds; a password pass followed by `refresh_manifest` likewise.
- iOS host tests for the view-model changes; both conformance scripts;
  Android `:kit` + `:app` build; `cd desktop && pnpm test`.

## 6. Left to the builder

- Function and variant names (the working names above are placeholders).
- Whether the guard compares bytes or BLAKE3 hashes, provided it compares
  against the exact envelope the session last loaded or wrote, and the
  builder confirms `encode_manifest_file(decode(bytes)) == bytes` holds or
  stores the bytes/hash instead.
- How the browse view model is told to reload after sync.
- Splitting files that cross 500 lines.
- Updating `ROADMAP.md`, `README.md` status rows and the relevant CLAUDE.md
  lines once shipped.
