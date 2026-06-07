# D.1.14 — Desktop sync UI (the *sync verb* on the D.1.13 bridge primitives)

**Date:** 2026-06-06
**Sub-project:** D (desktop UI), fourteenth feature slice — built on D.1.6–D.1.13.
**Status:** design approved; ready for implementation plan.

## 1. Problem

D.1.13 shipped the bridge-thick sync primitives — `sync_status` (read-only projection of the
per-vault `SyncState`) and `sync_vault` (the pause-on-conflict mutation) — plus the five
`FfiVaultError`/`AppError` sync variants threaded through every binding
([PR #188](https://github.com/hherb/secretary/pull/188)). But there is **no way to invoke them from
the desktop**: no Tauri command, no TS wrapper, no UI. A user with an unlocked vault cannot see
whether the vault has ever synced, cannot tell when it last synced, and cannot trigger a sync pass.

This slice is the **D.1.13 → D.1.14** pair, mirroring **D.1.10 (revoke primitive) → D.1.11 (revoke
UI)**: D.1.13 was the primitive; D.1.14 is the desktop verb.

## 2. Goal

Give a user with an unlocked vault, in the desktop TopBar:

- A **sync-status indicator** — a single combined "pill" showing when the vault last synced
  ("Synced 2m ago" / "Never synced"), refreshed on unlock and after each manual sync.
- A **"Sync now" action** — the pill itself is the control. Clicking it opens a centered password
  modal (sync re-opens a fresh identity; the password is never retained), runs `sync_vault`, and
  reports the outcome as a toast.

`sync_vault` is a real vault mutation (merge + atomic write of peer changes, or a pause that writes
nothing on conflict). The UI treats it as such: a deliberate password re-prompt, strict
(non-lenient) typed-error surfacing, and a manifest refresh when peer changes land.

## 3. Scope

**In scope**

- Two new Tauri IPC commands + testable `_impl`s in a new
  [commands/sync.rs](../../../desktop/src-tauri/src/commands/sync.rs):
  - `sync_status` — read-only; projects the bridge `SyncStatusDto` to a desktop DTO.
  - `sync_now(password, now_ms)` — the mutation; delegates to bridge `sync_vault`.
  Both registered in [main.rs](../../../desktop/src-tauri/src/main.rs); module declared in
  [commands/mod.rs](../../../desktop/src-tauri/src/commands/mod.rs).
- A new [dtos/sync.rs](../../../desktop/src-tauri/src/dtos/sync.rs): desktop `SyncStatusDto`
  (drops `device_clocks`) + a serde-tagged `SyncOutcomeDto` mirroring the bridge's six variants.
- A `vault_folder: PathBuf` field added to `UnlockedSession`
  ([session.rs](../../../desktop/src-tauri/src/session.rs)), set at `unlock()` — `sync_vault` needs
  the folder path and the session is the right (server-side) owner of it.
- The five sync `AppError` codes wired into the **TS** side
  ([errors.ts](../../../desktop/src/lib/errors.ts)) — `APP_ERROR_CODES`, the `AppError` union, and
  `userMessageFor` (the Rust `AppError` + `map_ffi_error` side already landed in D.1.13). This is
  where the real user-facing `SyncFailed` copy lands (replacing the terse Rust `Display` string).
- Two TS IPC wrappers `syncStatus()` / `syncNow(password)` in
  [ipc.ts](../../../desktop/src/lib/ipc.ts).
- A pure [src/lib/sync.ts](../../../desktop/src/lib/sync.ts): `syncOutcomeToast(outcome)` (the
  outcome→toast mapping, with the three "applied" arms collapsed) and `lastSyncedLabel(status, now)`
  ("Synced 2m ago" / "Never synced"), reusing `format.ts` relative-time.
- A new [SyncPill.svelte](../../../desktop/src/components/SyncPill.svelte) (the combined indicator +
  trigger) and [SyncPasswordDialog.svelte](../../../desktop/src/components/SyncPasswordDialog.svelte)
  (the centered re-prompt modal), mounted into
  [TopBar.svelte](../../../desktop/src/components/TopBar.svelte).
- Tests at every layer (pure helpers, IPC wrappers, both Rust `_impl`s, both components) + a manual
  GUI smoke against a **temp copy** of the golden vault.

**Out of scope (deferred)**

- **`core/`, `ffi/`, `FfiVaultError`, and UDL changes.** The bridge `sync_status` / `sync_vault` and
  all five error variants are complete (D.1.13). This is a pure D-phase UI slice — **no crypto-review
  rigor, no UDL/Swift/Kotlin/pyo3 change, no `FfiVaultError` variant churn, and therefore no
  cross-language conformance run** (per [[project_secretary_ffivaulterror_workspace_match]]).
- **Per-device clock detail in the UI.** `SyncStatusDto.device_clocks` (the technical
  `device_uuid_hex · counter` rows) is **not** surfaced in v1 — a plain "last synced" time is
  enough. The desktop DTO drops the field entirely.
- **Background / automatic sync.** No timer, no window-focus polling, no `notify` daemon loop.
  Status refreshes only on unlock and after a manual sync. Live polling belongs to the deferred
  background-sync daemon.
- **Interactive conflict resolution.** `ConflictsPending { veto_count }` surfaces a count and a
  "coming soon" toast; the veto-resolution UX (over `DraftMerge`) remains deferred beyond D.1.14.
- **Exposing `sync_vault` / `sync_status` via uniffi/pyo3** — tracked by
  [#187](https://github.com/hherb/secretary/issues/187) (pairs with #167); the functions stay
  bridge-only.

## 4. Architecture (bridge-thick; `core/` and bridge frozen and untouched)

Held from D.1.6–D.1.13: all vault/merge knowledge stays in the bridge; the desktop never learns the
on-disk vault layout or the sync-pass internals. The new Tauri commands are thin delegates to the
existing bridge `sync_status` / `sync_vault`.

### 4.1 Session — `vault_folder` retention

`sync_vault(vault_folder: &Path, password, now_ms)` needs the vault's folder path, which
`UnlockedSession` does not currently retain (it keeps `identity`, `manifest`, `settings`,
`device_uuid`, `pending_warnings`). Add:

```rust
pub struct UnlockedSession {
    pub identity: UnlockedIdentity,
    pub manifest: OpenVaultManifest,
    pub settings: Settings,
    pub device_uuid: [u8; 16],
    pub pending_warnings: Vec<AppWarning>,
    /// Absolute path the vault was opened from. Needed by `sync_now` to call
    /// the bridge `sync_vault`, which takes a folder path (a different entry
    /// point than the manifest handle). Plain value, no secret material.
    pub vault_folder: PathBuf,
}
```

Set in `VaultSession::unlock()` from the existing `folder: &Path` parameter
(`vault_folder: folder.to_path_buf()`). No `Drop`-order change — it is a plain value with no secret
bytes. Retaining it server-side (rather than having the JS frontend hand a filesystem path back into
a mutation) keeps the path out of the renderer's control.

### 4.2 Rust IPC commands — `commands/sync.rs`

```rust
#[tauri::command]
pub async fn sync_status(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<SyncStatusDto, AppError> {
    sync_status_impl(state.inner())
}

pub fn sync_status_impl(state: &Mutex<VaultSession>) -> Result<SyncStatusDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let vault_uuid = uuid_16(&u.manifest.vault_uuid())?; // Vec<u8> -> [u8; 16]
        let dto = bridge_sync_status(vault_uuid).map_err(map_ffi_error)?;
        Ok(SyncStatusDto::from(dto)) // drops device_clocks
    })
}

#[tauri::command]
pub async fn sync_now(
    state: State<'_, Mutex<VaultSession>>,
    password: Password,
) -> Result<SyncOutcomeDto, AppError> {
    sync_now_impl(state.inner(), &password, now_ms())
}

pub fn sync_now_impl(
    state: &Mutex<VaultSession>,
    password: &Password,
    now_ms: u64,
) -> Result<SyncOutcomeDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let outcome = bridge_sync_vault(
            &u.vault_folder,
            SecretBytes::from(password.expose()),
            now_ms,
        )
        .map_err(map_ffi_error)?;
        Ok(SyncOutcomeDto::from(outcome))
    })
}
```

- Imports `sync_status as bridge_sync_status`, `sync_vault as bridge_sync_vault` from
  `secretary_ffi_bridge`.
- `now_ms()` is the existing wall-clock helper used by `share`/`revoke` commands; the `#[command]`
  wrapper supplies it so `sync_now_impl` stays deterministic under test (the `now_ms` only affects
  the merge timestamp on the rare concurrent-clean-merge arm — see D.1.13 §3).
- `uuid_16` is a small `Vec<u8> -> [u8; 16]` helper (length-checked → `AppError::Internal` on a
  malformed manifest uuid, which is unreachable for an opened vault but must not panic).
- `password.expose()` yields `&[u8]`; `sync_vault` takes an owned `SecretBytes`, so we build one
  from the exposed bytes. The `Password` (and the constructed `SecretBytes`) are `ZeroizeOnDrop` and
  dropped at `_impl` end; never stashed/cloned beyond the call.
- `with_unlocked` borrows the session immutably and **asserts the unlocked state** (→
  `AppError::NotUnlocked` when locked). `sync_vault` opens its *own* identity from the password and
  mutates the on-disk vault directly — it does **not** mutate the session's in-memory `manifest`,
  which therefore goes **stale** when peer changes land (see §5.3).

### 4.3 Desktop DTOs — `dtos/sync.rs`

```rust
/// Read-only sync status for the TopBar pill. Projects the bridge
/// `SyncStatusDto`, dropping `device_clocks` (not surfaced in v1).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusDto {
    pub has_state: bool,
    pub last_state_write_ms: Option<u64>,
}

/// Outcome of a sync pass. Serde-tagged for the TS discriminated union.
/// `rename_all_fields` is required so the `veto_count` field of the
/// `ConflictsPending` variant serializes as `vetoCount` (the enum-level
/// `rename_all` renames *variants* only, not struct-variant *fields*).
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SyncOutcomeDto {
    NothingToDo,
    AppliedAutomatically,
    SilentMerge,
    MergedClean,
    ConflictsPending { veto_count: u32 },
    RollbackRejected,
}
```

Both derive `From<bridge::SyncStatusDto>` / `From<bridge::SyncOutcomeDto>`. The desktop DTO is a
deliberate projection, not a re-export, so the bridge can evolve its DTO independently and so the
UI-facing shape is owned by the desktop crate (consistent with every other `dtos/*` module).

### 4.4 TS error variants — `errors.ts`

D.1.13 added the five variants to the Rust `AppError` + `map_ffi_error` but left the **TS** side
unthreaded (D.1.13 had no UI). Add to `errors.ts`:

- `APP_ERROR_CODES`: `'sync_in_progress'`, `'sync_evidence_stale'`,
  `'sync_state_vault_mismatch'`, `'sync_state_corrupt'`, `'sync_failed'` (the exact `code` strings
  are the serde-rename of the Rust variants — confirmed against `errors.rs` during implementation).
- The five `| { code: '…' }` arms on the `AppError` union (`sync_state_corrupt` and `sync_failed`
  carry no client-visible `detail` — D.1.13 strips it at the IPC seam).
- `userMessageFor` cases (`{ title, actionHint }`):
  - `sync_in_progress` → "Another sync is in progress" · "Wait for it to finish, then try again."
  - `sync_evidence_stale` → "The vault changed during sync" · "Something modified the vault while it
    was syncing. Try again."
  - `sync_state_vault_mismatch` → "Sync state belongs to a different vault" · "The local sync cache
    doesn't match this vault."
  - `sync_state_corrupt` → "Sync state cache is unreadable" · "The local sync cache is corrupt and
    will be rebuilt on the next sync."
  - `sync_failed` → "Sync didn't complete" · "Something went wrong during sync. Try again." (the
    real user copy for the Rust placeholder.)

### 4.5 TS IPC wrappers — `ipc.ts`

```ts
export async function syncStatus(): Promise<SyncStatusDto> {
  return call<SyncStatusDto>('sync_status');
}

export async function syncNow(password: string): Promise<SyncOutcome> {
  return call<SyncOutcome>('sync_now', { password });
}
```

`SyncStatusDto` / `SyncOutcome` types live in `lib/sync.ts`. The password is a plain string on the
JS side (Tauri serializes it; the Rust `Password` deserializer overwrites the intermediate
`String` into `SecretBytes`) — the same path `unlockWithPassword` already uses.

### 4.6 Pure module — `src/lib/sync.ts`

```ts
export type SyncStatusDto = { hasState: boolean; lastStateWriteMs: number | null };

export type SyncOutcome =
  | { kind: 'nothingToDo' }
  | { kind: 'appliedAutomatically' }
  | { kind: 'silentMerge' }
  | { kind: 'mergedClean' }
  | { kind: 'conflictsPending'; vetoCount: number }
  | { kind: 'rollbackRejected' };

export type ToastKind = 'success' | 'warning' | 'error';
export type SyncToast = { kind: ToastKind; text: string };

/** Map a sync outcome to its toast. The three "changes applied safely" arms
 *  collapse to one success message; the distinction isn't user-actionable. */
export function syncOutcomeToast(outcome: SyncOutcome): SyncToast;

/** Whether an outcome changed vault data (so the manifest view must refresh). */
export function syncChangedData(outcome: SyncOutcome): boolean;

/** "Synced 2m ago" / "Never synced" for the pill label. */
export function lastSyncedLabel(status: SyncStatusDto, nowMs: number): string;
```

`syncOutcomeToast` mapping:

| `SyncOutcome.kind` | kind | text |
|---|---|---|
| `nothingToDo` | success | "Already up to date" |
| `appliedAutomatically` / `silentMerge` / `mergedClean` | success | "Synced — your vault is up to date" |
| `conflictsPending` | warning | "{vetoCount} conflict(s) need resolution — coming soon" |
| `rollbackRejected` | error | "Sync rejected — a peer tried to roll back protected data" |

`syncChangedData` is `true` for the three applied/merged arms (drives the §5.3 manifest refresh),
`false` for `nothingToDo` / `conflictsPending` / `rollbackRejected` (which write nothing). All
mapping logic is pure and table-tested; no Svelte, no I/O.

## 5. UI surfaces

### 5.1 SyncPill.svelte (the combined indicator + trigger, in the TopBar)

- Renders a single pill in `top-bar__right`, before Settings/Lock: a ↻ icon + the
  `lastSyncedLabel(...)` text. `aria-label` of the form
  `Sync now — last synced {relative time}` / `Sync now — never synced`.
- **States:**
  - *idle* — clickable; shows last-synced label.
  - *syncing* — disabled, "Syncing…" + spinner, while `syncNow` is in flight.
  - (no persistent error state on the pill itself — failures are toasts; the label simply doesn't
    advance.)
- Reads `syncStatus()` on mount (i.e. when the unlocked Vault view mounts) and again after every
  completed sync, updating the label. A read failure leaves the prior label and is non-fatal (the
  pill is informational; the *action* path is strict).
- Click → opens `SyncPasswordDialog`. On the dialog's success callback with a `SyncOutcome`:
  1. render `syncOutcomeToast(outcome)` via the existing `Toast`;
  2. re-read `syncStatus()` to refresh the label;
  3. if `syncChangedData(outcome)`, signal the parent to refresh the manifest view (§5.3).

### 5.2 SyncPasswordDialog.svelte (the centered re-prompt modal)

- A centered, app-dimming modal (the heavyweight "enter a secret" treatment chosen over an anchored
  popover): title "Confirm your password", a `type="password"` input (autofocused), Cancel / Sync
  buttons, an inline error slot, **Esc-to-cancel**, and focus-trap.
- **Sync** → `syncNow(password)`:
  - success → clear + zero the local password string, close, invoke `onSynced(outcome)`.
  - failure → render the typed `AppError` via `userMessageFor` **inline in the dialog** (the dialog
    stays open so the user can correct a mistyped password and retry); **strict surfacing — no
    read-path leniency**. A wrong password surfaces as the core's existing unlock-failure
    `AppError` mapped by `map_ffi_error` (e.g. `WrongPassword`), not a silent no-op.
- The password string is component-local, cleared on close/cancel/success; never stored in a store
  or logged.

### 5.3 Refresh / consistency

`sync_vault` mutates the on-disk vault directly and does **not** touch the session's in-memory
`manifest`, so after an applied/merged outcome the records view is stale. On `syncChangedData(...)`,
SyncPill calls the existing manifest-refresh path (the `refreshManifest()` / `get_manifest`
convention the records view already uses) so the block list reflects merged peer changes. For
`nothingToDo` / `conflictsPending` / `rollbackRejected` — which write nothing — no refresh is
issued. The pill's own label always refreshes via `syncStatus()` regardless of outcome.

## 6. Error handling

- Every `sync_now` failure surfaces as a **typed** `AppError` through `userMessageFor`, rendered
  inline in the dialog. The mutation path does **not** inherit the read-only display's leniency.
- The five sync variants map 1:1 from the bridge (D.1.13's `map_ffi_error`); the TS copy
  (§4.4) is the user-facing surface. `sync_in_progress` (a daemon or a second client holds the
  lockfile) and `sync_evidence_stale` (the vault changed mid-sync) are both "try again" conditions;
  `sync_state_*` indicate a local-cache problem that the next sync rebuilds.
- `sync_status` read failures are non-fatal and do not block the UI — the pill keeps its prior
  label. (The *status* is informational; only the *action* is strict.)

## 7. Testing (TDD, red-first per unit)

- **`sync.ts`** (pure): `syncOutcomeToast` over all six variants (incl. the three-arm collapse and
  `conflictsPending` count interpolation); `syncChangedData` true/false partition;
  `lastSyncedLabel` for `hasState=false` ("Never synced"), a recent ms, and an older ms.
- **`errors.ts`**: the five new codes are in `APP_ERROR_CODES`; `userMessageFor` returns the
  expected `{title, actionHint}` for each (extends `errors.test.ts` / a new `errorsSync.test.ts`).
- **`ipc.ts`**: `syncStatus` invokes `invoke('sync_status')`; `syncNow` invokes
  `invoke('sync_now', { password })`; typed-error re-throw on both.
- **Desktop sync commands — seam-only, hermetic** (decision: keep the slice pure-desktop, no bridge
  change). The bridge's public `sync_status` / `sync_vault` use the **default OS state dir**, and the
  temp-dir-injecting `sync_status_in` / `sync_vault_in` are `pub(crate)` (invisible to the desktop
  crate), so a desktop *integration* test that drove real sync would touch the real OS state dir —
  violating this repo's "every test injects its own TempDir" discipline. The end-to-end sync path
  (folder + password → outcome, all six arms, wrong-password, lockfile-held) is already exhaustively
  covered hermetically by **D.1.13's bridge tests** (`ffi/secretary-ffi-bridge/src/sync/*` with
  `TempDir` state dirs) and is re-verified by the **mandatory manual GUI smoke**. The desktop layer
  therefore tests only its own seam, hermetically:
  - **`commands/sync.rs`** (`ipc_integration.rs`): `sync_status` and `sync_now` both return
    `NotUnlocked` when the session is locked (no bridge call, no state-dir touch).
  - **`dtos/sync.rs`** (`#[cfg(test)]` unit tests): the `From<bridge::…>` conversions + serde
    wire-format pinning — `SyncStatusDto` drops `device_clocks` and emits `camelCase`; the tagged
    `SyncOutcomeDto` emits `{ "kind": "conflictsPending", "vetoCount": N }` (the
    `rename_all_fields` check) and the unit variants emit `{ "kind": "nothingToDo" }` etc. This is
    the wire-contract gate the bridge↔TS union depends on.
  - Tests generate any crypto inputs at runtime, never hardcoded
    ([[feedback_test_crypto_random_not_hardcoded]]).
- **SyncPill.svelte**: renders the `lastSyncedLabel`; click opens the dialog; on `onSynced` it
  toasts, re-reads status, and triggers a manifest refresh iff `syncChangedData`; "Syncing…"
  disabled state during flight.
- **SyncPasswordDialog.svelte**: submit → `syncNow` invoked with the typed password; success closes
  + calls `onSynced(outcome)`; failure renders `userMessageFor` inline and keeps the dialog open;
  Cancel and Esc close without invoking; password cleared on close.
- **Manual GUI smoke** against a **temp copy** of the golden vault (mandatory — this slice mutates):
  open the app, observe the pill ("Synced …"/"Never synced"), click → modal → enter password →
  observe the outcome toast and (for an applied outcome) the refreshed records view; verify a
  wrong password shows the inline error and keeps the dialog open; verify Esc/Cancel.

## 8. Risks & open items

- **`sync_now` re-prompts even though the vault is already unlocked.** This is inherent to the
  shipped bridge surface — `sync_vault` takes a `password` and opens its own identity (the session's
  `UnlockedIdentity` is not reusable as a `password`), and the bridge is frozen for this slice. The
  modal makes the re-prompt explicit rather than a surprise.
- **Wrong-password mapping.** A mistyped password surfaces through `map_ffi_error` as the core's
  existing unlock-failure variant; confirm during implementation that the dialog renders a sensible
  `userMessageFor` for it (it should already be a known `AppError` code from the unlock path) and
  add a TS case if any code is still unthreaded.
- **`now_ms` source.** The `#[command]` wrapper supplies wall-clock; only the rare
  concurrent-clean-merge arm uses it (for the merge timestamp). No correctness impact on the common
  arms.
- **Carry-forwards (unchanged by this slice):** #161 (L4 e2e — no tauri-driver on macOS WKWebView),
  #162 (PathPicker e2e hook), #186 (dedup bridge test helpers), #187 (project sync onto
  uniffi/pyo3), #189 (lean-binding CI guard), #190 (bridge `MergedClean`-under-lock test). None
  block D.1.14. New TopBar controls follow the existing `aria-label` convention.
