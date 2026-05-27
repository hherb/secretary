# D.1.1 — Tauri walking skeleton (design spec)

**Date:** 2026-05-27
**Sub-project:** D.1.1 (first slice of the new Tauri-based Sub-project D)
**Status:** Proposed — spec authored, plan + tasks downstream
**Supersedes:** ADR 0001 (the Python + NiceGUI portion of Sub-project D); does not affect the Rust-core or mobile-via-uniffi portions

## 1. What this slice ships

D.1.1 is the first end-to-end Tauri client. It exists to prove the architecture, not to deliver feature breadth. A user can:

1. Launch a Tauri-native desktop window (macOS or Linux).
2. Pick a vault folder via a native folder dialog and enter a password.
3. Successfully unlock an existing vault.
4. See a list of the vault's blocks (name + record count + last-modified timestamp), with click stubbed for the next slice.
5. Open a Settings dialog and change the auto-lock timeout (persisted in the vault).
6. Trigger auto-lock by idling, or explicit lock via the Lock button, and return cleanly to the unlock screen.
7. Close the window and have the process exit with all secret state wiped via the Rust `ZeroizeOnDrop` chain.

Everything beyond this list is deferred (see §13 "Out of scope").

## 2. Why Tauri (not NiceGUI)

The original Sub-project D plan was three separate UI codebases: Python + NiceGUI for desktop, SwiftUI for iOS, Compose for Android — each consuming `secretary-core` through its own FFI binding (PyO3, uniffi-Swift, uniffi-Kotlin). The plan was correct given what was known at the time but is being revisited now that Tauri 2 (October 2024 stable) has matured.

Tauri changes the calculus on two independent axes:

**Security:**

- NiceGUI runs uvicorn/FastAPI on `127.0.0.1:<port>` even in `native=True` mode. Any other localhost process or browser extension on the machine can probe the listening port; same-origin is the only thing keeping them off the unlocked vault.
- Tauri uses an in-process IPC channel via the `tauri://` custom URL scheme. There is no HTTP server. The attack surface "other localhost processes" closes entirely.
- NiceGUI marshals secret material into a Python process. Python's allocator (small-object cache, string intern table) is opaque enough that some bytes may linger longer than the Rust `ZeroizeOnDrop` discipline guarantees. Tauri keeps secrets in the same Rust address space they were generated in — `ZeroizeOnDrop` is deterministic on stack drop.

**Codebase consolidation:**

- Tauri 2 targets desktop (macOS, Linux, Windows) and mobile (iOS, Android) from a single Rust + TypeScript codebase. The original D.1 (NiceGUI desktop) + D.2 (SwiftUI iOS) + D.3 (Compose Android) plan was three separate UIs.
- This pivot makes D.1, D.2, and D.3 share one codebase rather than three.

**Costs (taken honestly):**

- +30–50% upfront effort for D.1.1 relative to NiceGUI (Tauri scaffold + frontend framework setup + IPC commands instead of consuming the existing Python FFI). PyO3 work in `ffi/secretary-ffi-py` is not lost — it stays as the path for scripting / automation / future Python consumers.
- Solo developer learning-curve cost — Rust + a frontend framework. Mitigated by 8+ months of Rust experience accumulated through Sub-projects A and C; framework choice (Svelte) is the smallest concept-vocabulary option.
- Tauri 2 mobile is newer than uniffi-based native UI. Desktop is rock-solid; mobile will likely have rougher edges encountered in D.3.

Full rationale + alternatives considered + consequences are in [ADR 0007](../../adr/0007-d-row-tauri.md).

## 3. Architecture approach

One approach stands up; the alternatives are rejected by the security model.

| Approach | Verdict |
|---|---|
| **A. Plain Tauri + Mutex-guarded `tauri::State<VaultSession>`** | **Chosen.** A `VaultSession` struct holds the live `UnlockedIdentity` + `OpenVault` + `IdleTracker`, mutex-guarded, registered as `tauri::State`. Explicit `lock()` drops the `UnlockedSession` (which has a `Drop` impl that calls `vault.wipe()` then `identity.wipe()`). |
| B. Tauri's IPC layer with secrets in JavaScript-side state | **Rejected.** Holding any secret material in the WebView's V8 heap defeats the address-space-isolation property that motivated the Tauri pivot. Secrets stay Rust-side; the WebView gets stripped DTOs only. |
| C. Sub-process isolation (FFI in a worker subprocess, UI in main) | **Rejected for D.1.1.** Adds IPC complexity (pickling secrets across process boundaries → leftover frames in the receiving process). Worthwhile defense-in-depth for a later hardening slice; over-engineering for the walking skeleton. |

## 4. Project layout

```
desktop/                                # was placeholder; now the Tauri project root
├── README.md                           # rewrite — Tauri dev loop, prerequisites
├── package.json                        # frontend deps (Svelte, TS, Vite)
├── pnpm-lock.yaml
├── tsconfig.json
├── vite.config.ts
├── svelte.config.js
├── src/                                # FRONTEND (Svelte + TS, runs in WebView)
│   ├── main.ts                         # Svelte mount point
│   ├── App.svelte                      # root — routes between Unlock and Vault
│   ├── lib/
│   │   ├── ipc.ts                      # typed wrappers around Tauri's invoke()
│   │   ├── stores.ts                   # Svelte stores: sessionState, currentSettings, autoLockNotice
│   │   ├── auto_lock.ts                # idle tracker — pure TS, Vitest-covered
│   │   └── errors.ts                   # IPC error → user message (pure TS)
│   ├── routes/                         # folder organization (not file-based routing)
│   │   ├── Unlock.svelte
│   │   └── Vault.svelte
│   ├── components/
│   │   ├── BlockCard.svelte
│   │   ├── PathPicker.svelte
│   │   ├── SettingsDialog.svelte
│   │   ├── LockButton.svelte
│   │   └── Toast.svelte
│   └── theme.css                       # CSS custom properties (no Tailwind, no CSS framework)
├── src-tauri/                          # BACKEND (Rust, in-process; consumes secretary-core directly)
│   ├── Cargo.toml                      # workspace member; depends on secretary-core via path
│   ├── tauri.conf.json                 # window config, CSP, bundle identifier
│   ├── build.rs
│   └── src/
│       ├── main.rs                     # tauri::Builder + state setup + command registration + timer
│       ├── session.rs                  # VaultSession (UnlockedIdentity + OpenVault), Mutex-guarded
│       ├── settings.rs                 # secretary-settings record schema + load/save (PURE helpers)
│       ├── auto_lock.rs                # idle tracker (PURE Rust)
│       ├── errors.rs                   # thiserror-based AppError; serde-serializable
│       └── commands/                   # one file per #[tauri::command]
│           ├── mod.rs
│           ├── unlock.rs               # unlock_with_password
│           ├── vault.rs                # list_blocks, get_manifest
│           ├── settings.rs             # get_settings, set_settings
│           └── lock.rs                 # explicit lock command + notify_activity
├── tests/                              # frontend Vitest (pure TS modules)
│   ├── auto_lock.test.ts
│   └── errors.test.ts
└── e2e/                                # Playwright/WDIO end-to-end smoke (one test in D.1.1)
    └── unlock_and_browse.spec.ts
```

**Workspace integration:** the root `Cargo.toml` gets `"desktop/src-tauri"` added to `[workspace] members`. The Tauri backend depends on `secretary-ffi-bridge = { path = "../../ffi/secretary-ffi-bridge" }` (NOT `secretary-core` directly) — the bridge crate already exposes the consumer-facing orchestration API (`open_vault_with_password`, `read_block`, `save_block`, …) plus stable error types (`FfiVaultError`), and its semantics are already validated across PyO3 and uniffi. Tauri becomes a third wrapper around the same bridge surface, which keeps cross-language consumer behavior consistent. There is no FFI hop — the bridge is a normal Rust crate in the workspace, consumed via `path` dep. Both `cargo test --workspace` and `cargo tauri dev` see the same `Cargo.lock`; the bridge + core build once.

## 5. Module decomposition + responsibilities

### Backend (`src-tauri/src/`)

| Module | Owns | Doesn't own |
|---|---|---|
| `Cargo.toml` (`src-tauri/`) | Dependency on `secretary-ffi-bridge` via workspace path (`secretary-ffi-bridge = { path = "../../ffi/secretary-ffi-bridge" }`), Tauri 2.x, serde, thiserror, tracing | No direct dependency on `secretary-core` — that's a bridge-internal concern |
| `main.rs` | Tauri builder setup, window config, `tauri::State<Mutex<VaultSession>>` initialization, command registration, the auto-lock periodic timer thread | Any business logic — pure orchestration |
| `session.rs` | `VaultSession` struct (holds `Option<UnlockedSession>` + `IdleTracker`), Mutex-guarded. Methods: `unlock(path, password)`, `lock()`, `notify_activity()`, `with_open_vault<F>(f)`. **The only place `secretary-ffi-bridge` unlock/open calls happen.** | No knowledge of Tauri (testable without the framework) |
| `settings.rs` | Pure: `parse_settings_record(&Record) -> Result<Settings, AppError>`, `serialize_settings(&Settings) -> RecordInput`. Reserved record_type string and field name (see §8). Side-effect facade: `load_from_vault(&OpenVault) -> Result<Settings, AppError>`, `save_to_vault(&UnlockedIdentity, &OpenVault, &Settings)` | No Tauri awareness; no timer state |
| `auto_lock.rs` | Pure `IdleTracker { last_activity_ms: u64 }`, `now_ms()`, `is_expired(threshold_ms, now_ms) -> bool` | The actual timer thread (`main.rs`); the lock action (`session.rs::lock()`) |
| `errors.rs` | `AppError` enum (thiserror, serde-serializable). Variants enumerated in §9 | Doesn't transport secret material across IPC |
| `commands/unlock.rs` | `#[tauri::command] async unlock_with_password(state, path, password) -> Result<ManifestDto, AppError>`. ~25 LOC: input validation → `session.unlock(...)` → DTO marshaling | No core crypto logic |
| `commands/vault.rs` | `list_blocks(state) -> Result<Vec<BlockSummaryDto>, AppError>`, `get_manifest(state) -> Result<ManifestDto, AppError>`. Read-only via `session.with_open_vault(...)` | No I/O of its own |
| `commands/settings.rs` | `get_settings(state) -> Result<Settings, AppError>`, `set_settings(state, settings) -> Result<(), AppError>`. Latter triggers `save_block` via core | No timer plumbing |
| `commands/lock.rs` | `lock(state)` (explicit), `notify_activity(state)` (frontend-driven idle reset). Periodic timer thread spawned in `main.rs` calls `session.maybe_auto_lock(threshold)` | No core knowledge |

### Frontend (`src/`)

| Module | Owns | Doesn't own |
|---|---|---|
| `lib/ipc.ts` | Typed wrappers over `@tauri-apps/api/core::invoke`. One function per backend command. Catches IPC errors and re-throws as typed TS errors via `lib/errors.ts` | No UI rendering; no Svelte |
| `lib/stores.ts` | Svelte `writable` stores: `sessionState` (discriminated union), `currentSettings`, `autoLockNotice` | No IPC of its own — derived from `lib/ipc.ts` callers |
| `lib/auto_lock.ts` | Browser-side activity detection (mousemove/keydown listeners), debounced `ipc.notifyActivity()` calls | The lock decision (backend timer) |
| `lib/errors.ts` | TS discriminated union mirroring `AppError`. `userMessageFor(AppError) -> { title, detail?, actionHint? }`. Pure | No DOM/Svelte |
| `routes/Unlock.svelte` | Unlock screen layout, form state, submit handler | The unlock IPC call (delegates to `lib/ipc.ts`) |
| `routes/Vault.svelte` | Post-unlock layout: block-list grid, lock button slot, settings-dialog trigger | Settings persistence (delegates to `lib/ipc.ts`) |
| `components/*.svelte` | Small focused leaf components; each owns one visual concern | Routing or session decisions |
| `App.svelte` | Subscribes to `$sessionState`, renders `Unlock` or `Vault` accordingly | Anything else |

### IPC boundary discipline

- **Only one secret crosses the boundary in D.1.1**: the password during `unlock_with_password`. Stringly typed at the IPC seam (no way around it for the password specifically). The Rust side wraps it in `SecretString` immediately on receipt and the local `String` is consumed without further duplication.
- **No record-field secrets cross the boundary in D.1.1.** Browse + reveal lands in D.1.2.
- **DTOs are stripped types.** Rust domain types (`BlockSummary` with `Vec<u8>` UUIDs) become DTOs (`BlockSummaryDto` with hex-encoded UUIDs as strings) at the command boundary. Conversion functions live next to the command. No `Zeroize`-typed value ever gets `serde::Serialize`d.

## 6. Vault session lifecycle

### State machine

```
                                  ┌───────────────────────────────┐
                                  │  Locked (initial)             │
                                  │  VaultSession.inner = None    │
                                  └───────────────┬───────────────┘
                                                  │
                            user submits unlock form (path + password)
                                                  │
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │  Unlocking (transient, async) │
                                  │  IPC unlock_with_password in  │
                                  │  flight; mutex held briefly   │
                                  └─────┬───────────────────┬─────┘
                                        │                   │
                  unlock_with_password   │                   │ unlock_with_password
                  returns Ok             │                   │ returns Err(AppError)
                                        ▼                   ▼
              ┌──────────────────────────────┐   ┌──────────────────────────────┐
              │  Unlocked                    │   │  Locked (with lastError set) │
              │  inner = Some({identity,     │   │  Frontend shows typed        │
              │    vault, settings})         │   │  user message; form resets   │
              │  idle.last_activity = now()  │   └──────────────────────────────┘
              └─────┬────────┬────────┬─────┘
                    │        │        │
       explicit lock│        │        │auto-lock timer fires
       (Lock button)│   ───  │  ───   │(idle.is_expired)
                    │        │        │
                    └────────┼────────┘
                             │
                             ▼
                  ┌──────────────────────────────┐
                  │  Locked (post-unlock)        │
                  │  inner dropped → wipe() runs │
                  │  Tauri event `vault-locked`  │
                  │  emitted to frontend         │
                  └──────────────────────────────┘
```

### Backend data shape

```rust
// src-tauri/src/session.rs (sketch)
pub struct VaultSession {
    pub inner: Option<UnlockedSession>,  // None when locked
    pub idle: IdleTracker,                // last_activity_ms
    pub last_error: Option<AppError>,     // surfaced on next query
}

pub struct UnlockedSession {
    pub identity: UnlockedIdentity,       // ZeroizeOnDrop
    pub vault: OpenVault,                 // has explicit .wipe() — called in Drop
    pub settings: Settings,               // loaded from vault on unlock
}

impl Drop for UnlockedSession {
    fn drop(&mut self) {
        self.vault.wipe();
        self.identity.wipe();
        // settings has no secret material; default Drop
    }
}
```

Wrapped as `tauri::State<Mutex<VaultSession>>`. Multi-threaded Tauri runtime → Mutex (not RwLock — read paths still need to mutate `idle.last_activity_ms`).

### Auto-lock timer

- Spawned in `main.rs` after `tauri::Builder` finalization (so `AppHandle` is available for event emission). Independent OS thread, not a Tokio task.
- Tick interval `AUTO_LOCK_TICK_MS = 5_000` (5 s). Each tick:
  1. `try_lock()` the mutex (non-blocking — if a command is mid-flight, skip).
  2. If `session.inner.is_some()` AND `idle.is_expired(settings.auto_lock_timeout_ms, now_ms())`: invoke `session.lock()`.
  3. Release mutex.
  4. Sleep `AUTO_LOCK_TICK_MS`.

### Activity notification

- Frontend installs `mousemove` and `keydown` listeners on `document`. Debounced to at most once per `ACTIVITY_NOTIFY_MIN_INTERVAL_MS = 2_000` (2 s).
- Each debounced call: `invoke('notify_activity')` → backend `session.idle.last_activity_ms = now_ms()`. No-op if locked (safe).

### Settings loading on unlock

After `secretary_core::open_vault_with_password` succeeds inside `session.unlock(...)`:

1. `settings::load_from_vault(&open_vault)` is called.
2. If the settings block (see §8) is absent from the manifest: return `Settings::default()` (which has `auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS`). No I/O. Vault stays byte-identical for users who never change defaults.
3. If the settings block is present but `read_block` fails or the record is malformed: emit a non-blocking `AppWarning::SettingsCorrupt`, return defaults, unlock proceeds.
4. If the settings record exists and parses but value is out of bounds: emit `AppWarning::SettingsClamped`, return clamped value, unlock proceeds.
5. If the settings record uses an unknown schema version: emit `AppWarning::SettingsUnknownVersion`, return defaults, unlock proceeds.
6. On success: settings live in `UnlockedSession.settings` until lock.

### Race conditions (all closed by the Mutex)

- **`notify_activity` arrives while lock is in-flight.** Mutex serializes. If lock acquires first, `inner = None` when `notify_activity` runs → silent no-op. If `notify_activity` acquires first, idle resets, then lock proceeds anyway (the lock decision is on the timer thread, which re-checks `is_expired(...)` inside the mutex — a freshly-bumped `last_activity_ms` saves the session on the next tick check).
- **Second `unlock_with_password` arrives while first is in-flight.** Mutex serializes. Second sees `inner.is_some()` and returns `AppError::AlreadyUnlocked`. Frontend disables the submit button while in-flight as belt-and-braces; backend defends regardless.
- **`UnlockedSession::Drop` ordering.** `vault.wipe()` called before `identity.wipe()` because the vault holds signature material that references the identity. Both are `ZeroizeOnDrop` anyway; this is belt-and-braces, mirrors the secretary-core convention.

## 7. Page routes & navigation

Two routes — `Unlock` and `Vault` — swapped by Svelte conditional rendering on the `$sessionState` store. No URL routing, no browser history state, no deep-link bypass risk.

### App.svelte (top-level orchestration)

```svelte
<script>
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import { sessionState, autoLockNotice } from './lib/stores';
  import Unlock from './routes/Unlock.svelte';
  import Vault from './routes/Vault.svelte';
  import Toast from './components/Toast.svelte';

  onMount(() => {
    const unlisten = listen<{ reason: 'idle' | 'explicit' | 'window_close' }>(
      'vault-locked',
      (event) => {
        sessionState.set({ status: 'locked', lastError: null });
        if (event.payload.reason === 'idle') {
          autoLockNotice.set('Vault auto-locked due to inactivity');
        }
      }
    );
    return () => { unlisten.then((fn) => fn()); };
  });
</script>

{#if $sessionState.status === 'unlocked'}
  <Vault />
{:else}
  <Unlock />
{/if}

{#if $autoLockNotice}<Toast message={$autoLockNotice} />{/if}
```

### Transitions

| Trigger | From | To | Mechanism |
|---|---|---|---|
| App startup | (cold) | Unlock | `sessionState` initializes to `{ status: 'locked' }` |
| Unlock form submit (success) | Unlock | Vault | `unlockWithPassword()` IPC resolves → store set to `{ status: 'unlocked', manifest, settings }` |
| Unlock form submit (failure) | Unlock | Unlock (with error) | IPC rejects → store stays locked with `lastError` populated; form re-enables |
| Lock button click | Vault | Unlock | `lock()` IPC → backend wipes session, emits `vault-locked { reason: 'explicit' }` → frontend transitions on event |
| Auto-lock timer fires | Vault | Unlock (with toast) | Backend timer thread → `session.lock()` → emits `vault-locked { reason: 'idle' }` → frontend transitions + toast |
| Window close | (any) | (process exit) | Tauri runtime drops state → Rust Drop chain wipes |

The Lock click does not preemptively transition; frontend waits for the `vault-locked` event so the frontend state mirrors backend reality with no out-of-sync window.

### Store shape

```typescript
// src/lib/stores.ts (sketch)
export type SessionState =
  | { status: 'locked';      lastError: AppError | null }
  | { status: 'unlocking';   lastError: null }
  | { status: 'unlocked';    manifest: ManifestDto; settings: Settings }
  | { status: 'locking';     lastError: null };

export const sessionState = writable<SessionState>({ status: 'locked', lastError: null });
export const autoLockNotice = writable<string | null>(null);
export const currentSettings = derived(sessionState, ($s) =>
  $s.status === 'unlocked' ? $s.settings : null
);
```

Discriminated union — TypeScript narrows inside `{#if $sessionState.status === '...'}` blocks; exhaustive across the four states.

### Settings dialog

A modal overlay on Vault, not a separate route. Implemented as a Svelte component `<SettingsDialog>` with `bind:open` prop, backed by the native HTML5 `<dialog>` element (accessible focus-trap + ESC-to-close built in; no JS-managed accessibility state). Closing without submitting leaves `sessionState` untouched. Submitting calls `setSettings(...)` IPC.

## 8. Settings record schema

### Where it lives in the vault

| Element | Value | Rationale |
|---|---|---|
| Block name | `"__secretary_app_settings__"` | Reserved; double-underscore marks "internal"; unlikely to collide with user-created block names |
| Block UUID | `SHA-256("__secretary_app_settings__")[0..16]` (deterministic) | Required for CRDT correctness: two devices both creating the settings block independently produce the same UUID, so the merge layer treats them as concurrent updates of one block, not two separate blocks. Also a debugging aid. |
| Record type | `"secretary.settings.v1"` | Versioned. Future schema migrations get `v2`, etc. Forward-compat: unknown version on load → `Settings::default()` + warning DTO |
| Record UUID | `SHA-256("secretary.settings.v1")[0..16]` (deterministic) | Same reasoning |
| Record tags | `[]` | No tag taxonomy yet |
| Record fields | One: `{ name: "auto_lock_timeout_ms", value: Text(<base-10 integer string>) }` | Single-field, one concern per record |

### Field value encoding

- `FieldInputValue::Text(SecretString)` — the FFI's text variant. UTF-8 base-10 integer string.
- The auto-lock timeout is NOT a secret, but it IS stored encrypted at rest because the vault encrypts everything inside it. Wrapping in `SecretString` is the FFI's discipline ([[feedback_security_no_assumptions]] — typed enforcement over plausibility), not a semantic claim about the value's sensitivity.

### Validation (in `settings.rs`, applied to both load and save paths)

- Must parse via `<&str>::parse::<u64>()`.
- Lower bound `AUTO_LOCK_MIN_MS = 60_000` (1 minute). Below this, re-typing the password becomes tedious without measurable security gain.
- Upper bound `AUTO_LOCK_MAX_MS = 86_400_000` (24 hours). Above this, auto-lock is effectively disabled — security antipattern we won't ship as configurable.
- **On out-of-bounds load**: clamp to nearest bound, emit `AppWarning::SettingsClamped { original_ms, clamped_ms }`, proceed with clamped value. Don't fail unlock for out-of-bounds settings — would render a vault unusable.
- **On out-of-bounds save**: reject at the IPC boundary with `AppError::SettingsOutOfRange { min, max }`. Frontend's settings dialog also validates client-side; this round-trips only on adversarial input.

### Lazy creation

- The settings block is NOT created on first unlock if absent. The app uses `Settings::default()` in-memory; vault stays byte-identical.
- The settings block is created on the first `set_settings` call from the frontend (the user's first explicit action to mutate the value away from the default).
- Modest privacy property: vaults of users who never open the settings dialog don't carry Secretary-app metadata in their manifest.

### Constants (canonical reference)

| Constant | Value | Where used | Why this value |
|---|---|---|---|
| `AUTO_LOCK_DEFAULT_MS` | `600_000` | Fallback when no settings record exists; new-vault default | 10 minutes. Matches 1Password (10 min default), Bitwarden (15 min). Long enough to not annoy; short enough that "I walked away for lunch" leaves the vault locked |
| `AUTO_LOCK_MIN_MS` | `60_000` | Validation lower bound | 1 minute. Below this, re-prompts become tedious with no security gain (30 s vs 60 s adversary window isn't materially different in a physical-access threat model) |
| `AUTO_LOCK_MAX_MS` | `86_400_000` | Validation upper bound | 24 hours. Anything longer is effectively "never auto-lock" — we won't ship that as configurable |
| `AUTO_LOCK_TICK_MS` | `5_000` | Auto-lock timer thread tick interval | 5 seconds. Coarse enough to be free of measurable CPU cost; fine enough that auto-lock fires within 5 s of the threshold expiring (acceptable jitter vs the 1-minute minimum threshold) |
| `ACTIVITY_NOTIFY_MIN_INTERVAL_MS` | `2_000` | Frontend debounce for `notify_activity` calls | 2 seconds. Each mousemove during typing shouldn't issue an IPC; 2 s is well below any plausible threshold so the timer never spuriously fires while the user is active |
| `SETTINGS_BLOCK_NAME` | `"__secretary_app_settings__"` | Reserved block name lookup | See above |
| `SETTINGS_RECORD_TYPE` | `"secretary.settings.v1"` | Versioned record_type for forward-compat | See above |
| `SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS` | `"auto_lock_timeout_ms"` | Field name string | Snake-case matches Rust convention; matches the Rust constant name for grep-ability |

**Discipline:** these constants live in code as `pub const` with doc-comments quoting the rationale verbatim from this table — no magic numbers. The spec is the canonical source; code references it by name.

## 9. Error model

Three-layer pipeline: `secretary-core` typed errors → Rust `AppError` (thiserror, serde-serializable) → TypeScript discriminated union → user-facing message.

### `AppError` enum (`src-tauri/src/errors.rs`)

```rust
#[derive(thiserror::Error, Debug, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AppError {
    #[error("Vault folder does not exist or is not readable")]
    VaultPathNotFound { path: String },

    #[error("Folder exists but doesn't contain a vault")]
    VaultPathNotAVault { path: String },

    #[error("Vault is currently locked by another process")]
    VaultPathLocked { path: String },

    #[error("Wrong password")]
    WrongPassword,

    #[error("Vault uses KDF parameters below the minimum")]
    KdfTooWeak { current_memory_kib: u32, min_memory_kib: u32 },

    #[error("Vault is corrupted; consider restoring from a backup")]
    VaultCorrupt {
        #[serde(skip_serializing)]  // dev-facing detail; not exposed to frontend
        detail: String,
    },

    #[error("Vault already unlocked")]
    AlreadyUnlocked,

    #[error("No vault currently unlocked")]
    NotUnlocked,

    #[error("Settings record is malformed; using defaults")]
    SettingsCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Settings record uses an unknown schema version")]
    SettingsUnknownVersion { version: String },

    #[error("Auto-lock timeout must be between {min} and {max} ms")]
    SettingsOutOfRange { min: u64, max: u64 },

    #[error("Filesystem error")]
    Io {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Internal error — this is a bug")]
    Internal {
        #[serde(skip_serializing)]
        detail: String,
    },
}
```

### Key disciplines

- **`#[serde(tag = "code", rename_all = "snake_case")]`** — every variant becomes `{ "code": "wrong_password", ... }` on the wire. TypeScript discriminates on `code`.
- **`#[serde(skip_serializing)]` on `detail` fields** — developer-facing detail is logged via `tracing` on the Rust side but **never** crosses the IPC seam. The user sees the variant-level message; the dev sees the full chain in stderr.
- **No `From<E>` for arbitrary error types.** Every `secretary_core::*Error` → `AppError` conversion is an explicit `match` so we choose the user-facing variant — default would wrap-in-`Internal` which is wrong for known cases.
- **`WrongPassword` collapse rule.** Anything decryption-failure shaped collapses to `WrongPassword`. Information-leak prevention: padding-oracle-style probes could otherwise distinguish "wrong password" from "vault corrupt" subtleties. True corruption (manifest signature failure, block hash mismatch) gets `VaultCorrupt`; the line is drawn at the cryptographic seam.

### Non-error warnings — `manifest.warnings`

Some conditions are warnings, not errors — unlock succeeds with a caveat. The `ManifestDto` returned by `unlock_with_password` carries:

```rust
#[derive(serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AppWarning {
    SettingsCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },
    SettingsClamped { original_ms: u64, clamped_ms: u64 },
    SettingsUnknownVersion { version: String },
}

#[derive(serde::Serialize)]
pub struct ManifestDto {
    pub vault_uuid_hex: String,
    pub owner_user_uuid_hex: String,
    pub block_count: u64,
    pub block_summaries: Vec<BlockSummaryDto>,
    pub warnings: Vec<AppWarning>,
}
```

Frontend renders warnings as non-blocking toast/banner; unlock flow proceeds.

### Frontend mapping (`src/lib/errors.ts`)

```typescript
export type AppError =
  | { code: 'vault_path_not_found'; path: string }
  | { code: 'vault_path_not_a_vault'; path: string }
  | { code: 'vault_path_locked'; path: string }
  | { code: 'wrong_password' }
  | { code: 'kdf_too_weak'; current_memory_kib: number; min_memory_kib: number }
  | { code: 'vault_corrupt' }
  | { code: 'already_unlocked' }
  | { code: 'not_unlocked' }
  | { code: 'settings_corrupt' }
  | { code: 'settings_unknown_version'; version: string }
  | { code: 'settings_out_of_range'; min: number; max: number }
  | { code: 'io' }
  | { code: 'internal' };

export function userMessageFor(err: AppError): { title: string; detail?: string; actionHint?: string } {
  // exhaustive switch — adding a variant without a case is a TS type error
  switch (err.code) {
    case 'wrong_password':
      return { title: 'Wrong password', actionHint: 'Check Caps Lock and keyboard layout.' };
    // ... all variants enumerated; each returns curated user-facing strings.
  }
}
```

Pure, exhaustive, Vitest-covered.

### Logging discipline

`AppError::*` constructions log via `tracing::warn!()` or `tracing::error!()` with the full `detail` field before serializing to IPC. Dev-facing detail captured in logs; user-facing IPC payload stripped. `tracing` initialized in `main.rs` via `tracing_subscriber::fmt()` to stderr.

## 10. Testing strategy

Four layers, fastest first:

| Layer | Scope | Tool | Location | When |
|---|---|---|---|---|
| **L1 — Rust unit tests** | Pure functions in `auto_lock.rs`, `settings.rs`, `errors.rs` | `cargo test` | `#[cfg(test)] mod tests` inline per file | `cargo test --release --workspace` (existing gauntlet) |
| **L2 — TS unit tests** | Pure functions in `lib/auto_lock.ts`, `lib/errors.ts`, IPC wrappers | Vitest | `tests/*.test.ts` | New gauntlet line: `pnpm test` |
| **L3 — Rust integration tests** | Backend session + settings against a real vault | `cargo test` | `src-tauri/tests/session_integration.rs` | Same as L1 |
| **L4 — End-to-end smoke** | Full unlock → block list → lock cycle through WebView | `tauri-driver` + WebdriverIO | `e2e/unlock_and_browse.spec.ts` | `pnpm e2e` — not in CI for D.1.1 |

### L1 — Rust unit tests

- `auto_lock.rs`: `IdleTracker::is_expired` truth table (fresh activity, expired, exactly at threshold), monotonic clock invariants.
- `settings.rs`: parse-fixed-strings tests covering valid integer, invalid utf-8, integer with whitespace, negative, zero, max-u64, value just below `AUTO_LOCK_MIN_MS`, just above `AUTO_LOCK_MAX_MS`, unknown `record_type`, unknown version. `serialize_settings` round-trip property test. Deterministic block UUID frozen-string check against SHA-256-truncated-16 hex.
- `errors.rs`: per-variant `serde_json::to_string(&error).contains("\"code\":\"…\"")` checks (catches accidental rename via `#[serde(tag = ...)]`).

All under workspace `cargo test --release --workspace --tests`.

### L2 — TS unit tests

- `lib/auto_lock.ts`: debounce timing via Vitest fake timers (`vi.useFakeTimers()` + `vi.advanceTimersByTime(...)`), activity-event handler attach/detach lifecycle, `notifyActivity` called at most once per `ACTIVITY_NOTIFY_MIN_INTERVAL_MS`.
- `lib/errors.ts`: every `AppError` variant maps to a non-empty title; exhaustiveness compiles.
- `lib/ipc.ts`: each wrapper unwraps Tauri's `invoke` correctly on success, re-throws typed errors on rejection (mock via `vi.mock('@tauri-apps/api/core')`).

### L3 — Rust integration tests

`src-tauri/tests/session_integration.rs`:

- Unlock against `core/tests/data/golden_vault_001/` with known password → session unlocked, manifest readable.
- Wrong password → `WrongPassword` (no leak via `format!()`).
- Unlock-lock cycles → state transitions correct; mutex re-acquirable; second unlock works.
- Settings load from a vault with no settings block → defaults returned, no I/O.
- Settings load from a vault with a corrupt settings block (constructed via fresh vault + malformed-record injection at test setup) → `SettingsCorrupt` warning, unlock proceeds with defaults.
- Settings save round-trip → set new value, lock, unlock → loaded value matches.

Reuses `golden_vault_001` (read-only) + ephemeral `tempfile::tempdir()` vaults for write paths.

### L4 — End-to-end smoke

`e2e/unlock_and_browse.spec.ts` using `tauri-driver` + WDIO:

1. Launch debug binary (`cargo tauri build --debug` artifact path).
2. Wait for Unlock screen.
3. Fill folder path with `golden_vault_001` absolute path.
4. Fill password with known good.
5. Click Unlock.
6. Wait for Vault screen.
7. Assert ≥ 1 block card rendered.
8. Click Lock.
9. Wait for Unlock screen.

Runs via `pnpm e2e` against a pre-built debug binary. **NOT in CI for D.1.1** — CI integration requires WebKitGTK + tauri-driver setup beyond this slice's scope. Filed as a follow-up.

### Coverage discipline

- Every pure function in `lib/*` (TS) and `src-tauri/src/*.rs` (excluding `main.rs` and `commands/*`) has a unit test before its first use in production code — TDD per repo policy.
- Commands (`commands/*.rs`) are thin wrappers — tested via L3 integration tests.
- No Svelte component-level unit tests in D.1.1 — L4 smoke covers rendering.

### Expanded gauntlet at D.1.1 close

```
cargo test --release --workspace                          # L1 + L3 — adds ~30-50 tests
cargo clippy --release --workspace --tests -- -D warnings # unchanged
cargo fmt --all -- --check                                # unchanged
uv run core/tests/python/conformance.py                   # unchanged
uv run core/tests/python/spec_test_name_freshness.py      # unchanged
cd desktop && pnpm test                                   # L2 — NEW gauntlet line
cd desktop && pnpm tsc --noEmit                           # NEW gauntlet line — TS type-check
cd desktop && pnpm svelte-check                           # NEW gauntlet line — Svelte type-check
cd desktop && pnpm lint                                   # NEW gauntlet line — ESLint
```

L4 (`pnpm e2e`) runs manually before tagging a release; not per-task.

## 11. Dev loop & dependencies

### Prerequisites (developer machine)

| Tool | Version | Install | Why |
|---|---|---|---|
| Rust toolchain | Stable per existing `rust-toolchain.toml` | rustup | Backend + workspace |
| Node.js | LTS (≥ 20.x) | nvm/fnm/system | Frontend toolchain |
| pnpm | ≥ 9.x | `npm install -g pnpm` or corepack | Package manager |
| Tauri CLI | `^2.x` | `devDependencies` in `desktop/package.json` (invoke via `pnpm tauri ...`) | Per-project pin |
| WebKitGTK (Linux only) | `2.40+` | `apt install libwebkit2gtk-4.1-dev` or distro equivalent | Linux WebView runtime |
| `tauri-driver` (L4 only) | latest | `cargo install tauri-driver` | WebDriver shim |

macOS: zero install beyond Rust + Node + pnpm. Linux adds the webkit2gtk apt package. Windows isn't a target ([[feedback_windows_not_primary]]).

### Why pnpm over npm/yarn

- Hardlinked content-addressable store — faster installs, smaller `node_modules`.
- Strict by default (no phantom deps).
- Workspace support if `desktop/` later splits into sub-packages.
- Lockfile discipline (`pnpm-lock.yaml`) fits the repo pattern (`Cargo.lock`, `uv.lock`).

### Project initialization (D.1.1 task 1 — one-time)

**Manual scaffold over `pnpm create tauri-app`**, because:

- The CLI is interactive (prompts), doesn't fit the non-interactive task-execution pattern of `uv run`/`cargo`.
- The CLI scaffolds with example content (Counter app, etc.) — deleted immediately anyway.
- Manual scaffolding produces the exact layout in §4 with zero cruft.

Steps:

1. `desktop/package.json` written from a documented template (frontend deps enumerated).
2. `desktop/src-tauri/Cargo.toml` with `secretary-core = { path = "../../core" }`.
3. Root `Cargo.toml` `[workspace] members` adds `"desktop/src-tauri"`.
4. `desktop/src-tauri/tauri.conf.json` — bundle ID `org.secretary.desktop`, 1024×768 window, CSP per §11.4.
5. `desktop/vite.config.ts`, `svelte.config.js`, `tsconfig.json` from Tauri 2 + Svelte canonical templates.

### Content Security Policy (`tauri.conf.json`)

```json
{
  "app": {
    "security": {
      "csp": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ipc: tauri:; script-src 'self'"
    }
  }
}
```

- `default-src 'self'` — blocks any external load.
- `script-src 'self'` (no `'unsafe-inline'`/`'unsafe-eval'`) — Vite prod build outputs only bundled JS files.
- `connect-src 'self' ipc: tauri:` — allows Tauri IPC only.
- `style-src 'self' 'unsafe-inline'` — Svelte injects scoped styles inline; cannot avoid without disabling Svelte's style scoping. Acceptable: no untrusted HTML rendering in the app.
- `img-src 'self' data:` — `data:` allows inlining the logo as a base64 PNG.

### Dev loop

```bash
# One-time:
cd desktop
pnpm install                           # installs frontend deps + tauri CLI
cd src-tauri && cargo build --debug    # warms cargo cache

# Inner loop:
cd desktop
pnpm tauri dev                          # launches Vite dev server + Tauri window
# Frontend changes: Vite hot-reload, no restart.
# Backend changes: tauri dev auto-rebuilds + restarts (~5-10 s).

# Test layers:
pnpm test                               # L2 — Vitest
pnpm tsc --noEmit                       # TS type-check
pnpm svelte-check                       # Svelte type-check
pnpm lint                               # ESLint
cargo test --release --workspace        # L1 + L3 — from repo root
pnpm e2e                                # L4 — requires a fresh `cargo tauri build --debug`
```

### CSS strategy

Plain CSS via `src/theme.css` custom properties. No Tailwind, no component library. Frontend deps stay minimal: `svelte`, `vite`, `@sveltejs/vite-plugin-svelte`, `typescript`, `@tauri-apps/api`, `@tauri-apps/cli`, `vitest`, plus WDIO + tauri-driver for L4.

### Build artifacts (out of D.1.1 scope)

- `cd desktop && pnpm tauri build` produces `.dmg`/`.app` (macOS), `.deb`/`.AppImage`/`.rpm` (Linux).
- Code signing / notarization deferred to a dedicated release-engineering slice.

## 12. UX details (from brainstorming wireframes)

### Unlock screen (single-screen layout)

- Centered card, ~420 px max width.
- Top: 🔐 icon + "Secretary" title + "Open a vault" subtitle.
- "Vault folder" label + read-only input (showing currently-selected folder) + "Choose…" button to invoke the native folder dialog via Tauri's `@tauri-apps/api/dialog`.
- "Password" label + masked input. **No show/hide toggle in D.1.1** — adds DOM mutation to a sensitive input field; revisit if user research shows it's missed.
- "Unlock" button (full width, disabled while folder is empty or in-flight).
- Footer: "Lost your password? Use recovery phrase (coming soon)" — placeholder, no action.
- On submit failure: inline error block above the Unlock button using the typed `AppError` → `userMessageFor()` mapping.

### Vault screen (block list scaffold)

- Top bar: "Secretary · vault: \<folder-name\>" left, "⚙️ Settings" + "🔒 Lock" right.
- Block list area: vertical stack of `BlockCard` components, one per `block_summary` in the manifest.
- Each card: block name (bold), record count + last-modified timestamp (subtle).
- Click on a card: no-op + cursor: not-allowed (D.1.2 will wire this up). A tooltip / aria-label notes "Block details coming in the next release".
- "⚙️ Settings" opens the settings dialog.
- "🔒 Lock" invokes the `lock()` IPC.

### Settings dialog

- Native `<dialog>` element.
- Single field for D.1.1: "Auto-lock after" + input (in minutes; converted to ms at IPC boundary) + "minutes" suffix.
- Validation: integer ≥ 1, ≤ 1440 (24 hrs). Client-side validation matches `AUTO_LOCK_MIN_MS` / `AUTO_LOCK_MAX_MS` from §8.
- Buttons: "Cancel" (close, no-op) + "Save" (calls `setSettings()` IPC; on success closes the dialog).
- On IPC error: inline error below the input.

### Toast notifications

- Slide-in from top-right, auto-dismiss after 5 seconds.
- Used for: "Vault auto-locked due to inactivity" on auto-lock event.

## 13. Out of scope for D.1.1

Explicitly deferred (each gets a future slice or umbrella):

| Item | Lands in |
|---|---|
| Vault create wizard (new vault from scratch, mnemonic display) | D.1.3 |
| Block detail view — click a block, see records | D.1.2 |
| Record view + reveal secret field | D.1.2 |
| Add/edit records, `save_block` write path beyond settings | D.1.4 |
| Share block / trash / restore | D.1.5 |
| Recovery-phrase unlock (24-word entry) | D.1.x or folded into D.1.3 |
| Recent-vaults list on Unlock screen | Future |
| Drag-and-drop vault folder onto window | Future |
| Browser-mode fallback | Probably never |
| Windows desktop builds | Per [[feedback_windows_not_primary]] — not promised |
| iOS / Android via Tauri 2 mobile | D.3 (new shape; replaces old D.2 + D.3 plan) |
| Code signing / notarization | Dedicated release-engineering slice |
| Auto-update mechanism | Future |
| Telemetry / crash reporting | Never (offline-first project) |
| Multi-window support (multiple vaults open) | Future |
| Multi-user / shared-vault UI surface | Future |
| Settings beyond `auto_lock_timeout_ms` | Added incrementally as D.1.x slices need them |
| L4 e2e in CI | Dedicated CI-infra slice |
| Custom URL handler `secretary://` | Future |
| AutoFill / browser-extension interop | Future (was D.4) |
| Clipboard "copy secret" | D.1.2 (folded into reveal-secret UX) |
| Locale / i18n | Future |
| Full accessibility audit beyond semantic HTML + native `<dialog>` | Future |
| Show/hide password toggle on Unlock | Revisit if user research shows it's missed |
| `Sub-project B` Python FFI deprecation | Not happening — stays as scripting/automation consumer path |
| `Sub-project B uniffi` Swift/Kotlin deprecation | Same — stays as third-party-consumer path |
| `Sub-project C.3` rationale revisit | Out of D.1.1's scope; revisit when D.3 is planned |

## 14. Broader project implications (in the first D.1.1 PR)

The Tauri pivot affects four documents that ride with the first D.1.1 PR, separate from code:

1. **`README.md`** — Sub-project D summary row rewrites from "Python + NiceGUI + SwiftUI + Compose" to "Tauri-based universal client across desktop + mobile".
2. **`ROADMAP.md`** — D-row section restructured. D.1 / D.2 / D.3 entries replaced with the new shape:
   - **D.1** — Tauri walking skeleton (macOS desktop first).
   - **D.1.x** — browse / create / edit / share, planned per-slice.
   - **D.2** — Linux + Windows desktop (CI matrix).
   - **D.3** — Tauri 2 mobile (iOS + Android).
   The "Where we are" bullet does NOT yet flip to "D.1 ✅" — that waits for D.1.1 implementation to land.
3. **`docs/adr/0007-d-row-tauri.md`** — new ADR. Format mirrors existing ADRs 0001–0006:
   - Context: the original D-row was decided when Rust core was alone.
   - Decision: Tauri replaces NiceGUI + SwiftUI + Compose for UIs.
   - Consequences: enumerated security + codebase-consolidation wins, upfront effort + learning curve costs.
   - Alternatives considered: stay with NiceGUI (rejected); hybrid (rejected).
4. **`desktop/README.md`** — rewrites from a 1-line stub to a proper "what's here + dev-loop quick-start" file.

Sub-projects C.3 (mobile sync adapters) and C.4 (cross-device convergence) **are NOT renamed** by this pivot — they're independent of the UI layer. The C.3 uniffi-Swift/Kotlin bindings remain useful for non-Tauri consumers (Apple Shortcuts, Android AutoFill). If Tauri 2's mobile plugins end up handling the watcher work, C.3 becomes scope-narrowed at that point — a decision for whenever C.3 is picked up next.

## 15. Acceptance criteria for the D.1.1 implementation

When all of the following hold, D.1.1 is shippable:

1. **Manual smoke** — From a fresh checkout, after running `cd desktop && pnpm install && pnpm tauri build --debug`, the produced binary can be launched and the developer can:
   - See the Unlock screen.
   - Use the "Choose…" button to pick `core/tests/data/golden_vault_001/`.
   - Enter the known-good password.
   - See the Vault screen with the golden vault's blocks listed.
   - Open Settings, change auto-lock from 10 min to 1 min, save.
   - Idle for >1 minute → vault auto-locks with the toast notification.
   - Re-unlock + verify the 1-minute value is persisted.
   - Click Lock → returns to Unlock screen.
2. **Gauntlet** — All lines in §10's expanded gauntlet pass clean:
   - `cargo test --release --workspace` → all green
   - `cargo clippy --release --workspace --tests -- -D warnings` → clean
   - `cargo fmt --all -- --check` → clean
   - `uv run core/tests/python/conformance.py` → PASS
   - `uv run core/tests/python/spec_test_name_freshness.py` → PASS
   - `cd desktop && pnpm test` → all green
   - `cd desktop && pnpm tsc --noEmit` → clean
   - `cd desktop && pnpm svelte-check` → clean
   - `cd desktop && pnpm lint` → clean
3. **L4 e2e (manual)** — `cd desktop && pnpm e2e` runs cleanly against the debug binary.
4. **Documentation** — README.md and ROADMAP.md reflect the new Tauri-based D-row. ADR 0007 committed. `desktop/README.md` rewritten.
5. **Process discipline** — Every file under 500 LOC (per [[feedback_split_files_proactively]]). No magic numbers — every constant is named and documented. Pure functions in their own modules (per [[feedback_pure_functions]]). Tests use random crypto values where applicable (per [[feedback_test_crypto_random_not_hardcoded]]).

## 16. References

- [ADR 0001 — Rust core with Python / Swift / Kotlin clients via FFI](../../adr/0001-rust-core.md) (supersedes the desktop-UI portion)
- [ADR 0007 — Sub-project D pivot to Tauri](../../adr/0007-d-row-tauri.md) (new in this PR)
- [Tauri documentation](https://v2.tauri.app/) — version 2.x
- [Svelte documentation](https://svelte.dev/) — Svelte 5
- [`secretary-core` vault format spec](../../vault-format.md)
- [`secretary-core` crypto design](../../crypto-design.md)
- Existing precedent: [C.2 headless sync CLI design](2026-05-23-c2-headless-sync-cli-design.md) for the brainstorming → spec → plan workflow shape.
