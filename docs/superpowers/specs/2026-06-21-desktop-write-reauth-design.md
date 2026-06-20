# Desktop password re-auth before a write — design

**Date:** 2026-06-21
**Branch:** `feature/desktop-write-reauth`
**Scope:** Desktop (Tauri 2 / Svelte) only. Sits over the password-based unlock and the existing IPC write commands. Brings the iOS write-reauth feature (#275) to the desktop, adapted to the desktop's primitives. **No `core/`, crypto/vault spec, `*.udl`, pyo3, iOS, or Android changes.** Unlike the iOS slices, this slice **does** touch `desktop/src-tauri` Rust (a verify command + a settings-schema extension) — the guardrails are *not* empty.

## Problem

A desktop vault session authenticates **once** at unlock (password → `open_vault_with_password`), then every mutating write runs against the open session with no further proof of presence. A machine left unlocked-and-open lets anyone mutate the vault. We want a re-auth gate **before** each mutating write — the desktop analog of the iOS biometric write-reauth.

The desktop has **no biometric / Secure-Enclave / device-secret primitive** (verified: the only `biometr|reauth|device-secret` hit under `desktop/` is variant names in `errors.rs`). Unlock is password-only and the password is **not retained** after unlock. So the desktop presence proof must be password re-entry.

## Decisions (locked during brainstorm)

1. **Primitive = password re-entry.** Before a mutating write outside the grace window, the user re-types the vault password. It is verified by re-running `open_vault_with_password(session.vault_folder, password)` and **immediately dropping** the transient handle. This reuses the existing, frozen crypto — no new crypto, no `*.udl`, no spec change. (OS biometrics — macOS Touch ID via SwiftUI, Linux polkit/fprintd, Windows Hello — are explicitly deferred to a filed follow-up issue.)
2. **Policy = grace window.** A write prompts only if more than `reauth_grace_window_ms` have elapsed since the last successful auth. One prompt covers a burst of edits. The unlock event seeds the clock, so the first write within the window needs no prompt.
3. **Engagement = opt-in setting, default ON.** New `require_password_before_edits: bool` setting, default `true` (secure by default), user-toggleable. "Secretary enables maximum security; the user decides what is necessary."
4. **Grace window = user-configurable, default 2 minutes.** New `reauth_grace_window_ms: u64` setting, default `120_000`, bounded by named constants, editable in the Settings dialog. Low-friction users may widen it; security-conscious users may tighten it.
5. **Injection point = frontend (Svelte/TS) layer.** The gate is a host-testable (vitest) module injected at the write call sites — *not* a Rust IPC chokepoint — so a cancel keeps the originating dialog open and the prompt shows a tailored reason. This mirrors the iOS VM-level decision.

## Non-goals (YAGNI)

- No OS biometric on desktop in this slice (separate follow-up: macOS / Linux / Windows).
- No per-write-type custom windows (one global value).
- No change to auto-lock behavior (it independently locks the whole vault on idle; it is an orthogonal backstop).
- No gating of the settings-save itself (see Deliberate decisions).
- No retention of password material to make verification cheaper (would weaken the threat model; rejected).

## Architecture

```
desktop/src/lib/
  reauth.ts        PURE: needsReauth(opts: { enabled, lastAuthAtMs, nowMs, windowMs }) -> boolean
                     - enabled === false            → false   (gate disabled)
                     - lastAuthAtMs == null         → true    (never authed this session)
                     - nowMs - lastAuthAtMs >= win  → true    (boundary inclusive: >=)
                     - else                         → false   (inside grace)
  writeGuard.ts    authorizeWrite(reason: string): Promise<void>
                     - reads current settings (enabled + windowMs) from the session store
                     - if !needsReauth(...) → resolve (no prompt)
                     - else: open the password-prompt store with `reason`; await user;
                       on submit call ipc.verifyPassword(pw); on Ok advance lastAuthAtMs = now()
                       and resolve; on wrong-password keep the prompt open with an inline error;
                       on Cancel reject with a ReauthCancelled sentinel
                     - holds module-level `lastAuthAtMs` + an injected `now: () => number`
                       and an injected prompt/verify pair (for tests)
  stores.ts        a `writable` for the pending re-auth prompt
                     ({ reason, resolve, reject } | null) so any caller drives one shared modal

desktop/src/components/
  ReauthPasswordDialog.svelte   modal bound to the prompt store: shows `reason`,
                                a password input, inline "wrong password" error,
                                Cancel / Confirm. Mounted once in the vault shell.

desktop/src-tauri/src/commands/
  reauth.rs (new)  #[tauri::command] verify_password(state, password) -> Result<(), AppError>
                     - reads session.vault_folder under the session mutex (NotUnlocked if locked)
                     - runs open_vault_with_password(folder, &password); drops the handle
                     - Ok(()) on success; typed AppError on wrong password / IO
                     - thin shell + testable verify_password_impl, same pattern as edit/delete
  unlock.rs        registration only (or co-locate the command here)

desktop/src-tauri/src/settings/parse.rs   Settings gains two fields; parse/serialize become
                                          multi-field with backward-compat defaults
desktop/src-tauri/src/constants.rs        REAUTH_WINDOW_DEFAULT_MS / _MIN_MS / _MAX_MS,
                                          REQUIRE_PASSWORD_DEFAULT, new field-name constants
```

### Why the gate is a frontend port (not a Rust IPC wrapper)

Wrapping the write commands in Rust would (a) put the prompt/grace/cancel logic in the backend where it can't keep a Svelte dialog open or show a tailored reason, and (b) require blocking on a UI password prompt from inside a command. Keeping the gate in the frontend matches iOS (VM-level), keeps the policy a pure host-tested function (`needsReauth`), and lets each call site decide what to do on cancel. The backend's only new responsibility is the stateless `verify_password` check.

## Settings schema extension (multi-field record)

Today the settings record is a single field (`auto_lock_timeout_ms`). This slice extends it:

```rust
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,   // NEW, default true
    pub reauth_grace_window_ms: u64,           // NEW, default 120_000, clamped to [MIN, MAX]
}
```

- **Serialize** writes all three fields into the settings record.
- **Parse** tolerates a record missing the new fields (older client) → fills defaults, no error. Unknown *extra* field names remain an error (forward-compat is not promised; matches current strictness) — but see the open note below; we may relax unknown-field handling to a warning to avoid a future-client write tripping an older client. Decision recorded in the plan.
- **Validate-on-save** rejects out-of-range `reauth_grace_window_ms` with `SettingsOutOfRange` (reusing the existing pattern); `require_password_before_edits` is a bool (no range).
- Bounds/defaults are **named constants** in `constants.rs` (no magic numbers).

The current `parse_settings_field(record_type, field_name, value)` single-field signature is replaced by a multi-field parser (e.g. `parse_settings_fields(record_type, &[(name, value)])`) — the record carries multiple fields now. The `clamp_with_warning` load-path behavior is preserved per numeric field.

## Gated write set

All vault-mutating IPC writes are gated (the guard is one shared call, so coverage is cheap per site):

| Layer | IPC | Reason string (illustrative) |
|---|---|---|
| record | `saveRecord` (append) | "Confirm saving this entry" |
| record | `saveRecordEdit` | "Confirm saving your changes" |
| record | `tombstoneRecord` (delete) | "Confirm deleting this entry" |
| record | `resurrectRecord` (restore) | "Confirm restoring this entry" |
| record | `moveRecord` | "Confirm moving this entry" |
| block | `createBlock` | "Confirm creating this block" |
| block | `renameBlock` | "Confirm renaming this block" |
| block | `trashBlock` | "Confirm trashing this block" |
| block | `restoreBlock` | "Confirm restoring this block" |
| sharing | `shareBlock` | "Confirm sharing this block" |
| sharing | `revokeBlockFrom` | "Confirm revoking access" |
| contacts | `deleteContactCard` | "Confirm deleting this contact" |

**Not gated:** `set_settings` (settings save). Gating it creates a confusing "re-auth in order to disable re-auth" loop, and the Settings dialog is already behind unlock. Read commands (`readBlock`, `revealRecord`, `listBlocks`, `listTrashedBlocks`, sync, …) are never gated.

Each handler becomes `await authorizeWrite(reason); await ipc.<write>(...)`. Input validation (blank name, same-block move, etc.) stays **before** `authorizeWrite` — no password prompt for input the app would reject anyway.

## Data flow (one write)

```
user clicks Delete / Save / Move / Create-block / Rename / Share / Revoke
  ▼  handler (Svelte component)
  └─ (input validation first — short-circuits before any prompt)
  └─ await authorizeWrite("Confirm deleting this entry")
        ▼ writeGuard.authorizeWrite
        ├─ if !needsReauth({enabled, lastAuthAtMs, now(), windowMs}) → resolve  (disabled OR within grace)
        ├─ open prompt store with reason → ReauthPasswordDialog mounts
        ├─ user submits → ipc.verifyPassword(pw)
        │     ├─ Ok  → lastAuthAtMs = now(); close prompt; resolve
        │     └─ Err(wrong password) → keep prompt open, show inline error
        └─ user cancels → reject(ReauthCancelled)
  │  (reject → caught by handler; ipc write NOT called; dialog/sheet stays open; error toast)
  ▼  await ipc.tombstoneRecord(...)            // unchanged
```

Three terminal outcomes per write, identical in spirit to iOS:
1. **Authorized** — disabled, or within grace, or password verified → the existing write runs.
2. **Cancelled / wrong-password-then-cancel** — write not attempted; originating dialog stays open; error surfaced.
3. **Clock seeding** — unlock seeds `lastAuthAtMs = now()` so the first write within the window needs no prompt; `lock()`/auto-lock resets the guard state.

## Error handling

- `verify_password` returns a typed `AppError`: a new `ReauthFailed { detail }` (or reuse of an existing wrong-password variant if one fits — verified in the plan) for a wrong password, `NotUnlocked` if locked.
- This is an **`AppError`** (desktop-local enum), distinct from the bridge `FfiVaultError` — adding/using a variant does **not** touch `*.udl` or the Swift/Kotlin conformance harnesses ([[project_secretary_ffivaulterror_workspace_match]] does not apply). If a new `AppError` variant is added, the existing `errors.ts` union + its exhaustive handling are updated in lockstep (vitest covers this).
- The frontend `ReauthCancelled` is a sentinel value, not an `AppError`; the handler distinguishes "user cancelled" (silent or soft toast) from "wrong password handled inside the dialog".

## Testing (TDD)

**`needsReauth` (vitest, pure):**
- enabled `false` → `false` regardless of clock.
- `lastAuthAtMs == null` → `true`.
- elapsed `< window` → `false`.
- elapsed `>= window` (boundary at exactly `window`) → `true`.

**`writeGuard.authorizeWrite` (vitest, fake prompt + fake verify):**
- disabled → resolves, prompt never opened, verify never called.
- enabled, never authed → prompt opened once; verify Ok → resolves; `lastAuthAtMs` set.
- enabled, within grace → prompt not opened.
- enabled, past grace → prompt opened again.
- verify wrong-password → prompt stays open; `lastAuthAtMs` unchanged; resolves only after a later Ok.
- cancel → rejects with `ReauthCancelled`; `lastAuthAtMs` unchanged.
- success advances the clock so the next immediate write is free.

**Component tests (vitest):** a gated handler with a stubbed guard performs **zero** ipc write on cancel and keeps its dialog open; happy path performs the write. Existing write-path component/store tests updated to await the now-guarded actions with a pass-through (disabled or auto-resolve) fake guard so they don't regress.

**`ReauthPasswordDialog.svelte` (vitest):** renders the reason; Confirm calls verify with the typed password; wrong-password shows the inline error and keeps the field; Cancel rejects.

**Rust (`cargo test`):**
- `verify_password_impl`: right password → `Ok`; wrong password → typed error; locked session → `NotUnlocked`. (Uses a temp copy of the golden vault — never the tracked fixture, per [[feedback_smoke_test_temp_copy_golden_vault]].)
- Settings multi-field parse/serialize round-trip; backward-compat: a record missing the new fields loads defaults with no error; out-of-range window rejected on save; clamp-on-load warning preserved.

**Lint/format:** `cargo clippy --release --workspace --tests -- -D warnings`, `cargo fmt --all`, `pnpm lint` + `pnpm svelte-check` (per [[project_secretary_svelte_smartquote_svelte_check]]) clean.

## Acceptance criteria

- With the setting ON, a mutating write outside the grace window prompts for the password before the write; within the window it does not re-prompt; a wrong password keeps the prompt open; a cancel prevents the write (zero ipc write asserted) and leaves the originating dialog open.
- With the setting OFF, all writes proceed exactly as today (no prompt — regression-free).
- The grace window and the on/off toggle are editable in the Settings dialog and persist across lock/unlock (round-trip through the vault settings record).
- `verify_password` accepts the correct password and rejects a wrong one with a typed error against a temp copy of the golden vault.
- A vault settings record written by an older (single-field) client loads with the two new fields defaulted, no error.
- Green: `desktop` `pnpm test` + `pnpm lint` + `pnpm svelte-check`; `cargo test --release --workspace` + `cargo clippy ... -D warnings` + `cargo fmt --all --check`.
- Guardrails: **empty** for `core/ | crypto-design | vault-format | *.udl | secretary-ffi-py | ios/ | android/`. **Non-empty (expected)** for `desktop/` incl. `desktop/src-tauri/*.rs`.

## Risks / open notes

- **Argon2id cost on verify.** `open_vault_with_password` is m=256 MiB, t=3 (~1–2s + a memory spike) per re-auth. The grace window (default 2 min, user-tunable) amortizes it; the verify runs in an async Tauri command off the UI thread. A second transient open against the same files while a session is live is read-only and drops immediately — no exclusive-lock concern (verified in the plan).
- **Settings multi-field migration.** The single→multi-field parser change is the largest mechanical piece; backward-compat-default + round-trip tests pin it. Whether an *unknown extra* field becomes a warning (forward-compat) vs an error is decided in the plan; current behavior is an error.
- **Async ripple.** Each gated handler gains an `await authorizeWrite(...)` before its existing `await ipc.<write>(...)`; call sites are already async, so the cost is low, but every existing test driving those handlers must account for the (pass-through) guard.
- **Auto-lock interaction.** Auto-lock and re-auth are independent: auto-lock locks the whole vault on idle; re-auth gates active writes. Locking resets the guard's `lastAuthAtMs`.

## Follow-up filed this slice

- **OS biometric write re-auth on desktop** — macOS Touch ID (likely via the existing SwiftUI/iOS work as a minor expansion), Linux polkit/fprintd, Windows Hello. Out of scope here; a GitHub issue is filed and linked from the handoff.
