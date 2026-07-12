# Mobile per-vault settings — retention window + re-auth grace — design

**Date:** 2026-07-12
**Follows:** the last deferred mobile-Trash item (per NEXT_SESSION #411 handoff "What's next" #1) and [[project_secretary_ios_settings_ffi_gap]].
**Scope:** cross-cutting — **new shared Rust settings module in the bridge**, FFI projection (uniffi + pyo3), **desktop migration to the shared module**, and a **native mobile Settings screen** (iOS + Android). No `core` / crypto / on-disk-format / `manifest_version` change; no new `FfiVaultError` variant; `#![forbid(unsafe_code)]` intact.

## Problem

App settings are stored as a **record inside the vault** — a block named `__secretary_app_settings__` (deterministic UUID), one record of type `secretary.settings.v1`, with text fields `auto_lock_timeout_ms`, `require_password_before_edits`, `reauth_grace_window_ms`, `retention_window_ms`. But the **schema + parse / serialize / validate logic lives only in the desktop Tauri layer** (`desktop/src-tauri/src/settings/{parse,io}.rs`). There is **no settings surface anywhere in the FFI bridge / pyo3 / uniffi**.

Consequently the mobile Trash browsers (iOS #412, Android #414) hard-code the frozen 90-day default: both read `port.defaultRetentionWindowMs()` (the uniffi-projected `DEFAULT_RETENTION_WINDOW_MS` constant) at three sites each — the `retentionWindowMs` accessor, `previewRetention()`, and `runRetention()` — because there is no way to read a *per-vault* retention setting, and neither mobile app has a Settings screen at all. The re-auth grace window is likewise hard-coded on mobile: `GraceWindowReauthGate` uses `ReauthWindow.v1Default` (2 min), never a per-vault value.

## Goal (one sentence)

Lift the settings schema into a **single shared Rust module** in `secretary-ffi-bridge`, project typed `read_settings` / `write_settings` onto uniffi + pyo3, migrate desktop to consume it, and build a native mobile Settings screen exposing **two** per-vault controls — retention window and re-auth grace — with the Trash retention path and the live re-auth gate reading the persisted values.

## Decisions (from brainstorm)

1. **Architecture — bridge owns settings; desktop migrates.** One Rust implementation of the settings schema/parse/validate for all four surfaces (desktop, iOS, Android, python). Desktop's `settings/*` becomes a thin adapter over the bridge.
2. **Mobile UI scope — retention + re-auth grace.** The Settings screen exposes exactly two controls. `auto_lock_timeout_ms` and `require_password_before_edits` get **no mobile UI** but are round-tripped on every write so they are never dropped.
3. **Re-auth grace timing — live retarget.** On a successful settings save, the live re-auth gate is retargeted to the new grace window (the very next write uses it). Android reuses its existing `RetargetableReauthGate`; iOS gains an equivalent.
4. **pyo3 projected** alongside uniffi, for parity + a python round-trip test (no production python consumer today).

## Non-goals

- No change to the **on-disk settings record format** (field names, record_type, block name, deterministic UUID derivation all preserved — a mobile-written record must read back identically on desktop and vice-versa).
- No mobile UI for `auto_lock_timeout_ms` / `require_password_before_edits` (round-tripped, not surfaced).
- No new `FfiVaultError` variant: `read_settings` / `write_settings` propagate the **existing** errors of `read_block` / `save_block`; bounds validation surfaces the **existing** `VaultError::InvalidArgument` at the binding wrapper. So the Swift/Kotlin `ConformanceErrors.*` harnesses and the core-KAT match are untouched.
- No new Tauri command semantics on desktop (the existing settings IPC commands keep their signatures; only their Rust implementation delegates to the bridge).

## Architecture

### Component A — shared settings module `ffi/secretary-ffi-bridge/src/settings/`

A directory module (one concept per file, mirroring the bridge's existing `retention/`, `repair/` layout; keep each file well under 500 lines per [[feedback_split_files_proactively]]):

- **`schema.rs`** — the `Settings` value type (all **4** fields) + all constants:
  `SETTINGS_BLOCK_NAME`, `SETTINGS_RECORD_TYPE`, the four `SETTINGS_FIELD_*` names,
  `RETENTION_WINDOW_{DEFAULT,MIN,MAX}_MS`, `REAUTH_WINDOW_{DEFAULT,MIN,MAX}_MS`,
  `AUTO_LOCK_{DEFAULT,MIN,MAX}_MS`, `REQUIRE_PASSWORD_DEFAULT`, `MS_PER_DAY`, and
  `deterministic_uuid_16` (moved from `desktop/src-tauri/src/constants.rs`, SHA-256-based). `DEFAULT_RETENTION_WINDOW_MS` is already re-exported by the bridge from `secretary-core`; `RETENTION_WINDOW_DEFAULT_MS` aliases it so the mobile default can never diverge from core's frozen value.
- **`parse.rs`** — pure, `&str`-in / owned-out (no I/O):
  `parse_settings_fields(record_type, &[(name, value)]) -> Result<(Settings, Vec<SettingsWarning>), SettingsParseError>`,
  `serialize_settings(&Settings) -> Vec<(record_type, name, value)>`,
  `validate_save_settings(&Settings) -> Result<(), SettingsBoundsError>`.
  A **bridge-native** `SettingsWarning` enum (`Clamped { original_ms, clamped_ms }`, `Corrupt { detail }`) replaces desktop's `AppWarning`; `SettingsParseError` (`UnknownVersion { version }`, `Corrupt { detail }`) replaces the parse-side `AppError`. Load-path clamps with a warning; save-path rejects out-of-range (no silent clamp). The existing desktop parse unit tests move here verbatim (retargeted to the new warning/error types).
- **`orchestration.rs`** — two stateful orchestrators over the existing `read_block` / `save_block`:
  - `read_settings(identity, manifest) -> Result<(Settings, Vec<SettingsWarning>), FfiVaultError>` — find the settings block by name → `read_block` → collect text fields → `parse_settings_fields`. Returns `(Settings::default(), vec![])` when **no settings block exists** (the happy path for a vault whose owner never opened Settings). Lenient on record shape (a non-text or payload-missing field is a warning, not a hard error) — a broken record must never block vault access.
  - `write_settings(identity, manifest, &Settings, device_uuid: [u8;16], now_ms: u64) -> Result<(), FfiVaultError>` — `validate_save_settings` (defense-in-depth for direct Rust callers) → find-or-create block by name (`deterministic_uuid_16(SETTINGS_BLOCK_NAME)` fallback) → `record_uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE)` → serialize **all 4 fields** into `FieldInput::Text(SecretString)` → `save_block(…, device_uuid, now_ms)`. `now_ms` is a caller parameter (kept out of the pure/bridge layer; mobile passes system time, desktop passes its `now_ms()`), matching `save_block`.

**Field-preservation invariant (load-bearing):** `write_settings` always serializes the full `Settings`. A caller that read → mutated only `retention_window_ms` → wrote back therefore preserves `auto_lock_timeout_ms`, `require_password_before_edits`, and `reauth_grace_window_ms` by construction. This is the correctness property that makes a retention-only (or retention+grace-only) mobile UI safe against clobbering desktop-only fields. Pinned by a dedicated orchestration test.

### Component B — FFI projection (uniffi + pyo3)

- **uniffi** (`ffi/secretary-ffi-uniffi/`): add `read_settings` / `write_settings` to the `.udl` + a `namespace/settings.rs` wrapper; project the `Settings` dictionary and `SettingsWarning` enum as uniffi types (`wrappers/settings.rs`). The wrapper validates `device_uuid` length (→ `VaultError::InvalidArgument`, existing) and calls `validate_save_settings` before `write_settings` (→ `InvalidArgument` on out-of-range), per the "input validation at the binding wrapper" convention ([[project_secretary_input_validation_at_binding_wrapper]]). Exposes the bound constants (defaults/min/max) so the mobile UIs validate against one source.
- **pyo3** (`ffi/secretary-ffi-py/`): mirror `read_settings` / `write_settings` + `Settings` for parity and a python round-trip test. Follow the `from_py_object`/`skip_from_py_object` discipline ([[project_secretary_pyo3_028_fromtopyobject_deprecation]]).

Per [[project_secretary_conformance_scripts_dont_compile_kit]] and [[project_secretary_ffivaulterror_workspace_match]]: no new `FfiVaultError` variant means the conformance-error harnesses need no edit, but the `.udl` shape change still requires building `:kit` + `:app` (and running the Swift/Kotlin conformance runners is *not* needed since no error variant changed — but re-run them if any shared error enum is touched).

### Component C — desktop migration

`desktop/src-tauri/src/settings/`:
- `parse.rs`: `Settings`, `parse_settings_fields`, `serialize_settings`, `validate_save_settings`, `deterministic_uuid_16`, and the bound constants become **re-exports** of the bridge module. Desktop keeps `AppError` / `AppWarning` and adds a small mapping (`SettingsWarning → AppWarning::{SettingsClamped,SettingsCorrupt}`, `SettingsParseError → AppError::{SettingsUnknownVersion,SettingsCorrupt}`, `SettingsBoundsError → AppError::SettingsOutOfRange`).
- `io.rs`: `load_from_vault` / `save_to_vault` delegate to the bridge `read_settings` / `write_settings` (mapping errors/warnings). The per-vault device-UUID persistence stays desktop-side and feeds `device_uuid` into `write_settings`.
- `constants.rs`: the settings/retention/reauth bound constants re-export from the bridge (single definition; `deterministic_uuid_16` moves out).

Desktop's existing settings suite (`SettingsDialog.test.ts`, `ipc_integration.rs`, and the parse tests that stay as integration coverage) is the safety net proving the migration preserved behavior. This is the one place the slice touches shipped code.

### Component D — mobile FFI adapters + view-models

- **FFI adapters** — iOS `SecretaryKit` (`UniffiVaultSession`), Android `:kit` (`UniffiVaultOpenPort`): add `readSettings()` / `writeSettings(...)` to a new `SettingsPort` (host-defined, FFI-free protocol/interface in `SecretaryVaultAccess` / `:vault-access`), implemented over the new uniffi fns. Android overrides go **in-class** on the session, not via extension ([[project_secretary_kotlin_interface_conformance_in_class]]).
- **View-models** (host-testable, FFI-free — iOS `SettingsViewModel` in `SecretaryVaultAccessUI`, Android `SettingsModel` in `:vault-access`):
  - Load `Settings` on open; hold editable retention-days + reauth-grace state; validate client-side against the projected bounds.
  - **Save routes through the existing re-auth gate** (`reauthedWrite` / `guardedWrite`) — a settings change is a vault write, so it obeys the same gate-integrity invariants as the Trash destructive ops (guard set before the gate await; refused re-auth → no write; failure → no reload; clear notice at write-start). Value types captured across the offload boundary stay `Sendable`, and the `save_block` work offloads off the main actor ([[project_secretary_ios_value_types_sendable_offload]]).
  - **On successful save, retarget the live gate** to the new `reauth_grace_window_ms`. Android reuses `RetargetableReauthGate`. **iOS gains a `RetargetableReauthGate` equivalent** in `SecretaryVaultAccessUI` (mirroring Android's swap-delegate semantics), so the composition root injects a retargetable gate that both the Settings save and all other writers share.
  - **Security ordering (load-bearing): retarget happens strictly *after* a successful save.** The save is therefore always evaluated against the **current (pre-save)** grace window. This gives mobile — for free, because every mobile write is gated — the property desktop enforces explicitly via its `reducesProtection` / `weakensWriteGate` branch (`newSettings.reauthGraceWindowMs > currentWindowMs`, evaluated against pre-save policy): within the live grace window the save resolves silently, but a user at an unlocked-but-unattended session **cannot widen their own grace window to self-authorize the widening** — outside the current grace window the widening still demands a biometric proof. If the retarget ran before/during the save, a widening could self-authorize; the ordering is the guard. Unlike desktop, mobile needs **no** special `reducesProtection` branch, because the settings save is unconditionally gated (desktop's gate is opt-in via `requirePasswordBeforeEdits`, hence its explicit force-gate).

### Component E — mobile Settings screen + Trash integration

- **Settings screen** (app target — iOS `SettingsScreen.swift`, Android `SettingsScreen.kt`):
  - **Retention window** — a days input/stepper, default 90, clamp **1–3650** days (`RETENTION_WINDOW_{MIN,MAX}_MS / MS_PER_DAY`), mirroring desktop `SettingsDialog`. ms↔days conversion is a pure helper (whole days).
  - **Re-auth grace** — a **minutes** input (matching desktop `SettingsDialog`, which stores `reauthGraceWindowMs = inputWindowMinutes * MS_PER_MINUTE`), bounds `REAUTH_WINDOW_{MIN,MAX}_MS` = 0 … 3,600,000 ms (0 … 60 min; default 2 min). ms↔minutes conversion is a pure helper (whole minutes). *(Retention is in days, grace is in minutes — mirroring desktop exactly.)*
  - A Save action behind the re-auth gate; an inline status/error banner reusing the Trash banner idiom, with a stable `testTag("settings-…")` / `accessibilityIdentifier` for a future render test.
  - **Entry point:** a gear/settings action from the main vault (browse) screen — exact placement (top-bar icon vs overflow) chosen per platform idiom during implementation.
- **Trash integration:** replace the three `defaultRetentionWindowMs()` reads per platform with the effective per-vault value — `readSettings().retentionWindowMs`, which already falls back to `Settings::default()` (90 d) when no settings block exists. The `SettingsPort` read is the shared source for both the Settings screen and the Trash retention path.

## Testing (TDD — test first)

- **Bridge:** the lifted parse/serialize/validate unit tests (moved from desktop, retargeted to the new warning/error types) + new orchestration tests:
  - `read_settings` on absent block → `(default, [])`; on a present valid block → round-trips; on a corrupt/shape-wrong record → lenient warnings, not an error.
  - `write_settings` create-then-update (same block UUID replaces the manifest entry).
  - **field-preservation test**: seed a settings record with non-default values for all 4 fields; `read_settings` → mutate only `retention_window_ms` → `write_settings` → `read_settings` asserts the other 3 fields are unchanged.
- **FFI:** pyo3 python round-trip test (write via pyo3 → read via pyo3 → values match; field-preservation across a partial update). uniffi surface exercised transitively by the mobile host tests.
- **Desktop:** existing settings suite stays green (the migration's proof); no new desktop tests required beyond adjusting for the re-exported types.
- **Mobile** (host-tested view-models — iOS `swift test` on `SecretaryVaultAccess`, Android `:vault-access:test`), via a `FakeSettingsPort`:
  - load populates the two controls from the read;
  - client-side clamp/validation of out-of-range input;
  - save-success publishes the notice **and retargets the gate** (assert the injected fake gate received the new window);
  - **retarget-after-save ordering**: the write is evaluated against the *pre-save* gate window (assert the fake gate's window at the moment `writeSettings` is invoked is the OLD value, and only the post-success retarget sets the new one) — a widening cannot self-authorize;
  - gate-refusal → no write, no retarget, no notice;
  - **field-preservation** at the VM level (a save touching only retention/grace writes back all 4 fields — assert via the fake port's captured `Settings`);
  - Trash view-model reads the per-vault window from the settings port (not the frozen default) for preview + commit.
  - iOS retargetable-gate unit tests (swap-delegate semantics, seeded-instant carry-over, mirroring the existing `GraceWindowReauthGate` tests).
- **Render** (Compose/SwiftUI screen) stays host-untested (same gap as [#417](https://github.com/hherb/secretary/issues/417)); `testTag`/`accessibilityIdentifier` hooks added for a future instrumented/Compose assertion.

## Acceptance criteria

1. A single shared `settings` module in `secretary-ffi-bridge` owns the `Settings` schema + parse/serialize/validate + `deterministic_uuid_16`; desktop consumes it (no second Rust definition of the schema/constants).
2. `read_settings` / `write_settings` projected on uniffi **and** pyo3; `write_settings` round-trips all 4 fields (field-preservation test green on the bridge and on both mobile VMs).
3. The mobile Settings screen (iOS + Android) shows a retention-days control (default 90, clamp 1–3650) and a re-auth-grace control (bounds mirrored from the shared constants); Save is gated by re-auth.
4. A changed retention window is read by the mobile Trash retention preview + commit (no remaining `defaultRetentionWindowMs()` read on the retention path); a changed grace window **retargets the live gate** so the next write uses it.
5. Desktop settings behavior is unchanged: its existing suite (`pnpm test` + `svelte-check`; `ipc_integration.rs`) stays green after the migration.
6. All gates green: `cargo test --release --workspace`, `cargo clippy --release --workspace --tests -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` (public-item doc links — [[project_secretary_rustdoc_gate_public_items_only]]), lean-binding guard, desktop `pnpm test`/`svelte-check`, iOS `swift test`, Android `:vault-access:test` + `:kit`/`:app` build + `:kit:lintDebug`.
7. No `core` / crypto / on-disk-format / `manifest_version` change; no new `FfiVaultError` variant; `#![forbid(unsafe_code)]` intact.

## Sequencing (proposed PRs — each independently reviewable, user merges each)

1. **Bridge settings module + FFI projection (uniffi + pyo3) + desktop migration.** The lift is only trustworthy when its reference consumer (desktop) migrates and its suite passes in the same PR. Ships no mobile change.
2. **iOS** — `SettingsPort` adapter, `SettingsViewModel`, retargetable gate, `SettingsScreen.swift`, Trash retention integration.
3. **Android** — `SettingsPort` adapter, `SettingsModel`, `SettingsScreen.kt`, Trash retention integration (reuses the existing `RetargetableReauthGate`).

## Risks / open items

- **Desktop migration churns a shipped, well-tested path** (accepted trade-off for single-source-of-truth). Mitigated by the existing desktop suite as the behavioral oracle; migrate in one PR so a regression is caught immediately.
- **iOS retargetable-gate is genuinely new code** (the live-retarget choice) — the highest-novelty piece. Unit-tested against the existing `GraceWindowReauthGate` semantics before wiring. The **retarget-after-save ordering** is the security guard (see Component D) — a review must confirm no path retargets before the gated save resolves.
- **Mobile screen render remains host-untested** (existing gap, #417); mitigated by `testTag`/`accessibilityIdentifier` hooks + host-tested VM logic.
- **Two concurrent devices editing settings** merge via the existing CRDT block layer (settings is an ordinary vault block); no special handling — but note that any client re-serializing only the 4 known fields drops a *future* v2 field. That is a pre-existing desktop property, not introduced here; a v2 field would be an intentional format-version bump.
- **Stale `.claude/worktrees/*` trees** duplicate these paths — all edits target the live `.worktrees/mobile-vault-settings` paths ([[feedback_edit_tool_targets_main_not_worktree]]).
