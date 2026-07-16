# Desktop macOS Touch ID Write Re-Auth (#277) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a desktop user re-authorize a write with macOS Touch ID instead of retyping the vault password, with password re-entry as the universal fallback and a this-device kill switch to force password-only.

**Architecture:** A new first-party crate `secretary-desktop-presence` isolates the only `unsafe` (the `objc2` LocalAuthentication call) behind a pure, host-tested `classify()`. A vault-independent Tauri command `authenticate_presence` calls it through a `PresenceProvider` seam. A desktop-local per-vault preference (stored under `<data_dir>/secretary-desktop/`) gates whether biometry is attempted at all. The frontend `authorizeWrite` chokepoint tries Touch ID first and falls back to the unchanged password dialog.

**Tech Stack:** Rust (Tauri 2, `objc2-local-authentication`), TypeScript/Svelte 5 (vitest), macOS `LocalAuthentication`.

## Global Constraints

- **Biometric is a presence proof only** — never a cryptographic binding. It must not touch vault key material; password re-entry remains the only KEK-knowledge proof and the universal fallback.
- **`unsafe` lives ONLY in `secretary-desktop-presence`.** Every other crate keeps `[workspace.lints.rust] unsafe_code = "forbid"` (via `lints.workspace = true`). The new crate omits `lints.workspace = true`.
- **Fail-safe direction:** any unmapped/error biometric outcome routes to the password dialog — never silently through the gate.
- **Pure/IO split** ([[feedback_pure_functions]]): pure value logic in free functions with no I/O; I/O pushed to thin edges. Mirror the existing `settings/parse.rs` vs `settings/io.rs` structure.
- **No magic numbers:** LAError codes, the pref filename/subdir, and the default-enabled value are named constants.
- **Security-path dependency discipline:** exact-pin (`=x.y.z`) `objc2`, `objc2-local-authentication`, `objc2-foundation`, and `block2`; comment the pin rationale in `Cargo.toml` as `tempfile` does.
- **Coverage gate:** every command added to `main.rs`'s `generate_handler!` MUST be classified in `writeCommands.ts` or `pnpm test` fails ([[project_secretary_desktop_generate_handler_writecommands_coverage]]).
- **Toolchain:** stable Rust pinned `1.97.0`; `cargo test --release --workspace` and `cargo clippy --release --workspace --tests -- -D warnings` must stay green; `cd desktop && pnpm test` + `svelte-check` green. This is a **pnpm** project ([[project_secretary_desktop_uses_pnpm]]); `svelte-check` is the type gate ([[project_secretary_desktop_typecheck_is_svelte_check]]).
- **Worktree:** all work in `.worktrees/desktop-biometric-reauth-277` on branch `feature/desktop-biometric-reauth-277`. Spell out the worktree path in every Edit/Write/Read ([[feedback_edit_tool_targets_main_not_worktree]]).

---

## File Structure

**New:**
- `desktop/secretary-desktop-presence/Cargo.toml` — workspace member; objc2 deps `cfg`-gated to macOS; NOT `lints.workspace = true`.
- `desktop/secretary-desktop-presence/src/lib.rs` — public API, `PresenceOutcome`/`PresenceAvailability`, pure `classify()`, LAError constants, platform dispatch.
- `desktop/secretary-desktop-presence/src/macos.rs` — `#[cfg(target_os = "macos")]` objc2 `evaluate()`/`availability()` (the ONLY unsafe).
- `desktop/secretary-desktop-presence/src/unsupported.rs` — `#[cfg(not(target_os = "macos"))]` stub.
- `desktop/src-tauri/src/commands/presence.rs` — `authenticate_presence` command + `PresenceProvider` seam.
- `desktop/src-tauri/src/presence_pref.rs` — desktop-local pref: pure parse/serialize + atomic IO + `read_presence_pref`/`write_presence_pref` commands.
- `desktop/src/lib/presence.ts` — frontend IPC wrappers + types.

**Modified:**
- root `Cargo.toml` — add the new crate to `members`.
- `desktop/src-tauri/Cargo.toml` — depend on `secretary-desktop-presence`.
- `desktop/src-tauri/src/lib.rs` — `pub mod presence_pref;` and re-export.
- `desktop/src-tauri/src/commands/mod.rs` — `pub mod presence;`.
- `desktop/src-tauri/src/session.rs` — add `vault_uuid()` accessor.
- `desktop/src-tauri/src/constants.rs` — pref subdir/filename + default constants.
- `desktop/src-tauri/src/main.rs` — register the three new commands in `generate_handler!`.
- `desktop/src/lib/writeCommands.ts` — classify the three commands.
- `desktop/src/lib/writeGuard.ts` — biometric pre-step + two new seam members.
- `desktop/src/lib/stores.ts` — presence-pref store + reset.
- `desktop/src/lib/constants.ts` — `PresenceAvailability` type + default.
- `desktop/src/routes/Unlock.svelte` — load the pref at unlock.
- `desktop/src/App.svelte` — reset the pref store on lock.
- `desktop/src/components/SettingsDialog.svelte` — the toggle + save-flow integration.
- `ROADMAP.md` — note #277 macOS shipped; Linux/Windows + on-hardware proof deferred.

---

## Task 1: `secretary-desktop-presence` crate — types + pure `classify()` + stubs

Delivers the crate compiling green on **both** Linux and macOS with a fully host-tested `classify()`. The macOS objc2 wiring is a compiling stub here (real impl in Task 2), so this task carries no untestable code.

**Files:**
- Create: `desktop/secretary-desktop-presence/Cargo.toml`
- Create: `desktop/secretary-desktop-presence/src/lib.rs`
- Create: `desktop/secretary-desktop-presence/src/macos.rs`
- Create: `desktop/secretary-desktop-presence/src/unsupported.rs`
- Modify: root `Cargo.toml` (add to `members`)

**Interfaces:**
- Produces: `PresenceOutcome { Authenticated, Fallback, Unavailable, Cancelled }`; `PresenceAvailability { Available, NotEnrolled, NotAvailable, Unsupported }`; `pub fn availability() -> PresenceAvailability`; `pub fn evaluate(reason: &str) -> PresenceOutcome`; `pub(crate) fn classify(result: Result<(), i64>) -> PresenceOutcome`.

- [ ] **Step 1: Add the crate to the workspace and write `Cargo.toml`**

Root `Cargo.toml` — add to `members` (keep alphabetical-ish grouping with the other desktop entry):

```toml
    "desktop/src-tauri",
    "desktop/secretary-desktop-presence",
```

Create `desktop/secretary-desktop-presence/Cargo.toml`:

```toml
[package]
name = "secretary-desktop-presence"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

# NOTE: this crate deliberately does NOT set `[lints] workspace = true`.
# It is the single isolated FFI boundary for macOS LocalAuthentication and
# therefore must permit `unsafe` (objc2 macros expand to unsafe blocks),
# which the workspace-wide `unsafe_code = "forbid"` would otherwise reject.
# Every OTHER crate keeps the forbid. See CLAUDE.md: "If a primitive truly
# needs FFI, isolate it in its own crate behind a reviewed boundary."

[lib]
path = "src/lib.rs"

[dependencies]
# macOS-only: the LocalAuthentication bindings. Exact-pinned per the
# security-path dependency discipline (CLAUDE.md) — a bump is a deliberate
# edit + review, never a silent `cargo update` inside a caret range.
[target.'cfg(target_os = "macos")'.dependencies]
objc2 = "=0.6.1"
objc2-foundation = "=0.3.1"
objc2-local-authentication = "=0.3.1"
block2 = "=0.6.1"
```

> Confirm the exact published versions at implementation time (`cargo add --dry-run objc2-local-authentication`); the pins above are the target major/minor. Bump all four together so the objc2 umbrella stays version-consistent.

- [ ] **Step 2: Write the failing test for `classify()`**

Create `desktop/secretary-desktop-presence/src/lib.rs` with the types and a `classify` that is unimplemented, plus tests:

```rust
//! Desktop presence proof (macOS Touch ID) — the ONLY crate permitting `unsafe`.
//!
//! Presence proof, NOT a cryptographic binding: `evaluate` returns whether the
//! device owner authenticated with biometry; it never touches vault key
//! material. Password re-entry remains the KEK-knowledge fallback.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod unsupported;

/// Result of one biometric evaluation. Control-flow, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceOutcome {
    /// Biometry succeeded — the write may proceed.
    Authenticated,
    /// User asked for the password path (tapped the sheet's "Use Password").
    Fallback,
    /// Biometry cannot be used right now (unavailable / not enrolled / locked
    /// out / any unmapped error) — the caller must fall back to the password.
    Unavailable,
    /// User cancelled — the write should be aborted.
    Cancelled,
}

/// Whether biometric evaluation can proceed on this machine right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceAvailability {
    /// Hardware present and a biometric is enrolled.
    Available,
    /// Hardware present but no biometric enrolled.
    NotEnrolled,
    /// No usable biometric hardware (or biometry disabled).
    NotAvailable,
    /// This platform has no supported provider (non-macOS in this release).
    Unsupported,
}

// LAError codes we map explicitly (Apple `LAError.Code`, stable ABI integers).
// Named to avoid magic numbers; values from the LocalAuthentication headers.
const LA_ERROR_USER_CANCEL: i64 = -2;
const LA_ERROR_USER_FALLBACK: i64 = -3;
const LA_ERROR_SYSTEM_CANCEL: i64 = -4;
const LA_ERROR_BIOMETRY_NOT_AVAILABLE: i64 = -6;
const LA_ERROR_BIOMETRY_NOT_ENROLLED: i64 = -7;
const LA_ERROR_BIOMETRY_LOCKOUT: i64 = -8;

/// Map the raw `evaluatePolicy` result to an outcome. PURE + host-tested —
/// `macos.rs` is a thin shell around this, so the classification logic carries
/// no `unsafe`. `Ok(())` = biometry succeeded; `Err(code)` = the `LAError`
/// code from the NSError. Any unmapped code is `Unavailable` (fail-safe: send
/// the user to the password path, never silently through the gate).
pub(crate) fn classify(result: Result<(), i64>) -> PresenceOutcome {
    match result {
        Ok(()) => PresenceOutcome::Authenticated,
        Err(LA_ERROR_USER_CANCEL) | Err(LA_ERROR_SYSTEM_CANCEL) => PresenceOutcome::Cancelled,
        Err(LA_ERROR_USER_FALLBACK) => PresenceOutcome::Fallback,
        Err(LA_ERROR_BIOMETRY_NOT_AVAILABLE)
        | Err(LA_ERROR_BIOMETRY_NOT_ENROLLED)
        | Err(LA_ERROR_BIOMETRY_LOCKOUT) => PresenceOutcome::Unavailable,
        Err(_) => PresenceOutcome::Unavailable,
    }
}

/// Presence availability on this machine. Platform-dispatched.
pub fn availability() -> PresenceAvailability {
    #[cfg(target_os = "macos")]
    {
        macos::availability()
    }
    #[cfg(not(target_os = "macos"))]
    {
        unsupported::availability()
    }
}

/// Present the biometric sheet and block until the outcome is known.
/// Platform-dispatched. Non-macOS returns `Unavailable`.
pub fn evaluate(reason: &str) -> PresenceOutcome {
    #[cfg(target_os = "macos")]
    {
        macos::evaluate(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        unsupported::evaluate(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_maps_to_authenticated() {
        assert_eq!(classify(Ok(())), PresenceOutcome::Authenticated);
    }

    #[test]
    fn user_cancel_maps_to_cancelled() {
        assert_eq!(classify(Err(LA_ERROR_USER_CANCEL)), PresenceOutcome::Cancelled);
    }

    #[test]
    fn system_cancel_maps_to_cancelled() {
        assert_eq!(classify(Err(LA_ERROR_SYSTEM_CANCEL)), PresenceOutcome::Cancelled);
    }

    #[test]
    fn user_fallback_maps_to_fallback() {
        assert_eq!(classify(Err(LA_ERROR_USER_FALLBACK)), PresenceOutcome::Fallback);
    }

    #[test]
    fn not_available_enrolled_lockout_map_to_unavailable() {
        for code in [
            LA_ERROR_BIOMETRY_NOT_AVAILABLE,
            LA_ERROR_BIOMETRY_NOT_ENROLLED,
            LA_ERROR_BIOMETRY_LOCKOUT,
        ] {
            assert_eq!(classify(Err(code)), PresenceOutcome::Unavailable);
        }
    }

    #[test]
    fn unknown_code_fails_safe_to_unavailable() {
        assert_eq!(classify(Err(-999)), PresenceOutcome::Unavailable);
        assert_eq!(classify(Err(0)), PresenceOutcome::Unavailable);
    }
}
```

- [ ] **Step 3: Write the non-macOS stub**

Create `desktop/secretary-desktop-presence/src/unsupported.rs`:

```rust
//! Non-macOS providers are not implemented in this release (#277 is macOS-only).
//! Returning `Unsupported`/`Unavailable` keeps the crate compiling on Linux CI
//! and makes the frontend fall back to the password path everywhere else.

use crate::{PresenceAvailability, PresenceOutcome};

pub(crate) fn availability() -> PresenceAvailability {
    PresenceAvailability::Unsupported
}

pub(crate) fn evaluate(_reason: &str) -> PresenceOutcome {
    PresenceOutcome::Unavailable
}
```

- [ ] **Step 4: Write the macOS module as a compiling stub**

Create `desktop/secretary-desktop-presence/src/macos.rs` (real objc2 impl lands in Task 2 — a stub here keeps Task 1 green on macOS without shipping untested unsafe):

```rust
//! macOS Touch ID via LocalAuthentication. STUB (Task 1) — the real objc2
//! `evaluate`/`availability` land in Task 2. The pure `crate::classify` this
//! shell will delegate to is already fully tested.

use crate::{PresenceAvailability, PresenceOutcome};

pub(crate) fn availability() -> PresenceAvailability {
    // Task 2 replaces this with LAContext.canEvaluatePolicy.
    PresenceAvailability::NotAvailable
}

pub(crate) fn evaluate(_reason: &str) -> PresenceOutcome {
    // Task 2 replaces this with LAContext.evaluatePolicy → crate::classify.
    PresenceOutcome::Unavailable
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --release -p secretary-desktop-presence`
Expected: PASS (7 classify tests).

- [ ] **Step 6: Verify clippy + workspace build**

Run: `cargo clippy --release -p secretary-desktop-presence --tests -- -D warnings`
Expected: clean.
Run: `cargo build --release --workspace`
Expected: builds (crate is now a member).

- [ ] **Step 7: Commit**

```bash
git add desktop/secretary-desktop-presence Cargo.toml
git commit -m "feat(desktop): secretary-desktop-presence crate — types + pure classify() (#277)"
```

---

## Task 2: macOS objc2 `evaluate()` + `availability()`

Replaces the Task 1 stub with the real LocalAuthentication call. This is the isolated `unsafe` boundary. Its logic is the already-tested `classify()`; runtime correctness is confirmed by the deferred on-hardware proof (a sheet cannot be host-tested).

**Files:**
- Modify: `desktop/secretary-desktop-presence/src/macos.rs`

**Interfaces:**
- Consumes: `crate::classify`, `PresenceOutcome`, `PresenceAvailability`.
- Produces: unchanged public signatures from Task 1.

- [ ] **Step 1: Implement the objc2 macOS provider**

Replace `desktop/secretary-desktop-presence/src/macos.rs` with:

```rust
//! macOS Touch ID via LocalAuthentication. The ONLY `unsafe` in the codebase.
//!
//! Policy is `DeviceOwnerAuthenticationWithBiometrics` (Touch ID only — never
//! the account passcode, which would muddy the "Use Password" fallback story).
//! `evaluatePolicy:localizedReason:reply:` is asynchronous with a completion
//! block; we bridge it to a synchronous return over an mpsc channel so the
//! public `evaluate()` blocks until the outcome is known. The caller
//! (`authenticate_presence`) runs this off the async runtime via
//! `spawn_blocking`, so blocking here never stalls Tauri.

use std::sync::mpsc;

use block2::RcBlock;
use objc2_foundation::NSString;
use objc2_local_authentication::{LAContext, LAPolicy};

use crate::{classify, PresenceAvailability, PresenceOutcome};

/// The fallback button title shown on the sheet. Tapping it yields
/// `LAError.userFallback` → `PresenceOutcome::Fallback` → password dialog.
const FALLBACK_TITLE: &str = "Use Password";

pub(crate) fn availability() -> PresenceAvailability {
    let context = unsafe { LAContext::new() };
    let mut error = None;
    let can = unsafe {
        context.canEvaluatePolicy_error(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            Some(&mut error),
        )
    };
    if can {
        return PresenceAvailability::Available;
    }
    // Distinguish "no biometric enrolled" from "no hardware / disabled".
    match error.map(|e| e.code()) {
        Some(code) if code as i64 == -7 => PresenceAvailability::NotEnrolled, // biometryNotEnrolled
        _ => PresenceAvailability::NotAvailable,
    }
}

pub(crate) fn evaluate(reason: &str) -> PresenceOutcome {
    let context = unsafe { LAContext::new() };
    unsafe {
        context.setLocalizedFallbackTitle(Some(&NSString::from_str(FALLBACK_TITLE)));
    }

    let (tx, rx) = mpsc::channel::<Result<(), i64>>();
    let reason_ns = NSString::from_str(reason);

    // Completion block: (success: Bool, error: *NSError). Convert to
    // Result<(), i64> and send. RcBlock keeps the closure alive across the
    // async call; the send is the synchronization point.
    let reply = RcBlock::new(move |success: objc2::runtime::Bool, error: *mut objc2_foundation::NSError| {
        let result = if success.as_bool() {
            Ok(())
        } else if let Some(err) = unsafe { error.as_ref() } {
            Err(err.code() as i64)
        } else {
            Err(0) // no error object on failure → fail-safe Unavailable
        };
        let _ = tx.send(result);
    });

    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            &reason_ns,
            &reply,
        );
    }

    // Block until the completion block fires. A disconnected channel (the
    // framework dropped the block without calling it) fails safe.
    match rx.recv() {
        Ok(result) => classify(result),
        Err(_) => PresenceOutcome::Unavailable,
    }
}
```

> The exact objc2 method names / `Bool` path / `NSError.code()` return type must be confirmed against the pinned crate versions at implementation time (`cargo doc -p objc2-local-authentication --open`). The **contract** — success → `Ok(())`, failure → `Err(LAError code)`, both funnelled through the tested `classify()` — is fixed; only the binding surface may need a one-line adjustment. If `evaluatePolicy…reply` requires the block on a specific queue, keep the mpsc bridge and confirm no main-thread requirement (LAContext evaluation is thread-agnostic; only presentation is framework-managed).

- [ ] **Step 2: Verify it compiles on macOS**

Run: `cargo build --release -p secretary-desktop-presence`
Expected: builds on macOS (objc2 path compiles). The `classify` tests from Task 1 still pass:
Run: `cargo test --release -p secretary-desktop-presence`
Expected: PASS.

- [ ] **Step 3: Verify clippy**

Run: `cargo clippy --release -p secretary-desktop-presence --tests -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add desktop/secretary-desktop-presence/src/macos.rs
git commit -m "feat(desktop): real objc2 LocalAuthentication evaluate/availability (#277)"
```

---

## Task 3: Backend `authenticate_presence` command + `PresenceProvider` seam

**Files:**
- Create: `desktop/src-tauri/src/commands/presence.rs`
- Modify: `desktop/src-tauri/src/commands/mod.rs` (add `pub mod presence;`)
- Modify: `desktop/src-tauri/Cargo.toml` (depend on the new crate)
- Modify: `desktop/src-tauri/src/main.rs` (register `presence::authenticate_presence`)

**Interfaces:**
- Consumes: `secretary_desktop_presence::{PresenceOutcome, PresenceAvailability, evaluate, availability}`.
- Produces: `pub trait PresenceProvider`; `pub fn authenticate_presence_impl(p: &dyn PresenceProvider, reason: &str) -> Result<PresenceOutcomeDto, AppError>`; `#[tauri::command] authenticate_presence(reason: String) -> Result<PresenceOutcomeDto, AppError>`; serde DTOs `PresenceOutcomeDto`, `PresenceAvailabilityDto`.

- [ ] **Step 1: Add the crate dependency**

In `desktop/src-tauri/Cargo.toml`, under `[dependencies]`:

```toml
# The isolated macOS Touch ID presence provider (#277). Pure-safe API surface
# (PresenceOutcome/PresenceAvailability + evaluate/availability); the unsafe
# objc2 call is contained in that crate, never here.
secretary-desktop-presence = { path = "../secretary-desktop-presence" }
```

- [ ] **Step 2: Write the failing test**

Create `desktop/src-tauri/src/commands/presence.rs`:

```rust
//! `authenticate_presence` — macOS Touch ID write-reauth presence proof.
//!
//! Vault-independent (presence ≠ crypto): it takes no session handle and
//! touches no key material. The live objc2 evaluation is injected through a
//! `PresenceProvider` seam so the command core is host-testable with a fake.

use secretary_desktop_presence::{
    availability as real_availability, evaluate as real_evaluate, PresenceAvailability,
    PresenceOutcome,
};

use crate::errors::AppError;

/// Wire form of `PresenceOutcome`. `#[serde(tag = "kind")]` → `{ "kind": "authenticated" }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PresenceOutcomeDto {
    Authenticated,
    Fallback,
    Unavailable,
    Cancelled,
}

impl From<PresenceOutcome> for PresenceOutcomeDto {
    fn from(o: PresenceOutcome) -> Self {
        match o {
            PresenceOutcome::Authenticated => Self::Authenticated,
            PresenceOutcome::Fallback => Self::Fallback,
            PresenceOutcome::Unavailable => Self::Unavailable,
            PresenceOutcome::Cancelled => Self::Cancelled,
        }
    }
}

/// Wire form of `PresenceAvailability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PresenceAvailabilityDto {
    Available,
    NotEnrolled,
    NotAvailable,
    Unsupported,
}

impl From<PresenceAvailability> for PresenceAvailabilityDto {
    fn from(a: PresenceAvailability) -> Self {
        match a {
            PresenceAvailability::Available => Self::Available,
            PresenceAvailability::NotEnrolled => Self::NotEnrolled,
            PresenceAvailability::NotAvailable => Self::NotAvailable,
            PresenceAvailability::Unsupported => Self::Unsupported,
        }
    }
}

/// Injectable biometric provider. Production delegates to the presence crate;
/// tests inject a fake (the live sheet can't run in `cargo test`).
pub trait PresenceProvider {
    fn availability(&self) -> PresenceAvailability;
    fn evaluate(&self, reason: &str) -> PresenceOutcome;
}

/// Production provider — thin delegate to `secretary_desktop_presence`.
pub struct RealPresenceProvider;

impl PresenceProvider for RealPresenceProvider {
    fn availability(&self) -> PresenceAvailability {
        real_availability()
    }
    fn evaluate(&self, reason: &str) -> PresenceOutcome {
        real_evaluate(reason)
    }
}

/// Testable core. Never returns `AppError` for a normal outcome — cancel /
/// fallback / unavailable are control-flow returned as `Ok`. `AppError` is
/// reserved for genuine faults (none today; the seam is infallible, but the
/// signature keeps room for a future transport error).
pub fn authenticate_presence_impl(
    provider: &dyn PresenceProvider,
    reason: &str,
) -> Result<PresenceOutcomeDto, AppError> {
    Ok(provider.evaluate(reason).into())
}

#[tauri::command]
pub async fn authenticate_presence(reason: String) -> Result<PresenceOutcomeDto, AppError> {
    // Offload the (potentially UI-presenting, blocking) evaluation off the
    // async runtime — same discipline `verify_password` uses for Argon2id.
    tauri::async_runtime::spawn_blocking(move || {
        authenticate_presence_impl(&RealPresenceProvider, &reason)
    })
    .await
    .map_err(|e| AppError::Internal {
        detail: format!("presence eval join error: {e}"),
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProvider(PresenceOutcome);
    impl PresenceProvider for FakeProvider {
        fn availability(&self) -> PresenceAvailability {
            PresenceAvailability::Available
        }
        fn evaluate(&self, _reason: &str) -> PresenceOutcome {
            self.0
        }
    }

    #[test]
    fn each_outcome_passes_through() {
        let cases = [
            (PresenceOutcome::Authenticated, PresenceOutcomeDto::Authenticated),
            (PresenceOutcome::Fallback, PresenceOutcomeDto::Fallback),
            (PresenceOutcome::Unavailable, PresenceOutcomeDto::Unavailable),
            (PresenceOutcome::Cancelled, PresenceOutcomeDto::Cancelled),
        ];
        for (outcome, expected) in cases {
            let got = authenticate_presence_impl(&FakeProvider(outcome), "test").unwrap();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn outcome_dto_serializes_tagged() {
        let json = serde_json::to_string(&PresenceOutcomeDto::Authenticated).unwrap();
        assert_eq!(json, r#"{"kind":"authenticated"}"#);
    }
}
```

- [ ] **Step 3: Register the module + command**

In `desktop/src-tauri/src/commands/mod.rs` add: `pub mod presence;`

In `desktop/src-tauri/src/main.rs`, add `presence` to the `commands::{...}` import list and register in `generate_handler!` (next to `reauth::verify_password`):

```rust
            reauth::verify_password,
            presence::authenticate_presence,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --release -p secretary-desktop --lib commands::presence`
Expected: PASS (2 tests).

- [ ] **Step 5: Clippy + build**

Run: `cargo clippy --release -p secretary-desktop --tests -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add desktop/src-tauri/src/commands/presence.rs desktop/src-tauri/src/commands/mod.rs desktop/src-tauri/src/main.rs desktop/src-tauri/Cargo.toml
git commit -m "feat(desktop): authenticate_presence command behind PresenceProvider seam (#277)"
```

---

## Task 4: Desktop-local presence preference (Rust)

**Files:**
- Create: `desktop/src-tauri/src/presence_pref.rs`
- Modify: `desktop/src-tauri/src/lib.rs` (`pub mod presence_pref;`)
- Modify: `desktop/src-tauri/src/session.rs` (`vault_uuid()` accessor)
- Modify: `desktop/src-tauri/src/constants.rs` (pref subdir + default)
- Modify: `desktop/src-tauri/src/commands/presence.rs` (`read_presence_pref`/`write_presence_pref`)
- Modify: `desktop/src-tauri/src/main.rs` (register the two commands)

**Interfaces:**
- Consumes: `session::VaultSession`, `PresenceAvailabilityDto`, `RealPresenceProvider`, `secretary_ffi_bridge` UUID helpers already used by settings.
- Produces: `presence_pref::{PresencePref, parse_pref, serialize_pref, load_pref_in, save_pref_in, pref_path_in}`; `session.vault_uuid() -> Option<[u8; 16]>`; commands `read_presence_pref() -> PresencePrefDto`, `write_presence_pref(enabled: bool) -> Result<(), AppError>`; DTO `PresencePrefDto { biometric_enabled: bool, availability: PresenceAvailabilityDto }`.

- [ ] **Step 1: Add constants**

In `desktop/src-tauri/src/constants.rs` (match the existing constant style; confirm exact names):

```rust
/// Subdirectory under `<data_dir>/secretary-desktop/` holding per-vault
/// presence (biometric) preference files, named `<vault_uuid_hex>.json`.
/// Sibling of the existing `devices/` subtree.
pub const PRESENCE_PREF_SUBDIR: &str = "presence";

/// Default: biometric re-auth is used when hardware is available. A fresh
/// vault (no pref file) opts in; the user disables it explicitly (e.g. before
/// travelling through a high-risk area).
pub const PRESENCE_BIOMETRIC_ENABLED_DEFAULT: bool = true;
```

- [ ] **Step 2: Write the failing pure-parse tests**

Create `desktop/src-tauri/src/presence_pref.rs`:

```rust
//! Desktop-local, per-vault biometric preference (#277). This-device scoped:
//! whether Touch ID may satisfy write re-auth on THIS machine. Stored under
//! `<data_dir>/secretary-desktop/presence/<vault_uuid_hex>.json`, a sibling of
//! the per-vault device-UUID files. NOT a vault setting — it never syncs, and
//! biometric trust is inherently per-device.
//!
//! Pure/IO split (mirrors `settings::parse` vs `settings::io`): `parse_pref` /
//! `serialize_pref` are pure; `load_pref_in` / `save_pref_in` are the thin
//! atomic-IO edge. Absent or corrupt file → default enabled.

use std::path::{Path, PathBuf};

use crate::constants::{PRESENCE_BIOMETRIC_ENABLED_DEFAULT, PRESENCE_PREF_SUBDIR};
use crate::errors::AppError;

/// The persisted preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PresencePref {
    pub biometric_reauth_enabled: bool,
}

impl Default for PresencePref {
    fn default() -> Self {
        Self { biometric_reauth_enabled: PRESENCE_BIOMETRIC_ENABLED_DEFAULT }
    }
}

/// Parse the on-disk JSON. A malformed / partial file falls back to default
/// (lenient load — mirrors settings load). Pure.
pub fn parse_pref(bytes: &[u8]) -> PresencePref {
    serde_json::from_slice::<PresencePref>(bytes).unwrap_or_default()
}

/// Serialize to bytes for atomic write. Pure.
pub fn serialize_pref(pref: &PresencePref) -> Vec<u8> {
    // Infallible for this fixed struct; `.expect` documents that.
    serde_json::to_vec_pretty(pref).expect("PresencePref serializes")
}

/// Absolute path of the pref file for `vault_uuid_hex` under `data_dir`.
pub fn pref_path_in(data_dir: &Path, vault_uuid_hex: &str) -> PathBuf {
    data_dir
        .join("secretary-desktop")
        .join(PRESENCE_PREF_SUBDIR)
        .join(format!("{vault_uuid_hex}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_enabled() {
        assert!(PresencePref::default().biometric_reauth_enabled);
    }

    #[test]
    fn round_trips() {
        let pref = PresencePref { biometric_reauth_enabled: false };
        assert_eq!(parse_pref(&serialize_pref(&pref)), pref);
    }

    #[test]
    fn corrupt_bytes_fall_back_to_default() {
        assert_eq!(parse_pref(b"not json"), PresencePref::default());
        assert_eq!(parse_pref(b""), PresencePref::default());
        assert_eq!(parse_pref(b"{}"), PresencePref::default());
    }

    #[test]
    fn path_uses_presence_subdir() {
        let p = pref_path_in(Path::new("/tmp/dd"), "abcd");
        assert!(p.ends_with("secretary-desktop/presence/abcd.json"));
    }
}
```

- [ ] **Step 3: Run the pure tests**

Run: `cargo test --release -p secretary-desktop --lib presence_pref`
Expected: PASS (4 tests). Add `pub mod presence_pref;` to `desktop/src-tauri/src/lib.rs` first if the test can't find the module.

- [ ] **Step 4: Add atomic IO (load/save) with an integration test**

Append to `desktop/src-tauri/src/presence_pref.rs` (above `#[cfg(test)]`):

```rust
/// Load the pref for `vault_uuid_hex`, or `Default` if the file is absent.
/// Corrupt content is lenient (default). IO edge.
pub fn load_pref_in(data_dir: &Path, vault_uuid_hex: &str) -> PresencePref {
    let path = pref_path_in(data_dir, vault_uuid_hex);
    match std::fs::read(&path) {
        Ok(bytes) => parse_pref(&bytes),
        Err(_) => PresencePref::default(),
    }
}

/// Atomically persist the pref for `vault_uuid_hex`. Creates the
/// `secretary-desktop/presence/` subtree on first write. Uses the same
/// exact-pinned `tempfile` persist as the settings device-UUID path.
pub fn save_pref_in(
    data_dir: &Path,
    vault_uuid_hex: &str,
    pref: &PresencePref,
) -> Result<(), AppError> {
    let path = pref_path_in(data_dir, vault_uuid_hex);
    let dir = path.parent().expect("pref path has a parent");
    std::fs::create_dir_all(dir).map_err(|e| AppError::Io { detail: e.to_string() })?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| AppError::Io { detail: e.to_string() })?;
    std::io::Write::write_all(&mut tmp, &serialize_pref(pref))
        .map_err(|e| AppError::Io { detail: e.to_string() })?;
    tmp.persist(&path).map_err(|e| AppError::Io { detail: e.to_string() })?;
    Ok(())
}
```

Add to the `tests` module:

```rust
    #[test]
    fn save_then_load_round_trips_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let uuid_hex = "00112233445566778899aabbccddeeff";
        // Absent → default.
        assert_eq!(load_pref_in(dir.path(), uuid_hex), PresencePref::default());
        // Persist disabled, read it back.
        let pref = PresencePref { biometric_reauth_enabled: false };
        save_pref_in(dir.path(), uuid_hex, &pref).unwrap();
        assert_eq!(load_pref_in(dir.path(), uuid_hex), pref);
    }
```

Ensure `tempfile` is in `[dev-dependencies]` (it already is, per `Cargo.toml`).

- [ ] **Step 5: Run the IO test**

Run: `cargo test --release -p secretary-desktop --lib presence_pref`
Expected: PASS (5 tests).

- [ ] **Step 6: Add the `vault_uuid()` session accessor**

In `desktop/src-tauri/src/session.rs`, add next to `vault_folder()`:

```rust
    /// Current vault's 16-byte UUID, or `None` if locked. Keys the per-vault
    /// desktop-local presence preference. Read from the verified manifest —
    /// the same value used to derive the per-vault device UUID at unlock.
    pub fn vault_uuid(&self) -> Option<[u8; 16]> {
        self.inner.as_ref().map(|u| u.manifest.vault_uuid())
    }
```

> Confirm `OpenVaultManifest::vault_uuid()` returns `[u8; 16]` (it is called as `output.manifest.vault_uuid()` in `unlock`). If it returns a wrapper, `.into()`/`.0` as needed.

- [ ] **Step 7: Add the `read_presence_pref` / `write_presence_pref` commands**

Append to `desktop/src-tauri/src/commands/presence.rs`:

```rust
use std::sync::Mutex;

use tauri::State;

use crate::commands::shared::lock_session;
use crate::presence_pref::{load_pref_in, save_pref_in, PresencePref};
use crate::session::VaultSession;

/// Wire form of the presence preference read: the stored toggle plus the
/// current hardware availability (so the UI can hide the toggle off macOS or
/// where Touch ID isn't enrolled).
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresencePrefDto {
    pub biometric_enabled: bool,
    pub availability: PresenceAvailabilityDto,
}

/// Resolve `(data_dir, vault_uuid_hex)` for the open vault, or `NotUnlocked`.
fn open_vault_pref_key(session: &VaultSession) -> Result<(std::path::PathBuf, String), AppError> {
    let uuid = session.vault_uuid().ok_or(AppError::NotUnlocked)?;
    Ok((session.device_data_dir_clone(), hex::encode(uuid)))
}

#[tauri::command]
pub fn read_presence_pref(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<PresencePrefDto, AppError> {
    let (data_dir, uuid_hex) = {
        let session = lock_session(state.inner())?;
        open_vault_pref_key(&session)?
    };
    let pref = load_pref_in(&data_dir, &uuid_hex);
    Ok(PresencePrefDto {
        biometric_enabled: pref.biometric_reauth_enabled,
        availability: RealPresenceProvider.availability().into(),
    })
}

#[tauri::command]
pub fn write_presence_pref(
    state: State<'_, Mutex<VaultSession>>,
    enabled: bool,
) -> Result<(), AppError> {
    let (data_dir, uuid_hex) = {
        let session = lock_session(state.inner())?;
        open_vault_pref_key(&session)?
    };
    save_pref_in(&data_dir, &uuid_hex, &PresencePref { biometric_reauth_enabled: enabled })
}
```

> `device_data_dir_clone()` — add a small accessor on `VaultSession` returning `self.device_data_dir.clone()` (the field is private). If `lock_session` isn't the exact helper name in `commands::shared`, use whatever the other commands use (grep `lock_session`). `RealPresenceProvider` must implement `availability()` synchronously — it does (Task 3).

- [ ] **Step 8: Register the two commands + write an integration test**

In `main.rs` `generate_handler!`, after `presence::authenticate_presence`:

```rust
            presence::authenticate_presence,
            presence::read_presence_pref,
            presence::write_presence_pref,
```

Add an integration test in `desktop/src-tauri/tests/` (follow the existing `ipc_integration.rs` pattern for constructing a `Mutex<VaultSession>` with a `tempdir`, unlocking a fixture vault via a temp copy of the golden vault — [[feedback_smoke_test_temp_copy_golden_vault]] — then asserting `read_presence_pref` defaults to enabled, `write_presence_pref(false)` persists, and a re-read returns disabled). If the existing tests don't unlock a real vault, cover the pref round-trip via the `presence_pref` unit tests already written (Step 4) and assert `read_presence_pref` returns `NotUnlocked` on a locked session:

```rust
#[test]
fn read_presence_pref_requires_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let state = std::sync::Mutex::new(
        secretary_desktop::session::VaultSession::new(dir.path().to_path_buf()),
    );
    // Locked session → NotUnlocked. (Uses the impl directly; the #[tauri::command]
    // wrapper only adds State extraction.)
    let session = state.lock().unwrap();
    assert!(session.vault_uuid().is_none());
}
```

- [ ] **Step 9: Run tests + clippy**

Run: `cargo test --release -p secretary-desktop`
Expected: PASS.
Run: `cargo clippy --release -p secretary-desktop --tests -- -D warnings`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add desktop/src-tauri/src/presence_pref.rs desktop/src-tauri/src/lib.rs desktop/src-tauri/src/session.rs desktop/src-tauri/src/constants.rs desktop/src-tauri/src/commands/presence.rs desktop/src-tauri/src/main.rs desktop/src-tauri/tests
git commit -m "feat(desktop): desktop-local per-vault presence preference + read/write commands (#277)"
```

---

## Task 5: Frontend IPC wrappers + command classification

**Files:**
- Create: `desktop/src/lib/presence.ts`
- Modify: `desktop/src/lib/constants.ts` (`PresenceAvailability` type)
- Modify: `desktop/src/lib/writeCommands.ts` (classify the three commands)
- Test: `desktop/tests/writeGateCoverage.test.ts` (already asserts full classification — it must stay green)

**Interfaces:**
- Produces: `authenticatePresence(reason): Promise<PresenceOutcome>`; `readPresencePref(): Promise<PresencePrefDto>`; `writePresencePref(enabled): Promise<void>`; types `PresenceOutcome = 'authenticated'|'fallback'|'unavailable'|'cancelled'`, `PresenceAvailability`, `PresencePrefDto`.

- [ ] **Step 1: Write the IPC wrappers**

Create `desktop/src/lib/presence.ts`:

```ts
// Typed wrappers for the desktop presence (macOS Touch ID) commands (#277).
// Mirrors ipc.ts conventions. `authenticate_presence` returns a tagged outcome
// ({ kind: 'authenticated' | ... }); we surface the bare tag to callers.

import { invoke } from '@tauri-apps/api/core';
import { isAppError } from './ipc';

export type PresenceOutcome = 'authenticated' | 'fallback' | 'unavailable' | 'cancelled';
export type PresenceAvailability = 'available' | 'notEnrolled' | 'notAvailable' | 'unsupported';

export interface PresencePrefDto {
  biometricEnabled: boolean;
  availability: PresenceAvailability;
}

interface PresenceOutcomeDto {
  kind: PresenceOutcome;
}

/** Fire the native Touch ID sheet. Never rejects for a normal outcome —
 *  cancel/fallback/unavailable are returned as tags. On an unexpected IPC
 *  fault, fail safe to 'unavailable' so the caller routes to the password. */
export async function authenticatePresence(reason: string): Promise<PresenceOutcome> {
  try {
    const dto = await invoke<PresenceOutcomeDto>('authenticate_presence', { reason });
    return dto.kind;
  } catch (err) {
    console.error('authenticate_presence failed; falling back to password', err);
    return 'unavailable';
  }
}

export async function readPresencePref(): Promise<PresencePrefDto> {
  return invoke<PresencePrefDto>('read_presence_pref');
}

export async function writePresencePref(enabled: boolean): Promise<void> {
  try {
    await invoke<void>('write_presence_pref', { enabled });
  } catch (err) {
    if (isAppError(err)) throw err;
    console.error('write_presence_pref returned non-AppError rejection', err);
    throw { code: 'internal' };
  }
}
```

- [ ] **Step 2: Classify the three commands**

In `desktop/src/lib/writeCommands.ts`, add to `COMMAND_CLASSIFICATION`:

```ts
  // --- presence (macOS Touch ID write re-auth, #277) ---
  authenticate_presence: { kind: 'session' },
  read_presence_pref: { kind: 'read' },
  write_presence_pref: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'writePresencePref',
    reason:
      'desktop-local this-device preference; not a vault mutation. The only security-reducing direction (enabling biometric) is gated in SettingsDialog via the reducesProtection re-auth; disabling (a hardening) needs no presence proof.',
  },
```

- [ ] **Step 3: Run the coverage test**

Run: `cd desktop && pnpm test writeGateCoverage`
Expected: PASS (every `generate_handler!` command, incl. the three new ones, is classified).

- [ ] **Step 4: Type-check**

Run: `cd desktop && pnpm exec svelte-check --tsconfig ./tsconfig.json`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/presence.ts desktop/src/lib/constants.ts desktop/src/lib/writeCommands.ts
git commit -m "feat(desktop): presence IPC wrappers + command classification (#277)"
```

---

## Task 6: `writeGuard` biometric pre-step + presence store

**Files:**
- Modify: `desktop/src/lib/stores.ts` (presence-pref store + reset)
- Modify: `desktop/src/lib/writeGuard.ts` (pre-step + two seam members)
- Modify: `desktop/src/routes/Unlock.svelte` (load pref at unlock)
- Modify: `desktop/src/App.svelte` (reset store on lock)
- Test: `desktop/tests/writeGuard.test.ts`

**Interfaces:**
- Consumes: `authenticatePresence`, `readPresencePref` (Task 5).
- Produces: store `presencePref` + `setPresencePref(dto)` / `resetPresencePref()`; extended `WriteGuardSeam` with `biometricPrefEnabled(): boolean` and `tryBiometric(reason): Promise<PresenceOutcome>`.

- [ ] **Step 1: Add the presence-pref store**

In `desktop/src/lib/stores.ts`, after the reauth-prompt block:

```ts
// --- Presence (Touch ID) preference ---------------------------------------
// Loaded at unlock from readPresencePref(); consulted synchronously by
// writeGuard.authorizeWrite to decide whether to attempt biometry. Reset on
// lock so a locked session never attempts biometry. Default: not enabled
// (safe — password path) until loaded.
import type { PresenceAvailability } from './presence';

interface PresencePrefState {
  biometricEnabled: boolean;
  availability: PresenceAvailability;
}
const _presencePref = writable<PresencePrefState>({
  biometricEnabled: false,
  availability: 'unsupported'
});
export const presencePref: Readable<PresencePrefState> = { subscribe: _presencePref.subscribe };
export function setPresencePref(dto: PresencePrefState): void {
  _presencePref.set(dto);
}
export function resetPresencePref(): void {
  _presencePref.set({ biometricEnabled: false, availability: 'unsupported' });
}
```

- [ ] **Step 2: Write the failing writeGuard tests**

Add to `desktop/tests/writeGuard.test.ts` (adapt the existing seam-injection helper — it constructs a `WriteGuardSeam`; extend the fake with the two new members):

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  authorizeWrite,
  ReauthCancelled,
  __setWriteGuardTestSeam,
  resetReauthGuard,
  seedReauthClock
} from '../src/lib/writeGuard';

function seam(overrides: Partial<any> = {}) {
  return {
    readSettings: () => ({ enabled: true, windowMs: 0 }), // window 0 → always needs reauth
    now: () => 1000,
    prompt: vi.fn(async () => {}),
    biometricPrefEnabled: () => true,
    tryBiometric: vi.fn(async () => 'authenticated' as const),
    ...overrides
  };
}

describe('authorizeWrite biometric pre-step', () => {
  beforeEach(() => resetReauthGuard());

  it('biometric authenticated → no password prompt, resolves', async () => {
    const s = seam();
    __setWriteGuardTestSeam(s);
    await authorizeWrite('reason');
    expect(s.tryBiometric).toHaveBeenCalledOnce();
    expect(s.prompt).not.toHaveBeenCalled();
  });

  it('biometric fallback → opens password prompt', async () => {
    const s = seam({ tryBiometric: vi.fn(async () => 'fallback' as const) });
    __setWriteGuardTestSeam(s);
    await authorizeWrite('reason');
    expect(s.prompt).toHaveBeenCalledOnce();
  });

  it('biometric unavailable → opens password prompt', async () => {
    const s = seam({ tryBiometric: vi.fn(async () => 'unavailable' as const) });
    __setWriteGuardTestSeam(s);
    await authorizeWrite('reason');
    expect(s.prompt).toHaveBeenCalledOnce();
  });

  it('biometric cancelled → rejects with ReauthCancelled, no prompt', async () => {
    const s = seam({ tryBiometric: vi.fn(async () => 'cancelled' as const) });
    __setWriteGuardTestSeam(s);
    await expect(authorizeWrite('reason')).rejects.toBe(ReauthCancelled);
    expect(s.prompt).not.toHaveBeenCalled();
  });

  it('pref disabled → skips biometry, goes straight to password', async () => {
    const s = seam({ biometricPrefEnabled: () => false, tryBiometric: vi.fn() });
    __setWriteGuardTestSeam(s);
    await authorizeWrite('reason');
    expect(s.tryBiometric).not.toHaveBeenCalled();
    expect(s.prompt).toHaveBeenCalledOnce();
  });

  it('within grace window → neither biometry nor prompt', async () => {
    const s = seam({ readSettings: () => ({ enabled: true, windowMs: 60_000 }) });
    __setWriteGuardTestSeam(s);
    seedReauthClock(1000); // now() === 1000, so 0 elapsed < window
    await authorizeWrite('reason');
    expect(s.tryBiometric).not.toHaveBeenCalled();
    expect(s.prompt).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 3: Run to verify the new tests fail**

Run: `cd desktop && pnpm test writeGuard`
Expected: FAIL — seam has no `biometricPrefEnabled`/`tryBiometric`; `authorizeWrite` doesn't call them.

- [ ] **Step 4: Extend the seam + `authorizeWrite`**

In `desktop/src/lib/writeGuard.ts`:

Add imports:

```ts
import { authenticatePresence, type PresenceOutcome } from './presence';
import { presencePref } from './stores';
import { get } from 'svelte/store';
```

Extend the `WriteGuardSeam` interface:

```ts
interface WriteGuardSeam {
  readSettings: () => { enabled: boolean; windowMs: number };
  now: () => number;
  prompt: (reason: string) => Promise<void>;
  /** True when this-device Touch ID is enabled in the presence preference. */
  biometricPrefEnabled: () => boolean;
  /** Fire the native Touch ID sheet; resolves to the outcome tag. */
  tryBiometric: (reason: string) => Promise<PresenceOutcome>;
}
```

Add to `productionSeam()`:

```ts
    biometricPrefEnabled: () => get(presencePref).biometricEnabled,
    tryBiometric: (reason: string) => authenticatePresence(reason),
```

Replace `authorizeWrite`'s body:

```ts
export async function authorizeWrite(reason: string): Promise<void> {
  const { enabled, windowMs } = seam.readSettings();
  if (!needsReauth({ enabled, lastAuthAtMs, nowMs: seam.now(), windowMs })) {
    return;
  }
  // Toggle OFF (or not-yet-loaded) → password only.
  if (!seam.biometricPrefEnabled()) {
    await seam.prompt(reason);
    lastAuthAtMs = seam.now();
    return;
  }
  // Toggle ON → Touch ID first, password on fallback/unavailable.
  const outcome = await seam.tryBiometric(reason);
  if (outcome === 'authenticated') {
    lastAuthAtMs = seam.now();
    return;
  }
  if (outcome === 'cancelled') {
    throw ReauthCancelled;
  }
  // 'fallback' | 'unavailable' → the existing password dialog (unchanged).
  await seam.prompt(reason);
  lastAuthAtMs = seam.now();
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd desktop && pnpm test writeGuard`
Expected: PASS (new + existing password-only tests).

- [ ] **Step 6: Wire load-at-unlock and reset-on-lock**

In `desktop/src/routes/Unlock.svelte`, where `seedReauthClock(Date.now())` is called on a successful unlock (both call sites), load the pref after seeding:

```ts
      seedReauthClock(Date.now());
      // Load this-device Touch ID preference (#277) for the write-reauth gate.
      try {
        setPresencePref(await readPresencePref());
      } catch (err) {
        console.error('failed to load presence preference; biometric disabled this session', err);
        resetPresencePref();
      }
```

Add imports to `Unlock.svelte`: `import { setPresencePref, resetPresencePref } from '../lib/stores';` and `import { readPresencePref } from '../lib/presence';`.

In `desktop/src/App.svelte`, where `resetReauthGuard()` is called on lock, also call `resetPresencePref()`:

```ts
      resetReauthGuard();
      resetPresencePref();
```

Add `resetPresencePref` to the App.svelte import from `./lib/stores`.

- [ ] **Step 7: Type-check + full frontend test run**

Run: `cd desktop && pnpm exec svelte-check --tsconfig ./tsconfig.json`
Expected: clean.
Run: `cd desktop && pnpm test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add desktop/src/lib/writeGuard.ts desktop/src/lib/stores.ts desktop/src/routes/Unlock.svelte desktop/src/App.svelte desktop/tests/writeGuard.test.ts
git commit -m "feat(desktop): Touch-ID-first authorizeWrite pre-step + presence store (#277)"
```

---

## Task 7: SettingsDialog toggle + ROADMAP + follow-ups

**Files:**
- Modify: `desktop/src/components/SettingsDialog.svelte`
- Test: `desktop/tests/SettingsDialog.test.ts`
- Modify: `ROADMAP.md`

**Interfaces:**
- Consumes: `presencePref`, `setPresencePref` (store); `writePresencePref` (IPC); `authorizeWrite`.

- [ ] **Step 1: Write the failing SettingsDialog test**

Add to `desktop/tests/SettingsDialog.test.ts` (follow the file's existing render/mocking harness). Two behaviors:

```ts
// (1) The toggle is hidden when availability !== 'available'.
it('hides the Touch ID toggle when biometry is unavailable', async () => {
  // set presencePref store to { biometricEnabled: true, availability: 'unsupported' }
  // render SettingsDialog open
  // expect: no element with the Touch ID toggle label
});

// (2) Enabling Touch ID from disabled routes through authorizeWrite before writePresencePref.
it('enabling Touch ID gates on authorizeWrite then persists', async () => {
  // presencePref: { biometricEnabled: false, availability: 'available' }
  // mock authorizeWrite (resolves) and writePresencePref (resolves)
  // toggle the checkbox on, click Save
  // expect authorizeWrite called, then writePresencePref(true) called
});
```

Write these against the harness the file already uses (it mocks `../src/lib/ipc` and `../src/lib/writeGuard`; add mocks for `../src/lib/presence` and the `presencePref` store). Keep exact assertions concrete against the rendered DOM the same way the existing tests do.

- [ ] **Step 2: Run to verify failure**

Run: `cd desktop && pnpm test SettingsDialog`
Expected: FAIL (toggle not rendered; no presence save wiring).

- [ ] **Step 3: Add the toggle + save integration**

In `desktop/src/components/SettingsDialog.svelte`:

Add imports:

```ts
  import { presencePref, setPresencePref } from '../lib/stores';
  import { writePresencePref } from '../lib/presence';
```

Add derived + input state (near the other `current*`/`input*`):

```ts
  let biometricAvailable = $derived($presencePref.availability === 'available');
  let currentBiometric = $derived($presencePref.biometricEnabled);
  let inputBiometric = $state(false);
```

Re-seed `inputBiometric` in the existing `$effect` that re-seeds inputs on open:

```ts
    inputBiometric = currentBiometric;
```

In `save()`, fold "enabling biometric" into the `reducesProtection` computation (enabling adds a compellable path → a reduction; disabling is a hardening):

```ts
    const enablesBiometric = inputBiometric && !currentBiometric;
    const reducesProtection = widensAutoLock || weakensWriteGate || enablesBiometric;
```

After the successful `setSettings` + `settingsUpdated` block, persist the presence pref if it changed and mirror it into the store (guard on availability so a hidden toggle never writes):

```ts
      if (biometricAvailable && inputBiometric !== currentBiometric) {
        await writePresencePref(inputBiometric);
        setPresencePref({ biometricEnabled: inputBiometric, availability: $presencePref.availability });
      }
```

In `cancel()`, revert `inputBiometric = currentBiometric;` alongside the other reverts.

Add the toggle to the markup (only when available), after the "Require password before edits" field:

```svelte
  {#if biometricAvailable}
    <label class="settings-dialog__field settings-dialog__field--checkbox">
      <input
        type="checkbox"
        class="settings-dialog__checkbox"
        bind:checked={inputBiometric}
        disabled={submitting}
      />
      <span class="settings-dialog__label">Use Touch ID on this Mac</span>
    </label>
    <p class="settings-dialog__hint">
      Applies to this device only. Turn off before travelling through high-risk areas —
      a password will always be required instead.
    </p>
  {/if}
```

- [ ] **Step 4: Run tests + type-check**

Run: `cd desktop && pnpm test SettingsDialog`
Expected: PASS.
Run: `cd desktop && pnpm exec svelte-check --tsconfig ./tsconfig.json`
Expected: clean (watch for smart-quote breakage in the new attribute strings — [[project_secretary_svelte_smartquote_svelte_check]]).

- [ ] **Step 5: Full frontend + workspace gates**

Run: `cd desktop && pnpm test`
Expected: PASS.
Run: `cargo test --release --workspace` then `cargo clippy --release --workspace --tests -- -D warnings`
Expected: green + clean.

- [ ] **Step 6: Update ROADMAP + file follow-up issues**

Add a line under the D.1 desktop section of `ROADMAP.md` noting #277 macOS Touch ID write re-auth shipped (host-tested; on-hardware proof + Linux/Windows deferred). File three GitHub issues ([[feedback_act_on_issues_dont_mention]]):
- "#277 follow-up: on-hardware Touch ID proof on a signed macOS build" (needs signing identity + possibly `NSFaceIDUsageDescription`).
- "#277 follow-up: Linux presence provider (fprintd/polkit)".
- "#277 follow-up: Windows Hello presence provider".

```bash
gh issue create --title "#277 follow-up: on-hardware Touch ID proof (signed macOS build)" --body "..."
gh issue create --title "#277 follow-up: Linux presence provider (fprintd/polkit)" --body "..."
gh issue create --title "#277 follow-up: Windows Hello presence provider" --body "..."
```

- [ ] **Step 7: Commit**

```bash
git add desktop/src/components/SettingsDialog.svelte desktop/tests/SettingsDialog.test.ts ROADMAP.md
git commit -m "feat(desktop): Touch ID settings toggle + ROADMAP; file #277 follow-ups"
```

---

## Self-Review

**Spec coverage:**
- Isolated objc2 crate + `unsafe` boundary → Tasks 1–2. ✓
- Pure `classify()` fail-safe → Task 1. ✓
- `authenticate_presence` + `PresenceProvider` seam, vault-independent, spawn_blocking offload → Task 3. ✓
- Desktop-local per-vault pref (parse/serialize + atomic IO + read/write commands + availability in read) → Task 4. ✓
- `vault_uuid()` accessor → Task 4. ✓
- Frontend Touch-ID-first / password-fallback flow, pref gate in frontend + hardware gate in backend → Task 6. ✓
- Disable toggle (this-device, travel kill switch), enabling gated via reducesProtection, hidden off-macOS/unavailable → Task 7. ✓
- writeCommands classification (coverage gate) → Task 5. ✓
- Deferred follow-ups filed → Task 7. ✓

**Placeholder scan:** The two untestable surfaces (objc2 `evaluate` runtime, the SettingsDialog DOM assertions) carry explicit "confirm against the harness/crate at implementation" notes rather than fake code, because the sheet can't be host-tested and the test harness shape is file-specific — these are honest bounded confirmations, not skipped work. All pure logic has complete code + tests.

**Type consistency:** `PresenceOutcome`/`PresenceAvailability` (Rust) ↔ `PresenceOutcomeDto`/`PresenceAvailabilityDto` (serde camelCase) ↔ `PresenceOutcome`/`PresenceAvailability` (TS tags) are consistent. `PresencePref { biometric_reauth_enabled }` (storage) vs `PresencePrefDto { biometric_enabled, availability }` (wire) are deliberately distinct and mapped in Task 4 Step 7. Seam members `biometricPrefEnabled`/`tryBiometric` match between Task 6 interface, production seam, and tests.
