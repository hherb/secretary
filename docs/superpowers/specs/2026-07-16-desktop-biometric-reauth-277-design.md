# Design — `#277`: desktop write re-auth via macOS Touch ID

**Date:** 2026-07-16
**Issue:** [#277](https://github.com/hherb/secretary/issues/277) — *Desktop write re-auth via OS biometric (macOS Touch ID / Linux / Windows)*
**Branch:** `feature/desktop-biometric-reauth-277` (worktree `.worktrees/desktop-biometric-reauth-277`, off `main` @ `ebbc9c9f`)
**Scope:** Pure desktop slice, **macOS only** this pass. New first-party crate + Tauri backend command + frontend policy + a desktop-local disable toggle. No change to `core/`, `ffi/`, `ios/`, or `android/`. Linux/Windows and the on-hardware Touch ID proof are explicit, tracked follow-ups.

## Problem

Desktop write re-authentication (PR #276) currently proves presence one way: re-entering the vault password, which re-runs `open_vault_with_password` (full Argon2id + unlock + manifest verify) and discards the handle. The `authorizeWrite` chokepoint in [`desktop/src/lib/writeGuard.ts`](../../../desktop/src/lib/writeGuard.ts) opens the password dialog whenever the grace window (`needsReauth`) has elapsed.

Issue #277 asks for an OS-biometric presence proof — macOS Touch ID via `LocalAuthentication` — so a user inside an unlocked session can re-authorize a write with a fingerprint instead of retyping the password, while password re-entry remains the universal fallback.

### Two facts that shape the whole design

1. **Biometric is a presence proof, not a cryptographic binding.** macOS `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` returns only a boolean *"the device owner authenticated with biometry."* It does **not** re-derive the Master KEK, does **not** prove knowledge of the vault password, and touches **no** vault key material. This is a genuine downgrade from the password path — acceptable **only** because the write-reauth gate is explicitly a *presence-assurance grace window* (see the `reauth.ts` module comment), not a cryptographic gate, and because **password re-entry stays as the universal fallback and the only KEK-knowledge proof.** The vault unlock itself is unaffected — this gate only governs re-authorizing writes *within* an already-unlocked session.

2. **The Tauri desktop crate forbids `unsafe`.** `desktop/src-tauri` is a workspace member with `[lints] workspace = true`, so it inherits `[workspace.lints.rust] unsafe_code = "forbid"`. `LocalAuthentication` is an Objective-C framework reached through `objc2`, whose macros expand to `unsafe`. `forbid` cannot be locally overridden with `#[allow]`. Therefore the biometric call **cannot** live in `src-tauri`; it must be isolated in its own crate behind a reviewed boundary — exactly what CLAUDE.md prescribes: *"If a primitive truly needs FFI, isolate it in its own crate behind a reviewed boundary."*

## Decisions (approved in brainstorm — do not re-litigate)

- **FFI boundary:** a new first-party crate wrapping `objc2-local-authentication`, not the community `tauri-plugin-biometry` (single-maintainer plugin on the auth path of a secrets manager; bundles storage we don't want) and not a Swift sidecar (adds a Swift build + code-signed sidecar bundling step to desktop packaging).
- **Session scope:** macOS Touch ID only. On-hardware proof is a tracked follow-up (a signed build is required — see Risks). Linux/Windows deferred.
- **UX:** Touch ID first, password on fallback. `authorizeWrite` fires the native sheet directly; no dialog on success.
- **Disable toggle:** a **desktop-local, per-vault** preference (this-device scoped), not a vault-synced setting — a vault setting would touch `core/ffi` and break the pure-desktop scope. Motivated by the high-risk-travel threat model: biometrics are compellable, so the user must be able to force password-only on the at-risk machine.

## Architecture

Four units, each independently testable, communicating through narrow interfaces:

```
secretary-desktop-presence  (new crate, the ONLY unsafe)   ── pure classify() + objc2 evaluate()
        ▲ (Rust call)
src-tauri/commands/presence.rs  (PresenceProvider seam)     ── authenticate_presence command
src-tauri/settings (or presence_pref)  (desktop-local)      ── read/write_presence_pref
        ▲ (Tauri IPC)
desktop/src/lib/writeGuard.ts  (frontend policy)            ── authorizeWrite biometric pre-step
```

### 1. `desktop/secretary-desktop-presence` — the isolated boundary

New workspace member, sibling to `src-tauri`. The **only** crate in the repo that permits `unsafe`: it omits `lints.workspace = true`, so the workspace `unsafe_code = "forbid"` does not apply. All `objc2` dependencies are `cfg`-gated to macOS and **exact-pinned** (security-path dependency discipline).

```
desktop/secretary-desktop-presence/
  Cargo.toml          # objc2 deps: [target.'cfg(target_os="macos")'.dependencies]; NOT lints.workspace=true
  src/lib.rs          # public API + PresenceOutcome / PresenceAvailability + pure classify()
  src/macos.rs        # #[cfg(target_os = "macos")] — the ONE evaluatePolicy call + block→sync bridge
  src/unsupported.rs  # #[cfg(not(target_os = "macos"))] — returns Unsupported (keeps Linux CI compiling)
```

Pure free functions (no struct state — an `LAContext` is created per call):

```rust
/// Whether biometric evaluation can proceed on this machine right now.
pub enum PresenceAvailability { Available, NotEnrolled, NotAvailable, Unsupported }

/// The result of one biometric evaluation. Control-flow, not error.
pub enum PresenceOutcome { Authenticated, Fallback, Unavailable, Cancelled }

pub fn availability() -> PresenceAvailability;      // wraps LAContext.canEvaluatePolicy
pub fn evaluate(reason: &str) -> PresenceOutcome;   // presents the Touch ID sheet, blocks on completion

/// PURE, host-tested: maps the raw evaluatePolicy result to an outcome. `macos.rs`
/// is a thin shell around this — the classification logic carries no `unsafe`.
/// `Ok(())` = biometry succeeded; `Err(code)` = the `LAError` code from the NSError.
pub(crate) fn classify(result: Result<(), i64>) -> PresenceOutcome;
```

macOS specifics: policy `LAPolicy::DeviceOwnerAuthenticationWithBiometrics` (Touch ID only — never the OS account passcode, which would confuse the fallback story); `localizedReason = reason`; `localizedFallbackTitle = "Use Password"` so the sheet shows the fallback button. `evaluatePolicy` is asynchronous with a completion handler — `macos.rs` bridges it to a synchronous return over a `std::sync::mpsc` channel so the public `evaluate()` blocks until the outcome is known.

The non-macOS `unsupported.rs` returns `PresenceAvailability::Unsupported` / `PresenceOutcome::Unavailable`, so the crate compiles on Linux (the `desktop` CI test job runs on Linux) and the real objc2 path compiles only on macOS.

### 2. `src-tauri/src/commands/presence.rs` — backend command + provider seam

New Tauri command. Touches **no** vault state (presence ≠ crypto), so it takes no session handle. A `PresenceProvider` trait makes the core host-testable (the live objc2 path cannot run in a headless `cargo test`):

```rust
pub trait PresenceProvider {
    fn availability(&self) -> PresenceAvailability;
    fn evaluate(&self, reason: &str) -> PresenceOutcome;
}
// Production impl delegates to secretary_desktop_presence::{availability, evaluate}.

/// Testable core: reason string in, outcome or fault out.
fn authenticate_presence_impl(p: &dyn PresenceProvider, reason: &str) -> Result<PresenceOutcome, AppError>;

#[tauri::command]
pub async fn authenticate_presence(reason: String) -> Result<PresenceOutcome, AppError>;
```

`PresenceOutcome` is serde-tagged and crosses the IPC seam as normal control-flow returned in `Ok`. `AppError` is reserved for genuine transport/internal faults (e.g. a poisoned channel), never for "user cancelled" or "no biometry." The live evaluation runs off the async command thread via `tauri::async_runtime::spawn_blocking`, the same offload discipline `verify_password` uses for its ~1–2 s Argon2id, so the sheet's presentation never blocks the async runtime.

Registered in `generate_handler!` and classified in `writeCommands.ts` as a **non-write** command (it authorizes writes but mutates nothing) — the #280 coverage test (`pnpm test`) fails if it is left unclassified; `cargo` cannot see that gap.

### 3. Desktop-local presence preference

A per-vault, this-device preference stored under the existing `<data_dir>/secretary-desktop/` mechanism (the same home as the per-vault device-UUID file), keyed by `vault_uuid`. Written atomically. Absent or corrupt file → default **enabled** (biometric used when hardware is available).

- **Pure/IO split** mirroring `settings/parse.rs` vs `settings/io.rs`: a pure parse/serialize (`{ biometric_reauth_enabled: bool }`, host-tested round-trip + default-on-absent/corrupt) and a thin atomic-write IO layer.
- **Two IPC commands:** `read_presence_pref() -> { biometricEnabled: bool }` and `write_presence_pref(enabled: bool)`. Both resolve the currently-open vault's `vault_uuid` from the session (read-only; `NotUnlocked` if locked), the same way `verify_password_impl` resolves the open vault's folder — note this is distinct from `authenticate_presence`, which is vault-independent. The pref is loaded into a frontend store at unlock so `authorizeWrite` can consult it synchronously.
- **Changing the toggle routes through `authorizeWrite`.** It is a security-policy change, so it requires presence: this prevents a passer-by at an unlocked-but-idle session, after the grace window, from silently enabling biometric and then compelling it. The `SettingsDialog` save performs one re-auth, then persists the vault settings (existing path) and the presence pref (new path) together.
- **UI:** a clearly this-device-scoped toggle in `SettingsDialog.svelte`, e.g. **"Use Touch ID on this Mac"**, with a one-line hint naming the travel use case. Shown only on macOS (or shown disabled with an "unavailable on this platform" note off macOS — a UI detail settled in the plan).

### 4. `writeGuard.ts` — the frontend biometric pre-step

`authorizeWrite` gains a biometric pre-step *before* the existing password prompt. The `WriteGuardSeam` grows two members: `biometricPrefEnabled(): boolean` (from the store) and `tryBiometric(reason): Promise<PresenceOutcome>` (production → the `authenticate_presence` IPC). The password-dialog path (`seam.prompt`) is **unchanged** — it is literally the fallback.

```ts
export async function authorizeWrite(reason: string): Promise<void> {
  const { enabled, windowMs } = seam.readSettings();
  if (!needsReauth({ enabled, lastAuthAtMs, nowMs: seam.now(), windowMs })) return;

  if (!seam.biometricPrefEnabled()) {           // toggle OFF → password only
    await seam.prompt(reason); lastAuthAtMs = seam.now(); return;
  }
  switch (await seam.tryBiometric(reason)) {
    case 'authenticated': lastAuthAtMs = seam.now(); return;             // done — NO dialog
    case 'fallback':                                                     // sheet's "Use Password"
    case 'unavailable':  await seam.prompt(reason); lastAuthAtMs = seam.now(); return;
    case 'cancelled':    throw ReauthCancelled;                          // user aborted the write
  }
}
```

The **preference gate** lives here (host-testable in vitest); the **hardware gate** stays in the backend (`availability` → `Unavailable` → password). When the toggle is OFF, biometry is never attempted — the high-risk-travel guarantee.

## Error handling / fail-safe

The pure `classify()` maps LAError codes so that **no outcome ever bypasses re-auth**:

| Condition | Outcome | Frontend effect |
|---|---|---|
| success | `Authenticated` | write proceeds, clock advances |
| `LAError.userCancel` | `Cancelled` | write aborted (`ReauthCancelled`) |
| `LAError.userFallback` (tapped "Use Password") | `Fallback` | password dialog opens |
| `biometryNotAvailable` / `biometryNotEnrolled` / `biometryLockout` | `Unavailable` | password dialog opens |
| any other / unmapped code | `Unavailable` | password dialog opens |

The default arm is **fail-safe toward the password path** — an unknown or error code sends the user to the password dialog, never silently through the gate. This mirrors the iOS "funnel LAError codes" discipline (the iOS coordinator funnels cancel/non-match into `LAError.userCancel` and never mislabels a failure as success).

## Testing strategy (TDD, all host-testable)

- **`secretary-desktop-presence`:** pure `classify()` unit tests for every LAError code plus the "unknown code → `Unavailable`" fail-safe. The live `evaluate()` objc2 path is exercised only by the deferred on-hardware proof — untestable headlessly by nature.
- **Backend `authenticate_presence_impl`:** a fake `PresenceProvider` returning each `PresenceOutcome` → assert pass-through, and `AppError` only on a provider fault.
- **Presence-pref parse/serialize:** pure round-trip + default-on-absent + default-on-corrupt tests; atomic-write IO covered by an integration test with an injected `tempfile::tempdir()` (mirrors `load_or_create_device_uuid_in`).
- **Frontend `writeGuard`:** injected seam covering all branches — pref-off → password; authenticated → no dialog + clock advanced; fallback → dialog; unavailable → dialog; cancelled → `ReauthCancelled`; and the existing password-only tests stay green.
- **`writeGateCoverage` / `writeCommands.ts`:** classify the new commands (`pnpm test` is the only gate that catches a miss).

## Scope boundaries

**In scope (this PR):**
- macOS Touch ID presence proof, full stack, host-tested with a fake provider.
- The desktop-local per-vault disable toggle + its Settings UI.
- Linux/Windows providers return `Unsupported` → password (crate stub compiles on Linux CI).

**Deferred (tracked follow-ups — file as issues):**
- On-hardware Touch ID proof on a **signed** build (mirrors iOS #202). `cargo tauri dev` / unsigned builds may fail biometry with `LAErrorNotInteractive`; a signing identity and possibly an `NSFaceIDUsageDescription` Info.plist key are needed. The PR is **not** blocked on this.
- Linux fprintd/polkit provider.
- Windows Hello provider (Windows is not a primary target).
- A vault-synced, cross-device biometric policy (that one legitimately needs `core/ffi`).

## Risks

1. **Code-signing gates real biometry.** The on-hardware proof is the only acceptance that cannot be locally guaranteed — hence its deferral. Everything shipped in this PR is host-tested.
2. **objc2 completion-handler → sync bridge.** `evaluatePolicy` calls its completion block on a framework-managed queue; `macos.rs` must bridge that to a blocking return over a channel without deadlocking the async command thread (`spawn_blocking` isolates it). An implementation detail for the plan.
3. **Dependency pinning.** Exact-pin `objc2-local-authentication` (and any `objc2` transitive we name directly) per the security-path convention; document the pin rationale in the crate's `Cargo.toml`, as `tempfile` does.

## Files

**New:**
- `desktop/secretary-desktop-presence/{Cargo.toml, src/lib.rs, src/macos.rs, src/unsupported.rs}`
- `desktop/src-tauri/src/commands/presence.rs`
- desktop-local pref module (new file under `src-tauri/src/`, e.g. `presence_pref.rs`, or a `settings` sibling — settled in the plan)
- `desktop/src/lib/presence.ts` (IPC wrappers) — or fold into `ipc.ts` per existing convention

**Modified:**
- root `Cargo.toml` — add `desktop/secretary-desktop-presence` to workspace members
- `desktop/src-tauri/src/commands/mod.rs` + `main.rs` — register commands in `generate_handler!`
- `desktop/src/lib/writeGuard.ts` — biometric pre-step
- `desktop/src/lib/writeCommands.ts` — classify new commands
- `desktop/src/components/SettingsDialog.svelte` — the toggle
- `desktop/src/lib/stores.ts` — presence-pref store, reset on lock/unlock

## Acceptance

- `cargo test --release --workspace` green (incl. new crate + backend command tests).
- `cargo clippy --release --workspace --tests -- -D warnings` clean.
- `cd desktop && pnpm test` green (incl. new writeGuard branches + writeCommands coverage).
- `svelte-check` clean (SettingsDialog edit).
- Terminal acceptance (deferred, tracked): a signed macOS build authorizes a write via Touch ID, and with the toggle OFF falls through to the password dialog with biometry never invoked.
