# NEXT_SESSION.md — D.1.1 Task 4 (IPC commands + DTOs) shipped

**Session date:** 2026-05-28 (continues immediately from the D.1.1 Task 3 session earlier the same day; Task 3 landed via PR #142 at `6f984d4` on `main`. This session wires the Task-3 `VaultSession` through the Tauri IPC surface — seven `#[tauri::command]` handlers, four DTO types, JSON wire-format pinning end-to-end.)
**Status:** D.1.1 Task 4 authored on branch `feature/d11-task-4`; PR pending. Predecessors on `main`: D.1.1 spec + ADR 0007 (PR #130, `a5d85b9`), D.1.1 Task 1 scaffold (PR #131, `e329087`), D.1.1 Task 2 pure modules (PR #137, `a3ee9e9`), D.1.1 Task 3 VaultSession (PR #142, `6f984d4`).

## (1) What we shipped this session

Wires Task 3's `VaultSession` into the Tauri IPC layer. Seven `#[tauri::command]` handlers each split into a thin Tauri shell plus a testable `*_impl(state: &Mutex<VaultSession>, ...)` helper — the pragmatic alternative to `tauri::test::mock_builder()` per the Task 4 plan note. Four DTOs serialize the bridge's plaintext metadata projections to camelCase JSON with hex-encoded UUIDs.

| Artifact | Path | Notes |
|---|---|---|
| DTO module | [`desktop/src-tauri/src/dtos.rs`](../../desktop/src-tauri/src/dtos.rs) | `BlockSummaryDto` (block_uuid_hex + block_name + created_at_ms + last_modified_ms — `recipient_uuids` deferred for D.1.2 sharing UI), `ManifestDto` (vault_uuid_hex + owner_user_uuid_hex + block_count + block_summaries + warnings), `SettingsDto` / `SettingsInput` (Serialize / Deserialize split so future read-only fields don't leak into the write-side shape), `From<&BridgeType>` impls co-located per the spec §5 review-in-one-place discipline. **7 dtos::tests** pin camelCase serde shape, hex UUID encoding, bridge-projection round-trip, warning pass-through, and explicit snake_case rejection (so a Task 6 TS-pin regression surfaces here rather than at Svelte runtime). |
| Commands module dir | [`desktop/src-tauri/src/commands/`](../../desktop/src-tauri/src/commands/) | `mod.rs` (25 LOC re-export surface + design-rationale doc on the `*_impl` split), `unlock.rs` (178 LOC: path validation via `validate_vault_path`, async Tauri handler + sync `unlock_with_password_impl`), `vault.rs` (58 LOC: `list_blocks` + `get_manifest`), `settings.rs` (58 LOC: `get_settings` + `set_settings`), `lock.rs` (77 LOC: `lock` + `notify_activity`, with `VAULT_LOCKED_EVENT` + `LOCK_REASON_EXPLICIT` named constants for the Tauri event payload). Each command's `#[tauri::command]` wrapper does `state.inner()` + delegates to a `*_impl` helper taking `&Mutex<VaultSession>` synchronously. **5 unlock-validation unit tests** pin the path-branching (nonexistent / regular file / empty folder / partial vault / full vault). |
| Wired main.rs | [`desktop/src-tauri/src/main.rs`](../../desktop/src-tauri/src/main.rs) | `tracing_subscriber::fmt()` installed on stderr with `RUST_LOG` env-filter fallback to `info`. `dirs::data_dir().expect(...)` resolved once at startup with a tight-scoped panic message (every supported platform — macOS, Linux, Windows — returns `Some`; a `None` is a "unsupported platform" failure where degraded behaviour would be unhelpful). `tauri::Builder::default().manage(Mutex::new(VaultSession::new(device_data_dir))).invoke_handler(tauri::generate_handler![...all 7...]).run(...)`. |
| IPC integration tests | [`desktop/src-tauri/tests/ipc_integration.rs`](../../desktop/src-tauri/tests/ipc_integration.rs) | **18 tests** driving every `*_impl` against the golden vault (read-path: 9 tests) and ephemeral `tempfile::tempdir()` write-path copies (write-path: 2 tests), plus locked-state rejection coverage for each command (7 tests). Three goals: functional coverage, wire-format pinning (each happy-path response serialized to `serde_json::Value` and asserted field-by-field for camelCase + hex UUIDs), and `AppError` detail-strip enforcement end-to-end (`code` field present, `detail` field absent on every error variant). Hermetic — every test injects its own `TempDir` for the device-UUID file. |
| Lib re-exports | [`desktop/src-tauri/src/lib.rs`](../../desktop/src-tauri/src/lib.rs) | Added `pub mod commands;` + `pub mod dtos;` so the integration tests can `use secretary_desktop::commands::{lock, settings, unlock, vault};` + `use secretary_desktop::dtos::SettingsInput;`. |
| Cargo dep | [`desktop/src-tauri/Cargo.toml`](../../desktop/src-tauri/Cargo.toml) | New `tracing-subscriber = { version = "0.3", features = ["env-filter"] }` — binary-only concern; lib tests run without an installed subscriber and the `tracing::warn!` calls become no-ops, which is what we want. |

**Commits on `feature/d11-task-4`** (3 originals):

| SHA | Subject |
|---|---|
| `4ef5bc5` | `feat(d11): Task 4 — DTOs (BlockSummaryDto, ManifestDto, SettingsDto, SettingsInput)` |
| `2f2fe16` | `feat(d11): Task 4 — IPC commands + handler registration + tracing init` |
| `bc26c3f` | `test(d11): Task 4 — IPC integration tests against golden vault + ephemeral writes` |

Post-squash-merge SHA on `main` will differ.

### Gauntlet (live, performed)

```
PASSED: 1041 FAILED: 0 IGNORED: 10        # baseline was 1011 / 0 / 10
cargo clippy --release --workspace --tests -- -D warnings   → clean (after 1 doc-lazy-continuation fix)
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS
```

Plan predicted **+10** tests (1011 → ~1022 was the original target, scaled from the plan's 999 → 1002 target since the actual Task-3 baseline came in 12 over plan). Actual was **+30** (1041) — surplus split:

- `dtos::tests`: +7 instead of the plan's +3. Added a `snake_case` rejection test (deserialization MUST fail when the TS frontend sends a snake_case payload — pins the wire-format contract such that a Task 6 TS-pin regression cannot pass through silently), `block_summary_dto_from_bridge_round_trips_uuid_bytes_to_hex` (uses a distinct-byte UUID literal so off-by-one slicing bugs in `hex::encode` aren't masked by `[0u8; 16]`), and `manifest_dto_passes_warnings_through` (asserts `AppWarning`'s `tag = "code"` snake_case payload survives nested inside the camelCase parent).
- `commands::unlock::tests`: +5 new tests pinning the `validate_vault_path` branching that the plan didn't enumerate (the plan's body inlined the validation; the test surface materialised when the function was extracted). Each of `nonexistent_folder_yields_vault_path_not_found`, `regular_file_path_yields_vault_path_not_found`, `empty_folder_yields_vault_path_not_a_vault`, `folder_with_only_vault_toml_yields_not_a_vault`, `folder_with_both_files_passes_validation` pins one branch of the `exists → is_dir → vault.toml → identity.bundle.enc` chain.
- `tests/ipc_integration.rs`: +18 instead of the plan's +2. The plan implicitly bundled "test the commands" with "test the underlying VaultSession (already done by Task 3)"; the materialised surface added end-to-end wire-format JSON inspection on every command (per the plan's spec §5 acceptance criterion) plus locked-path NotUnlocked coverage on every command (the plan listed only `list_blocks` for this; the property generalises).

Per the plan's note on prediction tracking: surplus tests are good news; Task 5's gauntlet baseline becomes **1041 / 0 / 10** rather than **1022 / 0 / 10**.

### Plan execution trace (for the reviewer)

- Plan Steps 1–9 followed with adaptations called out in §(3); the manual dev-tools smoke (Step 10) and the in-PR review fixup pass are deferred / not yet needed.
- Step 11 (full gauntlet) executed; result above.
- Step 12 (commit + push + PR) executed at the end of this session.
- File sizes (all comfortably under the 500-LOC CLAUDE.md threshold): dtos.rs ≈ 260 LOC, commands/unlock.rs ≈ 178 LOC, tests/ipc_integration.rs ≈ 449 LOC, commands/lock.rs ≈ 77 LOC, commands/vault.rs ≈ 58 LOC, commands/settings.rs ≈ 58 LOC, commands/mod.rs ≈ 25 LOC, main.rs ≈ 60 LOC.
- Per-module TDD discipline preserved: the DTOs commit (1 of 3) carries its own wire-format tests; commands commit (2 of 3) carries its own path-validation tests; integration tests commit (3 of 3) carries the end-to-end coverage. Each commit compiles + passes its own scope independently.

## (2) What's next — D.1.1 Task 5 (auto-lock timer + `vault-locked` event emission)

Per the plan (Task 5 begins at line 2800 of [`docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md`](docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md)), Task 5 spawns the OS-thread timer that periodically checks `session.should_auto_lock(...)` and triggers a backend lock + frontend event when the threshold expires. Single task; ~80 LOC of plumbing in main.rs plus the pure tick body for testability:

- `desktop/src-tauri/src/timer.rs` — `pub fn tick(session_mutex: &Mutex<VaultSession>, threshold_ms: u64) -> TickOutcome` (where `TickOutcome ∈ {NoAction, AutoLocked, Skipped}`). `try_lock` (non-blocking — if a command is mid-flight, skip and let the next tick retry). Pure body so the unit tests can exercise the state machine without a running Tauri runtime.
- `desktop/src-tauri/src/main.rs` — `std::thread::spawn` after `tauri::Builder::default().setup(...)`, ticks every `AUTO_LOCK_TICK_MS` (5 s, named constant from Task 2). On `TickOutcome::AutoLocked`, the thread emits a `vault-locked` Tauri event with `{ "reason": "auto" }` (mirrors the `explicit` reason already in `commands::lock`).
- `desktop/src-tauri/src/lib.rs` — `pub mod timer;`.

**Acceptance criteria for Task 5 (from the plan):**

- Gauntlet count goes from **1041 → ~1048** (+5 from `timer::tests` covering NoAction / Skipped / AutoLocked / threshold-not-yet-met / threshold-just-exceeded paths; +2 from any add-on integration tests around the `vault-locked` event emission shape).
- The pure `tick()` body lets the unit tests drive the state machine deterministically (no `sleep` loops; tests inject the `last_activity_ms` directly via a `#[cfg(test)]` accessor on `VaultSession` if needed — the plan's test sketch suggests this).
- The thread terminates cleanly when the Tauri runtime shuts down (the plan calls for using `tauri::Builder::default().setup(...)` so the thread's `JoinHandle` is owned by the app lifecycle rather than leaked).
- Clippy + fmt + conformance + spec-freshness all stay green.

**Open Task-5 question (worth thinking about during the worktree-add window):** the plan's `tick()` body takes `threshold_ms` as a parameter rather than reading it from `session.settings` because the settings live inside the mutex (would need a second acquisition). But the threshold itself is the `auto_lock_timeout_ms` settings field — so the timer thread needs to either (a) acquire the mutex once and read both `last_activity_ms` + `auto_lock_timeout_ms` inside the same critical section (cleaner), or (b) snapshot the threshold separately under its own (read-only) lock and pass it to `tick()`. Option (a) is simpler and avoids a "settings changed but timer didn't notice" race — the plan's sketch should be adapted to it.

**Estimate:** ~45–60 min (the pure tick body is small; the thread spawn + event emission is canonical Tauri 2 plumbing; the main novelty is the `#[cfg(test)]` accessor on `VaultSession` to drive the deterministic test cases).

## (3) Open decisions and risks

### Plan adaptations (worth flagging to the reviewer)

1. **`*_impl` testable helpers are sync + take `&Mutex<VaultSession>`; the `#[tauri::command]` wrapper is a thin shell.** The plan's command bodies were all-in-one (`#[tauri::command] async fn ... { ...inline logic... }`), which would force the integration tests through `tauri::test::mock_builder()` to exercise the meaningful logic. The plan's own note ("or — pragmatically — by testing the underlying VaultSession methods plus testing the DTO conversions in isolation") sanctions a less heavyweight path. Adapted: each command's body is `*_impl(state.inner(), ...)`, where `*_impl` is a normal sync function taking `&Mutex<VaultSession>`. Tests drive `*_impl` directly. This pattern matches the project's "prefer pure functions in reusable modules" feedback and keeps the runtime-mock layer out of CI's hot path.
2. **`unlock_with_password` skips the plan's "second decrypt to re-read warnings".** The plan called for unlocking via `session.unlock` (which discards warnings) and then doing a second `settings::load_from_vault` to recover them for the ManifestDto's `warnings` field. That double-decrypt is now unnecessary because Task 3's review fixup added `UnlockedSession::pending_warnings` — the warnings vec is retained on the unlocked-session bundle for exactly this purpose. The Task 4 implementation reads from that field directly: `u.pending_warnings.clone()` inside `with_unlocked`. Strictly an efficiency win; behaviour matches the plan's intent.
3. **`validate_vault_path` is its own extracted function (not inlined).** The plan inlined the path-validation logic inside `unlock_with_password`. Extracting it as a named function buys two things: (a) the five branch-coverage unit tests in `commands::unlock::tests` become possible without spinning up a full vault, (b) the two canonical filenames (`vault.toml`, `identity.bundle.enc`) get named constants at module scope rather than dangling literals.
4. **`BlockSummaryDto` drops `record_count`; uses real bridge field names.** The plan's sketch DTO had `record_count: u32` and `last_mod_ms: u64`. The actual `BlockSummary` struct (in [`ffi/secretary-ffi-bridge/src/vault/inner.rs`](../../ffi/secretary-ffi-bridge/src/vault/inner.rs)) has no `record_count` (record-level metadata is inside the encrypted block payload, not the manifest summary) and uses `created_at_ms` / `last_modified_ms` (full words, not abbreviations). DTO follows the bridge truth.

Neither adaptation changes the spec or the architectural decisions. All four are encounters with reality that the plan author couldn't have predicted without the live attempt.

### Decisions settled

- **Tracing subscriber init lives in main.rs (binary-only)**, not lib.rs. Library code that calls `tracing::warn!` becomes a no-op if no subscriber is installed — which is exactly what we want for `cargo test` (test runs don't need stderr noise from the every-error-mapper `warn!` calls; the unit tests assert behaviour directly).
- **`dirs::data_dir()` is resolved once at startup with `.expect(...)`**. Every supported platform (macOS, Linux, Windows) returns `Some`; a `None` is a "unsupported platform / broken environment" failure where degraded behaviour would be unhelpful. The expect message names the failure clearly for the bug report.
- **`vault-locked` event payload uses `{ "reason": "explicit" | "auto" }`.** `commands::lock::LOCK_REASON_EXPLICIT` is the named constant for the explicit path; Task 5 will add `LOCK_REASON_AUTO` for the timer path. The frontend toast phrases differently per reason; Task 6's TS layer pins the discriminator.
- **`get_manifest` never re-emits warnings.** Warnings are an unlock-time concern; the frontend caches them at unlock and any periodic `get_manifest` refresh returns an empty warnings vec. Otherwise every poll would produce a duplicate banner.
- **The IPC layer's `get_settings` returns `AppError::NotUnlocked` while locked, not defaults.** `VaultSession::current_settings()` returns `Settings::default()` defensively while locked (Rust-internal affordance), but the IPC contract is explicit: locked sessions cannot read settings. This is a deliberate divergence — the frontend's settings dialog is gated on `is_unlocked` anyway, so the explicit error makes the gating contract visible at the wire format.

### Risks carried forward

- **Password handling at the IPC boundary is not yet zeroize-typed.** `unlock_with_password` receives `password: String` from Tauri's IPC deserializer and hands `password.as_bytes()` to the bridge; the `String` then drops with default (non-zeroizing) allocator behaviour. A NOTE comment in `commands/unlock.rs` documents this as deferred hardening: the fix requires a co-dependent bridge-side API change (so the wrapper can be deserialized into a zeroizing buffer) which doesn't exist yet. Not blocking for D.1.1 walking skeleton; the issue should be filed before D.1.4 (record edit/save lands actual user secret data crossing this boundary).
- **`AppError::KdfTooWeak` still has no producer** (carry-over from Task 2). Survives as a typed variant for the future where the bridge surfaces structured `WeakKdfParams`. Test `kdf_too_weak_carries_payload` keeps the wire format pinned.
- **Bridge `RecordInput.record_type` workaround** (issue #141, carry-over from Task 3) — still in place; no change in Task 4. Best scheduled before D.1.1 Task 6 (TS discriminated union) so the on-disk record_type is settled before the wire-format pin.

### Issues currently open (carry-over)

- #37, #117, #120, #122, #123 — none affected by Task 4.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none affected.
- #139 — desktop: `AppError` lacks `Deserialize`; carry-over from Task 2; revisit alongside Task 6 TS discriminated union. **Status update:** still relevant — the integration tests in `ipc_integration.rs` re-parse error JSON via `serde_json::Value` rather than `serde_json::from_str::<AppError>`, which is the workaround. Adding `Deserialize` would let those tests use a typed round-trip instead.
- #140 — desktop: `parse_settings_field` text-only invariant; carry-over from Task 2 + Task 3 status update. **Status update:** Task 4 doesn't touch this; the I/O boundary enforcement Task 3 added still holds.
- #141 — bridge: `RecordInput` lacks `record_type` field; carry-over from Task 3.

### Housekeeping (stale worktrees on disk)

Carry-over from the prior baton. Remaining stale worktrees that can be removed at any pause:

```bash
# From /Users/hherb/src/secretary, after the present PR merges:
git worktree remove .worktrees/c1-1b-sync-merge   && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec     && git branch -D feature/c2-task-1-spec
for n in 1 2 3 4 5 6 7 8 9 10; do
  git worktree remove .worktrees/c2-task-$n       && git branch -D feature/c2-task-$n
done
git worktree remove .worktrees/d11-tauri-spec     && git branch -D feature/d11-tauri-spec
git worktree remove .worktrees/d11-task-3         && git branch -D feature/d11-task-3
# Keep .worktrees/d11-task-4 until this PR merges; remove after.
```

## (4) Exact commands to resume (Task 5)

```bash
# After this Task 4 PR (feature/d11-task-4) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short              # expect: clean
git checkout main
git pull --ff-only origin main

# Re-baseline the gauntlet on fresh main (expect 1041 / 0 / 10):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'

# Set up the Task 5 worktree:
git worktree add .worktrees/d11-task-5 -b feature/d11-task-5 main
cd .worktrees/d11-task-5

# Open the plan and follow Task 5 step-by-step:
#   docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md
# Search for "## Task 5:" (line ~2800). Each step block is self-contained.

# After timer.rs + main.rs thread spawn + tests:
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
```

## Closing inventory

- **Branch state on close:** `main` at `6f984d4` (D.1.1 Task 3 PR #142 merged earlier today). `feature/d11-task-4` carries 3 commits on top (DTOs + commands/main + integration tests) plus this baton commit.
- **Workspace tests on `feature/d11-task-4`:** **1041 passed + 10 ignored** (+30 over the post-Task-3 baseline of 1011).
- **README.md:** unchanged. Per the prior baton's standing pattern, per-task status flips on a sub-project in early implementation phase would be noise; the existing "D.1.1 walking skeleton ... in design" covers the implementation phase as a whole until D.1.1 ships end-to-end (Task 12).
- **ROADMAP.md:** unchanged. Same logic as README.
- **CLAUDE.md:** unchanged this session.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **`docs/adr/`:** unchanged.
- **`desktop/src-tauri/src/`:** new `dtos.rs` (260 LOC), new `commands/` dir (`mod.rs` 25 LOC, `unlock.rs` 178 LOC, `vault.rs` 58 LOC, `settings.rs` 58 LOC, `lock.rs` 77 LOC), `main.rs` expanded (60 LOC: tracing init + `dirs::data_dir()` + handler registration), `lib.rs` adds `pub mod commands;` + `pub mod dtos;` (7 LOC total).
- **`desktop/src-tauri/tests/`:** new `ipc_integration.rs` (449 LOC). Joins `session_integration.rs` from Task 3.
- **`desktop/src-tauri/Cargo.toml`:** gains `tracing-subscriber = { version = "0.3", features = ["env-filter"] }` (binary-only dep).
- **`desktop/src/` (Svelte):** untouched in Task 4.
- **Open issues:** see §(3) — none closed with this PR; no new issues opened.
- **Open PRs:** one to be opened at end of this session (D.1.1 Task 4 — IPC commands + DTOs).
- **Worktrees on disk:** stale worktrees listed in §(3) can be cleaned up at any pause; `feature/d11-task-4` stays until merge.
- **This file:** the live baton for the Task 4 close. The next slice opens with `docs/handoffs/<date>-d11-task-5-shipped.md`.
