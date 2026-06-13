# NEXT_SESSION.md — FFI folder-writing `create_vault` (Slice 1 of iOS create/import) ✅

**Session date:** 2026-06-13. Flow: `/nextsession` → confirmed iOS record-CRUD arc (#220 + #221) merged to `main` (`7cfe13e`) + cleaned up both stale worktrees → brainstormed next direction → user picked **iOS vault create/import** → exploration found the handoff's "zero Rust change" assumption was **wrong** (the bridge `create_vault` is identity-level only; the browse flow's folder-open needs a manifest + contact card it never writes) → scoped to **Slice 1: FFI folder-writing create only** → design (mnemonic-only return, thin bridge, new typed `VaultFolderNotEmpty`) → 6-task TDD plan → executed inline (subagent hit the account spend-limit; took over with the same rigor) → full gauntlet green.

**Status:** ✅ **code-complete + all-green** on branch `feature/ffi-folder-create-vault`. PR: see §4. **Slice 1 of 2** — lands the FFI surface a native-iOS create wizard (Slice 2) will sit on. Crosses Rust only (bridge + uniffi + pyo3 + desktop-match + Swift/Kotlin harnesses); **no `core/src` change, no on-disk-format / frozen-spec change** (`git diff main..HEAD --name-only | grep -E '^core/src/|docs/vault-format|docs/crypto-design'` is empty).

## (1) What we shipped this session

A folder-writing `create_vault_in_folder` exposed through the FFI bridge → uniffi + pyo3, delegating to the already-tested `core::vault::create_vault` so a client can create a **complete, browsable** vault (all four canonical files: `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, `contacts/<owner-uuid>.card`). It returns just the one-shot `MnemonicOutput` (no auto-open — the caller re-opens with the password to browse, mirroring desktop D.1.3). Requires an existing empty dir (the platform layer owns mkdir/subfolder). A new typed `FfiVaultError::VaultFolderNotEmpty` distinguishes "not empty" from a wrong path / corruption.

| Layer | What landed | Commit |
|---|---|---|
| **Spec + plan** | design (mnemonic-only return, thin bridge, typed not-empty error) + 6-task TDD plan | `d511cc5` `63f2d28` |
| **Error variant (atomic)** | `FfiVaultError::VaultFolderNotEmpty` threaded through **every** workspace exhaustive match — bridge `From<VaultError>` (`Io{AlreadyExists}`→here), uniffi enum+`From`, pyo3 exception+mapper, core `variant_name_vault`, **desktop `map_ffi_error`** — + UDL | `94f33bd` |
| **Bridge fn** | `create_vault_in_folder(folder, password, display_name, created_at_ms) -> MnemonicOutput`; `OsRng` + `V1_DEFAULT` hardcoded; round-trip (incl. cross-open via folder password + recovery) + not-empty + missing tests | `7e87cfb` |
| **uniffi** | namespace wrapper + UDL decl returning `MnemonicOutput`; UTF-8-path/zeroize discipline; wrapper test | `2a0a575` |
| **pyo3** | pyfunction returning `MnemonicOutput`; wrapper-side zeroize; pytest round-trip + 2 error contracts | `baee964` |
| **Swift + Kotlin** | `VaultFolderNotEmpty` in both `ConformanceErrors.{swift,kt}` (incl. the Kotlin `vaultExceptionDetail` exhaustive `when`); `create_vault_in_folder` round-trip + not-empty asserts in `SmokeFolderIn.{swift,kt}` | `d6044be` |
| **Docs** | README status row + ROADMAP entry + this handoff/symlink | `52e547e` (+ this commit) |

Branch from `main` @ `7cfe13e`. **Squash-merge collapses to one commit on `main`.**

### Two plan gaps caught during execution (both fixed)
The plan enumerated four exhaustive `FfiVaultError` sites; **two more existed** and the gauntlet caught them:
1. **`desktop/src-tauri/src/errors.rs::map_ffi_error`** (`FfiVaultError`→`AppError`) — the desktop app is in the workspace, so `cargo test --workspace` broke until covered. Folded the path-less bridge variant to `AppError::Io` (mirroring the existing `FolderInvalid`→`Io` precedent; desktop's own create command constructs the path-aware `AppError::VaultFolderNotEmpty { path }` itself).
2. **Kotlin `vaultExceptionDetail`** — unlike the Swift/Rust detail extractors (which have catch-alls), the Kotlin `when` is exhaustive, so it needed an explicit `VaultFolderNotEmpty -> null` arm.

### Acceptance (green — full gauntlet this session)
```
cargo test --release --workspace                                  → 74 suites, 0 failures
cargo clippy --release --workspace --tests -- -D warnings         → clean
(cd ffi/secretary-ffi-py && uv run --with pytest pytest -q)       → 86 passed
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh      → 27/27
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh                  → smoke OK (create asserts)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh     → 27/27
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh                 → smoke OK (create asserts)
git diff main..HEAD --name-only | grep -E '^core/src/|docs/vault-format|docs/crypto-design'  → empty
```

## (2) What's next — Slice 2: iOS vault create / import UI

The FFI is now ready. **Slice 2 (next session, 100% Swift)** lands the native-iOS create wizard on this surface. **Acceptance:** from the selection screen, the user can **create a brand-new encrypted vault** (set master password + confirm, display name, then a 24-word recovery-phrase screen with a "I wrote it down" confirmation) which then flows into the existing unlock→browse→CRUD path; **and import** = select a folder that already contains a vault and unlock it (the existing flow), with folder validation UX (detect empty-vs-vault, mirror desktop's "this folder isn't a vault / create one here"). Host-tested `VaultProvisioningViewModel` + a simulator test that creates a vault in a **tempdir** (never the frozen golden fixture) and opens it. Mirror desktop D.1.3 parity (3-step wizard, no password-strength UI, no auto-open). The Swift layer owns the `mkdir`/subfolder logic (the bridge requires an existing empty dir). New uniffi Swift name is `createVaultInFolder`; it returns a `MnemonicOutput` whose `takePhrase()` is one-shot.

**Other carried candidates (not picked):** iOS read-path `include_deleted` Rust gate (mirror desktop D.1.5); biometric re-auth before a write (policy decision first); Rust-core backlog **#193** (`pipeline.rs` refactor), **#192** (collision-population test).

**Open follow-up issues:** carried **#192 / #193 / #186 / #189 / #190 / #161 / #162 / #167**.

## (3) Open decisions and risks

- **Naming asymmetry** — `create_vault` (bytes, identity-level, B.3b) vs `create_vault_in_folder` (folder, complete vault). Accurate but uneven; the bytes form is left unchanged (additive only).
- **Mnemonic-only return, no auto-open** — deliberate (desktop parity). Slice 2 must create → show phrase → then `open_vault_with_password(folder)` to browse.
- **Thin bridge (caller supplies empty dir)** — the `mkdir`/subfolder UX is Slice 2's Swift job, exactly as desktop's `create_dir_all` lives in its Tauri command, not the bridge.
- **`VaultFolderNotEmpty` is a unit variant** (no path) — the bridge doesn't know the caller's path; platform layers that do (desktop create command; Slice 2 Swift) construct path-aware messages themselves.
- **The exhaustive-match obligation is wider than the bridge** — this session proved it spans `desktop/` and the Kotlin detail extractor too. Any future `FfiVaultError` variant must be verified with `cargo test --workspace` (catches the Rust sites incl. desktop) **and both** `run_conformance.sh` scripts (the Swift/Kotlin sites `cargo` can't see).

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — confirm / review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/ffi-folder-create-vault

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/ffi-folder-create-vault && git branch -D feature/ffi-folder-create-vault
git worktree prune && git worktree list

# 3) Next slice (iOS create wizard — Slice 2): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/ffi-folder-create-vault
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
( cd ffi/secretary-ffi-py && uv run --with pytest pytest -q )
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh && bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh && bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `7cfe13e`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `7cfe13e`; `feature/ffi-folder-create-vault` carries spec + plan + the 6-task implementation + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — see §1. No `core/src` / frozen-format change (the only `core/` touch is the `conformance_kat_helpers/errors.rs` test helper).
- **Process note:** executed inline (not subagent-driven) after the account spend-limit made subagent dispatch unreliable; spec+quality review folded into the per-task TDD loop (read every match site, verified placement, ran each layer's tests before committing). Two plan gaps caught + fixed (desktop `map_ffi_error`, Kotlin `vaultExceptionDetail`).
- **README.md / ROADMAP.md:** updated — FFI folder-writing create_vault ✅.
- **NEXT_SESSION.md:** symlink retargeted to this file.
