# NEXT_SESSION.md — D.1.3 ✅ vault create wizard (first write slice)

**Session date:** 2026-05-29 → 2026-05-30 (D.1.3 — the third Sub-project D feature slice, built on the D.1.1 skeleton + D.1.2 browse). Authored spec + plan, then executed all 6 implementation tasks via subagent-driven development (fresh implementer per task + two-stage spec/quality review after each + a final whole-branch review).
**Status:** D.1.3 ✅ complete on branch `feature/d13-create`; **PR pending** (see §(4)). All automated gates green. The one human gate left is the **manual GUI smoke** (§(3)) — it cannot run headless.

## (1) What we shipped this session

A user with **no vault** can now create one from the desktop app: open the wizard (from the empty state, or via the now-actionable D.1.1 "Not a vault" hint) → choose a folder (empty, or offered a subfolder if non-empty) → set a display name + password + confirm → create (one Argon2id pass) → see the 24-word recovery mnemonic (copy + acknowledge) → land back on Unlock with the new path pre-filled + a "Vault created" banner → unlock into the empty vault. This is the **first write path** in Sub-project D. It also **closes the D.1.1 plain-`String` password carry-forward**: the IPC password boundary is now a zeroize-typed `Password` newtype (create **and** retrofit unlock).

All commits are on `feature/d13-create` (branched from `main` @ `2a35a04`; the spec + plan ride on the same branch, so the ship PR carries everything):

| Commit | What it landed |
|---|---|
| `a58b5b9` | D.1.3 design spec (`docs/superpowers/specs/2026-05-29-d13-create-vault-design.md`, 16 sections, mirrors D.1.2) |
| `96df942` | D.1.3 implementation plan (`docs/superpowers/plans/2026-05-29-d13-create-vault.md`, 6 tasks) |
| `8587456` | **Task 1** — `secret_arg.rs` `Password` newtype (zeroizing `Deserialize`) + retrofit `unlock_with_password` shell (the `*_impl` keeps `&[u8]`, untouched) + `dtos/create.rs` (`CreateVaultDto`/`CreateTargetProbeDto`, camelCase, serde-pinned). |
| `916fe8a` | **Task 2** — typed `AppError::VaultFolderNotEmpty { path }` + `VaultCreateFailed { detail (skip) }` + wire tests. |
| `7925592` | **Task 3** — `create_vault` + `probe_create_target` IPC commands (thin shell + `*_impl`) wrapping core's atomic `vault::create_vault` orchestrator; `rand_core 0.6` dep for a compatible `OsRng`; 5 L3 tests (tempdir, runtime-random password, re-open round-trip). |
| `7d13b7d` | **Task 3 review fix** — redact `Debug` on `CreateVaultDto` (the mnemonic field) to match the `Mnemonic`/`CreatedVault` precedent. |
| `2e895c8` | **Task 4** — frontend `ipc.ts` (`createVault`/`probeCreateTarget` + DTO interfaces) + `errors.ts` (2 codes + messages) + `lib/route.ts` (pre-unlock `appRoute` store, kept out of the session state machine). |
| `7590d95` | **Task 4 review fix** — tighten a tautological `createVault` assertion + cover the no-arg `openCreateWizard()` path. |
| `105066a` | **Task 5** — pure `lib/create.ts` (step machine + `passwordsMatch`/`joinSubfolder`/`groupMnemonicWords`) + `FolderStep`/`CredentialsStep`/`MnemonicStep` + `CreateVault.svelte` host. |
| `d272729` | **Task 5 review fix** — **fire** the pending clipboard-clear on `MnemonicStep` unmount (not just cancel it) so the recovery phrase can't be stranded in the OS clipboard, mirroring the D.1.2 `FieldRow` precedent; + FolderStep probe-race guard, `seedPath` comment, `onCreate` prop type, FolderStep cancel/subfolder tests, a `CreateVault` host test. |
| `0185c20` | **Task 6** — App routes to `CreateVault` on `appRoute==='create'`; Unlock turns the "Not a vault" hint into a "Create a vault here" button + shows the "Vault created" banner; README + ROADMAP mark D.1.3 ✅. |
| `1ea7c7c` | **Task 6 review fix** — make the "Vault created" banner strictly **one-shot** (Unlock consumes-and-clears `createdVaultPath` on mount; `cancelCreateWizard` clears it too) so it can't replay on a later unrelated unlock. |
| (ship) | this handoff + symlink retarget. |

**Process note:** one worktree (`.worktrees/d13-create`, branch `feature/d13-create`), one reviewed commit per task + an inline review-fix commit where a finding warranted it (every finding fixed before proceeding — Task 3 Debug-redaction, Task 4 test-rigor, Task 5 clipboard-unmount, Task 6 one-shot banner). Same rigor as the D.1.2 run.

### Automated gauntlet (final whole-branch review, run fresh on `feature/d13-create`)

```
Rust:        PASSED 1081 FAILED 0 IGNORED 10   (+12 over the D.1.2 baseline of 1069)
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS

Frontend:    Vitest 270 / 0 (29 files; new: create, route, FolderStep, CredentialsStep,
             MnemonicStep, CreateVault, AppRoute, UnlockCreate + additions to ipc/errors)
pnpm typecheck      → clean
pnpm svelte-check   → 0 errors, 2 warnings (both intentional `state_referenced_locally`,
                      documented in-code: FolderStep seedPath + Unlock one-time prefill)
pnpm lint           → clean
```

### Secret-handling story (verified end-to-end by the final review — CLEAN, no leak path)

- **Password:** zeroize-typed at the IPC boundary (`Password(SecretBytes)`, `Deserialize` zeroizes the intermediate `String`); borrowed not cloned into core; dropped when the command shell returns. Frontend holds it only in `CredentialsStep` `$state`, cleared right after `onCreate`.
- **Mnemonic:** the **single** widening point (`CreateVaultDto.mnemonic`, redacting `Debug`); produced once by core, held only in `MnemonicStep` `$state`, dropped on unmount; the clipboard copy is write-only and the pending auto-clear is **fired on unmount**. Never stored in a route store, logged, or cached.
- **Logging:** the one `tracing::warn!(?e)` on a create failure logs a `VaultError` whose Display is structural (no secret bytes); its `detail` is `#[serde(skip_serializing)]` (stripped at the IPC seam, pinned by `vault_create_failed_detail_is_stripped`).
- **Honest limitation (spec §13, in `secret_arg.rs` docs):** the `Password` wrapper zeroizes *our* copy; it cannot wipe `serde_json`'s own parse buffer. A bounded improvement over plain `String`, not a perfect end-to-end guarantee — the one item worth a human security glance on the PR, alongside the mnemonic widening point.

## (3) ⚠️ Manual GUI smoke — the user's pre-merge gate (NOT run this session; headless)

> **⚠️ Smoke against a TEMP path, never the git-tracked golden fixture.** See [[feedback_smoke_test_temp_copy_golden_vault]]. Create writes a brand-new vault, so just point it at a disposable temp path.

```bash
cd /Users/hherb/src/secretary/.worktrees/d13-create/desktop
pnpm install && pnpm tauri build --debug
./src-tauri/target/debug/secretary-desktop
```

Walk (spec §15): from the empty state (or point Unlock at a non-vault folder → click **"Create a vault here"**) → pick an empty folder, OR a non-empty one and accept the **subfolder** offer (type a name) → set display name + password + matching confirm (mismatch must disable Create) → **Create** → see the **24-word** mnemonic → **Copy** + paste elsewhere (matches) → tick **"I have written down my recovery phrase"** (Continue must stay disabled until ticked) → land on **Unlock** with the path **pre-filled** + **"Vault created"** banner → unlock with the **same password** → empty browse view. Re-run create into the now-non-empty folder → typed **"Folder isn't empty"** message. If any step fails it's a D.1.3 regression; don't merge until fixed. (The automated gauntlet is green, so a smoke failure would point at a real WebView/IPC/CSP/runtime issue the unit tests can't reach — exactly what the deferred L4 e2e #161 would catch automatically.)

## (2) What's next — D.1.4 (vault edit: add / edit records, the `save_block` write path)

D.1.3 creates an empty vault; D.1.2 reads existing ones. D.1.4 lets a user **add and edit records** — the `save_block` write path that mutates an existing manifest and writes blocks.

**Acceptance criteria (refine when authoring the D.1.4 plan — none exists yet):**
- An "add record" / "edit record" flow from the browse view: create a block / add a record with typed fields → `save_block` over the bridge → manifest + block written atomically → the browse view reflects the change.
- New IPC command(s) over the bridge's `save_block` surface; mirror the D.1.1/D.1.2/D.1.3 thin-command + `*_impl` + DTO-serde-pin + typed-`AppError` pattern. The `RecordFieldValue` zeroize-typing (`Text(SecretString)`/`Bytes(SecretBytes)`) must be preserved across the boundary.
- **Bridge `RecordInput.record_type` gap (#141) matters HERE** (it didn't for read/create) — check it before designing the field-input DTO.
- Reuse the zeroize-typed boundary discipline established in D.1.3 for any new secret-bearing inputs.
- Gauntlet: Rust +N (save_block IPC tests, ephemeral-tempdir vaults), Vitest +N (editor components); all type-checks clean. No magic numbers, files < 500 LOC, pure modules, random crypto in tests, manual smoke against a temp vault copy (NOT the golden fixture).

Author the D.1.4 plan first via `superpowers:brainstorming` → `superpowers:writing-plans`, mirroring how D.1.1/D.1.2/D.1.3 were structured.

## (3b) Open decisions and risks

- **Manual GUI smoke is the pre-merge gate** (§(3)). Until #161's L4 e2e lands, every D.1.x ship leans on a human walk-through.
- **Security-review surface for the PR:** the recovery-mnemonic widening point + the zeroize-boundary's documented `serde_json`-buffer limitation (spec §13). The final review found **no** other secret-leak path.
- **Post-create flow is "return to Unlock", not auto-open** (one Argon2id pass; password dropped immediately) — a deliberate UX/security choice, not a limitation.
- Carry-forwards, all still live: **#153** (re-migrate component styles off `theme.css` once Vite 6 `preprocessCSS` is fixed — D.1.3 added `.wizard*`/`.mnemonic-grid*` there), **#154** (emoji/glyphs → inline SVG before external release; D.1.3 adds a "Copied ✓" glyph in MnemonicStep), **#161** (L4 e2e harness deferred), **#162** (PathPicker e2e hook), **#141** (bridge `RecordInput.record_type` — **becomes load-bearing for D.1.4 edit**), **#144/#145/#158/#159** (unlock-time + auto-lock edge cases), **#164** (`Esc`-to-pop from D.1.2).
- **Two new intentional `state_referenced_locally` svelte-check warnings** (FolderStep `seedPath`, Unlock one-time prefill) — both documented in-code as deliberate one-time mount reads; accepted, not errors.

### Verified non-issues (don't re-investigate — checked this session)
- **`Password` deserialize coverage:** exercised by `secret_arg.rs` unit tests (`"hunter2"` → `b"hunter2"`), not through the live `invoke` path — consistent with the repo's deliberate `*_impl` test seam (the `#[tauri::command]` macro path needs the runtime; documented in `commands/mod.rs`). The contract is pinned; not a gap.
- **probe → create TOCTOU:** `probe_create_target` is an advisory UX hint; `create_vault_impl` re-checks emptiness authoritatively and returns the typed `VaultFolderNotEmpty` before any core call. Safe by design.
- **Banner/pre-fill momentary mismatch:** moot — Unlock fully remounts on the `appRoute` switch, so `folderPath` resets to `''` and the pre-fill + banner are consistent.
- **`WeakKdfParams` unreachable from the desktop:** both core's orchestrator and the bridge hardcode `Argon2idParams::V1_DEFAULT` (256 MiB ≫ the 64 MiB floor); the desktop never supplies custom KDF params. No UX/test built for an error that can't fire.

## (4) Exact commands to resume (D.1.4)

```bash
# Merge the D.1.3 PR first (feature/d13-create), then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.3 ship PR landed

# Re-baseline the automated gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED 1081 FAILED 0 IGNORED 10 (D.1.3 baseline)
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint && cd ..
# Expect: Vitest 270 passing

# Author the D.1.4 plan (none exists yet):
#   superpowers:brainstorming  → scope the add/edit-record (save_block) slice
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-05-29-d13-create-vault.md

# Then the first implementation worktree:
git worktree add .worktrees/d14-edit -b feature/d14-edit main
cd .worktrees/d14-edit/desktop && pnpm install
```

### Housekeeping (after the D.1.3 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d13-create 2>/dev/null && git branch -D feature/d13-create 2>/dev/null
git worktree prune && git worktree list
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open the next slice: author `docs/handoffs/<date>-d14-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `2a35a04`. `feature/d13-create` carries the spec + plan + 6 task commits + 4 review-fix commits + the ship commit (this handoff + symlink). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** Rust **1081 / 0 / 10**; clippy clean; fmt clean; conformance PASS; spec-freshness PASS; Vitest **270 / 0**; typecheck clean; svelte-check 0 errors / 2 intentional warnings; lint clean.
- **Final whole-branch review:** Ready to merge; secret-leak verdict CLEAN; capabilities/registration PASS (no new capability needed; both commands registered).
- **Manual §15 GUI smoke + L4 e2e:** NOT performed (headless). Manual smoke is the user's pre-merge gate (§(3)); L4 e2e deferred (#161).
- **README.md / ROADMAP.md:** D.1.3 marked ✅; D.1.4 next.
- **CLAUDE.md / `docs/adr/`:** unchanged (no format/architecture change — D.1.3 consumes the frozen core create orchestrator).
- **Issues filed this session:** none new.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.3 ship baton. The next slice opens with `docs/handoffs/<date>-d14-*.md`.
