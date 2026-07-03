# NEXT_SESSION.md — Desktop IPC path-binding (#353) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-03. Shipped the **last open deferral** from the 2026-07-02 pre-release audit: [#353](https://github.com/hherb/secretary/issues/353) — desktop Tauri IPC commands accepted arbitrary filesystem paths from the (potentially compromised) webview. Both 2026-07-02 audit deferrals are now closed (#350 shipped in PR #375; #353 here). Worktree `.worktrees/desktop-path-binding-353`, branch `feature/desktop-path-binding-353` (cut from `main` @ `cd6d530`). **Desktop-only — no change to `core/`, `ffi/`, on-disk format, KATs, or conformance.** Built via subagent-driven development (fresh implementer + task reviewer per task; opus for the final whole-branch review).

## (1) What we shipped this session

Backend-mediated dialogs bind every webview-supplied path argument to a path the user actually picked in a native, backend-invoked dialog. Three new `pick_*` commands open native dialogs from Rust, canonicalize the choice, and store it in a per-purpose slot on `VaultSession`; the five path-taking commands validate their argument against the matching slot before any filesystem work.

- **`path_auth.rs` security core** (`8e451b6`, `d2881e5`): pure, Tauri/`AppError`-free module — `PathPurpose{VaultFolder,ContactCard,ExportDir}`, `MatchMode{Exact,Containment}`, `PathApprovals` (per-purpose last-approved slot, `clear()` on lock). `canonicalize_for_auth` rejects any `..` component and resolves symlinks in the deepest *existing* ancestor (re-appending the not-yet-created tail); `is_contained` matches on component boundaries (`/a/vaults` ≠ `/a/vaults-evil`). Includes a real-symlink escape regression test.
- **`PathNotApproved` typed error** (`9f16230`): wire code `path_not_approved`, carries the offending path; frontend `errors.ts` maps it to a "pick again" affordance.
- **`VaultSession` approvals slot** (`37c1b61`): field independent of `inner` (reachable while locked — create/probe/unlock all run locked); `lock()` clears it. Pass-throughs `approve_path` / `is_path_approved`.
- **Backend `pick_*` commands** (`5890c24`, `063e2d6`): `pick_vault_folder` / `pick_contact_card` (`.card` filter) / `pick_export_dir` over `tauri-plugin-dialog` 2.7.1 `DialogExt::blocking_pick_*`; testable `pick_into_slot_impl` core (cancel → `Ok(None)`, stores nothing).
- **Frontend switch + capability removal** (`fd9fb55`): `PathPicker.svelte` invokes the backend picker (drops `@tauri-apps/plugin-dialog`); `dialog:allow-open` removed from `capabilities/default.json`; npm dep removed; 4 call sites + ipc wrappers + the #280 write-gate classification updated.
- **Five command gates** (`523d26b` unlock/Exact; `64f95a7` create+probe/Containment, both `*_impl`s gain `state`; `4d8953a` import+export/Exact). Each rejects an unapproved path before its `fs` op; import's check precedes the `fs::read` (closes the arbitrary-read oracle); probe's check closes the while-locked existence oracle.
- **Housekeeping** (`ee692b3` cargo fmt across cross-task rustfmt drift; `2041e1f`/`9f11e84` test strengthening; `a06427e` README/ROADMAP; `27a3527` corrected stale JS-dialog comments in `Cargo.toml`/`main.rs`).

**Verification.** Full workspace `cargo test --release --workspace` green; `cargo clippy --release --workspace --tests -- -D warnings` clean; `cargo fmt --all --check` clean; `cargo doc -D warnings` clean; `conformance.py` PASS (desktop-only, no format drift); `pnpm svelte-check` 0 errors; `pnpm test` 570/570. **Final opus whole-branch review: Ready to merge = With fixes** — 0 Critical/Important; the one actionable Minor (stale comments) was fixed (`27a3527`); two remaining items filed as follow-ups (#378, #379).

### Branch commits (off `main` @ `cd6d530`)
17 commits: `97e85e0`/`d52bb5b` (design + plan) → `8e451b6`…`4d8953a` (impl/test) → `ee692b3` (fmt) → `a06427e` (docs) → `27a3527` (comment fix). See `git log main..HEAD`.

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
cargo test --release --workspace                                  # 0 failures
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo fmt --all --check                                           # clean
cd desktop && pnpm svelte-check && pnpm test                      # 0 errors; 570 pass
```

## (2) What's next
#353 is complete. Follow-ups, roughly in priority order:

1. **Manual GUI smoke of the four dialog flows (the one thing automated tests can't cover).** `blocking_pick_*` is isolated in the untested `#[tauri::command]` shells. Run `cd desktop && pnpm tauri dev` against a **temp copy** of the golden vault (`cp -R core/tests/data/golden_vault_001 /tmp/smoke_vault_353` — never the tracked fixture) and confirm: (a) unlock → pick folder → unlock; (b) create → pick folder → "create a subfolder" → create; (c) Contacts → Export my card → pick folder; (d) Share → Import a contact → pick `.card`. Confirm the webview can no longer open a dialog on its own.
2. **[#378](https://github.com/hherb/secretary/issues/378)** — shared `VaultFolder` slot lets an unlock-pick authorize `create_vault` in a subfolder (Containment). Bounded (empty-vault write in a user-picked tree; no secret read/overwrite). Optional hardening: split into a distinct `PathPurpose::CreateParent` with its own picker.
3. **[#379](https://github.com/hherb/secretary/issues/379)** — `errors.rs` is 726 lines; split (enum / `map_ffi_error` / serde tests). Pre-existing; keep the `code` wire strings identical.
4. **[#374](https://github.com/hherb/secretary/issues/374)** — FFI projection of `repair_vault` + platform "repair now?" UX (carried from #350): bridge fn + typed-error surface (workspace exhaustive-match + Swift/Kotlin conformance obligation), desktop reference UX, crashed-share informed-consent path, device-secret-arm repair test.
5. **iOS on-device Face ID acceptance (#284/#347)** — still pending the physical iPhone 13 Pro Max walkthrough (no code); spot-check the multi-vault case (button absent for un-enrolled vault B). Flip the README/ROADMAP "pending" note if it passes.
6. **Carried Android items:** instrumented UI assertions (#341/#342, optional); #338 on-device biometric cloud-open proof; #331 SAF picker on custom ROMs; #334 native cloud-provider epic (ADR + threat-model first).

## (3) Open decisions and risks
- **Manual GUI smoke is the only unverified surface.** Every `*_impl` is unit/integration-tested; the native-dialog shells are not driveable headlessly. Low risk (the shells are thin: dialog → `into_path().ok()` → `pick_into_slot_impl`), but a human pass is the honest confirmation. See (2.1).
- **[#378] shared VaultFolder slot cross-intent** — filed, by-design, bounded. Not a path-binding bypass (no secret read/exfil; empty-folder check prevents overwrite; target confined to a user-picked tree). The opus review judged it acceptable to ship.
- **Approval lifecycle is "persist until lock", not one-shot** — deliberate: it makes the pick-on-unlock → create-wizard seed flow work, and is cleared on `lock()`. One-shot would be stricter but break that UX.
- **`spec_test_name_freshness.py` still fails on `main`** (3 pre-existing #290 threat-model false-positives). Not touched here.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/desktop-path-binding-353 && \
#   git branch -D feature/desktop-path-binding-353
git worktree list && git status -s
# Desktop acceptance: cargo test --release --workspace ; cd desktop && pnpm test && pnpm svelte-check
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink is retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/desktop-path-binding-353` (17 commits incl. this docs/handoff commit). Worktree `.worktrees/desktop-path-binding-353`. #353 resolved (PR carries `Fixes #353`).
- **Acceptance:** full workspace green; frontend green; conformance PASS; opus whole-branch review "Ready to merge: With fixes" — the one actionable Minor fixed, two items filed (#378, #379); 0 Critical/Important.
- **README / ROADMAP:** updated (both 2026-07-02 audit deferrals closed; #353 remediation recorded).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-03-desktop-path-binding-353-shipped.md`.
