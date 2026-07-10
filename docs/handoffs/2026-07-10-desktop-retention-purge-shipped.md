# NEXT_SESSION.md — Desktop retention + per-block purge UX ✅ SHIPPED (PR opening)

**Session date:** 2026-07-10. Ships the **desktop (Tauri 2) UX for the #399/#402 trash-purge FFI**: "Run retention now" (two-step preview → commit), per-block "Delete forever", and a configurable retention-window vault setting. Branch `feature/desktop-retention` cut from `main` @ `1b769706` (after #406 merged). Full design-first flow: brainstorm → spec → plan → subagent-driven execution (9 tasks, fresh implementer + task-reviewer per task, opus whole-branch review). Worked in isolated worktree `.worktrees/desktop-retention/`. **FFI-consuming UI slice — no `core` / crypto / on-disk-format change; no new `FfiVaultError` / `AppError` variant; `#![forbid(unsafe_code)]` intact.**

## (1) What we shipped this session

The #402 core + #406 FFI slices deliberately deferred the platform surface. This slice closes the desktop half of that surface. The desktop backend consumes `secretary-ffi-bridge` **directly** (in-process, no pyo3/uniffi), so three new Tauri commands call the bridge natively.

**Three destructive trash operations, wired end-to-end:**
1. **Run retention now** — a two-step dialog (`RetentionDialog.svelte`): on open, `preview_retention` → `expired_trash_entries` shows "N items trashed more than X days ago will be permanently deleted (oldest: Y days)"; a danger "Purge N items" confirm runs `run_retention` → `auto_purge_expired`. Empty preview → "Nothing to purge", Close only.
2. **Delete forever** — a per-row action in `TrashView.svelte` → the shared `ConfirmDialog` (block name in the body) → `purge_block`.
3. **Configurable retention window** — a new `retention_window_ms` vault setting (days in the UI; default 90 = bridge `DEFAULT_RETENTION_WINDOW_MS`, bounds 1–3650 days), edited in `SettingsDialog`.

**Security properties (independently verified in the final opus review):**
- Both irreversible writes (`run_retention`, `purge_block`) go through the existing `authorizeWrite(...)` password re-auth gate, `ReauthCancelled` caught to abort. Enforced by the #280 static write-gate scanner (`writeGateCoverage` green).
- **Arg-order integrity**: `auto_purge_expired(identity, manifest, window_ms, now_ms, device_uuid)` — `window_ms` from settings, `now_ms` from `auto_lock::now_ms()`; and `purge_block(…, block_uuid, device_uuid, …)`. Both have same-`u64`/same-`[u8;16]` swap hazards that compile silently — confirmed correct in shipped code and empirically test-covered (a swap flips a real assertion).
- Error mapping stays **exhaustive** (no `_` catch-all); retention/purge bridge errors (`CorruptVault`/`FolderInvalid`/`SaveCryptoFailure`/`BlockNotInTrash`) all map through existing `map_ffi_error` arms → **no new variant**.
- **No secret widening**: the new DTOs (`ExpiredEntryDto`/`RetentionReportDto`/`PurgeReportDto`) project only UUID-hex, counts, timestamps — no plaintext. (The block name in the "Delete forever?" confirm comes from the pre-existing `TrashedBlockDto`.)
- Retention-window edits are **not** behind the `reducesProtection` re-auth gate — widening only delays discarding ciphertext (not a security reduction); the gate stays scoped to genuine reductions.

### Branch commits (off `main` @ `1b769706`, in order)
- `d803b2ad` design · `7b671fd9` plan
- `71b0ebdd` T1 `retention_window_ms` setting + bounds (constant is a bridge re-export → no drift)
- `370c40b8` T2 project field through `SettingsDto`/`SettingsInput` (closes a Task-1 interim `..default()` reset gap; round-trip test with a non-default window)
- `7992fb61` T3 retention/purge wire DTOs (hex UUID, camelCase)
- `23c84fbb` T4 `preview_retention` / `run_retention` / `purge_block` commands + `generate_handler!` wiring
- `05dca06e` T5 frontend constants (mirror backend) + pure `retention.ts` helpers
- `3b3459e9` T6 IPC wrappers + write-gate classification + TS `SettingsDto` field
- `2de8ca3f` T6 review fix — add `retentionWindowMs` to 9 settings test mocks (required-field type-check)
- `61f586e5` T7 `RetentionDialog` two-step preview+commit
- `7fe2f21d` T8 TrashView "Run retention now" button + per-block "Delete forever"
- `a9aba49c` T9 configurable retention window in Settings (svelte-check → 0 errors)
- `b57d7362` final-review fixes — `purge_block` arg-order guard comment + `PurgeReportDto` None-serde test
- `d048c77d` docs — README + ROADMAP
- → then this handoff commit.

### Acceptance (all verified green this session, from the worktree root)
```bash
cargo fmt --all -- --check                                        # clean
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo test --release --workspace                                  # 0 failed
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace        # clean
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh  # pass
cd desktop && pnpm test                                           # 624/624 (78 files)
cd desktop && pnpm exec svelte-check                              # 0 errors / 0 warnings
```

**Final opus whole-branch review: Ready to merge = Yes; 0 Critical / 0 Important.** It independently verified: both same-type arg-order hazards correct + test-covered; both destructive paths write-gated; exhaustive error mapping / no new variant; settings field genuinely round-trips (non-default window, `assert_ne!` guard); no secret widening; writeCommands ↔ generate_handler ↔ ipc.ts name consistency. The two actionable Minors it raised were fixed in `b57d7362`.

**Filed follow-up:** [#408](https://github.com/hherb/secretary/issues/408) — the #280 write-gate static scanner is comment-naive (a `runRetention()`/`purgeBlock()` mention *inside a src comment* trips it). Currently mitigated with inline "don't write `wrapper(` in a comment" warnings; #408 asks to make the scanner comment-aware and remove the workarounds.

## (2) What's next

1. **Empty-trash desktop UX (the natural sibling slice):** wire `empty_trash` ("Delete all trash now") into TrashView — the one trash destructive op this slice deferred. **Acceptance:** a "Empty trash" button → confirm showing the total count → `empty_trash` bridge call → report `purged_count`; same write-gate + a new `empty_trash` Tauri command classified in `writeCommands.ts`. Small slice — the DTO/command pattern is now established (`dtos/retention.rs`, `commands/retention.rs`).
2. **iOS + Android retention/purge UX (native over uniffi):** the FFI (`default_retention_window_ms()` / `expired_trash_entries` / `auto_purge_expired` / `purge_block`) is already projected on uniffi. Mirror this desktop flow: preview dialog (count + oldest age) → commit; per-block delete-forever; a per-platform retention-window setting. File one slice per platform.
3. **#408** (write-gate scanner comment-naivety) — make the scanner strip comments before matching, then drop the inline workaround warnings in `RetentionDialog.svelte`/`TrashView.svelte`. Add a fixture proving it still fires on a genuinely ungated call.
4. **Housekeeping (carried):** #387 (`:kit` NewApi lint — `StrongBoxUnavailableException` needs `@RequiresApi(28)`/baseline), #290 (`spec_test_name_freshness.py` D.4 false-positives), #383 (drop RUSTSEC-2026-0194/0195 from `.cargo/audit.toml` when `cargo tree -i quick-xml` shows a single ≥0.41).
5. **Manual GUI smoke (human-only, carried):** the #374 consent flow (`pnpm tauri dev` against a **temp copy** of a staged vault — [[feedback_smoke_test_temp_copy_golden_vault]]). Also worth an eyeball on the new retention/purge dialogs against a temp copy with staged old trash.
6. **Carried mobile (on-device / human-only):** iOS Face ID spot-check; Android #338 on-device biometric cloud-open, #331 SAF custom-ROM, #334 native cloud-provider epic (ADR + threat-model first).

## (3) Open decisions and risks

- **Caller-supplied window + `now_ms` everywhere** (no scheduler in core/bridge/bindings; the desktop reads the window from vault settings and `now_ms` from `auto_lock`). All retention is caller-invoked — there is no open-time auto-purge. Automatic periodic purge remains a deferred ADR + threat-model decision (when is it safe to auto-discard ciphertext), not a code change.
- **`SettingsInput.retention_window_ms` is mandatory** (no serde default) on both the Rust and TS side — a settings save that omits it fails deserialization. This is by design (mirrors the other three settings fields) and is why the TS field + all settings mocks were updated in-branch; it round-trips correctly against the real backend.
- **TS↔Rust constant mirror**: `RETENTION_WINDOW_DEFAULT_MS` is a hand-copied literal in `constants.ts` while Rust re-exports the bridge const — the established "change both" convention for every desktop constant (no cross-language pin test exists for any of them). Reviewer flagged the retention default now has a live upstream source, making its drift asymmetric; accepted as consistent with siblings.
- **No new `FfiVaultError`/`AppError` variant / no `manifest_version` bump / no crypto / KEM / signature-site / equal-clock change. `#![forbid(unsafe_code)]` intact.**

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, drop the branch + its worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/desktop-retention && git branch -D feature/desktop-retention
git worktree list && git status -s
# Re-run the desktop retention suite any time (from the worktree while the branch is live):
cargo test --release -p secretary-desktop 2>&1 | tail -15 \
  && cargo clippy --release --workspace --tests -- -D warnings \
  && (cd desktop && pnpm test && pnpm exec svelte-check)
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/desktop-retention` (worktree `.worktrees/desktop-retention`). 15 branch commits (design + plan + 9 task commits incl. 1 task-review fix + 1 final-review fix + docs + this handoff).
- **Acceptance:** full workspace green; clippy `-D warnings`, `cargo fmt -- --check`, rustdoc `-D warnings` clean; lean-binding pass; desktop `pnpm test` 624/624; `svelte-check` 0/0. Final opus review: 0 Critical / 0 Important; actionable Minors fixed.
- **Follow-up still open:** empty-trash desktop UX; iOS/Android retention/purge UX (file per platform); #408 (scanner comment-naivety); #387/#290/#383 housekeeping.
- **README / ROADMAP:** updated (desktop retention/purge UX shipped; iOS/Android + empty-trash deferred).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-10-desktop-retention-purge-shipped.md`.
