# NEXT_SESSION.md — iOS Trash browser ✅ SHIPPED (PR opening)

**Session date:** 2026-07-11. Ships the **native iOS (SwiftUI) Trash browser** — the first of the mobile retention/purge/empty-trash slices, mirroring the desktop reference (#409/#410) minus the retention-window *setting*. Branch `feature/ios-trash-browser` cut from `main` @ `7fba706d` (after #410 merged). Full design-first flow: brainstorm → spec → plan → subagent-driven execution (7 tasks, fresh implementer + task-reviewer per task, opus whole-branch review). Worked in isolated worktree `.worktrees/ios-trash-browser/`. **Adds one FFI projection (`list_trashed_blocks` → uniffi + pyo3) + iOS UI; no `core` / crypto / on-disk-format change; no new `FfiVaultError` variant; no `manifest_version` bump; `#![forbid(unsafe_code)]` intact.**

## (1) What we shipped this session

The `list_trashed_blocks` bridge fn already existed but was **bridge-only** (used directly by desktop). This slice projects it onto both mobile bindings and builds a native iOS Trash screen on top of the already-projected retention/purge FFI (`expired_trash_entries` / `auto_purge_expired` / `purge_block` / `empty_trash` / `default_retention_window_ms`, live on uniffi since #402/#399).

**A native iOS Trash browser, end-to-end:**
- **List** all trashed blocks (name + "trashed <yyyy-MM-dd>"), newest-first.
- **Restore** (`restore_block`) and **Delete forever** (`purge_block`) per block — swipe/confirm actions.
- **Empty trash** (`empty_trash`) — toolbar button shown only when the list is non-empty; single confirm.
- **Run retention now** — a sheet that previews the expired set (`expired_trash_entries`) against the **fixed 90-day default** (`default_retention_window_ms`), then commits `auto_purge_expired`.
- Reached from a **"Trash" toolbar item** on `VaultBrowseScreen` (push-navigation).
- All destructive ops go through the **existing Face ID `GraceWindowReauthGate`** (grace-window parity with desktop — no new gate code); `previewRetention` is an ungated read. Reports are discarded (empty list = success signal, parity with desktop).

**Architecture (bottom-up, one concept per file):**
- FFI: `list_trashed_blocks` + `TrashedBlock` projected onto **uniffi** (`wrappers/trash.rs`, UDL dict + `[Throws=VaultError]` fn, namespace, re-exports) and **pyo3** (`trash.rs` `#[pyclass(frozen, get_all)]` + pyfn). Only `CorruptVault`/`FolderInvalid` — **no new `FfiVaultError` variant**, so the Swift/Kotlin `ConformanceErrors` harnesses are untouched.
- Pure FFI-free `SecretaryVaultAccess`: `TrashPort` protocol, value types (`TrashedBlockInfo` etc.), formatting helpers (`sortTrashed`/`emptyTrashConfirmBody`/`retentionSummary`/`msToDays`), and host-tested `TrashViewModel` (mirrors `VaultBrowseViewModel.reauthedWrite`: `isWriting` set before the gate await; refused re-auth aborts silently).
- Adapter `UniffiVaultSession: TrashPort` (`SecretaryKit`) reuses the existing `lock`/`wiped`/`deviceUuid`/`nowMs`/`mapVaultAccessError` machinery; `BlockNotInTrash`/`BlockPurged` mapped to `.blockNotFound` (no new `VaultAccessError` case).
- SwiftUI `TrashScreen` + `RetentionSheet` + `VaultBrowseViewModel.makeTrashViewModel()` factory (optional `trashPort`, nil-safe for existing browse tests).

### Branch commits (off `main` @ `7fba706d`, in order)
- `6c2c30b2` design spec · `82184436` plan
- `71c20940` T1 pyo3 projection + pytest
- `628b3590` T2 uniffi projection (+ Swift/Kotlin conformance 38/38)
- `878ed82b` T3 pure value types + `TrashPort` + formatting helpers
- `9f298396` T4 `TrashViewModel` + `FakeTrashPort` (host-tested; gate parity, report discarded)
- `c5b086ab` T5 `UniffiVaultSession` `TrashPort` adapter
- `2c5700d6` T6 SwiftUI Trash screen + browse entry point + composition wiring
- `d39c63b2` T7 docs — README + ROADMAP
- `7e4f4bb9` final-review fixups (msToDays round-half-up parity + formatTrashedWhen doc)
- `/review` fixups (this handoff commit): retention-sheet preview stale-flash (`clearPreview()` + `.onDisappear`), restore-path + adapter error-mapping (`BlockNotInTrash`/`BlockPurged`→`.blockNotFound`) test coverage, lock-discipline invariant note on the `internal` handle widening; UTC date-parity gap filed as #413. Verified green: pure `swift test` 225/225, `xcodebuild test -scheme SecretaryKit` 45/45, `build-app.sh` BUILD SUCCEEDED.

### Acceptance (all verified green this session, from the worktree root)
```bash
# Rust (unchanged after the uniffi commit 628b3590):
cargo test --release --workspace                                 # 0 failed
cargo clippy --release --workspace --tests -- -D warnings        # clean
cargo fmt --all -- --check ; RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace  # clean
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh  # pass
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh     # 38/38
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh    # 38/38
cd ffi/secretary-ffi-py && uv run maturin develop && uv run pytest tests/test_trash_restore.py  # 12/12
# iOS:
cd ios/SecretaryVaultAccess && swift test                        # 222/222, zero warnings
bash ios/scripts/build-xcframework.sh                            # regen bindings (exit 0)
(cd ios/SecretaryKit && xcodebuild test -scheme SecretaryKit -destination 'platform=iOS Simulator,name=iPhone 16')  # TEST SUCCEEDED 43/43
bash ios/scripts/build-app.sh                                    # BUILD SUCCEEDED
```

**Final opus whole-branch review: Ready to merge = Yes; 0 Critical / 0 Important.** It independently verified all five security invariants against source: (1) no record plaintext crosses the FFI boundary and the adapter adds no decrypt; (2) every destructive write is gated and `previewRetention`/`listTrashedBlocks` are provably ungated reads; (3) no new `FfiVaultError` variant / no format / no `manifest_version` change; (4) trash ops honor the same `NSLock`+`wiped` guard as existing session ops; (5) verbatim desktop copy parity. The two Minor findings (copy parity) were fixed in `7e4f4bb9`.

## (2) What's next

1. **iOS retention-window *setting* (the deferred half of this slice):** needs (a) projecting vault-settings read/write (`get_settings`/`set_settings`, or at least `retention_window_ms`) onto uniffi — **currently NOT projected at all** — and (b) a **Settings screen on iOS** (none exists today). Acceptance: a days-input setting (default 90, clamp 1–3650, mirroring desktop `SettingsDialog`) that the Trash retention preview/commit reads instead of the hard-coded `default_retention_window_ms()`. File as one slice; it's a settings-subsystem introduction, not a small add.
2. **Android trash-browser mirror (native Jetpack Compose over uniffi):** same feature as this iOS slice — `list_trashed_blocks` is now on uniffi (Kotlin) already, so no new FFI. Mirror the desktop/iOS flow: trash list → restore / delete-forever / empty-trash / run-retention-now against the 90-day default, behind the Android biometric write-reauth gate. iOS is now the mobile reference (`ios/SecretaryVaultAccess/.../TrashViewModel.swift`, `SecretaryKit/.../UniffiVaultSession+Trash.swift`, `SecretaryApp/.../TrashScreen.swift`).
3. **#411** (destructive-trash post-op feedback) — surface the actual purge counts ("Purged N items") from the `PurgeResultInfo`/`EmptyTrashReportInfo`/`RetentionReportInfo` the iOS `TrashPort` already returns (and the desktop DTOs already carry). UI-only, cross-platform; the iOS value types are already wired to carry the counts.
4. **#408** (write-gate scanner comment-naivety, desktop tooling) — strip comments before matching in the #280 scanner; add a fixture.
5. **Housekeeping (carried):** #387 (`:kit` NewApi lint), #290 (`spec_test_name_freshness.py` D.4 false-positives), #383 (drop RUSTSEC-2026-0194/0195 from `.cargo/audit.toml` when `quick-xml` is a single ≥0.41).
6. **Manual GUI smoke (human-only):** the iOS Trash browser on-device/simulator against a **temp copy** of a staged vault with old trash (settings live in the vault — [[feedback_smoke_test_temp_copy_golden_vault]]); iOS Face ID spot-check on the destructive ops.

## (3) Open decisions and risks

- **Retention window is the fixed 90-day default on iOS** (`default_retention_window_ms()`), not a per-vault setting — deliberate scope cut (see #2 above). The retention preview count is **indicative** (the bridge recomputes the target set at commit time) — same honest-count caveat as desktop; #411 is the cross-cutting fix.
- **`formatTrashedWhen` renders the tombstone day in UTC** (fixed `yyyy-MM-dd`), a deliberate choice to keep the pure helper host-testable without a fixed clock/zone. Trade-off (documented in-code): a block trashed within a few hours of local midnight can show the adjacent calendar day. Desktop uses a locale-aware short date. If this matters, inject a timezone/formatter in a later pass.
- **Two reviewer-blessed non-defect minors left as optional follow-ups:** the `write`/`writeTrashReturning`/`writeTrash` wrapper trio could collapse into one generic helper; `makeTrashViewModel()` allocates a throwaway VM per toolbar render (harmless — `@StateObject` latches, init does no I/O; mirrors the shipped `makeEditViewModel`).
- **No new `FfiVaultError`/`VaultAccessError` variant / no `manifest_version` bump / no crypto / KEM / signature-site / equal-clock change. `#![forbid(unsafe_code)]` intact.** The bridge trash logic is unchanged.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, drop the branch + its worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/ios-trash-browser && git branch -D feature/ios-trash-browser
git worktree list && git status -s
# Re-run the iOS suite any time (from the worktree while the branch is live). The xcframework
# build is multi-minute + silent — run it backgrounded with log-polling, not a blocking watchdog:
#   bash ios/scripts/run-ios-tests.sh
# Fast host-only iteration on the pure package (no xcframework):
#   (cd ios/SecretaryVaultAccess && swift test)
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/ios-trash-browser` (worktree `.worktrees/ios-trash-browser`). 10 branch commits (spec + plan + 7 task commits + final-review fixups + this handoff).
- **Acceptance:** Rust workspace green (clippy/fmt/rustdoc `-D warnings`, lean-binding, Swift+Kotlin conformance 38/38, pyo3 12/12); iOS pure package `swift test` 222/222; SecretaryKit `xcodebuild test` 43/43; app `build-app.sh` BUILD SUCCEEDED. Final opus review: 0 Critical / 0 Important; both Minor findings fixed.
- **Follow-up still open:** iOS retention-window setting (settings FFI + Settings screen); Android trash-browser mirror; #411; #408; #387/#290/#383 housekeeping.
- **README / ROADMAP:** updated (iOS Trash browser shipped; retention-window setting + Android mirror deferred).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-11-ios-trash-browser-shipped.md`.
