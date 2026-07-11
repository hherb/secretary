# NEXT_SESSION.md — Android Trash browser ✅ SHIPPED (PR opening)

**Session date:** 2026-07-11. Ships the **native Android (Jetpack Compose) Trash browser** — the Android mirror of the iOS Trash browser (#412) and desktop reference (#409/#410), **minus** the retention-window *setting*. Branch `feature/android-trash-browser` cut from `main` @ `d235c592` (after #412 merged). Full design-first flow: brainstorm → spec → plan → subagent-driven execution (6 tasks, fresh implementer + task-reviewer per task, opus whole-branch review, two review-fix commits + re-review). Worked in isolated worktree `.worktrees/android-trash-browser/`. **Adds NO FFI (all trash/retention fns already on the Kotlin uniffi surface), NO `core`/crypto/on-disk-format change, NO new `VaultBrowseError` variant, NO `manifest_version` bump; `#![forbid(unsafe_code)]` intact. Touches only `android/` + docs.**

## (1) What we shipped this session

A native Android Trash browser, end-to-end, feature-parity with iOS #412:
- **List** all trashed blocks (name + "trashed yyyy-MM-dd"), newest-first.
- **Restore** (`restore_block`) and **Delete forever** (`purge_block`) per block — trailing icon buttons; delete behind an `AlertDialog` confirm.
- **Empty trash** (`empty_trash`) — top-bar action shown only when the list is non-empty; single confirm.
- **Run retention now** — a `ModalBottomSheet` previewing the expired set (`expired_trash_entries`) against the **fixed 90-day default** (`default_retention_window_ms`), then commits `auto_purge_expired`.
- Reached from a **"Trash" entry** on the browse (`BrowseWithSyncScreen`) surface.
- All destructive ops go through the **existing Android biometric `GraceWindowReauthGate`** (same instance the browse write path uses — no second FFI open, no new gate code); `previewRetention` is an ungated read. Reports are **discarded** (parity with iOS/desktop — the reloaded list is the success signal; purge-count surfacing is the cross-platform #411).

**Architecture (bottom-up, one concept per file):**
- **`:vault-access`** (pure, host-tested, JVM — no emulator): `TrashModels.kt` (value types + `TrashPort` interface, signed `Long`/`Int`), `TrashFormatting.kt` (pure helpers `msToDays` round-half-up / `sortTrashed` / `formatTrashedWhen` UTC `yyyy-MM-dd` / `emptyTrashConfirmBody` / `retentionSummary`, byte-parity with iOS/desktop), and `TrashBrowseModel.kt` (StateFlow VM mirroring `VaultBrowseModel.guardedWrite`: `_writing` before the gate await, `UserCancelled`→silent, `CancellationException` never caught, report discarded). Tests: `FakeTrashPort.kt` + `TrashBrowseModelTest.kt` (9 tests incl. a true `CompletableDeferred`-race re-entrancy test) + `TrashFormattingTest.kt`.
- **`:kit`** (real adapter): `UniffiVaultSession` now `: VaultSession, TrashPort` — the 7 overrides live **in the class body** (Kotlin can't conform via an extension file), reusing the existing `private` `sessionLock`/`wiped`/`write`/`mapErrors`/`identity`/`manifest` — **no member widened to `internal`** (stricter than iOS, which widened for its extension file). `BrowseMapping.kt`: `BlockNotInTrash`/`BlockPurged` → existing `VaultBrowseError.BlockNotFound` (no new variant); `BrowseMappingTrashTest.kt`.
- **`:browse-ui`** (Compose): `TrashScreen.kt` (icon-button rows + `AlertDialog` confirms + retention `ModalBottomSheet`; `TrashErrorBanner` mirrors `BrowseScreen.ErrorBanner`'s anti-leak message shaping) + thin `TrashBrowseViewModel.kt` bridge (mirror of `VaultBrowseViewModel`).
- **`:app`** (wiring): optional `BrowseSession.trash: TrashBrowseViewModel?` (built from the already-open session `as? TrashPort` + the same gate in `openBrowseWithSync` — cloud path inherits it free); `Route.Browse.showTrash`; a "Trash" `TextButton` (`testTag("open-trash")`) on `BrowseWithSyncScreen`; `AppRoot` renders `TrashScreen` guarded by `trash != null`.

### Branch commits (off `main` @ `d235c592`, in order)
- `8b48712f` design spec · `a0053a55` spec correction (Kotlin in-class conformance) · `0f7d5dcb` plan
- `b9e28b1d` T1 value types + `TrashPort` + formatting (host-tested; implementer caught a 3-day-off timestamp in the plan's test fixture and fixed it)
- `a67e6d39` T2 `TrashBrowseModel` + `FakeTrashPort` (gate parity, report-discard)
- `725abd88` T3 real `TrashPort` adapter (in-class, no widening) + trash-gone error mapping
- `fb706b20` T4 Compose `TrashScreen` + `TrashBrowseViewModel` bridge
- `ad70a018` T5 reach the Trash browser from the browse surface
- `26ce2885` T6 docs — README + ROADMAP
- `5e5bce72` final-review fix M4: force re-entrancy race on the write guard (`CompletableDeferred` writeGate)
- `3e42590f` final-review fix M7: friendly trash error banner instead of raw `toString()`
- `<this handoff commit>` handoff doc + symlink retarget

### Acceptance (all verified green this session, from the worktree root — daemon warmed)
```bash
cd android
./gradlew :vault-access:test                                  # host tests green (Trash* + all existing)
./gradlew :kit:testDebugUnitTest                              # 61/61 (incl. BrowseMappingTrashTest)
./gradlew :browse-ui:testDebugUnitTest :browse-ui:compileDebugKotlin   # green
./gradlew :app:testDebugUnitTest :app:assembleDebug          # green (cross-module gate + APK)
```
Consolidated final run: **`BUILD SUCCESSFUL`** across `:vault-access:test :kit:testDebugUnitTest :browse-ui:testDebugUnitTest :app:testDebugUnitTest :app:assembleDebug`.

**Final opus whole-branch review: Ready to merge = Yes; 0 Critical / 0 Important.** It independently proved all five security invariants against source: (1) no record plaintext crosses the FFI boundary for trash ops (only names/UUIDs/counts; no decrypt/expose call); (2) every destructive write is gated and `previewRetention`/`listTrashedBlocks`/`expiredTrashEntries` are provably ungated reads; (3) trash ops honor the same `sessionLock`+`wiped` guard as existing session ops with **no member widened to `internal`**; (4) no new FFI / no new `VaultBrowseError` variant / no format / no `manifest_version` change (branch confined to `android/`+docs); (5) `guardedWrite` never swallows `CancellationException` and `_writing` is set-before-await / reset-in-`finally`. Two deferred Minors (M4 race-test gap, M7 raw-`toString()` error banner) were **fixed this session** (`5e5bce72`, `3e42590f`) and re-reviewed clean; M1/M2/M3/M6/M8 were adjudicated No-change (contract-correct or consistent with existing patterns).

## (2) What's next

1. **Instrumented (emulator) androidTest pass for the Trash browser** — NOT run this session (no emulator on the box); the gates were the cross-module compile (`:app:assembleDebug`) + host unit tests. Security invariants don't depend on it (the gating/cancellation logic is host-proven in `TrashBrowseModel`; the Compose layer only forwards), but the wiring deserves one green round-trip. Acceptance: an instrumented test that taps the "Trash" entry (`testTag("open-trash")`), asserts `TrashScreen` renders the seeded trashed blocks, and exercises restore/delete-forever/empty/run-retention against a staged vault (mirror `BrowseScreenSoftDeleteTest`), behind the biometric gate stub. Run against a **temp copy** of a staged vault ([[feedback_smoke_test_temp_copy_golden_vault]]).
2. **Mobile retention-window *setting* (deferred half on BOTH iOS and Android):** project vault-settings read/write (`retention_window_ms`, currently NOT on uniffi at all — [[project_secretary_ios_settings_ffi_gap]]) + build a Settings screen on each platform (neither has one). Acceptance: a days-input setting (default 90, clamp 1–3650, mirroring desktop `SettingsDialog`) that the Trash retention preview/commit reads instead of the hard-coded `default_retention_window_ms()`. File as its own slice — a settings-subsystem introduction.
3. **#411** (destructive-trash post-op feedback) — surface actual purge counts ("Purged N items") from the report DTOs the `TrashPort` already returns (Android `PurgeResultInfo`/`EmptyTrashReportInfo`/`RetentionReportInfo` are plumbed and ready). UI-only, cross-platform (desktop + iOS + Android).
4. **#413** (locale-aware trashed-date vs UTC `yyyy-MM-dd`) — cross-platform with iOS; inject a timezone/formatter.
5. **#408** (write-gate scanner comment-naivety, desktop tooling) — strip comments before matching in the #280 scanner; add a fixture.
6. **Housekeeping (carried):** #387 (`:kit` NewApi lint), #290 (`spec_test_name_freshness.py` D.4 false-positives), #383 (drop RUSTSEC-2026-0194/0195 from `.cargo/audit.toml` when `quick-xml` is a single ≥0.41).

## (3) Open decisions and risks

- **Retention window is the fixed 90-day default on Android** (`default_retention_window_ms()`), not a per-vault setting — deliberate scope cut (see #2). The retention preview count is **indicative** (the bridge recomputes the target set at commit time) — same honest-count caveat as iOS/desktop; #411 is the cross-cutting fix.
- **`formatTrashedWhen` renders the tombstone day in UTC** (fixed `yyyy-MM-dd`) — same deliberate host-testable choice + same #413 caveat as iOS (a block trashed near local midnight can show the adjacent day).
- **`:kit` `TrashPort` conformance is in-class, no `internal` widening** — a Kotlin language constraint (can't conform via an extension file), which happens to keep the session handles fully `private` (stricter than iOS). Documented in the spec.
- **Instrumented androidTests not run this session** — the one real coverage gap; see next-step #1. Not a merge blocker per the opus review (host-proven security core), but should land soon.
- **No new `FfiVaultError`/`VaultBrowseError` variant / no `manifest_version` bump / no crypto / KEM / signature-site / equal-clock change. `#![forbid(unsafe_code)]` intact.** The bridge trash logic is unchanged (pure downstream consumption of the existing uniffi surface).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, drop the branch + its worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/android-trash-browser && git branch -D feature/android-trash-browser
git worktree list && git status -s
# Re-run the Android suite any time (from the worktree while the branch is live). Gradle host tests
# need no emulator; the :kit/:app builds trigger a Rust→JNI build that is multi-minute + silent on a
# cold daemon — warm it once, then incremental runs are seconds:
#   cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:testDebugUnitTest :app:assembleDebug
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-trash-browser` (worktree `.worktrees/android-trash-browser`). 12 branch commits (2 spec + plan + 6 task commits + 2 final-review fixups + this handoff).
- **Acceptance:** Android host + compile gates green (`:vault-access:test`, `:kit:testDebugUnitTest` 61/61, `:browse-ui`/`:app` compile, `:app:assembleDebug`); consolidated run `BUILD SUCCESSFUL`. Final opus review: 0 Critical / 0 Important; all 5 security invariants proven; M4+M7 fixed & re-reviewed clean.
- **Follow-up still open:** instrumented emulator androidTest pass; mobile retention-window setting (settings FFI + Settings screens, iOS+Android); #411 purge counts; #413 locale date; #408; #387/#290/#383 housekeeping.
- **README / ROADMAP:** updated (Android Trash browser shipped; retention-window setting + #411/#413 deferred; stale "Android deferred/mirror" claims on the desktop/iOS rows corrected).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-11-android-trash-browser-shipped.md`.
