# NEXT_SESSION.md — Android cloud-drive provisioning, Slice 6 (instrumented E2E + #327) ✅ SHIPPED (PR opening) — EPIC #321 COMPLETE

**Session date:** 2026-06-28. Executed the **final slice (6/6)** of the **Android cloud-drive vault-provisioning epic** ([#321](https://github.com/hherb/secretary/issues/321)), resuming from the Slice-5 baton (Slice 5, PR #326, merged @ `d7ba7b8`). This session shipped **the instrumented E2E + offline/conflict test suite over REAL SAF on a real device, plus the #327 offline-create data-loss fix**. With this, **epic #321 is complete** — Android can open/create a vault in a cloud-drive folder via the SAF working-copy shim, proven end-to-end. Executed subagent-driven (fresh implementer per task → spec+quality review per task → fix loop → whole-branch opus review → cosmetic fix wave) in project-local worktree `.worktrees/android-cloud-drive-slice6-instrumented-e2e`, branch `feature/android-cloud-drive-slice6-instrumented-e2e` (cut from `main` @ `d7ba7b8`). **Kotlin/Android only — no core `src/`, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change** (conformance stayed 27/27 Kotlin + Swift).

## (1) What we shipped this session

**The #327 fix (offline-create data-loss gap)** — two load-bearing parts that compose:
- **`VaultMirror.materialize()` refuses to pull from a manifest-less cloud** (`android/vault-access/.../mirror/VaultMirror.kt`): when the cloud lacks `manifest.cbor.enc` but the working copy has one, materialize is a no-op (returns empty `MirrorReport`, deletes nothing). This is the **true backstop** — an empty/never-pushed cloud can never clobber an un-pushed (offline-created) vault, independent of marker state. No false-positive on a legitimate first-open (cloud HAS a manifest → normal pull), regression-guarded.
- **`createThenOpen` verify-after-set escalation** (`VaultWorkingCopyCoordinator.kt`): on a failed offline-create push it sets the marker, re-checks `isSet()`, and throws the new typed `PendingFlushNotPersisted(uuid, cause)` when the marker could not persist. `:app` (`CloudVaultOpen.kt`, pure host-testable `cloudOpenFailureRoute` helper) handles it distinctly and **preserves `isCreate=true`** so a reopen never materializes. `PendingFlushMarker.set()` stays best-effort; `afterCommit` still never throws.
- **Why #327 is real (corrected mid-session):** the offline-created vault IS persisted as a remembered location *before* its first push (`VaultProvisioningViewModel.create` "persist BEFORE mnemonic" + `recordSelection` at `onAcknowledge`), so the **selection-screen Open route** (`openExisting → materialize`) is reachable and the pending-flush marker is **load-bearing**. (My initial spec claim that it wasn't persisted was wrong; corrected in commit `7f4a31a`.)

**Instrumented test suite over REAL SAF (real `.so` + real `content://`):**
- **`TestCloudDocumentsProvider`** (`:kit` androidTest) — a temp-dir-backed `DocumentsProvider` + `TestCloudTree.install(context) → TreeHandle(treeUri, rootDir)` with fault injection (`failWritePaths`/`failCreatePaths`/`deleteReturnsFalsePaths`, `"*"` wildcard). Drives the real SAF stack (`DocumentFile.fromTreeUri`, `ContentResolver "wt"`, `DocumentsContract`) deterministically, no interactive picker. **On-device truths learned:** a `DocumentsProvider` MUST be `exported="true"` + `android:permission="android.permission.MANAGE_DOCUMENTS"` (system-only gate; cannot be `exported="false"`), needs an `isChildDocument` override, and a non-empty root doc id (`"root"`).
- **`SafCloudFolderPortInstrumentedTest`** — the on-device-only factory branches: nested dir walk+create, `findOrCreate` overwrite (delete-then-create + `"wt"` truncation), `deleteFile`-returns-false guard ("cannot delete"/"cannot overwrite"), idempotent delete-of-absent.
- **`CloudWorkingCopyLifecycleInstrumentedTest`** — create→flush→materialize→open round-trip, AND the **#327 offline-create-no-clobber** proof (push faulted + marker pointed at an unwritable path → `PendingFlushNotPersisted` → working vault survives a reopen over the manifest-less cloud).
- **`TwoWorkingCopiesConflictInstrumentedTest`** — **full-content convergence**: two working copies append disjoint records (`[0xAA]`/`[0xBB]`, distinct device UUIDs), forked through real SAF as **both** a `.sync-conflict-from-device-b` manifest sibling AND block sibling (a manifest-only sibling silently drops the peer edit — verified by an on-device RED), merged by the native `sync` FFI (`MergedClean`), asserting identical `{recordUuid→field}` on both sides incl. B's record visible on side A. Non-obvious pivot: the `SyncState` must be seeded so the relation is **Concurrent** (not Ahead) to trigger ingest.

**Verification:** host gate green (`:vault-access:test` + `:kit:testDebugUnitTest` + `:app:testDebugUnitTest` + both `:app` compile targets); Rust `fmt --check` + `clippy -D warnings` clean; Kotlin + Swift conformance **27/27**; instrumented **56/56 on the emulator** (incl. the 7 Slice-4 screen tests — `VaultSelectionScreenUiTest` 3/3, `CreateVaultWizardScreenUiTest` 4/4); **all `:kit` real-`.so`/SAF instrumented tests pass on BOTH the emulator and the real RedMagic 11 Pro** (serial `912607710061`). README.md + ROADMAP.md updated (epic complete, accurately scoped).

**Whole-branch review (opus): READY TO MERGE** — 0 Critical, 0 Important; the #327 fix verified to compose correctly (materialize guard = backstop, escalation = user signal); the convergence test verified non-vacuous. Cosmetic minors all cleared in `cfef58d` and re-verified (host green + 8/8 instrumented on emulator). **Zero technical debt.**

**Branch commits** (off `main` @ `d7ba7b8`):
| SHA | What |
|---|---|
| `f0a7bb7` | docs: slice-6 design |
| `7f4a31a` | docs: correct #327 analysis — marker is load-bearing |
| `1763094` | docs: slice-6 plan + spec refinements |
| `a329d7a` | fix: `createThenOpen` escalates `PendingFlushNotPersisted` (#327) |
| `50cf31e` | fix: `materialize` refuses manifest-less-cloud pull (#327) |
| `abb83d7` | fix: `:app` handles `PendingFlushNotPersisted` distinctly (#327) |
| `8bda42b` | test: test-only `DocumentsProvider` over a temp dir |
| `6fb8c24` | fix: test provider `"wt"` truncates via O_TRUNC; KDoc |
| `dcaec39` | test: instrumented `SafCloudFolderPort` factory branches |
| `0b376b4` | test: instrumented working-copy lifecycle + offline-create no-clobber (#327) |
| `35ce534` | test: two working copies converge to identical merged content |
| `38083ed` | docs: epic complete — README/ROADMAP |
| `cfef58d` | test: clear final-review cosmetic nits |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-slice6-instrumented-e2e
cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings   # clean
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh   # 27/27
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh    # 27/27
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :app:testDebugUnitTest \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin                            # green
# Instrumented (emulator authoritative; :kit also green on RedMagic 912607710061):
ANDROID_SERIAL=emulator-5554 ./gradlew :kit:connectedDebugAndroidTest :app:connectedDebugAndroidTest  # 56/56
```

## (2) What's next
**Epic #321 is COMPLETE.** Android now has open-existing + create-in-cloud parity with iOS, proven end-to-end. Candidate next steps (pick at brainstorm; all are deferred items from this epic's specs):

1. **Cloud-vault device enrollment + biometric write-reauth.** The cloud path currently uses `NoopReauthGate` (device-secret enrollment is only against the demo/local vault). *Acceptance:* enroll a device secret against a cloud working copy; a `GraceWindowReauthGate` gates writes with a real biometric prompt over a cloud vault; host-tested coordinator + on-device biometric proof.
2. **Vault-shape probe before `recordSelection`** (iOS has `looksLikeVault`). *Acceptance:* a SAF folder that is not a vault is rejected at pick time with a typed error, before any materialize; host + instrumented test. (treeUri-keying already makes a wrong pick non-destructive; this is a UX guard.)
3. **[#327 follow-up already absorbed]** — the `FilePendingFlushMarker.set()` silent-failure path is now backstopped by the materialize guard + escalation; #327 closes with this PR.
4. **Interactive-picker + `takePersistableUriPermission` UiAutomator E2E** (lowest priority; deliberately deferred for picker flakiness). *Acceptance:* one UiAutomator test driving the real system document-tree picker over the emulator's `ExternalStorageProvider`, proving the genuine persistable-grant round-trip.

## (3) Open decisions and risks
- **`:app` Compose-UI instrumented tests fail on the RedMagic 11 Pro (Android 16)** with "No compose hierarchies found" (`createComposeRule` harness timeout). **Pre-existing, device/harness-specific, NOT introduced by this slice** — they pass on the emulator (35/35). Every test *this slice delivers* (all `:kit` real-`.so`/SAF) passes on **both** devices. Low risk; if you run instrumented `:app` Compose tests, use the emulator. Possibly worth a tracking issue if the RedMagic becomes a primary test target.
- **Cloud path still `NoopReauthGate`** (see next-step #1) — an un-enrolled `GraceWindowReauthGate` behaves identically today; revisit when cloud-vault device enrollment lands.
- **The interactive picker + persistable-grant** is exercised only in manual use + the Slice-2 wiring, not instrumented (next-step #4).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/android-cloud-drive-slice6-instrumented-e2e && \
#   git branch -D feature/android-cloud-drive-slice6-instrumented-e2e
git worktree list && git status -s
# Epic #321 is complete. Pick the next item (see §2): cloud-vault biometric reauth (#1) is the
# most impactful. brainstorm → plan → subagent-driven execute. Android toolchain on this machine:
# emulator-5554 + a real RedMagic 11 Pro (serial 912607710061) connect; adb/emulator need absolute
# paths (~/Library/Android/sdk/platform-tools/adb); logcat is blocked on the RedMagic (production device).
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-cloud-drive-slice6-instrumented-e2e` (13 commits + handoff). Worktree `.worktrees/android-cloud-drive-slice6-instrumented-e2e`. **Epic #321 complete; #327 fixed (closes on merge).**
- **Acceptance:** Rust fmt + clippy clean; conformance 27/27 both; host gate green; instrumented 56/56 on emulator incl. Slice-4 screens; `:kit` real-SAF suite green on both emulator + RedMagic. Whole-branch review (opus) READY TO MERGE; cosmetic minors cleared.
- **README.md / ROADMAP.md:** updated (epic complete, scoped). **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-28-android-cloud-drive-slice6-instrumented-e2e-shipped.md`.
