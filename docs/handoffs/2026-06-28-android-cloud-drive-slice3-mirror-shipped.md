# NEXT_SESSION.md — Android cloud-drive provisioning, Slice 3 (CloudFolderPort + VaultMirror) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-28. Resumed the **Android cloud-drive vault-provisioning epic** ([#321](https://github.com/hherb/secretary/issues/321)) from the Slice-2 baton. Slice 2 (`VaultLocationStore`, PR #322) had merged; this session shipped **Slice 3 of 6 — the SAF working-copy mirror mechanism**. Executed subagent-driven (fresh implementer per task → spec+quality review per task → whole-branch review) in project-local worktree `.worktrees/android-cloud-drive-mirror`, branch `feature/android-cloud-drive-mirror` (cut from `main` @ `59a45e15`). Kotlin/Android only. **No core `src/` change, no FFI surface change, no on-disk-format / spec / `conformance.py` / KAT change** (verified: branch diff touches only `android/` + the plan doc).

## (1) What we shipped this session

**Slice 3 — the mirror mechanism.** The shim that lets the Rust core (direct POSIX I/O, no storage seam) operate on a vault stored in a **path-less Android cloud-drive folder** (Drive/Dropbox/OneDrive, reachable only via SAF `content://`). The core operates on a real-filesystem **working copy**; this slice is responsible for *which bytes move between the working copy and the cloud folder, and in what order*. Merge stays entirely in the audited core — the shim only moves bytes. New package `org.secretary.mirror` across both modules.

- **Pure layer (`:vault-access`, package `org.secretary.mirror`, all host-tested):**
  - `sha256Hex(bytes)` — content hash (`java.util.HexFormat` + `MessageDigest`). The change-detection signal: a fresh nonce per block rewrite keeps byte *length* but changes content, so size alone can't detect change — content hash is the only reliable signal.
  - `CloudFolderPort` — `list()/read()/write()/delete()` over a vault-relative-POSIX-path keyed folder; typed `CloudFolderException` boundary (mirrors `DeviceUuidException`). **`delete` is idempotent-on-absent by contract.**
  - `VaultMirrorPlanner` — **the pure heart.** `planMirror(source, dest): List<MirrorOp>` over two `Map<String, FileFingerprint(size, sha256)>`; `MirrorOp = Copy | Delete`; `const val MANIFEST_FILENAME`. **Block-first ordering (vault-format §9):** non-manifest copies → manifest copy **last** → deletes **after all copies**. So a destination is never left with a manifest referencing a not-yet-written block, nor a still-referenced block deleted before the superseding manifest lands — only recoverable intermediate states.
  - `VaultMirror` orchestrator — `materialize(workingDir)` (cloud→working) / `flush(workingDir)` (working→cloud), same planner both directions (source/dest swap). Working copy via `java.io.File`/nio (the `DeviceUuid` precedent), cloud via the port; **stateless content-hash diff** (the local-sidecar flush optimization is consciously deferred to Slice 5). One typed `VaultMirrorException` boundary folding both working-copy `IOException` and `CloudFolderException`. Returns `MirrorReport(copied, deleted)`. In-memory `FakeCloudFolderPort` test double (records mutating-call order + fault injection) lives in `src/test`.
- **Real adapter (`:kit`, package `org.secretary.mirror`):** `SafCloudFolderPort` — seam-structured **exactly** like `SafVaultLocationStore`: the class body holds **zero Android types** (four function seams), so delegation + error-folding is host-tested with fakes; all DocumentFile/ContentResolver traversal (recursive `walk`, path-segment `resolve`/`findOrCreate`, overwrite) lives only in the `safCloudFolderPort(context, treeUri)` factory — the one Android-bound piece, deferred-tested to Slice 6's instrumented E2E. Added `androidx.documentfile:documentfile:1.0.1`.

**TDD throughout (subagent-driven).** Per-task: implementer (RED→GREEN→commit) → spec+quality review → fix loop where needed → mark complete. Test counts: `ContentHashTest` 4, `VaultMirrorPlannerTest` 11, `FakeCloudFolderPortTest` 6, `VaultMirrorTest` 11, `SafCloudFolderPortTest` 6.

**Reviews & fixes.** Tasks 1–3 reviewed clean. **Task 4** (sonnet review) found 3 Important, all fixed (`e9ac075b`): working-copy `deleteWorking` was swallowing `File.delete()`'s `false` → switched to `Files.deleteIfExists` (no-op on absent, throws on real failure → folds to `VaultMirrorException`); added a materialize block-first ordering test; added a *deterministic* IOException-folding test (pre-create a regular file where a directory must go). **Task 5** (sonnet review) found 2 Important: (1) `"wt"` openOutputStream mode flagged as "invalid" — **adjudicated as a false positive** (`"wt"` = write+truncate is a documented `ContentResolver` mode; kept it, added a clarifying comment); (2) SAF `delete()` returning `false` on a *present* file was swallowed → now throws `CloudFolderException` while keeping idempotent-on-absent (`902c8e3e`). **Whole-branch review (opus): Ready to merge — Yes**, no Critical/Important; 4 Minors, all deferred-by-plan (perf/streaming/sidecar, push-before-pull wiring) or confirmed-correct boundaries. **Post-open `/review` follow-up:** `findOrCreate`'s overwrite-delete still swallowed `delete()==false` (the same divergence class Task-5 fixed for `deleteFile`, but on the factory's overwrite path) — now throws `CloudFolderException` on a failed delete of a present file, symmetric with the `deleteFile` seam.

**Branch commits** (off `main` @ `59a45e15`):
| SHA | What |
|---|---|
| `65c200f0` | docs: slice-3 plan |
| `3d3fbda3` | feat: `sha256Hex` content hash |
| `1aedef42` | feat: pure `VaultMirrorPlanner` (block-first) |
| `8968ea79` | feat: `CloudFolderPort` seam + in-memory fake |
| `75bb45f7` | feat: `VaultMirror` orchestrator (materialize/flush) |
| `e9ac075b` | fix: surface working-copy delete/IO failures + test materialize ordering (Task-4 review) |
| `86f42dad` | feat: `SafCloudFolderPort` SAF adapter + factory (`:kit`) |
| `902c8e3e` | fix: surface real SAF delete failures + document `wt` write mode (Task-5 review) |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-mirror/android
./gradlew :vault-access:test          # host — ContentHash/Planner/Fake/VaultMirror suites green (32 mirror cases)
./gradlew :kit:testDebugUnitTest      # host — SafCloudFolderPort seam suite 6/6 green
```
No emulator/device needed this slice.

## (2) What's next
**Slice 3 is done (PR open). Continue the epic with Slice 4.** Each slice is its own plan + PR through the review loop. Remaining slices (from the design spec):
4. **Provisioning view models + screens + `AppRoot` routing** (`VaultSelectionViewModel`, `VaultProvisioningViewModel`, `VaultSelectionScreen`, `CreateVaultWizardScreen`, SAF picker launchers; keep the demo entry). **This is the first slice that wires `VaultCreatePort` (Slice 1) + `VaultLocationStore` (Slice 2) into an observable Android capability — so it EARNS the README/ROADMAP capability entry the epic has been deferring.**
5. **Working-copy lifecycle:** materialize → `sync_once` → operate → **flush-after-every-commit** + pending-flush retry (push-before-pull). **`SyncState` keyed by `vault_uuid` lands here.** This is where `VaultMirror.flush`/`materialize` get *called* at the right times, and where the **local-sidecar flush optimization** (deferred from Slice 3) belongs — flush re-reading the whole cloud to fingerprint is fine for a one-off mirror but wasteful flush-after-every-commit.
6. **Instrumented E2E + offline-flush + conflict-copy-ingest tests** (two working copies over one SAF tree, mirroring `cli/tests/two_instance_convergence.rs`). **Must exercise the on-device-only factory paths the host suite can't reach: `findOrCreate` overwrite (incl. its new `delete()`-returns-false throw) + the `deleteFile` `delete()`-returns-false branch (Slice-3 review fixes that have never run against real SAF).** Also the deferred real-SAF `takePersistableUriPermission` round-trip from Slice 2.

**Acceptance template:** TDD (RED proven), typed-error/null surface proven not assumed on security paths, host (+ instrumented where automatable) gate green, pure logic in `:vault-access` / FFI+Android in `:kit`, no merge logic in Kotlin (the core owns CRDT).

## (3) Open decisions and risks
- **push-before-pull is NOT enforced in Slice 3 (by design).** `flush` and `materialize` ship as independent mechanisms; the *ordering between them* (always flush pending local edits before pulling cloud→working) is Slice 5's lifecycle job. **Slice 5's acceptance gate must include a test proving "on open, flush-pending runs before materialize"** — nothing in Slice 3 can guarantee it, and it's the keystone that keeps all merge inside the audited core (opus final-review recommendation).
- **Stateless content-hash diff → flush re-reads the whole cloud to fingerprint.** Correct + obviously-right for Slice 3; the natural fix is a Slice-5 local sidecar (cloud-side fingerprint cache) so flush-after-every-commit doesn't re-download unchanged blocks each pass. Already deferred; make it a conscious line in the Slice-5 plan.
- **`"wt"` openOutputStream mode** was challenged in review and kept as a documented write+truncate mode (comment added). If Slice 6's real-SAF test ever shows an OEM provider rejecting it, `"w"` is the fallback (findOrCreate already deletes-then-creates, so the file is always fresh).
- **Minor (open, recorded for triage):** `SafCloudFolderPortTest` uses `assertEquals(true, …)` (plan-mandated, cosmetic) — could become `assertTrue`. Non-blocking.
- **Risk:** low. New package, two modules; pure planner + orchestrator fully host-tested; the only un-host-tested code is the SAF DocumentFile factory (inherent to SAF; deferred to Slice 6). No core/FFI/format/observable-byte change.
- **README.md / ROADMAP.md unchanged** — consistent with Slices 1–2 and [[feedback_readme_style]]: Slice 3 is internal mirror plumbing with no observable Android-app capability yet. The epic earns its ROADMAP capability entry when the **create/open wizard lands (Slice 4)**.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If this PR merged, remove the worktree + branch:
#   git worktree remove .worktrees/android-cloud-drive-mirror && git branch -D feature/android-cloud-drive-mirror
git worktree list && git status -s
# Start Slice 4 from the design spec's component table (#4/#5 rows: view models + screens + AppRoot routing);
# brainstorm → plan → subagent-driven execute. File work continues under issue #321 (epic).
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-cloud-drive-mirror` (9 commits: 1 plan + 6 feat/fix + handoff). Worktree `.worktrees/android-cloud-drive-mirror`. Epic issue #321.
- **Acceptance:** host `:vault-access:test` + `:kit:testDebugUnitTest` green (38 new mirror test cases); whole-branch review (opus) Ready-to-merge Yes; all per-task + final Important findings fixed, Minors recorded.
- **README.md / ROADMAP.md / CLAUDE.md:** unchanged (internal mirror-mechanism slice of an in-flight epic).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-28-android-cloud-drive-slice3-mirror-shipped.md`.
