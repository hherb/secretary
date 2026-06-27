# NEXT_SESSION.md — Android cloud-drive provisioning, Slice 2 (VaultLocationStore) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-27 (second session of the day). Resumed the **Android cloud-drive vault-provisioning epic** from the Slice-1 baton. Slice 1 (`VaultCreatePort`, PR #320) had merged at 10:36; this session filed the epic tracking issue and shipped **Slice 2 of 6 — the `VaultLocationStore`**. Executed in project-local worktree `.worktrees/android-cloud-drive-locstore`, branch `feature/android-cloud-drive-locstore` (cut from `main` @ `4a254e4a`). Kotlin/Android only. **No core `src/` change, no FFI surface change, no on-disk-format / spec / `conformance.py` / KAT change.**

## (1) What we shipped this session

**Epic tracking issue filed:** **[#321](https://github.com/hherb/secretary/issues/321)** — "Epic: Android cloud-drive vault provisioning (SAF working-copy shim)", with the 6-slice checklist (Slice 1 ticked).

**Context — the epic.** Let the Android app open/create the user's own vault in a **cloud-drive folder** (Drive/Dropbox/OneDrive). The Rust core does direct POSIX I/O with no storage seam, but Android cloud-drive folders are reachable only via SAF `content://` URIs → the approved design is a **SAF working-copy shim** with a **push-before-pull** invariant. Full architecture + 6-slice plan: [`docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md`](../superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md). Slice-2 plan: [`docs/superpowers/plans/2026-06-27-android-cloud-drive-slice2-location-store.md`](../superpowers/plans/2026-06-27-android-cloud-drive-slice2-location-store.md).

**Slice 2 (this PR) — the `VaultLocationStore`.** Remembers ONE vault location (a SAF tree URI string + display name), takes a durable persistable-URI permission, and reports whether that permission is still granted. Parity port of iOS `VaultLocation` / `VaultLocationStore` / `BookmarkVaultLocationStore`.

- **Pure layer (`:vault-access`, package `org.secretary.browse`):**
  - `data class VaultLocation(val displayName: String, val treeUri: String)` — **`data class`** (value equality is useful + safe; carries NO secret, unlike Slice-1's plain-class `CreatedVault`). No `vault_uuid` (brainstorm decision — unknown at persist time; `SyncState` keying is a Slice-5 concern).
  - `interface VaultLocationStore { load(): VaultLocation?; persist(location); clear(); isAvailable(location): Boolean }` — synchronous (no crypto → no `suspend`). **No `beginAccess → path`**: SAF exposes no real path until working-copy *materialize* (Slice 3/5), so the honest Slice-2 surface is an `isAvailable` boolean probe (the spec's "stale permission → re-pick" path).
  - `VaultLocationCodec` — pure free functions `encodeVaultLocation` / `decodeVaultLocation`. **Single atomic blob** (one pref value, so a location can never half-persist — an improvement over iOS's two-key split), version-tagged + **length-prefixed** name (`"v1:<name.length>:<name><uri>"`) so the name needs no escaping and may contain the `:` delimiter. `decode` returns null on anything malformed (never throws): bad/absent version, missing delimiter, non-numeric/negative length, payload shorter than declared name length, **or an empty tree URI**.
- **Real adapter (`:kit`):** `SafVaultLocationStore` — the class body holds **zero Android types**: four String-based seams (`readPref`/`writePref`/`takePermission`/`hasPermission`), exactly mirroring Slice-1's `createFn` seam, so all persist/load/clear/availability logic is host-testable with fakes. Android (`Context`/`Uri`/`ContentResolver.takePersistableUriPermission`/`persistedUriPermissions`/`Intent` flags) lives ONLY in the top-level `safVaultLocationStore(context)` factory. `persist` takes the SAF permission **before** writing the pref (never persist a URI we haven't secured). Named constants `PREFS_NAME` / `KEY_LOCATION`.

**TDD throughout (subagent-driven: implementer → spec+quality review per task → whole-branch review).**
- Host `:vault-access` — `VaultLocationCodecTest` (10 cases: round-trips incl. `:`-in-name + empty name, all decode-reject branches, empty-treeUri reject, value-equality).
- Host `:kit` — `SafVaultLocationStoreTest` (7 cases via fake seams: take-permission-before-write **ordering** (ordered event list, genuinely falsifiable), load decodes, malformed→null, clear, replace-prior, `isAvailable` forwarding).
- **No instrumented test this slice (documented, not silent):** a real persistable *tree* URI needs driving the system SAF picker (UiAutomator), not automatable in a unit slice → deferred to Slice 6's E2E. (Slice 1 had an instrumented test only because the FFI `.so` create *is* automatable; SAF grants are not.)

**Reviews.** Per-task: Task 1 ✅ (1 Minor — empty-`treeUri` accepted by decode — **fixed**, `1e51fc22`, as a conservative-under-report guard the persisted format depends on); Task 2 ✅ (3 Minors, all non-defects: test-count verbosity / const placement matches house style / replace-test asserts via `load()` — reviewer "fine"). Whole-branch review (opus): **Ready to merge: Yes**, no Critical/Important. Two Minor KDoc nits (empty-treeUri case missing from the malformed-list; "reversible" overclaim) **fixed** in `70a5ec24`.

**Post-review `/review` fix (persistable-URI grant leak).** A precision PR review flagged that `SafVaultLocationStore.clear()` (and `persist()` superseding a *different* tree URI) relinquished nothing — `takePersistableUriPermission` consumes an Android per-package grant slot, and clearing the SharedPreferences blob alone does **not** release the SAF grant, so the design's "stale permission → re-pick" loop would leak a grant on every re-pick toward the system cap. **Fixed** by adding a fifth `releasePermission` seam (mirroring `takePermission`): `persist` releases the prior grant *after* securing+recording the new one (skipped when the URI is unchanged); `clear` releases before forgetting. iOS needs no analogue (a `UserDefaults` bookmark consumes no system-wide slot). Three new falsifiable host cases (clear-releases, replace-different-releases-old with an ordered event assertion, replace-same-keeps); `:kit` suite now 10/10 green.

**Branch commits** (off `main` @ `4a254e4a`):
| SHA | What |
|---|---|
| `28569ec2` | docs: slice-2 plan |
| `211e6808` | feat: pure `VaultLocationStore` port + `VaultLocation` + codec (`:vault-access`) |
| `1e51fc22` | fix: reject empty `treeUri` in `decodeVaultLocation` (Task-1 review Minor) |
| `e84b54e8` | feat: `SafVaultLocationStore` adapter + factory (`:kit`) |
| `70a5ec24` | docs: align codec KDoc with empty-treeUri reject + qualify reversibility (final-review Minors) |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-locstore/android
./gradlew :vault-access:test            # host — codec suite green (incl. empty-treeUri reject)
./gradlew :kit:testDebugUnitTest        # host — SafVaultLocationStore suite 7/7 green
```
No emulator/device needed this slice.

## (2) What's next
**Slice 2 is done (PR open). Continue the epic with Slice 3.** Each slice is its own plan + PR through the review loop. Remaining slices (from the design spec):
3. `CloudFolderPort` (list/read/write/delete over SAF) + **pure** `VaultMirrorPlanner` (which files to move, **block-first** ordering, changed-file detection — the host-testable heart) + `VaultMirror` orchestrator.
4. Provisioning view models + `VaultSelectionScreen` / `CreateVaultWizardScreen` + `AppRoot` routing (keep the demo entry). **This is the first slice that wires `VaultCreatePort` + `VaultLocationStore` into an observable Android capability.**
5. Working-copy lifecycle: materialize → `sync_once` → operate → **flush-after-every-commit** + pending-flush retry (push-before-pull). **`SyncState` keyed by `vault_uuid` lands here** — see the v2-codec note in (3).
6. Instrumented E2E + offline-flush + conflict-copy-ingest tests (two working copies over one SAF tree, mirroring `cli/tests/two_instance_convergence.rs`). **Includes the deferred real-SAF `takePersistableUriPermission` round-trip for Slice 2.**

**Acceptance template:** TDD (RED proven), typed-error/null surface proven not assumed on security paths, host (+ instrumented where automatable) gate green, pure logic in `:vault-access` / FFI+Android in `:kit`, no merge logic in Kotlin (the core owns CRDT).

## (3) Open decisions and risks
- **Forward-compat note for Slice 5 (`vault_uuid`):** the design-spec Slice-2 row literally lists `vault_uuid` in the location; we deliberately dropped it (unknown at persist time, `SyncState` keying is Slice 5). The codec is already **version-tagged (`v1`)** for exactly this — when Slice 5 adds `vault_uuid`, bump to a **`v2`** encoding. Because `decode` returns null for any non-`v1` blob, a `v1→v2` upgrade silently forgets the one remembered location and re-prompts a pick — acceptable for a single-vault store, but make it a *conscious* line in the Slice-5 plan, not a surprise.
- **`isAvailable` (not iOS `beginAccess`) is the right Android shape** — SAF has no resolvable path until materialize; porting `beginAccess → path` here would have forced a fake path. Confirmed sound by the final review.
- **Risk:** low. Two new Kotlin source files + tests, plus a factory; wraps SAF + SharedPreferences; changes no core/FFI/format. No observable byte/semantics change.
- **README.md / ROADMAP.md unchanged** — consistent with Slice 1 (PR #320) and [[feedback_readme_style]]: Slices 1–2 are internal port plumbing with no observable Android-app capability yet. The epic earns its ROADMAP capability entry when the **create/open wizard lands (Slice 4)**.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If this PR merged, remove the worktree + branch:
#   git worktree remove .worktrees/android-cloud-drive-locstore && git branch -D feature/android-cloud-drive-locstore
git worktree list && git status -s
# Start Slice 3 from the design spec's component table (#3 row); brainstorm → plan → subagent-driven execute.
# File work continues under issue #321 (epic).
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-cloud-drive-locstore` (6 commits: 1 plan + 4 feat/fix/docs + handoff). Worktree `.worktrees/android-cloud-drive-locstore`. Epic issue #321.
- **Acceptance:** host `:vault-access:test` + `:kit:testDebugUnitTest` green; whole-branch review (opus) Ready-to-merge Yes; all per-task + final Minors fixed or consciously kept.
- **README.md / ROADMAP.md / CLAUDE.md:** unchanged (internal port slice of an in-flight epic).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-27-android-cloud-drive-slice2-location-store-shipped.md`.
