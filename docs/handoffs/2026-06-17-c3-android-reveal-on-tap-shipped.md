# NEXT_SESSION.md — C.3 Android slice 8: reveal-on-tap ✅

**Session date:** 2026-06-17. Flow: `/nextsession` → slice-7 baton (PR #249 merged, `main` @ `162c5e2`) → housekeeping (removed merged `c3-android-open-browse` worktree/branch) → chose **Android slice 8** (reveal-on-tap) → brainstormed (4 decisions: mirror-iOS retain-open-blocks, exact iOS hide policy, reveal-only scope, add instrumented Compose UI tests) → spec → 8-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-branch review (opus, "Ready to merge") → docs + this handoff.

**Status:** ✅ **code-complete + all-green**, **pushed — PR [#250](https://github.com/hherb/secretary/pull/250) open and MERGEABLE**, on branch `feature/c3-android-reveal-on-tap` (worktree `.worktrees/c3-android-reveal-on-tap`). First resume step is **review + squash-merge PR #250** (the user merges; this session does not merge). This is the **first Android slice where a secret value crosses the adapter**: tap a field → real `expose_text`/`expose_bytes` → plaintext, with 30s auto-hide, tap-to-hide, drop-on-background. Mirrors the proven iOS reveal architecture. **No `core`/`ffi`/`ios`/format change** — both guardrail greps empty.

## (1) What we shipped this session

**The central idea:** browsing stays metadata-only until the user taps a field; then the retained `FieldHandle` materializes that one value on demand via the FFI `expose_*`. The session retains each decrypted `BlockReadOutput` (reversing slice 7's close-immediately) so reveal closures stay valid until `wipe()`, which zeroizes **blocks → manifest → identity** in that order. The **only** `expose_*` call sites in the whole codebase are inside one reveal lambda (`buildRevealableField`) — verified by grep in two reviews. A revealed value auto-hides after `RevealPolicy.autoHideSeconds = 30` (Compose-driven, injectable for tests), hides on tap, and is dropped with the whole session on background (slice-7 lock-on-background). The decision to retain blocks (vs. re-decrypt per reveal) was deliberate: the master key is resident in memory either way, so an attacker who can read it can decrypt any block — the re-decrypt variant buys no real security while diverging from iOS.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | slice-8 design doc + 8-task plan | `e340749` `42a8322` |
| **Task 1 — reveal types** | `RevealedValue`/`FieldKind`/`RevealableField`/`RevealPolicy` in `:vault-access` | `cf7e881` |
| **Task 2 — RecordSummaryView + :kit reveal** | `RecordSummaryView.fields`; `UniffiVaultSession` retains blocks + wires `expose_*` on demand + corrupt-null + wipe order; `fieldKindOf` | `284316d` (+fix `b7e599f`) |
| **Task 3 — model reveal seams** | `VaultBrowseModel` reveal/hide/hideAll + `revealed` map + clear-on-reload/lock | `410a118` (+fix `0eb6a3e`) |
| **Task 4 — VM forwarding** | `VaultBrowseViewModel` reveal/hide/hideAll + `revealed` | `ca58c4f` |
| **Task 5 — render helper** | `revealedText` (text as-is, bytes as hex) | `2689bdd` |
| **Task 6 — BrowseScreen reveal UI** | per-field reveal/hide toggle + keyed auto-hide + injectable `autoHideMillis` | `72c47d7` |
| **Task 7 — Compose UI test** | instrumented `BrowseScreenRevealTest` (reveal/hide/auto-hide) | `c0563b6` (+fix `56883e1`) |
| **Task 8 — on-device reveal smoke** | `OpenBrowseSmokeTest` reveal case → real `.so` yields `hunter2` | `8dcde4c` |
| **Final review + docs** | comment wrap + README/ROADMAP + this handoff | `4dfc14d` `14385d6` (+ this commit) |

Branch from `main` @ `162c5e2`. **Squash-merge collapses to one commit on `main`** (per-task SHAs above are pre-squash).

### Architecture (where the pieces live)

- **`:vault-access` (package `org.secretary.browse`) — pure, host-tested JUnit5:**
  - `Reveal.kt` — `RevealedValue` (sealed: `Text(String)`, `Bytes(ByteArray)` with `contentEquals`), `FieldKind {Text,Bytes}`, `RevealableField(name, kind, reveal: () -> RevealedValue)` (NOT a data class — holds a closure), `RevealPolicy { autoHideSeconds = 30 }`.
  - `BrowseModels.kt` — `RecordSummaryView` now carries `fields: List<RevealableField>`; `fieldNames` is a computed `get()`.
  - `VaultBrowseModel` — `revealed: StateFlow<Map<String,RevealedValue>>` keyed `"<recordUuidHex>/<fieldName>"`; `reveal`/`hide`/`hideAll`; `selectBlock`/`clearSelection`/`lock` clear reveals first; `reveal` folds any throwable (typed → that error; unexpected → `Failed`).
- **`:kit` (package `org.secretary.browse`) — FFI adapters, host-tested where pure:**
  - `UniffiVaultSession` — retains `openBlocks: MutableList<BlockReadOutput>`; `readBlock` appends the block before mapping; `buildRevealableField` is the **sole** `expose_*` site (lazy lambda); in-range `null` from `recordAt`/`fieldAt`/`expose_*` → `VaultBrowseError.CorruptVault`; `wipe()` = blocks → manifest → identity.
  - `FieldKindMapping.kt` — pure `fieldKindOf(isText)` (host-tested).
- **`:browse-ui` (package `org.secretary.browse.ui`) — FFI-free Compose:**
  - `VaultBrowseViewModel` — re-exposes `revealed`, forwards reveal/hide/hideAll.
  - `BrowseScreen` — per-field row with Reveal/Hide toggle; revealed text via `revealedText`; auto-hide `LaunchedEffect(uuidHex, name, value){ delay(autoHideMillis); hide() }`; `autoHideMillis = RevealPolicy.autoHideSeconds * MILLIS_PER_SECOND` (named const, injectable).
  - `revealedText` render helper.
- **`:app`** — **unchanged**: slice-7 `ON_STOP` lock-on-background already wipes the session; `lock()` now also clears the reveal map, so revealed values vanish on background with no new wiring.

### Acceptance (green — full gauntlet this session)

```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test   → BUILD SUCCESSFUL (host JUnit5)
cd android && ./gradlew :browse-ui:connectedDebugAndroidTest                                   → BrowseScreenRevealTest 2/2 on Medium_Phone_API_36.1
cd android && ./gradlew :app:connectedDebugAndroidTest                                         → OpenBrowseSmokeTest 3/3 + MakeVaultSyncSmokeTest 2/2 (5/5, real .so → "hunter2")
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'               → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)

- **Retain open blocks (mirror iOS), not re-decrypt-per-reveal.** Master key is resident either way; re-decrypt buys no real security and diverges from iOS. Documented in the spec Risks.
- **Single secret-pull boundary.** Only `buildRevealableField`'s lambda calls `expose_*`. Keep it that way — a reviewer greps for it.
- **Revealed values land in non-zeroizable Kotlin `String`/`ByteArray`** (same documented residue limit as iOS + the unlock password field). Mitigated by keeping the reveal map small + short-lived (cleared on hide/auto-hide/reload/lock); the underlying `SecretString`/`SecretBytes` is zeroized by `BlockReadOutput.wipe()` on lock.
- **`reveal()` folds unexpected throwables to `Failed`** (mirror iOS) so a misbehaving field lambda can't crash the UI.
- **Lock-on-background = full session wipe** (no lighter hide-on-`ON_PAUSE`). Matches iOS lock semantics; returning re-prompts for the password (one more Argon2id).
- **`RecordSummaryView` stays a data class** — a reload returns the same `RevealableField` instances from the fake, so structural equality still holds in tests; name retained from slice 7 though it now carries reveal capability.

## (2) What's next

- **Show-deleted toggle + swipe delete/restore/edit** (iOS browse parity). `VaultSession.readBlock` already takes `includeDeleted`; the FFI write surface (`appendRecord`/`editRecord`/`tombstoneRecord`/`resurrectRecord`) is exposed and used by iOS. Acceptance: a toggle re-reads the block with `includeDeleted=true`; tombstoned records render with a deleted marker; swipe tombstones/resurrects and re-reads.
- **Sync-badge re-integration onto `BrowseScreen`** — unify browse + the existing slice-5 sync flow into one screen. `AppSyncStateDir` is retained in `:app` for this.
- **Recovery-phrase + device-secret open paths** on Android (this + slice 7 are password-only; the uniffi surface `open_with_recovery` / `open_with_device_secret` already exists).
- **On-device veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).
- Optional `WorkManager` background detection (deferred from slice 3).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202. **Filed this session (post-review fixup):** #251 (cross-platform `openBlocks` decrypted-plaintext accumulation).

## (3) Open decisions and risks

**Post-review fixup (this session, on this branch after the slice landed):**
- **Fixed — `wipe()` / `readBlock` race (`UniffiVaultSession`).** Android runs `readBlock` on the IO dispatcher while `wipe()` runs on the main thread (`ON_STOP`), an unsynchronized cross-thread touch of the FFI handles + `openBlocks` that iOS's synchronous `readBlock` doesn't have. Now serialized under a `sessionLock` + a `wiped` guard: a read that loses the race to a concurrent `wipe()` zeroizes its just-decrypted block instead of leaving plaintext resident past the lock. Verified on-device (`:app` 5/5, `:browse-ui` 2/2). Only `android/kit/.../UniffiVaultOpenPort.kt` changed; both guardrails still empty.
- **Filed #251 — `openBlocks` accumulates every visited block's decrypted plaintext until `wipe()`** (no per-navigation eviction; re-selecting a block appends a duplicate). This is faithful iOS parity (the iOS `UniffiVaultSession` does the same), so it's a deliberate cross-platform residency decision to make once and apply to both, not an Android-only fix — hence an issue, not an in-branch divergence. The same issue notes the derived `Record`/`FieldHandle` wrappers are no longer `.use{}`-closed (iOS-identical, zeroized via the `BlockReadOutput` cascade, proven by the on-device smoke).

- **No Compose UI test of `:app`'s unlock→browse→reveal glue end-to-end.** The instrumented coverage is `:browse-ui`'s `BrowseScreenRevealTest` (fake-backed, real Compose) + `:app`'s `OpenBrowseSmokeTest` (real `.so`, ViewModel layer). The `:app` route Compose render itself isn't UI-tested — same deliberate choice as slices 6/7.
- **Pre-existing sibling-test patterns left as-is** (out of scope, flagged by reviews): `OpenBrowseSmokeTest` happy-path + slice-7 cases don't close the `VaultSession` in `@After` (the new reveal case does `lock()`); a `!!` unwrap on `selectedRecords`. Consistent with the existing file; changing them would diverge from the established style.
- **`VaultBrowseViewModel.hideAll()` has no production caller yet** — kept for iOS parity; exercised transitively via the model test. Borderline YAGNI, acceptable.
- **`arm64-v8a` only** — matches `:kit`; irrelevant on the arm64 emulator/devices used here.
- **No production change to anything pre-existing** — `:app` route untouched; `core`/`ffi`/`ios`/format untouched (both guardrails empty).

## (4) Exact commands to resume

```bash
# 0) PR #250 is OPEN and MERGEABLE. Review + squash-merge it (the user merges; this session does not):
#    https://github.com/hherb/secretary/pull/250
#    (branch already pushed; nothing to push unless you add fixup commits)

# 1) After review, squash-merge, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-reveal-on-tap && git branch -D feature/c3-android-reveal-on-tap
git worktree prune && git worktree list

# 2) Next direction (show-deleted + edit/delete slice — spec first):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on the branch (emulator must be running for connected tests):
cd /Users/hherb/src/secretary/.worktrees/c3-android-reveal-on-tap/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test    # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-reveal-on-tap/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest :app:connectedDebugAndroidTest    # 2/2 + 5/5, emulator running

# Guardrail greps (both must be empty):
cd /Users/hherb/src/secretary/.worktrees/c3-android-reveal-on-tap
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`162c5e2`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `162c5e2`; `feature/c3-android-reveal-on-tap` carries spec + plan + 11 task/fix commits + final-review + docs + this handoff commit. Squash-merge → one commit on `main`. **Not yet pushed.**
- **Acceptance:** green — `:vault-access`/`:kit`/`:browse-ui`/`:app` host suites + `BrowseScreenRevealTest` 2/2 + `OpenBrowseSmokeTest` 3/3 + `MakeVaultSyncSmokeTest` 2/2 on `Medium_Phone_API_36.1`; both guardrails clean. See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task). Final whole-branch review (opus) = "Ready to merge", secret-pull boundary verified airtight end-to-end; one cosmetic Minor fixed, rest pre-existing/iOS-parity.
- **README.md / ROADMAP.md:** updated — Android C.3 slice 8 ✅ (reveal-on-tap).
- **NEXT_SESSION.md:** symlink retargeted to this file.
