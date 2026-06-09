# NEXT_SESSION.md — D.3 slice 1 ✅ iOS XCFramework + linked-call proof

**Session date:** 2026-06-10 (D.3 slice 1 — the FIRST native-iOS slice under [ADR 0008]: bootstraps a reproducible iOS XCFramework build pipeline for the `secretary-ffi-uniffi` bindings + an automated on-simulator XCTest that opens the golden vault, proving `secretary-core` runs through uniffi on-device). Flow: settled the prior session's open ADR question (already resolved by ADR 0008, merged as #199) → `superpowers:brainstorming` (3 scope questions → thinnest-slice design) → `superpowers:writing-plans` (7-task TDD plan) → `superpowers:subagent-driven-development` (fresh implementer per task + spec + code-quality review after each + final whole-branch review).
**Status:** ✅ code-complete on branch `feature/d3-ios-xcframework`. **PR: see §4.** Acceptance entry point **green** (`bash ios/scripts/run-ios-tests.sh` → `** TEST SUCCEEDED **`, exit 0, both XCTests passing on the `iPhone 16` simulator). The Task-1 additive change re-ran the existing gauntlet green (clippy + workspace tests + Swift/Kotlin smoke). Final whole-branch review: **APPROVE TO MERGE**, zero Critical/Important/Minor.
**No app/GUI gate** — this slice ships no UI (XCTest only). The on-simulator proof IS the verification and it is scripted/automated.

## (1) What we shipped this session

The **iOS XCFramework + linked-call proof** (D.3 slice 1). Concretely, six new/changed surfaces — all under `ios/` plus one additive crate-type line:

- **`ffi/secretary-ffi-uniffi/Cargo.toml`** — added `"staticlib"` to crate-type (`["cdylib", "rlib", "staticlib"]`). **Purely additive**: no `src/`/UDL change, so the cross-language conformance gauntlet is untouched and still green. Enables cross-compiling the uniffi core as a static archive for iOS.
- **`ios/scripts/build-xcframework.sh`** — cross-compiles the uniffi staticlib for the three iOS triples (`aarch64-apple-ios` device + `aarch64-apple-ios-sim` + `x86_64-apple-ios`), `lipo`'s the two simulator slices into one fat archive, generates the Swift bindings via the in-crate `uniffi-bindgen`, assembles `ios/Secretary.xcframework` (device + simulator slices, headers + `module.modulemap`), and stages `golden_vault_001` (+ its inputs JSON) as an SPM test resource. **Key wrinkle:** bindgen reads the **host cdylib** (not the cross-compiled iOS `.a`) — uniffi-bindgen is a host tool that can't read cross-compiled archive metadata; the generated Swift/header/modulemap are host-arch-independent source, so packaging the iOS slices remains correct. Documented in a script comment (mirrors the desktop `tests/swift/run.sh`).
- **`ios/SecretaryKit/Package.swift`** — an SPM package: `binaryTarget` `SecretaryFFI` → `../Secretary.xcframework`; library `SecretaryKit` wrapping the generated `secretary.swift` (which `import secretaryFFI`, the Clang module the modulemap vends); test target `SecretaryKitTests` bundling the fixture via `.copy(...)` (NOT `.process` — preserves the directory tree + byte-identical KAT). iOS 17 floor.
- **`ios/SecretaryKit/Tests/SecretaryKitTests/OpenVaultLinkTests.swift`** — two tests: `testOpenGoldenVaultOnDevice` (opens a per-test temp copy of the bundled vault via `openVaultWithPassword`, asserts `manifest.vaultUuid()` == the UUID read from the bundled inputs JSON + `blockCount() > 0`, wipes both handles) and `testWrongPasswordSurfacesTypedError` (`VaultError.WrongPasswordOrCorrupt`). Read-only-fixture hygiene (temp copy), no hardcoded UUID bytes.
- **`ios/scripts/run-ios-tests.sh`** — the acceptance entry point: runs `build-xcframework.sh` then `xcodebuild test` on a simulator. **Resolves the simulator name → a concrete UDID** (the bare `name=iPhone 16` destination is ambiguous on this host across runtimes); `IOS_SIM` overrides (default `iPhone 16`). Exits non-zero on failure with a device list.
- **`ios/.gitignore` + docs** — gitignores the generated XCFramework / `secretary.swift` / staged Resources / `.build`; `ios/README.md` rewritten (status + how-to-run); root `README.md` + `ROADMAP.md` record D.3 slice 1 ✅ (2026-06-10).

Commits on `feature/d3-ios-xcframework` (branched from `main` @ `43014c9`):

| Commit | What it landed |
|---|---|
| `b55c1a2` / `ed8357b` | design spec (+ iOS-17-floor amendment) |
| `a9f33f6` | 7-task TDD plan |
| `48fde5e` | Task 1 — `staticlib` crate-type (+ additive-gauntlet proof) |
| `806dea6` / `6fa0d4f` | Task 2 — `build-xcframework.sh` (+ review: honest docstring, dedupe, comments) |
| `b68b138` | Task 3 — `ios/.gitignore` |
| `f2090b9` | Task 4 — SPM `Package.swift` |
| `7703d2e` / `e30ba0a` | Task 5 — `OpenVaultLinkTests` (+ review: hex-helper XCTUnwrap + length assert) |
| `265dc6a` / `c477cee` | Task 6 — `run-ios-tests.sh` (+ review: capture device list once; ERE note) |
| `effd1fc` / `e881821` | Task 7 — README/ROADMAP (+ tighten root README to brief style) |
| _(ship)_ | this handoff + symlink retarget |

**Process notes:**
- The planned `xcodebuild ... -destination 'platform=iOS Simulator,name=iPhone 16'` is **ambiguous** on this host (multiple runtime/arch entries share the name). Both the test run and the runner script resolve the name → a UDID and target by `id=`. Remember this for any future iOS `xcodebuild` invocation here.
- `xcodebuild` errors if `-resultBundlePath` already exists — `rm -rf` it between manual runs (the runner script doesn't use it, so the one-command path is unaffected).
- uniffi 0.31 Swift codegen names the error case `VaultError.WrongPasswordOrCorrupt` (capitalized), and the generated API matched the planned symbols exactly (no test adaptation needed).

### Acceptance (re-run clean @ HEAD `e881821`)
```
bash ios/scripts/run-ios-tests.sh        → ** TEST SUCCEEDED **, exit 0 (2 tests pass on iPhone 16 sim)
# plus the additive-change gauntlet from Task 1:
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo test --release --workspace                            → 0 failed
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh            → OK
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh           → OK
```

## (2) What's next

No slice is pre-committed. Natural next-deferred (pick one → brainstorm → plan → execute):

- **D.3 slice 2 — hardware-backed, biometric-bound key release (the ADR 0008 headline).** Keychain / Secure Enclave + `LocalAuthentication` (Face ID / Touch ID) gating a Keystore/Enclave-held wrapping key, consumed from native Swift. This is the security-critical reason ADR 0008 chose native; it deserves its own **threat-model-careful brainstorm**. Acceptance (to refine): a wrapping key is generated/held in the Secure Enclave (non-exportable), released only after a successful biometric/`LAContext` evaluation, and used to unwrap the vault identity; a clear failure mode when biometry is unavailable/locked out; no secret key material crosses into a GC'd runtime in exportable form. Likely needs a small SwiftUI host to drive the auth UI — so it may pair with / precede the app-skeleton slice.
- **D.3 slice — SwiftUI walking-skeleton app.** A real app target (not just an XCTest) with an unlock screen → block list, consuming `SecretaryKit`. Decide the app project structure then (xcodeproj vs XcodeGen vs SPM-app) — slice 1 deliberately left that open. Pairs naturally with slice 2 (the app drives the biometric unlock).
- **CI wiring for the iOS XCTest** — the runner is CLI-reproducible but invoked manually this session; wiring `xcodebuild test` into CI (macOS runner + simulator cost) is a deferred decision.
- **Desktop / sync deferred items still open:** background auto-sync (Tauri desktop), reveal-to-decide, **#192** (collision-population test), **#193** (pipeline.rs refactor).

**Acceptance criteria for whichever is chosen:** author via `superpowers:brainstorming` → `superpowers:writing-plans`. Anything touching `core`/`ffi`/`FfiVaultError`/UDL re-triggers the full workspace gauntlet **and** the Swift+Kotlin conformance runs ([[project_secretary_ffivaulterror_workspace_match]]). The Secure-Enclave slice is security-critical: enforce-don't-assume on the key-release path, and prove the both-halves / non-exportable invariants rather than asserting them.

**Open follow-up issues:** carried **#192/#193/#186/#189/#190/#161/#162/#167**. D.3 slice 1 closes with this PR.

## (3) Open decisions and risks

- **App project structure is deliberately unsettled.** Slice 1 used an SPM package (right for a no-UI test target). A real app target (slice 2/skeleton) needs an app project — xcodeproj (conventional, merge-hostile), XcodeGen (text → xcodeproj, adds a tool), or SPM-app. Decide when the app slice starts.
- **iOS deployment floor = iOS 17** (set forward-looking; the test-only slice is floor-agnostic). Revisit when the app slice sets a real minimum.
- **Secure Enclave is the unproven security frontier.** ADR 0008's entire rationale is hardware-backed keys; slice 1 deliberately kept key material in-memory in the test. The hard, must-be-right work (Enclave key binding + biometric release) is entirely ahead — treat slice 2 as the security-critical core of the iOS port.
- **Bindgen-from-host-cdylib coupling.** The build reads bindgen metadata from the host cdylib, not the iOS slices. Correct and documented, but it means a host that can't build the cdylib can't generate iOS bindings. No action; noted for awareness.

### Verified non-issues (don't re-investigate)
- **Additivity (HIGH confidence):** the only `ffi/` change is the one crate-type line; no `src/`/UDL change; the existing gauntlet (clippy + workspace + Swift/Kotlin smoke) re-ran green.
- **No committed artifacts/secrets:** `git ls-files ios/` lists only the 6 hand-authored files; the XCFramework, generated `secretary.swift`, and staged fixture are gitignored — confirmed clean even after a real build produced them on disk.
- **Secret hygiene:** password handled as UTF-8 `Data`, never logged; both `OpenVaultOutput` handles wiped via `defer`; the golden fixture is opened from a per-test TEMP COPY, never mutated in place; pinned UUID read from the inputs JSON (no hardcoded bytes).
- **Cross-file coherence:** `SecretaryFFI` (SPM target) ↔ `secretaryFFI` (Clang module) ↔ `SecretaryKit` (scheme/lib) ↔ `.copy` resource paths ↔ `Bundle.module` lookups all line up; the test's API names match the generated bindings exactly.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — confirm / review):
cd /Users/hherb/src/secretary && gh pr list --head feature/d3-ios-xcframework

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d3-ios-xcframework && git branch -D feature/d3-ios-xcframework
git worktree prune && git worktree list

# 3) Next slice (likely D.3 slice 2 — Secure Enclave / biometric key release): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the iOS acceptance on the branch (from the worktree; needs macOS + Xcode):
cd /Users/hherb/src/secretary/.worktrees/d3-ios-xcframework
bash ios/scripts/run-ios-tests.sh        # build XCFramework + XCTest on the simulator (IOS_SIM overrides device)
# First run on a fresh checkout fetches iOS Rust std via `rustup target add`.
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. main did NOT move during this session (branch point == origin/main == `43014c9`), so the symlink retarget merges cleanly. Next slice: author `docs/handoffs/<date>-<slug>-shipped.md` + `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, both committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `43014c9`; `feature/d3-ios-xcframework` carries design + plan + 11 task/review/doc commits + this ship commit. Squash-merge collapses to one commit on `main`.
- **Acceptance:** green — `bash ios/scripts/run-ios-tests.sh` → `** TEST SUCCEEDED **` (2 tests on iPhone 16 sim); Task-1 additive gauntlet (clippy/workspace/Swift+Kotlin smoke) green.
- **Final whole-branch review:** **APPROVE TO MERGE** — zero Critical/Important/Minor; the reviewer independently ran the acceptance pipeline to a pass and confirmed no artifacts committed.
- **README.md / ROADMAP.md:** D.3 slice 1 ✅ 2026-06-10.
- **CLAUDE.md / `docs/adr/`:** unchanged (no new on-disk-format/crypto decision; ADR 0008 already governs the native-mobile-via-uniffi direction).
- **Open decision for next session:** app project structure (xcodeproj vs XcodeGen vs SPM-app) when the app/UI slice starts; D.3 slice 2 (Secure Enclave) is the security-critical next frontier.
- **NEXT_SESSION.md:** symlink retargeted to this file.

[ADR 0008]: ../adr/0008-native-mobile-via-uniffi.md
