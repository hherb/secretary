# iOS `UniffiVaultSession` TSan concurrency coverage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a TSan-verified concurrency test suite that genuinely drives `UniffiVaultSession`'s lock-protected paths (readBlock / wipe / writes) from multiple threads, plus a path-gated macOS CI job that runs the SecretaryKit suite under ThreadSanitizer — closing the "by-construction + doc-comment only" gap left by PR #304 (#300).

**Architecture:** Three XCTest cases drive the session concurrently against a temp copy of `golden_vault_001`, sharing the non-`Sendable` session through an explicit `@unchecked Sendable` box. A new lean `run-ios-tsan.sh` builds the xcframework and runs the whole suite with `-enableThreadSanitizer YES`; the simulator-name→UDID resolver is extracted into a sourceable helper shared with the existing `run-ios-tests.sh`. A dedicated path-gated workflow runs it in CI.

**Tech Stack:** Swift / XCTest, `xcodebuild` (iOS Simulator), ThreadSanitizer, bash, GitHub Actions.

## Global Constraints

- **iOS test + CI only.** No `core/` change, no `docs/crypto-design.md` / `docs/vault-format.md` change, no `conformance.py` change, no `FfiVaultError` variant, no `UniffiVaultSession` production-code change.
- **Zero-warning bar.** Swift must compile with no concurrency / unused warnings (see [[project_secretary_ios_value_types_sendable_offload]]).
- **No magic numbers.** Thread/iteration/session counts are named constants.
- **Never mutate the frozen KAT.** Tests open a `cp -R` temp copy of `golden_vault_001`, never the tracked fixture ([[feedback_smoke_test_temp_copy_golden_vault]]).
- **No unpinned third-party GitHub Action.** Reuse only actions already established in the repo (`actions/checkout@v4`, `Swatinem/rust-cache@v2`).
- **Assertions must be timing-independent** — no-crash + count/contents that hold under any valid interleaving. Never assert a specific race outcome (that would be flaky).
- **Golden vault password:** `correct horse battery staple` (matches the existing iOS integration tests).
- **Default simulator:** `iPhone 16`, overridable via `IOS_SIM`.

---

## File Structure

- **Create** `ios/scripts/lib/resolve-simulator.sh` — sourceable helper: one function resolving a simulator name to a UDID.
- **Modify** `ios/scripts/run-ios-tests.sh` — source the helper instead of inlining the resolver (pure extraction; behavior identical).
- **Create** `ios/scripts/run-ios-tsan.sh` — build xcframework + run whole SecretaryKit suite under TSan.
- **Create** `ios/SecretaryKit/Tests/SecretaryKitTests/SessionConcurrencyIntegrationTests.swift` — the three concurrency tests.
- **Modify** `ios/SecretaryKit/Tests/SecretaryKitTests/SessionWipeGuardIntegrationTests.swift` — update the docstring that claims concurrency is "not unit-tested".
- **Create** `.github/workflows/ios-tsan.yml` — path-gated macOS TSan job.

> **Spec deviation (documented):** the spec placed the CI job "in `test.yml`". The plan uses a **separate workflow file** instead, because workflow-level `paths:` filtering is the only clean, no-third-party-action way to path-gate this one heavy macOS job without also gating `test.yml`'s rust/desktop/conformance jobs (which must run on every PR). Same constraints, cleaner mechanism.

---

### Task 1: Extract the simulator resolver + add the TSan runner script

**Files:**
- Create: `ios/scripts/lib/resolve-simulator.sh`
- Modify: `ios/scripts/run-ios-tests.sh:31-61` (replace the inlined resolver block with a `source` + call)
- Create: `ios/scripts/run-ios-tsan.sh`

**Interfaces:**
- Produces: `resolve_simulator <sim-name>` — bash function; echoes the resolved UDID on stdout; on no match prints the available-device list to stderr and `return 2`.
- Consumes: existing `ios/scripts/build-xcframework.sh` (builds the xcframework + stages `golden_vault_001`).

- [ ] **Step 1: Create the resolver helper**

Create `ios/scripts/lib/resolve-simulator.sh`:

```bash
#!/usr/bin/env bash
# Resolve an iOS simulator *name* to a concrete UDID. Sourced by run-ios-tests.sh
# and run-ios-tsan.sh so the resolution logic lives in exactly one place.
#
# Usage:  source .../lib/resolve-simulator.sh; SIM_ID="$(resolve_simulator 'iPhone 16')"
# Echoes the UDID on stdout. On no match it prints the available-device list to
# stderr and returns 2 — the caller, under `set -e` with command substitution,
# aborts. (Bash note: `SIM_ID="$(resolve_simulator …)"` does propagate a non-zero
# return under `set -e`.)
resolve_simulator() {
    local sim_name="$1"
    local devices sim_id
    # Capture the device list ONCE: a genuine `simctl` failure aborts here under
    # `set -e` rather than being swallowed by the `|| true` below and misreported
    # as a missing device. The `|| true` then guards ONLY the grep pipeline, where
    # a no-match is legitimately empty.
    devices="$(xcrun simctl list devices available)"
    # Anchor the match to "<name> (" so "iPhone 16" does not also match
    # "iPhone 16 Pro" / "iPhone 16 Plus" / "iPhone 16e". `head -1` takes the first
    # matching device regardless of runtime (simctl groups by runtime); it assumes
    # every installed runtime is >= the Package.swift deployment floor (iOS 17).
    # NB: $sim_name is interpolated into an ERE — fine for real device names, which
    # contain no regex metacharacters.
    sim_id="$(printf '%s\n' "$devices" \
        | grep -E "^[[:space:]]*${sim_name} \(" \
        | head -1 \
        | grep -oE '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}' || true)"
    if [[ -z "$sim_id" ]]; then
        echo "ERROR: no available simulator named '$sim_name'. Available devices:" >&2
        printf '%s\n' "$devices" >&2
        echo "Set IOS_SIM to one of the device names listed above." >&2
        return 2
    fi
    printf '%s\n' "$sim_id"
}
```

- [ ] **Step 2: Refactor `run-ios-tests.sh` to use the helper**

Replace the current Step-3 block in `ios/scripts/run-ios-tests.sh` (lines 31-61, the `# --- Step 3: resolve the simulator name to a concrete UDID ---` comment through the closing `echo "    -> $SIM_ID"`) with:

```bash
# --- Step 3: resolve the simulator name to a concrete UDID ---
echo "==> resolving simulator: $SIM_NAME"
# shellcheck source=lib/resolve-simulator.sh
source "$SCRIPT_DIR/lib/resolve-simulator.sh"
SIM_ID="$(resolve_simulator "$SIM_NAME")"
echo "    -> $SIM_ID"
```

Leave all other steps (1, 2, 4, 5) of `run-ios-tests.sh` unchanged.

- [ ] **Step 3: Create the TSan runner**

Create `ios/scripts/run-ios-tsan.sh`:

```bash
#!/usr/bin/env bash
# TSan acceptance entry point (#300 follow-up): build the Secretary.xcframework,
# then run the full SecretaryKit XCTest suite under ThreadSanitizer on an iOS
# simulator. The SessionConcurrencyIntegrationTests are the teeth — they drive
# UniffiVaultSession's readBlock/wipe/writes concurrently, so TSan flags any
# unsynchronized access to its mutable state (the #300 lock).
#
# Run from anywhere — paths resolve relative to this script.
# Override the simulator with IOS_SIM, e.g.  IOS_SIM='iPhone 15' run-ios-tsan.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$IOS_DIR/SecretaryKit"
SIM_NAME="${IOS_SIM:-iPhone 16}"

# --- Step 1: build the framework + stage fixtures (golden_vault_001) ---
echo "==> build-xcframework.sh"
bash "$SCRIPT_DIR/build-xcframework.sh"

# --- Step 2: resolve the simulator name to a concrete UDID ---
echo "==> resolving simulator: $SIM_NAME"
# shellcheck source=lib/resolve-simulator.sh
source "$SCRIPT_DIR/lib/resolve-simulator.sh"
SIM_ID="$(resolve_simulator "$SIM_NAME")"
echo "    -> $SIM_ID"

# --- Step 3: run the whole suite under ThreadSanitizer ---
# -enableThreadSanitizer YES instruments the Swift build. The uniffi Rust dylib is
# opaque to TSan (calls into it carry no happens-before), which is fine: the races
# #300 guards are on Swift-side mutable stored properties (currentBlock / wiped /
# cachedDeviceUuid), which NSLock (TSan-aware) synchronizes. xcodebuild's exit
# status is the acceptance result; it is the last command, so `set -e` propagates a
# non-zero test/TSan failure as this script's exit code.
echo "==> xcodebuild test -enableThreadSanitizer YES (simulator: $SIM_NAME / $SIM_ID)"
cd "$PKG_DIR"
xcodebuild test -scheme SecretaryKit \
    -destination "platform=iOS Simulator,id=$SIM_ID" \
    -enableThreadSanitizer YES
```

- [ ] **Step 4: Make the new scripts executable**

Run:
```bash
chmod +x ios/scripts/lib/resolve-simulator.sh ios/scripts/run-ios-tsan.sh
```

- [ ] **Step 5: Verify the resolver function in isolation (fast)**

Run (from repo root):
```bash
bash -c 'set -e; source ios/scripts/lib/resolve-simulator.sh; resolve_simulator "iPhone 16"'
```
Expected: prints a single UDID line (e.g. `A1B2C3D4-...`). If it prints the device list + a non-zero exit, set `IOS_SIM` to an available device name and retry.

- [ ] **Step 6: Verify `run-ios-tests.sh` still works after the refactor**

Run:
```bash
bash ios/scripts/run-ios-tests.sh
```
Expected: same behavior as before — host swift tests pass, xcframework builds, `xcodebuild test` reports `** TEST SUCCEEDED **` (32 tests), app builds. (This is the regression check for the pure extraction.)

- [ ] **Step 7: Verify the existing suite is TSan-clean (before adding new tests)**

Run:
```bash
bash ios/scripts/run-ios-tsan.sh
```
Expected: `** TEST SUCCEEDED **` with **no** `ThreadSanitizer: data race` lines in the output.
**Contingency:** if TSan reports a race originating in the uninstrumented Rust dylib or a system framework (not in `SecretaryKit` Swift code), add a narrowly-scoped, commented suppressions file `ios/SecretaryKit/Tests/SecretaryKitTests/Resources/tsan-suppressions.txt` and pass it via `TSAN_OPTIONS=suppressions=...` in `run-ios-tsan.sh` (stage it like the golden vault if it must be bundled). Resolve every report explicitly — real Swift-side race vs. opaque-FFI false positive; do NOT blanket-suppress. If the existing suite is clean, skip this contingency.

- [ ] **Step 8: Commit**

```bash
git add ios/scripts/lib/resolve-simulator.sh ios/scripts/run-ios-tests.sh ios/scripts/run-ios-tsan.sh
git commit -m "test(ios): add run-ios-tsan.sh + extract shared simulator resolver (#300)"
```

---

### Task 2: Concurrency tests + retire the "not unit-tested" caveat

**Files:**
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/SessionConcurrencyIntegrationTests.swift`
- Modify: `ios/SecretaryKit/Tests/SecretaryKitTests/SessionWipeGuardIntegrationTests.swift` (docstring only)
- Test: the file itself; run via `xcodebuild test`.

**Interfaces:**
- Consumes (existing SecretaryKit API): `SecretaryKit.openVaultWithPassword(folderPath: Data, password: Data) -> OpenVaultOutput`; `UniffiVaultSession(output:deviceUuids:)`; `UniffiVaultSession.blockSummaries() -> [BlockSummary]` (each `.uuid: [UInt8]`); `readBlock(blockUuid: [UInt8], includeDeleted: Bool) throws -> [RecordView]` (each `.uuid: [UInt8]`); `appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8]`; `wipe()`; `RecordContentInput(recordType:tags:fields:)`; `FieldContentInput(name:value:)` with `.text(String)`; `DeviceUuidProviding`.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the concurrency test file**

Create `ios/SecretaryKit/Tests/SecretaryKitTests/SessionConcurrencyIntegrationTests.swift`:

```swift
import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// #300 concurrency coverage: drive `UniffiVaultSession`'s lock-protected paths
/// (readBlock / wipe / writes) from multiple threads at once. Run under
/// ThreadSanitizer (`ios/scripts/run-ios-tsan.sh`) these prove the `NSLock` +
/// `wiped` guard actually serialize access to the mutable stored properties
/// `currentBlock`, `wiped`, and `cachedDeviceUuid`: with the lock TSan sees a clean
/// happens-before; remove the lock and TSan reports a data race here. Assertions are
/// deliberately timing-independent (no-crash + count/contents that hold under any
/// interleaving), so the tests are NOT flaky — only race *detection*, which TSan
/// does deterministically.
///
/// Opens a temp copy of the frozen `golden_vault_001` KAT (never mutates the
/// original), mirroring `SessionWipeGuardIntegrationTests`.
final class SessionConcurrencyIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    /// Concurrent worker threads per scenario — large enough that accesses reliably
    /// overlap, small enough to keep the (TSan-slowed) run quick.
    private static let concurrentWorkers = 8
    /// Fresh sessions for the read-vs-wipe scenario: each session's `wipe()` is
    /// terminal, so every concurrent read-vs-wipe sample needs its own session.
    private static let wipeRaceSessions = 4

    /// Shares a non-`Sendable` value across threads. The unsafety is the POINT under
    /// test: `UniffiVaultSession`'s lock is what makes the concurrent access
    /// race-free. Confined to this test target.
    private final class UncheckedBox<T>: @unchecked Sendable {
        let value: T
        init(_ value: T) { self.value = value }
    }

    /// Thread-safe accumulator for results gathered across worker threads.
    private final class Collector<T>: @unchecked Sendable {
        private var items: [T] = []
        private let lock = NSLock()
        func add(_ item: T) { lock.withLock { items.append(item) } }
        var snapshot: [T] { lock.withLock { items } }
    }

    private struct FixedDeviceUuid: DeviceUuidProviding {
        let value: [UInt8]
        func deviceUuid(forVaultHex vaultHex: String) throws -> [UInt8] { value }
    }

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-concurrency-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy {
            try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent())
        }
    }

    private func openSession() throws -> UniffiVaultSession {
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: Data(vaultCopy.path.utf8), password: Data(goldenPassword.utf8))
        return UniffiVaultSession(
            output: out, deviceUuids: FixedDeviceUuid(value: [UInt8](repeating: 0x5A, count: 16)))
    }

    private func firstBlockUuid(_ session: UniffiVaultSession) throws -> [UInt8] {
        try XCTUnwrap(session.blockSummaries().first).uuid
    }

    /// Concurrent reads of the same block are race-free. Exercises the `currentBlock`
    /// evict-and-replace path under contention; every read sees the same fully
    /// decoded block as a single-threaded read.
    func testConcurrentReadsAreRaceFree() throws {
        let session = try openSession()
        let block = try firstBlockUuid(session)
        let baseline = try session.readBlock(blockUuid: block, includeDeleted: false).count
        let box = UncheckedBox(session)
        let blockBox = UncheckedBox(block)
        DispatchQueue.concurrentPerform(iterations: Self.concurrentWorkers) { _ in
            let records = (try? box.value.readBlock(blockUuid: blockBox.value, includeDeleted: false)) ?? []
            XCTAssertEqual(records.count, baseline, "a concurrent read saw a different record count")
        }
    }

    /// Concurrent reads racing one `wipe()` must not crash. Each read either returns
    /// records, returns empty, or throws — all valid open/closed outcomes. The
    /// assertion is reaching the end without a crash or a TSan report on the
    /// `currentBlock`/`wiped` race.
    func testConcurrentReadAndWipeAreRaceFree() throws {
        for _ in 0..<Self.wipeRaceSessions {
            let session = try openSession()
            let block = try firstBlockUuid(session)
            let box = UncheckedBox(session)
            let blockBox = UncheckedBox(block)
            let group = DispatchGroup()
            let queue = DispatchQueue(label: "secretary.concurrency.readwipe", attributes: .concurrent)
            for _ in 0..<Self.concurrentWorkers {
                queue.async(group: group) {
                    _ = try? box.value.readBlock(blockUuid: blockBox.value, includeDeleted: false)
                }
            }
            queue.async(group: group) { box.value.wipe() }
            group.wait()
        }
    }

    /// Concurrent writes are race-free and all land. Exercises `write()`
    /// serialization + the first-write `cachedDeviceUuid` memoization; every appended
    /// record is present on a final single-threaded read.
    func testConcurrentWritesAreRaceFree() throws {
        let session = try openSession()
        let block = try firstBlockUuid(session)
        let box = UncheckedBox(session)
        let blockBox = UncheckedBox(block)
        let appended = Collector<Data>()
        DispatchQueue.concurrentPerform(iterations: Self.concurrentWorkers) { i in
            let content = RecordContentInput(
                recordType: "login", tags: ["concurrent"],
                fields: [FieldContentInput(name: "idx", value: .text("\(i)"))])
            if let uuid = try? box.value.appendRecord(blockUuid: blockBox.value, content: content) {
                appended.add(Data(uuid))
            }
        }
        let got = appended.snapshot
        XCTAssertEqual(got.count, Self.concurrentWorkers, "every concurrent append must succeed")
        let records = try session.readBlock(blockUuid: block, includeDeleted: false)
        let present = Set(records.map { Data($0.uuid) })
        for uuid in got {
            XCTAssertTrue(present.contains(uuid), "an appended record was missing after concurrent writes")
        }
    }
}
```

- [ ] **Step 2: Run the new tests (normal build) to confirm they pass**

Run:
```bash
SIM_ID="$(bash -c 'source ios/scripts/lib/resolve-simulator.sh; resolve_simulator "iPhone 16"')"
cd ios/SecretaryKit
xcodebuild test -scheme SecretaryKit -destination "platform=iOS Simulator,id=$SIM_ID" \
  -only-testing:SecretaryKitTests/SessionConcurrencyIntegrationTests
cd ../..
```
Expected: `** TEST SUCCEEDED **`, 3 tests pass. (They pass because the #304 lock is present; this confirms the tests are correct and don't deadlock/crash.)

- [ ] **Step 3: Prove the tests have teeth (TDD red, under TSan)**

Temporarily neuter the lock to confirm TSan flags the race. In `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift`, comment out the `lock.withLock {` wrappers in `readBlock`, `wipe`, and `write` (and their matching closing braces) so the bodies run unguarded. Then run:
```bash
bash ios/scripts/run-ios-tsan.sh 2>&1 | tee /tmp/tsan-red.log
grep -c "ThreadSanitizer: data race" /tmp/tsan-red.log
```
Expected: one or more `ThreadSanitizer: data race` reports naming `UniffiVaultSession` / `currentBlock` / `wiped` / `cachedDeviceUuid` (count ≥ 1), and/or a crash. **Capture this output for the handoff** (evidence the tests have teeth).

- [ ] **Step 4: Restore the lock and confirm green under TSan**

`git checkout ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultSession.swift` to undo the temporary edit, then:
```bash
bash ios/scripts/run-ios-tsan.sh 2>&1 | tee /tmp/tsan-green.log
grep -c "ThreadSanitizer: data race" /tmp/tsan-green.log   # expect 0
```
Expected: `** TEST SUCCEEDED **`, full suite (35 tests) passes, **zero** `ThreadSanitizer: data race` lines.

- [ ] **Step 5: Update the wipe-guard docstring**

In `ios/SecretaryKit/Tests/SecretaryKitTests/SessionWipeGuardIntegrationTests.swift`, replace the docstring sentence:

```swift
/// The lock's mutual exclusion under genuine concurrency is
/// by-construction + documented (not unit-tested — a deterministic interleave would
/// need an injected mid-read seam; a stress test would be flaky).
```

with:

```swift
/// The lock's mutual exclusion under genuine concurrency is exercised separately by
/// `SessionConcurrencyIntegrationTests` (run under ThreadSanitizer via
/// `ios/scripts/run-ios-tsan.sh`); this file covers the single-threaded `wiped`-guard
/// semantics.
```

- [ ] **Step 6: Re-run the full suite (normal build) to confirm no regression**

Run:
```bash
SIM_ID="$(bash -c 'source ios/scripts/lib/resolve-simulator.sh; resolve_simulator "iPhone 16"')"
cd ios/SecretaryKit
xcodebuild test -scheme SecretaryKit -destination "platform=iOS Simulator,id=$SIM_ID"
cd ../..
```
Expected: `** TEST SUCCEEDED **`, 35 tests (32 existing + 3 new).

- [ ] **Step 7: Commit**

```bash
git add ios/SecretaryKit/Tests/SecretaryKitTests/SessionConcurrencyIntegrationTests.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/SessionWipeGuardIntegrationTests.swift
git commit -m "test(ios): concurrency tests for UniffiVaultSession lock under TSan (#300)"
```

---

### Task 3: Path-gated macOS TSan CI job

**Files:**
- Create: `.github/workflows/ios-tsan.yml`

**Interfaces:**
- Consumes: `ios/scripts/run-ios-tsan.sh` (Task 1).
- Produces: nothing.

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/ios-tsan.yml`:

```yaml
name: iOS TSan

# #300 follow-up: run the SecretaryKit XCTest suite under ThreadSanitizer so the
# UniffiVaultSession lock is exercised under genuine concurrency
# (SessionConcurrencyIntegrationTests). macOS-only and heavy (builds the uniffi
# xcframework, then runs the suite instrumented), so it is path-gated to iOS
# changes. A separate workflow file is the cleanest no-third-party-action way to
# scope this without gating test.yml's rust/desktop/conformance jobs (which must
# run on every PR).

on:
  push:
    branches: [main]
    paths:
      - 'ios/**'
      - '.github/workflows/ios-tsan.yml'
  pull_request:
    paths:
      - 'ios/**'
      - '.github/workflows/ios-tsan.yml'

concurrency:
  group: ios-tsan-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  ios-tsan:
    name: SecretaryKit ThreadSanitizer
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - name: Cache cargo build
        uses: Swatinem/rust-cache@v2
      # Builds the uniffi xcframework (compiles the Rust core for the iOS-sim
      # target) then runs the whole SecretaryKit suite under -enableThreadSanitizer.
      - name: SecretaryKit suite under ThreadSanitizer
        run: bash ios/scripts/run-ios-tsan.sh
```

- [ ] **Step 2: Validate the workflow YAML**

Run (uses the pinned actionlint container; no global install):
```bash
docker run --rm -v "$(pwd):/repo" --workdir /repo rhysd/actionlint:latest -color .github/workflows/ios-tsan.yml
```
Expected: no errors. If `docker` is unavailable, instead confirm valid YAML:
```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ios-tsan.yml')); print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ios-tsan.yml
git commit -m "ci(ios): path-gated macOS ThreadSanitizer job for SecretaryKit (#300)"
```

---

## Self-Review

**1. Spec coverage:**
- Concurrency tests (reads / read+wipe / writes) → Task 2, Step 1. ✓
- `@unchecked Sendable` box → Task 2 (`UncheckedBox`). ✓
- Timing-independent assertions → Task 2 (count/contents/no-crash only). ✓
- No magic numbers → Task 2 (`concurrentWorkers`, `wipeRaceSessions` constants). ✓
- Temp-copy golden vault → Task 2 (`setUpWithError` `copyItem`). ✓
- `run-ios-tsan.sh` whole suite under TSan → Task 1, Step 3. ✓
- Extracted shared resolver → Task 1, Steps 1-2. ✓
- Path-gated CI, no unpinned third-party action → Task 3. ✓
- TDD red→green proof → Task 2, Steps 3-4. ✓
- Docstring update → Task 2, Step 5. ✓
- README/ROADMAP/spec/conformance untouched → Global Constraints + no task touches them. ✓
- TSan-suppressions contingency for FFI false positives → Task 1, Step 7 contingency. ✓

**2. Placeholder scan:** No TBD/TODO/"add error handling"/"similar to" — all steps carry concrete code/commands. ✓

**3. Type consistency:** `resolve_simulator` used identically in both scripts; `UncheckedBox`/`Collector` defined and used within one file; `RecordView.uuid: [UInt8]` and `appendRecord -> [UInt8]` both bridged via `Data(...)` for the `Set<Data>` membership check; `concurrentWorkers`/`wipeRaceSessions` referenced exactly as named. ✓
