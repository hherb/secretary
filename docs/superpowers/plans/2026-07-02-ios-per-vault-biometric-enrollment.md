# iOS per-vault-keyed biometric enrollment (#347) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scope "Unlock with Face ID" to the vault actually being opened by namespacing the Secure-Enclave key and enrollment metadata per vault (SHA-256 of the vault path), so a multi-vault user never gets a doomed biometric prompt for a vault this device isn't enrolled for.

**Architecture:** Mirror Android's per-vault model — per-vault-ness lives in the Keychain storage keys, not in the `DeviceEnrollment` struct. A pure derivation in the FFI-free `SecretaryDeviceUnlock` package turns a vault path into a stable `vaultKey` and the three per-vault Keychain identifiers; a thin `SecretaryKit` factory (`makePerVaultDeviceUnlock`) builds a coordinator + same-keyed enclave from those identifiers; the six app construction sites (all of which already hold the vault path) call the factory. `coordinator.isEnrolled` then becomes correct-by-construction; no coordinator/enclave protocol changes.

**Tech Stack:** Swift 6 (strict concurrency), Swift Package Manager, CryptoKit (system framework, `SHA256`), XCTest. iOS 17 / macOS 13.

## Global Constraints

- **iOS-only.** No `core`/`ffi` Rust, no on-disk vault-format / spec / conformance / FFI-surface change. No change to `DeviceEnrollment`, `DeviceEnrollmentMetadataStore`, `DeviceSecretEnclave`, or `DeviceUnlockCoordinator` *APIs*.
- **No magic numbers.** The hex length is a named constant `sha256HexLength = 64`.
- **Swift 6 strict concurrency is a hard compile error.** New public types crossing actor boundaries must be `Sendable` (the existing enclave/coordinator are already `Sendable`).
- **TDD, DRY, YAGNI, frequent commits.** Pure logic gets real unit tests; the factory is thin composition proven by compile + existing suites.
- **`#![forbid(unsafe_code)]` is Rust-side only; N/A here — but do not introduce force-unwraps on untrusted input.**
- **Files stay focused / under ~500 lines.**
- **Keychain services stay stable; the per-vault key rides in the account / applicationTag** (`blobService = "com.secretary.deviceSecret"`, enrollment `service = "com.secretary.enrollment"` unchanged).
- **Reuse existing constructor parameters:** `SecureEnclaveDeviceSecretStore(keyTag:blobService:blobAccount:)` and `KeychainEnrollmentMetadataStore(service:account:)` are already parameterizable — do not add new adapter parameters.

---

### Task 1: Pure per-vault key + identifier derivation

**Files:**
- Create: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/PerVaultDeviceUnlockIdentifiers.swift`
- Test: `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/PerVaultDeviceUnlockIdentifiersTests.swift`

**Interfaces:**
- Consumes: nothing (leaf module; CryptoKit system framework).
- Produces (relied on by Task 2):
  - `func vaultKey(fromPath vaultPath: Data) -> String` — lowercase SHA-256 hex (64 chars).
  - `struct PerVaultDeviceUnlockIdentifiers: Equatable, Sendable { let seKeyTag: String; let blobService: String; let blobAccount: String; let enrollmentService: String; let enrollmentAccount: String }`
  - `func perVaultDeviceUnlockIdentifiers(vaultPath: Data) -> PerVaultDeviceUnlockIdentifiers`
  - `let sha256HexLength = 64` (internal constant).

- [ ] **Step 1: Write the failing test**

Create `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/PerVaultDeviceUnlockIdentifiersTests.swift`:

```swift
import XCTest
import Crypto
@testable import SecretaryDeviceUnlock

final class PerVaultDeviceUnlockIdentifiersTests: XCTestCase {
    // Fixed known-answer: SHA-256("secretary") lowercase hex.
    // Pinned vector (KAT-style) so a hashing change is caught, per the repo's
    // "KATs via fixtures / random elsewhere" discipline.
    private let sampleBytes = Data("secretary".utf8)
    private let sampleKey =
        "a8148532caf684760a38c6e5100fe4742cbe0c0030df36ad74a71abbad4d8369"

    func testVaultKeyIsPinnedSha256Hex() {
        XCTAssertEqual(vaultKey(fromPath: sampleBytes), sampleKey)
    }

    func testVaultKeyIsDeterministic() {
        XCTAssertEqual(vaultKey(fromPath: Data("/a/b/c".utf8)),
                       vaultKey(fromPath: Data("/a/b/c".utf8)))
    }

    func testDifferentPathsYieldDifferentKeys() {
        XCTAssertNotEqual(vaultKey(fromPath: Data("/vault/a".utf8)),
                          vaultKey(fromPath: Data("/vault/b".utf8)))
    }

    func testVaultKeyIsLowercaseHexOfExpectedLength() {
        let key = vaultKey(fromPath: Data("/some/path".utf8))
        XCTAssertEqual(key.count, sha256HexLength)
        XCTAssertTrue(key.allSatisfy { "0123456789abcdef".contains($0) })
    }

    func testIdentifiersCarryDocumentedPrefixesAndVaultKey() {
        let path = Data("/vault/a".utf8)
        let key = vaultKey(fromPath: path)
        let ids = perVaultDeviceUnlockIdentifiers(vaultPath: path)
        XCTAssertEqual(ids.seKeyTag, "com.secretary.deviceSecret.seKey.\(key)")
        XCTAssertEqual(ids.blobService, "com.secretary.deviceSecret")
        XCTAssertEqual(ids.blobAccount, "wrappedDeviceSecret.\(key)")
        XCTAssertEqual(ids.enrollmentService, "com.secretary.enrollment")
        XCTAssertEqual(ids.enrollmentAccount, "deviceEnrollment.\(key)")
    }

    func testDifferentVaultsYieldDistinctPerVaultIdentifiers() {
        let a = perVaultDeviceUnlockIdentifiers(vaultPath: Data("/vault/a".utf8))
        let b = perVaultDeviceUnlockIdentifiers(vaultPath: Data("/vault/b".utf8))
        XCTAssertNotEqual(a.seKeyTag, b.seKeyTag)
        XCTAssertNotEqual(a.blobAccount, b.blobAccount)
        XCTAssertNotEqual(a.enrollmentAccount, b.enrollmentAccount)
        // Stable, shared services group all Secretary items under one service.
        XCTAssertEqual(a.blobService, b.blobService)
        XCTAssertEqual(a.enrollmentService, b.enrollmentService)
    }
}
```

Note on the import: this repo's pure packages run on the macOS host. Use `import Crypto` only if a swift-crypto dependency exists; otherwise use `import CryptoKit`. **This plan uses CryptoKit (system framework, no dependency).** If the test file above shows `import Crypto`, change it to `import CryptoKit` before running — see Step 3, which also imports CryptoKit in the source. (Keep the two in sync.)

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd ios/SecretaryDeviceUnlock && swift test --filter PerVaultDeviceUnlockIdentifiersTests
```
Expected: FAIL to compile — `vaultKey` / `perVaultDeviceUnlockIdentifiers` / `sha256HexLength` / `PerVaultDeviceUnlockIdentifiers` are undefined.

- [ ] **Step 3: Write minimal implementation**

Create `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/PerVaultDeviceUnlockIdentifiers.swift`:

```swift
import Foundation
import CryptoKit

/// Length of a lowercase SHA-256 hex string (32 bytes × 2).
let sha256HexLength = 64

/// Stable per-vault namespace token: lowercase SHA-256 hex of the vault path
/// bytes. Pure — same path → same key; different path → (overwhelmingly)
/// different key. The iOS mirror of Android's `cloudVaultKey(treeUri)`.
///
/// Not security-critical: this is a namespacing hash for Keychain accounts, not
/// a KDF. Correctness (the opened vault matches the enrollment) is still enforced
/// by the coordinator's `vaultId` guard and the post-open UUID check.
public func vaultKey(fromPath vaultPath: Data) -> String {
    SHA256.hash(data: vaultPath)
        .map { String(format: "%02x", $0) }
        .joined()
}

/// The three Keychain identifiers that isolate one vault's device-unlock state
/// from another's. Services stay stable (all Secretary items share one service);
/// the per-vault key rides in the account / applicationTag.
public struct PerVaultDeviceUnlockIdentifiers: Equatable, Sendable {
    public let seKeyTag: String
    public let blobService: String
    public let blobAccount: String
    public let enrollmentService: String
    public let enrollmentAccount: String
}

/// Derive the per-vault Keychain identifiers for a vault path. Pure.
public func perVaultDeviceUnlockIdentifiers(vaultPath: Data) -> PerVaultDeviceUnlockIdentifiers {
    let key = vaultKey(fromPath: vaultPath)
    return PerVaultDeviceUnlockIdentifiers(
        seKeyTag: "com.secretary.deviceSecret.seKey.\(key)",
        blobService: "com.secretary.deviceSecret",
        blobAccount: "wrappedDeviceSecret.\(key)",
        enrollmentService: "com.secretary.enrollment",
        enrollmentAccount: "deviceEnrollment.\(key)")
}
```

Then fix the test's import to `import CryptoKit` (delete `import Crypto`).

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
cd ios/SecretaryDeviceUnlock && swift test --filter PerVaultDeviceUnlockIdentifiersTests
```
Expected: PASS (6 tests). If `testVaultKeyIsPinnedSha256Hex` fails, verify the pinned vector equals `printf secretary | shasum -a 256` (`a8148532caf684760a38c6e5100fe4742cbe0c0030df36ad74a71abbad4d8369`).

- [ ] **Step 5: Run the whole pure package to confirm no regression**

Run:
```bash
cd ios/SecretaryDeviceUnlock && swift test
```
Expected: PASS (all existing SecretaryDeviceUnlock + UI tests plus the new file).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/PerVaultDeviceUnlockIdentifiers.swift \
        ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/PerVaultDeviceUnlockIdentifiersTests.swift
git commit -m "feat(ios): pure per-vault device-unlock key + identifier derivation (#347)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `makePerVaultDeviceUnlock` factory

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/PerVaultDeviceUnlock.swift`

**Interfaces:**
- Consumes (from Task 1): `perVaultDeviceUnlockIdentifiers(vaultPath:) -> PerVaultDeviceUnlockIdentifiers`.
- Consumes (existing): `SecureEnclaveDeviceSecretStore(keyTag:blobService:blobAccount:)`, `KeychainEnrollmentMetadataStore(service:account:)`, `UniffiVaultDeviceSlotPort()`, `DeviceUnlockCoordinator(slotPort:enclave:metadata:)`.
- Produces (relied on by Task 3):
  - `struct PerVaultDeviceUnlock { let coordinator: DeviceUnlockCoordinator; let enclave: DeviceSecretEnclave }`
  - `func makePerVaultDeviceUnlock(vaultPath: Data) -> PerVaultDeviceUnlock`

This task is thin composition. Its correctness (the keying) is proven by Task 1's pure tests; its wiring is proven by compile + the existing on-simulator suites in Task 4. No new unit test (a Keychain-touching factory test would be a real-device/simulator test with no logic beyond what Task 1 already covers — adding one would be vacuous). The deliverable is a clean compile.

- [ ] **Step 1: Write the implementation**

Create `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/PerVaultDeviceUnlock.swift`:

```swift
import Foundation
import SecretaryDeviceUnlock

/// A vault-scoped device-unlock bundle: the coordinator (enroll / isEnrolled /
/// unlock) and the SAME-keyed enclave (needed by the write-reauth gate's
/// `EnclaveBiometricAuthorizer`, which must act on this vault's Secure-Enclave
/// key). iOS analog of Android's `cloudDeviceUnlockCoordinator`.
public struct PerVaultDeviceUnlock {
    public let coordinator: DeviceUnlockCoordinator
    public let enclave: DeviceSecretEnclave
}

/// Build the per-vault device-unlock bundle for `vaultPath`. All Keychain state
/// (Secure-Enclave key, wrapped-secret blob, enrollment metadata) is namespaced
/// by `vaultKey(fromPath:)`, so one vault's enrollment is invisible to another's
/// coordinator — `coordinator.isEnrolled` is thus correct per vault.
public func makePerVaultDeviceUnlock(vaultPath: Data) -> PerVaultDeviceUnlock {
    let ids = perVaultDeviceUnlockIdentifiers(vaultPath: vaultPath)
    let enclave = SecureEnclaveDeviceSecretStore(
        keyTag: ids.seKeyTag,
        blobService: ids.blobService,
        blobAccount: ids.blobAccount)
    let metadata = KeychainEnrollmentMetadataStore(
        service: ids.enrollmentService,
        account: ids.enrollmentAccount)
    let coordinator = DeviceUnlockCoordinator(
        slotPort: UniffiVaultDeviceSlotPort(),
        enclave: enclave,
        metadata: metadata)
    return PerVaultDeviceUnlock(coordinator: coordinator, enclave: enclave)
}
```

- [ ] **Step 2: Compile-check SecretaryKit**

Run:
```bash
cd ios/SecretaryKit && swift build
```
Expected: build succeeds (the SecretaryFFI xcframework must already be built — if `swift build` complains about the missing binary target, run `bash ios/scripts/build-xcframework.sh` once first, then re-run).

- [ ] **Step 3: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/PerVaultDeviceUnlock.swift
git commit -m "feat(ios): makePerVaultDeviceUnlock factory over per-vault Keychain keying (#347)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Rewire the six app construction sites to per-vault

**Files:**
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift`
- Modify: `ios/SecretaryApp/Sources/DeviceUnlockOpen.swift`

**Interfaces:**
- Consumes (from Task 2): `makePerVaultDeviceUnlock(vaultPath:) -> PerVaultDeviceUnlock`.

All six sites already have the vault path (`scoped.pathData`, or `vaultPath:` for `DeviceUnlockOpen.open`). This task replaces the device-global `SecureEnclaveDeviceSecretStore()` / `localCoordinator()` constructions with factory calls.

- [ ] **Step 1: Replace `localCoordinator()` and the password-path gate in `SecretaryApp.swift`**

`localCoordinator()` (currently at ~lines 253-257) is device-global and is called at four sites. Delete it and replace each caller with `makePerVaultDeviceUnlock(vaultPath:)`.

1a. `.select` `onOpen` (currently ~line 73):

```swift
onOpen: { scoped in
    biometricUnlockError = nil          // reset on route entry
    rememberDevice = false               // reset on route entry (#342-safe)
    // Per-vault snapshot: only true when THIS vault is enrolled (#347).
    biometricEnrolled = makePerVaultDeviceUnlock(vaultPath: scoped.pathData)
        .coordinator.isEnrolled
    route = .unlock(scoped)
},
```

1b. `.unlock` case (currently ~line 96): replace `let coordinator = localCoordinator()` with:

```swift
case .unlock(let scoped):
    let coordinator = makePerVaultDeviceUnlock(vaultPath: scoped.pathData).coordinator
    UnlockScreen(
```

1c. `onUnlocked` enroll block (currently ~line 154): replace `let coordinator = localCoordinator()` with:

```swift
                                let coordinator = makePerVaultDeviceUnlock(vaultPath: scoped.pathData).coordinator
                                let vaultPath = scoped.pathData
                                let vaultId = session.vaultUuidHex
```

(Leave the surrounding off-main-actor enroll `Task` and its comment unchanged.)

1d. `onUnlocked` password-path gate (currently ~lines 189-192): the gate's authorizer enclave must be this vault's enclave:

```swift
                            let gate = GraceWindowReauthGate(
                                authorizer: EnclaveBiometricAuthorizer(
                                    enclave: makePerVaultDeviceUnlock(vaultPath: scoped.pathData).enclave),
                                clock: MonotonicInstant.now)   // initialAuthAt stays nil (#284)
```

1e. `openDemo()` (currently ~line 247):

```swift
        biometricEnrolled = makePerVaultDeviceUnlock(vaultPath: scoped.pathData)
            .coordinator.isEnrolled  // per-vault snapshot (#347)
```

1f. Delete the now-unused `localCoordinator()` method (~lines 251-258) and its doc comment.

- [ ] **Step 2: Replace the biometric-path gate in `DeviceUnlockOpen.swift`**

In `DeviceUnlockOpen.open` (currently ~lines 56-59), the success-path gate's authorizer enclave must be this vault's enclave. The function already has `vaultPath: Data`:

```swift
            let gate = GraceWindowReauthGate(
                authorizer: EnclaveBiometricAuthorizer(
                    enclave: makePerVaultDeviceUnlock(vaultPath: vaultPath).enclave),
                clock: MonotonicInstant.now,
                initialAuthAt: reauthInitialAuthAt(biometricUnlock: true, now: MonotonicInstant.now()))
```

Ensure `import SecretaryKit` is present at the top of `DeviceUnlockOpen.swift` (it already is — the factory lives in SecretaryKit).

- [ ] **Step 3: Build the app (compile proof)**

Run:
```bash
bash ios/scripts/build-app.sh
```
Expected: XcodeGen + simulator compile succeeds. If it fails on a missing xcframework, run `bash ios/scripts/build-xcframework.sh` first. (This build is multi-minute and silent — run it patiently; do not background-poll from a watchdog-bounded subagent. See the repo's xcframework-build note.)

- [ ] **Step 4: Commit**

```bash
git add ios/SecretaryApp/Sources/SecretaryApp.swift ios/SecretaryApp/Sources/DeviceUnlockOpen.swift
git commit -m "feat(ios): scope Face ID unlock + reauth gate to the opened vault (#347)

Route every device-unlock construction site through makePerVaultDeviceUnlock,
so 'Unlock with Face ID' shows only for the enrolled vault and the write-reauth
grace gate is armed per vault. Removes the device-global localCoordinator().

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Full iOS acceptance run (no regression)

**Files:** none (verification only).

- [ ] **Step 1: Run the full iOS test entry point**

Run:
```bash
bash ios/scripts/run-ios-tests.sh
```
Expected: green end-to-end —
- Step 1 host `swift test` (pure `SecretaryDeviceUnlock`) includes the new `PerVaultDeviceUnlockIdentifiersTests`;
- the xcframework builds;
- `SecretaryKit` XCTest passes on the simulator (including the unchanged `DeviceUnlockIntegrationTests` / `EnclaveBiometricAuthorizerTests` — no regression);
- the app builds.

This is the multi-minute xcframework path — warm-build once and let it run to completion; do not abort on the silent build phase.

- [ ] **Step 2: Confirm no stray device-global construction remains**

Run:
```bash
grep -rn "SecureEnclaveDeviceSecretStore()" ios/SecretaryApp ios/SecretaryKit/Sources
grep -rn "localCoordinator" ios/SecretaryApp
```
Expected: no matches (every enclave construction now flows through `makePerVaultDeviceUnlock`; the two grace-gate sites that build `SecureEnclaveDeviceSecretStore()` directly are gone). A remaining match in `DeviceUnlockOpen`/`SecretaryApp` is a missed site — fix it before proceeding.

- [ ] **Step 3: No commit** (verification task; nothing changed).

---

### Task 5: Docs + baton

**Files:**
- Modify: `README.md` (iOS status line, if it references vault-agnostic Face ID)
- Modify: `ROADMAP.md` (mark #347 addressed)
- Create: `docs/handoffs/2026-07-02-ios-per-vault-biometric-enrollment-347-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget symlink)

- [ ] **Step 1: Update README.md / ROADMAP.md**

Locate the iOS device-unlock status and the #347 mention (search: `grep -rn "347\|Face ID\|vault-agnostic" README.md ROADMAP.md`). Update to reflect that Face ID unlock is now vault-scoped (per-vault Keychain keying); keep README status terse (dot points), per the README-style rule.

- [ ] **Step 2: Author the handoff**

Create `docs/handoffs/2026-07-02-ios-per-vault-biometric-enrollment-347-shipped.md` capturing: what shipped (with commit SHAs), acceptance commands + results, open decisions/risks (path-hash stability; reauth gate now per-vault; no migration), and the exact resume commands.

- [ ] **Step 3: Retarget the NEXT_SESSION.md symlink**

```bash
ln -snf docs/handoffs/2026-07-02-ios-per-vault-biometric-enrollment-347-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows the -> target
head -3 NEXT_SESSION.md  # reads the handoff transparently
```

- [ ] **Step 4: Commit docs + handoff together**

```bash
git add README.md ROADMAP.md docs/handoffs/2026-07-02-ios-per-vault-biometric-enrollment-347-shipped.md NEXT_SESSION.md
git commit -m "docs: README/ROADMAP + handoff — iOS per-vault Face ID (#347)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 5: Push + open PR**

```bash
git push -u origin feature/ios-per-vault-biometric-enrollment-347
gh pr create --title "feat(ios): per-vault-keyed biometric enrollment (#347)" --body "<summary + Closes #347 + acceptance>"
```

---

## Self-Review

**Spec coverage:**
- §2 approach (storage-key namespacing, no struct field) → Tasks 1–3. ✓
- §3.1 pure `vaultKey` in FFI-free package → Task 1. ✓
- §3.2 namespacing scheme (SE tag / blob account / enrollment account; stable services) → Task 1 (`perVaultDeviceUnlockIdentifiers` + tests) → Task 2 (wired). ✓
- §3.3 factory returning coordinator + same-keyed enclave → Task 2. ✓
- §3.4 all six call sites → Task 3 (steps 1a–1f + 2). ✓
- §5 reauth gate becomes per-vault → Task 3 steps 1d + 2 (both gate sites use `.enclave`). ✓
- §6 testing (pure host tests; factory by compile + existing suites) → Task 1 + Task 4. ✓
- §5 risks (path stability, no migration, demo included) → captured in Task 5 handoff. ✓

**Placeholder scan:** none — every code step shows full code; the only `<...>` is the PR body free-text in Task 5 Step 5 (intended). ✓

**Type consistency:** `vaultKey(fromPath:)`, `perVaultDeviceUnlockIdentifiers(vaultPath:)`, `PerVaultDeviceUnlockIdentifiers` (fields `seKeyTag`/`blobService`/`blobAccount`/`enrollmentService`/`enrollmentAccount`), `PerVaultDeviceUnlock` (`coordinator`/`enclave`), `makePerVaultDeviceUnlock(vaultPath:)` — used identically across Tasks 1→2→3. Constructor labels match the verified existing signatures `SecureEnclaveDeviceSecretStore(keyTag:blobService:blobAccount:)` and `KeychainEnrollmentMetadataStore(service:account:)`. ✓
