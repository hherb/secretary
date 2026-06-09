# D.3 slice 1 — iOS XCFramework + linked-call proof — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a reproducible iOS XCFramework build pipeline for the `secretary-ffi-uniffi` bindings and an automated `xcodebuild` XCTest that opens `golden_vault_001` on an iOS simulator — proving `secretary-core` runs through uniffi on-device.

**Architecture:** Add a `staticlib` crate-type to the uniffi crate; a shell script cross-compiles it for the three iOS triples, generates Swift bindings via the in-crate `uniffi-bindgen`, and assembles an XCFramework (device slice + lipo'd simulator slice + headers/modulemap). A Swift Package (`ios/SecretaryKit/`) consumes the XCFramework via a `binaryTarget`; an XCTest target opens the golden vault on a simulator. A second script runs the whole thing one-command and exits non-zero on failure.

**Tech Stack:** Rust (stable, cross-compiled to `aarch64-apple-ios`/`aarch64-apple-ios-sim`/`x86_64-apple-ios`), `uniffi 0.31`, `xcodebuild -create-xcframework`, Swift Package Manager, XCTest, iOS Simulator.

**Spec:** `docs/superpowers/specs/2026-06-09-d3-ios-xcframework-linkproof-design.md` (source of truth).

**Worktree / branch:** all work in `.worktrees/d3-ios-xcframework` on `feature/d3-ios-xcframework`. Run every command from the worktree root unless stated otherwise.

---

## File structure

| Path | Responsibility | Committed? |
|---|---|---|
| `ffi/secretary-ffi-uniffi/Cargo.toml` | add `"staticlib"` to crate-type (additive) | yes (modify) |
| `ios/.gitignore` | ignore generated XCFramework, generated swift, staged fixture, `.build/` | yes |
| `ios/scripts/build-xcframework.sh` | cross-compile + bindgen + assemble xcframework + stage fixture | yes |
| `ios/scripts/run-ios-tests.sh` | build, then `xcodebuild test` on a simulator; the acceptance entry point | yes |
| `ios/SecretaryKit/Package.swift` | SPM manifest: `binaryTarget` + lib + test target | yes |
| `ios/SecretaryKit/Sources/SecretaryKit/secretary.swift` | generated high-level Swift API | **no** (generated) |
| `ios/SecretaryKit/Tests/SecretaryKitTests/OpenVaultLinkTests.swift` | the linked-call proof XCTest | yes |
| `ios/SecretaryKit/Tests/SecretaryKitTests/Resources/` | staged `golden_vault_001` + inputs json | **no** (staged) |
| `ios/Secretary.xcframework/` | assembled XCFramework | **no** (generated) |
| `ios/README.md` | update from bare placeholder | yes (modify) |
| `README.md`, `ROADMAP.md` | D.3 slice 1 status | yes (modify) |

## Exact binding API (verified against `src/secretary.udl`)

- `func openVaultWithPassword(folderPath: Data, password: Data) throws -> OpenVaultOutput`
  - `folderPath` = the vault directory path as UTF-8 `Data` (`Data(url.path.utf8)`).
  - golden_vault_001 password = `"correct horse battery staple"`.
- `OpenVaultOutput` has `.identity: UnlockedIdentity` and `.manifest: OpenVaultManifest` — **both are live handles; wipe both.**
- `OpenVaultManifest`: `func vaultUuid() -> Data` (16 bytes), `func blockCount() -> UInt64`, `func wipe()`.
- `UnlockedIdentity`: `func wipe()`.
- Wrong password throws `VaultError.WrongPasswordOrCorrupt`.
- golden_vault_001 pinned `vault_uuid` = `00112233-4455-6677-8899-aabbccddeeff` (read at test time from the bundled `golden_vault_001_inputs.json`, dash-stripped + hex-decoded to 16 bytes — do not hardcode the byte array).

---

### Task 1: Add the `staticlib` crate-type and prove it is additive

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/Cargo.toml` (the `[lib] crate-type` line)

- [ ] **Step 1: Read the current crate-type line**

Run: `grep -n 'crate-type' ffi/secretary-ffi-uniffi/Cargo.toml`
Expected: `crate-type = ["cdylib", "rlib"]`

- [ ] **Step 2: Add `"staticlib"`**

Edit `ffi/secretary-ffi-uniffi/Cargo.toml` so the line reads:

```toml
crate-type = ["cdylib", "rlib", "staticlib"]
```

- [ ] **Step 3: Install the iOS Rust targets (idempotent, one-time network fetch)**

Run:
```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
```
Expected: each prints "info: installing component" or "is up to date".

- [ ] **Step 4: Prove the staticlib cross-compiles for all three iOS triples**

Run:
```bash
for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  cargo build --release -p secretary-ffi-uniffi --target "$t"
  ls -la "target/$t/release/libsecretary_ffi_uniffi.a"
done
```
Expected: three `.a` archives exist, each command exits 0.

- [ ] **Step 5: Prove the change is additive — re-run the existing gauntlet**

Run:
```bash
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```
Expected: clippy clean, workspace tests 0 failed, both smoke runners print OK. (This confirms `cdylib`/`rlib` consumers are unaffected.)

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-uniffi/Cargo.toml
git commit -m "build(uniffi): add staticlib crate-type for iOS XCFramework

Additive: cdylib (desktop smoke) and rlib (workspace) consumers
unchanged; the existing gauntlet passes. Enables cross-compiling the
uniffi core as a static archive for iOS XCFramework packaging (D.3).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `build-xcframework.sh` — cross-compile, generate bindings, assemble the XCFramework

**Files:**
- Create: `ios/scripts/build-xcframework.sh`

- [ ] **Step 1: Write the build script**

Create `ios/scripts/build-xcframework.sh`:

```bash
#!/usr/bin/env bash
# Build the Secretary.xcframework for iOS (device + simulator) from the
# secretary-ffi-uniffi crate, generate the Swift bindings, and stage the
# golden-vault test fixture into the SPM test target's resources.
#
# Produces (all gitignored):
#   ios/Secretary.xcframework/
#   ios/SecretaryKit/Sources/SecretaryKit/secretary.swift
#   ios/SecretaryKit/Tests/SecretaryKitTests/Resources/{golden_vault_001, golden_vault_001_inputs.json}
#
# Run from anywhere — paths resolve relative to this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$IOS_DIR/.." && pwd)"

CRATE="secretary-ffi-uniffi"
LIB="libsecretary_ffi_uniffi.a"
XCFRAMEWORK="$IOS_DIR/Secretary.xcframework"
PKG_SRC="$IOS_DIR/SecretaryKit/Sources/SecretaryKit"
RES_DIR="$IOS_DIR/SecretaryKit/Tests/SecretaryKitTests/Resources"
STAGING="$IOS_DIR/.build-staging"

# --- Preflight: macOS + required tools ---
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: iOS builds require macOS (got $(uname -s))" >&2; exit 2
fi
for tool in xcodebuild lipo rustup cargo; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not found in PATH" >&2; exit 2; }
done

DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")

# --- Step 1: iOS targets ---
echo "==> rustup target add (iOS)"
rustup target add "$DEVICE_TARGET" "${SIM_TARGETS[@]}"

# --- Step 2: cross-compile the staticlib for each triple ---
echo "==> cargo build staticlib (device + simulators)"
for t in "$DEVICE_TARGET" "${SIM_TARGETS[@]}"; do
    (cd "$REPO_ROOT" && cargo build --release -p "$CRATE" --target "$t")
done

# --- Step 3: lipo the two simulator archives into one fat archive ---
echo "==> lipo simulator archives"
rm -rf "$STAGING"; mkdir -p "$STAGING"
SIM_FAT="$STAGING/sim/$LIB"; mkdir -p "$STAGING/sim"
lipo -create \
    "$REPO_ROOT/target/aarch64-apple-ios-sim/release/$LIB" \
    "$REPO_ROOT/target/x86_64-apple-ios/release/$LIB" \
    -output "$SIM_FAT"
DEVICE_LIB="$REPO_ROOT/target/$DEVICE_TARGET/release/$LIB"

# --- Step 4: generate Swift bindings (uniffi-bindgen) ---
echo "==> uniffi-bindgen generate (Swift)"
BIND_OUT="$STAGING/bindings"; mkdir -p "$BIND_OUT"
(cd "$REPO_ROOT" && cargo run --release --features cli -p "$CRATE" \
    --bin uniffi-bindgen -- generate \
    --library "$DEVICE_LIB" \
    --language swift \
    --out-dir "$BIND_OUT")

# Copy the high-level Swift API into the SPM lib target.
mkdir -p "$PKG_SRC"
cp "$BIND_OUT/secretary.swift" "$PKG_SRC/secretary.swift"

# Assemble the XCFramework headers dir: the FFI header + a module.modulemap
# (Clang requires the file be named module.modulemap inside an xcframework's
# Headers dir). uniffi emits <name>.h and <name>.modulemap; copy by glob so a
# uniffi rename surfaces as a build error here, not silently.
HDRS="$STAGING/headers"; mkdir -p "$HDRS"
cp "$BIND_OUT"/*.h "$HDRS/"
cp "$BIND_OUT"/*.modulemap "$HDRS/module.modulemap"

# --- Step 5: assemble the XCFramework (clean-rebuild; -create refuses overwrite) ---
echo "==> xcodebuild -create-xcframework"
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" -headers "$HDRS" \
    -library "$SIM_FAT" -headers "$HDRS" \
    -output "$XCFRAMEWORK"

# --- Step 6: stage the golden-vault fixture as an SPM test resource ---
echo "==> stage golden_vault_001 fixture"
rm -rf "$RES_DIR"; mkdir -p "$RES_DIR"
cp -R "$REPO_ROOT/core/tests/data/golden_vault_001" "$RES_DIR/golden_vault_001"
cp "$REPO_ROOT/core/tests/data/golden_vault_001_inputs.json" "$RES_DIR/golden_vault_001_inputs.json"

echo "==> done: $XCFRAMEWORK"
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x ios/scripts/build-xcframework.sh`

- [ ] **Step 3: Run it (verify the pipeline produces all artifacts)**

Run: `bash ios/scripts/build-xcframework.sh`
Expected: exits 0; prints `==> done: …/ios/Secretary.xcframework`.

- [ ] **Step 4: Verify the artifacts exist and the binding import matches the modulemap**

Run:
```bash
ls -d ios/Secretary.xcframework/*/ \
  && ls ios/SecretaryKit/Sources/SecretaryKit/secretary.swift \
  && ls -d ios/SecretaryKit/Tests/SecretaryKitTests/Resources/golden_vault_001 \
  && echo "--- import line ---" \
  && grep -nE '^import ' ios/SecretaryKit/Sources/SecretaryKit/secretary.swift \
  && echo "--- modulemap module name ---" \
  && grep -nE 'module ' ios/Secretary.xcframework/*/Headers/module.modulemap | head -1
```
Expected: two framework slices (`ios-arm64`, `ios-arm64_x86_64-simulator`); `secretary.swift` present; staged fixture present; the low-level module named in `secretary.swift`'s `import` line (e.g. `import secretaryFFI`) **matches** the `module <name>` in the modulemap. If they differ, that is a uniffi-version naming detail — the `import` is authoritative; the modulemap declares whatever uniffi emitted, so they already agree. Note the module name; the SPM `binaryTarget` will vend it.

- [ ] **Step 5: Commit (script only — artifacts are gitignored in Task 3)**

```bash
git add ios/scripts/build-xcframework.sh
git commit -m "build(ios): build-xcframework.sh — cross-compile + bindgen + assemble

Cross-compiles the uniffi staticlib for the three iOS triples, lipo's the
simulator slices, generates Swift bindings, assembles Secretary.xcframework
(device + simulator), and stages golden_vault_001 as an SPM test resource.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `ios/.gitignore` — keep generated artifacts out of git

**Files:**
- Create: `ios/.gitignore`

- [ ] **Step 1: Write the gitignore**

Create `ios/.gitignore`:

```gitignore
# Generated by ios/scripts/build-xcframework.sh — reproducible, not committed.
/Secretary.xcframework/
/.build-staging/
/SecretaryKit/Sources/SecretaryKit/secretary.swift
/SecretaryKit/Tests/SecretaryKitTests/Resources/
# SwiftPM build products
/SecretaryKit/.build/
.DS_Store
```

- [ ] **Step 2: Verify the generated artifacts are now ignored**

Run: `git -C "$(git rev-parse --show-toplevel)" status --porcelain ios/ | grep -E 'Secretary.xcframework|secretary.swift|Resources/' || echo "clean: generated artifacts ignored"`
Expected: `clean: generated artifacts ignored` (no generated paths show as untracked).

- [ ] **Step 3: Commit**

```bash
git add ios/.gitignore
git commit -m "build(ios): gitignore generated XCFramework, bindings, staged fixture

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `Package.swift` — the SPM manifest

**Files:**
- Create: `ios/SecretaryKit/Package.swift`

NOTE: this task assumes Task 2 already produced `Secretary.xcframework`, `secretary.swift`, and the staged `Resources/`. If not, run `bash ios/scripts/build-xcframework.sh` first.

- [ ] **Step 1: Write the manifest**

Create `ios/SecretaryKit/Package.swift`:

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecretaryKit",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "SecretaryKit", targets: ["SecretaryKit"]),
    ],
    targets: [
        // The XCFramework built by ios/scripts/build-xcframework.sh.
        .binaryTarget(name: "SecretaryFFI", path: "../Secretary.xcframework"),
        // High-level Swift API generated by uniffi-bindgen (secretary.swift),
        // which imports the low-level Clang module vended by the XCFramework.
        .target(name: "SecretaryKit", dependencies: ["SecretaryFFI"]),
        // Linked-call proof: opens golden_vault_001 on the simulator.
        .testTarget(
            name: "SecretaryKitTests",
            dependencies: ["SecretaryKit"],
            resources: [
                .copy("Resources/golden_vault_001"),
                .copy("Resources/golden_vault_001_inputs.json"),
            ]
        ),
    ]
)
```

- [ ] **Step 2: Verify the package resolves and lists the iOS test scheme**

Run (from inside the package dir — `xcodebuild -list` resolves an SPM package with no `.xcodeproj`):
```bash
cd ios/SecretaryKit && { xcodebuild -list 2>&1 | head -20; swift package describe 2>&1 | grep -E 'Name:|Type:' | head; }; cd - >/dev/null
```
Expected: a `SecretaryKit` scheme is listed (SPM auto-generates it) and `swift package describe` prints the three targets (`SecretaryFFI` binary, `SecretaryKit` library, `SecretaryKitTests` test). If `swift package describe` errors, the manifest does not parse — fix it before proceeding.

- [ ] **Step 3: Commit**

```bash
git add ios/SecretaryKit/Package.swift
git commit -m "build(ios): SPM Package.swift — binaryTarget + lib + test target

iOS 17 floor; SecretaryFFI binaryTarget wraps Secretary.xcframework;
SecretaryKit wraps the generated secretary.swift; the test target bundles
golden_vault_001 as a copied resource for on-simulator reads.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `OpenVaultLinkTests.swift` — the linked-call proof (write + run red→green)

**Files:**
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/OpenVaultLinkTests.swift`

- [ ] **Step 1: Write the test**

Create `ios/SecretaryKit/Tests/SecretaryKitTests/OpenVaultLinkTests.swift`:

```swift
import XCTest
@testable import SecretaryKit

/// Proves `secretary-core` runs through the uniffi bindings on an iOS
/// simulator: opens the golden vault with its known password and asserts the
/// returned vault UUID matches the value pinned in the fixture's inputs JSON.
final class OpenVaultLinkTests: XCTestCase {
    /// golden_vault_001's password (see core/tests/data/golden_vault_001_inputs.json).
    private let goldenPassword = "correct horse battery staple"

    /// A writable per-test copy of the read-only golden-vault fixture.
    /// Opening a vault may write vault-stored settings, so we never open the
    /// bundled fixture in place.
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh"
        )
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }

    /// Happy path: full on-device crypto+FFI round-trip.
    func testOpenGoldenVaultOnDevice() throws {
        let folderPath = Data(vaultCopy.path.utf8)
        let out = try openVaultWithPassword(folderPath: folderPath,
                                            password: Data(goldenPassword.utf8))
        defer { out.manifest.wipe(); out.identity.wipe() }

        let expected = try pinnedVaultUuid()
        XCTAssertEqual(out.manifest.vaultUuid(), expected,
                       "on-device vault UUID must match the pinned fixture value")
        XCTAssertGreaterThan(out.manifest.blockCount(), 0,
                             "golden_vault_001 has at least one block")
    }

    /// Negative: a wrong password surfaces the typed error across the FFI.
    func testWrongPasswordSurfacesTypedError() throws {
        let folderPath = Data(vaultCopy.path.utf8)
        XCTAssertThrowsError(
            try openVaultWithPassword(folderPath: folderPath,
                                      password: Data("definitely wrong".utf8))
        ) { error in
            guard case VaultError.WrongPasswordOrCorrupt = error else {
                return XCTFail("expected VaultError.WrongPasswordOrCorrupt, got \(error)")
            }
        }
    }

    /// Read the pinned `vault_uuid` from the bundled inputs JSON and decode the
    /// dashed hex string to 16 bytes. Keeps core/tests/data the single source
    /// of truth (no hardcoded byte array).
    private func pinnedVaultUuid() throws -> Data {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001_inputs", withExtension: "json")
        )
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        let dict = try XCTUnwrap(json as? [String: Any])
        let dashed = try XCTUnwrap(dict["vault_uuid"] as? String)
        let hex = dashed.replacingOccurrences(of: "-", with: "")
        var bytes = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            bytes.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        return Data(bytes)
    }
}
```

- [ ] **Step 2: Run the test on the simulator (expect it to build and pass)**

Run (from the worktree root; pick an installed simulator — `xcrun simctl list devices available` lists them):
```bash
cd ios/SecretaryKit && \
xcodebuild test -scheme SecretaryKit \
  -destination 'platform=iOS Simulator,name=iPhone 16' \
  -resultBundlePath /tmp/secretarykit-result 2>&1 | tail -30; cd - >/dev/null
```
Expected: `Test Suite 'OpenVaultLinkTests' passed`, two tests passed (`** TEST SUCCEEDED **`).

If the build fails on the `import`/module name, re-check Task 2 Step 4: the `binaryTarget` vends the Clang module named in the modulemap; the generated `secretary.swift` imports that exact name. If the named simulator is missing, substitute any device from `xcrun simctl list devices available`.

- [ ] **Step 3: Commit**

```bash
git add ios/SecretaryKit/Tests/SecretaryKitTests/OpenVaultLinkTests.swift
git commit -m "test(ios): OpenVaultLinkTests — open golden_vault_001 on simulator

Happy-path on-device open (asserts the pinned vault UUID + non-empty block
count) plus a wrong-password typed-error assertion. Opens a per-test temp
copy of the bundled fixture (read-only-fixture hygiene). Proves
secretary-core runs through uniffi on iOS.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `run-ios-tests.sh` — the one-command acceptance entry point

**Files:**
- Create: `ios/scripts/run-ios-tests.sh`

- [ ] **Step 1: Write the runner**

Create `ios/scripts/run-ios-tests.sh`:

```bash
#!/usr/bin/env bash
# Acceptance entry point for D.3 slice 1: build the XCFramework, then run the
# SecretaryKit XCTest on an iOS simulator. Exits non-zero on any failure.
#
# Override the simulator with IOS_SIM, e.g.  IOS_SIM='iPhone 15' run-ios-tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$IOS_DIR/SecretaryKit"
SIM_NAME="${IOS_SIM:-iPhone 16}"

# --- Step 1: build the framework + stage fixtures ---
echo "==> build-xcframework.sh"
bash "$SCRIPT_DIR/build-xcframework.sh"

# --- Step 2: ensure the requested simulator exists ---
if ! xcrun simctl list devices available | grep -qF "$SIM_NAME"; then
    echo "ERROR: simulator '$SIM_NAME' not found. Available devices:" >&2
    xcrun simctl list devices available >&2
    echo "Set IOS_SIM to one of the above." >&2
    exit 2
fi

# --- Step 3: run the XCTest on the simulator ---
echo "==> xcodebuild test (simulator: $SIM_NAME)"
cd "$PKG_DIR"
xcodebuild test -scheme SecretaryKit \
    -destination "platform=iOS Simulator,name=$SIM_NAME"
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x ios/scripts/run-ios-tests.sh`

- [ ] **Step 3: Run the full acceptance entry point from a clean tree**

Run:
```bash
rm -rf ios/Secretary.xcframework ios/.build-staging \
       ios/SecretaryKit/Sources/SecretaryKit/secretary.swift \
       ios/SecretaryKit/Tests/SecretaryKitTests/Resources \
       ios/SecretaryKit/.build
bash ios/scripts/run-ios-tests.sh
```
Expected: builds from scratch, then `** TEST SUCCEEDED **`; the command exits 0.

- [ ] **Step 4: Commit**

```bash
git add ios/scripts/run-ios-tests.sh
git commit -m "build(ios): run-ios-tests.sh — one-command build + simulator test

Acceptance entry point: builds Secretary.xcframework then runs the
SecretaryKit XCTest on \$IOS_SIM (default iPhone 16). Exits non-zero on
failure; lists available simulators if the named one is missing.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Documentation — `ios/README.md`, `README.md`, `ROADMAP.md`

**Files:**
- Modify: `ios/README.md`
- Modify: `README.md`
- Modify: `ROADMAP.md`

- [ ] **Step 1: Rewrite `ios/README.md`**

Replace the contents of `ios/README.md` with:

```markdown
# ios/

Native iOS client for Secretary (Sub-project D.3), per
[ADR 0008](../docs/adr/0008-native-mobile-via-uniffi.md): a Swift app
consuming `secretary-core` through the `ffi/secretary-ffi-uniffi` bindings.

## Status — D.3 slice 1: XCFramework + linked-call proof ✅

The first slice establishes the iOS build pipeline and proves the core runs
on-device. There is no app UI yet, and no Keychain/Secure-Enclave key storage
yet (that is the next slice).

- `scripts/build-xcframework.sh` — cross-compiles the uniffi staticlib for the
  three iOS triples, generates the Swift bindings, and assembles
  `Secretary.xcframework` (device + simulator). Also stages `golden_vault_001`
  as an SPM test resource.
- `SecretaryKit/` — a Swift Package: a `binaryTarget` for the XCFramework, a
  `SecretaryKit` library wrapping the generated `secretary.swift`, and an
  XCTest target that opens the golden vault on a simulator.
- `scripts/run-ios-tests.sh` — the acceptance entry point: builds the framework
  then runs the XCTest on a simulator (`IOS_SIM` overrides the device; default
  `iPhone 16`). Requires macOS + Xcode; the first run fetches the iOS Rust std
  via `rustup target add`.

```bash
bash ios/scripts/run-ios-tests.sh        # build + test on the simulator
```

The XCFramework, generated `secretary.swift`, and staged fixtures are
build artifacts (gitignored) — rebuild them with the script.
```

- [ ] **Step 2: Update the root `README.md` status for Sub-project D / iOS**

Run: `grep -nE 'iOS|Sub-project D|ios/' README.md | head`
Then, in the section that describes the platform-UI / status (where the desktop Tauri client and the binding consumers are described), add a concise dot-point noting D.3 slice 1. Keep it brief (README style — no test-count walls). Example line to add under the relevant status list:

```markdown
- **iOS (D.3)**: build pipeline bootstrapped — an `Secretary.xcframework` (uniffi staticlib, device + simulator) consumed by a Swift Package, with an automated simulator XCTest opening the golden vault on-device. No app UI / Secure-Enclave key storage yet. See [ios/](ios/).
```

Place it adjacent to the existing mobile/ADR-0008 mention; match the surrounding bullet style.

- [ ] **Step 3: Update `ROADMAP.md`**

Run: `grep -nE 'Sub-project D|D\.3|native iOS|ADR 0008' ROADMAP.md | head`
Add a D.3 entry recording slice 1 as shipped. Match the existing `D.1.x ✅ shipped (date)` prose style used in the Sub-project D paragraph. Example sentence to append to the Sub-project D status:

```markdown
**D.3 slice 1 (iOS XCFramework + linked-call proof) ✅ shipped (2026-06-09)** — bootstraps the native-iOS path (ADR 0008): a `build-xcframework.sh` cross-compiles the uniffi staticlib for the three iOS triples and assembles `Secretary.xcframework` (device + simulator); a Swift Package (`ios/SecretaryKit/`) consumes it via a `binaryTarget`; an automated `xcodebuild` XCTest opens `golden_vault_001` on a simulator and asserts the pinned vault UUID — proving `secretary-core` runs through uniffi on-device. The additive `staticlib` crate-type leaves the existing cdylib/rlib consumers (and the full conformance gauntlet) unchanged. No app UI, no Keychain/Secure-Enclave key storage yet (next slice).
```

Also extend the Sub-project D progress bar line / any D-row summary if one enumerates sub-slices, appending `+ D.3 s1 iOS link-proof ✅` in the same style.

- [ ] **Step 4: Verify docs reference real paths**

Run:
```bash
grep -RnE 'ios/scripts/run-ios-tests.sh|Secretary.xcframework|ios/SecretaryKit' ios/README.md README.md ROADMAP.md
test -f ios/scripts/run-ios-tests.sh && test -f ios/SecretaryKit/Package.swift && echo "paths OK"
```
Expected: references resolve to files that exist; prints `paths OK`.

- [ ] **Step 5: Commit**

```bash
git add ios/README.md README.md ROADMAP.md
git commit -m "docs: D.3 slice 1 — iOS XCFramework + linked-call proof shipped

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification (run after all tasks)

- [ ] **Acceptance entry point green from a clean tree**

```bash
rm -rf ios/Secretary.xcframework ios/.build-staging \
       ios/SecretaryKit/Sources/SecretaryKit/secretary.swift \
       ios/SecretaryKit/Tests/SecretaryKitTests/Resources ios/SecretaryKit/.build
bash ios/scripts/run-ios-tests.sh
```
Expected: `** TEST SUCCEEDED **`, exit 0.

- [ ] **Existing gauntlet still green (staticlib was additive)**

```bash
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```
Expected: clippy clean; workspace 0 failed; both smoke runners OK.

- [ ] **No generated artifacts tracked by git**

```bash
git status --porcelain ios/ | grep -E 'Secretary.xcframework|secretary.swift|Resources/' && echo "LEAK" || echo "clean"
```
Expected: `clean`.

---

## Self-review notes (author)

- **Spec coverage:** staticlib crate-type → Task 1; build-xcframework.sh → Task 2; gitignore → Task 3; Package.swift (binaryTarget + iOS 17 floor + resource bundling) → Task 4; OpenVaultLinkTests (happy + wrong-password) → Task 5; run-ios-tests.sh → Task 6; README/ROADMAP → Task 7; acceptance criteria → Final verification. All spec sections covered.
- **API consistency:** `openVaultWithPassword(folderPath:password:)`, `OpenVaultOutput.{identity,manifest}`, `OpenVaultManifest.{vaultUuid(),blockCount(),wipe()}`, `UnlockedIdentity.wipe()`, `VaultError.WrongPasswordOrCorrupt` — all verified against `src/secretary.udl`.
- **No hardcoded crypto values:** the pinned UUID is read from the bundled inputs JSON at test time, not literal bytes ([[feedback_test_crypto_random_not_hardcoded]]).
- **Read-only fixture hygiene:** the test opens a per-test temp copy, never the bundled fixture in place ([[feedback_smoke_test_temp_copy_golden_vault]]).
- **Empirical iteration points (inherent to iOS packaging):** the Clang module name (Task 2 Step 4) and the simulator device name (Task 5 Step 2 / `IOS_SIM`) may need adjustment to the host; each has an explicit verification step and fallback.
