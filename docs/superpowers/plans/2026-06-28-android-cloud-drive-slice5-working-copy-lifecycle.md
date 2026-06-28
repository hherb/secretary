# Android cloud-drive Slice 5 — working-copy lifecycle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two Slice-4 seams (deferred cloud-open; create-then-return-to-Selection) with the real working-copy lifecycle — materialize (SAF→working) → sync → operate → flush (working→SAF, after every commit) — enforcing push-before-pull.

**Architecture:** A pure `:vault-access` `VaultWorkingCopyCoordinator` owns the ordering invariant (push any pending edits before pulling). It calls injected seams (a working-copy mirror, a pending-flush marker, an open+sync function), so the keystone ordering is host-testable with order-recording fakes. The SAF/FFI specifics stay in `:kit`/`:app`. Merge stays entirely in the audited Rust core. A small additive FFI change lets `create_vault_in_folder` return the new vault's `vault_uuid` (needed to key `SyncState` and the persisted location).

**Tech Stack:** Rust (secretary-ffi-bridge + uniffi udl + pyo3), Kotlin (Gradle modules `:vault-access` pure / `:kit` adapters / `:app` Compose), Swift (iOS uniffi call site — compile only).

**Design:** [docs/superpowers/specs/2026-06-28-android-cloud-drive-slice5-working-copy-lifecycle-design.md](../specs/2026-06-28-android-cloud-drive-slice5-working-copy-lifecycle-design.md)

## Global Constraints

- **Worktree:** `.worktrees/android-cloud-drive-working-copy-lifecycle`, branch `feature/android-cloud-drive-working-copy-lifecycle` (cut from `main` @ `f0e1499a`). Verify `pwd && git branch --show-current` before any `cargo`/`gradlew`/`git` call. Use absolute paths or chain `cd` in one Bash call (shell state does not persist).
- **No core `src/`, on-disk-format, `conformance.py`, conflict-KAT, or observable-byte change.** The create FFI gaining a `vault_uuid` field is additive and is NOT part of `conformance_kat.json`.
- **Rust:** stable toolchain; `#![forbid(unsafe_code)]`; `cargo clippy --release --workspace --tests -- -D warnings` stays clean; `cargo fmt --all`.
- **After any FFI signature change**, run both cross-language conformance harnesses (they compile the Kotlin + Swift bindings): `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` and `.../kotlin/run_conformance.sh`. (`create` is not in the KAT, but the harness compiling against the regenerated binding is the guard that nothing else broke.)
- **Kotlin layering:** pure logic in `:vault-access` (host-tested, no Android imports in the class body); FFI + Android in `:kit`; UI/glue in `:app`. **No CRDT/merge logic in Kotlin** — the core owns it.
- **Files < 500 lines, one concept per file.** Split proactively.
- **TDD:** every behavior gets a failing test first (RED proven by running it), then minimal GREEN. Security/ordering surfaces (push-before-pull, flush-failure→marker, the FFI uuid round-trip) are proven by a test, not assumed.
- **Python:** `uv` only, never `pip`.
- **Android host test commands** (run from `android/`): `./gradlew :vault-access:test`, `./gradlew :kit:testDebugUnitTest`, `./gradlew :app:testDebugUnitTest`. Compile gates: `./gradlew :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin`. (adb/emulator are NOT needed for this slice; instrumented E2E is Slice 6.)

---

### Task 1: Bridge — `create_vault_in_folder` returns `vault_uuid` + mnemonic

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/create.rs` (the `create_vault_in_folder` fn ~297-315; add a return struct; add a test in the existing `mod tests`)

**Interfaces:**
- Produces (Rust, consumed by Task 2): `pub struct CreatedVaultInFolder { pub vault_uuid: [u8; 16], pub mnemonic: MnemonicOutput }`; `create_vault_in_folder(folder, password, display_name, created_at_ms) -> Result<CreatedVaultInFolder, FfiVaultError>`.
- Consumes: `secretary_core::unlock::vault_toml::decode` (pub) → `VaultToml { pub vault_uuid: [u8;16], .. }`; the existing `secretary_core::vault::create_vault` (unchanged — it still returns `Mnemonic`).

- [ ] **Step 1: Write the failing test** (append inside `mod tests` in `create.rs`)

```rust
#[test]
fn create_vault_in_folder_returns_vault_uuid_matching_vault_toml() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = create_vault_in_folder(dir.path(), b"correct horse", "Test Vault", 1_700_000_000_000)
        .expect("create must succeed into an empty dir");

    // The returned uuid must equal vault.toml's vault_uuid (the authoritative on-disk value).
    let toml = std::fs::read_to_string(dir.path().join("vault.toml")).expect("vault.toml readable");
    let vt = secretary_core::unlock::vault_toml::decode(&toml).expect("vault.toml decodes");
    assert_eq!(out.vault_uuid, vt.vault_uuid, "returned uuid must match vault.toml");
    assert_eq!(out.vault_uuid.len(), 16);
    assert_ne!(out.vault_uuid, [0u8; 16], "uuid must not be all-zero");

    // The mnemonic handle still yields a 24-word phrase exactly once.
    let phrase = out.mnemonic.take_phrase().expect("phrase available once");
    assert_eq!(phrase.split(|b| *b == b' ').count(), 24);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-working-copy-lifecycle && cargo test --release -p secretary-ffi-bridge create_vault_in_folder_returns_vault_uuid -- --nocapture`
Expected: FAIL — `CreatedVaultInFolder` / field `vault_uuid` does not exist (compile error).

- [ ] **Step 3: Write minimal implementation** — add the struct and change the fn return. Replace the existing `create_vault_in_folder` (lines ~297-315) with:

```rust
/// Result of [`create_vault_in_folder`]: the new vault's `vault_uuid` plus the
/// one-shot recovery mnemonic. `vault_uuid` is recovered by decoding the
/// just-written `vault.toml` (the same re-parse `core::vault::create_vault`
/// does internally for the manifest header); it lets the platform key the
/// per-device `SyncState` and the remembered location without re-opening the
/// vault. Additive — the iOS / Python / Kotlin call sites destructure
/// `.mnemonic` exactly as before and may ignore `.vault_uuid`.
pub struct CreatedVaultInFolder {
    /// 16-byte vault identifier from the freshly-written `vault.toml`.
    pub vault_uuid: [u8; 16],
    /// One-shot opaque handle for the 24-word recovery phrase (unchanged semantics).
    pub mnemonic: MnemonicOutput,
}

pub fn create_vault_in_folder(
    folder: &Path,
    password: &[u8],
    display_name: &str,
    created_at_ms: u64,
) -> Result<CreatedVaultInFolder, FfiVaultError> {
    let pw = SecretBytes::from(password);
    let mut rng = OsRng;
    let mnemonic = secretary_core::vault::create_vault(
        folder,
        &pw,
        display_name,
        Argon2idParams::V1_DEFAULT,
        created_at_ms,
        &mut rng,
    )
    .map_err(FfiVaultError::from)?;

    // Recover vault_uuid from the canonical on-disk vault.toml we just wrote.
    // A read/decode failure here is an internal bug (we authored the file a
    // moment ago), so it folds to the rare-crypto CorruptVault arm rather than
    // a user-facing folder error.
    let toml = std::fs::read_to_string(folder.join("vault.toml"))
        .map_err(|e| FfiVaultError::CorruptVault { detail: format!("vault.toml unreadable post-create: {e}") })?;
    let vt = secretary_core::unlock::vault_toml::decode(&toml)
        .map_err(|e| FfiVaultError::CorruptVault { detail: format!("vault.toml undecodable post-create: {e}") })?;

    Ok(CreatedVaultInFolder { vault_uuid: vt.vault_uuid, mnemonic: MnemonicOutput::new(mnemonic) })
}
```

Note: confirm the exact `FfiVaultError::CorruptVault` variant shape by reading `ffi/secretary-ffi-bridge/src/error.rs` (it may be `CorruptVault { detail: String }` or a tuple — match the existing form used elsewhere in `create.rs`). Update the re-export on `ffi/secretary-ffi-bridge/src/lib.rs:130` to add `CreatedVaultInFolder` to the `pub use create::{…}` list.

- [ ] **Step 4: Run test to verify it passes** — also fix any other in-crate caller of the old return type.

Run: `cargo test --release -p secretary-ffi-bridge create_vault_in_folder -- --nocapture`
Expected: PASS. Then `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings` clean.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/create.rs ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(ffi): create_vault_in_folder returns vault_uuid (bridge)"
```

---

### Task 2: Thread the FFI bindings (uniffi Kotlin+Swift, pyo3)

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (line 36-45 fn return + a new dictionary near `CreateVaultOutput` ~478)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (`create_vault_in_folder` wrapper ~150-178)
- Modify: `ffi/secretary-ffi-py/src/unlock.rs` (`create_vault_in_folder` ~240-258)
- Modify: iOS `ios/.../VaultAccess/UniffiVaultCreatePort.swift` (the `mnem = try …createVaultInFolder(…)` call site)

**Interfaces:**
- Consumes: Task 1's `secretary_ffi_bridge::CreatedVaultInFolder`.
- Produces (Kotlin, consumed by Task 3): generated `uniffi.secretary.createVaultInFolder(...)` now returns a `CreatedVaultInFolder` record `{ vaultUuid: ByteArray, mnemonic: MnemonicOutput }`.

- [ ] **Step 1: Add the uniffi dictionary + change the fn return (udl)**

In `secretary.udl`, change the `create_vault_in_folder` declaration (lines ~39-45) return type from `MnemonicOutput` to `CreatedVaultInFolder`:

```
    [Throws=VaultError]
    CreatedVaultInFolder create_vault_in_folder(
        bytes folder_path,
        bytes password,
        string display_name,
        u64 created_at_ms
    );
```

Add the dictionary next to `CreateVaultOutput` (after line ~488):

```
/// Result of create_vault_in_folder: the new vault's 16-byte vault_uuid plus
/// the one-shot recovery mnemonic handle. (cloud-drive provisioning Slice 5)
dictionary CreatedVaultInFolder {
    /// 16-byte vault identifier from the freshly-written vault.toml.
    bytes vault_uuid;
    /// One-shot opaque handle for the recovery phrase.
    MnemonicOutput mnemonic;
};
```

- [ ] **Step 2: Update the uniffi wrapper (`namespace/mod.rs`)** — replace the `create_vault_in_folder` body's tail so it returns the record. The uniffi-generated Rust struct is `CreatedVaultInFolder { vault_uuid: Vec<u8>, mnemonic: std::sync::Arc<MnemonicOutput> }` (a uniffi `dictionary` with an interface field mirrors `CreateVaultOutput`). Read the existing `CreateVaultOutput` construction in this file for the exact record/Arc idiom, then:

```rust
    password.zeroize();
    let bridge_out = result?; // now secretary_ffi_bridge::CreatedVaultInFolder
    Ok(CreatedVaultInFolder {
        vault_uuid: bridge_out.vault_uuid.to_vec(),
        mnemonic: std::sync::Arc::new(MnemonicOutput(bridge_out.mnemonic)),
    })
```

Adjust the `result` binding's type to `Result<secretary_ffi_bridge::CreatedVaultInFolder, VaultError>` and define/derive the uniffi `CreatedVaultInFolder` record per the `CreateVaultOutput` precedent (it is declared in the udl, so uniffi expects a matching Rust struct in scope — follow how `CreateVaultOutput` is declared/used in `namespace/mod.rs` + `lib.rs`).

- [ ] **Step 3: Update pyo3 (`ffi/secretary-ffi-py/src/unlock.rs`)** — `create_vault_in_folder` returns a 2-tuple `(vault_uuid_bytes, MnemonicOutput)`:

```rust
#[pyfunction]
pub(crate) fn create_vault_in_folder(
    folder: std::path::PathBuf,
    mut password: Vec<u8>,
    display_name: &str,
    created_at_ms: u64,
) -> PyResult<(Vec<u8>, MnemonicOutput)> {
    let result = secretary_ffi_bridge::create_vault_in_folder(&folder, &password, display_name, created_at_ms);
    password.zeroize();
    let out = result.map_err(ffi_vault_error_to_pyerr)?;
    Ok((out.vault_uuid.to_vec(), MnemonicOutput(out.mnemonic)))
}
```

(If a Python test asserts the old single return, update it to unpack the tuple. Search `ffi/secretary-ffi-py` tests for `create_vault_in_folder`.)

- [ ] **Step 4: Update the iOS Swift call site** — in `UniffiVaultCreatePort.swift`, the block that assigns `mnem`:

```swift
            let mnem: MnemonicOutput
            do {
                mnem = try withZeroizingData(password) { pw in
                    try SecretaryKit.createVaultInFolder(
                        folderPath: Data(folder.path.utf8),
                        password: pw,
                        displayName: displayName,
                        createdAtMs: UInt64(Date().timeIntervalSince1970 * 1000)).mnemonic
                }
            } catch let e as VaultError {
                throw mapProvisioningError(e)
            }
```

(iOS derives its location from a bookmark, not the uuid, so it ignores `.vault_uuid` — append `.mnemonic` to the call as shown.)

- [ ] **Step 5: Build + generate + conformance**

Run (from repo root in the worktree):
```bash
cargo build --release -p secretary-ffi-uniffi -p secretary-ffi-py
cargo test --release -p secretary-ffi-uniffi -p secretary-ffi-py -- --nocapture
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
```
Expected: all build/test/conformance green (conformance proves the regenerated Kotlin + Swift bindings still compile + replay identically). clippy clean on both crates.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-uniffi ffi/secretary-ffi-py ios
git commit -m "feat(ffi): thread vault_uuid through uniffi + pyo3 + iOS create binding"
```

---

### Task 3: Kotlin `CreatedVault.vaultUuid` + port + VM threading

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultCreatePort.kt` (`CreatedVault`)
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/UniffiVaultCreatePort.kt` (`createFn` seam + read uuid)
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultProvisioningViewModel.kt` (thread uuid into `Done.location.vaultUuidHex`)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultProvisioningViewModelTest.kt` (add a case)

**Interfaces:**
- Consumes: Task 2's generated `createVaultInFolder(...).vaultUuid` / `.mnemonic`, and Task 4's `VaultLocation(..., vaultUuidHex)`.
- Produces (consumed by Task 8): `CreatedVault(val phrase: ByteArray, val vaultUuid: ByteArray)`; the provisioning VM's `Done.location.vaultUuidHex` is the created uuid in lowercase hex.

> Depends on Task 4 for `VaultLocation.vaultUuidHex`. If executing strictly in order, do Task 4 first or land them together.

- [ ] **Step 1: Write the failing test** — add to `VaultProvisioningViewModelTest.kt`. Use the existing fake create-port pattern in that file; make the fake return a `CreatedVault` with a known uuid:

```kotlin
@Test
fun done_location_carries_created_vault_uuid_hex() = runTest {
    val uuid = ByteArray(16) { (it + 1).toByte() } // 0102..10
    val vm = VaultProvisioningViewModel(
        createPort = fakeCreatePort(phrase = "word ".repeat(24).trim().toByteArray(), vaultUuid = uuid),
        store = InMemoryVaultLocationStore(),
    )
    vm.chooseFolder(treeUri = "content://tree/x", vaultName = "Vault")
    vm.create(folderPath = "/tmp/working", password = "pw".toByteArray(), confirm = "pw".toByteArray())
    vm.acknowledgeMnemonic()
    val done = vm.step as VaultProvisioningStep.Done
    assertEquals("0102030405060708090a0b0c0d0e0f10", done.location.vaultUuidHex)
}
```

(Match the real VM constructor parameter names + the fake/store test doubles already present in the file; adjust `fakeCreatePort` to take a `vaultUuid`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-working-copy-lifecycle/android && ./gradlew :vault-access:test --tests '*VaultProvisioningViewModelTest.done_location_carries_created_vault_uuid_hex'`
Expected: FAIL — `CreatedVault` has no `vaultUuid` / `VaultLocation` has no `vaultUuidHex`.

- [ ] **Step 3: Implement**

`VaultCreatePort.kt` — extend the class (keep it a plain class; phrase stays secret):
```kotlin
class CreatedVault(val phrase: ByteArray, val vaultUuid: ByteArray)
```

`UniffiVaultCreatePort.kt` — change the `createFn` seam to surface both, and build the richer `CreatedVault`:
```kotlin
    private val createFn: (ByteArray, ByteArray, String, ULong) -> Pair<ByteArray, ByteArray>? =
        { folderPath, password, displayName, createdAtMs ->
            createVaultInFolder(folderPath, password, displayName, createdAtMs).let { out ->
                out.mnemonic.use { it.takePhrase() }?.let { phrase -> phrase to out.vaultUuid }
            }
        },
```
and in `createInFolder`:
```kotlin
            val result = mapProvisioningErrors {
                createFn(folderPath.toByteArray(Charsets.UTF_8), password, displayName, clockMs().toULong())
            } ?: throw VaultProvisioningError.CreateFailed("recovery phrase unavailable")
            CreatedVault(phrase = result.first, vaultUuid = result.second)
```
(Confirm the generated record exposes `vaultUuid` as `ByteArray` and `mnemonic` as the `MnemonicOutput` `AutoCloseable` — adjust `.use {}` placement so the handle is released after `takePhrase`.)

`VaultProvisioningViewModel.kt` — where `create()` stores the `CreatedVault` and `acknowledgeMnemonic()` builds `Done(location)`, set `vaultUuidHex = hexOfBytes(created.vaultUuid)` on the location (use the existing `hexOfBytes` helper in `org.secretary.browse`). Keep zeroizing `phrase` exactly as before.

- [ ] **Step 4: Run tests**

Run: `./gradlew :vault-access:test :kit:testDebugUnitTest`
Expected: PASS (incl. the new case + all existing provisioning/create tests).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access android/kit
git commit -m "feat(android): CreatedVault carries vaultUuid; provisioning VM threads it into the location"
```

---

### Task 4: `VaultLocation.vaultUuidHex` + codec v2 (tolerant of v1)

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocation.kt`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultLocationCodec.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultLocationCodecTest.kt`

**Interfaces:**
- Produces (consumed by Tasks 3, 8): `data class VaultLocation(val displayName: String, val treeUri: String, val vaultUuidHex: String = "")`. The default `""` means "uuid not yet known" (a SAF-picked existing vault learns it on first open); existing Slice-4 call sites that pass only `(displayName, treeUri)` keep compiling.
- Codec: round-trips `vaultUuidHex`; a `v1` blob (no uuid) decodes with `vaultUuidHex = ""` (tolerant, per the design).

- [ ] **Step 1: Write the failing tests** (add to `VaultLocationCodecTest.kt`)

```kotlin
@Test fun v2_roundtrips_vault_uuid_hex() {
    val loc = VaultLocation("My Vault", "content://tree/abc", "0102030405060708090a0b0c0d0e0f10")
    assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
}

@Test fun v2_roundtrips_empty_uuid() {
    val loc = VaultLocation("My Vault", "content://tree/abc") // vaultUuidHex defaults ""
    assertEquals(loc, decodeVaultLocation(encodeVaultLocation(loc)))
}

@Test fun v1_blob_decodes_with_empty_uuid() {
    // A pre-Slice-5 v1 blob has no uuid segment; it must decode (tolerant), not return null.
    val v1 = "v1:8:My Vaultcontent://tree/abc"
    assertEquals(VaultLocation("My Vault", "content://tree/abc", ""), decodeVaultLocation(v1))
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-working-copy-lifecycle/android && ./gradlew :vault-access:test --tests '*VaultLocationCodecTest'`
Expected: FAIL — `VaultLocation` 3rd arg / v2 format absent.

- [ ] **Step 3: Implement**

`VaultLocation.kt`:
```kotlin
data class VaultLocation(val displayName: String, val treeUri: String, val vaultUuidHex: String = "")
```

`VaultLocationCodec.kt` — bump to `v2`, append a length-prefixed uuid segment, and keep a `v1` decode path that yields `vaultUuidHex = ""`. Format v2: `"v2:<nameLen>:<uuidLen>:<name><uuid><treeUri>"` (two length prefixes; treeUri is the remainder). Concretely:

```kotlin
internal const val VAULT_LOCATION_CODEC_VERSION = "v2"

fun encodeVaultLocation(location: VaultLocation): String =
    "$VAULT_LOCATION_CODEC_VERSION:${location.displayName.length}:${location.vaultUuidHex.length}:" +
        "${location.displayName}${location.vaultUuidHex}${location.treeUri}"

fun decodeVaultLocation(encoded: String): VaultLocation? {
    if (encoded.startsWith("v2:")) return decodeV2(encoded.substring(3))
    if (encoded.startsWith("v1:")) return decodeV1(encoded.substring(3)) // tolerant: uuid = ""
    return null
}

private fun decodeV2(rest: String): VaultLocation? {
    val c1 = rest.indexOf(':'); if (c1 < 0) return null
    val nameLen = rest.substring(0, c1).toIntOrNull()?.takeIf { it >= 0 } ?: return null
    val afterName = rest.substring(c1 + 1)
    val c2 = afterName.indexOf(':'); if (c2 < 0) return null
    val uuidLen = afterName.substring(0, c2).toIntOrNull()?.takeIf { it >= 0 } ?: return null
    val payload = afterName.substring(c2 + 1)
    if (payload.length < nameLen + uuidLen) return null
    val name = payload.substring(0, nameLen)
    val uuid = payload.substring(nameLen, nameLen + uuidLen)
    val treeUri = payload.substring(nameLen + uuidLen)
    if (treeUri.isEmpty()) return null
    return VaultLocation(name, treeUri, uuid)
}

private fun decodeV1(rest: String): VaultLocation? {
    val colon = rest.indexOf(':'); if (colon < 0) return null
    val nameLen = rest.substring(0, colon).toIntOrNull()?.takeIf { it >= 0 } ?: return null
    val payload = rest.substring(colon + 1)
    if (payload.length < nameLen) return null
    val name = payload.substring(0, nameLen)
    val treeUri = payload.substring(nameLen)
    if (treeUri.isEmpty()) return null
    return VaultLocation(name, treeUri, "")
}
```

Update the file-level kdoc to describe the v2 format + the v1-tolerant path. `SafVaultLocationStore` needs no change (it delegates to the codec) — confirm it still compiles.

- [ ] **Step 4: Run tests**

Run: `./gradlew :vault-access:test :kit:testDebugUnitTest`
Expected: PASS (new codec cases + existing ones).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access
git commit -m "feat(android): VaultLocation carries vaultUuidHex; codec v2 (v1-tolerant)"
```

---

### Task 5: `PendingFlushMarker` port + `FilePendingFlushMarker`

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/mirror/PendingFlushMarker.kt`
- Create: `android/kit/src/main/kotlin/org/secretary/mirror/FilePendingFlushMarker.kt`
- Test: `android/kit/src/test/kotlin/org/secretary/mirror/FilePendingFlushMarkerTest.kt`

**Interfaces:**
- Produces (consumed by Tasks 6, 8): `interface PendingFlushMarker { fun isSet(): Boolean; fun set(); fun clear() }`; `class FilePendingFlushMarker(markerFile: File) : PendingFlushMarker`.

> **Correctness note (verified against `VaultMirror.readWorking`):** the marker file MUST live OUTSIDE the working copy. `VaultMirror` mirrors *every* file under `workingDir` (`walkTopDown().filter { it.isFile }`), so a marker inside the working dir would be pushed to the cloud and then deleted on the next materialize. `:app` (Task 8) places it in the app-private sync state dir, keyed by vault uuid.

- [ ] **Step 1: Write the failing test** (`FilePendingFlushMarkerTest.kt`)

```kotlin
package org.secretary.mirror

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class FilePendingFlushMarkerTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test fun absent_by_default_then_set_then_clear() {
        val marker = FilePendingFlushMarker(java.io.File(tmp.root, "v123.pending-flush"))
        assertFalse("fresh marker must be unset", marker.isSet())
        marker.set()
        assertTrue("set() makes it present", marker.isSet())
        marker.set() // idempotent
        assertTrue(marker.isSet())
        marker.clear()
        assertFalse("clear() removes it", marker.isSet())
        marker.clear() // idempotent on already-absent
        assertFalse(marker.isSet())
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-working-copy-lifecycle/android && ./gradlew :kit:testDebugUnitTest --tests '*FilePendingFlushMarkerTest'`
Expected: FAIL — types do not exist.

- [ ] **Step 3: Implement**

`PendingFlushMarker.kt` (`:vault-access`):
```kotlin
package org.secretary.mirror

/**
 * A durable one-bit "the working copy holds edits not yet pushed to the cloud" flag. Set when a
 * flush fails (offline / SAF error); checked on the next open to enforce push-before-pull. Kept
 * behind a port so the coordinator's ordering logic is host-testable with an in-memory fake.
 */
interface PendingFlushMarker {
    fun isSet(): Boolean
    fun set()
    fun clear()
}
```

`FilePendingFlushMarker.kt` (`:kit`):
```kotlin
package org.secretary.mirror

import java.io.File

/**
 * A [PendingFlushMarker] backed by a sentinel file. The file MUST live outside the vault working
 * copy (e.g. the app-private sync-state dir) — [VaultMirror] mirrors every file under the working
 * dir, so a marker placed there would be pushed to the cloud and then deleted on materialize.
 *
 * Best-effort and idempotent: [set] creates the file if absent; [clear] deletes it tolerating
 * already-absent; I/O failures are swallowed (a marker we failed to write degrades to "no pending
 * flush", which a later successful flush makes moot — crashing the background flush would be worse).
 */
class FilePendingFlushMarker(private val markerFile: File) : PendingFlushMarker {
    override fun isSet(): Boolean = markerFile.exists()

    override fun set() {
        try {
            if (!markerFile.exists()) {
                markerFile.parentFile?.mkdirs()
                markerFile.createNewFile()
            }
        } catch (_: Exception) { /* see kdoc: best-effort */ }
    }

    override fun clear() {
        try { markerFile.delete() } catch (_: Exception) { /* idempotent best-effort */ }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `./gradlew :vault-access:test :kit:testDebugUnitTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add android/vault-access android/kit
git commit -m "feat(android): PendingFlushMarker port + file-backed impl (outside working copy)"
```

---

### Task 6: `VaultWorkingCopyCoordinator` (the push-before-pull keystone)

**Files:**
- Create: `android/vault-access/src/main/kotlin/org/secretary/mirror/WorkingCopyMirror.kt`
- Create: `android/vault-access/src/main/kotlin/org/secretary/mirror/VaultWorkingCopyCoordinator.kt`
- Test: `android/vault-access/src/test/kotlin/org/secretary/mirror/VaultWorkingCopyCoordinatorTest.kt`

**Interfaces:**
- Consumes: `PendingFlushMarker` (Task 5).
- Produces (consumed by Task 8): `interface WorkingCopyMirror { fun materialize(): MirrorReport; fun flush(): MirrorReport }`; `class VaultWorkingCopyCoordinator<S>(mirror, marker, openAndSync: suspend () -> S)` with `suspend fun openExisting(): S`, `suspend fun createThenOpen(createdVaultUuidHex: String, persistLocation: (String) -> Unit): S`, `suspend fun afterCommit()`.

- [ ] **Step 1: Write the failing tests** (`VaultWorkingCopyCoordinatorTest.kt`)

```kotlin
package org.secretary.mirror

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private class RecordingMirror(private val order: MutableList<String>, var flushFails: Boolean = false) : WorkingCopyMirror {
    val empty = MirrorReport(emptyList(), emptyList())
    override fun materialize(): MirrorReport { order.add("materialize"); return empty }
    override fun flush(): MirrorReport {
        order.add("flush")
        if (flushFails) throw VaultMirrorException("offline")
        return empty
    }
}

private class FakeMarker(private var set: Boolean = false) : PendingFlushMarker {
    val events = mutableListOf<String>()
    override fun isSet() = set
    override fun set() { set = true; events.add("set") }
    override fun clear() { set = false; events.add("clear") }
}

class VaultWorkingCopyCoordinatorTest {

    @Test fun openExisting_flushes_before_materialize_when_pending() = runTest {
        val order = mutableListOf<String>()
        val marker = FakeMarker(set = true)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order), marker) { order.add("open"); "S" }
        val s = coord.openExisting()
        assertEquals("S", s)
        assertEquals(listOf("flush", "materialize", "open"), order) // push-before-pull keystone
        assertFalse("marker cleared after a successful push", marker.isSet())
    }

    @Test fun openExisting_no_pending_marker_skips_flush() = runTest {
        val order = mutableListOf<String>()
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order), FakeMarker(set = false)) { order.add("open"); "S" }
        coord.openExisting()
        assertEquals(listOf("materialize", "open"), order) // no spurious flush when clean
    }

    @Test fun openExisting_pending_flush_failure_aborts_before_materialize() = runTest {
        val order = mutableListOf<String>()
        val marker = FakeMarker(set = true)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order, flushFails = true), marker) { order.add("open"); "S" }
        var threw = false
        try { coord.openExisting() } catch (e: VaultMirrorException) { threw = true }
        assertTrue("a failed push must propagate", threw)
        assertEquals(listOf("flush"), order) // never materialized / opened
        assertTrue("marker stays set so the next open retries the push", marker.isSet())
    }

    @Test fun createThenOpen_flushes_then_persists_then_opens() = runTest {
        val order = mutableListOf<String>()
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order), FakeMarker()) { order.add("open"); "S" }
        var persistedUuid: String? = null
        val s = coord.createThenOpen("deadbeef") { uuid -> order.add("persist"); persistedUuid = uuid }
        assertEquals("S", s)
        assertEquals(listOf("flush", "persist", "open"), order)
        assertEquals("deadbeef", persistedUuid)
    }

    @Test fun afterCommit_sets_marker_on_flush_failure_and_never_throws() = runTest {
        val order = mutableListOf<String>()
        val marker = FakeMarker(set = false)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(order, flushFails = true), marker) { "S" }
        coord.afterCommit() // must not throw
        assertTrue("flush failure marks pending", marker.isSet())
    }

    @Test fun afterCommit_clears_marker_on_success() = runTest {
        val marker = FakeMarker(set = true)
        val coord = VaultWorkingCopyCoordinator(RecordingMirror(mutableListOf()), marker) { "S" }
        coord.afterCommit()
        assertFalse("a successful flush clears any prior pending state", marker.isSet())
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-working-copy-lifecycle/android && ./gradlew :vault-access:test --tests '*VaultWorkingCopyCoordinatorTest'`
Expected: FAIL — coordinator types do not exist.

- [ ] **Step 3: Implement**

`WorkingCopyMirror.kt`:
```kotlin
package org.secretary.mirror

import java.io.File

/**
 * A working-copy mirror bound to one vault's [workingDir] and cloud folder: pull cloud→working
 * ([materialize]) and push working→cloud ([flush]). A thin seam over [VaultMirror] so the
 * coordinator can be host-tested with an order-recording fake and `:app` can bind the real one.
 */
interface WorkingCopyMirror {
    fun materialize(): MirrorReport
    fun flush(): MirrorReport
}

/** Binds a [VaultMirror] (built from a [CloudFolderPort]) to a fixed [workingDir]. */
class VaultMirrorWorkingCopy(private val mirror: VaultMirror, private val workingDir: File) : WorkingCopyMirror {
    override fun materialize(): MirrorReport = mirror.materialize(workingDir)
    override fun flush(): MirrorReport = mirror.flush(workingDir)
}
```

`VaultWorkingCopyCoordinator.kt`:
```kotlin
package org.secretary.mirror

/**
 * Orchestrates the per-session working-copy lifecycle that lets the POSIX-only core operate on a
 * path-less SAF cloud folder, enforcing the one ordering rule the shim guarantees:
 *
 *   **push-before-pull** — before pulling cloud→working, always flush any pending local edits.
 *
 * Pure of Android/SAF/FFI: [mirror], [marker], and [openAndSync] are injected, so the ordering is
 * host-testable with order-recording fakes. The coordinator NEVER merges — merge stays entirely in
 * the audited Rust core ([openAndSync] runs the existing sync pass); this type only decides which
 * bytes move and in what order.
 *
 * @param S the opaque opened-session handle the caller hands to Browse (e.g. a BrowseSession).
 * @param openAndSync materialized working copy is on disk when this runs: it unlocks + runs the
 *   existing sync_vault_in/makeVaultSync pass against the working dir and returns the browse handle.
 */
class VaultWorkingCopyCoordinator<S>(
    private val mirror: WorkingCopyMirror,
    private val marker: PendingFlushMarker,
    private val openAndSync: suspend () -> S,
) {
    /**
     * Open a remembered cloud vault. If a prior flush failed (marker set), push the un-pushed
     * working-copy edits FIRST; only on a successful push do we clear the marker and pull. A failed
     * push propagates and we do NOT materialize (pulling would risk clobbering un-pushed edits) — the
     * marker stays set so the next open retries. With no pending marker the working copy is already
     * clean, so we skip straight to materialize → open+sync.
     */
    suspend fun openExisting(): S {
        if (marker.isSet()) {
            mirror.flush()   // throws on failure → no materialize, marker stays set (push-before-pull)
            marker.clear()
        }
        mirror.materialize()
        return openAndSync()
    }

    /**
     * Push the just-created working copy up to its fresh cloud folder, persist the location keyed by
     * [createdVaultUuidHex], then open it into Browse. (The create itself already wrote the working
     * dir; the caller passes the new uuid from CreatedVault.)
     */
    suspend fun createThenOpen(createdVaultUuidHex: String, persistLocation: (vaultUuidHex: String) -> Unit): S {
        mirror.flush()
        persistLocation(createdVaultUuidHex)
        return openAndSync()
    }

    /**
     * Flush after a successful commit. Success clears any prior pending state; failure sets the
     * pending marker (non-blocking "saved locally, not yet synced") so the next [openExisting]
     * retries the push before pulling. NEVER throws — a failed background flush must not crash Browse.
     */
    suspend fun afterCommit() {
        try {
            mirror.flush()
            marker.clear()
        } catch (e: Exception) {
            marker.set()
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `./gradlew :vault-access:test`
Expected: PASS — all six coordinator cases (the keystone `openExisting_flushes_before_materialize_when_pending` is the gate).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access
git commit -m "feat(android): VaultWorkingCopyCoordinator enforces push-before-pull (host-tested keystone)"
```

---

### Task 7: `VaultBrowseModel` flush-after-commit hook

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseModel.kt` (add an injected `onCommit` suspend callback; invoke after each successful mutating commit)
- Test: `android/vault-access/src/test/kotlin/org/secretary/browse/VaultBrowseModelTest.kt` (add a case)

**Interfaces:**
- Produces (consumed by Task 8): `VaultBrowseModel(session, gate, onCommit: suspend () -> Unit = {})`; `onCommit` fires exactly once after each successful mutating op (delete/restore/add-edit-commit/create-block/rename-block/move-record) and NOT after a read-only op or a failed write.

- [ ] **Step 1: Write the failing test** — using the existing fake `VaultSession` in `VaultBrowseModelTest.kt`:

```kotlin
@Test fun onCommit_fires_after_a_successful_write_not_after_a_read() = runTest {
    var commits = 0
    val model = VaultBrowseModel(fakeSession(/* existing happy-path fake */), onCommit = { commits++ })
    model.loadBlocks()
    model.selectBlock(model.blocks.value.first())
    assertEquals("reads must not trigger a flush", 0, commits)
    model.delete(model.selectedRecords.value!!.first()) // a successful mutating commit
    assertEquals("one commit → one flush hook", 1, commits)
}
```

(Match the file's existing fake-session construction + how it seeds a block/record. If the happy-path fake is a helper, reuse it.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-working-copy-lifecycle/android && ./gradlew :vault-access:test --tests '*VaultBrowseModelTest.onCommit_fires_after_a_successful_write_not_after_a_read'`
Expected: FAIL — `onCommit` parameter does not exist.

- [ ] **Step 3: Implement** — add the constructor param and invoke it at the single commit choke points. Read the current `commitThenReload` (~220) and `onEditCommitted` (~172) paths; invoke `onCommit()` after the write succeeds and the reload completes, inside the success path only (never in a catch). Concretely:

```kotlin
class VaultBrowseModel(
    private val session: VaultSession,
    private val gate: WriteReauthGate = NoopReauthGate,
    private val onCommit: suspend () -> Unit = {},
) {
```
In `commitThenReload(...)`, after the op + reload succeed (before returning), call `onCommit()`. In `onEditCommitted()`, after the edit is persisted + state reloaded successfully, call `onCommit()`. Guard so a thrown/failed write does NOT call it. Confirm both add and edit funnel through these two points (move/create/rename block route through `commitThenReload` — verify by reading the methods at lines ~250-296).

- [ ] **Step 4: Run tests**

Run: `./gradlew :vault-access:test`
Expected: PASS (new case + all existing `VaultBrowseModel*Test` cases — the default `onCommit = {}` keeps every existing test unchanged).

- [ ] **Step 5: Commit**

```bash
git add android/vault-access
git commit -m "feat(android): VaultBrowseModel onCommit flush-after-commit hook (default no-op)"
```

---

### Task 8: `:app` wiring — replace both seams, hook flush-after-commit

**Files:**
- Modify: `android/app/src/main/kotlin/org/secretary/app/AppRoot.kt` (the `onOpen` cloud-open seam ~178-183; the `onAcknowledge` create-then-Selection seam ~226-240; build the coordinator + SAF adapters)
- Modify: `android/app/src/main/kotlin/org/secretary/app/ProvisioningRouting.kt` (a `workingVaultDir(filesDir, vaultUuidHex)` keyed-by-uuid overload for the open path; keep the name-keyed one for create)
- Modify: `android/app/src/main/kotlin/org/secretary/app/BrowseSession.kt` if needed to thread `onCommit` into `VaultBrowseModel`
- Test: extend an existing `:app` instrumented test (authored; emulator run is Slice 6) for the new routing where automatable; otherwise compile-gate only

**Interfaces:**
- Consumes: Tasks 3–7 (`CreatedVault.vaultUuid`, `VaultLocation.vaultUuidHex`, `FilePendingFlushMarker`, `VaultWorkingCopyCoordinator`, `VaultMirrorWorkingCopy`, `VaultBrowseModel(onCommit=…)`), plus existing `safCloudFolderPort(context, treeUri)`, `VaultMirror`, `openBrowseWithSync`, `syncStateDir`.
- Produces: real cloud open + create-then-open; flush-after-commit wired to `coordinator.afterCommit()`.

> This task is integration glue exercised end-to-end by Slice 6's instrumented tests (real `.so` + real SAF). Here the gate is: both `:app` compile targets green, the two seams replaced with real coordinator calls, no demo-path regression. Keep the pure ordering logic in the coordinator (Task 6) — do not reimplement it here.

- [ ] **Step 1: Build the per-vault coordinator factory** — add a private helper in `AppRoot.kt` (or a new small `CloudVaultOpen.kt` if `AppRoot` nears 500 lines — split proactively):

```kotlin
/**
 * Assemble the working-copy coordinator for a remembered cloud [location]. The pending-flush marker
 * lives in the app-private sync-state dir (NOT the working copy — VaultMirror mirrors every working
 * file). [openAndSync] runs the existing open+sync pass against the materialized working dir.
 */
private fun cloudCoordinator(
    context: Context,
    location: VaultLocation,
    workingDir: File,
    openAndSync: suspend () -> BrowseSession,
): VaultWorkingCopyCoordinator<BrowseSession> {
    val cloud = safCloudFolderPort(context, location.treeUri)
    val mirror = VaultMirrorWorkingCopy(VaultMirror(cloud), workingDir)
    val markerFile = File(syncStateDir(context.filesDir), "${location.vaultUuidHex}.pending-flush")
    return VaultWorkingCopyCoordinator(mirror, FilePendingFlushMarker(markerFile), openAndSync)
}
```

- [ ] **Step 2: Replace the cloud-open seam (`onOpen`)** — when a remembered `Located` location is opened, materialize-then-open via the coordinator instead of `markUnavailable(CLOUD_OPEN_DEFERRED_REASON)`:

```kotlin
            onOpen = {
                val loc = (selectionState as? VaultSelectionState.Located)?.location
                if (loc == null) {
                    selectionVm.markUnavailable("No remembered vault to open.")
                    selectionState = selectionVm.state
                } else {
                    scope.launch {
                        try {
                            val workingDir = workingVaultDirForUuid(context.filesDir, loc.vaultUuidHex)
                            val coordinator = cloudCoordinator(context, loc, workingDir) {
                                openCloudBrowse(context, scope, workingDir, loc, /* credential */)
                            }
                            route = Route.Browse(coordinator.openExisting(), workingDir)
                        } catch (e: Exception) {
                            Log.w(TAG, "cloud open failed", e)
                            selectionVm.markUnavailable("Couldn't open from your cloud folder — check access and try again.")
                            selectionState = selectionVm.state
                        }
                    }
                }
            },
```

The credential flow needs a password (the cloud open re-unlocks). Reuse the existing unlock UI: route the Located→Open action through `Route.Unlock` carrying the cloud working-dir + location + coordinator (mirror the demo path's `unlockAndOpen`, but pass the materialized `workingDir`/`stateDir`/`vaultUuid` instead of the golden vault, and wrap the open in `coordinator.openExisting`). Implement `openCloudBrowse(...)` as a sibling of `unlockAndOpen` that: builds `openBrowseWithSync(openPort, workingDir, stateDir, hexToBytes(loc.vaultUuidHex), credential, gate)` and wires `onCommit = { coordinator.afterCommit() }` into its `VaultBrowseModel`. (If `vaultUuidHex` is empty — a SAF-picked existing vault whose uuid we don't know yet — read it from the opened session via `session.browse` / the underlying `VaultSession.vaultUuidHex()` after materialize+open, then persist it back into the location. Materialize happens before open regardless, so the uuid is always learnable post-open.)

- [ ] **Step 3: Replace the create-then-Selection seam (`onAcknowledge`)** — open the created vault into Browse via `createThenOpen` instead of returning to Selection:

```kotlin
            onAcknowledge = {
                provisioningVm.acknowledgeMnemonic()
                val done = provisioningVm.step as? VaultProvisioningStep.Done
                if (done != null) {
                    scope.launch {
                        try {
                            val workingDir = workingVaultDir(context.filesDir, /* created vault name */)
                            val coordinator = cloudCoordinator(context, done.location, workingDir) {
                                openCloudBrowse(context, scope, workingDir, done.location, /* credential */)
                            }
                            route = Route.Browse(
                                coordinator.createThenOpen(done.location.vaultUuidHex) { uuid ->
                                    selectionVm.recordSelection(done.location) // already carries uuid
                                },
                                workingDir,
                            )
                        } catch (e: Exception) {
                            Log.w(TAG, "create-then-open failed", e)
                            selectionVm.recordSelection(done.location) // fall back to remembered (next open retries)
                            selectionState = selectionVm.state
                            route = Route.Selection
                        }
                    }
                } else {
                    syncProvisioning()
                }
            },
```

Note: `createThenOpen` re-opens the working copy, which needs the password. The create wizard already collected it; reuse it (the create flow holds the password only transiently). If threading the password into the open is awkward in this slice, the acceptable fallback is: flush + persist via the coordinator, then route to `Route.Unlock` carrying the cloud working-dir (the user re-enters the password once, mirroring desktop "no auto-open"). Pick whichever keeps the password-zeroize discipline intact; document the choice in the handoff.

- [ ] **Step 4: Add the uuid-keyed working dir helper** (`ProvisioningRouting.kt`):

```kotlin
/**
 * The working copy for a remembered cloud vault, keyed by its [vaultUuidHex] (stable across opens,
 * unlike the create-time name). Materialize populates it; it is NOT reset on open (it carries
 * un-pushed edits across an offline session). Falls back to a name-safe slug if uuid is empty.
 */
internal fun workingVaultDirForUuid(filesDir: File, vaultUuidHex: String): File {
    val key = vaultUuidHex.ifEmpty { "unknown" }
    val dir = File(filesDir, "working/$key")
    dir.mkdirs()
    check(dir.isDirectory) { "failed to create working vault dir: ${dir.path}" }
    return dir
}
```

(Do NOT `deleteRecursively()` here — unlike the create path, an existing working dir may hold un-pushed edits. Materialize reconciles it with the cloud.)

- [ ] **Step 5: Compile gates**

Run: `cd /Users/hherb/src/secretary/.worktrees/android-cloud-drive-working-copy-lifecycle/android && ./gradlew :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin :app:testDebugUnitTest`
Expected: all BUILD SUCCESSFUL. The demo path (`onDemo → Route.Unlock → unlockAndOpen` over the golden vault) is unchanged — verify by reading the diff that `unlockAndOpen` and the demo route are untouched.

- [ ] **Step 6: Commit**

```bash
git add android/app
git commit -m "feat(android): wire cloud open + create-then-open via VaultWorkingCopyCoordinator; flush-after-commit"
```

---

### Task 9: README / ROADMAP capability entry (accurately scoped)

**Files:**
- Modify: `README.md` (Android status dot points)
- Modify: `ROADMAP.md` (epic #321 progress)

**Interfaces:** none (docs).

- [ ] **Step 1: Update README** — extend the Android status (brief dot points, per [[feedback_readme_style]]): the Android app now opens a remembered cloud-drive vault and opens a newly-created vault into Browse via the SAF working-copy round-trip (materialize→sync→operate→flush, push-before-pull). Do NOT overclaim: note instrumented E2E / offline / conflict device tests land in Slice 6.

- [ ] **Step 2: Update ROADMAP** — mark epic #321 Slice 5 (working-copy lifecycle) done; Slice 6 (instrumented E2E + offline/conflict) remaining.

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: Android cloud-drive working-copy lifecycle (slice 5) — README/ROADMAP"
```

---

## Self-Review

**Spec coverage:**
- materialize→sync→operate→flush lifecycle → Task 6 (coordinator) + Task 8 (wiring). ✓
- push-before-pull keystone (flush-pending before materialize) → Task 6 keystone test. ✓
- flush-after-commit + failure→pending marker + retry-on-open → Tasks 5, 6 (`afterCommit`, `openExisting` retry), 7 (`onCommit` hook), 8 (wiring). ✓
- `CreatedVault` returns `vault_uuid` (FFI extension, threaded across bindings) → Tasks 1, 2, 3. ✓
- `VaultLocation` gains `vaultUuidHex`, v1-tolerant codec → Task 4. ✓
- SyncState / working-dir keyed by vault_uuid → Task 8 (`workingVaultDirForUuid`, marker keyed by uuid; SyncState keying reuses existing `makeVaultSync`/`syncStateDir`). ✓
- Replace both Slice-4 seams → Task 8. ✓
- Demo path untouched → Task 8 Step 5 verification. ✓
- No core/format/conformance/KAT change → enforced by Global Constraints + Task 1 using core's existing decoder. ✓
- Marker outside the working copy (VaultMirror mirrors all working files) → Task 5 note + Task 8 placement. ✓

**Placeholder scan:** the only deliberately-open items are the `/* credential */` flow in Task 8 (with a documented acceptable fallback) — integration glue resolved against the live AppRoot during execution, exercised E2E in Slice 6. All pure-logic tasks (1–7) carry complete code + tests.

**Type consistency:** `CreatedVault(phrase, vaultUuid)` (Task 3) ↔ `done.location.vaultUuidHex` (Tasks 3, 4) ↔ coordinator `createThenOpen(createdVaultUuidHex)` (Task 6) ↔ `workingVaultDirForUuid`/marker keyed by `vaultUuidHex` (Task 8). `WorkingCopyMirror`/`VaultMirrorWorkingCopy`/`VaultWorkingCopyCoordinator`/`PendingFlushMarker`/`FilePendingFlushMarker` names are consistent across Tasks 5, 6, 8. `MirrorReport`/`VaultMirrorException` reused from Slice 3. ✓
