# B.2 — FFI projection of the per-device wrap slot — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the B.1 per-device wrap slot across the FFI surface — `add_device_slot`, `open_with_device_secret`, `remove_device_slot` — joining the folder-in (B.4) family, with honest typed errors and a full cross-language conformance proof.

**Architecture:** The device path becomes a first-class folder-in vault open via a new additive `Unlocker::DeviceSecret` arm in core. The bridge crate (`secretary-ffi-bridge`) is the single source of truth; uniffi + pyo3 are thin projections. Three new `FfiVaultError` variants (`DeviceSlotNotFound`, `WrongDeviceSecretOrCorrupt`, `DeviceUuidMismatch`); wrong-length inputs raise `InvalidArgument` at the binding layer (bridge takes fixed arrays). Conformance reuses the existing `vault_dir` replay plus a writable-temp enrol round-trip.

**Tech Stack:** Rust (stable), uniffi 0.31 (UDL), PyO3 0.28, Swift + Kotlin conformance harnesses, Python stdlib clean-room (`conformance.py`), `uv` for Python.

**Spec:** `docs/superpowers/specs/2026-06-10-b2-device-slot-ffi-design.md`

**Conventions every task follows:**
- Work in the worktree: `/Users/hherb/src/secretary/.worktrees/b2-device-slot-ffi` on branch `feature/b2-device-slot-ffi`. Verify with `pwd && git branch --show-current` before path-sensitive commands.
- TDD: failing test → run-to-fail → implement → run-to-pass → commit.
- No hardcoded crypto literals in tests — pinned values come from `core/tests/data/golden_vault_001_inputs.json` (`device_slot_uuid_hex = d0d0…d0`, `device_slot_secret_hex = 000102…`).
- Build/test always `--release` (crypto crates are slow in debug).
- Pinned device-slot facts: golden fixture wrap file `core/tests/data/golden_vault_001/devices/d0d0d0d0-d0d0-d0d0-d0d0-d0d0d0d0d0d0.wrap`; the password for `golden_vault_001` resolves from `golden_vault_001_inputs.json:password`.

---

## File Structure

**Core**
- Modify `core/src/vault/orchestrators.rs` — add `Unlocker::DeviceSecret` + `open_vault` arm + unit tests.

**Bridge (`ffi/secretary-ffi-bridge/`)**
- Modify `src/error/vault/mod.rs` — 3 new `FfiVaultError` variants; intercept device unlock errors; promote `DeviceSlotNotFound`.
- Modify `src/error/vault/tests.rs` — invert/extend tripwires.
- Create `src/device.rs` — `add_device_slot`, `open_with_device_secret`, `remove_device_slot`, `DeviceEnrollOutput`, `DeviceSecretOutput` + integration tests.
- Modify `src/lib.rs` — `pub mod device;` + re-exports.

**uniffi (`ffi/secretary-ffi-uniffi/`)**
- Modify `src/errors/vault.rs` — 3 `From<FfiVaultError>` arms + tripwires.
- Modify `src/secretary.udl` — 3 `VaultError` variants; `DeviceSecretOutput` interface; `DeviceEnrollOutput` dictionary; 3 namespace fns.
- Modify `src/wrappers/identity.rs` (or new `src/wrappers/device.rs`) — `DeviceSecretOutput` object + `DeviceEnrollOutput` dict.
- Modify `src/namespace/mod.rs` — 3 namespace fns with length pre-checks + zeroize.
- Modify `tests/swift/ConformanceErrors.swift` + `tests/kotlin/ConformanceErrors.kt` — 3 new variant cases.
- Modify Swift/Kotlin smoke + conformance runners (Tasks 11–12).

**pyo3 (`ffi/secretary-ffi-py/`)**
- Create `src/device.rs` — 3 `#[pyfunction]` + `DeviceSecretOutput` + `DeviceEnrollOutput` pyclasses.
- Modify `src/errors.rs` — 3 exception classes + translator arms.
- Modify `src/lib.rs` — register.
- Add `tests/test_device_slot.py` (pyo3 pytest).

**Conformance**
- Modify `core/tests/conformance_kat_helpers/types.rs` — `Operation::OpenWithDeviceSecret`.
- Modify `core/tests/conformance_kat_helpers/dispatch/open.rs` + `fixtures.rs` — dispatch + input resolution.
- Modify `core/tests/conformance_kat.rs` — dispatch arm.
- Modify `core/tests/data/conformance_kat.json` — vectors (regenerated).
- Modify Swift + Kotlin conformance runners — dispatch arm + enrol round-trip.
- Modify `core/tests/python/conformance.py` — clean-room device-slot checks.

**Docs**
- `README.md`, `ROADMAP.md`, `CLAUDE.md`, handoff.

---

## Task 1: Core — `Unlocker::DeviceSecret`

**Files:**
- Modify: `core/src/vault/orchestrators.rs` (enum at ~397, `open_vault` dispatch at ~520)
- Test: same file's `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing test**

Add to the test module in `core/src/vault/orchestrators.rs` (the module already has helpers that build a vault on disk; follow the existing `open_vault(&dest, Unlocker::Password(&password), None)` pattern at line ~2346). This test enrols a device into a freshly-created on-disk vault, then opens via the new `Unlocker::DeviceSecret` arm and asserts parity with the password open.

```rust
#[test]
fn open_vault_with_device_secret_matches_password_open() {
    use crate::vault::device_slot::add_device_slot;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    // Build a real on-disk vault (helper used elsewhere in this module).
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path();
    let password = SecretBytes::new(b"hunter2".to_vec());
    write_test_vault(dest, &password); // existing module helper (create_vault_unchecked + writes)

    // Enrol a device slot (writes devices/<uuid>.wrap).
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let enrolled = add_device_slot(dest, &password, &mut rng).expect("enrol");

    // Open via the new device-secret arm.
    let by_dev = open_vault(
        dest,
        Unlocker::DeviceSecret {
            device_uuid: &enrolled.device_uuid,
            secret: &enrolled.device_secret,
        },
        None,
    )
    .expect("device open");

    let by_pw = open_vault(dest, Unlocker::Password(&password), None).expect("pw open");

    assert_eq!(
        by_dev.identity_block_key.expose(),
        by_pw.identity_block_key.expose(),
        "device-secret open must recover the same IBK as the password open",
    );
    assert_eq!(by_dev.identity.user_uuid, by_pw.identity.user_uuid);
    assert_eq!(
        by_dev.manifest.vector_clock, by_pw.manifest.vector_clock,
        "both opens must verify + decrypt the same manifest",
    );
}

#[test]
fn open_vault_with_device_secret_absent_slot_is_device_slot_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path();
    let password = SecretBytes::new(b"hunter2".to_vec());
    write_test_vault(dest, &password);

    // No device enrolled → the wrap file is absent.
    let secret = SecretBytes::new(vec![0u8; 32]);
    let err = open_vault(
        dest,
        Unlocker::DeviceSecret {
            device_uuid: &[0xAB; 16],
            secret: &secret,
        },
        None,
    )
    .unwrap_err();
    assert!(matches!(err, VaultError::DeviceSlotNotFound), "got {err:?}");
}
```

> If `write_test_vault` does not already exist as a module helper, search the test module for the existing vault-on-disk builder (e.g. the one used at line ~2346) and reuse its exact name. Do NOT invent a new helper — the test module already constructs vaults for `open_vault` tests.

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/b2-device-slot-ffi && cargo test --release -p secretary-core open_vault_with_device_secret -- --nocapture`
Expected: FAIL — `Unlocker::DeviceSecret` variant does not exist (compile error).

- [ ] **Step 3: Add the enum variant**

In the `Unlocker<'a>` enum (after the `Recovery(&'a str)` variant):

```rust
    /// Per-device wrap secret (ADR 0009 / §5a). Recovers the IBK from
    /// `devices/<device_uuid>.wrap` via `unlock::device::open_with_device_secret`.
    /// `device_uuid` locates the wrap file AND is the §3a structural check
    /// (header device_uuid must equal it). The 32-byte secret is what B.3's
    /// Secure Enclave releases after a biometric check.
    DeviceSecret {
        /// 16-byte device UUID — the `devices/<uuid>.wrap` filename + §3a header check.
        device_uuid: &'a [u8; 16],
        /// 32-byte device secret (high-entropy random; not password-derived).
        secret: &'a SecretBytes,
    },
```

- [ ] **Step 4: Add the `open_vault` dispatch arm**

In `open_vault`'s step-2 `match unlocker { … }` (after the `Unlocker::Recovery` arm). It must read the wrap file relative to `folder` (absent → `DeviceSlotNotFound`) and route through the existing B.1 pure-crypto open. Reuse the device-slot folder helpers; the filename format is `devices/<hyphenated-uuid>.wrap` (`format_uuid_hyphenated`).

```rust
        Unlocker::DeviceSecret { device_uuid, secret } => {
            // Read devices/<uuid>.wrap relative to the vault folder. Absent →
            // DeviceSlotNotFound (mirrors vault::device_slot::open_identity_with_device_secret).
            let wrap_path = folder
                .join("devices")
                .join(format!("{}.wrap", format_uuid_hyphenated(device_uuid)));
            let wrap_bytes = match std::fs::read(&wrap_path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(VaultError::DeviceSlotNotFound);
                }
                Err(e) => {
                    return Err(VaultError::Io {
                        context: "failed to read device wrap file",
                        source: e,
                    });
                }
            };
            unlock::device::open_with_device_secret(
                &vault_toml_bytes,
                &wrap_bytes,
                &identity_bundle_bytes,
                device_uuid,
                secret,
            )?
        }
```

> `format_uuid_hyphenated` is already imported/used in `device_slot.rs`; confirm it is in scope in `orchestrators.rs` (it lives in `crate::vault::orchestrators`, so it is local). `unlock::device::open_with_device_secret` is `pub` (B.1). The trailing `?` maps `UnlockError` → `VaultError::Unlock` via the existing `From` (the `Password`/`Recovery` arms rely on the same conversion).

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test --release -p secretary-core open_vault_with_device_secret -- --nocapture`
Expected: PASS (both tests).

- [ ] **Step 6: Clippy + commit**

Run: `cargo clippy --release -p secretary-core --tests -- -D warnings`
Expected: clean.

```bash
git add core/src/vault/orchestrators.rs
git commit -m "feat(core): Unlocker::DeviceSecret — first-class device-secret vault open (B.2)"
```

---

## Task 2: Bridge — promote `FfiVaultError` device variants

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (enum ~36–314; `From` match ~317; device fold ~452; `VE::Unlock` arm ~327)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/tests.rs`

- [ ] **Step 1: Write the failing tests**

Add to `ffi/secretary-ffi-bridge/src/error/vault/tests.rs` (mirror the existing `From<core::VaultError>` pin-test style). Use `secretary_core::vault::VaultError` and `secretary_core::unlock::UnlockError`.

```rust
#[test]
fn device_slot_not_found_promotes_to_dedicated_variant() {
    let core = secretary_core::vault::VaultError::DeviceSlotNotFound;
    let ffi: FfiVaultError = core.into();
    assert!(matches!(ffi, FfiVaultError::DeviceSlotNotFound), "got {ffi:?}");
}

#[test]
fn unlock_wrong_device_secret_promotes_on_vault_error() {
    use secretary_core::unlock::UnlockError;
    let core = secretary_core::vault::VaultError::Unlock(UnlockError::WrongDeviceSecretOrCorrupt);
    let ffi: FfiVaultError = core.into();
    assert!(matches!(ffi, FfiVaultError::WrongDeviceSecretOrCorrupt), "got {ffi:?}");
}

#[test]
fn unlock_device_uuid_mismatch_promotes_on_vault_error() {
    use secretary_core::unlock::UnlockError;
    let core = secretary_core::vault::VaultError::Unlock(UnlockError::DeviceUuidMismatch);
    let ffi: FfiVaultError = core.into();
    assert!(matches!(ffi, FfiVaultError::DeviceUuidMismatch { .. }), "got {ffi:?}");
}

#[test]
fn unlock_malformed_device_file_folds_to_corrupt_vault() {
    use secretary_core::unlock::{device_file::DeviceFileError, UnlockError};
    let core = secretary_core::vault::VaultError::Unlock(
        UnlockError::MalformedDeviceFile(DeviceFileError::BadMagic { got: 0 }),
    );
    let ffi: FfiVaultError = core.into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }), "got {ffi:?}");
}

#[test]
fn unlock_malformed_device_secret_folds_to_corrupt_vault_unreachable() {
    // Structurally unreachable through any FFI surface (bridge takes &[u8;32]);
    // the binding layer raises InvalidArgument first. Pinned like WeakKdfParams.
    use secretary_core::unlock::UnlockError;
    let core = secretary_core::vault::VaultError::Unlock(UnlockError::MalformedDeviceSecret { len: 7 });
    let ffi: FfiVaultError = core.into();
    assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }), "got {ffi:?}");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge device_slot_not_found_promotes -- --nocapture`
Expected: FAIL — `FfiVaultError::DeviceSlotNotFound` / `WrongDeviceSecretOrCorrupt` / `DeviceUuidMismatch` do not exist.

- [ ] **Step 3: Add the three enum variants**

In `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, in `pub enum FfiVaultError` (place after `CannotDeleteOwnerContact` or near the other device-adjacent variants; order is not semantically significant but keep it grouped + documented):

```rust
    /// ADR 0009 (B.2): the requested device slot (`devices/<uuid>.wrap`) does
    /// not exist. Returned by `open_with_device_secret` / `remove_device_slot`.
    /// A benign "unknown device" caller condition, NOT a data-integrity failure —
    /// hence its own variant rather than a `CorruptVault` fold.
    #[error("device slot not found")]
    DeviceSlotNotFound,

    /// ADR 0009 (B.2): wrong device secret OR wrap-file corruption —
    /// deliberately conflated (anti-oracle, parallel to
    /// `WrongPasswordOrCorrupt`). AEAD tag failure under `device_kek` is
    /// indistinguishable from corruption to the cryptography.
    #[error("wrong device secret or vault corruption")]
    WrongDeviceSecretOrCorrupt,

    /// ADR 0009 (B.2): the wrap file's header `device_uuid` does not equal the
    /// device UUID it was looked up by (vault-format §3a relabel-integrity
    /// check). Structural, not a secret oracle. `detail` is free-form.
    #[error("device UUID mismatch: {detail}")]
    DeviceUuidMismatch {
        /// Diagnostic text; free-form, not part of the API contract.
        detail: String,
    },
```

- [ ] **Step 4: Intercept device unlock errors + promote `DeviceSlotNotFound`**

Two edits in the `From<core::VaultError> for FfiVaultError` match:

(a) Replace the single `VE::Unlock(unlock_err) => { … }` arm (~327) so device-class unlock errors are intercepted *before* the generic `FfiUnlockError` fold. Add `use secretary_core::unlock::UnlockError as UE;` at the top of the `fn from` body (next to `use … VaultError as VE;`).

```rust
            // Device-slot unlock errors (ADR 0009 / B.2): promote the two
            // honest variants; the corrupt-file + (unreachable) bad-secret
            // cases fold to CorruptVault via the generic path below.
            VE::Unlock(UE::WrongDeviceSecretOrCorrupt) => FfiVaultError::WrongDeviceSecretOrCorrupt,
            VE::Unlock(UE::DeviceUuidMismatch) => FfiVaultError::DeviceUuidMismatch {
                detail: "device wrap header UUID does not match the requested device".to_string(),
            },

            // All other unlock-class errors: delegate to the FfiUnlockError
            // translation so the mirrored variants stay drift-free.
            // (MalformedDeviceFile + the structurally-unreachable
            // MalformedDeviceSecret fold to CorruptVault via this path.)
            VE::Unlock(unlock_err) => {
                let intermediate: super::FfiUnlockError = unlock_err.into();
                intermediate.into()
            }
```

(b) Remove `VE::DeviceSlotNotFound` from the trailing `CorruptVault` catchall group (~452) and give it its own arm. Add before the catchall group:

```rust
            // ADR 0009 (B.2): promoted to its own variant (was a CorruptVault
            // fold in B.1 when no FFI surface existed).
            VE::DeviceSlotNotFound => FfiVaultError::DeviceSlotNotFound,
```

Then delete the `| VE::DeviceSlotNotFound` line (and its preceding comment block) from the `e @ ( … )` catchall.

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge -- device_slot device_uuid malformed_device --nocapture`
Expected: PASS (5 new tests). The compiler also confirms the `From` match stays exhaustive.

- [ ] **Step 6: Clippy + commit**

Run: `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings`

```bash
git add ffi/secretary-ffi-bridge/src/error/vault/mod.rs ffi/secretary-ffi-bridge/src/error/vault/tests.rs
git commit -m "feat(bridge): promote DeviceSlotNotFound/WrongDeviceSecret/DeviceUuidMismatch FfiVaultError variants (B.2)"
```

---

## Task 3: Bridge — `device.rs` ops + handles

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/device.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`

- [ ] **Step 1: Write the failing integration test**

Create `ffi/secretary-ffi-bridge/src/device.rs` with the test module first (drives the API shape). Use `include_bytes!`-free, on-disk fixtures by copying `golden_vault_001` into a tempdir (the writable-temp pattern; see `core/tests/conformance_kat_helpers` for `copy_dir_all` precedent, or use a small inline recursive copy).

```rust
//! FFI-bridge folder-in device-slot ops (ADR 0009 / B.2). Siblings of
//! `vault::open_vault_with_password`. Pure crypto/folder logic lives in
//! `secretary_core::vault::device_slot`; this layer adapts to the
//! `FfiVaultError` surface + the one-shot `DeviceSecretOutput` handle.

use std::path::Path;
use std::sync::Mutex;

use secretary_core::crypto::secret::SecretBytes;
use zeroize::Zeroize as _;

use crate::error::FfiVaultError;
use crate::vault::OpenVaultOutput;

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_golden() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        copy_dir_all(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/tests/data/golden_vault_001"),
            tmp.path(),
        );
        tmp
    }

    // Minimal recursive copy (test-only). Mirrors the conformance helper.
    fn copy_dir_all(src: std::path::PathBuf, dst: &Path) {
        for entry in std::fs::read_dir(&src).unwrap() {
            let entry = entry.unwrap();
            let to = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                std::fs::create_dir_all(&to).unwrap();
                copy_dir_all(entry.path(), &to);
            } else {
                std::fs::copy(entry.path(), &to).unwrap();
            }
        }
    }

    const PASSWORD: &[u8] = b"correct horse battery staple"; // overwritten below from inputs

    fn password() -> Vec<u8> {
        // Source of truth: golden_vault_001_inputs.json:password.
        let raw = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../core/tests/data/golden_vault_001_inputs.json"),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["password"].as_str().unwrap().as_bytes().to_vec()
    }

    #[test]
    fn enroll_then_open_round_trips() {
        let tmp = temp_golden();
        let mut out = add_device_slot(tmp.path(), &password()).expect("enrol");
        assert_eq!(out.device_uuid.len(), 16);
        let uuid: [u8; 16] = out.device_uuid.clone().try_into().unwrap();
        let secret = out.device_secret.take_secret().expect("first take");
        assert_eq!(secret.len(), 32);
        assert!(out.device_secret.take_secret().is_none(), "one-shot");

        let secret_arr: [u8; 32] = secret.clone().try_into().unwrap();
        let opened = open_with_device_secret(tmp.path(), &uuid, &secret_arr).expect("open");
        assert_eq!(opened.identity.user_uuid().len(), 16);
    }

    #[test]
    fn enroll_wrong_password_is_wrong_password_or_corrupt() {
        let tmp = temp_golden();
        let err = add_device_slot(tmp.path(), b"wrong-password").unwrap_err();
        assert!(matches!(err, FfiVaultError::WrongPasswordOrCorrupt), "got {err:?}");
    }

    #[test]
    fn open_absent_slot_is_device_slot_not_found() {
        let tmp = temp_golden();
        let err = open_with_device_secret(tmp.path(), &[0xAB; 16], &[0u8; 32]).unwrap_err();
        assert!(matches!(err, FfiVaultError::DeviceSlotNotFound), "got {err:?}");
    }

    #[test]
    fn remove_then_open_is_device_slot_not_found() {
        let tmp = temp_golden();
        let mut out = add_device_slot(tmp.path(), &password()).unwrap();
        let uuid: [u8; 16] = out.device_uuid.clone().try_into().unwrap();
        out.device_secret.wipe();
        remove_device_slot(tmp.path(), &uuid).expect("remove");
        let err = remove_device_slot(tmp.path(), &uuid).unwrap_err();
        assert!(matches!(err, FfiVaultError::DeviceSlotNotFound), "second remove");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge enroll_then_open -- --nocapture`
Expected: FAIL — `add_device_slot` / `open_with_device_secret` / `DeviceSecretOutput` undefined.

- [ ] **Step 3: Implement the handles + ops**

Prepend to `device.rs` (above the test module):

```rust
/// Opaque one-shot handle for a freshly-minted 32-byte device secret. Mirrors
/// `MnemonicOutput`: `take_secret()` returns `Some` once then `None`; `wipe()`
/// is idempotent. The secret is the only thing B.3 stores in the Secure Enclave.
pub struct DeviceSecretOutput {
    inner: Mutex<Option<SecretBytes>>,
}

impl DeviceSecretOutput {
    pub(crate) fn new(s: SecretBytes) -> Self {
        Self { inner: Mutex::new(Some(s)) }
    }

    /// Test-only constructor (sibling crates' wrapper tests).
    #[doc(hidden)]
    pub fn new_for_test(s: SecretBytes) -> Self {
        Self::new(s)
    }

    /// Take the 32-byte secret as fresh caller-owned bytes. ONE-SHOT — the
    /// inner `SecretBytes` is consumed + dropped (zeroized) here; the returned
    /// `Vec<u8>` is copied out before the drop. Subsequent calls return `None`.
    /// The caller MUST zeroize the returned bytes after use.
    pub fn take_secret(&self) -> Option<Vec<u8>> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let s = guard.take()?;
        let bytes = s.expose().to_vec();
        Some(bytes) // s drops here → SecretBytes ZeroizeOnDrop wipes its buffer
    }

    /// Idempotent explicit close; drops + zeroizes any still-resident secret.
    pub fn wipe(&self) {
        let _ = self.inner.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

/// Output of `add_device_slot`: the new device UUID (non-secret) + a one-shot
/// handle to its secret.
pub struct DeviceEnrollOutput {
    pub device_uuid: Vec<u8>,
    pub device_secret: DeviceSecretOutput,
}

/// Enrol a new device into the vault at `folder`. Recovers + validates the IBK
/// with `password`, mints a fresh device UUID + secret, and atomically writes
/// `devices/<uuid>.wrap`. Wrong password errors before any file is written.
///
/// `password` is borrowed and copied into a `SecretBytes` internally; the
/// caller's buffer is the binding layer's concern.
pub fn add_device_slot(folder: &Path, password: &[u8]) -> Result<DeviceEnrollOutput, FfiVaultError> {
    let pw = SecretBytes::from(password);
    let mut rng = rand_core::OsRng;
    let enrolled = secretary_core::vault::device_slot::add_device_slot(folder, &pw, &mut rng)?;
    Ok(DeviceEnrollOutput {
        device_uuid: enrolled.device_uuid.to_vec(),
        device_secret: DeviceSecretOutput::new(enrolled.device_secret),
    })
}

/// Open a vault from a device secret (full vault open: identity + manifest).
/// `device_uuid` + `device_secret` are FIXED arrays — length is validated at
/// the binding layer (wrong length → InvalidArgument there), so a wrong length
/// is unrepresentable here.
pub fn open_with_device_secret(
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let secret = SecretBytes::from(&device_secret[..]);
    let core_out = secretary_core::vault::open_vault(
        folder,
        secretary_core::vault::Unlocker::DeviceSecret { device_uuid, secret: &secret },
        None,
    )?;
    Ok(crate::vault::split_core_open_vault(core_out, folder.to_path_buf()))
}

/// Revoke a device by deleting `devices/<uuid>.wrap`. Missing file →
/// `DeviceSlotNotFound`.
pub fn remove_device_slot(folder: &Path, device_uuid: &[u8; 16]) -> Result<(), FfiVaultError> {
    secretary_core::vault::device_slot::remove_device_slot(folder, device_uuid)?;
    Ok(())
}
```

> Notes for the implementer:
> - `split_core_open_vault` is currently private in `vault/orchestration.rs`. Make it `pub(crate)` so `device.rs` can reuse it (it already returns the bridge `OpenVaultOutput`). If that proves awkward, expose a thin `pub(crate) fn open_vault_with_device_secret(folder, uuid, &secret) -> Result<OpenVaultOutput, FfiVaultError>` inside `vault/orchestration.rs` and call it from `device.rs`. Either way, do NOT duplicate the split logic.
> - `SecretBytes::from(&[u8])` / `SecretBytes::from(&device_secret[..])`: confirm the `From<&[u8]>` impl exists (used as `SecretBytes::from(password)` in `create.rs`). If the impl is `From<&[u8]>`, `SecretBytes::from(password)` works; for the array use `SecretBytes::new(device_secret.to_vec())`.
> - `rand_core::OsRng` is the same RNG `create_vault` uses; confirm the import path matches `create.rs` (`use rand_core::OsRng;` or `secretary_core::...`).
> - `serde_json` is a dev-dependency for the test; if absent from the bridge's `[dev-dependencies]`, add it (it is already a workspace dep).

- [ ] **Step 4: Register in lib.rs**

In `ffi/secretary-ffi-bridge/src/lib.rs`, add `pub mod device;` (alphabetical, near `pub mod create;`) and a re-export:

```rust
pub use device::{add_device_slot, open_with_device_secret, remove_device_slot, DeviceEnrollOutput, DeviceSecretOutput};
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge -- enroll_ open_absent remove_then --nocapture`
Expected: PASS (4 tests).

- [ ] **Step 6: Clippy + commit**

Run: `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings`

```bash
git add ffi/secretary-ffi-bridge/src/device.rs ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/src/vault/orchestration.rs ffi/secretary-ffi-bridge/Cargo.toml
git commit -m "feat(bridge): device-slot folder ops + one-shot DeviceSecretOutput (B.2)"
```

---

## Task 4: uniffi — `VaultError` variants + `From` arms

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/errors/vault.rs`

- [ ] **Step 1: Write the failing tripwire tests**

Add to the test module in `ffi/secretary-ffi-uniffi/src/errors/vault.rs` (mirror the existing `From<FfiVaultError>` 1:1 pin tests):

```rust
#[test]
fn device_slot_not_found_maps_one_to_one() {
    let u: VaultError = FfiVaultError::DeviceSlotNotFound.into();
    assert!(matches!(u, VaultError::DeviceSlotNotFound));
}

#[test]
fn wrong_device_secret_maps_one_to_one() {
    let u: VaultError = FfiVaultError::WrongDeviceSecretOrCorrupt.into();
    assert!(matches!(u, VaultError::WrongDeviceSecretOrCorrupt));
}

#[test]
fn device_uuid_mismatch_maps_one_to_one() {
    let u: VaultError = FfiVaultError::DeviceUuidMismatch { detail: "x".into() }.into();
    assert!(matches!(u, VaultError::DeviceUuidMismatch { detail } if detail == "x"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-ffi-uniffi device_slot_not_found_maps -- --nocapture`
Expected: FAIL — uniffi-side `VaultError::DeviceSlotNotFound` etc. do not exist.

- [ ] **Step 3: Add the three variants + From arms**

In the `pub enum VaultError` in `errors/vault.rs` (group near the other vault-specific variants):

```rust
    /// Mirrors `FfiVaultError::DeviceSlotNotFound` (ADR 0009 / B.2).
    #[error("device slot not found")]
    DeviceSlotNotFound,
    /// Mirrors `FfiVaultError::WrongDeviceSecretOrCorrupt` (anti-oracle).
    #[error("wrong device secret or vault corruption")]
    WrongDeviceSecretOrCorrupt,
    /// Mirrors `FfiVaultError::DeviceUuidMismatch` (§3a relabel integrity).
    #[error("device UUID mismatch: {detail}")]
    DeviceUuidMismatch { detail: String },
```

In `impl From<FfiVaultError> for VaultError`, add the three 1:1 arms:

```rust
            FfiVaultError::DeviceSlotNotFound => Self::DeviceSlotNotFound,
            FfiVaultError::WrongDeviceSecretOrCorrupt => Self::WrongDeviceSecretOrCorrupt,
            FfiVaultError::DeviceUuidMismatch { detail } => Self::DeviceUuidMismatch { detail },
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release -p secretary-ffi-uniffi -- device_slot_not_found wrong_device device_uuid_mismatch --nocapture`
Expected: PASS.

- [ ] **Step 5: Clippy + commit**

Run: `cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings`

```bash
git add ffi/secretary-ffi-uniffi/src/errors/vault.rs
git commit -m "feat(uniffi): mirror device-slot VaultError variants (B.2)"
```

---

## Task 5: uniffi — UDL surface + namespace fns + handles

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Create: `ffi/secretary-ffi-uniffi/src/wrappers/device.rs` (+ `mod device;` in `wrappers/mod.rs`)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`

- [ ] **Step 1: Write the failing wrapper test**

Create `ffi/secretary-ffi-uniffi/src/wrappers/device.rs`:

```rust
//! uniffi-side device-slot handles: `DeviceSecretOutput` (one-shot) + the
//! `DeviceEnrollOutput` dictionary. Thin forwarders to the bridge handles.

/// uniffi opaque one-shot handle around `bridge::DeviceSecretOutput`.
/// `take_secret()` returns `Some` once then `null`; `wipe()` idempotent.
/// Same `close → wipe` rename rationale as `MnemonicOutput`.
pub struct DeviceSecretOutput(pub(crate) secretary_ffi_bridge::DeviceSecretOutput);

impl DeviceSecretOutput {
    pub fn take_secret(&self) -> Option<Vec<u8>> {
        self.0.take_secret()
    }
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi dictionary for `add_device_slot`'s return: the 16-byte device UUID
/// (non-secret) + the one-shot secret handle.
pub struct DeviceEnrollOutput {
    pub device_uuid: Vec<u8>,
    pub device_secret: std::sync::Arc<DeviceSecretOutput>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::crypto::secret::SecretBytes;

    #[test]
    fn device_secret_output_is_one_shot_through_wrapper() {
        let bridge = secretary_ffi_bridge::DeviceSecretOutput::new_for_test(
            SecretBytes::new(vec![7u8; 32]),
        );
        let h = DeviceSecretOutput(bridge);
        assert_eq!(h.take_secret().unwrap().len(), 32);
        assert!(h.take_secret().is_none());
        h.wipe(); // idempotent after take
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-ffi-uniffi device_secret_output_is_one_shot -- --nocapture`
Expected: FAIL — module not declared.

- [ ] **Step 3: Wire the module + namespace fns**

In `wrappers/mod.rs` add `pub mod device;`. In `namespace/mod.rs` import the new types and add the three functions (mirror the `save_block` length pre-check pattern at ~227 and the `open_with_password` zeroize pattern):

```rust
use crate::wrappers::device::{DeviceEnrollOutput, DeviceSecretOutput};

/// Enrol a new device slot. uniffi-projected (B.2). Writes `devices/<uuid>.wrap`
/// into `folder_path`. Returns the device UUID + a one-shot secret handle.
pub fn add_device_slot(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
) -> Result<DeviceEnrollOutput, VaultError> {
    let folder = match std::str::from_utf8(&folder_path) {
        Ok(s) => std::path::PathBuf::from(s),
        Err(_) => {
            password.zeroize();
            return Err(VaultError::FolderInvalid {
                detail: "folder_path is not valid UTF-8".to_string(),
            });
        }
    };
    let result = secretary_ffi_bridge::add_device_slot(&folder, &password)
        .map(|o| DeviceEnrollOutput {
            device_uuid: o.device_uuid,
            device_secret: std::sync::Arc::new(DeviceSecretOutput(o.device_secret)),
        })
        .map_err(VaultError::from);
    password.zeroize();
    result
}

/// Open a vault from a device secret. uniffi-projected (B.2). `device_uuid`
/// must be 16 bytes and `device_secret` 32 bytes, else `InvalidArgument`.
pub fn open_with_device_secret(
    folder_path: Vec<u8>,
    device_uuid: Vec<u8>,
    mut device_secret: Vec<u8>,
) -> Result<std::sync::Arc<OpenVaultOutput>, VaultError> {
    if device_uuid.len() != 16 {
        device_secret.zeroize();
        return Err(VaultError::InvalidArgument {
            detail: format!("device_uuid must be 16 bytes, got {}", device_uuid.len()),
        });
    }
    if device_secret.len() != 32 {
        let got = device_secret.len();
        device_secret.zeroize();
        return Err(VaultError::InvalidArgument {
            detail: format!("device_secret must be 32 bytes, got {got}"),
        });
    }
    let folder = match std::str::from_utf8(&folder_path) {
        Ok(s) => std::path::PathBuf::from(s),
        Err(_) => {
            device_secret.zeroize();
            return Err(VaultError::FolderInvalid {
                detail: "folder_path is not valid UTF-8".to_string(),
            });
        }
    };
    let uuid: [u8; 16] = device_uuid.as_slice().try_into().expect("len checked");
    let mut secret_arr: [u8; 32] = device_secret.as_slice().try_into().expect("len checked");
    let result = secretary_ffi_bridge::open_with_device_secret(&folder, &uuid, &secret_arr)
        .map(|inner| std::sync::Arc::new(OpenVaultOutput::from_bridge(inner)))
        .map_err(VaultError::from);
    secret_arr.zeroize();
    device_secret.zeroize();
    result
}

/// Revoke a device slot. uniffi-projected (B.2). `device_uuid` must be 16 bytes.
pub fn remove_device_slot(
    folder_path: Vec<u8>,
    device_uuid: Vec<u8>,
) -> Result<(), VaultError> {
    if device_uuid.len() != 16 {
        return Err(VaultError::InvalidArgument {
            detail: format!("device_uuid must be 16 bytes, got {}", device_uuid.len()),
        });
    }
    let folder = std::str::from_utf8(&folder_path)
        .map_err(|_| VaultError::FolderInvalid {
            detail: "folder_path is not valid UTF-8".to_string(),
        })?;
    let uuid: [u8; 16] = device_uuid.as_slice().try_into().expect("len checked");
    secretary_ffi_bridge::remove_device_slot(&std::path::PathBuf::from(folder), &uuid)
        .map_err(VaultError::from)
}
```

> `OpenVaultOutput::from_bridge` — confirm how `open_vault_with_password`'s namespace fn wraps the bridge `OpenVaultOutput` (it may construct the uniffi `OpenVaultOutput` directly from fields rather than a `from_bridge` ctor). Match that existing pattern exactly — read `namespace/mod.rs`'s `open_vault_with_password` body and copy its wrapping idiom.

- [ ] **Step 4: Add UDL declarations**

In `src/secretary.udl`:

Namespace block (after the existing device-free folder ops):

```
    /// Enrol a new device slot, writing devices/<uuid>.wrap. (B.2)
    [Throws=VaultError]
    DeviceEnrollOutput add_device_slot(bytes folder_path, bytes password);

    /// Open a vault from a device secret. device_uuid=16 bytes, device_secret=32. (B.2)
    [Throws=VaultError]
    OpenVaultOutput open_with_device_secret(bytes folder_path, bytes device_uuid, bytes device_secret);

    /// Revoke a device slot (delete devices/<uuid>.wrap). (B.2)
    [Throws=VaultError]
    void remove_device_slot(bytes folder_path, bytes device_uuid);
```

`VaultError` interface — add the 3 variants (match `errors/vault.rs`):

```
    DeviceSlotNotFound();
    WrongDeviceSecretOrCorrupt();
    DeviceUuidMismatch(string detail);
```

New interface + dictionary (near `MnemonicOutput` / `CreateVaultOutput`):

```
/// One-shot opaque handle for an enrolled device's 32-byte secret. take_secret()
/// returns the bytes once then null; wipe() idempotent. Same close→wipe rename
/// rationale as MnemonicOutput.
interface DeviceSecretOutput {
    sequence<u8>? take_secret();
    void wipe();
};

/// Output of add_device_slot: the 16-byte device UUID (non-secret) + a one-shot
/// secret handle.
dictionary DeviceEnrollOutput {
    bytes device_uuid;
    DeviceSecretOutput device_secret;
};
```

- [ ] **Step 5: Run to verify it passes (build + wrapper test)**

Run: `cargo test --release -p secretary-ffi-uniffi device_secret_output_is_one_shot -- --nocapture`
Expected: PASS. The UDL scaffolding must also compile (uniffi build.rs runs); if the UDL has a typo the crate fails to build.

- [ ] **Step 6: Clippy + commit**

Run: `cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings`

```bash
git add ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/wrappers/device.rs ffi/secretary-ffi-uniffi/src/wrappers/mod.rs ffi/secretary-ffi-uniffi/src/namespace/mod.rs
git commit -m "feat(uniffi): add_device_slot/open_with_device_secret/remove_device_slot + DeviceSecretOutput (B.2)"
```

---

## Task 6: pyo3 — exception classes + translator arms

**Files:**
- Modify: `ffi/secretary-ffi-py/src/errors.rs`, `ffi/secretary-ffi-py/src/lib.rs`

- [ ] **Step 1: Add the three exception classes**

In `ffi/secretary-ffi-py/src/errors.rs`, next to the other `Vault*` classes:

```rust
create_exception!(secretary_ffi_py, VaultDeviceSlotNotFound, PyException);
create_exception!(secretary_ffi_py, VaultWrongDeviceSecretOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultDeviceUuidMismatch, PyException);
```

In `ffi_vault_error_to_pyerr`, add the three arms (the match is exhaustive — the compiler will demand them once Task 2's bridge variants exist):

```rust
        FfiVaultError::DeviceSlotNotFound => VaultDeviceSlotNotFound::new_err(e.to_string()),
        FfiVaultError::WrongDeviceSecretOrCorrupt => {
            VaultWrongDeviceSecretOrCorrupt::new_err(e.to_string())
        }
        FfiVaultError::DeviceUuidMismatch { detail } => VaultDeviceUuidMismatch::new_err(detail),
```

- [ ] **Step 2: Register in lib.rs**

In `ffi/secretary-ffi-py/src/lib.rs`, add to the `use errors::{…}` import and the module registration block:

```rust
    m.add("VaultDeviceSlotNotFound", py.get_type::<VaultDeviceSlotNotFound>())?;
    m.add("VaultWrongDeviceSecretOrCorrupt", py.get_type::<VaultWrongDeviceSecretOrCorrupt>())?;
    m.add("VaultDeviceUuidMismatch", py.get_type::<VaultDeviceUuidMismatch>())?;
```

- [ ] **Step 3: Run to verify it builds**

Run: `cargo build --release -p secretary-ffi-py`
Expected: compiles (the exhaustive `ffi_vault_error_to_pyerr` match now covers the new bridge variants).

- [ ] **Step 4: Clippy + commit**

Run: `cargo clippy --release -p secretary-ffi-py --tests -- -D warnings`

```bash
git add ffi/secretary-ffi-py/src/errors.rs ffi/secretary-ffi-py/src/lib.rs
git commit -m "feat(pyo3): device-slot exception classes + translator arms (B.2)"
```

---

## Task 7: pyo3 — `device.rs` pyfunctions + handles + pytest

**Files:**
- Create: `ffi/secretary-ffi-py/src/device.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs`
- Create: `ffi/secretary-ffi-py/tests/test_device_slot.py`

- [ ] **Step 1: Write the failing pytest**

Create `ffi/secretary-ffi-py/tests/test_device_slot.py`. Follow the existing pyo3 test conventions (look at `tests/` for the maturin/`uv` setup + how the golden fixture is copied to a tempdir — reuse the existing fixture-copy helper if one exists). Load the pinned password/uuid/secret from `golden_vault_001_inputs.json`.

```python
import json
import shutil
from pathlib import Path

import secretary_ffi_py as sec
import pytest

DATA = Path(__file__).resolve().parents[3] / "core" / "tests" / "data"
INPUTS = json.loads((DATA / "golden_vault_001_inputs.json").read_text())


def _temp_vault(tmp_path: Path) -> Path:
    dst = tmp_path / "vault"
    shutil.copytree(DATA / "golden_vault_001", dst)
    return dst


def test_enroll_then_open_round_trip(tmp_path):
    vault = _temp_vault(tmp_path)
    pw = INPUTS["password"].encode()
    out = sec.add_device_slot(str(vault).encode(), bytearray(pw))
    assert len(out.device_uuid) == 16
    with out.device_secret as ds:
        secret = ds.take_secret()
        assert secret is not None and len(secret) == 32
        assert ds.take_secret() is None  # one-shot
    opened = sec.open_with_device_secret(
        str(vault).encode(), out.device_uuid, bytes(secret)
    )
    assert len(opened.identity.user_uuid) == 16


def test_open_absent_slot_raises_device_slot_not_found(tmp_path):
    vault = _temp_vault(tmp_path)
    with pytest.raises(sec.VaultDeviceSlotNotFound):
        sec.open_with_device_secret(str(vault).encode(), bytes(16), bytes(32))


def test_open_wrong_length_secret_raises_value_error(tmp_path):
    vault = _temp_vault(tmp_path)
    with pytest.raises(ValueError):
        sec.open_with_device_secret(str(vault).encode(), bytes(16), bytes(31))


def test_remove_twice_raises_device_slot_not_found(tmp_path):
    vault = _temp_vault(tmp_path)
    out = sec.add_device_slot(str(vault).encode(), bytearray(INPUTS["password"].encode()))
    out.device_secret.close()
    sec.remove_device_slot(str(vault).encode(), out.device_uuid)
    with pytest.raises(sec.VaultDeviceSlotNotFound):
        sec.remove_device_slot(str(vault).encode(), out.device_uuid)
```

- [ ] **Step 2: Run to verify it fails**

Build + run (mirror the project's pyo3 test invocation; if a stale `.so` is suspected, nuke the venv + uv cache per the maturin/uv note):

Run:
```bash
cd ffi/secretary-ffi-py && maturin develop --release && uv run --with pytest pytest tests/test_device_slot.py -v
```
Expected: FAIL — `add_device_slot` / `open_with_device_secret` / `remove_device_slot` not in module.

- [ ] **Step 3: Implement `device.rs`**

Create `ffi/secretary-ffi-py/src/device.rs` (mirror `unlock.rs`'s `MnemonicOutput` + zeroize discipline + the `OpenVaultOutput` wrapping used by `open_vault_with_password` in pyo3):

```rust
//! pyo3 device-slot ops (ADR 0009 / B.2): add / open / remove + one-shot
//! DeviceSecretOutput handle.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use zeroize::Zeroize;

use crate::errors::ffi_vault_error_to_pyerr;
use crate::vault::OpenVaultOutput; // confirm the pyo3 OpenVaultOutput path

#[pyclass]
pub struct DeviceSecretOutput(pub(crate) secretary_ffi_bridge::DeviceSecretOutput);

#[pymethods]
impl DeviceSecretOutput {
    /// Take the 32-byte secret as `bytes`. ONE-SHOT — second call → None.
    /// Caller MUST zeroize the returned bytes after use.
    fn take_secret<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.take_secret().map(|v| PyBytes::new(py, &v))
    }
    fn close(&self) {
        self.0.wipe();
    }
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }
    fn __exit__(
        &self,
        _t: Option<&Bound<'_, PyType>>,
        _v: Option<&Bound<'_, PyAny>>,
        _tb: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.0.wipe();
        false
    }
}

#[pyclass]
pub struct DeviceEnrollOutput {
    device_uuid: Vec<u8>,
    device_secret: Option<DeviceSecretOutput>,
}

#[pymethods]
impl DeviceEnrollOutput {
    #[getter]
    fn device_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.device_uuid)
    }
    /// One-shot take of the secret handle (same destructive-getter pattern as
    /// CreateVaultOutput.mnemonic).
    #[getter]
    fn device_secret(&mut self) -> PyResult<DeviceSecretOutput> {
        self.device_secret.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "DeviceEnrollOutput.device_secret already taken (one-shot)",
            )
        })
    }
}

#[pyfunction]
pub(crate) fn add_device_slot(
    folder_path: &[u8],
    mut password: Vec<u8>,
) -> PyResult<DeviceEnrollOutput> {
    let folder = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path is not valid UTF-8"))?;
    let result = secretary_ffi_bridge::add_device_slot(std::path::Path::new(folder), &password)
        .map(|o| DeviceEnrollOutput {
            device_uuid: o.device_uuid,
            device_secret: Some(DeviceSecretOutput(o.device_secret)),
        })
        .map_err(ffi_vault_error_to_pyerr);
    password.zeroize();
    result
}

#[pyfunction]
pub(crate) fn open_with_device_secret(
    folder_path: &[u8],
    device_uuid: &[u8],
    mut device_secret: Vec<u8>,
) -> PyResult<OpenVaultOutput> {
    if device_uuid.len() != 16 {
        device_secret.zeroize();
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_uuid must be 16 bytes, got {}",
            device_uuid.len()
        )));
    }
    if device_secret.len() != 32 {
        let got = device_secret.len();
        device_secret.zeroize();
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_secret must be 32 bytes, got {got}"
        )));
    }
    let folder = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path is not valid UTF-8"))?;
    let uuid: [u8; 16] = device_uuid.try_into().expect("len checked");
    let mut secret_arr: [u8; 32] = device_secret.as_slice().try_into().expect("len checked");
    let result =
        secretary_ffi_bridge::open_with_device_secret(std::path::Path::new(folder), &uuid, &secret_arr)
            .map(OpenVaultOutput::from) // match the existing pyo3 OpenVaultOutput wrapping
            .map_err(ffi_vault_error_to_pyerr);
    secret_arr.zeroize();
    device_secret.zeroize();
    result
}

#[pyfunction]
pub(crate) fn remove_device_slot(folder_path: &[u8], device_uuid: &[u8]) -> PyResult<()> {
    if device_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "device_uuid must be 16 bytes, got {}",
            device_uuid.len()
        )));
    }
    let folder = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path is not valid UTF-8"))?;
    let uuid: [u8; 16] = device_uuid.try_into().expect("len checked");
    secretary_ffi_bridge::remove_device_slot(std::path::Path::new(folder), &uuid)
        .map_err(ffi_vault_error_to_pyerr)
}
```

> `OpenVaultOutput::from` / the exact wrapping — read the pyo3 `open_vault_with_password` pyfunction and copy how it converts `secretary_ffi_bridge::vault::OpenVaultOutput` into the pyo3 `OpenVaultOutput`. Use the identical idiom; do not invent a new conversion.

- [ ] **Step 4: Register in lib.rs**

`pub mod device;` + in the module init:

```rust
    m.add_class::<device::DeviceSecretOutput>()?;
    m.add_class::<device::DeviceEnrollOutput>()?;
    m.add_function(wrap_pyfunction!(device::add_device_slot, m)?)?;
    m.add_function(wrap_pyfunction!(device::open_with_device_secret, m)?)?;
    m.add_function(wrap_pyfunction!(device::remove_device_slot, m)?)?;
```

- [ ] **Step 5: Run to verify it passes**

Run:
```bash
cd ffi/secretary-ffi-py && maturin develop --release && uv run --with pytest pytest tests/test_device_slot.py -v
```
Expected: PASS (4 tests). If pytest sees a stale `.so`, nuke `.venv` + `~/.cache/uv` and rerun.

- [ ] **Step 6: Clippy + commit**

Run: `cargo clippy --release -p secretary-ffi-py --tests -- -D warnings`

```bash
git add ffi/secretary-ffi-py/src/device.rs ffi/secretary-ffi-py/src/lib.rs ffi/secretary-ffi-py/tests/test_device_slot.py
git commit -m "feat(pyo3): device-slot ops + one-shot DeviceSecretOutput + pytest (B.2)"
```

---

## Task 8: Conformance — Rust dispatch + KAT vectors

**Files:**
- Modify: `core/tests/conformance_kat_helpers/types.rs` (`Operation`)
- Modify: `core/tests/conformance_kat_helpers/dispatch/open.rs`, `core/tests/conformance_kat_helpers/fixtures.rs`
- Modify: `core/tests/conformance_kat.rs`
- Modify: `core/tests/data/conformance_kat.json`

- [ ] **Step 1: Add the Operation variant + dispatch fn**

In `types.rs`, add to `enum Operation`:

```rust
    OpenWithDeviceSecret,
```

In `dispatch/open.rs`, add a runner mirroring `run_open_password` but resolving device inputs and calling `bridge::device::open_with_device_secret`:

```rust
pub fn run_open_device_secret(
    vault_dir: &std::path::Path,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError> {
    secretary_ffi_bridge::device::open_with_device_secret(vault_dir, device_uuid, device_secret)
}
```

In `fixtures.rs`, add resolution for `device_uuid_source` / `device_secret_source` inputs (hex from `golden_vault_001_inputs.json:device_slot_uuid_hex` / `:device_slot_secret_hex`). Follow the existing `resolve_source` hex/utf8 conventions. Add a `resolve_device_uuid`/`resolve_device_secret` returning fixed arrays, and the synthetic-length path: if a vector's `device_secret` resolves to ≠32 bytes, return `BridgeOrSyntheticErr::Synthetic { variant: "InvalidArgument", … }` rather than calling the bridge (mirror the block_uuid synthetic precedent).

- [ ] **Step 2: Add the dispatch arm in `conformance_kat.rs`**

In the `match (&vector.operation, &vector.after)` loop, add:

```rust
            (Operation::OpenWithDeviceSecret, None) => {
                let result = /* resolve uuid+secret; short secret → synthetic InvalidArgument */;
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => assert_open_ok(label, &out, payload),
                    (Expected::Err { .. }, Err(e)) => {
                        assert_err(label, &vector.expected, variant_name_vault(&e), vault_error_detail(&e))
                    }
                    (Expected::Ok(_), Err(e)) => panic!("{label}: expected Ok, got Err {e:?}"),
                    (Expected::Err { .. }, Ok(_)) => panic!("{label}: expected Err, got Ok"),
                }
            }
```

> Match the exact helper names + the synthetic-error handling the `ReadBlock` arm uses for wrong-length `block_uuid` (`read_block_err_variant`/`read_block_err_detail` + `BridgeOrSyntheticErr`). Reuse them or add device equivalents in `errors.rs` consistent with that pattern.

- [ ] **Step 3: Add the vectors to `conformance_kat.json`**

Add five vectors to the `vectors` array (inputs reference the golden fixture + pinned inputs). The happy vector's `expected` mirrors `open_password_happy` (`display_name: "Owner"`, `block_uuid_hex: "112233445566778899aabbccddeeff00"` — copy the exact values from the existing `open_password_happy` vector):

```json
{
  "name": "open_device_secret_happy",
  "description": "open_with_device_secret against golden_vault_001 using the pinned device slot from golden_vault_001_inputs.json.",
  "operation": "open_with_device_secret",
  "inputs": {
    "vault_dir": "golden_vault_001",
    "device_uuid_source": "golden_vault_001_inputs.json:device_slot_uuid_hex",
    "device_secret_source": "golden_vault_001_inputs.json:device_slot_secret_hex"
  },
  "expected": { "kind": "ok", "display_name": "Owner", "block_count": 1, "block_uuid_hex": "112233445566778899aabbccddeeff00" }
},
{
  "name": "open_device_secret_wrong_secret",
  "description": "Wrong (but 32-byte) device secret → WrongDeviceSecretOrCorrupt.",
  "operation": "open_with_device_secret",
  "inputs": { "vault_dir": "golden_vault_001", "device_uuid_source": "golden_vault_001_inputs.json:device_slot_uuid_hex", "device_secret_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
  "expected": { "kind": "err", "variant": "WrongDeviceSecretOrCorrupt" }
},
{
  "name": "open_device_secret_uuid_mismatch",
  "description": "Looking up the wrap by a different device_uuid than its header → DeviceUuidMismatch.",
  "operation": "open_with_device_secret",
  "inputs": { "vault_dir": "golden_vault_001", "device_uuid_hex": "99999999999999999999999999999999", "device_secret_source": "golden_vault_001_inputs.json:device_slot_secret_hex" },
  "expected": { "kind": "err", "variant": "DeviceSlotNotFound" }
},
{
  "name": "open_device_secret_short_secret",
  "description": "31-byte device secret → InvalidArgument (binding-layer length pre-check / synthetic).",
  "operation": "open_with_device_secret",
  "inputs": { "vault_dir": "golden_vault_001", "device_uuid_source": "golden_vault_001_inputs.json:device_slot_uuid_hex", "device_secret_hex": "00010203040506070809101112131415161718192021222324252627282930" },
  "expected": { "kind": "err", "variant": "InvalidArgument" }
}
```

> IMPORTANT — DeviceUuidMismatch vs DeviceSlotNotFound: looking up a *non-existent* device_uuid returns `DeviceSlotNotFound` (no wrap file at that name). To exercise `DeviceUuidMismatch` you need a wrap file whose *header* disagrees with its *filename* — that requires a purpose-built fixture (a renamed copy of the golden wrap). DECISION for this plan: cover `DeviceUuidMismatch` in the Rust **bridge unit test** (Task 3, where a tampered file is cheap to build) and the `conformance.py` clean-room, and have the conformance-KAT vector set cover `happy` + `wrong_secret` + `short_secret` + `absent → DeviceSlotNotFound`. Do NOT ship a relabeled-wrap fixture into `golden_vault_001/` (it would pollute the frozen golden vault). If a cross-language DeviceUuidMismatch replay is wanted, add a *separate* tiny fixture dir under `core/tests/data/` in a follow-up — out of scope here. Adjust the JSON above accordingly (drop the `uuid_mismatch` vector; keep four).

- [ ] **Step 4: Regenerate + verify the Rust replay**

The happy vector's expected fields must match reality. Regenerate if the generator supports the new op; otherwise hand-author and verify by running:

Run: `cargo test --release --workspace --test conformance_kat -- --nocapture`
Expected: PASS — `replay_conformance_kat` replays the new vectors green.

- [ ] **Step 5: Clippy + commit**

Run: `cargo clippy --release --workspace --tests -- -D warnings`

```bash
git add core/tests/conformance_kat_helpers/ core/tests/conformance_kat.rs core/tests/data/conformance_kat.json
git commit -m "test(conformance): OpenWithDeviceSecret KAT vectors + Rust replay (B.2)"
```

---

## Task 9: Conformance — Swift + Kotlin runners + ConformanceErrors

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`, the Swift conformance runner, + `tests/kotlin/ConformanceErrors.kt`, the Kotlin runner.

- [ ] **Step 1: Add the 3 variant cases to the error harnesses**

`ConformanceErrors.swift` — `vaultErrorName(_:)` switch:

```swift
    case .DeviceSlotNotFound: return "DeviceSlotNotFound"
    case .WrongDeviceSecretOrCorrupt: return "WrongDeviceSecretOrCorrupt"
    case .DeviceUuidMismatch: return "DeviceUuidMismatch"
```

…and in `vaultErrorDetail(_:)`: `case .DeviceUuidMismatch(let d): return d`.

`ConformanceErrors.kt` — `vaultExceptionVariantName`:

```kotlin
    is VaultException.DeviceSlotNotFound -> "DeviceSlotNotFound"
    is VaultException.WrongDeviceSecretOrCorrupt -> "WrongDeviceSecretOrCorrupt"
    is VaultException.DeviceUuidMismatch -> "DeviceUuidMismatch"
```

…and `vaultExceptionDetail`: `is VaultException.DeviceUuidMismatch -> e.detail`; add the two no-detail variants to the `-> null` group.

- [ ] **Step 2: Add the `open_with_device_secret` dispatch arm to both runners**

In the Swift + Kotlin conformance replay dispatch (the `switch`/`when` on `operation`), add an `open_with_device_secret` case that resolves `device_uuid`/`device_secret` from inputs (hex), does the 32-byte length pre-check (short → synthesize `"InvalidArgument"`), calls the binding `openWithDeviceSecret(folderPath:deviceUuid:deviceSecret:)`, and asserts ok/err like the `open_vault_with_password` arm.

- [ ] **Step 3: Add the enrol round-trip assertion to both runners**

A standalone assertion (not a JSON vector): copy `golden_vault_001` to a temp dir, call `addDeviceSlot(folderPath:password:)`, `takeSecret()` from the handle (assert non-nil + 32 bytes + second call nil), then `openWithDeviceSecret` with the returned uuid+secret and assert `display_name == "Owner"`. Mirror the `open_vault_with_password_writable` temp-copy idiom already used in the runners (or `SmokeFolderIn`).

- [ ] **Step 4: Run both conformance scripts**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: both green; assertion counts increase (was 22/22 → higher).

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift ffi/secretary-ffi-uniffi/tests/kotlin
git commit -m "test(conformance): Swift+Kotlin device-secret dispatch + enrol round-trip + error variants (B.2)"
```

---

## Task 10: Conformance — `conformance.py` clean-room

**Files:**
- Modify: `core/tests/python/conformance.py`

- [ ] **Step 1: Add the clean-room device-slot replay**

`conformance.py` already has `verify_device_slot` (B.1) which derives `device_kek`, unwraps the IBK, and cross-checks it. Add a function that exercises the B.2 *operations*' observable contract clean-room:
- **open**: re-use `verify_device_slot` against `golden_vault_001/devices/d0d0….wrap` with the pinned secret/uuid, asserting the recovered IBK equals the password-path IBK and the §3a header `device_uuid == filename`.
- **enrol round-trip (stdlib)**: derive a fresh device_kek from a test secret, wrap the password-recovered IBK into an in-memory wrap-file byte layout per vault-format §3a, decode it back, unwrap, and assert IBK parity — proving the §3a encode/decode + §5a KEK derivation are spec-implementable for the enrol direction too.

Call it from the script's `main()` alongside the existing B.1 device check; print `device-slot B.2 ops: OK`.

- [ ] **Step 2: Run**

Run: `uv run core/tests/python/conformance.py`
Expected: PASS, including the new B.2 line.

- [ ] **Step 3: Spec-freshness + commit**

Run: `uv run core/tests/python/spec_test_name_freshness.py`
Expected: PASS (if it flags a new citation, add the test-name reference or allowlist entry per its guidance).

```bash
git add core/tests/python/conformance.py
git commit -m "test(conformance): clean-room device-slot B.2 ops (open + enrol round-trip) (B.2)"
```

---

## Task 11: Smoke parity (uniffi Swift/Kotlin) + full gauntlet

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/SmokeFolderIn.swift` (+ Kotlin equivalent)

- [ ] **Step 1: Add a device-slot smoke block**

Mirror the existing `SmokeFolderIn` asserts: temp-copy the golden vault, `addDeviceSlot`, `openWithDeviceSecret`, `removeDeviceSlot`, and assert the post-remove open throws `DeviceSlotNotFound`. Keep it brief (a handful of asserts), consistent with the existing smoke style.

- [ ] **Step 2: Run the full gauntlet**

Run each, expect the stated result:
```bash
cargo clippy --release --workspace --tests -- -D warnings        # clean
cargo test --release --workspace                                 # 0 failed
uv run core/tests/python/conformance.py                          # PASS (B.2 line)
uv run core/tests/python/spec_test_name_freshness.py             # PASS
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh     # green
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh    # green
cd ffi/secretary-ffi-py && maturin develop --release && uv run --with pytest pytest -q   # pass
```

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests
git commit -m "test(smoke): Swift+Kotlin device-slot folder-op smoke (B.2)"
```

---

## Task 12: Docs + handoff

**Files:**
- Modify: `README.md`, `ROADMAP.md`, `CLAUDE.md`
- Create: `docs/handoffs/2026-06-10-b2-device-slot-ffi-shipped.md`; retarget `NEXT_SESSION.md`

- [ ] **Step 1: README + ROADMAP + CLAUDE.md**

- README: bump the status row (B.2 ✅ device-slot FFI projection).
- ROADMAP: mark B.2 done; note B.3 (#202) next.
- CLAUDE.md: add a bullet under crypto-layering / FFI that the device slot is FFI-projected as folder-in ops on `FfiVaultError`; note the new `Unlocker::DeviceSecret` core arm. Update the "Commands" conformance line if assertion counts are cited.

- [ ] **Step 2: Handoff doc + symlink**

Author `docs/handoffs/2026-06-10-b2-device-slot-ffi-shipped.md` (shipped SHAs, what's next = B.3/#202 with acceptance, open risks, resume commands), then:

```bash
ln -snf docs/handoffs/2026-06-10-b2-device-slot-ffi-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

- [ ] **Step 3: Final gauntlet re-run + commit + PR**

Re-run the full gauntlet (Task 11 Step 2). Then commit docs+handoff and open the PR.

```bash
git add README.md ROADMAP.md CLAUDE.md docs/handoffs/2026-06-10-b2-device-slot-ffi-shipped.md NEXT_SESSION.md
git commit -m "docs: B.2 device-slot FFI projection — README/ROADMAP/CLAUDE + handoff (B.2)"
git push -u origin feature/b2-device-slot-ffi
gh pr create --fill --base main
```

---

## Self-Review notes (for the executor)

- **Spec coverage:** Task 1 = §3 core arm; Task 2 = §4 error promotion; Task 3 = §2 ops + handle; Tasks 4–5 = uniffi §5; Tasks 6–7 = pyo3 §5; Tasks 8–10 = §6 conformance; Task 11 = §7 smoke + gauntlet; Task 12 = docs. The `DeviceUuidMismatch` cross-language KAT vector is intentionally descoped to unit + clean-room coverage (Task 8 Step 3 note) to avoid polluting the frozen golden vault — this is the one place the plan narrows §6's "4 error vectors" to 3 KAT vectors + unit/clean-room for the 4th; flagged here so it is a deliberate, logged narrowing (not silent).
- **Type consistency:** bridge `DeviceSecretOutput.take_secret()/wipe()`; uniffi forwards the same; pyo3 uses `take_secret()/close()` + CM (the pyo3 handle convention). `DeviceEnrollOutput { device_uuid: Vec<u8>, device_secret }` everywhere. Bridge ops take `&[u8;16]`/`&[u8;32]`; bindings take `Vec<u8>` + length-check.
- **Verify-before-write:** every "confirm the existing pattern" note (split_core_open_vault visibility, OpenVaultOutput wrapping idiom, SecretBytes::from impl, OsRng import path, fixture-copy helpers) must be checked against the real code before writing — do not assume.
