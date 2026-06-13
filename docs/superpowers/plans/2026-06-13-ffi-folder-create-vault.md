# FFI folder-writing `create_vault` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose a folder-writing `create_vault_in_folder` through the FFI bridge → uniffi + pyo3 so a client can create a complete, browsable vault (all four canonical files), delegating to the already-tested `core::vault::create_vault`.

**Architecture:** Purely additive FFI surface. A new bridge function delegates to `secretary_core::vault::create_vault` (which atomically writes `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, `contacts/<owner-uuid>.card`) and returns the one-shot recovery `MnemonicOutput`. A new typed `FfiVaultError::VaultFolderNotEmpty` distinguishes "you picked a non-empty folder" from a wrong path or data corruption. No `core` change, no on-disk-format / frozen-spec change.

**Tech Stack:** Rust (stable), `secretary-ffi-bridge` (thiserror), `secretary-ffi-uniffi` (uniffi 0.31, UDL), `secretary-ffi-py` (PyO3), Swift + Kotlin conformance/smoke harnesses, `uv` for pytest.

**Spec:** `docs/superpowers/specs/2026-06-13-ffi-folder-create-vault-design.md` (committed `d511cc5`).

**Worktree:** `/Users/hherb/src/secretary/.worktrees/ffi-folder-create-vault`, branch `feature/ffi-folder-create-vault`.

> **Working-directory discipline:** every `cargo` / `git` / `uv` command below assumes you are inside the worktree. Prefix with `cd /Users/hherb/src/secretary/.worktrees/ffi-folder-create-vault &&` or chain in one call — shell state does NOT persist between tool calls.

---

## Why Task 1 is one atomic commit

`FfiVaultError` is matched **exhaustively (no wildcard)** in four Rust sites across three crates: the bridge `From<VaultError>`, the uniffi `From<FfiVaultError> for VaultError`, the pyo3 `ffi_vault_error_to_pyerr`, and the core conformance helper `variant_name_vault`. Adding a variant breaks `cargo build` everywhere at once until all four are updated. Task 1 therefore adds the variant **and** threads it through every Rust match in a single commit so the workspace stays green. The two `cargo`-invisible Swift/Kotlin harnesses are updated in Task 5.

---

### Task 1: Add the `VaultFolderNotEmpty` error variant end-to-end (Rust)

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (variant + mapping arm)
- Test: `ffi/secretary-ffi-bridge/src/error/vault/tests.rs` (mapping test)
- Modify: `ffi/secretary-ffi-uniffi/src/errors/vault.rs` (enum + From arm + test)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (UDL enum)
- Modify: `ffi/secretary-ffi-py/src/errors.rs` (exception class + map arm)
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (import + module registration)
- Modify: `core/tests/conformance_kat_helpers/errors.rs` (`variant_name_vault` arm)

- [ ] **Step 1: Write the failing bridge mapping test**

In `ffi/secretary-ffi-bridge/src/error/vault/tests.rs`, add (the file already imports `VaultError` and `FfiVaultError` — see the existing `VaultError::Io` test near line 55):

```rust
#[test]
fn io_already_exists_maps_to_vault_folder_not_empty() {
    // ensure_empty_directory surfaces a non-empty target as
    // Io { ErrorKind::AlreadyExists }; it must route to the dedicated
    // typed variant, NOT fold to CorruptVault.
    let core_err = VaultError::Io {
        context: "vault folder is not empty",
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "expected an empty directory",
        ),
    };
    let ffi = FfiVaultError::from(core_err);
    assert!(
        matches!(ffi, FfiVaultError::VaultFolderNotEmpty),
        "Io{{AlreadyExists}} must map to VaultFolderNotEmpty, got {ffi:?}",
    );
}
```

- [ ] **Step 2: Run it — expect a COMPILE error**

Run: `cargo test --release -p secretary-ffi-bridge io_already_exists_maps_to_vault_folder_not_empty`
Expected: FAIL to compile — `no variant named VaultFolderNotEmpty found for enum FfiVaultError`.

- [ ] **Step 3: Add the bridge variant**

In `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, append after the last variant (`DeviceUuidMismatch { detail: String }`, just before the closing `}` of `pub enum FfiVaultError`):

```rust
    /// The `create_vault_in_folder` target directory already contains
    /// entries. `core::vault::create_vault` requires an empty directory
    /// (it refuses to clobber an unrelated folder), so a non-empty target
    /// surfaces as `core::VaultError::Io { ErrorKind::AlreadyExists }`.
    /// This dedicated variant keeps that caller-actionable condition
    /// ("pick an empty folder or make a subfolder") distinct from a wrong
    /// or unreadable path (`FolderInvalid`) and from data corruption
    /// (`CorruptVault`). No payload — the name is the whole story and the
    /// folder is the caller's own input.
    #[error("vault folder is not empty")]
    VaultFolderNotEmpty,
```

- [ ] **Step 4: Add the bridge mapping arm**

In the same file, inside `impl From<VaultError> for FfiVaultError`'s `match e`, insert this arm immediately **after** the existing `VE::Io { .. } if matches!(source.kind(), NotFound | PermissionDenied) => FolderInvalid` arm and **before** the explicit `e @ (VE::Io { .. } | ...)` catch-all:

```rust
            // Folder-create precondition: the target directory already
            // contains entries. `ensure_empty_directory` surfaces this as
            // Io { AlreadyExists }; route it to the dedicated typed variant
            // so `create_vault_in_folder` callers can tell "not empty"
            // apart from a wrong path (`FolderInvalid`) and from corruption
            // (`CorruptVault`). Must precede the generic Io catch-all below.
            VE::Io { source, .. }
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                FfiVaultError::VaultFolderNotEmpty
            }
```

- [ ] **Step 5: Thread through the uniffi enum + From impl**

In `ffi/secretary-ffi-uniffi/src/errors/vault.rs`, append to `pub enum VaultError` (after the last variant `DeviceUuidMismatch { detail: String }`):

```rust
    /// Create-in-folder target directory already contains entries.
    /// Mirrors `FfiVaultError::VaultFolderNotEmpty`.
    #[error("vault folder is not empty")]
    VaultFolderNotEmpty,
```

In the same file, add to `impl From<FfiVaultError> for VaultError`'s match (after the `DeviceUuidMismatch` arm):

```rust
            FfiVaultError::VaultFolderNotEmpty => VaultError::VaultFolderNotEmpty,
```

And add an assertion to the existing `vault_error_maps_each_variant_one_to_one` test (after the last `assert!`):

```rust
        assert!(matches!(
            VaultError::from(B::VaultFolderNotEmpty),
            VaultError::VaultFolderNotEmpty
        ));
```

- [ ] **Step 6: Thread through the uniffi UDL**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside `[Error] interface VaultError { ... }`, add after `DeviceUuidMismatch(string detail);`:

```
    VaultFolderNotEmpty();
```

- [ ] **Step 7: Thread through the pyo3 exception class + mapper**

In `ffi/secretary-ffi-py/src/errors.rs`, add the exception class after `create_exception!(secretary_ffi_py, VaultDeviceUuidMismatch, PyException);`:

```rust
// Folder-create precondition — target directory not empty. Mirrors the
// bridge's FfiVaultError::VaultFolderNotEmpty.
create_exception!(secretary_ffi_py, VaultFolderNotEmpty, PyException);
```

In the same file, add to `ffi_vault_error_to_pyerr`'s match (after the `DeviceUuidMismatch` arm, before the closing `}`):

```rust
        FfiVaultError::VaultFolderNotEmpty => VaultFolderNotEmpty::new_err(e.to_string()),
```

- [ ] **Step 8: Register the pyo3 exception in the module**

In `ffi/secretary-ffi-py/src/lib.rs`, add `VaultFolderNotEmpty` to the `use errors::{ ... };` import list (alphabetically near `VaultFolderInvalid`), and register it in the module body alongside the other vault exception registrations (e.g. right after the `m.add("VaultFolderInvalid", ...)` line near line 176):

```rust
    m.add("VaultFolderNotEmpty", py.get_type::<VaultFolderNotEmpty>())?;
```

- [ ] **Step 9: Thread through the core conformance helper**

In `core/tests/conformance_kat_helpers/errors.rs`, add to `variant_name_vault`'s match (after the `DeviceUuidMismatch` arm — this match is exhaustive with no wildcard):

```rust
        E::VaultFolderNotEmpty => "VaultFolderNotEmpty",
```

(No change to `vault_error_detail` — it has a `_ => None` catch-all and `VaultFolderNotEmpty` carries no detail.)

- [ ] **Step 10: Build + test the workspace green**

Run: `cargo test --release --workspace`
Expected: PASS, including `io_already_exists_maps_to_vault_folder_not_empty` and `vault_error_maps_each_variant_one_to_one`.

- [ ] **Step 11: Lint**

Run: `cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean, no warnings.

- [ ] **Step 12: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/error/ ffi/secretary-ffi-uniffi/src/errors/vault.rs ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-py/src/errors.rs ffi/secretary-ffi-py/src/lib.rs core/tests/conformance_kat_helpers/errors.rs
git commit -m "feat(ffi): add typed VaultFolderNotEmpty error variant

Threads a new FfiVaultError::VaultFolderNotEmpty through every Rust
exhaustive match (bridge mapping, uniffi enum+From, pyo3 exception+mapper,
core conformance variant_name_vault) and the uniffi UDL. Io{AlreadyExists}
from ensure_empty_directory now routes here instead of folding to the
misleading CorruptVault. Swift/Kotlin conformance harnesses updated in a
later task.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Bridge `create_vault_in_folder`

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/create.rs` (function + imports)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (re-export)
- Test: `ffi/secretary-ffi-bridge/src/create.rs` (tests module)

- [ ] **Step 1: Write the failing round-trip test**

In `ffi/secretary-ffi-bridge/src/create.rs`, inside `mod tests`, add:

```rust
    #[test]
    fn create_vault_in_folder_writes_complete_openable_vault() {
        // Real Argon2idParams::V1_DEFAULT. Proves the folder-writing path
        // produces ALL FOUR canonical files (not just the 2 identity-level
        // byte artifacts the bytes-based create_vault returns) — the
        // folder-based open_vault_with_password validates the manifest
        // signature + owner card, so a successful open IS the proof the
        // manifest + contacts/<uuid>.card were written and are valid.
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = dir.path();

        let out = create_vault_in_folder(folder, b"hunter2", "Folder-Bob", 1_700_000_000_000)
            .expect("create_vault_in_folder should succeed");

        assert!(folder.join("vault.toml").is_file(), "vault.toml missing");
        assert!(
            folder.join("identity.bundle.enc").is_file(),
            "identity.bundle.enc missing",
        );
        assert!(
            folder.join("manifest.cbor.enc").is_file(),
            "manifest.cbor.enc missing",
        );
        assert!(folder.join("contacts").is_dir(), "contacts/ missing");

        // Folder-based password open must succeed → the vault is browsable.
        let opened = crate::open_vault_with_password(folder, b"hunter2")
            .expect("folder open with the same password must succeed");
        assert_eq!(opened.identity.display_name(), "Folder-Bob");

        // The returned mnemonic opens the same vault via the recovery path.
        let phrase = out.take_phrase().expect("phrase must be available");
        let opened2 = crate::open_vault_with_recovery(folder, &phrase)
            .expect("folder open with the just-taken phrase must succeed");
        assert_eq!(opened2.identity.display_name(), "Folder-Bob");
    }

    #[test]
    fn create_vault_in_folder_rejects_nonempty_folder() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("junk"), b"x").expect("seed junk file");
        let err = create_vault_in_folder(dir.path(), b"pw", "X", 1_700_000_000_000)
            .expect_err("non-empty folder must error");
        assert!(
            matches!(err, FfiVaultError::VaultFolderNotEmpty),
            "non-empty folder must surface VaultFolderNotEmpty, got {err:?}",
        );
    }

    #[test]
    fn create_vault_in_folder_rejects_missing_folder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");
        let err = create_vault_in_folder(&missing, b"pw", "X", 1_700_000_000_000)
            .expect_err("missing folder must error");
        assert!(
            matches!(err, FfiVaultError::FolderInvalid { .. }),
            "missing folder must surface FolderInvalid, got {err:?}",
        );
    }
```

- [ ] **Step 2: Run it — expect a COMPILE error**

Run: `cargo test --release -p secretary-ffi-bridge create_vault_in_folder`
Expected: FAIL to compile — `cannot find function create_vault_in_folder`.

- [ ] **Step 3: Add the imports**

At the top of `ffi/secretary-ffi-bridge/src/create.rs`, alongside the existing `use` lines, add:

```rust
use std::path::Path;

use crate::error::FfiVaultError;
```

(`SecretBytes`, `OsRng`, `Argon2idParams`, and `MnemonicOutput` are already in scope.)

- [ ] **Step 4: Add the function**

In `ffi/secretary-ffi-bridge/src/create.rs`, after the existing `create_vault` function (before `#[cfg(test)] mod tests`):

```rust
/// Create a fresh v1 vault **on disk** in `folder`, writing all four
/// canonical files via `core::vault::create_vault`, and return the one-shot
/// recovery mnemonic.
///
/// This is the folder-writing sibling of [`create_vault`]. Where
/// `create_vault` returns identity-level byte artifacts for the caller to
/// persist (and pairs with the bytes-based `open_with_password`), this
/// function produces a **complete, browsable** vault — including
/// `manifest.cbor.enc` and `contacts/<owner-uuid>.card` — that opens through
/// the folder-based [`crate::open_vault_with_password`] /
/// [`crate::open_vault_with_recovery`].
///
/// `folder` MUST already exist as an empty directory; the platform layer
/// owns the mkdir / subfolder decision (mirroring core's
/// `ensure_empty_directory` contract). The function does NOT auto-open the
/// vault — the caller re-opens with the master password to browse, matching
/// the desktop "no auto-open, re-enter password" flow.
///
/// `OsRng` and `Argon2idParams::V1_DEFAULT` are hardcoded — no foreign
/// RNG/KDF knobs, same rationale as [`create_vault`].
///
/// # Errors
///
/// - [`FfiVaultError::VaultFolderNotEmpty`] — `folder` contains entries.
/// - [`FfiVaultError::FolderInvalid`] — `folder` is missing or unreadable.
/// - [`FfiVaultError::CorruptVault`] — rare crypto/serialization failure.
pub fn create_vault_in_folder(
    folder: &Path,
    password: &[u8],
    display_name: &str,
    created_at_ms: u64,
) -> Result<MnemonicOutput, FfiVaultError> {
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
    Ok(MnemonicOutput::new(mnemonic))
}
```

- [ ] **Step 5: Re-export at the bridge crate root**

In `ffi/secretary-ffi-bridge/src/lib.rs`, update the create re-export line:

```rust
pub use create::{create_vault, create_vault_in_folder, CreateVaultOutput, MnemonicOutput};
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --release -p secretary-ffi-bridge create_vault_in_folder`
Expected: PASS — all three tests green.

- [ ] **Step 7: Lint**

Run: `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/create.rs ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(ffi-bridge): folder-writing create_vault_in_folder

Delegates to core::vault::create_vault to write all four canonical files
(vault.toml, identity.bundle.enc, manifest.cbor.enc, contacts/<uuid>.card)
and returns the one-shot recovery MnemonicOutput. Hardcodes OsRng +
V1_DEFAULT; requires an existing empty dir; no auto-open. Round-trip +
not-empty + missing-folder tests.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: uniffi `create_vault_in_folder`

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (namespace declaration)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (wrapper + test)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs` (re-export)

- [ ] **Step 1: Write the failing UTF-8-guard wrapper test**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, inside the tests module, add (mirrors the existing namespace tests that assert `FolderInvalid` on invalid UTF-8 paths — this avoids a slow Argon2id run; the real create round-trip is covered by the bridge test + the Swift/Kotlin smoke):

```rust
    #[test]
    fn create_vault_in_folder_invalid_utf8_path_maps_to_folder_invalid() {
        // 0xFF is not valid UTF-8; the wrapper must reject before touching
        // the bridge / KDF.
        let bad_path = vec![0xFFu8];
        let err = create_vault_in_folder(
            bad_path,
            b"pw".to_vec(),
            "X".to_string(),
            1_700_000_000_000,
        )
        .expect_err("invalid-UTF-8 folder path must error");
        assert!(
            matches!(err, VaultError::FolderInvalid { .. }),
            "invalid UTF-8 path must surface FolderInvalid, got {err:?}",
        );
    }
```

- [ ] **Step 2: Run it — expect a COMPILE error**

Run: `cargo test --release -p secretary-ffi-uniffi create_vault_in_folder_invalid_utf8_path`
Expected: FAIL to compile — `cannot find function create_vault_in_folder`.

- [ ] **Step 3: Add the namespace wrapper**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, after the `create_vault` wrapper (around line 127), add:

```rust
/// Create a fresh v1 vault on disk in an existing empty `folder_path`.
/// uniffi-projected. (iOS create/import Slice 1.)
///
/// `folder_path` is the UTF-8-encoded filesystem path to an existing empty
/// directory. Writes all four canonical files and returns the one-shot
/// recovery mnemonic; the caller re-opens with `open_vault_with_password`
/// to browse (no auto-open). The bridge hardcodes `OsRng` +
/// `Argon2idParams::V1_DEFAULT`.
///
/// # Errors
///
/// Returns [`VaultError`]: `VaultFolderNotEmpty` if the directory contains
/// entries, `FolderInvalid` if the path is missing / unreadable / not
/// valid UTF-8, `CorruptVault` on rare crypto failure.
pub fn create_vault_in_folder(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
    display_name: String,
    created_at_ms: u64,
) -> Result<std::sync::Arc<MnemonicOutput>, VaultError> {
    // Compute the full result chain into a single binding so the password
    // is zeroized BEFORE any `?`-propagation (mirrors open_vault_with_password).
    let result: Result<secretary_ffi_bridge::MnemonicOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::create_vault_in_folder(
                    &path,
                    &password,
                    &display_name,
                    created_at_ms,
                )
                .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    password.zeroize();
    let bridge_mnemonic = result?;
    Ok(std::sync::Arc::new(MnemonicOutput(bridge_mnemonic)))
}
```

> Confirm `MnemonicOutput`, `VaultError`, and `zeroize::Zeroize` are already imported at the top of `namespace/mod.rs` (the existing `create_vault` wrapper constructs `MnemonicOutput` and `open_vault_with_password` calls `password.zeroize()`, so they are). If `MnemonicOutput` is referenced via a path in `create_vault`, match that exact path.

- [ ] **Step 4: Add the UDL declaration**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside `namespace secretary { ... }`, after the `create_vault(...)` declaration (around line 34):

```
    /// Create a fresh v1 vault on disk in an existing empty `folder_path`.
    /// Writes all four canonical files; returns the one-shot recovery
    /// mnemonic. (iOS create/import Slice 1)
    [Throws=VaultError]
    MnemonicOutput create_vault_in_folder(
        bytes folder_path,
        bytes password,
        string display_name,
        u64 created_at_ms
    );
```

- [ ] **Step 5: Re-export from lib.rs**

In `ffi/secretary-ffi-uniffi/src/lib.rs`, add `create_vault_in_folder` to the `pub use namespace::{ ... };` list (next to `create_vault`):

```rust
    add_device_slot, append_record, create_vault, create_vault_in_folder, edit_record,
    open_vault_with_password,
```

- [ ] **Step 6: Run the test + workspace build**

Run: `cargo test --release -p secretary-ffi-uniffi create_vault_in_folder_invalid_utf8_path`
Expected: PASS.

Run: `cargo build --release -p secretary-ffi-uniffi`
Expected: PASS — UDL scaffolding regenerates with the new function + variant.

- [ ] **Step 7: Lint**

Run: `cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/namespace/mod.rs ffi/secretary-ffi-uniffi/src/lib.rs
git commit -m "feat(ffi-uniffi): project create_vault_in_folder

uniffi namespace wrapper + UDL declaration returning MnemonicOutput, with
the same UTF-8-path / zeroize discipline as open_vault_with_password.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: pyo3 `create_vault_in_folder`

**Files:**
- Modify: `ffi/secretary-ffi-py/src/unlock.rs` (pyfunction + import)
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (import + registration)
- Test: `ffi/secretary-ffi-py/tests/test_smoke.py` (round-trip + errors)

- [ ] **Step 1: Write the failing pytest**

In `ffi/secretary-ffi-py/tests/test_smoke.py`, add (the module already `import secretary_ffi_py` and uses `tempfile` patterns; if `tempfile`/`pathlib` are not imported at the top, add `import tempfile` and `from pathlib import Path`):

```python
def test_create_vault_in_folder_writes_openable_vault() -> None:
    """create_vault_in_folder writes all four canonical files; the folder
    then opens through open_vault_with_password (which validates the
    manifest + owner card)."""
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp) / "vault"
        folder.mkdir()
        mnem = secretary_ffi_py.create_vault_in_folder(
            str(folder), b"hunter2", "Py-Folder-Bob", 1_700_000_000_000
        )
        phrase = mnem.take_phrase()
        assert phrase is not None
        assert len(bytes(phrase).split(b" ")) == 24

        assert (folder / "vault.toml").is_file()
        assert (folder / "identity.bundle.enc").is_file()
        assert (folder / "manifest.cbor.enc").is_file()
        assert (folder / "contacts").is_dir()

        out = secretary_ffi_py.open_vault_with_password(str(folder), b"hunter2")
        assert out.identity.display_name() == "Py-Folder-Bob"


def test_create_vault_in_folder_rejects_nonempty_folder() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp) / "vault"
        folder.mkdir()
        (folder / "junk").write_bytes(b"x")
        with pytest.raises(secretary_ffi_py.VaultFolderNotEmpty):
            secretary_ffi_py.create_vault_in_folder(
                str(folder), b"pw", "X", 1_700_000_000_000
            )


def test_create_vault_in_folder_rejects_missing_folder() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        missing = Path(tmp) / "does-not-exist"
        with pytest.raises(secretary_ffi_py.VaultFolderInvalid):
            secretary_ffi_py.create_vault_in_folder(
                str(missing), b"pw", "X", 1_700_000_000_000
            )
```

(`pytest` is already imported in `test_smoke.py`.)

- [ ] **Step 2: Run it — expect failure (function not found)**

Run: `cd ffi/secretary-ffi-py && uv run --with pytest --with maturin maturin develop && uv run --with pytest pytest tests/test_smoke.py -k create_vault_in_folder -v`
Expected: FAIL — `AttributeError: module 'secretary_ffi_py' has no attribute 'create_vault_in_folder'`.

> If `pytest` sees a stale `.so` after a rebuild, nuke the venv + uv cache (see [[project_secretary_maturin_uv_cache]]).

- [ ] **Step 3: Extend the unlock.rs import**

In `ffi/secretary-ffi-py/src/unlock.rs`, change the errors import to pull in the vault mapper:

```rust
use crate::errors::{ffi_unlock_error_to_pyerr, ffi_vault_error_to_pyerr};
```

- [ ] **Step 4: Add the pyfunction**

In `ffi/secretary-ffi-py/src/unlock.rs`, after the existing `create_vault` pyfunction:

```rust
/// Create a fresh v1 vault on disk in an existing empty `folder` and return
/// the one-shot recovery `MnemonicOutput`. Writes all four canonical files
/// via the bridge's folder-writing path; the caller re-opens with
/// `open_vault_with_password` to browse (no auto-open). Bridge hardcodes
/// `OsRng` + `Argon2idParams::V1_DEFAULT`.
///
/// Raises `VaultFolderNotEmpty` if the directory is non-empty,
/// `VaultFolderInvalid` if it is missing / unreadable, `VaultCorruptVault`
/// on rare crypto failure.
#[pyfunction]
pub(crate) fn create_vault_in_folder(
    folder: std::path::PathBuf,
    mut password: Vec<u8>,
    display_name: &str,
    created_at_ms: u64,
) -> PyResult<MnemonicOutput> {
    // Mirrors create_vault's wrapper-side zeroize discipline: the bridge
    // wraps password into SecretBytes; this Vec is the projection-side
    // cleartext transient. Zero it whether the call succeeds or fails.
    let result =
        secretary_ffi_bridge::create_vault_in_folder(&folder, &password, display_name, created_at_ms);
    password.zeroize();
    let mnemonic = result.map_err(ffi_vault_error_to_pyerr)?;
    Ok(MnemonicOutput(mnemonic))
}
```

- [ ] **Step 5: Register the pyfunction in lib.rs**

In `ffi/secretary-ffi-py/src/lib.rs`, add `create_vault_in_folder` to the `use unlock::{ ... };` import (next to `create_vault`):

```rust
use unlock::{
    create_vault, create_vault_in_folder, open_with_password, open_with_recovery, CreateVaultOutput,
    MnemonicOutput,
};
```

And register it in the module body, right after the `create_vault` registration (near line 154):

```rust
    m.add_function(wrap_pyfunction!(create_vault_in_folder, m)?)?;
```

- [ ] **Step 6: Rebuild + run the tests**

Run: `cd ffi/secretary-ffi-py && uv run --with pytest --with maturin maturin develop && uv run --with pytest pytest tests/test_smoke.py -k create_vault_in_folder -v`
Expected: PASS — all three tests green.

- [ ] **Step 7: Lint**

Run: `cargo clippy --release -p secretary-ffi-py --tests -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-py/src/unlock.rs ffi/secretary-ffi-py/src/lib.rs ffi/secretary-ffi-py/tests/test_smoke.py
git commit -m "feat(ffi-py): project create_vault_in_folder

PyO3 pyfunction returning MnemonicOutput, with wrapper-side password
zeroize. pytest round-trip (4 files + open) + VaultFolderNotEmpty +
VaultFolderInvalid error contracts.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Swift + Kotlin conformance error harness + folder-in create smoke

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift` (variant name)
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt` (variant name)
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/SmokeFolderIn.swift` (create asserts)
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeFolderIn.kt` (create asserts)

> These four files are invisible to `cargo`/`clippy`; only `run_conformance.sh` builds them. They are the easy-to-miss tail of the workspace-match obligation.

- [ ] **Step 1: Add the Swift conformance variant name**

In `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`, add to the `vaultErrorName` switch (after the `.DeviceUuidMismatch` case):

```swift
    case .VaultFolderNotEmpty: return "VaultFolderNotEmpty"
```

(No `vaultErrorDetail` change — `VaultFolderNotEmpty` has no associated value and the `default: return nil` arm covers it.)

- [ ] **Step 2: Add the Kotlin conformance variant name**

In `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt`, add to the `vaultExceptionVariantName` `when` (after the `is VaultException.DeviceUuidMismatch` branch):

```kotlin
    is VaultException.VaultFolderNotEmpty -> "VaultFolderNotEmpty"
```

- [ ] **Step 3: Add the Swift create-in-folder smoke asserts**

In `ffi/secretary-ffi-uniffi/tests/swift/SmokeFolderIn.swift`, at the end of `runFolderInAsserts`, add (uses `FileManager` for a temp dir, mirroring the file's existing `env`-based pattern):

```swift
    // =============================================================================
    // create_vault_in_folder — write a complete vault, then open it.
    // =============================================================================

    // Assert: create_vault_in_folder writes an openable vault.
    do {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("create-folder-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let folderPath = Data(tmp.path.utf8)
        let mnem = try createVaultInFolder(
            folderPath: folderPath,
            password: Data("create-smoke-pw".utf8),
            displayName: "Swift-Create-Bob",
            createdAtMs: 1_700_000_000_000
        )
        defer { mnem.wipe() }
        let phrase = mnem.takePhrase()
        let wordCount = phrase.map { String(decoding: $0, as: UTF8.self).split(separator: " ").count } ?? 0

        let opened = try openVaultWithPassword(folderPath: folderPath, password: Data("create-smoke-pw".utf8))
        defer { opened.identity.wipe() }
        defer { opened.manifest.wipe() }
        check(
            wordCount == 24 && opened.identity.displayName() == "Swift-Create-Bob",
            "create_vault_in_folder → 24-word phrase + openable vault (displayName=\"\(opened.identity.displayName())\")"
        )
    } catch {
        check(false, "create_vault_in_folder smoke threw \(error), expected success")
    }

    // Assert: create_vault_in_folder on a non-empty folder → VaultError.VaultFolderNotEmpty.
    do {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("create-nonempty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        try Data("x".utf8).write(to: tmp.appendingPathComponent("junk"))

        _ = try createVaultInFolder(
            folderPath: Data(tmp.path.utf8),
            password: Data("pw".utf8),
            displayName: "X",
            createdAtMs: 1_700_000_000_000
        )
        check(false, "non-empty folder should have thrown VaultError.VaultFolderNotEmpty")
    } catch VaultError.VaultFolderNotEmpty {
        check(true, "create_vault_in_folder non-empty → VaultError.VaultFolderNotEmpty")
    } catch {
        check(false, "non-empty folder threw \(error), expected VaultError.VaultFolderNotEmpty")
    }
```

> Confirm the generated Swift function name is `createVaultInFolder` and the take method is `takePhrase()` (uniffi lower-camel-cases UDL names; `take_phrase` → `takePhrase`). If the generated names differ, match the generated bindings.

- [ ] **Step 4: Add the Kotlin create-in-folder smoke asserts**

In `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeFolderIn.kt`, at the end of `runFolderInAsserts`, add (mirror the Swift logic; use `kotlin.io.path.createTempDirectory` and `import uniffi.secretary.createVaultInFolder`):

```kotlin
    // create_vault_in_folder — write a complete vault, then open it.
    run {
        val tmp = kotlin.io.path.createTempDirectory("create-folder-").toFile()
        try {
            val folderPath = tmp.path.toByteArray(Charsets.UTF_8)
            val mnem = createVaultInFolder(
                folderPath,
                "create-smoke-pw".toByteArray(Charsets.UTF_8),
                "Kotlin-Create-Bob",
                1_700_000_000_000uL,
            )
            val phrase = mnem.takePhrase()
            val wordCount = phrase?.toByteArray()?.toString(Charsets.UTF_8)?.split(" ")?.size ?: 0
            mnem.wipe()

            val opened = openVaultWithPassword(folderPath, "create-smoke-pw".toByteArray(Charsets.UTF_8))
            val name = opened.identity.displayName()
            opened.identity.wipe()
            opened.manifest.wipe()
            check(
                wordCount == 24 && name == "Kotlin-Create-Bob",
                "create_vault_in_folder → 24-word phrase + openable vault (displayName=\"$name\")",
            )
        } finally {
            tmp.deleteRecursively()
        }
    }

    // create_vault_in_folder on a non-empty folder → VaultException.VaultFolderNotEmpty.
    run {
        val tmp = kotlin.io.path.createTempDirectory("create-nonempty-").toFile()
        try {
            java.io.File(tmp, "junk").writeText("x")
            createVaultInFolder(
                tmp.path.toByteArray(Charsets.UTF_8),
                "pw".toByteArray(Charsets.UTF_8),
                "X",
                1_700_000_000_000uL,
            )
            check(false, "non-empty folder should have thrown VaultException.VaultFolderNotEmpty")
        } catch (e: VaultException.VaultFolderNotEmpty) {
            check(true, "create_vault_in_folder non-empty → VaultException.VaultFolderNotEmpty")
        } finally {
            tmp.deleteRecursively()
        }
    }
```

> `phrase?.toByteArray()` assumes uniffi maps `sequence<u8>?` to a `List<UByte>?`/`ByteArray?`; match whatever `takePhrase()` actually returns in the generated bindings (the existing mnemonic smoke, if any, is the reference — otherwise decode the returned sequence to a UTF-8 string and split on spaces).

- [ ] **Step 5: Run the Swift conformance + smoke**

Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh`
Expected: PASS — builds the Swift binding (picks up the new variant + function), all asserts green including the new create asserts.

- [ ] **Step 6: Run the Kotlin conformance + smoke**

Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh`
Expected: PASS — all asserts green including the new create asserts.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt ffi/secretary-ffi-uniffi/tests/swift/SmokeFolderIn.swift ffi/secretary-ffi-uniffi/tests/kotlin/SmokeFolderIn.kt
git commit -m "test(ffi-uniffi): Swift+Kotlin create_vault_in_folder smoke + error parity

Adds VaultFolderNotEmpty to the Swift/Kotlin ConformanceErrors variant-name
harnesses (the cargo-invisible workspace-match sites) and create_vault_in_folder
round-trip + non-empty-folder asserts to SmokeFolderIn.{swift,kt}.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Docs — README + ROADMAP

**Files:**
- Modify: `README.md` (status row)
- Modify: `ROADMAP.md` (entry)

- [ ] **Step 1: Update README status**

Open `README.md`, find the FFI / sub-project-B status section, and add a brief dot-point that the FFI now exposes folder-writing vault creation (`create_vault_in_folder`) on uniffi + pyo3. Keep it brief, audience = curious contributors (no test-count walls) per [[feedback_readme_style]].

- [ ] **Step 2: Update ROADMAP**

Open `ROADMAP.md`, find the iOS create/import line (or the FFI/B section), and add an entry noting Slice 1 (FFI folder-writing create_vault) is shipped, with the iOS create-wizard UI as Slice 2 (next). Match the existing ROADMAP entry style.

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: FFI folder-writing create_vault shipped — README + ROADMAP

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final acceptance gauntlet

Run from the worktree root after all tasks:

```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cd ffi/secretary-ffi-py && uv run --with pytest --with maturin maturin develop && uv run --with pytest pytest -q && cd ../..
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
git diff main..HEAD --name-only | grep -E '^core/src/|docs/vault-format|docs/crypto-design'   # MUST be empty (no core src / frozen-format change)
```

(The last check tolerates `core/tests/conformance_kat_helpers/errors.rs` — a *test* helper — but must show no `core/src/` or frozen-spec doc change.)

## Notes for the implementer

- **`core/` boundary:** the only `core/` file this slice touches is `core/tests/conformance_kat_helpers/errors.rs` (a test helper). `core/src/` and the frozen `docs/vault-format.md` / `docs/crypto-design.md` must NOT change. If you find yourself editing `core/src/`, stop — the design assumes `core::vault::create_vault` is reused unchanged.
- **uniffi generated names:** uniffi 0.31 lower-camel-cases UDL identifiers for Swift/Kotlin (`create_vault_in_folder` → `createVaultInFolder`, `take_phrase` → `takePhrase`). Verify against the generated bindings if a name doesn't resolve (see [[project_secretary_uniffi_codegen_renames]]).
- **Tests use random crypto values:** all passwords/timestamps here are literal test inputs, not crypto material; the vault's keys/salt/nonce are generated at runtime by `OsRng` inside `core::vault::create_vault`, so there is no hardcoded-crypto-value concern (per [[feedback_test_crypto_random_not_hardcoded]]).
- **Handoff:** update `NEXT_SESSION.md` (symlink → new `docs/handoffs/` file) on this branch BEFORE opening the PR (per [[feedback_next_session_in_pr]]).
```
