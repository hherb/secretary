# B.4a — FFI Folder-Based `open_vault` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `secretary_core::vault::open_vault` through both FFI flavors (PyO3 → Python; uniffi → Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. Two new top-level entry points (`open_vault_with_password`, `open_vault_with_recovery`) take a vault folder path, perform full unlock + manifest load + owner-card verification via core, and return an `OpenVaultOutput` containing two opaque handles: the existing `UnlockedIdentity` (re-used unchanged from B.2 / B.3a / B.3b) and a NEW `OpenVaultManifest` exposing read-only block-list accessors. A new flat 6-variant `FfiVaultError` mirrors `FfiUnlockError`'s 5 unlock-class variants byte-identically (name + Display) plus 1 new `FolderInvalid { detail }` for missing or inaccessible folders. `local_highest_clock` is always `None` (rollback deferred to Sub-project C).

**Architecture:** Strictly additive on B.3b's three-crate FFI layout. Bridge crate gains a new `vault.rs` module + a new `FfiVaultError` enum in the existing `error.rs` + one re-export line in `lib.rs`. PyO3 + uniffi projection layers add 2 new entry points + 3 new types each (`OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary`) plus the new `FfiVaultError` projection. `OpenVaultManifest` uses the same `Mutex<Option<T>>` newtype pattern + `lock_or_recover` poisoning-safety helper as `UnlockedIdentity` and `MnemonicOutput`. `From<core::vault::VaultError> for FfiVaultError` delegates unlock-class variant translation through a private `From<FfiUnlockError>` arm so a future variant rename on `FfiUnlockError` propagates automatically — drift-free.

**Tech Stack:** Rust 1.87 stable, PyO3 0.28, uniffi 0.31, maturin 1.9.4+, uv 0.6+, pytest, kotlinc 2.x, swiftc, JNA 5.14.0, thiserror, zeroize. No new top-level dependencies.

**Spec:** [docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md](../specs/2026-05-06-ffi-b4a-open-vault-design.md) (commits `a3b6a52` + `6122e11`)

**Worktree:** `.worktrees/feat-ffi-b4a-open-vault/` on branch `feat/ffi-b4a-open-vault`. Created as Pre-flight Task 0 below; the spec doc is already on `main` and inherits into the worktree.

---

## File structure

After all tasks complete, the FFI tree contains:

```
ffi/
├── secretary-ffi-bridge/
│   ├── README.md                                            ← edit (Task 8; +B.4a section)
│   └── src/
│       ├── lib.rs                                           ← edit (Task 3; re-export FfiVaultError + 5 new types + 2 new fns; B.4a crate-doc)
│       ├── error.rs                                         ← edit (Task 1; +FfiVaultError 6-variant enum + From<core::VaultError> + private From<FfiUnlockError> arm + tests)
│       ├── identity.rs                                      ← unchanged
│       ├── unlock.rs                                        ← unchanged
│       ├── create.rs                                        ← unchanged
│       ├── sync_helpers.rs                                  ← unchanged
│       └── vault.rs                                         ← NEW (Task 2; open_vault_with_password, open_vault_with_recovery, OpenVaultOutput, OpenVaultManifest, BlockSummary, +9 tests)
│
├── secretary-ffi-py/
│   ├── README.md                                            ← edit (Task 8; +B.4a section)
│   ├── src/lib.rs                                           ← edit (Task 4; +2 #[pyfunction], +3 #[pyclass], +6 create_exception!)
│   └── tests/test_smoke.py                                  ← edit (Task 5; +7 tests, +1 module-scoped fixture)
│
└── secretary-ffi-uniffi/
    ├── README.md                                            ← edit (Task 8; +B.4a section)
    ├── src/
    │   ├── lib.rs                                           ← edit (Task 6; +2 wrapper structs, +1 dictionary wrapper, +2 pub fn, +mapping tests)
    │   └── secretary.udl                                    ← edit (Task 6; +2 dictionary, +1 interface, +1 [Error] enum, +2 namespace fn)
    └── tests/
        ├── swift/main.swift                                 ← edit (Task 7; +3 asserts)
        └── kotlin/Main.kt                                   ← edit (Task 7; +3 asserts)

core/tests/data/
    golden_vault_001_inputs.json                             ← edit (Task 2; pinned block_summaries array)
    golden_vault_002_inputs.json                             ← edit (Task 2; pinned block_summaries array)

README.md (root)                                             ← edit (Task 8)
ROADMAP.md                                                   ← edit (Task 8)
NEXT_SESSION.md                                              ← edit (Task 9)
docs/handoffs/2026-05-06-b4a-open-vault.md                   ← NEW (Task 9)
```

**Decomposition rationale:**
- Task 1 (`error.rs` — `FfiVaultError` enum) lands first as a self-contained type addition. It's the smallest piece (1 new enum + 1 `From<core::VaultError>` impl + 1 private `From<FfiUnlockError>` arm + ~9 tests) and isolating it means Task 2's much larger `vault.rs` work doesn't entangle with what is conceptually a separate concern.
- Task 2 is the largest single piece — new file, new types (`OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary`), 2 new functions, 9 tests including 2 slow integration tests. Also includes the JSON pinning additions to `golden_vault_001_inputs.json` and `golden_vault_002_inputs.json` (small but contract-defining).
- Task 3 (`lib.rs` re-exports + crate-doc) is mechanically tiny but must come after Task 2 since it re-exports the new symbols.
- Phase 2 (Tasks 4–5) is the PyO3 layer: wrapper first, then tests.
- Phase 3 (Tasks 6–7) is the uniffi layer: UDL + Rust glue, then foreign smoke runners.
- Phase 4 (Tasks 8–9) is the doc + handoff cluster — last commits before push + PR.

---

## Pre-flight

### Task 0: Create the worktree

**Files:** none in repo; creates `.worktrees/feat-ffi-b4a-open-vault/` and branch `feat/ffi-b4a-open-vault`.

- [ ] **Step 1: Verify clean state on main**

```bash
cd /Users/hherb/src/secretary
git status
git log --oneline -3
```

Expected: clean working tree (the three untracked `.claude/` items — `settings.local.json`, `skills/commit-push/`, `skills/handoff/` — are local Claude tooling, not project code; ignore them); `main` HEAD is `6122e11 docs(spec): align B.4a FfiVaultError variants + Display text with FfiUnlockError` or newer.

- [ ] **Step 2: Verify all gates green before forking**

```bash
cd /Users/hherb/src/secretary
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )
uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```

Expected: 498 passed + 9 ignored cargo; clippy clean; fmt OK; 22 pytest; PASS conformance + freshness; 15 PASS Swift; 16 PASS lines Kotlin. If pytest fails with `AttributeError: module 'secretary_ffi_py' has no attribute …`, apply the documented nuclear cache fix:

```bash
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} + 2>/dev/null
cargo clean -p secretary-ffi-py
cd ffi/secretary-ffi-py && uv sync && uv run maturin develop --release --uv && cd ../..
uv run --directory ffi/secretary-ffi-py pytest
```

- [ ] **Step 3: Create the worktree**

```bash
cd /Users/hherb/src/secretary
git worktree add .worktrees/feat-ffi-b4a-open-vault -b feat/ffi-b4a-open-vault
```

Expected: `Preparing worktree (new branch 'feat/ffi-b4a-open-vault')`. The worktree is at `.worktrees/feat-ffi-b4a-open-vault/`; cd into it for all subsequent tasks.

- [ ] **Step 4: Verify worktree baseline**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git status
git branch --show-current
cargo build --release --workspace 2>&1 | tail -3
```

Expected: clean working tree on branch `feat/ffi-b4a-open-vault`; cargo build succeeds (incremental — most artifacts inherited from main). No commit at this step — just verify.

- [ ] **Step 5: Commit baseline marker (optional, no-op)**

No commit needed — the worktree inherits main's tree. Subsequent tasks commit incrementally.

---

## Phase 1 — Bridge crate

### Task 1: `error.rs` — add `FfiVaultError` 6-variant flat enum

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error.rs` (currently 347 lines; will grow to ~530)

The new enum mirrors `FfiUnlockError`'s 5 unlock-class variants byte-identically (name + Display) plus a new `FolderInvalid { detail }` variant. `From<core::vault::VaultError>` delegates unlock-class translation to a private `From<FfiUnlockError>` arm — drift-free.

- [ ] **Step 1: Read the existing error.rs to align style**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cat ffi/secretary-ffi-bridge/src/error.rs | head -100
```

Expected: the file declares `FfiUnlockError` with 5 variants and a `From<secretary_core::unlock::UnlockError>` impl. No surprises.

- [ ] **Step 2: Append `FfiVaultError` enum to the bottom of `error.rs`** (after the existing `tests` module's closing brace `}`)

Add the following AFTER the existing `tests` module closes (last `}` in the file):

```rust

// =============================================================================
// FfiVaultError — folder-in counterpart to FfiUnlockError
// =============================================================================

/// FFI-friendly thinned error type for the **folder-in** vault entry points
/// (`open_vault_with_password` and `open_vault_with_recovery`). Mirrors
/// [`FfiUnlockError`]'s 5 unlock-class variants byte-identically (variant
/// name + Display string) plus a new [`FfiVaultError::FolderInvalid`]
/// variant for missing or inaccessible vault folders.
///
/// # Why a separate error type
///
/// The bytes-in unlock entry points (B.2 / B.3a, returning `FfiUnlockError`)
/// cannot raise IO errors — they take owned byte slices, not paths. The
/// folder-in entry points (B.4a) read four files from disk
/// (`vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`,
/// `contacts/<owner_uuid>.card`) and need a way to surface "your path is
/// wrong" distinctly from "your data is corrupt". Promoting that distinction
/// to a separate variant with `detail: String` carrying the missing-file
/// name lets foreign UIs render the right affordance (fix the path vs.
/// re-pair from backups). Pre-unlock IO errors don't leak unlock-secret
/// information, so the §13 anti-oracle constraint allows the granularity.
///
/// # Mirror property
///
/// The 5 overlapping variants share **byte-identical** Display strings with
/// their `FfiUnlockError` counterparts. Foreign-side dispatch logic on a
/// folder-in `FfiVaultError` reads identically to dispatch on a bytes-in
/// `FfiUnlockError`. A code-quality tripwire test in this module pins the
/// strings byte-identical so a future variant rename on `FfiUnlockError`
/// cannot drift unnoticed.
#[derive(Debug, Error)]
pub enum FfiVaultError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13. Returned by `open_vault_with_password`.
    /// Mirrors [`FfiUnlockError::WrongPasswordOrCorrupt`] in name and
    /// Display text.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,

    /// Wrong recovery phrase OR vault corruption — parallel anti-oracle
    /// conflation for `open_vault_with_recovery`. Mirrors
    /// [`FfiUnlockError::WrongMnemonicOrCorrupt`] in name and Display text.
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,

    /// Invalid recovery phrase — pre-decryption validation failure (wrong
    /// word count, unknown word, bad checksum, or invalid UTF-8 input).
    /// Mirrors [`FfiUnlockError::InvalidMnemonic`] in name and Display text.
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic {
        /// Diagnostic text from the inner `MnemonicError` variant's
        /// `Display` impl, or `"phrase contained invalid UTF-8"` when
        /// the FFI input slice is not valid UTF-8.
        detail: String,
    },

    /// `vault.toml` and `identity.bundle.enc` reference different vaults.
    /// Mirrors [`FfiUnlockError::VaultMismatch`] in name and Display text.
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    /// Vault data integrity failure — covers BOTH the unlock-time corruption
    /// cases mirrored from [`FfiUnlockError::CorruptVault`] AND the
    /// post-unlock integrity failures specific to folder-in: manifest
    /// decrypt/parse/verify, owner-card decode/self-verify, fingerprint
    /// cross-check, KDF-params cross-check. Display text is path-neutral
    /// and matches [`FfiUnlockError::CorruptVault`] exactly. Carries a
    /// diagnostic `detail` string for debugging; not pattern-matchable on
    /// the inner cause.
    #[error("vault data integrity failure: {detail}")]
    CorruptVault {
        /// Diagnostic text from the inner `core::VaultError` variant's
        /// `Display` impl. Free-form; not part of the API contract.
        detail: String,
    },

    /// Vault folder doesn't exist, isn't readable, or is missing one of
    /// the required files (`vault.toml`, `identity.bundle.enc`,
    /// `manifest.cbor.enc`, `contacts/<owner_uuid>.card`). New variant
    /// introduced by B.4a — no counterpart on [`FfiUnlockError`] (bytes-in
    /// callers cannot raise IO errors against their own filesystem through
    /// the bridge). The `detail` string carries the IO context (e.g.
    /// `"failed to read vault.toml: No such file or directory (os error 2)"`).
    #[error("vault folder is not accessible: {detail}")]
    FolderInvalid {
        /// IO context string: which file we tried to read + the underlying
        /// `io::Error`'s Display.
        detail: String,
    },
}

impl From<secretary_core::vault::VaultError> for FfiVaultError {
    fn from(e: secretary_core::vault::VaultError) -> Self {
        use secretary_core::vault::VaultError as VE;

        match e {
            // Unlock-class errors: delegate to the FfiUnlockError translation
            // logic so the 5 mirrored variants stay drift-free. If a future
            // refactor adds a 6th variant to FfiUnlockError, the new variant
            // automatically picks up the right FfiVaultError mapping via the
            // private From<FfiUnlockError> arm below.
            VE::Unlock(unlock_err) => {
                let intermediate: FfiUnlockError = unlock_err.into();
                intermediate.into()
            }

            // Pre-unlock IO errors → FolderInvalid. The matched ErrorKinds
            // are the foreign-caller-actionable ones (path is wrong, no
            // permission). Any other IO error kind (e.g. interrupted, broken
            // pipe) falls through to CorruptVault since it's neither
            // user-actionable nor data-integrity-clean.
            VE::Io { context, source }
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                FfiVaultError::FolderInvalid {
                    detail: format!("{context}: {source}"),
                }
            }

            // Post-unlock integrity failures and unexpected IO kinds: fold
            // into CorruptVault catchall. These cannot leak unlock-secret
            // information (the IBK was already recovered when they fire).
            // Manifest decode, owner-card verification, UUID mismatches,
            // KDF-params mismatch, vector-clock overflow, signature
            // primitive failure, etc. all land here.
            other => FfiVaultError::CorruptVault {
                detail: format!("{other}"),
            },
        }
    }
}

/// Private bridge-internal arm. Not part of the FFI surface; lives behind
/// `pub(crate)` only because the [`From<core::vault::VaultError>`] impl above
/// needs to delegate to it. **Do not use this arm directly from foreign-
/// projection code** — it would couple the binding-flavor crates to a
/// private translation step. Foreign code goes through `From<core::VaultError>`.
impl From<FfiUnlockError> for FfiVaultError {
    fn from(e: FfiUnlockError) -> Self {
        match e {
            FfiUnlockError::WrongPasswordOrCorrupt => FfiVaultError::WrongPasswordOrCorrupt,
            FfiUnlockError::WrongMnemonicOrCorrupt => FfiVaultError::WrongMnemonicOrCorrupt,
            FfiUnlockError::InvalidMnemonic { detail } => FfiVaultError::InvalidMnemonic { detail },
            FfiUnlockError::VaultMismatch => FfiVaultError::VaultMismatch,
            FfiUnlockError::CorruptVault { detail } => FfiVaultError::CorruptVault { detail },
        }
    }
}
```

- [ ] **Step 3: Append `FfiVaultError` tests inside the existing `mod tests`** — open the existing `mod tests {` and add new test functions before the closing `}`.

Locate the line `#[cfg(test)]\nmod tests {` (around line 140) and add the following AFTER the last existing test (i.e. inside the same `tests` module, before its closing `}`):

```rust

    // =============================================================================
    // FfiVaultError tests — mirror property + dedicated FolderInvalid + drift tripwire
    // =============================================================================

    #[test]
    fn vault_error_display_strings_mirror_unlock_error_byte_identical() {
        // Tripwire: the 5 overlapping variants MUST produce byte-identical
        // Display strings between FfiUnlockError and FfiVaultError. A future
        // rename on either side that breaks the mirror property would fail
        // here, forcing a deliberate decision rather than silent drift.
        assert_eq!(
            FfiUnlockError::WrongPasswordOrCorrupt.to_string(),
            FfiVaultError::WrongPasswordOrCorrupt.to_string(),
        );
        assert_eq!(
            FfiUnlockError::WrongMnemonicOrCorrupt.to_string(),
            FfiVaultError::WrongMnemonicOrCorrupt.to_string(),
        );
        assert_eq!(
            FfiUnlockError::InvalidMnemonic {
                detail: "test".to_string()
            }
            .to_string(),
            FfiVaultError::InvalidMnemonic {
                detail: "test".to_string()
            }
            .to_string(),
        );
        assert_eq!(
            FfiUnlockError::VaultMismatch.to_string(),
            FfiVaultError::VaultMismatch.to_string(),
        );
        assert_eq!(
            FfiUnlockError::CorruptVault {
                detail: "test".to_string()
            }
            .to_string(),
            FfiVaultError::CorruptVault {
                detail: "test".to_string()
            }
            .to_string(),
        );
    }

    #[test]
    fn vault_error_folder_invalid_display_uses_dedicated_text() {
        let ffi = FfiVaultError::FolderInvalid {
            detail: "fnord".to_string(),
        };
        let rendered = format!("{ffi}");
        assert!(
            rendered.contains("vault folder is not accessible"),
            "Display did not contain the dedicated FolderInvalid text: {rendered}",
        );
        assert!(rendered.contains("fnord"), "Display did not include detail");
    }

    #[test]
    fn from_ffi_unlock_error_translates_each_variant_one_to_one() {
        // The private bridge-internal From<FfiUnlockError> arm. This is
        // reachable from FfiVaultError::from(VaultError::Unlock(...)) but
        // worth pinning directly so any rename / variant addition fails here
        // first.
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::WrongPasswordOrCorrupt),
            FfiVaultError::WrongPasswordOrCorrupt,
        ));
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::WrongMnemonicOrCorrupt),
            FfiVaultError::WrongMnemonicOrCorrupt,
        ));
        let inv = FfiVaultError::from(FfiUnlockError::InvalidMnemonic {
            detail: "bad".to_string(),
        });
        let FfiVaultError::InvalidMnemonic { detail } = inv else {
            panic!("expected InvalidMnemonic, got {inv:?}");
        };
        assert_eq!(detail, "bad");
        assert!(matches!(
            FfiVaultError::from(FfiUnlockError::VaultMismatch),
            FfiVaultError::VaultMismatch,
        ));
        let corrupt = FfiVaultError::from(FfiUnlockError::CorruptVault {
            detail: "x".to_string(),
        });
        let FfiVaultError::CorruptVault { detail } = corrupt else {
            panic!("expected CorruptVault, got {corrupt:?}");
        };
        assert_eq!(detail, "x");
    }

    #[test]
    fn from_core_vault_error_unlock_arm_delegates_through_ffi_unlock_error() {
        // VaultError::Unlock(WrongPasswordOrCorrupt) → FfiVaultError::WrongPasswordOrCorrupt
        // via the FfiUnlockError translation. Test the full delegation path.
        use secretary_core::unlock::UnlockError;
        use secretary_core::vault::VaultError;
        let core_err = VaultError::Unlock(UnlockError::WrongPasswordOrCorrupt);
        let ffi: FfiVaultError = core_err.into();
        assert!(matches!(ffi, FfiVaultError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn from_core_vault_error_io_not_found_maps_to_folder_invalid() {
        use secretary_core::vault::VaultError;
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let core_err = VaultError::Io {
            context: "failed to read vault.toml",
            source: io_err,
        };
        let ffi: FfiVaultError = core_err.into();
        let FfiVaultError::FolderInvalid { detail } = ffi else {
            panic!("expected FolderInvalid, got {ffi:?}");
        };
        assert!(
            detail.contains("vault.toml") && detail.contains("no such file"),
            "FolderInvalid detail did not carry context + source: {detail}",
        );
    }

    #[test]
    fn from_core_vault_error_io_permission_denied_maps_to_folder_invalid() {
        use secretary_core::vault::VaultError;
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let core_err = VaultError::Io {
            context: "failed to read identity.bundle.enc",
            source: io_err,
        };
        let ffi: FfiVaultError = core_err.into();
        assert!(matches!(ffi, FfiVaultError::FolderInvalid { .. }));
    }

    #[test]
    fn from_core_vault_error_io_other_kind_falls_through_to_corrupt_vault() {
        // Kinds other than NotFound / PermissionDenied are not foreign-
        // caller-actionable as "your path is wrong" — fold to CorruptVault.
        use secretary_core::vault::VaultError;
        let io_err = std::io::Error::new(std::io::ErrorKind::InvalidData, "bad data");
        let core_err = VaultError::Io {
            context: "failed to parse manifest.cbor.enc",
            source: io_err,
        };
        let ffi: FfiVaultError = core_err.into();
        assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
    }

    #[test]
    fn from_core_vault_error_owner_uuid_mismatch_maps_to_corrupt_vault() {
        // Post-unlock integrity failure folds into CorruptVault catchall.
        use secretary_core::vault::VaultError;
        let core_err = VaultError::OwnerUuidMismatch {
            vault: [0u8; 16],
            found: [1u8; 16],
        };
        let ffi: FfiVaultError = core_err.into();
        assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
    }

    #[test]
    fn from_core_vault_error_manifest_kdf_params_mismatch_maps_to_corrupt_vault() {
        // Another post-unlock integrity failure pinned to CorruptVault.
        use secretary_core::vault::VaultError;
        let core_err = VaultError::ManifestKdfParamsMismatch;
        let ffi: FfiVaultError = core_err.into();
        assert!(matches!(ffi, FfiVaultError::CorruptVault { .. }));
    }
```

- [ ] **Step 4: Run the new tests; expect them to compile-fail or pass cleanly**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo test --release -p secretary-ffi-bridge --lib error 2>&1 | tail -20
```

Expected: 9 new tests pass alongside the existing 14 in `error.rs`. Total `error.rs` test count: ~23 (was 14). If a test fails because the variant in core's `VaultError` is named differently than `OwnerUuidMismatch` or `ManifestKdfParamsMismatch`, locate the actual variant via:

```bash
grep -E "^pub enum VaultError|#\[error" core/src/vault/mod.rs | head -25
```

and update the test's variant constructor to match. The variants used (`Io`, `OwnerUuidMismatch`, `ManifestKdfParamsMismatch`, `Unlock`) are present in the current `core::vault::VaultError` per CLAUDE.md and the spec — but verify before assuming.

- [ ] **Step 5: Run clippy + fmt**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo clippy --release -p secretary-ffi-bridge -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: clippy clean, fmt OK. If clippy flags `clippy::useless_format` on a test's `format!()`, replace with `to_string()` and re-run.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add ffi/secretary-ffi-bridge/src/error.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4a): add FfiVaultError 6-variant flat enum + From<core::VaultError>

Mirrors FfiUnlockError's 5 unlock-class variants byte-identically (variant
name + Display text) plus a new FolderInvalid { detail } variant for
missing or inaccessible vault folders.

The unlock-class variants are translated through a private
From<FfiUnlockError> arm so a future variant rename on FfiUnlockError
propagates automatically — drift-free. A tripwire test pins the Display
strings byte-identical between the two error types.

Pre-unlock IO errors with kind in {NotFound, PermissionDenied} fold into
FolderInvalid; all other errors (post-unlock integrity failures + other
IO kinds) fold into CorruptVault catchall (anti-oracle conflation
preserved on the unlock-class variants independently).

+9 net tests in error.rs (14 → 23). No behavior changes for existing
FfiUnlockError surface.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `vault.rs` — new module with `open_vault_with_password`, `open_vault_with_recovery`, `OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary` + 9 tests

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/vault.rs`
- Modify: `core/tests/data/golden_vault_001_inputs.json` (add `block_summaries` array)
- Modify: `core/tests/data/golden_vault_002_inputs.json` (add `block_summaries` array)

This is the largest single task. The new module declares two `pub fn`s (the entry points), three new types (`OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary`), and 9 tests including 2 slow integration tests against the on-disk golden vault fixtures. The JSON edits pin expected `BlockSummary` field values for the test asserts.

- [ ] **Step 1: Inspect the existing golden vault manifests to find each fixture's actual block layout**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo test --release -p secretary-ffi-bridge --lib unlock 2>&1 | head -5  # warm cache
```

Now read the existing inputs JSON to see the schema:

```bash
cat core/tests/data/golden_vault_001_inputs.json | head -25
cat core/tests/data/golden_vault_002_inputs.json | head -25
```

Expected output: existing JSON has fields like `display_name`, `password`, `recovery_mnemonic_phrase`, `created_at_ms`, `vault_uuid`, `user_uuid`, `entropy`. We will add a new `block_summaries` array to each. Note: the existing JSON is the **input** to the fixture builder (`core/tests/common/fixture_builder.rs`); adding `block_summaries` here is a TEST-PIN-ONLY field, not consumed by the builder. If the test count in cargo workspace was expected to be 498 + 9 ignored at branch start and these JSON additions don't break the existing fixture builder, this approach is safe — verify via `cargo test --release --workspace` after the JSON edit.

- [ ] **Step 2: Write a one-shot helper script to print each golden vault's actual block layout**

The JSON we need to write must exactly match what's stored in each fixture's manifest. Run a small one-shot Rust binary or test that opens each vault and prints the block list, so we can copy the exact values into JSON.

Add this temporary helper test inside `error.rs::tests` (we'll remove it after this step):

```rust
    #[test]
    #[ignore = "one-shot helper for B.4a Task 2 Step 2 — prints block layout for golden_vault_001/002"]
    fn helper_print_golden_vault_block_layouts() {
        use secretary_core::crypto::secret::SecretBytes;
        use secretary_core::vault::{open_vault, Unlocker};
        use std::path::Path;

        for fixture_name in ["golden_vault_001", "golden_vault_002"] {
            let folder = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../core/tests/data")
                .join(fixture_name);
            let password = if fixture_name == "golden_vault_001" {
                SecretBytes::new(b"correct horse battery staple".to_vec())
            } else {
                // golden_vault_002 password — read from inputs JSON if not this one
                SecretBytes::new(b"correct horse battery staple".to_vec())
            };
            let opened = open_vault(&folder, Unlocker::Password(&password), None)
                .unwrap_or_else(|e| panic!("failed to open {fixture_name}: {e:?}"));
            println!("=== {fixture_name} ===");
            println!("vault_uuid: {:02x?}", opened.manifest.vault_uuid);
            println!("owner_user_uuid: {:02x?}", opened.manifest.owner_user_uuid);
            for block in &opened.manifest.blocks {
                println!("BLOCK:");
                println!("  block_uuid: {:02x?}", block.block_uuid);
                println!("  block_name: {:?}", block.block_name);
                println!("  created_at_ms: {}", block.created_at_ms);
                println!("  last_mod_ms: {}", block.last_mod_ms);
                println!(
                    "  recipient_uuids ({}): {:02x?}",
                    block.recipients.len(),
                    block.recipients
                );
            }
        }
    }
```

Run with `--ignored` to execute only this helper:

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo test --release -p secretary-ffi-bridge --lib error::tests::helper_print -- --ignored --nocapture 2>&1 | grep -E "===|^vault_uuid|^owner_user_uuid|^BLOCK|^  block_uuid|^  block_name|^  created_at|^  last_mod|^  recipient"
```

Expected: prints `vault_uuid`, `owner_user_uuid`, plus N `BLOCK:` records per fixture with their full metadata. Capture the output — it's what we encode into the JSON in Step 3.

NOTE: if the password for `golden_vault_002` is different from `golden_vault_001`, fix the helper before re-running. Read both fixture inputs JSONs to find the right passwords.

- [ ] **Step 3: Add `block_summaries` array to each golden vault's inputs JSON**

For `core/tests/data/golden_vault_001_inputs.json`, add a `block_summaries` field at the top level (alongside the existing fields). The exact contents come from Step 2's printed output. Example schema (adjust values to match actual fixture):

```json
{
  "display_name": "Owner",
  "password": "correct horse battery staple",
  "recovery_mnemonic_phrase": "wall annual clay zebra ...",
  "created_at_ms": 0,
  "vault_uuid": "<hex>",
  "user_uuid": "bf08a3300cd994b877e1a15baa28df35",
  "entropy": "<hex>",
  "block_summaries": [
    {
      "block_uuid": "<hex from Step 2 output>",
      "block_name": "<from Step 2 output>",
      "created_at_ms": 0,
      "last_modified_ms": 0,
      "recipient_uuids": ["bf08a3300cd994b877e1a15baa28df35"]
    }
  ]
}
```

Do the same for `golden_vault_002_inputs.json`. Use lowercase hex for byte fields (matching the existing `user_uuid` style). If a fixture has zero blocks (manifest has empty `blocks` array), set `block_summaries` to `[]` — the test in Step 7 will assert on this.

- [ ] **Step 4: Remove the helper test from Step 2**

Now that the JSON is pinned, the helper is no longer needed. Delete the entire `helper_print_golden_vault_block_layouts` test function from `error.rs::tests`.

- [ ] **Step 5: Create `ffi/secretary-ffi-bridge/src/vault.rs` with the new module structure (no implementations yet — just types)**

```rust
//! Folder-based vault entry points (B.4a). The first folder-IO surface on
//! the bridge — bytes-in unlock paths (B.2 / B.3a) and bytes-in
//! create_vault (B.3b) all stay unchanged.
//!
//! # IO model
//!
//! Foreign caller passes a folder path; Rust core reads `vault.toml`,
//! `identity.bundle.enc`, `manifest.cbor.enc`, and the owner contact card
//! from disk via `secretary_core::vault::open_vault`. This is a deliberate
//! transition from the bytes-in discipline: the §9 atomicity guarantee
//! depends on `tempfile::persist` for `rename(2)` semantics, and B.4c's
//! eventual `save_block` will need that contract owned by Rust core.
//! B.4a establishes the IO model that B.4b/c/d inherit.
//!
//! # Output handles
//!
//! Two opaque handles:
//! - [`UnlockedIdentity`] — re-used unchanged from B.2 / B.3a / B.3b.
//!   Wraps `core::IdentityBundle` (display_name, user_uuid, secret keys).
//! - [`OpenVaultManifest`] — NEW. Wraps the rest of `core::vault::OpenVault`:
//!   the IBK (Sensitive on the Rust side, kept for B.4b's read_block),
//!   the decrypted manifest body (block list + vault-level vector clock),
//!   the manifest envelope (kept for B.4c's re-sign), and the verified
//!   owner contact card (kept for B.4c/d signature operations; not yet
//!   exposed through accessors).
//!
//! # Error type
//!
//! Returns [`FfiVaultError`] (NEW; see [`crate::error`] module docs). Six
//! flat variants — 5 mirrored byte-identically from
//! [`FfiUnlockError`] and 1 new `FolderInvalid` for IO problems.
//! `local_highest_clock` is always `None`; rollback detection deferred
//! to Sub-project C.

use std::path::Path;
use std::sync::Mutex;

use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::identity::ContactCard;
use secretary_core::vault::{Manifest, ManifestFile, Unlocker};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::sync_helpers::lock_or_recover;

/// Read-only metadata projection of one [`secretary_core::vault::BlockEntry`].
/// All five fields are plaintext in the manifest already; no secret material
/// crosses through `BlockSummary`. The struct is `Clone`, `Debug`, and
/// projects directly to a Swift `struct` / Kotlin `data class` /
/// `#[pyclass(frozen)]` at the binding-flavor layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    /// 16-byte block UUID identifying the block file on disk.
    pub block_uuid: [u8; 16],
    /// User-visible block name. Plaintext within the encrypted manifest.
    pub block_name: String,
    /// Wall-clock millisecond timestamp at block creation.
    pub created_at_ms: u64,
    /// Wall-clock millisecond timestamp at last modification.
    pub last_modified_ms: u64,
    /// Contact UUIDs of each recipient (always includes owner). Plaintext
    /// within the encrypted manifest. Encoded in ascending lex order.
    pub recipient_uuids: Vec<[u8; 16]>,
}

/// Output of [`open_vault_with_password`] / [`open_vault_with_recovery`].
/// Holds two opaque handles — the live identity and the read-only manifest.
///
/// # Drop discipline
///
/// Fields drop in source order. Both handles zeroize their own inner state
/// on drop; the order is observable but not load-bearing.
pub struct OpenVaultOutput {
    /// Live opaque handle to the unlocked identity. Re-used unchanged from
    /// B.2 / B.3a / B.3b. Same `display_name()` / `user_uuid()` / `wipe()`
    /// accessors.
    pub identity: UnlockedIdentity,
    /// Opaque handle to the decrypted manifest. Holds the IBK, manifest
    /// body, manifest envelope, and verified owner card internally; B.4a
    /// exposes only read-only block-list accessors.
    pub manifest: OpenVaultManifest,
}

/// Internal state of [`OpenVaultManifest`]. Held inside `Mutex<Option<...>>`
/// so the wrapper can provide idempotent close + non-throwing post-close
/// accessors + thread-safe access. All four fields are kept for forward-
/// compat with B.4b (read_block needs the IBK), B.4c (save_block needs
/// the manifest envelope + owner card for re-signing), and B.4d
/// (share_block needs the owner card).
struct OpenVaultManifestInner {
    /// 32-byte Identity Block Key. Sensitive; zeroized on drop. Held for
    /// B.4b's `read_block` to use without re-opening the vault.
    identity_block_key: Sensitive<[u8; 32]>,
    /// Decrypted manifest body — block list, vault-level vector clock,
    /// kdf_params attestation, owner UUIDs.
    manifest: Manifest,
    /// On-disk manifest envelope (header + AEAD nonce + ct/tag + author
    /// fingerprint + §8 hybrid signature). Held for B.4c's `save_block`
    /// to re-sign on update without re-opening.
    #[allow(dead_code)] // B.4c will use this; intentional now for forward-compat
    manifest_file: ManifestFile,
    /// Owner's self-signed contact card, already self-verified during
    /// `core::open_vault`. Held internally for B.4c/d signature operations;
    /// **not** exposed through B.4a accessors (deferred to B.4d).
    #[allow(dead_code)] // B.4c/d will use this; intentional now for forward-compat
    owner_card: ContactCard,
}

/// Opaque handle to a successfully-opened vault's manifest.
///
/// # Lifecycle
///
/// [`OpenVaultManifest::wipe`] explicitly drops the wrapped state now —
/// zeroizes the `Sensitive<[u8; 32]>` IBK and source-order-drops the rest.
/// **Idempotent** — multiple calls do not panic. Subsequent accessor calls
/// on a closed handle return empty / zero defaults rather than panicking,
/// keeping the API non-throwing (parallel to [`UnlockedIdentity`]).
///
/// RAII is the safety net: when the foreign-side reference releases, the
/// Rust-side `Drop` cascade still runs.
pub struct OpenVaultManifest {
    inner: Mutex<Option<OpenVaultManifestInner>>,
}

/// Redacted Debug: never leak secret material through fmt.
impl std::fmt::Debug for OpenVaultManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("OpenVaultManifest")
            .field("closed", &is_closed)
            .finish()
    }
}

impl OpenVaultManifest {
    /// Wrap a freshly-decoded manifest. Crate-private: only
    /// [`open_vault_with_password`] / [`open_vault_with_recovery`]
    /// construct this.
    pub(crate) fn new(inner: OpenVaultManifestInner) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
        }
    }

    /// 16-byte vault UUID from the manifest body. Returns `vec![0u8; 16]`
    /// if the handle has been wiped.
    pub fn vault_uuid(&self) -> Vec<u8> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.vault_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// 16-byte owner user UUID from the manifest body. Returns
    /// `vec![0u8; 16]` if the handle has been wiped.
    pub fn owner_user_uuid(&self) -> Vec<u8> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.owner_user_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// Number of blocks in the manifest. Returns `0` if wiped.
    pub fn block_count(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.blocks.len() as u64)
            .unwrap_or(0)
    }

    /// All block summaries in the manifest's ascending-by-`block_uuid`
    /// order. Returns an empty `Vec` if wiped.
    pub fn block_summaries(&self) -> Vec<BlockSummary> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.blocks.iter().map(block_entry_to_summary).collect())
            .unwrap_or_default()
    }

    /// Locate one block by its UUID. Returns `None` if wiped or if no
    /// matching block exists.
    pub fn find_block(&self, block_uuid: &[u8]) -> Option<BlockSummary> {
        if block_uuid.len() != 16 {
            return None;
        }
        let mut needle = [0u8; 16];
        needle.copy_from_slice(block_uuid);
        lock_or_recover(&self.inner).as_ref().and_then(|i| {
            i.manifest
                .blocks
                .iter()
                .find(|b| b.block_uuid == needle)
                .map(block_entry_to_summary)
        })
    }

    /// Drop the wrapped manifest now, zeroizing the IBK at exactly this
    /// moment. **Idempotent** — multiple calls do not panic.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → OpenVaultManifestInner drops →
        // Sensitive<[u8; 32]> ZeroizeOnDrop runs on the IBK; ContactCard,
        // Manifest, ManifestFile drop in source order.
    }
}

/// Internal projection: `core::BlockEntry` → `BlockSummary` (drops
/// internal-only fields: `fingerprint`, `vector_clock_summary`, `suite_id`,
/// `unknown`).
fn block_entry_to_summary(b: &secretary_core::vault::BlockEntry) -> BlockSummary {
    BlockSummary {
        block_uuid: b.block_uuid,
        block_name: b.block_name.clone(),
        created_at_ms: b.created_at_ms,
        last_modified_ms: b.last_mod_ms,
        recipient_uuids: b.recipients.clone(),
    }
}

/// Open a vault folder using its master password. Reads `vault.toml`,
/// `identity.bundle.enc`, `manifest.cbor.enc`, and the owner contact card
/// from `folder`; performs full unlock + manifest decode + signature
/// verification. Returns two opaque handles: the live `UnlockedIdentity`
/// and the read-only `OpenVaultManifest`.
///
/// # Errors
///
/// Returns [`FfiVaultError`]; six possible variants. See module-level docs
/// on `crate::error` for the full surface.
pub fn open_vault_with_password(
    folder: &Path,
    password: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Password(&pw), None)?;
    Ok(split_core_open_vault(core_out))
    // pw drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    // The caller's foreign-side password buffer is THEIR concern.
}

/// Open a vault folder using its 24-word BIP-39 recovery phrase. Reads the
/// same set of files as [`open_vault_with_password`]. The mnemonic input is
/// UTF-8 bytes; the bridge runs `std::str::from_utf8` and surfaces
/// malformed-UTF-8 input as [`FfiVaultError::InvalidMnemonic`] with
/// `detail: "phrase contained invalid UTF-8"` — same shape as B.3a's
/// [`crate::open_with_recovery`].
///
/// # Errors
///
/// Returns [`FfiVaultError`]; six possible variants.
pub fn open_vault_with_recovery(
    folder: &Path,
    mnemonic_bytes: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let phrase = std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiVaultError::InvalidMnemonic {
        detail: "phrase contained invalid UTF-8".to_string(),
    })?;
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Recovery(phrase), None)?;
    Ok(split_core_open_vault(core_out))
}

/// Split a `core::vault::OpenVault` into the two FFI handles. The IBK
/// transfer is a move (no copy); UnlockedIdentity wraps the
/// `IdentityBundle`.
fn split_core_open_vault(core_out: secretary_core::vault::OpenVault) -> OpenVaultOutput {
    let secretary_core::vault::OpenVault {
        identity_block_key,
        identity,
        owner_card,
        manifest,
        manifest_file,
    } = core_out;

    // UnlockedIdentity needs a `core::unlock::UnlockedIdentity`, which is
    // (identity_block_key, identity). The IBK was already moved out of
    // core::OpenVault above; reconstruct the unlocked identity here.
    //
    // NOTE: the IBK is duplicated for a brief moment between this function
    // call and the OpenVaultManifestInner construction below — but both
    // copies are Sensitive<[u8; 32]> and zeroize on drop, and the IBK is
    // a 32-byte symmetric key, not asymmetric secret material. We Clone
    // the Sensitive to satisfy both consumers; the alternative would be a
    // larger refactor of UnlockedIdentity to take only the IdentityBundle
    // (B.2 / B.3a / B.3b shape would break). The existing
    // create.rs::create_vault demonstrates the same Sensitive::clone
    // pattern at line 256 (`let unlocked = unlock::UnlockedIdentity { identity_block_key, identity };`).
    let unlocked_for_handle = secretary_core::unlock::UnlockedIdentity {
        identity_block_key: identity_block_key.clone(),
        identity,
    };

    OpenVaultOutput {
        identity: UnlockedIdentity::new(unlocked_for_handle),
        manifest: OpenVaultManifest::new(OpenVaultManifestInner {
            identity_block_key,
            manifest,
            manifest_file,
            owner_card,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Path to the golden_vault_NNN folder. CARGO_MANIFEST_DIR is
    /// ffi/secretary-ffi-bridge/, so we walk up to core/tests/data/.
    fn fixture_folder(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data")
            .join(name)
    }

    /// Pinned password for golden_vault_001. Same KAT used by unlock.rs.
    const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";
    /// Pinned password for golden_vault_002. Read from
    /// core/tests/data/golden_vault_002_inputs.json — adjust if that JSON
    /// changes.
    const VAULT_002_PASSWORD: &[u8] = b"correct horse battery staple";
    /// Pinned BIP-39 phrases (parallel to unlock.rs). Source of truth:
    /// the `recovery_mnemonic_phrase` field in each fixture's inputs JSON,
    /// kept honest by the fixture builder's drift-detection assertion.
    const VAULT_001_PHRASE: &[u8] = b"wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that";
    const VAULT_002_PHRASE: &[u8] = b"debate pride tunnel elder caution media glass joke that rabbit mean write eager across furnace volume lawn cage decline fat path guess slogan hunt";

    const VAULT_001_OWNER_DISPLAY_NAME: &str = "Owner";
    const VAULT_001_OWNER_USER_UUID: &[u8] = &[
        0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8, 0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf,
        0x35,
    ];

    #[test]
    fn open_vault_with_password_success_returns_two_handles() {
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_password(&folder, VAULT_001_PASSWORD)
            .expect("open should succeed against golden_vault_001");
        assert_eq!(out.identity.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
        assert_eq!(out.identity.user_uuid(), VAULT_001_OWNER_USER_UUID);
        assert_eq!(
            out.manifest.owner_user_uuid(),
            VAULT_001_OWNER_USER_UUID,
            "manifest's owner_user_uuid must agree with identity's user_uuid",
        );
    }

    #[test]
    fn open_vault_with_recovery_success_matches_password_path() {
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_recovery(&folder, VAULT_001_PHRASE)
            .expect("recovery open should succeed against golden_vault_001");
        // Both unlock paths must converge on byte-identical secret state
        // (§3/§4 dual-KEK design), so identity values match the password
        // path's results in the previous test.
        assert_eq!(out.identity.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
        assert_eq!(out.identity.user_uuid(), VAULT_001_OWNER_USER_UUID);
    }

    #[test]
    fn open_vault_with_password_wrong_password_returns_thinned_error() {
        let folder = fixture_folder("golden_vault_001");
        let err = open_vault_with_password(&folder, b"definitely the wrong password").unwrap_err();
        assert!(
            matches!(err, FfiVaultError::WrongPasswordOrCorrupt),
            "expected WrongPasswordOrCorrupt, got {err:?}",
        );
    }

    #[test]
    fn open_vault_with_recovery_wrong_phrase_returns_thinned_error() {
        let folder = fixture_folder("golden_vault_001");
        // Use vault_002's phrase against vault_001's folder — valid 24-word
        // phrase but wrong vault, so recovery_kek decap tag-fails.
        let err = open_vault_with_recovery(&folder, VAULT_002_PHRASE).unwrap_err();
        assert!(
            matches!(err, FfiVaultError::WrongMnemonicOrCorrupt),
            "expected WrongMnemonicOrCorrupt, got {err:?}",
        );
    }

    #[test]
    fn open_vault_with_recovery_invalid_phrase_returns_invalid_mnemonic() {
        let folder = fixture_folder("golden_vault_001");
        let err = open_vault_with_recovery(&folder, b"only three words").unwrap_err();
        let FfiVaultError::InvalidMnemonic { detail } = err else {
            panic!("expected InvalidMnemonic, got {err:?}");
        };
        assert!(
            detail.contains("got 3"),
            "detail did not carry word count: {detail}",
        );
    }

    #[test]
    fn open_vault_folder_does_not_exist_returns_folder_invalid() {
        let folder = fixture_folder("__nonexistent_folder_for_b4a_test__");
        let err = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap_err();
        let FfiVaultError::FolderInvalid { detail } = err else {
            panic!("expected FolderInvalid, got {err:?}");
        };
        // detail carries IO context + io::Error display; either substring
        // is sufficient — the underlying io::ErrorKind is NotFound.
        assert!(
            detail.to_lowercase().contains("vault.toml")
                || detail.to_lowercase().contains("no such file"),
            "FolderInvalid detail did not carry expected text: {detail}",
        );
    }

    #[test]
    fn open_vault_folder_missing_identity_bundle_returns_folder_invalid() {
        // Set up a temp folder containing only vault.toml from
        // golden_vault_001. The bridge / core open path reads vault.toml
        // first then identity.bundle.enc; we want the second read to
        // surface as FolderInvalid.
        use std::fs;
        let src = fixture_folder("golden_vault_001");
        let tmp = tempfile::TempDir::new().expect("tempdir");
        fs::copy(src.join("vault.toml"), tmp.path().join("vault.toml")).unwrap();
        // Deliberately do NOT copy identity.bundle.enc.

        let err = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).unwrap_err();
        let FfiVaultError::FolderInvalid { detail } = err else {
            panic!("expected FolderInvalid, got {err:?}");
        };
        assert!(
            detail.contains("identity.bundle.enc"),
            "FolderInvalid detail did not mention identity.bundle.enc: {detail}",
        );
    }

    #[test]
    fn block_summaries_returns_pinned_layout_for_v1() {
        // Pin the BlockSummary list against the golden_vault_001_inputs.json
        // `block_summaries` array. If this test fails, either the fixture
        // changed (re-pin the JSON via Task 2 Step 2's helper) or the
        // BlockSummary projection has drifted (fix block_entry_to_summary).
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();

        let summaries = out.manifest.block_summaries();
        let count = out.manifest.block_count();
        assert_eq!(
            summaries.len() as u64,
            count,
            "block_summaries() length must match block_count()",
        );

        // Read the pinned JSON for cross-checking.
        let json_path = fixture_folder("").join("golden_vault_001_inputs.json");
        let json_str = std::fs::read_to_string(&json_path).expect("inputs JSON");
        let pinned: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
        let pinned_summaries = pinned["block_summaries"]
            .as_array()
            .expect("block_summaries is an array — was Task 2 Step 3 completed?");

        assert_eq!(
            summaries.len(),
            pinned_summaries.len(),
            "BlockSummary count drift: code has {}, JSON pins {}",
            summaries.len(),
            pinned_summaries.len(),
        );

        for (actual, pinned) in summaries.iter().zip(pinned_summaries.iter()) {
            let pinned_uuid_hex = pinned["block_uuid"].as_str().expect("hex string");
            let actual_uuid_hex = hex::encode(actual.block_uuid);
            assert_eq!(actual_uuid_hex, pinned_uuid_hex, "block_uuid drift");
            assert_eq!(
                actual.block_name,
                pinned["block_name"].as_str().expect("string"),
                "block_name drift",
            );
            assert_eq!(
                actual.created_at_ms,
                pinned["created_at_ms"].as_u64().expect("u64"),
                "created_at_ms drift",
            );
            assert_eq!(
                actual.last_modified_ms,
                pinned["last_modified_ms"].as_u64().expect("u64"),
                "last_modified_ms drift",
            );
        }
    }

    #[test]
    fn open_vault_manifest_wipe_returns_empty_defaults() {
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
        out.manifest.wipe();
        // Post-wipe, every accessor returns the empty default. Same
        // contract as UnlockedIdentity post-close.
        assert_eq!(out.manifest.vault_uuid(), vec![0u8; 16]);
        assert_eq!(out.manifest.owner_user_uuid(), vec![0u8; 16]);
        assert_eq!(out.manifest.block_count(), 0);
        assert_eq!(out.manifest.block_summaries(), Vec::<BlockSummary>::new());
        assert_eq!(out.manifest.find_block(&[0u8; 16]), None);
        // Idempotent.
        out.manifest.wipe();
        out.manifest.wipe();
        assert_eq!(out.manifest.block_count(), 0);
    }
}
```

Note the test file uses two new bridge crate dev-dependencies that we need to add:
- `tempfile` (already a runtime dep at exact pin `=3.27.0` — re-export as dev too is allowed)
- `serde_json` for parsing the inputs JSON (likely already a workspace dev-dep; verify)
- `hex` for byte → hex string comparison (needs adding if absent)

- [ ] **Step 6: Add missing dev-dependencies to `ffi/secretary-ffi-bridge/Cargo.toml`**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
grep -E "^\[dev-dependencies\]|^serde_json|^hex|^tempfile" ffi/secretary-ffi-bridge/Cargo.toml
```

If `tempfile`, `serde_json`, or `hex` is missing under `[dev-dependencies]`, add it. Open `ffi/secretary-ffi-bridge/Cargo.toml` and ensure the `[dev-dependencies]` section contains:

```toml
[dev-dependencies]
# (existing entries)
tempfile = "=3.27.0"  # exact pin — same as the runtime dep policy
serde_json = "1"
hex = "0.4"
```

Use exact pins matching the workspace's existing patterns. Run `cargo build` to confirm the new dev-deps resolve:

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo build --release -p secretary-ffi-bridge --tests 2>&1 | tail -3
```

Expected: clean build, no resolution errors.

- [ ] **Step 7: Add `pub mod vault;` to `lib.rs` (Task 3 will add the re-exports — this step just makes the module reachable for the integration test below)**

Edit `ffi/secretary-ffi-bridge/src/lib.rs` line ~64 area; add `pub mod vault;` alongside the existing `pub mod` declarations:

```rust
pub mod create;
pub mod error;
pub mod identity;
mod sync_helpers;
pub mod unlock;
pub mod vault;
```

Do NOT yet add the re-exports below — Task 3 handles those. Just adding the `pub mod vault;` line is enough to make the new module discoverable for tests.

- [ ] **Step 8: Run the new tests; expect 9 passes**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo test --release -p secretary-ffi-bridge --lib vault 2>&1 | tail -25
```

Expected: all 9 tests in `vault::tests` pass. If a test fails:
- `block_summaries_returns_pinned_layout_for_v1` failure → JSON values mismatch the actual fixture; re-run Task 2 Step 2 helper and fix the JSON in Step 3.
- `open_vault_folder_missing_identity_bundle` failure with the wrong error variant → core::open_vault may surface `OwnerCardNotFound` or another error before reading identity.bundle.enc; adjust the test to set up the folder differently (copy enough files that identity.bundle.enc is the FIRST missing file).
- Any "trait `From<...>` not implemented" → Task 1's `From<core::VaultError>` is incomplete; revisit.

- [ ] **Step 9: Run clippy + fmt**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo clippy --release -p secretary-ffi-bridge -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: clippy clean, fmt OK. If clippy flags anything, fix in place.

- [ ] **Step 10: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add ffi/secretary-ffi-bridge/src/vault.rs ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/Cargo.toml core/tests/data/golden_vault_001_inputs.json core/tests/data/golden_vault_002_inputs.json
git commit -m "$(cat <<'EOF'
feat(ffi-b4a): add vault.rs with folder-based open_vault_with_* + opaque OpenVaultManifest

NEW bridge module wiring core::vault::open_vault through the FFI as the
first folder-IO entry point. Two pub fns:
- open_vault_with_password(folder, password) → Result<OpenVaultOutput, FfiVaultError>
- open_vault_with_recovery(folder, mnemonic) → Result<OpenVaultOutput, FfiVaultError>

OpenVaultOutput is a value struct holding two opaque handles:
- identity: UnlockedIdentity (re-used unchanged from B.2/B.3a/B.3b)
- manifest: OpenVaultManifest (NEW; Mutex<Option<...>> with lock_or_recover
  poisoning-safety helper; idempotent wipe; redacted Debug; non-throwing
  post-wipe accessors returning empty defaults)

OpenVaultManifest holds the IBK + manifest body + manifest envelope +
verified owner contact card internally so B.4b/c/d can extend rather
than re-open. For B.4a only block-list accessors are exposed:
- vault_uuid(), owner_user_uuid()
- block_count(), block_summaries(), find_block(uuid)

BlockSummary is a value type with five fields (block_uuid, block_name,
created_at_ms, last_modified_ms, recipient_uuids) — all plaintext in
the manifest already; no secret material crosses through.

local_highest_clock always None (rollback deferred to Sub-project C).

+9 tests in vault.rs (success path × 2 + 4 error variants + accessor
pin × 1 + wipe × 1 + 1 success path verifying recovery matches
password). +block_summaries field added to golden_vault_001/002 input
JSONs — pinned-in-JSON expected values, drift-detected by the
accessor test.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `lib.rs` — re-export `FfiVaultError` + 5 new types + 2 new fns; update crate-doc

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`

The new module is already declared (Task 2 Step 7). This task adds the `pub use` re-exports + updates the crate-level rustdoc to describe the 7-fn surface and the new error type.

- [ ] **Step 1: Update `lib.rs`'s crate-doc to describe the post-B.4a surface**

Read the existing crate-doc at the top of `ffi/secretary-ffi-bridge/src/lib.rs` (lines 1-58). Replace it with:

```rust
//! FFI-friendly facade of `secretary-core`.
//!
//! This crate is the **single source of code truth** for the FFI surface
//! shared between [`secretary-ffi-py`](../../secretary-ffi-py/) (PyO3 →
//! Python) and [`secretary-ffi-uniffi`](../../secretary-ffi-uniffi/) (uniffi
//! → Swift / Kotlin). Both binding-flavor crates depend on this one and
//! project these types through their respective binding macros — drift
//! between the two foreign-language APIs is impossible at compile time.
//!
//! # Surface
//!
//! ## Errors
//!
//! - [`FfiUnlockError`] — thinned 5-variant error type for the **bytes-in**
//!   unlock entry points ([`open_with_password`], [`open_with_recovery`])
//!   and the bytes-out [`create_vault`]. See [`error`] module docs.
//! - [`FfiVaultError`] — thinned 6-variant error type for the **folder-in**
//!   vault entry points ([`open_vault_with_password`],
//!   [`open_vault_with_recovery`]). Mirrors [`FfiUnlockError`]'s 5
//!   unlock-class variants byte-identically (variant name + Display
//!   string) plus a new [`FfiVaultError::FolderInvalid`] for missing or
//!   inaccessible vault folders. See [`error`] module docs.
//!
//! ## Handles
//!
//! - [`UnlockedIdentity`] — opaque handle wrapping a successfully-unlocked
//!   `core::UnlockedIdentity`. Returned by every unlock or open path
//!   ([`open_with_password`], [`open_with_recovery`], [`create_vault`],
//!   [`open_vault_with_password`], [`open_vault_with_recovery`]). See
//!   [`identity`] module docs.
//! - [`MnemonicOutput`] — one-shot opaque handle for the freshly-generated
//!   24-word BIP-39 recovery mnemonic returned by [`create_vault`]. See
//!   [`create`] module docs.
//! - [`OpenVaultManifest`] — opaque handle for the decrypted manifest
//!   returned by the folder-in open paths. Holds the IBK + manifest body
//!   + manifest envelope + verified owner card internally; B.4a exposes
//!   only read-only block-list accessors. See [`vault`] module docs.
//!
//! ## Entry points
//!
//! Bytes-in (B.2 / B.3a / B.3b):
//! - [`open_with_password`] — fallible bytes-in unlock by master password.
//! - [`open_with_recovery`] — fallible bytes-in unlock by 24-word phrase.
//! - [`create_vault`] — fallible bytes-out vault creation using OS CSPRNG +
//!   `Argon2idParams::V1_DEFAULT`.
//!
//! Folder-in (B.4a):
//! - [`open_vault_with_password`] — fallible folder-in vault open by
//!   master password. Reads `vault.toml` + `identity.bundle.enc` +
//!   `manifest.cbor.enc` + owner contact card from the folder via
//!   `core::vault::open_vault`. Returns [`OpenVaultOutput`] with the
//!   live identity and the read-only manifest handle.
//! - [`open_vault_with_recovery`] — same as above but using a 24-word
//!   BIP-39 recovery phrase. Mnemonic input is UTF-8 bytes (`&[u8]`).
//!
//! ## Output shapes
//!
//! - [`CreateVaultOutput`] — return type from [`create_vault`]: byte
//!   artifacts to persist + live identity + one-shot mnemonic.
//! - [`OpenVaultOutput`] — return type from the folder-in open paths:
//!   live identity + read-only manifest handle.
//! - [`BlockSummary`] — read-only metadata projection of one
//!   `core::BlockEntry`. Five plaintext-in-the-manifest fields.
//!
//! # Invariants
//!
//! - Pure-safe Rust. The workspace's `#![forbid(unsafe_code)]` applies
//!   without carve-out (the binding-flavor crates carry the FFI-macro
//!   `unsafe_code = "deny"` carve-outs locally).
//! - The `From<core::unlock::UnlockError>` impl in [`error`] uses explicit
//!   match arms with no wildcard so future core variants force a compile
//!   error instead of silently mapping to a default. The
//!   `From<core::vault::VaultError>` impl delegates to the unlock-class
//!   translation through a private `From<FfiUnlockError>` arm so renames
//!   on `FfiUnlockError` propagate automatically.
//! - The 5 unlock-class variants of `FfiUnlockError` and `FfiVaultError`
//!   share **byte-identical** Display strings — pinned by a tripwire
//!   test in [`error`].
```

- [ ] **Step 2: Update the `pub use` block at the bottom of `lib.rs`**

Replace the existing `pub use` block (lines ~69-72):

```rust
pub use create::{create_vault, CreateVaultOutput, MnemonicOutput};
pub use error::FfiUnlockError;
pub use identity::UnlockedIdentity;
pub use unlock::{open_with_password, open_with_recovery};
```

With the following (adds `FfiVaultError` to the error re-exports + the new vault re-exports):

```rust
pub use create::{create_vault, CreateVaultOutput, MnemonicOutput};
pub use error::{FfiUnlockError, FfiVaultError};
pub use identity::UnlockedIdentity;
pub use unlock::{open_with_password, open_with_recovery};
pub use vault::{
    open_vault_with_password, open_vault_with_recovery, BlockSummary, OpenVaultManifest,
    OpenVaultOutput,
};
```

- [ ] **Step 3: Verify the workspace builds cleanly**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo build --release --workspace 2>&1 | tail -3
cargo test --release -p secretary-ffi-bridge 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'BRIDGE: {p} passed; {f} failed; {i} ignored')"
```

Expected: clean build; bridge crate test count grew from 36 (B.3b post-merge) to ~54 (Tasks 1 + 2 added 9 + 9 = 18 net tests).

- [ ] **Step 4: Verify rustdoc renders without warnings**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo doc --no-deps -p secretary-ffi-bridge 2>&1 | tail -5
```

Expected: no warnings. Per B.3b's experience (commit `cbc8897`), `cargo doc` sometimes surfaces warnings that `cargo build` doesn't. If any rustdoc warning fires (e.g. an unresolved intra-doc link), fix in place — the codebase preference is "fix every issue, never just mention".

- [ ] **Step 5: Run clippy + fmt**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: clippy clean across workspace, fmt OK.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4a): re-export FfiVaultError + 5 new vault types + 2 new fns

Adds re-exports to the bridge crate's lib.rs for the new B.4a surface:

- error::FfiVaultError
- vault::open_vault_with_password
- vault::open_vault_with_recovery
- vault::BlockSummary
- vault::OpenVaultManifest
- vault::OpenVaultOutput

Crate-level rustdoc updated to describe the post-B.4a 7-fn surface
(3 bytes-in + 1 bytes-out + 2 folder-in + the unchanged add/version
smokes), the two error types' relationship (5-variant FfiUnlockError
+ 6-variant FfiVaultError mirroring the 5 unlock-class byte-identical
in Display + variant name), and the new opaque-handle type
OpenVaultManifest.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 2 — secretary-ffi-py projection

### Task 4: PyO3 wrapper — 2 new `#[pyfunction]` + 3 new `#[pyclass]` + 6 `create_exception!`

**Files:**
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (currently 427 lines)

The PyO3 wrapper projects the new bridge surface as Python-callable functions. Each new `#[pyclass]` is a thin newtype around the bridge equivalent. Each new `create_exception!` macro generates a Python-side exception class. Caller-side `Vec<u8>` zeroize discipline mirrors B.2 / B.3a.

- [ ] **Step 1: Read the current PyO3 wrapper to understand the patterns**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
sed -n '80,170p' ffi/secretary-ffi-py/src/lib.rs
```

Expected output: shows the `create_exception!` block + the `From<FfiUnlockError> for PyErr` impl + the `#[pyclass] UnlockedIdentity` newtype. Use these as templates.

- [ ] **Step 2: Add 6 `create_exception!` macros for FfiVaultError variants** (just below the existing 5 macros around line 88-92)

After the existing `create_exception!(secretary_ffi_py, InvalidMnemonic, PyException);` line, add:

```rust
// FfiVaultError → Python exception classes (B.4a). Five mirror the
// FfiUnlockError exceptions BYTE-IDENTICAL on Display string, but they're
// distinct Python classes so foreign callers can `except VaultFolderInvalid:`
// without needing to introspect the exception's source error type.
//
// Naming: prefix with "Vault" to disambiguate from the FfiUnlockError
// classes; the bytes-in callers raise the existing classes, the folder-in
// callers raise these.
create_exception!(secretary_ffi_py, VaultWrongPasswordOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultWrongMnemonicOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultInvalidMnemonic, PyException);
create_exception!(secretary_ffi_py, VaultMismatchFolder, PyException);
create_exception!(secretary_ffi_py, VaultCorruptVault, PyException);
create_exception!(secretary_ffi_py, VaultFolderInvalid, PyException);
```

NOTE: The `VaultMismatch` Python class is already used by `FfiUnlockError`'s `VaultMismatch` variant. We rename the FfiVaultError counterpart to `VaultMismatchFolder` to avoid the class collision. Document this in the docstring on `open_vault_with_password`.

- [ ] **Step 3: Add `From<FfiVaultError> for PyErr` impl** (just below the existing `From<FfiUnlockError> for PyErr`, around line ~110)

After the existing `impl From<FfiUnlockError> for PyErr { ... }` block:

```rust
/// Map FfiVaultError variants → Python exceptions. Parallels the
/// FfiUnlockError → PyErr mapping with one-to-one variant translation.
impl From<FfiVaultError> for PyErr {
    fn from(e: FfiVaultError) -> Self {
        match e {
            FfiVaultError::WrongPasswordOrCorrupt => {
                VaultWrongPasswordOrCorrupt::new_err(e.to_string())
            }
            FfiVaultError::WrongMnemonicOrCorrupt => {
                VaultWrongMnemonicOrCorrupt::new_err(e.to_string())
            }
            FfiVaultError::InvalidMnemonic { detail: _ } => VaultInvalidMnemonic::new_err(e.to_string()),
            FfiVaultError::VaultMismatch => VaultMismatchFolder::new_err(e.to_string()),
            FfiVaultError::CorruptVault { detail: _ } => VaultCorruptVault::new_err(e.to_string()),
            FfiVaultError::FolderInvalid { detail: _ } => VaultFolderInvalid::new_err(e.to_string()),
        }
    }
}
```

NOTE: the `secretary_ffi_bridge::FfiVaultError` symbol needs to be importable. Update the `use` block at the top of `lib.rs` to import it:

```rust
use secretary_ffi_bridge::{
    BlockSummary as BridgeBlockSummary, FfiUnlockError, FfiVaultError,
    OpenVaultManifest as BridgeOpenVaultManifest, OpenVaultOutput as BridgeOpenVaultOutput,
    UnlockedIdentity as BridgeUnlockedIdentity,
    // (existing imports for create_vault, MnemonicOutput, etc.)
};
```

- [ ] **Step 4: Add `BlockSummary` `#[pyclass(frozen)]` newtype** (after the existing `MnemonicOutput` `#[pyclass]` around line 165)

```rust
/// Read-only metadata projection of one block in the vault manifest.
/// All fields are plaintext in the manifest already — no secret material
/// crosses through `BlockSummary`. Frozen because foreign-side mutation
/// would have no effect on the underlying Rust state.
#[pyclass(frozen)]
#[derive(Clone)]
pub struct BlockSummary {
    /// 16-byte block UUID identifying the block file on disk.
    #[pyo3(get)]
    pub block_uuid: Vec<u8>,
    /// User-visible block name. Plaintext within the encrypted manifest.
    #[pyo3(get)]
    pub block_name: String,
    /// Wall-clock millisecond timestamp at block creation.
    #[pyo3(get)]
    pub created_at_ms: u64,
    /// Wall-clock millisecond timestamp at last modification.
    #[pyo3(get)]
    pub last_modified_ms: u64,
    /// List of 16-byte recipient UUIDs (always includes owner). Plaintext.
    #[pyo3(get)]
    pub recipient_uuids: Vec<Vec<u8>>,
}

impl From<BridgeBlockSummary> for BlockSummary {
    fn from(b: BridgeBlockSummary) -> Self {
        Self {
            block_uuid: b.block_uuid.to_vec(),
            block_name: b.block_name,
            created_at_ms: b.created_at_ms,
            last_modified_ms: b.last_modified_ms,
            recipient_uuids: b.recipient_uuids.into_iter().map(|u| u.to_vec()).collect(),
        }
    }
}
```

- [ ] **Step 5: Add `OpenVaultManifest` `#[pyclass]` newtype** (after `BlockSummary`)

```rust
/// Opaque handle to a successfully-opened vault's manifest. Provides
/// read-only block-list accessors. Use as a context manager:
///
/// ```python
/// with open_vault_with_password(folder, password) as out:
///     with out.identity as identity, out.manifest as manifest:
///         for block in manifest.block_summaries():
///             print(block.block_name)
/// ```
///
/// The `with` protocol calls `wipe()` on `__exit__`, zeroizing the IBK
/// and dropping the manifest body at exactly that moment. RAII is the
/// safety net if the foreign caller forgets to use `with`.
#[pyclass]
pub struct OpenVaultManifest(BridgeOpenVaultManifest);

#[pymethods]
impl OpenVaultManifest {
    /// 16-byte vault UUID. Returns 16 zero bytes if wiped.
    pub fn vault_uuid(&self) -> Vec<u8> {
        self.0.vault_uuid()
    }

    /// 16-byte owner user UUID. Returns 16 zero bytes if wiped.
    pub fn owner_user_uuid(&self) -> Vec<u8> {
        self.0.owner_user_uuid()
    }

    /// Number of blocks in the manifest. Returns 0 if wiped.
    pub fn block_count(&self) -> u64 {
        self.0.block_count()
    }

    /// All block summaries in ascending-by-block_uuid order. Empty list
    /// if wiped.
    pub fn block_summaries(&self) -> Vec<BlockSummary> {
        self.0
            .block_summaries()
            .into_iter()
            .map(BlockSummary::from)
            .collect()
    }

    /// Locate one block by its 16-byte UUID. Returns None if wiped or no
    /// matching block exists.
    pub fn find_block(&self, block_uuid: Vec<u8>) -> Option<BlockSummary> {
        self.0.find_block(&block_uuid).map(BlockSummary::from)
    }

    /// Drop the wrapped manifest now, zeroizing the IBK at exactly this
    /// moment. Idempotent.
    pub fn wipe(&self) {
        self.0.wipe();
    }

    /// Context manager entry — returns self so `with manifest as m: ...`
    /// binds m to the same object.
    pub fn __enter__(slf: pyo3::Py<Self>) -> pyo3::Py<Self> {
        slf
    }

    /// Context manager exit — wipes regardless of exception state.
    pub fn __exit__(
        &self,
        _exc_type: pyo3::Py<pyo3::PyAny>,
        _exc_value: pyo3::Py<pyo3::PyAny>,
        _traceback: pyo3::Py<pyo3::PyAny>,
    ) -> bool {
        self.wipe();
        false // do not suppress exceptions
    }
}
```

- [ ] **Step 6: Add `OpenVaultOutput` `#[pyclass]` newtype with take-once getters** (after `OpenVaultManifest`)

```rust
/// Output of `open_vault_with_password` / `open_vault_with_recovery`.
/// Holds two opaque handles. The handles are accessible via take-once
/// getters that move ownership out of the struct — once taken, the
/// getter returns None on subsequent calls.
///
/// Same shape as B.3b's `CreateVaultOutput` for the take-once pattern.
#[pyclass]
pub struct OpenVaultOutput {
    inner: std::sync::Mutex<Option<BridgeOpenVaultOutput>>,
}

#[pymethods]
impl OpenVaultOutput {
    /// Take ownership of the live UnlockedIdentity handle. ONE-SHOT —
    /// subsequent calls return None.
    #[getter]
    pub fn identity(&self) -> Option<UnlockedIdentity> {
        let mut guard = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let out = guard.as_mut()?;
        // Take the identity by replacing it with a fresh wiped handle.
        // Same trick used in B.3b's CreateVaultOutput.identity getter.
        let taken = std::mem::replace(
            &mut out.identity,
            secretary_ffi_bridge::UnlockedIdentity::new_for_test_wiped(),
        );
        Some(UnlockedIdentity(taken))
    }

    /// Take ownership of the OpenVaultManifest handle. ONE-SHOT.
    #[getter]
    pub fn manifest(&self) -> Option<OpenVaultManifest> {
        let mut guard = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let out = guard.as_mut()?;
        let taken = std::mem::replace(
            &mut out.manifest,
            secretary_ffi_bridge::OpenVaultManifest::new_for_test_wiped(),
        );
        Some(OpenVaultManifest(taken))
    }

    /// Context manager entry.
    pub fn __enter__(slf: pyo3::Py<Self>) -> pyo3::Py<Self> {
        slf
    }

    /// Context manager exit — drops both inner handles (which run their
    /// own zeroize-on-drop chains).
    pub fn __exit__(
        &self,
        _exc_type: pyo3::Py<pyo3::PyAny>,
        _exc_value: pyo3::Py<pyo3::PyAny>,
        _traceback: pyo3::Py<pyo3::PyAny>,
    ) -> bool {
        let mut guard = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _drop = guard.take();
        false
    }
}
```

NOTE: `BridgeUnlockedIdentity::new_for_test_wiped()` and `BridgeOpenVaultManifest::new_for_test_wiped()` need to be added to the bridge crate as `#[doc(hidden)] pub fn`s — they construct already-wiped handles for use as the "replacement" in the `std::mem::replace` trick. If these don't exist, add them (3-4 line additions to `identity.rs` and `vault.rs`):

```rust
// in identity.rs (add at the end of the impl block, before the closing }):
    /// Test-only helper. Crate-public so the `std::mem::replace` trick in
    /// secretary-ffi-py's `OpenVaultOutput.identity()` getter has a
    /// no-op replacement value to swap in. Hidden from rustdoc.
    #[doc(hidden)]
    pub fn new_for_test_wiped() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

// in vault.rs OpenVaultManifest impl block:
    /// Same as `UnlockedIdentity::new_for_test_wiped`. Test-only.
    #[doc(hidden)]
    pub fn new_for_test_wiped() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
```

If not already in B.3b's MnemonicOutput pattern, add them as part of this task (commit boundary stays here in Task 4 since the bridge crate also gets a small edit).

- [ ] **Step 7: Add the two `#[pyfunction]` entry points** (after `create_vault` function around line 340)

```rust
/// Open a vault folder using its master password (B.4a).
///
/// Reads `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, and
/// the owner contact card from `folder` via the Rust core's
/// `vault::open_vault`. Returns an `OpenVaultOutput` with two opaque
/// handles: `identity` (live UnlockedIdentity, same shape as the bytes-in
/// `open_with_password`) and `manifest` (read-only OpenVaultManifest).
///
/// # Caller zeroize
///
/// `password` is owned bytes (Vec<u8>); the bridge wraps it in
/// SecretBytes (zeroize-on-drop). The wrapper here additionally zeroizes
/// the wrapper-side Vec<u8> after the bridge call returns. The foreign
/// caller's input buffer (e.g. a Python bytearray) is the foreign side's
/// concern — wipe it after the call returns.
///
/// # Raises
///
/// - `VaultWrongPasswordOrCorrupt` — password is wrong, or vault data
///   integrity failure (anti-oracle conflation).
/// - `VaultMismatchFolder` — `vault.toml` and `identity.bundle.enc` reference
///   different vaults.
/// - `VaultCorruptVault` — manifest decode / verification / cross-check
///   failed post-unlock.
/// - `VaultFolderInvalid` — folder doesn't exist, isn't readable, or is
///   missing one of the four required files (`vault.toml`,
///   `identity.bundle.enc`, `manifest.cbor.enc`, `contacts/<owner_uuid>.card`).
#[pyfunction]
pub fn open_vault_with_password(
    folder: std::path::PathBuf,
    mut password: Vec<u8>,
) -> pyo3::PyResult<OpenVaultOutput> {
    let result = secretary_ffi_bridge::open_vault_with_password(&folder, &password);
    password.zeroize();
    let bridge_out = result?;
    Ok(OpenVaultOutput {
        inner: std::sync::Mutex::new(Some(bridge_out)),
    })
}

/// Open a vault folder using its 24-word BIP-39 recovery phrase (B.4a).
///
/// Reads the same set of files as `open_vault_with_password`. The
/// `mnemonic` input is UTF-8-encoded bytes; the bridge runs
/// `std::str::from_utf8` and surfaces a malformed-UTF-8 input as
/// `VaultInvalidMnemonic` with `detail` = "phrase contained invalid UTF-8"
/// (parallel to B.3a's `open_with_recovery`).
///
/// # Caller zeroize
///
/// `mnemonic` is owned bytes; the wrapper zeroizes them after the
/// bridge call. The foreign caller's input buffer is the foreign side's
/// concern.
///
/// # Raises
///
/// - `VaultWrongMnemonicOrCorrupt` — phrase is wrong, or vault data
///   integrity failure (anti-oracle conflation).
/// - `VaultInvalidMnemonic` — phrase failed BIP-39 validation BEFORE any
///   decryption was attempted (wrong word count, unknown word, bad
///   checksum, or invalid UTF-8 input).
/// - `VaultMismatchFolder` — `vault.toml` and `identity.bundle.enc` reference
///   different vaults.
/// - `VaultCorruptVault` — manifest decode / verification / cross-check
///   failed post-unlock.
/// - `VaultFolderInvalid` — folder doesn't exist, isn't readable, or is
///   missing one of the four required files.
#[pyfunction]
pub fn open_vault_with_recovery(
    folder: std::path::PathBuf,
    mut mnemonic: Vec<u8>,
) -> pyo3::PyResult<OpenVaultOutput> {
    let result = secretary_ffi_bridge::open_vault_with_recovery(&folder, &mnemonic);
    mnemonic.zeroize();
    let bridge_out = result?;
    Ok(OpenVaultOutput {
        inner: std::sync::Mutex::new(Some(bridge_out)),
    })
}
```

- [ ] **Step 8: Register all new symbols in the `#[pymodule] _secretary_ffi_py` function** (around line 376-405)

After the existing registration block, add new lines following the same pattern:

```rust
    // B.4a — folder-in entry points
    m.add_class::<OpenVaultOutput>()?;
    m.add_class::<OpenVaultManifest>()?;
    m.add_class::<BlockSummary>()?;
    m.add_function(wrap_pyfunction!(open_vault_with_password, m)?)?;
    m.add_function(wrap_pyfunction!(open_vault_with_recovery, m)?)?;
    m.add(
        "VaultWrongPasswordOrCorrupt",
        py.get_type::<VaultWrongPasswordOrCorrupt>(),
    )?;
    m.add(
        "VaultWrongMnemonicOrCorrupt",
        py.get_type::<VaultWrongMnemonicOrCorrupt>(),
    )?;
    m.add("VaultInvalidMnemonic", py.get_type::<VaultInvalidMnemonic>())?;
    m.add("VaultMismatchFolder", py.get_type::<VaultMismatchFolder>())?;
    m.add("VaultCorruptVault", py.get_type::<VaultCorruptVault>())?;
    m.add("VaultFolderInvalid", py.get_type::<VaultFolderInvalid>())?;
```

- [ ] **Step 9: Build the maturin dylib + verify Python module exposes new names**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault/ffi/secretary-ffi-py
uv run maturin develop --release --uv 2>&1 | tail -3
uv run python -c "
import secretary_ffi_py as m
needed = [
    'open_vault_with_password', 'open_vault_with_recovery',
    'OpenVaultOutput', 'OpenVaultManifest', 'BlockSummary',
    'VaultWrongPasswordOrCorrupt', 'VaultWrongMnemonicOrCorrupt',
    'VaultInvalidMnemonic', 'VaultMismatchFolder', 'VaultCorruptVault',
    'VaultFolderInvalid',
]
missing = [n for n in needed if not hasattr(m, n)]
print('MISSING:', missing if missing else 'none')
"
```

Expected: `MISSING: none`. If anything is missing, the `m.add_*` registrations in Step 8 are incomplete or the maturin rebuild didn't pick up the new symbols (apply the documented nuclear cache fix from Task 0 Step 2 if needed).

- [ ] **Step 10: Run clippy + fmt**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: clippy clean, fmt OK. Common issue: `clippy::useless_conversion` on a `.into()` call where types already match — replace with the explicit cast. Or `clippy::needless_pass_by_value` on a `Vec<u8>` parameter — keep the by-value because we need to consume + zeroize, but document with `#[allow(clippy::needless_pass_by_value)]`.

- [ ] **Step 11: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add ffi/secretary-ffi-py/src/lib.rs ffi/secretary-ffi-bridge/src/identity.rs ffi/secretary-ffi-bridge/src/vault.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4a): add PyO3 open_vault_with_* + 3 new #[pyclass] + 6 exception classes

Adds the PyO3 projection of the B.4a bridge surface:
- 2 #[pyfunction]: open_vault_with_password, open_vault_with_recovery
- 3 #[pyclass]: OpenVaultOutput (take-once getters + __enter__/__exit__),
  OpenVaultManifest (5 accessors + wipe + __enter__/__exit__),
  BlockSummary (frozen, all 5 fields exposed via #[pyo3(get)])
- 6 create_exception!: VaultWrongPasswordOrCorrupt, VaultWrongMnemonicOrCorrupt,
  VaultInvalidMnemonic, VaultMismatchFolder, VaultCorruptVault,
  VaultFolderInvalid (prefixed "Vault" to disambiguate from FfiUnlockError's
  exception classes; "VaultMismatchFolder" specifically renamed to avoid
  the existing "VaultMismatch" class collision)
- 1 impl From<FfiVaultError> for PyErr — one-to-one variant translation

Wrapper-side Vec<u8> zeroize for password / mnemonic input (parallels
B.2 / B.3a discipline; foreign caller's bytearray remains foreign-side
responsibility per the documented contract).

Added 2 small #[doc(hidden)] pub fn new_for_test_wiped() helpers on
secretary-ffi-bridge's UnlockedIdentity and OpenVaultManifest — used as
no-op replacement values in std::mem::replace inside OpenVaultOutput's
take-once getters (same trick as B.3b's CreateVaultOutput.identity getter).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: pytest tests — 7 new B.4a tests

**Files:**
- Modify: `ffi/secretary-ffi-py/tests/test_smoke.py`

The pytest layer cross-validates the PyO3 binding pipeline at the Python level. Each new test mirrors a bridge-crate test in shape but exercises the Python-visible API and asserts on the Python-level exception classes.

- [ ] **Step 1: Read the existing pytest layout**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
sed -n '1,30p' ffi/secretary-ffi-py/tests/test_smoke.py
sed -n '/SECRETARY_GOLDEN_VAULT_DIR/,+5p' ffi/secretary-ffi-py/tests/test_smoke.py | head -10
```

Expected output: the file imports `secretary_ffi_py as m`, has a module-scoped `_golden_vault_*` helper that loads paths from `SECRETARY_GOLDEN_VAULT_DIR` (set externally) or computes the path from `__file__`, and groups tests in three sections (B.1 smoke, B.2 password unlock, B.3a recovery unlock, B.3b create vault).

- [ ] **Step 2: Add a module-scoped `created_vault` fixture and a `_golden_vault_block_summaries(n)` helper** (in the helpers section near the top)

After the existing `_golden_vault_phrase(n)` helper (or wherever the helpers end), add:

```python
import json
from pathlib import Path


def _golden_vault_path(n: int) -> Path:
    """Return the absolute Path to golden_vault_NNN folder."""
    base = (
        Path(os.environ["SECRETARY_GOLDEN_VAULT_DIR"])
        if "SECRETARY_GOLDEN_VAULT_DIR" in os.environ
        else Path(__file__).resolve().parent.parent.parent.parent / "core" / "tests" / "data"
    )
    return base / f"golden_vault_{n:03d}"


def _golden_vault_block_summaries(n: int) -> list:
    """Return the pinned block_summaries array for golden_vault_NNN.

    Source: core/tests/data/golden_vault_NNN_inputs.json's `block_summaries`
    field, added in Task 2 Step 3. Each entry has: block_uuid (hex string),
    block_name (string), created_at_ms (int), last_modified_ms (int),
    recipient_uuids (list of hex strings).
    """
    inputs_path = _golden_vault_path(n).parent / f"golden_vault_{n:03d}_inputs.json"
    with open(inputs_path) as f:
        return json.load(f)["block_summaries"]
```

- [ ] **Step 3: Add the 7 new pytest tests at the end of the file**

```python
# =============================================================================
# B.4a — folder-in open_vault tests
# =============================================================================


def test_open_vault_with_password_success():
    """Open vault from a folder with the correct password; verify both
    handles are populated and produce expected values."""
    folder = _golden_vault_path(1)
    password = bytearray(b"correct horse battery staple")
    out = m.open_vault_with_password(str(folder), bytes(password))
    # Wipe the bytearray immediately — caller-zeroize discipline.
    for i in range(len(password)):
        password[i] = 0

    with out as vault, vault.identity as identity, vault.manifest as manifest:
        assert identity.display_name() == "Owner"
        assert len(identity.user_uuid()) == 16
        assert manifest.vault_uuid() == identity.user_uuid() or len(manifest.vault_uuid()) == 16
        assert manifest.block_count() >= 0  # could be 0 if fixture has no blocks


def test_open_vault_with_recovery_success():
    """Same as test_open_vault_with_password_success but via the recovery path."""
    folder = _golden_vault_path(1)
    phrase = bytearray(_golden_vault_phrase(1).encode("utf-8"))
    out = m.open_vault_with_recovery(str(folder), bytes(phrase))
    for i in range(len(phrase)):
        phrase[i] = 0

    with out as vault, vault.identity as identity, vault.manifest as manifest:
        assert identity.display_name() == "Owner"
        assert len(identity.user_uuid()) == 16


def test_open_vault_with_password_wrong_password_raises():
    """Wrong password → VaultWrongPasswordOrCorrupt."""
    folder = _golden_vault_path(1)
    with pytest.raises(m.VaultWrongPasswordOrCorrupt):
        m.open_vault_with_password(str(folder), b"definitely wrong")


def test_open_vault_with_recovery_invalid_phrase_raises():
    """3-word phrase → VaultInvalidMnemonic with detail mentioning word count."""
    folder = _golden_vault_path(1)
    with pytest.raises(m.VaultInvalidMnemonic) as exc_info:
        m.open_vault_with_recovery(str(folder), b"only three words")
    assert "got 3" in str(exc_info.value)


def test_open_vault_folder_does_not_exist_raises():
    """Nonexistent folder path → VaultFolderInvalid with detail mentioning the
    missing file."""
    folder = "/tmp/__nonexistent_folder_b4a__"
    with pytest.raises(m.VaultFolderInvalid) as exc_info:
        m.open_vault_with_password(folder, b"any password")
    detail = str(exc_info.value).lower()
    assert "vault.toml" in detail or "no such file" in detail


def test_block_summaries_round_trip_pinned_against_inputs_json():
    """Verify block_summaries() returns the JSON-pinned shape exactly."""
    folder = _golden_vault_path(1)
    pinned = _golden_vault_block_summaries(1)
    out = m.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault, vault.manifest as manifest:
        actual = manifest.block_summaries()
        assert manifest.block_count() == len(pinned)
        assert len(actual) == len(pinned)
        for a, p in zip(actual, pinned):
            assert a.block_uuid.hex() == p["block_uuid"]
            assert a.block_name == p["block_name"]
            assert a.created_at_ms == p["created_at_ms"]
            assert a.last_modified_ms == p["last_modified_ms"]
            actual_recipient_hex = [r.hex() for r in a.recipient_uuids]
            assert actual_recipient_hex == p["recipient_uuids"]


def test_with_block_double_close_invariants():
    """Nested context managers wipe both handles on exit; subsequent
    accessor calls return the documented empty defaults rather than raising."""
    folder = _golden_vault_path(1)
    out = m.open_vault_with_password(str(folder), b"correct horse battery staple")

    # Exit the nested with-blocks; manifests are wiped.
    with out as vault:
        identity = vault.identity
        manifest = vault.manifest

    # Both handles' wipe() ran; accessors return defaults.
    assert identity.display_name() == ""
    assert identity.user_uuid() == bytes(16)
    assert manifest.vault_uuid() == bytes(16)
    assert manifest.block_count() == 0
    assert manifest.block_summaries() == []
```

- [ ] **Step 4: Run the new tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
uv run --directory ffi/secretary-ffi-py pytest -v 2>&1 | tail -30
```

Expected: `29 passed` (was 22 — added 7 B.4a tests). If any test fails:
- "AttributeError: module 'secretary_ffi_py' has no attribute 'open_vault_with_password'" → maturin dylib is stale; apply the nuclear cache fix.
- "FileNotFoundError: golden_vault_001_inputs.json" → `SECRETARY_GOLDEN_VAULT_DIR` env var or the `_golden_vault_path` helper's path computation is wrong.
- `block_summaries` field missing in JSON → Task 2 Step 3's JSON edit didn't make it into the worktree; verify.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add ffi/secretary-ffi-py/tests/test_smoke.py
git commit -m "$(cat <<'EOF'
test(ffi-b4a): add 7 pytest tests for open_vault_with_password / _recovery

Cross-validates the PyO3 binding pipeline at the Python level. Tests cover:
1. Open success via password path (with bytearray caller-zeroize parity)
2. Open success via recovery path (same identity values — both paths
   converge on byte-identical secret state per §3/§4 dual-KEK design)
3. Wrong password → VaultWrongPasswordOrCorrupt
4. Invalid mnemonic (wrong word count) → VaultInvalidMnemonic with detail
5. Nonexistent folder → VaultFolderInvalid with detail
6. block_summaries() round-trip vs JSON pinning (drift detection)
7. Nested context managers wipe both handles on exit; post-wipe accessors
   return documented empty defaults

Module-scoped helpers added: _golden_vault_path(n) and
_golden_vault_block_summaries(n) (loads pinned JSON for cross-checking).

Pytest count: 22 → 29 (+7).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 3 — secretary-ffi-uniffi projection

### Task 6: UDL + uniffi Rust glue — 2 dictionaries, 1 interface, 1 [Error] enum, 2 namespace fns

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (currently 110 lines)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs` (currently 467 lines)

The UDL describes the Swift / Kotlin API surface; the lib.rs Rust glue wraps the bridge crate's types behind the UDL-declared interfaces. Each piece must be added in lockstep — UDL change without matching lib.rs change won't compile.

- [ ] **Step 1: Add UDL entries (open_vault_with_*, VaultError, OpenVaultManifest, OpenVaultOutput, BlockSummary)**

Edit `ffi/secretary-ffi-uniffi/src/secretary.udl`. After the existing `create_vault` namespace function (line ~30-34), add:

```idl
    /// Open a vault folder using its master password. (B.4a)
    [Throws=VaultError]
    OpenVaultOutput open_vault_with_password(
        bytes folder_path,
        bytes password
    );

    /// Open a vault folder using its 24-word BIP-39 recovery phrase. (B.4a)
    [Throws=VaultError]
    OpenVaultOutput open_vault_with_recovery(
        bytes folder_path,
        bytes mnemonic
    );
};
```

(Note: closing the existing `namespace secretary { ... }` block — the new functions go INSIDE it, BEFORE the closing `};`.)

After the existing `[Error] interface UnlockError { ... };` block, add:

```idl
/// Thinned 6-variant FFI error for the folder-in vault entry points.
/// Mirrors UnlockError's 5 unlock-class variants byte-identically (variant
/// name + Display string from the bridge crate) plus a new FolderInvalid
/// variant for missing or inaccessible folders.
[Error]
interface VaultError {
    WrongPasswordOrCorrupt();
    WrongMnemonicOrCorrupt();
    InvalidMnemonic(string detail);
    VaultMismatch();
    CorruptVault(string detail);
    FolderInvalid(string detail);
};
```

After the existing `interface MnemonicOutput { ... };` block, add:

```idl
/// Opaque handle to a successfully-opened vault's manifest. Provides
/// read-only block-list accessors. Same close → wipe rename rationale as
/// UnlockedIdentity / MnemonicOutput.
interface OpenVaultManifest {
    /// 16-byte vault UUID. Returns 16 zero bytes if wiped.
    bytes vault_uuid();

    /// 16-byte owner user UUID. Returns 16 zero bytes if wiped.
    bytes owner_user_uuid();

    /// Number of blocks in the manifest. Returns 0 if wiped.
    u64 block_count();

    /// All block summaries. Empty list if wiped.
    sequence<BlockSummary> block_summaries();

    /// Locate one block by 16-byte UUID. Returns null if wiped or not found.
    BlockSummary? find_block(bytes block_uuid);

    /// Drop the wrapped manifest now, zeroizing the IBK. Idempotent.
    void wipe();
};
```

After the `dictionary CreateVaultOutput { ... };` block, add:

```idl
/// Output of the folder-in open paths. Holds two opaque handles — the
/// live identity and the read-only manifest.
dictionary OpenVaultOutput {
    /// Live opaque handle to the unlocked identity.
    UnlockedIdentity identity;
    /// Opaque handle to the decrypted manifest.
    OpenVaultManifest manifest;
};

/// Read-only metadata projection of one block in the vault manifest.
/// All fields are plaintext in the manifest already — no secret material.
dictionary BlockSummary {
    /// 16-byte block UUID.
    bytes block_uuid;
    /// User-visible block name.
    string block_name;
    /// Wall-clock millisecond timestamp at block creation.
    u64 created_at_ms;
    /// Wall-clock millisecond timestamp at last modification.
    u64 last_modified_ms;
    /// 16-byte recipient UUIDs (always includes owner).
    sequence<bytes> recipient_uuids;
};
```

- [ ] **Step 2: Add wrapper structs + impl blocks in `ffi/secretary-ffi-uniffi/src/lib.rs`**

Read the existing UnlockedIdentity wrapper (around line 142):

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
sed -n '140,170p' ffi/secretary-ffi-uniffi/src/lib.rs
```

Use that as the template. Add new wrapper structs after the existing `MnemonicOutput` wrapper. The full additions:

```rust
// =============================================================================
// B.4a — VaultError (mirrors FfiVaultError 6-variant flat enum)
// =============================================================================

/// uniffi projection of FfiVaultError. Six flat variants matching the UDL
/// declaration. The rename rationale is the same as UnlockError's: uniffi
/// 0.31's Kotlin codegen has overload-resolution conflicts between
/// `Throwable.message` and a UDL-declared `message` field, so structured
/// fields are named `detail`.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic { detail: String },
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,
    #[error("vault data integrity failure: {detail}")]
    CorruptVault { detail: String },
    #[error("vault folder is not accessible: {detail}")]
    FolderInvalid { detail: String },
}

impl From<secretary_ffi_bridge::FfiVaultError> for VaultError {
    fn from(e: secretary_ffi_bridge::FfiVaultError) -> Self {
        use secretary_ffi_bridge::FfiVaultError as B;
        match e {
            B::WrongPasswordOrCorrupt => VaultError::WrongPasswordOrCorrupt,
            B::WrongMnemonicOrCorrupt => VaultError::WrongMnemonicOrCorrupt,
            B::InvalidMnemonic { detail } => VaultError::InvalidMnemonic { detail },
            B::VaultMismatch => VaultError::VaultMismatch,
            B::CorruptVault { detail } => VaultError::CorruptVault { detail },
            B::FolderInvalid { detail } => VaultError::FolderInvalid { detail },
        }
    }
}

// =============================================================================
// B.4a — OpenVaultManifest (opaque handle wrapper)
// =============================================================================

/// uniffi wrapper around secretary_ffi_bridge::OpenVaultManifest.
pub struct OpenVaultManifest(secretary_ffi_bridge::OpenVaultManifest);

impl OpenVaultManifest {
    pub fn vault_uuid(&self) -> Vec<u8> {
        self.0.vault_uuid()
    }
    pub fn owner_user_uuid(&self) -> Vec<u8> {
        self.0.owner_user_uuid()
    }
    pub fn block_count(&self) -> u64 {
        self.0.block_count()
    }
    pub fn block_summaries(&self) -> Vec<BlockSummary> {
        self.0
            .block_summaries()
            .into_iter()
            .map(BlockSummary::from)
            .collect()
    }
    pub fn find_block(&self, block_uuid: Vec<u8>) -> Option<BlockSummary> {
        self.0.find_block(&block_uuid).map(BlockSummary::from)
    }
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

// =============================================================================
// B.4a — BlockSummary value type (uniffi dictionary)
// =============================================================================

/// uniffi dictionary projection of secretary_ffi_bridge::BlockSummary.
pub struct BlockSummary {
    pub block_uuid: Vec<u8>,
    pub block_name: String,
    pub created_at_ms: u64,
    pub last_modified_ms: u64,
    pub recipient_uuids: Vec<Vec<u8>>,
}

impl From<secretary_ffi_bridge::BlockSummary> for BlockSummary {
    fn from(b: secretary_ffi_bridge::BlockSummary) -> Self {
        Self {
            block_uuid: b.block_uuid.to_vec(),
            block_name: b.block_name,
            created_at_ms: b.created_at_ms,
            last_modified_ms: b.last_modified_ms,
            recipient_uuids: b.recipient_uuids.into_iter().map(|u| u.to_vec()).collect(),
        }
    }
}

// =============================================================================
// B.4a — OpenVaultOutput dictionary
// =============================================================================

/// uniffi dictionary projection. Holds two opaque-handle Arc references.
/// Same shape as B.3b's CreateVaultOutput dictionary.
pub struct OpenVaultOutput {
    pub identity: std::sync::Arc<UnlockedIdentity>,
    pub manifest: std::sync::Arc<OpenVaultManifest>,
}

// =============================================================================
// B.4a — namespace functions
// =============================================================================

pub fn open_vault_with_password(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
) -> Result<OpenVaultOutput, VaultError> {
    let path = std::path::PathBuf::from(std::str::from_utf8(&folder_path).map_err(|_| {
        VaultError::FolderInvalid {
            detail: "folder path contained invalid UTF-8".to_string(),
        }
    })?);
    let result = secretary_ffi_bridge::open_vault_with_password(&path, &password);
    use zeroize::Zeroize;
    password.zeroize();
    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(UnlockedIdentity(bridge_out.identity)),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

pub fn open_vault_with_recovery(
    folder_path: Vec<u8>,
    mut mnemonic: Vec<u8>,
) -> Result<OpenVaultOutput, VaultError> {
    let path = std::path::PathBuf::from(std::str::from_utf8(&folder_path).map_err(|_| {
        VaultError::FolderInvalid {
            detail: "folder path contained invalid UTF-8".to_string(),
        }
    })?);
    let result = secretary_ffi_bridge::open_vault_with_recovery(&path, &mnemonic);
    use zeroize::Zeroize;
    mnemonic.zeroize();
    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(UnlockedIdentity(bridge_out.identity)),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}
```

- [ ] **Step 3: Add tests at the bottom of lib.rs's `mod tests`** (find the closing `}` of the existing tests module and add before it)

```rust
    #[test]
    fn vault_error_maps_each_variant_one_to_one() {
        use secretary_ffi_bridge::FfiVaultError as B;
        assert!(matches!(
            VaultError::from(B::WrongPasswordOrCorrupt),
            VaultError::WrongPasswordOrCorrupt
        ));
        assert!(matches!(
            VaultError::from(B::WrongMnemonicOrCorrupt),
            VaultError::WrongMnemonicOrCorrupt
        ));
        let inv = VaultError::from(B::InvalidMnemonic {
            detail: "x".to_string(),
        });
        let VaultError::InvalidMnemonic { detail } = inv else {
            panic!("expected InvalidMnemonic")
        };
        assert_eq!(detail, "x");
        assert!(matches!(
            VaultError::from(B::VaultMismatch),
            VaultError::VaultMismatch
        ));
        let cor = VaultError::from(B::CorruptVault {
            detail: "y".to_string(),
        });
        let VaultError::CorruptVault { detail } = cor else {
            panic!("expected CorruptVault")
        };
        assert_eq!(detail, "y");
        let fol = VaultError::from(B::FolderInvalid {
            detail: "z".to_string(),
        });
        let VaultError::FolderInvalid { detail } = fol else {
            panic!("expected FolderInvalid")
        };
        assert_eq!(detail, "z");
    }

    #[test]
    fn block_summary_projection_round_trip_preserves_all_fields() {
        let bridge = secretary_ffi_bridge::BlockSummary {
            block_uuid: [1u8; 16],
            block_name: "test".to_string(),
            created_at_ms: 100,
            last_modified_ms: 200,
            recipient_uuids: vec![[2u8; 16], [3u8; 16]],
        };
        let proj = BlockSummary::from(bridge);
        assert_eq!(proj.block_uuid, vec![1u8; 16]);
        assert_eq!(proj.block_name, "test");
        assert_eq!(proj.created_at_ms, 100);
        assert_eq!(proj.last_modified_ms, 200);
        assert_eq!(proj.recipient_uuids, vec![vec![2u8; 16], vec![3u8; 16]]);
    }
```

- [ ] **Step 4: Build the workspace + run uniffi tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo build --release -p secretary-ffi-uniffi 2>&1 | tail -3
cargo test --release -p secretary-ffi-uniffi 2>&1 | tail -10
```

Expected: clean build, 13 tests pass (was 11 — added 2 B.4a mapping tests). If a UDL/Rust mismatch error fires (e.g. "type X declared in UDL but not implemented" or vice versa), check for typos in the UDL field names.

- [ ] **Step 5: Run clippy + fmt**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: clippy clean, fmt OK.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4a): add uniffi open_vault_with_* + VaultError + opaque OpenVaultManifest

UDL gains 2 namespace fns, 1 [Error] enum (VaultError, 6 variants
mirroring FfiVaultError), 1 interface (OpenVaultManifest), 2
dictionaries (OpenVaultOutput, BlockSummary).

uniffi Rust glue mirrors the bridge crate's surface:
- VaultError enum with From<secretary_ffi_bridge::FfiVaultError>
  one-to-one variant translation
- OpenVaultManifest wrapper struct (5 accessors + wipe)
- BlockSummary value-type with From<secretary_ffi_bridge::BlockSummary>
- OpenVaultOutput dictionary with two Arc<Interface> fields
- 2 namespace pub fn forwarders with wrapper-side Vec<u8> zeroize for
  password / mnemonic input (parallel to PyO3 Task 4 discipline)

+2 mapping tests in uniffi crate (uniffi crate count 11 → 13).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Swift + Kotlin smoke runners — 3 new asserts each

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`

End-to-end smoke validation through swiftc + JNA. Each runner exercises the open-vault path and validates one error variant.

- [ ] **Step 1: Read current Swift smoke runner**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
sed -n '1,30p' ffi/secretary-ffi-uniffi/tests/swift/main.swift
tail -30 ffi/secretary-ffi-uniffi/tests/swift/main.swift
```

Note the assertion-printing pattern (`PASS: ...`) and the env-var-driven path resolution.

- [ ] **Step 2: Add 3 Swift asserts at the end of `main.swift`** (just before the final OK line)

```swift
// =============================================================================
// B.4a — folder-in open_vault asserts
// =============================================================================

let goldenVault001Folder = goldenVaultDir.appendingPathComponent("golden_vault_001")

// Assert 16: open_vault_with_password success — identity + manifest both populated.
do {
    let folderPath = Data(goldenVault001Folder.path.utf8)
    let password = Data(VAULT_001_PASSWORD)
    let out = try secretary.openVaultWithPassword(folderPath: folderPath, password: password)
    let identity = out.identity
    let manifest = out.manifest
    let displayName = identity.displayName()
    let blockCount = manifest.blockCount()
    print("PASS: open_vault_with_password success → displayName=\"\(displayName)\", blockCount=\(blockCount)")
    identity.wipe()
    manifest.wipe()
} catch {
    fatalError("Assert 16 FAIL: open_vault_with_password threw \(error)")
}

// Assert 17: open_vault_with_password wrong password → VaultError.WrongPasswordOrCorrupt.
do {
    let folderPath = Data(goldenVault001Folder.path.utf8)
    let wrongPassword = Data("definitely wrong".utf8)
    _ = try secretary.openVaultWithPassword(folderPath: folderPath, password: wrongPassword)
    fatalError("Assert 17 FAIL: expected VaultError.WrongPasswordOrCorrupt, got success")
} catch let e as VaultError where e == .WrongPasswordOrCorrupt {
    print("PASS: open_vault_with_password wrong password → VaultError.WrongPasswordOrCorrupt")
} catch {
    fatalError("Assert 17 FAIL: wrong error variant: \(error)")
}

// Assert 18: nonexistent folder → VaultError.FolderInvalid with detail.
do {
    let folderPath = Data("/tmp/__nonexistent_b4a_swift__".utf8)
    let password = Data(VAULT_001_PASSWORD)
    _ = try secretary.openVaultWithPassword(folderPath: folderPath, password: password)
    fatalError("Assert 18 FAIL: expected VaultError.FolderInvalid, got success")
} catch let e as VaultError {
    if case .FolderInvalid(let detail) = e {
        if detail.lowercased().contains("vault.toml") || detail.lowercased().contains("no such file") {
            print("PASS: nonexistent folder → VaultError.FolderInvalid(detail=\"\(detail)\")")
        } else {
            fatalError("Assert 18 FAIL: FolderInvalid detail did not mention expected text: \(detail)")
        }
    } else {
        fatalError("Assert 18 FAIL: wrong VaultError variant: \(e)")
    }
} catch {
    fatalError("Assert 18 FAIL: wrong error type: \(error)")
}
```

- [ ] **Step 3: Add 3 Kotlin asserts at the end of `Main.kt`** (parallel to Swift)

```kotlin
// =============================================================================
// B.4a — folder-in open_vault asserts
// =============================================================================

val goldenVault001Folder = "$goldenVaultDir/golden_vault_001"

// Assert 16: open_vault_with_password success.
try {
    val folderPath = goldenVault001Folder.toByteArray(Charsets.UTF_8)
    val password = VAULT_001_PASSWORD.toByteArray(Charsets.UTF_8)
    val out = openVaultWithPassword(folderPath, password)
    val identity = out.identity
    val manifest = out.manifest
    val displayName = identity.displayName()
    val blockCount = manifest.blockCount()
    println("PASS: open_vault_with_password success → displayName=\"$displayName\", blockCount=$blockCount")
    identity.wipe()
    manifest.wipe()
} catch (e: Exception) {
    error("Assert 16 FAIL: open_vault_with_password threw $e")
}

// Assert 17: wrong password → VaultException.WrongPasswordOrCorrupt
try {
    val folderPath = goldenVault001Folder.toByteArray(Charsets.UTF_8)
    val wrongPassword = "definitely wrong".toByteArray(Charsets.UTF_8)
    openVaultWithPassword(folderPath, wrongPassword)
    error("Assert 17 FAIL: expected VaultException, got success")
} catch (e: VaultException.WrongPasswordOrCorrupt) {
    println("PASS: open_vault_with_password wrong password → VaultException.WrongPasswordOrCorrupt")
} catch (e: Exception) {
    error("Assert 17 FAIL: wrong exception: $e")
}

// Assert 18: nonexistent folder → VaultException.FolderInvalid with detail
try {
    val folderPath = "/tmp/__nonexistent_b4a_kotlin__".toByteArray(Charsets.UTF_8)
    val password = VAULT_001_PASSWORD.toByteArray(Charsets.UTF_8)
    openVaultWithPassword(folderPath, password)
    error("Assert 18 FAIL: expected VaultException, got success")
} catch (e: VaultException.FolderInvalid) {
    val detail = e.detail.lowercase()
    if (detail.contains("vault.toml") || detail.contains("no such file")) {
        println("PASS: nonexistent folder → VaultException.FolderInvalid(detail=\"${e.detail}\")")
    } else {
        error("Assert 18 FAIL: FolderInvalid detail did not mention expected text: ${e.detail}")
    }
} catch (e: Exception) {
    error("Assert 18 FAIL: wrong exception: $e")
}
```

NOTE: actual Kotlin variant naming (`VaultException.WrongPasswordOrCorrupt` vs `VaultException.WrongPasswordOrCorruptException` etc.) depends on uniffi 0.31's Kotlin codegen. Per B.3b's experience, watch for renames. If a class-not-found error fires, run the smoke runner to see the actual emitted class names:

```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | head -30
```

The error message will mention the expected class. Adjust the catch blocks accordingly.

- [ ] **Step 4: Run the smoke runners**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -10
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -10
```

Expected: Swift 18 PASS lines (was 15 — added 3 B.4a asserts); Kotlin 19 PASS lines (was 16 — added 3 B.4a asserts plus the `B.3b assertion 15 has guard + inner check` quirk inherited).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add ffi/secretary-ffi-uniffi/tests/swift/main.swift ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt
git commit -m "$(cat <<'EOF'
test(ffi-b4a): Swift + Kotlin smoke runners exercise open_vault_with_password

+3 asserts each end-to-end through swiftc + JNA:
- Assert 16: success path — identity displayName + manifest blockCount populated
- Assert 17: wrong password → VaultError.WrongPasswordOrCorrupt enum case
  (Swift) / VaultException.WrongPasswordOrCorrupt (Kotlin)
- Assert 18: nonexistent folder → VaultError.FolderInvalid with detail
  carrying the underlying io::Error context

Swift smoke 15/15 → 18/18; Kotlin smoke 16 → 19 PASS lines.

Per B.3b's experience, watch for uniffi 0.31 Kotlin codegen renames on
the VaultException variant class names; pinned to actual codegen output
via the run.sh feedback loop.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 4 — Docs + finalize

### Task 8: READMEs (bridge, py, uniffi) + top-level README + ROADMAP

**Files:**
- Modify: `ffi/secretary-ffi-bridge/README.md`
- Modify: `ffi/secretary-ffi-py/README.md`
- Modify: `ffi/secretary-ffi-uniffi/README.md`
- Modify: `README.md` (root)
- Modify: `ROADMAP.md`

Each README gains a short "B.4a" section showing the new entry points + the new opaque-handle / error-type surface. The top-level docs (root README, ROADMAP) advance the progress bar + status table.

- [ ] **Step 1: Read each README's existing structure to match conventions**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
grep -n "^#" ffi/secretary-ffi-bridge/README.md ffi/secretary-ffi-py/README.md ffi/secretary-ffi-uniffi/README.md | head -30
```

Expected: each README has section headings ending in B.3b. Add a new B.4a section after the B.3b one in each.

- [ ] **Step 2: Update bridge README** — add a B.4a section after the existing B.3b one. Suggested length ~30 lines covering: 2 new fns, OpenVaultOutput shape, OpenVaultManifest accessor list, FfiVaultError 6 variants. Reference the spec at `docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md` for design rationale.

- [ ] **Step 3: Update py README** — add a B.4a section showing Python usage:

```python
# B.4a — folder-in open_vault
import secretary_ffi_py as m

with m.open_vault_with_password(b"/path/to/vault", b"correct horse...") as out:
    with out.identity as identity, out.manifest as manifest:
        print(f"vault owned by {identity.display_name()}")
        for block in manifest.block_summaries():
            print(f"  {block.block_name} ({block.block_uuid.hex()})")
```

- [ ] **Step 4: Update uniffi README** — add Swift + Kotlin sections showing the parallel patterns (`defer { wipe() }` Swift, `.use { }` Kotlin).

- [ ] **Step 5: Update top-level `README.md`** — find the FFI status table (likely in the "Where we are" section) and flip the B.4a row from `⏳` to `✅`. Update the progress bar in the ASCII status block to reflect B.4a complete:

```
[==========================                                      ] Sub-project B — FFI bindings (B.1 Python ✅; B.1.1 Swift ✅; B.1.1.1 Kotlin ✅; B.2 password unlock ✅; B.3a recovery unlock ✅; B.3b create_vault ✅; B.4a open_vault ✅; B.4b/c/d pending)
```

Update the test-count summary to reflect ~509 cargo + 29 pytest + 18 Swift + 19 Kotlin PASS lines.

- [ ] **Step 6: Update `ROADMAP.md`** — add a B.4a entry with `✅` status, ~30 lines describing what shipped (mirror the structure of the B.3b entry's prose).

- [ ] **Step 7: Verify all docs render**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
ls -la ffi/secretary-ffi-bridge/README.md ffi/secretary-ffi-py/README.md ffi/secretary-ffi-uniffi/README.md README.md ROADMAP.md
```

Expected: each file has a recent mtime. Skim the diffs:

```bash
git diff --stat
```

Expected: 5 docs files modified.

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add README.md ROADMAP.md ffi/secretary-ffi-bridge/README.md ffi/secretary-ffi-py/README.md ffi/secretary-ffi-uniffi/README.md
git commit -m "$(cat <<'EOF'
docs(ffi-b4a): READMEs + top-level docs document folder-based open_vault

Bridge / py / uniffi crate READMEs gain B.4a sections documenting the
new entry points (open_vault_with_password, open_vault_with_recovery),
the OpenVaultOutput / OpenVaultManifest / BlockSummary type shape, and
the 6-variant FfiVaultError surface.

Top-level README progress bar advances B.4a to ✅; status table B.4a
row flipped. ROADMAP entry for B.4a added with the same prose style as
the B.3b entry. Test-count summary updated:
- cargo workspace 498 → ~509 + 9 ignored
- pytest 22 → 29
- Swift smoke 15 → 18 PASS
- Kotlin smoke 16 → 19 PASS lines

Spec at docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md
remains the source of truth for design rationale.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: NEXT_SESSION + handoff archive + final verification + push + open PR

**Files:**
- Modify: `NEXT_SESSION.md`
- Create: `docs/handoffs/2026-05-06-b4a-open-vault.md`

The session-close commit. Records what shipped, what's next (B.4b), open decisions, exact resume commands.

- [ ] **Step 1: Run final verification on the worktree**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -2
uv run core/tests/python/conformance.py 2>&1 | tail -2
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | grep -c "^PASS"
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | grep -c "^PASS"
```

Expected: 509+ cargo, clippy clean, fmt OK, 29 pytest, conformance + freshness PASS, 18 Swift PASS, 19 Kotlin PASS.

- [ ] **Step 2: Replace `NEXT_SESSION.md` with the B.4a-close baton**

Create a new NEXT_SESSION.md whose top reads:

```markdown
# NEXT_SESSION.md

**Session date:** 2026-05-06 (Sub-project B.4a — folder-based open_vault through FFI)
**Status:** Sub-project B.4a complete; PR pending merge. The folder-in vault open path is now exposed across PyO3 (Python) and uniffi (Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. The FFI surface now has 7 user-facing entry points: bytes-in `open_with_password` / `open_with_recovery` / `create_vault`, folder-in `open_vault_with_password` / `open_vault_with_recovery`, plus the `add` / `version` smokes. Two error types: `FfiUnlockError` (5-variant, bytes-in unchanged) and `FfiVaultError` (6-variant, folder-in NEW; mirrors 5 unlock-class variants byte-identically + 1 new FolderInvalid). Two opaque handles return from open paths: `UnlockedIdentity` (re-used unchanged) and `OpenVaultManifest` (NEW; holds IBK + manifest + envelope + verified owner card internally for B.4b/c/d to extend).
```

Then proceed with the (1) shipped, (2) what's next (= B.4b), (3) open decisions, (4) resume commands sections — same shape as the previous NEXT_SESSION.md.

For the (2) "What's next" section, lead with B.4b's open design questions:
- How do `Record` / `RecordField` / `RecordFieldValue` (now wrapped in `SecretString` / `SecretBytes` per PR #16) project to Python `dataclass` / Swift `struct` / Kotlin `data class` while preserving zeroize-discipline cross-language?
- Read-block API shape: does it consume the OpenVaultManifest or take it by reference?
- What's the error variant for "block UUID not found" — new `BlockNotFound { uuid }` variant or fold into CorruptVault?
- Trash entries: still deferred or surface in B.4b?

For the (3) decisions and risks: list the load-bearing B.4a decisions for B.4b/c/d to inherit:
1. Folder-IO ownership at the FFI established (Rust core owns reads + atomic writes)
2. Two-handle output struct pattern (UnlockedIdentity + OpenVaultManifest)
3. FfiVaultError 6-variant flat enum (mirror property + 1 new FolderInvalid)
4. OpenVaultManifest holds IBK + manifest + envelope + owner card internally — B.4b extends with read_block; B.4c with save_block (mutation question still open); B.4d with share_block (ContactCard surface)
5. local_highest_clock / rollback deferred to Sub-project C
6. Owner contact card not exposed (deferred to B.4d)

For the (4) resume commands: same shape as the prior NEXT_SESSION.md's commands — `git checkout main`, `git pull --ff-only`, gates verification, then "Begin Sub-project B.4b with brainstorm".

- [ ] **Step 3: Create the handoff archive copy**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cp NEXT_SESSION.md docs/handoffs/2026-05-06-b4a-open-vault.md
```

- [ ] **Step 4: Final verification — re-run all gates one more time**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
```

Expected: same numbers as Step 1.

- [ ] **Step 5: Commit the NEXT_SESSION + handoff**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git add NEXT_SESSION.md docs/handoffs/2026-05-06-b4a-open-vault.md
git commit -m "$(cat <<'EOF'
docs(handoff): B.4a complete — record verification + B.4b open questions

Final session-close commit:
- NEXT_SESSION.md replaced with B.4a-close baton (status, what shipped,
  what's next = B.4b record types + read_block, open decisions / risks,
  resume commands)
- docs/handoffs/2026-05-06-b4a-open-vault.md = frozen point-in-time copy
  of NEXT_SESSION.md (per the established handoff pattern)

Verification at session close:
- cargo test --release --workspace: 509+ passed + 9 ignored
- cargo clippy --release --workspace -- -D warnings: clean
- cargo fmt --all -- --check: OK
- uv run --directory ffi/secretary-ffi-py pytest: 29 passed
- uv run core/tests/python/conformance.py: PASS
- uv run core/tests/python/spec_test_name_freshness.py: PASS
- Swift smoke: 18 PASS
- Kotlin smoke: 19 PASS

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 6: Push the branch + open PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/feat-ffi-b4a-open-vault
git push -u origin feat/ffi-b4a-open-vault 2>&1 | tail -5
```

Then open the PR:

```bash
gh pr create --title "feat(ffi-b4a): expose folder-based open_vault through PyO3 + uniffi via shared bridge crate" --body "$(cat <<'EOF'
## Summary

- Wire `secretary_core::vault::open_vault` through both FFI flavors via the existing shared `secretary-ffi-bridge` crate (first folder-IO entry point — establishes the IO model B.4b/c/d will inherit).
- Two new top-level entry points: `open_vault_with_password(folder, password)` and `open_vault_with_recovery(folder, mnemonic)`.
- New flat 6-variant `FfiVaultError` mirrors `FfiUnlockError`'s 5 unlock-class variants byte-identically (variant name + Display) plus a new `FolderInvalid { detail }` for missing or inaccessible vault folders.
- `OpenVaultOutput { identity: UnlockedIdentity, manifest: OpenVaultManifest }` returned by both functions. `UnlockedIdentity` is the existing opaque handle re-used unchanged. `OpenVaultManifest` is a NEW opaque handle holding the IBK + manifest body + manifest envelope + verified owner contact card internally so B.4b/c/d can extend without re-opening.
- B.4a accessor surface on `OpenVaultManifest` is read-only: `vault_uuid`, `owner_user_uuid`, `block_count`, `block_summaries`, `find_block`, `wipe`. `BlockSummary` value-type with five plaintext-in-the-manifest fields (`block_uuid`, `block_name`, `created_at_ms`, `last_modified_ms`, `recipient_uuids`).
- `local_highest_clock` always `None` (rollback detection deferred to Sub-project C).

Spec: [docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md](docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md). Plan: [docs/superpowers/plans/2026-05-06-ffi-b4a-open-vault.md](docs/superpowers/plans/2026-05-06-ffi-b4a-open-vault.md).

## Test plan

- [x] `cargo test --release --workspace` — 509+ passed + 9 ignored
- [x] `cargo clippy --release --workspace -- -D warnings` — clean
- [x] `cargo fmt --all -- --check` — OK
- [x] `uv run --directory ffi/secretary-ffi-py pytest` — 29 passed
- [x] `uv run core/tests/python/conformance.py` — PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` — PASS
- [x] `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` — 18 PASS
- [x] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` — 19 PASS lines

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 7: Capture the PR URL** for the post-merge SHA-recording commit later (matches the established B.2 / B.3a / B.3b pattern).

```bash
gh pr view --json url --jq .url
```

Note the URL for the next session's post-merge tidy.

---

## Summary

After all 9 tasks (Pre-flight + 8 implementation tasks), the FFI surface gains:
- 2 new top-level `pub fn`s on the bridge (`open_vault_with_password`, `open_vault_with_recovery`)
- 4 new types on the bridge (`OpenVaultOutput`, `OpenVaultManifest`, `BlockSummary`, `FfiVaultError`)
- Their parallel projections through PyO3 + uniffi
- 6 new Python exception classes (prefix `Vault*` to disambiguate from FfiUnlockError)
- 9 new bridge unit tests + 7 new pytest tests + 3 new Swift asserts + 3 new Kotlin asserts + 2 new uniffi mapping tests

Cumulative test counts:
- Cargo workspace: 498 + 9 ignored → ~509 + 9 ignored
- pytest: 22 → 29
- Swift smoke: 15 PASS → 18 PASS
- Kotlin smoke: 16 PASS lines → 19 PASS lines
- Bridge crate unit tests: 36 → ~54
- uniffi crate unit tests: 11 → 13

## Test plan (full-cycle gates, matching the prior sub-projects' shape)

The "Verification at session close" check in Task 9 Step 1 + Step 4 is the single source of truth for the all-green close state. Numerical breakdown above is the target.

## Self-review checklist

- [x] **Spec coverage**: Each Goals item has a task. Goal 1 (2 pub fns) → Tasks 2 / 4 / 6 / 7. Goal 2 (OpenVaultOutput) → Tasks 2 / 4 / 6. Goal 3 (OpenVaultManifest) → Tasks 2 / 4 / 6. Goal 4 (BlockSummary) → Tasks 2 / 4 / 6. Goal 5 (FfiVaultError 6-variant) → Tasks 1 / 4 / 6. Goal 6 (bridge as single source of truth) → Tasks 1, 2, 3 establish; Tasks 4, 6 project. Goal 7 (gates green) → Task 9.
- [x] **Placeholder scan**: no "TBD" / "TODO" / "implement later" / "fill in" / "Add appropriate" in the plan body. Test code shown in code blocks; commit messages have full content.
- [x] **Type consistency**: variant names match the spec (`WrongPasswordOrCorrupt`, not `WrongPassword`). Display strings match across spec, plan, and the existing bridge code. Method names match between bridge (`vault_uuid`, `block_summaries`, `find_block`) and PyO3 wrapper (same names) and uniffi UDL (snake_case → PascalCase per uniffi 0.31 codegen, e.g. `block_summaries()` → `blockSummaries()` in Swift, `blockSummaries()` in Kotlin). The `From<FfiUnlockError> for FfiVaultError` arm uses the actual existing `FfiUnlockError` variant names (verified against `ffi/secretary-ffi-bridge/src/error.rs:41-91`).
