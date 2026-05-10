# B.4c — save_block Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `save_block` (encrypt + atomic-persist one block of records) surface to the bridge crate, then expose it through the uniffi (Swift / Kotlin) and PyO3 (Python) flavors. v1 single-author: recipients = [owner_card]; multi-recipient is B.4d.

**Architecture:** New `save/` module on the bridge crate mirroring the existing `record/` directory. Free-function `save_block(identity, manifest, input, device_uuid, now_ms)` that locks both inner mutexes, builds a temporary `core::vault::OpenVault` from clones, calls `core::vault::save_block` (atomic-write through `tempfile::persist`), and on `Ok(())` writes back the mutated manifest + manifest_file into the bridge handle. New `FfiVaultError::SaveCryptoFailure` variant separates save-time crypto failures (on already-validated inputs) from on-disk corruption.

**Tech Stack:** Rust (workspace, stable), uniffi 0.31, PyO3 0.28, maturin, uv, proptest, tempfile, rand, zeroize.

---

## File Structure

**Bridge crate (`ffi/secretary-ffi-bridge/src/`):**

| Action | Path | Responsibility |
|---|---|---|
| Create | `save/mod.rs` | Module root: `pub mod input; pub mod orchestration;` + `pub use input::{...}; pub use orchestration::save_block;` + module-level docs |
| Create | `save/input.rs` | `SecretString` newtype + `FieldInputValue` / `FieldInput` / `RecordInput` / `BlockInput` types + conversion helpers + tests |
| Create | `save/orchestration.rs` | `save_block` free function + cfg(unix) failure-invariant test + proptest |
| Modify | `error.rs` | Add `FfiVaultError::SaveCryptoFailure { detail }` variant + Debug redaction + test |
| Modify | `identity.rs` | Add `signer_secret_keys()` accessor + `SignerSecretKeysError` enum + tests |
| Modify | `vault.rs` | Add `snapshot_for_save_block()` accessor + tests |
| Modify | `lib.rs` | `mod save;` + `pub use save::{save_block, BlockInput, RecordInput, FieldInput, FieldInputValue, SecretString};` |

**uniffi crate (`ffi/secretary-ffi-uniffi/src/`):**

| Action | Path | Responsibility |
|---|---|---|
| Modify | `secretary.udl` | Add `SaveCryptoFailure` to VaultError; add `BlockInput`/`RecordInput`/`FieldInput`/`FieldInputValue` dictionaries + tagged enum; add `save_block` namespace fn |
| Modify | `errors.rs` | Mirror `SaveCryptoFailure` variant on uniffi `VaultError` + From-impl arm |
| Create | `wrappers/save_input.rs` | uniffi-side input-struct wrappers (uniffi expects flat dictionaries; same shape as bridge `BlockInput` etc.) — only needed if uniffi codegen requires distinct types; otherwise re-export bridge types |
| Modify | `wrappers/mod.rs` | Add `pub mod save_input;` if created |
| Modify | `namespace.rs` | Add `save_block` namespace fn that converts uniffi-side input → bridge `BlockInput` and calls `secretary_ffi_bridge::save_block` |
| Modify | `lib.rs` | `pub use namespace::save_block;` + `pub use wrappers::save_input::*;` if module created |
| Modify | `tests/swift_smoke.swift` | Add 4 Swift smoke tests |
| Modify | `tests/kotlin_smoke.kt` | Add 4 Kotlin smoke tests |

**PyO3 crate (`ffi/secretary-ffi-py/src/`):**

| Action | Path | Responsibility |
|---|---|---|
| Modify | `lib.rs` | Add `VaultSaveCryptoFailure` exception class + From-impl arm; add `PyBlockInput` / `PyRecordInput` / `PyFieldInput` / `PyFieldInputValue` `#[pyclass]` types; add `#[pyfunction] save_block`; register everything in `#[pymodule]` |
| Modify | `tests/test_smoke.py` | Add 10 pytest tests |

**Docs (committed pre-push per the feedback memory):**

| Action | Path | Responsibility |
|---|---|---|
| Modify | `README.md` | Update "Where we are" totals (570 cargo + 9 ignored, 50 pytest, 26 Swift, 27 Kotlin, B.4c shipped) |
| Modify | `ROADMAP.md` | Mark B.4c done, point at B.4d |
| Modify | `NEXT_SESSION.md` | Replace with B.4d (or B.4-cleanup-2) baton |
| Create | `docs/handoffs/2026-05-XX-b4c-save-block.md` | Timestamped session handoff |

---

## Task 1: Bridge accessors, types, and new error variant

**Goal:** Land everything `save_block` needs *except* the orchestrator itself. Ships an internally-consistent commit that compiles + tests cleanly.

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/save/mod.rs`
- Create: `ffi/secretary-ffi-bridge/src/save/input.rs`
- Modify: `ffi/secretary-ffi-bridge/src/error.rs` (add SaveCryptoFailure variant)
- Modify: `ffi/secretary-ffi-bridge/src/identity.rs` (add signer_secret_keys + SignerSecretKeysError)
- Modify: `ffi/secretary-ffi-bridge/src/vault.rs` (add snapshot_for_save_block)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (mod save; pub use)

### Task 1.1: Add `FfiVaultError::SaveCryptoFailure` variant

- [ ] **Step 1: Read the current FfiVaultError enum context**

Run: `grep -n "BlockNotFound\|FfiVaultError" ffi/secretary-ffi-bridge/src/error.rs | head -20`

Locate the `BlockNotFound` variant declaration. The new `SaveCryptoFailure` variant is added immediately after `BlockNotFound`.

- [ ] **Step 2: Write the failing test**

Add to `ffi/secretary-ffi-bridge/src/error.rs` inside the existing `mod tests`:

```rust
#[test]
fn save_crypto_failure_display_pins_detail_text() {
    let err = FfiVaultError::SaveCryptoFailure {
        detail: "failed to encrypt block: pq sig generation aborted".into(),
    };
    assert_eq!(
        err.to_string(),
        "save-time crypto failure: failed to encrypt block: pq sig generation aborted"
    );
}

#[test]
fn save_crypto_failure_debug_redacts_detail() {
    let err = FfiVaultError::SaveCryptoFailure {
        detail: "secret-bearing-detail-string".into(),
    };
    let dbg = format!("{:?}", err);
    assert!(
        !dbg.contains("secret-bearing-detail-string"),
        "Debug must redact: {dbg}"
    );
    assert!(dbg.contains("redacted"), "Debug must include 'redacted' marker: {dbg}");
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --release --workspace -p secretary-ffi-bridge save_crypto_failure 2>&1 | tail -10`
Expected: FAIL — `SaveCryptoFailure` variant unknown.

- [ ] **Step 4: Add the variant to `FfiVaultError`**

In `ffi/secretary-ffi-bridge/src/error.rs`, add immediately after `BlockNotFound { uuid_hex: String }`:

```rust
    /// Save-time crypto failure on already-validated inputs. Distinguished
    /// from `CorruptVault` (which means on-disk bytes failed verification)
    /// because save failures here originate from in-memory state that
    /// passed `open_vault` checks, so the failure mode is post-unlock
    /// corruption / structural-impossibility rather than an on-disk corrupt
    /// envelope.
    ///
    /// Mapped from: `tick_clock` saturation, `MlKem768Public::from_bytes`
    /// failures on the owner card, canonical-CBOR encode failures,
    /// `encrypt_block` / `sign_manifest` / `encode_block_file` /
    /// `encode_manifest_file` failures, and post-unlock identity-bundle
    /// in-memory parse failures.
    ///
    /// `detail` is redacted in Debug. Display includes the detail.
    SaveCryptoFailure { detail: String },
```

- [ ] **Step 5: Add Display arm for the variant**

Locate the `impl std::fmt::Display for FfiVaultError` block (search: `grep -n "impl.*Display.*FfiVaultError" ffi/secretary-ffi-bridge/src/error.rs`). Add an arm:

```rust
            FfiVaultError::SaveCryptoFailure { detail } => {
                write!(f, "save-time crypto failure: {detail}")
            }
```

- [ ] **Step 6: Add Debug redaction arm**

Locate the manual `impl std::fmt::Debug for FfiVaultError` (search for the existing redacted-detail Debug pattern on `CorruptVault`). Add the parallel arm for `SaveCryptoFailure { detail: _ }`:

```rust
            FfiVaultError::SaveCryptoFailure { detail: _ } => f
                .debug_struct("SaveCryptoFailure")
                .field("detail", &"<redacted>")
                .finish(),
```

- [ ] **Step 7: Run tests; confirm they pass + nothing else broke**

Run: `cargo test --release --workspace -p secretary-ffi-bridge 2>&1 | tail -10`
Expected: PASS for the two new tests; ALL other bridge tests still pass.

- [ ] **Step 8: Update the existing variant-mapping pin test if present**

Run: `grep -n "vault_error_maps_each_variant_one_to_one\|each_variant\|_one_to_one" ffi/secretary-ffi-bridge/src/error.rs ffi/secretary-ffi-uniffi/src/errors.rs`

If there's an exhaustive-match style test, it likely fails the build with a `non_exhaustive` warning. Add the new arm to that test's match block:

```rust
        FfiVaultError::SaveCryptoFailure { detail } => {
            assert_eq!(detail, "save-crypto-test");
        }
```

The bridge-side variant pin test can remain a Display assertion (Steps 2–7 already covered). The uniffi-side mirror is updated in Task 3.

- [ ] **Step 9: cargo clippy + fmt; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
```
Expected: clippy clean, fmt clean.

```bash
git add ffi/secretary-ffi-bridge/src/error.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): add FfiVaultError::SaveCryptoFailure variant

Save-time crypto failures on already-validated inputs are categorically
different from on-disk vault corruption — the existing CorruptVault
variant is correct for read failures (where the input is on-disk bytes)
but wrong for save failures (where the input is in-memory state that
passed open_vault checks). New variant lets foreign callers distinguish
these cases.

Per docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §6.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 1.2: Add `SecretString` wrapper and input types

- [ ] **Step 1: Create `ffi/secretary-ffi-bridge/src/save/mod.rs`**

```rust
//! save_block input types and orchestrator. Mirrors `record/`'s structure:
//! `input.rs` holds the foreign-facing shapes; `orchestration.rs` holds the
//! free-function entry point.
//!
//! Rationale: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md

pub mod input;
// orchestration is added in Task 2; not declared yet.

pub use input::{BlockInput, FieldInput, FieldInputValue, RecordInput, SecretString};
```

(`orchestration` will be declared in Task 2.1.)

- [ ] **Step 2: Write the failing tests for `SecretString`**

Create `ffi/secretary-ffi-bridge/src/save/input.rs` with the test module first:

```rust
//! save_block input types: SecretString, FieldInputValue, FieldInput,
//! RecordInput, BlockInput.
//!
//! Rationale: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §4.

use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::vault::record::{Record as CoreRecord, RecordField, RecordFieldValue};
use std::str::Utf8Error;
use zeroize::Zeroize;

/// Bridge-side wrapper for secret UTF-8 text. Wraps a `Sensitive<Vec<u8>>`
/// validated UTF-8 at construction. Empty strings allowed. Zeroize-on-drop.
///
/// `expose_str()` is the explicit boundary used by `save/orchestration.rs`
/// when populating `core::vault::record::RecordFieldValue::Text(String)` —
/// the brief plaintext copy lives only inside the BlockPlaintext under
/// construction.
#[derive(Clone)]
pub struct SecretString {
    inner: Sensitive<Vec<u8>>,
}

impl SecretString {
    /// Wrap an owned `String`. Empty strings allowed.
    pub fn new(s: String) -> Self {
        Self {
            inner: Sensitive::new(s.into_bytes()),
        }
    }

    /// Wrap arbitrary bytes after validating UTF-8.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Utf8Error> {
        std::str::from_utf8(&bytes)?;
        Ok(Self {
            inner: Sensitive::new(bytes),
        })
    }

    /// Crate-internal: peek the wrapped bytes as `&str`. Used by the
    /// orchestrator to construct `core::RecordFieldValue::Text(String)`.
    pub(crate) fn expose_str(&self) -> &str {
        // SAFETY-equivalent: the constructors validate UTF-8.
        std::str::from_utf8(self.inner.expose())
            .expect("SecretString invariant: inner bytes are valid UTF-8")
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretString")
            .field("len", &self.inner.expose().len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_round_trips_utf8_text() {
        let s = SecretString::new("hello \u{1F511}".to_string());
        assert_eq!(s.expose_str(), "hello \u{1F511}");
    }

    #[test]
    fn secret_string_allows_empty() {
        let s = SecretString::new(String::new());
        assert_eq!(s.expose_str(), "");
    }

    #[test]
    fn secret_string_from_bytes_accepts_valid_utf8() {
        let s = SecretString::from_bytes(b"hello".to_vec()).expect("valid utf8");
        assert_eq!(s.expose_str(), "hello");
    }

    #[test]
    fn secret_string_rejects_invalid_utf8_in_from_bytes() {
        let bad = vec![0xFF, 0xFE, 0xFD];
        assert!(SecretString::from_bytes(bad).is_err());
    }

    #[test]
    fn secret_string_debug_does_not_expose_inner() {
        let s = SecretString::new("super-secret-password".to_string());
        let dbg = format!("{:?}", s);
        assert!(!dbg.contains("super-secret-password"), "got: {dbg}");
        assert!(dbg.contains("SecretString"));
        assert!(dbg.contains("len"));
    }
}
```

- [ ] **Step 3: Wire the new module into `lib.rs`**

In `ffi/secretary-ffi-bridge/src/lib.rs`, find the existing `pub mod` declarations and add:

```rust
pub mod save;

pub use save::{BlockInput, FieldInput, FieldInputValue, RecordInput, SecretString};
```

(`save_block` itself is added in Task 2.)

- [ ] **Step 4: Run tests — confirm SecretString tests pass**

Run: `cargo test --release --workspace -p secretary-ffi-bridge save::input 2>&1 | tail -15`
Expected: 5 tests for SecretString PASS.

- [ ] **Step 5: Add `FieldInputValue` enum and conversion path tests**

Append to `save/input.rs` (above the `#[cfg(test)]` block):

```rust
/// Tagged value for a single field. Mirrors `core::vault::record::RecordFieldValue`
/// on the input side, but with bridge-side zeroize wrappers for the secret payload.
#[derive(Clone, Debug)]
pub enum FieldInputValue {
    /// UTF-8 text, wrapped in a zeroize-on-drop SecretString.
    Text(SecretString),
    /// Raw bytes, wrapped in the existing zeroize-on-drop SecretBytes.
    Bytes(SecretBytes),
}

impl FieldInputValue {
    /// Crate-internal: consume self and produce a `core::RecordFieldValue`.
    /// The conversion briefly exposes inner String / Vec<u8> while populating
    /// the un-zeroized core arms; the bridge-side wrappers drop afterwards.
    pub(crate) fn into_core_value(self) -> RecordFieldValue {
        match self {
            FieldInputValue::Text(s) => RecordFieldValue::Text(s.expose_str().to_string()),
            FieldInputValue::Bytes(b) => RecordFieldValue::Bytes(b.expose().to_vec()),
        }
    }
}

/// One field on a record. `name` is plaintext (already plaintext in
/// `core::RecordField.name`).
#[derive(Clone, Debug)]
pub struct FieldInput {
    pub name: String,
    pub value: FieldInputValue,
}

impl FieldInput {
    pub(crate) fn into_core_field(
        self,
        last_mod_ms: u64,
        device_uuid: [u8; 16],
    ) -> RecordField {
        RecordField {
            name: self.name,
            value: self.value.into_core_value(),
            last_mod_ms,
            device_uuid,
            unknown: std::collections::BTreeMap::new(),
        }
    }
}

/// One record in a block.
#[derive(Clone, Debug)]
pub struct RecordInput {
    pub record_uuid: [u8; 16],
    pub fields: Vec<FieldInput>,
}

impl RecordInput {
    pub(crate) fn into_core_record(self, now_ms: u64, device_uuid: [u8; 16]) -> CoreRecord {
        CoreRecord {
            record_uuid: self.record_uuid,
            record_type: String::new(),
            tags: Vec::new(),
            created_at_ms: now_ms,
            last_mod_ms: now_ms,
            tombstoned_at_ms: None,
            vector_clock: Vec::new(),
            fields: self
                .fields
                .into_iter()
                .map(|f| f.into_core_field(now_ms, device_uuid))
                .collect(),
            unknown: std::collections::BTreeMap::new(),
        }
    }
}

/// One block. Empty `records` allowed (spec permits empty blocks).
#[derive(Clone, Debug)]
pub struct BlockInput {
    pub block_uuid: [u8; 16],
    pub block_name: String,
    pub records: Vec<RecordInput>,
}
```

**Note for the engineer:** the exact field names on `core::vault::record::Record` and `core::vault::record::RecordField` (e.g. `record_type`, `tags`, `unknown`, `tombstoned_at_ms`, `vector_clock`) MUST match the current core definitions. Before adding the conversion methods, run:

```bash
grep -n "pub struct Record\b\|pub struct RecordField\b" core/src/vault/record.rs
```

and read the field list. Adjust `into_core_record` / `into_core_field` to match exactly. If a core field has changed since this plan was written, **prefer the current core definition over what's in this plan** — the conversion is mechanical.

- [ ] **Step 6: Add tests for the conversion methods**

Append to the `mod tests` block in `save/input.rs`:

```rust
    #[test]
    fn field_input_value_text_converts_to_core_record_field_value_text() {
        let input = FieldInputValue::Text(SecretString::new("password123".to_string()));
        match input.into_core_value() {
            RecordFieldValue::Text(s) => assert_eq!(s, "password123"),
            other => panic!("expected Text, got {:?}", other),
        }
    }

    #[test]
    fn field_input_value_bytes_converts_to_core_record_field_value_bytes() {
        let input = FieldInputValue::Bytes(SecretBytes::new(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        match input.into_core_value() {
            RecordFieldValue::Bytes(b) => assert_eq!(b, vec![0xDE, 0xAD, 0xBE, 0xEF]),
            other => panic!("expected Bytes, got {:?}", other),
        }
    }

    #[test]
    fn block_input_to_block_plaintext_preserves_uuid_and_name() {
        // Sanity: Smoke that BlockInput's struct fields are addressable;
        // the full BlockInput → BlockPlaintext conversion is exercised
        // end-to-end in save_block tests (Task 2).
        let input = BlockInput {
            block_uuid: [0u8; 16],
            block_name: "Notes".to_string(),
            records: vec![],
        };
        assert_eq!(input.block_uuid, [0u8; 16]);
        assert_eq!(input.block_name, "Notes");
        assert!(input.records.is_empty());
    }
```

- [ ] **Step 7: Run tests; confirm all input tests pass**

Run: `cargo test --release --workspace -p secretary-ffi-bridge save::input 2>&1 | tail -15`
Expected: 8 tests PASS (5 SecretString + 2 FieldInputValue + 1 BlockInput sanity).

- [ ] **Step 8: cargo clippy + fmt; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-bridge/src/save/ ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): add SecretString wrapper and BlockInput input types

New save/ module mirroring record/. SecretString wraps Sensitive<Vec<u8>>
with UTF-8 invariant validated at construction. Bridge-side zeroize
discipline at the FFI boundary; the brief plaintext exposure during
BlockInput → BlockPlaintext conversion is unavoidable until the v2
RecordFieldValue zeroize-typing redesign (CLAUDE.md-flagged).

Per docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §3-4.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 1.3: Add `signer_secret_keys()` accessor on UnlockedIdentity

- [ ] **Step 1: Read the existing `reader_secret_keys` for the structural template**

Run: `sed -n '100,155p' ffi/secretary-ffi-bridge/src/identity.rs`

`signer_secret_keys` mirrors this pattern but returns `(Ed25519Secret, MlDsa65Secret)` for the signing keys.

- [ ] **Step 2: Write the failing tests**

Add to the `mod tests` block at the bottom of `ffi/secretary-ffi-bridge/src/identity.rs`:

```rust
    #[test]
    fn signer_secret_keys_after_wipe_returns_handle_closed() {
        let id = fresh_unlocked_identity();
        id.wipe();
        assert_eq!(
            id.signer_secret_keys().err(),
            Some(SignerSecretKeysError::HandleClosed)
        );
    }

    #[test]
    fn signer_secret_keys_when_live_returns_ok_tuple() {
        let id = fresh_unlocked_identity();
        // The returned types are Sensitive-wrapped and don't expose Eq;
        // we only assert that we get an Ok tuple back.
        assert!(id.signer_secret_keys().is_ok());
    }
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --release --workspace -p secretary-ffi-bridge signer_secret_keys 2>&1 | tail -10`
Expected: FAIL — `signer_secret_keys` and `SignerSecretKeysError` undefined.

- [ ] **Step 4: Add the `SignerSecretKeysError` enum**

In `ffi/secretary-ffi-bridge/src/identity.rs`, immediately after the existing `ReaderSecretKeysError` enum, add:

```rust
/// Bridge-internal failure mode for [`UnlockedIdentity::signer_secret_keys`].
/// Mirrors [`ReaderSecretKeysError`] semantics for the signing-key path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignerSecretKeysError {
    /// The identity handle has been wiped.
    HandleClosed,
    /// ML-DSA-65 secret key parse failed on bytes that were already
    /// validated at unlock-time. Structurally impossible — implies
    /// post-unlock memory corruption.
    MlDsa65ParseFailed,
}
```

- [ ] **Step 5: Add the `signer_secret_keys` method on UnlockedIdentity**

In the `impl UnlockedIdentity` block (locate via `grep -n "impl UnlockedIdentity" ffi/secretary-ffi-bridge/src/identity.rs`), add immediately after `reader_secret_keys`:

```rust
    /// Bridge-internal accessor returning fresh clones of the Ed25519 +
    /// ML-DSA-65 signer secret keys for `core::vault::manifest::sign_manifest`
    /// and `core::vault::block::encrypt_block`. NOT exposed through PyO3 /
    /// uniffi — used only by `crate::save::save_block`.
    ///
    /// Mirrors `reader_secret_keys` for the signing path. Distinct typed
    /// errors for handle-closed vs. post-unlock parse failure so the
    /// orchestrator can attach a non-misleading detail string.
    pub(crate) fn signer_secret_keys(
        &self,
    ) -> Result<
        (
            secretary_core::crypto::sig::Ed25519Secret,
            secretary_core::crypto::sig::MlDsa65Secret,
        ),
        SignerSecretKeysError,
    > {
        use secretary_core::crypto::secret::Sensitive;
        use secretary_core::crypto::sig;
        use zeroize::Zeroize as _;

        let guard = lock_or_recover(&self.inner);
        let id = guard.as_ref().ok_or(SignerSecretKeysError::HandleClosed)?;

        // Ed25519: copy the 32 bytes onto the stack, mint a Sensitive,
        // zeroize the stack copy. Mirrors `crate::vault::split_core_open_vault`
        // and `reader_secret_keys`.
        let mut ed_sk_bytes: [u8; 32] = *id.identity.ed25519_sk.expose();
        let ed_sk: sig::Ed25519Secret = Sensitive::new(ed_sk_bytes);
        ed_sk_bytes.zeroize();

        // ML-DSA-65: from_bytes returns Result<_, SigError>. Bundle was
        // already validated at unlock-time; failure here implies
        // post-unlock memory corruption — surface distinctly.
        let pq_sk = sig::MlDsa65Secret::from_bytes(id.identity.ml_dsa_65_sk.expose())
            .map_err(|_| SignerSecretKeysError::MlDsa65ParseFailed)?;

        Ok((ed_sk, pq_sk))
    }
```

**Note for the engineer:** before pasting, verify the actual core type paths by running `grep -n "pub struct Ed25519Secret\|pub struct MlDsa65Secret\|pub fn from_bytes" core/src/crypto/sig.rs | head -10`. Adjust the `use sig;` import and `from_bytes` call to match the current core surface.

- [ ] **Step 6: Run tests; confirm they pass**

Run: `cargo test --release --workspace -p secretary-ffi-bridge signer_secret_keys 2>&1 | tail -10`
Expected: 2 tests PASS.

- [ ] **Step 7: Verify no regression in the broader test suite**

Run: `cargo test --release --workspace -p secretary-ffi-bridge 2>&1 | grep -E "^test result:" | tail -5`
Expected: All bridge tests still PASS; the two new ones add to the count.

- [ ] **Step 8: cargo clippy + fmt; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-bridge/src/identity.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): add signer_secret_keys accessor on UnlockedIdentity

Mirrors reader_secret_keys for the Ed25519 + ML-DSA-65 signing keys that
core::save_block needs for manifest re-sign and block encrypt-and-sign.
Crate-private; not exposed through PyO3 / uniffi.

Per docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §4.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 1.4: Add `snapshot_for_save_block()` accessor on OpenVaultManifest

- [ ] **Step 1: Read the existing `snapshot_for_read_block` for the structural template**

Run: `sed -n '288,320p' ffi/secretary-ffi-bridge/src/vault.rs`

The new snapshot folds five fields into one critical section. Note that the IBK is `Sensitive<[u8; 32]>` and clone via `Sensitive::new(*expose())` to keep the source slot intact.

- [ ] **Step 2: Write the failing tests**

Add to the existing `mod tests` block at the bottom of `ffi/secretary-ffi-bridge/src/vault.rs`:

```rust
    #[test]
    fn snapshot_for_save_block_returns_some_when_live_and_none_when_wiped() {
        let (_id, manifest) = fresh_open_vault();
        assert!(manifest.snapshot_for_save_block().is_some());
        manifest.wipe();
        assert!(manifest.snapshot_for_save_block().is_none());
    }

    #[test]
    fn snapshot_for_save_block_atomic_under_concurrent_wipe() {
        // TOCTOU coverage parallel to snapshot_for_read_block:
        // the snapshot's 5 fields must come from the same critical
        // section (no observable wipe between any pair).
        let (_id, manifest) = fresh_open_vault();
        let snap = manifest.snapshot_for_save_block();
        assert!(snap.is_some());
        // We cannot easily race against wipe deterministically in a unit
        // test; the structural guarantee is that snapshot_for_save_block
        // takes the lock once and reads all 5 fields under that lock.
        // The matching read-side test pattern is in
        // snapshot_for_read_block_returns_some_triple_when_live_and_none_when_wiped.
    }
```

**Note for the engineer:** if there's an existing helper named `fresh_open_vault` in `vault.rs` tests, use it. If not, the existing `snapshot_for_read_block_returns_some_triple_when_live_and_none_when_wiped` test (search: `grep -n "snapshot_for_read_block_returns_some_triple" ffi/secretary-ffi-bridge/src/vault.rs`) shows how that file constructs a test fixture. Reuse the same pattern.

- [ ] **Step 3: Run tests to confirm they fail**

Run: `cargo test --release --workspace -p secretary-ffi-bridge snapshot_for_save_block 2>&1 | tail -10`
Expected: FAIL — method undefined.

- [ ] **Step 4: Add the accessor method**

In the `impl OpenVaultManifest` block, immediately after `snapshot_for_read_block`, add:

```rust
    /// Bridge-internal atomic snapshot of the five pieces
    /// `crate::save::save_block` needs in one shot: the manifest body,
    /// the on-disk manifest envelope (for re-sign chaining), the verified
    /// owner contact card, a fresh clone of the IBK (Sensitive::new on a
    /// new slot), and the vault folder path. NOT exposed through PyO3 /
    /// uniffi.
    ///
    /// Folds the five sequential `lock_or_recover` calls in `save_block`
    /// into a single critical section, closing the same TOCTOU window
    /// `snapshot_for_read_block` closes for the read path.
    ///
    /// Returns `None` if the handle has been wiped before the lock was
    /// taken.
    pub(crate) fn snapshot_for_save_block(
        &self,
    ) -> Option<(
        Manifest,
        ManifestFile,
        ContactCard,
        Sensitive<[u8; 32]>,
        std::path::PathBuf,
    )> {
        lock_or_recover(&self.inner).as_ref().map(|i| {
            (
                i.manifest.clone(),
                i.manifest_file.clone(),
                i.owner_card.clone(),
                Sensitive::new(*i.identity_block_key.expose()),
                i.vault_folder.clone(),
            )
        })
    }
```

**Note for the engineer:** the IBK clone uses `Sensitive::new(*i.identity_block_key.expose())`. The dereference `*` copies the `[u8; 32]` array (Copy); the source slot's `Sensitive<...>` keeps its original bytes intact and zeroizes them on its own drop. The cloned `Sensitive<[u8; 32]>` returned by this accessor zeroizes when the orchestrator drops it. No explicit stack-copy zeroize is needed here because the dereference produces a temporary that's immediately moved into `Sensitive::new` — but verify this matches the patterns in `crate::vault::split_core_open_vault` (run `grep -n "split_core_open_vault\|Sensitive::new(\\*" ffi/secretary-ffi-bridge/src/vault.rs`).

- [ ] **Step 5: Run tests; confirm they pass**

Run: `cargo test --release --workspace -p secretary-ffi-bridge snapshot_for_save_block 2>&1 | tail -10`
Expected: 2 tests PASS.

- [ ] **Step 6: Add a method-removal warning suppressant if the new accessor lints as unused**

If clippy or rustc warns "method is never used" because Task 2 hasn't landed yet, add `#[allow(dead_code)]` immediately above the method (mirrors the existing `vault_folder()` / `manifest_body()` / `owner_card()` accessors which use the same allow). This allow is removed automatically when Task 2's `save_block` consumes the method.

```rust
    #[allow(dead_code)] // consumed by crate::save::save_block in Task 2
    pub(crate) fn snapshot_for_save_block(
```

- [ ] **Step 7: cargo clippy + fmt; full bridge test run; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
cargo test --release --workspace -p secretary-ffi-bridge 2>&1 | grep -E "^test result:" | tail -5
```
Expected: all bridge tests PASS, count is up by 9 (2 SaveCryptoFailure + 5 SecretString + 3 FieldInputValue/BlockInput sanity — wait, count from this task only: 2 snapshot tests). Confirm no regressions.

```bash
git add ffi/secretary-ffi-bridge/src/vault.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): add snapshot_for_save_block accessor on OpenVaultManifest

Folds the 5 sequential lock acquisitions save_block needs (manifest,
manifest_file, owner_card, IBK clone, vault folder) into a single
critical section. Mirrors snapshot_for_read_block's TOCTOU-closing
pattern.

Per docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §5.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Bridge `save_block` orchestrator

**Goal:** Land the `save_block` free function. End of this task: full bridge round-trip works (save → read returns same records, save→reopen→read returns same records).

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/save/orchestration.rs`
- Modify: `ffi/secretary-ffi-bridge/src/save/mod.rs` (declare `pub mod orchestration;` + `pub use orchestration::save_block;`)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (add `pub use save::save_block;`)
- Modify: `ffi/secretary-ffi-bridge/src/vault.rs` (remove `#[allow(dead_code)]` from `snapshot_for_save_block` since it's now consumed)

### Task 2.1: Stub the orchestrator with a single failing test

- [ ] **Step 1: Write the round-trip integration test FIRST (will fail to compile because `save_block` doesn't exist yet)**

Create `ffi/secretary-ffi-bridge/src/save/orchestration.rs`:

```rust
//! `save_block` — free-function entry point that locks both handles,
//! builds a temporary `core::vault::OpenVault` from clones, calls
//! `core::vault::save_block`, and on Ok writes back the mutated manifest +
//! manifest_file into the bridge handle.
//!
//! Failure invariant: bridge in-memory state is byte-identical to pre-call
//! on Err. On-disk state may have a partial write (block file present,
//! manifest re-sign failed) — harmless because `open_vault` reads only
//! entries listed in the manifest.
//!
//! v1 single-author: recipients = [owner_card]. Multi-recipient is B.4d.
//!
//! Rationale: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §5.

use rand::rngs::OsRng;
use secretary_core::vault::block::BlockPlaintext;
use secretary_core::vault::orchestrators::OpenVault;
use secretary_core::vault::VaultError;

use crate::error::FfiVaultError;
use crate::identity::{SignerSecretKeysError, UnlockedIdentity};
use crate::save::input::BlockInput;
use crate::vault::OpenVaultManifest;

/// Encrypt and atomically persist one block of records.
///
/// See module-level docs for the failure invariant. v1 single-author:
/// recipients are owner-only; multi-recipient is B.4d.
pub fn save_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    input: BlockInput,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // Stub: implementation in Step 3.
    let _ = (identity, manifest, input, device_uuid, now_ms);
    Err(FfiVaultError::SaveCryptoFailure {
        detail: "save_block not yet implemented".into(),
    })
}

#[cfg(test)]
mod tests {
    // Tests added in subsequent steps.
}
```

- [ ] **Step 2: Wire `save_block` into the module + lib re-exports**

Edit `ffi/secretary-ffi-bridge/src/save/mod.rs` to declare orchestration:

```rust
pub mod input;
pub mod orchestration;

pub use input::{BlockInput, FieldInput, FieldInputValue, RecordInput, SecretString};
pub use orchestration::save_block;
```

Edit `ffi/secretary-ffi-bridge/src/lib.rs` to re-export `save_block` at crate root:

```rust
pub use save::{save_block, BlockInput, FieldInput, FieldInputValue, RecordInput, SecretString};
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build --release --workspace -p secretary-ffi-bridge 2>&1 | tail -10`
Expected: clean build. (No tests yet; we'll add the round-trip test in Task 2.2.)

- [ ] **Step 4: Remove the `#[allow(dead_code)]` from `snapshot_for_save_block`**

In `ffi/secretary-ffi-bridge/src/vault.rs`, delete the `#[allow(dead_code)]` line above `snapshot_for_save_block` (it's no longer needed once the orchestrator references it; even though the stub doesn't reference it yet, it will after Task 2.3).

Actually — the stub does NOT reference `snapshot_for_save_block` yet. **Keep the `#[allow(dead_code)]` for now**; remove it in Task 2.3 Step 5 (after the real implementation lands).

- [ ] **Step 5: Commit the stub**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-bridge/src/save/ ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): stub save_block free function

Returns SaveCryptoFailure unconditionally for now — the real data flow
lands in the next commit. This commit pins the public surface (signature
+ module structure) so the round-trip tests and PyO3/uniffi wrappers
can compile against it incrementally.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 2.2: Write the round-trip test (still failing)

- [ ] **Step 1: Read the test fixture pattern from `record/orchestration.rs`**

Run: `grep -n "fn fresh_\|fn build_\|setup_\|fn vault_with_" ffi/secretary-ffi-bridge/src/record/orchestration.rs ffi/secretary-ffi-bridge/src/vault.rs ffi/secretary-ffi-bridge/src/unlock.rs | head -20`

Locate the existing helper that constructs a `(UnlockedIdentity, OpenVaultManifest)` pair backed by a tempdir. Reuse it.

- [ ] **Step 2: Add the round-trip integration test in `save/orchestration.rs`**

Append to the `#[cfg(test)] mod tests` block in `save/orchestration.rs`:

```rust
    use super::*;
    use crate::record::read_block;
    use crate::save::input::{FieldInput, FieldInputValue, RecordInput};
    use secretary_core::crypto::secret::SecretBytes;
    use crate::save::input::SecretString;

    /// Fixture: opens a fresh vault in a tempdir, returns (tempdir,
    /// identity, manifest). The tempdir is held by the test so the
    /// vault folder stays alive for the duration of the test.
    fn fresh_open_vault_with_tempdir() -> (
        tempfile::TempDir,
        UnlockedIdentity,
        OpenVaultManifest,
    ) {
        // The exact construction depends on the existing test helpers in
        // the bridge crate. See vault.rs's
        // `snapshot_for_read_block_returns_some_triple_when_live_and_none_when_wiped`
        // for the canonical fixture; mirror it here.
        unimplemented!("port the existing fixture; see vault.rs tests")
    }

    #[test]
    fn save_block_insert_round_trips_through_read_block() {
        let (_tmp, identity, manifest) = fresh_open_vault_with_tempdir();
        let device_uuid = [7u8; 16];
        let now_ms: u64 = 1_715_000_000_000;
        let block_uuid = [0xABu8; 16];

        let input = BlockInput {
            block_uuid,
            block_name: "Notes".to_string(),
            records: vec![RecordInput {
                record_uuid: [0xCDu8; 16],
                fields: vec![
                    FieldInput {
                        name: "title".to_string(),
                        value: FieldInputValue::Text(SecretString::new("wifi password".to_string())),
                    },
                    FieldInput {
                        name: "key".to_string(),
                        value: FieldInputValue::Bytes(SecretBytes::new(vec![0xDE, 0xAD, 0xBE, 0xEF])),
                    },
                ],
            }],
        };

        save_block(&identity, &manifest, input, device_uuid, now_ms)
            .expect("save_block should succeed");

        // The manifest should now report the new block.
        assert_eq!(manifest.block_count(), 1);
        let summary = manifest.find_block(&block_uuid).expect("block findable");
        assert_eq!(summary.block_name, "Notes");

        // Round-trip: read it back.
        let output = read_block(&identity, &manifest, &block_uuid)
            .expect("read_block should succeed");
        assert_eq!(output.record_count(), 1);
        let record = output.record_at(0).expect("record present");
        assert_eq!(record.field_count(), 2);
        let title = record.field_by_name("title").expect("field present");
        assert_eq!(title.expose_text().as_deref(), Some("wifi password"));
        let key = record.field_by_name("key").expect("field present");
        assert_eq!(key.expose_bytes(), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }
```

**Note for the engineer:** the `fresh_open_vault_with_tempdir` helper is `unimplemented!()` here as a placeholder. **Before Step 4 of Task 2.3, port the actual fixture from `vault.rs`'s test module** (search: `grep -n "snapshot_for_read_block_returns_some_triple\|fn fresh_open_vault" ffi/secretary-ffi-bridge/src/vault.rs`). The exact helper differs by what's in scope; copy the working pattern.

- [ ] **Step 3: Run the test; confirm it fails**

Run: `cargo test --release --workspace -p secretary-ffi-bridge save_block_insert_round_trips 2>&1 | tail -15`
Expected: FAIL — either the helper panics with `unimplemented!()` (port it before continuing) or the test reaches `save_block` which currently returns the stub `SaveCryptoFailure`. Either failure mode is fine for now; we're seeing the test exists and fails for the expected reason.

- [ ] **Step 4: Port the fixture helper**

Replace the `unimplemented!()` body of `fresh_open_vault_with_tempdir` with the actual logic. Cross-reference the existing helper in `vault.rs` tests (do not commit broken code; the test helper must construct a real `(tempdir, identity, manifest)` triple).

If the existing fixture in `vault.rs` is private to that module's `tests` block, either:
- Promote it to a `pub(crate) mod test_helpers` shared module, or
- Duplicate the helper in `save/orchestration.rs`'s test module (acceptable for first-cut; can DRY later).

The simpler choice is duplication for now; the helper is ~30 lines.

- [ ] **Step 5: Confirm the test now compiles + runs to the stub**

Run: `cargo test --release --workspace -p secretary-ffi-bridge save_block_insert_round_trips 2>&1 | tail -15`
Expected: FAIL with stub error message ("save_block not yet implemented"). The fixture works; the orchestrator is the only missing piece.

(Don't commit yet; Task 2.3 implements the real orchestrator and commits both together.)

### Task 2.3: Implement the real orchestrator

- [ ] **Step 1: Replace the stub body with the data flow**

Edit `ffi/secretary-ffi-bridge/src/save/orchestration.rs`. Replace the stub `save_block` body with:

```rust
pub fn save_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    input: BlockInput,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    use crate::sync_helpers::lock_or_recover;
    use secretary_core::crypto::secret::Sensitive;
    use zeroize::Zeroize as _;

    // Step 1: snapshot the manifest under one lock acquisition.
    let (manifest_body, manifest_file, owner_card, ibk, vault_folder) = manifest
        .snapshot_for_save_block()
        .ok_or(FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    // Step 2: snapshot the identity (clone for the temporary OpenVault).
    let identity_clone = {
        let guard = lock_or_recover(&identity.inner);
        let id = guard.as_ref().ok_or(FfiVaultError::CorruptVault {
            detail: "identity handle has been closed".into(),
        })?;
        id.identity.clone()
    };
    // Drop the identity lock here; we have the owned clone.

    // Step 3: build BlockPlaintext from BlockInput (briefly exposes
    // SecretString / SecretBytes contents to populate core's un-zeroized
    // RecordFieldValue arms; the bridge wrappers drop after this).
    let plaintext = build_block_plaintext(input, now_ms, device_uuid);

    // Step 4: build the temporary OpenVault. Cloning manifest + manifest_file
    // is the unmodified-on-failure invariant.
    let mut open_vault = OpenVault {
        identity_block_key: ibk,
        identity: identity_clone,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    };

    // Step 5: call core. Owner-only recipients via from_ref.
    let result = secretary_core::vault::orchestrators::save_block(
        &vault_folder,
        &mut open_vault,
        plaintext,
        std::slice::from_ref(&open_vault.owner_card),
        device_uuid,
        now_ms,
        &mut OsRng,
    );

    // Step 6: on Ok, write back the mutated manifest + manifest_file into
    // the bridge handle.
    match result {
        Ok(()) => {
            let mut guard = lock_or_recover(&manifest.inner);
            // The handle could have been wiped between Step 1 and now in a
            // theoretical concurrent-wipe race. If so, the on-disk write
            // already succeeded; we surface a CorruptVault to the caller
            // because the bridge state is no longer authoritative.
            let inner = guard.as_mut().ok_or(FfiVaultError::CorruptVault {
                detail: "vault manifest handle has been closed during save".into(),
            })?;
            inner.manifest = open_vault.manifest;
            inner.manifest_file = open_vault.manifest_file;
            // open_vault drops here; identity, owner_card, ibk all
            // zeroize-on-drop via their wrappers.
            Ok(())
        }
        Err(e) => Err(map_core_vault_error(e)),
    }
}

/// Convert `BlockInput` → `core::vault::block::BlockPlaintext`. Briefly
/// exposes the wrapped String / Vec<u8> to populate `RecordFieldValue::Text`
/// / `RecordFieldValue::Bytes`; the SecretString / SecretBytes wrappers
/// drop after this conversion.
fn build_block_plaintext(
    input: BlockInput,
    now_ms: u64,
    device_uuid: [u8; 16],
) -> BlockPlaintext {
    BlockPlaintext {
        block_uuid: input.block_uuid,
        block_name: input.block_name,
        created_at_ms: now_ms,
        last_mod_ms: now_ms,
        records: input
            .records
            .into_iter()
            .map(|r| r.into_core_record(now_ms, device_uuid))
            .collect(),
        trash: Vec::new(),
        unknown: std::collections::BTreeMap::new(),
    }
}

/// Map `core::vault::VaultError` → `FfiVaultError` per spec §6.
fn map_core_vault_error(e: VaultError) -> FfiVaultError {
    // The exact arms depend on the current VaultError shape. Rough mapping:
    //   - Io { ... }                   → FolderInvalid { detail: format!("{e}") }
    //   - everything crypto/encoding   → SaveCryptoFailure { detail }
    // Verify the current variants by grepping core::vault::VaultError;
    // adjust arms accordingly. Default for unmatched: SaveCryptoFailure
    // with the Display string preserved, since save-time failures on
    // already-validated inputs are categorically save-crypto.
    match &e {
        VaultError::Io { context, .. } => FfiVaultError::FolderInvalid {
            detail: format!("{context}: {e}"),
        },
        _ => FfiVaultError::SaveCryptoFailure {
            detail: format!("{e}"),
        },
    }
}
```

**Note for the engineer:** the actual `core::vault::block::BlockPlaintext` struct field names may differ from the sketch above. **Before pasting**, run:

```bash
grep -n "pub struct BlockPlaintext" core/src/vault/block.rs
sed -n '/pub struct BlockPlaintext/,/^}/p' core/src/vault/block.rs
```

and adjust `build_block_plaintext` to match the current core surface (especially `trash`, `unknown`, and any `vector_clock` field). The conversion is mechanical; just preserve the fields that exist and use the values from `input` / `now_ms` / `device_uuid`.

Similarly, run `grep -n "pub enum VaultError\|^    [A-Z]" core/src/vault/mod.rs core/src/vault/orchestrators.rs | head -30` to identify the actual `VaultError` variants and tighten `map_core_vault_error` to match. `Io { context, source }` is one known variant; the others (e.g. `Crypto`, `Block`, `Manifest`) all map to `SaveCryptoFailure`.

- [ ] **Step 2: Run the round-trip test; confirm it passes**

Run: `cargo test --release --workspace -p secretary-ffi-bridge save_block_insert_round_trips 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 3: Remove the `#[allow(dead_code)]` from `snapshot_for_save_block`**

In `ffi/secretary-ffi-bridge/src/vault.rs`, delete the `#[allow(dead_code)] // consumed by crate::save::save_block in Task 2` line above `snapshot_for_save_block`.

- [ ] **Step 4: Run the full bridge test suite; confirm no regressions**

Run: `cargo test --release --workspace -p secretary-ffi-bridge 2>&1 | grep -E "^test result:" | tail -5`
Expected: count up by 1 (the new round-trip test); all existing tests still PASS.

- [ ] **Step 5: cargo clippy + fmt; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-bridge/src/save/orchestration.rs ffi/secretary-ffi-bridge/src/vault.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): implement save_block free function

Locks both inner mutexes once each (snapshot_for_save_block + identity
clone), builds a temporary core::vault::OpenVault from clones, calls
core::save_block, and on Ok writes back the mutated manifest +
manifest_file. Failure invariant: bridge in-memory state unchanged on
Err; clones drop and zeroize.

Per docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §5.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 2.4: Add the remaining bridge tests

- [ ] **Step 1: Add the update / empty / mixed / persists / wiped-* tests**

Append to the `mod tests` block in `save/orchestration.rs`:

```rust
    #[test]
    fn save_block_update_replaces_existing_entry_and_advances_clock() {
        let (_tmp, identity, manifest) = fresh_open_vault_with_tempdir();
        let device_uuid = [7u8; 16];
        let block_uuid = [0xABu8; 16];

        let input1 = BlockInput {
            block_uuid,
            block_name: "v1".to_string(),
            records: vec![],
        };
        save_block(&identity, &manifest, input1, device_uuid, 1_000).expect("first save");
        let v1_summary = manifest.find_block(&block_uuid).expect("v1 present");
        assert_eq!(v1_summary.block_name, "v1");
        let created_at_v1 = v1_summary.created_at_ms;

        let input2 = BlockInput {
            block_uuid,
            block_name: "v2".to_string(),
            records: vec![],
        };
        save_block(&identity, &manifest, input2, device_uuid, 2_000).expect("second save");
        assert_eq!(manifest.block_count(), 1, "still one block (replaced, not appended)");
        let v2_summary = manifest.find_block(&block_uuid).expect("v2 present");
        assert_eq!(v2_summary.block_name, "v2");
        assert_eq!(v2_summary.created_at_ms, created_at_v1, "created_at_ms preserved across updates");
        assert!(v2_summary.last_modified_ms > v1_summary.last_modified_ms);
    }

    #[test]
    fn save_block_with_empty_records_succeeds() {
        let (_tmp, identity, manifest) = fresh_open_vault_with_tempdir();
        let input = BlockInput {
            block_uuid: [0xABu8; 16],
            block_name: "empty".to_string(),
            records: vec![],
        };
        save_block(&identity, &manifest, input, [7u8; 16], 1_000).expect("empty block save");
        assert_eq!(manifest.block_count(), 1);
    }

    #[test]
    fn save_block_with_mixed_text_and_bytes_fields_round_trips() {
        let (_tmp, identity, manifest) = fresh_open_vault_with_tempdir();
        let block_uuid = [0xABu8; 16];
        let input = BlockInput {
            block_uuid,
            block_name: "mixed".to_string(),
            records: vec![RecordInput {
                record_uuid: [0xCDu8; 16],
                fields: vec![
                    FieldInput {
                        name: "t".to_string(),
                        value: FieldInputValue::Text(SecretString::new("text".to_string())),
                    },
                    FieldInput {
                        name: "b".to_string(),
                        value: FieldInputValue::Bytes(SecretBytes::new(vec![1, 2, 3])),
                    },
                ],
            }],
        };
        save_block(&identity, &manifest, input, [7u8; 16], 1_000).expect("mixed save");

        let output = read_block(&identity, &manifest, &block_uuid).expect("read back");
        let r = output.record_at(0).unwrap();
        assert_eq!(r.field_by_name("t").unwrap().expose_text().as_deref(), Some("text"));
        assert_eq!(r.field_by_name("b").unwrap().expose_bytes(), Some(vec![1, 2, 3]));
    }

    #[test]
    fn save_block_persists_to_disk_visible_to_fresh_open() {
        // After save_block, drop the manifest handle, re-open the vault,
        // confirm the new block is in the fresh manifest.
        let (tmp, identity, manifest) = fresh_open_vault_with_tempdir();
        let block_uuid = [0xABu8; 16];
        let input = BlockInput {
            block_uuid,
            block_name: "persisted".to_string(),
            records: vec![],
        };
        save_block(&identity, &manifest, input, [7u8; 16], 1_000).expect("save");

        // Drop the original handles. Re-open via the same fixture password.
        // The fixture helper exposes the password used; if not, parameterize.
        drop(manifest);
        drop(identity);

        // Re-open. The exact password and re-open logic mirror the fixture
        // helper; copy the relevant snippet from
        // crate::record::orchestration::tests's persistence test.
        // (If no equivalent re-open test exists yet, this is the first;
        // construct the minimal re-open via crate::open_vault_with_password.)
        let folder = tmp.path();
        // ... (re-open logic; see fixture helper for the exact construction)
        // assert_eq!(reopened_manifest.block_count(), 1);
        // assert_eq!(reopened_manifest.find_block(&block_uuid).unwrap().block_name, "persisted");
        let _ = folder; // placeholder until re-open code is filled in by the engineer
    }

    #[test]
    fn save_block_on_wiped_manifest_returns_corrupt_vault_handle_closed() {
        let (_tmp, identity, manifest) = fresh_open_vault_with_tempdir();
        manifest.wipe();
        let input = BlockInput {
            block_uuid: [0xABu8; 16],
            block_name: "x".to_string(),
            records: vec![],
        };
        let err = save_block(&identity, &manifest, input, [7u8; 16], 1_000).unwrap_err();
        match err {
            FfiVaultError::CorruptVault { detail } => {
                assert!(detail.contains("manifest"), "got: {detail}");
            }
            other => panic!("expected CorruptVault, got: {other:?}"),
        }
    }

    #[test]
    fn save_block_on_wiped_identity_returns_corrupt_vault_handle_closed() {
        let (_tmp, identity, manifest) = fresh_open_vault_with_tempdir();
        identity.wipe();
        let input = BlockInput {
            block_uuid: [0xABu8; 16],
            block_name: "x".to_string(),
            records: vec![],
        };
        let err = save_block(&identity, &manifest, input, [7u8; 16], 1_000).unwrap_err();
        match err {
            FfiVaultError::CorruptVault { detail } => {
                assert!(detail.contains("identity"), "got: {detail}");
            }
            other => panic!("expected CorruptVault, got: {other:?}"),
        }
    }
```

**Note for the engineer:** the `save_block_persists_to_disk_visible_to_fresh_open` test has a placeholder for the re-open logic. Before running the test, fill in the re-open by calling whatever the bridge's folder-based open path is (e.g. `crate::vault::open_vault_with_password` or similar). Search for the canonical "open the same vault twice" pattern in the existing bridge test suite — it's how B.4a's tests verify open works.

- [ ] **Step 2: Run all save_block tests; confirm they pass**

Run: `cargo test --release --workspace -p secretary-ffi-bridge save_block 2>&1 | tail -20`
Expected: 7 PASS (insert + update + empty + mixed + persists + wiped-manifest + wiped-identity).

- [ ] **Step 3: Add the failure-invariant test (cfg(unix))**

Append to the same `mod tests`:

```rust
    #[cfg(unix)]
    #[test]
    fn save_block_failure_leaves_in_memory_manifest_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let (tmp, identity, manifest) = fresh_open_vault_with_tempdir();
        let block_uuid = [0xABu8; 16];

        // Take a snapshot of the pre-call state.
        let pre_count = manifest.block_count();

        // Make the vault folder read-only so blocks/ creation / write fails.
        let mut perms = std::fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(tmp.path(), perms.clone()).unwrap();

        let input = BlockInput {
            block_uuid,
            block_name: "doomed".to_string(),
            records: vec![],
        };
        let result = save_block(&identity, &manifest, input, [7u8; 16], 1_000);

        // Restore perms so the tempdir cleanup works.
        let mut restored = std::fs::metadata(tmp.path()).unwrap().permissions();
        restored.set_mode(0o755);
        std::fs::set_permissions(tmp.path(), restored).unwrap();

        // The save must have failed (FolderInvalid).
        assert!(matches!(result, Err(FfiVaultError::FolderInvalid { .. })),
            "expected FolderInvalid, got: {:?}", result);

        // CRITICAL: in-memory state unchanged.
        assert_eq!(manifest.block_count(), pre_count);
        assert!(manifest.find_block(&block_uuid).is_none());
    }
```

- [ ] **Step 4: Run the failure-invariant test**

Run: `cargo test --release --workspace -p secretary-ffi-bridge save_block_failure_leaves 2>&1 | tail -10`
Expected: PASS on macOS / Linux. On Windows the test is `#[cfg(unix)]` and skipped — skipping is acceptable.

- [ ] **Step 5: cargo clippy + fmt; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-bridge/src/save/orchestration.rs
git commit -m "$(cat <<'EOF'
test(ffi-b4c): add update / empty / mixed / persists / wiped-* / failure-invariant tests

Failure invariant: chmod the vault folder to read-only, expect FolderInvalid,
assert manifest.block_count() and find_block() remain at pre-call values.
cfg(unix); Windows analogue is out of scope (the property under test is
bridge-side, not platform-IO-side).

Per docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md §7, §8.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 2.5: Add the proptest

- [ ] **Step 1: Check that `proptest` is already in dev-dependencies for the bridge crate**

Run: `grep -n "proptest" ffi/secretary-ffi-bridge/Cargo.toml`

If not present, add to `[dev-dependencies]`:

```toml
proptest = "1"
```

- [ ] **Step 2: Add the proptest**

Append to `mod tests` in `save/orchestration.rs`:

```rust
    use proptest::prelude::*;

    fn arb_field_input() -> impl Strategy<Value = FieldInput> {
        let name = "[a-z]{1,16}";
        let text_value = "[ -~]{0,64}";
        let bytes_value = proptest::collection::vec(any::<u8>(), 0..64);
        (
            name.prop_map(String::from),
            prop_oneof![
                text_value.prop_map(|s| FieldInputValue::Text(SecretString::new(s))),
                bytes_value.prop_map(|b| FieldInputValue::Bytes(SecretBytes::new(b))),
            ],
        )
            .prop_map(|(name, value)| FieldInput { name, value })
    }

    fn arb_record_input() -> impl Strategy<Value = RecordInput> {
        (
            any::<[u8; 16]>(),
            proptest::collection::vec(arb_field_input(), 0..4),
        )
            .prop_map(|(record_uuid, fields)| RecordInput { record_uuid, fields })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn block_input_round_trips_through_save_and_read(
            block_uuid in any::<[u8; 16]>(),
            block_name in "[a-z]{1,32}",
            records in proptest::collection::vec(arb_record_input(), 0..4),
        ) {
            let (_tmp, identity, manifest) = fresh_open_vault_with_tempdir();
            let input = BlockInput { block_uuid, block_name: block_name.clone(), records: records.clone() };
            save_block(&identity, &manifest, input, [7u8; 16], 1_000)?;

            let output = read_block(&identity, &manifest, &block_uuid)
                .map_err(|e| TestCaseError::fail(format!("read failed: {e:?}")))?;
            prop_assert_eq!(output.record_count() as usize, records.len());
        }
    }
```

(64 cases is conservative; bump to 256 later if stable.)

- [ ] **Step 3: Run the proptest**

Run: `cargo test --release --workspace -p secretary-ffi-bridge block_input_round_trips_through 2>&1 | tail -20`
Expected: PASS for 64 cases.

- [ ] **Step 4: Confirm full bridge test count**

Run: `cargo test --release --workspace -p secretary-ffi-bridge 2>&1 | grep -E "^test result:" | tail -5`
Expected: total bridge test count = 83 (post-PR-#33 baseline) + 17 unit + 1 proptest = 101 PASS lines.

- [ ] **Step 5: cargo clippy + fmt; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-bridge/Cargo.toml ffi/secretary-ffi-bridge/src/save/orchestration.rs
git commit -m "$(cat <<'EOF'
test(ffi-b4c): add proptest for save_block → read_block round-trip

64 cases over arbitrary BlockInput shapes (block_uuid, block_name, mixed
text/bytes fields). Pins the property that any well-formed BlockInput
round-trips through save_block + read_block without losing records.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: uniffi surface

**Goal:** Expose `save_block` to Swift / Kotlin via uniffi 0.31. End of this task: 4 Swift smoke tests + 4 Kotlin smoke tests pass.

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (add SaveCryptoFailure variant; add input dictionaries; add namespace fn)
- Modify: `ffi/secretary-ffi-uniffi/src/errors.rs` (mirror SaveCryptoFailure variant + From-impl)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace.rs` (add save_block namespace fn)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs` (add input types + save_block to pub use)
- Modify: `ffi/secretary-ffi-uniffi/tests/swift_smoke.swift` or equivalent (add 4 tests)
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin_smoke.kt` or equivalent (add 4 tests)

### Task 3.1: Mirror the SaveCryptoFailure variant in uniffi

- [ ] **Step 1: Read the current uniffi VaultError**

Run: `grep -n "interface VaultError\|SaveCryptoFailure\|FolderInvalid\|BlockNotFound" ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/errors.rs`

The UDL has `[Error] interface VaultError` with 8 variants. We add `SaveCryptoFailure(string detail)` as the 9th.

- [ ] **Step 2: Add the variant to the UDL**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside `[Error] interface VaultError { ... }`, add immediately after `InvalidArgument(string detail);`:

```
    SaveCryptoFailure(string detail);
```

- [ ] **Step 3: Mirror the variant in `errors.rs` and update the From-impl**

In `ffi/secretary-ffi-uniffi/src/errors.rs`, locate the uniffi-side `VaultError` enum and add the variant:

```rust
    /// Save-time crypto failure on already-validated inputs.
    /// Mirrors `secretary_ffi_bridge::FfiVaultError::SaveCryptoFailure`.
    SaveCryptoFailure { detail: String },
```

Then in the `From<bridge::FfiVaultError> for VaultError` impl, add the arm:

```rust
            bridge::FfiVaultError::SaveCryptoFailure { detail } => {
                VaultError::SaveCryptoFailure { detail }
            }
```

- [ ] **Step 4: Add the variant pin test**

In `errors.rs`'s test module, locate `vault_error_maps_each_variant_one_to_one` (search: `grep -n "vault_error_maps_each_variant" ffi/secretary-ffi-uniffi/src/errors.rs`). Add a new test function:

```rust
    #[test]
    fn vault_error_save_crypto_failure_maps_one_to_one() {
        let bridge_err = bridge::FfiVaultError::SaveCryptoFailure {
            detail: "test detail".into(),
        };
        match VaultError::from(bridge_err) {
            VaultError::SaveCryptoFailure { detail } => assert_eq!(detail, "test detail"),
            other => panic!("expected SaveCryptoFailure, got {:?}", other),
        }
    }
```

- [ ] **Step 5: Run uniffi tests; confirm new test passes + no regressions**

Run: `cargo test --release --workspace -p secretary-ffi-uniffi 2>&1 | grep -E "^test result:" | tail -5`
Expected: count up by 1; all tests PASS.

- [ ] **Step 6: cargo clippy + fmt; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/errors.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): mirror SaveCryptoFailure variant on uniffi VaultError

Adds the 9th variant to the uniffi-side VaultError, mirroring
secretary_ffi_bridge::FfiVaultError::SaveCryptoFailure byte-for-byte
(variant name + detail). UDL declaration + Rust enum + From-impl arm
+ variant pin test.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 3.2: Add the input types and `save_block` namespace fn

- [ ] **Step 1: Add the input types to the UDL**

In `secretary.udl`, after the `BlockSummary` dictionary, add:

```
/// Tagged value for a single field on save. Maps to a Kotlin sealed class
/// / Swift enum / Python tagged dataclass at the binding-flavor layer.
[Enum]
interface FieldInputValue {
    /// UTF-8 text payload.
    Text(string text);
    /// Raw bytes payload.
    Bytes(bytes bytes);
};

/// One field on a record being saved.
dictionary FieldInput {
    /// Field name (plaintext).
    string name;
    /// Tagged value.
    FieldInputValue value;
};

/// One record being saved.
dictionary RecordInput {
    /// 16-byte record UUID.
    bytes record_uuid;
    /// Ordered list of fields.
    sequence<FieldInput> fields;
};

/// One block being saved. `records` may be empty (spec permits empty blocks).
dictionary BlockInput {
    /// 16-byte block UUID. Same uuid → update existing entry.
    bytes block_uuid;
    /// User-visible block name.
    string block_name;
    /// Records to save in this block.
    sequence<RecordInput> records;
};
```

- [ ] **Step 2: Add the namespace fn declaration**

Inside `namespace secretary { ... }` in the UDL, after the existing `read_block` declaration, add:

```
    /// Encrypt and atomically persist one block of records. (B.4c)
    [Throws=VaultError]
    void save_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        BlockInput input,
        bytes device_uuid,
        u64 now_ms
    );
```

- [ ] **Step 3: Add the namespace fn implementation**

In `ffi/secretary-ffi-uniffi/src/namespace.rs`, after the existing `read_block` namespace fn, add:

```rust
/// uniffi namespace fn: save_block. (B.4c)
///
/// Takes uniffi-side input dictionaries, converts them to bridge-side
/// types (which wrap secrets in SecretString / SecretBytes), and calls
/// `secretary_ffi_bridge::save_block`.
pub fn save_block(
    identity: std::sync::Arc<crate::wrappers::identity::UnlockedIdentity>,
    manifest: std::sync::Arc<crate::wrappers::vault::OpenVaultManifest>,
    input: BlockInput,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), crate::errors::VaultError> {
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_ffi_bridge::SecretString;

    // Validate device_uuid length first (uniffi-only InvalidArgument arm).
    let device_uuid: [u8; 16] = device_uuid
        .as_slice()
        .try_into()
        .map_err(|_| crate::errors::VaultError::InvalidArgument {
            detail: format!("device_uuid must be 16 bytes, got {}", device_uuid.len()),
        })?;

    // Validate input.block_uuid length.
    let block_uuid: [u8; 16] = input
        .block_uuid
        .as_slice()
        .try_into()
        .map_err(|_| crate::errors::VaultError::InvalidArgument {
            detail: format!("input.block_uuid must be 16 bytes, got {}", input.block_uuid.len()),
        })?;

    // Convert RecordInputs.
    let records: Result<Vec<_>, _> = input
        .records
        .into_iter()
        .map(|r| convert_record_input(r))
        .collect();
    let records = records?;

    let bridge_input = secretary_ffi_bridge::BlockInput {
        block_uuid,
        block_name: input.block_name,
        records,
    };

    secretary_ffi_bridge::save_block(
        identity.bridge_handle(),
        manifest.bridge_handle(),
        bridge_input,
        device_uuid,
        now_ms,
    )
    .map_err(crate::errors::VaultError::from)
}

fn convert_record_input(
    r: RecordInput,
) -> Result<secretary_ffi_bridge::RecordInput, crate::errors::VaultError> {
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_ffi_bridge::SecretString;

    let record_uuid: [u8; 16] = r
        .record_uuid
        .as_slice()
        .try_into()
        .map_err(|_| crate::errors::VaultError::InvalidArgument {
            detail: format!("record_uuid must be 16 bytes, got {}", r.record_uuid.len()),
        })?;

    let fields = r
        .fields
        .into_iter()
        .map(|f| secretary_ffi_bridge::FieldInput {
            name: f.name,
            value: match f.value {
                FieldInputValue::Text { text } => {
                    secretary_ffi_bridge::FieldInputValue::Text(SecretString::new(text))
                }
                FieldInputValue::Bytes { bytes } => {
                    secretary_ffi_bridge::FieldInputValue::Bytes(SecretBytes::new(bytes))
                }
            },
        })
        .collect();

    Ok(secretary_ffi_bridge::RecordInput { record_uuid, fields })
}

/// uniffi-flat dictionary mirrors of the bridge `BlockInput` etc. The UDL
/// declares these as record types; uniffi codegen emits matching Rust
/// structs that we convert into bridge types in `save_block` above.
#[derive(uniffi::Record)]
pub struct BlockInput {
    pub block_uuid: Vec<u8>,
    pub block_name: String,
    pub records: Vec<RecordInput>,
}

#[derive(uniffi::Record)]
pub struct RecordInput {
    pub record_uuid: Vec<u8>,
    pub fields: Vec<FieldInput>,
}

#[derive(uniffi::Record)]
pub struct FieldInput {
    pub name: String,
    pub value: FieldInputValue,
}

#[derive(uniffi::Enum)]
pub enum FieldInputValue {
    Text { text: String },
    Bytes { bytes: Vec<u8> },
}
```

**Note for the engineer:** uniffi 0.31 supports both UDL-only and proc-macro-augmented declarations. The crate currently uses UDL (per `secretary.udl`). If the project is UDL-only, the `#[derive(uniffi::Record)]` / `#[derive(uniffi::Enum)]` derives in this snippet are NOT needed — uniffi generates the Rust structs from the UDL automatically, and your `save_block` implementation just consumes the generated types. Check `uniffi::include_scaffolding!()` usage in `lib.rs` and follow whichever pattern (UDL-driven generation OR proc-macro derives) is already in use. If UDL-driven, remove the four `#[derive(uniffi::...)]` blocks above.

The `bridge_handle()` accessor on the uniffi wrapper types may not exist yet; if so, add `pub(crate) fn bridge_handle(&self) -> &secretary_ffi_bridge::UnlockedIdentity { &self.0 }` to `wrappers/identity.rs::UnlockedIdentity` (and similarly for `OpenVaultManifest`). If the wrapper field is not `pub(crate)`-accessible, add the accessor.

- [ ] **Step 4: Wire `save_block` into `lib.rs`'s pub use**

In `ffi/secretary-ffi-uniffi/src/lib.rs`:

```rust
pub use namespace::{
    create_vault, open_vault_with_password, open_vault_with_recovery, open_with_password,
    open_with_recovery, read_block, save_block,  // <-- add save_block
};

// Also re-export the input types if uniffi codegen needs them at crate root:
pub use namespace::{BlockInput, FieldInput, FieldInputValue, RecordInput};
```

- [ ] **Step 5: Build to confirm UDL + Rust agree**

Run: `cargo build --release --workspace -p secretary-ffi-uniffi 2>&1 | tail -20`
Expected: clean build. uniffi's `build.rs` regenerates scaffolding from `secretary.udl`; if there's a UDL/Rust mismatch, fix it before proceeding (errors will name the offending type).

- [ ] **Step 6: cargo clippy + fmt; commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-uniffi/
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): add save_block namespace fn + input dictionaries to uniffi

UDL declares BlockInput / RecordInput / FieldInput dictionaries +
FieldInputValue tagged enum + save_block namespace fn. Rust impl
converts uniffi-flat dictionaries to bridge SecretString / SecretBytes
wrappers and calls secretary_ffi_bridge::save_block.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 3.3: Swift smoke tests

- [ ] **Step 1: Locate the existing Swift smoke test runner**

Run: `find ffi/secretary-ffi-uniffi -name "*.swift" -o -name "swift_smoke*" -o -name "Package.swift" 2>/dev/null | head -10`

The project has an existing Swift smoke test harness from B.4b. The test invocation is documented in `ffi/secretary-ffi-uniffi/README.md` or the bindings directory.

- [ ] **Step 2: Add 4 new Swift smoke tests**

In the Swift smoke test file (likely `ffi/secretary-ffi-uniffi/bindings/swift/SmokeTests.swift` or similar), add:

```swift
func testSaveBlock_insertRoundTripsThroughReadBlock() throws {
    let (identity, manifest, _) = try freshOpenVault()
    let blockUuid = Data(repeating: 0xAB, count: 16)
    let input = BlockInput(
        blockUuid: blockUuid,
        blockName: "Notes",
        records: [
            RecordInput(
                recordUuid: Data(repeating: 0xCD, count: 16),
                fields: [
                    FieldInput(name: "title", value: .text(text: "wifi password")),
                    FieldInput(name: "key", value: .bytes(bytes: Data([0xDE, 0xAD, 0xBE, 0xEF]))),
                ]
            )
        ]
    )
    try saveBlock(identity: identity, manifest: manifest, input: input, deviceUuid: Data(repeating: 0x07, count: 16), nowMs: 1_000)

    let output = try readBlock(identity: identity, manifest: manifest, blockUuid: blockUuid)
    assert(output.recordCount() == 1)
}

func testSaveBlock_updateAdvancesVectorClock() throws {
    let (identity, manifest, _) = try freshOpenVault()
    let blockUuid = Data(repeating: 0xAB, count: 16)
    let inputV1 = BlockInput(blockUuid: blockUuid, blockName: "v1", records: [])
    try saveBlock(identity: identity, manifest: manifest, input: inputV1, deviceUuid: Data(repeating: 0x07, count: 16), nowMs: 1_000)
    let inputV2 = BlockInput(blockUuid: blockUuid, blockName: "v2", records: [])
    try saveBlock(identity: identity, manifest: manifest, input: inputV2, deviceUuid: Data(repeating: 0x07, count: 16), nowMs: 2_000)
    assert(manifest.blockCount() == 1)
    assert(manifest.findBlock(blockUuid: blockUuid)?.blockName == "v2")
}

func testSaveBlock_onWipedManifestSurfacesTypedError() throws {
    let (identity, manifest, _) = try freshOpenVault()
    manifest.wipe()
    let input = BlockInput(blockUuid: Data(repeating: 0xAB, count: 16), blockName: "x", records: [])
    do {
        try saveBlock(identity: identity, manifest: manifest, input: input, deviceUuid: Data(repeating: 0x07, count: 16), nowMs: 1_000)
        assertionFailure("expected throw")
    } catch VaultError.CorruptVault(let detail) {
        assert(detail.contains("manifest"))
    }
}

func testSaveBlock_textAndBytesFieldsRoundTrip() throws {
    let (identity, manifest, _) = try freshOpenVault()
    let blockUuid = Data(repeating: 0xAB, count: 16)
    let input = BlockInput(
        blockUuid: blockUuid,
        blockName: "mixed",
        records: [
            RecordInput(
                recordUuid: Data(repeating: 0xCD, count: 16),
                fields: [
                    FieldInput(name: "t", value: .text(text: "text")),
                    FieldInput(name: "b", value: .bytes(bytes: Data([1, 2, 3]))),
                ]
            )
        ]
    )
    try saveBlock(identity: identity, manifest: manifest, input: input, deviceUuid: Data(repeating: 0x07, count: 16), nowMs: 1_000)
    let output = try readBlock(identity: identity, manifest: manifest, blockUuid: blockUuid)
    let r = output.recordAt(idx: 0)!
    assert(r.fieldByName(name: "t")?.exposeText() == "text")
    assert(r.fieldByName(name: "b")?.exposeBytes() == Data([1, 2, 3]))
}
```

**Note for the engineer:** the exact test-runner invocation and helper signatures (`freshOpenVault`, `assert`, `assertionFailure`) come from the existing B.4b Swift smoke harness. Use the same patterns; cross-reference `testReadBlock_*` tests if you need a working baseline.

- [ ] **Step 3: Run the Swift smoke tests**

Run: (use whatever the existing project's Swift smoke runner invocation is; document it in the task's notes if not obvious from the README)

```bash
# Example, adjust to match the project's actual harness:
cd ffi/secretary-ffi-uniffi
./run-swift-tests.sh   # or equivalent
```

Expected: 26 total Swift PASS lines (22 existing + 4 new).

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-uniffi/bindings/  # or wherever Swift tests live
git commit -m "$(cat <<'EOF'
test(ffi-b4c): add 4 Swift smoke tests for save_block

Insert round-trip, update vector-clock advancement, wiped-manifest typed
error, and text/bytes field round-trip. Total Swift smoke: 22 → 26.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 3.4: Kotlin smoke tests

- [ ] **Step 1: Add 4 Kotlin smoke tests**

In the Kotlin smoke test file (likely `ffi/secretary-ffi-uniffi/bindings/kotlin/SmokeTests.kt` or similar), add the parallel four tests. The Kotlin sealed-class form of `FieldInputValue` is `FieldInputValue.Text(text = "...")` / `FieldInputValue.Bytes(bytes = byteArrayOf(...))`. The tests mirror the Swift ones structurally:

```kotlin
@Test fun saveBlock_insertRoundTripsThroughReadBlock() {
    val (identity, manifest, _) = freshOpenVault()
    val blockUuid = ByteArray(16) { 0xAB.toByte() }
    val input = BlockInput(
        blockUuid = blockUuid,
        blockName = "Notes",
        records = listOf(
            RecordInput(
                recordUuid = ByteArray(16) { 0xCD.toByte() },
                fields = listOf(
                    FieldInput(name = "title", value = FieldInputValue.Text(text = "wifi password")),
                    FieldInput(name = "key", value = FieldInputValue.Bytes(bytes = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()))),
                )
            )
        )
    )
    saveBlock(identity, manifest, input, ByteArray(16) { 0x07 }, 1_000UL)

    val output = readBlock(identity, manifest, blockUuid)
    assert(output.recordCount() == 1UL)
}

@Test fun saveBlock_updateAdvancesVectorClock() {
    val (identity, manifest, _) = freshOpenVault()
    val blockUuid = ByteArray(16) { 0xAB.toByte() }
    saveBlock(identity, manifest, BlockInput(blockUuid, "v1", emptyList()), ByteArray(16) { 0x07 }, 1_000UL)
    saveBlock(identity, manifest, BlockInput(blockUuid, "v2", emptyList()), ByteArray(16) { 0x07 }, 2_000UL)
    assert(manifest.blockCount() == 1UL)
    assert(manifest.findBlock(blockUuid)?.blockName == "v2")
}

@Test fun saveBlock_onWipedManifestSurfacesTypedError() {
    val (identity, manifest, _) = freshOpenVault()
    manifest.wipe()
    val input = BlockInput(ByteArray(16) { 0xAB.toByte() }, "x", emptyList())
    try {
        saveBlock(identity, manifest, input, ByteArray(16) { 0x07 }, 1_000UL)
        error("expected throw")
    } catch (e: VaultException.CorruptVault) {
        assert(e.detail.contains("manifest"))
    }
}

@Test fun saveBlock_textAndBytesFieldsRoundTrip() {
    val (identity, manifest, _) = freshOpenVault()
    val blockUuid = ByteArray(16) { 0xAB.toByte() }
    val input = BlockInput(
        blockUuid = blockUuid,
        blockName = "mixed",
        records = listOf(
            RecordInput(
                recordUuid = ByteArray(16) { 0xCD.toByte() },
                fields = listOf(
                    FieldInput(name = "t", value = FieldInputValue.Text(text = "text")),
                    FieldInput(name = "b", value = FieldInputValue.Bytes(bytes = byteArrayOf(1, 2, 3))),
                )
            )
        )
    )
    saveBlock(identity, manifest, input, ByteArray(16) { 0x07 }, 1_000UL)
    val output = readBlock(identity, manifest, blockUuid)
    val r = output.recordAt(0UL)!!
    assert(r.fieldByName("t")?.exposeText() == "text")
    assert(r.fieldByName("b")?.exposeBytes()?.contentEquals(byteArrayOf(1, 2, 3)) == true)
}
```

- [ ] **Step 2: Run the Kotlin smoke tests**

Run: (use the existing project's Kotlin smoke runner invocation)

Expected: 27 total Kotlin PASS lines (23 existing + 4 new).

- [ ] **Step 3: Commit**

```bash
git add ffi/secretary-ffi-uniffi/bindings/   # or wherever Kotlin tests live
git commit -m "$(cat <<'EOF'
test(ffi-b4c): add 4 Kotlin smoke tests for save_block

Mirrors the Swift coverage: insert round-trip, update vector-clock,
wiped-manifest typed error, text/bytes round-trip. Total Kotlin smoke:
23 → 27.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: PyO3 surface

**Goal:** Expose `save_block` to Python via PyO3 0.28. End of this task: 10 new pytest tests pass.

**Files:**
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (exception class + #[pyclass] inputs + #[pyfunction] save_block + module registration)
- Modify: `ffi/secretary-ffi-py/tests/test_smoke.py` (10 new tests)

### Task 4.1: Add the exception class and From-impl arm

- [ ] **Step 1: Read the existing exception-class registration pattern**

Run: `grep -n "create_exception\|VaultBlockNotFound\|VaultCorruptVault" ffi/secretary-ffi-py/src/lib.rs | head -10`

The pattern: `create_exception!(secretary_ffi_py, VaultBlockNotFound, PyException)` at the top, `m.add("VaultBlockNotFound", py.get_type::<VaultBlockNotFound>())?;` in the module-init block.

- [ ] **Step 2: Add the exception class**

In `ffi/secretary-ffi-py/src/lib.rs`, alongside the existing `VaultBlockNotFound` `create_exception!` macro:

```rust
create_exception!(secretary_ffi_py, VaultSaveCryptoFailure, PyException);
```

- [ ] **Step 3: Add the From-impl arm**

Locate the `From<bridge::FfiVaultError> for PyErr` impl (search: `grep -n "impl From<.*FfiVaultError" ffi/secretary-ffi-py/src/lib.rs`). Add the arm:

```rust
            bridge::FfiVaultError::SaveCryptoFailure { detail } => {
                VaultSaveCryptoFailure::new_err(detail)
            }
```

- [ ] **Step 4: Register the exception class in the module**

In the `#[pymodule] fn secretary_ffi_py(...)` body, add:

```rust
    m.add("VaultSaveCryptoFailure", py.get_type::<VaultSaveCryptoFailure>())?;
```

- [ ] **Step 5: Build to confirm**

Run: `( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv ) 2>&1 | tail -5`
Expected: clean build.

- [ ] **Step 6: Commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-py/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): add VaultSaveCryptoFailure PyO3 exception class

Mirrors uniffi's VaultError.SaveCryptoFailure variant on the Python side.
From<bridge::FfiVaultError::SaveCryptoFailure> for PyErr maps the variant
to VaultSaveCryptoFailure(detail).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 4.2: Add the input #[pyclass] types and save_block #[pyfunction]

- [ ] **Step 1: Add the input types**

In `ffi/secretary-ffi-py/src/lib.rs`, after the existing `BlockSummary` `#[pyclass]` block, add:

```rust
#[pyclass]
#[derive(Clone)]
pub struct PyFieldInputValue {
    inner: secretary_ffi_bridge::FieldInputValue,
}

#[pymethods]
impl PyFieldInputValue {
    #[staticmethod]
    pub fn text(s: String) -> Self {
        Self {
            inner: secretary_ffi_bridge::FieldInputValue::Text(
                secretary_ffi_bridge::SecretString::new(s),
            ),
        }
    }

    #[staticmethod]
    pub fn bytes(b: Vec<u8>) -> Self {
        Self {
            inner: secretary_ffi_bridge::FieldInputValue::Bytes(
                secretary_core::crypto::secret::SecretBytes::new(b),
            ),
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyFieldInput {
    #[pyo3(get, set)]
    pub name: String,
    pub value: PyFieldInputValue,
}

#[pymethods]
impl PyFieldInput {
    #[new]
    pub fn new(name: String, value: PyFieldInputValue) -> Self {
        Self { name, value }
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyRecordInput {
    pub record_uuid: [u8; 16],
    pub fields: Vec<PyFieldInput>,
}

#[pymethods]
impl PyRecordInput {
    #[new]
    pub fn new(record_uuid: Vec<u8>, fields: Vec<PyFieldInput>) -> PyResult<Self> {
        let record_uuid: [u8; 16] = record_uuid
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("record_uuid must be 16 bytes"))?;
        Ok(Self { record_uuid, fields })
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyBlockInput {
    pub block_uuid: [u8; 16],
    #[pyo3(get, set)]
    pub block_name: String,
    pub records: Vec<PyRecordInput>,
}

#[pymethods]
impl PyBlockInput {
    #[new]
    pub fn new(block_uuid: Vec<u8>, block_name: String, records: Vec<PyRecordInput>) -> PyResult<Self> {
        let block_uuid: [u8; 16] = block_uuid
            .try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("block_uuid must be 16 bytes"))?;
        Ok(Self { block_uuid, block_name, records })
    }
}
```

- [ ] **Step 2: Add the save_block #[pyfunction]**

After the existing `read_block` #[pyfunction], add:

```rust
#[pyfunction]
pub fn save_block(
    identity: &PyUnlockedIdentity,
    manifest: &PyOpenVaultManifest,
    input: &PyBlockInput,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let device_uuid: [u8; 16] = device_uuid
        .try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("device_uuid must be 16 bytes"))?;

    let bridge_records: Vec<secretary_ffi_bridge::RecordInput> = input
        .records
        .iter()
        .map(|r| secretary_ffi_bridge::RecordInput {
            record_uuid: r.record_uuid,
            fields: r
                .fields
                .iter()
                .map(|f| secretary_ffi_bridge::FieldInput {
                    name: f.name.clone(),
                    value: f.value.inner.clone(),
                })
                .collect(),
        })
        .collect();

    let bridge_input = secretary_ffi_bridge::BlockInput {
        block_uuid: input.block_uuid,
        block_name: input.block_name.clone(),
        records: bridge_records,
    };

    secretary_ffi_bridge::save_block(
        identity.bridge_handle(),
        manifest.bridge_handle(),
        bridge_input,
        device_uuid,
        now_ms,
    )
    .map_err(PyErr::from)
}
```

**Note for the engineer:** the `bridge_handle()` accessors on `PyUnlockedIdentity` and `PyOpenVaultManifest` may not exist yet — add them as `pub(crate) fn bridge_handle(&self) -> &secretary_ffi_bridge::UnlockedIdentity { &self.0 }` (and parallel for the manifest) if needed. The exact field name depends on the existing wrapper struct shape; cross-reference `PyOpenVaultManifest::vault_uuid` etc. for how the field is currently accessed.

- [ ] **Step 3: Register the new types and function in the module**

In `#[pymodule]`, add:

```rust
    m.add_class::<PyFieldInputValue>()?;
    m.add_class::<PyFieldInput>()?;
    m.add_class::<PyRecordInput>()?;
    m.add_class::<PyBlockInput>()?;
    m.add_function(wrap_pyfunction!(save_block, m)?)?;
```

(Use whatever name the existing `read_block` registration uses for consistency.)

- [ ] **Step 4: Rebuild and confirm load**

Run:
```bash
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv ) 2>&1 | tail -5
uv run --directory ffi/secretary-ffi-py python -c "import secretary_ffi_py; print(secretary_ffi_py.save_block)"
```
Expected: `<built-in function save_block>`.

- [ ] **Step 5: Commit**

```bash
cargo clippy --release --workspace -- -D warnings
cargo fmt --all
git add ffi/secretary-ffi-py/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b4c): add PyO3 save_block #[pyfunction] + input types

PyBlockInput / PyRecordInput / PyFieldInput / PyFieldInputValue with
length-validated constructors (16-byte UUIDs raise ValueError).
PyFieldInputValue.text / .bytes static methods construct the wrapped
SecretString / SecretBytes. save_block #[pyfunction] converts to bridge
types and calls secretary_ffi_bridge::save_block.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task 4.3: Add the 10 pytest tests

- [ ] **Step 1: Apply the maturin/uv cache nuclear reset before adding tests**

Per CLAUDE.md and the auto-memory note about `maturin develop + uv editable cache stickiness`:

```bash
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} + 2>/dev/null || true
( cd ffi/secretary-ffi-py && uv sync && uv run maturin develop --release --uv )
```

- [ ] **Step 2: Add the tests**

Append to `ffi/secretary-ffi-py/tests/test_smoke.py`:

```python
import os
import tempfile

import pytest
import secretary_ffi_py as ffi


def fresh_open_vault(tmp_path: str):
    """Helper: create + open a fresh vault in tmp_path. Returns (identity, manifest, password)."""
    # Mirror the existing B.4b helper used by test_read_block_*; cross-reference
    # the test_smoke.py test that opens a vault for read_block testing.
    ...  # PORT THE EXISTING HELPER HERE


def test_save_block_round_trip_insert(tmp_path):
    identity, manifest = fresh_open_vault(str(tmp_path))
    block_uuid = bytes([0xAB] * 16)
    input = ffi.PyBlockInput(
        block_uuid=block_uuid,
        block_name="Notes",
        records=[
            ffi.PyRecordInput(
                record_uuid=bytes([0xCD] * 16),
                fields=[
                    ffi.PyFieldInput("title", ffi.PyFieldInputValue.text("wifi password")),
                    ffi.PyFieldInput("key", ffi.PyFieldInputValue.bytes(b"\xDE\xAD\xBE\xEF")),
                ],
            ),
        ],
    )
    ffi.save_block(identity, manifest, input, bytes([0x07] * 16), 1_000)
    assert manifest.block_count() == 1
    output = ffi.read_block(identity, manifest, block_uuid)
    assert output.record_count() == 1


def test_save_block_update_advances_vector_clock(tmp_path):
    identity, manifest = fresh_open_vault(str(tmp_path))
    uuid = bytes([0xAB] * 16)
    ffi.save_block(identity, manifest, ffi.PyBlockInput(uuid, "v1", []), bytes([0x07] * 16), 1_000)
    ffi.save_block(identity, manifest, ffi.PyBlockInput(uuid, "v2", []), bytes([0x07] * 16), 2_000)
    assert manifest.block_count() == 1
    assert manifest.find_block(uuid).block_name == "v2"


def test_save_block_text_field_round_trip(tmp_path):
    identity, manifest = fresh_open_vault(str(tmp_path))
    uuid = bytes([0xAB] * 16)
    rec = ffi.PyRecordInput(
        record_uuid=bytes([0xCD] * 16),
        fields=[ffi.PyFieldInput("t", ffi.PyFieldInputValue.text("text"))],
    )
    ffi.save_block(identity, manifest, ffi.PyBlockInput(uuid, "x", [rec]), bytes([0x07] * 16), 1_000)
    output = ffi.read_block(identity, manifest, uuid)
    r = output.record_at(0)
    assert r.field_by_name("t").expose_text() == "text"


def test_save_block_bytes_field_round_trip(tmp_path):
    identity, manifest = fresh_open_vault(str(tmp_path))
    uuid = bytes([0xAB] * 16)
    rec = ffi.PyRecordInput(
        record_uuid=bytes([0xCD] * 16),
        fields=[ffi.PyFieldInput("b", ffi.PyFieldInputValue.bytes(b"\x01\x02\x03"))],
    )
    ffi.save_block(identity, manifest, ffi.PyBlockInput(uuid, "x", [rec]), bytes([0x07] * 16), 1_000)
    output = ffi.read_block(identity, manifest, uuid)
    r = output.record_at(0)
    assert r.field_by_name("b").expose_bytes() == b"\x01\x02\x03"


def test_save_block_empty_records_allowed(tmp_path):
    identity, manifest = fresh_open_vault(str(tmp_path))
    uuid = bytes([0xAB] * 16)
    ffi.save_block(identity, manifest, ffi.PyBlockInput(uuid, "empty", []), bytes([0x07] * 16), 1_000)
    assert manifest.block_count() == 1


def test_save_block_on_wiped_manifest_raises_corrupt_vault_error(tmp_path):
    identity, manifest = fresh_open_vault(str(tmp_path))
    manifest.wipe()
    with pytest.raises(ffi.VaultCorruptVault):
        ffi.save_block(identity, manifest, ffi.PyBlockInput(bytes([0xAB] * 16), "x", []), bytes([0x07] * 16), 1_000)


def test_save_block_on_wiped_identity_raises_corrupt_vault_error(tmp_path):
    identity, manifest = fresh_open_vault(str(tmp_path))
    identity.wipe()
    with pytest.raises(ffi.VaultCorruptVault):
        ffi.save_block(identity, manifest, ffi.PyBlockInput(bytes([0xAB] * 16), "x", []), bytes([0x07] * 16), 1_000)


def test_save_block_wrong_length_block_uuid_raises_value_error(tmp_path):
    with pytest.raises(ValueError):
        ffi.PyBlockInput(b"\x00" * 5, "x", [])  # too short


def test_save_block_persists_visible_to_fresh_open(tmp_path):
    # Save, drop handles, re-open, confirm block visible.
    identity, manifest = fresh_open_vault(str(tmp_path))
    uuid = bytes([0xAB] * 16)
    ffi.save_block(identity, manifest, ffi.PyBlockInput(uuid, "persisted", []), bytes([0x07] * 16), 1_000)
    # Re-open via the same fixture password; cross-reference fresh_open_vault.
    # ... (port re-open logic from existing helper)
    ...


def test_save_crypto_failure_error_class_is_distinct(tmp_path):
    # Smoke: VaultSaveCryptoFailure is importable and distinct from
    # VaultCorruptVault.
    assert ffi.VaultSaveCryptoFailure is not ffi.VaultCorruptVault
    assert issubclass(ffi.VaultSaveCryptoFailure, Exception)
```

**Note for the engineer:** the `fresh_open_vault` helper and the re-open logic in `test_save_block_persists_visible_to_fresh_open` are placeholders. Port them from the existing read_block tests; the helper exists in some form because B.4b's test_smoke.py opens a vault.

- [ ] **Step 3: Run pytest**

Run: `uv run --directory ffi/secretary-ffi-py pytest -v 2>&1 | tail -30`
Expected: 50 PASS (40 existing + 10 new).

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-py/tests/test_smoke.py
git commit -m "$(cat <<'EOF'
test(ffi-b4c): add 10 pytest tests for save_block

Insert / update / text / bytes / empty / wiped-manifest /
wiped-identity / wrong-length / persists / SaveCryptoFailure-distinct.
Total pytest: 40 → 50.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Docs (rides on the same branch, BEFORE pushing)

**Goal:** Update README.md, ROADMAP.md, NEXT_SESSION.md, and write a timestamped handoff. Per the user's explicit feedback memory, NEXT_SESSION.md is committed on the FEATURE branch BEFORE pushing the PR — not after merge.

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Modify: `NEXT_SESSION.md`
- Create: `docs/handoffs/YYYY-MM-DD-b4c-save-block.md`

### Task 5.1: Update README.md "Where we are"

- [ ] **Step 1: Read current "Where we are" section**

Run: `grep -n "Where we are\|cargo + .* ignored\|552\|570" README.md`

- [ ] **Step 2: Update the totals**

Replace the post-PR-#33 numbers (552 cargo + 9 ignored, 83 bridge, 18 uniffi, 40 pytest, 22 Swift, 23 Kotlin) with the post-B.4c numbers:

- 570 cargo + 9 ignored
- ~101 bridge (83 + 17 unit + 1 proptest)
- 22 uniffi (18 + 1 SaveCryptoFailure mirror test + 3 namespace fn tests if added in passing)
- 50 pytest
- 26 Swift smoke
- 27 Kotlin smoke

(Adjust uniffi count to whatever the actual post-Task 3 count is.)

- [ ] **Step 3: Add a B.4c bullet to "What's done"**

In the "What's done" section under B.4, add:

> - **B.4c (Sub-project B.4 task 3):** `save_block` end-to-end — bridge orchestrator + PyO3 + uniffi (Swift + Kotlin) surfaces; round-trip through `read_block` verified at every flavor.

### Task 5.2: Update ROADMAP.md

- [ ] **Step 1: Mark B.4c done**

Find the B.4c entry in `ROADMAP.md` and update its status row to "shipped" with the date `2026-05-XX`. Move B.4d to the next-up slot.

### Task 5.3: Replace NEXT_SESSION.md with the B.4d baton

- [ ] **Step 1: Write the new NEXT_SESSION.md**

The new content should:
- Identify what shipped this session (B.4c with task commit SHAs — pull from `git log --oneline feat/ffi-b4c-save-block`)
- Identify what's next (B.4d — share_block, multi-recipient extension; or B.4-cleanup-2 if that's the priority)
- Open decisions / risks for B.4d
- Exact commands to resume on the next session (cd, branch, test command)

The format mirrors the previous NEXT_SESSION.md (this very session's). Use the prior file as a template; replace the B.4b cleanup specifics with B.4c specifics.

### Task 5.4: Create the timestamped handoff

- [ ] **Step 1: Create the handoff file**

```bash
DATE=$(date +%Y-%m-%d)
cp NEXT_SESSION.md docs/handoffs/${DATE}-b4c-save-block.md
```

(The handoff file is a snapshot of NEXT_SESSION.md at session-end; the canonical copy in the repo root rolls forward.)

### Task 5.5: Run final verification, commit docs, push, open PR

- [ ] **Step 1: Final full verification**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"

cargo clippy --release --workspace -- -D warnings
cargo fmt --all -- --check

uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -5
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Swift + Kotlin smokes (use the project's invocation)
```

Expected:
- TOTAL: 570 passed; 0 failed; 9 ignored
- clippy clean
- fmt OK
- 50 pytest passed
- conformance PASS
- spec freshness PASS
- 26 Swift PASS
- 27 Kotlin PASS

- [ ] **Step 2: Commit docs**

```bash
git add README.md ROADMAP.md NEXT_SESSION.md docs/handoffs/
git commit -m "$(cat <<'EOF'
docs(ffi-b4c): update README + ROADMAP + NEXT_SESSION + handoff

Post-B.4c totals: 570 cargo + 9 ignored, 50 pytest, 26 Swift, 27 Kotlin.
Handoff: docs/handoffs/YYYY-MM-DD-b4c-save-block.md.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

(Replace `YYYY-MM-DD` in the handoff filename with the actual date — `git add docs/handoffs/` should pick up the actual file.)

- [ ] **Step 3: Push and open PR**

```bash
git push -u origin feat/ffi-b4c-save-block

gh pr create --title "feat(ffi-b4c): save_block end-to-end through bridge + PyO3 + uniffi" --body "$(cat <<'EOF'
## Summary

- Adds `save_block` to the bridge crate as a free function mirroring B.4b's `read_block` shape.
- Exposes it through PyO3 (`secretary_ffi_py.save_block`) and uniffi (`save_block` namespace fn) with type-safe input shapes.
- New `FfiVaultError::SaveCryptoFailure` variant separates save-time crypto failures (on already-validated inputs) from on-disk vault corruption.
- v1 single-author: recipients are owner-only; multi-recipient extension is B.4d.
- Spec: docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md.

## Test plan

- [x] `cargo test --release --workspace` (570 passed + 9 ignored)
- [x] `cargo clippy --release --workspace -- -D warnings` (clean)
- [x] `cargo fmt --all -- --check` (OK)
- [x] `uv run --directory ffi/secretary-ffi-py pytest` (50 passed)
- [x] `uv run core/tests/python/conformance.py` (PASS)
- [x] `uv run core/tests/python/spec_test_name_freshness.py` (PASS)
- [x] Swift smoke (26 PASS)
- [x] Kotlin smoke (27 PASS)

\u{1F916} Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

Spec coverage:
- §2 architectural decisions → enforced by Task 1 (locking + interior mutability via existing Mutex), Task 1.2 (input shape), Task 2 (caller-provides ID/now_ms in fn signature), Task 2.3 (owner-only via `from_ref`), Task 1.2 (SecretString wrappers).
- §3 module structure → Task 1.2 creates `save/`, Task 2.1 adds `orchestration.rs`.
- §4 public bridge API → Task 1.2 + Task 2.1 + Task 2.3 land it.
- §5 data flow → Task 2.3 implements the 6 steps.
- §6 error mapping → Task 1.1 adds the variant; Task 2.3's `map_core_vault_error` implements the table.
- §7 failure invariant → Task 2.4 adds the cfg(unix) test.
- §8 test plan → Tasks 1.1–1.4 (accessors + variant), 2.2–2.5 (round-trip + variants + proptest), 3.3–3.4 (Swift + Kotlin smoke), 4.3 (pytest).
- §9 scope boundaries → honored throughout (no multi-recipient, no trash, no perf, no v2 zeroize-typing).
- §10 risks → documented in spec; failure invariant has a test; clone cost is acknowledged in plan.
- §11 build sequence → Tasks 1–5 mirror it.

Placeholder scan: 4 places explicitly say "PORT THE EXISTING HELPER HERE" or `unimplemented!()` for fixture helpers. These are intentional engineer-attention markers (the existing helper is in a different module's test block; the engineer has to either DRY it into a shared helper or duplicate it). Each occurrence is flagged with a "Note for the engineer" paragraph explaining what to copy from where. Acceptable per the writing-plans skill's tolerance for "engineer-attention markers" — NOT acceptable for hidden TBDs that lack the explicit note.

Type consistency: `save_block` signature is identical across Tasks 1.4 (declaration), 2.1 (stub), 2.3 (impl). `BlockInput` / `RecordInput` / `FieldInput` / `FieldInputValue` / `SecretString` field names are consistent across Tasks 1.2, 2.1, 3.2 (uniffi), 4.2 (PyO3). `FfiVaultError::SaveCryptoFailure { detail: String }` shape is identical at every binding flavor.
