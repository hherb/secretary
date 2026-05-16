# B.6 v1 pre-v2 cleanup bundle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land four B.6 v1 PR-review follow-ups (#60 file split, #61 broader read_block wrong-length coverage, #62 Swift+Kotlin assertion-block factoring, #63 Kotlin cache drain) as one branch with one commit per issue, so the test harness is structurally + semantically ready for B.6 v2 (#59).

**Architecture:** Pure refactor + small additive changes. No `core/src/` or bridge-crate changes. The four commits are sequenced #60 → #61 → #62 → #63: the file split lands first so #61's new vectors slot into the new structure; #62's helper-factoring lands before #63's Kotlin-only cache drain so the latter rebases cleanly on top.

**Tech Stack:** Rust 1.x (stable) + Swift 5.x (host runner) + Kotlin/JVM (host runner via uniffi). No new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-16-b6-pre-v2-cleanup-bundle-design.md](../specs/2026-05-16-b6-pre-v2-cleanup-bundle-design.md)

**Branch:** `chore/b6-pre-v2-cleanup` (already created off `main` at `d1595c5`)

---

## Pre-flight (already done — for reference only)

- ✅ Workspace synced to `main` at `d1595c5` (B.6 v1 squash merge).
- ✅ Stale `feature/ffi-b6-conformance-kat-v1` branch deleted via `clean_gone` skill.
- ✅ Baseline gauntlet on main passes (cargo test exit 0; clippy clean; fmt OK; Python conformance + freshness PASS).
- ✅ Branch `chore/b6-pre-v2-cleanup` checked out.
- ✅ Spec doc committed as `85163b2`.

If resuming a fresh session, verify via:
```bash
cd /Users/hherb/src/secretary
git branch --show-current   # expect: chore/b6-pre-v2-cleanup
git log --oneline -2        # expect: 85163b2 docs(specs): ... pre-v2 cleanup bundle, d1595c5 feat(b6): ... PR #58
git status --short          # expect: clean
```

---

## Task 1: Split `core/tests/conformance_kat.rs` into directory module (closes #60)

**Files:**
- Modify: [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs) — shrinks from 595 LOC to ~120 LOC (entry only)
- Create: `core/tests/conformance_kat_helpers/mod.rs` — module aggregator
- Create: `core/tests/conformance_kat_helpers/types.rs` — `Kat`, `Vector`, `Operation`, `Expected`, `OkPayload`, `ExpectedRecord`, `ExpectedField`, `BridgeOrSyntheticErr`
- Create: `core/tests/conformance_kat_helpers/fixtures.rs` — `kat_path`, `fixtures_dir`, `resolve_*` family
- Create: `core/tests/conformance_kat_helpers/errors.rs` — `variant_name_vault`, `vault_error_detail`, `assert_err`, `read_block_err_*`
- Create: `core/tests/conformance_kat_helpers/dispatch.rs` — `run_*`, `assert_open_ok`, `assert_read_block_ok`
- Test (pre + post): the existing `replay_conformance_kat` + `generate_conformance_kat` tests; no new test code added.

**Pattern reference:** [core/tests/common/](../../../core/tests/common/) (existing mod.rs + sibling .rs pattern).

### Step 1.1: Establish baseline before any edit

- [ ] **Confirm pre-split baseline**

Run:
```bash
cargo test --release --workspace --no-fail-fast --test conformance_kat 2>&1 | grep -E "^test result:"
```
Expected: `test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in <X>s` (1 passed = `replay_conformance_kat`; 1 ignored = `generate_conformance_kat`).

Run:
```bash
wc -l core/tests/conformance_kat.rs
```
Expected: `594 core/tests/conformance_kat.rs` (current count, off by ±1 OK).

### Step 1.2: Create the helpers module skeleton

- [ ] **Create directory and empty mod.rs**

Run:
```bash
mkdir -p core/tests/conformance_kat_helpers
```

Create `core/tests/conformance_kat_helpers/mod.rs` with:

```rust
//! Helpers extracted from `conformance_kat.rs` for the B.6 v1 read-only
//! cross-language FFI conformance KAT replay. Split to keep the entry
//! file (the two `#[test]` fns) below the project's 500-LOC guideline.
//!
//! See `docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md`
//! for the protocol; see [`crate::replay_conformance_kat`] for the entry test.

pub mod dispatch;
pub mod errors;
pub mod fixtures;
pub mod types;
```

### Step 1.3: Move type definitions into `types.rs`

- [ ] **Create `types.rs`**

Create `core/tests/conformance_kat_helpers/types.rs` with the type defs lifted from current `conformance_kat.rs:31-103` and `:295-302`, plus `Deserialize` import:

```rust
//! KAT vector deserialization types and the bridge-or-synthetic error wrapper.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Kat {
    pub version: u32,
    #[serde(default)]
    #[allow(dead_code)] // documentation field; the replay does not read it.
    pub comment: String,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
pub struct Vector {
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation field; the replay does not read it.
    pub description: String,
    pub operation: Operation,
    pub inputs: serde_json::Value,
    #[serde(default)]
    pub after: Option<String>,
    pub expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    OpenVaultWithPassword,
    OpenVaultWithRecovery,
    ReadBlock,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expected {
    Ok(OkPayload),
    Err {
        variant: String,
        #[serde(default)]
        detail_contains: Option<String>,
    },
}

#[derive(Debug, Deserialize, Default)]
pub struct OkPayload {
    // Open ops:
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub block_count: Option<u64>,
    #[serde(default)]
    pub block_uuid_hex: Option<String>,
    // read_block records:
    #[serde(default)]
    pub records: Option<Vec<ExpectedRecord>>,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedRecord {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub fields: Vec<ExpectedField>,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String, // "text" or "bytes"
    #[serde(default)]
    pub value_utf8: Option<String>,
    #[serde(default)]
    pub value_hex: Option<String>,
}

/// Internal wrapper letting `run_read_block` surface either a real
/// `FfiVaultError` (from the bridge) OR a synthesized "InvalidArgument"
/// case-name when the input fails the wrong-length pre-check (the
/// bridge's `read_block` signature is `&[u8; 16]` so wrong-length is
/// rejected at the binding layer in production, not in core).
///
/// Synthesis rationale: see design doc §11 (B.6 v1) + plan Task 3.
#[derive(Debug)]
pub enum BridgeOrSyntheticErr {
    Bridge(secretary_ffi_bridge::error::FfiVaultError),
    Synthetic {
        variant: &'static str,
        detail: String,
    },
}
```

### Step 1.4: Move fixture / input-resolution helpers into `fixtures.rs`

- [ ] **Create `fixtures.rs`**

Create `core/tests/conformance_kat_helpers/fixtures.rs` with the fixture and resolver fns lifted from current `conformance_kat.rs:24-29` and `:109-167`:

```rust
//! Path resolvers + KAT vector input-resolution helpers.

use std::path::PathBuf;

pub fn kat_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("conformance_kat.json")
}

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
}

/// Resolves a `*_source` style input (e.g. `golden_vault_001_inputs.json:password`)
/// to its concrete bytes. Returns the UTF-8 bytes of the named JSON string field.
pub fn resolve_source(source: &str) -> Vec<u8> {
    let (file, field) = source
        .split_once(':')
        .unwrap_or_else(|| panic!("malformed source ref: {source}"));
    let path = fixtures_dir().join(file);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let json: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
    let value = json
        .get(field)
        .unwrap_or_else(|| panic!("field '{field}' missing in {}", path.display()));
    value
        .as_str()
        .unwrap_or_else(|| panic!("field '{field}' in {} is not a string", path.display()))
        .as_bytes()
        .to_vec()
}

pub fn resolve_vault_dir(inputs: &serde_json::Value) -> PathBuf {
    if let Some(s) = inputs.get("vault_dir").and_then(|v| v.as_str()) {
        return fixtures_dir().join(s);
    }
    if let Some(s) = inputs.get("vault_dir_literal").and_then(|v| v.as_str()) {
        return PathBuf::from(s);
    }
    panic!(
        "inputs must carry one of vault_dir / vault_dir_literal: {}",
        inputs
    );
}

pub fn resolve_password(inputs: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = inputs.get("password_source").and_then(|v| v.as_str()) {
        return resolve_source(s);
    }
    if let Some(s) = inputs.get("password_literal_utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    panic!("open_vault_with_password vector missing password_* input");
}

pub fn resolve_mnemonic(inputs: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = inputs.get("mnemonic_source").and_then(|v| v.as_str()) {
        return resolve_source(s);
    }
    if let Some(s) = inputs.get("mnemonic_literal_utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    panic!("open_vault_with_recovery vector missing mnemonic_* input");
}
```

### Step 1.5: Move error-mapping helpers into `errors.rs`

- [ ] **Create `errors.rs`**

Create `core/tests/conformance_kat_helpers/errors.rs` with the error-mapping helpers from current `conformance_kat.rs:173-205`, `:266-282`, and `:327-339`:

```rust
//! Error → variant-name mapping + assertion helpers shared by the dispatch loop.

use super::types::{BridgeOrSyntheticErr, Expected};

pub fn variant_name_vault(e: &secretary_ffi_bridge::error::FfiVaultError) -> &'static str {
    use secretary_ffi_bridge::error::FfiVaultError as E;
    match e {
        E::WrongPasswordOrCorrupt => "WrongPasswordOrCorrupt",
        E::WrongMnemonicOrCorrupt => "WrongMnemonicOrCorrupt",
        E::InvalidMnemonic { .. } => "InvalidMnemonic",
        E::VaultMismatch => "VaultMismatch",
        E::CorruptVault { .. } => "CorruptVault",
        E::FolderInvalid { .. } => "FolderInvalid",
        E::BlockNotFound { .. } => "BlockNotFound",
        E::SaveCryptoFailure { .. } => "SaveCryptoFailure",
        E::NotAuthor { .. } => "NotAuthor",
        E::RecipientAlreadyPresent => "RecipientAlreadyPresent",
        E::MissingRecipientCard { .. } => "MissingRecipientCard",
        E::CardDecodeFailure { .. } => "CardDecodeFailure",
        E::BlockUuidAlreadyLive { .. } => "BlockUuidAlreadyLive",
        E::BlockNotInTrash { .. } => "BlockNotInTrash",
    }
}

pub fn vault_error_detail(e: &secretary_ffi_bridge::error::FfiVaultError) -> Option<&str> {
    use secretary_ffi_bridge::error::FfiVaultError as E;
    match e {
        E::InvalidMnemonic { detail } => Some(detail.as_str()),
        E::CorruptVault { detail } => Some(detail.as_str()),
        E::FolderInvalid { detail } => Some(detail.as_str()),
        E::SaveCryptoFailure { detail } => Some(detail.as_str()),
        E::CardDecodeFailure { detail } => Some(detail.as_str()),
        E::BlockUuidAlreadyLive { detail } => Some(detail.as_str()),
        E::BlockNotInTrash { detail } => Some(detail.as_str()),
        _ => None,
    }
}

pub fn assert_err(
    label: &str,
    actual_variant: &str,
    actual_detail: Option<&str>,
    expected: &Expected,
) {
    let Expected::Err {
        variant,
        detail_contains,
    } = expected
    else {
        panic!("{label}: assert_err called but vector.expected is Ok — programmer error in caller");
    };
    assert_eq!(actual_variant, variant, "{label}: variant mismatch");
    if let Some(needle) = detail_contains {
        let haystack = actual_detail.unwrap_or("");
        assert!(
            haystack.contains(needle.as_str()),
            "{label}: detail '{haystack}' does not contain '{needle}'"
        );
    }
}

pub fn read_block_err_variant(e: &BridgeOrSyntheticErr) -> &str {
    match e {
        BridgeOrSyntheticErr::Bridge(b) => variant_name_vault(b),
        BridgeOrSyntheticErr::Synthetic { variant, .. } => variant,
    }
}

pub fn read_block_err_detail(e: &BridgeOrSyntheticErr) -> Option<&str> {
    match e {
        BridgeOrSyntheticErr::Bridge(b) => vault_error_detail(b),
        BridgeOrSyntheticErr::Synthetic { detail, .. } => Some(detail.as_str()),
    }
}
```

### Step 1.6: Move dispatch helpers into `dispatch.rs`

- [ ] **Create `dispatch.rs`**

Create `core/tests/conformance_kat_helpers/dispatch.rs` with the per-op runner + assert helpers from current `conformance_kat.rs:211-264`, `:304-325`, `:341-430`:

```rust
//! Per-operation dispatch + Ok-payload assertion helpers.
//!
//! `run_*` invoke the bridge crate; `assert_*` check the observable
//! output against the pinned expectation. The synthesis path in
//! `run_read_block` handles non-16-byte UUIDs at the test layer
//! because `FfiVaultError` doesn't expose an `InvalidArgument` variant
//! (that variant lives only on the uniffi-projected `VaultError`).

use super::fixtures::{resolve_mnemonic, resolve_password, resolve_vault_dir};
use super::types::{BridgeOrSyntheticErr, ExpectedField, ExpectedRecord, OkPayload};

pub fn run_open_password(
    inputs: &serde_json::Value,
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    let password = resolve_password(inputs);
    secretary_ffi_bridge::vault::open_vault_with_password(&vault_dir, &password)
}

pub fn run_open_recovery(
    inputs: &serde_json::Value,
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    let mnemonic = resolve_mnemonic(inputs);
    secretary_ffi_bridge::vault::open_vault_with_recovery(&vault_dir, &mnemonic)
}

pub fn run_read_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<secretary_ffi_bridge::record::BlockReadOutput, BridgeOrSyntheticErr> {
    let bytes_hex = inputs
        .get("block_uuid_hex")
        .or_else(|| inputs.get("block_uuid_bytes_hex"))
        .and_then(|v| v.as_str())
        .expect("read_block inputs need block_uuid_hex or block_uuid_bytes_hex");
    let bytes = hex::decode(bytes_hex).expect("block_uuid hex must decode");

    if bytes.len() != 16 {
        return Err(BridgeOrSyntheticErr::Synthetic {
            variant: "InvalidArgument",
            detail: format!("block_uuid must be exactly 16 bytes, got {}", bytes.len()),
        });
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes);
    secretary_ffi_bridge::record::read_block(&cached.identity, &cached.manifest, &uuid)
        .map_err(BridgeOrSyntheticErr::Bridge)
}

pub fn assert_open_ok(
    label: &str,
    output: &secretary_ffi_bridge::vault::OpenVaultOutput,
    expected: &OkPayload,
) {
    if let Some(name) = &expected.display_name {
        assert_eq!(
            &output.identity.display_name(),
            name,
            "{label}: display_name mismatch"
        );
    }
    if let Some(count) = expected.block_count {
        assert_eq!(
            output.manifest.block_count(),
            count,
            "{label}: block_count mismatch"
        );
    }
    if let Some(hex_str) = &expected.block_uuid_hex {
        hex::decode(hex_str).expect("block_uuid_hex must be valid hex");
        let summaries = output.manifest.block_summaries();
        assert!(
            !summaries.is_empty(),
            "{label}: manifest has no blocks but block_uuid_hex was pinned"
        );
        let actual_hex = hex::encode(summaries[0].block_uuid);
        assert_eq!(
            actual_hex,
            hex_str.to_lowercase(),
            "{label}: block_uuid mismatch"
        );
    }
}

pub fn assert_read_block_ok(
    label: &str,
    output: &secretary_ffi_bridge::record::BlockReadOutput,
    expected: &OkPayload,
) {
    let Some(records) = &expected.records else {
        // Vector pinned only the success shape; nothing more to check.
        return;
    };
    assert_eq!(
        output.record_count(),
        records.len(),
        "{label}: record_count mismatch"
    );
    for (i, exp_rec) in records.iter().enumerate() {
        let rec = output
            .record_at(i)
            .unwrap_or_else(|| panic!("{label}: record_at({i}) returned None"));
        assert_record(label, &rec, exp_rec, i);
    }
}

fn assert_record(
    label: &str,
    rec: &secretary_ffi_bridge::record::RecordHandle<'_>,
    exp_rec: &ExpectedRecord,
    i: usize,
) {
    assert_eq!(
        hex::encode(rec.record_uuid()),
        exp_rec.record_uuid_hex,
        "{label}: records[{i}].record_uuid mismatch"
    );
    assert_eq!(
        rec.record_type(),
        exp_rec.record_type,
        "{label}: records[{i}].record_type mismatch"
    );
    assert_eq!(
        rec.tags(),
        exp_rec.tags,
        "{label}: records[{i}].tags mismatch"
    );
    assert_eq!(
        rec.field_count(),
        exp_rec.fields.len(),
        "{label}: records[{i}].field_count mismatch"
    );
    for (j, exp_field) in exp_rec.fields.iter().enumerate() {
        let field = rec
            .field_at(j)
            .unwrap_or_else(|| panic!("{label}: records[{i}].field_at({j}) None"));
        assert_field(label, &field, exp_field, i, j);
    }
}

fn assert_field(
    label: &str,
    field: &secretary_ffi_bridge::record::FieldHandle<'_>,
    exp_field: &ExpectedField,
    i: usize,
    j: usize,
) {
    assert_eq!(
        field.name(),
        exp_field.name,
        "{label}: records[{i}].fields[{j}].name mismatch"
    );
    match exp_field.field_type.as_str() {
        "text" => {
            assert!(
                field.is_text(),
                "{label}: records[{i}].fields[{j}] expected text"
            );
            let actual = field
                .expose_text()
                .unwrap_or_else(|| panic!("{label}: expose_text returned None"));
            assert_eq!(
                &actual,
                exp_field
                    .value_utf8
                    .as_ref()
                    .expect("text field must pin value_utf8"),
                "{label}: records[{i}].fields[{j}].value_utf8 mismatch"
            );
        }
        "bytes" => {
            assert!(
                field.is_bytes(),
                "{label}: records[{i}].fields[{j}] expected bytes"
            );
            let actual = field
                .expose_bytes()
                .unwrap_or_else(|| panic!("{label}: expose_bytes returned None"));
            let expected_bytes = hex::decode(
                exp_field
                    .value_hex
                    .as_ref()
                    .expect("bytes field must pin value_hex"),
            )
            .expect("value_hex must decode");
            assert_eq!(
                actual, expected_bytes,
                "{label}: records[{i}].fields[{j}].value_hex mismatch"
            );
        }
        other => panic!("{label}: unknown field type '{other}'"),
    }
}
```

**Note on the `assert_record` / `assert_field` split:** I extracted these as small private helpers inside `dispatch.rs` because keeping the inline three-level nested loop made `assert_read_block_ok` ~90 LOC. Splitting them into focused helpers preserves the exact behaviour (same panic messages, same field-at indexing) while keeping each fn under ~50 LOC. Verify the type names `RecordHandle<'_>` and `FieldHandle<'_>` against the bridge crate at `ffi/secretary-ffi-bridge/src/record/` — if those are not the public types, fall back to inlining `assert_record` + `assert_field` directly inside `assert_read_block_ok`. (See Step 1.7 verification.)

### Step 1.7: Verify bridge crate handle types

- [ ] **Confirm `RecordHandle` and `FieldHandle` are nameable from the test crate**

Run:
```bash
grep -nE "^pub (struct|fn) (Record|Field)" ffi/secretary-ffi-bridge/src/record/*.rs ffi/secretary-ffi-bridge/src/record.rs 2>/dev/null
```

Expected: shows `pub struct RecordHandle` and `pub struct FieldHandle` (or similar). If the lifetime parameter differs from `<'_>` (e.g. it's `<'a>` with an explicit relationship), adjust the `assert_record` / `assert_field` signatures to match, or — simpler — inline both helpers back into `assert_read_block_ok`.

**Decision rule:**
- If `RecordHandle<'_>` + `FieldHandle<'_>` compile: keep the split.
- If they don't: revert to the inlined version (copy the body of `assert_record` into the `for` loop in `assert_read_block_ok`, copy `assert_field` body into its inner loop). Resulting `assert_read_block_ok` will be ~90 LOC and `dispatch.rs` will be ~200 LOC instead of ~230 — still well under 500.

### Step 1.8: Rewrite the entry file `conformance_kat.rs`

- [ ] **Replace `core/tests/conformance_kat.rs` contents**

Overwrite the existing file with this content (entry file only — the helpers live in the new module):

```rust
//! Cross-language FFI conformance KAT replay (B.6 v1 read-only path).
//!
//! Loads `core/tests/data/conformance_kat.json` and replays each
//! vector through the secretary-ffi-bridge crate, asserting the
//! observable output matches the pinned expectation. This is the
//! Rust side of a three-way contract; the Swift + Kotlin replays
//! live under `ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/`.
//!
//! Two entry points:
//!
//! - `replay_conformance_kat` — runs on every `cargo test` and
//!   gates protocol changes.
//! - `generate_conformance_kat` — `#[ignore]`-marked; runs the
//!   bridge crate against `golden_vault_001` and emits the JSON.
//!   Manually triggered on intentional protocol change; the diff
//!   is human-reviewed before commit.
//!
//! Implementation helpers live in [`conformance_kat_helpers`]; this
//! file is the test-fn entry surface only.

#![forbid(unsafe_code)]

mod conformance_kat_helpers;

use conformance_kat_helpers::dispatch::{
    assert_open_ok, assert_read_block_ok, run_open_password, run_open_recovery, run_read_block,
};
use conformance_kat_helpers::errors::{
    assert_err, read_block_err_detail, read_block_err_variant, variant_name_vault,
    vault_error_detail,
};
use conformance_kat_helpers::fixtures::{fixtures_dir, kat_path, resolve_source};
use conformance_kat_helpers::types::{Expected, Kat, Operation};

use std::collections::HashMap;

#[test]
fn replay_conformance_kat() {
    let raw = std::fs::read_to_string(kat_path()).expect("conformance_kat.json must be readable");
    let kat: Kat = serde_json::from_str(&raw).expect("conformance_kat.json must parse");
    assert_eq!(kat.version, 1, "KAT version must be 1");

    let mut cache: HashMap<String, secretary_ffi_bridge::vault::OpenVaultOutput> = HashMap::new();

    for vector in &kat.vectors {
        let label = &vector.name;
        match (&vector.operation, &vector.after) {
            (Operation::OpenVaultWithPassword, None) => {
                let result = run_open_password(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => {
                        assert_open_ok(label, &out, payload);
                        cache.insert(label.clone(), out);
                    }
                    (Expected::Err { .. }, Err(e)) => {
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => panic!("{label}: expected Ok, got Err {e:?}"),
                    (Expected::Err { .. }, Ok(_)) => panic!("{label}: expected Err, got Ok"),
                }
            }
            (Operation::OpenVaultWithRecovery, None) => {
                let result = run_open_recovery(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => {
                        assert_open_ok(label, &out, payload);
                        cache.insert(label.clone(), out);
                    }
                    (Expected::Err { .. }, Err(e)) => {
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => panic!("{label}: expected Ok, got Err {e:?}"),
                    (Expected::Err { .. }, Ok(_)) => panic!("{label}: expected Err, got Ok"),
                }
            }
            (Operation::ReadBlock, Some(predecessor)) => {
                let cached = cache.get(predecessor).unwrap_or_else(|| {
                    panic!("{label}: predecessor '{predecessor}' did not produce a cacheable Ok")
                });
                let result = run_read_block(&vector.inputs, cached);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => assert_read_block_ok(label, &out, payload),
                    (Expected::Err { .. }, Err(e)) => {
                        let v = read_block_err_variant(&e);
                        let d = read_block_err_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => {
                        panic!(
                            "{label}: expected Ok, got Err {}",
                            read_block_err_variant(&e)
                        )
                    }
                    (Expected::Err { .. }, Ok(_)) => panic!("{label}: expected Err, got Ok"),
                }
            }
            (Operation::ReadBlock, None) => {
                panic!("{label}: ReadBlock vectors must specify `after:`")
            }
            (Operation::OpenVaultWithPassword | Operation::OpenVaultWithRecovery, Some(_)) => {
                panic!("{label}: open_vault_* vectors must not specify `after:`")
            }
        }
    }
}

/// Re-emits `core/tests/data/conformance_kat.json` with `read_block_happy`'s
/// `records[]` array populated from the bridge crate's read_block output.
///
/// Run manually only on an intentional protocol change:
///
///     cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture
///
/// The diff is human-reviewed before commit. If the diff touches anything
/// OTHER than `read_block_happy.expected.records`, that's a regression in
/// the bridge crate or a wider protocol change — investigate before
/// accepting the generated file.
#[test]
#[ignore]
fn generate_conformance_kat() {
    let raw = std::fs::read_to_string(kat_path()).expect("conformance_kat.json must be readable");
    let mut kat: serde_json::Value =
        serde_json::from_str(&raw).expect("conformance_kat.json must parse");

    // Unlock golden_vault_001 once.
    let vault_dir = fixtures_dir().join("golden_vault_001");
    let password = resolve_source("golden_vault_001_inputs.json:password");
    let opened = secretary_ffi_bridge::vault::open_vault_with_password(&vault_dir, &password)
        .expect("open_vault_with_password(golden_vault_001) must succeed");

    let block_uuid_hex = "112233445566778899aabbccddeeff00";
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&hex::decode(block_uuid_hex).unwrap());
    let read = secretary_ffi_bridge::record::read_block(&opened.identity, &opened.manifest, &uuid)
        .expect("read_block(golden_vault_001 block) must succeed");

    let mut records_json = Vec::new();
    for i in 0..read.record_count() {
        let rec = read.record_at(i).expect("record_at must succeed");
        let mut fields_json = Vec::new();
        for j in 0..rec.field_count() {
            let f = rec.field_at(j).expect("field_at must succeed");
            let field_obj = if f.is_text() {
                serde_json::json!({
                    "name": f.name(),
                    "type": "text",
                    "value_utf8": f.expose_text().expect("text field must expose"),
                })
            } else {
                serde_json::json!({
                    "name": f.name(),
                    "type": "bytes",
                    "value_hex": hex::encode(f.expose_bytes().expect("bytes field must expose")),
                })
            };
            fields_json.push(field_obj);
        }
        records_json.push(serde_json::json!({
            "record_uuid_hex": hex::encode(rec.record_uuid()),
            "record_type": rec.record_type(),
            "tags": rec.tags(),
            "fields": fields_json,
        }));
    }

    let vectors = kat
        .get_mut("vectors")
        .and_then(|v| v.as_array_mut())
        .expect("vectors must be an array");
    let happy = vectors
        .iter_mut()
        .find(|v| v.get("name").and_then(|n| n.as_str()) == Some("read_block_happy"))
        .expect("read_block_happy vector must exist in the skeleton");
    happy
        .get_mut("expected")
        .and_then(|e| e.as_object_mut())
        .expect("expected must be an object")
        .insert(
            "records".to_string(),
            serde_json::Value::Array(records_json),
        );

    let pretty = serde_json::to_string_pretty(&kat).expect("KAT must reserialize") + "\n";
    std::fs::write(kat_path(), pretty).expect("KAT must be writable");
    eprintln!(
        "generate_conformance_kat: wrote {} ({} records under read_block_happy)",
        kat_path().display(),
        read.record_count()
    );
}
```

### Step 1.9: Run the test gauntlet

- [ ] **Verify all targeted tests still pass**

Run:
```bash
cargo test --release --workspace --no-fail-fast --test conformance_kat 2>&1 | grep -E "^test result:"
```
Expected: `test result: ok. 1 passed; 0 failed; 1 ignored; ...` (unchanged from baseline).

Then the full gauntlet:
```bash
cargo test --release --workspace --no-fail-fast 2>&1 | tee /tmp/cargo-test-task1.log | tail -5
```
Expected: exit code 0; the tail shows the last test result line.

Verify total count:
```bash
grep -E "^test result:" /tmp/cargo-test-task1.log | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
```
Expected: `TOTAL: 641 passed; 0 failed; 10 ignored` (unchanged from B.6 v1 close).

### Step 1.10: Run clippy + fmt

- [ ] **Verify lints + format clean**

Run:
```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
```
Expected: clean (no warnings, no errors). If there are warnings about unused imports in `conformance_kat.rs`, adjust the `use` block accordingly.

```bash
cargo fmt --all -- --check 2>&1 | tail -5
```
Expected: OK (no output, exit 0). If there's formatting drift, run `cargo fmt --all` and stage the resulting changes too.

### Step 1.11: Verify file sizes

- [ ] **Confirm split satisfied the 500-LOC guideline**

Run:
```bash
wc -l core/tests/conformance_kat.rs core/tests/conformance_kat_helpers/*.rs
```
Expected: each file under 500 LOC. Rough targets (approximations — exact counts may differ):
- `conformance_kat.rs`: ~150 LOC
- `conformance_kat_helpers/mod.rs`: ~10 LOC
- `conformance_kat_helpers/types.rs`: ~85 LOC
- `conformance_kat_helpers/fixtures.rs`: ~60 LOC
- `conformance_kat_helpers/errors.rs`: ~75 LOC
- `conformance_kat_helpers/dispatch.rs`: ~200 LOC (or ~250 if not splitting `assert_record`/`assert_field`)

### Step 1.12: Commit

- [ ] **Stage + commit the split**

Run:
```bash
git add core/tests/conformance_kat.rs core/tests/conformance_kat_helpers/
git status --short
```
Expected: 6 files (1 modified + 5 created).

```bash
git commit -m "$(cat <<'EOF'
chore(b6): split conformance_kat.rs into directory module helpers (closes #60)

595-LOC test file was past the project's 500-line guideline. Pure
structural refactor — no semantic change. Split into:

- conformance_kat.rs (entry): the two #[test] fns + the dispatch
  loop, ~150 LOC.
- conformance_kat_helpers/types.rs: KAT vector deserialization types
  + BridgeOrSyntheticErr wrapper.
- conformance_kat_helpers/fixtures.rs: kat_path, fixtures_dir, and
  the resolve_* family.
- conformance_kat_helpers/errors.rs: variant_name_vault,
  vault_error_detail, assert_err, read_block_err_* helpers.
- conformance_kat_helpers/dispatch.rs: per-op runners +
  assert_open_ok + assert_read_block_ok (with assert_record /
  assert_field private helpers).

Mirrors the existing core/tests/common/ pattern (mod.rs + sibling
.rs files). All existing test names, semantics, panic messages, and
counts are preserved unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Verify:
```bash
git log --oneline -2
```
Expected: top line is the new commit; second line is `85163b2 docs(specs): ...`.

---

## Task 2: Broaden read_block wrong-length UUID coverage (closes #61)

**Files:**
- Modify: [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json) — add 2 new vectors
- Test (existing, no change to test code): `core/tests/conformance_kat.rs::replay_conformance_kat`, Swift+Kotlin conformance runners.

### Step 2.1: Add the two new vectors to the KAT

- [ ] **Insert oversize + zero-length vectors before `read_block_wrong_length_uuid`**

Open `core/tests/data/conformance_kat.json`. Find the `read_block_wrong_length_uuid` vector (currently the last vector). Insert two new vector objects **before** it, preserving the array's trailing comma rules.

The current tail of the file looks like:

```json
    {
      "name": "read_block_wrong_length_uuid",
      "description": "read_block with a non-16-byte block_uuid → synthesized InvalidArgument at the replay layer (FfiVaultError doesn't expose this variant; it lives on the uniffi-projected VaultError only). Each replay engine emits its host's analogue.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_bytes_hex": "1122"
      },
      "expected": {
        "kind": "err",
        "variant": "InvalidArgument"
      }
    }
  ]
}
```

After the edit, it should look like:

```json
    {
      "name": "read_block_oversize_uuid",
      "description": "read_block with a 17-byte block_uuid (one byte too many) → synthesized InvalidArgument at the replay layer; uniffi binding rejects with VaultError.InvalidArgument on Swift + Kotlin.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_bytes_hex": "112233445566778899aabbccddeeff0011"
      },
      "expected": {
        "kind": "err",
        "variant": "InvalidArgument"
      }
    },
    {
      "name": "read_block_wrong_length_uuid",
      "description": "read_block with a non-16-byte block_uuid → synthesized InvalidArgument at the replay layer (FfiVaultError doesn't expose this variant; it lives on the uniffi-projected VaultError only). Each replay engine emits its host's analogue.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_bytes_hex": "1122"
      },
      "expected": {
        "kind": "err",
        "variant": "InvalidArgument"
      }
    },
    {
      "name": "read_block_zero_length_uuid",
      "description": "read_block with an empty block_uuid (0 bytes) → synthesized InvalidArgument at the replay layer; uniffi binding rejects with VaultError.InvalidArgument on Swift + Kotlin.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_bytes_hex": ""
      },
      "expected": {
        "kind": "err",
        "variant": "InvalidArgument"
      }
    }
  ]
}
```

**Order rationale:** keep the existing vector's literal text bytes intact (no diff to its content), and add `read_block_oversize_uuid` **before** and `read_block_zero_length_uuid` **after** it. This minimises the diff: only two `},` line additions inside the existing vector boundaries and two new object blocks.

Use Edit tool, not Write (the file has the comment + 8 other vectors that must stay byte-identical).

### Step 2.2: Verify JSON parses

- [ ] **Validate JSON syntax**

Run:
```bash
uv run python3 -c "import json; json.load(open('core/tests/data/conformance_kat.json'))" && echo "JSON OK"
```
Expected: prints `JSON OK`. If it fails, fix the comma placement.

Run:
```bash
uv run python3 -c "import json; print(len(json.load(open('core/tests/data/conformance_kat.json'))['vectors']))"
```
Expected: `11`

### Step 2.3: Verify the Rust replay accepts the new vectors

- [ ] **Run the conformance test**

Run:
```bash
cargo test --release --workspace --no-fail-fast --test conformance_kat 2>&1 | grep -E "^test result:"
```
Expected: `test result: ok. 1 passed; 0 failed; 1 ignored; ...` (still 1 passed; the test fn iterates over all 11 vectors internally).

### Step 2.4: Verify Swift runner accepts the new vectors

- [ ] **Run Swift conformance**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -15
```
Expected: ends with `OK: secretary uniffi Swift conformance — all 11/11 vectors passed.` and exit code 0.

If a vector fails with the empty-bytes input: check that Swift's `readBlock` rejects empty `Data()` as `VaultError.InvalidArgument`. The expected behavior is the uniffi-projected `VaultError.InvalidArgument` variant. If a different variant fires (e.g. `IllegalArgumentException` from the JNA layer), document and adjust either the vector's `expected.variant` or stop and ask before continuing.

### Step 2.5: Verify Kotlin runner accepts the new vectors

- [ ] **Run Kotlin conformance**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -15
```
Expected: ends with `OK: secretary uniffi Kotlin conformance — all 11/11 vectors passed.` and exit code 0.

Same edge case as Swift: the empty `ByteArray(0)` input may hit a JNA-layer guard before reaching the uniffi-projected `VaultException.InvalidArgument`. If the variant differs, stop and ask.

### Step 2.6: Commit

- [ ] **Stage + commit the new vectors**

Run:
```bash
git add core/tests/data/conformance_kat.json
git status --short
```
Expected: 1 file modified.

```bash
git commit -m "$(cat <<'EOF'
test(b6): broaden read_block wrong-length UUID coverage with empty + oversize vectors (closes #61)

Adds read_block_oversize_uuid (17 bytes) and read_block_zero_length_uuid
(0 bytes) to the conformance KAT. The existing read_block_wrong_length_uuid
vector only exercised a 2-byte UUID, leaving the symmetric extremes
unverified. All three replay engines (Rust synthesis, Swift uniffi binding,
Kotlin uniffi binding) reject all three wrong-length cases as
InvalidArgument identically.

Vector count: 9 → 11. No code change to any replay engine; the
synthesized-InvalidArgument path already handles arbitrary lengths.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Factor Swift+Kotlin open_vault_with_password / open_vault_with_recovery assertion blocks (closes #62)

**Files:**
- Modify: [ffi/secretary-ffi-uniffi/tests/swift/conformance.swift](../../../ffi/secretary-ffi-uniffi/tests/swift/conformance.swift) — extract `handleOpenOk` + `handleOpenError` top-level fns; compress the two switch arms.
- Modify: [ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt](../../../ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt) — extract `handleOpenOk` + `handleOpenError` `private fun`s; compress the two `when` branches.
- Test (existing): both runners' 11-vector PASS gauntlet.

### Step 3.1: Factor the Swift runner

- [ ] **Add the helper fns to `conformance.swift`**

Open `ffi/secretary-ffi-uniffi/tests/swift/conformance.swift`. After the `encodeHex` function (currently around line 115) and **before** the `// --- Main entry point ---` comment block, insert these two new top-level functions:

```swift
// --- Open-result helpers (factored from open_vault_with_password / open_vault_with_recovery arms) ---
//
// Symmetric with the Kotlin runner's handleOpenOk / handleOpenError.
// Same parameter order, same assertion order. The cache is `inout`
// so the helper can insert on success.

func handleOpenOk(
    out: OpenVaultOutput,
    expected: [String: Any],
    name: String,
    kind: String,
    cache: inout [String: OpenVaultOutput],
    check: (Bool, String, String) -> Bool
) {
    if kind != "ok" {
        _ = check(false, name, "expected err, got ok")
        return
    }
    if let display = expected["display_name"] as? String {
        _ = check(out.identity.displayName() == display, name, "display_name mismatch")
    }
    if let bc = expected["block_count"] as? Int {
        _ = check(Int(out.manifest.blockCount()) == bc, name, "block_count mismatch")
    }
    if let bu = expected["block_uuid_hex"] as? String {
        let summaries = out.manifest.blockSummaries()
        if !summaries.isEmpty {
            _ = check(encodeHex(Data(summaries[0].blockUuid)) == bu, name, "block_uuid mismatch")
        } else {
            _ = check(false, name, "manifest has no blocks but block_uuid pinned")
        }
    }
    cache[name] = out
}

func handleOpenError(
    e: VaultError,
    expected: [String: Any],
    name: String,
    kind: String,
    check: (Bool, String, String) -> Bool
) {
    if kind != "err" {
        _ = check(false, name, "expected ok, got err: \(e)")
        return
    }
    let want = expected["variant"] as? String ?? ""
    _ = check(vaultErrorName(e) == want, name, "variant mismatch (got \(vaultErrorName(e)), expected \(want))")
    if let needle = expected["detail_contains"] as? String {
        let detail = vaultErrorDetail(e) ?? ""
        _ = check(detail.contains(needle), name, "detail '\(detail)' missing '\(needle)'")
    }
}
```

### Step 3.2: Compress the two Swift switch arms

- [ ] **Replace the open_vault_with_password switch arm**

Find the existing `case ("open_vault_with_password", nil):` block (currently lines 200–231). Replace its body with:

```swift
            case ("open_vault_with_password", nil):
                let vaultDir = resolveVaultDir(inputs, goldenVaultDir: goldenVaultDir)
                let password = resolvePassword(inputs, goldenVaultDir: goldenVaultDir)
                do {
                    let out = try openVaultWithPassword(folderPath: vaultDir, password: password)
                    handleOpenOk(out: out, expected: expected, name: name, kind: kind, cache: &cache, check: check)
                } catch let e as VaultError {
                    handleOpenError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }
```

- [ ] **Replace the open_vault_with_recovery switch arm**

Find the existing `case ("open_vault_with_recovery", nil):` block (currently lines 233–264). Replace its body with:

```swift
            case ("open_vault_with_recovery", nil):
                let vaultDir = resolveVaultDir(inputs, goldenVaultDir: goldenVaultDir)
                let mnemonic = resolveMnemonic(inputs, goldenVaultDir: goldenVaultDir)
                do {
                    let out = try openVaultWithRecovery(folderPath: vaultDir, mnemonic: mnemonic)
                    handleOpenOk(out: out, expected: expected, name: name, kind: kind, cache: &cache, check: check)
                } catch let e as VaultError {
                    handleOpenError(e: e, expected: expected, name: name, kind: kind, check: check)
                } catch {
                    _ = check(false, name, "unexpected non-VaultError exception: \(error)")
                }
```

**Closure-capture note:** Swift's `static func main()` already holds `cache` and `failures` as `var` locals; the nested `func check(...)` captures them. The new top-level helpers receive `cache` via `inout` and `check` via parameter — they do not capture anything from `main`. This is intentional: keeps the helpers free of closure state and reusable for the same pattern in B.6 v2.

### Step 3.3: Build + verify Swift runner

- [ ] **Run Swift conformance**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -20
```
Expected: ends with `OK: secretary uniffi Swift conformance — all 11/11 vectors passed.` and exit code 0.

If `swiftc` errors on the closure-conversion (`(Bool, String, String) -> Bool` not Sendable, or capture-list issues), the most likely fix is to annotate the helper signatures with `@escaping`. Try:

```swift
func handleOpenOk(
    out: OpenVaultOutput,
    expected: [String: Any],
    name: String,
    kind: String,
    cache: inout [String: OpenVaultOutput],
    check: (Bool, String, String) -> Bool
) {
```
…and only add `@escaping` if the compiler explicitly demands it (Swift 5.x usually doesn't for non-escaping closures).

- [ ] **Run Swift smoke runner (regression guard)**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -5
```
Expected: `OK: secretary uniffi Swift smoke — all 37/37 ...` (or similar; unchanged from baseline). The smoke runner doesn't load the conformance harness so any compilation issue in `conformance.swift` won't break it, but verifies no unrelated regression.

### Step 3.4: Factor the Kotlin runner

- [ ] **Add the helper fns to `Conformance.kt`**

Open `ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt`. After the `encodeHex` function (currently around line 138) and **before** `// --- Main ---` (currently line 140), insert these two new top-level functions:

```kotlin
// --- Open-result helpers (factored from open_vault_with_password / open_vault_with_recovery branches) ---
//
// Symmetric with the Swift runner's handleOpenOk / handleOpenError.
// Same parameter order, same assertion order. The cache is a mutable
// reference (Kotlin maps are reference types — no inout marker needed).

private fun handleOpenOk(
    out: OpenVaultOutput,
    expected: JSONObject,
    name: String,
    kind: String,
    cache: MutableMap<String, OpenVaultOutput>,
    check: (Boolean, String, String) -> Boolean,
) {
    if (kind != "ok") {
        check(false, name, "expected err, got ok")
        return
    }
    expected.optString("display_name", null)?.let { wantDisplay ->
        check(out.identity.displayName() == wantDisplay, name,
            "display_name mismatch (got '${out.identity.displayName()}', want '$wantDisplay')")
    }
    if (expected.has("block_count")) {
        val wantBc = expected.getInt("block_count")
        check(out.manifest.blockCount().toInt() == wantBc, name,
            "block_count mismatch (got ${out.manifest.blockCount()}, want $wantBc)")
    }
    expected.optString("block_uuid_hex", null)?.let { wantUuid ->
        val summaries = out.manifest.blockSummaries()
        if (summaries.isNotEmpty()) {
            check(encodeHex(summaries[0].blockUuid) == wantUuid, name,
                "block_uuid mismatch (got '${encodeHex(summaries[0].blockUuid)}', want '$wantUuid')")
        } else {
            check(false, name, "manifest has no blocks but block_uuid_hex pinned")
        }
    }
    cache[name] = out
}

private fun handleOpenError(
    e: VaultException,
    expected: JSONObject,
    name: String,
    kind: String,
    check: (Boolean, String, String) -> Boolean,
) {
    if (kind != "err") {
        check(false, name, "expected ok, got err: $e")
        return
    }
    val wantVariant = expected.optString("variant", "")
    val gotVariant = vaultExceptionVariantName(e)
    check(gotVariant == wantVariant, name, "variant mismatch (got $gotVariant, expected $wantVariant)")
    expected.optString("detail_contains", null)?.let { needle ->
        val detail = vaultExceptionDetail(e) ?: ""
        check(detail.contains(needle), name, "detail '$detail' missing '$needle'")
    }
}
```

### Step 3.5: Compress the two Kotlin when branches

- [ ] **Replace the open_vault_with_password branch**

Find the existing `operation == "open_vault_with_password" && after == null -> {` block (currently lines 224–264). Replace its body with:

```kotlin
            operation == "open_vault_with_password" && after == null -> {
                val vaultDir = resolveVaultDir(inputs, goldenVaultDir)
                val password = resolvePassword(inputs, goldenVaultDir)
                try {
                    val out = openVaultWithPassword(vaultDir, password)
                    handleOpenOk(out, expected, name, kind, cache, ::check)
                } catch (e: VaultException) {
                    handleOpenError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }
```

- [ ] **Replace the open_vault_with_recovery branch**

Find the existing `operation == "open_vault_with_recovery" && after == null -> {` block (currently lines 266–306). Replace its body with:

```kotlin
            operation == "open_vault_with_recovery" && after == null -> {
                val vaultDir = resolveVaultDir(inputs, goldenVaultDir)
                val mnemonic = resolveMnemonic(inputs, goldenVaultDir)
                try {
                    val out = openVaultWithRecovery(vaultDir, mnemonic)
                    handleOpenOk(out, expected, name, kind, cache, ::check)
                } catch (e: VaultException) {
                    handleOpenError(e, expected, name, kind, ::check)
                } catch (e: Throwable) {
                    check(false, name, "unexpected non-VaultException: $e")
                }
            }
```

**Function-reference note:** `::check` works only if the `check` local function is reachable as a function reference. Kotlin allows this for local functions in 1.x, but if the compiler rejects it (older Kotlin versions sometimes do), wrap it: `{ ok, vn, msg -> check(ok, vn, msg) }` and pass that lambda instead. The expected behaviour is identical — `check` updates `failures` via closure capture, which both forms preserve.

### Step 3.6: Build + verify Kotlin runner

- [ ] **Run Kotlin conformance**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -20
```
Expected: ends with `OK: secretary uniffi Kotlin conformance — all 11/11 vectors passed.` and exit code 0.

If `kotlinc` errors on `::check` not being resolvable, switch to the lambda form (`{ a, b, c -> check(a, b, c) }`) at both call sites.

- [ ] **Run Kotlin smoke runner (regression guard)**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -5
```
Expected: `OK: secretary uniffi Kotlin smoke — all 37/37 ...` (or similar; unchanged).

### Step 3.7: Negative-test exercise — confirm gating fix survived the refactor

The PR #58 commits `4dd9aae` (Swift) and `fdfc302` (Kotlin) introduced gated PASS printing: a vector that produces any FAIL sub-line must NOT emit a PASS line. The factoring must preserve this — `handleOpenOk` calling `check(...)` with a falsy result must still bump the failure counter that `failures.count == preFailureCount` reads at the bottom of the loop.

- [ ] **Manually corrupt a KAT entry and verify FAIL-then-no-PASS**

Open `core/tests/data/conformance_kat.json` and **temporarily** change `open_password_happy`'s `display_name` from `"Owner"` to `"OwnerXXX"`. Save.

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | grep -E "^(PASS|FAIL): open_password_happy"
```
Expected: `FAIL: open_password_happy: display_name mismatch` and NO line starting with `PASS: open_password_happy`.

Run the same check for Kotlin:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | grep -E "^(PASS|FAIL): open_password_happy"
```
Expected: `FAIL: open_password_happy: ...` and NO `PASS: open_password_happy`.

- [ ] **Revert the KAT corruption**

```bash
git checkout -- core/tests/data/conformance_kat.json
```

Verify the runners both pass again:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
```
Expected: both end with `OK: ... 11/11 vectors passed.`

### Step 3.8: Commit

- [ ] **Stage + commit the factoring**

Run:
```bash
git add ffi/secretary-ffi-uniffi/tests/swift/conformance.swift ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt
git status --short
```
Expected: 2 files modified.

```bash
git commit -m "$(cat <<'EOF'
refactor(b6): factor open_vault_with_password/recovery into handleOpenOk + handleOpenError helpers (closes #62)

The Swift conformance.swift and Kotlin Conformance.kt runners each had
two near-duplicate switch/when arms for open_vault_with_password and
open_vault_with_recovery — identical OK assertions (display_name,
block_count, block_uuid_hex), identical error-arm shape (variant +
detail_contains). Only the bridge fn call (openVaultWithPassword vs
openVaultWithRecovery) and the input resolver (resolvePassword vs
resolveMnemonic) differed.

Extracts symmetric helpers in both languages:
  - handleOpenOk: receives the OpenVaultOutput, runs the three OK
    assertions in the same order, inserts into the cache on success.
  - handleOpenError: receives the VaultError/VaultException, asserts
    variant + optional detail substring.

Both helpers take the cache as a parameter rather than capturing it,
so they're reusable for B.6 v2's lifecycle ops (save_block etc.) that
will hit the same shape.

PR #58's gated-PASS-after-FAIL fix is preserved: the helpers route
all failure paths through the original `check` fn, so the
preFailureCount snapshot at the bottom of the loop still suppresses
PASS lines for any vector that produced sub-check failures. Verified
by temporarily corrupting open_password_happy and confirming no PASS
line appears for either runner.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Drain Kotlin OpenVaultOutput cache before exit (closes #63)

**Files:**
- Modify: [ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt](../../../ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt) — add cache-drain before both `exitProcess` calls; update the cache-lifetime comment.

### Step 4.1: Update the cache-lifetime comment

- [ ] **Replace the comment at the cache declaration**

Find the comment block at `Conformance.kt:180-185` (the lines starting `// Cache: vector name → OpenVaultOutput ...` through `... "predecessor did not produce a cacheable Ok".`). Replace with:

```kotlin
    // Cache: vector name → OpenVaultOutput for chained read_block vectors.
    // Drained explicitly at end-of-main before exitProcess (see below) —
    // calls each cached value's .destroy() so the Rust-side handle is
    // released deterministically rather than waiting for the JVM Cleaner
    // thread. If a source vector fails, its key is absent from the map
    // and chained vectors report "predecessor did not produce a cacheable
    // Ok".
```

### Step 4.2: Add the drain before both exitProcess paths

- [ ] **Insert drain before the success exit**

Find the success branch in `main()`'s summary block (currently `Conformance.kt:421-424`):

```kotlin
    if (failures.isEmpty()) {
        println("OK: secretary uniffi Kotlin conformance — all $vectorsRun/$vectorsRun vectors passed.")
        exitProcess(0)
```

Add the drain ABOVE the `if (failures.isEmpty())` line so both exit paths get it exactly once:

```kotlin
    // Drain cached OpenVaultOutput handles deterministically.
    // The JVM Cleaner thread would release them eventually, but a future
    // second-pass replay (B.6 v2) could re-enter main and the handles
    // would pin Rust-side allocations for that duration. Explicit drain
    // releases them at end-of-run — see issue #63.
    cache.values.forEach { it.destroy() }
    cache.clear()

    // --- Summary ---
    if (failures.isEmpty()) {
```

(The `// --- Summary ---` comment already exists at line 421; the drain block goes immediately above it. Adjust whitespace as needed.)

### Step 4.3: Run Kotlin conformance

- [ ] **Verify drain doesn't break anything**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -10
```
Expected: ends with `OK: secretary uniffi Kotlin conformance — all 11/11 vectors passed.` and exit code 0.

### Step 4.4: Optional manual sanity check (do during development, do not commit)

- [ ] **Confirm drain runs over the expected 2 keys**

**Temporarily** add a debug line above the drain:
```kotlin
System.err.println("draining cache: ${cache.size} entries")
cache.values.forEach { it.destroy() }
cache.clear()
```

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | grep "draining"
```
Expected: `draining cache: 2 entries` (the two source vectors that succeed: `open_password_happy` and `open_recovery_happy`).

Remove the debug line before committing — verify with:
```bash
grep -n "draining" ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt
```
Expected: no matches.

### Step 4.5: Run Kotlin smoke (regression guard)

- [ ] **Verify smoke runner unaffected**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -5
```
Expected: `OK: secretary uniffi Kotlin smoke — all 37/37 ...` (unchanged).

### Step 4.6: Commit

- [ ] **Stage + commit the drain**

Run:
```bash
git add ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt
git status --short
```
Expected: 1 file modified.

```bash
git commit -m "$(cat <<'EOF'
fix(b6): drain OpenVaultOutput cache before Kotlin runner exit (closes #63)

The Kotlin conformance runner cached OpenVaultOutput instances in a
MutableMap and never called .destroy() on them. Read_block invocations
destroyed their BlockReadOutput/RecordHandle/FieldHandle returns
explicitly, but the chained predecessor's OpenVaultOutput stayed alive
in the map until process exit (JVM Cleaner thread eventually released
the Rust handle).

No visible leak today (test runner exits after one pass) but a future
second-pass replay (e.g. B.6 v2's lifecycle vectors where the same
vault might be re-opened between groups) would turn the cache into a
growing pin that JNA can't reclaim until the JVM exits.

Adds cache.values.forEach { it.destroy() }; cache.clear() above the
summary if/else, so both exit paths drain the cache deterministically.
Swift runner needs no equivalent — ARC reclaims the dictionary on
process exit automatically.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Final gauntlet sweep

After all four commits land on the branch:

- [ ] **Full cargo test gauntlet**

Run:
```bash
cargo test --release --workspace --no-fail-fast 2>&1 | tee /tmp/cargo-test-final.log | tail -5
grep -E "^test result:" /tmp/cargo-test-final.log | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
```
Expected: `TOTAL: 641 passed; 0 failed; 10 ignored`.

- [ ] **Clippy + fmt**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all -- --check 2>&1 | tail -5
```
Expected: clippy clean; fmt OK (no output).

- [ ] **Python conformance + freshness**

```bash
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -5
```
Expected: both PASS. Freshness count may shift slightly from 96/0/2 due to the #60 split; document the new baseline in the PR description if it changes.

- [ ] **Swift + Kotlin smoke + conformance**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
```
Expected:
- Swift smoke: 37/37 PASS (unchanged)
- Swift conformance: **11/11 PASS** (was 9/9)
- Kotlin smoke: 37/37 PASS (unchanged)
- Kotlin conformance: **11/11 PASS** (was 9/9)

- [ ] **Final branch verification**

```bash
git log --oneline main..HEAD
```
Expected 5 commits (oldest first):
1. `85163b2` docs(specs): design doc for B.6 v1 pre-v2 cleanup bundle
2. `<sha>` chore(b6): split conformance_kat.rs into directory module helpers (closes #60)
3. `<sha>` test(b6): broaden read_block wrong-length UUID coverage with empty + oversize vectors (closes #61)
4. `<sha>` refactor(b6): factor open_vault_with_password/recovery into handleOpenOk + handleOpenError helpers (closes #62)
5. `<sha>` fix(b6): drain OpenVaultOutput cache before Kotlin runner exit (closes #63)

---

## Task 6: Documentation + handoff

- [ ] **Check whether README.md needs updating**

Read [README.md](../../../README.md) and confirm whether the cleanup affects any user-visible documentation. The four issues are internal test-harness improvements — most likely no README change is needed. If `README.md` mentions the conformance KAT test count or runner invocations, update accordingly.

- [ ] **Check whether ROADMAP.md needs updating**

Read [ROADMAP.md](../../../ROADMAP.md). The B.6 v1 progress bar should already reflect v1 complete from PR #58. If the ROADMAP enumerates open follow-ups (#60–#63), strike them through. Otherwise, no change.

- [ ] **Write NEXT_SESSION.md and freeze handoff snapshot**

Overwrite `NEXT_SESSION.md` with this session's outcome following the standard template (shipped commit list with SHAs; what's next with concrete acceptance criteria; open decisions/risks; exact resume commands). Make the next-step recommendation **B.6 v2 design (#59) via brainstorming on the save_block determinism question**, since the pre-v2 cleanup is now complete.

Save an exact copy to `docs/handoffs/2026-05-16-b6-pre-v2-cleanup-bundle.md` (timestamped frozen archive).

- [ ] **Commit NEXT_SESSION.md + handoff snapshot inside this branch (before PR push)**

User feedback `feedback_next_session_in_pr.md` is explicit: NEXT_SESSION.md must ride inside the PR, not after merge. Stage and commit both files:
```bash
git add NEXT_SESSION.md docs/handoffs/2026-05-16-b6-pre-v2-cleanup-bundle.md
# (Plus any README.md / ROADMAP.md changes from the prior step)
git commit -m "docs: NEXT_SESSION.md + handoff snapshot for B.6 pre-v2 cleanup bundle"
```

---

## Task 7: Push branch and open PR

- [ ] **Push the branch**

```bash
git push -u origin chore/b6-pre-v2-cleanup
```

- [ ] **Open the PR**

```bash
gh pr create --title "chore(b6): pre-v2 cleanup bundle (#60 #61 #62 #63)" --body "$(cat <<'EOF'
## Summary

Bundle of four B.6 v1 PR-review follow-ups landing before B.6 v2 lifecycle KAT work begins. Each issue gets its own commit; structure-first ordering means semantic changes slot into the post-split file layout.

- **#60** — split `core/tests/conformance_kat.rs` (595 LOC → 5 files under `core/tests/conformance_kat_helpers/`, mirrors `core/tests/common/` pattern).
- **#61** — add `read_block_zero_length_uuid` (empty input) + `read_block_oversize_uuid` (17-byte input) vectors; coverage now 11 vectors in `conformance_kat.json`. All three replay engines reject all three wrong-length cases as InvalidArgument identically.
- **#62** — factor Swift `handleOpenOk` + `handleOpenError` helpers; symmetric Kotlin `handleOpenOk` + `handleOpenError`. Each runner's two open_* arms shrink ~32 LOC → ~10 LOC. Sets up shape for B.6 v2 lifecycle ops.
- **#63** — Kotlin runner explicitly drains `cache.values.forEach { it.destroy() }` before both exit paths. No leak today; relevant for B.6 v2 second-pass replays.

Design doc: `docs/superpowers/specs/2026-05-16-b6-pre-v2-cleanup-bundle-design.md` (committed as 85163b2).
Implementation plan: `docs/superpowers/plans/2026-05-16-b6-pre-v2-cleanup-bundle.md`.

## Test plan

- [ ] `cargo test --release --workspace --no-fail-fast` — TOTAL 641 passed + 10 ignored (unchanged from B.6 v1 close)
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` — clean
- [ ] `cargo fmt --all -- --check` — OK
- [ ] `uv run core/tests/python/conformance.py` — PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` — PASS (count may shift from 96/0/2 baseline due to #60 split; verify before merge)
- [ ] `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` — 37/37 PASS
- [ ] `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` — **11/11 PASS** (was 9/9)
- [ ] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` — 37/37 PASS
- [ ] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` — **11/11 PASS** (was 9/9)
- [ ] Negative-test: temporarily corrupt `open_password_happy`'s `display_name`; confirm both runners emit `FAIL:` and NO `PASS:` for that vector (PR #58 gated-PASS fix preserved through #62 refactor)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: prints the PR URL. Report it to the user.

---

## Self-review against spec

**Spec coverage:** all four spec sections (commits 1–4 in §3) → tasks 1–4 here. §4 testing strategy → task 5. §5 risks: addressed by step 3.7 (gating fix preservation), step 1.7 (handle-type verification fallback), step 1.11 (file-size verification). §6 out-of-scope: none added.

**Placeholders:** none — every code block is concrete, every command has an expected output.

**Type consistency:** `handleOpenOk` / `handleOpenError` are the names in both Swift and Kotlin per spec §3 Commit 3. Parameter orders match: `out, expected, name, kind, cache, check` (Ok) and `e, expected, name, kind, check` (Err). The `BridgeOrSyntheticErr` enum + `ExpectedRecord` / `ExpectedField` / `OkPayload` types are referenced consistently across types.rs / dispatch.rs / errors.rs files in Task 1.

**Test count baseline:** stated as 641 + 10 ignored consistently in steps 1.9 and 5 and the PR body.

**Vector count baseline:** stated as 11 (was 9) consistently in steps 2.2, 2.4, 2.5, 5, and the PR body.

No further fixes needed.
