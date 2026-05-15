# B.6 v1 — Cross-language FFI Conformance KAT (read-only path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a frozen `core/tests/data/conformance_kat.json` plus three replay engines (Rust bridge, Swift uniffi, Kotlin uniffi) that all agree on what the read-only half of the uniffi FFI surface must emit for `golden_vault_001`. A divergence in any binding fails its replay.

**Architecture:** Rust generator (`#[ignore]` test) runs the bridge crate against `golden_vault_001` and dumps the FFI-surface output to JSON. Three replay engines (one in `core/tests/conformance_kat.rs`, one Swift binary, one Kotlin binary) load the same JSON and assert their bindings produce identical observable values. Source vectors run first, cache their `OpenVaultOutput`, then chained `read_block` vectors execute using the cached unlock state.

**Tech Stack:** Rust + `serde_json` (dev-dependency) + `secretary-ffi-bridge` (workspace path). Swift `swiftc` + uniffi-generated bindings + Foundation's `JSONSerialization`. Kotlin `kotlinc` + JNA + uniffi-generated bindings + a minimal JSON parser (org.json bundled or hand-rolled — TBD in Task 4). All hosts read fixtures via `SECRETARY_GOLDEN_VAULT_DIR` (existing) + `SECRETARY_CONFORMANCE_KAT` (new).

**Design doc:** [docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md](../specs/2026-05-15-ffi-b6-conformance-kat-design.md). Read §4 (vector format) + §5 (replay engine) + §9 (implementation outline) before starting Task 1.

**Branch + worktree:** Work happens on `feature/ffi-b6-conformance-kat-v1` (branch already exists, design doc committed at `cca13b2`). No worktree split — this is a single sequential PR.

**Pre-task gauntlet check:** Before Task 1, verify the baseline still matches the resume gauntlet:

```bash
cd /Users/hherb/src/secretary
git checkout feature/ffi-b6-conformance-kat-v1
git status --short                                 # Expect: clean
cargo test --release --workspace --no-fail-fast 2>&1 | grep -cE "^test result: ok"
                                                   # Expect: matches the count of test binaries; aggregate via the Python one-liner below if curious.
```

---

## File structure

| File | Lifecycle | Purpose |
|---|---|---|
| [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json) | Created Task 1, populated Tasks 2 + 3 | The frozen cross-language KAT. 9 vectors. |
| [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs) | Created Task 1, expanded Tasks 2 + 3 | Rust replay + `#[ignore]` generator. ~300 LOC total. |
| [core/Cargo.toml](../../../core/Cargo.toml) | Modified Task 1 | Add `hex = "0.4"` to `[dev-dependencies]` (used by the replay to decode `*_hex` fields). `serde_json` already present at line `serde_json = "1"` in `[dev-dependencies]`. |
| [ffi/secretary-ffi-uniffi/tests/swift/conformance.swift](../../../ffi/secretary-ffi-uniffi/tests/swift/conformance.swift) | Created Task 4 | Swift host runner. ~300 LOC. |
| [ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh](../../../ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh) | Created Task 4 | Swift build + run wrapper. ~85 LOC. |
| [ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt](../../../ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt) | Created Task 5 | Kotlin host runner. ~300 LOC. |
| [ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh](../../../ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh) | Created Task 5 | Kotlin build + run wrapper (mirrors Swift, plus JNA fetch). ~125 LOC. |
| [CLAUDE.md](../../../CLAUDE.md) | Modified Task 6 | Add the two `run_conformance.sh` lines to the Commands section. |
| [ROADMAP.md](../../../ROADMAP.md) | Modified Task 6 | Line 34 current-state: mark B.6 v1 done; add B.6 v2 (lifecycle) follow-up. |

---

## Task 1: Rust scaffold — empty-vectors KAT + replay + generator skeleton (red → green)

**Files:**
- Create: `core/tests/conformance_kat.rs`
- Create: `core/tests/data/conformance_kat.json`
- Modify: `core/Cargo.toml` (add `hex` to `[dev-dependencies]`)

This task lands a no-op KAT (`vectors: []`) plus the Rust deserialization + dispatch types. The replay test asserts "the KAT file loads cleanly and version=1". The generator test is stubbed (compiles, does nothing). Subsequent tasks add real vectors.

- [ ] **Step 1: Add `hex` to `core` dev-deps**

Edit [core/Cargo.toml](../../../core/Cargo.toml). Find the `[dev-dependencies]` section (already contains `serde_json = "1"`) and add directly below:

```toml
# Used by core/tests/conformance_kat.rs to decode UUID-hex / bytes-hex
# fields in the KAT into the [u8; 16] / Vec<u8> shapes the bridge crate
# accepts. Matches the version pinned in ffi/secretary-ffi-bridge/Cargo.toml.
hex = "0.4"
```

- [ ] **Step 2: Write the skeleton KAT JSON**

Create [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json):

```json
{
  "version": 1,
  "comment": "Cross-language FFI conformance KAT for the read-only half of the uniffi surface. See docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md. Generated by `cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture`; intentional protocol changes regenerate, diffs are human-reviewed. Verified by core/tests/conformance_kat.rs::replay_conformance_kat (every cargo test) plus the Swift + Kotlin host runners in ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/.",
  "vectors": []
}
```

- [ ] **Step 3: Write the failing test**

Create [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs):

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
//! - [`replay_conformance_kat`] — runs on every `cargo test` and
//!   gates protocol changes.
//! - [`generate_conformance_kat`] — `#[ignore]`-marked; runs the
//!   bridge crate against `golden_vault_001` and emits the JSON.
//!   Manually triggered on intentional protocol change; the diff
//!   is human-reviewed before commit.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn kat_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("conformance_kat.json")
}

#[derive(Debug, Deserialize, Serialize)]
struct Kat {
    version: u32,
    #[serde(default)]
    #[allow(dead_code)] // documentation field; the replay does not read it.
    comment: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    name: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation field.
    description: String,
}

#[test]
fn replay_conformance_kat_loads_kat_file() {
    let raw = std::fs::read_to_string(kat_path()).expect("conformance_kat.json must be readable");
    let kat: Kat = serde_json::from_str(&raw).expect("conformance_kat.json must parse");
    assert_eq!(kat.version, 1, "KAT version must be 1");
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --workspace conformance_kat -- --nocapture`

Expected: PASS with `test replay_conformance_kat_loads_kat_file ... ok`.

- [ ] **Step 5: Verify wider gauntlet still clean**

Run:

```bash
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
```

Both: clean.

- [ ] **Step 6: Commit**

```bash
git add core/Cargo.toml core/tests/data/conformance_kat.json core/tests/conformance_kat.rs
git commit -m "$(cat <<'EOF'
feat(b6): scaffold conformance KAT JSON + Rust replay (empty vectors)

First commit of the B.6 v1 cross-language FFI conformance KAT. Lands
the JSON skeleton (vectors: []), the Rust replay test that loads it
and asserts version=1, and a hex dev-dep needed by later tasks.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Source vectors (no `after:`) + Rust source-vector dispatch

**Files:**
- Modify: `core/tests/conformance_kat.rs`
- Modify: `core/tests/data/conformance_kat.json`

Adds the 6 source vectors (3 happy paths + 3 error paths) covering `open_vault_with_password` and `open_vault_with_recovery`, plus the dispatch logic that runs them. After this task the KAT exercises all the unlock surface; chained `read_block` vectors come in Task 3.

- [ ] **Step 1: Extend Vector + add Expected/Operation enums**

Replace the `Vector` struct in [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs) with the richer type set. Add directly under the existing `Kat` struct definition:

```rust
#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    name: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation field.
    description: String,
    operation: Operation,
    inputs: serde_json::Value,
    #[serde(default)]
    after: Option<String>,
    expected: Expected,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    OpenVaultWithPassword,
    OpenVaultWithRecovery,
    ReadBlock,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Expected {
    Ok(OkPayload),
    Err {
        variant: String,
        #[serde(default)]
        detail_contains: Option<String>,
    },
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct OkPayload {
    // Open ops:
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_uuid_hex: Option<String>,
    // read_block:
    #[serde(default, skip_serializing_if = "Option::is_none")]
    records: Option<Vec<ExpectedRecord>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExpectedRecord {
    record_uuid_hex: String,
    record_type: String,
    tags: Vec<String>,
    fields: Vec<ExpectedField>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExpectedField {
    name: String,
    #[serde(rename = "type")]
    field_type: String, // "text" or "bytes"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value_utf8: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value_hex: Option<String>,
}
```

- [ ] **Step 2: Add input-resolution helpers**

Add directly under the enum definitions:

```rust
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
}

/// Resolves a `*_source` style input (e.g. `golden_vault_001_inputs.json:password`)
/// to its concrete bytes. Returns the UTF-8 bytes of the named JSON string field.
fn resolve_source(source: &str) -> Vec<u8> {
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

fn resolve_vault_dir(inputs: &serde_json::Value) -> PathBuf {
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

fn resolve_password(inputs: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = inputs.get("password_source").and_then(|v| v.as_str()) {
        return resolve_source(s);
    }
    if let Some(s) = inputs.get("password_literal_utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    panic!("open_vault_with_password vector missing password_* input");
}

fn resolve_mnemonic(inputs: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = inputs.get("mnemonic_source").and_then(|v| v.as_str()) {
        return resolve_source(s);
    }
    if let Some(s) = inputs.get("mnemonic_literal_utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    panic!("open_vault_with_recovery vector missing mnemonic_* input");
}
```

- [ ] **Step 3: Add Rust-side error → variant-name mapping**

Add directly under the resolvers:

```rust
fn variant_name_unlock(_e: &secretary_ffi_bridge::error::FfiUnlockError) -> &'static str {
    // The FfiUnlockError type is not what open_vault_with_* returns — that's
    // FfiVaultError. UnlockError variants surface via the unlock-only path,
    // which B.6 v1 does not exercise. Kept here as a guard for future scope.
    unreachable!("B.6 v1 read-only path returns FfiVaultError only")
}

fn variant_name_vault(e: &secretary_ffi_bridge::error::FfiVaultError) -> &'static str {
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
        E::InvalidArgument { .. } => "InvalidArgument",
    }
}

fn vault_error_detail(e: &secretary_ffi_bridge::error::FfiVaultError) -> Option<&str> {
    use secretary_ffi_bridge::error::FfiVaultError as E;
    match e {
        E::InvalidMnemonic { detail } => Some(detail.as_str()),
        E::CorruptVault { detail } => Some(detail.as_str()),
        E::FolderInvalid { detail } => Some(detail.as_str()),
        E::SaveCryptoFailure { detail } => Some(detail.as_str()),
        E::CardDecodeFailure { detail } => Some(detail.as_str()),
        E::BlockUuidAlreadyLive { detail } => Some(detail.as_str()),
        E::BlockNotInTrash { detail } => Some(detail.as_str()),
        E::InvalidArgument { detail } => Some(detail.as_str()),
        _ => None,
    }
}

// Silence the unused-warning on the unused unlock helper until B.6 v2.
#[allow(dead_code)]
fn _suppress_unused() {
    let _ = variant_name_unlock;
}
```

Verify the variant arms cover every actually-emitted `FfiVaultError` variant by grepping. Run:

```bash
grep -nE "FfiVaultError::" ffi/secretary-ffi-bridge/src/error/*.rs | grep -oE "FfiVaultError::[A-Z][A-Za-z]+" | sort -u
```

Cross-check the output against the match arms above. If any variant is missing from the match, the next `cargo test` will fail on the exhaustive-match check.

- [ ] **Step 4: Add vector execution dispatch**

Add directly under the variant-mapping helpers:

```rust
fn run_open_password(
    inputs: &serde_json::Value,
) -> Result<
    secretary_ffi_bridge::vault::OpenVaultOutput,
    secretary_ffi_bridge::error::FfiVaultError,
> {
    let vault_dir = resolve_vault_dir(inputs);
    let password = resolve_password(inputs);
    secretary_ffi_bridge::vault::open_vault_with_password(
        vault_dir.to_string_lossy().as_bytes(),
        &password,
    )
}

fn run_open_recovery(
    inputs: &serde_json::Value,
) -> Result<
    secretary_ffi_bridge::vault::OpenVaultOutput,
    secretary_ffi_bridge::error::FfiVaultError,
> {
    let vault_dir = resolve_vault_dir(inputs);
    let mnemonic = resolve_mnemonic(inputs);
    secretary_ffi_bridge::vault::open_vault_with_recovery(
        vault_dir.to_string_lossy().as_bytes(),
        &mnemonic,
    )
}

fn assert_open_ok(
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
        let expected_uuid = hex::decode(hex_str).expect("block_uuid_hex must be valid hex");
        let summaries = output.manifest.block_summaries();
        assert!(
            !summaries.is_empty(),
            "{label}: manifest has no blocks but block_uuid_hex was pinned"
        );
        let actual_hex = hex::encode(summaries[0].block_uuid);
        assert_eq!(
            actual_hex,
            hex::encode(&expected_uuid),
            "{label}: block_uuid mismatch"
        );
    }
}

fn assert_err(label: &str, actual_variant: &str, actual_detail: Option<&str>, expected: &Expected) {
    let Expected::Err {
        variant,
        detail_contains,
    } = expected
    else {
        panic!("{label}: expected Ok but operation returned Err");
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
```

- [ ] **Step 5: Replace the no-op replay test with the real dispatch loop**

In [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs), replace the existing `replay_conformance_kat_loads_kat_file` test with:

```rust
#[test]
fn replay_conformance_kat() {
    let raw = std::fs::read_to_string(kat_path()).expect("conformance_kat.json must be readable");
    let kat: Kat = serde_json::from_str(&raw).expect("conformance_kat.json must parse");
    assert_eq!(kat.version, 1, "KAT version must be 1");

    for vector in &kat.vectors {
        let label = &vector.name;
        if vector.after.is_some() {
            // Chained vectors land in Task 3.
            continue;
        }
        match vector.operation {
            Operation::OpenVaultWithPassword => {
                let result = run_open_password(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => assert_open_ok(label, &out, payload),
                    (Expected::Err { .. }, Err(e)) => {
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => {
                        panic!("{label}: expected Ok, got Err {:?}", e)
                    }
                    (Expected::Err { .. }, Ok(_)) => {
                        panic!("{label}: expected Err, got Ok")
                    }
                }
            }
            Operation::OpenVaultWithRecovery => {
                let result = run_open_recovery(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => assert_open_ok(label, &out, payload),
                    (Expected::Err { .. }, Err(e)) => {
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => {
                        panic!("{label}: expected Ok, got Err {:?}", e)
                    }
                    (Expected::Err { .. }, Ok(_)) => {
                        panic!("{label}: expected Err, got Ok")
                    }
                }
            }
            Operation::ReadBlock => {
                continue; // chained — Task 3
            }
        }
    }
}
```

- [ ] **Step 6: Add the 6 source vectors to the KAT JSON**

Replace [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json)'s `"vectors": []` with the six source vectors:

```json
{
  "version": 1,
  "comment": "Cross-language FFI conformance KAT for the read-only half of the uniffi surface. See docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md. Generated by `cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture`; intentional protocol changes regenerate, diffs are human-reviewed. Verified by core/tests/conformance_kat.rs::replay_conformance_kat (every cargo test) plus the Swift + Kotlin host runners in ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/.",
  "vectors": [
    {
      "name": "open_password_happy",
      "description": "open_vault_with_password against golden_vault_001 using the pinned password from golden_vault_001_inputs.json:password.",
      "operation": "open_vault_with_password",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "password_source": "golden_vault_001_inputs.json:password"
      },
      "expected": {
        "kind": "ok",
        "display_name": "Owner",
        "block_count": 1,
        "block_uuid_hex": "11223344556677889900aabbccddeeff"
      }
    },
    {
      "name": "open_password_wrong",
      "description": "open_vault_with_password with a literal wrong password → typed VaultError.WrongPasswordOrCorrupt.",
      "operation": "open_vault_with_password",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "password_literal_utf8": "wrong"
      },
      "expected": {
        "kind": "err",
        "variant": "WrongPasswordOrCorrupt"
      }
    },
    {
      "name": "open_password_nonexistent_folder",
      "description": "open_vault_with_password against a bogus folder path → typed VaultError.FolderInvalid.",
      "operation": "open_vault_with_password",
      "inputs": {
        "vault_dir_literal": "/this/folder/does/not/exist",
        "password_source": "golden_vault_001_inputs.json:password"
      },
      "expected": {
        "kind": "err",
        "variant": "FolderInvalid"
      }
    },
    {
      "name": "open_recovery_happy",
      "description": "open_vault_with_recovery using the pinned 24-word phrase from golden_vault_001_inputs.json.",
      "operation": "open_vault_with_recovery",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "mnemonic_source": "golden_vault_001_inputs.json:recovery_mnemonic_phrase"
      },
      "expected": {
        "kind": "ok",
        "display_name": "Owner",
        "block_count": 1,
        "block_uuid_hex": "11223344556677889900aabbccddeeff"
      }
    },
    {
      "name": "open_recovery_wrong_phrase",
      "description": "open_vault_with_recovery using vault_002's phrase against vault_001's folder → typed VaultError.WrongMnemonicOrCorrupt.",
      "operation": "open_vault_with_recovery",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "mnemonic_source": "golden_vault_002_inputs.json:recovery_mnemonic_phrase"
      },
      "expected": {
        "kind": "err",
        "variant": "WrongMnemonicOrCorrupt"
      }
    },
    {
      "name": "open_recovery_short_phrase",
      "description": "open_vault_with_recovery with a 3-word phrase → typed VaultError.InvalidMnemonic with detail containing 'got 3'.",
      "operation": "open_vault_with_recovery",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "mnemonic_literal_utf8": "one two three"
      },
      "expected": {
        "kind": "err",
        "variant": "InvalidMnemonic",
        "detail_contains": "got 3"
      }
    }
  ]
}
```

The `block_uuid_hex` value `11223344556677889900aabbccddeeff` comes from `golden_vault_001_inputs.json:block_uuid` (hyphens stripped). Verify with `grep block_uuid core/tests/data/golden_vault_001_inputs.json`.

- [ ] **Step 7: Run the dispatch loop**

Run: `cargo test --release --workspace replay_conformance_kat -- --nocapture`

Expected: PASS — 6 vectors exercised (3 happy + 3 err), no failures.

If the test fails on `open_recovery_short_phrase` because the `detail_contains: "got 3"` substring doesn't match the actual error text, **do not weaken the substring** — instead inspect the actual error string with `cargo test --release --workspace replay_conformance_kat -- --nocapture 2>&1 | grep "got"` and adjust the substring to match the actual text (e.g. `"got 3 words"`). Document the precise substring shape in the JSON `description` field if it's non-obvious.

- [ ] **Step 8: Re-run the full gauntlet**

Run:

```bash
cargo test --release --workspace --no-fail-fast
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
```

All three: clean. Test count: prior baseline + 1 (`replay_conformance_kat`).

- [ ] **Step 9: Commit**

```bash
git add core/tests/conformance_kat.rs core/tests/data/conformance_kat.json
git commit -m "$(cat <<'EOF'
feat(b6): add 6 source vectors + Rust source-vector dispatch

Covers open_vault_with_password / open_vault_with_recovery happy + error
paths (WrongPasswordOrCorrupt, FolderInvalid, WrongMnemonicOrCorrupt,
InvalidMnemonic with detail_contains substring match). Chained
read_block vectors land in Task 3 once the generator is wired up.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Chained `read_block` vectors + `#[ignore]` generator + populated KAT

**Files:**
- Modify: `core/tests/conformance_kat.rs`
- Modify: `core/tests/data/conformance_kat.json`

Lands the 3 `read_block` vectors (1 happy + 2 error), wires the cache-and-chain logic in the replay engine, and adds the `#[ignore]` generator that the happy-path vector's `records[]` placeholders depend on.

- [ ] **Step 1: Add the 3 chained vectors with `<filled-by-generator>` placeholders**

Append to the `"vectors"` array in [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json) (after the existing 6 source vectors):

```json
,
    {
      "name": "read_block_happy",
      "description": "read_block on golden_vault_001's sole block (the 'Personal logins' block). Record list populated by the generator; see core/tests/data/golden_vault_001_inputs.json for the source-of-truth plaintext.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_hex": "11223344556677889900aabbccddeeff"
      },
      "expected": {
        "kind": "ok",
        "records": []
      }
    },
    {
      "name": "read_block_unknown_uuid",
      "description": "read_block with a UUID not present in the manifest → typed VaultError.BlockNotFound.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_hex": "00000000000000000000000000000000"
      },
      "expected": {
        "kind": "err",
        "variant": "BlockNotFound"
      }
    },
    {
      "name": "read_block_wrong_length_uuid",
      "description": "read_block with a non-16-byte block_uuid → typed VaultError.InvalidArgument. NOTE: the bridge's read_block takes &[u8; 16], so wrong-length input is rejected at the binding boundary (uniffi's `bytes` parameter is decoded into a [u8; 16] by the wrapper). The Rust replay must surface InvalidArgument as a synthetic err vector because no bridge entry point with this signature returns it directly.",
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
```

Note: `read_block_happy.expected.records` is `[]` for now. The generator (Step 4 below) will populate it.

- [ ] **Step 2: Extend the replay engine with chained-vector dispatch + the InvalidArgument synthetic path**

In [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs), add directly under the existing helpers:

```rust
use std::collections::HashMap;

fn run_read_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<
    secretary_ffi_bridge::record::BlockReadOutput,
    secretary_ffi_bridge::error::FfiVaultError,
> {
    // Two input shapes:
    //   - block_uuid_hex: exactly 32 hex chars → 16 bytes.
    //   - block_uuid_bytes_hex: arbitrary hex → arbitrary length. If it
    //     decodes to a 16-byte slice, dispatch via read_block; otherwise
    //     synthesize a FfiVaultError::InvalidArgument matching what the
    //     uniffi wrapper would emit for wrong-length input.
    let bytes_hex = inputs
        .get("block_uuid_hex")
        .or_else(|| inputs.get("block_uuid_bytes_hex"))
        .and_then(|v| v.as_str())
        .expect("read_block inputs need block_uuid_hex or block_uuid_bytes_hex");
    let bytes = hex::decode(bytes_hex).expect("block_uuid hex must decode");

    if bytes.len() != 16 {
        return Err(
            secretary_ffi_bridge::error::FfiVaultError::InvalidArgument {
                detail: format!("block_uuid must be exactly 16 bytes, got {}", bytes.len()),
            },
        );
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes);
    secretary_ffi_bridge::record::read_block(&cached.identity, &cached.manifest, &uuid)
}

fn assert_read_block_ok(
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
            assert_eq!(
                field.name(),
                exp_field.name,
                "{label}: records[{i}].fields[{j}].name mismatch"
            );
            match exp_field.field_type.as_str() {
                "text" => {
                    assert!(field.is_text(), "{label}: records[{i}].fields[{j}] expected text");
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
                    assert!(field.is_bytes(), "{label}: records[{i}].fields[{j}] expected bytes");
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
    }
}
```

- [ ] **Step 3: Replace the replay function body to handle chained vectors**

Replace the `replay_conformance_kat` function body in [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs) with:

```rust
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
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => panic!("{label}: expected Ok, got Err {e:?}"),
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
```

- [ ] **Step 4: Run the test (it WILL fail on `read_block_happy`)**

Run: `cargo test --release --workspace replay_conformance_kat -- --nocapture`

Expected: FAIL on `read_block_happy` because the KAT pins `records: []` but the bridge returns 1 record (`33445566-7788-99aa-bbcc-ddeeff001122` → `login`). The error message will say something like `read_block_happy: record_count mismatch`.

This is the "red" half of the TDD cycle — the next step ("write the generator") will run the bridge and dump the actual records into the KAT, turning red into green.

- [ ] **Step 5: Implement the `#[ignore]` generator**

Add directly below the `replay_conformance_kat` test in [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs):

```rust
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
    let opened = secretary_ffi_bridge::vault::open_vault_with_password(
        vault_dir.to_string_lossy().as_bytes(),
        &password,
    )
    .expect("open_vault_with_password(golden_vault_001) must succeed");

    // Find the read_block_happy vector and populate its records.
    let block_uuid_hex = "11223344556677889900aabbccddeeff";
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
        .insert("records".to_string(), serde_json::Value::Array(records_json));

    let pretty =
        serde_json::to_string_pretty(&kat).expect("KAT must reserialize") + "\n";
    std::fs::write(kat_path(), pretty).expect("KAT must be writable");
    eprintln!(
        "generate_conformance_kat: wrote {} ({} records under read_block_happy)",
        kat_path().display(),
        read.record_count()
    );
}
```

- [ ] **Step 6: Run the generator to populate the KAT**

Run: `cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture`

Expected: PASS with `generate_conformance_kat: wrote .../conformance_kat.json (1 records under read_block_happy)`.

- [ ] **Step 7: Diff-review the populated KAT**

Run: `git diff core/tests/data/conformance_kat.json`

Expected diff: only the `read_block_happy.expected.records` array changed from `[]` to a 1-element array with `record_uuid_hex`, `record_type: "login"`, `tags: ["work"]`, and 2 text fields (`username` = `owner@example.com`, `password` = `hunter2`). No other vectors should change.

If the diff touches any other field, **STOP and investigate** — that's a regression.

- [ ] **Step 8: Run the replay to confirm it now passes**

Run: `cargo test --release --workspace replay_conformance_kat -- --nocapture`

Expected: PASS — all 9 vectors exercised (6 source + 3 chained), no failures.

- [ ] **Step 9: Full gauntlet**

Run:

```bash
cargo test --release --workspace --no-fail-fast
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
```

All three: clean. Test count = baseline + 1 non-ignored + 1 ignored.

- [ ] **Step 10: Commit**

```bash
git add core/tests/conformance_kat.rs core/tests/data/conformance_kat.json
git commit -m "$(cat <<'EOF'
feat(b6): add read_block vectors + generator + populated KAT

Lands the 3 chained read_block vectors (happy + BlockNotFound + wrong-
length UUID synthesizes InvalidArgument), the chained-vector cache-and-
lookup logic in the replay engine, and the #[ignore] generator that
dumps the bridge crate's read_block output into the KAT.

The Rust side is now complete — Swift + Kotlin runners in Tasks 4 + 5
consume the same JSON.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Swift conformance harness

**Files:**
- Create: `ffi/secretary-ffi-uniffi/tests/swift/conformance.swift`
- Create: `ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh`

Builds the Swift host runner. Loads `conformance_kat.json` via Foundation's `JSONSerialization`, executes each vector through the uniffi-generated `secretary` module, prints one PASS/FAIL per vector + a final summary.

- [ ] **Step 1: Write the runner skeleton**

Create [ffi/secretary-ffi-uniffi/tests/swift/conformance.swift](../../../ffi/secretary-ffi-uniffi/tests/swift/conformance.swift):

```swift
// macOS-host Swift conformance KAT replay (B.6 v1).
//
// Parallels the Rust replay in core/tests/conformance_kat.rs. Loads
// conformance_kat.json, dispatches each vector through the uniffi-
// generated Swift wrapper, asserts the observable output matches the
// pinned expectation. One PASS/FAIL line per vector + a final summary.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh

import Foundation

// --- Path resolution ---

guard let kat_path = ProcessInfo.processInfo.environment["SECRETARY_CONFORMANCE_KAT"] else {
    FileHandle.standardError.write(
        Data("error: SECRETARY_CONFORMANCE_KAT not set; run via tests/swift/run_conformance.sh\n".utf8)
    )
    exit(1)
}
guard let golden_vault_dir = ProcessInfo.processInfo.environment["SECRETARY_GOLDEN_VAULT_DIR"] else {
    FileHandle.standardError.write(
        Data("error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/swift/run_conformance.sh\n".utf8)
    )
    exit(1)
}

let kat_data: Data
do {
    kat_data = try Data(contentsOf: URL(fileURLWithPath: kat_path))
} catch {
    FileHandle.standardError.write(Data("error: failed to read \(kat_path): \(error)\n".utf8))
    exit(1)
}

guard let kat = try? JSONSerialization.jsonObject(with: kat_data) as? [String: Any] else {
    FileHandle.standardError.write(Data("error: \(kat_path) does not parse as a JSON object\n".utf8))
    exit(1)
}

guard (kat["version"] as? Int) == 1 else {
    FileHandle.standardError.write(Data("error: KAT version must be 1\n".utf8))
    exit(1)
}

guard let vectors = kat["vectors"] as? [[String: Any]] else {
    FileHandle.standardError.write(Data("error: vectors array missing or wrong type\n".utf8))
    exit(1)
}

var failures: [String] = []
var vectors_run: Int = 0
var cache: [String: OpenVaultOutput] = [:]
```

- [ ] **Step 2: Add input-resolution helpers**

Append to [conformance.swift](../../../ffi/secretary-ffi-uniffi/tests/swift/conformance.swift):

```swift
// --- Input resolution helpers ---

func resolve_source(_ source: String) -> Data {
    let parts = source.split(separator: ":", maxSplits: 1)
    guard parts.count == 2 else {
        FileHandle.standardError.write(Data("malformed source ref: \(source)\n".utf8))
        exit(1)
    }
    let file = URL(fileURLWithPath: golden_vault_dir).appendingPathComponent(String(parts[0]))
    let field = String(parts[1])
    guard let bytes = try? Data(contentsOf: file),
        let obj = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
        let str = obj[field] as? String
    else {
        FileHandle.standardError.write(Data("failed to resolve \(source)\n".utf8))
        exit(1)
    }
    return Data(str.utf8)
}

func resolve_vault_dir(_ inputs: [String: Any]) -> Data {
    if let s = inputs["vault_dir"] as? String {
        let url = URL(fileURLWithPath: golden_vault_dir).appendingPathComponent(s)
        return Data(url.path.utf8)
    }
    if let s = inputs["vault_dir_literal"] as? String {
        return Data(s.utf8)
    }
    FileHandle.standardError.write(Data("vector inputs missing vault_dir / vault_dir_literal\n".utf8))
    exit(1)
}

func resolve_password(_ inputs: [String: Any]) -> Data {
    if let s = inputs["password_source"] as? String { return resolve_source(s) }
    if let s = inputs["password_literal_utf8"] as? String { return Data(s.utf8) }
    FileHandle.standardError.write(Data("vector inputs missing password_*\n".utf8))
    exit(1)
}

func resolve_mnemonic(_ inputs: [String: Any]) -> Data {
    if let s = inputs["mnemonic_source"] as? String { return resolve_source(s) }
    if let s = inputs["mnemonic_literal_utf8"] as? String { return Data(s.utf8) }
    FileHandle.standardError.write(Data("vector inputs missing mnemonic_*\n".utf8))
    exit(1)
}

func decode_hex(_ s: String) -> Data {
    var bytes: [UInt8] = []
    var chars = Array(s)
    var i = 0
    while i + 1 < chars.count {
        guard let b = UInt8(String(chars[i]) + String(chars[i + 1]), radix: 16) else {
            FileHandle.standardError.write(Data("malformed hex: \(s)\n".utf8))
            exit(1)
        }
        bytes.append(b)
        i += 2
    }
    return Data(bytes)
}

func encode_hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}
```

- [ ] **Step 3: Add error-variant-name extraction**

Append:

```swift
// --- Error variant name extraction (mirrors the Rust variant_name_vault helper) ---

func vault_error_name(_ e: VaultError) -> String {
    switch e {
    case .WrongPasswordOrCorrupt: return "WrongPasswordOrCorrupt"
    case .WrongMnemonicOrCorrupt: return "WrongMnemonicOrCorrupt"
    case .InvalidMnemonic: return "InvalidMnemonic"
    case .VaultMismatch: return "VaultMismatch"
    case .CorruptVault: return "CorruptVault"
    case .FolderInvalid: return "FolderInvalid"
    case .BlockNotFound: return "BlockNotFound"
    case .SaveCryptoFailure: return "SaveCryptoFailure"
    case .NotAuthor: return "NotAuthor"
    case .RecipientAlreadyPresent: return "RecipientAlreadyPresent"
    case .MissingRecipientCard: return "MissingRecipientCard"
    case .CardDecodeFailure: return "CardDecodeFailure"
    case .BlockUuidAlreadyLive: return "BlockUuidAlreadyLive"
    case .BlockNotInTrash: return "BlockNotInTrash"
    case .InvalidArgument: return "InvalidArgument"
    }
}

func vault_error_detail(_ e: VaultError) -> String? {
    switch e {
    case .InvalidMnemonic(let d): return d
    case .CorruptVault(let d): return d
    case .FolderInvalid(let d): return d
    case .SaveCryptoFailure(let d): return d
    case .CardDecodeFailure(let d): return d
    case .BlockUuidAlreadyLive(let d): return d
    case .BlockNotInTrash(let d): return d
    case .InvalidArgument(let d): return d
    default: return nil
    }
}

func check(_ ok: Bool, _ vector_name: String, _ message: String) -> Bool {
    if ok { return true }
    failures.append("\(vector_name): \(message)")
    FileHandle.standardError.write(Data("FAIL: \(vector_name): \(message)\n".utf8))
    return false
}
```

Note: this match enumerates every variant of `VaultError`. If uniffi adds a new case the Swift compiler will emit a non-exhaustive-switch error — that's the intended tripwire.

- [ ] **Step 4: Add the dispatch loop body**

Append:

```swift
// --- Vector dispatch loop ---

for vec in vectors {
    vectors_run += 1
    guard let name = vec["name"] as? String,
        let operation = vec["operation"] as? String,
        let inputs = vec["inputs"] as? [String: Any],
        let expected = vec["expected"] as? [String: Any],
        let kind = expected["kind"] as? String
    else {
        failures.append("vector \(vectors_run) is malformed")
        continue
    }
    let after = vec["after"] as? String

    switch (operation, after) {
    case ("open_vault_with_password", nil):
        let vault_dir = resolve_vault_dir(inputs)
        let password = resolve_password(inputs)
        do {
            let out = try openVaultWithPassword(folderPath: vault_dir, password: password)
            if kind != "ok" { _ = check(false, name, "expected err, got ok"); continue }
            if let display = expected["display_name"] as? String {
                _ = check(out.identity.displayName() == display, name, "display_name mismatch")
            }
            if let bc = expected["block_count"] as? Int {
                _ = check(Int(out.manifest.blockCount()) == bc, name, "block_count mismatch")
            }
            if let bu = expected["block_uuid_hex"] as? String {
                let summaries = out.manifest.blockSummaries()
                if !summaries.isEmpty {
                    _ = check(encode_hex(Data(summaries[0].blockUuid)) == bu, name, "block_uuid mismatch")
                } else {
                    _ = check(false, name, "manifest has no blocks but block_uuid pinned")
                }
            }
            cache[name] = out
            print("PASS: \(name)")
        } catch let e as VaultError {
            if kind != "err" { _ = check(false, name, "expected ok, got err: \(e)"); continue }
            let want = expected["variant"] as? String ?? ""
            _ = check(vault_error_name(e) == want, name, "variant mismatch (got \(vault_error_name(e)), expected \(want))")
            if let needle = expected["detail_contains"] as? String {
                let detail = vault_error_detail(e) ?? ""
                _ = check(detail.contains(needle), name, "detail '\(detail)' missing '\(needle)'")
            }
            print("PASS: \(name)")
        } catch {
            _ = check(false, name, "unexpected non-VaultError exception: \(error)")
        }

    case ("open_vault_with_recovery", nil):
        let vault_dir = resolve_vault_dir(inputs)
        let mnemonic = resolve_mnemonic(inputs)
        do {
            let out = try openVaultWithRecovery(folderPath: vault_dir, mnemonic: mnemonic)
            if kind != "ok" { _ = check(false, name, "expected err, got ok"); continue }
            if let display = expected["display_name"] as? String {
                _ = check(out.identity.displayName() == display, name, "display_name mismatch")
            }
            if let bc = expected["block_count"] as? Int {
                _ = check(Int(out.manifest.blockCount()) == bc, name, "block_count mismatch")
            }
            if let bu = expected["block_uuid_hex"] as? String {
                let summaries = out.manifest.blockSummaries()
                if !summaries.isEmpty {
                    _ = check(encode_hex(Data(summaries[0].blockUuid)) == bu, name, "block_uuid mismatch")
                } else {
                    _ = check(false, name, "manifest has no blocks but block_uuid pinned")
                }
            }
            cache[name] = out
            print("PASS: \(name)")
        } catch let e as VaultError {
            if kind != "err" { _ = check(false, name, "expected ok, got err: \(e)"); continue }
            let want = expected["variant"] as? String ?? ""
            _ = check(vault_error_name(e) == want, name, "variant mismatch (got \(vault_error_name(e)), expected \(want))")
            if let needle = expected["detail_contains"] as? String {
                let detail = vault_error_detail(e) ?? ""
                _ = check(detail.contains(needle), name, "detail '\(detail)' missing '\(needle)'")
            }
            print("PASS: \(name)")
        } catch {
            _ = check(false, name, "unexpected non-VaultError exception: \(error)")
        }

    case ("read_block", let predecessor?):
        guard let cached = cache[predecessor] else {
            _ = check(false, name, "predecessor '\(predecessor)' did not produce a cacheable Ok")
            continue
        }
        // Decide between block_uuid_hex (32 chars = 16 bytes) and block_uuid_bytes_hex (any length).
        var raw = Data()
        if let s = inputs["block_uuid_hex"] as? String { raw = decode_hex(s) }
        else if let s = inputs["block_uuid_bytes_hex"] as? String { raw = decode_hex(s) }
        else { _ = check(false, name, "missing block_uuid_*"); continue }

        do {
            // uniffi's read_block expects a 16-byte sequence; the binding-layer
            // wrapper rejects non-16-byte input as InvalidArgument before
            // dispatching to the bridge.
            let out = try readBlock(identity: cached.identity, manifest: cached.manifest, blockUuid: raw)
            if kind != "ok" { _ = check(false, name, "expected err, got ok"); continue }
            if let records = expected["records"] as? [[String: Any]] {
                _ = check(Int(out.recordCount()) == records.count, name, "record_count mismatch")
                for (i, exp_rec) in records.enumerated() {
                    guard let rec = out.recordAt(idx: UInt64(i)) else {
                        _ = check(false, name, "record_at(\(i)) returned nil")
                        continue
                    }
                    if let uhex = exp_rec["record_uuid_hex"] as? String {
                        _ = check(encode_hex(Data(rec.recordUuid())) == uhex, name, "records[\(i)].record_uuid mismatch")
                    }
                    if let rtype = exp_rec["record_type"] as? String {
                        _ = check(rec.recordType() == rtype, name, "records[\(i)].record_type mismatch")
                    }
                    if let tags = exp_rec["tags"] as? [String] {
                        _ = check(rec.tags() == tags, name, "records[\(i)].tags mismatch")
                    }
                    if let fields = exp_rec["fields"] as? [[String: Any]] {
                        _ = check(Int(rec.fieldCount()) == fields.count, name, "records[\(i)].field_count mismatch")
                        for (j, exp_f) in fields.enumerated() {
                            guard let fh = rec.fieldAt(idx: UInt64(j)) else {
                                _ = check(false, name, "records[\(i)].field_at(\(j)) nil")
                                continue
                            }
                            if let fname = exp_f["name"] as? String {
                                _ = check(fh.name() == fname, name, "records[\(i)].fields[\(j)].name mismatch")
                            }
                            if let ftype = exp_f["type"] as? String {
                                if ftype == "text" {
                                    _ = check(fh.isText(), name, "records[\(i)].fields[\(j)] expected text")
                                    if let ev = exp_f["value_utf8"] as? String {
                                        _ = check(fh.exposeText() == ev, name, "records[\(i)].fields[\(j)].value_utf8 mismatch")
                                    }
                                } else if ftype == "bytes" {
                                    _ = check(fh.isBytes(), name, "records[\(i)].fields[\(j)] expected bytes")
                                    if let ev = exp_f["value_hex"] as? String {
                                        let actual = encode_hex(Data(fh.exposeBytes() ?? []))
                                        _ = check(actual == ev, name, "records[\(i)].fields[\(j)].value_hex mismatch")
                                    }
                                }
                            }
                        }
                    }
                }
            }
            print("PASS: \(name)")
        } catch let e as VaultError {
            if kind != "err" { _ = check(false, name, "expected ok, got err: \(e)"); continue }
            let want = expected["variant"] as? String ?? ""
            _ = check(vault_error_name(e) == want, name, "variant mismatch (got \(vault_error_name(e)), expected \(want))")
            if let needle = expected["detail_contains"] as? String {
                let detail = vault_error_detail(e) ?? ""
                _ = check(detail.contains(needle), name, "detail '\(detail)' missing '\(needle)'")
            }
            print("PASS: \(name)")
        } catch {
            _ = check(false, name, "unexpected non-VaultError exception: \(error)")
        }

    default:
        _ = check(false, name, "unhandled operation '\(operation)' with after=\(String(describing: after))")
    }
}

if failures.isEmpty {
    print("OK: secretary uniffi Swift conformance — all \(vectors_run)/\(vectors_run) vectors passed.")
    exit(0)
} else {
    FileHandle.standardError.write(
        Data("FAIL: secretary uniffi Swift conformance — \(failures.count) of \(vectors_run) vectors failed\n".utf8)
    )
    for f in failures { FileHandle.standardError.write(Data("  - \(f)\n".utf8)) }
    exit(1)
}
```

- [ ] **Step 5: Write `run_conformance.sh`**

Create [ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh](../../../ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh):

```bash
#!/usr/bin/env bash
# macOS-host Swift conformance KAT replay runner.
#
# Parallels tests/swift/run.sh (smoke runner) but compiles a different
# binary (secretary_conformance) and points it at the conformance KAT
# JSON via SECRETARY_CONFORMANCE_KAT.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
BINDINGS_DIR="$CRATE_DIR/bindings/swift"
TARGET_DIR="$REPO_ROOT/target/release"
CDYLIB="$TARGET_DIR/libsecretary_ffi_uniffi.dylib"
BIN_OUT="$SCRIPT_DIR/secretary_conformance"

export SECRETARY_GOLDEN_VAULT_DIR="$REPO_ROOT/core/tests/data"
export SECRETARY_CONFORMANCE_KAT="$REPO_ROOT/core/tests/data/conformance_kat.json"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: this conformance runner targets macOS hosts (got $(uname -s))" >&2
    exit 2
fi
if ! command -v swiftc >/dev/null 2>&1; then
    echo "ERROR: swiftc not found in PATH" >&2
    exit 2
fi

echo "==> cargo build --release -p secretary-ffi-uniffi"
(cd "$REPO_ROOT" && cargo build --release -p secretary-ffi-uniffi)
[[ -f "$CDYLIB" ]] || { echo "ERROR: cdylib not produced at $CDYLIB" >&2; exit 3; }

echo "==> uniffi-bindgen generate (Swift)"
mkdir -p "$BINDINGS_DIR"
(cd "$REPO_ROOT" && cargo run --release --features cli -p secretary-ffi-uniffi \
    --bin uniffi-bindgen -- generate \
    --library "$CDYLIB" \
    --language swift \
    --out-dir "$BINDINGS_DIR")

echo "==> swiftc conformance runner"
swiftc \
    -O \
    -I "$BINDINGS_DIR" \
    -L "$TARGET_DIR" \
    -lsecretary_ffi_uniffi \
    -Xcc -fmodule-map-file="$BINDINGS_DIR/secretaryFFI.modulemap" \
    "$BINDINGS_DIR/secretary.swift" \
    "$SCRIPT_DIR/conformance.swift" \
    -o "$BIN_OUT"

echo "==> running $BIN_OUT"
DYLD_LIBRARY_PATH="$TARGET_DIR" "$BIN_OUT"
```

Mark it executable: `chmod +x ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh`.

- [ ] **Step 6: Run the Swift conformance harness**

Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh`

Expected: `OK: secretary uniffi Swift conformance — all 9/9 vectors passed.`

If a vector fails, inspect the FAIL line: it identifies the vector name + the specific mismatch (e.g. `records[0].field_count mismatch`).

Common gotchas:
- `block_uuid_hex` is lowercase hex; the encode helper uses `%02x`. If a vector's pinned UUID is uppercase, the encode comparison fails — re-emit the KAT or adjust expectations to lowercase.
- `displayName()` is the Swift accessor (camelCase), unlike the Rust `display_name()`. If the binding regenerates to `display_name()`, this code would not compile — adjust to the new accessor.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/conformance.swift ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
git commit -m "$(cat <<'EOF'
feat(b6): Swift conformance harness replays cross-language KAT

New conformance.swift + run_conformance.sh. Loads conformance_kat.json,
executes each vector against the uniffi-generated Swift wrapper, asserts
observable parity with the Rust replay. One PASS/FAIL line per vector +
final summary; exits non-zero on any divergence.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Kotlin conformance harness

**Files:**
- Create: `ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt`
- Create: `ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh`

Direct port of the Swift runner. Uses Kotlin's `java.io.File` + a hand-rolled minimal JSON parser (the JVM stdlib's `org.json` is not on the classpath; pulling it in would add a Maven fetch comparable to JNA's). Instead this task uses Kotlin's no-dependency option: `javax.json` is not stdlib, `org.json` is not stdlib — the runner uses the bundled `kotlin-stdlib` and a tiny hand-rolled JSON parser specifically for the KAT's shape.

**Decision (deferred from design §11):** Use `org.json:json` fetched via Maven Central, pinned + SHA-256 verified like the existing JNA fetch. Hand-rolling a JSON parser for nested record arrays is fragile; reusing the JNA-fetch+verify pattern keeps risk contained. The new fetch adds ~80KB to `tests/kotlin/lib/`.

- [ ] **Step 1: Write the Kotlin runner**

Create [ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt](../../../ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt):

```kotlin
// JVM-host Kotlin conformance KAT replay (B.6 v1).
//
// Parallels conformance.swift + Rust's replay_conformance_kat. Loads
// conformance_kat.json via org.json, executes each vector against the
// uniffi-generated Kotlin wrapper, prints one PASS/FAIL line per vector
// + a final summary.
//
// Invocation: ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh

import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import uniffi.secretary.*

val kat_path: String = System.getenv("SECRETARY_CONFORMANCE_KAT")
    ?: run {
        System.err.println("error: SECRETARY_CONFORMANCE_KAT not set; run via tests/kotlin/run_conformance.sh")
        kotlin.system.exitProcess(1)
    }
val golden_vault_dir: String = System.getenv("SECRETARY_GOLDEN_VAULT_DIR")
    ?: run {
        System.err.println("error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/kotlin/run_conformance.sh")
        kotlin.system.exitProcess(1)
    }

val failures = mutableListOf<String>()
var vectors_run = 0
val cache = mutableMapOf<String, OpenVaultOutput>()

fun resolveSource(source: String): ByteArray {
    val parts = source.split(":", limit = 2)
    require(parts.size == 2) { "malformed source ref: $source" }
    val obj = JSONObject(File("$golden_vault_dir/${parts[0]}").readText())
    return obj.getString(parts[1]).toByteArray(Charsets.UTF_8)
}

fun resolveVaultDir(inputs: JSONObject): ByteArray {
    if (inputs.has("vault_dir")) {
        return "$golden_vault_dir/${inputs.getString("vault_dir")}".toByteArray(Charsets.UTF_8)
    }
    if (inputs.has("vault_dir_literal")) {
        return inputs.getString("vault_dir_literal").toByteArray(Charsets.UTF_8)
    }
    error("vector inputs missing vault_dir / vault_dir_literal")
}

fun resolvePassword(inputs: JSONObject): ByteArray {
    if (inputs.has("password_source")) return resolveSource(inputs.getString("password_source"))
    if (inputs.has("password_literal_utf8")) return inputs.getString("password_literal_utf8").toByteArray(Charsets.UTF_8)
    error("vector inputs missing password_*")
}

fun resolveMnemonic(inputs: JSONObject): ByteArray {
    if (inputs.has("mnemonic_source")) return resolveSource(inputs.getString("mnemonic_source"))
    if (inputs.has("mnemonic_literal_utf8")) return inputs.getString("mnemonic_literal_utf8").toByteArray(Charsets.UTF_8)
    error("vector inputs missing mnemonic_*")
}

fun decodeHex(s: String): ByteArray {
    require(s.length % 2 == 0) { "odd-length hex: $s" }
    return ByteArray(s.length / 2) { i ->
        s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

fun encodeHex(data: ByteArray): String = data.joinToString("") { "%02x".format(it) }

fun vaultErrorName(e: VaultException): String = when (e) {
    is VaultException.WrongPasswordOrCorrupt -> "WrongPasswordOrCorrupt"
    is VaultException.WrongMnemonicOrCorrupt -> "WrongMnemonicOrCorrupt"
    is VaultException.InvalidMnemonic -> "InvalidMnemonic"
    is VaultException.VaultMismatch -> "VaultMismatch"
    is VaultException.CorruptVault -> "CorruptVault"
    is VaultException.FolderInvalid -> "FolderInvalid"
    is VaultException.BlockNotFound -> "BlockNotFound"
    is VaultException.SaveCryptoFailure -> "SaveCryptoFailure"
    is VaultException.NotAuthor -> "NotAuthor"
    is VaultException.RecipientAlreadyPresent -> "RecipientAlreadyPresent"
    is VaultException.MissingRecipientCard -> "MissingRecipientCard"
    is VaultException.CardDecodeFailure -> "CardDecodeFailure"
    is VaultException.BlockUuidAlreadyLive -> "BlockUuidAlreadyLive"
    is VaultException.BlockNotInTrash -> "BlockNotInTrash"
    is VaultException.InvalidArgument -> "InvalidArgument"
}

fun vaultErrorDetail(e: VaultException): String? = when (e) {
    is VaultException.InvalidMnemonic -> e.detail
    is VaultException.CorruptVault -> e.detail
    is VaultException.FolderInvalid -> e.detail
    is VaultException.SaveCryptoFailure -> e.detail
    is VaultException.CardDecodeFailure -> e.detail
    is VaultException.BlockUuidAlreadyLive -> e.detail
    is VaultException.BlockNotInTrash -> e.detail
    is VaultException.InvalidArgument -> e.detail
    else -> null
}

fun check(ok: Boolean, name: String, message: String): Boolean {
    if (ok) return true
    failures.add("$name: $message")
    System.err.println("FAIL: $name: $message")
    return false
}

fun main() {
    val katRaw = File(kat_path).readText()
    val kat = JSONObject(katRaw)
    require(kat.getInt("version") == 1) { "KAT version must be 1" }
    val vectors = kat.getJSONArray("vectors")

    for (idx in 0 until vectors.length()) {
        vectors_run += 1
        val vec = vectors.getJSONObject(idx)
        val name = vec.getString("name")
        val operation = vec.getString("operation")
        val inputs = vec.getJSONObject("inputs")
        val expected = vec.getJSONObject("expected")
        val kind = expected.getString("kind")
        val after = if (vec.has("after")) vec.getString("after") else null

        when (Pair(operation, after)) {
            "open_vault_with_password" to null -> dispatchOpenPassword(name, inputs, expected, kind)
            "open_vault_with_recovery" to null -> dispatchOpenRecovery(name, inputs, expected, kind)
            else -> if (operation == "read_block" && after != null) {
                dispatchReadBlock(name, inputs, expected, kind, after)
            } else {
                check(false, name, "unhandled operation '$operation' with after=$after")
            }
        }
    }

    if (failures.isEmpty()) {
        println("OK: secretary uniffi Kotlin conformance — all $vectors_run/$vectors_run vectors passed.")
        kotlin.system.exitProcess(0)
    } else {
        System.err.println("FAIL: secretary uniffi Kotlin conformance — ${failures.size} of $vectors_run vectors failed")
        failures.forEach { System.err.println("  - $it") }
        kotlin.system.exitProcess(1)
    }
}

fun dispatchOpenPassword(name: String, inputs: JSONObject, expected: JSONObject, kind: String) {
    val vaultDir = resolveVaultDir(inputs)
    val password = resolvePassword(inputs)
    try {
        val out = openVaultWithPassword(vaultDir, password)
        if (kind != "ok") { check(false, name, "expected err, got ok"); return }
        if (expected.has("display_name")) check(out.identity.displayName() == expected.getString("display_name"), name, "display_name mismatch")
        if (expected.has("block_count")) check(out.manifest.blockCount().toLong() == expected.getLong("block_count"), name, "block_count mismatch")
        if (expected.has("block_uuid_hex")) {
            val summaries = out.manifest.blockSummaries()
            if (summaries.isNotEmpty()) {
                check(encodeHex(summaries[0].blockUuid) == expected.getString("block_uuid_hex"), name, "block_uuid mismatch")
            } else {
                check(false, name, "manifest has no blocks but block_uuid pinned")
            }
        }
        cache[name] = out
        println("PASS: $name")
    } catch (e: VaultException) {
        if (kind != "err") { check(false, name, "expected ok, got err: $e"); return }
        val want = expected.getString("variant")
        check(vaultErrorName(e) == want, name, "variant mismatch (got ${vaultErrorName(e)}, expected $want)")
        if (expected.has("detail_contains")) {
            val detail = vaultErrorDetail(e) ?: ""
            check(detail.contains(expected.getString("detail_contains")), name, "detail '$detail' missing")
        }
        println("PASS: $name")
    }
}

fun dispatchOpenRecovery(name: String, inputs: JSONObject, expected: JSONObject, kind: String) {
    val vaultDir = resolveVaultDir(inputs)
    val mnemonic = resolveMnemonic(inputs)
    try {
        val out = openVaultWithRecovery(vaultDir, mnemonic)
        if (kind != "ok") { check(false, name, "expected err, got ok"); return }
        if (expected.has("display_name")) check(out.identity.displayName() == expected.getString("display_name"), name, "display_name mismatch")
        if (expected.has("block_count")) check(out.manifest.blockCount().toLong() == expected.getLong("block_count"), name, "block_count mismatch")
        if (expected.has("block_uuid_hex")) {
            val summaries = out.manifest.blockSummaries()
            if (summaries.isNotEmpty()) {
                check(encodeHex(summaries[0].blockUuid) == expected.getString("block_uuid_hex"), name, "block_uuid mismatch")
            } else {
                check(false, name, "manifest has no blocks but block_uuid pinned")
            }
        }
        cache[name] = out
        println("PASS: $name")
    } catch (e: VaultException) {
        if (kind != "err") { check(false, name, "expected ok, got err: $e"); return }
        val want = expected.getString("variant")
        check(vaultErrorName(e) == want, name, "variant mismatch (got ${vaultErrorName(e)}, expected $want)")
        if (expected.has("detail_contains")) {
            val detail = vaultErrorDetail(e) ?: ""
            check(detail.contains(expected.getString("detail_contains")), name, "detail '$detail' missing")
        }
        println("PASS: $name")
    }
}

fun dispatchReadBlock(name: String, inputs: JSONObject, expected: JSONObject, kind: String, predecessor: String) {
    val cached = cache[predecessor] ?: run {
        check(false, name, "predecessor '$predecessor' did not produce a cacheable Ok")
        return
    }
    val raw = when {
        inputs.has("block_uuid_hex") -> decodeHex(inputs.getString("block_uuid_hex"))
        inputs.has("block_uuid_bytes_hex") -> decodeHex(inputs.getString("block_uuid_bytes_hex"))
        else -> { check(false, name, "missing block_uuid_*"); return }
    }
    try {
        val out = readBlock(cached.identity, cached.manifest, raw)
        if (kind != "ok") { check(false, name, "expected err, got ok"); return }
        if (expected.has("records")) {
            val records = expected.getJSONArray("records")
            check(out.recordCount().toLong() == records.length().toLong(), name, "record_count mismatch")
            for (i in 0 until records.length()) {
                val expRec = records.getJSONObject(i)
                val rec = out.recordAt(idx = i.toULong()) ?: run {
                    check(false, name, "record_at($i) null"); continue
                }
                if (expRec.has("record_uuid_hex")) check(encodeHex(rec.recordUuid()) == expRec.getString("record_uuid_hex"), name, "records[$i].record_uuid mismatch")
                if (expRec.has("record_type")) check(rec.recordType() == expRec.getString("record_type"), name, "records[$i].record_type mismatch")
                if (expRec.has("tags")) {
                    val expTags = expRec.getJSONArray("tags").let { ta -> (0 until ta.length()).map { ta.getString(it) } }
                    check(rec.tags() == expTags, name, "records[$i].tags mismatch")
                }
                if (expRec.has("fields")) {
                    val fields = expRec.getJSONArray("fields")
                    check(rec.fieldCount().toLong() == fields.length().toLong(), name, "records[$i].field_count mismatch")
                    for (j in 0 until fields.length()) {
                        val expF = fields.getJSONObject(j)
                        val fh = rec.fieldAt(idx = j.toULong()) ?: run {
                            check(false, name, "records[$i].field_at($j) null"); continue
                        }
                        if (expF.has("name")) check(fh.name() == expF.getString("name"), name, "records[$i].fields[$j].name mismatch")
                        when (expF.optString("type")) {
                            "text" -> {
                                check(fh.isText(), name, "records[$i].fields[$j] expected text")
                                if (expF.has("value_utf8")) check(fh.exposeText() == expF.getString("value_utf8"), name, "records[$i].fields[$j].value_utf8 mismatch")
                            }
                            "bytes" -> {
                                check(fh.isBytes(), name, "records[$i].fields[$j] expected bytes")
                                if (expF.has("value_hex")) check(encodeHex(fh.exposeBytes() ?: byteArrayOf()) == expF.getString("value_hex"), name, "records[$i].fields[$j].value_hex mismatch")
                            }
                        }
                    }
                }
            }
        }
        println("PASS: $name")
    } catch (e: VaultException) {
        if (kind != "err") { check(false, name, "expected ok, got err: $e"); return }
        val want = expected.getString("variant")
        check(vaultErrorName(e) == want, name, "variant mismatch (got ${vaultErrorName(e)}, expected $want)")
        if (expected.has("detail_contains")) {
            val detail = vaultErrorDetail(e) ?: ""
            check(detail.contains(expected.getString("detail_contains")), name, "detail '$detail' missing")
        }
        println("PASS: $name")
    }
}
```

- [ ] **Step 2: Find a verified org.json SHA-256**

Run:

```bash
curl -fsSL https://repo1.maven.org/maven2/org/json/json/20240303/json-20240303.jar -o /tmp/json-20240303.jar
sha256sum /tmp/json-20240303.jar
```

Record the hash output. The version `20240303` is the most recent at the time of this plan; if Maven Central serves a newer one, prefer that and capture its hash.

- [ ] **Step 3: Write `run_conformance.sh`**

Create [ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh](../../../ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh):

```bash
#!/usr/bin/env bash
# JVM-host Kotlin conformance KAT replay runner.
#
# Parallels tests/kotlin/run.sh (smoke runner). Adds org.json (pinned +
# SHA-256 verified) for KAT JSON parsing; JNA fetch unchanged from
# run.sh because the cdylib bridge is identical.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
BINDINGS_DIR="$CRATE_DIR/bindings/kotlin"
TARGET_DIR="$REPO_ROOT/target/release"
LIB_DIR="$SCRIPT_DIR/lib"
JAR_OUT="$SCRIPT_DIR/secretary_conformance.jar"

export SECRETARY_GOLDEN_VAULT_DIR="$REPO_ROOT/core/tests/data"
export SECRETARY_CONFORMANCE_KAT="$REPO_ROOT/core/tests/data/conformance_kat.json"

case "$(uname -s)" in
    Darwin*)  CDYLIB_NAME="libsecretary_ffi_uniffi.dylib" ;;
    Linux*)   CDYLIB_NAME="libsecretary_ffi_uniffi.so" ;;
    MINGW*|MSYS*|CYGWIN*) CDYLIB_NAME="secretary_ffi_uniffi.dll" ;;
    *) echo "ERROR: unsupported host OS $(uname -s)" >&2; exit 2 ;;
esac
CDYLIB="$TARGET_DIR/$CDYLIB_NAME"

JNA_VERSION="5.14.0"
JNA_SHA256="34ed1e1f27fa896bca50dbc4e99cf3732967cec387a7a0d5e3486c09673fe8c6"
JNA_URL="https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"
JNA_JAR="$LIB_DIR/jna-${JNA_VERSION}.jar"

JSON_VERSION="20240303"
JSON_SHA256="<PASTE HASH FROM STEP 2>"  # ← REPLACE with the hash output from Step 2
JSON_URL="https://repo1.maven.org/maven2/org/json/json/${JSON_VERSION}/json-${JSON_VERSION}.jar"
JSON_JAR="$LIB_DIR/json-${JSON_VERSION}.jar"

if ! command -v kotlinc >/dev/null 2>&1; then
    echo "ERROR: kotlinc not found in PATH" >&2; exit 2
fi
if ! command -v java >/dev/null 2>&1; then
    echo "ERROR: java not found in PATH" >&2; exit 2
fi

echo "==> cargo build --release -p secretary-ffi-uniffi"
(cd "$REPO_ROOT" && cargo build --release -p secretary-ffi-uniffi)
[[ -f "$CDYLIB" ]] || { echo "ERROR: cdylib not produced at $CDYLIB" >&2; exit 3; }

echo "==> uniffi-bindgen generate (Kotlin)"
mkdir -p "$BINDINGS_DIR"
(cd "$REPO_ROOT" && cargo run --release --features cli -p secretary-ffi-uniffi \
    --bin uniffi-bindgen -- generate \
    --library "$CDYLIB" \
    --language kotlin \
    --out-dir "$BINDINGS_DIR")

GENERATED_KT="$BINDINGS_DIR/uniffi/secretary/secretary.kt"
[[ -f "$GENERATED_KT" ]] || { echo "ERROR: expected $GENERATED_KT" >&2; exit 3; }

verify_jar() {
    local jar="$1"; local want="$2"; local url="$3"; local label="$4"
    mkdir -p "$LIB_DIR"
    if [[ ! -f "$jar" ]]; then
        echo "==> fetching $label from Maven Central"
        curl -fsSL "$url" -o "$jar.tmp" && mv "$jar.tmp" "$jar"
    fi
    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$jar" | awk '{print $1}')"
    else
        actual="$(shasum -a 256 "$jar" | awk '{print $1}')"
    fi
    if [[ "$actual" != "$want" ]]; then
        echo "ERROR: $label SHA-256 mismatch (got $actual, want $want)" >&2
        exit 4
    fi
}
trap 'rm -f "$JNA_JAR.tmp" "$JSON_JAR.tmp"' EXIT

verify_jar "$JNA_JAR"  "$JNA_SHA256"  "$JNA_URL"  "jna-${JNA_VERSION}.jar"
verify_jar "$JSON_JAR" "$JSON_SHA256" "$JSON_URL" "json-${JSON_VERSION}.jar"

echo "==> kotlinc conformance runner"
kotlinc \
    -classpath "$JNA_JAR:$JSON_JAR" \
    -include-runtime \
    -d "$JAR_OUT" \
    "$GENERATED_KT" \
    "$SCRIPT_DIR/Conformance.kt"

echo "==> running $JAR_OUT"
java \
    -Djna.library.path="$TARGET_DIR" \
    -cp "$JAR_OUT:$JNA_JAR:$JSON_JAR" \
    ConformanceKt
```

Mark it executable: `chmod +x ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh`.

After Step 2 produces the actual SHA-256 hash, paste it into the `JSON_SHA256=` line above (replacing `<PASTE HASH FROM STEP 2>`).

- [ ] **Step 4: Run the Kotlin conformance harness**

Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh`

Expected: `OK: secretary uniffi Kotlin conformance — all 9/9 vectors passed.`

Common gotchas:
- The Kotlin top-level `main()` compiles to a class named after the source file with `Kt` appended — `Conformance.kt` → `ConformanceKt`. If you renamed the file, update the `java -cp ... <ClassName>` invocation.
- Generated uniffi Kotlin uses `kotlin.system.exitProcess`, not `System.exit`. Avoid `System.exit` to keep the binding-import consistent.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
git commit -m "$(cat <<'EOF'
feat(b6): Kotlin conformance harness replays cross-language KAT

New Conformance.kt + run_conformance.sh. Loads conformance_kat.json via
org.json (pinned + SHA-256 verified, same discipline as the JNA fetch),
executes each vector against the uniffi-generated Kotlin wrapper,
asserts observable parity with the Rust + Swift replays. Exits non-zero
on any divergence.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Docs — CLAUDE.md + ROADMAP.md

**Files:**
- Modify: `CLAUDE.md`
- Modify: `ROADMAP.md`

This task does NOT touch NEXT_SESSION.md or the handoff snapshot — those are written by the parent /nextsession session at session close, not as part of this PR's tasks. Once Task 6 is committed, the PR is ready to push and open.

- [ ] **Step 1: Update CLAUDE.md Commands section**

Edit [CLAUDE.md](../../../CLAUDE.md). Find the Commands section (around line 65, the `# Format` paragraph block). After the existing smoke runner entries (which mention `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` and `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh`), add a new paragraph block:

Find this kind of region in the file:

```
# Launch the NiceGUI fuzz dashboard at http://localhost:8080
uv run core/fuzz/monitor.py
```

After the existing block (above the `### Fuzz harness` subsection), add:

```bash
# Cross-language conformance KAT replay (B.6 v1; read-only FFI surface)
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh

# Regenerate conformance_kat.json after an intentional protocol change
# (diff is human-reviewed before commit):
cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture
```

If the exact insertion point text differs from what's shown above, place the new block somewhere reasonable in the Commands section — the goal is discoverability, not a specific line number.

- [ ] **Step 2: Update ROADMAP.md current-state line**

Edit [ROADMAP.md](../../../ROADMAP.md). Find line 34 (the current-state wall). Append a brief note for B.6 v1.

Run first to locate the exact line:

```bash
grep -n "Swift 37" ROADMAP.md
```

Then edit the line to add a parenthetical or sub-bullet for B.6 v1:

```
... Swift 37/37 / Kotlin 37/37 conformance KAT 9/9 (B.6 v1; read-only path).
```

Keep the addition brief — single phrase, no walls of text. Per `feedback_readme_style.md` discipline.

- [ ] **Step 3: Run the full gauntlet one last time**

Run:

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
# Expect: TOTAL: 641 passed; 0 failed; 10 ignored

cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh                 # 37/37 PASS
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh     # 9/9 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh                # 37/37 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh    # 9/9 PASS
```

All checks: green.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md ROADMAP.md
git commit -m "$(cat <<'EOF'
docs(b6): document conformance KAT runners + mark v1 done in ROADMAP

CLAUDE.md Commands section gets the two new run_conformance.sh entries
and the regeneration command. ROADMAP.md current-state line gets a
brief note that Swift + Kotlin both replay 9/9 KAT vectors.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Final: open the PR

After Task 6 lands, the branch carries 7 commits (1 design doc + 6 implementation). Push and open:

```bash
git push -u origin feature/ffi-b6-conformance-kat-v1

gh pr create --title "feat(b6): cross-language FFI conformance KAT (v1 read-only path)" --body "$(cat <<'EOF'
## Summary
- Adds `core/tests/data/conformance_kat.json` — a frozen JSON contract pinning the observable output of `open_vault_with_password` / `open_vault_with_recovery` / `read_block` against `golden_vault_001`.
- Three replay engines validate the contract: Rust bridge (`core/tests/conformance_kat.rs`, every `cargo test`), Swift uniffi (`tests/swift/conformance.swift`), Kotlin uniffi (`tests/kotlin/Conformance.kt`). All three must agree or any fails.
- 9 vectors total: 3 happy paths (open_password, open_recovery, read_block) + 6 error paths (WrongPassword, FolderInvalid, WrongMnemonic, InvalidMnemonic with `detail_contains`, BlockNotFound, InvalidArgument).
- Read-only scope by design — lifecycle vectors (save/share/trash/restore) deferred to a v2 KAT once `save_block` non-determinism is resolved (filed as a follow-up issue, link below).

Design doc: [docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md](docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md).

## Test plan
- [ ] `cargo test --release --workspace` — 641 passed + 10 ignored (+1 each over baseline).
- [ ] `cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture` — regenerates the KAT cleanly; diff is empty when re-run twice.
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` — clean.
- [ ] `cargo fmt --all -- --check` — OK.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` — 9/9 PASS.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` — 9/9 PASS.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` + `tests/kotlin/run.sh` — 37/37 PASS each (unchanged).
- [ ] `uv run core/tests/python/conformance.py` + `spec_test_name_freshness.py` — both PASS (unchanged).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

After the PR opens, file the v2 follow-up issue:

```bash
gh issue create --title "B.6 v2: lifecycle conformance KAT (save / share / trash / restore vectors)" --body "$(cat <<'EOF'
B.6 v1 (PR <link to this PR>) added the read-only half of the cross-language FFI conformance KAT. v2 extends it to the lifecycle ops.

## Scope
- `save_block` (insert + update + persist-and-reopen)
- `share_block` (happy + RecipientAlreadyPresent + MissingRecipientCard)
- `trash_block` (happy + unknown UUID)
- `restore_block` (happy + never-trashed + live-collision)

## Open design question (the blocker for v1)
- `save_block` uses OS-CSPRNG-driven AEAD nonces, so the on-disk block bytes differ between runs even for byte-identical inputs.
- Options for v2:
  1. Add a `#[cfg(test)]` RNG knob to the bridge that seeds the AEAD nonce stream deterministically; pin full output bytes.
  2. Keep nondeterminism; pin shape-only assertions (block_count delta, manifest signature presence, trash entry exists, etc.) instead of bytes.
  3. Refactor save_block to take a `dyn RngCore` parameter; production passes `OsRng`, tests pass a seeded generator.

(2) is the lightest touch; (3) is the cleanest if we ever need write-path determinism elsewhere. Brainstorm + design doc + spec review before implementation.

## Acceptance criteria (preliminary, refine during brainstorming)
- All four lifecycle ops have at least one happy + one error vector in the KAT.
- The three replay engines (Rust + Swift + Kotlin) all execute the new vectors and pass.
- The chosen determinism approach is documented in the v2 design doc with the rationale for not picking the other two.
EOF
)"
```

---

## Self-review (run before announcing plan ready)

### 1. Spec coverage

| Spec section | Plan task(s) |
|---|---|
| §1 Purpose | Covered by Tasks 1–5 collectively. |
| §2 Architectural decisions: parity contract | All three replay engines exist (Task 3 Rust + Task 4 Swift + Task 5 Kotlin). |
| §2 Architectural decisions: read-only scope | All 9 vectors are read-only (Tasks 2 + 3). No save/share/trash/restore. |
| §2 Architectural decisions: Rust generator | Task 3 Step 5. |
| §2 Architectural decisions: three partners | All three replay engines: Tasks 3, 4, 5. |
| §2 Architectural decisions: separate harness | Task 4 + 5 each create new `*_conformance.{swift,kt}` + `run_conformance.sh`. |
| §2 Architectural decisions: vector identifier `name` | Used throughout the JSON (Tasks 2 + 3). |
| §2 Architectural decisions: `after:` chain | Task 3 Step 1 (JSON) + Step 3 (replay logic). |
| §2 Architectural decisions: `expected.kind` discriminator | All replay engines (Tasks 3, 4, 5). |
| §2 Architectural decisions: record-field positional pinning | Tasks 3 (Rust) + 4 (Swift) + 5 (Kotlin) all assert positional fields[]. |
| §2 Architectural decisions: error fixture inputs | Task 2 JSON (literal + source forms); Tasks 3/4/5 resolve them. |
| §2 Architectural decisions: path resolution via env vars | Tasks 4 + 5 `run_conformance.sh` set `SECRETARY_CONFORMANCE_KAT`. |
| §2 Architectural decisions: regeneration policy | Task 3 Step 5 implements the `#[ignore]` generator. |
| §3 Module structure | Task 1 creates `core/tests/conformance_kat.rs` + JSON; Tasks 4 + 5 create the host harness files. |
| §4 KAT vector format | Tasks 2 (6 source vectors) + 3 (3 chained vectors). |
| §5 Replay engine semantics | All three engines implement the same algorithm — Tasks 3 (Rust), 4 (Swift), 5 (Kotlin). |
| §5 Predecessor-failed-FAIL clarification | Task 3 Step 3 implements; Tasks 4 + 5 mirror. |
| §6 CI integration | Task 6 documents the entries in CLAUDE.md. |
| §7 Spec/docs updates | Task 6. |
| §8 Designed-against failure modes | Covered implicitly — any variant rename / field reorder / NUL-strip would fail the per-vector assertions. |
| §9 Implementation outline (5 commits → 6 tasks) | Plan has 6 tasks/commits; the original 5-commit estimate split out the docs task as its own commit for clean review. |
| §10 Test gauntlet | Task 6 Step 3 runs the full gauntlet. |
| §11 Deferred questions | Resolved inline: hex format (lowercase, no separators), Swift/Kotlin caseName extraction (inline `switch`/`when` in Tasks 4/5 — chosen for clarity over a code-generated extension), regen env-var gating (NOT added; `#[ignore]` is sufficient guardrail). |
| §12 Acceptance criteria | All 8 criteria touched by Tasks 1–6; PR description in "Final" section reasserts. |

### 2. Placeholder scan

| Placeholder found | Resolution |
|---|---|
| `<PASTE HASH FROM STEP 2>` in Task 5 Step 3 | Intentional — the actual hash depends on Maven Central's current artifact. Step 2 produces it; the engineer pastes it manually. Documented as such. |
| `<filled-by-generator>` in earlier design doc (§4) | Not in the plan — the plan uses concrete `records: []` skeleton + generator. Resolved. |
| "TODO" / "TBD" anywhere | None found. |
| "implement later" / "handle edge cases" | None. |

### 3. Type consistency

| Identifier | Task 3 Rust | Task 4 Swift | Task 5 Kotlin |
|---|---|---|---|
| Open vault function | `open_vault_with_password` | `openVaultWithPassword` | `openVaultWithPassword` |
| Read block function | `read_block` | `readBlock` | `readBlock` |
| Display name accessor | `display_name()` | `displayName()` | `displayName()` |
| Block count accessor | `block_count()` | `blockCount()` | `blockCount()` |
| Record UUID accessor | `record_uuid()` | `recordUuid()` | `recordUuid()` |
| Field exposure | `expose_text()` / `expose_bytes()` | `exposeText()` / `exposeBytes()` | `exposeText()` / `exposeBytes()` |
| Vault error type | `FfiVaultError` | `VaultError` | `VaultException` |

All consistent within each language (uniffi auto-camelCases). The replay engines extract the variant name as a stable string ("WrongPasswordOrCorrupt") that all three agree on.

Plan complete.

---

## Execution Handoff

Plan complete and saved to [docs/superpowers/plans/2026-05-15-ffi-b6-conformance-kat.md](2026-05-15-ffi-b6-conformance-kat.md).

Two execution options:

**1. Subagent-Driven (recommended)** — dispatch one fresh subagent per task with two-stage review between tasks. Tightest blast radius if a task goes sideways; fastest iteration on a long plan like this (6 tasks).

**2. Inline Execution** — work through tasks in the current session using `superpowers:executing-plans`, batch execution with checkpoints for review.

Which approach?
