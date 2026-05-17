# B.6 v2 — Cross-language FFI Conformance KAT (lifecycle ops) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `core/tests/data/conformance_kat.json` (currently v1, 11 read-only vectors) with 9 lifecycle vectors covering `save_block`, `share_block`, `trash_block`, `restore_block`. Each of three replay engines (Rust bridge, Swift uniffi, Kotlin uniffi) extends to dispatch the new operations and assert shape + round-trip outputs.

**Architecture:** Replay-side-only — **no bridge crate changes**. One `open_vault_with_password_writable` vector at the head of the v2 chain copies `golden_vault_001/` to a tempdir; subsequent write vectors `after:` it and mutate the cached `OpenVaultOutput` in place (via interior mutability inside `OpenVaultManifest`). Each replay engine adds a recursive-copy helper, dispatch arms for the 5 new ops, and post-state assertion helpers reading `block_count`, `find_block(uuid)`, and `BlockSummary.recipient_uuids.len()`. The Rust `#[ignore]` generator extends to fill the round-trip `read_block` records placeholder in `save_block_insert_happy`.

**Tech Stack:** Unchanged from v1. Rust + `serde_json` + `secretary-ffi-bridge` + `hex` (all already dev-deps); Swift + `Foundation.FileManager`; Kotlin + `java.nio.file.Files`.

**Design doc:** [docs/superpowers/specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md](../specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md). Read §3 (KAT vector format), §4 (vector inventory), §5 (replay engine semantics), §9 (implementation outline) before Task 1.

**Branch:** Work happens on `design/b6-v2-lifecycle-conformance-kat` (already exists; the spec is committed at `c5bb678` on this branch). No worktree split — sequential PR.

**Pre-task baseline:** Before Task 1, verify the gauntlet matches the post-session-end baseline carried by NEXT_SESSION.md (642 cargo passed + 10 ignored; 11/11 Swift + Kotlin conformance):

```bash
cd /Users/hherb/src/secretary
git checkout design/b6-v2-lifecycle-conformance-kat
git status --short                                    # Expect: clean
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
                                                      # Expect: TOTAL: 642 passed; 0 failed; 10 ignored
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh   # Expect: 11/11 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh  # Expect: 11/11 PASS
```

---

## File structure

| File | Lifecycle | Purpose |
|---|---|---|
| [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json) | Modified Tasks 7 + 10 | Bump `version: 1 → 2`; append 9 v2 vectors. |
| [core/tests/conformance_kat_helpers/types.rs](../../../core/tests/conformance_kat_helpers/types.rs) | Modified Task 2 | Add 5 `Operation` variants + `PostState`/`ExpectedReadBlock` structs + extend `OkPayload` with `post_state`. |
| [core/tests/conformance_kat_helpers/fixtures.rs](../../../core/tests/conformance_kat_helpers/fixtures.rs) | Modified Task 3 | Add `copy_vault_to_tempdir(src_name: &str) -> tempfile::TempDir` + `read_contact_card_bytes(vault_dir: &Path, user_uuid_hex: &str) -> Vec<u8>`. |
| [core/tests/conformance_kat_helpers/dispatch.rs](../../../core/tests/conformance_kat_helpers/dispatch.rs) | Modified Tasks 4 + 5 | Add `run_open_writable` + `run_save_block` + `run_share_block` + `run_trash_block` + `run_restore_block` + `assert_post_state` (write-op shape assertions) + `assert_read_block_records` (shared by v1's `assert_read_block_ok` and v2's post-save round-trip). |
| [core/tests/conformance_kat_helpers/errors.rs](../../../core/tests/conformance_kat_helpers/errors.rs) | NO CHANGE | All lifecycle error variants (`NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, `BlockUuidAlreadyLive`, `BlockNotInTrash`) are already mapped from v1. |
| [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs) | Modified Tasks 6 + 9 | Extend the replay loop with 5 new dispatch arms + tempdir-lifecycle tracking. Extend the `#[ignore]` generator to fill `save_block_insert_happy.expected.post_state.read_block.records`. |
| [ffi/secretary-ffi-uniffi/tests/swift/conformance.swift](../../../ffi/secretary-ffi-uniffi/tests/swift/conformance.swift) | Modified Task 11 | Add `_recursiveCopy` + `_readContactCardBytes` + dispatch arms for 5 new ops + post_state assertions. |
| [ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt](../../../ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt) | Modified Task 12 | Same as Swift; `Files.walkFileTree` + `Files.copy` recursive helpers. |
| [ROADMAP.md](../../../ROADMAP.md) | Modified Task 13 | Mark B.6 v2 done; bump per-binding conformance count `11/11 → 20/20`. |
| [NEXT_SESSION.md](../../../NEXT_SESSION.md) | Modified Task 15 | Live handoff with shipped commits + new next-chunk. |
| [docs/handoffs/2026-05-MM-…md](../../../docs/handoffs/) | Created Task 15 | Frozen snapshot of NEXT_SESSION.md per the standing `feedback_next_session_in_pr.md` rule. |

**No changes** under `core/src/`, `ffi/secretary-ffi-bridge/src/`, or `ffi/secretary-ffi-uniffi/src/` — v2 is replay-side-only per spec §2.

---

## Task 1: Pre-flight gauntlet baseline (verify session resumes cleanly)

**Files:** none modified.

This task is a sanity check — verify the gauntlet still passes on `design/b6-v2-lifecycle-conformance-kat` before touching anything.

- [ ] **Step 1: Confirm branch + clean tree**

```bash
cd /Users/hherb/src/secretary
git checkout design/b6-v2-lifecycle-conformance-kat
git status --short
git log --oneline -3
```

Expected: clean tree; `design/b6-v2-lifecycle-conformance-kat` checked out; the top three commits include the spec (`3d44e83`), the alice-UUID correction (`c5bb678`), and the plan (this commit, once committed).

- [ ] **Step 2: Run gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | tail -5
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all -- --check && echo "FMT OK"
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
```

Expected: all green. Cargo aggregate = 642 + 10. Swift + Kotlin conformance = 11/11.

If anything fails: stop. Do NOT proceed. Investigate the regression first — the baseline is the prerequisite for adding new vectors.

---

## Task 2: Extend `types.rs` — `Operation` enum + `PostState` struct + `OkPayload.post_state` field

**Files:**
- Modify: [core/tests/conformance_kat_helpers/types.rs](../../../core/tests/conformance_kat_helpers/types.rs)

Add the 5 new `Operation` variants and the `PostState` deserialization struct. Extend `OkPayload` with the optional `post_state` field. No replay logic yet — just deserialization shapes.

- [ ] **Step 1: Extend the `Operation` enum**

Edit [core/tests/conformance_kat_helpers/types.rs](../../../core/tests/conformance_kat_helpers/types.rs). Replace the existing enum:

```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    OpenVaultWithPassword,
    OpenVaultWithRecovery,
    ReadBlock,
}
```

…with:

```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    OpenVaultWithPassword,
    OpenVaultWithRecovery,
    ReadBlock,
    // v2 lifecycle ops — issue #59.
    OpenVaultWithPasswordWritable,
    SaveBlock,
    ShareBlock,
    TrashBlock,
    RestoreBlock,
}
```

- [ ] **Step 2: Add `PostState` + `ExpectedReadBlock` structs**

Append directly below the `ExpectedField` struct:

```rust
/// Post-call manifest-shape assertions for v2 write ops. All fields
/// optional; the replay engine asserts only what the vector pins.
#[derive(Debug, Deserialize, Default)]
pub struct PostState {
    /// Required on every v2 Ok post_state. Pins `manifest.block_count()`.
    #[serde(default)]
    pub block_count: Option<u64>,
    /// `"<hex>"` asserts `manifest.find_block(hex).is_some()` and
    /// hex-equals the returned summary's `block_uuid`. `null` asserts
    /// `is_none()`. Absent (`Option::None`) asserts nothing.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_null")]
    pub find_block_uuid_hex: Option<Option<String>>,
    /// share_block only. Pins `manifest.find_block(uuid).recipient_uuids.len()`.
    #[serde(default)]
    pub recipient_count: Option<u64>,
    /// save_block_*_happy only. Triggers a chained `read_block(uuid)`
    /// after the op and asserts records bit-for-bit.
    #[serde(default)]
    pub read_block: Option<ExpectedReadBlock>,
}

/// The round-trip read_block payload pinned post-save. Same `records`
/// shape that v1's `OkPayload::records` carries.
#[derive(Debug, Deserialize)]
pub struct ExpectedReadBlock {
    pub records: Vec<ExpectedRecord>,
}

/// Distinguishes "field absent" from "field present and null" so the
/// replay can tell `find_block_uuid_hex: null` (asserts is_none) from
/// `find_block_uuid_hex` omitted (asserts nothing).
fn deserialize_optional_string_or_null<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(Some(Option::<String>::deserialize(deserializer)?))
}
```

- [ ] **Step 3: Extend `OkPayload` with `post_state`**

In the same file, find:

```rust
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
```

…and append the new field directly before the closing brace:

```rust
    // v2 lifecycle ops:
    #[serde(default)]
    pub post_state: Option<PostState>,
```

- [ ] **Step 4: Verify it compiles**

```bash
cargo build --release --workspace --tests 2>&1 | tail -5
```

Expected: compiles cleanly. No new warnings. The new variants + `PostState` are dead-code from the replay's perspective right now — that's fine; later tasks wire them up.

- [ ] **Step 5: Commit**

```bash
git add core/tests/conformance_kat_helpers/types.rs
git commit -m "$(cat <<'EOF'
test(conformance-kat): types for B.6 v2 lifecycle ops

Add OpenVaultWithPasswordWritable / SaveBlock / ShareBlock / TrashBlock
/ RestoreBlock to the Operation enum plus PostState + ExpectedReadBlock
deserialization shapes for the new post_state expected-payload field.
Pure type additions; the replay loop still only dispatches v1 ops.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Extend `fixtures.rs` — `copy_vault_to_tempdir` + `read_contact_card_bytes`

**Files:**
- Modify: [core/tests/conformance_kat_helpers/fixtures.rs](../../../core/tests/conformance_kat_helpers/fixtures.rs)

Add two helpers: one for recursively copying a fixture vault to a tempdir (head of the writable chain), one for reading a contact-card file directly from a vault's `contacts/` directory (share_block target).

- [ ] **Step 1: Add the recursive-copy helper**

Append to [core/tests/conformance_kat_helpers/fixtures.rs](../../../core/tests/conformance_kat_helpers/fixtures.rs):

```rust
use std::path::Path;

/// Recursively copy `src` into `dst`. Mirrors the established pattern
/// in [`ffi/secretary-ffi-bridge/tests/save_block.rs`] (`copy_dir_recursive`).
fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap_or_else(|e| {
        panic!(
            "failed to create dst dir {}: {e}",
            dst.display()
        )
    });
    for entry in std::fs::read_dir(src)
        .unwrap_or_else(|e| panic!("failed to read src dir {}: {e}", src.display()))
    {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type().unwrap();
        if ft.is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap_or_else(|e| {
                panic!(
                    "failed to copy {} → {}: {e}",
                    from.display(),
                    to.display()
                )
            });
        }
    }
}

/// Copy `<fixtures_dir>/<vault_name>/` into a fresh `tempfile::TempDir`
/// and return the TempDir handle. The caller MUST hold the TempDir for
/// the duration of any subsequent operations against the copy — dropping
/// it removes the directory.
pub fn copy_vault_to_tempdir(vault_name: &str) -> tempfile::TempDir {
    let src = fixtures_dir().join(vault_name);
    let tmp = tempfile::tempdir().expect("tempdir for writable vault");
    copy_dir_recursive(&src, tmp.path());
    tmp
}
```

- [ ] **Step 2: Add the contact-card reader**

Append directly below:

```rust
/// Read the canonical-CBOR bytes of a contact card from a vault's
/// `contacts/` directory. `user_uuid_hex` is 32 lowercase hex chars
/// (no separators). The card filename on disk is the uuid in 8-4-4-4-12
/// hyphenated form (matches `tempfile::TempDir`'s contents copied from
/// `golden_vault_001/contacts/`).
pub fn read_contact_card_bytes(vault_dir: &Path, user_uuid_hex: &str) -> Vec<u8> {
    assert_eq!(
        user_uuid_hex.len(),
        32,
        "user_uuid_hex must be 32 chars, got {}",
        user_uuid_hex.len()
    );
    // Reshape "bf08a3300cd994b877e1a15baa28df35"
    //      → "bf08a330-0cd9-94b8-77e1-a15baa28df35.card"
    let h = user_uuid_hex;
    let hyphenated = format!(
        "{}-{}-{}-{}-{}.card",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    );
    let path = vault_dir.join("contacts").join(&hyphenated);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read contact card {}: {e}",
            path.display()
        )
    })
}
```

- [ ] **Step 3: Add `tempfile` to `core` dev-deps if not already present**

```bash
grep -n "^tempfile" core/Cargo.toml
```

Expected: `tempfile = "=3.27.0"` already present (the project uses an exact pin per CLAUDE.md's "Atomic-write contract" section). No edit needed. If for some reason it's not in `[dev-dependencies]`, add the same pin:

```toml
# tempfile is exact-pinned at the workspace level for atomicity reasons
# (see CLAUDE.md). Re-state the pin here for clarity at the dev-dep call
# site (conformance KAT writable vault copies).
tempfile = "=3.27.0"
```

- [ ] **Step 4: Verify it compiles**

```bash
cargo build --release --workspace --tests 2>&1 | tail -5
```

Expected: compiles cleanly.

- [ ] **Step 5: Commit**

```bash
git add core/tests/conformance_kat_helpers/fixtures.rs
git commit -m "$(cat <<'EOF'
test(conformance-kat): tempdir copy + contact-card reader

Add copy_vault_to_tempdir + read_contact_card_bytes helpers for the
B.6 v2 lifecycle replay. The first creates the writable vault copy
at the head of the v2 chain (mirrors fresh_writable_vault() in the
bridge integration tests); the second reads pre-bundled .card bytes
from a vault's contacts/ directory for share_block's new_recipient
input.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Add `run_*` dispatch helpers for the 5 new operations

**Files:**
- Modify: [core/tests/conformance_kat_helpers/dispatch.rs](../../../core/tests/conformance_kat_helpers/dispatch.rs)

Add five new run helpers — one per new operation. Each is a thin wrapper that pulls typed inputs from the JSON `serde_json::Value`, calls the bridge, and returns the standard `Result<_, FfiVaultError>` or the `BridgeOrSyntheticErr` wrapper if the op has a uniffi-layer length check (save_block / share_block / trash_block / restore_block all have one on `block_uuid` and `device_uuid`).

- [ ] **Step 1: Add input-parsing helpers (uuid + record list)**

Append to [core/tests/conformance_kat_helpers/dispatch.rs](../../../core/tests/conformance_kat_helpers/dispatch.rs):

```rust
use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_ffi_bridge::{BlockInput, FieldInput, FieldInputValue, RecordInput};

/// Parse a `*_hex` or `*_bytes_hex` input field into a `[u8; 16]`.
/// Returns `Err(BridgeOrSyntheticErr::Synthetic{"InvalidArgument"})`
/// for any non-16-byte input — matches the uniffi-layer
/// `uuid_from_vec` behavior so Swift/Kotlin get a real
/// VaultError.InvalidArgument while Rust gets the synthesized analogue.
fn uuid_from_inputs(
    inputs: &serde_json::Value,
    primary_field: &str,
    bytes_field: &str,
    label: &str,
) -> Result<[u8; 16], BridgeOrSyntheticErr> {
    let raw = inputs
        .get(primary_field)
        .or_else(|| inputs.get(bytes_field))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!("inputs need {primary_field} or {bytes_field} (vector dispatch error)")
        });
    let bytes = hex::decode(raw)
        .unwrap_or_else(|e| panic!("{label}: {primary_field} hex decode: {e}"));
    if bytes.len() != 16 {
        return Err(BridgeOrSyntheticErr::Synthetic {
            variant: "InvalidArgument",
            detail: format!("{label} must be exactly 16 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build a `BlockInput` from the JSON `inputs.records` array. Each
/// record has `record_uuid_hex` + `fields[]`; each field has `name`,
/// `type` (`"text"` or `"bytes"`), and a value (`value_utf8` or
/// `value_hex`). The bridge's `RecordInput` does not carry `record_type`
/// or `tags` (both default to empty inside `into_core_record`).
fn block_input_from_inputs(inputs: &serde_json::Value) -> BlockInput {
    let block_uuid_hex = inputs
        .get("block_uuid_hex")
        .and_then(|v| v.as_str())
        .expect("save_block inputs need block_uuid_hex");
    let block_uuid_bytes = hex::decode(block_uuid_hex).expect("block_uuid hex decode");
    assert_eq!(
        block_uuid_bytes.len(),
        16,
        "save_block.block_uuid must be 16 bytes (use save_block_invalid_input with block_uuid_bytes_hex for the wrong-length path)"
    );
    let mut block_uuid = [0u8; 16];
    block_uuid.copy_from_slice(&block_uuid_bytes);

    let block_name = inputs
        .get("block_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let records: Vec<RecordInput> = inputs
        .get("records")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|rec| {
                    let record_uuid_hex = rec
                        .get("record_uuid_hex")
                        .and_then(|v| v.as_str())
                        .expect("record needs record_uuid_hex");
                    let mut record_uuid = [0u8; 16];
                    record_uuid.copy_from_slice(
                        &hex::decode(record_uuid_hex).expect("record_uuid hex decode"),
                    );
                    let fields: Vec<FieldInput> = rec
                        .get("fields")
                        .and_then(|v| v.as_array())
                        .map(|fs| {
                            fs.iter()
                                .map(|f| {
                                    let name = f
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .expect("field needs name")
                                        .to_string();
                                    let ftype = f
                                        .get("type")
                                        .and_then(|v| v.as_str())
                                        .expect("field needs type");
                                    let value = match ftype {
                                        "text" => FieldInputValue::Text(SecretString::from(
                                            f.get("value_utf8")
                                                .and_then(|v| v.as_str())
                                                .expect("text field needs value_utf8")
                                                .to_string(),
                                        )),
                                        "bytes" => FieldInputValue::Bytes(SecretBytes::from(
                                            hex::decode(
                                                f.get("value_hex")
                                                    .and_then(|v| v.as_str())
                                                    .expect("bytes field needs value_hex"),
                                            )
                                            .expect("value_hex decode"),
                                        )),
                                        other => panic!("unknown field type {other}"),
                                    };
                                    FieldInput { name, value }
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    RecordInput { record_uuid, fields }
                })
                .collect()
        })
        .unwrap_or_default();

    BlockInput {
        block_uuid,
        block_name,
        records,
    }
}

/// Extract `now_ms` (required for all v2 write ops).
fn now_ms_from_inputs(inputs: &serde_json::Value) -> u64 {
    inputs
        .get("now_ms")
        .and_then(|v| v.as_u64())
        .expect("v2 write-op vector needs now_ms")
}
```

- [ ] **Step 2: Add `run_open_writable`**

Append:

```rust
use super::fixtures::copy_vault_to_tempdir;

/// Copies the named fixture vault to a fresh tempdir, opens the copy
/// with the resolved password, and returns the open output paired with
/// the TempDir handle. The caller is responsible for holding the TempDir
/// alongside the cached OpenVaultOutput so the dir survives until replay
/// completes.
pub fn run_open_writable(
    inputs: &serde_json::Value,
) -> Result<
    (
        secretary_ffi_bridge::vault::OpenVaultOutput,
        tempfile::TempDir,
    ),
    secretary_ffi_bridge::error::FfiVaultError,
> {
    let vault_name = inputs
        .get("vault_dir")
        .and_then(|v| v.as_str())
        .expect("open_vault_with_password_writable needs vault_dir (fixture-relative)");
    let tmp = copy_vault_to_tempdir(vault_name);
    let password = super::fixtures::resolve_password(inputs);
    let out = secretary_ffi_bridge::vault::open_vault_with_password(tmp.path(), &password)?;
    Ok((out, tmp))
}
```

- [ ] **Step 3: Add `run_save_block`**

Append:

```rust
/// Dispatch save_block. Returns the BridgeOrSyntheticErr wrapper so
/// non-16-byte block_uuid / device_uuid synthesize `InvalidArgument`
/// at the test layer (matching the uniffi-layer length checks; the
/// bridge's `[u8; 16]` parameters are type-bounded so the bridge itself
/// can't surface that variant).
pub fn run_save_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<(), BridgeOrSyntheticErr> {
    // Length-check device_uuid first (uniffi checks this before
    // building the BlockInput). block_uuid is checked inside
    // block_input_from_inputs via uuid_from_inputs if we go through
    // the bytes_hex path; the happy-path uses block_uuid_hex (validated
    // to 16 bytes by block_input_from_inputs).
    let device_uuid = uuid_from_inputs(
        inputs,
        "device_uuid_hex",
        "device_uuid_bytes_hex",
        "device_uuid",
    )?;
    // If the vector pinned block_uuid_bytes_hex (wrong-length test),
    // synthesize InvalidArgument before building the BlockInput.
    if let Some(raw) = inputs
        .get("block_uuid_bytes_hex")
        .and_then(|v| v.as_str())
    {
        let bytes = hex::decode(raw).expect("block_uuid_bytes_hex decode");
        if bytes.len() != 16 {
            return Err(BridgeOrSyntheticErr::Synthetic {
                variant: "InvalidArgument",
                detail: format!("input.block_uuid must be exactly 16 bytes, got {}", bytes.len()),
            });
        }
    }
    let input = block_input_from_inputs(inputs);
    let now_ms = now_ms_from_inputs(inputs);
    secretary_ffi_bridge::save_block(
        &cached.identity,
        &cached.manifest,
        input,
        device_uuid,
        now_ms,
    )
    .map_err(BridgeOrSyntheticErr::Bridge)
}
```

- [ ] **Step 4: Add `run_share_block`**

Append:

```rust
use super::fixtures::read_contact_card_bytes;

/// Dispatch share_block. Reads existing_recipient_cards from the
/// manifest (`owner_card_bytes()`) augmented by the
/// `existing_recipient_uuid_hexes` JSON array (each entry is a
/// 32-char user_uuid_hex of a contact card already in
/// <writable_vault>/contacts/). new_recipient is read from
/// `<writable_vault>/contacts/<new_recipient_user_uuid_hex>.card`.
pub fn run_share_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
    writable_vault_dir: &std::path::Path,
) -> Result<(), BridgeOrSyntheticErr> {
    let block_uuid = uuid_from_inputs(inputs, "block_uuid_hex", "block_uuid_bytes_hex", "block_uuid")?;
    let device_uuid = uuid_from_inputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex", "device_uuid")?;
    let now_ms = now_ms_from_inputs(inputs);

    // existing_recipient_cards: start with the manifest's owner card,
    // then append any extras listed in inputs.existing_recipient_uuid_hexes
    // (used for the duplicate-share case where the existing list must
    // include alice's card from the previous share_block_happy).
    let mut existing_recipient_cards: Vec<Vec<u8>> = Vec::new();
    let owner_bytes = cached
        .manifest
        .owner_card_bytes()
        .expect("owner_card_bytes I/O")
        .expect("owner_card_bytes returned None — manifest wiped?");
    existing_recipient_cards.push(owner_bytes);
    if let Some(extras) = inputs
        .get("existing_recipient_uuid_hexes")
        .and_then(|v| v.as_array())
    {
        for hex_val in extras {
            let h = hex_val
                .as_str()
                .expect("existing_recipient_uuid_hexes entry must be string");
            existing_recipient_cards.push(read_contact_card_bytes(writable_vault_dir, h));
        }
    }

    let new_recipient_hex = inputs
        .get("new_recipient_user_uuid_hex")
        .and_then(|v| v.as_str())
        .expect("share_block inputs need new_recipient_user_uuid_hex");
    let new_recipient = read_contact_card_bytes(writable_vault_dir, new_recipient_hex);

    secretary_ffi_bridge::share_block(
        &cached.identity,
        &cached.manifest,
        block_uuid,
        &existing_recipient_cards,
        &new_recipient,
        device_uuid,
        now_ms,
    )
    .map_err(BridgeOrSyntheticErr::Bridge)
}
```

- [ ] **Step 5: Add `run_trash_block` and `run_restore_block`**

Append:

```rust
pub fn run_trash_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<(), BridgeOrSyntheticErr> {
    let block_uuid = uuid_from_inputs(inputs, "block_uuid_hex", "block_uuid_bytes_hex", "block_uuid")?;
    let device_uuid = uuid_from_inputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex", "device_uuid")?;
    let now_ms = now_ms_from_inputs(inputs);
    secretary_ffi_bridge::trash_block(
        &cached.identity,
        &cached.manifest,
        block_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(BridgeOrSyntheticErr::Bridge)
}

pub fn run_restore_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<(), BridgeOrSyntheticErr> {
    let block_uuid = uuid_from_inputs(inputs, "block_uuid_hex", "block_uuid_bytes_hex", "block_uuid")?;
    let device_uuid = uuid_from_inputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex", "device_uuid")?;
    let now_ms = now_ms_from_inputs(inputs);
    secretary_ffi_bridge::restore_block(
        &cached.identity,
        &cached.manifest,
        block_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(BridgeOrSyntheticErr::Bridge)
}
```

- [ ] **Step 6: Verify compile**

```bash
cargo build --release --workspace --tests 2>&1 | tail -5
```

Expected: compiles cleanly. The new helpers are dead-code until Task 6 wires them into the replay loop — that's fine.

- [ ] **Step 7: Commit**

```bash
git add core/tests/conformance_kat_helpers/dispatch.rs
git commit -m "$(cat <<'EOF'
test(conformance-kat): run_* dispatch helpers for v2 ops

Add run_open_writable / run_save_block / run_share_block /
run_trash_block / run_restore_block plus shared input-parsing helpers
(uuid_from_inputs, block_input_from_inputs, now_ms_from_inputs).

Wrong-length block_uuid / device_uuid synthesize InvalidArgument at
the test layer (matching uniffi's namespace-layer length check; the
bridge's [u8; 16] params can't surface that variant).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Add post-state assertion helpers

**Files:**
- Modify: [core/tests/conformance_kat_helpers/dispatch.rs](../../../core/tests/conformance_kat_helpers/dispatch.rs)

Add `assert_post_state` which checks `block_count` + `find_block_uuid_hex` + `recipient_count` + the optional round-trip `read_block.records` against the post-call manifest state.

- [ ] **Step 1: Add `assert_post_state`**

Append to [core/tests/conformance_kat_helpers/dispatch.rs](../../../core/tests/conformance_kat_helpers/dispatch.rs):

```rust
use super::types::PostState;

/// Assert all pinned post_state fields against the post-call manifest.
/// `cached` is the same OpenVaultOutput the write op mutated in place
/// (the bridge's OpenVaultManifest uses interior mutability).
///
/// For `read_block` round-trip assertions, the engine calls
/// `secretary_ffi_bridge::record::read_block` against the cached
/// manifest using the pinned `find_block_uuid_hex` as the lookup key
/// (the same uuid the save op just inserted).
pub fn assert_post_state(
    label: &str,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
    pinned: &PostState,
) {
    if let Some(count) = pinned.block_count {
        assert_eq!(
            cached.manifest.block_count(),
            count,
            "{label}: post_state.block_count mismatch"
        );
    }
    let mut round_trip_uuid: Option<[u8; 16]> = None;
    if let Some(maybe_hex) = &pinned.find_block_uuid_hex {
        match maybe_hex {
            None => {
                // pinned as JSON null → assert absent.
                // The pin doesn't carry which uuid to check, so the
                // calling vector MUST also pin the uuid via the vector's
                // own `inputs.block_uuid_hex`. We re-extract it from the
                // most recently dispatched op via the cached manifest's
                // block list (trash_block sets find_block to null for
                // the just-trashed uuid; this assertion catches a
                // regression where the bridge keeps it findable).
                // For null assertion we don't need the uuid — we just
                // check no block currently lives under any of the
                // post_state.find_block_uuid_hex inputs. But since this
                // is a singleton field, the trash/restore vectors
                // *explicitly* re-read the uuid from inputs. Implement
                // that here:
                panic!(
                    "{label}: post_state.find_block_uuid_hex=null requires the calling vector \
                     to supply the uuid via inputs.block_uuid_hex; the engine asserts this in \
                     the dispatch arm, not here."
                );
            }
            Some(hex_str) => {
                let bytes = hex::decode(hex_str)
                    .unwrap_or_else(|e| panic!("{label}: find_block_uuid_hex decode: {e}"));
                assert_eq!(bytes.len(), 16, "{label}: find_block_uuid_hex must be 16 bytes");
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&bytes);
                let summary = cached.manifest.find_block(&uuid).unwrap_or_else(|| {
                    panic!(
                        "{label}: post_state.find_block_uuid_hex={hex_str} not in manifest"
                    )
                });
                assert_eq!(
                    hex::encode(summary.block_uuid),
                    hex_str.to_lowercase(),
                    "{label}: find_block returned wrong uuid"
                );
                round_trip_uuid = Some(uuid);
            }
        }
    }
    if let Some(rc) = pinned.recipient_count {
        let uuid = round_trip_uuid.expect(
            "post_state.recipient_count requires post_state.find_block_uuid_hex to be set so \
             the engine knows which block to inspect",
        );
        let summary = cached
            .manifest
            .find_block(&uuid)
            .expect("recipient_count: block must be findable");
        assert_eq!(
            summary.recipient_uuids.len() as u64,
            rc,
            "{label}: post_state.recipient_count mismatch"
        );
    }
    if let Some(read_pin) = &pinned.read_block {
        let uuid = round_trip_uuid.expect(
            "post_state.read_block requires post_state.find_block_uuid_hex to be set",
        );
        let output = secretary_ffi_bridge::record::read_block(
            &cached.identity,
            &cached.manifest,
            &uuid,
        )
        .unwrap_or_else(|e| panic!("{label}: round-trip read_block failed: {e:?}"));
        assert_read_block_records(label, &output, &read_pin.records);
    }
}
```

- [ ] **Step 2: Factor `assert_read_block_records` out of `assert_read_block_ok`**

The v1 `assert_read_block_ok` checks records against an `OkPayload`. The new helper needs the same per-record check but takes a `&[ExpectedRecord]` directly so the v2 post_state can reuse it.

Find the existing `assert_read_block_ok` in [core/tests/conformance_kat_helpers/dispatch.rs](../../../core/tests/conformance_kat_helpers/dispatch.rs):

```rust
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
        // ... 60 lines of per-record / per-field assertions ...
    }
}
```

Refactor it: extract the body after the early-return into a new free function:

```rust
use super::types::ExpectedRecord;

pub fn assert_read_block_records(
    label: &str,
    output: &secretary_ffi_bridge::record::BlockReadOutput,
    records: &[ExpectedRecord],
) {
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
    }
}
```

Then simplify `assert_read_block_ok` to delegate:

```rust
pub fn assert_read_block_ok(
    label: &str,
    output: &secretary_ffi_bridge::record::BlockReadOutput,
    expected: &OkPayload,
) {
    let Some(records) = &expected.records else {
        return;
    };
    assert_read_block_records(label, output, records);
}
```

- [ ] **Step 3: Verify compile + v1 tests still pass**

```bash
cargo build --release --workspace --tests 2>&1 | tail -5
cargo test --release --workspace replay_conformance_kat 2>&1 | tail -5
```

Expected: compiles cleanly; `replay_conformance_kat ... ok` (11/11 v1 vectors unchanged).

- [ ] **Step 4: Commit**

```bash
git add core/tests/conformance_kat_helpers/dispatch.rs
git commit -m "$(cat <<'EOF'
test(conformance-kat): assert_post_state for v2 + factor records check

Add assert_post_state covering block_count, find_block_uuid_hex
(Some(hex) asserts presence + uuid match; None requires the caller to
pre-extract the uuid from inputs.block_uuid_hex), recipient_count
(read from BlockSummary.recipient_uuids.len()), and round-trip
read_block records.

Factor assert_read_block_records out of assert_read_block_ok so the
new post_state.read_block assertion shares the per-field byte-equal
check.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Extend `conformance_kat.rs` replay loop with the 5 new dispatch arms

**Files:**
- Modify: [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs)

The replay loop's `match (&vector.operation, &vector.after)` block needs five new arms. The tempdir handles produced by `run_open_writable` must be held for the full replay duration in a parallel `Vec<tempfile::TempDir>`.

- [ ] **Step 1: Add tempdir vec + dispatch arms**

Open [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs). Find the existing `let mut cache: HashMap<…> = HashMap::new();` line. Right after it, add:

```rust
let mut tempdirs: Vec<tempfile::TempDir> = Vec::new();
let mut writable_vault_dirs: HashMap<String, std::path::PathBuf> = HashMap::new();
```

The `tempdirs` vec keeps every writable-vault TempDir alive until replay exits. The `writable_vault_dirs` map records each writable-open vector's tempdir path so chained `share_block` calls can read contact cards from it.

- [ ] **Step 2: Add `run_open_writable` dispatch arm**

In the existing `match (&vector.operation, &vector.after)` block, after the `(Operation::OpenVaultWithRecovery, None) => { ... }` arm, add:

```rust
(Operation::OpenVaultWithPasswordWritable, None) => {
    let result = run_open_writable(&vector.inputs);
    match (&vector.expected, result) {
        (Expected::Ok(payload), Ok((out, tmp))) => {
            assert_open_ok(label, &out, payload);
            writable_vault_dirs.insert(label.clone(), tmp.path().to_path_buf());
            tempdirs.push(tmp);
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
```

- [ ] **Step 3: Add `run_save_block` dispatch arm**

After the `OpenVaultWithPasswordWritable` arm, add:

```rust
(Operation::SaveBlock, Some(predecessor)) => {
    let cached = cache
        .get(predecessor)
        .unwrap_or_else(|| panic!("{label}: predecessor '{predecessor}' missing from cache"));
    let result = run_save_block(&vector.inputs, cached);
    match (&vector.expected, result) {
        (Expected::Ok(payload), Ok(())) => {
            if let Some(ps) = &payload.post_state {
                assert_post_state(label, cached, ps);
            }
        }
        (Expected::Err { .. }, Err(e)) => {
            let v = read_block_err_variant(&e); // works for any BridgeOrSyntheticErr
            let d = read_block_err_detail(&e);
            assert_err(label, v, d, &vector.expected);
        }
        (Expected::Ok(_), Err(e)) => {
            panic!("{label}: expected Ok, got Err {}", read_block_err_variant(&e))
        }
        (Expected::Err { .. }, Ok(())) => panic!("{label}: expected Err, got Ok"),
    }
}
```

- [ ] **Step 4: Add `run_share_block` dispatch arm**

```rust
(Operation::ShareBlock, Some(predecessor)) => {
    // share_block needs the writable vault dir for read_contact_card_bytes.
    // Trace `after` chain back to the open_writable vector that holds the dir.
    let writable_dir = find_writable_dir(predecessor, &writable_vault_dirs, &kat.vectors)
        .unwrap_or_else(|| {
            panic!("{label}: cannot find writable vault dir along after-chain from {predecessor}")
        });
    let cached = cache
        .get(predecessor)
        .unwrap_or_else(|| panic!("{label}: predecessor '{predecessor}' missing from cache"));
    let result = run_share_block(&vector.inputs, cached, &writable_dir);
    match (&vector.expected, result) {
        (Expected::Ok(payload), Ok(())) => {
            if let Some(ps) = &payload.post_state {
                assert_post_state(label, cached, ps);
            }
        }
        (Expected::Err { .. }, Err(e)) => {
            let v = read_block_err_variant(&e);
            let d = read_block_err_detail(&e);
            assert_err(label, v, d, &vector.expected);
        }
        (Expected::Ok(_), Err(e)) => {
            panic!("{label}: expected Ok, got Err {}", read_block_err_variant(&e))
        }
        (Expected::Err { .. }, Ok(())) => panic!("{label}: expected Err, got Ok"),
    }
}
```

- [ ] **Step 5: Add `find_writable_dir` helper**

At the bottom of `conformance_kat.rs` (after `replay_conformance_kat` but inside the same file), add:

```rust
/// Walk the `after:` chain from `start` back to the first vector whose
/// name appears in `writable_vault_dirs`. Returns that vector's tempdir
/// path. Returns `None` if no writable-open vector is upstream — which
/// is a vector-authoring error (every share_block needs a writable
/// vault upstream for the contact-card read).
fn find_writable_dir(
    start: &str,
    writable_vault_dirs: &std::collections::HashMap<String, std::path::PathBuf>,
    vectors: &[conformance_kat_helpers::types::Vector],
) -> Option<std::path::PathBuf> {
    let mut current = start.to_string();
    loop {
        if let Some(dir) = writable_vault_dirs.get(&current) {
            return Some(dir.clone());
        }
        let parent = vectors
            .iter()
            .find(|v| v.name == current)
            .and_then(|v| v.after.clone());
        match parent {
            Some(p) => current = p,
            None => return None,
        }
    }
}
```

- [ ] **Step 6: Add `run_trash_block` + `run_restore_block` arms**

```rust
(Operation::TrashBlock, Some(predecessor)) => {
    let cached = cache
        .get(predecessor)
        .unwrap_or_else(|| panic!("{label}: predecessor '{predecessor}' missing from cache"));
    let result = run_trash_block(&vector.inputs, cached);
    handle_write_op_result(label, &vector.expected, result, cached);
}
(Operation::RestoreBlock, Some(predecessor)) => {
    let cached = cache
        .get(predecessor)
        .unwrap_or_else(|| panic!("{label}: predecessor '{predecessor}' missing from cache"));
    let result = run_restore_block(&vector.inputs, cached);
    handle_write_op_result(label, &vector.expected, result, cached);
}
```

Then add the shared helper at the bottom of the file:

```rust
fn handle_write_op_result(
    label: &str,
    expected: &conformance_kat_helpers::types::Expected,
    result: Result<(), conformance_kat_helpers::types::BridgeOrSyntheticErr>,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) {
    use conformance_kat_helpers::types::Expected;
    match (expected, result) {
        (Expected::Ok(payload), Ok(())) => {
            if let Some(ps) = &payload.post_state {
                conformance_kat_helpers::dispatch::assert_post_state(label, cached, ps);
            }
        }
        (Expected::Err { .. }, Err(e)) => {
            let v = conformance_kat_helpers::errors::read_block_err_variant(&e);
            let d = conformance_kat_helpers::errors::read_block_err_detail(&e);
            conformance_kat_helpers::errors::assert_err(label, v, d, expected);
        }
        (Expected::Ok(_), Err(e)) => panic!(
            "{label}: expected Ok, got Err {}",
            conformance_kat_helpers::errors::read_block_err_variant(&e)
        ),
        (Expected::Err { .. }, Ok(())) => panic!("{label}: expected Err, got Ok"),
    }
}
```

- [ ] **Step 7: Add exhaustiveness-error arms**

The compiler will now complain about non-exhaustive match. Add catch-all arms below the existing `OpenVaultWithPassword | OpenVaultWithRecovery, Some(_)` arm:

```rust
(Operation::OpenVaultWithPasswordWritable, Some(_)) => {
    panic!("{label}: open_vault_with_password_writable must not specify `after:`")
}
(Operation::SaveBlock | Operation::ShareBlock
 | Operation::TrashBlock | Operation::RestoreBlock, None) => {
    panic!("{label}: write-op vectors must specify `after:`")
}
```

- [ ] **Step 8: Update the `use` block**

At the top of the file, find the existing dispatch + errors imports. Extend them:

```rust
use conformance_kat_helpers::dispatch::{
    assert_open_ok, assert_post_state, assert_read_block_ok, run_open_password,
    run_open_recovery, run_open_writable, run_read_block, run_restore_block, run_save_block,
    run_share_block, run_trash_block,
};
use conformance_kat_helpers::errors::{
    assert_err, read_block_err_detail, read_block_err_variant, variant_name_vault,
    vault_error_detail,
};
use conformance_kat_helpers::types::{Expected, Kat, Operation};
```

- [ ] **Step 9: Verify compile + v1 still passes**

```bash
cargo build --release --workspace --tests 2>&1 | tail -5
cargo test --release --workspace replay_conformance_kat 2>&1 | tail -5
```

Expected: compiles cleanly. `replay_conformance_kat ... ok` (still 11/11 v1 vectors — v2 vectors not yet added).

- [ ] **Step 10: Commit**

```bash
git add core/tests/conformance_kat.rs
git commit -m "$(cat <<'EOF'
test(conformance-kat): replay loop dispatch for v2 lifecycle ops

Wire run_open_writable / run_save_block / run_share_block /
run_trash_block / run_restore_block into the replay loop. Tempdir
handles produced by run_open_writable are held in a Vec<TempDir>
alongside the cache for the replay duration. A helper find_writable_dir
walks the `after:` chain so share_block vectors can locate the writable
vault's contact-card directory.

v1 replay still passes 11/11 — v2 vectors not yet added to the KAT.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Append 9 v2 vectors to `conformance_kat.json` (with `<filled-in-by-generator>` placeholder)

**Files:**
- Modify: [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json)

Bump `version: 1 → 2`. Update the `comment` field to mention v2 scope. Append the 9 v2 vectors to the existing 11-vector `vectors` array.

- [ ] **Step 1: Bump version + update comment**

Edit [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json). Change line 2:

```json
  "version": 1,
```

to:

```json
  "version": 2,
```

Change line 3 (the comment) from the existing v1 string to:

```json
  "comment": "Cross-language FFI conformance KAT. v1 (read-only path: open/recovery/read_block) frozen by docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md (PR #58). v2 (lifecycle path: save/share/trash/restore) added by docs/superpowers/specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md (issue #59). Generated by `cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture`; intentional protocol changes regenerate, diffs are human-reviewed. Verified by core/tests/conformance_kat.rs::replay_conformance_kat (every cargo test) plus the Swift + Kotlin host runners in ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/.",
```

- [ ] **Step 2: Append the 9 v2 vectors**

Find the closing `]` of the `vectors` array (around line 173 of the v1 file). Insert the following 9 vectors directly before that closing bracket, after the final v1 vector's closing `}`. Don't forget to add a trailing comma to the previous v1 vector. The JSON is reproduced in full below:

```json
    ,
    {
      "name": "open_writable_happy",
      "description": "v2 head of the writable chain. Copies golden_vault_001/ to a tempdir, opens the copy with the pinned password. Cached output is mutated by chained write vectors; tempdir is held by the replay engine for the full run.",
      "operation": "open_vault_with_password_writable",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "password_source": "golden_vault_001_inputs.json:password"
      },
      "expected": {
        "kind": "ok",
        "display_name": "Owner",
        "block_count": 1,
        "block_uuid_hex": "112233445566778899aabbccddeeff00"
      }
    },
    {
      "name": "save_block_insert_happy",
      "description": "Inserts block 0xAB*16 with one note record into the writable vault. Asserts block_count goes 1→2, find_block returns the new uuid, and read_block(new_uuid) round-trips the input record (records placeholder filled by the generator).",
      "operation": "save_block",
      "after": "open_writable_happy",
      "inputs": {
        "block_uuid_hex": "abababababababababababababababab",
        "block_name": "Notes",
        "device_uuid_hex": "07070707070707070707070707070707",
        "now_ms": 1715000000000,
        "records": [
          {
            "record_uuid_hex": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "fields": [
              {
                "name": "title",
                "type": "text",
                "value_utf8": "wifi password"
              }
            ]
          }
        ]
      },
      "expected": {
        "kind": "ok",
        "post_state": {
          "block_count": 2,
          "find_block_uuid_hex": "abababababababababababababababab",
          "read_block": {
            "records": "<filled-in-by-generator>"
          }
        }
      }
    },
    {
      "name": "save_block_invalid_input",
      "description": "save_block with a 1-byte device_uuid (must be 16). Synthesized InvalidArgument at the Rust replay layer; real InvalidArgument at the uniffi namespace layer on Swift+Kotlin. Does not mutate cache.",
      "operation": "save_block",
      "after": "open_writable_happy",
      "inputs": {
        "block_uuid_hex": "abababababababababababababababab",
        "block_name": "x",
        "device_uuid_bytes_hex": "07",
        "now_ms": 1715000000000,
        "records": []
      },
      "expected": {
        "kind": "err",
        "variant": "InvalidArgument"
      }
    },
    {
      "name": "share_block_happy",
      "description": "Shares the new block (saved by the previous vector) with alice (user_uuid from golden_vault_001/contacts/). Asserts recipient_count goes 1→2.",
      "operation": "share_block",
      "after": "save_block_insert_happy",
      "inputs": {
        "block_uuid_hex": "abababababababababababababababab",
        "new_recipient_user_uuid_hex": "7921b6ed8fa8cff2baf61a43f3a66a9f",
        "device_uuid_hex": "07070707070707070707070707070707",
        "now_ms": 1715000001000
      },
      "expected": {
        "kind": "ok",
        "post_state": {
          "block_count": 2,
          "find_block_uuid_hex": "abababababababababababababababab",
          "recipient_count": 2
        }
      }
    },
    {
      "name": "share_block_recipient_already_present",
      "description": "Re-shares the same block with alice (the recipient just added). The replay engine includes alice's card in existing_recipient_uuid_hexes so existing_recipient_cards covers every recipient currently on the block.",
      "operation": "share_block",
      "after": "share_block_happy",
      "inputs": {
        "block_uuid_hex": "abababababababababababababababab",
        "new_recipient_user_uuid_hex": "7921b6ed8fa8cff2baf61a43f3a66a9f",
        "existing_recipient_uuid_hexes": ["7921b6ed8fa8cff2baf61a43f3a66a9f"],
        "device_uuid_hex": "07070707070707070707070707070707",
        "now_ms": 1715000002000
      },
      "expected": {
        "kind": "err",
        "variant": "RecipientAlreadyPresent"
      }
    },
    {
      "name": "trash_block_happy",
      "description": "Trashes the new block. Asserts block_count goes 2→1 and find_block returns None for the trashed uuid.",
      "operation": "trash_block",
      "after": "share_block_recipient_already_present",
      "inputs": {
        "block_uuid_hex": "abababababababababababababababab",
        "device_uuid_hex": "07070707070707070707070707070707",
        "now_ms": 1715000003000
      },
      "expected": {
        "kind": "ok",
        "post_state": {
          "block_count": 1
        }
      }
    },
    {
      "name": "trash_block_unknown_uuid",
      "description": "Trashes uuid 0x00*16 which was never live in the manifest. Bridge returns BlockNotFound.",
      "operation": "trash_block",
      "after": "trash_block_happy",
      "inputs": {
        "block_uuid_hex": "00000000000000000000000000000000",
        "device_uuid_hex": "07070707070707070707070707070707",
        "now_ms": 1715000004000
      },
      "expected": {
        "kind": "err",
        "variant": "BlockNotFound"
      }
    },
    {
      "name": "restore_block_happy",
      "description": "Restores the just-trashed block. Asserts block_count goes 1→2 and find_block returns the restored uuid again.",
      "operation": "restore_block",
      "after": "trash_block_unknown_uuid",
      "inputs": {
        "block_uuid_hex": "abababababababababababababababab",
        "device_uuid_hex": "07070707070707070707070707070707",
        "now_ms": 1715000005000
      },
      "expected": {
        "kind": "ok",
        "post_state": {
          "block_count": 2,
          "find_block_uuid_hex": "abababababababababababababababab"
        }
      }
    },
    {
      "name": "restore_block_not_in_trash",
      "description": "Re-restores the just-restored (now live) block. Bridge returns BlockNotInTrash.",
      "operation": "restore_block",
      "after": "restore_block_happy",
      "inputs": {
        "block_uuid_hex": "abababababababababababababababab",
        "device_uuid_hex": "07070707070707070707070707070707",
        "now_ms": 1715000006000
      },
      "expected": {
        "kind": "err",
        "variant": "BlockNotInTrash"
      }
    }
```

(Note: the leading `,` on the first line above closes the preceding v1 vector's array element.)

- [ ] **Step 3: Validate JSON syntax**

```bash
uv run python3 -c "import json; json.load(open('core/tests/data/conformance_kat.json'))" && echo OK
```

Expected: `OK`. Fix any JSON parse errors (stdlib `json` is sufficient; no extra packages needed).

- [ ] **Step 4: Do NOT commit yet**

Don't commit yet. Task 8 will run the replay against this placeholder-bearing file to demonstrate the red-checkpoint failure.

---

## Task 8: Verify replay fails on placeholder (red checkpoint)

**Files:** none modified.

This is the TDD red checkpoint. The replay should fail on `save_block_insert_happy` because `"records": "<filled-in-by-generator>"` is a string, not an array, and the deserializer rejects it.

- [ ] **Step 1: Run replay**

```bash
cargo test --release --workspace replay_conformance_kat 2>&1 | tail -10
```

Expected: FAIL. The failure message will be a serde deserialization error around `save_block_insert_happy.expected.post_state.read_block.records` — something like `invalid type: string "<filled-in-by-generator>", expected a sequence`. This is the expected red state.

- [ ] **Step 2: Confirm the failure shape**

If the failure is anything OTHER than a serde error on the placeholder string (e.g. a uniffi error or a panic in `find_writable_dir`), stop and investigate — that means an earlier task left a regression.

---

## Task 9: Extend the `#[ignore]` generator to fill the placeholder

**Files:**
- Modify: [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs)

Extend `generate_conformance_kat` to also dispatch the v2 vectors against `golden_vault_001` (in a tempdir) and rewrite `save_block_insert_happy.expected.post_state.read_block.records` with the actual round-trip output.

- [ ] **Step 1: Locate the existing generator**

Open [core/tests/conformance_kat.rs](../../../core/tests/conformance_kat.rs). Find the `#[test] #[ignore] fn generate_conformance_kat() { ... }` block. Read it end-to-end (it's about 80 lines and shows the v1 pattern: open vault, dispatch `read_block_happy`, capture records, edit the JSON, rewrite the file).

- [ ] **Step 2: Add a v2 generator block**

After the v1 generator's `read_block_happy` records-fill block (just before the final `fs::write(kat_path(), …)` call), add:

```rust
    // v2 lifecycle generator: run save_block_insert_happy against a
    // writable copy of golden_vault_001 and capture the round-trip
    // read_block records. Only this one vector has a generator-filled
    // placeholder; the other 8 v2 vectors are fully hand-pinned.
    {
        // Open writable copy. Mirrors run_open_writable.
        let tmp = conformance_kat_helpers::fixtures::copy_vault_to_tempdir("golden_vault_001");
        let password = conformance_kat_helpers::fixtures::resolve_source(
            "golden_vault_001_inputs.json:password",
        );
        let out = secretary_ffi_bridge::vault::open_vault_with_password(tmp.path(), &password)
            .expect("generator: open writable vault_001");

        // Dispatch save_block_insert_happy. Hardcoded inputs match the
        // vector pinned in conformance_kat.json. Keeping these in sync
        // is a manual review responsibility — the generator regen diff
        // catches drift between the two.
        use secretary_core::crypto::secret::SecretString;
        use secretary_ffi_bridge::{BlockInput, FieldInput, FieldInputValue, RecordInput};
        let input = BlockInput {
            block_uuid: [0xABu8; 16],
            block_name: "Notes".to_string(),
            records: vec![RecordInput {
                record_uuid: [0xCDu8; 16],
                fields: vec![FieldInput {
                    name: "title".to_string(),
                    value: FieldInputValue::Text(SecretString::from("wifi password")),
                }],
            }],
        };
        secretary_ffi_bridge::save_block(
            &out.identity,
            &out.manifest,
            input,
            [0x07u8; 16],
            1_715_000_000_000,
        )
        .expect("generator: save_block_insert_happy");

        // Round-trip read.
        let read_out = secretary_ffi_bridge::record::read_block(
            &out.identity,
            &out.manifest,
            &[0xABu8; 16],
        )
        .expect("generator: round-trip read_block");

        // Build the JSON array for records.
        let records_json: Vec<serde_json::Value> = (0..read_out.record_count())
            .map(|i| {
                let rec = read_out.record_at(i).unwrap();
                let fields: Vec<serde_json::Value> = (0..rec.field_count())
                    .map(|j| {
                        let f = rec.field_at(j).unwrap();
                        let (ty, value_field, value_val): (&str, &str, serde_json::Value) =
                            if f.is_text() {
                                let s = f.expose_text().unwrap();
                                ("text", "value_utf8", serde_json::Value::String(s))
                            } else {
                                let b = f.expose_bytes().unwrap();
                                ("bytes", "value_hex", serde_json::Value::String(hex::encode(b)))
                            };
                        serde_json::json!({
                            "name": f.name(),
                            "type": ty,
                            value_field: value_val,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "record_uuid_hex": hex::encode(rec.record_uuid()),
                    "record_type": rec.record_type(),
                    "tags": rec.tags(),
                    "fields": fields,
                })
            })
            .collect();

        // Patch the JSON document loaded earlier (the variable is `doc`
        // in the v1 generator code — match the existing local name).
        let v2_target = doc["vectors"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|v| v["name"] == "save_block_insert_happy")
            .expect("save_block_insert_happy must be in conformance_kat.json before regen");
        v2_target["expected"]["post_state"]["read_block"]["records"] =
            serde_json::Value::Array(records_json);

        // Drop the tempdir explicitly to free disk space before the
        // serializer writes; not strictly necessary (TempDir drops at
        // end-of-scope) but explicit is clearer for a long generator fn.
        drop(out.identity);
        drop(out.manifest);
        drop(tmp);
    }
```

- [ ] **Step 3: Verify the generator compiles**

```bash
cargo build --release --workspace --tests 2>&1 | tail -5
```

Expected: compiles cleanly. The generator is `#[ignore]`-gated so a normal `cargo test` doesn't run it.

- [ ] **Step 4: Do NOT run the generator yet**

Task 10 runs it. Don't commit yet.

---

## Task 10: Run the generator, commit populated JSON, verify replay passes

**Files:**
- Modify: [core/tests/data/conformance_kat.json](../../../core/tests/data/conformance_kat.json) (via generator)

- [ ] **Step 1: Run the generator**

```bash
cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture 2>&1 | tail -10
```

Expected: PASS. The generator writes the populated JSON.

- [ ] **Step 2: Inspect the diff**

```bash
git diff core/tests/data/conformance_kat.json | head -60
```

The diff MUST scope to:

- `save_block_insert_happy.expected.post_state.read_block.records` (the `"<filled-in-by-generator>"` string replaced with a populated array).
- Possibly trailing-newline / whitespace differences from `serde_json::to_string_pretty`'s output.

If the diff touches ANY other vector — that's a regression. Investigate before committing.

- [ ] **Step 3: Run replay to verify it now passes**

```bash
cargo test --release --workspace replay_conformance_kat 2>&1 | tail -5
```

Expected: `replay_conformance_kat ... ok`. All 20 vectors now pass.

- [ ] **Step 4: Commit the v2 vectors + generator + replay extensions all together**

```bash
git add core/tests/data/conformance_kat.json core/tests/conformance_kat.rs
git commit -m "$(cat <<'EOF'
test(conformance-kat): add 9 v2 lifecycle vectors to KAT

Bumps version 1 → 2. Appends 9 vectors: open_writable_happy at the
head, then save_block (happy + invalid_input), share_block (happy +
recipient_already_present), trash_block (happy + unknown_uuid),
restore_block (happy + not_in_trash). All write vectors chain via
after: to mutate the same writable vault copy.

Extends the #[ignore] generator to fill
save_block_insert_happy.expected.post_state.read_block.records with
the round-trip read of the newly-saved block. The diff on regen scopes
to this one field; everything else is hand-pinned.

Rust replay: 20/20 vectors now pass.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Run the full Rust gauntlet to confirm no regression elsewhere**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | tail -3
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check && echo FMT_OK
```

Expected: 642 + 10 (unchanged — one `#[test]` runs all 20 vectors internally), clippy clean, fmt OK.

---

## Task 11: Extend Swift conformance runner with v2 dispatch

**Files:**
- Modify: [ffi/secretary-ffi-uniffi/tests/swift/conformance.swift](../../../ffi/secretary-ffi-uniffi/tests/swift/conformance.swift)

Add Swift mirror of Tasks 2–6: extend dispatch + recursive-copy + contact-card reader. The Swift run_conformance.sh and run.sh share build infrastructure, so no shell-script changes are needed.

- [ ] **Step 1: Read the existing Swift conformance runner end-to-end**

```bash
wc -l ffi/secretary-ffi-uniffi/tests/swift/conformance.swift
```

Read the file in full. Identify the existing v1 dispatch loop pattern, the `caseName(_ error:)` helper for `VaultError`, and the cache structure.

- [ ] **Step 2: Add the recursive-copy helper**

Append (or insert near other helpers) — based on the precedent at [tests/swift/main.swift:530-548](../../../ffi/secretary-ffi-uniffi/tests/swift/main.swift#L530-L548):

```swift
func _recursiveCopy(_ from: URL, _ to: URL) throws {
    try FileManager.default.createDirectory(at: to, withIntermediateDirectories: true)
    for entry in try FileManager.default.contentsOfDirectory(at: from, includingPropertiesForKeys: nil) {
        var isDir: ObjCBool = false
        FileManager.default.fileExists(atPath: entry.path, isDirectory: &isDir)
        let dest = to.appendingPathComponent(entry.lastPathComponent)
        if isDir.boolValue {
            try _recursiveCopy(entry, dest)
        } else {
            try FileManager.default.copyItem(at: entry, to: dest)
        }
    }
}

func _readContactCardBytes(_ vaultDir: URL, _ userUuidHex: String) throws -> Data {
    precondition(userUuidHex.count == 32, "userUuidHex must be 32 chars")
    let h = userUuidHex
    let hyphenated = "\(h.prefix(8))-\(h.dropFirst(8).prefix(4))-\(h.dropFirst(12).prefix(4))-\(h.dropFirst(16).prefix(4))-\(h.dropFirst(20)).card"
    let path = vaultDir.appendingPathComponent("contacts").appendingPathComponent(hyphenated)
    return try Data(contentsOf: path)
}
```

- [ ] **Step 3: Add tempdir tracking**

Find the existing cache declaration (something like `var cache: [String: (UnlockedIdentity, OpenVaultManifest)] = [:]`). Right after, add:

```swift
var tempdirs: [URL] = []
var writableVaultDirs: [String: URL] = [:]
defer {
    for url in tempdirs {
        try? FileManager.default.removeItem(at: url)
    }
}
```

- [ ] **Step 4: Extend the dispatch switch**

The existing dispatch switch on the operation discriminator gains five new cases. The patterns mirror the Rust replay arms:

```swift
case "open_vault_with_password_writable":
    let vaultName = (vector["inputs"] as! [String: Any])["vault_dir"] as! String
    let src = URL(fileURLWithPath: vaultDir).appendingPathComponent(vaultName)
    let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("secretary_conf_v2_\(UUID().uuidString)")
    try _recursiveCopy(src, tmp)
    tempdirs.append(tmp)
    writableVaultDirs[label] = tmp
    let password = try _resolveSource(inputs)  // existing helper from v1
    let folderPath = Data(tmp.path.utf8)
    let out = try openVaultWithPassword(folderPath: folderPath, password: password)
    cache[label] = (out.identity, out.manifest)
    try _assertOpenOk(label, out: out, expectedPayload: expected)

case "save_block":
    let predecessor = vector["after"] as! String
    let (id, manifest) = cache[predecessor]!
    let input = try _blockInputFromInputs(inputs)
    let deviceUuid = try _uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex")
    let nowMs = inputs["now_ms"] as! UInt64
    do {
        try saveBlock(identity: id, manifest: manifest, input: input, deviceUuid: deviceUuid, nowMs: nowMs)
        if case .ok = expectedKind(expected) {
            try _assertPostState(label, manifest: manifest, identity: id, expected: expected)
        } else {
            failures.append("\(label): expected Err, got Ok"); continue
        }
    } catch let e as VaultError {
        try _assertErr(label, caseName: caseName(e), detail: detail(e), expected: expected)
    }

case "share_block":
    let predecessor = vector["after"] as! String
    let (id, manifest) = cache[predecessor]!
    let writableDir = _findWritableDir(predecessor, writableVaultDirs: writableVaultDirs, vectors: kat["vectors"] as! [[String: Any]])
    let blockUuid = try _uuidFromInputs(inputs, primary: "block_uuid_hex", bytes: "block_uuid_bytes_hex")
    let deviceUuid = try _uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex")
    let nowMs = inputs["now_ms"] as! UInt64
    let newRecipientHex = inputs["new_recipient_user_uuid_hex"] as! String
    let newRecipient = try _readContactCardBytes(writableDir!, newRecipientHex)
    var existingCards: [Data] = []
    existingCards.append(try manifest.ownerCardBytes()!)
    if let extras = inputs["existing_recipient_uuid_hexes"] as? [String] {
        for h in extras {
            existingCards.append(try _readContactCardBytes(writableDir!, h))
        }
    }
    do {
        try shareBlock(
            identity: id,
            manifest: manifest,
            blockUuid: blockUuid,
            existingRecipientCards: existingCards,
            newRecipient: newRecipient,
            deviceUuid: deviceUuid,
            nowMs: nowMs
        )
        if case .ok = expectedKind(expected) {
            try _assertPostState(label, manifest: manifest, identity: id, expected: expected)
        } else {
            failures.append("\(label): expected Err, got Ok"); continue
        }
    } catch let e as VaultError {
        try _assertErr(label, caseName: caseName(e), detail: detail(e), expected: expected)
    }

case "trash_block":
    // Same shape as save_block but with the simpler input list. Mirror the
    // existing pattern; only the bridge call differs.
    let predecessor = vector["after"] as! String
    let (id, manifest) = cache[predecessor]!
    let blockUuid = try _uuidFromInputs(inputs, primary: "block_uuid_hex", bytes: "block_uuid_bytes_hex")
    let deviceUuid = try _uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex")
    let nowMs = inputs["now_ms"] as! UInt64
    do {
        try trashBlock(identity: id, manifest: manifest, blockUuid: blockUuid, deviceUuid: deviceUuid, nowMs: nowMs)
        if case .ok = expectedKind(expected) {
            try _assertPostState(label, manifest: manifest, identity: id, expected: expected)
        } else {
            failures.append("\(label): expected Err, got Ok"); continue
        }
    } catch let e as VaultError {
        try _assertErr(label, caseName: caseName(e), detail: detail(e), expected: expected)
    }

case "restore_block":
    // Identical to trash_block at the dispatch level.
    let predecessor = vector["after"] as! String
    let (id, manifest) = cache[predecessor]!
    let blockUuid = try _uuidFromInputs(inputs, primary: "block_uuid_hex", bytes: "block_uuid_bytes_hex")
    let deviceUuid = try _uuidFromInputs(inputs, primary: "device_uuid_hex", bytes: "device_uuid_bytes_hex")
    let nowMs = inputs["now_ms"] as! UInt64
    do {
        try restoreBlock(identity: id, manifest: manifest, blockUuid: blockUuid, deviceUuid: deviceUuid, nowMs: nowMs)
        if case .ok = expectedKind(expected) {
            try _assertPostState(label, manifest: manifest, identity: id, expected: expected)
        } else {
            failures.append("\(label): expected Err, got Ok"); continue
        }
    } catch let e as VaultError {
        try _assertErr(label, caseName: caseName(e), detail: detail(e), expected: expected)
    }
```

- [ ] **Step 5: Add Swift helpers `_uuidFromInputs`, `_blockInputFromInputs`, `_assertPostState`, `_findWritableDir`, `caseName`/`detail` for the new variants**

Mirror the Rust dispatch helpers. The new `caseName` cases (`NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, `BlockUuidAlreadyLive`, `BlockNotInTrash`, `InvalidArgument`) follow the v1 pattern:

```swift
func caseName(_ e: VaultError) -> String {
    switch e {
    case .WrongPasswordOrCorrupt: return "WrongPasswordOrCorrupt"
    case .WrongMnemonicOrCorrupt: return "WrongMnemonicOrCorrupt"
    case .InvalidMnemonic: return "InvalidMnemonic"
    case .VaultMismatch: return "VaultMismatch"
    case .CorruptVault: return "CorruptVault"
    case .FolderInvalid: return "FolderInvalid"
    case .BlockNotFound: return "BlockNotFound"
    case .SaveCryptoFailure: return "SaveCryptoFailure"
    case .CardDecodeFailure: return "CardDecodeFailure"
    case .NotAuthor: return "NotAuthor"
    case .RecipientAlreadyPresent: return "RecipientAlreadyPresent"
    case .MissingRecipientCard: return "MissingRecipientCard"
    case .BlockUuidAlreadyLive: return "BlockUuidAlreadyLive"
    case .BlockNotInTrash: return "BlockNotInTrash"
    case .InvalidArgument: return "InvalidArgument"
    }
}
```

`_uuidFromInputs` is the Swift mirror of the Rust helper (16-byte length check + InvalidArgument synthesis on miss; the synthesis path is unreachable in Swift since the uniffi layer already throws InvalidArgument before the closure gets to `saveBlock`). Implement it for symmetry; it will mostly serve as the JSON-to-Data conversion path.

`_assertPostState`:

```swift
func _assertPostState(_ label: String, manifest: OpenVaultManifest, identity: UnlockedIdentity, expected: [String: Any]) throws {
    guard let postState = (expected["post_state"] as? [String: Any]) else { return }
    if let bc = postState["block_count"] as? UInt64 {
        check(manifest.blockCount() == bc, "\(label): post_state.block_count mismatch (expected \(bc), got \(manifest.blockCount()))")
    }
    var roundTripUuid: Data? = nil
    if let hexStr = postState["find_block_uuid_hex"] as? String {
        let uuidData = _hexToData(hexStr)
        let summary = manifest.findBlock(blockUuid: uuidData)
        check(summary != nil, "\(label): find_block(\(hexStr)) returned nil")
        if let s = summary {
            check(s.blockUuid == uuidData, "\(label): find_block returned wrong uuid")
            roundTripUuid = uuidData
        }
    }
    if let rc = postState["recipient_count"] as? UInt64 {
        guard let uuid = roundTripUuid else {
            failures.append("\(label): recipient_count needs find_block_uuid_hex"); return
        }
        let summary = manifest.findBlock(blockUuid: uuid)!
        check(UInt64(summary.recipientUuids.count) == rc, "\(label): recipient_count mismatch (expected \(rc), got \(summary.recipientUuids.count))")
    }
    if let readPin = postState["read_block"] as? [String: Any], let pinnedRecords = readPin["records"] as? [[String: Any]] {
        guard let uuid = roundTripUuid else {
            failures.append("\(label): read_block round-trip needs find_block_uuid_hex"); return
        }
        let output = try readBlock(identity: identity, manifest: manifest, blockUuid: uuid)
        defer { output.wipe() }
        try _assertReadBlockRecords(label, output: output, expected: pinnedRecords)
    }
}
```

`_assertReadBlockRecords` is a refactor of the existing v1 records check (factor it out into a separate function that v1's `_assertReadBlockOk` delegates to).

`_findWritableDir` walks the `after:` chain (same as Rust):

```swift
func _findWritableDir(_ start: String, writableVaultDirs: [String: URL], vectors: [[String: Any]]) -> URL? {
    var current = start
    while true {
        if let url = writableVaultDirs[current] { return url }
        guard let parent = vectors.first(where: { ($0["name"] as? String) == current })?["after"] as? String else {
            return nil
        }
        current = parent
    }
}
```

- [ ] **Step 6: Run Swift conformance**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -10
```

Expected: 20/20 PASS. Common failure modes if not:
- Cast mismatch on `expected["post_state"]` if the JSON parser returns `NSNumber` instead of `UInt64` — coerce as needed.
- `recipientUuids` Data-vs-Array equality — Swift's `Data == Data` is byte-equal; `[Data] == [Data]` element-wise.
- The error `case` for `InvalidArgument` may have a different associated payload than its detail string suggests — check the generated `secretary.swift` if `caseName` emits anything unexpected.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/conformance.swift
git commit -m "$(cat <<'EOF'
test(conformance-kat): Swift v2 dispatch for lifecycle ops

Extend the Swift uniffi conformance runner with the 5 new operation
dispatchers + _recursiveCopy + _readContactCardBytes +
_assertPostState. Mirrors the Rust replay engine semantics. caseName()
gains the 5 new VaultError lifecycle variants.

Swift conformance: 20/20 vectors now PASS (was 11/11).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Extend Kotlin conformance runner with v2 dispatch

**Files:**
- Modify: [ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt](../../../ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt)

Mirror Task 11 in Kotlin. The Swift→Kotlin translation is mechanical at this point; follow the existing v1 Kotlin runner's idioms (JNA imports, JSON parsing via `org.json` or hand-rolled, sealed-class pattern matching for `VaultException`).

- [ ] **Step 1: Read the existing Kotlin runner end-to-end**

```bash
wc -l ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt
```

Read in full. Identify the v1 dispatch loop + `caseName(error: VaultException)` helper.

- [ ] **Step 2: Add the recursive-copy helper**

Kotlin's standard library has `java.nio.file.Files.walkFileTree` but `kotlin.io.path.copyTo` plus a simple walk is simpler:

```kotlin
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import kotlin.io.path.*

fun recursiveCopy(src: Path, dst: Path) {
    Files.createDirectories(dst)
    Files.walk(src).use { stream ->
        for (entry in stream) {
            val rel = src.relativize(entry)
            val target = dst.resolve(rel.toString())
            if (Files.isDirectory(entry)) {
                Files.createDirectories(target)
            } else {
                Files.copy(entry, target, StandardCopyOption.REPLACE_EXISTING)
            }
        }
    }
}

fun readContactCardBytes(vaultDir: Path, userUuidHex: String): ByteArray {
    require(userUuidHex.length == 32) { "userUuidHex must be 32 chars" }
    val h = userUuidHex
    val hyphenated = "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20, 32)}.card"
    val path = vaultDir.resolve("contacts").resolve(hyphenated)
    return Files.readAllBytes(path)
}
```

- [ ] **Step 3: Add tempdir tracking + dispatch arms**

Same pattern as Swift:

```kotlin
val tempdirs = mutableListOf<Path>()
val writableVaultDirs = mutableMapOf<String, Path>()
try {
    // ... existing v1 dispatch loop ...
    // Add cases (translated from Swift):
    "open_vault_with_password_writable" -> {
        val vaultName = (inputs["vault_dir"] as String)
        val src = Paths.get(vaultDir, vaultName)
        val tmp = Files.createTempDirectory("secretary_conf_v2_")
        recursiveCopy(src, tmp)
        tempdirs.add(tmp)
        writableVaultDirs[label] = tmp
        val password = resolveSource(inputs)
        val out = openVaultWithPassword(tmp.toString().toByteArray(), password)
        cache[label] = Pair(out.identity, out.manifest)
        assertOpenOk(label, out, expected)
    }
    "save_block" -> {
        val predecessor = vector["after"] as String
        val (id, manifest) = cache[predecessor]!!
        val input = blockInputFromInputs(inputs)
        val deviceUuid = uuidFromInputs(inputs, "device_uuid_hex", "device_uuid_bytes_hex")
        val nowMs = (inputs["now_ms"] as Long).toULong()
        try {
            saveBlock(id, manifest, input, deviceUuid, nowMs)
            if (expectedKind(expected) == "ok") {
                assertPostState(label, manifest, id, expected)
            } else {
                failures.add("$label: expected Err, got Ok")
            }
        } catch (e: VaultException) {
            assertErr(label, caseName(e), detail(e), expected)
        }
    }
    "share_block" -> { /* mirror Swift */ }
    "trash_block" -> { /* mirror Swift */ }
    "restore_block" -> { /* mirror Swift */ }
} finally {
    for (path in tempdirs) {
        path.toFile().deleteRecursively()
    }
}
```

- [ ] **Step 4: Extend `caseName` for the 5 new variants**

```kotlin
fun caseName(e: VaultException): String = when (e) {
    is VaultException.WrongPasswordOrCorrupt -> "WrongPasswordOrCorrupt"
    is VaultException.WrongMnemonicOrCorrupt -> "WrongMnemonicOrCorrupt"
    is VaultException.InvalidMnemonic -> "InvalidMnemonic"
    is VaultException.VaultMismatch -> "VaultMismatch"
    is VaultException.CorruptVault -> "CorruptVault"
    is VaultException.FolderInvalid -> "FolderInvalid"
    is VaultException.BlockNotFound -> "BlockNotFound"
    is VaultException.SaveCryptoFailure -> "SaveCryptoFailure"
    is VaultException.CardDecodeFailure -> "CardDecodeFailure"
    is VaultException.NotAuthor -> "NotAuthor"
    is VaultException.RecipientAlreadyPresent -> "RecipientAlreadyPresent"
    is VaultException.MissingRecipientCard -> "MissingRecipientCard"
    is VaultException.BlockUuidAlreadyLive -> "BlockUuidAlreadyLive"
    is VaultException.BlockNotInTrash -> "BlockNotInTrash"
    is VaultException.InvalidArgument -> "InvalidArgument"
}
```

- [ ] **Step 5: Add `assertPostState` + `findWritableDir` + `uuidFromInputs` + `blockInputFromInputs`**

Mirror Swift one-to-one. The Kotlin types for the bridged `BlockInput`/`RecordInput`/`FieldInput` are uniffi-generated; check the existing smoke runner's invocations (search for `BlockInput(`, `RecordInput(`, `FieldInput(` in [tests/kotlin/Main.kt](../../../ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt)) for the exact constructor syntax.

- [ ] **Step 6: Run Kotlin conformance**

```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -10
```

Expected: 20/20 PASS. Common failure modes:
- `org.json` vs hand-rolled parser — type coercion may need `.toLong()` on integer fields.
- `ByteArray` equality — use `contentEquals`, not `==`.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt
git commit -m "$(cat <<'EOF'
test(conformance-kat): Kotlin v2 dispatch for lifecycle ops

Extend the Kotlin uniffi conformance runner with the 5 new operation
dispatchers + recursiveCopy + readContactCardBytes + assertPostState.
Mirrors the Swift + Rust replay engine semantics. caseName() gains
the 5 new VaultException lifecycle variants.

Kotlin conformance: 20/20 vectors now PASS (was 11/11).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Update ROADMAP.md

**Files:**
- Modify: [ROADMAP.md](../../../ROADMAP.md)

Mark B.6 v2 done; bump the per-binding conformance count from 11/11 to 20/20.

- [ ] **Step 1: Read the current ROADMAP**

```bash
grep -nE "B\.6|conformance|11/11" ROADMAP.md | head -20
```

Identify the line(s) that reference B.6 status and the 11/11 conformance count (likely line 34 per the previous handoffs).

- [ ] **Step 2: Apply the edits**

Find the line marking B.6 v1 as done + the "next forward chunk" row referencing B.6 v2. Update both:

- Bump cargo test count if the gauntlet revealed a new count (per Task 10, count should be unchanged at 642 — but verify before editing).
- Change the per-binding conformance description from "11/11" to "20/20".
- Mark B.6 v2 done. Remove the "next forward chunk" reference (Sub-project C kickoff becomes the new next chunk).

(Exact line text varies; the editor inspects the file at edit time. If the file's structure has drifted since the spec was written, follow its current shape.)

- [ ] **Step 3: Verify the diff**

```bash
git diff ROADMAP.md
```

Expected: a small, focused diff — counts updated, B.6 v2 marked done, next-chunk text updated.

- [ ] **Step 4: Commit**

```bash
git add ROADMAP.md
git commit -m "$(cat <<'EOF'
docs(roadmap): mark B.6 v2 done; bump conformance count 11→20

B.6 v2 lifecycle KAT extension closes issue #59. Per-binding
run_conformance.sh now passes 20/20 vectors on Rust + Swift + Kotlin.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Run the full gauntlet at session close

**Files:** none modified.

- [ ] **Step 1: Full gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check && echo FMT_OK
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
```

Expected:

- `TOTAL: 642 passed; 0 failed; 10 ignored`
- clippy clean
- FMT_OK
- Python conformance PASS
- Spec test name freshness PASS (96 / 0 / 2)
- Swift smoke OK (38 PASS asserts)
- Swift conformance 20/20 PASS
- Kotlin smoke OK (39 PASS asserts)
- Kotlin conformance 20/20 PASS

- [ ] **Step 2: If anything fails, stop and investigate**

A test count drift or a new clippy warning requires investigation — do not paper over it.

---

## Task 15: Write NEXT_SESSION.md + handoff snapshot (committed inside this PR)

**Files:**
- Modify: [NEXT_SESSION.md](../../../NEXT_SESSION.md)
- Create: `docs/handoffs/<YYYY-MM-DD>-ffi-b6-v2-lifecycle-conformance-kat.md` (frozen snapshot — replace `<YYYY-MM-DD>` with today's date)

Per the standing `feedback_next_session_in_pr.md` rule: NEXT_SESSION.md updates + the handoff snapshot ride INSIDE this PR. The previous handoff template is at [docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md](../../handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md) — mirror its structure.

- [ ] **Step 1: Author NEXT_SESSION.md**

Overwrite [NEXT_SESSION.md](../../../NEXT_SESSION.md) with the standard 4-section template:

1. **What we shipped this session** — table of commits (with SHAs from `git log --oneline` at session close) covering: types extension, fixtures helpers, dispatch helpers, replay loop, KAT vectors, generator extension, Swift runner, Kotlin runner, ROADMAP update.
2. **What's next** — Sub-project C kickoff. The B.6 design arc is now closed (v1 + v2 both merged).
3. **Open decisions / risks** — call out any open items surfaced during implementation (Swift JSON type-coercion gotchas, Kotlin `org.json` quirks, etc.).
4. **Exact commands to resume** — same shape as the 2026-05-16 NEXT_SESSION.md.

Include the closing-inventory section (cargo test count, per-binding conformance counts, files created/modified).

- [ ] **Step 2: Snapshot to docs/handoffs/**

```bash
cp NEXT_SESSION.md docs/handoffs/$(date +%Y-%m-%d)-ffi-b6-v2-lifecycle-conformance-kat.md
```

(Per the standing rule, the snapshot is an EXACT copy — do not re-author.)

- [ ] **Step 3: Commit**

```bash
git add NEXT_SESSION.md docs/handoffs/
git commit -m "$(cat <<'EOF'
docs: NEXT_SESSION + handoff snapshot for B.6 v2 close

Per feedback_next_session_in_pr.md: ship the handoff inside the PR
so post-merge main carries the correct baton.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: Push and open the PR

**Files:** none modified.

- [ ] **Step 1: Push the branch**

```bash
git push -u origin design/b6-v2-lifecycle-conformance-kat
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create \
  --base main \
  --head design/b6-v2-lifecycle-conformance-kat \
  --title "test(conformance-kat): B.6 v2 lifecycle KAT (closes #59)" \
  --body "$(cat <<'EOF'
## Summary

Extends [`core/tests/data/conformance_kat.json`](core/tests/data/conformance_kat.json) (v1, 11 read-only vectors) with 9 lifecycle vectors covering `save_block` / `share_block` / `trash_block` / `restore_block`. Each of three replay engines (Rust bridge, Swift uniffi, Kotlin uniffi) extends to dispatch the 5 new operations and assert shape + round-trip outputs.

Closes #59.

### Headline design decision: shape + round-trip, no byte-level pinning

All three host runners share the same Rust bridge crate, so AEAD nonce bytes cannot diverge by binding — cross-language parity does not require pinning on-disk bytes. The replay engine pins typed Ok/Err + post-call manifest shape (`block_count`, `find_block(uuid)`, `BlockSummary.recipient_uuids.len()`) + round-trip read after `save_block_insert`. **No bridge crate changes; v2 is replay-side-only.**

See [the design doc](docs/superpowers/specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md) §1.1 for the determinism reframing.

## Test plan

- [ ] `cargo test --release --workspace --no-fail-fast` → 642 + 10 (unchanged; one `#[test]` runs all 20 vectors)
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → OK
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` → 20/20 PASS
- [ ] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` → 20/20 PASS

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Capture the PR URL in the handoff snapshot**

The `gh pr create` command prints the URL. Note it for the session-close summary.

---

## Self-review checklist (run before declaring done)

- [ ] **Spec coverage:** every section of [the design doc](../specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md) §§3–4 has a corresponding task. §5 (replay engine) is covered by Tasks 6 + 11 + 12. §9 (implementation outline)'s 5 commits map to Tasks 2+3+4+5+6 (commit 1), 10 (commit 2), 11 (commit 3), 12 (commit 4), 13+15 (commit 5).
- [ ] **Placeholder scan:** no TBD / TODO / "fill in details" — every step has actual content.
- [ ] **Type consistency:** `Operation` variants in Task 2 match the dispatch arms in Task 6. `PostState` field names in Task 2 (`block_count`, `find_block_uuid_hex`, `recipient_count`, `read_block`) match the JSON keys in Task 7's appended vectors. `caseName` strings in Swift (Task 11) and Kotlin (Task 12) match the Rust `variant_name_vault` strings (existing v1 helper, unchanged).
- [ ] **TDD discipline:** Task 7 leaves the KAT in a red state (placeholder breaks deserialization); Task 8 verifies red; Task 10 (post-generator) verifies green. Each commit in between is buildable but does not advance functionality past its own scope.
- [ ] **DRY:** `assert_read_block_records` factored out of `assert_read_block_ok` in Task 5 so v2's `post_state.read_block` shares the per-field byte-equal check.
- [ ] **YAGNI:** No "save_block update path" / "multi-recipient share" / "NotAuthor variant" tasks — those are spec §8 non-goals.
- [ ] **Frequent commits:** 11 commits across 14 implementation tasks (Tasks 1, 8, 14 are verification-only and don't commit). Each commit is independently reviewable.
