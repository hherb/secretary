# Fuzz Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a coverage-guided fuzz harness for the six wire-format decoders identified in the Phase A.7 design spec, plus the durable regression and out-of-loop differential-replay infrastructure that supports it, then run the one-time bug-bash to shake out shallow findings before external cryptographic review.

**Architecture:** A standalone `core/fuzz/` cargo-fuzz crate (excluded from the workspace) hosts six libFuzzer targets. Each target is a 5–15 line wrapper that calls the decoder under test and (for five of six) asserts decode→encode roundtrip-eq. Seeds derive from existing `core/tests/data/` material. Crash repros get promoted from `core/fuzz/artifacts/` into `core/tests/data/fuzz_regressions/<target>/`, where a normal `cargo test` integration test exercises them — giving regression coverage that survives even if the fuzz harness is removed. An opt-in Cargo feature `differential-replay` runs the accumulated corpus through both Rust and the Python clean-room decoder in `core/tests/python/conformance.py`, asserting agreement.

**Tech Stack:** Rust stable (workspace), Rust nightly (path-scoped, `core/fuzz/` only), `cargo-fuzz` 0.12+, `libfuzzer-sys` 0.4, ASan + UBSan, Python 3.11+ with `uv` for the differential replay (existing toolchain — no new deps).

**Spec:** [docs/superpowers/specs/2026-04-30-fuzz-harness-design.md](../specs/2026-04-30-fuzz-harness-design.md).

**Pre-flight (one-time, before Task 1):**
- Branch off `main`: `git checkout -b feature/fuzz-harness`. All implementation commits land on this branch; merge to `main` happens after Task 14.
- Confirm `cargo test --release --workspace` is green on `main` before branching (sanity baseline).
- Install nightly Rust if not present: `rustup install nightly`. Confirm with `rustup toolchain list`.
- Install `cargo-fuzz` if not present: `cargo install cargo-fuzz` (uses stable toolchain to install the binary; the binary itself drives nightly when invoked from `core/fuzz/`).

---

## Task 1: Workspace plumbing — bootstrap `core/fuzz/`

Create the standalone cargo-fuzz crate skeleton, with no fuzz targets yet. Verify the workspace stays green and that `cargo fuzz list` works from inside `core/fuzz/`.

**Files:**
- Create: `core/fuzz/Cargo.toml`
- Create: `core/fuzz/rust-toolchain.toml`
- Create: `core/fuzz/.gitignore`
- Create: `core/fuzz/fuzz_targets/.gitkeep` (placeholder so the directory is committed)
- Create: `core/fuzz/seeds/.gitkeep`
- Modify: `Cargo.toml` (root) — add `exclude = ["core/fuzz"]`

- [ ] **Step 1: Add the `exclude` line to root `Cargo.toml`**

Find the `[workspace]` block and add the `exclude` key after `members`:

```toml
[workspace]
resolver = "2"
members = [
    "core",
    "ffi/secretary-ffi-py",
    "ffi/secretary-ffi-uniffi",
]
exclude = ["core/fuzz"]
```

- [ ] **Step 2: Create `core/fuzz/Cargo.toml`**

```toml
[package]
name = "secretary-core-fuzz"
version = "0.0.0"
publish = false
edition = "2021"
license = "AGPL-3.0-or-later"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
secretary-core = { path = ".." }

# Profile flags: see docs/superpowers/specs/2026-04-30-fuzz-harness-design.md §
# "Profile flags and sanitizers".
[profile.release]
debug = true            # symbols for crash backtraces
overflow-checks = true  # arithmetic overflow → panic → fuzzer finding
debug-assertions = true # internal assert!() → panic → fuzzer finding
```

(No `[[bin]]` entries yet; targets are added in Tasks 2–7.)

- [ ] **Step 3: Create `core/fuzz/rust-toolchain.toml`**

Path-scoped nightly pin so the rest of the workspace stays on stable.

```toml
[toolchain]
channel = "nightly-2026-04-29"
components = ["rustfmt", "clippy", "rust-src"]
```

(`rust-src` is needed by some sanitizer builds. **Pin convention:** Rust nightly always lags the calendar by one day — the nightly published on day N is built from the previous day's commits. The pin therefore uses `<plan_date - 1>` so it resolves on the day the plan is executed. The pinned date can be moved by a future maintainer; keeping it specific gives reproducibility.)

- [ ] **Step 4: Create `core/fuzz/.gitignore`**

```
# Runtime corpus and artifacts — gitignored. Seeds (committed) live in seeds/.
corpus/
artifacts/
target/
```

- [ ] **Step 5: Create placeholder dirs**

```bash
mkdir -p core/fuzz/fuzz_targets core/fuzz/seeds
touch core/fuzz/fuzz_targets/.gitkeep core/fuzz/seeds/.gitkeep
```

- [ ] **Step 6: Verify root workspace still builds and tests are green**

```bash
cargo test --release --workspace
```

Expected: all 399+ tests pass + 6 ignored. Same baseline as `main`.

- [ ] **Step 7: Verify `cargo fuzz list` works in `core/fuzz/`**

```bash
cd core/fuzz && cargo fuzz list
```

Expected: empty output (no targets yet) and exit code 0. The first invocation may download nightly and build `libfuzzer-sys` — be patient.

If you see `error: no such command: 'fuzz'`, install with `cargo install cargo-fuzz` and retry.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml core/fuzz/
git commit -m "chore(fuzz): bootstrap core/fuzz/ cargo-fuzz crate skeleton"
```

---

## Task 2: First fuzz target — `vault_toml` (crash-only)

The simplest of the six: TOML text input, crash-only oracle. Establishes the harness pattern.

**Files:**
- Modify: `core/fuzz/Cargo.toml` (add `[[bin]]` for `vault_toml`)
- Create: `core/fuzz/fuzz_targets/vault_toml.rs`
- Create: `core/fuzz/seeds/vault_toml/golden.toml`
- Create: `core/fuzz/seeds/vault_toml/minimal.toml`
- Create: `core/fuzz/seeds/vault_toml/empty.toml`

- [ ] **Step 1: Add `[[bin]]` entry to `core/fuzz/Cargo.toml`**

Append to the file:

```toml
[[bin]]
name = "vault_toml"
path = "fuzz_targets/vault_toml.rs"
test = false
doc = false
bench = false
```

(`test = false`, `doc = false`, `bench = false` prevent the fuzz binaries from interfering with normal `cargo test` / `cargo doc`.)

- [ ] **Step 2: Create `core/fuzz/fuzz_targets/vault_toml.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::unlock::vault_toml;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = vault_toml::decode(s);
    }
});
```

The decoder takes `&str`; non-UTF-8 inputs are filtered (libFuzzer mutates bytes, so most random input is invalid UTF-8 and would be wasted otherwise).

- [ ] **Step 3: Copy the golden vault TOML as a seed**

```bash
mkdir -p core/fuzz/seeds/vault_toml
cp core/tests/data/golden_vault_001/vault.toml core/fuzz/seeds/vault_toml/golden.toml
```

- [ ] **Step 4: Create a minimal valid seed**

`core/fuzz/seeds/vault_toml/minimal.toml` — the smallest TOML that `vault_toml::decode` accepts. Per the `VaultToml` struct at [core/src/unlock/vault_toml.rs](../../../core/src/unlock/vault_toml.rs), the required fields are: `format_version` (u16, must = `FORMAT_VERSION` = 1), `suite_id` (u16, must = `SUITE_ID` = 1), `vault_uuid` (16-byte UUID in 8-4-4-4-12 hex form), `created_at_ms` (u64), and a `[kdf]` section with `algorithm = "argon2id"`, `version = "1.3"`, `memory_kib`, `iterations`, `parallelism`, `salt_b64` (base64 of 32 bytes).

```toml
format_version = 1
suite_id = 1
vault_uuid = "00000000-0000-0000-0000-000000000000"
created_at_ms = 1714060800000

[kdf]
algorithm = "argon2id"
version = "1.3"
memory_kib = 65536
iterations = 3
parallelism = 1
salt_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

(`AAAA...AAAA=` is the base64 of 32 zero bytes. Verify by `python -c 'import base64; print(len(base64.b64decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")))'` — should print `32`.)

If the struct gains required fields after the plan was written, the implementer should re-read [core/src/unlock/vault_toml.rs](../../../core/src/unlock/vault_toml.rs) and adjust accordingly. The point is: smallest accepted input.

- [ ] **Step 5: Create an empty seed**

```bash
: > core/fuzz/seeds/vault_toml/empty.toml
```

(Empty file. `vault_toml::decode("")` returns `Err`, but the seed exercises the error path.)

- [ ] **Step 6: Build the target**

```bash
cd core/fuzz && cargo fuzz build vault_toml
```

Expected: clean build, no warnings. ASan instrumentation is on by default for `cargo fuzz build`.

- [ ] **Step 7: Run target against seeds (must not crash)**

```bash
cd core/fuzz && cargo fuzz run vault_toml seeds/vault_toml/ -- -runs=0
```

`-runs=0` means "execute every input in the corpus exactly once and exit". Expected: each seed exec'd, no crash, exit code 0.

- [ ] **Step 8: Quick smoke run (1000 mutations)**

```bash
cd core/fuzz && cargo fuzz run vault_toml -- -runs=1000
```

Expected: 1000 executions complete without crash. Confirms the harness is wired correctly. If a crash IS reported here, that's a finding — promote it via the procedure in Task 11 (you can come back).

- [ ] **Step 9: Commit**

```bash
git add core/fuzz/Cargo.toml core/fuzz/fuzz_targets/vault_toml.rs core/fuzz/seeds/vault_toml/
git commit -m "feat(fuzz): add vault_toml fuzz target (crash-only)"
```

---

## Task 3: `record` fuzz target (first roundtrip oracle) + seed extractor

This is the first target with a roundtrip oracle. The `record::decode` function already enforces canonical re-encode internally ([core/src/vault/record.rs:540](../../../core/src/vault/record.rs#L540)), so the external roundtrip in the fuzz target is defense-in-depth — a regression guard if that internal check is ever weakened.

Seeds for this target need to be canonical-CBOR-encoded `Record` values. Since these don't exist as raw bytes anywhere in the test data, we generate them via a one-shot Cargo example that's committed to the repo as a regeneration tool.

**Files:**
- Create: `core/examples/extract_record_seeds.rs`
- Modify: `core/fuzz/Cargo.toml` (add `[[bin]]` for `record`)
- Create: `core/fuzz/fuzz_targets/record.rs`
- Create: `core/fuzz/seeds/record/login.cbor`
- Create: `core/fuzz/seeds/record/secure_note.cbor`
- Create: `core/fuzz/seeds/record/api_key.cbor`

- [ ] **Step 1: Read the `Record` struct and the `RecordType`/`Field` shapes**

Open [core/src/vault/record.rs](../../../core/src/vault/record.rs) and read the `Record`, `RecordType`, `Field`, and `FieldValue` definitions. Note exact field names, the canonical-CBOR encoding rules, and any required versions/UUIDs. **Do not skip this step** — the `extract_record_seeds.rs` example must construct valid records, and the field shapes have evolved.

- [ ] **Step 2: Create `core/examples/extract_record_seeds.rs`**

A binary that constructs three known records of distinct `RecordType` variants and writes them as canonical CBOR to `core/fuzz/seeds/record/`. Idempotent: overwrites if files exist.

```rust
//! Regenerate `core/fuzz/seeds/record/*.cbor` — canonical-CBOR-encoded
//! `Record` values used as fuzz seeds. Run with:
//!
//!     cargo run --release --example extract_record_seeds
//!
//! Idempotent. Safe to re-run after Record schema changes.

use std::fs;
use std::path::PathBuf;
use secretary_core::vault::record::{self, Record /*, plus exact item types from the module */};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir: PathBuf = ["core", "fuzz", "seeds", "record"].iter().collect();
    fs::create_dir_all(&out_dir)?;

    // ──────────────────────────────────────────────────────────────────────
    // Construct three records. Use the exact constructor / struct-literal
    // shape from core/src/vault/record.rs read in Step 1. Below is a
    // placeholder for the shape — replace with the literal struct fields
    // that the current Record type requires.
    // ──────────────────────────────────────────────────────────────────────
    let login: Record = todo_construct_login_record();      // see Step 3
    let note: Record = todo_construct_secure_note_record(); // see Step 3
    let api_key: Record = todo_construct_api_key_record();  // see Step 3

    fs::write(out_dir.join("login.cbor"), record::encode(&login)?)?;
    fs::write(out_dir.join("secure_note.cbor"), record::encode(&note)?)?;
    fs::write(out_dir.join("api_key.cbor"), record::encode(&api_key)?)?;

    println!("wrote 3 record seeds to {}", out_dir.display());
    Ok(())
}

// Inline constructors below — replace `todo_construct_*` placeholders with
// concrete struct-literal Record values matching the current type.
```

- [ ] **Step 3: Replace placeholder constructors with concrete records**

The current `Record` struct (verify by re-reading [core/src/vault/record.rs:324-376](../../../core/src/vault/record.rs#L324-L376)) has all public fields, so direct struct-literal construction works. Concrete shape — adapt field names if the struct has changed since this plan was written:

```rust
use std::collections::BTreeMap;
use secretary_core::vault::record::{
    self, Record, RecordField, RecordFieldValue,
};

const REC_UUID_LOGIN: [u8; 16] = [
    0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2d, 0x75,
    0x75, 0x69, 0x64, 0x2d, 0x6b, 0x61, 0x74, 0x31,
]; // "record-uuid-kat1"
const DEVICE_UUID: [u8; 16] = [
    0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x75,
    0x75, 0x69, 0x64, 0x2d, 0x6b, 0x61, 0x74, 0x31,
]; // "device-uuid-kat1"

fn build_login_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "username".to_string(),
        RecordField {
            value: RecordFieldValue::Text("alice".to_string()),
            last_mod: 1714060800000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    fields.insert(
        "totp_seed".to_string(),
        RecordField {
            value: RecordFieldValue::Bytes(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
            last_mod: 1714060800000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );

    Record {
        record_uuid: REC_UUID_LOGIN,
        record_type: "login".to_string(),
        fields,
        tags: vec![],
        created_at_ms: 1714060800000,
        last_mod_ms: 1714060800000,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

fn build_secure_note_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "body".to_string(),
        RecordField {
            value: RecordFieldValue::Text("two-factor backup codes\n12345678\n23456789".to_string()),
            last_mod: 1714060801000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );

    Record {
        record_uuid: *b"record-uuid-kat2",
        record_type: "secure_note".to_string(),
        fields,
        tags: vec!["personal".to_string()],
        created_at_ms: 1714060801000,
        last_mod_ms: 1714060801000,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

fn build_api_key_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "key".to_string(),
        RecordField {
            value: RecordFieldValue::Text("sk_test_DEADBEEFCAFEBABE".to_string()),
            last_mod: 1714060802000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    fields.insert(
        "endpoint".to_string(),
        RecordField {
            value: RecordFieldValue::Text("https://api.example.test".to_string()),
            last_mod: 1714060802000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );

    Record {
        record_uuid: *b"record-uuid-kat3",
        record_type: "api_key".to_string(),
        fields,
        tags: vec!["work".to_string(), "ci".to_string()],
        created_at_ms: 1714060802000,
        last_mod_ms: 1714060802000,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}
```

Wire these into `main()` by replacing the `todo_construct_*` calls with `build_login_record()` etc.

Notes:
- All three records have distinct UUIDs (16 bytes each; ASCII content for human readability).
- Fixed timestamps (deliberately old) — never `SystemTime::now()`.
- Tags exercise empty (login), single-tag (note), multi-tag (api_key) — gives the fuzzer three distinct corpus shapes.
- `tombstone = false` / `tombstoned_at_ms = 0` — these encode as absent, exercising the §6.3 omit-when-default paths.
- All `unknown` maps empty — extending one with a non-empty `unknown` key is a valid future seed enhancement but out of scope for the initial harness.

If a future schema change makes any of these field literals fail to compile, treat that as a signal to update both the example and the seeds (re-run Step 4).

- [ ] **Step 4: Run the extractor**

```bash
cargo run --release --example extract_record_seeds
```

Expected: prints `wrote 3 record seeds to core/fuzz/seeds/record`. Three .cbor files exist:

```bash
ls -la core/fuzz/seeds/record/
```

- [ ] **Step 5: Verify each seed decodes cleanly via the existing API**

```bash
cargo test --release -p secretary-core record
```

(All existing record tests still green — seed generation didn't change semantics.)

Then a one-off check (write as an inline test, run, then delete the test):

```rust
// Add temporarily to core/tests/record.rs (or wherever existing record tests live)
#[test]
fn fuzz_seeds_decode_cleanly() {
    use std::fs;
    for entry in fs::read_dir("fuzz/seeds/record/").unwrap() {
        let path = entry.unwrap().path();
        let bytes = fs::read(&path).unwrap();
        secretary_core::vault::record::decode(&bytes)
            .unwrap_or_else(|e| panic!("seed {} did not decode: {:?}", path.display(), e));
    }
}
```

```bash
cargo test --release -p secretary-core fuzz_seeds_decode_cleanly
```

Expected: PASS. Then **remove** this test (it's a one-shot sanity check; the fuzz target itself will exercise these seeds).

- [ ] **Step 6: Add `[[bin]]` entry for `record` to `core/fuzz/Cargo.toml`**

```toml
[[bin]]
name = "record"
path = "fuzz_targets/record.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 7: Create `core/fuzz/fuzz_targets/record.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::record;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = record::decode(data) {
        let reencoded = record::encode(&parsed)
            .expect("encode after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "record decode→encode roundtrip mismatch"
        );
    }
});
```

The `expect` and `assert_eq!` both trigger libFuzzer crash reports if violated.

- [ ] **Step 8: Build and seed-run**

```bash
cd core/fuzz && cargo fuzz build record
cd core/fuzz && cargo fuzz run record seeds/record/ -- -runs=0
```

Expected: clean build, three seeds processed, no crash.

- [ ] **Step 9: Smoke run**

```bash
cd core/fuzz && cargo fuzz run record -- -runs=1000
```

Expected: 1000 executions, no crash.

- [ ] **Step 10: Commit**

```bash
git add core/examples/extract_record_seeds.rs core/fuzz/Cargo.toml core/fuzz/fuzz_targets/record.rs core/fuzz/seeds/record/
git commit -m "feat(fuzz): add record fuzz target with roundtrip oracle"
```

---

## Task 4: `contact_card` fuzz target

Roundtrip oracle. Seeds copied directly from existing committed CBOR.

**Files:**
- Modify: `core/fuzz/Cargo.toml`
- Create: `core/fuzz/fuzz_targets/contact_card.rs`
- Create: `core/fuzz/seeds/contact_card/unsigned.cbor`
- Create: `core/fuzz/seeds/contact_card/signed.cbor`

- [ ] **Step 1: Add `[[bin]]` entry**

```toml
[[bin]]
name = "contact_card"
path = "fuzz_targets/contact_card.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Copy seeds**

```bash
mkdir -p core/fuzz/seeds/contact_card
cp core/tests/data/card_kat.cbor        core/fuzz/seeds/contact_card/unsigned.cbor
cp core/tests/data/card_kat_signed.cbor core/fuzz/seeds/contact_card/signed.cbor
```

- [ ] **Step 3: Create `core/fuzz/fuzz_targets/contact_card.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::identity::card::ContactCard;

fuzz_target!(|data: &[u8]| {
    if let Ok(card) = ContactCard::from_canonical_cbor(data) {
        let reencoded = card
            .to_canonical_cbor()
            .expect("to_canonical_cbor after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "contact_card decode→encode roundtrip mismatch"
        );
    }
});
```

- [ ] **Step 4: Build, seed-run, smoke run**

```bash
cd core/fuzz && cargo fuzz build contact_card
cd core/fuzz && cargo fuzz run contact_card seeds/contact_card/ -- -runs=0
cd core/fuzz && cargo fuzz run contact_card -- -runs=1000
```

Expected: clean build; both seeds processed without crash; 1000 mutated execs without crash.

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/Cargo.toml core/fuzz/fuzz_targets/contact_card.rs core/fuzz/seeds/contact_card/
git commit -m "feat(fuzz): add contact_card fuzz target with roundtrip oracle"
```

---

## Task 5: `bundle_file` fuzz target

Roundtrip oracle. Seed from golden vault.

**Files:**
- Modify: `core/fuzz/Cargo.toml`
- Create: `core/fuzz/fuzz_targets/bundle_file.rs`
- Create: `core/fuzz/seeds/bundle_file/golden.bin`

- [ ] **Step 1: Add `[[bin]]` entry**

```toml
[[bin]]
name = "bundle_file"
path = "fuzz_targets/bundle_file.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Copy seed**

```bash
mkdir -p core/fuzz/seeds/bundle_file
cp core/tests/data/golden_vault_001/identity.bundle.enc core/fuzz/seeds/bundle_file/golden.bin
```

- [ ] **Step 3: Create `core/fuzz/fuzz_targets/bundle_file.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::unlock::bundle_file;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = bundle_file::decode(data) {
        let reencoded = bundle_file::encode(&parsed);
        assert_eq!(
            reencoded.as_slice(),
            data,
            "bundle_file decode→encode roundtrip mismatch"
        );
    }
});
```

(Note: `bundle_file::encode` returns `Vec<u8>` directly per its signature — no `Result`.)

- [ ] **Step 4: Build, seed-run, smoke run**

```bash
cd core/fuzz && cargo fuzz build bundle_file
cd core/fuzz && cargo fuzz run bundle_file seeds/bundle_file/ -- -runs=0
cd core/fuzz && cargo fuzz run bundle_file -- -runs=1000
```

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/Cargo.toml core/fuzz/fuzz_targets/bundle_file.rs core/fuzz/seeds/bundle_file/
git commit -m "feat(fuzz): add bundle_file fuzz target with roundtrip oracle"
```

---

## Task 6: `manifest_file` fuzz target

Roundtrip oracle. Seed from golden vault.

**Files:**
- Modify: `core/fuzz/Cargo.toml`
- Create: `core/fuzz/fuzz_targets/manifest_file.rs`
- Create: `core/fuzz/seeds/manifest_file/golden.bin`

- [ ] **Step 1: Add `[[bin]]` entry**

```toml
[[bin]]
name = "manifest_file"
path = "fuzz_targets/manifest_file.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Copy seed**

```bash
mkdir -p core/fuzz/seeds/manifest_file
cp core/tests/data/golden_vault_001/manifest.cbor.enc core/fuzz/seeds/manifest_file/golden.bin
```

- [ ] **Step 3: Create `core/fuzz/fuzz_targets/manifest_file.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = manifest::decode_manifest_file(data) {
        let reencoded = manifest::encode_manifest_file(&parsed)
            .expect("encode after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "manifest_file decode→encode roundtrip mismatch"
        );
    }
});
```

- [ ] **Step 4: Build, seed-run, smoke run**

```bash
cd core/fuzz && cargo fuzz build manifest_file
cd core/fuzz && cargo fuzz run manifest_file seeds/manifest_file/ -- -runs=0
cd core/fuzz && cargo fuzz run manifest_file -- -runs=1000
```

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/Cargo.toml core/fuzz/fuzz_targets/manifest_file.rs core/fuzz/seeds/manifest_file/
git commit -m "feat(fuzz): add manifest_file fuzz target with roundtrip oracle"
```

---

## Task 7: `block_file` fuzz target

Roundtrip oracle. Seed from golden vault block.

**Files:**
- Modify: `core/fuzz/Cargo.toml`
- Create: `core/fuzz/fuzz_targets/block_file.rs`
- Create: `core/fuzz/seeds/block_file/golden.bin`

- [ ] **Step 1: Add `[[bin]]` entry**

```toml
[[bin]]
name = "block_file"
path = "fuzz_targets/block_file.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Copy seed**

```bash
mkdir -p core/fuzz/seeds/block_file
cp core/tests/data/golden_vault_001/blocks/11223344-5566-7788-99aa-bbccddeeff00.cbor.enc \
   core/fuzz/seeds/block_file/golden.bin
```

(Filename in the destination is intentionally simpler — libFuzzer treats corpus filenames as opaque IDs.)

- [ ] **Step 3: Create `core/fuzz/fuzz_targets/block_file.rs`**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::block;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = block::decode_block_file(data) {
        let reencoded = block::encode_block_file(&parsed)
            .expect("encode after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "block_file decode→encode roundtrip mismatch"
        );
    }
});
```

- [ ] **Step 4: Build, seed-run, smoke run**

```bash
cd core/fuzz && cargo fuzz build block_file
cd core/fuzz && cargo fuzz run block_file seeds/block_file/ -- -runs=0
cd core/fuzz && cargo fuzz run block_file -- -runs=1000
```

- [ ] **Step 5: Commit**

```bash
git add core/fuzz/Cargo.toml core/fuzz/fuzz_targets/block_file.rs core/fuzz/seeds/block_file/
git commit -m "feat(fuzz): add block_file fuzz target with roundtrip oracle"
```

---

## Task 8: `fuzz_regressions` integration test

The durable regression harness — runs in plain `cargo test --release --workspace`, survives even if the fuzz crate is removed. Six regression directories with `.gitkeep` placeholders so the test compiles before any findings exist.

**Files:**
- Create: `core/tests/data/fuzz_regressions/<target>/.gitkeep` (× 6)
- Create: `core/tests/fuzz_regressions.rs`

- [ ] **Step 1: Create empty regression dirs with `.gitkeep`**

```bash
for t in vault_toml record contact_card bundle_file manifest_file block_file; do
  mkdir -p "core/tests/data/fuzz_regressions/$t"
  touch "core/tests/data/fuzz_regressions/$t/.gitkeep"
done
```

- [ ] **Step 2: Write the failing test (TDD)**

Create `core/tests/fuzz_regressions.rs`:

```rust
//! Replays committed fuzz crash repros through their respective decoders
//! and asserts no panic. Each input lives in
//! `core/tests/data/fuzz_regressions/<target>/`. The contract is "must
//! not panic" — `Err` returns are accepted; the whole point of a fuzz
//! regression is that an attacker-supplied byte sequence must never
//! crash a process.
//!
//! See docs/superpowers/specs/2026-04-30-fuzz-harness-design.md §
//! "Regression mechanics".

use std::fs;
use std::path::{Path, PathBuf};

fn replay_dir<F: Fn(&[u8])>(target: &str, decoder: F) {
    let dir: PathBuf = ["tests", "data", "fuzz_regressions", target].iter().collect();
    for entry in fs::read_dir(&dir).expect("regression dir exists") {
        let entry = entry.expect("readable dir entry");
        let path = entry.path();
        // Skip the .gitkeep placeholder.
        if path.file_name().and_then(|s| s.to_str()) == Some(".gitkeep") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).expect("read regression input");
        // Must not panic. Result is intentionally discarded.
        decoder(&bytes);
    }
}

#[test]
fn vault_toml_regressions_no_panic() {
    replay_dir("vault_toml", |bytes| {
        if let Ok(s) = std::str::from_utf8(bytes) {
            let _ = secretary_core::unlock::vault_toml::decode(s);
        }
    });
}

#[test]
fn record_regressions_no_panic() {
    replay_dir("record", |bytes| {
        let _ = secretary_core::vault::record::decode(bytes);
    });
}

#[test]
fn contact_card_regressions_no_panic() {
    replay_dir("contact_card", |bytes| {
        let _ = secretary_core::identity::card::ContactCard::from_canonical_cbor(bytes);
    });
}

#[test]
fn bundle_file_regressions_no_panic() {
    replay_dir("bundle_file", |bytes| {
        let _ = secretary_core::unlock::bundle_file::decode(bytes);
    });
}

#[test]
fn manifest_file_regressions_no_panic() {
    replay_dir("manifest_file", |bytes| {
        let _ = secretary_core::vault::manifest::decode_manifest_file(bytes);
    });
}

#[test]
fn block_file_regressions_no_panic() {
    replay_dir("block_file", |bytes| {
        let _ = secretary_core::vault::block::decode_block_file(bytes);
    });
}

// Suppress dead-code warning on Path import in case a future refactor
// inlines all uses. Keep imports minimal; remove this if Path is genuinely
// used elsewhere.
#[allow(dead_code)]
fn _unused_path_compile_check(_p: &Path) {}
```

- [ ] **Step 3: Verify the tests pass on empty dirs**

```bash
cargo test --release -p secretary-core --test fuzz_regressions
```

Expected: 6 tests, all pass (vacuously — only `.gitkeep` files in each dir, which are skipped). Output:

```
running 6 tests
test block_file_regressions_no_panic ... ok
test bundle_file_regressions_no_panic ... ok
test contact_card_regressions_no_panic ... ok
test manifest_file_regressions_no_panic ... ok
test record_regressions_no_panic ... ok
test vault_toml_regressions_no_panic ... ok
```

- [ ] **Step 4: Verify full workspace test suite still green**

```bash
cargo test --release --workspace
```

Expected: 405+ tests pass (399 pre-existing + 6 new). No regressions.

- [ ] **Step 5: Commit**

```bash
git add core/tests/data/fuzz_regressions/ core/tests/fuzz_regressions.rs
git commit -m "test(fuzz): add fuzz_regressions integration test scaffold"
```

---

## Task 9: `differential-replay` feature scaffold + Rust replay test

Wire up the Cargo feature and the Rust-side test. Initially the test fails because `conformance.py --diff-replay` doesn't exist yet — that's TDD-red, fixed in Task 10.

**Files:**
- Modify: `core/Cargo.toml` (add feature)
- Create: `core/tests/differential_replay.rs`
- Create: `core/tests/data/diff_regressions/<target>/.gitkeep` (× 6)

- [ ] **Step 1: Add `differential-replay` feature to `core/Cargo.toml`**

Add a `[features]` section (or extend the existing one) with:

```toml
[features]
differential-replay = []
```

- [ ] **Step 2: Create empty diff_regressions dirs**

```bash
for t in vault_toml record contact_card bundle_file manifest_file block_file; do
  mkdir -p "core/tests/data/diff_regressions/$t"
  touch "core/tests/data/diff_regressions/$t/.gitkeep"
done
```

- [ ] **Step 3: Write the failing test (TDD-red)**

Create `core/tests/differential_replay.rs`:

```rust
//! Out-of-loop differential replay: feeds the runtime fuzz corpus
//! (and any committed diff_regressions/) through both Rust decoders
//! and the Python clean-room decoder in
//! `core/tests/python/conformance.py`, asserting agreement on
//! accept/reject and (where applicable) on re-encoded bytes.
//!
//! Gated by feature `differential-replay`. Off by default to keep
//! `cargo test` Rust-only.
//!
//! See docs/superpowers/specs/2026-04-30-fuzz-harness-design.md §
//! "Out-of-loop differential replay".

#![cfg(feature = "differential-replay")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGETS: &[&str] = &[
    "vault_toml",
    "record",
    "contact_card",
    "bundle_file",
    "manifest_file",
    "block_file",
];

fn corpus_dirs(target: &str) -> Vec<PathBuf> {
    let mut dirs = vec![];
    // Runtime corpus (gitignored, may not exist locally).
    let runtime: PathBuf = ["..", "core", "fuzz", "corpus", target].iter().collect();
    if runtime.is_dir() {
        dirs.push(runtime);
    }
    // Committed seeds (always present).
    let seeds: PathBuf = ["..", "core", "fuzz", "seeds", target].iter().collect();
    if seeds.is_dir() {
        dirs.push(seeds);
    }
    // Committed diff regressions.
    let diffs: PathBuf = ["tests", "data", "diff_regressions", target].iter().collect();
    if diffs.is_dir() {
        dirs.push(diffs);
    }
    dirs
}

fn rust_decode(target: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    use secretary_core::*;
    match target {
        "vault_toml" => {
            let s = std::str::from_utf8(bytes).map_err(|e| format!("utf8: {}", e))?;
            unlock::vault_toml::decode(s)
                .map(|_| Vec::new()) // crash-only target; no roundtrip compare
                .map_err(|e| format!("{:?}", e))
        }
        "record" => vault::record::decode(bytes)
            .and_then(|r| vault::record::encode(&r))
            .map_err(|e| format!("{:?}", e)),
        "contact_card" => identity::card::ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .map_err(|e| format!("{:?}", e)),
        "bundle_file" => unlock::bundle_file::decode(bytes)
            .map(|f| unlock::bundle_file::encode(&f))
            .map_err(|e| format!("{:?}", e)),
        "manifest_file" => vault::manifest::decode_manifest_file(bytes)
            .and_then(|f| vault::manifest::encode_manifest_file(&f))
            .map_err(|e| format!("{:?}", e)),
        "block_file" => vault::block::decode_block_file(bytes)
            .and_then(|f| vault::block::encode_block_file(&f))
            .map_err(|e| format!("{:?}", e)),
        _ => panic!("unknown target {}", target),
    }
}

fn python_decode(target: &str, input_path: &Path) -> Result<Vec<u8>, String> {
    let output = Command::new("uv")
        .arg("run")
        .arg("--with").arg("cryptography")
        .arg("--with").arg("pynacl")
        .arg("--with").arg("pqcrypto")
        .arg("--with").arg("argon2-cffi")
        .arg("--with").arg("blake3")
        .arg("--with").arg("cbor2")
        .arg("../core/tests/python/conformance.py")
        .arg("--diff-replay")
        .arg(target)
        .arg(input_path)
        .output()
        .expect("uv run conformance.py");
    if !output.status.success() {
        return Err(format!(
            "python exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let json: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("python output not JSON: {} ({:?})", stdout, e));
    match json["status"].as_str() {
        Some("accept") => {
            let b64 = json["reencoded_b64"].as_str().unwrap_or("");
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| format!("base64: {}", e))
        }
        Some("reject") => Err(json["error_class"].as_str().unwrap_or("unknown").to_string()),
        _ => panic!("python output missing status: {}", stdout),
    }
}

#[test]
fn differential_replay_full_corpus() {
    let mut disagreements: Vec<String> = vec![];
    for target in TARGETS {
        for dir in corpus_dirs(target) {
            for entry in fs::read_dir(&dir).expect("read corpus dir") {
                let path = entry.expect("dir entry").path();
                if !path.is_file() {
                    continue;
                }
                if path.file_name().and_then(|s| s.to_str()) == Some(".gitkeep") {
                    continue;
                }
                let bytes = fs::read(&path).expect("read input");

                let rust = rust_decode(target, &bytes);
                let python = python_decode(target, &path);

                let ok = match (&rust, &python) {
                    // Both reject → agreement (don't compare error classes for now;
                    // can tighten later if we standardize them).
                    (Err(_), Err(_)) => true,
                    // Both accept: for crash-only target (vault_toml) compare nothing;
                    // for the rest, compare re-encoded bytes.
                    (Ok(r_bytes), Ok(p_bytes)) => {
                        if *target == "vault_toml" {
                            true
                        } else {
                            r_bytes == p_bytes
                        }
                    }
                    // Mismatch: one accepted, one rejected.
                    _ => false,
                };

                if !ok {
                    disagreements.push(format!(
                        "[{}] {}: rust={:?} python={:?}",
                        target,
                        path.display(),
                        rust.as_ref().map(|v| format!("Ok({} bytes)", v.len())).unwrap_or_else(|e| format!("Err({})", e)),
                        python.as_ref().map(|v| format!("Ok({} bytes)", v.len())).unwrap_or_else(|e| format!("Err({})", e)),
                    ));
                }
            }
        }
    }
    if !disagreements.is_empty() {
        panic!(
            "differential disagreements ({}):\n{}",
            disagreements.len(),
            disagreements.join("\n")
        );
    }
}
```

- [ ] **Step 4: Add the test's dev-dependencies to `core/Cargo.toml`**

The test uses `serde_json` and `base64`. `base64` is already a workspace dep; `serde_json` may not be. Check:

```bash
grep -E '^serde_json' core/Cargo.toml
```

If absent, add to `[dev-dependencies]`:

```toml
[dev-dependencies]
serde_json = "1"
# base64 is already in [dependencies]
```

- [ ] **Step 5: Verify the test fails (TDD-red)**

```bash
cargo test --release --workspace --features differential-replay --test differential_replay
```

Expected: FAIL. Stderr should contain something like `unknown command: --diff-replay` or `argparse error` from `conformance.py`. The exact error doesn't matter; the test should not pass before Task 10.

- [ ] **Step 6: Verify default `cargo test` still green (feature opt-in)**

```bash
cargo test --release --workspace
```

Expected: PASS. The differential test is gated and not compiled.

- [ ] **Step 7: Commit (TDD-red commit)**

```bash
git add core/Cargo.toml core/tests/differential_replay.rs core/tests/data/diff_regressions/
git commit -m "test(fuzz): add differential-replay test scaffold (currently red)"
```

---

## Task 10: `conformance.py --diff-replay` mode (TDD-green)

Extend the existing Python conformance script with a `--diff-replay <target> <input-file>` subcommand that runs the Python clean-room decoder for the named target and emits structured JSON.

**Files:**
- Modify: `core/tests/python/conformance.py`

- [ ] **Step 1: Read the current `main()` and CLI structure**

```bash
grep -n "def main\|argparse\|sys.argv" core/tests/python/conformance.py
```

Read the relevant function. Preserve backward compatibility: existing invocations like `uv run core/tests/python/conformance.py` must still run all conformance sections. Adding `--diff-replay` is a *new* mode that bypasses the §15 conformance sections.

- [ ] **Step 2: Add `--diff-replay` argument parsing**

At the top of `main()`, before the existing logic:

```python
import argparse, json, sys
parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument("--diff-replay", nargs=2, metavar=("TARGET", "INPUT_PATH"),
                    help="differential replay mode: decode one input file for one target, emit JSON")
args, _ = parser.parse_known_args()

if args.diff_replay:
    target, input_path = args.diff_replay
    return run_diff_replay(target, input_path)
# ... existing main body unchanged below ...
```

(`parse_known_args` ensures we don't break any other argparse usage already present.)

- [ ] **Step 3: Implement `run_diff_replay`**

Add this function (place near the bottom of the file, before `main`):

```python
def run_diff_replay(target: str, input_path: str) -> int:
    """Differential replay one input through the Python decoder for `target`.

    Output (always to stdout, single line of JSON):
      {"status": "accept", "reencoded_b64": "..."}    # for non-TOML targets
      {"status": "accept", "reencoded_b64": ""}       # for vault_toml (no roundtrip)
      {"status": "reject", "error_class": "..."}

    Exit code: always 0 for accept|reject, nonzero for unrecoverable script errors.
    """
    import base64
    with open(input_path, "rb") as f:
        data = f.read()

    try:
        if target == "vault_toml":
            # Crash-only target. Try to UTF-8 decode and parse; success = accept.
            text = data.decode("utf-8")  # raises UnicodeDecodeError if not utf-8
            _ = py_decode_vault_toml(text)  # see below
            print(json.dumps({"status": "accept", "reencoded_b64": ""}))
            return 0
        elif target == "record":
            parsed = py_decode_record(data)
            reencoded = py_encode_record(parsed)
            print(json.dumps({"status": "accept", "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii")}))
            return 0
        elif target == "contact_card":
            parsed = py_decode_contact_card(data)
            reencoded = py_encode_contact_card(parsed)
            print(json.dumps({"status": "accept", "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii")}))
            return 0
        elif target == "bundle_file":
            parsed = py_decode_bundle_file(data)
            reencoded = py_encode_bundle_file(parsed)
            print(json.dumps({"status": "accept", "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii")}))
            return 0
        elif target == "manifest_file":
            parsed = py_decode_manifest_file(data)
            reencoded = py_encode_manifest_file(parsed)
            print(json.dumps({"status": "accept", "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii")}))
            return 0
        elif target == "block_file":
            parsed = py_decode_block_file(data)
            reencoded = py_encode_block_file(parsed)
            print(json.dumps({"status": "accept", "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii")}))
            return 0
        else:
            print(json.dumps({"status": "reject", "error_class": f"unknown target {target}"}))
            return 0
    except Exception as e:
        # Decoder rejected the input. Exception class is the error category.
        print(json.dumps({"status": "reject", "error_class": type(e).__name__}))
        return 0
```

- [ ] **Step 4: Implement the per-target Python encode/decode helpers**

For each target, the decoder logic mostly already exists in `conformance.py` for the §15 conformance check — find the existing implementations and refactor them into the `py_decode_<target>` / `py_encode_<target>` functions. Where a helper doesn't yet exist (e.g. `py_decode_vault_toml`, `py_decode_record`, `py_decode_contact_card`), write it from the spec docs only:

- `py_decode_vault_toml`: parse TOML, validate required fields per `docs/vault-format.md` §2.
- `py_decode_record`: canonical-CBOR-decode per `docs/vault-format.md` §6.2 / `docs/crypto-design.md` §11.1, re-encode and compare for canonicality (must match Rust's strict-canonical-input check).
- `py_decode_contact_card`: canonical-CBOR-decode per `docs/crypto-design.md` §5.x.
- `py_decode_bundle_file`, `py_decode_manifest_file`, `py_decode_block_file`: lift from existing §15 conformance logic.

For `py_encode_*`: deterministic canonical CBOR output matching Rust. Use `cbor2.dumps(..., canonical=True)` for the CBOR cases; for binary file formats, mirror the Rust encoder structure section by section.

**Constraint:** Python uses only the existing pinned PEP 723 deps (`cryptography`, `pynacl`, `pqcrypto`, `argon2-cffi`, `blake3`, `cbor2`) plus stdlib. No new deps.

- [ ] **Step 5: Smoke-test the new mode by hand**

```bash
uv run core/tests/python/conformance.py --diff-replay vault_toml core/fuzz/seeds/vault_toml/golden.toml
```

Expected stdout: `{"status": "accept", "reencoded_b64": ""}`.

```bash
uv run core/tests/python/conformance.py --diff-replay record core/fuzz/seeds/record/login.cbor
```

Expected stdout: `{"status": "accept", "reencoded_b64": "<base64-of-canonical-cbor>"}`.

Repeat for all six targets against their respective seed inputs.

- [ ] **Step 6: Verify the existing §15 conformance still works**

```bash
uv run core/tests/python/conformance.py
```

Expected: all conformance sections still pass (no regression from the `--diff-replay` addition).

- [ ] **Step 7: Verify Rust differential-replay test now passes (TDD-green)**

```bash
cargo test --release --workspace --features differential-replay --test differential_replay
```

Expected: PASS. Each seed roundtrips identically through Rust and Python.

- [ ] **Step 8: Verify default test suite still green**

```bash
cargo test --release --workspace
```

Expected: 405+ tests pass. No regressions.

- [ ] **Step 9: Commit**

```bash
git add core/tests/python/conformance.py
git commit -m "test(fuzz): add --diff-replay mode to conformance.py

Closes the TDD-red of the previous commit. Each per-target Python
decoder/encoder pair mirrors the Rust side per the relevant spec
sections; outputs structured JSON for the Rust-side replay test
to compare. Backward-compatible: existing conformance sections
unchanged."
```

---

## Task 11: `core/fuzz/README.md` and operator instructions

Document how to run the harness, install nightly, run with UBSan, promote findings, and run differential replay. The calibration-result tables stay empty for now; they're filled in in Tasks 12–13.

**Files:**
- Create: `core/fuzz/README.md`
- Modify: `README.md` (root) — add a one-paragraph cross-link to the fuzz README

- [ ] **Step 1: Create `core/fuzz/README.md`**

```markdown
# Fuzz harness

Coverage-guided fuzz harness for the six wire-format decoders that ingest
attacker-controlled bytes from disk. See the design spec at
[docs/superpowers/specs/2026-04-30-fuzz-harness-design.md](../../docs/superpowers/specs/2026-04-30-fuzz-harness-design.md)
for goals and exit criteria.

## Targets

| Target          | Decoder                                              | Oracle                |
|-----------------|------------------------------------------------------|-----------------------|
| `vault_toml`    | `unlock::vault_toml::decode`                         | crash only            |
| `record`        | `vault::record::decode`                              | crash + roundtrip-eq  |
| `contact_card`  | `identity::card::ContactCard::from_canonical_cbor`   | crash + roundtrip-eq  |
| `bundle_file`   | `unlock::bundle_file::decode`                        | crash + roundtrip-eq  |
| `manifest_file` | `vault::manifest::decode_manifest_file`              | crash + roundtrip-eq  |
| `block_file`    | `vault::block::decode_block_file`                    | crash + roundtrip-eq  |

## One-time setup

```bash
rustup install nightly                  # this dir's rust-toolchain.toml pins nightly
cargo install cargo-fuzz                # uses stable to install the binary
```

## Run a target

ASan (default):

```bash
cd core/fuzz
cargo fuzz run <target>
```

UBSan:

```bash
cd core/fuzz
cargo fuzz run --sanitizer=undefined <target>
```

Replay seeds only (no mutation):

```bash
cd core/fuzz
cargo fuzz run <target> seeds/<target>/ -- -runs=0
```

## Calibrated exec-count floors

Per the spec's hardware-independent stop signal, each target has a calibrated
exec-count floor (the floor below which the run is considered too short to
have plateaued). These floors were calibrated on the operator's reference
workstation; reproduce by running each target until libFuzzer reports zero
new `cov` and `corp` for the last ≥10% of executions.

| Target          | ASan exec floor | UBSan exec floor | Reference wall-clock (combined) |
|-----------------|-----------------|------------------|---------------------------------|
| `vault_toml`    | _TBD — fill in during Task 12_ | _TBD_ | _TBD_ |
| `record`        | _TBD_           | _TBD_            | _TBD_                           |
| `contact_card`  | _TBD_           | _TBD_            | _TBD_                           |
| `bundle_file`   | _TBD_           | _TBD_            | _TBD_                           |
| `manifest_file` | _TBD_           | _TBD_            | _TBD_                           |
| `block_file`    | _TBD_           | _TBD_            | _TBD_                           |

To run to floor:

```bash
cd core/fuzz
cargo fuzz run <target> -- -runs=<floor>
```

## Promoting a crash to a regression

When `cargo fuzz run` reports a crash, libFuzzer writes the offending input
to `core/fuzz/artifacts/<target>/crash-<hash>`. To promote:

```bash
# 1. Verify reproducibility
cd core/fuzz
cargo fuzz run <target> artifacts/<target>/crash-<hash>

# 2. Minimize
cargo fuzz tmin <target> artifacts/<target>/crash-<hash>
# This produces artifacts/<target>/minimized-from-crash-<hash>.

# 3. Copy to the durable regression dir
cp artifacts/<target>/minimized-from-crash-<hash> \
   ../tests/data/fuzz_regressions/<target>/<descriptive-name>.bin

# 4. Add a sibling .md describing the bug (optional but encouraged)
$EDITOR ../tests/data/fuzz_regressions/<target>/<descriptive-name>.md

# 5. Fix the bug in core/, then verify:
cd ..
cargo test --release --workspace --test fuzz_regressions
```

The regression test runs as part of `cargo test --release --workspace`
unconditionally — it does not depend on the fuzz harness or nightly.

## Differential replay (out-of-loop)

Runs the accumulated runtime corpus + committed seeds + diff_regressions
through both the Rust decoder and the Python clean-room decoder in
`core/tests/python/conformance.py`, asserting agreement.

```bash
# default cargo test stays Rust-only:
cargo test --release --workspace

# opt in to differential replay (requires uv):
cargo test --release --workspace --features differential-replay
```

A disagreement is one of: Rust bug → fix Rust; Python bug → fix Python;
spec ambiguity → docs PR alongside the fix. Sticky disagreements get
committed as inputs in `core/tests/data/diff_regressions/<target>/`.
```

- [ ] **Step 2: Add a one-paragraph cross-link to root `README.md`**

In the testing / development section of `README.md`, add:

```markdown
### Fuzzing

A coverage-guided fuzz harness for the wire-format decoders lives in
[`core/fuzz/`](core/fuzz/README.md). It uses `cargo-fuzz` on a
path-scoped nightly toolchain. See the README in that directory for
how to run it and how to promote findings into durable regression
KATs.
```

(Adapt the placement to fit the existing README structure — don't crowd unrelated sections.)

- [ ] **Step 3: Sanity-check the README by following its own instructions**

```bash
cd core/fuzz
cargo fuzz run vault_toml seeds/vault_toml/ -- -runs=0     # documented seed-replay command
```

If any documented command fails, fix the README before committing.

- [ ] **Step 4: Commit**

```bash
git add core/fuzz/README.md README.md
git commit -m "docs(fuzz): add core/fuzz/README.md operator guide"
```

---

## Task 12: Bug-bash calibration (operator-driven)

This task is operator-driven: it requires running fuzz campaigns on the operator's reference workstation and recording the empirical plateau exec counts. Cannot be fully automated; the steps describe the procedure.

**Files:**
- Modify: `core/fuzz/README.md` (fill in calibrated exec floors)

- [ ] **Step 1: Run `vault_toml` to plateau under ASan**

```bash
cd core/fuzz
# Run for a long fixed budget; observe the live `cov:` and `corp:` columns.
cargo fuzz run vault_toml -- -runs=10000000 -print_final_stats=1
```

Watch the output. libFuzzer prints lines like:

```
#100000  pulse  cov: 234 ft: 567 corp: 12/2k exec/s: 45000 rss: 64Mb
```

The plateau is reached when `cov` and `corp` stop increasing for ~10% of the run length. Note the exec count at first plateau.

If the run completes the full 10M execs, the plateau may have been earlier — re-run with smaller `-runs=` to bracket.

- [ ] **Step 2: Re-run UBSan to plateau**

```bash
cd core/fuzz
cargo fuzz run --sanitizer=undefined vault_toml -- -runs=2000000 -print_final_stats=1
```

UBSan generally needs fewer execs to plateau than ASan (less coverage instrumentation surface). Note the plateau exec count.

- [ ] **Step 3: Calibrate the other targets relative to `vault_toml`**

Smaller decoders generally plateau at lower exec counts than larger ones. Apply a rough scaling rule of thumb:
- `vault_toml`: 1× (baseline)
- `record`: ~1.5× (more code paths, but bounded)
- `contact_card`: ~1.5×
- `bundle_file`: ~3× (binary file format with header + body)
- `manifest_file`: ~5× (larger binary format)
- `block_file`: ~5× (largest binary format)

Use this as a starting point, but **verify by running each target to plateau** — don't rely on the scaling rule blindly.

```bash
cd core/fuzz
for target in record contact_card bundle_file manifest_file block_file; do
  echo "=== ASan: $target ==="
  cargo fuzz run "$target" -- -runs=10000000 -print_final_stats=1
  echo "=== UBSan: $target ==="
  cargo fuzz run --sanitizer=undefined "$target" -- -runs=2000000 -print_final_stats=1
done
```

(Optional: redirect to a log per target with `tee`.)

Record the plateau exec counts.

- [ ] **Step 4: Round each plateau exec count up to a clean number**

Pick the next round number ≥ 1.5× plateau (gives a safety margin so a future contributor on a slower machine still hits plateau). E.g. plateau at 730k → floor of 1M.

- [ ] **Step 5: Fill in the calibration table in `core/fuzz/README.md`**

Replace each `_TBD_` with the chosen floor and the observed wall-clock time. Example:

```markdown
| `vault_toml`    | 1,000,000      | 200,000          | ~25 min                         |
```

(Use the operator's actual numbers.)

- [ ] **Step 6: Commit calibration update**

```bash
git add core/fuzz/README.md
git commit -m "docs(fuzz): record calibrated per-target exec-count floors"
```

---

## Task 13: Bug-bash session per target (operator-driven)

Run each of the six targets to plateau under ASan + UBSan, in the spec's recommended order (smallest blast radius first). Promote any findings as they happen.

**Files (per finding):**
- Create: `core/tests/data/fuzz_regressions/<target>/<descriptive-name>.bin`
- Optional: `core/tests/data/fuzz_regressions/<target>/<descriptive-name>.md`
- Modify: whichever Rust file in `core/src/` contains the bug

- [ ] **Step 1: Run `vault_toml` to floor under ASan**

```bash
cd core/fuzz
cargo fuzz run vault_toml -- -runs=<vault_toml_asan_floor>
```

(Use the floor from Task 12 Step 5.)

If a crash is reported: follow the promotion procedure in `core/fuzz/README.md` (Task 11 Step 1). Fix the bug in `core/src/`. Verify `cargo test --release --workspace --test fuzz_regressions` is green. Commit fix + regression input together:

```bash
cd <repo-root>
git add core/src/<fixed-file> core/tests/data/fuzz_regressions/vault_toml/
git commit -m "fix(<module>): <one-line bug description> (fuzz finding)

Fuzz target: vault_toml. Crash class: <panic|assert|overflow|...>.
Regression input committed for cargo-test-survival.
"
```

After fix, **re-run the target from scratch** (don't resume from corpus) to confirm no further crashes:

```bash
cd core/fuzz
rm -rf corpus/vault_toml             # discard mutated corpus
cargo fuzz run vault_toml seeds/vault_toml/ -- -runs=<vault_toml_asan_floor>
```

If clean to floor with `cov` and `corp` flat for ≥10% of execs, target is done under ASan.

- [ ] **Step 2: Run `vault_toml` to floor under UBSan**

```bash
cd core/fuzz
cargo fuzz run --sanitizer=undefined vault_toml -- -runs=<vault_toml_ubsan_floor>
```

Same finding-handling procedure as Step 1.

- [ ] **Step 3: Repeat for each remaining target in order**

Order: `record` → `contact_card` → `bundle_file` → `manifest_file` → `block_file`.

For each: ASan run to floor → handle findings → UBSan run to floor → handle findings → confirm plateau achieved.

- [ ] **Step 4: Final clean-run smoke test of all targets**

After all findings fixed, run each target once more to confirm:

```bash
cd core/fuzz
for target in vault_toml record contact_card bundle_file manifest_file block_file; do
  echo "=== Final ASan run: $target ==="
  cargo fuzz run "$target" -- -runs=<asan_floor_for_$target>
done
```

Expected: each finishes without crash, `cov`/`corp` flat for ≥10% of run.

- [ ] **Step 5: Verify `cargo test` survives all promoted regressions**

```bash
cargo test --release --workspace
```

Expected: PASS, including all 6 `<target>_regressions_no_panic` tests. Test count = 405 + (number of promoted regressions).

- [ ] **Step 6: Commit any final operator notes**

If the bug-bash produced no findings (best case), no extra commit. If findings were committed inline (per Step 1), they're already on the branch.

If the operator wants a session report, add a one-paragraph summary to `core/fuzz/README.md` under a "Bug-bash log" section listing the targets run, exec counts achieved, and findings (with PR-style references).

---

## Task 14: Differential replay full-corpus run + close-out

Run the differential replay against the full accumulated corpus (post-bug-bash) and triage any disagreements. Close out the Phase A.7 fuzz sub-deliverable.

**Files:**
- Modify: `secretary_next_session.md`
- Possibly modify: `core/tests/python/conformance.py` (Python bug fixes)
- Possibly modify: any Rust source (Rust bug fixes)
- Possibly create: `core/tests/data/diff_regressions/<target>/<name>.bin`

- [ ] **Step 1: Run the differential replay against the full corpus**

```bash
cargo test --release --workspace --features differential-replay --test differential_replay
```

Expected: PASS — Rust and Python agree on every input in seeds/, runtime corpus/, and diff_regressions/.

If FAIL with disagreements: triage each one per the spec's Failure triage policy:
- Rust bug → fix Rust, no regression input commit needed (the fuzz_regressions test already covers crash classes; differential disagreements that aren't crashes are a different contract).
- Python bug → fix Python in conformance.py.
- Spec ambiguity → docs PR alongside the chosen interpretation.

For each *non-crash* sticky disagreement, commit the input to `core/tests/data/diff_regressions/<target>/<name>.bin` so the differential test continues to cover it after the fix.

- [ ] **Step 2: Verify all exit criteria from the spec**

Walk through the spec's Exit criteria (§ "Exit criteria") and confirm each:

1. Six fuzz targets compile and run.
   ```bash
   cd core/fuzz && cargo fuzz list
   ```
2. `cargo fuzz run <target> seeds/<target>/ -- -runs=0` is green for each target.
3. Each target run to floor under ASan + UBSan with plateau achieved, no unfixed findings.
4. Findings (if any) promoted; `cargo test --release --workspace --test fuzz_regressions` green.
5. README documents nightly install, target run, UBSan, finding promotion, differential replay, **and the calibrated floors are filled in**.
6. `cargo test --release --workspace --features differential-replay` green.
7. `cargo test --release --workspace` (default) green throughout.

- [ ] **Step 3: Update `secretary_next_session.md`**

Mark Phase A.7 item 2 (fuzz harness) as closed. The current entry-point file says Phase A.7 has 5 sub-items; this PR closes one. Update the Phase A.7 section:

Find the bullet starting with `- **Fuzz harness for the wire-format decoders**` in `secretary_next_session.md` and replace its body with a brief closure note. Concretely, change:

```markdown
- **Fuzz harness for the wire-format decoders** (`cargo fuzz`). Targets:
  `decode_block_file`, `decode_manifest`, `decode_identity_bundle`,
  `decode_record`, `decode_contact_card`. Coverage-guided; corpus
  seeded from the §15 KAT fixtures.
```

to:

```markdown
- **Fuzz harness for the wire-format decoders** ✅ — landed in
  `feature/fuzz-harness` (PR-D). Six cargo-fuzz targets in `core/fuzz/`,
  ASan + UBSan, hardware-independent calibrated floors recorded in
  `core/fuzz/README.md`. Crash regressions live in
  `core/tests/data/fuzz_regressions/<target>/` and run as part of
  `cargo test --release --workspace`. Out-of-loop differential replay
  against the Python clean-room decoder is gated by the
  `differential-replay` Cargo feature.
```

(Use the actual PR number once assigned.)

- [ ] **Step 4: Final full-suite green check**

```bash
cargo test --release --workspace
cargo test --release --workspace --features differential-replay
cargo clippy --all-targets -- -D warnings
```

Expected: all green.

- [ ] **Step 5: Final commit**

```bash
git add secretary_next_session.md
git commit -m "docs: mark Phase A.7 fuzz harness sub-deliverable closed"
```

- [ ] **Step 6: Push and open PR**

```bash
git push -u origin feature/fuzz-harness
gh pr create --title "Phase A.7 sub-deliverable: wire-format fuzz harness" --body "$(cat <<'EOF'
## Summary

Implements item 2 of the five Phase A.7 components per [docs/superpowers/specs/2026-04-30-fuzz-harness-design.md](docs/superpowers/specs/2026-04-30-fuzz-harness-design.md):

- Six cargo-fuzz targets in `core/fuzz/` covering all wire-format decoders.
- ASan default + UBSan separate run per target. MSan deferred.
- Hardware-independent stop signal: per-target calibrated exec-count floors + libFuzzer plateau detection.
- Crash repros promoted to `core/tests/data/fuzz_regressions/<target>/`, replayed by a normal `cargo test` integration test that does not depend on the fuzz harness.
- Out-of-loop differential replay against the Python clean-room decoder, gated by the `differential-replay` Cargo feature.
- One-time bug-bash run against all six targets; findings (if any) fixed and committed as regressions.

## Test plan

- [ ] `cargo test --release --workspace` green (default features, no Python)
- [ ] `cargo test --release --workspace --features differential-replay` green (with Python via uv)
- [ ] `cargo clippy --all-targets -- -D warnings` green
- [ ] `cd core/fuzz && cargo fuzz run <target> seeds/<target>/ -- -runs=0` green for each target
- [ ] All six target dirs under `core/tests/data/fuzz_regressions/` exist (with at minimum `.gitkeep`); promoted regressions execute on every `cargo test`
- [ ] `core/fuzz/README.md` documents the calibrated exec-count floors

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

(Mark off the Test plan items as you confirm them locally; reviewers see them already-checked.)

---

## Self-review checklist

After completing all tasks, verify:

1. **Spec coverage:**
   - §2 targets and oracles → Tasks 2–7 (one per target). ✓
   - §3 workspace layout → Task 1. ✓
   - §3.5 sanitizers and profile flags → Task 1 (profile in `Cargo.toml`); Task 13 (UBSan run). ✓
   - §4 seed corpus → embedded in Tasks 2–7. ✓
   - §5 regression mechanics → Task 8 (test), Task 13 (procedure used). ✓
   - §6 differential replay → Tasks 9–10. ✓
   - §7 bug-bash plan → Tasks 12–13. ✓
   - §8 exit criteria → Task 14 Step 2 (verification walkthrough). ✓
   - §9 build sequence → matches Tasks 1–14 order. ✓

2. **Hardware-independent stop signal:** Task 12 calibrates floors empirically; Task 13 runs to those floors with plateau-on-tail-10% observation. ✓

3. **No placeholders in plan body:** every code block is concrete; no "TBD" except in the README's calibration table that Task 12 fills in. The README's `_TBD_` markers are an *artifact* the calibration step replaces, not a placeholder in the plan itself. ✓
