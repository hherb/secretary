# B.2 — FFI Vault Unlock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `secretary_core::unlock::open_with_password` through both FFI flavors (PyO3 → Python; uniffi → Swift / Kotlin) via a new shared `secretary-ffi-bridge` crate that holds the FFI-friendly facade, plus a sibling `golden_vault_002` fixture for cross-vault `VaultMismatch` tests.

**Architecture:** Three-crate FFI layout. `secretary-ffi-bridge` owns the thinned 3-variant `FfiUnlockError` enum, the opaque `UnlockedIdentity` wrapper (with `Mutex<Option<core::UnlockedIdentity>>` for explicit-close idempotence), and the `open_with_password` body. `secretary-ffi-py` and `secretary-ffi-uniffi` are thin projections via PyO3 macros and uniffi UDL respectively. Both binding flavors share underlying methods → drift is a compile error. Foreign-side smoke runners use the env-var convention `SECRETARY_GOLDEN_VAULT_DIR` set by `run.sh`; pytest uses script-relative path resolution.

**Tech Stack:** Rust 1.87 stable, PyO3 0.28, uniffi (current pinned version in `secretary-ffi-uniffi/Cargo.toml`), maturin 1.9.4+, uv 0.6+, pytest, kotlinc 2.x, swiftc, JNA 5.14.0 (already pinned), thiserror, zeroize.

**Spec:** [docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md](../specs/2026-05-04-ffi-b2-vault-unlock-design.md)

**Worktree:** `.worktrees/feat-ffi-b2-vault-unlock/` on branch `feat/ffi-b2-vault-unlock`. Created as Pre-flight Task 0 below; the spec doc commit `86c4521` is already in place on `main` and inherits into the worktree.

---

## File structure

After all tasks complete, the FFI tree contains:

```
ffi/
├── secretary-ffi-bridge/                                    ← NEW (Task 3)
│   ├── Cargo.toml                                           ← NEW
│   ├── README.md                                            ← NEW (Task 11)
│   └── src/
│       ├── lib.rs                                           ← NEW (Task 3)
│       ├── error.rs                                         ← NEW (Task 4)
│       ├── identity.rs                                      ← NEW (Task 5)
│       └── unlock.rs                                        ← NEW (Task 6)
│
├── secretary-ffi-py/
│   ├── Cargo.toml                                           ← edit (Task 7)
│   ├── README.md                                            ← edit (Task 11)
│   ├── src/lib.rs                                           ← edit (Task 7)
│   └── tests/test_smoke.py                                  ← edit (Task 8)
│
└── secretary-ffi-uniffi/
    ├── Cargo.toml                                           ← edit (Task 9)
    ├── README.md                                            ← edit (Task 11)
    ├── src/
    │   ├── lib.rs                                           ← edit (Task 9)
    │   └── secretary.udl                                    ← edit (Task 9)
    └── tests/
        ├── swift/{main.swift, run.sh}                       ← edit (Task 10)
        └── kotlin/
            ├── Main.kt                                      ← edit (Task 10)
            ├── UnlockedIdentityExt.kt                       ← NEW (Task 10)
            └── run.sh                                       ← edit (Task 10)

core/tests/
├── common/                                                  ← NEW (Task 1)
│   ├── mod.rs                                               ← NEW
│   └── fixture_builder.rs                                   ← NEW (extracted from golden_vault_001.rs)
├── golden_vault_001.rs                                      ← edit (Task 1; thin caller of common)
├── golden_vault_002.rs                                      ← NEW (Task 2; thin caller of common)
├── data/
│   ├── golden_vault_001_inputs.json                         ← unchanged
│   ├── golden_vault_001/                                    ← unchanged (verify pinned bytes after Task 1)
│   ├── golden_vault_002_inputs.json                         ← NEW (Task 2)
│   └── golden_vault_002/                                    ← NEW (Task 2; bytes committed to git)
└── python/conformance.py                                    ← edit (Task 2; one-line comment only)

Cargo.toml (root)                                            ← edit (Task 3; add bridge crate to workspace)
README.md (root)                                             ← edit (Task 11)
ROADMAP.md                                                   ← edit (Task 11)
NEXT_SESSION.md                                              ← edit (Task 12)
docs/handoffs/2026-MM-DD-b2-vault-unlock.md                  ← NEW (Task 12)
```

**Decomposition rationale (recap from spec):**
- Bridge crate is **single source of code truth**; binding flavors are projections. Drift is impossible at compile time.
- Bridge crate is pure-safe Rust (no PyO3, no uniffi): `#![forbid(unsafe_code)]` from workspace applies, no carve-out needed.
- Tasks within Phase 7.3 (4-6) split by responsibility: error mapping, opaque-handle wrapper, business logic. Each file is small (~80-200 lines) and tested independently.
- Tasks within Phase 7.5 (9-10) keep UDL/glue separate from per-language smoke runners — UDL changes are reviewable as a single unit before the test layer adapts.
- Tasks 11 and 12 (docs / handoff) are the last commit cluster; READMEs and ROADMAP flip together.

---

## Pre-flight

### Task 0: Create the worktree

**Files:** none in repo; creates `.worktrees/feat-ffi-b2-vault-unlock/` and branch `feat/ffi-b2-vault-unlock`.

- [ ] **Step 1: Verify clean state on main**

```bash
cd /Users/hherb/src/secretary
git status
git log --oneline -3
```

Expected: clean working tree; `main` HEAD includes the spec commit `86c4521 docs(spec): add B.2 FFI vault unlock design (PR-pending)`.

- [ ] **Step 2: Verify all gates green before forking**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | awk -F: '{print $2}' | tr -s ' ' | head -10
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
```

Expected: all `test result: ok`, clippy reports `Finished`. If anything fails, STOP and triage before forking.

- [ ] **Step 3: Create worktree + branch**

```bash
git worktree add -b feat/ffi-b2-vault-unlock .worktrees/feat-ffi-b2-vault-unlock main
cd .worktrees/feat-ffi-b2-vault-unlock
git status
```

Expected: new branch on the same commit as main; clean status.

- [ ] **Step 4: Verify worktree is project-local (per user preference)**

```bash
git worktree list
```

Expected: the new worktree is at `.worktrees/feat-ffi-b2-vault-unlock` (relative to repo root), NOT in a global location.

All subsequent tasks run from inside the worktree at `.worktrees/feat-ffi-b2-vault-unlock/`.

---

## Phase 7.1 — Generator refactor

### Task 1: Extract shared fixture-build infrastructure

The 944-line `core/tests/golden_vault_001.rs` becomes a thin caller of new shared module `core/tests/common/`. Pure structural refactor — pinned bytes must remain unchanged.

**Files:**
- Create: `core/tests/common/mod.rs`
- Create: `core/tests/common/fixture_builder.rs`
- Modify: `core/tests/golden_vault_001.rs`

- [ ] **Step 1: Read the existing generator to identify extraction boundaries**

```bash
grep -nE "^(fn |struct |impl |use )" core/tests/golden_vault_001.rs | head -40
```

Identify the helpers to extract (generic, deterministic, no test-name dependency):
- Hex helpers: `parse_hex`, `nib`, `parse_hex_array`, `parse_uuid`, `format_uuid_hyphenated`, `hex_encode`
- Builders: `identity_from_inputs`, `signed_card_from`, `build_block_plaintext`, `build_identity_envelope`, `build_golden_vault`, `compose_aad`
- Path helpers: `fixture_root`, `inputs_path` — **these become parameterized over `(inputs_path: &Path, fixture_root: &Path)` rather than hardcoded**
- Input types: `Inputs`, `InputsIdentity`, `InputsBlockPlaintext`, etc. — `Deserialize` derives stay; struct definitions move to `common::fixture_builder`

What stays in `golden_vault_001.rs` (specific to vault_001):
- Constants for the inputs path / fixture root (passed into the shared builder calls)
- The four named tests: `generate_golden_inputs`, `materialize_golden_vault_001`, `golden_vault_001_pinned`, `golden_vault_001_bootstrap_dump`, `golden_vault_001_opens_with_password`
- The `dump` helper inside `generate_golden_inputs` (uses 0xA0 / 0xA1 / 0xA2 seeds — vault_001-specific)

- [ ] **Step 2: Create `core/tests/common/mod.rs`**

```rust
//! Shared infrastructure for the `golden_vault_NNN` integration tests.
//!
//! Each `golden_vault_NNN.rs` integration-test file is compiled as a separate
//! test binary, so we use Rust's special `tests/common/mod.rs` convention to
//! share helpers without producing an extra phantom test binary. The actual
//! code lives in [`fixture_builder`].

pub mod fixture_builder;
```

- [ ] **Step 3: Create `core/tests/common/fixture_builder.rs` by moving helpers from golden_vault_001.rs**

Move every function and struct identified in Step 1 from `golden_vault_001.rs` to `core/tests/common/fixture_builder.rs`. Adjust:

- `fn fixture_root() -> PathBuf { ... }` → REMOVE; callers now pass an explicit `&Path` argument.
- `fn inputs_path() -> PathBuf { ... }` → REMOVE; callers now pass an explicit `&Path` argument.
- `fn load_inputs() -> Inputs { ... }` → `pub fn load_inputs(inputs_path: &Path) -> Inputs { ... }`. Body reads the passed path instead of calling `inputs_path()`.
- `fn build_golden_vault(inputs: &Inputs) -> BTreeMap<PathBuf, Vec<u8>> { ... }` — body unchanged; signature unchanged. The function builds path-keyed bytes; the caller decides what root to render them under.
- All other helpers: `pub` visibility added; bodies unchanged.

Module-level use statements at the top of `fixture_builder.rs`:

```rust
//! Pure-function fixture builders for the `golden_vault_NNN` integration tests.
//!
//! Parameterized over `(inputs_path, fixture_root)` so a single implementation
//! produces both `golden_vault_001/` and `golden_vault_002/` from their
//! respective `_inputs.json` files.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;
use serde::Deserialize;

use secretary_core::crypto::aead;
use secretary_core::crypto::hash::hash as blake3_hash;
use secretary_core::crypto::kdf::{
    derive_master_kek, derive_recovery_kek, Argon2idParams, TAG_ID_BUNDLE, TAG_ID_WRAP_PW,
    TAG_ID_WRAP_REC,
};
use secretary_core::crypto::kem::{self, MlKem768Public, MlKem768Secret};
use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::crypto::sig::{
    self, Ed25519Public, Ed25519Secret, MlDsa65Public, MlDsa65Secret,
};
use secretary_core::unlock;
use secretary_core::unlock::bundle::IdentityBundle;
use secretary_core::vault::{block::BlockPlaintext, contact::ContactCard, manifest::Manifest, record::Record};
```

(Adjust imports if reading the existing file shows different surface.)

- [ ] **Step 4: Update `core/tests/golden_vault_001.rs` to call into `common`**

Top of file gains:

```rust
mod common;
use common::fixture_builder::{
    build_golden_vault, hex_encode, identity_from_inputs, load_inputs,
    Inputs, InputsIdentity,
    // ...add anything else used by the four named tests
};
```

(Remove the `use serde::Deserialize` if no longer needed at file scope; it stays in `fixture_builder.rs`.)

The five named tests call into the shared helpers:
- `inputs_path()` / `fixture_root()` calls → `Path::new("core/tests/data/golden_vault_001_inputs.json")` / `Path::new("core/tests/data/golden_vault_001")` literals or local `fn` helpers that return these literals.
- `load_inputs()` → `load_inputs(Path::new("core/tests/data/golden_vault_001_inputs.json"))`.
- `build_golden_vault(&inputs)` → unchanged (function signature didn't change).

The `generate_golden_inputs` test stays in `golden_vault_001.rs` verbatim (it's vault_001-specific because of the 0xA0 / 0xA1 / 0xA2 seeds).

- [ ] **Step 5: Verify the refactor preserves pinned bytes**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:|FAIL|panicked"
```

Expected: all tests pass with the same counts as the baseline (451 + 6 ignored). No `FAIL` or `panicked`.

```bash
git diff core/tests/data/golden_vault_001/
```

Expected: **no output** — the on-disk fixture must be byte-identical after the refactor. If `git diff` shows any changes, the refactor introduced a semantic difference; STOP and triage.

- [ ] **Step 6: Verify clippy and conformance**

```bash
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected: clippy clean, conformance PASS, spec freshness PASS.

- [ ] **Step 7: Commit**

```bash
git add core/tests/common/ core/tests/golden_vault_001.rs
git commit -m "$(cat <<'EOF'
refactor(tests): extract shared fixture_builder from golden_vault_001.rs

The 944-line generator becomes a thin caller of new
core/tests/common/fixture_builder.rs. Pure structural refactor:
no semantic changes, pinned bytes under core/tests/data/golden_vault_001/
unchanged.

Enables a sibling golden_vault_002/ fixture (next commit) to share
the same generator infrastructure without code duplication.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 7.2 — Create golden_vault_002

### Task 2: Author golden_vault_002 inputs + generator + on-disk fixture

**Files:**
- Create: `core/tests/golden_vault_002.rs`
- Create: `core/tests/data/golden_vault_002_inputs.json`
- Create (committed bytes): `core/tests/data/golden_vault_002/{vault.toml, identity.bundle.enc, manifest.cbor.enc, blocks/<uuid>.cbor.enc, contacts/...}`
- Modify (1-line comment): `core/tests/python/conformance.py`

- [ ] **Step 1: Create the thin caller `core/tests/golden_vault_002.rs`**

This file mirrors the four named tests in `golden_vault_001.rs` but uses different paths and seeds. Full content:

```rust
//! `golden_vault_002/` — sibling fixture for cross-vault FFI tests.
//!
//! Distinct vault_uuid + password from `golden_vault_001/`; otherwise built
//! by the same shared `common::fixture_builder` infrastructure. Used by
//! `secretary-ffi-bridge`'s integration tests and the foreign-side smoke
//! runners (Python pytest, Swift, Kotlin) to test the `VaultMismatch`
//! error path with a real second vault rather than a synthesized mutation.
//!
//! conformance.py intentionally stays at `golden_vault_001/` only — one
//! canonical fixture is sufficient for the spec-clean-room contract.
//! `golden_vault_002/` exists for FFI tests, not for spec verification.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::unlock;

mod common;
use common::fixture_builder::{
    build_golden_vault, hex_encode, load_inputs,
};

const INPUTS_PATH: &str = "core/tests/data/golden_vault_002_inputs.json";
const FIXTURE_ROOT: &str = "core/tests/data/golden_vault_002";

#[test]
#[ignore = "bootstrap helper; populate golden_vault_002_inputs.json via cargo test -- --ignored generate_golden_inputs_002 --nocapture"]
fn generate_golden_inputs_002() {
    fn dump(label: &str, seed: [u8; 32]) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let display = match label {
            "owner" => "Owner-002",
            "alice" => "Alice-002",
            "bob"   => "Bob-002",
            _       => "X-002",
        };
        let id = unlock::bundle::generate(display, 2_000_000_000_000, &mut rng);
        eprintln!("---- {label} ----");
        eprintln!("user_uuid:       {}", hex_encode(&id.user_uuid));
        eprintln!("x25519_sk:       {}", hex_encode(id.x25519_sk.expose()));
        eprintln!("x25519_pk:       {}", hex_encode(&id.x25519_pk));
        eprintln!("ml_kem_768_sk:   {}", hex_encode(id.ml_kem_768_sk.expose()));
        eprintln!("ml_kem_768_pk:   {}", hex_encode(&id.ml_kem_768_pk));
        eprintln!("ed25519_sk:      {}", hex_encode(id.ed25519_sk.expose()));
        eprintln!("ed25519_pk:      {}", hex_encode(&id.ed25519_pk));
        eprintln!("ml_dsa_65_seed:  {}", hex_encode(id.ml_dsa_65_sk.expose()));
        eprintln!("ml_dsa_65_pk:    {}", hex_encode(&id.ml_dsa_65_pk));
    }

    dump("owner", [0xB0; 32]);
    dump("alice", [0xB1; 32]);
    dump("bob",   [0xB2; 32]);
}

#[test]
#[ignore = "writes fixture bytes to disk; run after a deliberate format change"]
fn materialize_golden_vault_002() {
    let inputs = load_inputs(Path::new(INPUTS_PATH));
    let files: BTreeMap<_, _> = build_golden_vault(&inputs);
    let root = Path::new(FIXTURE_ROOT);
    for (rel, bytes) in &files {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&abs, bytes).expect("write");
    }
}

#[test]
fn golden_vault_002_pinned() {
    let inputs = load_inputs(Path::new(INPUTS_PATH));
    let freshly_built: BTreeMap<_, _> = build_golden_vault(&inputs);
    let root = Path::new(FIXTURE_ROOT);
    for (rel, expected) in &freshly_built {
        let abs = root.join(rel);
        let on_disk = std::fs::read(&abs).unwrap_or_else(|e| panic!("read {abs:?}: {e}"));
        assert_eq!(
            &on_disk, expected,
            "fixture file diverged from rebuilt bytes: {abs:?}"
        );
    }
}

#[test]
#[ignore = "diagnostic helper; dumps freshly-built bytes to stderr on drift"]
fn golden_vault_002_bootstrap_dump() {
    let inputs = load_inputs(Path::new(INPUTS_PATH));
    let files: BTreeMap<_, _> = build_golden_vault(&inputs);
    for (rel, bytes) in &files {
        eprintln!("---- {rel:?} ({} bytes) ----", bytes.len());
        eprintln!("{}", hex_encode(bytes));
    }
}

#[test]
fn golden_vault_002_opens_with_password() {
    let inputs = load_inputs(Path::new(INPUTS_PATH));
    let root = Path::new(FIXTURE_ROOT);
    let vault_toml = std::fs::read(root.join("vault.toml")).expect("read vault.toml");
    let bundle = std::fs::read(root.join("identity.bundle.enc")).expect("read bundle");
    let password = secretary_core::crypto::secret::SecretBytes::new(
        inputs.password.as_bytes().to_vec(),
    );
    let unlocked = unlock::open_with_password(&vault_toml, &bundle, &password)
        .expect("open_with_password golden_vault_002");
    assert_eq!(
        unlocked.identity.display_name, "Owner-002",
        "vault_002 owner display_name mismatch",
    );
}
```

- [ ] **Step 2: Run `generate_golden_inputs_002` to produce identity bytes**

```bash
cargo test --release --test golden_vault_002 -- --ignored generate_golden_inputs_002 --nocapture 2>&1 | grep -E "^----|^[a-z_]+:" | head -40
```

Expected: stderr dump of three identities (owner / alice / bob) with all key hex bytes. **Capture this output** — you'll paste it into `golden_vault_002_inputs.json` in the next step.

- [ ] **Step 3: Author `core/tests/data/golden_vault_002_inputs.json`**

Use `golden_vault_001_inputs.json` as the schema reference. Distinct fields:

```json
{
  "_format": "secretary-golden-vault-002 v1",
  "_doc": "Sibling fixture to golden_vault_001 — distinct vault_uuid and password to enable cross-vault tests of the VaultMismatch error path. Built by the same core/tests/common/fixture_builder.rs infrastructure. Identities (owner-002 / alice-002 / bob-002) come from `cargo test ... -- --ignored generate_golden_inputs_002 --nocapture`; everything else is human-authored. KDF params are sub-floor (memory_kib=8192) for test speed — open_with_password does NOT enforce the v1 floor on read, only create_vault enforces it on write.",

  "vault_uuid": "aabbccdd-eeff-0011-2233-445566778899",
  "block_uuid": "ffeeddcc-bbaa-9988-7766-554433221100",
  "device_uuid": "33445566-7788-9900-aabb-ccddeeff1122",
  "created_at_ms": 2000000000000,
  "last_mod_ms": 2000000000000,
  "password": "correct horse battery staple two",

  "kdf_params": {
    "_doc": "Sub-floor memory_kib (8192) for test speed; same justification as vault_001. open_with_password does not enforce the v1 floor on read.",
    "memory_kib": 8192,
    "iterations": 1,
    "parallelism": 1,
    "salt": "0202020202020202020202020202020202020202020202020202020202020202"
  },

  "rng_seed_for_aead_nonces": "0303030303030303030303030303030303030303030303030303030303030303",

  "owner": {
    "_doc": "Generated via cargo test -- --ignored generate_golden_inputs_002 (seed [0xB0; 32]).",
    "user_uuid": "<paste from Step 2 dump>",
    "display_name": "Owner-002",
    "created_at_ms": 2000000000000,
    "x25519_sk": "<paste>",
    "x25519_pk": "<paste>",
    "ml_kem_768_sk": "<paste>",
    "ml_kem_768_pk": "<paste>",
    "ed25519_sk": "<paste>",
    "ed25519_pk": "<paste>",
    "ml_dsa_65_seed": "<paste>",
    "ml_dsa_65_pk": "<paste>"
  },

  "alice": { /* analogous; seed [0xB1; 32]; display_name "Alice-002" */ },
  "bob":   { /* analogous; seed [0xB2; 32]; display_name "Bob-002"   */ },

  "block_plaintext": {
    "_doc": "One block with two records, distinct from vault_001's plaintext to keep the fixtures byte-distinct end-to-end.",
    "/* Schema: copy structure from golden_vault_001_inputs.json's block_plaintext, change record contents to distinct values (e.g. 'Email: owner-002@example.invalid', 'Password: hunter22'). */":
    null
  }
}
```

Open `core/tests/data/golden_vault_001_inputs.json` side-by-side and mirror the schema exactly. The `<paste>` fields fill in from the Step 2 dump.

- [ ] **Step 4: Materialize the on-disk fixture**

```bash
cargo test --release --test golden_vault_002 -- --ignored materialize_golden_vault_002 --nocapture 2>&1 | tail -5
ls core/tests/data/golden_vault_002/
```

Expected: directory contains `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, `blocks/<uuid>.cbor.enc`, and `contacts/<uuid>.cbor.enc` files (mirroring golden_vault_001's layout).

- [ ] **Step 5: Run the pinning test to confirm bytes are stable**

```bash
cargo test --release --test golden_vault_002 golden_vault_002_pinned 2>&1 | tail -5
cargo test --release --test golden_vault_002 golden_vault_002_opens_with_password 2>&1 | tail -5
```

Expected: both tests pass.

- [ ] **Step 6: Add the conformance.py explanatory comment**

In `core/tests/python/conformance.py`, locate the section header (around line 290 — search for `Section 2: golden_vault_001`). Add a comment block before it:

```python
# Note: conformance.py verifies golden_vault_001/ only. core/tests/data/
# also contains a golden_vault_002/ fixture used by the FFI integration
# tests (secretary-ffi-bridge, secretary-ffi-py, secretary-ffi-uniffi)
# to exercise the VaultMismatch error path with a real second vault.
# That fixture is intentionally out of scope here — one canonical fixture
# is sufficient for the spec-clean-room contract this script enforces.
# §15 cross-language conformance is a per-fixture property; vault_002
# does not need its own conformance check because it shares vault_001's
# build pipeline (core/tests/common/fixture_builder.rs).
```

(Adjust phrasing to match conformance.py's existing comment style.)

- [ ] **Step 7: Verify all gates green**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')
"
```

Expected: `TOTAL: 454 passed; 0 failed; 8 ignored` (451 baseline + 3 vault_002 named tests; 6 ignored baseline + 2 new vault_002 #[ignore] tests). The exact counts may differ by one or two depending on what the materialize/bootstrap tests count as — verify no failures.

```bash
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected: conformance PASS, spec freshness PASS (may need one allowlist entry for vault_002 test names; if so, run with `--audit-allowlist` and add per the script's instructions).

- [ ] **Step 8: Commit**

```bash
git add core/tests/golden_vault_002.rs core/tests/data/golden_vault_002_inputs.json core/tests/data/golden_vault_002/ core/tests/python/conformance.py
git commit -m "$(cat <<'EOF'
test(fixtures): add golden_vault_002 sibling for cross-vault FFI tests

Distinct vault_uuid (aabbccdd-...) and password ("correct horse battery
staple two") from golden_vault_001. Generated via the new
common::fixture_builder shared infrastructure; identities from
generate_golden_inputs_002 (seeds 0xB0 / 0xB1 / 0xB2).

Used by upcoming secretary-ffi-bridge integration tests (and the
Python / Swift / Kotlin smoke runners) to exercise the VaultMismatch
error path against a real second vault rather than a synthesized
mutation.

conformance.py stays scoped to golden_vault_001 — one canonical
fixture suffices for the spec-clean-room contract; the new fixture
exists for FFI tests, not spec verification. Comment added to
conformance.py making this explicit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 7.3 — secretary-ffi-bridge crate

### Task 3: Bridge crate skeleton

Set up the new workspace member with empty modules and unit-test scaffolding.

**Files:**
- Create: `ffi/secretary-ffi-bridge/Cargo.toml`
- Create: `ffi/secretary-ffi-bridge/src/lib.rs`
- Modify: `Cargo.toml` (root, add workspace member)

- [ ] **Step 1: Create `ffi/secretary-ffi-bridge/Cargo.toml`**

```toml
[package]
name = "secretary-ffi-bridge"
version = "0.1.0"
edition = "2021"
publish = false
description = "FFI-friendly facade of secretary-core; projected through PyO3 (secretary-ffi-py) and uniffi (secretary-ffi-uniffi). Single source of code truth for FFI thinned-error mapping and opaque-handle wrappers."

[lints]
workspace = true

[dependencies]
secretary-core = { path = "../../core" }
thiserror = "2.0"
zeroize = "1.8"
```

(Verify `thiserror` and `zeroize` versions match the workspace's existing pins by `grep "thiserror\|zeroize" core/Cargo.toml`.)

- [ ] **Step 2: Create `ffi/secretary-ffi-bridge/src/lib.rs`**

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
//! - [`FfiUnlockError`] — thinned 3-variant error type expressing
//!   user-actionable intent rather than mirroring `core::UnlockError`'s
//!   internal enum structure. See [`error`] module docs.
//! - [`UnlockedIdentity`] — opaque handle wrapping a successfully-unlocked
//!   `core::UnlockedIdentity`. Foreign callers hold a refcount and read
//!   non-secret fields via accessor methods; the secret keys stay Rust-
//!   side and zeroize on drop. See [`identity`] module docs.
//! - [`open_with_password`] — fallible, secret-bearing operation: vault
//!   unlock by master password. See [`unlock`] module docs.
//!
//! # Invariants
//!
//! - Pure-safe Rust. The workspace's `#![forbid(unsafe_code)]` applies
//!   without carve-out (the binding-flavor crates carry the FFI-macro
//!   `unsafe_code = "deny"` carve-outs locally).
//! - The `From<core::unlock::UnlockError>` impl in [`error`] uses explicit
//!   match arms with no wildcard so future core variants force a compile
//!   error instead of silently mapping to a default.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod identity;
pub mod unlock;

pub use error::FfiUnlockError;
pub use identity::UnlockedIdentity;
pub use unlock::open_with_password;
```

- [ ] **Step 3: Add the bridge crate to the workspace `Cargo.toml`**

In the root `Cargo.toml`, find `[workspace] members = [...]` and add `"ffi/secretary-ffi-bridge"`. (The workspace already excludes `core/fuzz`; preserve that.)

```toml
[workspace]
members = [
    "core",
    "ffi/secretary-ffi-py",
    "ffi/secretary-ffi-uniffi",
    "ffi/secretary-ffi-bridge",  # NEW
]
exclude = ["core/fuzz"]
```

- [ ] **Step 4: Create empty module files (compilation-friendly stubs)**

```bash
touch ffi/secretary-ffi-bridge/src/error.rs
touch ffi/secretary-ffi-bridge/src/identity.rs
touch ffi/secretary-ffi-bridge/src/unlock.rs
```

Each gets one stub line so `lib.rs`'s `pub mod` declarations don't fail:

```rust
// ffi/secretary-ffi-bridge/src/error.rs
//! Thinned FFI error type — see Task 4.
```

```rust
// ffi/secretary-ffi-bridge/src/identity.rs
//! Opaque UnlockedIdentity wrapper — see Task 5.
```

```rust
// ffi/secretary-ffi-bridge/src/unlock.rs
//! open_with_password free function — see Task 6.
```

The `pub use` lines in `lib.rs` will fail to compile because `FfiUnlockError`, `UnlockedIdentity`, and `open_with_password` don't exist yet. Comment those `pub use` lines out for now; uncomment as each module fills in.

- [ ] **Step 5: Verify the skeleton builds**

```bash
cargo check --release -p secretary-ffi-bridge 2>&1 | tail -10
```

Expected: `Finished` with no errors. Warnings about unused stubs are acceptable at this stage.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml ffi/secretary-ffi-bridge/
git commit -m "$(cat <<'EOF'
feat(ffi-bridge): skeleton crate with empty error/identity/unlock modules

New workspace member ffi/secretary-ffi-bridge/ holds the FFI-friendly
facade of secretary-core. Empty stubs for error.rs, identity.rs, and
unlock.rs that subsequent commits fill in.

Pure-safe Rust: workspace #![forbid(unsafe_code)] applies without
carve-out. The two binding-flavor crates (secretary-ffi-py,
secretary-ffi-uniffi) will depend on this once the modules are
populated.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: error.rs — FfiUnlockError + From impl + tests

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (uncomment `pub use error::FfiUnlockError`)

- [ ] **Step 1: Write failing tests for the error mapping**

Replace the stub `error.rs` with:

```rust
//! Thinned 3-variant FFI-friendly error type.
//!
//! `core::unlock::UnlockError` has 7 variants reachable from
//! `open_with_password`, three of which wrap inner enums with their own
//! variant counts (`MalformedVaultToml(VaultTomlError)`, etc.). Mirroring
//! exactly to the foreign side either re-exposes ~15 inner types per
//! language (huge surface, churns on every internal refactor) or collapses
//! inners to strings (anti-pattern; foreign callers parse strings to
//! understand failure causes).
//!
//! [`FfiUnlockError`] thins to 3 variants expressing **user-actionable
//! intent**:
//!
//! - [`FfiUnlockError::WrongPasswordOrCorrupt`] — "your password is wrong,
//!   try again". **Deliberately conflates wrong-password and corruption**
//!   per `docs/threat-model.md` §13's anti-oracle property; this MUST NOT
//!   be split into separate variants on the foreign side.
//! - [`FfiUnlockError::VaultMismatch`] — "vault.toml and identity.bundle.enc
//!   reference different vaults; re-pair from backups".
//! - [`FfiUnlockError::CorruptVault`] — collapses
//!   `{core::CorruptVault, all MalformedX, KdfFailure}`. Carries a
//!   diagnostic `message: String` for debugging; structured pattern-
//!   matching on the inner cause is intentionally not supported.

use thiserror::Error;

/// FFI-friendly thinned error type for `open_with_password`. See [module
/// docs](self) for the rationale.
#[derive(Debug, Error)]
pub enum FfiUnlockError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,

    /// `vault.toml` and `identity.bundle.enc` reference different vaults.
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    /// Vault is corrupt or unreadable. Carries a diagnostic message for
    /// debugging; not pattern-matchable on the inner cause.
    #[error("vault is corrupt or unreadable: {message}")]
    CorruptVault {
        /// Diagnostic text from the inner `core::UnlockError` variant's
        /// `Display` impl. Free-form; not part of the API contract.
        message: String,
    },
}

impl From<secretary_core::unlock::UnlockError> for FfiUnlockError {
    fn from(e: secretary_core::unlock::UnlockError) -> Self {
        use secretary_core::unlock::UnlockError as E;

        // Explicit match arms (no wildcard) so future core variants force a
        // compile error here. The defensive arms at the bottom map currently-
        // unreachable variants for forward-compat: if a future change to
        // `open_with_password` makes them reachable, they fold into
        // `CorruptVault { message }` rather than panicking.
        match e {
            E::WrongPasswordOrCorrupt => Self::WrongPasswordOrCorrupt,
            E::VaultMismatch => Self::VaultMismatch,

            E::CorruptVault
            | E::MalformedVaultToml(_)
            | E::MalformedBundleFile(_)
            | E::MalformedBundle(_)
            | E::KdfFailure(_) => Self::CorruptVault { message: e.to_string() },

            // Defensive forward-compat: variants currently unreachable from
            // open_with_password (they require open_with_recovery or
            // create_vault) but mapped here so a future core change doesn't
            // silently cause a panic at the FFI boundary.
            E::WrongMnemonicOrCorrupt
            | E::InvalidMnemonic(_)
            | E::WeakKdfParams { .. } => Self::CorruptVault { message: e.to_string() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::unlock::{
        bundle::BundleError, bundle_file::BundleFileError, vault_toml::VaultTomlError,
        UnlockError,
    };
    use secretary_core::crypto::kdf::KdfError;

    #[test]
    fn wrong_password_or_corrupt_maps_one_to_one() {
        let core_err = UnlockError::WrongPasswordOrCorrupt;
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn vault_mismatch_maps_one_to_one() {
        let core_err = UnlockError::VaultMismatch;
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::VaultMismatch));
    }

    #[test]
    fn corrupt_vault_collapses_to_corrupt_vault() {
        let core_err = UnlockError::CorruptVault;
        let ffi: FfiUnlockError = core_err.into();
        let FfiUnlockError::CorruptVault { message } = ffi else {
            panic!("expected CorruptVault");
        };
        assert!(message.contains("vault data integrity failure"));
    }

    #[test]
    fn malformed_vault_toml_collapses_to_corrupt_vault_with_inner_display() {
        let inner = VaultTomlError::MissingField("kdf".to_string());
        let core_err = UnlockError::MalformedVaultToml(inner);
        let ffi: FfiUnlockError = core_err.into();
        let FfiUnlockError::CorruptVault { message } = ffi else {
            panic!("expected CorruptVault");
        };
        assert!(message.contains("malformed vault.toml"));
        assert!(message.contains("kdf"));
    }

    #[test]
    fn malformed_bundle_file_collapses_to_corrupt_vault() {
        let inner = BundleFileError::TruncatedHeader;
        let core_err = UnlockError::MalformedBundleFile(inner);
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn malformed_bundle_collapses_to_corrupt_vault() {
        let inner = BundleError::MalformedCbor("bad header".to_string());
        let core_err = UnlockError::MalformedBundle(inner);
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn kdf_failure_collapses_to_corrupt_vault() {
        let inner = KdfError::OutputLengthOutOfRange;
        let core_err = UnlockError::KdfFailure(inner);
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn wrong_mnemonic_or_corrupt_maps_defensively_to_corrupt_vault() {
        // Currently unreachable through open_with_password (only
        // open_with_recovery returns this). Defensive forward-compat
        // mapping so a future core change can't introduce a panic at
        // the FFI boundary silently.
        let core_err = UnlockError::WrongMnemonicOrCorrupt;
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn weak_kdf_params_maps_defensively_to_corrupt_vault() {
        let core_err = UnlockError::WeakKdfParams {
            memory_kib: 8,
            min_memory_kib: 65536,
        };
        let ffi: FfiUnlockError = core_err.into();
        assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
    }

    #[test]
    fn display_format_is_stable_for_each_variant() {
        // Pin the Display strings so foreign-side tests asserting against
        // them don't drift silently.
        assert_eq!(
            FfiUnlockError::WrongPasswordOrCorrupt.to_string(),
            "wrong password or vault corruption",
        );
        assert_eq!(
            FfiUnlockError::VaultMismatch.to_string(),
            "vault.toml and identity.bundle.enc reference different vaults",
        );
        let corrupt = FfiUnlockError::CorruptVault {
            message: "fnord".to_string(),
        };
        assert_eq!(
            corrupt.to_string(),
            "vault is corrupt or unreadable: fnord",
        );
    }
}
```

(If any of `BundleFileError::TruncatedHeader`, `BundleError::MalformedCbor`, `KdfError::OutputLengthOutOfRange`, or `VaultTomlError::MissingField` aren't actually variant names in the current core, adjust the test to use whatever variant name does exist — `grep -E "^pub enum (VaultTomlError|BundleFileError|BundleError|KdfError)" -A 30 core/src/` to confirm. Each test only needs *some* variant of each inner type to verify the wrapping arm is reached.)

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --release -p secretary-ffi-bridge --lib 2>&1 | tail -10
```

Expected: 10 tests, all failing or — depending on whether the `From` impl is in place — passing already if we wrote the impl + tests in one go. (Per TDD discipline, we'd ideally write the tests first; in practice for a mechanical mapping the From impl is co-authored with its tests.) If they pass on first run, **review the From impl manually** to ensure it's correct, not just vacuously matching.

- [ ] **Step 3: Uncomment the `pub use` line in `lib.rs`**

```rust
// ffi/secretary-ffi-bridge/src/lib.rs
pub use error::FfiUnlockError;   // uncomment this
// pub use identity::UnlockedIdentity;   // still commented; Task 5
// pub use unlock::open_with_password;   // still commented; Task 6
```

- [ ] **Step 4: Verify all 10 error tests pass**

```bash
cargo test --release -p secretary-ffi-bridge --lib 2>&1 | tail -5
```

Expected: `test result: ok. 10 passed; 0 failed`.

- [ ] **Step 5: Verify clippy clean**

```bash
cargo clippy --release -p secretary-ffi-bridge -- -D warnings && echo "OK"
```

Expected: `OK`.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/error.rs ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-bridge): FfiUnlockError + From<core::UnlockError> mapping

Thinned 3-variant error type expressing user-actionable intent rather
than mirroring core's 7-variant internal structure. Inner-error-wrapped
variants (MalformedVaultToml, MalformedBundleFile, MalformedBundle,
KdfFailure) collapse into CorruptVault { message } with the inner
Display preserved for diagnostics.

Defensive forward-compat: WrongMnemonicOrCorrupt, InvalidMnemonic, and
WeakKdfParams (currently unreachable from open_with_password) also map
to CorruptVault rather than panicking, in case future core changes
make them reachable.

Security-property note documented inline: WrongPasswordOrCorrupt
deliberately conflates wrong-password and corruption per threat-model
§13's anti-oracle property; MUST NOT be split on the foreign side.

10 unit tests pin the variant mappings + Display format stability.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: identity.rs — UnlockedIdentity wrapper + tests

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/identity.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (uncomment `pub use identity::UnlockedIdentity`)

- [ ] **Step 1: Write the wrapper + tests**

Replace the stub `identity.rs` with:

```rust
//! Opaque foreign-side handle to a successfully-unlocked vault identity.
//!
//! The wrapped `core::unlock::UnlockedIdentity` carries ~2.5 KB of
//! `Sensitive<...>`-wrapped secret material (the 32-byte IBK plus four
//! secret keys: X25519, ML-KEM-768, Ed25519, ML-DSA-65). Foreign callers
//! hold a refcount and read non-secret fields via accessor methods; the
//! secret state stays Rust-side and zeroizes on drop.
//!
//! # Lifecycle
//!
//! [`UnlockedIdentity::close`] explicitly drops the wrapped identity now
//! (zeroizing all `Sensitive<...>` fields at exactly this moment instead
//! of waiting for foreign GC). It is **idempotent** — multiple calls do
//! not panic. Subsequent accessor calls on a closed handle return empty
//! / zero values rather than panicking, keeping the API non-throwing.
//!
//! RAII is the safety net: when the foreign-side reference releases, the
//! Rust-side `Drop` cascade still runs.

use std::sync::Mutex;

/// Opaque handle to an unlocked vault identity. See [module docs](self).
pub struct UnlockedIdentity {
    /// Wrapped behind a `Mutex<Option<...>>` to provide:
    /// - **idempotent close** via `Option::take()`
    /// - **thread-safe accessors** (lock is short — clone a String or copy
    ///   16 bytes — for sub-microsecond read overhead)
    /// - **use-after-close non-throwing** semantics (`as_ref()` on `None`
    ///   yields default values via `unwrap_or_default()`)
    inner: Mutex<Option<secretary_core::unlock::UnlockedIdentity>>,
}

impl UnlockedIdentity {
    /// Wrap a freshly-unlocked `core::UnlockedIdentity`. Crate-private:
    /// only [`crate::unlock::open_with_password`] constructs this.
    pub(crate) fn new(inner: secretary_core::unlock::UnlockedIdentity) -> Self {
        Self { inner: Mutex::new(Some(inner)) }
    }

    /// User-facing display name from the IdentityBundle. UTF-8.
    ///
    /// Returns `""` if the handle has been explicitly closed.
    pub fn display_name(&self) -> String {
        self.inner
            .lock()
            .expect("UnlockedIdentity mutex poisoned")
            .as_ref()
            .map(|id| id.identity.display_name.clone())
            .unwrap_or_default()
    }

    /// 16-byte stable identifier from the IdentityBundle.
    ///
    /// Returns `vec![0u8; 16]` if the handle has been explicitly closed.
    pub fn user_uuid(&self) -> Vec<u8> {
        self.inner
            .lock()
            .expect("UnlockedIdentity mutex poisoned")
            .as_ref()
            .map(|id| id.identity.user_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// Drop the wrapped identity now, zeroizing all `Sensitive<...>`
    /// fields at exactly this moment. **Idempotent** — multiple calls do
    /// not panic.
    pub fn close(&self) {
        let _drop = self.inner
            .lock()
            .expect("UnlockedIdentity mutex poisoned")
            .take();
        // _drop goes out of scope here → core::UnlockedIdentity drops →
        // Sensitive<...> ZeroizeOnDrop runs for every secret field.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_core::crypto::kdf::Argon2idParams;
    use secretary_core::unlock::create_vault_unchecked;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    /// Helper: build a fresh UnlockedIdentity by creating + opening a
    /// throwaway vault. Keeps the test isolated from the on-disk fixtures
    /// (which are exercised by the integration tests in unlock.rs).
    fn fresh_unlocked_identity() -> UnlockedIdentity {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let params = Argon2idParams::new(8, 1, 1);
        let v = create_vault_unchecked(&password, "TestUser", 0, params, &mut rng).unwrap();
        let opened = secretary_core::unlock::open_with_password(
            &v.vault_toml_bytes,
            &v.identity_bundle_bytes,
            &password,
        ).unwrap();
        UnlockedIdentity::new(opened)
    }

    #[test]
    fn display_name_returns_unlocked_identity_display_name() {
        let id = fresh_unlocked_identity();
        assert_eq!(id.display_name(), "TestUser");
    }

    #[test]
    fn user_uuid_returns_16_bytes() {
        let id = fresh_unlocked_identity();
        let uuid = id.user_uuid();
        assert_eq!(uuid.len(), 16);
    }

    #[test]
    fn close_then_display_name_returns_empty() {
        let id = fresh_unlocked_identity();
        id.close();
        assert_eq!(id.display_name(), "");
    }

    #[test]
    fn close_then_user_uuid_returns_zero_bytes() {
        let id = fresh_unlocked_identity();
        id.close();
        assert_eq!(id.user_uuid(), vec![0u8; 16]);
    }

    #[test]
    fn close_is_idempotent() {
        let id = fresh_unlocked_identity();
        id.close();
        id.close();  // second call must not panic
        id.close();  // third call must not panic
        assert_eq!(id.display_name(), "");
    }

    #[test]
    fn accessors_thread_safe_with_close() {
        // Smoke test: spawn a reader thread; main thread closes; reader
        // gets a valid (possibly empty) string, never a panic.
        use std::sync::Arc;
        let id = Arc::new(fresh_unlocked_identity());
        let id2 = Arc::clone(&id);
        let handle = std::thread::spawn(move || {
            for _ in 0..1000 {
                let _ = id2.display_name();
            }
        });
        for _ in 0..500 {
            let _ = id.display_name();
        }
        id.close();
        handle.join().expect("reader thread panicked");
        // Post-join, all accessors return defaults.
        assert_eq!(id.display_name(), "");
        assert_eq!(id.user_uuid(), vec![0u8; 16]);
    }
}
```

(If `Argon2idParams::new` or `create_vault_unchecked` have different signatures than shown, adjust to match — `grep -E "pub (fn|struct) (Argon2idParams|create_vault_unchecked)" core/src/`.)

- [ ] **Step 2: Run tests**

```bash
cargo test --release -p secretary-ffi-bridge --lib identity:: 2>&1 | tail -10
```

Expected: 6 tests pass.

- [ ] **Step 3: Uncomment the lib.rs `pub use`**

```rust
// ffi/secretary-ffi-bridge/src/lib.rs
pub use error::FfiUnlockError;
pub use identity::UnlockedIdentity;          // uncomment
// pub use unlock::open_with_password;       // still commented; Task 6
```

- [ ] **Step 4: Verify all bridge tests pass**

```bash
cargo test --release -p secretary-ffi-bridge --lib 2>&1 | tail -5
cargo clippy --release -p secretary-ffi-bridge -- -D warnings && echo "OK"
```

Expected: 16 tests pass (10 error + 6 identity); clippy OK.

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/identity.rs ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-bridge): UnlockedIdentity opaque wrapper with explicit close

Wraps core::unlock::UnlockedIdentity in a Mutex<Option<...>> for:
- idempotent close() via Option::take()
- thread-safe accessors (sub-microsecond locks)
- use-after-close non-throwing (returns "" / [0u8;16])
- prompt zeroize via Sensitive<...> ZeroizeOnDrop cascade on close()

Two non-secret accessors: display_name() -> String, user_uuid() ->
Vec<u8> (16 bytes). The IBK + four secret keys stay inside the
inner core::UnlockedIdentity and never cross the Rust boundary.

6 unit tests pin the accessor passthrough, idempotent close, and
thread-safe behavior.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: unlock.rs — open_with_password free function + tests

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/unlock.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (uncomment `pub use unlock::open_with_password`)

- [ ] **Step 1: Write the function + integration tests**

Replace the stub `unlock.rs` with:

```rust
//! `open_with_password` — fallible, secret-bearing operation: vault unlock
//! by master password.
//!
//! FFI-friendly wrapper around `secretary_core::unlock::open_with_password`.
//! Maps the `Result<core::UnlockedIdentity, core::UnlockError>` shape to
//! `Result<UnlockedIdentity, FfiUnlockError>` (thinned + opaque).
//!
//! The input password slice is wrapped in [`SecretBytes`], which zeroizes
//! on drop. The caller's foreign-side buffer is the caller's concern —
//! see the per-language READMEs for the documented discipline.

use crate::{FfiUnlockError, UnlockedIdentity};

/// Unlock a vault using its master password. Returns an opaque handle
/// that exposes non-secret accessors and an explicit `close()`.
///
/// # Errors
///
/// - [`FfiUnlockError::WrongPasswordOrCorrupt`] — password is wrong, OR
///   one of the encrypted files has been tampered with. Indistinguishable
///   by design (anti-oracle property).
/// - [`FfiUnlockError::VaultMismatch`] — `vault_toml_bytes` and
///   `identity_bundle_bytes` reference different vault UUIDs / timestamps.
/// - [`FfiUnlockError::CorruptVault`] — the inputs cannot be decoded as
///   well-formed v1 vault files.
pub fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: &[u8],
) -> Result<UnlockedIdentity, FfiUnlockError> {
    let pw = secretary_core::crypto::secret::SecretBytes::new(password.to_vec());
    let unlocked = secretary_core::unlock::open_with_password(
        vault_toml_bytes,
        identity_bundle_bytes,
        &pw,
    )?;
    Ok(UnlockedIdentity::new(unlocked))
    // pw drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    // The caller's foreign-side password buffer is THEIR concern.
}

#[cfg(test)]
mod tests {
    use super::*;

    // Embed the on-disk fixtures via include_bytes! so the integration
    // tests don't depend on test-time filesystem layout.
    const VAULT_001_TOML: &[u8] = include_bytes!(
        "../../../core/tests/data/golden_vault_001/vault.toml"
    );
    const VAULT_001_BUNDLE: &[u8] = include_bytes!(
        "../../../core/tests/data/golden_vault_001/identity.bundle.enc"
    );
    const VAULT_002_TOML: &[u8] = include_bytes!(
        "../../../core/tests/data/golden_vault_002/vault.toml"
    );
    const VAULT_002_BUNDLE: &[u8] = include_bytes!(
        "../../../core/tests/data/golden_vault_002/identity.bundle.enc"
    );

    const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";
    const VAULT_001_OWNER_DISPLAY_NAME: &str = "Owner";
    /// Pinned KAT: hex `bf08a3300cd994b877e1a15baa28df35` from
    /// golden_vault_001_inputs.json. If this changes, all FFI smoke
    /// runners must update in the same commit.
    const VAULT_001_OWNER_USER_UUID: &[u8] = &[
        0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8,
        0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf, 0x35,
    ];

    #[test]
    fn open_with_password_success_returns_unlocked_handle() {
        let id = open_with_password(
            VAULT_001_TOML, VAULT_001_BUNDLE, VAULT_001_PASSWORD,
        ).expect("unlock should succeed");
        assert_eq!(id.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
        assert_eq!(id.user_uuid(), VAULT_001_OWNER_USER_UUID);
    }

    #[test]
    fn open_with_password_wrong_password_returns_thinned_error() {
        let err = open_with_password(
            VAULT_001_TOML, VAULT_001_BUNDLE, b"definitely the wrong password",
        ).unwrap_err();
        assert!(matches!(err, FfiUnlockError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn open_with_password_swapped_files_returns_vault_mismatch() {
        // Pair vault_001's vault.toml with vault_002's identity.bundle.enc.
        // Since they reference different vault_uuid + created_at_ms, the
        // cross-check in core::open_with_password fails before any KDF
        // work — surfaces as VaultMismatch.
        let err = open_with_password(
            VAULT_001_TOML, VAULT_002_BUNDLE, VAULT_001_PASSWORD,
        ).unwrap_err();
        assert!(
            matches!(err, FfiUnlockError::VaultMismatch),
            "expected VaultMismatch, got {err:?}",
        );
    }

    #[test]
    fn open_with_password_truncated_vault_toml_returns_corrupt_vault() {
        // Slice off the last 50 bytes of vault.toml — produces invalid TOML.
        let truncated = &VAULT_001_TOML[..VAULT_001_TOML.len().saturating_sub(50)];
        let err = open_with_password(
            truncated, VAULT_001_BUNDLE, VAULT_001_PASSWORD,
        ).unwrap_err();
        assert!(
            matches!(err, FfiUnlockError::CorruptVault { .. }),
            "expected CorruptVault, got {err:?}",
        );
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test --release -p secretary-ffi-bridge --lib unlock:: 2>&1 | tail -10
```

Expected: 4 tests pass.

- [ ] **Step 3: Uncomment the lib.rs `pub use`**

```rust
// ffi/secretary-ffi-bridge/src/lib.rs
pub use error::FfiUnlockError;
pub use identity::UnlockedIdentity;
pub use unlock::open_with_password;          // uncomment
```

- [ ] **Step 4: Verify all bridge tests pass**

```bash
cargo test --release -p secretary-ffi-bridge 2>&1 | tail -5
cargo clippy --release -p secretary-ffi-bridge -- -D warnings && echo "OK"
```

Expected: 20 tests pass (10 error + 6 identity + 4 unlock); clippy OK.

- [ ] **Step 5: Verify workspace baseline**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')
"
```

Expected: `TOTAL: 474 passed; 0 failed; 8 ignored` (454 after Phase 7.2 + 20 bridge crate). Adjust if exact counts differ — the load-bearing assertion is "no failures, +20 net from before Task 4".

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/unlock.rs ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-bridge): open_with_password with thinned-error mapping + tests

Free function wrapping secretary_core::unlock::open_with_password,
returning Result<UnlockedIdentity, FfiUnlockError>. Input password
slice wrapped in SecretBytes (zeroize-on-drop); caller's foreign-
side buffer is the caller's concern (documented in READMEs).

4 integration tests against the include_bytes!-embedded golden_vault
fixtures:
- success returns the pinned display_name + user_uuid for vault_001
- wrong password yields WrongPasswordOrCorrupt
- vault_001 vault.toml + vault_002 bundle yields VaultMismatch
- truncated vault.toml yields CorruptVault

Bridge crate baseline: 20 tests passing, clippy clean. Workspace
baseline grows from ~454 → ~474.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 7.4 — secretary-ffi-py projection

### Task 7: PyO3 wrapper + exception classes

**Files:**
- Modify: `ffi/secretary-ffi-py/Cargo.toml`
- Modify: `ffi/secretary-ffi-py/src/lib.rs`

- [ ] **Step 1: Add bridge dependency**

Edit `ffi/secretary-ffi-py/Cargo.toml`:

```toml
[dependencies]
pyo3 = "0.28"
secretary-core = { path = "../../core" }
secretary-ffi-bridge = { path = "../secretary-ffi-bridge" }   # NEW
```

(Verify the existing `pyo3` and `secretary-core` lines — adjust as needed.)

- [ ] **Step 2: Edit `ffi/secretary-ffi-py/src/lib.rs` to add unlock surface**

Add after the existing `add` / `version_py` / `secretary_ffi_py` (#[pymodule]) functions, before `mod tests`:

```rust
// ---------------------------------------------------------------------------
// B.2: open_with_password + UnlockedIdentity + exception classes.
//
// The actual logic lives in secretary-ffi-bridge; this file is the PyO3
// projection layer.
// ---------------------------------------------------------------------------

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::types::{PyBytes, PyType};
use secretary_ffi_bridge::FfiUnlockError;

create_exception!(secretary_ffi_py, WrongPasswordOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultMismatch, PyException);
create_exception!(secretary_ffi_py, CorruptVault, PyException);

/// Convert a bridge-crate `FfiUnlockError` into the appropriate Python
/// exception. Routed via `From<FfiUnlockError> for PyErr`.
fn ffi_unlock_error_to_pyerr(e: FfiUnlockError) -> PyErr {
    match e {
        FfiUnlockError::WrongPasswordOrCorrupt =>
            WrongPasswordOrCorrupt::new_err(e.to_string()),
        FfiUnlockError::VaultMismatch =>
            VaultMismatch::new_err(e.to_string()),
        FfiUnlockError::CorruptVault { message } =>
            CorruptVault::new_err(message),
    }
}

/// Opaque Python-side handle to a successfully-unlocked vault identity.
/// Newtype around `secretary_ffi_bridge::UnlockedIdentity`; methods are
/// thin forwarders. Implements the context-manager protocol so the
/// idiomatic usage is `with open_with_password(...) as id: ...`.
#[pyclass]
pub struct UnlockedIdentity(secretary_ffi_bridge::UnlockedIdentity);

#[pymethods]
impl UnlockedIdentity {
    /// User-facing display name from the IdentityBundle. Returns `""` if
    /// the handle has been explicitly closed.
    fn display_name(&self) -> String {
        self.0.display_name()
    }

    /// 16-byte stable identifier from the IdentityBundle. Returns
    /// `b'\\x00' * 16` if the handle has been explicitly closed.
    fn user_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.user_uuid())
    }

    /// Drop the wrapped identity now, zeroizing all secret fields at
    /// exactly this moment. Idempotent.
    fn close(&self) {
        self.0.close();
    }

    /// Context-manager `__enter__`. Returns `self` so `with ... as id`
    /// binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context-manager `__exit__`. Calls `close()` and returns `False`
    /// so any exception raised inside the `with`-block propagates after
    /// close runs.
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyType>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.0.close();
        false
    }
}

/// Unlock a vault using its master password. See module-level docs for
/// the exception classes raised on failure.
#[pyfunction]
fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: &[u8],
) -> PyResult<UnlockedIdentity> {
    secretary_ffi_bridge::open_with_password(
        vault_toml_bytes, identity_bundle_bytes, password,
    )
    .map(UnlockedIdentity)
    .map_err(ffi_unlock_error_to_pyerr)
}
```

- [ ] **Step 3: Update the `#[pymodule]` to register the new symbols**

Find the existing `#[pymodule] fn secretary_ffi_py(...)` and add registration calls:

```rust
#[pymodule]
fn secretary_ffi_py(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Existing B.1 surface:
    m.add_function(wrap_pyfunction!(add, m)?)?;
    m.add_function(wrap_pyfunction!(version_py, m)?)?;

    // B.2 surface:
    m.add_class::<UnlockedIdentity>()?;
    m.add_function(wrap_pyfunction!(open_with_password, m)?)?;
    m.add("WrongPasswordOrCorrupt", py.get_type::<WrongPasswordOrCorrupt>())?;
    m.add("VaultMismatch", py.get_type::<VaultMismatch>())?;
    m.add("CorruptVault", py.get_type::<CorruptVault>())?;

    Ok(())
}
```

(If the existing `#[pymodule]` signature didn't take `py: Python<'_>`, adjust it — the new exception registration calls need a `Python` token.)

- [ ] **Step 4: Build the wheel + run cargo tests**

```bash
cargo test --release -p secretary-ffi-py --lib 2>&1 | tail -5
```

Expected: existing 3 tests still pass (`add`, `version`, `add wrap`).

- [ ] **Step 5: Verify workspace + clippy**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | tail -5
cargo clippy --release --workspace -- -D warnings && echo "OK"
```

Expected: workspace baseline unchanged at ~474 (no new Rust unit tests in this task; the new logic is exercised by Python tests in Task 8). Clippy OK.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-py/Cargo.toml ffi/secretary-ffi-py/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-py): PyO3 projection of open_with_password + UnlockedIdentity

Adds secretary-ffi-bridge dependency. Wraps the bridge crate's
UnlockedIdentity in a #[pyclass] newtype with method forwarders
plus __enter__ / __exit__ for context-manager support (`with
open_with_password(...) as id: ...`).

Three exception classes (WrongPasswordOrCorrupt, VaultMismatch,
CorruptVault) registered at the module level via create_exception!.
A From<FfiUnlockError> for PyErr-style routing function picks the
right class per variant.

Existing B.1 add() / version() surface unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Python pytest tests + maturin build

**Files:**
- Modify: `ffi/secretary-ffi-py/tests/test_smoke.py`

- [ ] **Step 1: Read the existing test file's structure**

```bash
cat ffi/secretary-ffi-py/tests/test_smoke.py
```

Note the existing import + fixture patterns; add the new tests in the same style.

- [ ] **Step 2: Add unlock tests**

Append to `ffi/secretary-ffi-py/tests/test_smoke.py`:

```python
# ---------------------------------------------------------------------------
# B.2: open_with_password tests against golden_vault_001 + golden_vault_002.
# ---------------------------------------------------------------------------

from pathlib import Path
import pytest


def _golden_vault_dir(n: int) -> Path:
    """Resolve `core/tests/data/golden_vault_{n:03d}/` relative to this test
    file. Walks up 3 parents from `ffi/secretary-ffi-py/tests/` to repo root.
    """
    return Path(__file__).resolve().parents[3] / "core" / "tests" / "data" / f"golden_vault_{n:03d}"


def _read_fixture(n: int, name: str) -> bytes:
    return (_golden_vault_dir(n) / name).read_bytes()


# Pinned KAT values — must match secretary-ffi-bridge's tests and the
# golden_vault_001_inputs.json source of truth. KAT drift cannot land
# silently: bridge tests + this file + Swift/Kotlin smoke runners all
# pin the same values.
VAULT_001_PASSWORD = b"correct horse battery staple"
VAULT_001_OWNER_DISPLAY_NAME = "Owner"
VAULT_001_OWNER_USER_UUID = bytes.fromhex("bf08a3300cd994b877e1a15baa28df35")


def test_open_with_password_success_returns_pinned_identity():
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
        assert identity.user_uuid() == VAULT_001_OWNER_USER_UUID


def test_open_with_password_wrong_password_raises_wrong_password_or_corrupt():
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.WrongPasswordOrCorrupt):
        secretary_ffi_py.open_with_password(toml, bundle, b"definitely wrong")


def test_open_with_password_swapped_files_raises_vault_mismatch():
    # vault_001's vault.toml + vault_002's identity.bundle.enc → cross-check
    # at core/src/unlock/mod.rs's vault_uuid + created_at_ms comparison fails.
    toml_001 = _read_fixture(1, "vault.toml")
    bundle_002 = _read_fixture(2, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.VaultMismatch):
        secretary_ffi_py.open_with_password(toml_001, bundle_002, VAULT_001_PASSWORD)


def test_open_with_password_truncated_toml_raises_corrupt_vault():
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    truncated = toml[:-50]
    with pytest.raises(secretary_ffi_py.CorruptVault):
        secretary_ffi_py.open_with_password(truncated, bundle, VAULT_001_PASSWORD)


def test_close_is_idempotent():
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    identity = secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD)
    identity.close()
    identity.close()  # second call must not raise
    identity.close()  # third call must not raise


def test_use_after_close_returns_empty_values():
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    identity = secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD)
    identity.close()
    assert identity.display_name() == ""
    assert identity.user_uuid() == b"\x00" * 16


def test_open_with_password_accepts_bytearray_for_caller_zeroize_discipline():
    """Documents the design: passwords accepted as bytes-like; disciplined
    callers can zero a mutable bytearray after the call."""
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    pw = bytearray(VAULT_001_PASSWORD)
    with secretary_ffi_py.open_with_password(toml, bundle, pw) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
    # Caller's zeroize discipline (recommended for first-party clients):
    for i in range(len(pw)):
        pw[i] = 0
    assert all(b == 0 for b in pw)
```

(If the existing tests don't import `secretary_ffi_py` at file scope, copy whatever import pattern is already there. Don't duplicate imports.)

- [ ] **Step 3: Rebuild the Python extension**

Per the user's memory note about maturin + uv editable cache: nuke the venv and uv cache before rebuilding to avoid the stale-`.so` trap.

```bash
rm -rf ffi/secretary-ffi-py/.venv
uv cache clean
cd ffi/secretary-ffi-py
uv sync
uv run maturin develop --release
cd -
```

Expected: maturin builds the wheel and installs it into the venv at `ffi/secretary-ffi-py/.venv/`.

- [ ] **Step 4: Run pytest**

```bash
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -20
```

Expected: 10 tests pass (3 existing B.1 + 7 new B.2). Specifically:
- Existing: `test_add_returns_arithmetic_sum`, `test_add_wraps_on_overflow`, `test_version_returns_format_version`
- New: 7 unlock tests above

- [ ] **Step 5: Verify cargo tests still pass**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')
"
```

Expected: ~474 passed, 0 failed.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-py/tests/test_smoke.py
git commit -m "$(cat <<'EOF'
test(ffi-py): pytest tests for open_with_password + UnlockedIdentity

7 new tests exercising the PyO3 projection layer:
- success against golden_vault_001 with pinned display_name + user_uuid
- wrong password raises WrongPasswordOrCorrupt
- vault_001 toml + vault_002 bundle raises VaultMismatch (real
  cross-vault test using the new golden_vault_002 fixture)
- truncated toml raises CorruptVault
- close() idempotent
- use-after-close returns empty values (matches non-throwing semantics)
- bytearray input documents the caller-zeroize discipline

Pytest baseline grows from 3 → 10 passed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 7.5 — secretary-ffi-uniffi projection

### Task 9: UDL declarations + Rust glue

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/Cargo.toml`
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs`

- [ ] **Step 1: Add bridge dependency**

Edit `ffi/secretary-ffi-uniffi/Cargo.toml`:

```toml
[dependencies]
uniffi = { version = "...", features = ["build"] }   # existing line, version unchanged
secretary-core = { path = "../../core" }              # existing
secretary-ffi-bridge = { path = "../secretary-ffi-bridge" }   # NEW
```

(Match the existing `uniffi` version exactly.)

- [ ] **Step 2: Edit `ffi/secretary-ffi-uniffi/src/secretary.udl`**

Replace the file content with:

```
// uniffi UDL — namespace must match the argument to
// `uniffi::include_scaffolding!()` in lib.rs and the basename of this
// file (build.rs reads it from src/secretary.udl).
namespace secretary {
    /// Smoke-test addition. Wrapping `u32 + u32` semantics. (B.1.1)
    u32 add(u32 a, u32 b);

    /// Vault format version. (B.1.1)
    u16 version();

    /// Unlock a vault using its master password. (B.2)
    [Throws=UnlockError]
    UnlockedIdentity open_with_password(
        bytes vault_toml_bytes,
        bytes identity_bundle_bytes,
        bytes password
    );
};

/// Thinned 3-variant FFI error. See secretary-ffi-bridge docs for the
/// rationale (express user-actionable intent rather than mirroring core's
/// internal enum structure).
[Error]
interface UnlockError {
    WrongPasswordOrCorrupt();
    VaultMismatch();
    CorruptVault(string message);
};

/// Opaque handle to a successfully-unlocked vault identity. The wrapped
/// secret material stays Rust-side; Swift / Kotlin callers read non-secret
/// fields via the methods below and zeroize-on-close via `close()`.
interface UnlockedIdentity {
    /// User-facing display name. Returns "" if the handle has been closed.
    string display_name();

    /// 16-byte stable identifier. Returns 16 zero bytes if closed.
    bytes user_uuid();

    /// Drop the wrapped identity now, zeroizing all secret fields at
    /// exactly this moment. Idempotent.
    void close();
};
```

- [ ] **Step 3: Edit `ffi/secretary-ffi-uniffi/src/lib.rs`**

Append to the existing file (after `add` / `version`, before `mod tests`):

```rust
// ---------------------------------------------------------------------------
// B.2: open_with_password + UnlockedIdentity + UnlockError.
//
// The actual logic lives in secretary-ffi-bridge; this file is the uniffi
// projection layer.
// ---------------------------------------------------------------------------

use secretary_ffi_bridge::FfiUnlockError;

/// uniffi-side error type. uniffi auto-marshals this to Swift `enum
/// UnlockError: Error` and Kotlin `sealed class UnlockError`. Mirrors
/// the bridge crate's `FfiUnlockError` shape exactly.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,
    #[error("vault is corrupt or unreadable: {message}")]
    CorruptVault { message: String },
}

impl From<FfiUnlockError> for UnlockError {
    fn from(e: FfiUnlockError) -> Self {
        match e {
            FfiUnlockError::WrongPasswordOrCorrupt => Self::WrongPasswordOrCorrupt,
            FfiUnlockError::VaultMismatch => Self::VaultMismatch,
            FfiUnlockError::CorruptVault { message } => Self::CorruptVault { message },
        }
    }
}

/// uniffi-side opaque handle. Newtype around bridge's `UnlockedIdentity`;
/// methods are thin forwarders. Drops on foreign refcount → 0 (RAII safety
/// net) or via explicit `close()` (preferred — Kotlin `.use { }` /
/// Swift `defer { }`).
pub struct UnlockedIdentity(secretary_ffi_bridge::UnlockedIdentity);

impl UnlockedIdentity {
    pub fn display_name(&self) -> String {
        self.0.display_name()
    }

    pub fn user_uuid(&self) -> Vec<u8> {
        self.0.user_uuid()
    }

    pub fn close(&self) {
        self.0.close();
    }
}

/// Unlock a vault using its master password. uniffi-projected.
pub fn open_with_password(
    vault_toml_bytes: Vec<u8>,
    identity_bundle_bytes: Vec<u8>,
    password: Vec<u8>,
) -> Result<UnlockedIdentity, UnlockError> {
    secretary_ffi_bridge::open_with_password(
        &vault_toml_bytes, &identity_bundle_bytes, &password,
    )
    .map(UnlockedIdentity)
    .map_err(UnlockError::from)
}
```

(Note: uniffi typically wants `Vec<u8>` rather than `&[u8]` for `bytes` parameters because the Rust function is invoked from generated code that owns the data. If your uniffi version uses `&[u8]`, adapt accordingly.)

- [ ] **Step 4: Build the cdylib**

```bash
cargo build --release -p secretary-ffi-uniffi 2>&1 | tail -15
```

Expected: `Finished` with no errors. Look for any UDL parsing errors — if uniffi-bindgen complains about the `[Error] interface UnlockError` syntax, the current uniffi version may not support the complex-error form. In that case, see the spec's Risk register: fall back to flat `[Error] enum` and lose the `message` field on Swift / Kotlin (mitigated by baking the inner Display into `Display::fmt` for `UnlockError`).

- [ ] **Step 5: Verify cargo tests pass**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | tail -5
cargo clippy --release --workspace -- -D warnings && echo "OK"
```

Expected: workspace baseline unchanged (~474). The uniffi crate's existing 3 unit tests (`add`, `version`, `add_wrap`) still pass; no new Rust unit tests in this task.

- [ ] **Step 6: Run the existing Swift smoke runner to verify B.1.1 unaffected**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -10
```

Expected: existing 3 Swift asserts still PASS. (We haven't yet added the B.2 asserts; they come in Task 10.)

- [ ] **Step 7: Run the existing Kotlin smoke runner to verify B.1.1.1 unaffected**

```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -10
```

Expected: existing 3 Kotlin asserts still PASS.

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-uniffi/Cargo.toml ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-uniffi): UDL + Rust glue for open_with_password + UnlockedIdentity

Adds secretary-ffi-bridge dependency. UDL declares:
- interface UnlockedIdentity { display_name, user_uuid, close }
- [Error] interface UnlockError { WrongPasswordOrCorrupt(),
    VaultMismatch(), CorruptVault(message) } — uniffi's complex-error
    form preserves the message field on Swift / Kotlin
- namespace function [Throws=UnlockError] open_with_password(bytes,
    bytes, bytes) -> UnlockedIdentity

Rust glue mirrors the bridge crate's shapes exactly via thin newtype
wrappers + From<FfiUnlockError> for the uniffi-side error variant.

Existing B.1.1 / B.1.1.1 smoke runners (Swift + Kotlin) still pass —
the new UDL declarations are additive.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Swift + Kotlin smoke runners

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/run.sh`
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`
- Create: `ffi/secretary-ffi-uniffi/tests/kotlin/UnlockedIdentityExt.kt`

- [ ] **Step 1: Add fixture-dir env var to swift/run.sh and kotlin/run.sh**

In both files, find the section that sets up paths (just before invoking the compiler) and add:

```bash
# B.2: foreign-side smoke runners need the golden_vault fixtures.
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
export SECRETARY_GOLDEN_VAULT_DIR="$REPO_ROOT/core/tests/data"
```

(`$SCRIPT_DIR` is presumably already defined; if not, define it as `SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"`.)

- [ ] **Step 2: Add unlock asserts to `tests/swift/main.swift`**

Append the existing `add` / `version` asserts with:

```swift
import Foundation

// ---------------------------------------------------------------------------
// B.2: open_with_password + UnlockedIdentity asserts.
// Pinned KAT values match secretary-ffi-bridge tests + Python pytest.
// ---------------------------------------------------------------------------

guard let dir = ProcessInfo.processInfo.environment["SECRETARY_GOLDEN_VAULT_DIR"] else {
    FileHandle.standardError.write(
        "error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/swift/run.sh\n".data(using: .utf8)!
    )
    exit(1)
}

let vault001 = URL(fileURLWithPath: dir).appendingPathComponent("golden_vault_001")
let vault002 = URL(fileURLWithPath: dir).appendingPathComponent("golden_vault_002")

let toml001 = try! Data(contentsOf: vault001.appendingPathComponent("vault.toml"))
let bundle001 = try! Data(contentsOf: vault001.appendingPathComponent("identity.bundle.enc"))
let bundle002 = try! Data(contentsOf: vault002.appendingPathComponent("identity.bundle.enc"))
let password001 = "correct horse battery staple".data(using: .utf8)!
let expectedDisplayName = "Owner"
let expectedUserUuid = Data([
    0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8,
    0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf, 0x35,
])

// Success path
do {
    let identity = try openWithPassword(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        password: password001
    )
    defer { identity.close() }

    let displayName = identity.displayName()
    if displayName == expectedDisplayName {
        print("PASS: open_with_password success → display_name == \"\(displayName)\"")
    } else {
        print("FAIL: open_with_password success: expected \"\(expectedDisplayName)\", got \"\(displayName)\"")
        exit(1)
    }

    let uuid = identity.userUuid()
    if uuid == expectedUserUuid {
        print("PASS: open_with_password success → user_uuid matches pinned KAT")
    } else {
        print("FAIL: open_with_password success: user_uuid mismatch")
        exit(1)
    }
}

// Wrong password
do {
    let _ = try openWithPassword(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        password: "definitely wrong".data(using: .utf8)!
    )
    print("FAIL: wrong password should have thrown WrongPasswordOrCorrupt")
    exit(1)
} catch UnlockError.wrongPasswordOrCorrupt {
    print("PASS: wrong password → WrongPasswordOrCorrupt")
} catch {
    print("FAIL: wrong password threw \(error), expected WrongPasswordOrCorrupt")
    exit(1)
}

// Vault mismatch (vault_001 toml + vault_002 bundle)
do {
    let _ = try openWithPassword(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle002,
        password: password001
    )
    print("FAIL: vault mismatch should have thrown VaultMismatch")
    exit(1)
} catch UnlockError.vaultMismatch {
    print("PASS: vault_001 toml + vault_002 bundle → VaultMismatch")
} catch {
    print("FAIL: vault mismatch threw \(error), expected VaultMismatch")
    exit(1)
}

// Truncated TOML
do {
    let truncated = toml001.dropLast(50)
    let _ = try openWithPassword(
        vaultTomlBytes: Data(truncated),
        identityBundleBytes: bundle001,
        password: password001
    )
    print("FAIL: truncated toml should have thrown CorruptVault")
    exit(1)
} catch UnlockError.corruptVault(let message) {
    print("PASS: truncated toml → CorruptVault(\"\(message)\")")
} catch {
    print("FAIL: truncated toml threw \(error), expected CorruptVault")
    exit(1)
}

print("OK: secretary uniffi Swift smoke runner — all assertions passed.")
```

- [ ] **Step 3: Run Swift smoke runner**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -20
```

Expected: existing 3 asserts plus 4 new B.2 asserts all PASS, ending with "OK: secretary uniffi Swift smoke runner — all assertions passed."

- [ ] **Step 4: Create `tests/kotlin/UnlockedIdentityExt.kt`**

```kotlin
// 5-line extension function: bridges Kotlin's idiomatic .use { } pattern
// onto uniffi-generated UnlockedIdentity (which doesn't auto-implement
// AutoCloseable as of the current uniffi version). When uniffi natively
// supports Closeable, this file deletes (tracked by routine
// trig_018gYtGpiycgLXqUsDpV2NZD).

package uniffi.secretary

inline fun <T> UnlockedIdentity.use(block: (UnlockedIdentity) -> T): T {
    try { return block(this) }
    finally { close() }
}
```

(The `package` declaration must match the package uniffi-bindgen emits — likely `uniffi.secretary` per the namespace name. Verify by inspecting the generated `secretary.kt` after `cargo build`.)

- [ ] **Step 5: Add unlock asserts to `tests/kotlin/Main.kt`**

Append the existing asserts with:

```kotlin
import uniffi.secretary.*
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.system.exitProcess

// ---------------------------------------------------------------------------
// B.2: open_with_password + UnlockedIdentity asserts.
// Pinned KAT values match secretary-ffi-bridge tests + Python pytest.
// ---------------------------------------------------------------------------

val dir = System.getenv("SECRETARY_GOLDEN_VAULT_DIR")
    ?: run {
        System.err.println("error: SECRETARY_GOLDEN_VAULT_DIR not set; run via tests/kotlin/run.sh")
        exitProcess(1)
    }

val vault001 = Paths.get(dir, "golden_vault_001")
val vault002 = Paths.get(dir, "golden_vault_002")

val toml001 = Files.readAllBytes(vault001.resolve("vault.toml"))
val bundle001 = Files.readAllBytes(vault001.resolve("identity.bundle.enc"))
val bundle002 = Files.readAllBytes(vault002.resolve("identity.bundle.enc"))
val password001 = "correct horse battery staple".toByteArray(Charsets.UTF_8)
val expectedDisplayName = "Owner"
val expectedUserUuid = byteArrayOf(
    0xbf.toByte(), 0x08, 0xa3.toByte(), 0x30, 0x0c, 0xd9.toByte(), 0x94.toByte(), 0xb8.toByte(),
    0x77, 0xe1.toByte(), 0xa1.toByte(), 0x5b, 0xaa.toByte(), 0x28, 0xdf.toByte(), 0x35,
)

// Success path
openWithPassword(
    vaultTomlBytes = toml001,
    identityBundleBytes = bundle001,
    password = password001,
).use { identity ->
    val displayName = identity.displayName()
    if (displayName == expectedDisplayName) {
        println("PASS: open_with_password success → display_name == \"$displayName\"")
    } else {
        println("FAIL: open_with_password success: expected \"$expectedDisplayName\", got \"$displayName\"")
        exitProcess(1)
    }
    val uuid = identity.userUuid()
    if (uuid.contentEquals(expectedUserUuid)) {
        println("PASS: open_with_password success → user_uuid matches pinned KAT")
    } else {
        println("FAIL: open_with_password success: user_uuid mismatch")
        exitProcess(1)
    }
}

// Wrong password
try {
    openWithPassword(
        vaultTomlBytes = toml001,
        identityBundleBytes = bundle001,
        password = "definitely wrong".toByteArray(Charsets.UTF_8),
    )
    println("FAIL: wrong password should have thrown WrongPasswordOrCorrupt")
    exitProcess(1)
} catch (e: UnlockException.WrongPasswordOrCorrupt) {
    println("PASS: wrong password → WrongPasswordOrCorrupt")
} catch (e: Throwable) {
    println("FAIL: wrong password threw $e, expected WrongPasswordOrCorrupt")
    exitProcess(1)
}

// Vault mismatch (vault_001 toml + vault_002 bundle)
try {
    openWithPassword(
        vaultTomlBytes = toml001,
        identityBundleBytes = bundle002,
        password = password001,
    )
    println("FAIL: vault mismatch should have thrown VaultMismatch")
    exitProcess(1)
} catch (e: UnlockException.VaultMismatch) {
    println("PASS: vault_001 toml + vault_002 bundle → VaultMismatch")
} catch (e: Throwable) {
    println("FAIL: vault mismatch threw $e, expected VaultMismatch")
    exitProcess(1)
}

// Truncated TOML
try {
    val truncated = toml001.copyOfRange(0, toml001.size - 50)
    openWithPassword(
        vaultTomlBytes = truncated,
        identityBundleBytes = bundle001,
        password = password001,
    )
    println("FAIL: truncated toml should have thrown CorruptVault")
    exitProcess(1)
} catch (e: UnlockException.CorruptVault) {
    println("PASS: truncated toml → CorruptVault(\"${e.message}\")")
} catch (e: Throwable) {
    println("FAIL: truncated toml threw $e, expected CorruptVault")
    exitProcess(1)
}

println("OK: secretary uniffi Kotlin smoke runner — all assertions passed.")
```

(The exception class names — `UnlockException.WrongPasswordOrCorrupt` etc. — depend on uniffi's Kotlin codegen convention. Verify by inspecting the generated `secretary.kt` after the next cargo build. Some uniffi versions emit `UnlockError.WrongPasswordOrCorrupt` directly without the `Exception` suffix; adjust as needed.)

- [ ] **Step 6: Update `tests/kotlin/run.sh` to compile the extension file**

The existing run.sh compiles `Main.kt` via kotlinc. Add `UnlockedIdentityExt.kt` to the kotlinc invocation. Find the line that looks like:

```bash
kotlinc -include-runtime -classpath "$JNA_JAR" -d "$JAR_OUT" "$SCRIPT_DIR/Main.kt" "$BINDINGS_DIR/secretary.kt"
```

and change it to:

```bash
kotlinc -include-runtime -classpath "$JNA_JAR" -d "$JAR_OUT" \
    "$SCRIPT_DIR/Main.kt" "$SCRIPT_DIR/UnlockedIdentityExt.kt" "$BINDINGS_DIR/secretary.kt"
```

(Match the existing run.sh's flag patterns exactly.)

- [ ] **Step 7: Run Kotlin smoke runner**

```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -20
```

Expected: existing 3 asserts plus 4 new B.2 asserts all PASS, ending with "OK: secretary uniffi Kotlin smoke runner — all assertions passed."

- [ ] **Step 8: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/main.swift ffi/secretary-ffi-uniffi/tests/swift/run.sh \
        ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt ffi/secretary-ffi-uniffi/tests/kotlin/UnlockedIdentityExt.kt \
        ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
git commit -m "$(cat <<'EOF'
test(ffi-uniffi): Swift + Kotlin smoke runners for B.2 unlock

Each runner adds 4 new asserts mirroring the bridge-crate + pytest
test set:
- success against golden_vault_001 with pinned display_name + user_uuid
- wrong password → WrongPasswordOrCorrupt
- vault_001 toml + vault_002 bundle → VaultMismatch (real cross-vault)
- truncated toml → CorruptVault(message)

Both runners pick up the golden_vault fixtures via SECRETARY_GOLDEN_VAULT_DIR
env var set by run.sh — single source of truth for the path math.

Kotlin gets a 5-line UnlockedIdentityExt.kt providing the .use { }
extension function (until uniffi natively supports AutoCloseable;
tracked by routine trig_018gYtGpiycgLXqUsDpV2NZD).

Swift uses the native `defer { close() }` pattern.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Final phase — Documentation + handoff

### Task 11: Per-crate READMEs + top-level docs

**Files:**
- Create: `ffi/secretary-ffi-bridge/README.md`
- Modify: `ffi/secretary-ffi-py/README.md`
- Modify: `ffi/secretary-ffi-uniffi/README.md`
- Modify: `README.md` (top-level)
- Modify: `ROADMAP.md`

- [ ] **Step 1: Create `ffi/secretary-ffi-bridge/README.md`**

```markdown
# secretary-ffi-bridge

The FFI-friendly facade of `secretary-core`. Single source of code truth
for the FFI surface shared between [`secretary-ffi-py`](../secretary-ffi-py/)
(PyO3 → Python) and [`secretary-ffi-uniffi`](../secretary-ffi-uniffi/)
(uniffi → Swift / Kotlin).

## Why this crate exists

Both binding-flavor crates need the same logic:
- Map `core::UnlockError`'s 7 internal variants to a thinned 3-variant
  FFI surface
- Wrap `core::UnlockedIdentity` in an opaque handle with explicit close
- Forward `open_with_password` calls into core

Without a shared crate, this logic would duplicate in both binding
crates and **drift** as new operations land. With this crate, drift is
**impossible at compile time** — both binding flavors share the same
underlying methods and project them through their respective binding
macros.

## Surface

- `FfiUnlockError` — 3-variant thinned error: `WrongPasswordOrCorrupt`,
  `VaultMismatch`, `CorruptVault { message }`. Expresses user-actionable
  intent rather than mirroring core's internal enum structure.
- `UnlockedIdentity` — opaque handle. Two non-secret accessors
  (`display_name`, `user_uuid`) plus explicit `close()`. The wrapped
  secret material stays Rust-side.
- `open_with_password` — fallible operation: vault unlock by master
  password.

## Design rationale

### Thinned error type

Core's `UnlockError` has 7 reachable-from-`open_with_password` variants,
three wrapping inner enums (`MalformedVaultToml(VaultTomlError)`, etc.).
Mirroring exactly to the foreign side either re-exposes ~15 inner types
per language (huge surface, churns on every `core/` internal refactor)
or collapses inners to strings (anti-pattern; foreign callers parse
strings to understand failure causes).

The thinned 3-variant shape:
- `WrongPasswordOrCorrupt` — "your password is wrong, try again".
  **Deliberately conflates wrong-password and corruption** per
  [`docs/threat-model.md`](../../docs/threat-model.md) §13's anti-oracle
  property; **MUST NOT** be split into separate variants on the foreign
  side.
- `VaultMismatch` — "vault.toml and identity.bundle.enc reference
  different vaults; re-pair from backups".
- `CorruptVault { message }` — collapses {core::CorruptVault, all
  MalformedX, KdfFailure}. The `message` field carries the inner
  Display text for diagnostics; structured pattern-matching on the
  inner cause is intentionally not supported (corruption recovery is
  "restore from backup", not "branch on which file was malformed").

Internal core refactors fold automatically into `CorruptVault {
message: <new Display> }` without rippling foreign-API changes.

### `Mutex<Option<...>>` inside `UnlockedIdentity`

Provides:
- **idempotent close** via `Option::take()` (multiple `close()` calls
  don't panic)
- **thread-safe accessors** (sub-microsecond locks for cloning a
  `String` or copying 16 bytes)
- **use-after-close non-throwing** semantics (`as_ref()` on `None`
  yields default values, matching the B.1 non-throwing accessor
  pattern)
- **prompt zeroize** — `take()` consumes the inner Option, `Drop`
  cascades through `Sensitive<...> ZeroizeOnDrop`

Mutex overhead is acceptable for the opaque-handle pattern; if profile
data ever shows it as a hot path (it won't — accessors are unlock-time
operations, not record-read-time), `RwLock` is a drop-in upgrade.

## Lints / invariants

- Pure-safe Rust. Workspace's `#![forbid(unsafe_code)]` applies; no
  carve-out (the binding-flavor crates carry their FFI-macro
  `unsafe_code = "deny"` carve-outs locally).
- `cargo clippy --release --workspace -- -D warnings` clean.
- `From<core::unlock::UnlockError>` impl uses explicit match arms with
  no wildcard so future core variants force a compile error instead of
  silently mapping to a default.

## Testing

```bash
cargo test --release -p secretary-ffi-bridge
```

Tests embed both `golden_vault_001/` and `golden_vault_002/` via
`include_bytes!` so no runtime filesystem dependency. Pinned KAT values
(display_name, user_uuid) match those asserted in the foreign-side
smoke runners — KAT drift cannot land silently.
```

- [ ] **Step 2: Append B.2 section to `ffi/secretary-ffi-py/README.md`**

```markdown
## Vault unlock (B.2)

Three new symbols at the module level: `open_with_password()`,
`UnlockedIdentity` (opaque handle class), and three exception classes
`WrongPasswordOrCorrupt` / `VaultMismatch` / `CorruptVault`.

### Idiomatic usage

```python
import secretary_ffi_py

with open(".../vault.toml", "rb") as f:    toml = f.read()
with open(".../identity.bundle.enc", "rb") as f:    bundle = f.read()

with secretary_ffi_py.open_with_password(toml, bundle, b"my password") as identity:
    print(identity.display_name())   # str
    print(identity.user_uuid())      # bytes (16 bytes)
# `with` block exit → identity.close() → Sensitive<...> fields zeroized
```

### Error handling

```python
try:
    identity = secretary_ffi_py.open_with_password(toml, bundle, password)
except secretary_ffi_py.WrongPasswordOrCorrupt:
    # User's password is wrong, OR the vault has been tampered with.
    # These are deliberately indistinguishable per the §13 anti-oracle property.
    ...
except secretary_ffi_py.VaultMismatch:
    # vault.toml and identity.bundle.enc reference different vaults.
    # User should re-pair the two files from backups.
    ...
except secretary_ffi_py.CorruptVault as e:
    # Vault file is malformed beyond recovery. str(e) carries inner diagnostic.
    print(f"Vault corrupt: {e}")
```

### Password-input discipline (caller-zeroize)

Passwords are accepted as **bytes** (not `str`):

```python
# Convenience: bytes literal (not zeroizable)
secretary_ffi_py.open_with_password(toml, bundle, b"my password")

# First-party / disciplined caller: bytearray (zeroizable)
pw = bytearray(b"my password")
try:
    with secretary_ffi_py.open_with_password(toml, bundle, pw) as identity:
        ...
finally:
    for i in range(len(pw)):
        pw[i] = 0
```

**Third-party library consumers:** the bytes-input shape is intentional
to enable caller-side zeroize. Wrap your password handling in a
zeroizing context manager if you handle credentials over the long term.
First-party clients of this crate (the future `secretary-ui-py`,
desktop / web frontends) MUST zero their input buffers after the call;
this is the documented discipline.

### Lifecycle

`UnlockedIdentity` supports the context-manager protocol (`with ... as
id:`) AND has an explicit `close()` method:

```python
identity = secretary_ffi_py.open_with_password(toml, bundle, password)
try:
    print(identity.display_name())
finally:
    identity.close()   # explicit; pin drop time
```

After `close()`, accessors return empty / zero values rather than
raising — this matches the non-throwing pattern from B.1's `add` /
`version`.
```

- [ ] **Step 3: Append B.2 section to `ffi/secretary-ffi-uniffi/README.md`**

```markdown
## Vault unlock (B.2)

UDL adds: `interface UnlockedIdentity` (opaque handle), `[Error]
interface UnlockError` (3-variant), and namespace function
`[Throws=UnlockError] open_with_password(bytes, bytes, bytes) ->
UnlockedIdentity`.

### Swift idiom (`defer`)

```swift
import secretary

let toml = try Data(contentsOf: vaultTomlURL)
let bundle = try Data(contentsOf: identityBundleURL)
let password = "my password".data(using: .utf8)!

let identity = try openWithPassword(
    vaultTomlBytes: toml,
    identityBundleBytes: bundle,
    password: password
)
defer { identity.close() }    // pin drop time at scope exit

print(identity.displayName())
print(identity.userUuid())

// Error path:
do {
    let _ = try openWithPassword(...)
} catch UnlockError.wrongPasswordOrCorrupt {
    // ...
} catch UnlockError.corruptVault(let message) {
    print("Vault corrupt: \(message)")
}
```

### Kotlin idiom (`.use { }`)

```kotlin
import uniffi.secretary.*

val toml = Files.readAllBytes(vaultTomlPath)
val bundle = Files.readAllBytes(identityBundlePath)
val password = "my password".toByteArray(Charsets.UTF_8)

openWithPassword(
    vaultTomlBytes = toml,
    identityBundleBytes = bundle,
    password = password,
).use { identity ->
    println(identity.displayName())
    println(identity.userUuid().contentToString())
}
// .use exit → identity.close() → secret fields zeroized

// Error path:
try {
    openWithPassword(...)
} catch (e: UnlockException.WrongPasswordOrCorrupt) {
    // ...
} catch (e: UnlockException.CorruptVault) {
    println("Vault corrupt: ${e.message}")
}
```

The `.use { }` extension function lives at
`tests/kotlin/UnlockedIdentityExt.kt` (5 lines). Future uniffi versions
may natively support `AutoCloseable` (tracked by the `uniffi
Closeable-trait watch` routine `trig_018gYtGpiycgLXqUsDpV2NZD`); when
that lands, the extension file deletes.

### Password-input discipline (caller-zeroize)

Same as the Python crate: passwords accepted as **bytes** (`Data` in
Swift, `ByteArray` in Kotlin), not `String`. Disciplined first-party
clients should zero their mutable buffers after the call. Documented
discipline; not enforced at the FFI boundary.

### Test fixtures via env var

The Swift / Kotlin smoke runners read `SECRETARY_GOLDEN_VAULT_DIR`
(set by `run.sh`) for the `core/tests/data/` parent directory; runners
append `golden_vault_001` or `golden_vault_002` as needed. Standalone
runs (without `run.sh`) fail loudly with an actionable error message.
```

- [ ] **Step 4: Update top-level `README.md`**

Find the FFI status table; flip the `secretary-ffi-uniffi` and
`secretary-ffi-py` entries to ✅ B.2 (was ✅ B.1.1.1 / ✅ B.1). Update
the ASCII progress bar (advance a few characters per the existing
pattern).

Find the Sub-project B section; update the description to reference
B.2 as the most-recent shipped milestone.

(Exact edits depend on the current README state; preserve the existing
formatting.)

- [ ] **Step 5: Update `ROADMAP.md`**

Find § "Sub-project B" in `ROADMAP.md`. Flip the B.2 entry from ⏳ to
✅ with a description summarizing what shipped:
- `secretary-ffi-bridge` crate (single source of FFI code truth)
- `open_with_password` exposed through PyO3 + uniffi
- thinned 3-variant error type
- explicit close + RAII lifecycle
- `golden_vault_002` sibling fixture for cross-vault tests

Advance the ASCII progress bar.

- [ ] **Step 6: Verify all gates green**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')
"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
```

Expected:
- Cargo: ~474 passed, 0 failed, 8 ignored
- Clippy OK
- pytest: 10 passed
- Conformance: PASS
- Spec freshness: PASS (or with allowlist updates if Phase 7.2 added test names)
- Swift smoke: 7/7 PASS (3 existing + 4 new)
- Kotlin smoke: 7/7 PASS (3 existing + 4 new)

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/README.md ffi/secretary-ffi-py/README.md ffi/secretary-ffi-uniffi/README.md README.md ROADMAP.md
git commit -m "$(cat <<'EOF'
docs(ffi): READMEs + top-level status updates for B.2

New ffi/secretary-ffi-bridge/README.md describes the bridge crate's
role (FFI-friendly facade of secretary-core, single source of code
truth) plus the design-rationale notes (thinned error type, Mutex
choice, pure-safe Rust invariant).

ffi/secretary-ffi-py/README.md and ffi/secretary-ffi-uniffi/README.md
each gain a "Vault unlock (B.2)" section: idiomatic usage, error
handling, password-input discipline (caller-zeroize), lifecycle
(context-manager / .use / defer).

Top-level README.md flipped FFI entries to ✅ B.2; ROADMAP.md flipped
B.2 to ✅ with description; ASCII progress bars advanced.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: NEXT_SESSION + handoff archive + final verification

**Files:**
- Modify: `NEXT_SESSION.md`
- Create: `docs/handoffs/2026-MM-DD-b2-vault-unlock.md`

- [ ] **Step 1: Rewrite `NEXT_SESSION.md` for the post-B.2 state**

Match the structure of the prior session-handoff documents (NEXT_SESSION.md after PR #22). Sections:

```markdown
# NEXT_SESSION.md

**Session date:** 2026-MM-DD (Sub-project B.2 — vault unlock through FFI)
**Session-specific handoff** for the B.2 session(s). The first fallible,
secret-bearing FFI operation shipped — `open_with_password` exposed
through both PyO3 (Python) and uniffi (Swift / Kotlin), via the new
shared `secretary-ffi-bridge` crate. With B.2 done, the FFI now exposes
its first vault crypto operation; B.3 expands the surface with
`open_with_recovery` and (deferred-design) `create_vault`.

## (1) What we shipped this session

[Table of commits — fill in actual SHAs from the git log]

## (2) What's next, with concrete acceptance criteria

### Sub-project B.3 — second + third unlock paths

(Brainstorm + spec needed before code. Decisions: how does the
24-word BIP-39 mnemonic cross the boundary? Does `create_vault`
expose `WeakKdfParams`? See spec at
docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md
"Non-goals (YAGNI)" section for the carry-over context.)

## (3) Open decisions and risks

- (Carry-over from B.2: whether to refactor `generate_golden_inputs`
  to be parameterizable over RNG seed, or keep `generate_golden_inputs_002`
  as a sister test. Decision deferred until a third fixture is needed.)

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

# B.3 starts with brainstorming — read the deferred-items section of
# docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md before
# requesting the brainstorming skill.
```
```

(Fill in actual commit SHAs after running `git log --oneline main..HEAD` from the worktree at session close. The squash-merge SHA on `main` will be recorded in a post-merge follow-up commit, matching the post-PR-22 pattern at `36850ec`.)

- [ ] **Step 2: Create timestamped handoff archive**

```bash
TODAY="$(date -u +%Y-%m-%d)"
cp NEXT_SESSION.md "docs/handoffs/$TODAY-b2-vault-unlock.md"
```

- [ ] **Step 3: Final verification of all gates**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')
"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
```

All gates must show PASS / OK / 0 failed before committing the handoff.

- [ ] **Step 4: Commit handoff**

```bash
git add NEXT_SESSION.md docs/handoffs/
git commit -m "$(cat <<'EOF'
docs(handoff): record B.2 session — FFI vault unlock shipped

Session retrospective + B.3 forward-looking content. Handoff archive
under docs/handoffs/ preserves the timeline.

Per the user's "NEXT_SESSION.md must ride inside the PR" feedback,
this handoff lands on the feature branch BEFORE the PR opens; the
post-merge SHA fix-up follows the established ca936c6 / 36850ec
pattern when the squash-merge lands on main.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Push the branch + open PR**

```bash
git push -u origin feat/ffi-b2-vault-unlock 2>&1 | tail -5
gh pr create --title "feat(ffi-b2): expose open_with_password through PyO3 + uniffi via shared bridge crate" --body "$(cat <<'EOF'
## Summary

- New `secretary-ffi-bridge` crate as the single source of code truth
  for the FFI-friendly facade of `secretary-core`. Both binding-flavor
  crates (`secretary-ffi-py`, `secretary-ffi-uniffi`) project from this
  shared crate; drift between the two is impossible at compile time.
- `open_with_password` exposed through PyO3 (Python) and uniffi (Swift
  / Kotlin) with thinned 3-variant `FfiUnlockError` type and explicit
  close + RAII lifecycle (Python `with`, Kotlin `.use { }`, Swift `defer`).
- New `golden_vault_002/` sibling fixture (built via the parameterized
  `core/tests/common/fixture_builder.rs`, refactored from the previous
  monolithic `golden_vault_001.rs`) enables real cross-vault tests of
  the `VaultMismatch` error path.

Spec: [docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md](docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md)
Plan: [docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md](docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md)

## Test plan

- [ ] `cargo test --release --workspace` — ~474 passed, 0 failed (was 451)
- [ ] `cargo clippy --release --workspace -- -D warnings` — clean
- [ ] `uv run --directory ffi/secretary-ffi-py pytest` — 10 passed (was 3)
- [ ] `uv run core/tests/python/conformance.py` — PASS unchanged
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` — PASS
- [ ] `ffi/secretary-ffi-uniffi/tests/swift/run.sh` — 7/7 PASS (was 3/3)
- [ ] `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` — 7/7 PASS (was 3/3)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-review checklist (run before declaring plan complete)

- [ ] **Spec coverage:** every spec section has a corresponding task. Skim each requirement; fix any gaps.
- [ ] **Placeholder scan:** search for "TBD", "TODO", "FIXME", "implement later", or any incomplete code blocks. Fix inline.
- [ ] **Type consistency:** check that types named in later tasks match earlier definitions (e.g., `FfiUnlockError` is the same enum throughout; `UnlockedIdentity` is consistently the bridge crate's wrapper, not core's).
- [ ] **Code completeness:** every step that changes code shows the actual code. No "similar to above" without repeating the code.
- [ ] **Command commands:** every shell command has expected output described.
- [ ] **Commit messages:** every commit step has a HEREDOC commit message that ends with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.

---

## Estimated total scope

12 tasks, ~5-8 steps each. ~2 focused sessions for completion:
- **Session 1:** Tasks 0–6 (worktree, fixture refactor + golden_vault_002, bridge crate end-to-end)
- **Session 2:** Tasks 7–12 (PyO3 projection, uniffi projection, docs, handoff, PR)

Recommended split lets each session end with a stable commit cluster reviewable in isolation.
