# B.3a — FFI Recovery-Phrase Unlock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `secretary_core::unlock::open_with_recovery` through both FFI flavors (PyO3 → Python; uniffi → Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate, growing the thinned 3-variant `FfiUnlockError` to 5 variants (adding `WrongMnemonicOrCorrupt` and `InvalidMnemonic { detail }`), pinning the BIP-39 24-word recovery phrase as a derived-and-verified field in `core/tests/data/golden_vault_{001,002}_inputs.json`, and exercising every error path from each foreign language.

**Architecture:** Strictly additive on B.2's three-crate FFI layout. Bridge crate gains: 2 new error variants (`WrongMnemonicOrCorrupt`, `InvalidMnemonic { detail }`), a `CorruptVault.message → CorruptVault.detail` field rename for naming uniformity with the new variant, an updated `From<core::UnlockError>` impl that promotes the previously-defensive `WrongMnemonicOrCorrupt` and `InvalidMnemonic(_)` arms to active mappings, and a new `pub fn open_with_recovery` with UTF-8 validation seam (mnemonic input is `&[u8]`; bridge does `std::str::from_utf8` and surfaces failure as `InvalidMnemonic { detail: "phrase contained invalid UTF-8" }`). PyO3 + uniffi projection layers add 2 new exception classes / UDL variants + 1 new entry point, with wrapper-side `Vec<u8>` zeroize for the mnemonic input matching B.2's password pattern. Existing `golden_vault_001` and `golden_vault_002` on-disk fixtures are unchanged on disk; only the inputs JSON gains a `recovery_mnemonic_phrase` string field. A `bip39::Mnemonic::from_entropy(pinned_entropy).to_string() == pinned_phrase` drift-detection assertion in the fixture builder keeps the JSON pin honest.

**Tech Stack:** Rust 1.87 stable, PyO3 0.28, uniffi 0.31, maturin 1.9.4+, uv 0.6+, pytest, kotlinc 2.x, swiftc, JNA 5.14.0, thiserror, zeroize. The `bip39` crate is already in `secretary-core`'s dependency graph.

**Spec:** [docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md](../specs/2026-05-04-ffi-b3a-recovery-unlock-design.md) (commit `55aaef6`)

**Worktree:** `.worktrees/feat-ffi-b3a-recovery-unlock/` on branch `feat/ffi-b3a-recovery-unlock`. Created as Pre-flight Task 0 below; the spec doc commit `55aaef6` is already in place on `main` and inherits into the worktree.

---

## File structure

After all tasks complete, the FFI tree contains:

```
ffi/
├── secretary-ffi-bridge/
│   ├── README.md                                            ← edit (Task 9; +B.3a section)
│   └── src/
│       ├── lib.rs                                           ← edit (Task 4; re-export open_with_recovery, B.3a crate-doc)
│       ├── error.rs                                         ← edit (Task 2; +2 variants, message→detail rename, +5 tests)
│       ├── identity.rs                                      ← unchanged
│       └── unlock.rs                                        ← edit (Task 3; +open_with_recovery, +5 integration tests)
│
├── secretary-ffi-py/
│   ├── README.md                                            ← edit (Task 9; +B.3a section)
│   ├── src/lib.rs                                           ← edit (Task 5; +2 exception classes, +open_with_recovery #[pyfunction])
│   └── tests/test_smoke.py                                  ← edit (Task 6; +6 tests)
│
└── secretary-ffi-uniffi/
    ├── README.md                                            ← edit (Task 9; +B.3a section)
    ├── src/
    │   ├── lib.rs                                           ← edit (Task 7; +2 UnlockError variants, +open_with_recovery, +tests)
    │   └── secretary.udl                                    ← edit (Task 7; +2 [Error] variants, +open_with_recovery namespace fn)
    └── tests/
        ├── swift/main.swift                                 ← edit (Task 8; +4 asserts)
        └── kotlin/Main.kt                                   ← edit (Task 8; +4 asserts)

core/tests/
├── common/fixture_builder.rs                                ← edit (Task 1; +recovery_mnemonic_phrase field, +bip39 drift-detection assert)
├── data/golden_vault_001_inputs.json                        ← edit (Task 1; +recovery_mnemonic_phrase field)
├── data/golden_vault_002_inputs.json                        ← edit (Task 1; +recovery_mnemonic_phrase field)
├── data/golden_vault_001/                                   ← unchanged
└── data/golden_vault_002/                                   ← unchanged

README.md (root)                                             ← edit (Task 9)
ROADMAP.md                                                   ← edit (Task 9)
NEXT_SESSION.md                                              ← edit (Task 10)
docs/handoffs/2026-MM-DD-b3a-recovery-unlock.md              ← NEW (Task 10)
```

**Decomposition rationale:**
- Phase 1 lands the inputs-JSON pin first so all downstream tests have the recovery_mnemonic_phrase field available. The bip39 drift-detection assert in fixture_builder is the integrity bridge between pinned phrase ↔ pinned entropy ↔ pinned vault bytes.
- Phase 2 (Tasks 2-4) is pure-bridge work: error variants → unlock function → re-exports. Each task is independently testable.
- Phase 3 (PyO3) and Phase 4 (uniffi) are independent of each other once Phase 2 is done; they could in principle run in parallel, but the plan keeps them sequential to simplify subagent dispatch and review.
- Phase 5 (Tasks 9-10) is the doc + handoff cluster — last commit before push + PR.

---

## Pre-flight

### Task 0: Create the worktree

**Files:** none in repo; creates `.worktrees/feat-ffi-b3a-recovery-unlock/` and branch `feat/ffi-b3a-recovery-unlock`.

- [ ] **Step 1: Verify clean state on main**

```bash
cd /Users/hherb/src/secretary
git status
git log --oneline -3
```

Expected: clean working tree (the three untracked `.claude/` items are local Claude tooling, not project code; ignore them); `main` HEAD is `55aaef6 docs(spec): add B.3a FFI recovery unlock design (PR-pending)` or newer.

- [ ] **Step 2: Verify all gates green before forking**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_baseline.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_baseline.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: `TOTAL: 479 passed; 0 failed; 9 ignored`; clippy OK; fmt OK. If anything diverges, STOP and triage before forking.

- [ ] **Step 3: Create worktree + branch**

```bash
git worktree add -b feat/ffi-b3a-recovery-unlock .worktrees/feat-ffi-b3a-recovery-unlock main
cd .worktrees/feat-ffi-b3a-recovery-unlock
git status
```

Expected: new branch on the same commit as main; clean status.

- [ ] **Step 4: Verify worktree is project-local (per user preference)**

```bash
git worktree list
```

Expected: the new worktree is at `.worktrees/feat-ffi-b3a-recovery-unlock` (relative to repo root), NOT in a global location.

All subsequent tasks run from inside the worktree at `.worktrees/feat-ffi-b3a-recovery-unlock/`.

---

## Phase 1 — Inputs JSON pin

### Task 1: Add `recovery_mnemonic_phrase` field with drift-detection assertion

The pinned 32 bytes of recovery entropy in each vault's inputs JSON deterministically produces a specific 24-word BIP-39 phrase via `bip39::Mnemonic::from_entropy(entropy).to_string()`. This task adds that phrase as an explicit JSON field and adds a fixture-builder assertion that the JSON pin matches the bip39-derived value. The on-disk vault bytes do not change.

**Files:**
- Modify: `core/tests/common/fixture_builder.rs`
- Modify: `core/tests/data/golden_vault_001_inputs.json`
- Modify: `core/tests/data/golden_vault_002_inputs.json`

- [ ] **Step 1: Read the existing `Inputs` struct in fixture_builder.rs**

```bash
grep -n "^pub struct Inputs\|recovery_entropy\|fn build_golden_vault" core/tests/common/fixture_builder.rs | head -20
```

Identify:
- Where `Inputs` is defined (top of file, derive `Deserialize`)
- Where `recovery_entropy` is drawn from RNG (around line 394 in the existing file, per the spec)
- The function that builds `recovery_kek` from `recovery_entropy`

- [ ] **Step 2: Print the derived phrase for vault_001 to stdout**

This is a one-shot extraction: run the fixture-build path with a `println!` of the bip39-derived phrase, capture the value, then revert the print. The value goes into the JSON in Step 4.

Add a temporary line after `let recovery_entropy = ...; rng.fill_bytes(&mut recovery_entropy);` (or wherever the entropy is finalized — match the existing call site) inside the build function:

```rust
// TEMPORARY (this commit): print phrase for one-time JSON pin.
let _phrase = bip39::Mnemonic::from_entropy(&recovery_entropy)
    .expect("32 bytes is a valid BIP-39 entropy length")
    .to_string();
println!("DERIVED_PHRASE: {_phrase}");
```

Run vault_001's regenerator-and-pin test and capture the output:

```bash
cargo test --release --workspace --test golden_vault_001 -- --nocapture --ignored materialize_golden_vault_001 2>&1 | grep DERIVED_PHRASE
```

Expected: one line `DERIVED_PHRASE: <24 words>`. **Copy that exact phrase** — it goes into the JSON in Step 4 verbatim.

Run vault_002's regenerator-and-pin test:

```bash
cargo test --release --workspace --test golden_vault_002 -- --nocapture --ignored materialize_golden_vault_002 2>&1 | grep DERIVED_PHRASE
```

Expected: one line `DERIVED_PHRASE: <different 24 words>`. **Copy that phrase too**.

Note: the test names above match the existing convention from Task 1/2 in the B.2 plan (`materialize_golden_vault_001`, `materialize_golden_vault_002`). If the actual `#[ignore]`-marked test name differs in your tree, run `grep -n '#\[ignore\]' core/tests/golden_vault_00{1,2}.rs` to find the right one — the test prints golden bytes during regeneration so it's the right one to instrument.

- [ ] **Step 3: Remove the temporary `println!` lines**

Revert the changes from Step 2. The fixture_builder.rs should be back to its pre-Step-2 state. Re-run `cargo build --tests --workspace` to confirm clean compilation:

```bash
cargo build --tests --workspace 2>&1 | tail -5
```

Expected: `Finished` with no errors.

- [ ] **Step 4: Add `recovery_mnemonic_phrase` to both inputs JSON files**

Edit `core/tests/data/golden_vault_001_inputs.json` — add a new top-level field BEFORE the `"owner"` key (preserving the existing field order convention which groups vault-level metadata first):

```json
  "recovery_mnemonic_phrase": "<paste vault_001 phrase from Step 2 here>",
```

Same edit in `core/tests/data/golden_vault_002_inputs.json`:

```json
  "recovery_mnemonic_phrase": "<paste vault_002 phrase from Step 2 here>",
```

Both phrases are 24 lowercase space-separated English BIP-39 words; do NOT alter casing or whitespace; the bip39 library returns them in canonical form.

- [ ] **Step 5: Add the field to the `Inputs` struct in fixture_builder.rs**

Find the `Inputs` struct (or whatever name the deserialized JSON is bound to in `fixture_builder.rs`) and add the new field. Match the existing `Deserialize` derives and field ordering convention. If the existing fields have `_doc` siblings, this one does not need one — its purpose is documented via the bip39 derive-and-assert.

```rust
pub struct Inputs {
    // ... existing fields ...
    /// 24-word BIP-39 recovery phrase, lowercase, space-separated.
    /// Derived deterministically from the pinned `recovery_entropy` (also in
    /// this struct via the seeded ChaCha20 RNG draws). Pinned as a string so
    /// FFI smoke runners can read it directly without re-implementing BIP-39
    /// encoding. The fixture builder asserts at build time that the pinned
    /// string matches `bip39::Mnemonic::from_entropy(recovery_entropy).to_string()`,
    /// so JSON drift cannot land silently.
    pub recovery_mnemonic_phrase: String,
    // ...
}
```

(Field placement: alongside the existing `password` / `vault_uuid` / similar string fields, before the per-identity (`owner`/`alice`/`bob`) sub-objects. Match the JSON order from Step 4 if the struct is deserialized via field name — `serde` is order-tolerant, but consistency aids readability.)

- [ ] **Step 6: Add the bip39 drift-detection assertion in the build function**

Locate the function that builds the recovery-related artifacts (search for `derive_recovery_kek` to find it). Immediately after `recovery_entropy` is finalized (filled from RNG), add:

```rust
// SECURITY: pin the JSON `recovery_mnemonic_phrase` field to the
// bip39-derived value of the seeded entropy. If either side ever
// drifts (RNG seed change, JSON typo, bip39 wordlist update), this
// assertion fires loudly at fixture-build time. The pinned phrase
// is the source of truth for FFI smoke runners that don't link
// against bip39; the assertion proves the JSON cannot lie.
let derived_phrase = bip39::Mnemonic::from_entropy(&recovery_entropy)
    .expect("32 bytes is a valid BIP-39 entropy length")
    .to_string();
assert_eq!(
    derived_phrase, inputs.recovery_mnemonic_phrase,
    "pinned recovery_mnemonic_phrase drifted from RNG-derived entropy",
);
```

(Variable names — `recovery_entropy`, `inputs` — must match the actual local-variable names in the function. Use the exact names from the existing code.)

- [ ] **Step 7: Verify the assertion fires correctly when the JSON drifts (negative-path probe)**

Temporarily corrupt vault_001's JSON to verify the assert path is wired correctly. Change one word of the recovery_mnemonic_phrase to something else, then run:

```bash
cargo test --release --workspace --test golden_vault_001 2>&1 | grep -E "panicked|drifted|FAIL" | head -5
```

Expected: a panic with message `pinned recovery_mnemonic_phrase drifted from RNG-derived entropy`. If the assertion does NOT fire, STOP and triage — the wiring is wrong. If it does fire, **revert the JSON edit** before continuing.

```bash
git diff core/tests/data/golden_vault_001_inputs.json   # confirm reverted to step-4 state
```

Expected: only the addition of `recovery_mnemonic_phrase` from Step 4 remains; no other diff.

- [ ] **Step 8: Run the full workspace tests + clippy + fmt**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_t1.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_t1.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

Expected: `TOTAL: 479 passed; 0 failed; 9 ignored` (no count change — the assertion runs inside existing tests; no new test is added). clippy + fmt clean.

- [ ] **Step 9: Verify on-disk vault fixtures unchanged**

```bash
git diff core/tests/data/golden_vault_001/ core/tests/data/golden_vault_002/
```

Expected: **no output** — the binary fixtures are byte-identical to baseline. If anything diffs, STOP and triage.

- [ ] **Step 10: Conformance + freshness check**

```bash
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected: both PASS.

- [ ] **Step 11: Commit**

```bash
git add core/tests/common/fixture_builder.rs core/tests/data/golden_vault_001_inputs.json core/tests/data/golden_vault_002_inputs.json
git commit -m "$(cat <<'EOF'
test(fixtures): pin recovery_mnemonic_phrase derived from RNG entropy

Adds `recovery_mnemonic_phrase` field to golden_vault_{001,002}_inputs.json,
deterministically derived from the existing pinned recovery entropy via
`bip39::Mnemonic::from_entropy(...).to_string()`. The fixture builder
asserts the JSON pin matches the bip39-derived value at build time, so
JSON drift cannot land silently.

Enables B.3a FFI smoke runners (pytest, Swift, Kotlin) to read the
phrase directly without linking against bip39 themselves. The on-disk
vault bytes (vault.toml, identity.bundle.enc, manifest, blocks,
contacts) are byte-identical — only the inputs JSON metadata grows.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 2 — Bridge crate

### Task 2: error.rs — promote defensive arms to active variants, rename message → detail, add tests

The bridge's `FfiUnlockError` currently has 3 variants (`WrongPasswordOrCorrupt`, `VaultMismatch`, `CorruptVault { message }`) plus defensive `From<UnlockError>` arms that fold `WrongMnemonicOrCorrupt` into `WrongPasswordOrCorrupt` (anti-oracle preserving) and `InvalidMnemonic(_)` / `WeakKdfParams { .. }` into `CorruptVault`. B.3a promotes the recovery-path arms to active variants AND renames the `CorruptVault.message` field to `detail` for naming uniformity with the new `InvalidMnemonic { detail }`.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error.rs`

- [ ] **Step 1: Replace the `FfiUnlockError` enum with the 5-variant version**

Open `ffi/secretary-ffi-bridge/src/error.rs`. Locate the existing enum and replace it. The new shape:

```rust
/// FFI-friendly thinned error type for the unlock entry points
/// (`open_with_password` and `open_with_recovery`). See [module docs](self)
/// for the rationale.
#[derive(Debug, Error)]
pub enum FfiUnlockError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13. Returned by `open_with_password`.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,

    /// Wrong recovery phrase OR vault corruption — parallel to
    /// `WrongPasswordOrCorrupt` for the recovery path. Same anti-oracle
    /// conflation: AEAD tag failure under `recovery_kek` is
    /// indistinguishable from corruption to the cryptography. Returned by
    /// `open_with_recovery`.
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,

    /// Invalid recovery phrase — pre-decryption validation failure
    /// (wrong word count, unknown word, bad checksum, or invalid UTF-8).
    /// Carries a free-form `detail` string for UI rendering. NOT a
    /// security oracle: BIP-39 wordlist + checksum validation runs on
    /// the input *before* any vault byte is touched, so the failure
    /// mode is "fix the typo and retry" rather than "vault is gone".
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic {
        /// Diagnostic text from the inner `MnemonicError` variant's
        /// `Display` impl, or `"phrase contained invalid UTF-8"` when
        /// the FFI input slice is not valid UTF-8.
        detail: String,
    },

    /// `vault.toml` and `identity.bundle.enc` reference different vaults.
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    /// Vault is corrupt or unreadable. Carries a diagnostic message for
    /// debugging; not pattern-matchable on the inner cause.
    #[error("vault is corrupt or unreadable: {detail}")]
    CorruptVault {
        /// Diagnostic text from the inner `core::UnlockError` variant's
        /// `Display` impl. Free-form; not part of the API contract.
        ///
        /// Renamed from `message` to `detail` in B.3a for naming
        /// uniformity with `InvalidMnemonic { detail }`. The uniffi
        /// projection layer was already using `detail` in B.2 to
        /// avoid a Kotlin `Throwable.message` collision; B.3a propagates
        /// the rename back to the bridge so all layers agree.
        detail: String,
    },
}
```

- [ ] **Step 2: Update the `From<core::UnlockError>` impl**

Replace the impl with the 5-variant version:

```rust
impl From<secretary_core::unlock::UnlockError> for FfiUnlockError {
    fn from(e: secretary_core::unlock::UnlockError) -> Self {
        use secretary_core::unlock::UnlockError as E;

        // Explicit match arms (no wildcard) so future core variants force a
        // compile error here. Each arm is chosen to preserve the §13
        // anti-oracle property where applicable: WrongPasswordOrCorrupt and
        // WrongMnemonicOrCorrupt each conflate "wrong key OR corrupt"
        // independently for their respective unlock path; InvalidMnemonic is
        // pre-decryption and is NOT an oracle.
        match e {
            E::WrongPasswordOrCorrupt => Self::WrongPasswordOrCorrupt,
            E::WrongMnemonicOrCorrupt => Self::WrongMnemonicOrCorrupt,
            E::InvalidMnemonic(inner) => Self::InvalidMnemonic {
                detail: inner.to_string(),
            },
            E::VaultMismatch => Self::VaultMismatch,

            E::CorruptVault
            | E::MalformedVaultToml(_)
            | E::MalformedBundleFile(_)
            | E::MalformedBundle(_)
            | E::KdfFailure(_) => Self::CorruptVault {
                detail: e.to_string(),
            },

            // SECURITY: defensive forward-compat for the only currently-
            // unreachable variant. `WeakKdfParams` is returned by `create_vault`
            // (which enforces the §1.2 v1 floor at write time); neither
            // `open_with_password` nor `open_with_recovery` enforces the floor
            // at read time. With `create_vault` deferred to B.3b, the variant
            // is unreachable through B.3a's surface; the mapping is forward-
            // compat insurance. If `create_vault` enters scope, re-validate
            // the mapping (and either expose `WeakKdfParams` as its own variant
            // or leave it folded into `CorruptVault`).
            E::WeakKdfParams { .. } => Self::CorruptVault {
                detail: e.to_string(),
            },
        }
    }
}
```

The module-level docstring at the top of the file should also mention the 5-variant version. Update the SUMMARY paragraph (look for the bullet list of variants and replace):

```rust
//! [`FfiUnlockError`] thins to 5 variants expressing **user-actionable
//! intent** rather than mirroring the core enum's structural shape:
//!
//! - [`FfiUnlockError::WrongPasswordOrCorrupt`] — "your password is wrong,
//!   try again". Returned by `open_with_password`. **Deliberately conflates
//!   wrong-password and corruption** per `docs/threat-model.md` §13's
//!   anti-oracle property; this MUST NOT be split into separate variants.
//! - [`FfiUnlockError::WrongMnemonicOrCorrupt`] — parallel to the above for
//!   the `open_with_recovery` path. Same anti-oracle conflation under
//!   `recovery_kek`.
//! - [`FfiUnlockError::InvalidMnemonic`] — pre-decryption: the input does
//!   not validate as a 24-word BIP-39 phrase (wrong word count, unknown
//!   word, bad checksum, or invalid UTF-8). NOT a security oracle.
//! - [`FfiUnlockError::VaultMismatch`] — "vault.toml and identity.bundle.enc
//!   reference different vaults; re-pair from backups".
//! - [`FfiUnlockError::CorruptVault`] — collapses
//!   `{core::CorruptVault, all MalformedX, KdfFailure, WeakKdfParams}`.
//!   Carries a diagnostic `detail: String` for debugging; structured
//!   pattern-matching on the inner cause is intentionally not supported.
```

- [ ] **Step 3: Update the existing tests for the renamed `detail` field and removed defensive arms**

Inside `mod tests` at the bottom of the file:

(a) `corrupt_vault_collapses_to_corrupt_vault` — destructures `{ message }`. Change to `{ detail }`:

```rust
#[test]
fn corrupt_vault_collapses_to_corrupt_vault() {
    let core_err = UnlockError::CorruptVault;
    let ffi: FfiUnlockError = core_err.into();
    let FfiUnlockError::CorruptVault { detail } = ffi else {
        panic!("expected CorruptVault");
    };
    assert!(detail.contains("vault data integrity failure"));
}
```

(b) `malformed_vault_toml_collapses_to_corrupt_vault_with_inner_display` — same field rename:

```rust
#[test]
fn malformed_vault_toml_collapses_to_corrupt_vault_with_inner_display() {
    let inner = VaultTomlError::MissingField("kdf");
    let core_err = UnlockError::MalformedVaultToml(inner);
    let ffi: FfiUnlockError = core_err.into();
    let FfiUnlockError::CorruptVault { detail } = ffi else {
        panic!("expected CorruptVault");
    };
    assert!(detail.contains("malformed vault.toml"));
    assert!(detail.contains("kdf"));
}
```

(c) `wrong_mnemonic_or_corrupt_maps_to_wrong_password_or_corrupt_for_anti_oracle` — promote: this defensive mapping is GONE in B.3a (the variant now has its own active mapping). REPLACE the test entirely with:

```rust
#[test]
fn wrong_mnemonic_or_corrupt_maps_to_dedicated_variant() {
    // B.3a promotes WrongMnemonicOrCorrupt from a defensive fold-into-
    // WrongPasswordOrCorrupt to its own dedicated FFI variant. The two
    // variants are now mutually exclusive by call site (open_with_password
    // emits the password variant; open_with_recovery emits the mnemonic
    // variant). The §13 anti-oracle conflation is preserved within each
    // path independently.
    let core_err = UnlockError::WrongMnemonicOrCorrupt;
    let ffi: FfiUnlockError = core_err.into();
    assert!(matches!(ffi, FfiUnlockError::WrongMnemonicOrCorrupt));
}
```

(d) `invalid_mnemonic_maps_defensively_to_corrupt_vault` — same promotion: REPLACE with three new tests covering the three `MnemonicError` sub-variants (Step 4 below).

- [ ] **Step 4: Add 5 new tests to `mod tests`**

Append after the existing tests (and after the deletion in Step 3(d)):

```rust
#[test]
fn invalid_mnemonic_wrong_length_carries_detail() {
    use secretary_core::unlock::mnemonic::MnemonicError;
    let core_err = UnlockError::InvalidMnemonic(MnemonicError::WrongLength { got: 3 });
    let ffi: FfiUnlockError = core_err.into();
    let FfiUnlockError::InvalidMnemonic { detail } = ffi else {
        panic!("expected InvalidMnemonic, got {ffi:?}");
    };
    assert!(detail.contains("got 3"), "detail did not carry word count: {detail}");
}

#[test]
fn invalid_mnemonic_unknown_word_carries_detail() {
    use secretary_core::unlock::mnemonic::MnemonicError;
    let core_err = UnlockError::InvalidMnemonic(MnemonicError::UnknownWord("xyzzy".to_string()));
    let ffi: FfiUnlockError = core_err.into();
    let FfiUnlockError::InvalidMnemonic { detail } = ffi else {
        panic!("expected InvalidMnemonic, got {ffi:?}");
    };
    assert!(detail.contains("xyzzy"), "detail did not carry the offending word: {detail}");
}

#[test]
fn invalid_mnemonic_bad_checksum_carries_detail() {
    use secretary_core::unlock::mnemonic::MnemonicError;
    let core_err = UnlockError::InvalidMnemonic(MnemonicError::BadChecksum);
    let ffi: FfiUnlockError = core_err.into();
    let FfiUnlockError::InvalidMnemonic { detail } = ffi else {
        panic!("expected InvalidMnemonic, got {ffi:?}");
    };
    assert!(detail.to_lowercase().contains("checksum"), "detail did not mention checksum: {detail}");
}

#[test]
fn weak_kdf_params_remains_defensively_mapped_to_corrupt_vault() {
    // SECURITY: with create_vault deferred to B.3b, this variant is
    // unreachable from open_with_password / open_with_recovery. The
    // defensive mapping here is forward-compat insurance — if create_vault
    // enters scope, re-validate whether WeakKdfParams should be exposed
    // as its own variant or stay folded into CorruptVault.
    let core_err = UnlockError::WeakKdfParams {
        memory_kib: 16,
        min_memory_kib: 65536,
    };
    let ffi: FfiUnlockError = core_err.into();
    assert!(matches!(ffi, FfiUnlockError::CorruptVault { .. }));
}

#[test]
fn corrupt_vault_field_renamed_to_detail() {
    // Pin the field rename: B.2 used `message`, B.3a renames to `detail`
    // for uniformity with InvalidMnemonic { detail }. This test is a
    // tripwire — a future refactor that reverts to `message` would fail
    // here AND break the uniffi/PyO3 forwarders, so it must be deliberate.
    let ffi = FfiUnlockError::CorruptVault {
        detail: "tripwire".to_string(),
    };
    let rendered = format!("{ffi}");
    assert!(rendered.contains("tripwire"));
    let FfiUnlockError::CorruptVault { detail } = ffi else {
        unreachable!()
    };
    assert_eq!(detail, "tripwire");
}
```

- [ ] **Step 5: Run bridge unit tests in isolation**

```bash
cargo test --release --package secretary-ffi-bridge --lib 2>&1 | grep -E "^test result:|FAIL|panicked"
```

Expected: `test result: ok. 26 passed; 0 failed` (bridge baseline is 22 unit tests across error.rs + identity.rs + unlock.rs; Task 2 net change is +4 in error.rs: -2 deleted defensive tests, +6 new tests covering the 5 spec-named additions plus the weak_kdf_params forward-compat tripwire). No FAIL or panicked.

If the count differs from 26 because the actual error.rs baseline is different from 11, the discrepancy is benign as long as the delta is +4 from baseline AND nothing failed. Trust `0 failed` more than the absolute count.

- [ ] **Step 6: Run the full workspace build to catch downstream compile breakage**

The `CorruptVault.message → detail` rename is a breaking change for any caller that pattern-matches on the field name. The compile errors below are EXPECTED at this point — they will be fixed in Tasks 5 (PyO3) and 7 (uniffi). The point of running this here is to surface them for visibility:

```bash
cargo build --release --workspace 2>&1 | grep -E "^error\[|^error:" | head -20
```

Expected errors:
1. `ffi/secretary-ffi-py/src/lib.rs:82` — `FfiUnlockError::CorruptVault { message }` no longer matches; needs `{ detail }`.
2. `ffi/secretary-ffi-uniffi/src/lib.rs:91` — same.
3. `ffi/secretary-ffi-uniffi/src/lib.rs:212` — `FfiUnlockError::CorruptVault { message: ... }` constructor no longer matches; needs `{ detail: ... }`.

If you see exactly those three errors (and no others), proceed. If you see additional unexpected errors, STOP and triage.

- [ ] **Step 7: Commit (compile errors in downstream crates are intentional and will be fixed in Tasks 5 and 7)**

```bash
git add ffi/secretary-ffi-bridge/src/error.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3a): grow FfiUnlockError from 3 → 5 variants, rename CorruptVault.message → detail

Promotes WrongMnemonicOrCorrupt and InvalidMnemonic(_) from defensive
forward-compat arms to active variants in the From<core::UnlockError>
impl. Adds new InvalidMnemonic { detail } variant that flattens the
core MnemonicError sub-enum (WrongLength / UnknownWord / BadChecksum)
into a single Display string at the FFI boundary, decoupling the
foreign API from any future BIP-39 sub-variant additions.

Renames CorruptVault.message → CorruptVault.detail for naming
uniformity with InvalidMnemonic { detail }. The uniffi projection
layer (secretary-ffi-uniffi/src/lib.rs::UnlockError) was already
using `detail` in B.2 to avoid a Kotlin Throwable.message collision;
B.3a propagates the rename back to the bridge so all layers agree.

Downstream compile errors in secretary-ffi-py and secretary-ffi-uniffi
are expected at this commit and fixed in subsequent commits.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: unlock.rs — open_with_recovery + UTF-8 validation seam + integration tests

Add the new `pub fn open_with_recovery` to `ffi/secretary-ffi-bridge/src/unlock.rs`. The function takes mnemonic input as `&[u8]` (UTF-8 bytes), converts to `&str` via `std::str::from_utf8` (surfacing failure as `InvalidMnemonic { detail: "phrase contained invalid UTF-8" }`), and forwards to `core::unlock::open_with_recovery`.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/unlock.rs`

- [ ] **Step 1: Add the `open_with_recovery` free function**

Append AFTER the existing `open_with_password` function (and BEFORE the `#[cfg(test)] mod tests`):

```rust
/// Unlock a vault using its 24-word BIP-39 recovery phrase. Returns an
/// opaque handle that exposes non-secret accessors and an explicit `close()`.
///
/// The `mnemonic_bytes` input is UTF-8-encoded; the bridge calls
/// `std::str::from_utf8` and surfaces a malformed-UTF-8 input as
/// [`FfiUnlockError::InvalidMnemonic`] with `detail: "phrase contained
/// invalid UTF-8"`. Past that, `core::unlock::mnemonic::parse` does NFKD
/// normalization, lowercase, whitespace-collapse, BIP-39 wordlist lookup,
/// and checksum validation; the bridge does not duplicate any of that.
///
/// The input slice is borrowed; the bridge does not retain it. Wrapper-
/// side `Vec<u8>` zeroize is the binding-flavor crate's responsibility
/// (matches the B.2 password-input pattern).
///
/// # Errors
///
/// - [`FfiUnlockError::WrongMnemonicOrCorrupt`] — phrase is wrong, OR
///   one of the encrypted files has been tampered with. Indistinguishable
///   by design (anti-oracle property), parallel to
///   [`FfiUnlockError::WrongPasswordOrCorrupt`].
/// - [`FfiUnlockError::InvalidMnemonic`] — phrase failed BIP-39 validation
///   *before* any decryption was attempted (wrong word count, unknown
///   word, bad checksum, or invalid UTF-8 input).
/// - [`FfiUnlockError::VaultMismatch`] — `vault_toml_bytes` and
///   `identity_bundle_bytes` reference different vault UUIDs / timestamps.
/// - [`FfiUnlockError::CorruptVault`] — the inputs cannot be decoded as
///   well-formed v1 vault files.
pub fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mnemonic_bytes: &[u8],
) -> Result<UnlockedIdentity, FfiUnlockError> {
    let mnemonic_str = std::str::from_utf8(mnemonic_bytes).map_err(|_| {
        FfiUnlockError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".to_string(),
        }
    })?;
    let unlocked = secretary_core::unlock::open_with_recovery(
        vault_toml_bytes,
        identity_bundle_bytes,
        mnemonic_str,
    )?;
    Ok(UnlockedIdentity::new(unlocked))
    // mnemonic_str borrows from caller's slice; nothing to drop here.
    // The caller's foreign-side mnemonic buffer is THEIR concern (matches
    // the B.2 password-input pattern).
}
```

- [ ] **Step 2: Add `VAULT_002_TOML` and the two pinned phrase constants to the `mod tests` constants block**

In the existing `#[cfg(test)] mod tests` block, locate the `VAULT_001_TOML` / `VAULT_001_BUNDLE` / `VAULT_002_BUNDLE` constants and add:

```rust
const VAULT_002_TOML: &[u8] =
    include_bytes!("../../../core/tests/data/golden_vault_002/vault.toml");

/// Pinned 24-word BIP-39 recovery phrase for golden_vault_001.
/// Source of truth: `core/tests/data/golden_vault_001_inputs.json`'s
/// `recovery_mnemonic_phrase` field. The fixture builder asserts that
/// field matches `bip39::Mnemonic::from_entropy(pinned_entropy).to_string()`,
/// so this hardcoded copy stays honest as long as the JSON does. If
/// the JSON drifts, the open_with_recovery_success test fails loudly
/// with WrongMnemonicOrCorrupt.
const VAULT_001_PHRASE: &[u8] = b"<paste vault_001 phrase from Task 1 Step 2 here>";

/// Pinned 24-word BIP-39 recovery phrase for golden_vault_002.
/// Source of truth: `core/tests/data/golden_vault_002_inputs.json`.
const VAULT_002_PHRASE: &[u8] = b"<paste vault_002 phrase from Task 1 Step 2 here>";
```

(Replace the placeholder strings with the actual phrases captured in Task 1 Step 2.)

- [ ] **Step 3: Add 5 new integration tests inside `mod tests`**

Append these tests to `mod tests` after the existing `open_with_password_*` tests:

```rust
#[test]
fn open_with_recovery_success_returns_unlocked_handle() {
    let id = open_with_recovery(VAULT_001_TOML, VAULT_001_BUNDLE, VAULT_001_PHRASE)
        .expect("recovery unlock should succeed against vault_001");
    // Same KAT as open_with_password_success — both unlock paths must
    // converge on byte-identical secret state (§3/§4 dual-KEK design).
    assert_eq!(id.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
    assert_eq!(id.user_uuid(), VAULT_001_OWNER_USER_UUID);
}

#[test]
fn open_with_recovery_wrong_mnemonic_returns_thinned_error() {
    // vault_002's phrase against vault_001's vault — valid 24-word phrase
    // but wrong vault, so AEAD-decrypt under recovery_kek tag-fails →
    // WrongMnemonicOrCorrupt (anti-oracle preserving).
    let err = open_with_recovery(VAULT_001_TOML, VAULT_001_BUNDLE, VAULT_002_PHRASE)
        .unwrap_err();
    assert!(
        matches!(err, FfiUnlockError::WrongMnemonicOrCorrupt),
        "expected WrongMnemonicOrCorrupt, got {err:?}",
    );
}

#[test]
fn open_with_recovery_wrong_length_returns_invalid_mnemonic() {
    let err = open_with_recovery(VAULT_001_TOML, VAULT_001_BUNDLE, b"only three words")
        .unwrap_err();
    let FfiUnlockError::InvalidMnemonic { detail } = err else {
        panic!("expected InvalidMnemonic, got {err:?}");
    };
    assert!(
        detail.contains("got 3"),
        "detail did not carry word count: {detail}",
    );
}

#[test]
fn open_with_recovery_invalid_utf8_returns_invalid_mnemonic() {
    // 0xFF is not valid UTF-8 in any byte position. The bridge's UTF-8
    // validation seam runs BEFORE the BIP-39 wordlist lookup so this
    // produces the bridge-specific "phrase contained invalid UTF-8"
    // detail rather than a wordlist failure.
    let bad_utf8 = [0xFFu8; 32];
    let err = open_with_recovery(VAULT_001_TOML, VAULT_001_BUNDLE, &bad_utf8).unwrap_err();
    let FfiUnlockError::InvalidMnemonic { detail } = err else {
        panic!("expected InvalidMnemonic, got {err:?}");
    };
    assert!(
        detail.contains("UTF-8"),
        "detail did not mention UTF-8: {detail}",
    );
}

#[test]
fn open_with_recovery_swapped_files_returns_vault_mismatch() {
    // vault_001 toml + vault_002 bundle + vault_001 phrase →
    // VaultMismatch fires at core's vault_uuid + created_at_ms comparison
    // BEFORE the mnemonic is even parsed, so the mnemonic correctness
    // (or otherwise) is irrelevant to this assertion.
    let err = open_with_recovery(VAULT_001_TOML, VAULT_002_BUNDLE, VAULT_001_PHRASE)
        .unwrap_err();
    assert!(
        matches!(err, FfiUnlockError::VaultMismatch),
        "expected VaultMismatch, got {err:?}",
    );
}
```

- [ ] **Step 4: Run bridge tests in isolation to verify all 5 new integration tests pass**

```bash
cargo test --release --package secretary-ffi-bridge 2>&1 | grep -E "^test result:|FAIL|panicked"
```

Expected: `test result: ok. 31 passed; 0 failed` (was 26 after Task 2; +5 new integration tests in `unlock.rs::mod tests`). No FAIL. Same fallback as Task 2 Step 5: trust `0 failed` and the +5 delta over the absolute count.

- [ ] **Step 5: Verify clippy + fmt clean for the bridge crate**

```bash
cargo clippy --release --package secretary-ffi-bridge -- -D warnings && echo "bridge clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/unlock.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3a): add open_with_recovery to bridge crate with UTF-8 seam

Mnemonic input is &[u8] (UTF-8 bytes), matching B.2's password-input
pattern; bridge does std::str::from_utf8 and surfaces failure as
InvalidMnemonic { detail: "phrase contained invalid UTF-8" }. Past
that, core::unlock::mnemonic::parse handles NFKD normalization,
lowercase, whitespace-collapse, BIP-39 wordlist lookup, and checksum
validation; bridge does not duplicate any of that.

Five new integration tests pin: success path KAT (open_with_password
and open_with_recovery converge on byte-identical secret state per
§3/§4 dual-KEK design), wrong-mnemonic → WrongMnemonicOrCorrupt,
wrong-length → InvalidMnemonic with word-count detail, invalid-UTF-8
→ InvalidMnemonic with UTF-8 detail, vault-mismatch (mnemonic
correctness is irrelevant; UUID-comparison fires first).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: lib.rs — re-export open_with_recovery, update crate doc

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`

- [ ] **Step 1: Update the crate-level doc comment**

Open `ffi/secretary-ffi-bridge/src/lib.rs`. The existing crate-doc lists `[FfiUnlockError]` / `[UnlockedIdentity]` / `[open_with_password]` under "# Surface". Update to mention 5 variants and the new entry point. Locate this block and replace:

```rust
//! # Surface
//!
//! - [`FfiUnlockError`] — thinned 5-variant error type expressing
//!   user-actionable intent rather than mirroring `core::UnlockError`'s
//!   internal enum structure. Two variants per unlock path
//!   (`WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt`) plus a
//!   pre-decryption `InvalidMnemonic { detail }` for BIP-39 validation
//!   failures, plus the cross-path `VaultMismatch` and `CorruptVault { detail }`.
//!   See [`error`] module docs.
//! - [`UnlockedIdentity`] — opaque handle wrapping a successfully-unlocked
//!   `core::UnlockedIdentity`. Foreign callers hold a refcount and read
//!   non-secret fields via accessor methods; the secret keys stay Rust-
//!   side and zeroize on drop. Both unlock entry points return this same
//!   shape (the §3/§4 dual-KEK design produces byte-identical secret state).
//!   See [`identity`] module docs.
//! - [`open_with_password`] — fallible, secret-bearing operation: vault
//!   unlock by master password. See [`unlock`] module docs.
//! - [`open_with_recovery`] — fallible, secret-bearing operation: vault
//!   unlock by 24-word BIP-39 recovery phrase. Mnemonic input is UTF-8
//!   bytes (`&[u8]`), parallel to the password input shape. See [`unlock`]
//!   module docs.
```

- [ ] **Step 2: Add the `open_with_recovery` re-export**

Below the existing `pub use unlock::open_with_password;` line, add:

```rust
pub use unlock::open_with_recovery;
```

(The existing `pub use error::FfiUnlockError;` already re-exports the new variants automatically — no change there.)

- [ ] **Step 3: Verify bridge crate still builds cleanly**

```bash
cargo build --release --package secretary-ffi-bridge 2>&1 | tail -3
cargo test --release --package secretary-ffi-bridge 2>&1 | grep -E "^test result:"
```

Expected: `Finished` and `test result: ok. 31 passed; 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3a): re-export open_with_recovery from bridge crate

Updates crate-doc to describe the 5-variant FfiUnlockError surface
and the dual-KEK convergence property (open_with_password and
open_with_recovery both return UnlockedIdentity carrying byte-
identical secret state, per §3/§4 of crypto-design.md).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 3 — secretary-ffi-py projection

### Task 5: PyO3 wrapper — exception classes + open_with_recovery #[pyfunction]

**Files:**
- Modify: `ffi/secretary-ffi-py/src/lib.rs`

- [ ] **Step 1: Add 2 new `create_exception!` macros**

Open `ffi/secretary-ffi-py/src/lib.rs`. Locate the existing `create_exception!` block (around line 68-70):

```rust
create_exception!(secretary_ffi_py, WrongPasswordOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultMismatch, PyException);
create_exception!(secretary_ffi_py, CorruptVault, PyException);
```

Add two more:

```rust
create_exception!(secretary_ffi_py, WrongMnemonicOrCorrupt, PyException);
create_exception!(secretary_ffi_py, InvalidMnemonic, PyException);
```

The order doesn't matter (each macro is independent); place the new ones immediately after the existing three for clarity.

- [ ] **Step 2: Update `ffi_unlock_error_to_pyerr` for the new variants AND the renamed `detail` field**

Replace the existing `match` body (line 79-83):

```rust
fn ffi_unlock_error_to_pyerr(e: FfiUnlockError) -> PyErr {
    match e {
        FfiUnlockError::WrongPasswordOrCorrupt => WrongPasswordOrCorrupt::new_err(e.to_string()),
        FfiUnlockError::WrongMnemonicOrCorrupt => WrongMnemonicOrCorrupt::new_err(e.to_string()),
        FfiUnlockError::InvalidMnemonic { detail } => InvalidMnemonic::new_err(detail),
        FfiUnlockError::VaultMismatch => VaultMismatch::new_err(e.to_string()),
        FfiUnlockError::CorruptVault { detail } => CorruptVault::new_err(detail),
    }
}
```

Note the `CorruptVault { detail }` change (from `{ message }`) and the new `InvalidMnemonic` arm.

- [ ] **Step 3: Add the `open_with_recovery` `#[pyfunction]`**

After the existing `open_with_password` `#[pyfunction]` (around line 156), add:

```rust
/// Unlock a vault using its 24-word BIP-39 recovery phrase. See
/// module-level docs for the exception classes raised on failure.
#[pyfunction]
fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mut mnemonic: Vec<u8>,
) -> PyResult<UnlockedIdentity> {
    use zeroize::Zeroize;
    // Mirrors the open_with_password wrapper-side zeroize discipline:
    // the bridge takes &[u8] and never retains; this Vec is the wrapper's
    // owned copy of the foreign caller's bytes-like input. Zero it after
    // the bridge returns so the password-equivalent doesn't linger on
    // the wrapper heap.
    let result = secretary_ffi_bridge::open_with_recovery(
        vault_toml_bytes,
        identity_bundle_bytes,
        &mnemonic,
    )
    .map(UnlockedIdentity)
    .map_err(ffi_unlock_error_to_pyerr);
    mnemonic.zeroize();
    result
}
```

- [ ] **Step 4: Register the new `#[pyfunction]` and exception classes in `#[pymodule]`**

Locate the `#[pymodule]` `secretary_ffi_py` function (around line 161-178). Append to its body, after the existing B.2 registrations:

```rust
    // B.3a surface:
    m.add_function(wrap_pyfunction!(open_with_recovery, m)?)?;
    m.add(
        "WrongMnemonicOrCorrupt",
        py.get_type::<WrongMnemonicOrCorrupt>(),
    )?;
    m.add("InvalidMnemonic", py.get_type::<InvalidMnemonic>())?;
```

- [ ] **Step 5: Update the crate-level doc comment**

The existing comment ends with:

```rust
//! B.2 (this version) adds the `open_with_password` entry-point and the
//! `UnlockedIdentity` opaque handle, projecting `secretary-ffi-bridge`'s
//! FFI-friendly facade through PyO3.
```

Append below it:

```rust
//!
//! B.3a adds the `open_with_recovery` entry-point and 2 new exception
//! classes (`WrongMnemonicOrCorrupt`, `InvalidMnemonic`). Mnemonic
//! input is `bytes`/`bytearray` (UTF-8 encoded); the bridge's UTF-8-
//! validation seam surfaces malformed-UTF-8 input as `InvalidMnemonic`
//! with `detail: "phrase contained invalid UTF-8"`.
```

And add a B.3a rationale line near the existing B.2 rationale line:

```rust
//! Rationale (B.3a): docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md
```

- [ ] **Step 6: Build the maturin wheel**

```bash
cd ffi/secretary-ffi-py
uv run maturin develop --release --uv 2>&1 | tail -10
cd ../..
```

Expected: `Finished` then `Built wheel ...` then `Installed secretary_ffi_py-0.1.0`. If the build fails with a compile error mentioning `CorruptVault`'s field name, double-check Step 2.

- [ ] **Step 7: Run pytest to make sure nothing existing is broken**

```bash
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -5
```

Expected: `10 passed` (no count change yet — Task 6 adds the new tests). If tests fail, the most likely cause is a stale `.so` cache; run `( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )` again.

- [ ] **Step 8: Run cargo test on the secretary-ffi-py crate**

```bash
cargo test --release --package secretary-ffi-py 2>&1 | grep -E "^test result:|FAIL"
```

Expected: existing 3 unit tests pass.

- [ ] **Step 9: Verify clippy clean for the secretary-ffi-py crate**

```bash
cargo clippy --release --package secretary-ffi-py -- -D warnings && echo "py clippy OK"
```

- [ ] **Step 10: Commit**

```bash
git add ffi/secretary-ffi-py/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3a): add PyO3 open_with_recovery + 2 new exception classes

Projects the bridge crate's open_with_recovery free function through
PyO3 as the Python-facing #[pyfunction]. Adds two new exception
classes (WrongMnemonicOrCorrupt, InvalidMnemonic) registered under
the secretary_ffi_py module. Mnemonic input is bytes/bytearray
(UTF-8 encoded); wrapper-side Vec<u8> is zeroized after the bridge
returns, mirroring the B.2 password-input pattern.

Updates ffi_unlock_error_to_pyerr to handle the 5-variant
FfiUnlockError shape and the renamed CorruptVault.detail field.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: pytest tests — 6 new B.3a tests

**Files:**
- Modify: `ffi/secretary-ffi-py/tests/test_smoke.py`

- [ ] **Step 1: Add a JSON-loader helper for the recovery phrase**

Open `ffi/secretary-ffi-py/tests/test_smoke.py`. Below the existing `_read_fixture` helper (around line 47), add:

```python
import json


def _golden_vault_phrase(n: int) -> bytes:
    """Read the pinned `recovery_mnemonic_phrase` field from
    `core/tests/data/golden_vault_{n:03d}_inputs.json` and return it as
    UTF-8 bytes ready for `open_with_recovery`. The fixture builder
    asserts the JSON pin matches `bip39::Mnemonic::from_entropy(...)
    .to_string()`, so this stays honest as long as the JSON does."""
    inputs_path = (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}_inputs.json"
    )
    with inputs_path.open() as fh:
        data = json.load(fh)
    return data["recovery_mnemonic_phrase"].encode("utf-8")
```

(`json` is in stdlib so no new dependency. The `import json` line goes at the top of the file with the other imports.)

- [ ] **Step 2: Add 6 new pytest tests**

Append to the bottom of `test_smoke.py` after the existing B.2 tests:

```python
# ---------------------------------------------------------------------------
# B.3a: open_with_recovery tests against golden_vault_001 + golden_vault_002.
# ---------------------------------------------------------------------------


def test_open_with_recovery_success_returns_pinned_identity() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    phrase = _golden_vault_phrase(1)
    with secretary_ffi_py.open_with_recovery(toml, bundle, phrase) as identity:
        # Same KAT as the open_with_password success path — both unlock
        # paths converge on byte-identical secret state per §3/§4 dual-
        # KEK design.
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
        assert identity.user_uuid() == VAULT_001_OWNER_USER_UUID


def test_open_with_recovery_wrong_mnemonic_raises_wrong_mnemonic_or_corrupt() -> None:
    # vault_002's phrase against vault_001's vault — valid 24-word phrase
    # but wrong vault, so AEAD-decrypt under recovery_kek tag-fails →
    # WrongMnemonicOrCorrupt (anti-oracle preserving).
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    wrong_phrase = _golden_vault_phrase(2)
    with pytest.raises(secretary_ffi_py.WrongMnemonicOrCorrupt):
        secretary_ffi_py.open_with_recovery(toml, bundle, wrong_phrase)


def test_open_with_recovery_wrong_length_raises_invalid_mnemonic() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.InvalidMnemonic) as exc_info:
        secretary_ffi_py.open_with_recovery(toml, bundle, b"only three words")
    assert "got 3" in str(exc_info.value)


def test_open_with_recovery_invalid_utf8_raises_invalid_mnemonic() -> None:
    # 0xFF is not valid UTF-8 in any byte position; the bridge's UTF-8
    # validation seam catches this before the BIP-39 wordlist lookup.
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.InvalidMnemonic) as exc_info:
        secretary_ffi_py.open_with_recovery(toml, bundle, bytes([0xFF] * 32))
    assert "UTF-8" in str(exc_info.value)


def test_open_with_recovery_swapped_files_raises_vault_mismatch() -> None:
    # vault_001 toml + vault_002 bundle + vault_001 phrase. The vault_uuid
    # comparison fires BEFORE mnemonic parsing, so even an "invalid" phrase
    # would still produce VaultMismatch on this input pair.
    toml_001 = _read_fixture(1, "vault.toml")
    bundle_002 = _read_fixture(2, "identity.bundle.enc")
    phrase_001 = _golden_vault_phrase(1)
    with pytest.raises(secretary_ffi_py.VaultMismatch):
        secretary_ffi_py.open_with_recovery(toml_001, bundle_002, phrase_001)


def test_open_with_recovery_accepts_bytearray_for_caller_zeroize_discipline() -> None:
    """Documents the design: mnemonic accepted as bytes-like; disciplined
    callers can zero a mutable bytearray after the call (parallel to the
    password-input pattern from B.2)."""
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    phrase = bytearray(_golden_vault_phrase(1))
    with secretary_ffi_py.open_with_recovery(toml, bundle, phrase) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
    # Caller's zeroize discipline (recommended for first-party clients):
    for i in range(len(phrase)):
        phrase[i] = 0
    assert all(b == 0 for b in phrase)
```

- [ ] **Step 3: Rebuild the maturin wheel and run pytest**

```bash
cd ffi/secretary-ffi-py
uv run maturin develop --release --uv 2>&1 | tail -5
cd ../..
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -10
```

Expected: `16 passed` (was 10; +6).

- [ ] **Step 4: Commit**

```bash
git add ffi/secretary-ffi-py/tests/test_smoke.py
git commit -m "$(cat <<'EOF'
test(ffi-b3a): add 6 pytest tests for open_with_recovery

Six new tests pin the foreign-language surface for the recovery
unlock path: success-path KAT (display_name + user_uuid match B.2
values per dual-KEK convergence), wrong-mnemonic →
WrongMnemonicOrCorrupt, wrong-length / invalid-UTF-8 →
InvalidMnemonic with assertion on detail content, vault-mismatch
(bundle from a different vault), bytearray caller-zeroize discipline.

`_golden_vault_phrase(n)` helper reads the pinned phrase from
golden_vault_{n:03d}_inputs.json so the test file is the consumer
of the JSON, not a parallel source of truth. JSON drift is caught
by the bip39 derive-and-assert in core's fixture_builder.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 4 — secretary-ffi-uniffi projection

### Task 7: UDL + Rust glue — 2 new error variants, open_with_recovery namespace fn

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs`

- [ ] **Step 1: Update the UDL surface**

Open `ffi/secretary-ffi-uniffi/src/secretary.udl`. Locate the `[Error] interface UnlockError` block and add 2 new variants:

```idl
[Error]
interface UnlockError {
    WrongPasswordOrCorrupt();
    WrongMnemonicOrCorrupt();
    InvalidMnemonic(string detail);
    VaultMismatch();
    CorruptVault(string detail);
};
```

Inside the `namespace secretary { ... }` block, after the existing `open_with_password` declaration, add:

```idl
    /// Unlock a vault using its 24-word BIP-39 recovery phrase. (B.3a)
    [Throws=UnlockError]
    UnlockedIdentity open_with_recovery(
        bytes vault_toml_bytes,
        bytes identity_bundle_bytes,
        bytes mnemonic
    );
```

- [ ] **Step 2: Update the uniffi-side `UnlockError` enum in `lib.rs`**

Open `ffi/secretary-ffi-uniffi/src/lib.rs`. Locate the existing enum (around line 67-84) and replace with the 5-variant version:

```rust
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13. Returned by `open_with_password`.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    /// Wrong recovery phrase OR vault corruption — parallel to the password
    /// path. Returned by `open_with_recovery`.
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,
    /// Invalid recovery phrase — pre-decryption BIP-39 validation failure
    /// (wrong word count, unknown word, bad checksum, or invalid UTF-8).
    /// NOT a security oracle.
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic {
        /// Diagnostic text; free-form.
        detail: String,
    },
    /// `vault.toml` and `identity.bundle.enc` reference different vaults.
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,
    /// Vault is corrupt or unreadable. The `detail` field carries a
    /// diagnostic string from the inner core error.
    #[error("vault is corrupt or unreadable: {detail}")]
    CorruptVault {
        /// Diagnostic text from the inner `core::UnlockError` variant's
        /// `Display` impl. Free-form; not part of the API contract.
        detail: String,
    },
}
```

- [ ] **Step 3: Update the `From<FfiUnlockError> for UnlockError` impl**

Locate the existing impl (around line 86-94) and replace:

```rust
impl From<FfiUnlockError> for UnlockError {
    fn from(e: FfiUnlockError) -> Self {
        match e {
            FfiUnlockError::WrongPasswordOrCorrupt => Self::WrongPasswordOrCorrupt,
            FfiUnlockError::WrongMnemonicOrCorrupt => Self::WrongMnemonicOrCorrupt,
            FfiUnlockError::InvalidMnemonic { detail } => Self::InvalidMnemonic { detail },
            FfiUnlockError::VaultMismatch => Self::VaultMismatch,
            FfiUnlockError::CorruptVault { detail } => Self::CorruptVault { detail },
        }
    }
}
```

(Note: `CorruptVault { detail }` uses struct-shorthand now that the bridge field is also named `detail`. The previous `Self::CorruptVault { detail: message }` rename-on-translation is no longer needed.)

- [ ] **Step 4: Add the `open_with_recovery` `pub fn`**

After the existing `open_with_password` function (around line 158), add:

```rust
/// Unlock a vault using its 24-word BIP-39 recovery phrase. uniffi-projected.
///
/// Mnemonic input is UTF-8-encoded bytes (`Vec<u8>`); the bridge's UTF-8
/// validation seam surfaces malformed-UTF-8 input as
/// [`UnlockError::InvalidMnemonic`] with `detail: "phrase contained
/// invalid UTF-8"`.
///
/// # Errors
///
/// Returns [`UnlockError`] on failure. See the bridge crate's
/// [`FfiUnlockError`](secretary_ffi_bridge::FfiUnlockError) docs for the
/// thinned 5-variant rationale.
pub fn open_with_recovery(
    vault_toml_bytes: Vec<u8>,
    identity_bundle_bytes: Vec<u8>,
    mut mnemonic: Vec<u8>,
) -> Result<std::sync::Arc<UnlockedIdentity>, UnlockError> {
    use zeroize::Zeroize;
    // Mirrors the open_with_password wrapper-side stack-residue discipline:
    // zero the mnemonic Vec after the bridge returns. The bridge takes &[u8]
    // and never retains; this Vec is the projection-side transient.
    let result = secretary_ffi_bridge::open_with_recovery(
        &vault_toml_bytes,
        &identity_bundle_bytes,
        &mnemonic,
    )
    .map(|inner| std::sync::Arc::new(UnlockedIdentity(inner)))
    .map_err(UnlockError::from);
    mnemonic.zeroize();
    result
}
```

- [ ] **Step 5: Update the existing CorruptVault test for the renamed field, then add 2 new mapping tests**

Locate `from_bridge_corrupt_vault_preserves_message` (around line 207-219) and rename it to `from_bridge_corrupt_vault_preserves_detail` AND replace the `message: ` constructor usage with `detail: `:

```rust
#[test]
fn from_bridge_corrupt_vault_preserves_detail() {
    // B.3a renamed the bridge's CorruptVault field from `message` to
    // `detail` for naming uniformity with InvalidMnemonic { detail }.
    // Both layers now use `detail`; the From translation is a struct-
    // shorthand pass-through.
    let bridge_err = FfiUnlockError::CorruptVault {
        detail: "fnord".to_string(),
    };
    let uniffi_err: UnlockError = bridge_err.into();
    let UnlockError::CorruptVault { detail } = uniffi_err else {
        panic!("expected CorruptVault");
    };
    assert_eq!(detail, "fnord");
}
```

Then append 2 new mapping tests after it (inside the same `mod tests`):

```rust
#[test]
fn from_bridge_wrong_mnemonic_or_corrupt_maps_one_to_one() {
    let bridge_err = FfiUnlockError::WrongMnemonicOrCorrupt;
    let uniffi_err: UnlockError = bridge_err.into();
    assert!(matches!(uniffi_err, UnlockError::WrongMnemonicOrCorrupt));
}

#[test]
fn from_bridge_invalid_mnemonic_preserves_detail() {
    let bridge_err = FfiUnlockError::InvalidMnemonic {
        detail: "expected 24 words, got 3".to_string(),
    };
    let uniffi_err: UnlockError = bridge_err.into();
    let UnlockError::InvalidMnemonic { detail } = uniffi_err else {
        panic!("expected InvalidMnemonic");
    };
    assert_eq!(detail, "expected 24 words, got 3");
}
```

- [ ] **Step 6: Update the crate-level doc comment**

The existing comment ends with:

```rust
//! Rationale: secretary_next_session.md "Begin Sub-project B.1.1".
```

Append:

```rust
//!
//! B.3a (this version) adds the `open_with_recovery` namespace function
//! and 2 new `UnlockError` variants (`WrongMnemonicOrCorrupt`,
//! `InvalidMnemonic { detail }`). Mnemonic input is UTF-8 bytes; the
//! bridge's UTF-8 validation seam surfaces malformed input as
//! `InvalidMnemonic`.
//!
//! Rationale (B.3a): docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md
```

- [ ] **Step 7: Build the secretary-ffi-uniffi crate to surface compile errors**

```bash
cargo build --release --package secretary-ffi-uniffi 2>&1 | tail -10
```

Expected: `Finished` (no errors). uniffi's UDL-driven scaffolding regenerates from the new `secretary.udl`.

- [ ] **Step 8: Run unit tests for the secretary-ffi-uniffi crate**

```bash
cargo test --release --package secretary-ffi-uniffi 2>&1 | grep -E "^test result:"
```

Expected: `test result: ok. 8 passed; 0 failed` (was 6; +2 new mapping tests + 1 renamed test). If the count differs by more or less than expected, STOP and triage.

- [ ] **Step 9: Verify clippy + fmt clean**

```bash
cargo clippy --release --package secretary-ffi-uniffi -- -D warnings && echo "uniffi clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
```

- [ ] **Step 10: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/secretary.udl ffi/secretary-ffi-uniffi/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(ffi-b3a): add uniffi open_with_recovery + 2 new UnlockError variants

UDL gains two new [Error] interface variants
(WrongMnemonicOrCorrupt, InvalidMnemonic(string detail)) and one new
namespace function (open_with_recovery). uniffi-side UnlockError
enum + From<FfiUnlockError> impl mirror the bridge crate's 5-variant
shape exactly; the From translation is a struct-shorthand pass-
through now that bridge and uniffi-side both use `detail`.

Wrapper-side Vec<u8> zeroize for the mnemonic input mirrors the B.2
password-input pattern. Two new mapping tests pin
WrongMnemonicOrCorrupt and InvalidMnemonic.detail through the
projection layer.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Swift + Kotlin smoke runners — 4 new asserts each

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`

- [ ] **Step 1: Add `recovery_mnemonic_phrase` JSON-loader to Swift main.swift**

Open `ffi/secretary-ffi-uniffi/tests/swift/main.swift`. Locate the existing fixture-loading block (around lines 68-80, where `toml001`, `bundle001`, `bundle002` are read). After it, add a phrase-loading block:

```swift
// B.3a: read recovery_mnemonic_phrase from golden_vault_NNN_inputs.json.
// JSON path is sibling to the golden_vault_NNN/ fixture directory.
let inputs001Url = URL(fileURLWithPath: vaultDir).appendingPathComponent("golden_vault_001_inputs.json")
let inputs002Url = URL(fileURLWithPath: vaultDir).appendingPathComponent("golden_vault_002_inputs.json")

func _phraseFromInputs(_ url: URL) -> Data {
    do {
        let data = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let phrase = json?["recovery_mnemonic_phrase"] as? String else {
            FileHandle.standardError.write(
                Data("error: recovery_mnemonic_phrase missing or not a string in \(url.path)\n".utf8)
            )
            exit(1)
        }
        return phrase.data(using: .utf8)!
    } catch {
        FileHandle.standardError.write(
            Data("error: failed to read \(url.path): \(error)\n".utf8)
        )
        exit(1)
    }
}

let phrase001: Data = _phraseFromInputs(inputs001Url)
let phrase002: Data = _phraseFromInputs(inputs002Url)
```

- [ ] **Step 2: Add 4 new Swift asserts after the existing assertion 8**

Append after the closing `}` of the existing assertion 8 block (around line 193, before the `if !failures.isEmpty` block):

```swift
// --- B.3a: open_with_recovery assertions ---

// Assertion 9: recovery success path.
do {
    let identity = try openWithRecovery(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        mnemonic: phrase001
    )
    defer { identity.wipe() }

    let displayName = identity.displayName()
    let uuid = identity.userUuid()
    check(
        displayName == expectedDisplayName && uuid == expectedUserUuid,
        "open_with_recovery success → display_name + user_uuid match pinned KAT (got displayName=\"\(displayName)\")"
    )
} catch {
    check(false, "open_with_recovery success threw \(error), expected to succeed")
}

// Assertion 10: wrong recovery phrase → WrongMnemonicOrCorrupt.
do {
    _ = try openWithRecovery(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        mnemonic: phrase002
    )
    check(false, "vault_002 phrase against vault_001 should have thrown WrongMnemonicOrCorrupt")
} catch UnlockError.WrongMnemonicOrCorrupt {
    check(true, "vault_002 phrase against vault_001 → WrongMnemonicOrCorrupt")
} catch {
    check(false, "wrong phrase threw \(error), expected WrongMnemonicOrCorrupt")
}

// Assertion 11: 3-word phrase → InvalidMnemonic(detail).
do {
    let bad = "only three words".data(using: .utf8)!
    _ = try openWithRecovery(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle001,
        mnemonic: bad
    )
    check(false, "3-word phrase should have thrown InvalidMnemonic")
} catch let UnlockError.InvalidMnemonic(detail) {
    check(
        detail.contains("got 3"),
        "3-word phrase → InvalidMnemonic(detail=\"\(detail)\") should mention `got 3`"
    )
} catch {
    check(false, "3-word phrase threw \(error), expected InvalidMnemonic")
}

// Assertion 12: cross-vault file pair with recovery path → VaultMismatch.
// Mnemonic correctness is irrelevant here; the vault_uuid + created_at_ms
// comparison fires before any mnemonic parse.
do {
    _ = try openWithRecovery(
        vaultTomlBytes: toml001,
        identityBundleBytes: bundle002,
        mnemonic: phrase001
    )
    check(false, "vault_001 toml + vault_002 bundle (recovery) should have thrown VaultMismatch")
} catch UnlockError.VaultMismatch {
    check(true, "vault_001 toml + vault_002 bundle (recovery) → VaultMismatch")
} catch {
    check(false, "vault mismatch (recovery) threw \(error), expected VaultMismatch")
}
```

- [ ] **Step 3: Update the failure-summary assertion-count constant**

Locate the existing failure summary (around line 197):

```swift
if !failures.isEmpty {
    FileHandle.standardError.write(
        Data("FAIL: \(failures.count) of 8 assertion(s) failed\n".utf8)
    )
    exit(1)
}
```

Change `8` to `12`:

```swift
if !failures.isEmpty {
    FileHandle.standardError.write(
        Data("FAIL: \(failures.count) of 12 assertion(s) failed\n".utf8)
    )
    exit(1)
}
```

- [ ] **Step 4: Run the Swift smoke runner**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -20
```

Expected: 12 PASS lines, then `OK: secretary uniffi Swift smoke runner — all assertions passed.`

- [ ] **Step 5: Add the same 4-assert pattern to the Kotlin smoke runner**

Open `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`. After the imports (line 16), add JSON parsing imports:

```kotlin
import org.json.JSONObject
```

(`org.json` is in the JVM standard library — already on the classpath.)

After the existing `password001` declaration (around line 95), add the phrase-loading block. The existing fixture-read uses `java.nio.file.Files.readAllBytes`; mirror that pattern:

```kotlin
    // B.3a: read recovery_mnemonic_phrase from golden_vault_NNN_inputs.json.
    fun phraseFromInputs(name: String): ByteArray {
        val inputsPath = java.nio.file.Paths.get(vaultDir, name)
        return try {
            val text = java.nio.file.Files.readString(inputsPath)
            val obj = JSONObject(text)
            obj.getString("recovery_mnemonic_phrase").toByteArray(Charsets.UTF_8)
        } catch (e: Throwable) {
            System.err.println("error: failed to read $inputsPath: $e")
            exitProcess(1)
        }
    }

    val phrase001 = phraseFromInputs("golden_vault_001_inputs.json")
    val phrase002 = phraseFromInputs("golden_vault_002_inputs.json")
```

- [ ] **Step 6: Add 4 new Kotlin asserts after the existing assertion 8**

Append inside `fun main()` after the existing `try { ... } catch ... }` block for assertion 8 (around line 197), but BEFORE the `if (failures.isNotEmpty())` block:

```kotlin
    // --- B.3a: open_with_recovery assertions ---

    // Assertion 9: recovery success path.
    try {
        openWithRecovery(
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
            mnemonic = phrase001,
        ).use { identity ->
            val displayName = identity.displayName()
            val uuid = identity.userUuid()
            check(
                displayName == expectedDisplayName && uuid.contentEquals(expectedUserUuid),
                "open_with_recovery success → display_name + user_uuid match pinned KAT (got displayName=\"$displayName\")",
            )
        }
    } catch (e: Throwable) {
        check(false, "open_with_recovery success threw $e, expected to succeed")
    }

    // Assertion 10: wrong recovery phrase → WrongMnemonicOrCorrupt.
    try {
        openWithRecovery(
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
            mnemonic = phrase002,
        )
        check(false, "vault_002 phrase against vault_001 should have thrown WrongMnemonicOrCorrupt")
    } catch (e: UnlockException.WrongMnemonicOrCorrupt) {
        check(true, "vault_002 phrase against vault_001 → WrongMnemonicOrCorrupt")
    } catch (e: Throwable) {
        check(false, "wrong phrase threw $e, expected WrongMnemonicOrCorrupt")
    }

    // Assertion 11: 3-word phrase → InvalidMnemonic(detail).
    try {
        val bad = "only three words".toByteArray(Charsets.UTF_8)
        openWithRecovery(
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle001,
            mnemonic = bad,
        )
        check(false, "3-word phrase should have thrown InvalidMnemonic")
    } catch (e: UnlockException.InvalidMnemonic) {
        check(
            e.detail.contains("got 3"),
            "3-word phrase → InvalidMnemonic(detail=\"${e.detail}\") should mention `got 3`",
        )
    } catch (e: Throwable) {
        check(false, "3-word phrase threw $e, expected InvalidMnemonic")
    }

    // Assertion 12: cross-vault file pair with recovery path → VaultMismatch.
    try {
        openWithRecovery(
            vaultTomlBytes = toml001,
            identityBundleBytes = bundle002,
            mnemonic = phrase001,
        )
        check(false, "vault_001 toml + vault_002 bundle (recovery) should have thrown VaultMismatch")
    } catch (e: UnlockException.VaultMismatch) {
        check(true, "vault_001 toml + vault_002 bundle (recovery) → VaultMismatch")
    } catch (e: Throwable) {
        check(false, "vault mismatch (recovery) threw $e, expected VaultMismatch")
    }
```

- [ ] **Step 7: Update the Kotlin assertion-count constant**

Locate (around line 200):

```kotlin
    if (failures.isNotEmpty()) {
        System.err.println("FAIL: ${failures.size} of 8 assertion(s) failed")
        exitProcess(1)
    }
```

Change `8` to `12`.

- [ ] **Step 8: Add the openWithRecovery import to the existing import block**

Top of file, alongside `import uniffi.secretary.openWithPassword`:

```kotlin
import uniffi.secretary.openWithRecovery
```

- [ ] **Step 9: Run the Kotlin smoke runner**

```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -20
```

Expected: 12 PASS lines, then `OK: secretary uniffi Kotlin smoke runner — all assertions passed.`

- [ ] **Step 10: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/main.swift ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt
git commit -m "$(cat <<'EOF'
test(ffi-b3a): Swift + Kotlin smoke runners exercise open_with_recovery

Four new asserts each pin the foreign-language surface for the
recovery unlock path: success-path KAT (display_name + user_uuid
match B.2 values per dual-KEK convergence), wrong-mnemonic →
WrongMnemonicOrCorrupt, 3-word phrase → InvalidMnemonic.detail
contains "got 3", cross-vault → VaultMismatch.

Both runners read recovery_mnemonic_phrase from the
golden_vault_NNN_inputs.json files at runtime so the test files are
the consumers of the JSON, not parallel sources of truth. Swift uses
JSONSerialization; Kotlin uses org.json.JSONObject (both stdlib).

Failure-summary assertion counts updated 8 → 12 in both runners.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase 5 — Docs + finalize

### Task 9: READMEs (bridge, py, uniffi) + top-level README + ROADMAP

**Files:**
- Modify: `ffi/secretary-ffi-bridge/README.md`
- Modify: `ffi/secretary-ffi-py/README.md`
- Modify: `ffi/secretary-ffi-uniffi/README.md`
- Modify: `README.md` (root)
- Modify: `ROADMAP.md`

- [ ] **Step 1: Append a B.3a section to `ffi/secretary-ffi-bridge/README.md`**

Open the file and find the existing "B.2" section (it should be near the top of the body, after the crate purpose statement). Append a parallel B.3a section after the B.2 section:

```markdown
## B.3a — Recovery-phrase unlock

Adds `open_with_recovery` to the bridge surface. Mnemonic input is
`&[u8]` (UTF-8 bytes), parallel to B.2's password input shape; the
bridge does `std::str::from_utf8` and surfaces malformed-UTF-8 input
as `InvalidMnemonic { detail: "phrase contained invalid UTF-8" }`.

`FfiUnlockError` grows from 3 → 5 variants:

| Variant | Path | Trigger |
|---|---|---|
| `WrongPasswordOrCorrupt` | password only | AEAD tag fail under `master_kek` |
| `WrongMnemonicOrCorrupt` | recovery only | AEAD tag fail under `recovery_kek` |
| `InvalidMnemonic { detail }` | recovery only | wrong word count, unknown word, bad checksum, or invalid UTF-8 — pre-decryption |
| `VaultMismatch` | both | UUID/timestamp mismatch |
| `CorruptVault { detail }` | both | malformed TOML/CBOR/bundle |

The §13 anti-oracle conflation property is preserved: each unlock
path's "wrong key" variant is independently conflated with corruption.
`InvalidMnemonic` is pre-decryption and not an oracle.

`CorruptVault.message` was renamed to `CorruptVault.detail` in B.3a
for naming uniformity with `InvalidMnemonic { detail }`. The uniffi
projection layer was already using `detail` in B.2 to avoid a Kotlin
`Throwable.message` collision; B.3a propagates the rename to the
bridge so all layers agree.
```

- [ ] **Step 2: Append a B.3a section to `ffi/secretary-ffi-py/README.md`**

Find the existing "Vault unlock (B.2)" section. Append after it:

```markdown
### Vault unlock — recovery path (B.3a)

```python
import secretary_ffi_py as sec

# Mnemonic input as bytearray for caller-zeroize discipline:
phrase = bytearray(b"abandon abandon abandon ... 24 words")
try:
    with sec.open_with_recovery(toml_bytes, bundle_bytes, phrase) as identity:
        print(identity.display_name())
finally:
    for i in range(len(phrase)):
        phrase[i] = 0   # caller-side zeroize discipline (matches password path)
```

Two new exception classes:

- `secretary_ffi_py.WrongMnemonicOrCorrupt` — parallel to
  `WrongPasswordOrCorrupt` for the recovery path.
- `secretary_ffi_py.InvalidMnemonic` — pre-decryption BIP-39
  validation failure (wrong word count, unknown word, bad checksum,
  or invalid UTF-8). `str(e)` carries diagnostic text suitable for
  UI rendering ("expected 24 words, got 3", "word not in BIP-39
  English list: xyzzy", etc.).

`secretary_ffi_py.CorruptVault` — same class as before, exception
text comes from the bridge's `CorruptVault.detail` field.

Caller discipline for the mnemonic input is identical to the
password input: pass a mutable `bytearray`, zero it after the call
returns. The bridge wraps the input slice in a transient `Vec<u8>`
that is zeroized after the bridge returns; first-party clients
should zero their foreign-side buffer too.
```

- [ ] **Step 3: Append a B.3a section to `ffi/secretary-ffi-uniffi/README.md`**

Find the existing "Vault unlock (B.2)" section. Append after it:

```markdown
### Vault unlock — recovery path (B.3a)

**Swift:**

```swift
let phrase: [UInt8] = Array("abandon abandon ... 24 words".utf8)
do {
    let identity = try openWithRecovery(
        vaultTomlBytes: tomlBytes,
        identityBundleBytes: bundleBytes,
        mnemonic: phrase
    )
    defer { identity.wipe() }
    print(identity.displayName())
} catch UnlockError.InvalidMnemonic(let detail) {
    print("invalid: \(detail)")
} catch UnlockError.WrongMnemonicOrCorrupt {
    print("wrong phrase or vault tampered")
}
```

**Kotlin:**

```kotlin
val phrase = "abandon abandon ... 24 words".toByteArray(Charsets.UTF_8)
try {
    openWithRecovery(
        vaultTomlBytes = tomlBytes,
        identityBundleBytes = bundleBytes,
        mnemonic = phrase,
    ).use { identity ->
        println(identity.displayName())
    }
} catch (e: UnlockException.InvalidMnemonic) {
    println("invalid: ${e.detail}")
} catch (e: UnlockException.WrongMnemonicOrCorrupt) {
    println("wrong phrase or vault tampered")
} finally {
    phrase.fill(0)
}
```

The single `UnlockError` (Swift) / `UnlockException` (Kotlin) enum
spans both unlock entry points; foreign callers do not maintain
two error types. The variants they need to handle differ by which
entry point they called.

The smoke runners (`tests/swift/run.sh`, `tests/kotlin/run.sh`)
read `recovery_mnemonic_phrase` from
`core/tests/data/golden_vault_NNN_inputs.json` at runtime via
`SECRETARY_GOLDEN_VAULT_DIR` — no hardcoded phrases in test files.
```

- [ ] **Step 4: Update top-level `README.md`**

Find the "Where we are" / status table block. Locate the line referencing the current sub-project status and update:

(a) Update the date marker to `2026-05-04` (no change if already today).
(b) Update the test-counts line — currently shows `479 + 9` (or similar baseline); update to `~489 + 9 ignored` (use the actual final count from Task 10's verification, but the spec target is ~489 + 9 ignored).
(c) Advance the ASCII progress bar one segment toward "complete". Each existing bar segment was a B.x sub-step; B.3a is one more. Match the exact format of existing segments — count them (currently 14→21 ratio referenced in NEXT_SESSION.md → was 21 at B.2 close).

If the README has a "Sub-project B" entry-status table, advance B.3a from ⏳ → ✅:

```
| B.3a — `open_with_recovery` through bridge / PyO3 / uniffi    | ✅ |
```

(b) The pytest count appears in the status block as "10" — update to "16".
(c) Swift smoke "7" → "11"; Kotlin smoke "7" → "11".

- [ ] **Step 5: Update `ROADMAP.md`**

Open `ROADMAP.md`, find the Sub-project B section, and flip B.3a's checkbox from ⏳ → ✅. The exact format depends on how previous flips were done — match B.2's flip pattern in the same file. Add a one-line summary of what B.3a delivers (analogous to B.2's existing summary).

- [ ] **Step 6: Verify all gates green after the doc edits**

Doc edits don't affect compilation, but run the gates anyway as a smoke test:

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_t9.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_t9.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected:
- `TOTAL: ~489 passed; 0 failed; 9 ignored` (the actual count is whatever it is — record it for Task 10's NEXT_SESSION update).
- clippy + fmt OK.
- `16 passed` in pytest.
- `12 PASS` in Swift + Kotlin smoke runners (with `OK:` summary line).
- conformance + freshness PASS.

If anything fails, STOP and triage before proceeding to Task 10.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/README.md ffi/secretary-ffi-py/README.md ffi/secretary-ffi-uniffi/README.md README.md ROADMAP.md
git commit -m "$(cat <<'EOF'
docs(ffi-b3a): READMEs + top-level docs document recovery unlock path

Bridge crate README documents the 5-variant FfiUnlockError shape, the
anti-oracle preservation across the password and recovery paths, and
the CorruptVault.message → CorruptVault.detail field rename rationale.

PyO3 + uniffi crate READMEs document the new entry point with code
samples mirroring the B.2 password-path documentation: Python
bytearray + zeroize discipline; Swift defer-wipe pattern; Kotlin
.use { } via auto-AutoCloseable.

Top-level README progress bar advances; ROADMAP B.3a entry flipped
⏳ → ✅. Test-count baselines updated for the new gate counts.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: NEXT_SESSION + handoff archive + final verification + push + open PR

**Files:**
- Modify: `NEXT_SESSION.md`
- Create: `docs/handoffs/2026-MM-DD-b3a-recovery-unlock.md` (replace `MM-DD` with the actual completion date — likely `05-04` or whatever the date is when Task 10 runs)

- [ ] **Step 1: Determine the handoff date**

```bash
date +"%Y-%m-%d"
```

Use that date in the `docs/handoffs/` filename. (If the implementation spans multiple days, use the date of the final commit / PR.)

- [ ] **Step 2: Capture the final test counts for the NEXT_SESSION.md verification table**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_final.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_final.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'cargo: {p} passed; {f} failed; {i} ignored')"

cargo test --release --package secretary-ffi-bridge 2>&1 | grep -E "^test result:" | head -3
echo "---"
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
echo "---"
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | grep -E "^OK|FAIL" | tail -1
echo "---"
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | grep -E "^OK|FAIL" | tail -1
```

Record these numbers — they go into the NEXT_SESSION verification table.

- [ ] **Step 3: Replace `NEXT_SESSION.md` with B.3b forward-looking content**

The previous NEXT_SESSION.md (from B.2) is on `main` and now stale. Replace it with content following the same structure as before. Use the structure below as a template; replace placeholders with actual values:

```markdown
# NEXT_SESSION.md

**Session date:** YYYY-MM-DD (Sub-project B.3a — recovery-phrase unlock through FFI)
**Status:** Sub-project B.3a complete; PR pending merge. The recovery-phrase unlock path is now exposed across PyO3 (Python) and uniffi (Swift / Kotlin) via the existing shared `secretary-ffi-bridge` crate. `FfiUnlockError` grew from 3 → 5 variants. With B.3a done, the FFI surface includes both unlock entry points; B.3b expands it with `create_vault` (the output-direction mnemonic case).

## (1) What we shipped this session

| Task | Commit | What landed |
|---|---|---|
| 1 — JSON pin + drift assert | `<sha>` | recovery_mnemonic_phrase pinned in golden_vault_{001,002}_inputs.json; bip39 drift-detection assertion in fixture_builder. Vault bytes unchanged. |
| 2 — bridge error.rs | `<sha>` | FfiUnlockError grew 3→5 variants; CorruptVault.message renamed to .detail; defensive arms promoted to active mappings; +5 unit tests. |
| 3 — bridge unlock.rs | `<sha>` | open_with_recovery added with UTF-8-validation seam; +5 integration tests pinning all error paths. |
| 4 — bridge lib.rs | `<sha>` | Re-exports + crate-doc updated. |
| 5 — PyO3 wrapper | `<sha>` | open_with_recovery #[pyfunction]; 2 new exception classes; ffi_unlock_error_to_pyerr handles 5-variant shape and renamed detail field. |
| 6 — pytest | `<sha>` | +6 tests; `_golden_vault_phrase(n)` reads inputs JSON; bytearray caller-zeroize parity with B.2. |
| 7 — UDL + uniffi glue | `<sha>` | UDL gains 2 [Error] variants + 1 namespace function; uniffi UnlockError mirrors bridge 5-variant; +2 mapping tests; CorruptVault test renamed for detail field. |
| 8 — Swift + Kotlin smoke | `<sha>` | +4 asserts each; phrases loaded from inputs JSON via SECRETARY_GOLDEN_VAULT_DIR. |
| 9 — READMEs + ROADMAP | `<sha>` | Per-crate B.3a sections + top-level progress bar advance + ROADMAP B.3a flip. |
| 10 — NEXT_SESSION + handoff | `<this commit>` | This file + docs/handoffs/YYYY-MM-DD-b3a-recovery-unlock.md. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **<N> passed + 9 ignored** (was 479 + 9 at branch start; +<delta> from B.3a) |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run --directory ffi/secretary-ffi-py pytest` | **16 passed** (was 10) |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **12/12 PASS** (was 8/8) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **12/12 PASS** (was 8/8) |

## (2) What's next, with concrete acceptance criteria

### Sub-project B.3b — `create_vault` through the FFI

Brainstorm + spec needed before code. Open design questions to settle:

1. **Output-direction `Sensitive<T>` materialization on the foreign side.** `create_vault` returns a freshly-generated 24-word BIP-39 mnemonic that must cross the FFI back to the caller. How do Python `bytes`/`bytearray`, Swift `Data`, and Kotlin `ByteArray` handle "this came from a Sensitive<T>" — what zeroize discipline is documented? Options: one-shot accessor that consumes the inner Sensitive (zeroize on read); copy-into-foreign-allocated-buffer; new opaque handle type. (Same question deferred from B.2's "no genuinely-secret bytes crossing back" non-goal.)
2. **RNG seam.** Does `create_vault` accept a foreign-side RNG, or is the OS CSPRNG always used? First-party clients always want OS CSPRNG; tests want deterministic seeded RNG; uniffi's marshalling of "function pointer to a foreign RNG" is non-trivial.
3. **KDF params ergonomics.** Per current Rust core, `create_vault` enforces the §1.2 v1 floor (`memory_kib >= 65536`). Does the FFI expose params as a struct, or always use the default? The default is fine for production; tests need sub-floor for speed (`create_vault_unchecked`). FFI should NOT expose `unchecked` — first-party clients should hit the safe path.
4. **`WeakKdfParams` reachability.** B.3a left this defensively folded into `CorruptVault`. With B.3b's `create_vault` reachable, does it become its own variant or stay folded? Argument for own variant: distinct user remedy ("your params are too weak"). Argument for stay: the safe entry point won't return it; only `_unchecked` does.

Acceptance criteria for B.3b (refined during brainstorm):
- [ ] `create_vault(password, kdf_params?, recovery_output: ?)` exposed across PyO3 + uniffi.
- [ ] One-shot recovery-mnemonic accessor that consumes Sensitive on read.
- [ ] Test count grows: cargo +~10, pytest +~5, Swift +~3, Kotlin +~3.
- [ ] All gates green at session close.
- [ ] §13 anti-oracle conflation continues to hold OR is explicitly extended with documented rationale.
- [ ] Spec at `docs/superpowers/specs/<date>-ffi-b3b-create-vault-design.md` lands first; plan follows.

The deferred-items section in [docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md](docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md) "Non-goals (YAGNI)" carries the original carry-over context — read it before requesting the brainstorming skill.

## (3) Open decisions and risks

### Decisions made and load-bearing for B.3b

1. **Bridge crate stays the single source of FFI code truth.** New B.3b surface (`create_vault`) must live there first.
2. **5-variant thinned error preserves anti-oracle conflation.** New B.3b variants either fold into existing or add as 6th distinct user-actionable category. The §13 property (each unlock path's "wrong key OR corrupt" stays conflated) extends — `create_vault` is not a decryption path so doesn't add another anti-oracle variant.
3. **Bytes-not-string at the FFI boundary for secret inputs.** B.3a's mnemonic-input pattern matches B.2's password-input pattern. B.3b's password input also follows.
4. **`CorruptVault.detail` field naming uniform across all layers.** B.3a propagated the name from uniffi to bridge to PyO3.

### Risks for B.3b specifically

- **Output-direction Sensitive marshalling** is the highest-uncertainty design point. Each foreign language has different memory ownership semantics; the "right" answer might be a different one per language.
- **Test fixture extension**: B.3b's `create_vault` produces fresh randomness, so it can't pin against existing golden fixtures. Tests likely build synthetic vaults at runtime via seeded RNG; round-trip assertions exercise create-then-open. No new on-disk fixtures expected.

### Pre-existing technical debt

None outstanding from B.3a.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# Verify the post-merge state on main:
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"

# Re-build the maturin dylib BEFORE pytest:
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )

uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

# Begin Sub-project B.3b with brainstorm. Read the deferred-items section
# of docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md first.
# Then: /brainstorm
```

---

## Closing inventory

- **Branch:** `feat/ffi-b3a-recovery-unlock` (PR-pending; squash-merge target is `main`)
- **Total commits since branching from `main@55aaef6`:** 10 (1 fixture pin + 3 bridge edits + 2 PyO3 + 2 uniffi + 1 docs + 1 handoff). Will squash to 1.
- **Workspace tests:** <N> + 9 ignored
- **Pytest:** 16 (10 from B.1+B.2 + 6 B.3a)
- **Swift smoke:** 12/12 (8 from B.2 + 4 B.3a)
- **Kotlin smoke:** 12/12 (8 from B.2 + 4 B.3a)
- **Bridge crate:** ~31 unit tests (was 22; +9 net: +4 in error.rs, +5 in unlock.rs)
- **PR:** [#NN](https://github.com/hherb/secretary/pull/NN)
```

(Replace `<sha>`, `<N>`, `<delta>`, `<NN>`, and the dates with actual values when filling in.)

- [ ] **Step 4: Create the timestamped handoff archive**

Copy NEXT_SESSION.md to a date-stamped archive:

```bash
cp NEXT_SESSION.md docs/handoffs/$(date +"%Y-%m-%d")-b3a-recovery-unlock.md
```

(The two files have the same content at this point — the archive is a frozen snapshot.)

- [ ] **Step 5: Run all gates one final time**

```bash
cargo test --release --workspace 2>&1 | grep -E "^test result:" > /tmp/cargo_final2.txt
python3 -c "
import re
p=f=i=0
for line in open('/tmp/cargo_final2.txt'):
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
cargo clippy --release --workspace -- -D warnings && echo "clippy OK"
cargo fmt --all -- --check && echo "fmt OK"
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv 2>&1 | tail -3 )
uv run --directory ffi/secretary-ffi-py pytest 2>&1 | tail -3
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
```

Expected: all green. If any fail, STOP and triage before pushing.

- [ ] **Step 6: Commit the NEXT_SESSION + handoff archive**

```bash
git add NEXT_SESSION.md docs/handoffs/$(date +"%Y-%m-%d")-b3a-recovery-unlock.md
git commit -m "$(cat <<'EOF'
docs(handoff): B.3a complete — record verification + B.3b launch points

NEXT_SESSION.md updated with B.3a retrospective + B.3b
forward-looking content (open design questions for the brainstorm,
acceptance criteria, exact resume commands). Timestamped handoff
archive committed alongside on the feature branch so post-merge
main carries the correct baton.

All gates green at session close (cargo, clippy, fmt, pytest,
conformance, freshness, both smoke runners).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Push the branch + open PR**

```bash
git push -u origin feat/ffi-b3a-recovery-unlock
```

Then open a PR:

```bash
gh pr create --title "feat(ffi-b3a): expose open_with_recovery through PyO3 + uniffi via shared bridge crate" --body "$(cat <<'EOF'
## Summary
- Adds `open_with_recovery` to the bridge crate with UTF-8-validation seam; mnemonic input is `&[u8]` parallel to B.2's password input
- Grows `FfiUnlockError` from 3 → 5 variants (`WrongMnemonicOrCorrupt`, `InvalidMnemonic { detail }`); promotes previously-defensive `From` arms to active mappings; renames `CorruptVault.message → .detail` for naming uniformity across all layers
- Pins `recovery_mnemonic_phrase` in `golden_vault_{001,002}_inputs.json` derived from existing entropy via bip39; on-disk vault bytes unchanged; fixture-builder asserts derive-and-verify integrity

## Test plan
- [x] `cargo test --release --workspace` green (was 479 + 9 ignored)
- [x] `cargo clippy --release --workspace -- -D warnings` clean
- [x] `cargo fmt --all -- --check` OK
- [x] `uv run --directory ffi/secretary-ffi-py pytest` 16/16 (was 10)
- [x] `uv run core/tests/python/conformance.py` PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` PASS
- [x] `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` 12/12 (was 8)
- [x] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` 12/12 (was 8)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 8: Record the PR URL for the handoff**

Capture the PR URL from `gh pr create` output. Update `NEXT_SESSION.md` and the handoff archive's "PR" entry with the actual URL — make a small follow-up commit:

```bash
# After capturing the PR URL from gh pr create's output:
# Edit NEXT_SESSION.md and docs/handoffs/<date>-b3a-recovery-unlock.md
# replacing the [#NN] placeholder with the actual PR number.

git add NEXT_SESSION.md docs/handoffs/*-b3a-recovery-unlock.md
git commit -m "$(cat <<'EOF'
docs(handoff): record PR #<NN> URL in NEXT_SESSION + handoff archive

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"

git push
```

The PR is now ready for review. Subagent-driven-development workflow ends here; controller hands back to user for review/merge.

---

## Self-review checklist

After completing all 11 tasks (0 + 1-10), verify:

- [ ] All 11 commits on the feature branch (one per task, plus the optional PR-URL fix-up).
- [ ] No commits to `main` directly.
- [ ] Spec coverage: every section of the spec doc has a corresponding task.
- [ ] No placeholders (`TBD`, `TODO`, `FIXME`, `<paste here>`) remain in committed code.
- [ ] All gates green at the final commit before push.
- [ ] PR description references the spec doc.
- [ ] NEXT_SESSION.md and docs/handoffs/* live on the feature branch (NOT cherry-picked to main post-merge).
