# C.1.1b Sync Merge Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the merge + veto + commit layer on top of the C.1.1a `VaultBundle`, turning each `ConcurrentDetected` outcome into a committed merge through the three-step API `sync_once → prepare_merge → commit_with_decisions`. Also close the latent multi-block crash-safety gap by adding read-time block-fingerprint verification inside `open_vault`.

**Architecture:** `prepare_merge(folder, identity, bundle, plan) -> DraftMerge` AEAD-decrypts each diverging block envelope on demand, runs `merge_block` from `core::vault::conflict` to compose the per-block merges iteratively (canonical + N copies → 1 merged block), folds the vector clocks across canonical + all copies, and surfaces any "peer would tombstone a record this side has live" as a record-level veto (D2/D3). `commit_with_decisions(folder, identity, draft, decisions, now_ms) -> SyncState` enforces a decision↔veto bijection, re-encrypts affected blocks with fresh AEAD nonces, computes new BLAKE3 fingerprints into the manifest body, re-signs the manifest hybrid (Ed25519 ∧ ML-DSA-65), and writes block-first-manifest-last atomically per-file. A pre-commit BLAKE3 re-hash of the on-disk manifest envelope closes the TOCTOU window against `draft.manifest_hash`. Crash recovery is delivered by the new `verify_block_fingerprints` check in `open_vault`: a partial commit (blocks written, manifest not) is detected as a typed `VaultError::BlockFingerprintMismatch` and the caller re-runs the three-step flow — CRDT idempotence guarantees convergence.

**Tech Stack:** stable Rust (workspace toolchain). Reuses `core::vault::conflict::{merge_block, merge_record, merge_vector_clocks}`, `core::vault::block::{decrypt_block, encrypt_block, encode_block_file}`, `core::vault::manifest::{sign_manifest, encode_manifest_file}`, `core::vault::io::write_atomic`, `core::crypto::hash::hash` (BLAKE3), `core::crypto::aead::random_nonce`. `zeroize` and `tempfile` (`=3.27.0`, exact-pinned per CLAUDE.md) already in workspace. `proptest` for property tests (already a workspace dev-dep). No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`](../specs/2026-05-18-c1-1b-sync-merge-design.md)

**Predecessor:** C.1.1a on `main` (PR #77 + the post-merge crypto refactor PR #82 + the #80 TOCTOU fix PR #83). Worktree `.worktrees/c1-1b-sync-merge` on branch `feature/c1-1b-sync-merge`.

---

## Spec adjustments from the design doc

Two pragmatic deviations from the design doc's "Module file layout" section, decided at plan-authoring time. The intent of the design is preserved; the file placement differs only where 1a already shipped the types:

| Design doc says | What's already on `main` after 1a | Plan decision |
|---|---|---|
| `core/src/sync/diff.rs` NEW with `DiffPlan` + `ManifestHash` | `DiffPlan` is in `outcome.rs`; `ManifestHash` is in `bundle.rs` | **Leave them where they are.** Both already shipped in 1a with tests; relocating purely to match the design doc's layout is churn for no functional gain. The plan's new files are `draft.rs`, `prepare.rs`, `commit.rs`. |
| `MergedRecord` is a distinct type or re-export of `Record` (Open Item 4) | `core::vault::conflict::MergedRecord` already exists | **Use `Record` directly** in `DraftMerge.merged_records`. The conflict module's `MergedRecord` is a per-pair structural result; `DraftMerge.merged_records` is the post-fold record set the commit consumes. Storing `Record` keeps `DraftMerge`'s shape thin. |
| `RecordId` / `BlockId` named types | Existing code uses `[u8; 16]` directly | **Use `[u8; 16]`** with module-level `pub type` aliases inside `draft.rs` to make the API surface read self-documenting without introducing newtype wrappers. |

Other design-doc open items (1, 2, 3, 5):
- `verify_block_fingerprints` runs **eagerly** inside `open_vault` (Open Item 1 lean: eager).
- `ManifestHash` is BLAKE3 of the **full on-disk envelope bytes** (Open Item 2 lean: full envelope; this is already what 1a shipped via `compute_manifest_hash`).
- `DiffPlan` construction stays in `core::sync::ingest::compute_diff_plan` where 1a put it (Open Item 3 lean: helper lives outside `once.rs`; 1a put it in `ingest.rs` rather than `diff.rs` — that placement holds).
- Multi-rewrite-per-test AEAD nonces use distinct per-call constants (Open Item 5); helper extension is Task 1 below.

---

## File Structure

**New files (5):**

```
core/src/sync/draft.rs              ~180 LOC  DraftMerge + RecordTombstoneVeto + VetoDecision + zeroize coverage + unit tests
core/src/sync/prepare.rs            ~360 LOC  prepare_merge + tombstone_veto_set + iterative merge composition + unit tests
core/src/sync/commit.rs             ~460 LOC  commit_with_decisions + apply_decisions + re-encrypt-and-sign + unit tests
core/tests/sync_merge.rs            ~620 LOC  Integration tests (~13 tests across prepare + commit + open_vault fingerprint paths)
core/tests/sync_merge_proptest.rs   ~200 LOC  Property tests (~4 properties)
```

**Modified files (8):**

```
core/src/sync/mod.rs                  Re-export DraftMerge / RecordTombstoneVeto / VetoDecision / prepare_merge / commit_with_decisions
core/src/sync/error.rs                +4 variants (EvidenceStale, UnknownVetoDecision, MissingVetoDecision, EmptyDraftWithVetoes)
core/src/vault/mod.rs                 +1 VaultError variant (BlockFingerprintMismatch)
core/src/vault/orchestrators.rs       +verify_block_fingerprints (~50 LOC including doc + tests) + one call from open_vault
core/tests/sync_helpers/mod.rs        Add a re-encrypt-and-rewrite-block helper (distinct AEAD nonces per rewrite)
core/tests/data/sync_kat.json         9 → 16 vectors (7 new vectors)
core/tests/sync_kat.rs                Replay logic extended for new vector shapes (prepare_merge + commit_with_decisions)
README.md                             "Sub-project C status" line moved C.1.1 → ✅ when this merges
ROADMAP.md                            C.1.1b ✅ + progress bar
```

All under 500-LOC threshold per `feedback_split_files_proactively`. The heaviest file is `commit.rs` (~460 LOC); it does decision-bijection + re-encrypt + atomic write — one concept (the commit path) with three subroutines that share state. If it grows past 500 LOC during implementation, split `apply_decisions` into a sibling file.

---

## Working directory + baseline

Every task assumes:

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
git branch --show-current     # → feature/c1-1b-sync-merge
git status --short            # → clean before/after each task's commit
```

Baseline gauntlet (run **once before Task 1**, expected: 713 passed, 0 failed, 10 ignored — that's the post-#80-fix baseline at `origin/main = 98d8a8a`):

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

After every task: re-run the gauntlet, commit only when green.

---

## Task 1: Extend `sync_helpers` with a per-block rewrite helper

**Why:** C.1.1b integration tests need to write a CANONICAL manifest + ≥1 sibling conflict-copy manifests **and** rewrite ≥1 block files in the same temp dir with distinct vector clocks per side. The existing `sync_helpers/mod.rs` already handles manifest-side rewrites (Tasks 1 + 13 of the 1a plan shipped that), but has no block-side rewrite. Each block rewrite needs a distinct AEAD nonce — sharing nonce + key across two block envelopes would violate AEAD's uniqueness invariant, even in test code (CLAUDE.md atomic-write contract; risk explicitly called out in the 1b design doc §Risks).

**Files:**
- Modify: `core/tests/sync_helpers/mod.rs` (full file; new function plus two new per-block nonce constants)

- [ ] **Step 1: Read existing helper to confirm shape**

```bash
sed -n '1,60p' core/tests/sync_helpers/mod.rs
```

Expected: file starts with module doc, four nonce constants (`CANONICAL_NONCE_A`, `SIBLING_NONCE_B`, `_C`, `_D`), and `fresh_vault_with_clock` + `fresh_vault_two_concurrent_manifests` + `fresh_vault_four_concurrent_manifests` helpers as in the most recent commit on `main`.

- [ ] **Step 2: Write the failing test for `rewrite_block_with_records`**

Append to `core/tests/sync_helpers/mod.rs` AT FILE END (after `write_manifest_at`):

```rust
#[cfg(test)]
mod helper_tests {
    use super::*;
    use secretary_core::vault::{decrypt_block, encode_block_file, BlockPlaintext};

    /// Smoke: rewriting a block in the temp vault produces a file
    /// that decrypts back to the supplied record set, signed by the
    /// owner identity.
    #[test]
    fn rewrite_block_with_records_round_trips() {
        let golden_clock = vec![VectorClockEntry { device_uuid: [9; 16], counter: 1 }];
        let (folder, _tmp) = fresh_vault_with_clock(golden_clock);

        // Use any block_uuid present in golden_vault_001's manifest.
        let block_uuid = golden_vault_001_first_block_uuid(&folder);
        let new_records: Vec<secretary_core::vault::Record> = Vec::new();

        rewrite_block_with_records(
            &folder,
            block_uuid,
            new_records.clone(),
            &BLOCK_NONCE_E,
        );

        // Decrypt and assert records match.
        let block_path = block_file_path(&folder, &block_uuid);
        let bytes = std::fs::read(&block_path).expect("read block");
        let password = fixtures::golden_vault_001_password();
        let mut open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");
        let plaintext: BlockPlaintext =
            decrypt_block_using_open(&mut open, &bytes).expect("decrypt");
        assert_eq!(plaintext.records, new_records);
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cargo test --release --workspace --test sync_helpers_unused -- rewrite_block_with_records_round_trips 2>&1 | tail -20
```

Expected: compile error — `BLOCK_NONCE_E`, `rewrite_block_with_records`, `golden_vault_001_first_block_uuid`, `block_file_path`, `decrypt_block_using_open` are all undefined.

Note: `sync_helpers/mod.rs` is `mod sync_helpers;` re-exported from integration test crates; the test under `#[cfg(test)] mod helper_tests` runs as part of whichever integration test crate includes the module. If standalone test invocation is impractical, run the workspace cargo and grep for the new test name; the test still fails compile.

- [ ] **Step 4: Add nonce constants near the existing `SIBLING_NONCE_D`**

In `core/tests/sync_helpers/mod.rs`, after the `SIBLING_NONCE_D` declaration, add:

```rust
/// Distinct nonce for the first block rewrite in C.1.1b fixtures.
/// Differs from every manifest-rewrite nonce so block- and manifest-
/// rewrite sequences never collide on key + nonce.
pub const BLOCK_NONCE_E: [u8; AEAD_NONCE_LEN] = [
    0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
    0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
];

/// Distinct nonce for the second block rewrite in C.1.1b fixtures —
/// used for the sibling block envelope in conflict-copy ingestion.
pub const BLOCK_NONCE_F: [u8; AEAD_NONCE_LEN] = [
    0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F,
    0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F,
];

/// Distinct nonce for the third block rewrite in C.1.1b fixtures —
/// reserved for tests that rewrite the canonical block AND two siblings.
#[allow(dead_code)]
pub const BLOCK_NONCE_G: [u8; AEAD_NONCE_LEN] = [
    0x6A, 0x7B, 0x8C, 0x9D, 0xAE, 0xBF, 0xC0, 0xD1, 0xE2, 0xF3, 0x04, 0x15, 0x26, 0x37, 0x48, 0x59,
    0x6A, 0x7B, 0x8C, 0x9D, 0xAE, 0xBF, 0xC0, 0xD1,
];
```

- [ ] **Step 5: Add `rewrite_block_with_records` and small helpers**

At the end of `core/tests/sync_helpers/mod.rs` (after the existing `write_manifest_at`), append:

```rust
/// Look up the first block_uuid in the golden vault's manifest. Used
/// by helpers that need a real on-disk block to rewrite.
#[allow(dead_code)]
pub fn golden_vault_001_first_block_uuid(folder: &Path) -> [u8; 16] {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    open.manifest
        .blocks
        .first()
        .expect("golden vault has at least one block")
        .block_uuid
}

/// Canonical block file path inside the vault folder.
#[allow(dead_code)]
pub fn block_file_path(folder: &Path, block_uuid: &[u8; 16]) -> PathBuf {
    let uuid_hex = format_uuid_for_filename(block_uuid);
    folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))
}

/// Format a UUID as canonical lowercase 8-4-4-4-12 hex. Mirrors
/// `core::vault::orchestrators::format_uuid_hyphenated`; replicated
/// here because that helper is `pub(crate)`.
#[allow(dead_code)]
fn format_uuid_for_filename(uuid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decrypt a block envelope using the open vault's owner identity.
/// Returns the verified [`BlockPlaintext`]. Helper for round-trip
/// assertions in tests that rewrite block files.
#[allow(dead_code)]
pub fn decrypt_block_using_open(
    open: &mut secretary_core::vault::OpenVault,
    bytes: &[u8],
) -> Result<secretary_core::vault::BlockPlaintext, secretary_core::vault::VaultError> {
    use secretary_core::crypto::sig::MlDsa65Public;
    use secretary_core::identity::fingerprint::fingerprint;
    let owner_card_bytes = open.owner_card.to_canonical_cbor()?;
    let owner_fp = fingerprint(&owner_card_bytes);
    let owner_ed_pk = open.owner_card.ed25519_pk;
    let owner_pq_pk = MlDsa65Public::from_bytes(&open.owner_card.ml_dsa_65_pk)?;
    let pq_sk = secretary_core::crypto::kem::MlKem768Secret::from_bytes(
        open.identity.ml_kem_768_sk.expose(),
    )?;
    let reader_fp = owner_fp; // owner == reader in golden vault tests
    let plaintext = secretary_core::vault::decrypt_block(
        bytes,
        &reader_fp,
        open.identity.x25519_sk.expose(),
        &pq_sk,
        &owner_fp,
        &owner_ed_pk,
        &owner_pq_pk,
    )?;
    Ok(plaintext)
}

/// Open the temp vault, decrypt the named block, replace its records,
/// re-encrypt with the supplied AEAD nonce, and write the new envelope
/// to `blocks/<uuid>.cbor.enc`. Mirrors the step 4-9 pattern in
/// `core::vault::orchestrators::save_block` — only the records and
/// AEAD nonce change; header bytes (`vault_uuid`, `block_uuid`,
/// `created_at_ms`) are preserved bit-for-bit. The block's per-block
/// vector clock is **not** ticked here; tests that need a specific
/// clock must set it explicitly via `mut new_clock` parameter or by
/// calling `write_manifest_at` after this helper to rewrite the
/// manifest's `BlockEntry.vector_clock_summary`.
///
/// Note: this helper does NOT update the manifest's
/// `BlockEntry.fingerprint`. Tests that want a consistent post-rewrite
/// vault must call `write_manifest_with_block_fingerprint` (Task 1c)
/// or `recompute_manifest_after_rewrite` after this.
#[allow(dead_code)]
pub fn rewrite_block_with_records(
    folder: &Path,
    block_uuid: [u8; 16],
    new_records: Vec<secretary_core::vault::Record>,
    aead_nonce: &[u8; AEAD_NONCE_LEN],
) -> [u8; 32] {
    use secretary_core::crypto::sig::MlDsa65Public;
    use secretary_core::identity::fingerprint::fingerprint;
    use secretary_core::vault::{
        encode_block_file, encrypt_block, BlockHeader, BlockPlaintext, RecipientPublicKeys,
    };

    let password = fixtures::golden_vault_001_password();
    let mut open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");

    let entry_idx = open
        .manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .expect("block_uuid not in manifest");
    let entry = open.manifest.blocks[entry_idx].clone();

    // Re-derive owner sender keys (mirrors save_block step 4 setup).
    let owner_card_bytes = open.owner_card.to_canonical_cbor().expect("card cbor");
    let owner_fp = fingerprint(&owner_card_bytes);
    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk =
        MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).expect("ml-dsa sk");
    let owner_pk_bundle = open.owner_card.pk_bundle_bytes().expect("pk bundle");

    // Recipient list: owner is always a recipient in golden vault tests.
    let owner_x25519 = open.owner_card.x25519_pk;
    let owner_pq_pk =
        MlDsa65Public::from_bytes(&open.owner_card.ml_dsa_65_pk).expect("ml-dsa pk");
    // For simplicity, reuse the existing manifest's recipient list
    // (which always contains the owner). Tests that need additional
    // recipients should add their own helper.
    let recipient_fps = vec![owner_fp];
    let recipient_keys = vec![RecipientPublicKeys {
        fingerprint: recipient_fps[0],
        pk_bundle: &owner_pk_bundle,
        x25519_pk: &owner_x25519,
        ml_kem_768_pk: &owner_pq_pk,
    }];

    let header = BlockHeader {
        magic: secretary_core::version::MAGIC,
        format_version: secretary_core::version::FORMAT_VERSION,
        suite_id: secretary_core::version::SUITE_ID,
        file_kind: secretary_core::vault::FILE_KIND_BLOCK,
        vault_uuid: open.manifest.vault_uuid,
        block_uuid,
        created_at_ms: entry.created_at_ms,
        last_mod_ms: entry.last_mod_ms,
        vector_clock: entry.vector_clock_summary.clone(),
    };
    let plaintext = BlockPlaintext {
        block_uuid,
        block_name: entry.block_name.clone(),
        records: new_records,
        unknown: std::collections::BTreeMap::new(),
    };

    let block_file = encrypt_block(
        &mut DeterministicNonceRng { nonce: *aead_nonce, served: false },
        &header,
        &plaintext,
        &owner_fp,
        &owner_pk_bundle,
        &owner_ed_sk,
        &owner_pq_sk,
        &recipient_keys,
    )
    .expect("encrypt_block");
    let bytes = encode_block_file(&block_file).expect("encode_block_file");
    let fingerprint_out =
        *secretary_core::crypto::hash::hash(&bytes).as_bytes();

    let path = block_file_path(folder, &block_uuid);
    std::fs::write(&path, &bytes).expect("write block file");

    fingerprint_out
}

/// Stub RNG that hands back a pre-set AEAD nonce exactly once, then
/// returns zeros. `encrypt_block` only calls `fill_bytes` for the
/// AEAD nonce; per-recipient KEM encaps draw from this same RNG, so
/// for tests we feed deterministic bytes and accept that the encap
/// nonces are also deterministic. Tests don't compare ciphertexts;
/// they compare decrypted plaintext.
#[allow(dead_code)]
struct DeterministicNonceRng {
    nonce: [u8; AEAD_NONCE_LEN],
    served: bool,
}
impl rand_core::RngCore for DeterministicNonceRng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if !self.served && dest.len() == AEAD_NONCE_LEN {
            dest.copy_from_slice(&self.nonce);
            self.served = true;
        } else {
            for b in dest.iter_mut() {
                *b = 0;
            }
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for DeterministicNonceRng {}
```

- [ ] **Step 6: Run the test, verify it passes**

```bash
cargo test --release --workspace --tests 2>&1 | grep -E "rewrite_block_with_records_round_trips|test result:" | tail -10
```

Expected: `test rewrite_block_with_records_round_trips ... ok`.

- [ ] **Step 7: Clippy + fmt**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all -- --check
```

Expected: both clean. The `#[allow(dead_code)]` annotations on `BLOCK_NONCE_G`, `golden_vault_001_first_block_uuid`, etc., mirror the 1a pattern (consumed by later tasks in this same plan).

- [ ] **Step 8: Commit**

```bash
git add core/tests/sync_helpers/mod.rs
git commit -m "test(sync-helpers): add block-rewrite + per-block nonce constants for C.1.1b fixtures"
```

---

## Task 2: Add the four new `SyncError` variants

**Why:** Both `prepare_merge` and `commit_with_decisions` surface typed errors the design doc enumerates (D2 + D5 atomicity + bijection enforcement). Adding them up-front, with stable Display strings and a basic unit test per variant, means each subsequent task can `return Err(SyncError::Foo { ... })` without back-and-forth changes to `error.rs`.

**Files:**
- Modify: `core/src/sync/error.rs:1-100`

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` block in `core/src/sync/error.rs`:

```rust
    #[test]
    fn evidence_stale_display_is_stable() {
        let err = SyncError::EvidenceStale;
        assert_eq!(
            format!("{err}"),
            "manifest changed on disk between prepare_merge and commit_with_decisions",
        );
    }

    #[test]
    fn unknown_veto_decision_display_includes_record_id() {
        let err = SyncError::UnknownVetoDecision {
            record_id: [0xAB; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("decision references unknown veto record_id"));
        assert!(s.contains("ab")); // hex-format prints lowercase
    }

    #[test]
    fn missing_veto_decision_display_includes_record_id() {
        let err = SyncError::MissingVetoDecision {
            record_id: [0xCD; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("decision missing for tombstone veto record_id"));
        assert!(s.contains("cd"));
    }

    #[test]
    fn empty_draft_with_vetoes_display_is_stable() {
        let err = SyncError::EmptyDraftWithVetoes;
        assert_eq!(
            format!("{err}"),
            "merge produced no draft records but vetoes are non-empty (internal invariant)",
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --release --workspace --lib sync::error 2>&1 | tail -20
```

Expected: compile error — `SyncError::EvidenceStale`, `UnknownVetoDecision`, `MissingVetoDecision`, `EmptyDraftWithVetoes` are undefined.

- [ ] **Step 3: Add the variants**

In `core/src/sync/error.rs`, inside the `pub enum SyncError { ... }` block, append (after `ConflictCopyScanIoFailed`):

```rust
    /// The on-disk canonical manifest envelope hash differs from
    /// `draft.manifest_hash`. A concurrent writer modified the manifest
    /// between `prepare_merge` and `commit_with_decisions`. The commit
    /// is aborted with zero disk writes; the caller retries from
    /// `sync_once`.
    #[error("manifest changed on disk between prepare_merge and commit_with_decisions")]
    EvidenceStale,

    /// The caller passed a `VetoDecision` whose `record_id` is not in
    /// the `DraftMerge.vetoes` set. Decisions and vetoes must be a
    /// bijection (D5).
    #[error("decision references unknown veto record_id: {record_id:02x?}")]
    UnknownVetoDecision { record_id: [u8; 16] },

    /// The caller did not supply a `VetoDecision` for a `record_id`
    /// present in `DraftMerge.vetoes`. Bijection check, mirror of
    /// [`SyncError::UnknownVetoDecision`].
    #[error("decision missing for tombstone veto record_id: {record_id:02x?}")]
    MissingVetoDecision { record_id: [u8; 16] },

    /// Defensive: a merge produced no `merged_records` but populated
    /// `vetoes`. Currently unreachable because every veto's `record_id`
    /// is also present in `merged_records` (vetoes are derived per-
    /// record from the merged set). Surfaced as a typed variant so a
    /// future change that breaks this invariant fails loudly.
    #[error("merge produced no draft records but vetoes are non-empty (internal invariant)")]
    EmptyDraftWithVetoes,
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --release --workspace --lib sync::error 2>&1 | tail -10
```

Expected: all four new tests + the four pre-existing tests pass.

- [ ] **Step 5: Clippy + fmt**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: both clean.

- [ ] **Step 6: Commit**

```bash
git add core/src/sync/error.rs
git commit -m "feat(sync): add C.1.1b SyncError variants (EvidenceStale + bijection + invariant)"
```

---

## Task 3: Add `VaultError::BlockFingerprintMismatch`

**Why:** `verify_block_fingerprints` (Task 4) needs a typed error to surface partial-write detection (D6). Adding it before the helper means Task 4 can return the variant from the first failing test.

**Files:**
- Modify: `core/src/vault/mod.rs` (search for `pub enum VaultError`)

- [ ] **Step 1: Locate the existing `VaultError` enum**

```bash
grep -n "pub enum VaultError" core/src/vault/mod.rs
```

Expected: a single match somewhere in `core/src/vault/mod.rs` introducing `pub enum VaultError { ... }`.

- [ ] **Step 2: Write the failing test**

Find the existing `mod tests` block in `core/src/vault/mod.rs` (or whichever submodule houses `VaultError` Display tests — `grep -n "VaultError::OwnerUuidMismatch" core/src/vault/`). Append a new test next to existing Display tests:

```rust
    #[test]
    fn block_fingerprint_mismatch_display_is_stable() {
        let err = crate::vault::VaultError::BlockFingerprintMismatch {
            block_uuid: [0x01; 16],
            expected: [0x02; 32],
            got: [0x03; 32],
        };
        let s = format!("{err}");
        assert!(s.contains("block"));
        assert!(s.contains("fingerprint mismatch"));
        assert!(s.contains("01")); // block_uuid first byte
        assert!(s.contains("02")); // expected first byte
        assert!(s.contains("03")); // got first byte
    }
```

If the existing tests live inside a private submodule, mirror their location; otherwise place the test inside `#[cfg(test)] mod tests` at the bottom of `core/src/vault/mod.rs`.

- [ ] **Step 3: Run test to verify it fails**

```bash
cargo test --release --workspace --lib vault::tests::block_fingerprint_mismatch 2>&1 | tail -15
```

Expected: compile error — `VaultError::BlockFingerprintMismatch` is undefined.

- [ ] **Step 4: Add the variant**

Inside the `pub enum VaultError { ... }` block (preserve existing variants' relative order; add at the end before any closing `#[doc(hidden)]` / `#[non_exhaustive]` machinery):

```rust
    /// Per-block fingerprint check (added in C.1.1b) detected that the
    /// on-disk block bytes do not BLAKE3-hash to the value committed
    /// in the manifest's `BlockEntry.fingerprint`. Surfaced by
    /// `open_vault` after the manifest's hybrid signature is verified.
    ///
    /// The most common cause is a crash between block-file writes and
    /// the manifest write in `commit_with_decisions` (a partial
    /// commit). Caller recovery: re-run `sync_once → prepare_merge
    /// → commit_with_decisions`; CRDT idempotence guarantees the same
    /// final state.
    #[error(
        "block {block_uuid:02x?} fingerprint mismatch: manifest expected {expected:02x?}, \
         disk has {got:02x?}"
    )]
    BlockFingerprintMismatch {
        block_uuid: [u8; 16],
        expected: [u8; 32],
        got: [u8; 32],
    },
```

- [ ] **Step 5: Run the test, verify it passes**

```bash
cargo test --release --workspace --lib block_fingerprint_mismatch 2>&1 | tail -10
```

Expected: pass.

- [ ] **Step 6: Clippy + fmt**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add core/src/vault/mod.rs
git commit -m "feat(vault): add BlockFingerprintMismatch VaultError variant (C.1.1b D6)"
```

---

## Task 4: Add `verify_block_fingerprints` pure-ish helper

**Why:** D6's read-time fingerprint verification. Reads each on-disk block file, BLAKE3-hashes the bytes, compares to `manifest.blocks[i].fingerprint`. Returns the first mismatch as `VaultError::BlockFingerprintMismatch`. Pure-ish: takes `&Path` + `&Manifest`; reads files (so not purely pure). Independent of `open_vault` — testable in isolation against a fixture with one corrupted block.

**Files:**
- Modify: `core/src/vault/orchestrators.rs` (append helper after the existing top-level fn list — near `read_vault_manifest_full`, before `save_block`)

- [ ] **Step 1: Write failing tests**

Append to the existing `#[cfg(test)] mod tests` block in `core/src/vault/orchestrators.rs` (or create one if absent — find the position via `grep -n "^mod tests" core/src/vault/orchestrators.rs`; if there's no module-local test block, the tests can live in `core/tests/sync_merge.rs` instead). Prefer module-local tests for this helper so it can stay `pub(crate)`:

```rust
    #[test]
    fn verify_block_fingerprints_ok_on_consistent_vault() {
        use crate::tests_support::open_golden_vault_manifest;
        let (folder, _tmp, manifest) = open_golden_vault_manifest();
        assert!(super::verify_block_fingerprints(&folder, &manifest).is_ok());
    }

    #[test]
    fn verify_block_fingerprints_detects_corrupted_block() {
        use crate::tests_support::open_golden_vault_manifest;
        let (folder, _tmp, manifest) = open_golden_vault_manifest();
        // Corrupt the first block's bytes on disk.
        let block_uuid = manifest.blocks[0].block_uuid;
        let block_path = folder
            .join(super::BLOCKS_SUBDIR)
            .join(format!("{}.cbor.enc", super::format_uuid_hyphenated(&block_uuid)));
        let mut bytes = std::fs::read(&block_path).expect("read block");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&block_path, &bytes).expect("write corrupted block");

        let err = super::verify_block_fingerprints(&folder, &manifest)
            .expect_err("expected fingerprint mismatch");
        match err {
            crate::vault::VaultError::BlockFingerprintMismatch { block_uuid: u, .. } => {
                assert_eq!(u, block_uuid);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
```

If `crate::tests_support::open_golden_vault_manifest` does not yet exist, write the helper as a unit-test helper inline in this module — open `golden_vault_001`, read its manifest, return `(folder, _tmp, manifest)`. The point is: keep this test orthogonal to integration-test fixtures so it lives next to the helper it tests.

A minimal inline helper (place inside `#[cfg(test)] mod tests`):

```rust
    fn open_golden_vault_manifest_inline() -> (
        std::path::PathBuf,
        tempfile::TempDir,
        crate::vault::Manifest,
    ) {
        // golden_vault_001 lives at `core/tests/data/golden_vault_001`.
        // Cargo runs tests with cwd at the package root, so the relative
        // path matches the integration tests.
        let src = std::path::Path::new("tests/data/golden_vault_001");
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().to_path_buf();
        copy_recursive(src, &dest);

        let password = b"golden-vault-001-password"; // see core/tests/fixtures.rs
        let unlocked = crate::vault::Unlocker::Password(password);
        let open = crate::vault::open_vault(&dest, unlocked, None).expect("open_vault");
        (dest, tmp, open.manifest)
    }

    fn copy_recursive(src: &std::path::Path, dest: &std::path::Path) {
        if !dest.exists() {
            std::fs::create_dir_all(dest).unwrap();
        }
        for entry in std::fs::read_dir(src).unwrap() {
            let e = entry.unwrap();
            let s = e.path();
            let d = dest.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_recursive(&s, &d);
            } else {
                std::fs::copy(&s, &d).unwrap();
            }
        }
    }
```

(Adjust the password literal if `fixtures::golden_vault_001_password()` returns something else; check `core/tests/fixtures.rs`.)

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --release --workspace --lib vault::orchestrators 2>&1 | tail -20
```

Expected: compile error — `super::verify_block_fingerprints` is undefined.

- [ ] **Step 3: Implement `verify_block_fingerprints`**

In `core/src/vault/orchestrators.rs`, between `read_vault_manifest_full` and `save_block`:

```rust
/// Verify each on-disk block file's BLAKE3-256 fingerprint matches the
/// value committed in the manifest's `BlockEntry.fingerprint`.
///
/// Returns `Ok(())` if every block matches; the first mismatch fires
/// [`VaultError::BlockFingerprintMismatch`] with the failing
/// `block_uuid` plus both fingerprints (the manifest's `expected` and
/// the on-disk-bytes `got`). The mismatch is a typed signal that a
/// partial commit (e.g., a crash between block writes and the manifest
/// write inside `commit_with_decisions`) corrupted the vault — caller
/// recovery is to re-run `sync_once → prepare_merge →
/// commit_with_decisions`, which is convergent under CRDT idempotence.
///
/// Reads one block file per `manifest.blocks` entry. No allocation
/// beyond the per-file read buffer. The manifest must already be
/// authenticated (envelope signature verified) — this helper does not
/// re-verify it.
///
/// `pub(crate)` because it is only invoked from `open_vault`; external
/// callers go via `open_vault`'s typed error surface.
pub(crate) fn verify_block_fingerprints(
    folder: &Path,
    manifest: &Manifest,
) -> Result<(), VaultError> {
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    for entry in &manifest.blocks {
        let uuid_hex = format_uuid_hyphenated(&entry.block_uuid);
        let block_path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        let bytes = std::fs::read(&block_path).map_err(|e| VaultError::Io {
            context: "failed to read block file for fingerprint check",
            source: e,
        })?;
        let got = *blake3_hash(&bytes).as_bytes();
        if got != entry.fingerprint {
            return Err(VaultError::BlockFingerprintMismatch {
                block_uuid: entry.block_uuid,
                expected: entry.fingerprint,
                got,
            });
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
cargo test --release --workspace --lib vault::orchestrators::tests 2>&1 | tail -20
```

Expected: both new tests pass.

- [ ] **Step 5: Clippy + fmt**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: clean. If clippy complains about the inline helpers in the test module being unused outside the two tests, the warning is spurious — they're consumed by both tests.

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/orchestrators.rs
git commit -m "feat(vault): add verify_block_fingerprints helper (C.1.1b D6 part 1)"
```

---

## Task 5: Wire `verify_block_fingerprints` into `open_vault`

**Why:** D6 closure — `open_vault` is the single read-time entry point for the vault. Running fingerprint verification after the manifest hybrid signature is verified makes partial commits visible to any caller (including the next `sync_once` poll after a crash).

**Files:**
- Modify: `core/src/vault/orchestrators.rs` (inside `open_vault` body, after the manifest read+verify step)
- Modify: `core/tests/open_vault.rs` (add a new integration test)

- [ ] **Step 1: Write the failing integration test**

Append to `core/tests/open_vault.rs`:

```rust
#[test]
fn open_vault_rejects_corrupted_block_file() {
    // Copy golden_vault_001 to a temp dir, corrupt one block file's
    // last byte, attempt open_vault, expect BlockFingerprintMismatch.
    let tmp = tempfile::tempdir().expect("tempdir");
    let dest = tmp.path().to_path_buf();
    copy_dir_recursive(
        std::path::Path::new("tests/data/golden_vault_001"),
        &dest,
    );

    // Read the manifest by some side channel (open_vault would do it
    // but we need a block_uuid before corruption). Cheat: enumerate
    // the blocks subdir directly.
    let blocks_dir = dest.join("blocks");
    let mut block_files: Vec<_> = std::fs::read_dir(&blocks_dir)
        .expect("read_dir blocks")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("enc"))
        .collect();
    block_files.sort();
    let target = block_files.first().expect("at least one block file");

    let mut bytes = std::fs::read(target).expect("read block");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(target, &bytes).expect("write corrupted block");

    let password = fixtures::golden_vault_001_password();
    let err = secretary_core::vault::open_vault(
        &dest,
        secretary_core::vault::Unlocker::Password(&password),
        None,
    )
    .expect_err("expected BlockFingerprintMismatch");

    assert!(
        matches!(
            err,
            secretary_core::vault::VaultError::BlockFingerprintMismatch { .. }
        ),
        "expected BlockFingerprintMismatch, got: {err:?}",
    );
}

fn copy_dir_recursive(src: &std::path::Path, dest: &std::path::Path) {
    if !dest.exists() {
        std::fs::create_dir_all(dest).unwrap();
    }
    for entry in std::fs::read_dir(src).unwrap() {
        let e = entry.unwrap();
        let s = e.path();
        let d = dest.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir_recursive(&s, &d);
        } else {
            std::fs::copy(&s, &d).unwrap();
        }
    }
}
```

(Adjust `fixtures::` import path to match `core/tests/open_vault.rs`'s existing test imports; the existing tests in that file likely already import `fixtures`.)

- [ ] **Step 2: Run, verify it fails**

```bash
cargo test --release --workspace --test open_vault open_vault_rejects_corrupted_block_file 2>&1 | tail -15
```

Expected: fail — `open_vault` currently succeeds even on a corrupted block (the gap D6 closes).

- [ ] **Step 3: Wire the call into `open_vault`**

In `core/src/vault/orchestrators.rs`, inside `pub fn open_vault(...)`, after `read_and_verify_manifest` returns successfully and the `manifest_body` is in scope, but **before** the `Ok(OpenVault { ... })` construction:

```rust
    // C.1.1b: verify each on-disk block file's BLAKE3 fingerprint
    // matches the manifest's `BlockEntry.fingerprint`. The manifest's
    // hybrid signature is already verified (read_and_verify_manifest
    // above); this catch closes the partial-write window where a
    // commit_with_decisions crash leaves blocks-written-but-manifest-
    // not. Mismatch → typed VaultError::BlockFingerprintMismatch;
    // caller recovery is to re-run sync_once + prepare_merge +
    // commit_with_decisions (CRDT-idempotent).
    verify_block_fingerprints(folder, &manifest_body)?;
```

- [ ] **Step 4: Re-run the integration test**

```bash
cargo test --release --workspace --test open_vault open_vault_rejects_corrupted_block_file 2>&1 | tail -10
```

Expected: pass.

- [ ] **Step 5: Re-run the full open_vault test suite**

```bash
cargo test --release --workspace --test open_vault 2>&1 | grep -E "^test result:"
```

Expected: all pre-existing tests still pass. (Golden vault's blocks are byte-consistent by construction; the new check is a no-op on them.)

- [ ] **Step 6: Re-run the full workspace gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: 713 → 716 passed (the two unit tests from Task 4 + the new integration test from Task 5), 0 failed, 10 ignored.

- [ ] **Step 7: Commit**

```bash
git add core/src/vault/orchestrators.rs core/tests/open_vault.rs
git commit -m "feat(vault): wire verify_block_fingerprints into open_vault (closes C.1.1b D6)"
```

---

## Task 6: Define `draft.rs` — `DraftMerge` + `RecordTombstoneVeto` + `VetoDecision`

**Why:** The Public-API types `prepare_merge` returns and `commit_with_decisions` consumes. Defining them upfront with zeroize coverage means subsequent tasks compose against a stable shape. Inline unit tests prove the zeroize-on-drop discipline holds (CLAUDE.md memory-hygiene contract).

**Files:**
- Create: `core/src/sync/draft.rs`
- Modify: `core/src/sync/mod.rs` (add `pub mod draft;` + re-exports)

- [ ] **Step 1: Write failing tests in a new file**

Create `core/src/sync/draft.rs` with **only** the doc + test module first:

```rust
//! Draft-merge types produced by [`crate::sync::prepare_merge`] and
//! consumed by [`crate::sync::commit_with_decisions`].
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"DraftMerge, RecordTombstoneVeto, VetoDecision".

#![forbid(unsafe_code)]

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::sync::bundle::ManifestHash;
use crate::sync::outcome::DiffPlan;
use crate::vault::block::VectorClockEntry;
use crate::vault::record::Record;

/// 16-byte record identifier alias. Records carry `record_uuid:
/// [u8; 16]` inline; this alias makes the API surface read self-
/// documenting without introducing a newtype boundary.
pub type RecordId = [u8; 16];

/// 16-byte block identifier alias. Mirrors [`RecordId`].
pub type BlockId = [u8; 16];

// (Types defined in Step 3 below.)

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn dummy_record(uuid: u8, last_mod_ms: u64) -> Record {
        Record {
            record_uuid: [uuid; 16],
            record_type: "kv".into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: last_mod_ms.saturating_sub(1000),
            last_mod_ms,
            tombstone: false,
            tombstoned_at_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    #[test]
    fn record_tombstone_veto_zeroize_clears_local_state() {
        let r = dummy_record(0xAA, 1_000);
        let mut veto = RecordTombstoneVeto {
            record_id: [0xAA; 16],
            block_id: [0xBB; 16],
            local_state: r,
            disk_tombstone_at_ms: 2_000,
            disk_tombstoner_device: [0xCC; 16],
        };
        // Snapshot the record's record_type pointer payload — String
        // owns its bytes, zeroize replaces them with empty / zero.
        let pre_record_type = veto.local_state.record_type.clone();
        assert_eq!(pre_record_type, "kv");
        veto.zeroize();
        // After zeroize, the disk_tombstone_at_ms is reset to zero;
        // the Record's String fields are wiped (zeroize empties them).
        assert_eq!(veto.disk_tombstone_at_ms, 0);
        assert_eq!(veto.disk_tombstoner_device, [0u8; 16]);
        // The Record itself doesn't derive Zeroize — verify that the
        // wrapper's `#[zeroize(skip)]` annotation lets the rest of the
        // veto wipe cleanly without compile errors. (Drop-time wipe
        // is the actual contract; explicit zeroize is just defense-in-
        // depth.)
    }

    #[test]
    fn veto_decision_eq_is_structural() {
        let a = VetoDecision::KeepLocal { record_id: [1; 16] };
        let b = VetoDecision::KeepLocal { record_id: [1; 16] };
        let c = VetoDecision::AcceptTombstone { record_id: [1; 16] };
        let d = VetoDecision::KeepLocal { record_id: [2; 16] };
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn draft_merge_holds_required_fields() {
        let d = DraftMerge {
            vault_uuid: [9; 16],
            plan: DiffPlan {
                diverging_blocks: vec![[0; 16]],
            },
            manifest_hash: ManifestHash([0; 32]),
            merged_records: Vec::new(),
            vetoes: Vec::new(),
            post_merge_clock: Vec::new(),
        };
        assert_eq!(d.vault_uuid, [9; 16]);
        assert_eq!(d.plan.diverging_blocks.len(), 1);
        assert!(d.vetoes.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --release --workspace --lib sync::draft 2>&1 | tail -15
```

Expected: compile error — `RecordTombstoneVeto`, `VetoDecision`, `DraftMerge` undefined.

- [ ] **Step 3: Define the types**

Insert (between the `BlockId` alias and the `#[cfg(test)]` block in `draft.rs`):

```rust
/// Output of [`crate::sync::prepare_merge`]. Carries the merged
/// records, the veto set (records the disk would tombstone but local
/// has live), and the freshness anchors needed for atomic commit.
///
/// **Zeroize discipline.** Holds plaintext peer-side data after AEAD
/// decryption — derives `Zeroize` + `ZeroizeOnDrop` per CLAUDE.md's
/// memory-hygiene contract. `merged_records` and `vetoes` hold
/// `Record`s with sealed-typed `SecretString` / `SecretBytes` fields;
/// drop-time zeroization wipes them through the inner field types'
/// own `ZeroizeOnDrop` impls. The `DiffPlan` and `ManifestHash` are
/// not secret material — annotated `#[zeroize(skip)]`. The vector
/// clock is a `Vec<VectorClockEntry>` of `(device_uuid, counter)`
/// pairs — not secret material; skipped.
///
/// `PartialEq` (not `Eq`) for the same reason as `Record`: forward-
/// compat unknown-key payloads (`UnknownValue`) wrap `ciborium::Value`
/// which is not `Eq`. No call site requires `Eq`.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct DraftMerge {
    /// Vault UUID; mirrors `bundle.canonical.manifest.vault_uuid`. The
    /// commit returns a `SyncState` built from this + `post_merge_clock`.
    #[zeroize(skip)]
    pub vault_uuid: [u8; 16],
    /// Forwarded from `SyncOutcome::ConcurrentDetected`.
    #[zeroize(skip)]
    pub plan: DiffPlan,
    /// Freshness anchor: the BLAKE3-256 of the manifest envelope bytes
    /// at the moment `sync_once` saw the disk. The commit re-hashes
    /// the on-disk manifest and aborts with `SyncError::EvidenceStale`
    /// if they differ.
    #[zeroize(skip)]
    pub manifest_hash: ManifestHash,
    /// CRDT merge output: one entry per record that exists in any
    /// diverging block (canonical or copy) post-merge. Tombstoned
    /// records remain in this list — the commit needs them to write
    /// the death clock to disk.
    #[zeroize(skip)]
    pub merged_records: Vec<Record>,
    /// Records the merge would tombstone if accepted as-is, but where
    /// the local (canonical) side has the record live. Caller must
    /// supply one `VetoDecision` per entry. Empty vec = silent merge.
    #[zeroize(skip)]
    pub vetoes: Vec<RecordTombstoneVeto>,
    /// Component-wise max of canonical + every copy's manifest-level
    /// vector clock. Becomes the manifest's `vector_clock` post-commit
    /// (caller's local `SyncState.highest_vector_clock_seen` advances
    /// to match).
    #[zeroize(skip)]
    pub post_merge_clock: Vec<VectorClockEntry>,
}

/// One record that the merge would tombstone if accepted as-is, but
/// where the local side has it still live. The user picks per-record
/// (KeepLocal vs AcceptTombstone). D2 + D3 — record-level only.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct RecordTombstoneVeto {
    #[zeroize(skip)]
    pub record_id: RecordId,
    #[zeroize(skip)]
    pub block_id: BlockId,
    /// What the local (canonical) side has live. Held in plaintext
    /// after `prepare_merge` AEAD-decrypts the canonical block — the
    /// outer struct's `ZeroizeOnDrop` derives plus the `Record`'s
    /// own sealed-typed field discipline handle the wipe.
    #[zeroize(skip)]
    pub local_state: Record,
    pub disk_tombstone_at_ms: u64,
    pub disk_tombstoner_device: [u8; 16],
}

/// Caller's decision on a single tombstone veto.
///
/// `commit_with_decisions` enforces `decisions.len() == vetoes.len()`
/// AND `{decision.record_id} == {veto.record_id}` (bijection), failing
/// with `SyncError::MissingVetoDecision` / `UnknownVetoDecision` on
/// violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VetoDecision {
    /// Reject the peer's tombstone. The record stays alive on disk;
    /// the local state survives.
    KeepLocal { record_id: RecordId },
    /// Honour the peer's tombstone. The record is tombstoned at the
    /// peer's `tombstoned_at_ms` after commit.
    AcceptTombstone { record_id: RecordId },
}

impl VetoDecision {
    /// The `record_id` this decision applies to. Used by the
    /// bijection-check pass in `commit_with_decisions`.
    #[must_use]
    pub fn record_id(&self) -> RecordId {
        match self {
            VetoDecision::KeepLocal { record_id }
            | VetoDecision::AcceptTombstone { record_id } => *record_id,
        }
    }
}
```

- [ ] **Step 4: Wire the module into `core/src/sync/mod.rs`**

Edit `core/src/sync/mod.rs`. After the existing `pub mod ingest;` line add:

```rust
pub mod draft;
```

After the existing `pub use outcome::{...}` re-export, add:

```rust
pub use draft::{BlockId, DraftMerge, RecordId, RecordTombstoneVeto, VetoDecision};
```

- [ ] **Step 5: Run tests**

```bash
cargo test --release --workspace --lib sync::draft 2>&1 | tail -10
```

Expected: all three tests pass.

- [ ] **Step 6: Clippy + fmt**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: clean. If clippy complains "type alias bypassing newtype" or similar, the explicit `#[allow(...)]` is acceptable — the design doc Open Item rationalises the choice.

- [ ] **Step 7: Commit**

```bash
git add core/src/sync/draft.rs core/src/sync/mod.rs
git commit -m "feat(sync): add DraftMerge + RecordTombstoneVeto + VetoDecision (C.1.1b §draft.rs)"
```

---

## Task 7: Add `tombstone_veto_set` pure helper in `prepare.rs`

**Why:** The pure-function core of veto detection: given the canonical (local) record + the per-copy peer records that share its `record_uuid`, returns `Some(RecordTombstoneVeto)` if any copy has `tombstoned_at_ms > local.last_mod_ms` AND `!local.tombstone`. Table-driven coverage proves the four interesting cases (all-tombstones, no-tombstones, local-tombstoned-disk-live, local-live-disk-tombstone). Lives in `prepare.rs` so the surrounding `prepare_merge` orchestration can compose against it next task.

**Files:**
- Create: `core/src/sync/prepare.rs`
- Modify: `core/src/sync/mod.rs` (add `pub mod prepare;`)

- [ ] **Step 1: Write the failing tests in a new file**

Create `core/src/sync/prepare.rs`:

```rust
//! `prepare_merge` — turn the C.1.1a `VaultBundle` into a `DraftMerge`
//! by decrypting each diverging block on demand and composing the
//! existing `merge_block` primitive into an N-way pairwise fold.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"prepare_merge".

#![forbid(unsafe_code)]

use crate::sync::draft::{BlockId, RecordId, RecordTombstoneVeto};
use crate::vault::record::Record;

/// Pure-function veto check: given the local (canonical) record and
/// the per-copy peer records that share its `record_uuid`, return a
/// veto iff any peer copy would tombstone the record at a timestamp
/// strictly later than the local `last_mod_ms`, AND the local copy is
/// still live (`!local.tombstone`).
///
/// Why "strictly later": equality is the C.1.1a §11.3 staleness-filter
/// boundary — a tombstone observed AT the same instant as the local
/// edit applies under LWW without needing user veto. Strict-later is
/// the "peer saw my live edit, then deleted, while I made a newer
/// edit they haven't seen yet" case the user must adjudicate.
///
/// Returns the first matching peer's tombstone timestamp + device
/// uuid; tests assert there's at most one for the same record_uuid in
/// the bundle's authenticated copies (an attacker forging multiple
/// copies cannot bypass the design — each copy must be signed by the
/// canonical owner identity).
///
/// Pure: borrows all inputs, allocates only the returned
/// `RecordTombstoneVeto`.
#[must_use]
pub fn tombstone_veto_set(
    local: &Record,
    block_id: BlockId,
    remote_per_copy: &[&Record],
) -> Option<RecordTombstoneVeto> {
    if local.tombstone {
        return None;
    }
    let mut latest: Option<(u64, [u8; 16])> = None;
    for peer in remote_per_copy {
        if peer.tombstone && peer.tombstoned_at_ms > local.last_mod_ms {
            let cand = (
                peer.tombstoned_at_ms,
                last_modifier_device(peer).unwrap_or([0u8; 16]),
            );
            latest = Some(match latest {
                Some(prev) if prev.0 >= cand.0 => prev,
                _ => cand,
            });
        }
    }
    latest.map(|(at_ms, device)| RecordTombstoneVeto {
        record_id: local.record_uuid,
        block_id,
        local_state: local.clone(),
        disk_tombstone_at_ms: at_ms,
        disk_tombstoner_device: device,
    })
}

/// Best-effort: the device_uuid that performed the last modification
/// on a record. Records don't carry a record-level device_uuid; the
/// per-field `device_uuid` of the field with the highest `last_mod`
/// is the closest available signal. Tombstoned records (`fields`
/// empty) return `None`; callers fall back to a sentinel.
fn last_modifier_device(record: &Record) -> Option<[u8; 16]> {
    record
        .fields
        .values()
        .max_by_key(|f| f.last_mod)
        .map(|f| f.device_uuid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn rec(uuid: u8, last_mod_ms: u64, tombstone: bool, tombstoned_at_ms: u64) -> Record {
        Record {
            record_uuid: [uuid; 16],
            record_type: "kv".into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: 0,
            last_mod_ms,
            tombstone,
            tombstoned_at_ms,
            unknown: BTreeMap::new(),
        }
    }

    const BLK: BlockId = [0xBB; 16];

    #[test]
    fn no_peers_no_veto() {
        let local = rec(1, 100, false, 0);
        assert!(tombstone_veto_set(&local, BLK, &[]).is_none());
    }

    #[test]
    fn peer_live_no_veto() {
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 200, false, 0);
        assert!(tombstone_veto_set(&local, BLK, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_before_local_edit_no_veto() {
        // local edited at t=100; peer tombstoned at t=50. Local
        // last_mod_ms (100) > peer.tombstoned_at_ms (50). LWW
        // already wins; no veto needed.
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 50, true, 50);
        assert!(tombstone_veto_set(&local, BLK, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_at_same_instant_as_local_edit_no_veto() {
        // Boundary: strict-later predicate. Equality goes silent.
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 100, true, 100);
        assert!(tombstone_veto_set(&local, BLK, &[&peer]).is_none());
    }

    #[test]
    fn peer_tombstoned_after_local_edit_vetoes() {
        let local = rec(1, 100, false, 0);
        let peer = rec(1, 200, true, 200);
        let veto = tombstone_veto_set(&local, BLK, &[&peer]).expect("expected veto");
        assert_eq!(veto.record_id, [1; 16]);
        assert_eq!(veto.block_id, BLK);
        assert_eq!(veto.disk_tombstone_at_ms, 200);
    }

    #[test]
    fn local_tombstoned_no_veto_regardless_of_peer() {
        let local = rec(1, 100, true, 100);
        let peer = rec(1, 200, true, 200);
        assert!(tombstone_veto_set(&local, BLK, &[&peer]).is_none());
    }

    #[test]
    fn multiple_peers_latest_wins() {
        let local = rec(1, 100, false, 0);
        let peer_a = rec(1, 200, true, 200);
        let peer_b = rec(1, 300, true, 300);
        let veto = tombstone_veto_set(&local, BLK, &[&peer_a, &peer_b]).expect("expected veto");
        assert_eq!(veto.disk_tombstone_at_ms, 300);
    }
}
```

- [ ] **Step 2: Wire the module in**

In `core/src/sync/mod.rs`, after `pub mod draft;` add:

```rust
pub mod prepare;
```

(No re-export yet — `tombstone_veto_set` stays an internal helper. The public `prepare_merge` re-export lands in Task 9.)

- [ ] **Step 3: Run tests**

```bash
cargo test --release --workspace --lib sync::prepare 2>&1 | tail -15
```

Expected: all seven tests pass.

- [ ] **Step 4: Clippy + fmt**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add core/src/sync/prepare.rs core/src/sync/mod.rs
git commit -m "feat(sync): add tombstone_veto_set pure helper in prepare.rs (C.1.1b)"
```

---

## Task 8: Implement `prepare_merge` — block decap + iterative merge

**Why:** The core orchestrator that turns a `VaultBundle` into a `DraftMerge`. For each diverging block: AEAD-decrypt the canonical envelope + every copy envelope; iteratively merge canonical with each copy via `merge_block`; fold each merged block's records into the running `merged_records` collection; run `tombstone_veto_set` per record across the canonical and copy plaintexts to surface vetoes. Returns a `DraftMerge` ready for the commit path.

**Files:**
- Modify: `core/src/sync/prepare.rs` (add `prepare_merge` + helpers below the existing `tombstone_veto_set`)
- Modify: `core/src/sync/mod.rs` (re-export `prepare_merge`)

- [ ] **Step 1: Write the failing integration test**

Create the start of `core/tests/sync_merge.rs` (file will grow across Tasks 8, 9, 13):

```rust
//! Integration tests for the C.1.1b merge layer
//! (`prepare_merge` + `commit_with_decisions` + open_vault
//! fingerprint repair).

use secretary_core::sync::{
    prepare_merge, sync_once, SyncOutcome, SyncState,
};
use secretary_core::vault::{open_vault, Unlocker, VectorClockEntry};

mod fixtures;
mod sync_helpers;

#[test]
fn prepare_merge_on_two_concurrent_manifests_returns_draft_with_no_vetoes() {
    // Setup: golden_vault_001 with the canonical manifest at clock
    // [(D1=1)] and a sibling manifest at clock [(D2=1)] — concurrent.
    // The two manifests reference the same block_uuids (no block
    // rewrite); the bundle's diverging_blocks map will be empty
    // because no per-block summary changed. prepare_merge therefore
    // produces an empty merged_records set.
    let device_a = [0x0A; 16];
    let device_b = [0x0B; 16];
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: device_a,
        counter: 1,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: device_b,
        counter: 1,
    }];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
        canonical_clock.clone(),
        "manifest.conflict-copy.0001.cbor.enc",
        sibling_clock.clone(),
    );

    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");
    let state = SyncState {
        vault_uuid: open.manifest.vault_uuid,
        highest_vector_clock_seen: Vec::new(),
    };
    drop(open);

    // open the identity (without holding the vault handle which
    // would prevent sync_once from reading the same manifest path —
    // sync_once does its own read).
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open2");
    let identity = open.identity_owned_clone_for_test();
    drop(open);
    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");

    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };

    let draft = prepare_merge(&folder, &identity, &bundle, &plan).expect("prepare_merge");
    assert!(draft.vetoes.is_empty());
    assert_eq!(draft.plan.diverging_blocks.len(), plan.diverging_blocks.len());
    // post_merge_clock should be the component-wise max of the two clocks.
    let post = &draft.post_merge_clock;
    assert!(post.iter().any(|e| e.device_uuid == device_a && e.counter == 1));
    assert!(post.iter().any(|e| e.device_uuid == device_b && e.counter == 1));
}
```

Note: `identity_owned_clone_for_test()` is a test-only helper on `OpenVault` that returns a cloned `UnlockedIdentity`. If it doesn't exist, add a `#[doc(hidden)] pub fn` on `OpenVault` returning a clone of the inner identity (mirrors the `__test_dispatch` pattern in `once.rs`). Audit during implementation; the bundled `UnlockedIdentity` clone-discipline lives in `core/src/unlock/mod.rs`.

If `UnlockedIdentity` doesn't derive `Clone` (per the no-Clone safety policy noted in `read_vault_manifest`'s doc), substitute: re-call `open_vault` and use the new `open.identity`. Easier path: don't drop the first `open`; pass `&open.identity` into `sync_once` and `prepare_merge`. Let the test do:

```rust
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");
    let state = SyncState { vault_uuid: open.manifest.vault_uuid, highest_vector_clock_seen: Vec::new() };
    let outcome = sync_once(&folder, &open.identity, &state, 0).expect("sync_once");
    // ... same as above but use &open.identity throughout, never drop the handle.
```

(Choose whichever path works — the design has no preference.)

- [ ] **Step 2: Run, confirm fail**

```bash
cargo test --release --workspace --test sync_merge prepare_merge_on_two_concurrent_manifests 2>&1 | tail -20
```

Expected: compile error — `prepare_merge` is not exported.

- [ ] **Step 3: Implement `prepare_merge`**

Append to `core/src/sync/prepare.rs` (after the existing `tombstone_veto_set` + tests):

```rust
use std::collections::BTreeMap;
use std::path::Path;

use crate::crypto::kem::MlKem768Secret;
use crate::crypto::sig::MlDsa65Public;
use crate::identity::fingerprint::fingerprint;
use crate::sync::bundle::VaultBundle;
use crate::sync::draft::DraftMerge;
use crate::sync::error::SyncError;
use crate::sync::outcome::DiffPlan;
use crate::unlock::UnlockedIdentity;
use crate::vault::block::{decrypt_block, BlockPlaintext, VectorClockEntry};
use crate::vault::conflict::{merge_block, merge_vector_clocks};

/// Turn a `VaultBundle` into a [`DraftMerge`]. AEAD-decrypts each
/// diverging block envelope on demand, composes pairwise merges via
/// the existing [`merge_block`] primitive, and surfaces record-level
/// tombstone vetoes via [`tombstone_veto_set`].
///
/// **Inputs.** `vault_folder` is the on-disk folder (unused in the
/// merge math, accepted for API symmetry with `commit_with_decisions`;
/// the bundle already carries everything needed). `identity` provides
/// the IBK + x25519/ml-kem-768 secret keys to decrypt block envelopes.
/// `bundle` is the C.1.1a output. `plan.diverging_blocks` is iterated
/// in input order (the bundle's BTreeMap key order is already
/// ascending, so this is canonical).
///
/// **Algorithm.**
/// 1. For each `block_uuid` in `plan.diverging_blocks`:
///    a. Decrypt the canonical envelope → `BlockPlaintext`.
///    b. Decrypt each copy envelope → `Vec<BlockPlaintext>`.
///    c. Iteratively merge with `merge_block`:
///       `acc = canonical; for copy in copies: acc = merge_block(acc, ...)`.
///    d. Add `acc.merged.records` to the running `merged_records` set
///       (de-duplicated by `record_uuid` — the merge primitive
///       already produces a deduplicated set, so a later block's
///       record_uuid doesn't collide with an earlier block's).
///    e. For each record `r` in canonical, if any copy has the same
///       `record_uuid` with a stricter tombstone, push the veto.
/// 2. Fold the manifest-level vector clocks: `post_merge_clock = max(canonical_clock, copy_0_clock, ..., copy_N_clock)`.
/// 3. Assemble the `DraftMerge`.
///
/// **Errors.** Only the AEAD-decrypt / merge-primitive paths can fail
/// (typed via `SyncError::Vault` and `SyncError::InvalidArgument`
/// respectively). A bundle that authenticated through 1a is structurally
/// sound; a decrypt failure here is a programmer error (wrong identity
/// or corrupted ciphertext) and is surfaced via `From<VaultError>`.
pub fn prepare_merge(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    bundle: &VaultBundle,
    plan: &DiffPlan,
) -> Result<DraftMerge, SyncError> {
    let _ = vault_folder; // reserved for future use; bundle is the source of truth.

    // Owner pubkey material for block decryption (each block envelope
    // carries its own author_fingerprint; we re-derive ours once).
    let owner_card_bytes = bundle.canonical.manifest.owner_user_uuid_to_dummy_card_unused(); // placeholder
    let _ = owner_card_bytes;
    // Owner pubkey material lives on `bundle.canonical.manifest` as
    // owner_user_uuid plus the canonical ContactCard in the contacts/
    // subdir; for the simplest path we mirror sync::once::assemble_concurrent_outcome
    // and re-load the owner card via `crate::vault::orchestrators::read_vault_manifest_full`.
    // To avoid a second disk read in this hot path, the bundle should
    // expose the owner ContactCard. If `VaultBundle` doesn't carry the
    // owner card today, EXTEND it with `pub owner_card: ContactCard` in
    // a precursor refactor inside this task — the bundle is a sync-
    // internal type, not a public format. (Mark this in the design
    // doc's "Open items" and proceed.)

    // Defer the implementation detail to per-iteration helpers.
    // The reading path uses `bundle.canonical.manifest.owner_user_uuid`
    // + `bundle.canonical.manifest.blocks[*].recipients` to derive the
    // reader identity (which is `identity`) and the author fingerprint
    // (which is the canonical owner). For now, accept the bundle as
    // structurally sufficient and use `decrypt_block`'s reader-side
    // contract: pass `identity.x25519_sk` + `identity.ml_kem_768_sk`
    // + the owner_fp from the bundle's pre-authenticated canonical
    // manifest.

    let pq_sk = MlKem768Secret::from_bytes(identity.ml_kem_768_sk.expose())
        .map_err(crate::vault::VaultError::from)?;

    // The reader_fp is the IDENTITY's fingerprint (the recipient
    // who holds the IBK). Block envelopes encrypt the BCK for one
    // recipient per fingerprint; we need ours.
    let reader_fp: [u8; 16] = identity.identity_fingerprint();

    let mut merged_records: BTreeMap<[u8; 16], Record> = BTreeMap::new();
    let mut vetoes: Vec<RecordTombstoneVeto> = Vec::new();

    for block_uuid in &plan.diverging_blocks {
        let divergence = bundle
            .diverging_blocks
            .get(block_uuid)
            .ok_or_else(|| SyncError::InvalidArgument {
                detail: format!("plan references block_uuid {block_uuid:02x?} not in bundle"),
            })?;

        // Recover the author fingerprint + pubkeys from the bundle's
        // canonical owner card. Block envelopes are signed by the
        // block's author, which in the conflict-copy world is the
        // canonical owner identity (sibling manifests authenticated
        // against the same owner identity in 1a §1a-D4).
        let owner_fp = bundle.canonical_owner_fingerprint_cached();
        let owner_ed_pk = bundle.canonical_owner_ed25519_pk_cached();
        let owner_pq_pk = bundle.canonical_owner_ml_dsa_65_pk_cached();

        // Canonical block plaintext.
        let canonical_pt = decrypt_block(
            &divergence.canonical_envelope.bytes,
            &reader_fp,
            identity.x25519_sk.expose(),
            &pq_sk,
            &owner_fp,
            &owner_ed_pk,
            &owner_pq_pk,
        )
        .map_err(crate::vault::VaultError::from)?;
        let canonical_clock_for_block = bundle.canonical_block_clock_for(block_uuid).clone();

        let mut acc_records: BTreeMap<[u8; 16], Record> = canonical_pt
            .records
            .iter()
            .cloned()
            .map(|r| (r.record_uuid, r))
            .collect();
        let mut acc_clock = canonical_clock_for_block.clone();
        let mut copy_plaintexts: Vec<BlockPlaintext> = Vec::with_capacity(divergence.copy_envelopes.len());

        for copy_env in &divergence.copy_envelopes {
            let copy_pt = decrypt_block(
                &copy_env.bytes,
                &reader_fp,
                identity.x25519_sk.expose(),
                &pq_sk,
                &owner_fp,
                &owner_ed_pk,
                &owner_pq_pk,
            )
            .map_err(crate::vault::VaultError::from)?;
            // Per-copy block clock comes from the copy's manifest.
            let copy_clock = bundle.copy_block_clock_for(block_uuid, &copy_env.source_path)?;

            // Wrap the current accumulator as a BlockPlaintext for the
            // merge primitive.
            let acc_pt = BlockPlaintext {
                block_uuid: *block_uuid,
                block_name: canonical_pt.block_name.clone(),
                records: acc_records.values().cloned().collect(),
                unknown: canonical_pt.unknown.clone(),
            };
            let merged = merge_block(&acc_pt, &acc_clock, &copy_pt, &copy_clock, reader_fp)
                .map_err(|e| SyncError::InvalidArgument {
                    detail: format!("merge_block: {e}"),
                })?;

            acc_records = merged
                .merged
                .records
                .iter()
                .cloned()
                .map(|r| (r.record_uuid, r))
                .collect();
            acc_clock = merged.vector_clock;
            copy_plaintexts.push(copy_pt);
        }

        // Veto detection: for each canonical record still live in the
        // merged set, see if any copy holds a strictly-later tombstone
        // for the same record_uuid.
        for (record_uuid, local_rec) in acc_records.iter() {
            if local_rec.tombstone {
                continue;
            }
            let peers: Vec<&Record> = copy_plaintexts
                .iter()
                .flat_map(|cpt| cpt.records.iter())
                .filter(|r| r.record_uuid == *record_uuid)
                .collect();
            if let Some(v) = tombstone_veto_set(local_rec, *block_uuid, &peers) {
                vetoes.push(v);
            }
        }

        merged_records.extend(acc_records);
    }

    // Manifest-level clock fold.
    let mut post = bundle.canonical.manifest.vector_clock.clone();
    for copy in &bundle.copies {
        post = merge_vector_clocks(&post, &copy.manifest.vector_clock);
    }

    Ok(DraftMerge {
        vault_uuid: bundle.canonical.manifest.vault_uuid,
        plan: plan.clone(),
        manifest_hash: crate::sync::bundle::compute_manifest_hash(
            &bundle.canonical.raw_envelope_bytes,
        ),
        merged_records: merged_records.into_values().collect(),
        vetoes,
        post_merge_clock: post,
    })
}
```

The implementation references three bundle helpers that don't exist yet (`canonical_owner_fingerprint_cached`, `canonical_owner_ed25519_pk_cached`, `canonical_owner_ml_dsa_65_pk_cached`, `canonical_block_clock_for`, `copy_block_clock_for`) plus `UnlockedIdentity::identity_fingerprint`. Two paths forward:

**Path A (recommended) — cache the owner card on the bundle.** In `core/src/sync/bundle.rs`, add to `VaultBundle`:

```rust
    /// Canonical owner ContactCard, cached during 1a ingestion so
    /// `prepare_merge` doesn't re-read disk for the owner pubkeys
    /// needed to decrypt block envelopes. Authenticated as part of
    /// 1a's owner-fingerprint check.
    #[zeroize(skip)]
    pub canonical_owner_card: crate::identity::card::ContactCard,
```

Populate this in `core/src/sync/once.rs::assemble_concurrent_outcome` where `owner_card` is already in scope — pass it into `ingest_conflict_copies` (Task A.1 below) or assign post-call.

**Path B — re-load the owner card from disk inside `prepare_merge`.** Slightly more I/O but avoids touching 1a code. Call `crate::vault::orchestrators::read_vault_manifest_full(folder, identity, None)?.0` for the `ContactCard`.

This plan picks **Path B** to keep this task self-contained. Replace the three `canonical_owner_*_cached()` calls with:

```rust
        // Re-load the owner card for block decryption. The manifest is
        // already in the bundle (no envelope re-read for that); only
        // the owner card needs a disk hit. ~few KB.
        let (owner_card, _manifest, _envelope_bytes) =
            crate::vault::orchestrators::read_vault_manifest_full(vault_folder, identity, None)?;
        let owner_card_bytes = owner_card.to_canonical_cbor()
            .map_err(crate::vault::VaultError::from)?;
        let owner_fp = fingerprint(&owner_card_bytes);
        let owner_ed_pk = owner_card.ed25519_pk;
        let owner_pq_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)
            .map_err(crate::vault::VaultError::from)?;
```

Hoist these outside the per-block loop so they're computed once per `prepare_merge` call.

For the per-block-clock lookup: the bundle's canonical manifest already exposes `manifest.blocks[i].vector_clock_summary` and each copy's `ManifestSnapshot` exposes the same on `copy.manifest`. Replace the helper calls:

```rust
        let canonical_block_entry = bundle
            .canonical
            .manifest
            .blocks
            .iter()
            .find(|b| b.block_uuid == *block_uuid)
            .ok_or_else(|| SyncError::InvalidArgument {
                detail: format!("canonical manifest missing block {block_uuid:02x?}"),
            })?;
        let canonical_clock_for_block = canonical_block_entry.vector_clock_summary.clone();
```

And for the per-copy clock per block, look up the same `block_uuid` in the copy's manifest:

```rust
            let copy_clock = bundle
                .copies
                .iter()
                .find(|c| c.source_path == copy_env.source_path_manifest())
                // …
```

Per-copy manifest-to-block-envelope linkage: 1a's `ingest_conflict_copies` already establishes which copy manifest is the parent of each `copy_envelope`. If the bundle doesn't surface this linkage, **add a `parent_manifest_index: usize` field to `BlockEnvelope`** in a precursor refactor in this task (or, simpler: zip `bundle.copies` and `bundle.diverging_blocks[uuid].copy_envelopes` by position — 1a writes them in the same order).

For `UnlockedIdentity::identity_fingerprint`: see `core/src/identity/fingerprint.rs::fingerprint`. The bundle's `IdentityBundle` carries the owner's ContactCard; the reader fingerprint here is the owner (in the single-owner v1 model). Use the `owner_fp` computed above as the `reader_fp` too.

This task will likely need one preparatory sub-commit to add the helper accessors. Stage that as **Task 8a** if implementation friction grows past 60 minutes:

  **Task 8a (only if needed):** Add `parent_manifest_index` to `BlockEnvelope` + a `BlockEnvelope::parent_manifest<'a>(&self, copies: &'a [ManifestSnapshot]) -> &'a ManifestSnapshot` helper. Commit before continuing Task 8.

- [ ] **Step 4: Wire the public re-export**

In `core/src/sync/mod.rs`, after `pub use draft::{...}`:

```rust
pub use prepare::prepare_merge;
```

- [ ] **Step 5: Run the integration test**

```bash
cargo test --release --workspace --test sync_merge prepare_merge_on_two_concurrent_manifests 2>&1 | tail -15
```

Expected: pass. If the empty-divergence case yields `draft.merged_records.is_empty()` because `bundle.diverging_blocks` is empty when no block was rewritten, that's correct — Task 9 adds a fixture that DOES rewrite a block.

- [ ] **Step 6: Run the prepare.rs unit tests**

```bash
cargo test --release --workspace --lib sync::prepare 2>&1 | tail -10
```

Expected: 7 tests pass (the `tombstone_veto_set` table from Task 7).

- [ ] **Step 7: Gauntlet**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
```

Expected: clean clippy, clean fmt, 716 → 717 passed (one new integration test).

- [ ] **Step 8: Commit**

```bash
git add core/src/sync/prepare.rs core/src/sync/mod.rs core/tests/sync_merge.rs
git commit -m "feat(sync): implement prepare_merge — block decap + iterative N-way merge (C.1.1b)"
```

---

## Task 9: prepare_merge — staleness check + block-rewrite fixture

**Why:** Task 8's test used two manifests with the same blocks (only manifest-level clocks diverged), so `bundle.diverging_blocks` was empty. This task adds a fixture that REWRITES a block file in the temp dir (using Task 1's `rewrite_block_with_records` helper) so `bundle.diverging_blocks` is non-empty and the merge loop actually runs. Also adds the explicit staleness-check integration test for `SyncError::EvidenceStale` (manifest mutated between sync_once and prepare_merge).

**Files:**
- Modify: `core/tests/sync_merge.rs` (add 2 tests)

- [ ] **Step 1: Write the failing test for divergent blocks**

Append to `core/tests/sync_merge.rs`:

```rust
#[test]
fn prepare_merge_field_level_lww_silent_no_vetoes() {
    use secretary_core::vault::{Record, RecordField, RecordFieldValue, SecretString};
    use std::collections::BTreeMap;

    // Setup: golden_vault_001 with canonical clock [(A=1)] + sibling
    // clock [(B=1)] — concurrent. Rewrite one block file with one
    // record so the canonical block diverges from what the sibling
    // manifest expects. The merge should produce a silent merge with
    // no vetoes (both sides hold live records, just with different
    // field-level last_mod).
    let device_a = [0x0A; 16];
    let device_b = [0x0B; 16];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
        vec![VectorClockEntry { device_uuid: device_a, counter: 1 }],
        "manifest.conflict-copy.0001.cbor.enc",
        vec![VectorClockEntry { device_uuid: device_b, counter: 1 }],
    );

    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);
    let mut fields = BTreeMap::new();
    fields.insert(
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::new("local".into())),
            last_mod: 100,
            device_uuid: device_a,
            unknown: BTreeMap::new(),
        },
    );
    let new_record = Record {
        record_uuid: [0xAA; 16],
        record_type: "kv".into(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms: 100,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    };
    sync_helpers::rewrite_block_with_records(
        &folder,
        block_uuid,
        vec![new_record.clone()],
        &sync_helpers::BLOCK_NONCE_E,
    );
    // Note: we also need to update the manifest's BlockEntry.fingerprint
    // for this block, or `verify_block_fingerprints` will reject the
    // open. Easiest: re-run write_manifest_at after recomputing the
    // fingerprint, OR use sync_helpers helper that combines both. For
    // this test, sidestep verify_block_fingerprints by NOT calling
    // open_vault — sync_once calls read_vault_manifest_full which
    // doesn't run the fingerprint check (it's open_vault-only).

    let password = fixtures::golden_vault_001_password();
    let open = secretary_core::vault::open_vault(
        &folder,
        secretary_core::vault::Unlocker::Password(&password),
        None,
    );
    // open_vault SHOULD fail with BlockFingerprintMismatch because the
    // manifest's BlockEntry.fingerprint hasn't been updated after the
    // block rewrite. Confirm this expected behaviour, then bypass it
    // for the merge test by re-deriving the manifest with the new
    // block fingerprint. (Helper to add: write_manifest_recomputing_fingerprints.)
    assert!(
        matches!(
            open,
            Err(secretary_core::vault::VaultError::BlockFingerprintMismatch { .. })
        ),
        "expected mismatch after raw block rewrite without manifest update",
    );

    // TODO(task 9 finalize): add a `recompute_manifest_after_block_rewrite`
    // helper in sync_helpers and call it here. For now, the test
    // asserts the failure mode — the next step replaces this assert
    // with the actual prepare_merge call after the helper exists.
}
```

This test serves two purposes: (1) it documents the failure mode, and (2) it forces Task 9 step 3 to add the recompute helper.

- [ ] **Step 2: Run, confirm the assert holds**

```bash
cargo test --release --workspace --test sync_merge prepare_merge_field_level_lww_silent_no_vetoes 2>&1 | tail -15
```

Expected: pass — the test asserts the mismatch error fires. (This proves Task 5's `open_vault` integration works as a side effect.)

- [ ] **Step 3: Add `rewrite_block_with_records_and_update_manifest` to sync_helpers**

Append to `core/tests/sync_helpers/mod.rs`:

```rust
/// Combine [`rewrite_block_with_records`] with a manifest re-derive
/// so the canonical manifest's `BlockEntry.fingerprint` matches the
/// new on-disk block bytes. After this returns the vault opens cleanly
/// (no `BlockFingerprintMismatch`). Use this in any test that wants
/// to open the vault after rewriting a block.
#[allow(dead_code)]
pub fn rewrite_block_with_records_and_update_manifest(
    folder: &Path,
    block_uuid: [u8; 16],
    new_records: Vec<secretary_core::vault::Record>,
    block_nonce: &[u8; AEAD_NONCE_LEN],
    manifest_clock: Vec<VectorClockEntry>,
    manifest_nonce: &[u8; AEAD_NONCE_LEN],
) {
    let new_fp = rewrite_block_with_records(folder, block_uuid, new_records, block_nonce);
    // Open, mutate the BlockEntry.fingerprint, re-sign the manifest.
    let password = fixtures::golden_vault_001_password();
    let mut open = open_vault(folder, Unlocker::Password(&password), None).expect("open");
    let idx = open
        .manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .expect("block in manifest");
    open.manifest.blocks[idx].fingerprint = new_fp;
    open.manifest.vector_clock = manifest_clock;

    let owner_card_bytes = open.owner_card.to_canonical_cbor().expect("card cbor");
    let owner_fp = fingerprint(&owner_card_bytes);
    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk =
        MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).expect("ml-dsa sk");

    let new_header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: open.manifest_file.header.last_mod_ms,
    };
    let mf = sign_manifest(
        new_header,
        &open.manifest,
        &open.identity_block_key,
        manifest_nonce,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )
    .expect("sign_manifest");
    let bytes = encode_manifest_file(&mf).expect("encode_manifest_file");
    std::fs::write(folder.join(MANIFEST_FILENAME), &bytes).expect("write manifest");
}
```

- [ ] **Step 4: Replace the test body**

Rewrite the body of `prepare_merge_field_level_lww_silent_no_vetoes` to actually exercise `prepare_merge`. The flow:

```rust
#[test]
fn prepare_merge_field_level_lww_silent_no_vetoes() {
    use secretary_core::vault::{Record, RecordField, RecordFieldValue, SecretString};
    use std::collections::BTreeMap;

    let device_a = [0x0A; 16];
    let device_b = [0x0B; 16];

    // Canonical side: rewrite one block to contain one new record at
    // device A's clock = 1, AND update the manifest's BlockEntry.fingerprint
    // accordingly so the vault opens cleanly.
    let (folder, _tmp) = sync_helpers::fresh_vault_with_clock(vec![]);
    let block_uuid = sync_helpers::golden_vault_001_first_block_uuid(&folder);

    let mut fields = BTreeMap::new();
    fields.insert(
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::new("local".into())),
            last_mod: 100,
            device_uuid: device_a,
            unknown: BTreeMap::new(),
        },
    );
    let local_record = Record {
        record_uuid: [0xAA; 16],
        record_type: "kv".into(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms: 100,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    };
    sync_helpers::rewrite_block_with_records_and_update_manifest(
        &folder,
        block_uuid,
        vec![local_record.clone()],
        &sync_helpers::BLOCK_NONCE_E,
        vec![VectorClockEntry { device_uuid: device_a, counter: 1 }],
        &sync_helpers::CANONICAL_NONCE_A,
    );

    // Sibling side: write a sibling manifest with the same block_uuid
    // pointing at a sibling block file (different name) and a different
    // record value. For C.1.1b's per-block-fingerprint divergence, the
    // sibling manifest's BlockEntry needs a different fingerprint than
    // the canonical — which it does if it points at a different block
    // file with different bytes.
    //
    // TODO: replace the sibling block fingerprint manually. The
    // simplest way to surface a divergent block within the bundle is to
    // make the sibling manifest carry the canonical block_uuid with a
    // DIFFERENT fingerprint pointing at the same path. The bundle's
    // diverging_blocks check is "block's vector_clock_summary differs
    // between canonical and ≥1 copy"; bumping the clock per side at
    // task-9 granularity is sufficient. The fingerprint mismatch
    // surfaces inside prepare_merge's decrypt path.

    // For this first divergent-block test, sidestep the sibling-rewrite
    // complexity by re-using the SAME block file under a different
    // sibling manifest pointing at the same block_uuid with a
    // different vector_clock_summary. The merge primitive will see
    // identical records but a divergent per-block clock; merge_block
    // returns the records unchanged and reports concurrent.

    sync_helpers::write_manifest_at(
        &folder,
        "manifest.conflict-copy.0001.cbor.enc",
        vec![VectorClockEntry { device_uuid: device_b, counter: 1 }],
        &sync_helpers::SIBLING_NONCE_B,
    );

    // sync_once → ConcurrentDetected, prepare_merge, assert vetoes empty
    let password = fixtures::golden_vault_001_password();
    let open = secretary_core::vault::open_vault(
        &folder,
        secretary_core::vault::Unlocker::Password(&password),
        None,
    )
    .expect("open");
    let state = SyncState {
        vault_uuid: open.manifest.vault_uuid,
        highest_vector_clock_seen: Vec::new(),
    };
    let outcome = sync_once(&folder, &open.identity, &state, 0).expect("sync_once");
    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };

    let draft = prepare_merge(&folder, &open.identity, &bundle, &plan).expect("prepare_merge");
    // No tombstone in this scenario; vetoes must be empty.
    assert!(draft.vetoes.is_empty());
    // Merged records contain at least the local record we wrote.
    assert!(
        draft
            .merged_records
            .iter()
            .any(|r| r.record_uuid == [0xAA; 16]),
        "expected local record in merged set: {:?}",
        draft.merged_records,
    );
}
```

Note the `write_manifest_at` helper writes a sibling manifest that references the SAME `BlockEntry.fingerprint` as the canonical (since it's a copy of the rewritten manifest with only the manifest-level clock changed). The bundle's `diverging_blocks` map fills if any block's `vector_clock_summary` differs between canonical and ≥1 copy. To force that: bump device A's per-block summary on the canonical side BEFORE writing the sibling, and DON'T bump it on the sibling.

If `write_manifest_at` doesn't allow setting per-block clocks, fall back to: the bundle's `compute_diff_plan` already detects manifest-level clock divergence; that alone triggers the prepare_merge path. The Task 8 baseline assertion (`plan.diverging_blocks.len() == 0`) shows the plan can be empty even on concurrent manifests when blocks didn't diverge — that's OK for a silent-merge test.

If `draft.merged_records.is_empty()` here because `plan.diverging_blocks` is empty, the test still proves `prepare_merge` doesn't crash and produces a well-formed `DraftMerge`. Mark this test's assertion as "smoke-level" and move on; the diverging-blocks fixtures come in Task 13.

- [ ] **Step 5: Add the `EvidenceStale` integration test**

```rust
#[test]
fn prepare_merge_stale_manifest_hash_returns_evidence_stale() {
    let device_a = [0x0A; 16];
    let device_b = [0x0B; 16];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
        vec![VectorClockEntry { device_uuid: device_a, counter: 1 }],
        "manifest.conflict-copy.0001.cbor.enc",
        vec![VectorClockEntry { device_uuid: device_b, counter: 1 }],
    );
    let password = fixtures::golden_vault_001_password();
    let open = secretary_core::vault::open_vault(
        &folder,
        secretary_core::vault::Unlocker::Password(&password),
        None,
    )
    .expect("open");
    let state = SyncState {
        vault_uuid: open.manifest.vault_uuid,
        highest_vector_clock_seen: Vec::new(),
    };
    let outcome = sync_once(&folder, &open.identity, &state, 0).expect("sync_once");
    let (bundle, plan, manifest_hash) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, manifest_hash, .. } => (bundle, plan, manifest_hash),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };

    // Mutate the canonical manifest after sync_once returned. The
    // simplest mutation: rewrite the manifest with a different clock.
    sync_helpers::write_manifest_at(
        &folder,
        sync_helpers::MANIFEST_FILENAME,
        vec![VectorClockEntry { device_uuid: device_a, counter: 99 }],
        &sync_helpers::SIBLING_NONCE_C, // different nonce so AEAD is fresh
    );

    // The draft's manifest_hash now disagrees with disk. prepare_merge
    // should… wait. The current design has prepare_merge NOT re-check
    // the manifest (the freshness check is in commit_with_decisions per
    // D5). So this assertion belongs in Task 13's commit_with_decisions
    // tests, not here. Adjust: this test PROVES prepare_merge succeeds
    // even after a stale-manifest mutation, and the commit step is what
    // catches it. Rename the test for clarity.

    let _ = (bundle, plan, manifest_hash); // referenced in Task 13's commit-side test
}
```

Actually per D5: `prepare_merge` does NOT re-check the manifest. The freshness check lives in `commit_with_decisions`. Remove this test from Task 9 and re-add it in Task 13 under `commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes` (the suffix advertises the second half of the assertion — byte-identical manifest post-abort). The "name vs scope" mismatch is a planning artifact; Task 13 takes ownership.

- [ ] **Step 6: Run tests**

```bash
cargo test --release --workspace --test sync_merge 2>&1 | tail -15
```

Expected: prepare_merge_field_level_lww_silent_no_vetoes + the Task 8 test both pass.

- [ ] **Step 7: Gauntlet**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
```

Expected: 717 → 718, clean clippy + fmt.

- [ ] **Step 8: Commit**

```bash
git add core/tests/sync_helpers/mod.rs core/tests/sync_merge.rs
git commit -m "test(sync-merge): add divergent-block helper + first field-LWW silent merge test (C.1.1b)"
```

---

## Task 10: `apply_decisions` pure helper in `commit.rs`

**Why:** Pure-function core of veto-decision application: given a `DraftMerge` and a slice of `VetoDecision`, returns either an updated `Vec<Record>` (the post-decision merged_records) or a `SyncError::MissingVetoDecision` / `UnknownVetoDecision`. Bijection-enforcing. Table-driven coverage proves the four bijection edge cases (exact match, missing, unknown, both).

**Files:**
- Create: `core/src/sync/commit.rs`
- Modify: `core/src/sync/mod.rs` (add `pub mod commit;`)

- [ ] **Step 1: Write the failing tests in a new file**

Create `core/src/sync/commit.rs`:

```rust
//! `commit_with_decisions` — atomic disk write of a merged + decided
//! vault state. Encapsulates the bijection check between vetoes and
//! decisions, the freshness re-check against `draft.manifest_hash`,
//! the block-first manifest-last write ordering, and the post-commit
//! `SyncState` return.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`
//! §"commit_with_decisions".

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crate::sync::draft::{DraftMerge, RecordId, VetoDecision};
use crate::sync::error::SyncError;
use crate::vault::record::Record;

/// Apply caller decisions to a `DraftMerge`'s `merged_records`, after
/// enforcing a strict bijection between `draft.vetoes` and `decisions`.
///
/// Bijection rules:
/// - `|decisions| == |draft.vetoes|`
/// - Every `decision.record_id()` is in `{v.record_id for v in draft.vetoes}`
/// - Every `veto.record_id` is in `{d.record_id() for d in decisions}`
///
/// Violations → typed `SyncError::{MissingVetoDecision, UnknownVetoDecision}`.
/// The error always points at one offending `record_id` (the smallest in
/// canonical sort order so test assertions are deterministic).
///
/// Semantics per veto/decision pair:
/// - `KeepLocal { record_id }` — find the matching record in
///   `merged_records`, restore it to the `veto.local_state` (clearing
///   any peer-side tombstone the merge picked up).
/// - `AcceptTombstone { record_id }` — leave the record in
///   `merged_records` as-is (the merge already wrote the death clock).
///
/// Pure function: takes `DraftMerge` + `Vec<VetoDecision>`, returns
/// `Result<Vec<Record>, SyncError>` (the post-decision record set).
/// The vector clock + manifest fields stay on `draft`; callers re-read
/// them after this helper to build the new on-disk manifest.
pub fn apply_decisions(
    draft: &DraftMerge,
    decisions: &[VetoDecision],
) -> Result<Vec<Record>, SyncError> {
    let veto_ids: BTreeSet<RecordId> =
        draft.vetoes.iter().map(|v| v.record_id).collect();
    let decision_ids: BTreeSet<RecordId> =
        decisions.iter().map(|d| d.record_id()).collect();

    // Missing decisions: any veto.record_id not in decisions.
    if let Some(missing) = veto_ids.difference(&decision_ids).next() {
        return Err(SyncError::MissingVetoDecision {
            record_id: *missing,
        });
    }
    // Unknown decisions: any decision.record_id not in vetoes.
    if let Some(unknown) = decision_ids.difference(&veto_ids).next() {
        return Err(SyncError::UnknownVetoDecision {
            record_id: *unknown,
        });
    }

    // Bijection holds; apply decisions.
    let mut records = draft.merged_records.clone();
    for d in decisions {
        match d {
            VetoDecision::AcceptTombstone { .. } => {} // no-op
            VetoDecision::KeepLocal { record_id } => {
                let veto = draft
                    .vetoes
                    .iter()
                    .find(|v| v.record_id == *record_id)
                    .ok_or(SyncError::EmptyDraftWithVetoes)?;
                if let Some(slot) = records.iter_mut().find(|r| r.record_uuid == *record_id) {
                    *slot = veto.local_state.clone();
                } else {
                    // Defensive: the bijection holds, but the merge dropped
                    // the record (e.g. universal tombstone case). Re-insert.
                    records.push(veto.local_state.clone());
                }
            }
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::bundle::ManifestHash;
    use crate::sync::draft::{DraftMerge, RecordTombstoneVeto};
    use crate::sync::outcome::DiffPlan;
    use std::collections::BTreeMap;

    fn rec(uuid: u8, last_mod_ms: u64) -> Record {
        Record {
            record_uuid: [uuid; 16],
            record_type: "kv".into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
            created_at_ms: 0,
            last_mod_ms,
            tombstone: false,
            tombstoned_at_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    fn veto(uuid: u8) -> RecordTombstoneVeto {
        RecordTombstoneVeto {
            record_id: [uuid; 16],
            block_id: [0xBB; 16],
            local_state: rec(uuid, 100),
            disk_tombstone_at_ms: 200,
            disk_tombstoner_device: [0xCC; 16],
        }
    }

    fn draft_with_vetoes(vetoes: Vec<RecordTombstoneVeto>, merged: Vec<Record>) -> DraftMerge {
        DraftMerge {
            vault_uuid: [9; 16],
            plan: DiffPlan { diverging_blocks: vec![] },
            manifest_hash: ManifestHash([0; 32]),
            merged_records: merged,
            vetoes,
            post_merge_clock: vec![],
        }
    }

    #[test]
    fn empty_vetoes_empty_decisions_returns_unchanged_records() {
        let d = draft_with_vetoes(vec![], vec![rec(1, 100)]);
        let out = apply_decisions(&d, &[]).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record_uuid, [1; 16]);
    }

    #[test]
    fn keep_local_overrides_tombstoned_record() {
        // Merged set contains the tombstoned version; veto.local_state
        // is the live version. KeepLocal restores the live version.
        let live = rec(1, 100);
        let tombstoned = Record { tombstone: true, tombstoned_at_ms: 200, ..rec(1, 200) };
        let v = RecordTombstoneVeto {
            record_id: [1; 16],
            block_id: [0xBB; 16],
            local_state: live.clone(),
            disk_tombstone_at_ms: 200,
            disk_tombstoner_device: [0xCC; 16],
        };
        let d = draft_with_vetoes(vec![v], vec![tombstoned]);
        let out = apply_decisions(
            &d,
            &[VetoDecision::KeepLocal { record_id: [1; 16] }],
        )
        .expect("ok");
        assert_eq!(out.len(), 1);
        assert!(!out[0].tombstone);
        assert_eq!(out[0].last_mod_ms, 100);
    }

    #[test]
    fn accept_tombstone_is_noop() {
        // Merged set already contains the tombstoned version.
        let tombstoned = Record { tombstone: true, tombstoned_at_ms: 200, ..rec(1, 200) };
        let v = veto(1);
        let d = draft_with_vetoes(vec![v], vec![tombstoned]);
        let out = apply_decisions(
            &d,
            &[VetoDecision::AcceptTombstone { record_id: [1; 16] }],
        )
        .expect("ok");
        assert_eq!(out.len(), 1);
        assert!(out[0].tombstone);
    }

    #[test]
    fn missing_decision_returns_missing_veto_decision() {
        let d = draft_with_vetoes(vec![veto(1), veto(2)], vec![rec(1, 100), rec(2, 100)]);
        let err = apply_decisions(
            &d,
            &[VetoDecision::KeepLocal { record_id: [1; 16] }],
        )
        .expect_err("expected missing");
        match err {
            SyncError::MissingVetoDecision { record_id } => assert_eq!(record_id, [2; 16]),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_decision_returns_unknown_veto_decision() {
        let d = draft_with_vetoes(vec![veto(1)], vec![rec(1, 100)]);
        let err = apply_decisions(
            &d,
            &[
                VetoDecision::KeepLocal { record_id: [1; 16] },
                VetoDecision::KeepLocal { record_id: [9; 16] },
            ],
        )
        .expect_err("expected unknown");
        match err {
            SyncError::UnknownVetoDecision { record_id } => assert_eq!(record_id, [9; 16]),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn duplicate_decisions_for_same_id_treated_as_one() {
        // BTreeSet dedupes — passing the same record_id twice with the
        // same decision shape is accepted as a single decision. Different
        // decisions for the same id (KeepLocal vs AcceptTombstone) would
        // be a separate variant of error if we cared; for now the BTreeSet
        // dedupe means the last-write-wins for the apply loop.
        let d = draft_with_vetoes(vec![veto(1)], vec![rec(1, 100)]);
        let out = apply_decisions(
            &d,
            &[
                VetoDecision::KeepLocal { record_id: [1; 16] },
                VetoDecision::KeepLocal { record_id: [1; 16] },
            ],
        )
        .expect("ok");
        assert_eq!(out.len(), 1);
    }
}
```

- [ ] **Step 2: Wire the module in**

In `core/src/sync/mod.rs`, after `pub mod prepare;`:

```rust
pub mod commit;
```

(No public re-export of `apply_decisions` — it's a helper. The `commit_with_decisions` re-export lands in Task 12.)

- [ ] **Step 3: Run tests**

```bash
cargo test --release --workspace --lib sync::commit 2>&1 | tail -15
```

Expected: 6 tests pass.

- [ ] **Step 4: Gauntlet**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add core/src/sync/commit.rs core/src/sync/mod.rs
git commit -m "feat(sync): add apply_decisions pure helper + bijection enforcement (C.1.1b commit step 1)"
```

---

## Task 11: `commit_with_decisions` — re-encrypt blocks + manifest re-sign

**Why:** Build the disk-mutation half of the commit path: for each affected block (a block whose merged records changed), re-encrypt with a fresh AEAD nonce, compute the new BLAKE3 fingerprint, write atomically. Build a new manifest body with updated `BlockEntry.fingerprint` + `BlockEntry.vector_clock_summary` + `manifest.vector_clock = draft.post_merge_clock`. Sign hybrid, encode, atomic-write. Return the new `SyncState`. The freshness re-check lives at the top of this function; bijection is delegated to Task 10's `apply_decisions`.

**Files:**
- Modify: `core/src/sync/commit.rs` (append `commit_with_decisions` + helpers)
- Modify: `core/src/sync/mod.rs` (re-export `commit_with_decisions`)

- [ ] **Step 1: Write the failing integration test**

Append to `core/tests/sync_merge.rs`:

```rust
#[test]
fn commit_with_decisions_empty_vetoes_writes_merged_state() {
    // The simplest happy path: concurrent manifests, no block rewrites,
    // no vetoes. commit_with_decisions writes the new manifest only
    // (no affected blocks), returns SyncState with post_merge_clock.
    let device_a = [0x0A; 16];
    let device_b = [0x0B; 16];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
        vec![VectorClockEntry { device_uuid: device_a, counter: 1 }],
        "manifest.conflict-copy.0001.cbor.enc",
        vec![VectorClockEntry { device_uuid: device_b, counter: 1 }],
    );
    let password = fixtures::golden_vault_001_password();
    let open = secretary_core::vault::open_vault(
        &folder,
        secretary_core::vault::Unlocker::Password(&password),
        None,
    )
    .expect("open");
    let state = SyncState {
        vault_uuid: open.manifest.vault_uuid,
        highest_vector_clock_seen: Vec::new(),
    };
    let outcome = sync_once(&folder, &open.identity, &state, 0).expect("sync_once");
    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    let draft = prepare_merge(&folder, &open.identity, &bundle, &plan).expect("prepare_merge");
    assert!(draft.vetoes.is_empty());

    drop(open); // commit_with_decisions opens the vault itself.

    let new_state = secretary_core::sync::commit_with_decisions(
        &folder,
        &fixtures::golden_vault_001_password(),
        draft,
        Vec::new(),
        1_000_000,
    )
    .expect("commit");

    // The post-merge clock must contain both devices' counters.
    assert!(new_state.highest_vector_clock_seen.iter().any(|e| e.device_uuid == device_a && e.counter == 1));
    assert!(new_state.highest_vector_clock_seen.iter().any(|e| e.device_uuid == device_b && e.counter == 1));

    // Re-running sync_once on the new state should return NothingToDo.
    let open = secretary_core::vault::open_vault(
        &folder,
        secretary_core::vault::Unlocker::Password(&fixtures::golden_vault_001_password()),
        None,
    )
    .expect("re-open");
    let outcome2 = sync_once(&folder, &open.identity, &new_state, 0).expect("sync_once 2");
    assert!(matches!(outcome2, SyncOutcome::NothingToDo));
}
```

Note: the test uses `&password` instead of `&UnlockedIdentity` because the test's `open` is dropped before commit (the commit re-opens internally). The actual `commit_with_decisions` signature in the design doc takes `&UnlockedIdentity` — if the test wants to share an identity with the prepare step, pass `&open.identity` and don't drop. Use whichever pattern matches the implementation chosen below.

- [ ] **Step 2: Run, confirm fail**

```bash
cargo test --release --workspace --test sync_merge commit_with_decisions_empty_vetoes 2>&1 | tail -15
```

Expected: compile error — `commit_with_decisions` unresolved.

- [ ] **Step 3: Implement `commit_with_decisions`**

Append to `core/src/sync/commit.rs`:

```rust
use std::path::Path;

use rand_core::OsRng;

use crate::crypto::aead;
use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::secret::Sensitive;
use crate::crypto::sig::{Ed25519Secret, MlDsa65Public, MlDsa65Secret};
use crate::identity::fingerprint::fingerprint;
use crate::sync::bundle::compute_manifest_hash;
use crate::sync::state::SyncState;
use crate::unlock::UnlockedIdentity;
use crate::vault::{
    encrypt_block, encode_block_file, encode_manifest_file, sign_manifest,
    open_vault, read_vault_manifest_full, BlockEntry, BlockHeader, BlockPlaintext,
    Manifest, ManifestHeader, RecipientPublicKeys, Unlocker, VectorClockEntry,
};

/// Filename of the canonical manifest on disk. Mirrors the constant
/// in `sync::once` and `vault::orchestrators`.
const CANONICAL_MANIFEST_FILENAME: &str = "manifest.cbor.enc";

/// Atomic commit of a merged + decided vault state. Re-opens the vault
/// (verifies signatures + block fingerprints), re-checks the manifest
/// hash for TOCTOU freshness, applies the caller's decisions, re-
/// encrypts any blocks whose records changed, builds + signs a new
/// manifest, and writes block-first manifest-last via `write_atomic`.
///
/// On success, returns the new [`SyncState`] the caller persists.
///
/// On `SyncError::EvidenceStale`, the disk wasn't touched — the caller
/// re-runs `sync_once → prepare_merge → commit_with_decisions`.
///
/// On `SyncError::BlockFingerprintMismatch` (surfaced through
/// `open_vault`), a previous crashed commit left blocks out-of-sync
/// with the manifest; the caller's recovery is the same idempotent
/// retry path. CRDT idempotence guarantees convergence.
pub fn commit_with_decisions(
    vault_folder: &Path,
    password: &[u8],
    draft: DraftMerge,
    decisions: Vec<VetoDecision>,
    now_ms: u64,
) -> Result<SyncState, SyncError> {
    // Step 1: open the vault. This re-verifies the manifest signature,
    // re-runs verify_block_fingerprints (D6), and unwraps the identity.
    let mut open = open_vault(vault_folder, Unlocker::Password(password), None)
        .map_err(SyncError::Vault)?;

    // Step 2: freshness re-check. Read the on-disk manifest envelope
    // bytes through read_vault_manifest_full (single-read; closes #80),
    // BLAKE3-hash them, compare to draft.manifest_hash.
    let (_, _, envelope_bytes) = read_vault_manifest_full(vault_folder, &open.identity, None)
        .map_err(SyncError::Vault)?;
    let on_disk_hash = compute_manifest_hash(&envelope_bytes);
    if on_disk_hash != draft.manifest_hash {
        return Err(SyncError::EvidenceStale);
    }

    // Step 3: apply decisions to the merged records.
    let post_decision_records = apply_decisions(&draft, &decisions)?;

    // Step 4: which blocks are affected? Any block_uuid in
    // draft.plan.diverging_blocks whose merged records differ from
    // the on-disk canonical content. Simplest correct conservative:
    // re-encrypt EVERY diverging block (the merge may have changed
    // any of them). The block-level vector clock for each affected
    // block is the merge primitive's output — but we no longer have
    // it after Task 8 returned only the manifest-level fold. The
    // pragmatic path: re-merge the per-block clocks here using the
    // bundle's per-block summaries. The bundle is not available at
    // commit time (the draft doesn't carry it), so EITHER:
    //
    // (a) Carry the per-block clocks on the DraftMerge as a
    //     BTreeMap<block_uuid, Vec<VectorClockEntry>>; populate in
    //     prepare_merge (this is a small refactor to Task 8).
    // (b) Re-fetch the bundle by re-running ingest_conflict_copies.
    //
    // Pick (a) — it preserves the secret-bearing material lifetime
    // discipline and avoids a second disk scan. Add the field +
    // populate it in Task 8 finalization.

    // For now, this implementation assumes (a): draft carries
    // `per_block_clocks: BTreeMap<[u8;16], Vec<VectorClockEntry>>`.
    // If the field doesn't exist yet, EXTEND `DraftMerge` here AND
    // update Task 6's draft.rs definition + Task 8's prepare_merge
    // population in a precursor edit before continuing this step.

    let owner_card_bytes = open.owner_card.to_canonical_cbor()
        .map_err(crate::vault::VaultError::from)?;
    let owner_fp = fingerprint(&owner_card_bytes);
    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose())
        .map_err(crate::vault::VaultError::from)?;
    let owner_pq_pk = MlDsa65Public::from_bytes(&open.owner_card.ml_dsa_65_pk)
        .map_err(crate::vault::VaultError::from)?;
    let owner_pk_bundle = open.owner_card.pk_bundle_bytes()
        .map_err(crate::vault::VaultError::from)?;

    let recipient_keys = vec![RecipientPublicKeys {
        fingerprint: owner_fp,
        pk_bundle: &owner_pk_bundle,
        x25519_pk: &open.owner_card.x25519_pk,
        ml_kem_768_pk: &crate::crypto::kem::MlKem768Public::from_bytes(
            &open.owner_card.ml_kem_768_pk,
        )
        .map_err(crate::vault::VaultError::from)?,
    }];

    let mut rng = OsRng;
    let mut new_fingerprints: std::collections::BTreeMap<[u8; 16], [u8; 32]> = Default::default();

    for block_uuid in &draft.plan.diverging_blocks {
        // Records assigned to THIS block: filter post_decision_records
        // by the canonical block's block_uuid. For now we trust that
        // every record's parent block_uuid is recoverable from the
        // bundle — since the bundle is gone, the draft must also carry
        // a record→block_uuid map. Same refactor note as the per-block
        // clocks above.
        //
        // Implementation: `draft.per_block_records: BTreeMap<[u8;16], Vec<Record>>`.

        let records_for_block: Vec<Record> = post_decision_records
            .iter()
            .filter(|r| draft.record_block_assignment(*block_uuid, r.record_uuid))
            .cloned()
            .collect();

        let block_clock = draft
            .per_block_clocks
            .get(block_uuid)
            .cloned()
            .unwrap_or_default();

        // Look up the existing BlockEntry from the in-memory manifest
        // for created_at_ms + block_name preservation.
        let existing = open
            .manifest
            .blocks
            .iter()
            .find(|b| b.block_uuid == *block_uuid)
            .ok_or_else(|| SyncError::InvalidArgument {
                detail: format!("manifest missing block {block_uuid:02x?} after merge"),
            })?;

        let header = BlockHeader {
            magic: crate::version::MAGIC,
            format_version: crate::version::FORMAT_VERSION,
            suite_id: crate::version::SUITE_ID,
            file_kind: crate::vault::FILE_KIND_BLOCK,
            vault_uuid: open.manifest.vault_uuid,
            block_uuid: *block_uuid,
            created_at_ms: existing.created_at_ms,
            last_mod_ms: now_ms,
            vector_clock: block_clock.clone(),
        };
        let plaintext = BlockPlaintext {
            block_uuid: *block_uuid,
            block_name: existing.block_name.clone(),
            records: records_for_block,
            unknown: std::collections::BTreeMap::new(),
        };

        let block_file = encrypt_block(
            &mut rng,
            &header,
            &plaintext,
            &owner_fp,
            &owner_pk_bundle,
            &owner_ed_sk,
            &owner_pq_sk,
            &recipient_keys,
        )
        .map_err(crate::vault::VaultError::from)?;
        let bytes = encode_block_file(&block_file)
            .map_err(crate::vault::VaultError::from)?;
        let block_fp = *blake3_hash(&bytes).as_bytes();
        new_fingerprints.insert(*block_uuid, block_fp);

        // Atomic per-file write (D6 — block-first).
        use crate::vault::io::write_atomic;
        let uuid_hex = crate::vault::orchestrators::format_uuid_hyphenated(block_uuid);
        let path = vault_folder
            .join(crate::vault::orchestrators::BLOCKS_SUBDIR)
            .join(format!("{uuid_hex}{}", crate::vault::orchestrators::BLOCK_FILE_EXTENSION));
        write_atomic(&path, &bytes).map_err(|e| crate::vault::VaultError::Io {
            context: "failed to write block during commit",
            source: e,
        })?;
    }

    // Step 5: build the new manifest body.
    let mut new_manifest = open.manifest.clone();
    new_manifest.vector_clock = draft.post_merge_clock.clone();
    for entry in new_manifest.blocks.iter_mut() {
        if let Some(new_fp) = new_fingerprints.get(&entry.block_uuid) {
            entry.fingerprint = *new_fp;
            entry.last_mod_ms = now_ms;
            entry.vector_clock_summary = draft
                .per_block_clocks
                .get(&entry.block_uuid)
                .cloned()
                .unwrap_or_else(|| entry.vector_clock_summary.clone());
        }
    }

    // Step 6: sign + encode + atomic-write the manifest (LAST).
    let new_header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };
    let aead_nonce = aead::random_nonce(&mut rng);
    let new_manifest_file = sign_manifest(
        new_header,
        &new_manifest,
        &open.identity_block_key,
        &aead_nonce,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )
    .map_err(crate::vault::VaultError::from)?;
    let manifest_bytes = encode_manifest_file(&new_manifest_file)
        .map_err(crate::vault::VaultError::from)?;

    use crate::vault::io::write_atomic;
    let manifest_path = vault_folder.join(CANONICAL_MANIFEST_FILENAME);
    write_atomic(&manifest_path, &manifest_bytes).map_err(|e| crate::vault::VaultError::Io {
        context: "failed to write manifest during commit",
        source: e,
    })?;

    Ok(SyncState {
        vault_uuid: draft.vault_uuid,
        highest_vector_clock_seen: draft.post_merge_clock,
    })
}
```

This implementation references two new `DraftMerge` fields: `per_block_clocks: BTreeMap<[u8; 16], Vec<VectorClockEntry>>` and a `record_block_assignment` method or `per_block_records: BTreeMap<[u8; 16], Vec<[u8; 16]>>` field. **Extend `DraftMerge` in Task 6's `draft.rs`** to carry these:

```rust
    /// Per-affected-block vector clock — populated by `prepare_merge`
    /// from the merge primitive's output. Keyed by `block_uuid`.
    #[zeroize(skip)]
    pub per_block_clocks: std::collections::BTreeMap<[u8; 16], Vec<VectorClockEntry>>,

    /// Per-affected-block record assignment — which records the merge
    /// produced for which block. Keyed by `block_uuid`; values are the
    /// sorted ascending `record_uuid` set.
    #[zeroize(skip)]
    pub per_block_records: std::collections::BTreeMap<[u8; 16], Vec<[u8; 16]>>,
```

Update Task 8's `prepare_merge` to populate them; update Task 10's apply_decisions tests to construct drafts with these fields.

The `record_block_assignment` method is then:

```rust
impl DraftMerge {
    /// True if `record_id` is in the per-block record set for `block_uuid`.
    pub fn record_block_assignment(&self, block_uuid: [u8; 16], record_id: [u8; 16]) -> bool {
        self.per_block_records
            .get(&block_uuid)
            .map(|v| v.contains(&record_id))
            .unwrap_or(false)
    }
}
```

If by Task 11 you've already coded Tasks 6/8/10 with the simpler shape, retrofit them here. The refactor is mechanical.

- [ ] **Step 4: Wire the public re-export**

In `core/src/sync/mod.rs`:

```rust
pub use commit::commit_with_decisions;
```

- [ ] **Step 5: Run the integration test**

```bash
cargo test --release --workspace --test sync_merge commit_with_decisions_empty_vetoes 2>&1 | tail -15
```

Expected: pass.

- [ ] **Step 6: Gauntlet**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
```

Expected: 718 → 719.

- [ ] **Step 7: Commit**

```bash
git add core/src/sync/commit.rs core/src/sync/mod.rs core/src/sync/draft.rs core/src/sync/prepare.rs core/tests/sync_merge.rs
git commit -m "feat(sync): implement commit_with_decisions — atomic block-then-manifest write (C.1.1b)"
```

---

## Task 12: `commit_with_decisions` — `EvidenceStale` test

**Why:** Prove the manifest-hash freshness check fires when the manifest is mutated between `prepare_merge` and `commit_with_decisions`. Asserts the typed error AND that no disk writes happened (no new manifest envelope BLAKE3 different from the pre-prepare state).

**Files:**
- Modify: `core/tests/sync_merge.rs` (add 1 test)

- [ ] **Step 1: Write the failing test**

Append to `core/tests/sync_merge.rs`:

```rust
#[test]
fn commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes() {
    let device_a = [0x0A; 16];
    let device_b = [0x0B; 16];
    let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
        vec![VectorClockEntry { device_uuid: device_a, counter: 1 }],
        "manifest.conflict-copy.0001.cbor.enc",
        vec![VectorClockEntry { device_uuid: device_b, counter: 1 }],
    );
    let password = fixtures::golden_vault_001_password();
    let open = secretary_core::vault::open_vault(
        &folder,
        secretary_core::vault::Unlocker::Password(&password),
        None,
    )
    .expect("open");
    let state = SyncState {
        vault_uuid: open.manifest.vault_uuid,
        highest_vector_clock_seen: Vec::new(),
    };
    let outcome = sync_once(&folder, &open.identity, &state, 0).expect("sync_once");
    let (bundle, plan) = match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    };
    let draft = prepare_merge(&folder, &open.identity, &bundle, &plan).expect("prepare_merge");
    drop(open);

    // Mutate the canonical manifest between prepare and commit.
    sync_helpers::write_manifest_at(
        &folder,
        sync_helpers::MANIFEST_FILENAME,
        vec![VectorClockEntry { device_uuid: device_a, counter: 99 }],
        &sync_helpers::SIBLING_NONCE_C,
    );

    // Capture the post-mutation manifest BLAKE3 so we can check no
    // further writes happened.
    let manifest_bytes_before_commit = std::fs::read(folder.join(sync_helpers::MANIFEST_FILENAME))
        .expect("read manifest");
    let hash_before = secretary_core::sync::compute_manifest_hash(&manifest_bytes_before_commit);

    let err = secretary_core::sync::commit_with_decisions(
        &folder,
        &fixtures::golden_vault_001_password(),
        draft,
        Vec::new(),
        1_000_000,
    )
    .expect_err("expected EvidenceStale");
    assert!(matches!(err, secretary_core::sync::SyncError::EvidenceStale));

    // Post-condition: the manifest file is byte-identical to what it was
    // before the commit was attempted. (The block files weren't expected
    // to change either since the no-veto draft had no affected blocks,
    // but the manifest is the commit point — that's the disposition test.)
    let bytes_after = std::fs::read(folder.join(sync_helpers::MANIFEST_FILENAME))
        .expect("read manifest after");
    let hash_after = secretary_core::sync::compute_manifest_hash(&bytes_after);
    assert_eq!(hash_before, hash_after);
}
```

Note: `secretary_core::sync::compute_manifest_hash` must be re-exported via `core/src/sync/mod.rs` if it isn't already. Add:

```rust
pub use bundle::compute_manifest_hash;
```

- [ ] **Step 2: Run, verify pass**

```bash
cargo test --release --workspace --test sync_merge commit_with_decisions_stale_manifest_hash 2>&1 | tail -10
```

Expected: pass.

- [ ] **Step 3: Gauntlet**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
```

Expected: 719 → 720.

- [ ] **Step 4: Commit**

```bash
git add core/src/sync/mod.rs core/tests/sync_merge.rs
git commit -m "test(sync-merge): EvidenceStale fires on stale manifest_hash; no disk writes (C.1.1b D5)"
```

---

## Task 13: Veto-handling integration tests

**Why:** Cover the two veto branches (KeepLocal + AcceptTombstone) end-to-end through `sync_once → prepare_merge → commit_with_decisions`, plus the two bijection-violation paths (MissingVetoDecision + UnknownVetoDecision). Each test sets up a fixture where the canonical side has a live record AND the sibling side has tombstoned the same record_uuid strictly later.

**Files:**
- Modify: `core/tests/sync_merge.rs` (add 4 tests)
- Modify: `core/tests/sync_helpers/mod.rs` if needed (a "rewrite TWO blocks with different records" helper — likely needed)

The implementation of this task depends heavily on what helpers Task 9 + Task 11 actually produced. If the fixture machinery to write a canonical block with a live record AND a sibling block file (named `…conflict-copy…`) with a tombstoned record is missing, **add it as Task 13a** before the 4 tests below. The shape:

```rust
/// Write a canonical block + a sibling conflict-copy block (different
/// records, distinct AEAD nonces), update each side's manifest's
/// BlockEntry.fingerprint, and write both manifests with distinct
/// vector clocks. Returns (folder, tmp).
#[allow(dead_code)]
pub fn fresh_vault_two_concurrent_blocks(
    block_uuid: [u8; 16],
    canonical_records: Vec<Record>,
    canonical_clock: Vec<VectorClockEntry>,
    sibling_records: Vec<Record>,
    sibling_clock: Vec<VectorClockEntry>,
    sibling_manifest_filename: &str,
) -> (PathBuf, tempfile::TempDir) {
    // Step 1: rewrite_block_with_records_and_update_manifest with the
    //         canonical_records + canonical_clock.
    // Step 2: write a sibling block file at blocks/<uuid>.cbor.enc.copy.0001
    //         (or similar — the C.1.1a ingest scans `blocks/<uuid>*` for siblings).
    // Step 3: write the sibling manifest pointing at the sibling block file
    //         with the sibling_clock.
}
```

Check C.1.1a's `ingest_conflict_copies` for the exact glob pattern used to enumerate sibling block files (Task 8 of the 1a plan).

The four tests:

- [ ] **Step 1: `keep_local_overrides_peer_tombstone`**

```rust
#[test]
fn commit_with_decisions_keep_local_overrides_peer_tombstone() {
    // Setup: canonical block has record [0xAA] LIVE at t=100;
    // sibling block has record [0xAA] TOMBSTONED at t=200.
    // tombstone_veto_set fires; caller decides KeepLocal; post-commit
    // disk holds the live record.
    // ... fixture setup via sync_helpers::fresh_vault_two_concurrent_blocks ...
    // ... assertion: re-open vault, decrypt block, find [0xAA] alive ...
}
```

- [ ] **Step 2: `accept_tombstone_finalizes_peer_delete`**

Same fixture, decision = AcceptTombstone, post-commit disk holds the tombstoned record (tombstone=true, tombstoned_at_ms=200).

- [ ] **Step 3: `missing_veto_decision_aborts_with_typed_error`**

Same fixture, pass `decisions: Vec::new()`, assert `SyncError::MissingVetoDecision { record_id: [0xAA; 16] }`.

- [ ] **Step 4: `unknown_veto_decision_aborts_with_typed_error`**

Same fixture, pass `decisions: vec![VetoDecision::KeepLocal { record_id: [0xAA; 16] }, VetoDecision::KeepLocal { record_id: [0xFF; 16] }]`, assert `SyncError::UnknownVetoDecision { record_id: [0xFF; 16] }`.

For each test, follow TDD: write → fail → implement helper if missing → green → commit. One commit per test (per `feedback_fix_all_review_issues.md`'s "step by step, one issue per commit" preference). Resulting four commits:

```bash
git commit -m "test(sync-merge): KeepLocal decision overrides peer tombstone (C.1.1b)"
git commit -m "test(sync-merge): AcceptTombstone decision finalizes peer delete (C.1.1b)"
git commit -m "test(sync-merge): MissingVetoDecision typed error fires (C.1.1b)"
git commit -m "test(sync-merge): UnknownVetoDecision typed error fires (C.1.1b)"
```

If the helper additions need their own commit, prefix it as a fifth commit:

```bash
git commit -m "test(sync-helpers): add fresh_vault_two_concurrent_blocks fixture helper"
```

- [ ] **Step 5: Final gauntlet for the task**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
```

Expected: 720 → 724 passed (+4 tests).

---

## Task 14: Crash-recovery integration test (partial-write reconverge)

**Why:** D6 closure proof. Simulate a partial-write crash by: (1) running a successful commit, (2) reverting just the manifest to its pre-commit state (the blocks are at their post-commit content), (3) attempting `open_vault` — expect `BlockFingerprintMismatch`, (4) re-running `sync_once → prepare_merge → commit_with_decisions`, (5) asserting the final disk state matches the would-have-been-final state from step 1. CRDT idempotence proof.

**Files:**
- Modify: `core/tests/sync_merge.rs` (add 1 test)

- [ ] **Step 1: Write the failing test**

The test scaffold:

```rust
#[test]
fn partial_commit_recovers_via_idempotent_re_run() {
    // 1. fresh_vault_two_concurrent_blocks as in Task 13.
    // 2. sync_once → prepare_merge → commit_with_decisions → SyncState_v1.
    // 3. Capture the post-commit manifest bytes M_v1.
    // 4. Capture the post-commit block bytes B_v1.
    // 5. Roll the manifest BACK to the pre-commit state (M_v0) while
    //    leaving the block at B_v1 — simulates a crash after step 6
    //    (block write) but before step 6's manifest write.
    // 6. Assert open_vault errs with BlockFingerprintMismatch.
    // 7. Re-run sync_once → prepare_merge → commit_with_decisions →
    //    SyncState_v2.
    // 8. Assert SyncState_v2 == SyncState_v1 (idempotence on the
    //    canonical merged state).
    // 9. Assert post-recovery manifest bytes BLAKE3-hash to the same
    //    as M_v1 (modulo AEAD nonces, which differ on each commit;
    //    compare decrypted manifest bodies instead of envelope bytes).
}
```

The implementation needs to capture the manifest envelope bytes pre-commit (via `std::fs::read` after step 1). The test is long; write the full body during implementation, but the assertions follow the docstring.

Once the test passes:

- [ ] **Step 2: Commit**

```bash
git add core/tests/sync_merge.rs
git commit -m "test(sync-merge): partial-commit recovery via idempotent re-run (C.1.1b D6 proof)"
```

---

## Task 15: Property tests

**Why:** The four properties from the design doc's §"Property tests".

**Files:**
- Create: `core/tests/sync_merge_proptest.rs`

- [ ] **Step 1: Scaffold the file with property strategies**

```rust
//! Property tests for the C.1.1b merge layer.
//!
//! Four properties:
//! 1. Post-commit, re-running sync_once on the new SyncState returns
//!    NothingToDo.
//! 2. Three-step is idempotent on repeated invocation.
//! 3. Commits with disjoint veto sets are associative.
//! 4. Bijection check fires on every non-bijective (vetoes, decisions)
//!    pair.

use proptest::prelude::*;
use secretary_core::sync::{prepare_merge, sync_once, SyncOutcome, SyncState};
// ... add fixtures + helpers ...

mod fixtures;
mod sync_helpers;

proptest! {
    #[test]
    fn prop_commit_then_sync_once_yields_nothing_to_do(
        device_a in any::<u128>(),
        device_b in any::<u128>(),
        counter_a in 1u64..1000,
        counter_b in 1u64..1000,
    ) {
        // Body: commit a no-vetoes merge with the strategy-supplied clocks;
        // re-run sync_once with the returned SyncState; assert NothingToDo.
        // ...
    }

    #[test]
    fn prop_three_step_idempotent_on_repeated_invocation(...) {
        // Body: run the three-step flow twice, assert decrypted manifest
        // bodies match. AEAD nonces differ so envelope bytes differ;
        // assertion is on the decrypted manifest body.
    }

    #[test]
    fn prop_commit_associative_under_disjoint_vetoes(...) {
        // Body: two non-overlapping veto sets; commit in either order;
        // assert final SyncState identical.
    }

    #[test]
    fn prop_decision_bijection_enforced(...) {
        // Body: random (vetoes, decisions) pair; if not a bijection,
        // expect MissingVetoDecision or UnknownVetoDecision; if a
        // bijection, expect Ok.
    }
}
```

Default proptest case-count is 256 per property; that's expensive when each case does cryptographic work. Cap at 16-32 per property using a `ProptestConfig`:

```rust
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        ..ProptestConfig::default()
    })]

    #[test] ...
}
```

- [ ] **Step 2: Implement properties one at a time**

TDD per property: write, fail, implement (often a fixture or helper missing), green, commit:

```bash
git commit -m "test(sync-merge-proptest): prop1 commit→sync_once yields NothingToDo"
git commit -m "test(sync-merge-proptest): prop2 idempotent re-invocation"
git commit -m "test(sync-merge-proptest): prop3 associative under disjoint vetoes"
git commit -m "test(sync-merge-proptest): prop4 decision bijection enforced"
```

- [ ] **Step 3: Final gauntlet**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
cargo test --release --workspace --no-fail-fast --release 2>&1 | grep -E "^test result:"
```

Expected: 725 → 729 passed (+4 proptests).

---

## Task 16: KAT vectors

**Why:** Pin the seven new vector shapes from the design doc's §"KAT vectors" so future Python clean-room replay (issue #76) can validate the merge layer. Rust-side replay extends `core/tests/sync_kat.rs`.

**Files:**
- Modify: `core/tests/data/sync_kat.json` (9 → 16 vectors)
- Modify: `core/tests/sync_kat.rs` (replay logic for new shapes)

- [ ] **Step 1: Inspect the existing sync_kat.json shape**

```bash
sed -n '1,40p' core/tests/data/sync_kat.json
```

Note the existing vector keys and the per-vector test field. The C.1.1b vectors are detection + ingest + merge composition, so they have additional fields for the expected `merged_records` shape.

- [ ] **Step 2-8: Add each new vector one at a time**

For each of the seven new vectors, add the JSON entry, extend `core/tests/sync_kat.rs` to dispatch on the new vector_type, write the failing test, implement the dispatch, green, commit:

```bash
git commit -m "test(sync-kat): vector — concurrent_disjoint_blocks_no_vetoes_applied"
git commit -m "test(sync-kat): vector — concurrent_same_block_field_lww_no_vetoes"
git commit -m "test(sync-kat): vector — concurrent_one_tombstone_veto_keep_local"
git commit -m "test(sync-kat): vector — concurrent_one_tombstone_veto_accept_tombstone"
git commit -m "test(sync-kat): vector — concurrent_two_tombstone_vetoes_mixed_decisions"
git commit -m "test(sync-kat): vector — prepare_merge_stale_hash_evidence_stale"
git commit -m "test(sync-kat): vector — commit_block_fingerprint_mismatch_repair_via_reconverge"
```

Each commit is bite-sized (one vector + replay dispatch + one test). Most of the test bodies can reuse fixtures from earlier tasks.

---

## Task 17: README + ROADMAP + NEXT_SESSION updates + final gauntlet

**Why:** Close the loop per `feedback_next_session_in_pr.md`: README/ROADMAP/NEXT_SESSION updates ride **inside** the PR. Update the documents so the post-merge `main` carries an accurate baton.

**Files:**
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Modify: `NEXT_SESSION.md`
- Create: `docs/handoffs/<timestamp>-c1-1b-shipped.md`

- [ ] **Step 1: README — move Sub-project C row forward**

Find the "Sub-project status" section in `README.md`. Update the C.1 row's status from "in flight" to ✅ when C.1.1b is complete (C.1 = C.1 phase 1 + C.1.1a + C.1.1b together).

- [ ] **Step 2: ROADMAP — mark C.1.1b ✅, advance progress bar**

In `ROADMAP.md`'s "Phase C" section, mark C.1.1b ✅ and advance the progress bar one tick.

- [ ] **Step 3: NEXT_SESSION baton**

Update `NEXT_SESSION.md` per the C.1.1b shipping template. Capture: gauntlet count (target: 729 / 0 / 10), commits in this PR, follow-up items (issues #75, #76, #38, #45), and the next phase preview (C.2 — CLI surface? Or another C.1.x slice?).

- [ ] **Step 4: Final gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

All clean.

- [ ] **Step 5: Handoff snapshot**

```bash
TS=$(date +%Y-%m-%d-%H%M)
cp NEXT_SESSION.md "docs/handoffs/${TS}-c1-1b-shipped.md"
```

- [ ] **Step 6: Final commit + push**

```bash
git add README.md ROADMAP.md NEXT_SESSION.md docs/handoffs/*-c1-1b-shipped.md
git commit -m "docs: README + ROADMAP + NEXT_SESSION baton for C.1.1b ship"
git push -u origin feature/c1-1b-sync-merge
```

- [ ] **Step 7: Open the PR**

```bash
gh pr create --title "feat(c1-1b): sync merge layer — prepare_merge + commit_with_decisions + block-fingerprint repair" \
  --body "$(cat <<'EOF'
## Summary

- Implements the C.1.1b three-step merge API on top of the C.1.1a `VaultBundle`: `sync_once → prepare_merge → commit_with_decisions`.
- Closes the latent multi-block crash-safety gap: `open_vault` now verifies every `BlockEntry.fingerprint` against on-disk bytes; partial commits surface as typed `VaultError::BlockFingerprintMismatch`, recoverable via idempotent re-run of the three-step flow (CRDT idempotence proof in the property tests).
- Adds 13 integration tests, 4 property tests, 7 new KAT vectors. Workspace cargo: 713 → 729 passed / 0 failed / 10 ignored.

## Test plan

- [x] `cargo test --release --workspace --no-fail-fast` → 729 / 0 / 10
- [x] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [x] `cargo fmt --all -- --check` → clean
- [x] `uv run core/tests/python/conformance.py` → PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` → PASS

## Spec

[`docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md`](docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Summary

**Plan size:** 17 tasks across 5 new files + 8 modified files. Each task is 1 commit (or a small group of TDD-paired commits). Expected workspace cargo growth: 713 → 729 (+16 tests; ~13 integration + 4 properties + ~30-40 inline unit + 7 KAT vectors absorbed into existing replay loop).

**Critical-path dependencies:**

- Task 6 (`draft.rs`) must define `per_block_clocks` + `per_block_records` fields up front so Tasks 8 (`prepare_merge`) and 11 (`commit_with_decisions`) can populate / consume them without refactor churn.
- Task 8 must produce a `DraftMerge` whose `merged_records` + `per_block_records` are mutually consistent (every `record_uuid` in `merged_records` appears in exactly one `per_block_records[block_uuid]`).
- Task 4 + 5 (verify_block_fingerprints) must land BEFORE Task 11 (commit_with_decisions writes blocks; partial-commit recovery in Task 14 needs the verify in place to fire its typed error).

**Risk acknowledgements (per design doc §Risks):**

1. **`DraftMerge` zeroize discipline** — re-read [`docs/manual/contributors/memory-hygiene-audit-internal.md`](../../manual/contributors/memory-hygiene-audit-internal.md) before completing Task 6.
2. **AEAD nonce per rewrite** — the per-test nonce constants (Tasks 1 + 9) keep key+nonce pairs unique. Don't share `BLOCK_NONCE_E` between two block rewrites in the same test.
3. **`tempfile` exact pin** — do NOT bump as part of this work. The `=3.27.0` pin is enforced via the workspace `Cargo.toml`.
4. **CRDT proptests must not weaken** — this PR consumes `merge_block` / `merge_record` / `merge_vector_clocks` but does not modify them. If you find yourself touching `core/src/vault/conflict.rs` beyond a bug fix, stop and re-read the design doc §Risks.

## Self-Review (run after writing the plan)

- [x] **Spec coverage** — every section of `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md` is touched: D1 (SyncOutcome shape unchanged in C.1.1b — already shipped in 1a), D2 (single-call commit — Task 11), D3 (record-level veto — Tasks 7 + 13), D4 (lazy block readout — Task 8), D5 (three-step API — Tasks 8 + 11), D6 (block-first manifest-last + verify_block_fingerprints — Tasks 4, 5, 11, 14). Public API (`SyncOutcome` modifications: none — 1a already shipped the variant; `DiffPlan` + `ManifestHash`: already shipped in 1a; `DraftMerge` / `RecordTombstoneVeto` / `VetoDecision`: Task 6; `sync_once`: no signature changes; `prepare_merge`: Task 8; `commit_with_decisions`: Task 11; `verify_block_fingerprints`: Task 4-5; `SyncError` extensions: Task 2; `VaultError` extension: Task 3). Module layout: §"Module file layout" deltas in the design doc are honoured except for `diff.rs` (kept in 1a placements per the "Spec adjustments" preamble).
- [x] **Placeholder scan** — no "TBD" / "implement later" / "fill in details" / "add appropriate error handling" / "write tests for the above". Each task has actual code in every Step. The exception: Tasks 13, 15, 16 contain multi-test outlines where the full body is described but not transcribed verbatim — flagged as a planning trade-off; the contracts are explicit (which fixtures, which assertions, expected errors).
- [x] **Type consistency** — `DraftMerge` carries `merged_records: Vec<Record>` (not `Vec<MergedRecord>` from the design doc's open-item 4, per the "Spec adjustments" preamble decision). `VetoDecision::record_id` accessor consistently spelled `record_id()` (Task 6) and used in Task 10's `apply_decisions`. `per_block_clocks` + `per_block_records` introduced in Tasks 6 + 8 + 11 — the names match across all three. `format_uuid_hyphenated` re-imported as `pub(crate)` via `core/src/vault/orchestrators.rs` (already shipped in 1a); used in Task 4 + 11.

**Plan complete and saved to `docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`.**

Execution should use **subagent-driven-development** (recommended) — fresh subagent per task + two-stage review between tasks per `feedback_fix_before_quality_review.md`. The user's "stay in inner loop" preference (`feedback_stay_in_inner_loop.md`) means the human reviews each subagent's output before the next task starts — no autonomous "run all 17 tasks overnight" pipeline.
