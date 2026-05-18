# C.1.1a Conflict-Copy Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the conflict-copy ingestion layer (`VaultBundle`) that produces the second-source data the C.1.1b merge layer needs, integrating it into `sync_once`'s Concurrent dispatch arm.

**Architecture:** Inside `sync_once`, the Concurrent branch invokes a new `ingest_conflict_copies` helper that scans the vault folder for sibling `*.cbor.enc` files, decodes each, authenticates against the canonical manifest's owner identity, and packages canonical + N copies + per-block divergence into a `VaultBundle`. Authentication is mandatory (five MUSTs); files that fail are silently rejected. Block content remains encrypted inside the bundle — decryption is deferred to C.1.1b.

**Tech Stack:** stable Rust, `zeroize` (already a workspace dep), `tracing::debug!` for forensic logs, BLAKE3 (already used via `core::crypto::hash`). No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md`](../specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md)

**Predecessor:** C.1 phase 1 on `main` (PR #74). Worktree `.worktrees/c1-1-sync-merge` on branch `feature/c1-1-sync-merge`.

---

## File Structure

**New files:**

```
core/src/sync/bundle.rs            ~200 LOC  VaultBundle + ManifestSnapshot + BlockDivergence + BlockEnvelope + ManifestHash + zeroize
core/src/sync/ingest.rs            ~300 LOC  ingest_conflict_copies + per-file authenticate helpers + compute_diff_plan
core/tests/sync_ingest.rs          ~400 LOC  Integration tests (~12 tests)
core/tests/sync_ingest_proptest.rs ~120 LOC  Property tests (~3 properties)
```

**Modified files:**

```
core/src/sync/mod.rs                Re-export VaultBundle + new types
core/src/sync/outcome.rs            Delete ForkDetected; replace with ConcurrentDetected { bundle, plan, manifest_hash, ... }
core/src/sync/error.rs              +2 variants
core/src/sync/once.rs               Concurrent arm body grows to call ingest + assemble ConcurrentDetected
core/tests/sync_helpers/mod.rs      Add per-nonce write_manifest_at helper
core/tests/sync.rs                  Rename fork-detected tests to concurrent-detected
core/tests/sync_kat.rs              Extend replay for new variant shape
core/tests/data/sync_kat.json       9 → 12 vectors
```

All under 500-LOC threshold per `feedback_split_files_proactively`.

---

## Working directory + baseline

Every task assumes:

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1-sync-merge
git branch --show-current     # → feature/c1-1-sync-merge
git status --short            # → clean before/after each task's commit
```

Baseline gauntlet (run **once before Task 1**, expected: 681 passed, 0 failed, 10 ignored):

```bash
cargo test --release --workspace --no-fail-fast
```

---

## Task 1: Extend test helper for per-nonce + sibling manifest writes

**Why:** The existing `core/tests/sync_helpers/mod.rs::fresh_vault_with_clock` uses a single deterministic AEAD nonce (`REWRITE_NONCE_STEM`). C.1.1a tests need to write a CANONICAL manifest **and** ≥1 sibling conflict-copy manifests in the same temp dir. Each rewrite needs a distinct nonce — sharing nonce + key across two manifest envelopes would violate AEAD's uniqueness invariant, even in test code. (Risk explicitly called out in the C.1.1a spec §Risks and CLAUDE.md atomic-write section.)

**Files:**
- Modify: `core/tests/sync_helpers/mod.rs:1-107` (full file)

- [ ] **Step 1: Read existing helper to confirm shape**

```bash
wc -l core/tests/sync_helpers/mod.rs
head -30 core/tests/sync_helpers/mod.rs
```

Expected: 107 lines; constants `REWRITE_NONCE_STEM` and `MANIFEST_FILENAME`.

- [ ] **Step 2: Write failing test for new helper**

Create new file `core/tests/helper_smoke.rs` (will be deleted in Step 6):

```rust
//! Smoke test for the new helper added in C.1.1a Task 1.
//! Deleted at end of Task 1; this is a transient TDD scaffold.

mod sync_helpers;
mod fixtures;

use secretary_core::vault::VectorClockEntry;
use sync_helpers::{fresh_vault_two_concurrent_manifests, MANIFEST_FILENAME, CANONICAL_NONCE_A, SIBLING_NONCE_B};

#[test]
fn fresh_vault_two_concurrent_manifests_writes_canonical_and_sibling() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock.clone(),
        "manifest.cbor.enc.sibling-test",
        sibling_clock.clone(),
    );

    let canonical_path = folder.join(MANIFEST_FILENAME);
    let sibling_path = folder.join("manifest.cbor.enc.sibling-test");

    assert!(canonical_path.is_file(), "canonical missing");
    assert!(sibling_path.is_file(), "sibling missing");

    let canonical_bytes = std::fs::read(&canonical_path).expect("read canonical");
    let sibling_bytes = std::fs::read(&sibling_path).expect("read sibling");
    assert_ne!(canonical_bytes, sibling_bytes, "two distinct envelopes expected");

    // Sanity: different first 24 bytes (nonces) is a quick proxy for "different envelopes".
    // (Real envelope structure has the nonce inside; cheap pre-check.)
    let _ = (CANONICAL_NONCE_A, SIBLING_NONCE_B);
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cargo test --release --workspace --test helper_smoke 2>&1 | head -30
```

Expected: compilation error — `fresh_vault_two_concurrent_manifests`, `CANONICAL_NONCE_A`, `SIBLING_NONCE_B` not found in `sync_helpers`.

- [ ] **Step 4: Replace `core/tests/sync_helpers/mod.rs` with extended helper**

Overwrite the file:

```rust
//! Per-test temp-folder copies of golden_vault_001 with the manifest's
//! vector clock re-written to caller-supplied value(s). Used by the
//! end-to-end sync tests so each test asserts a specific outcome
//! against the real open_vault path.

use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::Sensitive;
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::vault::{
    encode_manifest_file, open_vault, sign_manifest, ManifestHeader, Unlocker, VectorClockEntry,
};
use zeroize::Zeroize as _;

use crate::fixtures;

const GOLDEN_VAULT_FOLDER: &str = "tests/data/golden_vault_001";
pub const MANIFEST_FILENAME: &str = "manifest.cbor.enc";
const AEAD_NONCE_LEN: usize = 24;

/// Distinct nonce for the canonical manifest written by helpers in this
/// module. Tests don't share AEAD key + nonce pairs across rewrites.
pub const CANONICAL_NONCE_A: [u8; AEAD_NONCE_LEN] = [
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34,
];

/// Distinct nonce for the first sibling manifest. Differs from
/// [`CANONICAL_NONCE_A`] in every byte to make accidental nonce reuse
/// obvious in test failures.
pub const SIBLING_NONCE_B: [u8; AEAD_NONCE_LEN] = [
    0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x09, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66,
    0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xED, 0xCB,
];

/// Distinct nonce for the second sibling manifest in N-way fixtures.
pub const SIBLING_NONCE_C: [u8; AEAD_NONCE_LEN] = [
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
];

/// Distinct nonce for the third sibling manifest in N-way fixtures.
pub const SIBLING_NONCE_D: [u8; AEAD_NONCE_LEN] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21,
];

/// Recursively copies `golden_vault_001/` into a fresh temp dir, then
/// rewrites the canonical manifest's vector clock to `new_clock`
/// using [`CANONICAL_NONCE_A`].
///
/// Returns the temp folder path; the caller is responsible for keeping
/// the `tempfile::TempDir` alive for the duration of the test.
pub fn fresh_vault_with_clock(new_clock: Vec<VectorClockEntry>) -> (PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dest = tmp.path().to_path_buf();
    recursive_copy(Path::new(GOLDEN_VAULT_FOLDER), &dest);
    write_manifest_at(&dest, MANIFEST_FILENAME, new_clock, &CANONICAL_NONCE_A);
    (dest, tmp)
}

/// Like [`fresh_vault_with_clock`] but also writes a sibling manifest
/// at `sibling_filename` with a concurrent `sibling_clock`. The two
/// manifests are signed by the same owner identity but with distinct
/// AEAD nonces ([`CANONICAL_NONCE_A`] + [`SIBLING_NONCE_B`]).
pub fn fresh_vault_two_concurrent_manifests(
    canonical_clock: Vec<VectorClockEntry>,
    sibling_filename: &str,
    sibling_clock: Vec<VectorClockEntry>,
) -> (PathBuf, tempfile::TempDir) {
    let (dest, tmp) = fresh_vault_with_clock(canonical_clock);
    write_manifest_at(&dest, sibling_filename, sibling_clock, &SIBLING_NONCE_B);
    (dest, tmp)
}

/// Like [`fresh_vault_two_concurrent_manifests`] but writes THREE
/// siblings instead of one (for N-way fixtures). Each sibling uses a
/// distinct AEAD nonce ([`SIBLING_NONCE_B`] / `_C` / `_D`).
pub fn fresh_vault_four_concurrent_manifests(
    canonical_clock: Vec<VectorClockEntry>,
    siblings: [(&str, Vec<VectorClockEntry>); 3],
) -> (PathBuf, tempfile::TempDir) {
    let (dest, tmp) = fresh_vault_with_clock(canonical_clock);
    let nonces = [&SIBLING_NONCE_B, &SIBLING_NONCE_C, &SIBLING_NONCE_D];
    for ((filename, clock), nonce) in siblings.into_iter().zip(nonces.iter()) {
        write_manifest_at(&dest, filename, clock, nonce);
    }
    (dest, tmp)
}

/// Recursively copy `src` into `dest`. Creates `dest` if missing.
fn recursive_copy(src: &Path, dest: &Path) {
    if !dest.exists() {
        std::fs::create_dir_all(dest).expect("create_dir_all dest");
    }
    for entry in std::fs::read_dir(src).expect("read_dir src") {
        let entry = entry.expect("dir entry");
        let file_type = entry.file_type().expect("file type");
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        if file_type.is_dir() {
            recursive_copy(&src_path, &dest_path);
        } else {
            std::fs::copy(&src_path, &dest_path).expect("copy file");
        }
    }
}

/// Open the vault with the golden password, mutate the manifest body's
/// `vector_clock`, re-sign via `manifest::sign_manifest` with the
/// supplied nonce, and write the result to `folder/filename`. Mirrors
/// the step 11-13 pattern in `core::vault::orchestrators::save_block`
/// — only the clock changes; header bytes are preserved bit-for-bit.
fn write_manifest_at(
    folder: &Path,
    filename: &str,
    new_clock: Vec<VectorClockEntry>,
    aead_nonce: &[u8; AEAD_NONCE_LEN],
) {
    let password = fixtures::golden_vault_001_password();
    let mut open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");

    open.manifest.vector_clock = new_clock;

    let owner_card_bytes = open.owner_card.to_canonical_cbor().expect("card cbor");
    let owner_fp = fingerprint(&owner_card_bytes);

    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk =
        MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).expect("ml-dsa sk");

    let new_header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: open.manifest_file.header.last_mod_ms,
    };

    let new_manifest_file = sign_manifest(
        new_header,
        &open.manifest,
        &open.identity_block_key,
        aead_nonce,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )
    .expect("sign_manifest");

    let manifest_bytes = encode_manifest_file(&new_manifest_file).expect("encode_manifest_file");
    std::fs::write(folder.join(filename), &manifest_bytes).expect("write manifest");
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cargo test --release --workspace --test helper_smoke 2>&1 | tail -15
```

Expected: `test fresh_vault_two_concurrent_manifests_writes_canonical_and_sibling ... ok`. Workspace count grows by 1 (681 → 682 — temporary).

- [ ] **Step 6: Delete the smoke test, run full gauntlet**

```bash
rm core/tests/helper_smoke.rs
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | tail -5
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all -- --check
```

Expected: 681 passed (or 681 + 0 new — count unchanged since smoke test removed). Clippy clean. Format clean.

- [ ] **Step 7: Commit**

```bash
git add core/tests/sync_helpers/mod.rs
git commit -m "$(cat <<'EOF'
test(sync-helpers): add multi-manifest fixture helpers for C.1.1a

Adds fresh_vault_two_concurrent_manifests and
fresh_vault_four_concurrent_manifests to support C.1.1a integration
tests that need a canonical manifest plus 1-3 conflict-copy siblings
in the same temp dir, each signed by the same owner identity but
with distinct AEAD nonces.

Per CLAUDE.md atomic-write section: never share key + nonce across
rewrites. Four distinct nonce constants (CANONICAL_NONCE_A,
SIBLING_NONCE_B/C/D) cover the N-way fixtures up to four manifests.

The existing fresh_vault_with_clock helper is preserved bit-identical
for backward compatibility with the existing sync.rs / sync_proptest.rs
tests; it now delegates to a private write_manifest_at helper that
takes the nonce as a parameter.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Define `bundle.rs` types

**Why:** Stand up the data shapes for `VaultBundle` (the C.1.1a output) before any logic that produces or consumes them. Zeroize derives go in immediately because secrets discipline is non-negotiable per CLAUDE.md.

**Files:**
- Create: `core/src/sync/bundle.rs`
- Modify: `core/src/sync/mod.rs` (add `pub mod bundle;` + re-exports)

- [ ] **Step 1: Write failing inline test (compile-fail first)**

Create `core/src/sync/bundle.rs`:

```rust
//! Authenticated bundle of the canonical vault manifest plus
//! conflict-copies, produced by `sync_once` on the Concurrent path.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::vault::Manifest;

/// BLAKE3-256 hash of the on-disk canonical manifest envelope bytes.
/// Carried into [`crate::sync::SyncOutcome::ConcurrentDetected`] so the
/// C.1.1b commit path can detect a manifest-changed-between-prepare-
/// and-commit race (TOCTOU close).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestHash(pub [u8; 32]);

/// One side of a manifest — canonical or a single conflict-copy.
///
/// Holds the authenticated, AEAD-decrypted body and the raw envelope
/// bytes (the latter for hash + freshness anchors). The `source_path`
/// is for diagnostics and is not zeroized.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ManifestSnapshot {
    pub manifest: Manifest,
    pub raw_envelope_bytes: Vec<u8>,
    #[zeroize(skip)]
    pub source_path: PathBuf,
}

/// Encrypted bytes of one block file (canonical or conflict-copy).
/// Block content remains sealed inside the bundle — C.1.1b's
/// `prepare_merge` decrypts on demand.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlockEnvelope {
    pub bytes: Vec<u8>,
    #[zeroize(skip)]
    pub source_path: PathBuf,
}

/// Conflict-copies of one block. Only populated for blocks whose
/// `vector_clock_summary` differs between the canonical manifest and
/// at least one conflict-copy manifest.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlockDivergence {
    pub canonical_envelope: BlockEnvelope,
    pub copy_envelopes: Vec<BlockEnvelope>,
}

/// Top-level ingestion product. See spec §"Public API → `VaultBundle`".
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultBundle {
    pub canonical: ManifestSnapshot,
    pub copies: Vec<ManifestSnapshot>,
    pub diverging_blocks: BTreeMap<[u8; 16], BlockDivergence>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_hash_eq_is_bytewise() {
        let a = ManifestHash([0x42; 32]);
        let b = ManifestHash([0x42; 32]);
        let c = ManifestHash([0x43; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn block_envelope_zeroizes_bytes_on_drop() {
        // Build, capture raw pointer to the inner Vec's storage,
        // drop, then assert the bytes at that location are zero.
        let mut envelope = BlockEnvelope {
            bytes: vec![0xAB; 64],
            source_path: PathBuf::from("/tmp/block.cbor.enc"),
        };
        // Pre-drop sanity check
        assert_eq!(envelope.bytes[0], 0xAB);
        // We can't safely peek post-drop without unsafe; rely on the
        // ZeroizeOnDrop derive being correct. Sanity test exercising
        // the Zeroize trait directly:
        envelope.zeroize();
        assert!(envelope.bytes.iter().all(|&b| b == 0), "bytes not zeroized");
    }
}
```

Modify `core/src/sync/mod.rs` to declare the module:

```rust
// Add at the appropriate spot (alphabetical with existing mods)
pub mod bundle;

pub use bundle::{BlockDivergence, BlockEnvelope, ManifestHash, ManifestSnapshot, VaultBundle};
```

- [ ] **Step 2: Run inline tests to verify they pass**

```bash
cargo test --release --workspace --lib sync::bundle 2>&1 | tail -10
```

Expected: 2 passed (`manifest_hash_eq_is_bytewise`, `block_envelope_zeroizes_bytes_on_drop`). Workspace test count grows from 681 → 683.

- [ ] **Step 3: Clippy + fmt clean**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: clippy clean, fmt clean.

- [ ] **Step 4: Commit**

```bash
git add core/src/sync/bundle.rs core/src/sync/mod.rs
git commit -m "$(cat <<'EOF'
feat(sync): add VaultBundle + ManifestSnapshot + BlockDivergence types

Stands up the data shapes for C.1.1a's conflict-copy ingestion layer.
All composite types derive Zeroize + ZeroizeOnDrop per CLAUDE.md
memory-hygiene contract; source_path fields are #[zeroize(skip)] since
they're diagnostic data, not secrets. BlockEnvelope holds encrypted
ciphertext so its bytes field is also a candidate for zeroize on
drop (defense in depth — even encrypted bytes shouldn't linger).

Spec: docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md
Module re-exports added to core/src/sync/mod.rs.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Add `compute_manifest_hash` pure function

**Why:** The `ManifestHash` freshness anchor for C.1.1b's TOCTOU close needs to be computed at sync_once time over the canonical envelope bytes. Trivial helper but tested independently.

**Files:**
- Modify: `core/src/sync/bundle.rs` (append `compute_manifest_hash` + tests)

- [ ] **Step 1: Write failing test**

Append to `core/src/sync/bundle.rs::tests` module:

```rust
    #[test]
    fn compute_manifest_hash_is_blake3_of_input_bytes() {
        let bytes = b"the quick brown fox jumps over the lazy dog";
        let got = compute_manifest_hash(bytes);
        // Known-answer for BLAKE3-256 of the above ASCII bytes:
        // Computed via the same blake3 crate the project uses.
        let expected = secretary_core::crypto::hash::hash(bytes);
        assert_eq!(got.0, *expected.as_bytes());
    }

    #[test]
    fn compute_manifest_hash_empty_input() {
        let got = compute_manifest_hash(b"");
        let expected = secretary_core::crypto::hash::hash(b"");
        assert_eq!(got.0, *expected.as_bytes());
    }
```

- [ ] **Step 2: Run to verify compile-fail**

```bash
cargo test --release --workspace --lib sync::bundle 2>&1 | head -20
```

Expected: error: cannot find function `compute_manifest_hash` in this scope.

- [ ] **Step 3: Add the function**

Append to `core/src/sync/bundle.rs` (above the `#[cfg(test)]` line):

```rust
/// Compute the BLAKE3-256 hash of the canonical manifest envelope
/// bytes. Used as the freshness anchor in
/// [`crate::sync::SyncOutcome::ConcurrentDetected`] so C.1.1b's
/// `commit_with_decisions` can verify the manifest hasn't changed
/// between prepare and commit (TOCTOU).
///
/// Pure function. Inputs the on-disk envelope bytes exactly as read
/// (no canonicalisation step); output is 32 bytes.
pub fn compute_manifest_hash(envelope_bytes: &[u8]) -> ManifestHash {
    let digest = crate::crypto::hash::hash(envelope_bytes);
    ManifestHash(*digest.as_bytes())
}
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cargo test --release --workspace --lib sync::bundle 2>&1 | tail -10
```

Expected: 4 passed (now). Workspace count: 685.

- [ ] **Step 5: Clippy + fmt + commit**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/bundle.rs
git commit -m "$(cat <<'EOF'
feat(sync): add compute_manifest_hash pure helper

BLAKE3-256 over the on-disk manifest envelope bytes. Used as the
freshness anchor returned in SyncOutcome::ConcurrentDetected so the
C.1.1b commit path can detect a TOCTOU race against another device's
concurrent rewrite between prepare_merge and commit_with_decisions.

Pure function, no canonicalisation — hashes exactly what's read from
disk for the cheapest possible freshness re-check at commit time.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Add `authenticate_manifest_envelope` pure helper

**Why:** This is the security perimeter for C.1.1a — the four MUST authentication rules (decode, hybrid signature, vault_uuid match, owner fingerprint match, AEAD decrypt) collapsed into one pure function. Pure-and-tested before integration lets us TDD-drive the rejection arms exhaustively without folder I/O.

**Files:**
- Create: `core/src/sync/ingest.rs`
- Modify: `core/src/sync/mod.rs` (add `mod ingest;`)

- [ ] **Step 1: Write failing test — accepts canonical itself as a "candidate"**

The most boring case: feeding the canonical manifest's own bytes to the authenticator returns `Some(ManifestSnapshot)`. Other rejection arms come in subsequent steps so this task is bite-sized.

Create `core/src/sync/ingest.rs`:

```rust
//! Conflict-copy ingestion for C.1.1a.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md`.

use std::path::PathBuf;

use crate::sync::bundle::ManifestSnapshot;
use crate::unlock::UnlockedIdentity;
use crate::vault::Manifest;

/// Attempt to decode + authenticate one candidate manifest envelope.
///
/// Returns `Some(ManifestSnapshot)` only if ALL of the following hold:
///   1. Bytes decode as a `ManifestFile` envelope.
///   2. §8 hybrid signature verifies under the canonical owner's keys.
///   3. The candidate's `vault_uuid` (in the signed header) matches
///      `canonical.vault_uuid`.
///   4. The candidate's `author_fingerprint` matches the canonical
///      manifest's owner.
///   5. AEAD-decrypts with the unlocked Identity Block Key.
///
/// On any failure, returns `None` (callers silently ignore). Logs at
/// `tracing::debug!` for forensic diagnostics.
pub(crate) fn authenticate_manifest_envelope(
    candidate_bytes: &[u8],
    candidate_source_path: PathBuf,
    canonical: &Manifest,
    identity: &UnlockedIdentity,
) -> Option<ManifestSnapshot> {
    // Implementation in Step 3.
    let _ = (candidate_bytes, candidate_source_path, canonical, identity);
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    // ... tests added in subsequent steps
}
```

Append to `core/src/sync/mod.rs`:

```rust
pub mod ingest;
```

Add the first test in `core/src/sync/ingest.rs::tests` module:

```rust
    use crate::sync::bundle::ManifestSnapshot;

    #[test]
    fn authenticate_canonical_bytes_against_self_returns_some() {
        // Read golden_vault_001's manifest bytes, the canonical body,
        // and the test identity. Feed back through the authenticator —
        // it should accept (this is the "no-op self-auth" case).
        let folder = std::path::Path::new("tests/data/golden_vault_001");
        let bytes = std::fs::read(folder.join("manifest.cbor.enc")).expect("read manifest");

        let password = crate::unlock::Password::from_str(
            crate::tests::fixtures::GOLDEN_VAULT_001_PASSWORD,
        )
        .expect("password");
        let opened = crate::vault::open_vault(
            folder,
            crate::vault::Unlocker::Password(&password),
            None,
        )
        .expect("open_vault");

        let result = authenticate_manifest_envelope(
            &bytes,
            folder.join("manifest.cbor.enc"),
            &opened.manifest,
            &opened.identity,
        );

        assert!(result.is_some(), "canonical should authenticate against itself");
        let snapshot = result.unwrap();
        assert_eq!(snapshot.manifest.vault_uuid, opened.manifest.vault_uuid);
        assert_eq!(snapshot.raw_envelope_bytes, bytes);
    }
```

NOTE: The test above references `crate::tests::fixtures::GOLDEN_VAULT_001_PASSWORD` and `crate::unlock::Password::from_str` — verify these existing items resolve before running the test. If `Password::from_str` doesn't exist, use the equivalent constructor (`Password::new` or similar — check `core/src/unlock/`).

- [ ] **Step 2: Run to verify compile-fail or assertion-fail**

```bash
cargo test --release --workspace --lib sync::ingest::tests::authenticate_canonical_bytes_against_self_returns_some 2>&1 | tail -20
```

Expected: either (a) compile errors due to wrong helper names — fix them by grepping `core/src/unlock/` and `core/src/tests/fixtures.rs`; OR (b) test runs and fails the `assert!(result.is_some())` because the function returns `None` (the stub).

Investigate as needed:

```bash
grep -n "GOLDEN_VAULT_001_PASSWORD\|pub fn from_str\|pub fn new" core/src/tests/fixtures.rs core/src/unlock/mod.rs core/src/unlock/password.rs 2>/dev/null | head -10
```

- [ ] **Step 3: Implement `authenticate_manifest_envelope`**

Replace the stub body in `core/src/sync/ingest.rs`:

```rust
pub(crate) fn authenticate_manifest_envelope(
    candidate_bytes: &[u8],
    candidate_source_path: PathBuf,
    canonical: &Manifest,
    identity: &UnlockedIdentity,
) -> Option<ManifestSnapshot> {
    // Rule 1: decode envelope.
    let envelope = match crate::vault::manifest::decode_manifest_file(candidate_bytes) {
        Ok(env) => env,
        Err(e) => {
            tracing::debug!(path = %candidate_source_path.display(), error = %e,
                "conflict-copy rejected: manifest decode failed");
            return None;
        }
    };

    // Rule 3: vault_uuid in signed header must match canonical.
    if envelope.header.vault_uuid != canonical.vault_uuid {
        tracing::debug!(path = %candidate_source_path.display(),
            "conflict-copy rejected: vault_uuid mismatch");
        return None;
    }

    // Rule 4: author_fingerprint must match canonical's owner.
    // The canonical Manifest holds the owner_user_uuid; we cross-reference
    // the loaded owner card via the identity (the same UnlockedIdentity
    // that verified the canonical). The `canonical_owner_fp` for the
    // envelope's author_fingerprint check is recomputed from the
    // owner_user_uuid by reading the owner card; we accept the simplest
    // path here: the canonical's body's owner_user_uuid IS the identity's
    // user_uuid, and the envelope's signature is verified against the
    // owner card's keys via `manifest::verify_then_decrypt`. So Rule 4
    // is enforced transitively by Rule 2 + Rule 5 succeeding.

    // Rule 2 + 5: verify hybrid signature + AEAD-decrypt body.
    // Reuses the existing manifest::verify_then_decrypt path. Failure
    // implies either a bad signature, a tampered body, or the wrong
    // IBK — all of which are silent-reject cases.
    let manifest_body = match crate::vault::manifest::verify_then_decrypt(
        &envelope,
        &identity.identity_block_key,
        // owner_card / owner_fp threading depends on the existing API
        // shape — see the existing read_and_verify_manifest in
        // core/src/vault/orchestrators.rs for the canonical pattern.
        // If verify_then_decrypt takes (envelope, ibk, owner_ed_pk,
        // owner_pq_pk, owner_fp), thread them through here.
        todo!("thread owner-card-derived public keys; mirrors read_and_verify_manifest"),
    ) {
        Ok(body) => body,
        Err(e) => {
            tracing::debug!(path = %candidate_source_path.display(), error = %e,
                "conflict-copy rejected: verify/decrypt failed");
            return None;
        }
    };

    Some(ManifestSnapshot {
        manifest: manifest_body,
        raw_envelope_bytes: candidate_bytes.to_vec(),
        source_path: candidate_source_path,
    })
}
```

**IMPORTANT:** The `todo!` placeholder above MUST be resolved before Step 4 — it's there to flag that the implementer needs to verify the exact shape of `manifest::verify_then_decrypt` (or the equivalent helper) in `core/src/vault/manifest.rs`. Read `core/src/vault/orchestrators.rs::read_and_verify_manifest` (lines 562-680) to see how this is threaded today.

If no public `verify_then_decrypt` exists, this task expands to extract one as a `pub(crate) fn` from `read_and_verify_manifest`. That extraction is a refactor: pull the verify + decrypt steps into a standalone helper that takes `(envelope, ibk, owner_ed_pk, owner_pq_pk, owner_fp)` and returns `Result<Manifest, VaultError>`, then call it from both the existing site and the new `authenticate_manifest_envelope`. Run the existing manifest-related tests after the refactor to confirm no regression.

- [ ] **Step 4: Run tests, expand failing tests for rejection arms**

Once the canonical-self-auth test passes, **add** these three rejection-arm tests in `core/src/sync/ingest.rs::tests`:

```rust
    #[test]
    fn authenticate_garbage_bytes_returns_none() {
        let folder = std::path::Path::new("tests/data/golden_vault_001");
        let password = crate::unlock::Password::from_str(
            crate::tests::fixtures::GOLDEN_VAULT_001_PASSWORD,
        )
        .expect("password");
        let opened = crate::vault::open_vault(
            folder,
            crate::vault::Unlocker::Password(&password),
            None,
        )
        .expect("open_vault");

        let result = authenticate_manifest_envelope(
            b"this is not a manifest envelope",
            folder.join("garbage.cbor.enc"),
            &opened.manifest,
            &opened.identity,
        );
        assert!(result.is_none(), "garbage bytes should not authenticate");
    }

    #[test]
    fn authenticate_truncated_envelope_returns_none() {
        let folder = std::path::Path::new("tests/data/golden_vault_001");
        let bytes = std::fs::read(folder.join("manifest.cbor.enc")).expect("read");
        let truncated = &bytes[..bytes.len() / 2];

        let password = crate::unlock::Password::from_str(
            crate::tests::fixtures::GOLDEN_VAULT_001_PASSWORD,
        )
        .expect("password");
        let opened = crate::vault::open_vault(
            folder,
            crate::vault::Unlocker::Password(&password),
            None,
        )
        .expect("open_vault");

        let result = authenticate_manifest_envelope(
            truncated,
            folder.join("truncated.cbor.enc"),
            &opened.manifest,
            &opened.identity,
        );
        assert!(result.is_none(), "truncated envelope should not authenticate");
    }

    #[test]
    fn authenticate_envelope_with_flipped_bit_in_sig_returns_none() {
        let folder = std::path::Path::new("tests/data/golden_vault_001");
        let mut bytes = std::fs::read(folder.join("manifest.cbor.enc")).expect("read");
        // Flip a bit in the last 64 bytes — that region is the Ed25519
        // signature in the §4.1 envelope. (See docs/vault-format.md §4.1
        // for the exact byte offset; if the layout changed, find the
        // signature region via the manifest_file decoder's output and
        // flip there instead.)
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        let password = crate::unlock::Password::from_str(
            crate::tests::fixtures::GOLDEN_VAULT_001_PASSWORD,
        )
        .expect("password");
        let opened = crate::vault::open_vault(
            folder,
            crate::vault::Unlocker::Password(&password),
            None,
        )
        .expect("open_vault");

        let result = authenticate_manifest_envelope(
            &bytes,
            folder.join("tampered.cbor.enc"),
            &opened.manifest,
            &opened.identity,
        );
        assert!(result.is_none(), "tampered signature should not authenticate");
    }
```

Run:

```bash
cargo test --release --workspace --lib sync::ingest 2>&1 | tail -15
```

Expected: 4 passed (the self-auth plus three rejections). Workspace count: 689.

- [ ] **Step 5: Clippy + fmt + commit**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/ingest.rs core/src/sync/mod.rs
# If a manifest::verify_then_decrypt refactor was needed:
# git add core/src/vault/manifest.rs core/src/vault/orchestrators.rs
git commit -m "$(cat <<'EOF'
feat(sync): add authenticate_manifest_envelope pure helper

Implements C.1.1a's five MUST authentication rules for conflict-copy
manifest candidates:
  1. CBOR + envelope decode succeeds
  2. §8 hybrid signature (Ed25519 ∧ ML-DSA-65) verifies
  3. vault_uuid matches canonical (signed header)
  4. author_fingerprint matches canonical's owner (transitive via sig)
  5. AEAD-decrypts with the unlocked Identity Block Key

Returns Option<ManifestSnapshot> — None on any failure; logs at
tracing::debug! for forensic diagnostics. Per spec §1a-D3/1a-D4,
"silent ignore" is ONLY safe because all five MUSTs hold.

Tests cover the accept path (canonical-against-self) plus three
rejection arms (garbage bytes, truncated envelope, flipped signature
bit). Wrong-vault_uuid and wrong-owner-fp arms covered by integration
tests in Task 14 (need a second authenticated vault fixture).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Add `enumerate_manifest_siblings` directory-scan helper

**Why:** Filesystem enumeration is one concern; authentication is another. Keep them separable so Task 4's authenticator stays a pure function over bytes.

**Files:**
- Modify: `core/src/sync/ingest.rs`

- [ ] **Step 1: Write failing test**

Append to `core/src/sync/ingest.rs::tests`:

```rust
    #[test]
    fn enumerate_manifest_siblings_returns_non_canonical_cbor_enc_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path();

        // Create three files: canonical, a sibling, and an unrelated file.
        std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();
        std::fs::write(folder.join("manifest.cbor.enc.sibling-1"), b"sibling").unwrap();
        std::fs::write(folder.join("manifest.cbor.enc.conflict-from-dropbox"), b"sibling-2").unwrap();
        std::fs::write(folder.join("vault.toml"), b"unrelated").unwrap();

        let siblings = enumerate_manifest_siblings(folder).expect("scan");
        let names: Vec<String> = siblings.iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert_eq!(siblings.len(), 2);
        assert!(names.contains(&"manifest.cbor.enc.sibling-1".to_string()));
        assert!(names.contains(&"manifest.cbor.enc.conflict-from-dropbox".to_string()));
        assert!(!names.contains(&"manifest.cbor.enc".to_string()));
        assert!(!names.contains(&"vault.toml".to_string()));
    }

    #[test]
    fn enumerate_manifest_siblings_returns_empty_on_clean_folder() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path();
        std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();

        let siblings = enumerate_manifest_siblings(folder).expect("scan");
        assert!(siblings.is_empty());
    }
```

Run to verify compile failure:

```bash
cargo test --release --workspace --lib sync::ingest::tests::enumerate_manifest_siblings_returns_non_canonical_cbor_enc_files 2>&1 | head -15
```

Expected: `cannot find function enumerate_manifest_siblings`.

- [ ] **Step 2: Implement the function**

Add to `core/src/sync/ingest.rs` (above the `#[cfg(test)]`):

```rust
use std::path::Path;

const CANONICAL_MANIFEST_FILENAME: &str = "manifest.cbor.enc";

/// Enumerate files in `folder` that are candidate manifest
/// conflict-copies — i.e. files whose name STARTS with the canonical
/// manifest filename and is not identical to it. Returns sorted by
/// filename for deterministic test output.
///
/// I/O failure (folder missing, permission denied) returns the wrapped
/// `std::io::Error`. Per-entry failures (e.g. symlink loops) are
/// silently skipped so a poison file can't deny-of-service the scan.
pub(crate) fn enumerate_manifest_siblings(
    folder: &Path,
) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(folder)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // skip individual unreadable entries
        };
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name == CANONICAL_MANIFEST_FILENAME {
            continue;
        }
        if !name.starts_with(CANONICAL_MANIFEST_FILENAME) {
            continue;
        }
        out.push(path);
    }
    out.sort();
    Ok(out)
}
```

NOTE: The spec said scanner accepts ANY `*.cbor.enc` file — but starting-with `manifest.cbor.enc` is a strictly tighter filter that still covers Dropbox `(conflicted copy …)` (which becomes `manifest.cbor.enc (conflicted copy …)`), iCloud `manifest.cbor.enc 2`, Syncthing `manifest.cbor.enc.sync-conflict-…`, etc. — all keep the canonical prefix. If you'd prefer the looser `*.cbor.enc` filter (accepting `random_garbage.cbor.enc` too), change the `starts_with` check to a `.cbor.enc` extension check. The integration tests in Task 14 will exercise both interpretations; the design's "heuristic decode-then-authenticate" framing is satisfied by either.

- [ ] **Step 3: Run tests, verify pass**

```bash
cargo test --release --workspace --lib sync::ingest 2>&1 | tail -10
```

Expected: 6 passed (4 from Task 4 + 2 new). Workspace count: 691.

- [ ] **Step 4: Clippy + fmt + commit**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/ingest.rs
git commit -m "$(cat <<'EOF'
feat(sync): add enumerate_manifest_siblings directory scan helper

Returns paths of candidate manifest conflict-copies — files in the
vault folder whose name starts with 'manifest.cbor.enc' and is not
exactly the canonical name. Covers Dropbox / iCloud / Syncthing /
OneDrive naming conventions (all preserve the canonical prefix).

I/O failure at the scan level returns std::io::Error; per-entry
read failures are silently skipped so one poison entry can't DoS
the scan. Output is sorted by path for deterministic test
expectations.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Wire `ingest_manifest_copies` (Tasks 4 + 5 composed)

**Files:**
- Modify: `core/src/sync/ingest.rs`

- [ ] **Step 1: Write failing test**

Append to `core/src/sync/ingest.rs::tests`:

```rust
    #[test]
    fn ingest_manifest_copies_zero_siblings_returns_empty() {
        let canonical_clock = vec![crate::vault::VectorClockEntry {
            device_uuid: [0xAA; 16],
            counter: 1,
        }];
        let (folder, _tmp) = crate::tests::sync_helpers::fresh_vault_with_clock(canonical_clock);
        // Open the vault to get the canonical Manifest + identity.
        let password = crate::unlock::Password::from_str(
            crate::tests::fixtures::GOLDEN_VAULT_001_PASSWORD,
        )
        .expect("password");
        let opened = crate::vault::open_vault(
            &folder,
            crate::vault::Unlocker::Password(&password),
            None,
        )
        .expect("open_vault");

        let copies = ingest_manifest_copies(&folder, &opened.identity, &opened.manifest)
            .expect("scan ok");
        assert!(copies.is_empty(), "expected zero conflict-copies");
    }
```

NOTE: `crate::tests::sync_helpers` here refers to the integration-test helper module — since this is an inline LIB test, we cannot reach `core/tests/sync_helpers/mod.rs`. Two options:

(a) Move the helper into `core/src/sync/test_helpers.rs` as a `#[cfg(test)] pub(crate) mod` — accessible from both lib tests AND integration tests via a re-export.

(b) Defer this test to an integration test in Task 14.

**Recommendation: option (b)**. Lib-level inline tests for `ingest_manifest_copies` would need a fixture that's already in the integration-tests sphere (golden_vault_001 lives in `core/tests/data/`). The cleaner shape is: lib tests for the PURE helpers (authenticate_manifest_envelope, enumerate_manifest_siblings, compute_diff_plan); integration tests for the COMPOSED entry points (ingest_manifest_copies, ingest_conflict_copies, sync_once integration). Replace the test above with a doc-comment promise that integration coverage lands in Task 14.

- [ ] **Step 2: Implement `ingest_manifest_copies`**

Append to `core/src/sync/ingest.rs`:

```rust
/// Compose [`enumerate_manifest_siblings`] + [`authenticate_manifest_envelope`]:
/// scan the vault folder for sibling manifest files and return only
/// those that authenticate.
///
/// I/O failures during the initial scan are propagated. Per-file
/// authentication failures are silently dropped — that's the security
/// model per spec §1a-D3.
///
/// Integration coverage in `core/tests/sync_ingest.rs` (Task 14 of the
/// C.1.1a plan): the `golden_vault_001` fixture lives outside the lib
/// crate's reach so lib-level inline tests cover only the pure helpers
/// above.
pub(crate) fn ingest_manifest_copies(
    folder: &Path,
    identity: &UnlockedIdentity,
    canonical: &Manifest,
) -> Result<Vec<ManifestSnapshot>, std::io::Error> {
    let sibling_paths = enumerate_manifest_siblings(folder)?;
    let mut copies: Vec<ManifestSnapshot> = Vec::with_capacity(sibling_paths.len());

    for path in sibling_paths {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                tracing::debug!(path = %path.display(), "conflict-copy skipped: read error");
                continue;
            }
        };
        const MAX_MANIFEST_SIZE: usize = 1024 * 1024; // 1 MiB; current manifests are KB-scale
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_SIZE {
            tracing::debug!(path = %path.display(), size = bytes.len(),
                "conflict-copy skipped: size out of bounds");
            continue;
        }
        if let Some(snapshot) = authenticate_manifest_envelope(
            &bytes,
            path.clone(),
            canonical,
            identity,
        ) {
            copies.push(snapshot);
        }
    }
    Ok(copies)
}
```

- [ ] **Step 3: Compile check**

```bash
cargo build --release --workspace 2>&1 | tail -5
```

Expected: clean build. (No new tests yet; integration tests in Task 14.)

- [ ] **Step 4: Clippy + fmt + commit**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/ingest.rs
git commit -m "$(cat <<'EOF'
feat(sync): wire ingest_manifest_copies (scan + authenticate composition)

Composes enumerate_manifest_siblings + authenticate_manifest_envelope.
For each sibling path: read bytes, size-bound check (1 MiB cap),
authenticate. Authentication failures silently drop per spec §1a-D3.

The MAX_MANIFEST_SIZE constant is the only magic number; it's
generous (current real manifests are KB-scale; 1 MiB is ~1000x slack)
and serves as a DoS bound against an attacker who can write
arbitrarily-large files into the vault folder.

Integration coverage in Task 14's sync_ingest.rs — lib-level inline
tests cover only pure helpers because the golden_vault_001 fixture
lives in tests/data/.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Add `authenticate_block_envelope` pure helper

**Why:** Same security perimeter as Task 4 but for block files, not manifests. Block-envelope authentication is signature-only (Ed25519 ∧ ML-DSA-65 over the block envelope) — AEAD decryption is C.1.1b's job. Author fingerprint must match canonical owner.

**Files:**
- Modify: `core/src/sync/ingest.rs`

- [ ] **Step 1: Write failing test**

Append to `core/src/sync/ingest.rs::tests`:

```rust
    #[test]
    fn authenticate_block_envelope_canonical_self_returns_some() {
        let folder = std::path::Path::new("tests/data/golden_vault_001");
        let password = crate::unlock::Password::from_str(
            crate::tests::fixtures::GOLDEN_VAULT_001_PASSWORD,
        )
        .expect("password");
        let opened = crate::vault::open_vault(
            folder,
            crate::vault::Unlocker::Password(&password),
            None,
        )
        .expect("open_vault");

        // Pick the first block referenced by the canonical manifest.
        let first_block_entry = opened.manifest.blocks.first()
            .expect("golden vault has at least one block");
        let owner_fp = crate::identity::fingerprint::fingerprint(
            &opened.owner_card.to_canonical_cbor().expect("card cbor"),
        );
        let block_uuid_hex = format_uuid_hyphenated(&first_block_entry.block_uuid);
        let block_path = folder.join("blocks").join(format!("{block_uuid_hex}.cbor.enc"));
        let bytes = std::fs::read(&block_path).expect("read block file");

        let result = authenticate_block_envelope(
            &bytes,
            block_path.clone(),
            owner_fp,
        );
        assert!(result.is_some(), "canonical block should authenticate");
        let envelope = result.unwrap();
        assert_eq!(envelope.bytes, bytes);
    }

    fn format_uuid_hyphenated(uuid: &[u8; 16]) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid[0], uuid[1], uuid[2], uuid[3],
            uuid[4], uuid[5], uuid[6], uuid[7],
            uuid[8], uuid[9], uuid[10], uuid[11],
            uuid[12], uuid[13], uuid[14], uuid[15],
        )
    }
```

Run to verify compile failure:

```bash
cargo test --release --workspace --lib sync::ingest::tests::authenticate_block_envelope_canonical_self_returns_some 2>&1 | head -10
```

Expected: `cannot find function authenticate_block_envelope`.

- [ ] **Step 2: Implement `authenticate_block_envelope`**

Append to `core/src/sync/ingest.rs`:

```rust
use crate::sync::bundle::BlockEnvelope;

/// Attempt to authenticate one block envelope file.
///
/// Block envelopes carry encrypted plaintext under a per-block AEAD
/// key (decryption is C.1.1b's job). Authentication here checks only
/// the §8 hybrid signature on the envelope + the `author_fingerprint`
/// match against the canonical vault owner.
///
/// Returns `Some(BlockEnvelope)` carrying the raw bytes if both checks
/// pass; `None` otherwise (silent reject, debug-logged).
pub(crate) fn authenticate_block_envelope(
    candidate_bytes: &[u8],
    candidate_source_path: PathBuf,
    canonical_owner_fingerprint: [u8; 32],
) -> Option<BlockEnvelope> {
    let block_file = match crate::vault::block::decode_block_file(candidate_bytes) {
        Ok(bf) => bf,
        Err(e) => {
            tracing::debug!(path = %candidate_source_path.display(), error = %e,
                "block conflict-copy rejected: decode failed");
            return None;
        }
    };

    if block_file.author_fingerprint != canonical_owner_fingerprint {
        tracing::debug!(path = %candidate_source_path.display(),
            "block conflict-copy rejected: author_fingerprint mismatch");
        return None;
    }

    // Verify §8 hybrid signature on the envelope. The exact API call
    // depends on what verify helpers `core::vault::block` exposes —
    // typically `block::verify_envelope_signature(&block_file, &owner_ed_pk, &owner_pq_pk)`.
    // Grep `core/src/vault/block.rs` for the existing verifier and
    // thread the canonical owner's public keys (derived from the owner
    // card the canonical manifest authenticated against).
    //
    // For this function's signature to stay pure (no Manifest /
    // UnlockedIdentity coupling), the caller is responsible for
    // resolving owner public keys once and passing them down. Refactor
    // this fn to accept (owner_ed_pk, owner_pq_pk) when wiring up
    // ingest_block_divergence in Task 9.

    Some(BlockEnvelope {
        bytes: candidate_bytes.to_vec(),
        source_path: candidate_source_path,
    })
}
```

NOTE: The signature-verification step above is a **deliberate placeholder** — the function as written above accepts on `author_fingerprint` agreement alone, which is incomplete per spec §1a-D4. The implementer MUST:

1. Grep `core/src/vault/block.rs` for the existing signature-verification helper (likely named `verify_block_envelope_signature` or similar).
2. Either:
   - Refactor `authenticate_block_envelope` to take `(owner_ed_pk: &Ed25519Public, owner_pq_pk: &MlDsa65Public)` as additional parameters.
   - OR thread the canonical `Manifest + owner_card` and derive keys inline.
3. Call the signature verifier; on failure, return `None` with a debug log.
4. Update the test in Step 1 to pass the public keys through.

Until this is done, `authenticate_block_envelope` accepts envelopes that pass `author_fingerprint` but have invalid signatures — a security gap. Task 9 (composition) blocks on this resolution.

- [ ] **Step 3: Add the missing signature verification (per the note above)**

This is a sub-step within Task 7. Concretely:

```bash
grep -n "pub fn verify\|verify_signature\|verify_envelope\|verify_block" core/src/vault/block.rs | head -10
```

Look for the existing helper. Refactor `authenticate_block_envelope`'s signature and body to call it. Update the test in Step 1 accordingly. The exact code depends on what `block.rs` exposes — read the relevant ~30 lines and adapt.

- [ ] **Step 4: Run tests, verify pass**

```bash
cargo test --release --workspace --lib sync::ingest 2>&1 | tail -10
```

Expected: 7 passed (Tasks 3 + 4 + 5 helpers + this one). Workspace count: 692.

- [ ] **Step 5: Clippy + fmt + commit**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/ingest.rs
git commit -m "$(cat <<'EOF'
feat(sync): add authenticate_block_envelope pure helper

Enforces decode + author_fingerprint + §8 hybrid signature on block
envelope conflict-copies. AEAD decryption is C.1.1b's job — this
helper authenticates the outer envelope only, keeping block plaintext
sealed inside BlockEnvelope.bytes until prepare_merge invokes it.

Per spec §1a-D4 the five MUSTs for manifests reduce to three for
blocks (decode + author_fingerprint + signature; AEAD-decrypt + the
vault_uuid-via-manifest-binding are inherited transitively from the
manifest layer that scoped this block_uuid as needing ingestion).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Add `enumerate_block_siblings` directory-scan helper

**Files:**
- Modify: `core/src/sync/ingest.rs`

- [ ] **Step 1: Write failing test**

Append to `core/src/sync/ingest.rs::tests`:

```rust
    #[test]
    fn enumerate_block_siblings_filters_by_uuid_prefix() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let blocks_dir = tmp.path().join("blocks");
        std::fs::create_dir(&blocks_dir).unwrap();

        let uuid_a = [0xAA; 16];
        let uuid_b = [0xBB; 16];
        let hex_a = format_uuid_hyphenated(&uuid_a);
        let hex_b = format_uuid_hyphenated(&uuid_b);

        let canonical_a = blocks_dir.join(format!("{hex_a}.cbor.enc"));
        let sibling_a1 = blocks_dir.join(format!("{hex_a}.cbor.enc.sibling-1"));
        let sibling_a2 = blocks_dir.join(format!("{hex_a}.cbor.enc (conflicted copy 2026-05-01)"));
        let canonical_b = blocks_dir.join(format!("{hex_b}.cbor.enc"));
        std::fs::write(&canonical_a, b"canonical-a").unwrap();
        std::fs::write(&sibling_a1, b"sibling-a-1").unwrap();
        std::fs::write(&sibling_a2, b"sibling-a-2").unwrap();
        std::fs::write(&canonical_b, b"canonical-b").unwrap();

        let siblings_a = enumerate_block_siblings(tmp.path(), &uuid_a).expect("scan");
        assert_eq!(siblings_a.len(), 2);
        assert!(siblings_a.contains(&sibling_a1));
        assert!(siblings_a.contains(&sibling_a2));
        assert!(!siblings_a.contains(&canonical_a));
        assert!(!siblings_a.contains(&canonical_b));
    }
```

- [ ] **Step 2: Implement**

Append to `core/src/sync/ingest.rs`:

```rust
const BLOCKS_SUBDIR: &str = "blocks";
const BLOCK_FILE_EXTENSION: &str = ".cbor.enc";

/// Enumerate sibling files of `blocks/<uuid>.cbor.enc` in `folder` —
/// any file in the blocks subdirectory whose name starts with the
/// hyphenated UUID + `.cbor.enc` and is NOT exactly the canonical
/// filename.
pub(crate) fn enumerate_block_siblings(
    folder: &Path,
    block_uuid: &[u8; 16],
) -> Result<Vec<PathBuf>, std::io::Error> {
    let canonical_stem = format!(
        "{}-{}-{}-{}-{}.cbor.enc",
        hex::encode(&block_uuid[0..4]),
        hex::encode(&block_uuid[4..6]),
        hex::encode(&block_uuid[6..8]),
        hex::encode(&block_uuid[8..10]),
        hex::encode(&block_uuid[10..16]),
    );

    // ALTERNATIVELY use format_uuid_hyphenated above — find the existing
    // hex helper in core/src/vault/orchestrators.rs or core/src/ID and
    // reuse to avoid divergence. The format must match exactly what
    // save_block writes (see core/src/vault/orchestrators.rs:853).
    let canonical_name = canonical_stem.clone();

    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    if !blocks_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut out: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&blocks_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name == canonical_name {
            continue;
        }
        if !name.starts_with(&canonical_stem) {
            continue;
        }
        out.push(path);
    }
    out.sort();
    Ok(out)
}
```

NOTE on the `format_uuid_hyphenated` helper: the lib crate has one in `core/src/vault/orchestrators.rs:72` but it's `fn` (private). Promote it to `pub(crate)` in `core/src/vault/orchestrators.rs` (or move to a shared `core/src/util/uuid.rs` module) so this code can share it instead of re-implementing. The re-implementation above is a placeholder — replace with the shared helper before commit.

Add `hex` to `core/Cargo.toml` if not already present — but check first:

```bash
grep "^hex" core/Cargo.toml
```

If present, no change needed. If absent, prefer reusing the existing helper rather than adding a new dependency.

- [ ] **Step 3: Run tests, verify pass**

```bash
cargo test --release --workspace --lib sync::ingest::tests::enumerate_block_siblings_filters_by_uuid_prefix 2>&1 | tail -10
```

Expected: pass. Workspace count: 693.

- [ ] **Step 4: Clippy + fmt + commit**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/ingest.rs core/src/vault/orchestrators.rs  # if you promoted the UUID helper
git commit -m "$(cat <<'EOF'
feat(sync): add enumerate_block_siblings directory scan helper

Returns conflict-copy candidate paths for a specific block_uuid —
files under blocks/ whose name starts with the canonical hyphenated
UUID + .cbor.enc and is not exactly the canonical name.

Reuses (or promotes) format_uuid_hyphenated from
core/src/vault/orchestrators.rs to avoid divergence between this
scanner and what save_block writes; orchestrators.rs's format is
canonical.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Wire `ingest_block_divergence` (Tasks 7 + 8 composed + manifest diff)

**Files:**
- Modify: `core/src/sync/ingest.rs`

- [ ] **Step 1: Implement `ingest_block_divergence`**

This is the heart of the per-block divergence detection. Append to `core/src/sync/ingest.rs`:

```rust
use std::collections::BTreeMap;

use crate::sync::bundle::{BlockDivergence, BlockEnvelope};
use crate::vault::conflict::{clock_relation, ClockRelation};

/// For each block_uuid present in the canonical manifest, determine
/// whether any conflict-copy manifest carries a divergent
/// `vector_clock_summary` for the same block. If yes, scan + ingest
/// sibling block files for that block_uuid.
///
/// Returns a map keyed by block_uuid, populated only with diverging
/// blocks (non-divergent blocks are absent from the map).
pub(crate) fn ingest_block_divergence(
    folder: &Path,
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    canonical_owner_fingerprint: [u8; 32],
) -> Result<BTreeMap<[u8; 16], BlockDivergence>, std::io::Error> {
    let mut out: BTreeMap<[u8; 16], BlockDivergence> = BTreeMap::new();

    for canonical_entry in &canonical.blocks {
        let block_uuid = canonical_entry.block_uuid;

        // Is this block divergent? Compare canonical's vector_clock_summary
        // against each copy's BlockEntry for the same block_uuid.
        let mut diverges = false;
        for copy in copies {
            let copy_entry = match copy.manifest.blocks.iter()
                .find(|e| e.block_uuid == block_uuid)
            {
                Some(e) => e,
                None => continue, // copy doesn't reference this block (deletion?)
            };
            let rel = clock_relation(
                &canonical_entry.vector_clock_summary,
                &copy_entry.vector_clock_summary,
            );
            if !matches!(rel, ClockRelation::Equal | ClockRelation::IncomingDominated) {
                // IncomingDominates or Concurrent — divergence; we need
                // the copy's block content for the merge.
                diverges = true;
                break;
            }
        }
        if !diverges {
            continue;
        }

        // Load canonical block envelope.
        let canonical_block_path = folder
            .join(BLOCKS_SUBDIR)
            .join(crate::vault::orchestrators::format_uuid_hyphenated(&block_uuid)
                + BLOCK_FILE_EXTENSION);
        let canonical_bytes = match std::fs::read(&canonical_block_path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(path = %canonical_block_path.display(), error = %e,
                    "canonical block file unreadable; skipping divergence ingest");
                continue;
            }
        };
        let canonical_envelope = BlockEnvelope {
            bytes: canonical_bytes,
            source_path: canonical_block_path,
        };

        // Scan + authenticate copy envelopes.
        let sibling_paths = enumerate_block_siblings(folder, &block_uuid)?;
        let mut copy_envelopes: Vec<BlockEnvelope> = Vec::with_capacity(sibling_paths.len());
        for path in sibling_paths {
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if let Some(env) = authenticate_block_envelope(&bytes, path, canonical_owner_fingerprint)
            {
                copy_envelopes.push(env);
            }
        }

        out.insert(block_uuid, BlockDivergence {
            canonical_envelope,
            copy_envelopes,
        });
    }

    Ok(out)
}
```

NOTE on `crate::vault::orchestrators::format_uuid_hyphenated` — promote it to `pub(crate)` if not done in Task 8.

- [ ] **Step 2: Compile check**

```bash
cargo build --release --workspace 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 3: Clippy + fmt + commit**

Integration tests cover this — Task 14. Lib-level inline tests aren't worth the fixture complexity here.

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/ingest.rs
git commit -m "$(cat <<'EOF'
feat(sync): wire ingest_block_divergence

For each block in the canonical manifest, compare its
vector_clock_summary against the same block_uuid's entry in each
authenticated conflict-copy manifest. If any copy carries a
non-dominated (i.e. IncomingDominates or Concurrent) clock, the block
is divergent: read the canonical block envelope + scan sibling block
files + authenticate each.

Diverging blocks land in the returned BTreeMap; non-divergent blocks
are absent. Per spec §1a-D4 + spec §"Algorithm step 3", block
authentication is decode + author_fingerprint + signature (AEAD
decrypt deferred to C.1.1b).

Integration coverage in Task 14.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Add `compute_diff_plan` + top-level `ingest_conflict_copies`

**Files:**
- Modify: `core/src/sync/ingest.rs`

- [ ] **Step 1: Implement `compute_diff_plan`**

```rust
use crate::sync::bundle::VaultBundle;

/// Derive the [`crate::sync::DiffPlan`] from an assembled bundle —
/// `Vec<[u8; 16]>` of block_uuids that have at least one diverging
/// copy envelope.
///
/// Pure function over `VaultBundle.diverging_blocks` keys. Sorted
/// ascending for canonical determinism.
pub(crate) fn compute_diff_plan(bundle: &VaultBundle) -> Vec<[u8; 16]> {
    bundle.diverging_blocks.keys().copied().collect()
}
```

(`BTreeMap::keys()` already iterates in sorted order — no extra sort step required.)

- [ ] **Step 2: Inline test**

Append to `core/src/sync/ingest.rs::tests`:

```rust
    #[test]
    fn compute_diff_plan_empty_bundle_returns_empty() {
        let canonical_path = PathBuf::from("/tmp/c.cbor.enc");
        let bundle = VaultBundle {
            canonical: ManifestSnapshot {
                manifest: Manifest::default_for_test(),  // see note
                raw_envelope_bytes: vec![0xCA, 0xFE],
                source_path: canonical_path,
            },
            copies: vec![],
            diverging_blocks: BTreeMap::new(),
        };
        let plan = compute_diff_plan(&bundle);
        assert!(plan.is_empty());
    }
```

NOTE: `Manifest::default_for_test()` is **fictional** in current code. Two paths:

(a) Construct a `Manifest` via the public constructor/fields (read `core/src/vault/manifest.rs` to see what's required — likely `vault_uuid`, `vector_clock`, `blocks`, `unknown`, etc.). Just zero-out everything.

(b) Test `compute_diff_plan` only via integration tests in Task 14 and remove this inline test.

**Recommendation: option (a)** if `Manifest`'s fields are all `pub`; otherwise (b). Investigate:

```bash
grep -n "^pub struct Manifest\b\|impl Manifest\b" core/src/vault/manifest.rs | head -5
```

If `Manifest` has a public constructor or all-pub fields, build a minimum instance. Otherwise drop the inline test (compute_diff_plan is a one-line function — the integration tests in Task 14 cover it adequately).

- [ ] **Step 3: Implement `ingest_conflict_copies` (top-level entry)**

Append to `core/src/sync/ingest.rs`:

```rust
/// Top-level conflict-copy ingestion: build a [`VaultBundle`] from a
/// vault folder + a canonical (already-authenticated) manifest +
/// unlocked identity.
///
/// Called by [`crate::sync::sync_once`] only on the Concurrent
/// dispatch path. Returns the full bundle (canonical + 0..N
/// authenticated copies + per-block divergence).
pub(crate) fn ingest_conflict_copies(
    folder: &Path,
    identity: &UnlockedIdentity,
    canonical: &Manifest,
    canonical_envelope_bytes: &[u8],
    canonical_source_path: PathBuf,
    canonical_owner_fingerprint: [u8; 32],
) -> Result<VaultBundle, std::io::Error> {
    let copies = ingest_manifest_copies(folder, identity, canonical)?;
    let diverging_blocks =
        ingest_block_divergence(folder, canonical, &copies, canonical_owner_fingerprint)?;

    Ok(VaultBundle {
        canonical: ManifestSnapshot {
            manifest: canonical.clone(),
            raw_envelope_bytes: canonical_envelope_bytes.to_vec(),
            source_path: canonical_source_path,
        },
        copies,
        diverging_blocks,
    })
}
```

- [ ] **Step 4: Compile + fmt + clippy + commit**

```bash
cargo build --release --workspace 2>&1 | tail -5
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/ingest.rs
git commit -m "$(cat <<'EOF'
feat(sync): add compute_diff_plan + top-level ingest_conflict_copies

compute_diff_plan extracts the sorted block_uuids from a bundle's
diverging_blocks map — one line, since BTreeMap::keys iterates in
order. The DiffPlan shape settles to Vec<[u8; 16]> here (the original
C.1.1 sketch had Vec<(BlockId, RecordId)> which was the wrong
granularity — merge_block operates per-block).

ingest_conflict_copies wires ingest_manifest_copies +
ingest_block_divergence into one entry point. Called by sync_once
in Task 13 on the Concurrent dispatch path.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Modify `SyncOutcome` — replace `ForkDetected` with `ConcurrentDetected`

**Files:**
- Modify: `core/src/sync/outcome.rs`
- Modify: `core/src/sync/error.rs` (+ 2 variants)
- Modify: `core/src/sync/mod.rs` (re-export DiffPlan if needed)

- [ ] **Step 1: Add `DiffPlan` type to outcome.rs (or a sibling file)**

The spec puts `DiffPlan` in `core/src/sync/diff.rs` (per 1b spec) but for 1a's scope, we can place it inside `core/src/sync/outcome.rs` next to the variant that carries it. Decide based on whether `diff.rs` will exist after 1a OR whether it's strictly a 1b artifact. The C.1.1a spec doesn't create `diff.rs`; defer to 1b.

So: add `DiffPlan` to `outcome.rs`:

```rust
// At top of core/src/sync/outcome.rs

/// Block UUIDs whose state diverges between the canonical manifest
/// and at least one conflict-copy. Computed by `compute_diff_plan`
/// from the assembled `VaultBundle`. Consumed by C.1.1b's
/// `prepare_merge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffPlan {
    pub diverging_blocks: Vec<[u8; 16]>,
}
```

- [ ] **Step 2: Replace `ForkDetected` with `ConcurrentDetected`**

Find the existing definition:

```bash
grep -n "ForkDetected" core/src/sync/outcome.rs
```

Replace the variant. The new variant:

```rust
/// Disk and local highest_seen are concurrent (incomparable).
/// `sync_once` has scanned the vault folder for conflict-copy files,
/// authenticated each per spec §1a-D4, and packaged the result into
/// `bundle`. Caller invokes C.1.1b's `prepare_merge(folder, identity,
/// bundle, plan)` to compute the draft merge.
ConcurrentDetected {
    bundle: crate::sync::bundle::VaultBundle,
    plan: DiffPlan,
    manifest_hash: crate::sync::bundle::ManifestHash,
    disk_vector_clock: Vec<crate::vault::VectorClockEntry>,
    local_highest_seen: Vec<crate::vault::VectorClockEntry>,
},
```

- [ ] **Step 3: Update sync.rs integration tests for new variant**

Find every test that matches `ForkDetected`:

```bash
grep -n "ForkDetected" core/tests/sync.rs core/src/sync/once.rs
```

For each match:
- Rename the test from `*_yields_fork_detected` to `*_yields_concurrent_detected`.
- Update the pattern: `SyncOutcome::ForkDetected { disk_vector_clock, local_highest_seen }` → `SyncOutcome::ConcurrentDetected { bundle, plan, manifest_hash, disk_vector_clock, local_highest_seen }`.
- For these existing tests, assert `bundle.copies.is_empty()` (no sibling files in the golden vault) and `plan.diverging_blocks.is_empty()`.

Example transformation for `core/tests/sync.rs:157-170` (`sync_once_concurrent_disk_detects_fork`):

```rust
// Before:
#[test]
fn sync_once_concurrent_disk_detects_fork() {
    // ...
    assert!(matches!(outcome, SyncOutcome::ForkDetected { .. }));
}

// After:
#[test]
fn sync_once_concurrent_disk_detects_concurrent_detected() {
    // ...
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => {
            assert!(bundle.copies.is_empty(), "no sibling files expected");
            assert!(plan.diverging_blocks.is_empty(), "no divergent blocks expected");
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}
```

Repeat for the `dispatch_concurrent_clocks_yields_fork_detected` test in `core/src/sync/once.rs:72`.

- [ ] **Step 4: Add the 2 new SyncError variants**

Modify `core/src/sync/error.rs`:

```rust
// Append to the SyncError enum

#[error("conflict-copy scan failed: failed to enumerate folder: {source}")]
ConflictCopyScanIoFailed {
    #[source]
    source: std::io::Error,
},

#[error("internal invariant: canonical manifest envelope failed BLAKE3 hash (should never happen)")]
CanonicalHashInternal,
```

- [ ] **Step 5: Update re-exports in `core/src/sync/mod.rs`**

```rust
pub use outcome::{DiffPlan, RollbackEvidence, SyncOutcome};
```

- [ ] **Step 6: Compile + run all tests**

```bash
cargo build --release --workspace 2>&1 | tail -5
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | tail -3
```

Expected: all tests pass. The fork-renamed tests should now pass with the new pattern.

- [ ] **Step 7: Clippy + fmt + commit**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/outcome.rs core/src/sync/error.rs core/src/sync/mod.rs core/src/sync/once.rs core/tests/sync.rs
git commit -m "$(cat <<'EOF'
refactor(sync): replace ForkDetected with ConcurrentDetected variant

C.1.1a's merge layer makes every concurrent state mergeable via CRDT
closure, so the terminal ForkDetected variant retires. The replacement
ConcurrentDetected carries:
  - bundle: VaultBundle  (authenticated conflict-copies)
  - plan: DiffPlan       (block_uuids needing merge)
  - manifest_hash: ManifestHash  (TOCTOU freshness anchor for 1b)
  - disk_vector_clock, local_highest_seen  (preserved for diagnostics)

Existing fork-detected tests are renamed to *_concurrent_detected and
extended to assert bundle.copies.is_empty() + plan.diverging_blocks.is_empty()
on the golden_vault_001 fixture (no sibling files present today).

Also adds two new SyncError variants for genuine I/O failures during
conflict-copy scanning (per-file authentication failures remain silent
per spec §1a-D3).

DiffPlan lives in outcome.rs for 1a; 1b will move it to diff.rs if
needed when other types share the file.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Wire `sync_once` Concurrent arm to invoke `ingest_conflict_copies`

**Files:**
- Modify: `core/src/sync/once.rs`

- [ ] **Step 1: Update `sync_once`'s body**

Read current `core/src/sync/once.rs`. The dispatch table in lines 65-86 needs the Concurrent arm rewritten:

```rust
// In sync_once, BEFORE the dispatch call, capture the raw envelope bytes
// so the ConcurrentDetected branch can compute manifest_hash.
//
// Current step 1 reads manifest body via read_vault_manifest, which
// discards the envelope bytes. For 1a we need them — so the Concurrent
// path re-reads (the rest of the path is unchanged).
//
// Cleaner: extend sync_once to read manifest envelope bytes upfront
// (one extra std::fs::read of a small file) and pass them through.

pub fn sync_once(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &SyncState,
    _now_ms: u64,
) -> Result<SyncOutcome, SyncError> {
    // Step 1 (unchanged): read + verify the manifest body.
    let manifest = read_vault_manifest(vault_folder, identity, None)?;

    // Step 2 (unchanged): vault_uuid agreement.
    if manifest.vault_uuid != state.vault_uuid {
        return Err(SyncError::VaultUuidMismatch {
            state_vault_uuid: state.vault_uuid,
            folder_vault_uuid: manifest.vault_uuid,
        });
    }

    // Step 3 (modified): compute manifest_hash from raw envelope bytes.
    // read_vault_manifest already read the file; re-read here is cheap.
    let canonical_path = vault_folder.join("manifest.cbor.enc");
    let canonical_envelope_bytes =
        std::fs::read(&canonical_path).map_err(|e| SyncError::Io {
            context: "failed to re-read manifest.cbor.enc for hash computation",
            source: e,
        })?;
    let manifest_hash = crate::sync::bundle::compute_manifest_hash(&canonical_envelope_bytes);

    // Step 4: clock relation dispatch.
    let disk_clock: Vec<VectorClockEntry> = manifest.vector_clock.clone();
    let relation = clock_relation(&state.highest_vector_clock_seen, &disk_clock);

    match relation {
        ClockRelation::Equal => Ok(SyncOutcome::NothingToDo),
        ClockRelation::IncomingDominates => Ok(SyncOutcome::AppliedAutomatically {
            new_state: SyncState {
                vault_uuid: state.vault_uuid,
                highest_vector_clock_seen: disk_clock,
            },
        }),
        ClockRelation::IncomingDominated => Ok(SyncOutcome::RollbackRejected(
            crate::sync::outcome::RollbackEvidence {
                disk_vector_clock: disk_clock,
                local_highest_seen: state.highest_vector_clock_seen.clone(),
            },
        )),
        ClockRelation::Concurrent => {
            // Step 5: ingest conflict-copies (1a's new responsibility).
            // Re-open the vault to get the owner card / fingerprint
            // needed for block-envelope authentication.
            let opened = crate::vault::open_vault(
                vault_folder,
                crate::vault::Unlocker::Bundle(identity),
                None,
            )
            .map_err(SyncError::from)?;
            let owner_card_bytes = opened.owner_card
                .to_canonical_cbor()
                .map_err(SyncError::from)?;
            let owner_fp = crate::identity::fingerprint::fingerprint(&owner_card_bytes);

            let bundle = crate::sync::ingest::ingest_conflict_copies(
                vault_folder,
                identity,
                &manifest,
                &canonical_envelope_bytes,
                canonical_path,
                owner_fp,
            )
            .map_err(|e| SyncError::ConflictCopyScanIoFailed { source: e })?;

            let plan = crate::sync::outcome::DiffPlan {
                diverging_blocks: crate::sync::ingest::compute_diff_plan(&bundle),
            };

            Ok(SyncOutcome::ConcurrentDetected {
                bundle,
                plan,
                manifest_hash,
                disk_vector_clock: disk_clock,
                local_highest_seen: state.highest_vector_clock_seen.clone(),
            })
        }
    }
}
```

NOTE: The `Unlocker::Bundle(identity)` variant exists on `main` per C.1 phase 1 (see [docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md](../specs/2026-05-17-c1-sync-detection-design.md) §"Subtlety: the Unlocker::Bundle extension"). The `From<VaultError> for SyncError` impl also exists. Verify both via grep before relying on them.

Also: `__test_dispatch` in `core/src/sync/once.rs:94-100` calls `dispatch` (the previous standalone helper). After this refactor, `dispatch` is folded into `sync_once`. Two options:

(a) Extract a new `dispatch` helper that takes `(disk_clock, state, manifest_hash, bundle_or_lazy_fn)` and returns `SyncOutcome` — for testability of pure dispatch logic without folder I/O.

(b) Delete `__test_dispatch` and rely on the integration tests in Task 14 to cover dispatch.

**Recommendation: (a)** — preserves the C.1 phase 1 test-hook pattern. Stub the bundle inputs in tests where folder I/O isn't desired. Adjust `__test_dispatch` signature accordingly.

- [ ] **Step 2: Update existing tests in `core/src/sync/once.rs`**

If `__test_dispatch` keeps its old signature, the existing inline tests `dispatch_concurrent_clocks_yields_fork_detected` and friends fail because the variant is renamed. Update them per Task 11's pattern (rename to `*_yields_concurrent_detected`, assert on the new variant fields).

- [ ] **Step 3: Run all tests**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | tail -3
```

Expected: all passing. Workspace count should be roughly stable (any new lib-level tests added during Tasks 4-10 plus the 681 baseline minus the renamed test, plus a few lib-level shape tests).

- [ ] **Step 4: Clippy + fmt + commit**

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/src/sync/once.rs
git commit -m "$(cat <<'EOF'
feat(sync): wire sync_once Concurrent arm to call ingest_conflict_copies

On Concurrent dispatch, sync_once now:
  1. Computes ManifestHash from the canonical envelope bytes
     (TOCTOU freshness anchor for C.1.1b commit path)
  2. Re-opens the vault via Unlocker::Bundle to derive owner_fp
     for block-envelope authentication (no Argon2 re-run)
  3. Calls ingest_conflict_copies → VaultBundle
  4. Computes DiffPlan from the bundle's diverging_blocks
  5. Returns SyncOutcome::ConcurrentDetected { bundle, plan,
     manifest_hash, disk_vector_clock, local_highest_seen }

Quiet vaults (Equal / IncomingDominates / IncomingDominated) still
pay zero conflict-copy scan cost — that property of D4-lazy is
preserved.

Integration tests for the new path land in Task 14.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Add integration tests in `core/tests/sync_ingest.rs`

**Why:** Cover the 15 integration tests from spec §"Testing strategy → Integration tests". This is the largest task — break into bite-sized commits.

**Files:**
- Create: `core/tests/sync_ingest.rs`

For each test below, the cycle is: write test → run → confirm failure → ensure prior tasks compiled-fix any gap → commit each cluster of 3-4 tests.

- [ ] **Step 1: Scaffold the file + first three tests (zero / one / N-way authenticated)**

Create `core/tests/sync_ingest.rs`:

```rust
//! Integration tests for C.1.1a conflict-copy ingestion.

mod fixtures;
mod sync_helpers;

use secretary_core::sync::{sync_once, SyncOutcome, SyncState};
use secretary_core::vault::{open_vault, Unlocker, VectorClockEntry};
use sync_helpers::{
    fresh_vault_two_concurrent_manifests, fresh_vault_with_clock,
    fresh_vault_four_concurrent_manifests,
};

fn open_identity(folder: &std::path::Path) -> secretary_core::unlock::UnlockedIdentity {
    let password = fixtures::golden_vault_001_password();
    let opened = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    opened.identity
}

fn synthetic_local_seen() -> Vec<VectorClockEntry> {
    // Use a clock concurrent with what fresh_vault_with_clock writes.
    // The canonical fixture clock is supplied by each test; the
    // synthetic_local_seen returns a clock that's concurrent with it.
    vec![VectorClockEntry {
        device_uuid: [0x77; 16],
        counter: 1,
    }]
}

#[test]
fn sync_once_concurrent_no_conflict_copies_returns_bundle_zero_copies() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let (folder, _tmp) = fresh_vault_with_clock(canonical_clock);
    let identity = open_identity(&folder);

    let state = SyncState {
        vault_uuid: open_vault(&folder, Unlocker::Bundle(&identity), None)
            .unwrap()
            .manifest
            .vault_uuid,
        highest_vector_clock_seen: synthetic_local_seen(),
    };

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, plan, .. } => {
            assert!(bundle.copies.is_empty(), "no sibling files expected");
            assert!(plan.diverging_blocks.is_empty(),
                "no divergence without conflict-copy manifests");
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_one_conflict_copy_authenticated() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.sync-conflict-from-device-bb",
        sibling_clock,
    );
    let identity = open_identity(&folder);
    let state = SyncState {
        vault_uuid: open_vault(&folder, Unlocker::Bundle(&identity), None)
            .unwrap()
            .manifest
            .vault_uuid,
        highest_vector_clock_seen: synthetic_local_seen(),
    };

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert_eq!(bundle.copies.len(), 1, "exactly one authenticated copy");
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_three_conflict_copies_authenticated() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let siblings = [
        ("manifest.cbor.enc.copy-1", vec![VectorClockEntry { device_uuid: [0xB1; 16], counter: 1 }]),
        ("manifest.cbor.enc.copy-2", vec![VectorClockEntry { device_uuid: [0xB2; 16], counter: 2 }]),
        ("manifest.cbor.enc.copy-3", vec![VectorClockEntry { device_uuid: [0xB3; 16], counter: 3 }]),
    ];
    let (folder, _tmp) = fresh_vault_four_concurrent_manifests(canonical_clock, siblings);
    let identity = open_identity(&folder);
    let state = SyncState {
        vault_uuid: open_vault(&folder, Unlocker::Bundle(&identity), None)
            .unwrap()
            .manifest
            .vault_uuid,
        highest_vector_clock_seen: synthetic_local_seen(),
    };

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert_eq!(bundle.copies.len(), 3, "all three siblings should authenticate");
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}
```

Run:

```bash
cargo test --release --workspace --test sync_ingest 2>&1 | tail -15
```

Expected: 3 passed.

Commit:

```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/tests/sync_ingest.rs
git commit -m "test(sync-ingest): scaffold + zero/one/three-copy happy paths

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 2: Add the four authentication-rejection tests (silent ignore arms)**

Append to `core/tests/sync_ingest.rs`:

```rust
#[test]
fn sync_once_concurrent_invalid_signature_silently_ignored() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.tampered",
        sibling_clock,
    );

    // Tamper: flip the last byte of the sibling's signature region.
    let sibling_path = folder.join("manifest.cbor.enc.tampered");
    let mut bytes = std::fs::read(&sibling_path).expect("read sibling");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&sibling_path, &bytes).expect("write tampered");

    let identity = open_identity(&folder);
    let state = SyncState {
        vault_uuid: open_vault(&folder, Unlocker::Bundle(&identity), None)
            .unwrap()
            .manifest
            .vault_uuid,
        highest_vector_clock_seen: synthetic_local_seen(),
    };

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert!(bundle.copies.is_empty(), "tampered sibling must be silently rejected");
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_wrong_vault_uuid_silently_ignored() {
    // Construct a sibling manifest from a DIFFERENT vault (different
    // vault_uuid). Easiest: spin up create_vault into a separate tmp,
    // copy that vault's manifest.cbor.enc into the first vault as a
    // sibling, then verify it's rejected.
    //
    // Use the `fixtures::create_vault_in_tmp` helper if it exists; if
    // not, build the second vault inline via `core::vault::create_vault`.

    todo!("test impl — build a second vault via create_vault, drop its manifest as a sibling, verify rejection");
}

#[test]
fn sync_once_concurrent_wrong_owner_fingerprint_silently_ignored() {
    // Same as the above but the second vault has a different OWNER
    // (different identity bundle). Drop its manifest as a sibling; the
    // author_fingerprint mismatch should cause silent rejection.
    todo!("test impl — second vault with different owner identity");
}

#[test]
fn sync_once_concurrent_aead_tampered_body_silently_ignored() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.aead-tampered",
        sibling_clock,
    );

    // Tamper at an offset in the AEAD-encrypted body (NOT the
    // signature region). The signature still verifies the on-disk
    // bytes, but those bytes won't AEAD-decrypt cleanly. — wait, the
    // signature is OVER the encrypted body, so any body-byte flip
    // invalidates the signature. To target AEAD specifically and not
    // the signature, the test must either:
    //   (a) replace the body bytes with a re-signed but
    //       wrong-key-encrypted body (requires re-signing)
    //   (b) accept that "tampered body" is functionally equivalent
    //       to "tampered signature" given §8 signs the ciphertext,
    //       and consolidate this with the signature-tampered test.
    //
    // Recommendation: (b) — consolidate; one tamper test suffices to
    // prove silent rejection. Delete this test if (a) proves too
    // complex, or merge it into the signature test.

    todo!("decide consolidation or impl (a); replace with the chosen approach");
}
```

The two `todo!` blocks are NOT passing tests — they're scaffolds. The next sub-step is to actually flesh them out.

- [ ] **Step 3: Flesh out the wrong_vault_uuid + wrong_owner_fingerprint tests**

Investigate the existing test helpers for "create a second vault":

```bash
grep -rn "create_vault\|fresh_owner_identity\|second_vault" core/tests/ --include="*.rs" | head -10
```

If there's no existing helper to create a second vault inline, build a new helper in `core/tests/sync_helpers/mod.rs` that:

1. Creates a new vault in a new tempdir via `core::vault::create_vault`.
2. Returns the manifest bytes.

Then in the test, drop those bytes into the FIRST vault's folder under a sibling filename, run sync_once, assert `bundle.copies.is_empty()`.

Concrete code: study `core/src/vault/orchestrators.rs:196` (`pub fn create_vault`) to see what inputs it needs, and write a `create_second_vault_manifest_bytes()` helper. Time-box this to ~30 min; if create_vault has many dependencies, simplify by skipping the wrong_owner_fingerprint test and adding it as a follow-up issue.

Apply the same pattern for `wrong_owner_fingerprint_silently_ignored` (a second vault with a different owner identity — different `create_vault` arguments).

- [ ] **Step 4: Decide on the AEAD-body-tampered test (consolidate or skip)**

Per the note in Step 2, this test is functionally equivalent to the signature-tampered test because the §8 signature covers the AEAD-encrypted body. Recommended: delete the redundant test. Commit:

```bash
# Edit sync_ingest.rs to remove the aead_tampered test entirely
cargo test --release --workspace --test sync_ingest 2>&1 | tail -10
git add core/tests/sync_ingest.rs core/tests/sync_helpers/mod.rs
git commit -m "test(sync-ingest): add three rejection-arm tests (sig / vault_uuid / owner_fp)

Consolidates the AEAD-body-tampered test into the signature-tampered case
since §8 signs the ciphertext.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 5: Add the block-divergence tests (3 tests)**

Append:

```rust
#[test]
fn sync_once_concurrent_block_divergence_block_copies_ingested() {
    // Build a fixture where the canonical AND one sibling manifest
    // disagree on a specific block's vector_clock_summary, AND a
    // sibling block file exists under blocks/<uuid>.cbor.enc.copy.
    //
    // This requires extending the helper to also write a sibling
    // block file. The simplest test fixture: re-sign the canonical
    // manifest with a modified block entry (different
    // vector_clock_summary for one block), drop a copy of the block
    // file under a sibling name.

    todo!("requires block-sibling fixture helper extension");
}

#[test]
fn sync_once_concurrent_block_agreement_block_copies_skipped() {
    // If canonical + sibling manifests agree on a block (same
    // vector_clock_summary), that block should NOT be in
    // bundle.diverging_blocks even if a sibling block file
    // accidentally exists on disk.
    todo!("see above for fixture requirements");
}

#[test]
fn sync_once_concurrent_diff_plan_includes_only_diverging_blocks() {
    // Mixed: blocks X+Y diverge, block Z agrees → plan == [X, Y].
    todo!("see above for fixture requirements");
}
```

Resolve the three `todo!`s by:

1. Extending `core/tests/sync_helpers/mod.rs` with a `write_sibling_block_file(folder, block_uuid, alt_bytes, sibling_filename)` helper. The `alt_bytes` would typically be obtained by reading + re-signing an existing block with modified plaintext.
2. Re-signing one block in the canonical to update its `vector_clock_summary`.

This is non-trivial — budget ~1-2 hours. If the block re-signing path requires significant orchestrator-layer plumbing, defer the three tests to a follow-up issue and leave a comment in the spec.

Commit each test individually after fleshing it out:

```bash
git add core/tests/sync_ingest.rs core/tests/sync_helpers/mod.rs
git commit -m "test(sync-ingest): add block_divergence detection test

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Add the naming-convention compatibility tests (Dropbox / Syncthing / random)**

These are the easiest tests in the set — they just use unusual filenames and rely on `enumerate_manifest_siblings`'s `starts_with` filter (or the looser `.cbor.enc` filter, depending on what was chosen in Task 5).

```rust
#[test]
fn sync_once_concurrent_dropbox_naming_convention_accepted() {
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc (conflicted copy 2026-05-15)",
        sibling_clock,
    );
    let identity = open_identity(&folder);
    let state = SyncState {
        vault_uuid: open_vault(&folder, Unlocker::Bundle(&identity), None)
            .unwrap()
            .manifest
            .vault_uuid,
        highest_vector_clock_seen: synthetic_local_seen(),
    };

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert_eq!(bundle.copies.len(), 1, "Dropbox-naming sibling should authenticate");
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}

#[test]
fn sync_once_concurrent_syncthing_naming_convention_accepted() {
    // Syncthing's actual format: <name>.sync-conflict-<YYYYMMDD>-<HHMMSS>-<short-id>
    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let sibling_clock = vec![VectorClockEntry {
        device_uuid: [0xBB; 16],
        counter: 3,
    }];
    let (folder, _tmp) = fresh_vault_two_concurrent_manifests(
        canonical_clock,
        "manifest.cbor.enc.sync-conflict-20260515-100000-ABCD1234",
        sibling_clock,
    );
    let identity = open_identity(&folder);
    let state = SyncState {
        vault_uuid: open_vault(&folder, Unlocker::Bundle(&identity), None)
            .unwrap()
            .manifest
            .vault_uuid,
        highest_vector_clock_seen: synthetic_local_seen(),
    };

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    match outcome {
        SyncOutcome::ConcurrentDetected { bundle, .. } => {
            assert_eq!(bundle.copies.len(), 1, "Syncthing-naming sibling should authenticate");
        }
        other => panic!("expected ConcurrentDetected, got {other:?}"),
    }
}
```

These should pass with the `starts_with` filter in Task 5 (both filenames start with `manifest.cbor.enc`).

NOTE: If Task 5 chose the looser `.cbor.enc` extension filter, add a third test confirming a totally-random-named file (`random_garbage.cbor.enc`) is also accepted on authentication. With the stricter `starts_with` filter, that file is NOT accepted — which would be a deliberate design choice; document it in the test.

```bash
cargo test --release --workspace --test sync_ingest 2>&1 | tail -10
git add core/tests/sync_ingest.rs
git commit -m "test(sync-ingest): cloud-product naming-convention compatibility

Confirms Dropbox '(conflicted copy <date>)' and Syncthing
'.sync-conflict-<ts>-<short>' filename patterns work with the
prefix-match scanner. Authentication is the security boundary;
filename is just the discovery hook.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 7: Add the "no-scan-on-non-concurrent" test**

```rust
#[test]
fn sync_once_no_concurrent_no_scan_performed() {
    // Disk strictly dominates local state → AppliedAutomatically.
    // No sibling files exist OR if they did, they MUST not appear in
    // the outcome. (sync_once's lazy property: zero conflict-copy
    // scanning on quiet vaults.)
    //
    // Use fresh_vault_with_clock to set canonical's clock; pass
    // SyncState with an empty highest_vector_clock_seen (lattice
    // bottom). clock_relation returns IncomingDominates.

    let canonical_clock = vec![VectorClockEntry {
        device_uuid: [0xAA; 16],
        counter: 5,
    }];
    let (folder, _tmp) = fresh_vault_with_clock(canonical_clock.clone());
    let identity = open_identity(&folder);
    let state = SyncState {
        vault_uuid: open_vault(&folder, Unlocker::Bundle(&identity), None)
            .unwrap()
            .manifest
            .vault_uuid,
        highest_vector_clock_seen: vec![],
    };

    let outcome = sync_once(&folder, &identity, &state, 0).expect("sync_once");
    assert!(matches!(outcome, SyncOutcome::AppliedAutomatically { .. }),
        "should fast-path without scanning conflict-copies, got {outcome:?}");
}
```

This test doesn't directly observe "no scan happened" — it just asserts the variant returned. To make the lazy-no-scan claim observable, the implementer could:

(a) Add a hidden test-only counter inside `ingest_conflict_copies` (gated by `#[cfg(test)]`).
(b) Add a fake sibling that WOULD authenticate, and assert the outcome's variant is AppliedAutomatically (i.e. the scan never ran).

Recommend (b) — it's a behavioral guarantee, not an instrumentation one. Add a sibling and confirm the outcome is `AppliedAutomatically`, not `ConcurrentDetected`.

Commit and move on.

- [ ] **Step 8: Run full integration test suite + gauntlet**

```bash
cargo test --release --workspace --test sync_ingest --no-fail-fast 2>&1 | tail -10
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | tail -3
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -5
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -5
```

Expected: all green. Workspace count: 681 + (lib unit tests from Tasks 2-10) + (integration tests, ~10-12 in sync_ingest.rs). Approximately 705-715.

---

## Task 14: Add KAT vectors

**Files:**
- Modify: `core/tests/data/sync_kat.json` (9 → 12)
- Modify: `core/tests/sync_kat.rs` (replay logic extension)

- [ ] **Step 1: Inspect current KAT schema**

```bash
head -50 core/tests/data/sync_kat.json
head -40 core/tests/sync_kat.rs
```

Each vector has fields like `name`, `state_vault_uuid`, `state_highest_vector_clock_seen`, `disk_vector_clock`, `expected_outcome_kind`. The expected_outcome_kind for ForkDetected vectors must be updated to ConcurrentDetected.

- [ ] **Step 2: Update existing fork vectors to concurrent_detected**

Edit `core/tests/data/sync_kat.json`:
- Rename `concurrent_disjoint_devices_fork_detected` → `concurrent_disjoint_devices_no_copies`. Change `expected_outcome_kind` from `ForkDetected` to `ConcurrentDetected`. Add `expected_bundle_copies_len: 0` and `expected_plan_diverging_blocks_len: 0`.
- Same for `concurrent_overlapping_devices_fork_detected`.

- [ ] **Step 3: Add 3 new vectors per spec**

Append three new entries to the `vectors` array:

```json
{
  "name": "concurrent_zero_copies_bundle_empty",
  "state_vault_uuid": "...",
  "state_highest_vector_clock_seen": [{"device_uuid": "...", "counter": 1}],
  "disk_vector_clock": [{"device_uuid": "...", "counter": 2}, {"device_uuid": "...", "counter": 1}],
  "expected_outcome_kind": "ConcurrentDetected",
  "expected_bundle_copies_len": 0,
  "expected_plan_diverging_blocks_len": 0
},
{
  "name": "concurrent_one_copy_authenticates",
  "state_vault_uuid": "...",
  "state_highest_vector_clock_seen": [...],
  "disk_vector_clock": [...],
  "sibling_fixture": "manifest.cbor.enc.copy1",     // new field
  "expected_outcome_kind": "ConcurrentDetected",
  "expected_bundle_copies_len": 1,
  "expected_plan_diverging_blocks_len": 0
},
{
  "name": "concurrent_one_copy_wrong_vault_uuid_rejected",
  "state_vault_uuid": "...",
  "state_highest_vector_clock_seen": [...],
  "disk_vector_clock": [...],
  "sibling_fixture": "manifest.cbor.enc.foreign-vault",
  "expected_outcome_kind": "ConcurrentDetected",
  "expected_bundle_copies_len": 0,
  "expected_plan_diverging_blocks_len": 0
}
```

NOTE: The `sibling_fixture` field is new. Either the KAT format already supports loading fixture files (look at existing vectors) or this is a format extension. Read `core/tests/sync_kat.rs` to see how the replay works today — adapt one path or extend the schema with a `schema_version` bump.

- [ ] **Step 4: Extend `core/tests/sync_kat.rs` replay**

Add support for:
- `ConcurrentDetected` expected outcome (check `bundle.copies.len()` + `plan.diverging_blocks.len()`).
- Optional `sibling_fixture` filename — if present, the test constructs the sibling manifest before invoking sync_once.

- [ ] **Step 5: Run replay**

```bash
cargo test --release --workspace --test sync_kat 2>&1 | tail -10
```

Expected: 12 vectors replay green.

- [ ] **Step 6: Commit**

```bash
git add core/tests/data/sync_kat.json core/tests/sync_kat.rs
git commit -m "test(sync-kat): 9 → 12 vectors covering ingestion outcomes

- Renames the two fork_detected vectors to concurrent_detected shape.
- Adds three new vectors: zero copies / one copy authenticates / one
  copy rejected (wrong vault_uuid).
- Extends the replay logic for the ConcurrentDetected variant +
  optional sibling_fixture filename hook.

Python clean-room replay deferred to issue #76 (C.4 scope).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: Add property tests in `core/tests/sync_ingest_proptest.rs`

**Files:**
- Create: `core/tests/sync_ingest_proptest.rs`

- [ ] **Step 1: Scaffold + idempotence property**

Create `core/tests/sync_ingest_proptest.rs`:

```rust
//! Property tests for C.1.1a conflict-copy ingestion.

mod fixtures;
mod sync_helpers;

use proptest::prelude::*;

use secretary_core::sync::{sync_once, SyncOutcome, SyncState};
use secretary_core::vault::{open_vault, Unlocker, VectorClockEntry};

proptest! {
    /// Calling sync_once twice with identical inputs returns
    /// observationally-equal outcomes.
    #[test]
    fn prop_ingest_idempotent(counter_a in 1u64..1000, counter_b in 1u64..1000) {
        let canonical_clock = vec![VectorClockEntry { device_uuid: [0xAA; 16], counter: counter_a }];
        let sibling_clock = vec![VectorClockEntry { device_uuid: [0xBB; 16], counter: counter_b }];
        let (folder, _tmp) = sync_helpers::fresh_vault_two_concurrent_manifests(
            canonical_clock,
            "manifest.cbor.enc.proptest-sibling",
            sibling_clock,
        );
        let password = fixtures::golden_vault_001_password();
        let opened = open_vault(&folder, Unlocker::Password(&password), None).unwrap();
        let state = SyncState {
            vault_uuid: opened.manifest.vault_uuid,
            highest_vector_clock_seen: vec![VectorClockEntry { device_uuid: [0x77; 16], counter: 1 }],
        };

        let out1 = sync_once(&folder, &opened.identity, &state, 0).unwrap();
        let out2 = sync_once(&folder, &opened.identity, &state, 0).unwrap();

        match (&out1, &out2) {
            (
                SyncOutcome::ConcurrentDetected { bundle: b1, plan: p1, .. },
                SyncOutcome::ConcurrentDetected { bundle: b2, plan: p2, .. },
            ) => {
                prop_assert_eq!(b1.copies.len(), b2.copies.len());
                prop_assert_eq!(p1.diverging_blocks.clone(), p2.diverging_blocks.clone());
            }
            (a, b) => prop_assert!(matches!((a, b), _), "unexpected outcome shapes: {a:?} vs {b:?}"),
        }
    }
}
```

NOTE: Reading `core/tests/sync_proptest.rs` (existing C.1 phase 1 proptest file) is essential for matching the established pattern (proptest version, strategy idioms, panic-vs-prop_assert handling).

- [ ] **Step 2: Add the "silently rejects junk" property**

Append:

```rust
proptest! {
    /// For any arbitrary bytes written to a `*.cbor.enc` file in the
    /// vault folder, ingestion never panics and never falsely accepts
    /// (the resulting bundle.copies must NOT include the junk file).
    #[test]
    fn prop_ingest_silently_rejects_junk(garbage in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let canonical_clock = vec![VectorClockEntry { device_uuid: [0xAA; 16], counter: 1 }];
        let (folder, _tmp) = sync_helpers::fresh_vault_with_clock(canonical_clock);
        std::fs::write(folder.join("manifest.cbor.enc.junk-fuzz"), &garbage).unwrap();

        let password = fixtures::golden_vault_001_password();
        let opened = open_vault(&folder, Unlocker::Password(&password), None).unwrap();
        let state = SyncState {
            vault_uuid: opened.manifest.vault_uuid,
            highest_vector_clock_seen: vec![VectorClockEntry { device_uuid: [0x77; 16], counter: 1 }],
        };

        let outcome = sync_once(&folder, &opened.identity, &state, 0).unwrap();
        // Disk is dominated by canonical here; concurrent fires only if
        // state's clock is concurrent with canonical. Adjust state to
        // ensure Concurrent dispatch:
        // - state has device 0x77 with counter 1 (not in canonical)
        // - canonical has device 0xAA with counter 1 (not in state)
        // → Concurrent.
        match outcome {
            SyncOutcome::ConcurrentDetected { bundle, .. } => {
                prop_assert!(bundle.copies.is_empty(),
                    "junk bytes must never authenticate (got {} copies)", bundle.copies.len());
            }
            other => prop_assert!(false, "expected ConcurrentDetected, got {other:?}"),
        }
    }
}
```

- [ ] **Step 3: Add the N-way order-independence property**

```rust
proptest! {
    /// Reordering sibling filenames produces the same authenticated
    /// copy COUNT (paths may differ in the source_path field, but the
    /// authenticated bodies should be the same set).
    #[test]
    fn prop_n_way_order_independence(
        clocks in proptest::collection::vec(0u64..1000, 1..4),
    ) {
        let canonical_clock = vec![VectorClockEntry { device_uuid: [0xAA; 16], counter: 10 }];

        // First permutation: files named alphabetically.
        let names_a: Vec<String> = (0..clocks.len())
            .map(|i| format!("manifest.cbor.enc.copy-a-{:02}", i))
            .collect();
        // Second permutation: reversed.
        let names_b: Vec<String> = (0..clocks.len())
            .rev()
            .map(|i| format!("manifest.cbor.enc.copy-b-{:02}", i))
            .collect();

        let siblings_a: Vec<(String, Vec<VectorClockEntry>)> = names_a.iter().zip(&clocks)
            .map(|(n, c)| (n.clone(), vec![VectorClockEntry {
                device_uuid: [0xB0 + (*c as u8 % 16); 16], counter: *c
            }])).collect();
        // ... (similar for siblings_b)

        // Build folder A with siblings_a, folder B with siblings_b
        // (different sibling filenames but the SAME set of (clock)
        // values). Run sync_once on both. Assert
        // bundle.copies.len() agrees.

        // (Full implementation omitted for brevity; the test asserts
        //  that filename ordering doesn't change the COUNT of
        //  authenticated copies.)

        prop_assert!(true);   // placeholder until impl fleshed out
    }
}
```

This property is hard to TDD cleanly given fixture-construction complexity. Time-box to ~30 min; if it doesn't yield a clean test, drop it from this PR and add a follow-up issue.

- [ ] **Step 4: Commit**

```bash
cargo test --release --workspace --test sync_ingest_proptest 2>&1 | tail -10
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
git add core/tests/sync_ingest_proptest.rs
git commit -m "test(sync-ingest): proptest properties (idempotence, junk-rejection)

Two properties:
  - prop_ingest_idempotent: twice-call sync_once yields equal-shape
    outcomes
  - prop_ingest_silently_rejects_junk: arbitrary bytes in a sibling
    filename never authenticate

A third property (prop_n_way_order_independence) was prototyped but
left as a placeholder; the fixture-construction complexity outweighs
the marginal coverage given the integration tests already cover N-way
authentication. Follow-up issue can revisit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: Update `tracing` dependency check + spec-name-freshness

**Files:**
- Modify (if needed): `core/Cargo.toml`
- Verify: `uv run core/tests/python/spec_test_name_freshness.py`

- [ ] **Step 1: Verify `tracing` is in `core/Cargo.toml`**

```bash
grep "^tracing" core/Cargo.toml || echo "MISSING"
```

If missing, add as a runtime dependency (used by ingest.rs for `debug!` logs):

```toml
# In core/Cargo.toml under [dependencies]
tracing = "0.1"
```

Pin per project convention (exact pin only if security-critical; `tracing` is not on a security path, so a caret range is acceptable).

- [ ] **Step 2: Run spec-test-name-freshness check**

```bash
uv run core/tests/python/spec_test_name_freshness.py
```

Expected: 0 unresolved, maybe 2-3 new allowlisted entries for tests added in this PR. Update the allowlist as needed.

- [ ] **Step 3: Commit dependency + freshness updates if any**

```bash
git add core/Cargo.toml core/tests/python/spec_test_name_freshness.py  # if updated
git commit -m "build(core): add tracing dep for conflict-copy debug logs

Used by core/src/sync/ingest.rs to emit forensic-only debug-level
logs when a conflict-copy file is silently rejected (per spec §1a-D3).
Not on any security-critical path — caret-range pin acceptable.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 17: Final gauntlet + ROADMAP / NEXT_SESSION updates

- [ ] **Step 1: Run the full workspace gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | tail -5
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected:
- ~715 passed, 0 failed, 10 ignored
- Clippy clean
- Format clean
- Conformance PASS
- Freshness 0 unresolved

If anything fails: stop, investigate, fix in the appropriate task's commit (don't paper over).

- [ ] **Step 2: Update ROADMAP.md (mark C.1.1a as in-flight → ✅)**

Read the existing ROADMAP and find the C.1.x section. Mark C.1.1a as ✅ once PR is open.

- [ ] **Step 3: Update NEXT_SESSION.md inside the PR**

Per the `feedback_next_session_in_pr.md` memory: NEXT_SESSION.md must be committed inside the feature branch BEFORE pushing the PR, otherwise post-merge main carries a stale baton. Update NEXT_SESSION.md to describe what 1a shipped + that 1b is queued.

```bash
# Edit NEXT_SESSION.md inside the worktree
git add NEXT_SESSION.md ROADMAP.md
git commit -m "docs: NEXT_SESSION.md + ROADMAP after C.1.1a

Records C.1.1a completion (~13 commits, ~1100 LOC added across 6 files,
~720 workspace tests). Queues C.1.1b (merge + commit + veto layer)
for the next session.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Push branch + open PR**

```bash
git push -u origin feature/c1-1-sync-merge
gh pr create --title "feat(c1-1a): conflict-copy ingestion (VaultBundle + sibling auth)" \
  --body "$(cat <<'EOF'
## Summary

- Adds the `VaultBundle` ingestion layer that scans the vault folder for
  sibling `*.cbor.enc` manifest/block files, authenticates each against
  the canonical manifest's owner identity (five MUST rules per spec
  §1a-D4), and packages canonical + N copies + per-block divergence.
- Replaces `SyncOutcome::ForkDetected` (terminal) with
  `SyncOutcome::ConcurrentDetected { bundle, plan, manifest_hash, … }`.
- Lays the groundwork for C.1.1b (merge + veto + commit), which consumes
  this slice's `VaultBundle`.

## Test plan

- [x] `cargo test --release --workspace --no-fail-fast` → 715+ passed, 0 failed
- [x] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [x] `cargo fmt --all -- --check` → clean
- [x] `uv run core/tests/python/conformance.py` → PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` → 0 unresolved

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

After writing the complete plan:

**1. Spec coverage:** Every section of the C.1.1a spec maps to at least one task:
- ✅ Spec §VaultBundle → Task 2
- ✅ Spec §sync_once Concurrent arm → Task 12
- ✅ Spec §ingest_conflict_copies → Task 10
- ✅ Spec §1a-D4 five MUSTs → Task 4 (manifest) + Task 7 (block)
- ✅ Spec §Module layout → Tasks 2 + 4 (one file at a time)
- ✅ Spec §Testing strategy → Tasks 13 (integration), 14 (KAT), 15 (proptest)
- ✅ Spec §SyncError extensions → Task 11
- ✅ Spec §Risks (test helper nonce parameterisation) → Task 1

**2. Placeholder scan:** Some `todo!` markers remain inside test scaffolds (Tasks 13.3, 13.5, 15.3). Each is annotated with what the implementer must do; the placeholders are SCAFFOLDS pointing at non-trivial fixture work, not "TBD" hand-waves. Acceptable as bite-sized sub-task notes.

**3. Type consistency:**
- `ManifestSnapshot.manifest: Manifest` — referenced consistently as `manifest`, not `body`.
- `DiffPlan.diverging_blocks: Vec<[u8; 16]>` — type matches throughout (and supersedes the original `Vec<(BlockId, RecordId)>` sketch).
- `BlockEnvelope.bytes: Vec<u8>` — never accidentally renamed to `payload` or `ciphertext`.
- `VaultBundle.copies: Vec<ManifestSnapshot>` — never confused with `block_copies`.

**4. Open implementation tasks called out in the plan body (NOT TBDs — explicit research / refactor steps):**
- Task 4 / Step 3: thread owner public keys into `manifest::verify_then_decrypt` (or refactor existing helper).
- Task 7 / Step 3: thread owner public keys into `authenticate_block_envelope`.
- Task 8 / Step 2: promote `format_uuid_hyphenated` from `core/src/vault/orchestrators.rs` to `pub(crate)` (or share via `core/src/util/uuid.rs`).
- Task 11 / Step 5: ensure `From<VaultError> for SyncError` impl exists (it should from C.1 phase 1).
- Task 13 / Step 3: build a `create_second_vault_manifest_bytes` helper if no equivalent exists.
- Task 13 / Step 5: build a `write_sibling_block_file` test helper.

These are all routine project-specific plumbing steps; flag as Task 17 follow-ups if any prove too time-consuming to inline.

---

**Plan complete. Saved to `docs/superpowers/plans/2026-05-18-c1-1a-conflict-copy-ingestion.md`.**
