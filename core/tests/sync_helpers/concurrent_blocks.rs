//! Two-manifest fixtures whose copies of one block diverge (canonical + sibling).

use super::*;

/// Per-block-divergent two-manifest fixture for C.1.1b Task 13's veto
/// tests. Writes BOTH a canonical block file (with `canonical_records`)
/// AND a sibling block file at
/// `blocks/<uuid>.cbor.enc<sibling_block_suffix>` (with `sibling_records`),
/// then re-signs the canonical manifest AND writes a sibling manifest
/// such that:
///
/// 1. The canonical manifest's `BlockEntry[block_uuid]` has
///    `fingerprint = BLAKE3(canonical_block_bytes)` and
///    `vector_clock_summary = canonical_block_clock`.
/// 2. The sibling manifest's `BlockEntry[block_uuid]` has
///    `fingerprint = BLAKE3(sibling_block_bytes)` and
///    `vector_clock_summary = sibling_block_clock`.
/// 3. Both manifests' top-level `vector_clock` are set per the
///    `*_manifest_clock` arguments.
///
/// This drives the C.1.1a ingest layer to emit a non-empty
/// `bundle.diverging_blocks` (because the canonical + sibling
/// `vector_clock_summary` for the same block_uuid are concurrent) and
/// `prepare_merge`'s [`crate::sync::parent_block_clock`] fingerprint
/// match to bind each block envelope to the correct manifest's
/// per-block clock.
///
/// The post-fixture vault opens cleanly: D6 only checks the CANONICAL
/// manifest's `BlockEntry.fingerprint` against the on-disk file at
/// `blocks/<uuid>.cbor.enc` — the sibling block file is invisible to
/// `verify_block_fingerprints`. The sibling manifest's claim of a
/// different fingerprint is fine because D6 doesn't inspect sibling
/// manifests.
///
/// Pre-condition: `block_uuid` MUST exist in `golden_vault_001`'s
/// manifest (caller obtains via [`golden_vault_001_first_block_uuid`]
/// for the single-block fixture, or knows the UUID a priori for a
/// fresh-built multi-block fixture).
///
/// Constraints on caller:
/// - `canonical_block_clock` and `sibling_block_clock` MUST be
///   concurrent (or sibling strictly dominate canonical) — otherwise
///   `ingest_block_divergence` skips this block and the bundle's
///   `diverging_blocks` is empty (same outcome as Task 9's smoke test).
/// - `canonical_manifest_clock` and `sibling_manifest_clock` MUST be
///   concurrent — otherwise `sync_once` returns a non-`ConcurrentDetected`
///   outcome and the merge pipeline never engages.
/// - `sibling_block_suffix` MUST start with a non-empty separator
///   (e.g. `".sync-conflict-from-device-bb"`) so the resulting filename
///   is recognized as a sibling by
///   [`crate::sync::enumerate_block_siblings`] (any filename strictly
///   starting with `<uuid>.cbor.enc` and not equal to it qualifies).
/// - `sibling_manifest_filename` MUST start with `"manifest.cbor.enc"`
///   for the same reason — see Task 8's existing helpers for the
///   convention.
///
/// `now_ms` is written into both blocks' `header.last_mod_ms` AND both
/// manifests' `BlockEntry.last_mod_ms` for the block_uuid (mirroring
/// `commit_with_decisions`'s step 5-6 production behavior at the
/// fixture level).
///
/// Returns `(folder, tmp)` — caller keeps `tmp` alive for the test scope.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn fresh_vault_two_concurrent_blocks(
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    canonical_records: Vec<secretary_core::vault::Record>,
    canonical_block_clock: Vec<VectorClockEntry>,
    canonical_manifest_clock: Vec<VectorClockEntry>,
    sibling_records: Vec<secretary_core::vault::Record>,
    sibling_block_clock: Vec<VectorClockEntry>,
    sibling_manifest_clock: Vec<VectorClockEntry>,
    sibling_manifest_filename: &str,
    sibling_block_suffix: &str,
    now_ms: u64,
) -> (PathBuf, tempfile::TempDir) {
    fresh_vault_two_concurrent_blocks_with_versions(
        block_uuid,
        canonical_records,
        canonical_block_clock,
        canonical_manifest_clock,
        V1_BLOCK_VERSIONS,
        sibling_records,
        sibling_block_clock,
        sibling_manifest_clock,
        sibling_manifest_filename,
        sibling_block_suffix,
        now_ms,
    )
}

/// [`fresh_vault_two_concurrent_blocks`], with the canonical block's
/// `(block_version, schema_version)` pair set by the caller (#761). The
/// sibling block carries [`V1_BLOCK_VERSIONS`].
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn fresh_vault_two_concurrent_blocks_with_versions(
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    canonical_records: Vec<secretary_core::vault::Record>,
    canonical_block_clock: Vec<VectorClockEntry>,
    canonical_manifest_clock: Vec<VectorClockEntry>,
    canonical_versions: (u32, u32),
    sibling_records: Vec<secretary_core::vault::Record>,
    sibling_block_clock: Vec<VectorClockEntry>,
    sibling_manifest_clock: Vec<VectorClockEntry>,
    sibling_manifest_filename: &str,
    sibling_block_suffix: &str,
    now_ms: u64,
) -> (PathBuf, tempfile::TempDir) {
    // Step 1: fresh copy of golden_vault_001 into a temp dir. The
    // canonical manifest's top-level clock is set to a placeholder
    // (we'll overwrite it in step 5); using an empty clock here means
    // the temp vault opens cleanly via the standard fresh helper.
    let (folder, tmp) = fresh_vault_with_clock(Vec::new());

    // Step 2: open the vault to cache identity material. The cached
    // handle drives both block encryptions AND both manifest re-signs
    // without ever re-reading disk during the fingerprint-inconsistent
    // window (mirrors the pattern in
    // [`rewrite_block_with_records_and_update_manifest`]).
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open_vault");

    // Step 3: encrypt the canonical block + sibling block in-process.
    // Both use the existing per-block name + created_at_ms from the
    // golden vault entry; the block_clock + records + AEAD seed vary
    // per envelope.
    let golden_entry = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .cloned()
        .expect("block_uuid not in golden manifest");

    let (canonical_fp, canonical_bytes) = encrypt_block_bytes_for_uuid(
        &open,
        block_uuid,
        canonical_records,
        canonical_block_clock.clone(),
        golden_entry.block_name.clone(),
        BTreeMap::new(),
        canonical_versions,
        golden_entry.created_at_ms,
        now_ms,
        &BLOCK_NONCE_E,
    );
    let (sibling_fp, sibling_bytes) = encrypt_block_bytes_for_uuid(
        &open,
        block_uuid,
        sibling_records,
        sibling_block_clock.clone(),
        golden_entry.block_name.clone(),
        BTreeMap::new(),
        V1_BLOCK_VERSIONS,
        golden_entry.created_at_ms,
        now_ms,
        &BLOCK_NONCE_F,
    );

    // Step 4: write both block files. Canonical goes to the
    // production path; sibling goes to the suffix path.
    let canonical_path = block_file_path(&folder, &block_uuid);
    if let Some(parent) = canonical_path.parent() {
        std::fs::create_dir_all(parent).expect("create_dir_all blocks/");
    }
    std::fs::write(&canonical_path, &canonical_bytes).expect("write canonical block");

    let sibling_path = canonical_path.with_file_name(format!(
        "{stem}{suffix}",
        stem = canonical_path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("canonical path utf-8"),
        suffix = sibling_block_suffix,
    ));
    std::fs::write(&sibling_path, &sibling_bytes).expect("write sibling block");

    // Step 5: build + sign the canonical manifest. Update its
    // BlockEntry.fingerprint / vector_clock_summary / last_mod_ms for
    // block_uuid; set the manifest-level vector_clock.
    write_manifest_with_block_entry(
        &folder,
        &open,
        MANIFEST_FILENAME,
        block_uuid,
        canonical_fp,
        canonical_block_clock,
        canonical_manifest_clock,
        now_ms,
        &CANONICAL_NONCE_A,
    );

    // Step 6: build + sign the sibling manifest. Same structure as
    // canonical but with sibling fingerprint + clocks, written to the
    // sibling filename.
    write_manifest_with_block_entry(
        &folder,
        &open,
        sibling_manifest_filename,
        block_uuid,
        sibling_fp,
        sibling_block_clock,
        sibling_manifest_clock,
        now_ms,
        &SIBLING_NONCE_B,
    );

    drop(open);
    (folder, tmp)
}
