//! Smoke tests for the helpers themselves; they run in every binary that
//! declares `mod sync_helpers`.

use super::*;

/// Smoke: rewriting a block in the temp vault produces a file
/// that decrypts back to the supplied (here: empty) record set
/// using the owner identity. Proves
/// [`rewrite_block_with_records`] + [`decrypt_block_using_open`]
/// agree on the wire format.
///
/// The cached `OpenVault` handle is taken BEFORE any rewrite so
/// that the cached manifest matches the on-disk block fingerprints
/// at open time (C.1.1b D6 — `open_vault` rejects any vault whose
/// manifest fingerprints disagree with the block bytes). Decryption
/// itself only consumes the IBK / identity / owner_card on the
/// handle, which are immune to block-byte changes.
#[test]
fn rewrite_block_with_records_round_trips() {
    let golden_clock = vec![VectorClockEntry {
        device_uuid: [9; SYNC_HELPERS_UUID_LEN],
        counter: 1,
    }];
    let (folder, _tmp) = fresh_vault_with_clock(golden_clock);

    let block_uuid = golden_vault_001_first_block_uuid(&folder);
    let new_records: Vec<secretary_core::vault::Record> = Vec::new();

    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");

    let new_fingerprint = rewrite_block_with_records(
        &folder,
        &open,
        block_uuid,
        new_records.clone(),
        &BLOCK_NONCE_E,
    );
    // Fingerprint must be a real BLAKE3-256 (non-zero with high
    // probability over fresh ciphertext); cheap sanity check that
    // we didn't silently return an all-zero placeholder.
    assert_ne!(new_fingerprint, [0u8; 32]);

    let block_path = block_file_path(&folder, &block_uuid);
    let bytes = std::fs::read(&block_path).expect("read block");
    let plaintext = decrypt_block_using_open(&open, &bytes).expect("decrypt");
    assert_eq!(plaintext.records, new_records);
    assert_eq!(plaintext.block_uuid, block_uuid);
}

/// After [`rewrite_block_with_records_and_update_manifest`] runs
/// once, the vault on disk opens cleanly: `verify_block_fingerprints`
/// (the C.1.1b D6 gate inside `open_vault`) sees the manifest's new
/// `BlockEntry.fingerprint` matches the rewritten block bytes. This
/// proves the helper actually re-signs the manifest in-process and
/// the canonical state is consistent post-rewrite — which is the
/// pre-condition every downstream merge-layer integration test
/// relies on.
#[test]
fn rewrite_block_and_update_manifest_round_trips_through_open_vault() {
    let initial_clock = vec![VectorClockEntry {
        device_uuid: [9; SYNC_HELPERS_UUID_LEN],
        counter: 1,
    }];
    let (folder, _tmp) = fresh_vault_with_clock(initial_clock);

    let block_uuid = golden_vault_001_first_block_uuid(&folder);
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");

    let device_a = [0x0A; SYNC_HELPERS_UUID_LEN];
    let post_rewrite_clock = vec![VectorClockEntry {
        device_uuid: device_a,
        counter: 2,
    }];
    let new_fp = rewrite_block_with_records_and_update_manifest(
        &folder,
        &open,
        block_uuid,
        Vec::new(),
        &BLOCK_NONCE_E,
        post_rewrite_clock.clone(),
        &CANONICAL_NONCE_A,
    );
    // Cheap sanity: BLAKE3-256 of a real encrypted block is
    // overwhelmingly unlikely to be all-zero.
    assert_ne!(new_fp, [0u8; 32]);

    // The D6 round-trip assertion: open_vault must succeed AND the
    // returned manifest must reflect both the new fingerprint and
    // the new top-level clock.
    let reopened = open_vault(&folder, Unlocker::Password(&password), None)
        .expect("post-rewrite open_vault must succeed");
    let entry = reopened
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("block still in manifest");
    assert_eq!(
        entry.fingerprint, new_fp,
        "manifest BlockEntry.fingerprint must match the rewritten block fingerprint"
    );
    assert_eq!(
        reopened.manifest.vector_clock, post_rewrite_clock,
        "manifest top-level vector_clock must reflect the helper's update"
    );
}

/// Passing the same 24-byte value for `block_seed` and
/// `manifest_nonce` must panic at the call site rather than silently
/// seeding two AEAD encryptions in the same vault with identical
/// material. The check is `assert_ne!` (not `debug_assert_ne!`) so
/// it survives `cargo test --release` — confirmed here by running
/// the panic-path under the project's standard release gauntlet.
#[test]
#[should_panic(expected = "block_seed and manifest_nonce must differ")]
fn rewrite_block_and_update_manifest_panics_on_shared_nonce() {
    let initial_clock = vec![VectorClockEntry {
        device_uuid: [9; SYNC_HELPERS_UUID_LEN],
        counter: 1,
    }];
    let (folder, _tmp) = fresh_vault_with_clock(initial_clock);
    let block_uuid = golden_vault_001_first_block_uuid(&folder);
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");

    let _ = rewrite_block_with_records_and_update_manifest(
        &folder,
        &open,
        block_uuid,
        Vec::new(),
        &BLOCK_NONCE_E,
        Vec::new(),
        &BLOCK_NONCE_E,
    );
}

/// Two rewrites with distinct seed nonces must produce distinct
/// on-disk bytes (and therefore distinct fingerprints). Proves
/// the per-rewrite ChaCha20Rng seeding actually delivers distinct
/// BCK + AEAD body nonces, so callers can rewrite multiple blocks
/// in the same vault without AEAD key+nonce reuse.
///
/// The cached `OpenVault` handle is taken before the first rewrite
/// — see `rewrite_block_with_records_round_trips` for the same
/// rationale (C.1.1b D6).
#[test]
fn rewrite_block_with_records_distinct_seeds_produce_distinct_ciphertexts() {
    let golden_clock = vec![VectorClockEntry {
        device_uuid: [9; SYNC_HELPERS_UUID_LEN],
        counter: 1,
    }];
    let (folder, _tmp) = fresh_vault_with_clock(golden_clock);
    let block_uuid = golden_vault_001_first_block_uuid(&folder);

    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");

    let fp_e = rewrite_block_with_records(&folder, &open, block_uuid, Vec::new(), &BLOCK_NONCE_E);
    let bytes_after_e = std::fs::read(block_file_path(&folder, &block_uuid)).expect("read");

    let fp_f = rewrite_block_with_records(&folder, &open, block_uuid, Vec::new(), &BLOCK_NONCE_F);
    let bytes_after_f = std::fs::read(block_file_path(&folder, &block_uuid)).expect("read");

    assert_ne!(
        fp_e, fp_f,
        "distinct seeds must yield distinct block fingerprints"
    );
    assert_ne!(
        bytes_after_e, bytes_after_f,
        "distinct seeds must yield distinct on-disk envelopes (AEAD uniqueness proof)"
    );
}

/// Smoke: [`fresh_vault_two_concurrent_blocks`] produces a vault
/// folder where:
///
/// 1. The canonical manifest opens cleanly via the standard
///    `open_vault` path (D6 fingerprint gate sees the canonical
///    block file matches `BlockEntry.fingerprint`).
/// 2. Both the canonical block file AND the sibling block file
///    exist on disk under the expected paths.
/// 3. The canonical manifest's BlockEntry for `block_uuid` carries
///    the canonical block's fingerprint + the supplied
///    `canonical_block_clock`.
/// 4. The two block files have distinct on-disk bytes (proves the
///    canonical vs sibling encryptions used distinct AEAD seeds).
/// 5. The SIBLING manifest decrypts cleanly under the same identity
///    and carries SIBLING-side data: its `BlockEntry` references the
///    sibling block's fingerprint + `sibling_block_clock`, and its
///    top-level `vector_clock` equals `sibling_manifest_clock`. This
///    rules out an accidental copy of canonical data into the
///    sibling manifest by `write_manifest_with_block_entry` — the
///    downstream Task 13 tests would catch a swap via
///    `plan.diverging_blocks` non-empty, but the failure mode would
///    point at `ingest_block_divergence`, not the fixture builder.
///
/// Acceptance for downstream Task 13 tests: this fixture produces
/// a per-block-divergent state that `sync_once` will detect as
/// concurrent AND `ingest_block_divergence` will include in
/// `bundle.diverging_blocks`.
#[test]
fn fresh_vault_two_concurrent_blocks_produces_consistent_canonical_with_sibling_on_disk() {
    use secretary_core::crypto::aead::AEAD_TAG_LEN;
    use secretary_core::vault::manifest::{decode_manifest_file, decrypt_manifest_body};

    let device_a = [0x0A; SYNC_HELPERS_UUID_LEN];
    let device_b = [0x0B; SYNC_HELPERS_UUID_LEN];

    let canonical_block_clock = vec![VectorClockEntry {
        device_uuid: device_a,
        counter: 1,
    }];
    let canonical_manifest_clock = canonical_block_clock.clone();
    let sibling_block_clock = vec![VectorClockEntry {
        device_uuid: device_b,
        counter: 1,
    }];
    let sibling_manifest_clock = sibling_block_clock.clone();

    // Discover the golden vault's first block_uuid via a throwaway
    // open. Using the same UUID for both canonical + sibling is
    // the per-block-divergent shape Task 13's tests require.
    let (probe_folder, _probe_tmp) = fresh_vault_with_clock(Vec::new());
    let block_uuid = golden_vault_001_first_block_uuid(&probe_folder);

    const SIBLING_MF_FILENAME: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
    const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";

    let (folder, _tmp) = fresh_vault_two_concurrent_blocks(
        block_uuid,
        Vec::new(),
        canonical_block_clock.clone(),
        canonical_manifest_clock,
        Vec::new(),
        sibling_block_clock.clone(),
        sibling_manifest_clock.clone(),
        SIBLING_MF_FILENAME,
        SIBLING_BLOCK_SUFFIX,
        1_000_000,
    );

    // D6 round-trip: the canonical manifest must open cleanly.
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None)
        .expect("canonical manifest must open after fixture build");
    let entry = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("block_uuid in canonical manifest");
    assert_eq!(
        entry.vector_clock_summary, canonical_block_clock,
        "canonical manifest must carry the fixture-supplied canonical_block_clock",
    );

    let canonical_path = block_file_path(&folder, &block_uuid);
    let sibling_path = canonical_path.with_file_name(format!(
        "{stem}{SIBLING_BLOCK_SUFFIX}",
        stem = canonical_path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8"),
    ));
    let canonical_bytes = std::fs::read(&canonical_path).expect("read canonical block");
    let sibling_bytes = std::fs::read(&sibling_path).expect("read sibling block");
    assert_ne!(
        canonical_bytes, sibling_bytes,
        "canonical and sibling block files must have distinct on-disk bytes",
    );

    // Decrypt + inspect the sibling manifest. Closes the gap where a
    // bug in [`write_manifest_with_block_entry`] could write
    // canonical data to both manifests — the downstream Task 13
    // tests rely on the sibling manifest carrying the sibling
    // fingerprint to drive `bundle.diverging_blocks` non-empty.
    let sibling_mf_bytes =
        std::fs::read(folder.join(SIBLING_MF_FILENAME)).expect("read sibling manifest");
    let sibling_mf =
        decode_manifest_file(&sibling_mf_bytes).expect("decode sibling manifest envelope");
    let mut ct_with_tag = Vec::with_capacity(sibling_mf.aead_ct.len() + AEAD_TAG_LEN);
    ct_with_tag.extend_from_slice(&sibling_mf.aead_ct);
    ct_with_tag.extend_from_slice(&sibling_mf.aead_tag);
    let sibling_body = decrypt_manifest_body(
        &sibling_mf.header,
        &ct_with_tag,
        &open.identity_block_key,
        &sibling_mf.aead_nonce,
    )
    .expect("decrypt sibling manifest body");

    assert_eq!(
        sibling_body.vector_clock, sibling_manifest_clock,
        "sibling manifest's top-level vector_clock must equal sibling_manifest_clock",
    );

    let sibling_entry = sibling_body
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .expect("block_uuid in sibling manifest");
    assert_eq!(
        sibling_entry.vector_clock_summary, sibling_block_clock,
        "sibling manifest's BlockEntry must reference sibling_block_clock, not canonical",
    );
    let sibling_fp = *secretary_core::crypto::hash::hash(&sibling_bytes).as_bytes();
    assert_eq!(
        sibling_entry.fingerprint, sibling_fp,
        "sibling manifest's BlockEntry.fingerprint must reference the sibling block file's bytes",
    );
    assert_ne!(
        sibling_entry.fingerprint, entry.fingerprint,
        "sibling manifest's BlockEntry.fingerprint must differ from canonical's",
    );
}
