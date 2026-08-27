//! Unit tests for the manifest per-array / per-entry parsers (§4.2).
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].
//!
//! Each test below pins one array parser's duplicate-key rejection and
//! also drives `encode::encode_manifest` and `decode::decode_manifest` to
//! get its hand-built duplicate onto the wire.

use crate::vault::manifest::test_support::dummy_kdf_params;
use crate::vault::manifest::{
    decode_manifest, encode_manifest, Manifest, FORMAT_VERSION_V1, MANIFEST_VERSION_V1, SUITE_ID_V1,
};

use super::*;

#[test]
fn rejects_duplicate_device_uuid_in_vector_clock() {
    // Hand-build a manifest with two vector_clock entries sharing the
    // same device_uuid. We can NOT rely on encode_manifest to produce
    // duplicates (the input already needs to have them and the encode
    // path doesn't dedupe — but the canonical sort doesn't either).
    // The simplest path: just build the duplicate input, then invoke
    // encode_manifest and decode it.
    let dupe_dev = [0x33; UUID_LEN];
    let m = Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: vec![
            VectorClockEntry {
                device_uuid: dupe_dev,
                counter: 1,
            },
            VectorClockEntry {
                device_uuid: dupe_dev,
                counter: 2,
            },
        ],
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    };
    let bytes = encode_manifest(&m).expect("encode duplicates");
    let err = decode_manifest(bytes.expose())
        .expect_err("duplicate device_uuid must be rejected on decode");
    assert!(
        matches!(err, ManifestError::VectorClockDuplicateDevice),
        "expected VectorClockDuplicateDevice, got {err:?}"
    );
}

#[test]
fn rejects_duplicate_block_uuid() {
    let dupe = [0x77; UUID_LEN];
    let make_block = |suffix: u8| BlockEntry {
        block_uuid: dupe,
        block_name: format!("blk-{suffix}"),
        fingerprint: [suffix; BLOCK_FINGERPRINT_LEN],
        recipients: vec![[0xc1; UUID_LEN]],
        vector_clock_summary: Vec::new(),
        suite_id: SUITE_ID_V1,
        created_at_ms: 1,
        last_mod_ms: 2,
        unknown: BTreeMap::new(),
    };
    let m = Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: Vec::new(),
        blocks: vec![make_block(1), make_block(2)],
        trash: Vec::new(),
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    };
    let bytes = encode_manifest(&m).expect("encode duplicates");
    let err = decode_manifest(bytes.expose())
        .expect_err("duplicate block_uuid must be rejected on decode");
    assert!(
        matches!(err, ManifestError::DuplicateBlockUuid),
        "expected DuplicateBlockUuid, got {err:?}"
    );
}

#[test]
fn rejects_duplicate_trash_uuid() {
    // The manifest carries the most-recent tombstone per block_uuid only
    // (vault-format §7), so two trash entries sharing a block_uuid are
    // nonsensical — a sign of corruption or attack — and rejected on
    // decode, mirroring the `blocks` duplicate rule.
    let dupe = [0x88; UUID_LEN];
    let make_trash = |suffix: u8| TrashEntry {
        block_uuid: dupe,
        tombstoned_at_ms: u64::from(suffix),
        tombstoned_by: [0xd1; UUID_LEN],
        fingerprint: Some([suffix; BLOCK_FINGERPRINT_LEN]),
        purged_at_ms: None,
        unknown: BTreeMap::new(),
    };
    let m = Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: vec![make_trash(1), make_trash(2)],
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    };
    let bytes = encode_manifest(&m).expect("encode duplicates");
    let err = decode_manifest(bytes.expose())
        .expect_err("duplicate trash block_uuid must be rejected on decode");
    assert!(
        matches!(err, ManifestError::DuplicateTrashUuid),
        "expected DuplicateTrashUuid, got {err:?}"
    );
}
