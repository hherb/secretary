//! Unit tests for conflict-copy ingestion (moved verbatim from `ingest.rs`).

use super::*;

/// Synthesizes minimal owner public keys for the rejection-arm
/// tests. Zero-byte ML-DSA-65 PK would fail length validation, so
/// build one of the correct length; Ed25519 is fixed 32 bytes.
fn dummy_owner_keys() -> (Ed25519Public, MlDsa65Public) {
    let ed_pk: Ed25519Public = [0u8; 32];
    // ML-DSA-65 public key is 1952 bytes per spec; from_bytes
    // accepts any byte sequence of that length.
    let pq_pk_bytes = vec![0u8; 1952];
    let pq_pk = MlDsa65Public::from_bytes(&pq_pk_bytes).expect("dummy pq pk length");
    (ed_pk, pq_pk)
}

fn dummy_ibk() -> AeadKey {
    AeadKey::new([0u8; 32])
}

#[test]
fn authenticate_rejects_empty_bytes() {
    let (ed, pq) = dummy_owner_keys();
    let ibk = dummy_ibk();
    let result = authenticate_manifest_envelope(
        &[],
        PathBuf::from("/tmp/empty.cbor.enc"),
        [0u8; 16],
        [0u8; 16],
        &ed,
        &pq,
        &ibk,
    );
    assert!(result.is_none(), "empty bytes must not authenticate");
}

#[test]
fn authenticate_rejects_garbage_bytes() {
    let (ed, pq) = dummy_owner_keys();
    let ibk = dummy_ibk();
    let result = authenticate_manifest_envelope(
        b"this is not a manifest envelope, just ASCII",
        PathBuf::from("/tmp/garbage.cbor.enc"),
        [0u8; 16],
        [0u8; 16],
        &ed,
        &pq,
        &ibk,
    );
    assert!(result.is_none(), "garbage bytes must not authenticate");
}

#[test]
fn enumerate_manifest_siblings_returns_non_canonical_prefix_matches() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let folder = tmp.path();

    std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();
    std::fs::write(folder.join("manifest.cbor.enc.sibling-1"), b"sibling").unwrap();
    std::fs::write(
        folder.join("manifest.cbor.enc (conflicted copy 2026-05-15)"),
        b"dropbox-style",
    )
    .unwrap();
    std::fs::write(folder.join("vault.toml"), b"unrelated").unwrap();
    std::fs::write(folder.join("identity_bundle.cbor.enc"), b"also-unrelated").unwrap();

    let siblings = enumerate_manifest_siblings(folder).expect("scan");
    let names: Vec<String> = siblings
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    assert_eq!(siblings.len(), 2, "exactly 2 sibling matches");
    assert!(names.contains(&"manifest.cbor.enc.sibling-1".to_string()));
    assert!(names.contains(&"manifest.cbor.enc (conflicted copy 2026-05-15)".to_string()));
    assert!(!names.contains(&"manifest.cbor.enc".to_string()));
    assert!(!names.contains(&"vault.toml".to_string()));
    assert!(!names.contains(&"identity_bundle.cbor.enc".to_string()));
}

#[test]
fn enumerate_manifest_siblings_returns_empty_on_canonical_only_folder() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let folder = tmp.path();
    std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();
    std::fs::write(folder.join("vault.toml"), b"vault-config").unwrap();

    let siblings = enumerate_manifest_siblings(folder).expect("scan");
    assert!(siblings.is_empty(), "no siblings expected");
}

#[test]
fn compute_diff_plan_empty_bundle_returns_empty_vec() {
    let bundle = VaultBundle {
        canonical: ManifestSnapshot {
            manifest: empty_manifest(),
            raw_envelope_bytes: vec![0xCA, 0xFE],
            source_path: PathBuf::from("/tmp/canonical.cbor.enc"),
        },
        copies: vec![],
        diverging_blocks: BTreeMap::new(),
    };
    let plan = compute_diff_plan(&bundle);
    assert!(plan.is_empty());
}

#[test]
fn compute_diff_plan_returns_keys_in_ascending_order() {
    let mut diverging: BTreeMap<[u8; 16], BlockDivergence> = BTreeMap::new();
    diverging.insert(
        [0xBB; 16],
        BlockDivergence {
            canonical_envelope: BlockEnvelope {
                bytes: vec![],
                source_path: PathBuf::new(),
            },
            copy_envelopes: vec![],
        },
    );
    diverging.insert(
        [0xAA; 16],
        BlockDivergence {
            canonical_envelope: BlockEnvelope {
                bytes: vec![],
                source_path: PathBuf::new(),
            },
            copy_envelopes: vec![],
        },
    );
    let bundle = VaultBundle {
        canonical: ManifestSnapshot {
            manifest: empty_manifest(),
            raw_envelope_bytes: vec![],
            source_path: PathBuf::new(),
        },
        copies: vec![],
        diverging_blocks: diverging,
    };
    let plan = compute_diff_plan(&bundle);
    assert_eq!(plan, vec![[0xAA; 16], [0xBB; 16]]);
}

/// Construct a minimal Manifest for unit tests. Empty arrays are
/// trivially-sorted under the canonical-CBOR discipline.
fn empty_manifest() -> Manifest {
    use crate::vault::{KdfParamsRef, Manifest as M};
    M {
        manifest_version: 1,
        vault_uuid: [0u8; 16],
        format_version: 1,
        suite_id: 1,
        owner_user_uuid: [0u8; 16],
        kdf_params: KdfParamsRef {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 1,
            salt: [0u8; 32],
        },
        vector_clock: vec![],
        blocks: vec![],
        trash: vec![],
        unknown: std::collections::BTreeMap::new(),
    }
}

#[test]
fn enumerate_block_siblings_returns_uuid_prefix_matches() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let blocks_dir = tmp.path().join("blocks");
    std::fs::create_dir(&blocks_dir).unwrap();

    let uuid_a = [0xAA; 16];
    let uuid_b = [0xBB; 16];
    let hex_a = crate::vault::orchestrators::format_uuid_hyphenated(&uuid_a);
    let hex_b = crate::vault::orchestrators::format_uuid_hyphenated(&uuid_b);

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

#[test]
fn enumerate_block_siblings_missing_blocks_dir_returns_empty() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Intentionally do NOT create blocks/ subdir.
    let result = enumerate_block_siblings(tmp.path(), &[0xAA; 16]).expect("missing dir is OK");
    assert!(result.is_empty());
}

#[test]
fn authenticate_block_envelope_rejects_garbage_bytes() {
    let (ed, pq) = dummy_owner_keys();
    let result = authenticate_block_envelope(
        b"not a block envelope",
        PathBuf::from("/tmp/garbage.cbor.enc"),
        [0u8; 16],
        &ed,
        &pq,
    );
    assert!(result.is_none(), "garbage bytes must not authenticate");
}

#[test]
fn authenticate_block_envelope_rejects_empty_bytes() {
    let (ed, pq) = dummy_owner_keys();
    let result = authenticate_block_envelope(
        &[],
        PathBuf::from("/tmp/empty.cbor.enc"),
        [0u8; 16],
        &ed,
        &pq,
    );
    assert!(result.is_none(), "empty bytes must not authenticate");
}

#[test]
fn ingest_manifest_copies_empty_folder_returns_empty() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let folder = tmp.path();
    std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();

    let (ed, pq) = dummy_owner_keys();
    let ibk = dummy_ibk();
    let copies =
        ingest_manifest_copies(folder, [0u8; 16], [0u8; 16], &ed, &pq, &ibk).expect("scan ok");
    assert!(copies.is_empty(), "no siblings → no copies");
}

#[test]
fn ingest_manifest_copies_silently_drops_junk_siblings() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let folder = tmp.path();
    std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();
    std::fs::write(folder.join("manifest.cbor.enc.junk-1"), b"not a manifest").unwrap();
    std::fs::write(folder.join("manifest.cbor.enc.junk-2"), vec![0xFF; 200]).unwrap();

    let (ed, pq) = dummy_owner_keys();
    let ibk = dummy_ibk();
    let copies =
        ingest_manifest_copies(folder, [0u8; 16], [0u8; 16], &ed, &pq, &ibk).expect("scan ok");
    assert!(copies.is_empty(), "junk siblings must not authenticate");
}

#[test]
fn ingest_manifest_copies_skips_oversize_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let folder = tmp.path();
    std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();
    // 2 MiB > MAX_MANIFEST_SIZE — write efficiently via Vec::with_capacity.
    let oversize: Vec<u8> = vec![0xAA; 2 * 1024 * 1024];
    std::fs::write(folder.join("manifest.cbor.enc.oversize"), &oversize).unwrap();

    let (ed, pq) = dummy_owner_keys();
    let ibk = dummy_ibk();
    let copies =
        ingest_manifest_copies(folder, [0u8; 16], [0u8; 16], &ed, &pq, &ibk).expect("scan ok");
    assert!(
        copies.is_empty(),
        "oversize file must be skipped pre-decode"
    );
}

#[test]
fn enumerate_manifest_siblings_errors_when_folder_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join("does-not-exist");
    let result = enumerate_manifest_siblings(&missing);
    assert!(result.is_err(), "missing folder should yield io::Error");
}

#[test]
fn authenticate_rejects_short_bytes_below_header_size() {
    let (ed, pq) = dummy_owner_keys();
    let ibk = dummy_ibk();
    // Manifest header is at least 42 bytes per docs/vault-format.md §4.1;
    // a 10-byte input can't possibly decode.
    let result = authenticate_manifest_envelope(
        &[0xCB, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        PathBuf::from("/tmp/short.cbor.enc"),
        [0u8; 16],
        [0u8; 16],
        &ed,
        &pq,
        &ibk,
    );
    assert!(result.is_none(), "short bytes must not authenticate");
}
