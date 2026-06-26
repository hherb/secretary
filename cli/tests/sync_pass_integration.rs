//! End-to-end tests for [`secretary_cli::pipeline::sync_pass_pause_on_conflict`]
//! against a staged `golden_vault_001`-backed on-disk vault.
//!
//! Two safe-arm tests (`AppliedAutomatically`, `NothingToDo`) mirror the
//! `run_one` integration tests, and one pause-path test proves that a
//! concurrent state carrying a tombstone-vs-edit veto returns
//! [`SyncPassOutcome::ConflictsPending`] and writes **nothing** — neither
//! the caller's [`SyncState`] nor the on-disk conflicting block change.
//!
//! ## Fixture access
//!
//! `cli/tests/` reaches the golden vault through the workspace-relative
//! path `../core/tests/data/golden_vault_001/`. The `core/tests/`
//! `fixtures` + `sync_helpers` modules are per-test-binary (not
//! cross-crate), so this file rebuilds the minimum it needs — the
//! per-block-divergent veto fixture — using only the **public**
//! `secretary_core` API surface (`open_vault`, `encrypt_block`,
//! `sign_manifest`, …). That keeps the pause-path proof self-contained
//! in the cli crate without reaching into core-internal test helpers.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use secretary_cli::pipeline::{
    sync_pass_commit_decisions, sync_pass_inspect, sync_pass_pause_on_conflict, InspectOutcome,
    SyncPassOutcome,
};
use secretary_cli::state::{default_state_dir, load, save, state_file_path};
use secretary_core::crypto::secret::{SecretBytes, SecretString, Sensitive};
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::sync::{
    prepare_merge, sync_once, SyncError, SyncOutcome, SyncState, VetoDecision,
};
use secretary_core::unlock::{open_with_password, vault_toml, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{
    encode_block_file, encode_manifest_file, encrypt_block, format_uuid_hyphenated, open_vault,
    sign_manifest, BlockHeader, BlockPlaintext, ManifestHeader, OpenVault, RecipientPublicKeys,
    Record, RecordField, RecordFieldValue, Unlocker, FILE_KIND_BLOCK,
};
use zeroize::Zeroize as _;

// --- Harness helpers (mirrored from cli/tests/pipeline_integration.rs;
//     each tests/*.rs is its own binary so duplicating the block keeps
//     per-test isolation consistent with the repo pattern) ----------------

/// Filename of the golden-vault inputs JSON living alongside the
/// fixture directory; the password we need to drive `open_with_password`
/// is stored there.
const GOLDEN_INPUTS_FILENAME: &str = "golden_vault_001_inputs.json";

/// Filename of the golden vault folder under `core/tests/data/`.
const GOLDEN_VAULT_DIRNAME: &str = "golden_vault_001";

/// Filenames inside the vault folder.
const VAULT_TOML_FILENAME: &str = "vault.toml";
const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.enc";

/// Path to `core/tests/data/` rooted at the workspace root. The cli's
/// `CARGO_MANIFEST_DIR` is the `cli/` crate directory; one level up is
/// the workspace root.
fn core_test_data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate dir has a parent (workspace root)")
        .join("core")
        .join("tests")
        .join("data")
}

/// Recursively copy `src` into `dst`. Mirrors the helper pattern used
/// in `core/tests/sync_helpers/mod.rs` so each test owns its own
/// writable vault tempdir.
fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create_dir_all dst");
    for entry in fs::read_dir(src).expect("read_dir src") {
        let entry = entry.expect("dir entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().expect("file_type").is_dir() {
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("copy file");
        }
    }
}

/// Extract the password from `golden_vault_001_inputs.json`. We use a
/// lightweight string-scan rather than pulling in a `serde_json`
/// dev-dep just for this — `golden_vault_001_inputs.json` is a stable
/// fixture and the inputs schema is single-sourced in `core/tests/`.
fn golden_vault_password() -> SecretBytes {
    let raw = fs::read_to_string(core_test_data_dir().join(GOLDEN_INPUTS_FILENAME))
        .expect("golden_vault_001_inputs.json must exist");
    let needle = "\"password\":";
    let start = raw.find(needle).expect("password key present");
    let after_key = &raw[start + needle.len()..];
    let first_quote = after_key
        .find('"')
        .expect("opening quote after password key");
    let rest = &after_key[first_quote + 1..];
    let closing_quote = rest.find('"').expect("closing quote after password value");
    let password = &rest[..closing_quote];
    SecretBytes::new(password.as_bytes().to_vec())
}

/// Stage a fresh writable copy of `golden_vault_001/` into a tempdir
/// and unlock it. Returns the tempdir (keep alive for the test's
/// lifetime), the vault folder path inside it, the unlocked identity,
/// the password, and the vault's UUID.
fn stage_and_unlock_golden() -> (
    tempfile::TempDir,
    PathBuf,
    UnlockedIdentity,
    SecretBytes,
    [u8; 16],
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let vault_dir = tmp.path().join(GOLDEN_VAULT_DIRNAME);
    let golden_src = core_test_data_dir().join(GOLDEN_VAULT_DIRNAME);
    copy_dir_recursive(&golden_src, &vault_dir);

    let vault_toml_bytes = fs::read(vault_dir.join(VAULT_TOML_FILENAME)).expect("read vault.toml");
    let identity_bundle_bytes =
        fs::read(vault_dir.join(IDENTITY_BUNDLE_FILENAME)).expect("read identity.bundle.enc");

    let password = golden_vault_password();
    let identity = open_with_password(&vault_toml_bytes, &identity_bundle_bytes, &password)
        .expect("open_with_password on golden vault must succeed");

    let vt_str = std::str::from_utf8(&vault_toml_bytes).expect("vault.toml utf-8");
    let vt = vault_toml::decode(vt_str).expect("decode vault.toml");
    (tmp, vault_dir, identity, password, vt.vault_uuid)
}

// --- Safe-arm tests ----------------------------------------------------

#[test]
fn sync_pass_returns_applied_automatically_on_fresh_state() {
    let (_tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    let outcome = sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0)
        .expect("sync pass");
    assert_eq!(outcome, SyncPassOutcome::AppliedAutomatically);
    assert!(!state.highest_vector_clock_seen.is_empty());
}

#[test]
fn sync_pass_returns_nothing_to_do_on_second_call() {
    let (_tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();
    let mut state = SyncState::empty(vault_uuid);
    sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0).expect("first");
    let before = state.clone();
    let outcome = sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0)
        .expect("second");
    assert_eq!(outcome, SyncPassOutcome::NothingToDo);
    assert_eq!(state, before);
}

// --- Pause-path (veto) fixture, rebuilt from public secretary_core API --

/// Record UUID shared by both copies of the divergent block — the record
/// the canonical and sibling sides disagree on. `0xAA` repeated so it
/// stays readable in failing-test output. Reused by both divergence
/// fixtures (tombstone-veto and non-tombstone collision).
const CONFLICT_RECORD_UUID: [u8; 16] = [0xAA; 16];
/// Canonical-side device anchor (the LIVE local edit).
const CANONICAL_DEVICE_UUID: [u8; 16] = [0x0A; 16];
/// Sibling-side device anchor (the peer TOMBSTONE / concurrent edit).
const SIBLING_DEVICE_UUID: [u8; 16] = [0x0B; 16];
/// Local device anchor — distinct from canonical/sibling so the
/// caller's `SyncState` clock is `Concurrent` with the disk manifest
/// (the `sync_once` precondition for `ConcurrentDetected`).
const LOCAL_DEVICE_UUID: [u8; 16] = [0x0C; 16];
/// Live record `last_mod_ms`; strictly less than the peer tombstone
/// stamp so the per-record veto pass fires.
const LOCAL_LAST_MOD_MS: u64 = 100;
/// Peer tombstone timestamp; strictly greater than `LOCAL_LAST_MOD_MS`.
const DISK_TOMBSTONE_AT_MS: u64 = 200;
/// Sibling-side concurrent-edit timestamp for the *collision* fixture;
/// strictly greater than `LOCAL_LAST_MOD_MS` so field-level LWW resolves
/// to the sibling value (the winner/loser asymmetry that records a
/// `FieldCollision`). Distinct value from `DISK_TOMBSTONE_AT_MS` so the
/// two fixtures stay legible side by side.
const SIBLING_COLLISION_LAST_MOD_MS: u64 = 150;
/// The field both sides of the collision fixture edit concurrently — the
/// `record_id`/`field_names` assertion target for #192.
const COLLISION_FIELD_NAME: &str = "k";
/// Fixture build/commit timestamp.
const FIXTURE_NOW_MS: u64 = 1_000_000;
/// Sibling manifest filename — must start with `manifest.cbor.enc`.
const SIBLING_MANIFEST_FILENAME: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
/// Sibling block suffix — must start with a non-empty separator.
const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";

/// Two distinct 24-byte ChaCha20Rng seeds for the canonical + sibling
/// block envelopes, and two distinct manifest AEAD nonces. Distinct in
/// every byte to preserve AEAD key+nonce uniqueness within one tempdir
/// (see CLAUDE.md "Atomic-write contract").
const BLOCK_SEED_CANONICAL: [u8; 24] = [
    0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
    0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
];
const BLOCK_SEED_SIBLING: [u8; 24] = [
    0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F,
    0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F,
];
const MANIFEST_NONCE_CANONICAL: [u8; 24] = [
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34,
];
const MANIFEST_NONCE_SIBLING: [u8; 24] = [
    0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x09, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66,
    0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xED, 0xCB,
];

const MANIFEST_FILENAME: &str = "manifest.cbor.enc";

/// Canonical block file path: `blocks/<uuid-hyphenated>.cbor.enc`.
fn block_file_path(folder: &Path, block_uuid: &[u8; 16]) -> PathBuf {
    let uuid_hex = format_uuid_hyphenated(block_uuid);
    folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))
}

/// Build the LIVE local record carried by the canonical block.
fn live_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        COLLISION_FIELD_NAME.to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("local")),
            last_mod: LOCAL_LAST_MOD_MS,
            device_uuid: CANONICAL_DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: CONFLICT_RECORD_UUID,
        record_type: "kv".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms: LOCAL_LAST_MOD_MS,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

/// Build the TOMBSTONED peer record carried by the sibling block. Its
/// `tombstoned_at_ms` is strictly greater than the live record's
/// `last_mod_ms`, so `prepare_merge`'s per-record veto pass fires.
fn tombstoned_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        COLLISION_FIELD_NAME.to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("ignored")),
            last_mod: DISK_TOMBSTONE_AT_MS,
            device_uuid: SIBLING_DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: CONFLICT_RECORD_UUID,
        record_type: "kv".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms: DISK_TOMBSTONE_AT_MS,
        tombstone: true,
        tombstoned_at_ms: DISK_TOMBSTONE_AT_MS,
        unknown: BTreeMap::new(),
    }
}

/// Build the sibling-side **LIVE** record for the *collision* fixture: a
/// concurrent edit of the same field (`COLLISION_FIELD_NAME`) on the same
/// record UUID as `live_record`, but with a different value and a strictly
/// greater `last_mod`. Because both sides are live and hold the field with
/// differing values, the §11.3 field-level LWW merge picks the sibling
/// (higher `last_mod`) and records a `FieldCollision`; because neither side
/// tombstones, the per-record veto pass raises NO veto. This is the input
/// `stage_concurrent_veto_vault`'s tombstone sibling cannot produce (see the
/// `if tombstone` arm in `core/src/vault/conflict.rs`, which returns an empty
/// collision set), and is exactly what #190/#192 need.
fn collision_sibling_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        COLLISION_FIELD_NAME.to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("remote")),
            last_mod: SIBLING_COLLISION_LAST_MOD_MS,
            device_uuid: SIBLING_DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: CONFLICT_RECORD_UUID,
        record_type: "kv".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms: SIBLING_COLLISION_LAST_MOD_MS,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

/// Encrypt `records` into a block envelope for `block_uuid` under the
/// owner identity reachable from `open`, using `seed` as a deterministic
/// ChaCha20Rng seed (drives BCK + every AEAD nonce). Returns the
/// BLAKE3-256 fingerprint of the envelope + the encoded bytes. No I/O.
#[allow(clippy::too_many_arguments)]
fn encrypt_block_bytes(
    open: &OpenVault,
    block_uuid: [u8; 16],
    records: Vec<Record>,
    block_clock: Vec<VectorClockEntry>,
    block_name: String,
    created_at_ms: u64,
    last_mod_ms: u64,
    seed24: &[u8; 24],
) -> ([u8; 32], Vec<u8>) {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use secretary_core::crypto::kem::MlKem768Public;

    const BLOCK_VERSION_V1: u32 = 1;
    const SCHEMA_VERSION_V1: u32 = 1;

    let owner_card_bytes = open.owner_card.to_canonical_cbor().expect("card cbor");
    let owner_fp = fingerprint(&owner_card_bytes);
    let owner_pk_bundle = open.owner_card.pk_bundle_bytes().expect("pk bundle");
    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk =
        MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).expect("ml-dsa sk");

    let owner_ml_kem_pk =
        MlKem768Public::from_bytes(&open.owner_card.ml_kem_768_pk).expect("ml-kem pk");
    let recipient_keys = vec![RecipientPublicKeys {
        fingerprint: owner_fp,
        pk_bundle: &owner_pk_bundle,
        x25519_pk: &open.owner_card.x25519_pk,
        ml_kem_768_pk: &owner_ml_kem_pk,
    }];

    let header = BlockHeader {
        magic: secretary_core::version::MAGIC,
        format_version: secretary_core::version::FORMAT_VERSION,
        suite_id: secretary_core::version::SUITE_ID,
        file_kind: FILE_KIND_BLOCK,
        vault_uuid: open.manifest.vault_uuid,
        block_uuid,
        created_at_ms,
        last_mod_ms,
        vector_clock: block_clock,
    };
    let plaintext = BlockPlaintext {
        block_version: BLOCK_VERSION_V1,
        block_uuid,
        block_name,
        schema_version: SCHEMA_VERSION_V1,
        records,
        unknown: BTreeMap::new(),
    };

    let mut seed = [0u8; 32];
    seed[..24].copy_from_slice(seed24);
    let mut rng = ChaCha20Rng::from_seed(seed);

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
    .expect("encrypt_block");
    let bytes = encode_block_file(&block_file).expect("encode_block_file");
    let fp = *secretary_core::crypto::hash::hash(&bytes).as_bytes();
    (fp, bytes)
}

/// Re-sign a manifest from the cached `open`, replacing one
/// `BlockEntry`'s fingerprint / clock-summary / last_mod and the
/// top-level vector clock, and write it to `folder/filename`.
#[allow(clippy::too_many_arguments)]
fn write_manifest_with_block_entry(
    folder: &Path,
    open: &OpenVault,
    filename: &str,
    block_uuid: [u8; 16],
    block_fingerprint: [u8; 32],
    block_clock: Vec<VectorClockEntry>,
    manifest_clock: Vec<VectorClockEntry>,
    block_last_mod_ms: u64,
    manifest_nonce: &[u8; 24],
) {
    let mut manifest = open.manifest.clone();
    let idx = manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .expect("block_uuid present in cached manifest");
    manifest.blocks[idx].fingerprint = block_fingerprint;
    manifest.blocks[idx].vector_clock_summary = block_clock;
    manifest.blocks[idx].last_mod_ms = block_last_mod_ms;
    manifest.vector_clock = manifest_clock;

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
        &manifest,
        &open.identity_block_key,
        manifest_nonce,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )
    .expect("sign_manifest");

    let manifest_bytes = encode_manifest_file(&new_manifest_file).expect("encode_manifest_file");
    fs::write(folder.join(filename), &manifest_bytes).expect("write manifest");
}

/// Stage golden_vault_001 and force a per-block-divergent state: the
/// first block exists as a canonical copy (carrying `live_record`, LIVE at
/// t=100) and a sibling conflict-copy (carrying `sibling_records`), with the
/// canonical and sibling manifests carrying concurrent clocks. Returns the
/// tempdir, vault folder, unlocked identity, password, vault UUID, and the
/// divergent block's UUID.
///
/// The sibling records are the single axis the two divergence fixtures vary
/// on: `stage_concurrent_veto_vault` passes a TOMBSTONED record (→ veto),
/// `stage_concurrent_collision_vault` passes a LIVE concurrent field edit
/// (→ field collision, no veto). Everything else — block envelopes, manifest
/// re-signing, concurrent clocks, deterministic seeds — is shared.
fn stage_concurrent_vault_with_sibling(
    sibling_records: Vec<Record>,
) -> (
    tempfile::TempDir,
    PathBuf,
    UnlockedIdentity,
    SecretBytes,
    [u8; 16],
    [u8; 16],
) {
    let (tmp, vault_dir, identity, password, vault_uuid) = stage_and_unlock_golden();

    let canonical_block_clock = vec![VectorClockEntry {
        device_uuid: CANONICAL_DEVICE_UUID,
        counter: 1,
    }];
    let sibling_block_clock = vec![VectorClockEntry {
        device_uuid: SIBLING_DEVICE_UUID,
        counter: 1,
    }];

    let open = open_vault(&vault_dir, Unlocker::Password(&password), None).expect("open_vault");
    let golden_entry = open
        .manifest
        .blocks
        .first()
        .cloned()
        .expect("golden vault has at least one block");
    let block_uuid = golden_entry.block_uuid;

    let (canonical_fp, canonical_bytes) = encrypt_block_bytes(
        &open,
        block_uuid,
        vec![live_record()],
        canonical_block_clock.clone(),
        golden_entry.block_name.clone(),
        golden_entry.created_at_ms,
        FIXTURE_NOW_MS,
        &BLOCK_SEED_CANONICAL,
    );
    let (sibling_fp, sibling_bytes) = encrypt_block_bytes(
        &open,
        block_uuid,
        sibling_records,
        sibling_block_clock.clone(),
        golden_entry.block_name.clone(),
        golden_entry.created_at_ms,
        FIXTURE_NOW_MS,
        &BLOCK_SEED_SIBLING,
    );

    let canonical_path = block_file_path(&vault_dir, &block_uuid);
    if let Some(parent) = canonical_path.parent() {
        fs::create_dir_all(parent).expect("create_dir_all blocks/");
    }
    fs::write(&canonical_path, &canonical_bytes).expect("write canonical block");
    let sibling_path = canonical_path.with_file_name(format!(
        "{stem}{SIBLING_BLOCK_SUFFIX}",
        stem = canonical_path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("canonical path utf-8"),
    ));
    fs::write(&sibling_path, &sibling_bytes).expect("write sibling block");

    write_manifest_with_block_entry(
        &vault_dir,
        &open,
        MANIFEST_FILENAME,
        block_uuid,
        canonical_fp,
        canonical_block_clock.clone(),
        canonical_block_clock,
        FIXTURE_NOW_MS,
        &MANIFEST_NONCE_CANONICAL,
    );
    write_manifest_with_block_entry(
        &vault_dir,
        &open,
        SIBLING_MANIFEST_FILENAME,
        block_uuid,
        sibling_fp,
        sibling_block_clock.clone(),
        sibling_block_clock,
        FIXTURE_NOW_MS,
        &MANIFEST_NONCE_SIBLING,
    );
    drop(open);

    (tmp, vault_dir, identity, password, vault_uuid, block_uuid)
}

/// Tombstone-veto divergence: the sibling conflict-copy TOMBSTONES the record
/// the canonical side still holds live, so `prepare_merge`'s per-record veto
/// pass fires. The original D.1.13 fixture — thin wrapper over the shared
/// staging now that the sibling record is the only varying axis.
fn stage_concurrent_veto_vault() -> (
    tempfile::TempDir,
    PathBuf,
    UnlockedIdentity,
    SecretBytes,
    [u8; 16],
    [u8; 16],
) {
    stage_concurrent_vault_with_sibling(vec![tombstoned_record()])
}

/// Non-tombstone collision divergence: both sides hold the record LIVE and
/// edit the same field concurrently, so the merge resolves cleanly (zero
/// vetoes) while recording a `FieldCollision`. The fixture #190/#192 need.
fn stage_concurrent_collision_vault() -> (
    tempfile::TempDir,
    PathBuf,
    UnlockedIdentity,
    SecretBytes,
    [u8; 16],
    [u8; 16],
) {
    stage_concurrent_vault_with_sibling(vec![collision_sibling_record()])
}

/// The pause-path contract: a concurrent state whose merge raises a
/// tombstone veto returns `ConflictsPending` and writes NOTHING — the
/// caller's `SyncState` is byte-identical and the on-disk conflicting
/// block is unchanged.
#[test]
fn sync_pass_pauses_on_tombstone_veto_without_writing() {
    let (_tmp, vault_dir, identity, password, vault_uuid, block_uuid) =
        stage_concurrent_veto_vault();

    // Local clock references a device absent from both disk manifests so
    // `sync_once` classifies the disk state as Concurrent (not dominated).
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let mut state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");
    let state_before = state.clone();

    let block_path = block_file_path(&vault_dir, &block_uuid);
    let block_bytes_before = fs::read(&block_path).expect("read canonical block pre-pass");

    let outcome = sync_pass_pause_on_conflict(&vault_dir, &identity, &password, &mut state, 0)
        .expect("sync pass must return Ok (pause is not an error)");

    match outcome {
        SyncPassOutcome::ConflictsPending { veto_count } => assert!(veto_count >= 1),
        other => panic!("expected ConflictsPending, got {other:?}"),
    }
    assert_eq!(state, state_before, "pause must not advance state");

    let block_bytes_after = fs::read(&block_path).expect("read canonical block post-pass");
    assert_eq!(
        block_bytes_after, block_bytes_before,
        "pause must not rewrite the conflicting block"
    );
}

// --- Inspect-path (stateless call-1) tests -----------------------------

/// BLAKE3-256 over every file in `folder` (recursive), folding each
/// file's relative path then its bytes into one rolling hasher. The
/// path is folded so a rename — not just a content change — registers
/// as a difference. Iteration order is sorted (by full path) so the
/// digest is deterministic across `read_dir` orderings. Uses
/// `secretary_core::crypto::hash` (already a proven import in this test
/// binary) rather than adding a `blake3` dev-dependency.
fn hash_dir(folder: &Path) -> [u8; 32] {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(folder, &mut files);
    files.sort();
    let mut acc = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(folder)
            .expect("collected path is under folder");
        acc.extend_from_slice(rel.to_string_lossy().as_bytes());
        acc.push(0); // path/content separator
        acc.extend_from_slice(&fs::read(path).expect("read file for hash_dir"));
        acc.push(0); // record separator
    }
    *secretary_core::crypto::hash::hash(&acc).as_bytes()
}

/// Recursively collect every regular file under `folder` into `out`.
fn collect_files(folder: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(folder).expect("read_dir for hash_dir") {
        let entry = entry.expect("dir entry for hash_dir");
        let path = entry.path();
        if entry.file_type().expect("file_type for hash_dir").is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// The inspect contract: a concurrent state whose merge raises a
/// tombstone veto returns [`InspectOutcome::ConflictsPending`] carrying
/// the full draft detail (vetoes + collision summaries + the
/// manifest-hash freshness token) and writes NOTHING — every file under
/// the vault folder is byte-identical, and the caller's `SyncState` is
/// unchanged.
///
/// Collision note: the reused `stage_concurrent_veto_vault` fixture
/// stages a tombstone-vs-live divergence. `merge_record` returns an
/// empty `collisions` set whenever the merge resolves to a tombstone
/// (see `core/src/vault/conflict.rs` — the `if tombstone` arm), so this
/// fixture yields a veto but no field-level collision. The
/// `collisions`-population path is therefore left to be covered at the
/// bridge/desktop layer with a non-tombstone concurrent-edit fixture.
#[test]
fn inspect_returns_veto_detail_and_leaves_disk_untouched() {
    let (_tmp, vault_dir, identity, password, vault_uuid, _block_uuid) =
        stage_concurrent_veto_vault();

    // Local clock references a device absent from both disk manifests so
    // `sync_once` classifies the disk state as Concurrent (not dominated).
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let mut state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");
    let state_before = state.clone();

    let before = hash_dir(&vault_dir);

    let outcome = sync_pass_inspect(&vault_dir, &identity, &password, &mut state, 0)
        .expect("inspect must return Ok (a pending conflict is not an error)");

    match outcome {
        InspectOutcome::ConflictsPending {
            vetoes,
            collisions,
            manifest_hash,
        } => {
            assert!(!vetoes.is_empty(), "expected at least one veto");
            // `ManifestHash(pub [u8; 32])` — the freshness token is a
            // fixed-width digest; a non-empty fingerprint is the
            // contract the UI consumes.
            assert_eq!(manifest_hash.0.len(), 32);
            assert_ne!(
                manifest_hash.0, [0u8; 32],
                "manifest hash must be a real BLAKE3 digest, not the zero default"
            );
            // No field collision in this tombstone-vs-live fixture: the
            // merge resolves to a tombstone, whose `merge_record` arm
            // returns an empty collision set. Asserting that
            // `prepare_merge` actually POPULATES `collisions` needs a
            // non-tombstone concurrent-edit fixture — tracked in #192.
            let _ = collisions;
        }
        other => panic!("expected ConflictsPending, got {other:?}"),
    }

    assert_eq!(state, state_before, "inspect must not advance state");
    assert_eq!(
        hash_dir(&vault_dir),
        before,
        "inspect must not write to disk"
    );
}

/// #192: prove `prepare_merge` POPULATES `DraftMerge.collisions` on a
/// non-tombstone concurrent field edit — the path previously verified only
/// by compilation. The sibling concurrent edit
/// (`stage_concurrent_collision_vault`) keeps the record LIVE on both sides
/// and edits the same field, so `merge_block` emits a `FieldCollision` that
/// `prepare_merge` must thread onto the draft. This is the positive
/// counterpart to `inspect_returns_veto_detail_and_leaves_disk_untouched`,
/// whose tombstone fixture yields a veto but (per `merge_record`'s tombstone
/// arm) an empty collision set.
///
/// Asserts at the `prepare_merge` layer directly: the zero-veto draft also
/// distinguishes this CLEAN-merge path from the veto path, so a single test
/// pins both halves (`vetoes` empty AND `collisions` populated). The bridge
/// `MergedClean` projection of this same fixture is covered separately
/// (#190).
#[test]
fn prepare_merge_populates_collisions_on_concurrent_field_edit() {
    let (_tmp, vault_dir, identity, _password, vault_uuid, _block_uuid) =
        stage_concurrent_collision_vault();

    // Local clock references a device absent from both disk manifests so
    // `sync_once` classifies the disk state as Concurrent (not dominated) —
    // the precondition for reaching the merge layer at all.
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    let (bundle, plan) =
        match sync_once(&vault_dir, &identity, &state, 0).expect("sync_once must succeed") {
            SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
            other => panic!("expected ConcurrentDetected, got {other:?}"),
        };
    assert!(
        !plan.diverging_blocks.is_empty(),
        "the collision fixture must produce a diverging block"
    );

    let draft = prepare_merge(&vault_dir, &identity, &bundle, &plan).expect("prepare_merge");

    // Zero vetoes: the non-tombstone edit resolves cleanly. This is the
    // discriminator that proves we exercised the collision path, not the
    // veto path — without it a fixture regression to a tombstone could
    // silently pass the collision assertion as a no-op.
    assert!(
        draft.vetoes.is_empty(),
        "a non-tombstone concurrent edit must raise no veto, got {:?}",
        draft.vetoes
    );

    // The collision summary is populated with the exact record + field.
    assert_eq!(
        draft.collisions.len(),
        1,
        "exactly one record collided, got {:?}",
        draft.collisions
    );
    let summary = &draft.collisions[0];
    assert_eq!(
        summary.record_id, CONFLICT_RECORD_UUID,
        "collision summary must name the diverging record"
    );
    assert_eq!(
        summary.field_names,
        vec![COLLISION_FIELD_NAME.to_string()],
        "collision summary must name the concurrently-edited field"
    );
}

// --- Commit-decisions (stateless call-2) tests -------------------------

/// Build the canonical Concurrent-classifying `SyncState` for the
/// `stage_concurrent_veto_vault` fixture: a local clock referencing a
/// device absent from both disk manifests, so `sync_once` sees the disk
/// state as Concurrent (not dominated).
fn concurrent_state(vault_uuid: [u8; 16]) -> SyncState {
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    SyncState::new(vault_uuid, local_clock).expect("SyncState::new")
}

/// The call-2 happy path: inspect (call-1) yields a veto set + freshness
/// token; resolving every veto as `KeepLocal` and feeding that back to
/// `sync_pass_commit_decisions` lands `MergedClean`. A follow-up inspect
/// against the committed state no longer reports a pending conflict (the
/// conflict copies were consumed and the canonical record stayed live).
#[test]
fn commit_decisions_keep_local_keeps_record_live() {
    let (_tmp, vault_folder, identity, password, vault_uuid, _block_uuid) =
        stage_concurrent_veto_vault();
    let mut state = concurrent_state(vault_uuid);

    // Read the veto set + token from a clone of the state so the real
    // `state` stays at its pre-commit value to commit against below.
    let mut probe_state = state.clone();
    let (vetoes, manifest_hash) = match sync_pass_inspect(
        &vault_folder,
        &identity,
        &password,
        &mut probe_state,
        0,
    )
    .unwrap()
    {
        InspectOutcome::ConflictsPending {
            vetoes,
            manifest_hash,
            ..
        } => (vetoes, manifest_hash),
        other => panic!("expected ConflictsPending, got {other:?}"),
    };
    let decisions: Vec<VetoDecision> = vetoes
        .iter()
        .map(|v| VetoDecision::KeepLocal {
            record_id: v.record_id,
        })
        .collect();

    let outcome = sync_pass_commit_decisions(
        &vault_folder,
        &identity,
        &password,
        &mut state,
        manifest_hash,
        decisions,
        1,
    )
    .expect("commit must succeed");
    assert_eq!(outcome, SyncPassOutcome::MergedClean);

    // After committing the merge the conflict copies are consumed; a
    // fresh inspect against the advanced state no longer raises a veto.
    let follow_up = sync_pass_inspect(&vault_folder, &identity, &password, &mut state, 2)
        .expect("follow-up inspect must return Ok");
    assert!(
        !matches!(follow_up, InspectOutcome::ConflictsPending { .. }),
        "after KeepLocal commit the conflict must be resolved, got {follow_up:?}"
    );
}

/// The TOCTOU freshness gate: a stale (bytewise-flipped) freshness token
/// is rejected with `EvidenceStale` BEFORE any write — the vault folder
/// is byte-identical afterwards. Flipping a byte of a real derived token
/// simulates a concurrent writer having advanced the manifest between
/// call-1 and call-2 without depending on the exact on-disk layout.
#[test]
fn commit_decisions_stale_token_is_rejected() {
    let (_tmp, vault_folder, identity, password, vault_uuid, _block_uuid) =
        stage_concurrent_veto_vault();
    let mut state = concurrent_state(vault_uuid);

    let mut probe_state = state.clone();
    let (vetoes, manifest_hash) = match sync_pass_inspect(
        &vault_folder,
        &identity,
        &password,
        &mut probe_state,
        0,
    )
    .unwrap()
    {
        InspectOutcome::ConflictsPending {
            vetoes,
            manifest_hash,
            ..
        } => (vetoes, manifest_hash),
        other => panic!("expected ConflictsPending, got {other:?}"),
    };
    let decisions: Vec<VetoDecision> = vetoes
        .iter()
        .map(|v| VetoDecision::AcceptTombstone {
            record_id: v.record_id,
        })
        .collect();

    // Deliberately wrong expected token: flip one byte of the real one.
    let mut bad = manifest_hash.clone();
    bad.0[0] ^= 0xff;
    let before = hash_dir(&vault_folder);

    let err = sync_pass_commit_decisions(
        &vault_folder,
        &identity,
        &password,
        &mut state,
        bad,
        decisions,
        1,
    )
    .unwrap_err();
    assert!(matches!(err, SyncError::EvidenceStale), "got {err:?}");
    assert_eq!(hash_dir(&vault_folder), before, "no write on stale token");
}

/// Simulate a **real** concurrent writer advancing the canonical manifest
/// on disk between call-1 (inspect) and call-2 (commit): re-sign the same
/// logical manifest — same diverging block entry, same clocks — under a
/// fresh AEAD nonce. The envelope ciphertext (and therefore the recomputed
/// `manifest_hash` freshness token) changes, while the merge shape
/// `sync_once` reclassifies stays identical, so call-2 still reaches the
/// `ConcurrentDetected` freshness gate.
///
/// Reads the current block entry straight out of the on-disk canonical
/// manifest (rather than reconstructing the staging constants) so the
/// rewrite is a faithful no-op on merge semantics — only the bytes move.
/// The nonce is runtime-generated, not a literal, to avoid CodeQL's
/// `rust/hard-coded-cryptographic-value` sink rule (see CLAUDE.md
/// `feedback_test_crypto_random_not_hardcoded`).
fn rewrite_canonical_manifest_fresh_nonce(
    vault_folder: &Path,
    password: &SecretBytes,
    block_uuid: [u8; 16],
) {
    use rand::RngCore as _;

    let open = open_vault(vault_folder, Unlocker::Password(password), None)
        .expect("re-open vault for concurrent manifest rewrite");
    let entry = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .cloned()
        .expect("divergent block present in canonical manifest");

    let mut fresh_nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut fresh_nonce);

    write_manifest_with_block_entry(
        vault_folder,
        &open,
        MANIFEST_FILENAME,
        block_uuid,
        entry.fingerprint,
        entry.vector_clock_summary.clone(),
        open.manifest.vector_clock.clone(),
        entry.last_mod_ms,
        &fresh_nonce,
    );
}

/// Real-race counterpart to `commit_decisions_stale_token_is_rejected`.
/// That test flips a byte of the token to *simulate* staleness; this one
/// induces genuine staleness — a concurrent writer re-writes the canonical
/// manifest on disk between call-1 and call-2 — while the operator still
/// holds the **genuine, unmodified** call-1 token. The recomputed manifest
/// hash no longer matches it, so the freshness gate trips with
/// [`SyncError::EvidenceStale`] and writes nothing.
///
/// This is the wiring proof the byte-flip test cannot give: it shows the
/// gate compares the token against the *live recompute source*, not against
/// itself. An `expected != expected` bug (or one recomputing from a stale
/// cached value) would pass `commit_decisions_stale_token_is_rejected` yet
/// fail here.
#[test]
fn commit_decisions_real_concurrent_manifest_rewrite_is_rejected() {
    let (_tmp, vault_folder, identity, password, vault_uuid, block_uuid) =
        stage_concurrent_veto_vault();
    let mut state = concurrent_state(vault_uuid);
    let state_before = state.clone();

    // Call-1: obtain the GENUINE freshness token + veto set.
    let mut probe_state = state.clone();
    let (vetoes, genuine_token) = match sync_pass_inspect(
        &vault_folder,
        &identity,
        &password,
        &mut probe_state,
        0,
    )
    .unwrap()
    {
        InspectOutcome::ConflictsPending {
            vetoes,
            manifest_hash,
            ..
        } => (vetoes, manifest_hash),
        other => panic!("expected ConflictsPending, got {other:?}"),
    };
    let decisions: Vec<VetoDecision> = vetoes
        .iter()
        .map(|v| VetoDecision::AcceptTombstone {
            record_id: v.record_id,
        })
        .collect();

    // A concurrent writer races the disk forward between call-1 and
    // call-2: same merge shape, fresh manifest bytes.
    rewrite_canonical_manifest_fresh_nonce(&vault_folder, &password, block_uuid);
    let before = hash_dir(&vault_folder);

    // Call-2 with the GENUINE (not flipped) token now trips the gate.
    let err = sync_pass_commit_decisions(
        &vault_folder,
        &identity,
        &password,
        &mut state,
        genuine_token,
        decisions,
        1,
    )
    .unwrap_err();

    assert!(matches!(err, SyncError::EvidenceStale), "got {err:?}");
    assert_eq!(
        hash_dir(&vault_folder),
        before,
        "no write on a genuinely stale token (real concurrent rewrite)"
    );
    assert_eq!(
        state, state_before,
        "state must not advance when the freshness gate rejects"
    );
}

// --- Manual-smoke staging helper (#161) --------------------------------

/// Materialize the two-device tombstone-veto divergence into a *persistent*
/// vault folder the desktop dev app can open, so the D.1.15 conflict-
/// resolution UI can be smoke-tested on a single machine with no second
/// device and no network — the "divergence" is purely the canonical +
/// sibling conflict-copy files `stage_concurrent_veto_vault` already writes.
///
/// **A staged vault alone does not fire a veto.** `sync_once` only
/// classifies the disk as `ConcurrentDetected` (the arm that raises the
/// tombstone veto) when the caller's local `SyncState` is *concurrent*
/// with the on-disk vector clocks — neither dominates. The desktop app
/// loads that state from the platform sync cache
/// ([`default_state_dir`]); for a never-synced vault it's **empty**, so
/// the disk strictly dominates and the pass auto-applies (`it just
/// synced`, no modal). So this helper also seeds a concurrent `SyncState`
/// (a local device absent from both manifests, mirroring the
/// `inspect_returns_veto_detail_*` test) into that same cache, keyed by
/// the staged vault's uuid. The desktop's first "Sync now" then loads it
/// and the veto fires.
///
/// `#[ignore]` so it never runs in the normal suite (it would otherwise
/// require `SMOKE_OUT` and write to the platform cache). Invoke explicitly:
///
/// ```bash
/// SMOKE_OUT=/tmp/veto_smoke cargo test --release -p secretary-cli \
///   --test sync_pass_integration -- --ignored stage_smoke_vault --nocapture
/// ```
///
/// It clears `$SMOKE_OUT` (so a re-run starts clean), copies the staged
/// divergent golden vault into it, seeds the concurrent sync state, and
/// prints the folder path + unlock password + the seeded state-file path
/// (so it can be deleted afterward). Then `cd desktop && pnpm tauri dev`,
/// open that folder, and click "Sync now" → the resolution modal lists the
/// disputed record.
///
/// The printed password is the *golden test vault's* fixture password, not
/// a real secret — printing it here is intentional and smoke-only.
#[test]
#[ignore = "manual smoke staging helper; set SMOKE_OUT and run with --ignored --nocapture"]
fn stage_smoke_vault() {
    let dest = std::env::var("SMOKE_OUT").expect(
        "set SMOKE_OUT to the destination vault folder, e.g. \
         SMOKE_OUT=/tmp/veto_smoke cargo test ... -- --ignored stage_smoke_vault --nocapture",
    );
    let dest = PathBuf::from(dest);

    // Stage the divergence in a tempdir (kept alive via `_tmp` until the copy
    // below completes), then persist a clean copy to $SMOKE_OUT.
    let (_tmp, vault_dir, identity, password, vault_uuid, block_uuid) =
        stage_concurrent_veto_vault();

    if dest.exists() {
        fs::remove_dir_all(&dest).expect("clear existing SMOKE_OUT folder for a clean re-run");
    }
    copy_dir_recursive(&vault_dir, &dest);

    // Seed the concurrent sync state into the SAME platform cache the desktop
    // app reads (default_state_dir, keyed by vault_uuid). Local device 0x0C is
    // absent from both disk manifests, so sync_once sees the disk as Concurrent
    // and the merge raises the veto. Without this the app's empty state lets
    // the disk dominate and the pass auto-applies (no modal).
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");
    let state_dir = default_state_dir()
        .expect("platform data dir for the sync-state cache (the desktop app uses the same path)");
    save(&state_dir, &state).expect("seed concurrent sync state");
    let state_file = state_file_path(&state_dir, vault_uuid);

    // Self-check: reload the seeded state from disk (exactly the read path the
    // desktop takes) and confirm an inspect against the persisted vault fires
    // the veto — so the smoke can't silently "just sync" again. The
    // ConflictsPending arm writes nothing and advances no state, so this does
    // not consume the conflict copies or disturb the seeded state file.
    let mut reloaded = load(&state_dir, vault_uuid).expect("reload seeded state");
    let veto_count = match sync_pass_inspect(&dest, &identity, &password, &mut reloaded, 0)
        .expect("inspect on the staged vault")
    {
        InspectOutcome::ConflictsPending { vetoes, .. } => vetoes.len(),
        other => panic!(
            "self-check FAILED: expected ConflictsPending, got {other:?} — \
             the GUI would not fire a veto. Did the staged vault or seeded \
             state drift?"
        ),
    };

    let pw = String::from_utf8_lossy(password.expose()).into_owned();
    println!("\n=== D.1.15 conflict-resolution smoke vault staged ===");
    println!("  vault folder : {}", dest.display());
    println!("  password     : {pw}");
    println!("  vault uuid   : {}", format_uuid_hyphenated(&vault_uuid));
    println!("  disputed blk : {}", format_uuid_hyphenated(&block_uuid));
    println!("  seeded state : {}", state_file.display());
    println!("  self-check   : inspect fires ConflictsPending with {veto_count} veto(es) ✓");
    println!("\nNext: `cd desktop && pnpm tauri dev`, open the folder above, click \"Sync now\",");
    println!("enter the password, and resolve the tombstone veto in the modal.");
    println!("(After the smoke, delete the seeded state file above to leave no trace.)\n");
}

// --- Committed fixture generator (#187 Python round-trip) ---------------

/// Generator (run on demand, human-reviewed diff) for the committed
/// two-device divergence fixture consumed by the Python #187 round-trip
/// test. Reuses `stage_concurrent_veto_vault` + a seeded Concurrent
/// `SyncState`, self-validates that the pair yields `ConflictsPending`,
/// then copies the vault folder + the serialized state into
/// `core/tests/data/sync_conflict_fixture/`.
///
/// Run:
///   cargo test --release -p secretary-cli --test sync_pass_integration -- \
///       --ignored generate_sync_conflict_fixture --nocapture
///
/// Diff is human-reviewed before commit; expected diff is scoped to
/// `core/tests/data/sync_conflict_fixture/` and nothing else.
#[test]
#[ignore = "fixture generator; run with --ignored generate_sync_conflict_fixture --nocapture"]
fn generate_sync_conflict_fixture() {
    let (_tmp, vault_dir, identity, password, vault_uuid, _block_uuid) =
        stage_concurrent_veto_vault();

    // Seeded local clock: a device absent from both disk manifests -> the
    // disk state classifies as Concurrent and the merge raises a veto.
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    // Self-validate: the fixture must actually pause on a veto, else it is
    // not a valid ConflictsPending fixture. Inspect writes nothing.
    let mut probe = state.clone();
    match sync_pass_inspect(&vault_dir, &identity, &password, &mut probe, 0)
        .expect("inspect must return Ok")
    {
        InspectOutcome::ConflictsPending { vetoes, .. } => {
            assert!(!vetoes.is_empty(), "fixture must yield >=1 veto");
        }
        other => panic!("fixture did not pause on a veto: {other:?}"),
    }

    // Destination tree under core/tests/data/.
    let dest =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../core/tests/data/sync_conflict_fixture");
    let _ = fs::remove_dir_all(&dest);
    let vault_dest = dest.join("vault");
    let state_dest = dest.join("state");
    fs::create_dir_all(&state_dest).expect("create_dir_all state/");
    copy_dir_recursive_fixture(&vault_dir, &vault_dest);

    // Persist the seeded concurrent SyncState into state/ (the exact bytes
    // the Python test will load as its state_dir).
    secretary_cli::state::save(&state_dest, &state).expect("save SyncState");

    fs::write(
        dest.join("README.md"),
        "# sync_conflict_fixture (#187, generated)\n\n\
         Two-device divergence: `vault/` holds a canonical manifest + a sibling\n\
         conflict-copy manifest that tombstones a record the canonical side\n\
         still has live; `state/<uuid>.state.cbor` is a seeded SyncState whose\n\
         clock is Concurrent with both manifests. Loading `vault/` with password\n\
         \"correct horse battery staple\" and `state/` as the state dir makes\n\
         `sync_vault` return ConflictsPending (vetoes non-empty, collisions\n\
         empty — the tombstone merge yields no field collision; see #192).\n\n\
         Regenerate via: cargo test --release -p secretary-cli --test \
         sync_pass_integration -- --ignored generate_sync_conflict_fixture \
         --nocapture\n",
    )
    .expect("write fixture README");

    eprintln!("wrote sync_conflict_fixture to {}", dest.display());
}

/// Generator (run on demand, human-reviewed diff) for the committed
/// **clean-collision** divergence fixture consumed by the bridge-level #190
/// `MergedClean` test. Sibling of `generate_sync_conflict_fixture`, but the
/// sibling record is a LIVE concurrent field edit (not a tombstone), so the
/// merge resolves cleanly (zero vetoes, ≥1 field collision) → `MergedClean`.
///
/// **Validation is read-only.** Unlike the veto generator — whose
/// `sync_pass_inspect` self-check returns `ConflictsPending` and writes
/// nothing — a clean collision merge COMMITS (rewrites the block, advances
/// state). So this generator validates with the non-writing `sync_once` +
/// `prepare_merge` pair and copies the still-PRE-merge divergence. The bridge
/// test performs the actual merge against its own temp copy.
///
/// Run:
///   cargo test --release -p secretary-cli --test sync_pass_integration -- \
///       --ignored generate_sync_collision_fixture --nocapture
///
/// Diff is human-reviewed before commit; expected diff is scoped to
/// `core/tests/data/sync_collision_fixture/` and nothing else.
#[test]
#[ignore = "fixture generator; run with --ignored generate_sync_collision_fixture --nocapture"]
fn generate_sync_collision_fixture() {
    let (_tmp, vault_dir, identity, _password, vault_uuid, _block_uuid) =
        stage_concurrent_collision_vault();

    // Seeded local clock: a device absent from both disk manifests -> the
    // disk state classifies as Concurrent and the merge runs (cleanly).
    let local_clock = vec![VectorClockEntry {
        device_uuid: LOCAL_DEVICE_UUID,
        counter: 1,
    }];
    let state = SyncState::new(vault_uuid, local_clock).expect("SyncState::new");

    // Self-validate WITHOUT writing: sync_once must see Concurrent, and the
    // prepared draft must be the clean-collision shape (zero vetoes, ≥1
    // populated collision). prepare_merge does not commit, so the staged
    // divergence on disk is untouched and faithfully copyable below.
    let (bundle, plan) =
        match sync_once(&vault_dir, &identity, &state, 0).expect("sync_once must succeed") {
            SyncOutcome::ConcurrentDetected { bundle, plan, .. } => (bundle, plan),
            other => panic!("fixture is not Concurrent: {other:?}"),
        };
    let draft = prepare_merge(&vault_dir, &identity, &bundle, &plan).expect("prepare_merge");
    assert!(
        draft.vetoes.is_empty(),
        "collision fixture must raise no veto, got {:?}",
        draft.vetoes
    );
    assert!(
        !draft.collisions.is_empty(),
        "collision fixture must yield >=1 field collision"
    );

    // Destination tree under core/tests/data/.
    let dest =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../core/tests/data/sync_collision_fixture");
    let _ = fs::remove_dir_all(&dest);
    let vault_dest = dest.join("vault");
    let state_dest = dest.join("state");
    fs::create_dir_all(&state_dest).expect("create_dir_all state/");
    copy_dir_recursive_fixture(&vault_dir, &vault_dest);

    // Persist the seeded concurrent SyncState into state/ (the bytes the
    // bridge test loads as its state_dir, keyed by vault_uuid).
    secretary_cli::state::save(&state_dest, &state).expect("save SyncState");

    fs::write(
        dest.join("README.md"),
        "# sync_collision_fixture (#190, generated)\n\n\
         Two-device divergence: `vault/` holds a canonical manifest + a sibling\n\
         conflict-copy manifest. Both sides keep the same record LIVE and edit\n\
         the same field concurrently, so the merge resolves CLEANLY — zero\n\
         tombstone vetoes, but >=1 field-level LWW collision (informational).\n\
         `state/<uuid>.state.cbor` is a seeded SyncState whose clock is\n\
         Concurrent with both manifests. Loading `vault/` with password\n\
         \"correct horse battery staple\" and `state/` as the state dir makes\n\
         the bridge `sync_vault_in` return MergedClean (commits the merge,\n\
         advances + persists state, rewrites the block). Contrast\n\
         `sync_conflict_fixture` (#187), whose tombstone sibling yields\n\
         ConflictsPending instead.\n\n\
         Regenerate via: cargo test --release -p secretary-cli --test \
         sync_pass_integration -- --ignored generate_sync_collision_fixture \
         --nocapture\n",
    )
    .expect("write fixture README");

    eprintln!("wrote sync_collision_fixture to {}", dest.display());
}

/// Local recursive dir copy for the generator (test-only).
fn copy_dir_recursive_fixture(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive_fixture(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}
