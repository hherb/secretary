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

use secretary_cli::pipeline::{sync_pass_pause_on_conflict, SyncPassOutcome};
use secretary_core::crypto::secret::{SecretBytes, SecretString, Sensitive};
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::sync::SyncState;
use secretary_core::unlock::{open_with_password, vault_toml, UnlockedIdentity};
use secretary_core::vault::block::VectorClockEntry;
use secretary_core::vault::{
    encode_block_file, encode_manifest_file, encrypt_block, format_uuid_hyphenated, open_vault,
    sign_manifest, BlockHeader, BlockPlaintext, ManifestHeader, OpenVault, Record, RecordField,
    RecordFieldValue, RecipientPublicKeys, Unlocker, FILE_KIND_BLOCK,
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

/// Record UUID shared by both copies of the divergent block. `0xAA`
/// repeated so it stays readable in failing-test output.
const VETO_RECORD_UUID: [u8; 16] = [0xAA; 16];
/// Canonical-side device anchor (the LIVE local edit).
const CANONICAL_DEVICE_UUID: [u8; 16] = [0x0A; 16];
/// Sibling-side device anchor (the peer TOMBSTONE).
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
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("local")),
            last_mod: LOCAL_LAST_MOD_MS,
            device_uuid: CANONICAL_DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: VETO_RECORD_UUID,
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
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from("ignored")),
            last_mod: DISK_TOMBSTONE_AT_MS,
            device_uuid: SIBLING_DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: VETO_RECORD_UUID,
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
/// first block exists as a canonical copy (record LIVE at t=100) and a
/// sibling conflict-copy (same record TOMBSTONED at t=200), with the
/// canonical and sibling manifests carrying concurrent clocks. Returns
/// the tempdir, vault folder, unlocked identity, password, vault UUID,
/// and the divergent block's UUID.
fn stage_concurrent_veto_vault() -> (
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
        vec![tombstoned_record()],
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
