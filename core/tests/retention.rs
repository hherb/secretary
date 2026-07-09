//! Integration test for the #402 retention auto-purge orchestrator.
//!
//! Mirrors the fixture pattern from `core/tests/purge.rs` (`fast_kdf`,
//! `make_fast_vault`, the open/save_block/trash_block sequence) — no shared
//! test-helper crate exists, so this file duplicates the same minimal
//! subset `purge.rs` needs.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::unlock::{create_vault_unchecked, mnemonic::Mnemonic, vault_toml};
use secretary_core::vault::{
    auto_purge_expired, empty_trash, encode_manifest_file, expired_trash_entries, open_vault,
    save_block, sign_manifest, trash_block, BlockEntry, BlockPlaintext, KdfParamsRef, Manifest,
    ManifestHeader, OpenVault, TrashEntry, Unlocker,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture helpers — duplicated from core/tests/purge.rs (see that file's
// header note: no shared test-helper crate exists yet).
// ---------------------------------------------------------------------------

fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

fn format_uuid_hyphenated(uuid: &[u8; 16]) -> String {
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

fn make_fast_vault(seed: u8, display_name: &str) -> (tempfile::TempDir, Mnemonic, SecretBytes) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    // Derive the vault password from the seeded RNG rather than a
    // hard-coded literal (feedback_test_crypto_random_not_hardcoded).
    let mut pw_bytes = [0u8; 16];
    rng.fill_bytes(&mut pw_bytes);
    let pw = SecretBytes::new(pw_bytes.to_vec());
    let created_at_ms = 1_714_060_800_000u64;
    let created =
        create_vault_unchecked(&pw, display_name, created_at_ms, fast_kdf(), &mut rng).unwrap();

    let vt = vault_toml::decode(std::str::from_utf8(&created.vault_toml_bytes).unwrap()).unwrap();

    let pq_sk = MlDsa65Secret::from_bytes(created.identity.ml_dsa_65_sk.expose()).unwrap();
    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: created.identity.user_uuid,
        display_name: created.identity.display_name.clone(),
        x25519_pk: created.identity.x25519_pk,
        ml_kem_768_pk: created.identity.ml_kem_768_pk.clone(),
        ed25519_pk: created.identity.ed25519_pk,
        ml_dsa_65_pk: created.identity.ml_dsa_65_pk.clone(),
        created_at_ms: created.identity.created_at_ms,
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    card.sign(&created.identity.ed25519_sk, &pq_sk).unwrap();
    let owner_card_bytes = card.to_canonical_cbor().unwrap();
    let author_fp = fingerprint(&owner_card_bytes);

    let manifest_body = Manifest {
        manifest_version: 1,
        vault_uuid: vt.vault_uuid,
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        owner_user_uuid: created.identity.user_uuid,
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: KdfParamsRef {
            memory_kib: vt.kdf.memory_kib,
            iterations: vt.kdf.iterations,
            parallelism: vt.kdf.parallelism,
            salt: vt.kdf.salt,
        },
        unknown: BTreeMap::new(),
    };
    let header = ManifestHeader {
        vault_uuid: vt.vault_uuid,
        created_at_ms,
        last_mod_ms: created_at_ms,
    };
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);

    let mf = sign_manifest(
        header,
        &manifest_body,
        &created.identity_block_key,
        &nonce,
        author_fp,
        &created.identity.ed25519_sk,
        &pq_sk,
    )
    .unwrap();
    let mf_bytes = encode_manifest_file(&mf).unwrap();

    let owner_uuid_hex = format_uuid_hyphenated(&created.identity.user_uuid);
    let contacts_dir = dir.path().join("contacts");
    fs::create_dir_all(&contacts_dir).unwrap();
    fs::write(dir.path().join("vault.toml"), &created.vault_toml_bytes).unwrap();
    fs::write(
        dir.path().join("identity.bundle.enc"),
        &created.identity_bundle_bytes,
    )
    .unwrap();
    fs::write(
        contacts_dir.join(format!("{owner_uuid_hex}.card")),
        &owner_card_bytes,
    )
    .unwrap();
    fs::write(dir.path().join("manifest.cbor.enc"), &mf_bytes).unwrap();

    (dir, created.recovery_mnemonic, pw)
}

fn make_simple_plaintext(block_uuid: [u8; 16], block_name: &str) -> BlockPlaintext {
    BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: block_name.to_string(),
        schema_version: 1,
        records: Vec::new(),
        unknown: BTreeMap::new(),
    }
}

/// Build a fresh vault, unlock it, and stage two owner-only trashed
/// blocks: `old_uuid` trashed at `old_tombstoned_ms`, `new_uuid` trashed at
/// `new_tombstoned_ms`. Returns the vault's temp dir (kept alive), the open
/// vault, the device uuid used throughout, and an RNG positioned to
/// continue the scenario (e.g. straight into `auto_purge_expired`).
fn stage_two_trashed_blocks(
    old_uuid: [u8; 16],
    old_tombstoned_ms: u64,
    new_uuid: [u8; 16],
    new_tombstoned_ms: u64,
) -> (
    tempfile::TempDir,
    OpenVault,
    [u8; 16],
    ChaCha20Rng,
    SecretBytes,
) {
    let (dir, _mnemonic, pw) = make_fast_vault(60, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x60; 32]);

    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0x61; 16];
    let recipients = vec![open.owner_card.clone()];

    save_block(
        folder,
        &mut open,
        make_simple_plaintext(old_uuid, "old"),
        &recipients,
        device_uuid,
        500,
        &mut rng,
    )
    .unwrap();
    trash_block(
        folder,
        &mut open,
        old_uuid,
        device_uuid,
        old_tombstoned_ms,
        &mut rng,
    )
    .unwrap();

    save_block(
        folder,
        &mut open,
        make_simple_plaintext(new_uuid, "fresh"),
        &recipients,
        device_uuid,
        9_900,
        &mut rng,
    )
    .unwrap();
    trash_block(
        folder,
        &mut open,
        new_uuid,
        device_uuid,
        new_tombstoned_ms,
        &mut rng,
    )
    .unwrap();

    (dir, open, device_uuid, rng, pw)
}

/// True iff no `trash/<uuid_hex>.cbor.enc.<tombstoned_at_ms>` file exists
/// for `block_uuid` at that exact stamp.
fn trash_file_absent(folder: &Path, block_uuid: [u8; 16], tombstoned_at_ms: u64) -> bool {
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let path = folder
        .join("trash")
        .join(format!("{uuid_hex}.cbor.enc.{tombstoned_at_ms}"));
    !path.exists()
}

/// Re-open the vault at `folder` with `pw` and assert it succeeds — proves
/// the signed manifest written by `auto_purge_expired` still verifies.
fn reopen_ok(folder: &Path, pw: &SecretBytes) {
    open_vault(folder, Unlocker::Password(pw), None).unwrap();
}

// ---------------------------------------------------------------------------
// auto_purge_expired — Task 4
// ---------------------------------------------------------------------------

/// The OLD block (age 9_000 > window 100) is purged; the FRESH block (age
/// 50 < window 100) is left untouched. Proves both the age-filtered
/// selection and the batch-commit write via `purge_batch_commit`.
#[test]
fn auto_purge_expired_purges_old_keeps_fresh() {
    let old_uuid = [0xA1; 16];
    let new_uuid = [0xB2; 16];
    let (dir, mut open, device, mut rng, pw) =
        stage_two_trashed_blocks(old_uuid, 1_000, new_uuid, 9_950);
    let folder = dir.path();

    let window_ms = 100;
    let now_ms = 10_000;
    let report =
        auto_purge_expired(folder, &mut open, window_ms, now_ms, device, &mut rng).unwrap();

    assert_eq!(report.purged_count, 1, "only the OLD block is purged");
    assert_eq!(report.window_ms, window_ms);
    assert_eq!(report.owner_only_count, 1);
    assert_eq!(report.shared_count, 0);
    assert_eq!(report.unknown_count, 0);
    assert!(report.files_removed >= 1);

    // OLD: purged_at_ms set + trash file gone.
    let old = open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == old_uuid)
        .unwrap();
    assert!(old.purged_at_ms.is_some(), "OLD marked purged");
    assert!(
        trash_file_absent(folder, old_uuid, 1_000),
        "OLD ciphertext removed"
    );

    // FRESH: untouched.
    let fresh = open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == new_uuid)
        .unwrap();
    assert!(fresh.purged_at_ms.is_none(), "FRESH not purged");
    assert!(
        !trash_file_absent(folder, new_uuid, 9_950),
        "FRESH ciphertext retained"
    );

    // Signed manifest still verifies after the write: re-open the vault.
    reopen_ok(folder, &pw);
}

/// Empty target set (nothing trashed) must return a zero-count report that
/// still echoes `window_ms`, WITHOUT touching the manifest at all.
#[test]
fn auto_purge_expired_on_empty_target_set_is_noop_no_resign() {
    let (dir, _mnemonic, pw) = make_fast_vault(62, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x62; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let device_uuid = [0x63; 16];

    let manifest_file_before = open.manifest_file.clone();
    let manifest_before = open.manifest.clone();

    let report = auto_purge_expired(folder, &mut open, 100, 10_000, device_uuid, &mut rng)
        .expect("empty target set must not error");

    assert_eq!(report.purged_count, 0);
    assert_eq!(report.shared_count, 0);
    assert_eq!(report.owner_only_count, 0);
    assert_eq!(report.unknown_count, 0);
    assert_eq!(report.files_removed, 0);
    assert_eq!(report.files_failed, 0);
    assert_eq!(report.window_ms, 100, "window_ms is echoed even when empty");
    assert_eq!(
        open.manifest_file, manifest_file_before,
        "empty target set must not re-sign the manifest"
    );
    assert_eq!(open.manifest, manifest_before);
}

/// Running `auto_purge_expired` twice: the second run at a later `now_ms`
/// must purge nothing new (OLD is already purged and skipped by the
/// not-purged clause; FRESH is still too young) AND must leave the
/// vector clock unchanged, proving the empty-target-set path did not
/// re-sign the manifest a second time.
#[test]
fn auto_purge_expired_is_idempotent() {
    let old_uuid = [0xA1; 16];
    let new_uuid = [0xB2; 16];
    let (dir, mut open, device, mut rng, _pw) =
        stage_two_trashed_blocks(old_uuid, 1_000, new_uuid, 9_950);
    let folder = dir.path();
    let (window_ms, now_ms) = (100u64, 10_000u64);

    let first = auto_purge_expired(folder, &mut open, window_ms, now_ms, device, &mut rng).unwrap();
    assert_eq!(first.purged_count, 1);
    let clock_after_first = open.manifest.vector_clock.clone();

    // Second run at a LATER now_ms: OLD is already purged (skipped by the
    // not-purged clause); FRESH is still too young. Nothing to do.
    let second =
        auto_purge_expired(folder, &mut open, window_ms, now_ms + 1, device, &mut rng).unwrap();
    assert_eq!(second.purged_count, 0, "no entry re-purged");
    assert_eq!(
        open.manifest.vector_clock, clock_after_first,
        "empty target set => no second re-sign / clock tick"
    );
}

// ---------------------------------------------------------------------------
// auto_purge_expired vs. empty_trash — subset relationship
// ---------------------------------------------------------------------------

/// With OLD past the window and FRESH within it, `auto_purge_expired`
/// purges exactly {OLD}; a following `empty_trash` on the same state mops
/// up the remainder ({FRESH}). Together every trash entry ends purged: the
/// age filter only ever removes targets from `empty_trash`'s full set, it
/// never adds any — auto_purge's purged set is a subset of empty_trash's.
#[test]
fn auto_purge_expired_is_subset_of_empty_trash() {
    let old_uuid = [0xA1; 16];
    let new_uuid = [0xB2; 16];
    let (dir, mut open, device, mut rng, _pw) =
        stage_two_trashed_blocks(old_uuid, 1_000, new_uuid, 9_950);
    let folder = dir.path();

    let auto = auto_purge_expired(folder, &mut open, 100, 10_000, device, &mut rng).unwrap();
    assert_eq!(auto.purged_count, 1);

    // Now empty_trash the remainder: FRESH (still not purged, not live).
    let rest = empty_trash(folder, &mut open, device, 11_000, &mut rng).unwrap();
    assert_eq!(
        rest.purged_count, 1,
        "empty_trash mops up the within-window entry auto-purge left"
    );

    // Together they purge every eligible entry — auto_purge's set ⊆ empty_trash's set.
    assert!(open.manifest.trash.iter().all(|t| t.purged_at_ms.is_some()));
}

// ---------------------------------------------------------------------------
// Cross-language KAT replay — Task 6
//
// Loads `core/tests/data/retention_kat.json` and replays each vector through
// `expired_trash_entries`, asserting the SET of selected UUIDs matches the
// fixture's `expected_uuids_hex`. The Python sibling
// (`core/tests/python/conformance.py::section4c_retention_kat`, Task 7)
// re-implements the eligibility predicate from `docs/vault-format.md` §7
// step 5 alone and replays the same fixture, completing the cross-language
// conformance contract for the retention selector (mirrors
// `core/tests/conflict.rs::trash_merge_kat_replays_match_rust`).
// ---------------------------------------------------------------------------

fn parse_hex_array<const N: usize>(s: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect();
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

/// Build a minimal `Manifest` from a KAT vector: `manifest.trash` from
/// `trash[]` (mirrors the `trash_entry` helper in
/// `core/src/vault/retention.rs`'s inline tests) and `manifest.blocks` from
/// `blocks[]` (mirrors `push_live_block`). `expired_trash_entries` reads
/// only these two fields, so the rest are minimal placeholders.
fn build_manifest_from_kat(vector: &serde_json::Value) -> Manifest {
    let mut manifest = Manifest {
        manifest_version: 1,
        vault_uuid: [0x01; 16],
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        owner_user_uuid: [0x02; 16],
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: KdfParamsRef {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 1,
            salt: [0x11; 32],
        },
        unknown: BTreeMap::new(),
    };

    // An absent "blocks" key is treated as an empty live set — mirrors the
    // Python side's `v.get("blocks", [])` in conformance.py's
    // `section4c_retention_kat` so a future KAT vector that omits the key
    // (all-purge / nothing-live scenario) doesn't panic here.
    let empty_blocks = Vec::new();
    let blocks = vector
        .get("blocks")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_blocks);
    for b in blocks {
        let block_uuid = parse_hex_array::<16>(b.as_str().expect("block uuid hex"));
        manifest.blocks.push(BlockEntry {
            block_uuid,
            block_name: String::new(),
            fingerprint: [0u8; 32],
            recipients: Vec::new(),
            vector_clock_summary: Vec::new(),
            suite_id: SUITE_ID,
            created_at_ms: 0,
            last_mod_ms: 0,
            unknown: BTreeMap::new(),
        });
    }

    for t in vector["trash"].as_array().expect("trash[]") {
        let block_uuid =
            parse_hex_array::<16>(t["block_uuid_hex"].as_str().expect("block_uuid_hex"));
        let tombstoned_at_ms = t["tombstoned_at_ms"].as_u64().expect("tombstoned_at_ms");
        let purged_at_ms = if t["purged_at_ms"].is_null() {
            None
        } else {
            Some(t["purged_at_ms"].as_u64().expect("purged_at_ms"))
        };
        manifest.trash.push(TrashEntry {
            block_uuid,
            tombstoned_at_ms,
            tombstoned_by: [0u8; 16],
            fingerprint: None,
            purged_at_ms,
            unknown: BTreeMap::new(),
        });
    }

    manifest
}

#[test]
fn expired_trash_entries_kat_replays_match_rust() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("retention_kat.json");
    let raw = std::fs::read_to_string(&path).expect("read retention_kat.json");
    let kat: serde_json::Value = serde_json::from_str(&raw).expect("parse retention_kat.json");
    assert_eq!(kat["version"], 1);

    for vector in kat["vectors"].as_array().expect("vectors[]") {
        let name = vector["name"].as_str().expect("name");
        let window_ms = vector["window_ms"].as_u64().expect("window_ms");
        let now_ms = vector["now_ms"].as_u64().expect("now_ms");
        let manifest = build_manifest_from_kat(vector);
        let got: std::collections::BTreeSet<[u8; 16]> =
            expired_trash_entries(&manifest, window_ms, now_ms)
                .into_iter()
                .map(|e| e.block_uuid)
                .collect();
        let expected: std::collections::BTreeSet<[u8; 16]> = vector["expected_uuids_hex"]
            .as_array()
            .expect("expected_uuids_hex[]")
            .iter()
            .map(|v| parse_hex_array::<16>(v.as_str().unwrap()))
            .collect();
        assert_eq!(got, expected, "vector {name}");
    }
}
