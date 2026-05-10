//! Integration tests for the folder-in vault surface. Test fixtures live
//! under `core/tests/data/golden_vault_NNN/`; the password / phrase
//! constants are pinned and kept honest by the fixture builder's
//! drift-detection assertion.

use std::path::PathBuf;

use secretary_core::identity::card::ContactCard;

use crate::error::FfiVaultError;

use super::inner::BlockSummary;
use super::manifest::ReplaceManifestError;
use super::orchestration::{open_vault_with_password, open_vault_with_recovery};

/// Path to the golden_vault_NNN folder. CARGO_MANIFEST_DIR is
/// ffi/secretary-ffi-bridge/, so we walk up to core/tests/data/.
fn fixture_folder(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/tests/data")
        .join(name)
}

/// Pinned password for golden_vault_001. Same KAT used by unlock.rs.
const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";
/// Pinned password for golden_vault_002. Read from
/// core/tests/data/golden_vault_002_inputs.json — adjust if that JSON
/// changes. Unused in vault.rs tests today; kept for reference.
#[allow(dead_code)]
const VAULT_002_PASSWORD: &[u8] = b"correct horse battery staple two";
/// Pinned BIP-39 phrases (parallel to unlock.rs). Source of truth:
/// the `recovery_mnemonic_phrase` field in each fixture's inputs JSON,
/// kept honest by the fixture builder's drift-detection assertion.
const VAULT_001_PHRASE: &[u8] = b"wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that";
const VAULT_002_PHRASE: &[u8] = b"debate pride tunnel elder caution media glass joke that rabbit mean write eager across furnace volume lawn cage decline fat path guess slogan hunt";

const VAULT_001_OWNER_DISPLAY_NAME: &str = "Owner";
const VAULT_001_OWNER_USER_UUID: &[u8] = &[
    0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8, 0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf, 0x35,
];

#[test]
fn open_vault_with_password_success_returns_two_handles() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD)
        .expect("open should succeed against golden_vault_001");
    assert_eq!(out.identity.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
    assert_eq!(out.identity.user_uuid(), VAULT_001_OWNER_USER_UUID);
    assert_eq!(
        out.manifest.owner_user_uuid(),
        VAULT_001_OWNER_USER_UUID,
        "manifest's owner_user_uuid must agree with identity's user_uuid",
    );
}

#[test]
fn open_vault_with_recovery_success_matches_password_path() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_recovery(&folder, VAULT_001_PHRASE)
        .expect("recovery open should succeed against golden_vault_001");
    // Both unlock paths must converge on byte-identical secret state
    // (§3/§4 dual-KEK design), so identity values match the password
    // path's results in the previous test.
    assert_eq!(out.identity.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
    assert_eq!(out.identity.user_uuid(), VAULT_001_OWNER_USER_UUID);
}

#[test]
fn open_vault_with_password_wrong_password_returns_thinned_error() {
    let folder = fixture_folder("golden_vault_001");
    let err = open_vault_with_password(&folder, b"definitely the wrong password").unwrap_err();
    assert!(
        matches!(err, FfiVaultError::WrongPasswordOrCorrupt),
        "expected WrongPasswordOrCorrupt, got {err:?}",
    );
}

#[test]
fn open_vault_with_recovery_wrong_phrase_returns_thinned_error() {
    let folder = fixture_folder("golden_vault_001");
    // Use vault_002's phrase against vault_001's folder — valid 24-word
    // phrase but wrong vault, so recovery_kek decap tag-fails.
    let err = open_vault_with_recovery(&folder, VAULT_002_PHRASE).unwrap_err();
    assert!(
        matches!(err, FfiVaultError::WrongMnemonicOrCorrupt),
        "expected WrongMnemonicOrCorrupt, got {err:?}",
    );
}

#[test]
fn open_vault_with_recovery_invalid_phrase_returns_invalid_mnemonic() {
    let folder = fixture_folder("golden_vault_001");
    let err = open_vault_with_recovery(&folder, b"only three words").unwrap_err();
    let FfiVaultError::InvalidMnemonic { detail } = err else {
        panic!("expected InvalidMnemonic, got {err:?}");
    };
    assert!(
        detail.contains("got 3"),
        "detail did not carry word count: {detail}",
    );
}

#[test]
fn open_vault_folder_does_not_exist_returns_folder_invalid() {
    let folder = fixture_folder("__nonexistent_folder_for_b4a_test__");
    let err = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap_err();
    let FfiVaultError::FolderInvalid { detail } = err else {
        panic!("expected FolderInvalid, got {err:?}");
    };
    // detail carries IO context + io::Error display; either substring
    // is sufficient — the underlying io::ErrorKind is NotFound.
    assert!(
        detail.to_lowercase().contains("vault.toml")
            || detail.to_lowercase().contains("no such file"),
        "FolderInvalid detail did not carry expected text: {detail}",
    );
}

#[test]
fn open_vault_folder_missing_identity_bundle_returns_folder_invalid() {
    // Set up a temp folder containing only vault.toml from
    // golden_vault_001. The bridge / core open path reads vault.toml
    // first then identity.bundle.enc; we want the second read to
    // surface as FolderInvalid.
    use std::fs;
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::TempDir::new().expect("tempdir");
    fs::copy(src.join("vault.toml"), tmp.path().join("vault.toml")).unwrap();
    // Deliberately do NOT copy identity.bundle.enc.

    let err = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).unwrap_err();
    let FfiVaultError::FolderInvalid { detail } = err else {
        panic!("expected FolderInvalid, got {err:?}");
    };
    assert!(
        detail.contains("identity.bundle.enc"),
        "FolderInvalid detail did not mention identity.bundle.enc: {detail}",
    );
}

#[test]
fn block_summaries_returns_pinned_layout_for_v1() {
    // Pin the BlockSummary list against the golden_vault_001_inputs.json
    // `block_summaries` array. If this test fails, either the fixture
    // changed (re-pin the JSON via Task 2 Step 2's helper) or the
    // BlockSummary projection has drifted (fix block_entry_to_summary).
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();

    let summaries = out.manifest.block_summaries();
    let count = out.manifest.block_count();
    assert_eq!(
        summaries.len() as u64,
        count,
        "block_summaries() length must match block_count()",
    );

    // Read the pinned JSON for cross-checking.
    let json_path = fixture_folder("").join("golden_vault_001_inputs.json");
    let json_str = std::fs::read_to_string(&json_path).expect("inputs JSON");
    let pinned: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
    let pinned_summaries = pinned["block_summaries"]
        .as_array()
        .expect("block_summaries is an array — was Task 2 Step 3 completed?");

    assert_eq!(
        summaries.len(),
        pinned_summaries.len(),
        "BlockSummary count drift: code has {}, JSON pins {}",
        summaries.len(),
        pinned_summaries.len(),
    );

    for (actual, pinned) in summaries.iter().zip(pinned_summaries.iter()) {
        let pinned_uuid_hex = pinned["block_uuid"].as_str().expect("hex string");
        let actual_uuid_hex = hex::encode(actual.block_uuid);
        assert_eq!(actual_uuid_hex, pinned_uuid_hex, "block_uuid drift");
        assert_eq!(
            actual.block_name,
            pinned["block_name"].as_str().expect("string"),
            "block_name drift",
        );
        assert_eq!(
            actual.created_at_ms,
            pinned["created_at_ms"].as_u64().expect("u64"),
            "created_at_ms drift",
        );
        assert_eq!(
            actual.last_modified_ms,
            pinned["last_modified_ms"].as_u64().expect("u64"),
            "last_modified_ms drift",
        );
        let pinned_recipient_hexes: Vec<&str> = pinned["recipient_uuids"]
            .as_array()
            .expect("recipient_uuids is an array")
            .iter()
            .map(|v| v.as_str().expect("hex string"))
            .collect();
        let actual_recipient_hexes: Vec<String> =
            actual.recipient_uuids.iter().map(hex::encode).collect();
        assert_eq!(
            actual_recipient_hexes,
            pinned_recipient_hexes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            "recipient_uuids drift",
        );
    }
}

#[test]
fn find_block_returns_some_for_known_block_uuid() {
    // Positive find_block test: looking up a UUID that IS in the
    // manifest must return Some(BlockSummary) whose fields agree with
    // the JSON pin. Complements the wipe test below (which exercises
    // the None path) and the ad-hoc len-check (find_block(&[0; 16]) on
    // a vault with no all-zero block UUID also returns None there).
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();

    let json_path = fixture_folder("").join("golden_vault_001_inputs.json");
    let json_str = std::fs::read_to_string(&json_path).expect("inputs JSON");
    let pinned: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
    let pinned_block = &pinned["block_summaries"][0];
    let known_uuid_hex = pinned_block["block_uuid"].as_str().expect("hex string");
    let known_uuid_bytes = hex::decode(known_uuid_hex).expect("valid hex");

    let summary = out
        .manifest
        .find_block(&known_uuid_bytes)
        .expect("find_block must return Some for a known block_uuid");
    assert_eq!(hex::encode(summary.block_uuid), known_uuid_hex);
    assert_eq!(
        summary.block_name,
        pinned_block["block_name"].as_str().expect("string"),
    );
    assert_eq!(
        summary.created_at_ms,
        pinned_block["created_at_ms"].as_u64().expect("u64"),
    );
}

#[test]
fn find_block_returns_none_for_wrong_length_uuid() {
    // The 16-byte runtime length check is the only validation on the
    // UUID input. Pin both the too-short and too-long rejections so a
    // future refactor (e.g. accepting [u8; 16] directly) is a deliberate
    // API change rather than a silent regression.
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    assert_eq!(out.manifest.find_block(&[0u8; 15]), None);
    assert_eq!(out.manifest.find_block(&[0u8; 17]), None);
}

#[test]
fn open_vault_manifest_wipe_returns_empty_defaults() {
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    out.manifest.wipe();
    // Post-wipe, every accessor returns the empty default. Same
    // contract as UnlockedIdentity post-wipe.
    assert_eq!(out.manifest.vault_uuid(), vec![0u8; 16]);
    assert_eq!(out.manifest.owner_user_uuid(), vec![0u8; 16]);
    assert_eq!(out.manifest.block_count(), 0);
    assert_eq!(out.manifest.block_summaries(), Vec::<BlockSummary>::new());
    assert_eq!(out.manifest.find_block(&[0u8; 16]), None);
    // Idempotent.
    out.manifest.wipe();
    out.manifest.wipe();
    assert_eq!(out.manifest.block_count(), 0);
}

#[test]
fn vault_folder_accessor_returns_path_when_live_and_none_when_wiped() {
    // Pin the bridge-internal vault_folder accessor's contract.
    // record::read_block (B.4b Task 3) depends on this returning
    // Some(path) before wipe and None after, so a regression here
    // would surface as a bogus FfiVaultError::CorruptVault from
    // read_block rather than a clean failure.
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let returned = out.manifest.vault_folder().expect("Some(path) before wipe");
    assert_eq!(
        returned, folder,
        "vault_folder() must return the path passed to open_vault_with_password",
    );
    out.manifest.wipe();
    assert_eq!(
        out.manifest.vault_folder(),
        None,
        "vault_folder() must return None after wipe",
    );
}

#[test]
fn owner_card_bytes_returns_canonical_cbor_round_tripping_to_owner_card() {
    // Pin the new B.4d accessor. owner_card_bytes() must encode on
    // demand to a byte sequence that decodes back to the same
    // ContactCard returned by owner_card(). This is the round-trip
    // contract that share_block's foreign callers rely on when they
    // pass `manifest.owner_card_bytes()` as the first element of
    // existing_recipient_cards.
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let bytes = out
        .manifest
        .owner_card_bytes()
        .expect("Some(bytes) before wipe");
    let card_from_bytes = ContactCard::from_canonical_cbor(&bytes).expect("decode round-trips");
    let card_direct = out.manifest.owner_card().expect("Some(card) before wipe");
    assert_eq!(
        card_from_bytes, card_direct,
        "owner_card_bytes() must decode back to the live ContactCard",
    );
    // And the canonical re-encoding of the decoded card is byte-equal
    // to the accessor output (idempotent).
    assert_eq!(
        card_from_bytes.to_canonical_cbor().expect("re-encode"),
        bytes,
        "canonical re-encoding must be idempotent",
    );
}

#[test]
fn owner_card_bytes_returns_none_after_wipe() {
    // Pin the wipe contract for the new accessor. After wipe() the
    // accessor returns None, matching the existing owner_card() and
    // manifest_body() shapes.
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    assert!(out.manifest.owner_card_bytes().is_some());
    out.manifest.wipe();
    assert!(out.manifest.owner_card_bytes().is_none());
}

#[test]
fn manifest_body_and_owner_card_accessors_return_some_when_live_and_none_when_wiped() {
    // Pin the two new bridge-internal accessors. read_block needs
    // them to drive core::block::decrypt_block; a None here when
    // the handle is live would manifest as CorruptVault from
    // read_block.
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let body = out
        .manifest
        .manifest_body()
        .expect("Some(body) before wipe");
    assert_eq!(body.vault_uuid.len(), 16, "vault_uuid is 16 bytes");
    assert!(
        !body.blocks.is_empty(),
        "golden_vault_001 must have at least one block",
    );
    let _card = out.manifest.owner_card().expect("Some(card) before wipe");
    out.manifest.wipe();
    assert_eq!(out.manifest.manifest_body(), None);
    assert!(out.manifest.owner_card().is_none());
}

#[test]
fn snapshot_for_read_block_returns_some_triple_when_live_and_none_when_wiped() {
    // Pin the single-lock atomic snapshot accessor used by
    // record::read_block. Closes a theoretical TOCTOU gap where
    // another thread could call wipe() between the 3 individual
    // accessor calls; a regression here would let the gap reopen.
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let (body, card, returned_folder) = out
        .manifest
        .snapshot_for_read_block()
        .expect("Some(triple) before wipe");
    assert_eq!(body.vault_uuid.len(), 16, "vault_uuid is 16 bytes");
    assert!(
        !body.blocks.is_empty(),
        "golden_vault_001 must have at least one block",
    );
    assert_eq!(
        returned_folder, folder,
        "snapshot folder must match open_vault_with_password input",
    );
    // Structural sanity on the returned card — full identity
    // verification is exercised in core::vault tests; here we
    // only need to know the snapshot returned the live card.
    assert_eq!(card.contact_uuid.len(), 16, "card contact_uuid is 16 bytes",);
    out.manifest.wipe();
    assert!(
        out.manifest.snapshot_for_read_block().is_none(),
        "snapshot_for_read_block must return None after wipe",
    );
}

#[test]
fn snapshot_for_save_block_returns_some_quintuple_when_live_and_none_when_wiped() {
    // Pin the single-lock atomic snapshot accessor used by
    // save::save_block. Mirrors snapshot_for_read_block's TOCTOU
    // closure for the save path's five-field surface (manifest +
    // manifest_file + owner_card + IBK clone + vault folder).
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let (body, manifest_file, card, _ibk, returned_folder) = out
        .manifest
        .snapshot_for_save_block()
        .expect("Some(quintuple) before wipe");
    assert_eq!(body.vault_uuid.len(), 16, "vault_uuid is 16 bytes");
    assert!(
        !body.blocks.is_empty(),
        "golden_vault_001 must have at least one block",
    );
    // ManifestFile carries the on-disk header for re-sign chaining;
    // structural sanity is enough here (the full re-sign pipeline is
    // exercised by save_block tests in Task 2).
    assert_eq!(
        manifest_file.header.vault_uuid, body.vault_uuid,
        "manifest envelope vault_uuid must match body vault_uuid",
    );
    assert_eq!(card.contact_uuid.len(), 16, "card contact_uuid is 16 bytes");
    assert_eq!(
        returned_folder, folder,
        "snapshot folder must match open_vault_with_password input",
    );
    // _ibk is Sensitive<[u8; 32]> — drop on scope exit zeroizes it.
    out.manifest.wipe();
    assert!(
        out.manifest.snapshot_for_save_block().is_none(),
        "snapshot_for_save_block must return None after wipe",
    );
}

#[test]
fn replace_manifest_and_file_on_wiped_handle_returns_handle_wiped() {
    // Pin the typed-error contract: a wiped handle surfaces as
    // ReplaceManifestError::HandleWiped (not the previous Err(())
    // unit-typed sentinel). The orchestrator depends on this typed
    // error to attach a non-misleading CorruptVault.detail via Display.
    let folder = fixture_folder("golden_vault_001");
    let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
    let (body, manifest_file, ..) = out
        .manifest
        .snapshot_for_save_block()
        .expect("snapshot before wipe");
    out.manifest.wipe();
    assert_eq!(
        out.manifest.replace_manifest_and_file(body, manifest_file),
        Err(ReplaceManifestError::HandleWiped),
    );
}

#[test]
fn replace_manifest_error_handle_wiped_display_pins_text() {
    // Tripwire: the orchestrator stringifies this Display into the
    // CorruptVault.detail surfaced through PyO3 / uniffi. The
    // tests/save_block.rs wiped-manifest assertions key on the word
    // "manifest" appearing in the detail; pin both the verbatim text
    // and the substring contract here so a future rename is a
    // deliberate decision.
    let rendered = ReplaceManifestError::HandleWiped.to_string();
    assert_eq!(
        rendered,
        "vault manifest handle has been closed during save",
    );
    assert!(rendered.contains("manifest"));
}
