//! Integration tests for `share_block` against a writable copy of
//! `golden_vault_001`. Each test gets its own tempdir so share mutations
//! never reach the on-disk fixture.
//!
//! Alice (the recipient) is minted directly via
//! `secretary_core::unlock::bundle::generate` + a self-signing helper —
//! NOT by spinning up a second full vault. This keeps the test fast
//! (no extra Argon2id KDF) and isolates the share path from create_vault.
//!
//! Cross-vault read (Alice opens a vault staged by share_block) is
//! covered by `core/tests/share_block.rs::share_block_round_trip` at the
//! crypto core level; the bridge tests here verify the FFI surface +
//! manifest-state mutations end-to-end.

use std::fs;
use std::path::{Path, PathBuf};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::secret::SecretString;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::unlock::bundle::{generate as generate_bundle, IdentityBundle};
// FfiVaultError is unused in Task-4's happy-path test but is consumed by
// the failure-mode tests added in subsequent tasks (NotAuthor, etc.).
// `#[allow]` keeps the import stable across the in-flight test growth.
#[allow(unused_imports)]
use secretary_ffi_bridge::{
    open_vault_with_password, save_block, share_block, BlockInput, FfiVaultError, FieldInput,
    FieldInputValue, OpenVaultManifest, RecordInput, UnlockedIdentity,
};

// ---------------------------------------------------------------------------
// Test fixture: writable golden_vault_001 copy
// ---------------------------------------------------------------------------

fn fixture_folder(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/tests/data")
        .join(name)
}

const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}

fn fresh_writable_vault() -> (tempfile::TempDir, UnlockedIdentity, OpenVaultManifest) {
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&src, tmp.path());
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
        .expect("open writable copy of golden_vault_001");
    (tmp, out.identity, out.manifest)
}

const NEW_BLOCK_UUID: [u8; 16] = [0xAB; 16];
const NEW_RECORD_UUID: [u8; 16] = [0xCD; 16];
const DEVICE_UUID: [u8; 16] = [0x07; 16];
const NOW_MS_BASE: u64 = 1_715_000_000_000;

// ---------------------------------------------------------------------------
// External-identity helpers (mint a ContactCard without spinning up a vault)
// ---------------------------------------------------------------------------

/// Mint an external identity from a deterministic seed and return its
/// canonical-CBOR-encoded self-signed ContactCard alongside the
/// IdentityBundle (kept in case future tests need to decrypt as that
/// identity).
fn mint_external_card(seed: u8, display_name: &str) -> (IdentityBundle, Vec<u8>) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let bundle = generate_bundle(display_name, 1_714_060_800_000, &mut rng);
    let pq_sk = MlDsa65Secret::from_bytes(bundle.ml_dsa_65_sk.expose()).unwrap();
    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: bundle.user_uuid,
        display_name: bundle.display_name.clone(),
        x25519_pk: bundle.x25519_pk,
        ml_kem_768_pk: bundle.ml_kem_768_pk.clone(),
        ed25519_pk: bundle.ed25519_pk,
        ml_dsa_65_pk: bundle.ml_dsa_65_pk.clone(),
        created_at_ms: bundle.created_at_ms,
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    card.sign(&bundle.ed25519_sk, &pq_sk).unwrap();
    let bytes = card.to_canonical_cbor().unwrap();
    (bundle, bytes)
}

/// Save a one-record block with a single text field. Returns nothing —
/// just panics on failure. Mirrors save_block.rs's inline pattern.
fn save_one_record_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    record_uuid: [u8; 16],
    field_name: &str,
    field_value: &str,
    now_ms: u64,
) {
    let input = BlockInput {
        block_uuid,
        block_name: "shared".to_string(),
        records: vec![RecordInput {
            record_uuid,
            fields: vec![FieldInput {
                name: field_name.to_string(),
                value: FieldInputValue::Text(SecretString::from(field_value)),
            }],
        }],
    };
    save_block(identity, manifest, input, DEVICE_UUID, now_ms).expect("save_block");
}

// ---------------------------------------------------------------------------
// Happy path: owner saves a block, owner shares with Alice, manifest's
// recipient list now includes Alice's contact UUID.
// ---------------------------------------------------------------------------

#[test]
fn share_block_owner_to_alice_appends_recipient_to_manifest() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        NEW_RECORD_UUID,
        "password",
        "hunter2",
        NOW_MS_BASE,
    );
    let pre = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block findable after save");
    assert_eq!(
        pre.recipient_uuids.len(),
        1,
        "v1 single-author save_block: only the owner is on the recipient list",
    );

    let owner_card_bytes = manifest
        .owner_card_bytes()
        .expect("owner card bytes from live handle");
    let (alice_bundle, alice_card_bytes) = mint_external_card(0xB1, "Alice");

    share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &alice_card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect("share_block must succeed for owner sharing their own block");

    let post = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block still findable after share");
    assert_eq!(
        post.recipient_uuids.len(),
        2,
        "share_block must append the new recipient to the manifest entry",
    );
    assert!(
        post.recipient_uuids.contains(&alice_bundle.user_uuid),
        "Alice's user_uuid must appear in the post-share recipient list",
    );
    assert!(
        post.last_modified_ms > pre.last_modified_ms,
        "last_modified_ms must advance across share",
    );
    assert_eq!(
        post.created_at_ms, pre.created_at_ms,
        "created_at_ms must be preserved across share",
    );
}
