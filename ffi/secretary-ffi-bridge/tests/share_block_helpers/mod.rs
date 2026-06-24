//! Shared helpers for the `share_block` integration-test bins.
//!
//! `tests/share_block.rs` and `tests/share_block_proptest.rs` are
//! independent compiled bins (Cargo treats every `tests/<name>.rs` as one
//! integration test bin). Files under `tests/<subdir>/` are NOT bins —
//! each consuming test bin pulls them in via `mod share_block_helpers;`.

use std::fs;
use std::path::{Path, PathBuf};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::secret::SecretString;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::unlock::bundle::{generate as generate_bundle, IdentityBundle};
use secretary_ffi_bridge::{
    open_vault_with_password, save_block, BlockInput, FieldInput, FieldInputValue,
    OpenVaultManifest, RecordInput, UnlockedIdentity,
};

/// Path to a fixture vault folder under `core/tests/data/`.
/// `CARGO_MANIFEST_DIR` is `ffi/secretary-ffi-bridge/`, so we walk up.
pub fn fixture_folder(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/tests/data")
        .join(name)
}

/// Pinned password for `golden_vault_001`.
pub const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

/// Recursive directory copy. Used by `fresh_writable_vault` to clone the
/// fixture into a writable tempdir before running mutation tests.
pub fn copy_dir_recursive(src: &Path, dst: &Path) {
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

/// Open a writable copy of `golden_vault_001` in a fresh tempdir. Returns
/// the tempdir guard (drop to clean up) plus the live `UnlockedIdentity`
/// and `OpenVaultManifest`.
pub fn fresh_writable_vault() -> (tempfile::TempDir, UnlockedIdentity, OpenVaultManifest) {
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&src, tmp.path());
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
        .expect("open writable copy of golden_vault_001");
    (tmp, out.identity, out.manifest)
}

/// Stable test UUIDs / timestamps. Block + record UUIDs are arbitrary
/// non-zero patterns; device UUID is `0x07`-filled; `NOW_MS_BASE` is a
/// fixed wall-clock timestamp so test runs are deterministic.
pub const NEW_BLOCK_UUID: [u8; 16] = [0xAB; 16];
pub const NEW_RECORD_UUID: [u8; 16] = [0xCD; 16];
pub const DEVICE_UUID: [u8; 16] = [0x07; 16];
pub const NOW_MS_BASE: u64 = 1_715_000_000_000;

/// Mint an external identity from a deterministic seed and return its
/// canonical-CBOR-encoded self-signed `ContactCard` alongside the
/// `IdentityBundle` (kept in case future tests need to decrypt as that
/// identity).
pub fn mint_external_card(seed: u8, display_name: &str) -> (IdentityBundle, Vec<u8>) {
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

/// Save a one-record block with a single text field. Panics on failure
/// (test-only helper). Mirrors `save_block.rs`'s inline pattern.
pub fn save_one_record_block(
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
            record_type: String::new(),
            tags: Vec::new(),
            fields: vec![FieldInput {
                name: field_name.to_string(),
                value: FieldInputValue::Text(SecretString::from(field_value)),
            }],
        }],
    };
    save_block(identity, manifest, input, DEVICE_UUID, now_ms).expect("save_block");
}

/// Mint a FORGED card: attacker keys (from `seed`) but a chosen
/// `contact_uuid` (the victim's). The card still self-verifies — it is
/// signed by its own embedded attacker keys — so `verify_self` alone does
/// NOT catch it; only the TOFU non-overwrite guard does. Used by the
/// #206 substitution teeth test.
#[allow(dead_code)]
pub fn mint_forged_card(
    seed: u8,
    display_name: &str,
    victim_uuid: [u8; 16],
) -> (IdentityBundle, Vec<u8>) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let bundle = generate_bundle(display_name, 1_714_060_800_000, &mut rng);
    let pq_sk = MlDsa65Secret::from_bytes(bundle.ml_dsa_65_sk.expose()).unwrap();
    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: victim_uuid, // impersonated UUID, attacker keys below
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

/// Write raw card bytes into the vault's `contacts/` dir under the canonical
/// hyphenated filename. Returns the card's `contact_uuid`.
#[allow(dead_code)]
pub fn place_card(folder: &Path, card_bytes: &[u8]) -> [u8; 16] {
    use secretary_core::vault::format_uuid_hyphenated;
    let card = ContactCard::from_canonical_cbor(card_bytes).expect("valid card");
    let path = folder.join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&card.contact_uuid)
    ));
    fs::write(&path, card_bytes).expect("write card");
    card.contact_uuid
}
