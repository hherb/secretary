//! Per-test temp-folder copies of golden_vault_001 with the manifest's
//! vector clock re-written to a caller-supplied value. Used by the
//! end-to-end sync_once tests in sync.rs so each test asserts a
//! specific clock_relation outcome end-to-end (open_vault path, not
//! just the dispatch hook).

use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::Sensitive;
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::vault::{
    encode_manifest_file, open_vault, sign_manifest, ManifestHeader, Unlocker, VectorClockEntry,
};
use zeroize::Zeroize as _;

use crate::fixtures;

const GOLDEN_VAULT_FOLDER: &str = "tests/data/golden_vault_001";
const MANIFEST_FILENAME: &str = "manifest.cbor.enc";
const AEAD_NONCE_LEN: usize = 24;

/// Deterministic-but-unique AEAD nonce stem for the rewritten manifest.
/// Each test gets a unique copy of the vault in its own tempdir, so
/// nonce reuse across tests is harmless (the IBK is the same, but the
/// envelopes never share a key + nonce pair across calls).
const REWRITE_NONCE_STEM: [u8; AEAD_NONCE_LEN] = [
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34,
];

/// Recursively copies `golden_vault_001/` into a fresh temp dir, then
/// rewrites the manifest's vector clock to the supplied value
/// (preserving every other byte of the manifest body and re-signing
/// with the owner identity from the bundle).
///
/// Returns the temp folder path; the caller is responsible for keeping
/// the `tempfile::TempDir` alive for the duration of the test.
pub fn fresh_vault_with_clock(
    new_clock: Vec<VectorClockEntry>,
) -> (PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dest = tmp.path().to_path_buf();
    recursive_copy(Path::new(GOLDEN_VAULT_FOLDER), &dest);
    rewrite_manifest_clock(&dest, new_clock);
    (dest, tmp)
}

/// Recursively copy `src` into `dest`. Creates `dest` if missing. The
/// implementation mirrors the smoke runners' `recursiveCopy` helpers
/// (Swift `SmokeHelpers.swift`, Kotlin `SmokeHelpers.kt`).
fn recursive_copy(src: &Path, dest: &Path) {
    if !dest.exists() {
        std::fs::create_dir_all(dest).expect("create_dir_all dest");
    }
    for entry in std::fs::read_dir(src).expect("read_dir src") {
        let entry = entry.expect("dir entry");
        let file_type = entry.file_type().expect("file type");
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        if file_type.is_dir() {
            recursive_copy(&src_path, &dest_path);
        } else {
            std::fs::copy(&src_path, &dest_path).expect("copy file");
        }
    }
}

/// Open the vault with the golden password, mutate the manifest body's
/// `vector_clock`, re-sign via `manifest::sign_manifest`, and write the
/// result back to `manifest.cbor.enc`. Mirrors the step 11-13 pattern
/// in `core::vault::orchestrators::save_block` — only the clock changes;
/// header bytes (`vault_uuid`, `created_at_ms`, `last_mod_ms`) are
/// preserved bit-for-bit.
fn rewrite_manifest_clock(folder: &Path, new_clock: Vec<VectorClockEntry>) {
    let password = fixtures::golden_vault_001_password();
    let mut open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");

    open.manifest.vector_clock = new_clock;

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
        &open.manifest,
        &open.identity_block_key,
        &REWRITE_NONCE_STEM,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )
    .expect("sign_manifest");

    let manifest_bytes = encode_manifest_file(&new_manifest_file).expect("encode_manifest_file");
    std::fs::write(folder.join(MANIFEST_FILENAME), &manifest_bytes).expect("write manifest");
}
