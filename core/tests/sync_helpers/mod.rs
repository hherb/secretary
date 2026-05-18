//! Per-test temp-folder copies of golden_vault_001 with the manifest's
//! vector clock re-written to caller-supplied value(s). Used by the
//! end-to-end sync_once tests in sync.rs (single-manifest fixtures) and
//! the C.1.1a conflict-copy ingestion tests (N-manifest fixtures) so
//! each test asserts a specific outcome against the real open_vault
//! path.
//!
//! All multi-manifest helpers use distinct AEAD nonce constants per
//! envelope so the AEAD uniqueness invariant (never share key + nonce
//! across rewrites) holds even within a single tempdir. See the
//! "Atomic-write contract" section of CLAUDE.md for the rationale.

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
pub const MANIFEST_FILENAME: &str = "manifest.cbor.enc";
const AEAD_NONCE_LEN: usize = 24;

/// Distinct nonce for the canonical manifest written by helpers in this
/// module. Tests don't share AEAD key + nonce pairs across rewrites.
pub const CANONICAL_NONCE_A: [u8; AEAD_NONCE_LEN] = [
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34,
];

/// Distinct nonce for the first sibling manifest. Differs from
/// [`CANONICAL_NONCE_A`] in every byte to make accidental nonce reuse
/// obvious in test failures.
pub const SIBLING_NONCE_B: [u8; AEAD_NONCE_LEN] = [
    0x5E, 0x4D, 0x3C, 0x2B, 0x1A, 0x09, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66,
    0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xED, 0xCB,
];

/// Distinct nonce for the second sibling manifest in N-way fixtures.
/// Consumed by [`fresh_vault_four_concurrent_manifests`] in C.1.1a
/// integration tests (Task 13). Annotated to suppress clippy
/// `dead_code` during the per-task TDD commits.
#[allow(dead_code)]
pub const SIBLING_NONCE_C: [u8; AEAD_NONCE_LEN] = [
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
];

/// Distinct nonce for the third sibling manifest in N-way fixtures.
/// Consumed by [`fresh_vault_four_concurrent_manifests`] in C.1.1a
/// integration tests (Task 13). Annotated to suppress clippy
/// `dead_code` during the per-task TDD commits.
#[allow(dead_code)]
pub const SIBLING_NONCE_D: [u8; AEAD_NONCE_LEN] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21,
];

/// Recursively copies `golden_vault_001/` into a fresh temp dir, then
/// rewrites the canonical manifest's vector clock to `new_clock`
/// using [`CANONICAL_NONCE_A`].
///
/// Returns the temp folder path; the caller is responsible for keeping
/// the `tempfile::TempDir` alive for the duration of the test.
pub fn fresh_vault_with_clock(new_clock: Vec<VectorClockEntry>) -> (PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dest = tmp.path().to_path_buf();
    recursive_copy(Path::new(GOLDEN_VAULT_FOLDER), &dest);
    write_manifest_at(&dest, MANIFEST_FILENAME, new_clock, &CANONICAL_NONCE_A);
    (dest, tmp)
}

/// Like [`fresh_vault_with_clock`] but also writes a sibling manifest
/// at `sibling_filename` with a concurrent `sibling_clock`. The two
/// manifests are signed by the same owner identity but with distinct
/// AEAD nonces ([`CANONICAL_NONCE_A`] + [`SIBLING_NONCE_B`]).
///
/// Consumed by C.1.1a integration tests (Task 13); annotated to
/// suppress clippy `dead_code` during the per-task TDD commits.
#[allow(dead_code)]
pub fn fresh_vault_two_concurrent_manifests(
    canonical_clock: Vec<VectorClockEntry>,
    sibling_filename: &str,
    sibling_clock: Vec<VectorClockEntry>,
) -> (PathBuf, tempfile::TempDir) {
    let (dest, tmp) = fresh_vault_with_clock(canonical_clock);
    write_manifest_at(&dest, sibling_filename, sibling_clock, &SIBLING_NONCE_B);
    (dest, tmp)
}

/// Like [`fresh_vault_two_concurrent_manifests`] but writes THREE
/// siblings instead of one (for N-way fixtures). Each sibling uses a
/// distinct AEAD nonce ([`SIBLING_NONCE_B`] / `_C` / `_D`).
///
/// Consumed by C.1.1a integration tests (Task 13); annotated to
/// suppress clippy `dead_code` during the per-task TDD commits.
#[allow(dead_code)]
pub fn fresh_vault_four_concurrent_manifests(
    canonical_clock: Vec<VectorClockEntry>,
    siblings: [(&str, Vec<VectorClockEntry>); 3],
) -> (PathBuf, tempfile::TempDir) {
    let (dest, tmp) = fresh_vault_with_clock(canonical_clock);
    let nonces = [&SIBLING_NONCE_B, &SIBLING_NONCE_C, &SIBLING_NONCE_D];
    for ((filename, clock), nonce) in siblings.into_iter().zip(nonces.iter()) {
        write_manifest_at(&dest, filename, clock, nonce);
    }
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
/// `vector_clock`, re-sign via `manifest::sign_manifest` with the
/// supplied nonce, and write the result to `folder/filename`. Mirrors
/// the step 11-13 pattern in `core::vault::orchestrators::save_block`
/// — only the clock changes; header bytes (`vault_uuid`,
/// `created_at_ms`, `last_mod_ms`) are preserved bit-for-bit.
fn write_manifest_at(
    folder: &Path,
    filename: &str,
    new_clock: Vec<VectorClockEntry>,
    aead_nonce: &[u8; AEAD_NONCE_LEN],
) {
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
        aead_nonce,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )
    .expect("sign_manifest");

    let manifest_bytes = encode_manifest_file(&new_manifest_file).expect("encode_manifest_file");
    std::fs::write(folder.join(filename), &manifest_bytes).expect("write manifest");
}
