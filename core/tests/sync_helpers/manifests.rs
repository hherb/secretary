//! Fresh golden-vault copies with re-written manifest clocks, and the manifest writer.

use super::*;

/// Recursively copies `golden_vault_001/` into a fresh temp dir, then
/// rewrites the canonical manifest's vector clock to `new_clock`
/// using [`CANONICAL_NONCE_A`].
///
/// Returns the temp folder path; the caller is responsible for keeping
/// the `tempfile::TempDir` alive for the duration of the test.
pub fn fresh_vault_with_clock(new_clock: Vec<VectorClockEntry>) -> (PathBuf, tempfile::TempDir) {
    let tmp = secretary_test_utils::copy_dir_to_tempdir(Path::new(GOLDEN_VAULT_FOLDER));
    let dest = tmp.path().to_path_buf();
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

/// Open the vault with the golden password, mutate the manifest body's
/// `vector_clock`, re-sign via `manifest::sign_manifest` with the
/// supplied nonce, and write the result to `folder/filename`. Mirrors
/// the step 11-13 pattern in `core::vault::orchestrators::save_block`
/// — only the clock changes; header bytes (`vault_uuid`,
/// `created_at_ms`, `last_mod_ms`) are preserved bit-for-bit.
///
/// **Pre-condition:** the vault on disk must open cleanly. After a
/// raw block rewrite via [`rewrite_block_with_records`] this is
/// **not** the case (the block fingerprint in the manifest no longer
/// matches the on-disk bytes; `open_vault` fails with
/// `BlockFingerprintMismatch` per C.1.1b D6). Callers needing to write
/// a manifest post-rewrite should use
/// [`rewrite_block_with_records_and_update_manifest`] instead — it
/// re-signs the manifest in-process from a cached `OpenVault` handle,
/// avoiding the inconsistent intermediate state on disk.
pub fn write_manifest_at(
    folder: &Path,
    filename: &str,
    new_clock: Vec<VectorClockEntry>,
    aead_nonce: &[u8; AEAD_NONCE_LEN],
) {
    write_manifest_at_with(folder, filename, new_clock, aead_nonce, |_| {});
}

/// [`write_manifest_at`], with `edit` applied to the manifest body after the
/// clock is set and before it is signed (e.g. to drop a block entry).
pub fn write_manifest_at_with(
    folder: &Path,
    filename: &str,
    new_clock: Vec<VectorClockEntry>,
    aead_nonce: &[u8; AEAD_NONCE_LEN],
    edit: impl FnOnce(&mut secretary_core::vault::Manifest),
) {
    let password = fixtures::golden_vault_001_password();
    let mut open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");

    open.manifest.vector_clock = new_clock;
    edit(&mut open.manifest);

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
