//! Extra conflict copies of a block, and the shared manifest-with-block-entry writer.

use super::*;

/// Add one more conflict copy of `block_uuid` to a vault built by
/// [`fresh_vault_two_concurrent_blocks`], so a merge folds three copies
/// (#751). Writes a sibling block at `blocks/<uuid>.cbor.enc<block_suffix>`
/// and a sibling manifest at `manifest_filename` whose `BlockEntry` binds
/// it, under [`BLOCK_NONCE_G`] / [`SIBLING_NONCE_C`]. The copy keeps the
/// canonical `block_name`, has no block-level `unknown` keys and carries
/// [`V1_BLOCK_VERSIONS`]; see [`add_block_sibling_with_meta`] to set any
/// of them.
///
/// The canonical manifest and block are untouched, so the vault still
/// opens; `manifest_filename` and `block_suffix` MUST differ from the
/// first sibling's, or this overwrites it. Call it at most once per
/// vault: every call encrypts under the same [`BLOCK_NONCE_G`] /
/// [`SIBLING_NONCE_C`], so a second call would reuse a key and nonce.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn add_concurrent_block_sibling(
    folder: &Path,
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    records: Vec<secretary_core::vault::Record>,
    block_clock: Vec<VectorClockEntry>,
    manifest_clock: Vec<VectorClockEntry>,
    manifest_filename: &str,
    block_suffix: &str,
    now_ms: u64,
) {
    add_block_sibling_with_meta(
        folder,
        block_uuid,
        records,
        None,
        BTreeMap::new(),
        V1_BLOCK_VERSIONS,
        block_clock,
        manifest_clock,
        manifest_filename,
        block_suffix,
        now_ms,
    );
}

/// [`add_concurrent_block_sibling`], with the copy's plaintext
/// `block_name` (`None` keeps the canonical one), block-level `unknown`
/// map (#759) and `(block_version, schema_version)` pair (#761) set by
/// the caller. The copy's manifest `BlockEntry.block_name` is left as the
/// canonical one, as a real writer's would not be; `prepare_merge` reads
/// the name from the plaintext only. Same single-call nonce rule.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn add_block_sibling_with_meta(
    folder: &Path,
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    records: Vec<secretary_core::vault::Record>,
    block_name: Option<&str>,
    unknown: BTreeMap<String, secretary_core::vault::record::UnknownValue>,
    versions: (u32, u32),
    block_clock: Vec<VectorClockEntry>,
    manifest_clock: Vec<VectorClockEntry>,
    manifest_filename: &str,
    block_suffix: &str,
    now_ms: u64,
) {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    let entry = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .cloned()
        .expect("block_uuid not in canonical manifest");

    let (fp, bytes) = encrypt_block_bytes_for_uuid(
        &open,
        block_uuid,
        records,
        block_clock.clone(),
        block_name.map_or(entry.block_name, str::to_string),
        unknown,
        versions,
        entry.created_at_ms,
        now_ms,
        &BLOCK_NONCE_G,
    );
    let canonical_path = block_file_path(folder, &block_uuid);
    let name = canonical_path
        .file_name()
        .and_then(|n| n.to_str())
        .expect("canonical path utf-8");
    let sibling_path = canonical_path.with_file_name(format!("{name}{block_suffix}"));
    std::fs::write(&sibling_path, &bytes).expect("write sibling block");

    write_manifest_with_block_entry(
        folder,
        &open,
        manifest_filename,
        block_uuid,
        fp,
        block_clock,
        manifest_clock,
        now_ms,
        &SIBLING_NONCE_C,
    );
}

/// Build + sign a manifest from a cached `OpenVault`, replacing one
/// `BlockEntry`'s `fingerprint` / `vector_clock_summary` / `last_mod_ms`
/// AND the manifest-level `vector_clock`, then write the result to
/// `folder.join(filename)`.
///
/// Lifted out of [`fresh_vault_two_concurrent_blocks`] so the canonical
/// and sibling manifest writes share one signing path. Mirrors the
/// step 5-7 sequence inside `commit_with_decisions::commit_with_decisions`
/// but is driven by the test's cached `OpenVault` rather than a fresh
/// `open_vault` call (necessary because the disk is in a fingerprint-
/// inconsistent state between block writes and manifest writes — D6
/// would reject a fresh open).
#[allow(clippy::too_many_arguments)]
pub(super) fn write_manifest_with_block_entry(
    folder: &Path,
    open: &secretary_core::vault::OpenVault,
    filename: &str,
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    block_fingerprint: [u8; 32],
    block_clock: Vec<VectorClockEntry>,
    manifest_clock: Vec<VectorClockEntry>,
    block_last_mod_ms: u64,
    manifest_aead_nonce: &[u8; AEAD_NONCE_LEN],
) {
    let mut manifest = open.manifest.clone();
    let idx = manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .unwrap_or_else(|| panic!("block_uuid {block_uuid:?} not present in cached manifest"));
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
        manifest_aead_nonce,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )
    .expect("sign_manifest");

    let manifest_bytes = encode_manifest_file(&new_manifest_file).expect("encode_manifest_file");
    std::fs::write(folder.join(filename), &manifest_bytes).expect("write manifest");
}
