//! Single-block helpers: a live record, block paths, decrypt, and an in-place rewrite.

use super::*;

// ---------------------------------------------------------------------------
// C.1.1b: per-block rewrite helpers (continued in block_encrypt,
// block_manifest, concurrent_blocks and block_siblings)
// ---------------------------------------------------------------------------

/// Number of UUID bytes used in vault on-disk identifiers (§4.2).
/// Local copy because the matching constant in `manifest::UUID_LEN` is
/// `pub(crate)` to the core crate.
pub(super) const SYNC_HELPERS_UUID_LEN: usize = 16;

/// Build a LIVE single-field `"kv"` record. `uuid` controls the
/// `record_uuid` so callers can give the canonical and sibling sides of
/// a divergence fixture distinct (non-conflicting) records; `marker`
/// becomes the value of the sole field `"k"`. Pure: no I/O, no globals —
/// every field is derived from the four arguments.
///
/// `dead_code` is tolerated because not every test target that compiles
/// `sync_helpers` exercises this constructor.
#[allow(dead_code)]
pub fn live_record(
    uuid: [u8; 16],
    device_uuid: [u8; 16],
    last_mod_ms: u64,
    marker: &str,
) -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "k".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::from(marker)),
            last_mod: last_mod_ms,
            device_uuid,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: uuid,
        record_type: "kv".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 50,
        last_mod_ms,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

/// Look up the first block_uuid in the golden vault's manifest. Used
/// by helpers that need a real on-disk block to rewrite.
///
/// `dead_code` until Task 9 of the C.1.1b plan wires the first
/// divergent-block test.
#[allow(dead_code)]
pub fn golden_vault_001_first_block_uuid(folder: &Path) -> [u8; SYNC_HELPERS_UUID_LEN] {
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(folder, Unlocker::Password(&password), None).expect("open_vault");
    open.manifest
        .blocks
        .first()
        .expect("golden vault has at least one block")
        .block_uuid
}

/// Canonical block file path inside the vault folder. Mirrors the
/// on-disk layout written by [`secretary_core::vault::save_block`]:
/// `blocks/<uuid-hyphenated>.cbor.enc`. Uses the core's
/// `format_uuid_hyphenated` (re-exported `#[doc(hidden)] pub`) so the
/// on-disk filename format is single-sourced — production code, the
/// sync layer, and these test helpers all go through one formatter.
#[allow(dead_code)]
pub fn block_file_path(folder: &Path, block_uuid: &[u8; SYNC_HELPERS_UUID_LEN]) -> PathBuf {
    let uuid_hex = secretary_core::vault::format_uuid_hyphenated(block_uuid);
    folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))
}

/// Decrypt a block envelope using the open vault's owner identity.
/// Returns the verified `BlockPlaintext`. Helper for round-trip
/// assertions in tests that rewrite block files.
///
/// Owner == author == reader in golden vault fixtures; this helper
/// derives all three from `open.owner_card` + `open.identity`.
#[allow(dead_code)]
pub fn decrypt_block_using_open(
    open: &secretary_core::vault::OpenVault,
    bytes: &[u8],
) -> Result<secretary_core::vault::BlockPlaintext, secretary_core::vault::VaultError> {
    use secretary_core::crypto::kem;
    use secretary_core::crypto::sig::MlDsa65Public;
    use secretary_core::identity::fingerprint::fingerprint;

    let owner_card_bytes = open.owner_card.to_canonical_cbor()?;
    let owner_fp = fingerprint(&owner_card_bytes);
    let owner_pk_bundle = open.owner_card.pk_bundle_bytes()?;
    let owner_pq_pk = MlDsa65Public::from_bytes(&open.owner_card.ml_dsa_65_pk)?;
    let reader_x_sk: kem::X25519Secret = Sensitive::new(*open.identity.x25519_sk.expose());
    let reader_pq_sk = kem::MlKem768Secret::from_bytes(open.identity.ml_kem_768_sk.expose())
        .map_err(secretary_core::vault::BlockError::from)?;

    let block_file = secretary_core::vault::decode_block_file(bytes)?;
    let plaintext = secretary_core::vault::decrypt_block(
        &block_file,
        &owner_fp,
        &owner_pk_bundle,
        &open.owner_card.ed25519_pk,
        &owner_pq_pk,
        &owner_fp,
        &owner_pk_bundle,
        &reader_x_sk,
        &reader_pq_sk,
    )?;
    Ok(plaintext)
}

/// Replace the named block's records using the caller's pre-unlocked
/// vault handle, re-encrypt with a deterministic per-rewrite RNG seeded
/// from `aead_nonce`, and write the new envelope to
/// `blocks/<uuid>.cbor.enc`. Returns the new block file's BLAKE3-256
/// fingerprint (32 bytes) — the value that belongs in
/// `BlockEntry.fingerprint` for callers that follow up with a manifest
/// rewrite.
///
/// Takes `&OpenVault` (not just `folder`) because as of C.1.1b D6 the
/// production `open_vault` rejects vaults whose manifest fingerprints
/// disagree with the on-disk block bytes — so two rewrites of the same
/// vault folder cannot share an internal `open_vault` call without a
/// matching manifest rewrite in between. Callers cache the
/// `OpenVault` from before the first rewrite; the IBK / identity /
/// owner_card it holds are independent of block fingerprints and
/// remain valid across rewrites. Task 9 introduces
/// `rewrite_block_with_records_and_update_manifest`, which composes
/// this primitive with the manifest re-sign step.
///
/// `aead_nonce` is the seed for [`rand_chacha::ChaCha20Rng`], not the
/// on-disk AEAD nonce: `encrypt_block` consumes RNG bytes for the BCK,
/// per-recipient KEM encapsulation, the wrap-AEAD nonce, AND the block
/// body AEAD nonce. Distinct seeds across rewrites produce distinct
/// BCKs and distinct body nonces, so AEAD uniqueness is preserved even
/// when two blocks are rewritten in the same vault directory (see
/// CLAUDE.md atomic-write section + C.1.1b design doc §Risks).
///
/// Mirrors the step 4-9 pattern in
/// `core::vault::orchestrators::save_block` for the encrypt-and-write
/// half. The block's per-block vector clock is **not** ticked here;
/// tests that need a specific clock must set it explicitly via a
/// follow-on `write_manifest_at` call. Likewise, this helper does NOT
/// update the manifest's `BlockEntry.fingerprint` — tests that want a
/// consistent post-rewrite vault must also re-sign the manifest with
/// the returned fingerprint.
#[allow(dead_code)]
pub fn rewrite_block_with_records(
    folder: &Path,
    open: &secretary_core::vault::OpenVault,
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    new_records: Vec<secretary_core::vault::Record>,
    aead_nonce: &[u8; AEAD_NONCE_LEN],
) -> [u8; 32] {
    let entry = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .cloned()
        .expect("block_uuid not in manifest");

    let (fp, bytes) = encrypt_block_bytes_for_uuid(
        open,
        block_uuid,
        new_records,
        entry.vector_clock_summary.clone(),
        entry.block_name.clone(),
        BTreeMap::new(),
        V1_BLOCK_VERSIONS,
        entry.created_at_ms,
        entry.last_mod_ms,
        aead_nonce,
    );

    let path = block_file_path(folder, &block_uuid);
    // Ensure blocks/ exists (golden vault always has it, but a future
    // caller may rewrite into a sparser fixture).
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create_dir_all blocks/");
    }
    std::fs::write(&path, &bytes).expect("write block file");

    fp
}
