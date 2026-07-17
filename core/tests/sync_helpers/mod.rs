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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use secretary_core::crypto::secret::{SecretString, Sensitive};
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::vault::{
    encode_manifest_file, open_vault, sign_manifest, ManifestHeader, Record, RecordField,
    RecordFieldValue, Unlocker, VectorClockEntry,
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

/// Distinct rewrite-seed for the first block rewrite in C.1.1b fixtures.
/// Consumed as the seed for a deterministic [`rand_chacha::ChaCha20Rng`]
/// inside [`rewrite_block_with_records`], which means each rewrite
/// derives a distinct Block Content Key AND a distinct on-disk AEAD
/// body nonce — no key+nonce collision when multiple blocks are
/// rewritten in the same test (see the `AEAD-uniqueness` rationale in
/// the module-level docstring and CLAUDE.md's atomic-write section).
/// Annotated `dead_code` because the helper that consumes it lands in
/// this same Task 1 commit but its first caller in tests appears in
/// Task 9 (per the C.1.1b plan).
#[allow(dead_code)]
pub const BLOCK_NONCE_E: [u8; AEAD_NONCE_LEN] = [
    0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
    0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
];

/// Distinct rewrite-seed for the second block rewrite in C.1.1b
/// fixtures — used for sibling block envelopes in conflict-copy
/// ingestion tests. Same ChaCha20Rng-seed semantics as
/// [`BLOCK_NONCE_E`].
#[allow(dead_code)]
pub const BLOCK_NONCE_F: [u8; AEAD_NONCE_LEN] = [
    0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F,
    0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F,
];

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

// ---------------------------------------------------------------------------
// C.1.1b: per-block rewrite helpers
// ---------------------------------------------------------------------------

/// Number of UUID bytes used in vault on-disk identifiers (§4.2).
/// Local copy because the matching constant in `manifest::UUID_LEN` is
/// `pub(crate)` to the core crate.
const SYNC_HELPERS_UUID_LEN: usize = 16;

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

/// Pure-encryption variant of [`rewrite_block_with_records`]: build a
/// `BlockHeader` + `BlockPlaintext` from the supplied parameters, encrypt
/// via `encrypt_block` under the owner identity reachable from `open`,
/// CBOR-encode the resulting `BlockFile`, and return the BLAKE3-256
/// fingerprint + envelope bytes. Performs **no I/O** — callers decide
/// where on disk to put the resulting envelope (canonical path,
/// sibling-suffix path, etc.).
///
/// Used by both [`rewrite_block_with_records`] (single canonical write)
/// and [`fresh_vault_two_concurrent_blocks`] (canonical + sibling block
/// pair). Splitting the encryption from the file write lets the
/// two-block fixture vary `block_clock` and `block_seed` per envelope
/// without re-deriving the owner keys.
///
/// `block_clock` is written verbatim into both the `BlockHeader.vector_clock`
/// (signed inside the block envelope) AND the `BlockPlaintext` record
/// list — the caller is responsible for matching this against the
/// manifest's `BlockEntry.vector_clock_summary` for self-consistency
/// (D6 doesn't check it, but `prepare_merge`'s veto detection compares
/// against the manifest copy, not the block header).
///
/// `block_name` / `created_at_ms` / `last_mod_ms` mirror save_block's
/// step 4-9 pattern. `last_mod_ms` is the moment-of-rewrite stamp; the
/// canonical block's existing value is preserved when this is called
/// from the no-mutation path.
///
/// `aead_seed` is the 24-byte rewrite seed for `ChaCha20Rng::from_seed`;
/// see [`rewrite_block_with_records`]'s docstring for the seed-vs-nonce
/// rationale and AEAD-uniqueness invariant.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
fn encrypt_block_bytes_for_uuid(
    open: &secretary_core::vault::OpenVault,
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    new_records: Vec<secretary_core::vault::Record>,
    block_clock: Vec<VectorClockEntry>,
    block_name: String,
    created_at_ms: u64,
    last_mod_ms: u64,
    aead_seed: &[u8; AEAD_NONCE_LEN],
) -> ([u8; 32], Vec<u8>) {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use secretary_core::crypto::kem::MlKem768Public;
    use secretary_core::identity::fingerprint::fingerprint;
    use secretary_core::vault::{
        encode_block_file, encrypt_block, BlockHeader, BlockPlaintext, RecipientPublicKeys,
        FILE_KIND_BLOCK,
    };

    // Spec-pinned protocol version literals for §6.3 BlockPlaintext;
    // every other call site in the codebase uses these same constants
    // (`save_block` core path, `save_block.rs` test fixtures).
    const BLOCK_VERSION_V1: u32 = 1;
    const SCHEMA_VERSION_V1: u32 = 1;

    // Re-derive owner sender keys (mirrors save_block step 4 setup).
    let owner_card_bytes = open.owner_card.to_canonical_cbor().expect("card cbor");
    let owner_fp = fingerprint(&owner_card_bytes);
    let owner_pk_bundle = open.owner_card.pk_bundle_bytes().expect("pk bundle");
    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk =
        MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).expect("ml-dsa sk");

    // Recipient list: golden vault is owner-only, so the rewritten
    // envelope's recipient table also contains exactly the owner.
    // `RecipientPublicKeys` takes the KEM keys (x25519 + ml-kem-768)
    // and the canonical pk_bundle bytes; the recipient DSA pk is not
    // part of this struct (it's the *sender* DSA secret that signs).
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
        records: new_records,
        unknown: std::collections::BTreeMap::new(),
    };

    // `ChaCha20Rng::from_seed` takes a 32-byte seed; the BLOCK_NONCE_*
    // constants are 24 bytes (the AEAD-nonce length). Copy them into
    // the first 24 bytes of the seed and leave the trailing 8 bytes
    // zero — distinct callers must pass nonces that differ in the
    // first 24 bytes, which all three BLOCK_NONCE_E/F/G do. Don't
    // "fix" the trailing zeros by injecting randomness here: that
    // would break determinism, which the `distinct_seeds_produce_
    // distinct_ciphertexts` invariant depends on.
    let mut seed = [0u8; 32];
    seed[..AEAD_NONCE_LEN].copy_from_slice(aead_seed);
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

/// Rewrite the block at `block_uuid` with `new_records` (via
/// [`rewrite_block_with_records`]) AND update the canonical manifest
/// so its `BlockEntry.fingerprint` matches the new on-disk bytes and
/// its top-level `vector_clock` is set to `manifest_clock`. The
/// resulting on-disk pair (manifest + block) opens cleanly: a fresh
/// [`open_vault`] succeeds because `verify_block_fingerprints` agrees
/// with the rewritten block.
///
/// **Why a dedicated helper?** Post-C.1.1b D6, `open_vault` rejects
/// any vault whose manifest disagrees with on-disk block bytes. A
/// naive "rewrite block, then open, then re-sign manifest" sequence
/// fails at step 2. This helper instead re-signs the manifest
/// **in-process from the caller's cached `OpenVault` handle**, never
/// re-reading disk during the inconsistent window. That same cached
/// handle (the IBK / identity / owner_card it carries) drives both
/// the block-rewrite and the manifest re-sign — see
/// [`rewrite_block_with_records`] for the same rationale.
///
/// Returns the new block file's BLAKE3-256 fingerprint (also written
/// into the manifest); useful to callers that want to assert on the
/// fingerprint or pass it forward to a sibling-manifest writer.
///
/// The block's per-block `vector_clock_summary` and `last_modifier_device`
/// are **preserved verbatim** from the cached manifest. Tasks that need
/// to force per-block divergence between canonical and sibling
/// manifests must extend this helper (or compose with a future sibling
/// writer) — out of scope for Task 9, which only needs a clean post-
/// rewrite vault for the merge-layer smoke test.
///
/// **Test helper: not crash-safe.** The block file is written before
/// the manifest is re-signed, so a crash between the two `std::fs::write`
/// calls leaves a `BlockEntry.fingerprint` that disagrees with the
/// on-disk block — exactly the state the C.1.1b D6 gate rejects on
/// the next `open_vault`. For test fixtures this just corrupts a
/// `tempfile::TempDir` that the test owns end-to-end; do NOT adapt
/// this sequence for production code paths. Production sync orchestrators
/// must use the atomic-write primitives in [`secretary_core::vault::io`]
/// (see CLAUDE.md "Atomic-write contract").
///
/// `block_seed` and `manifest_nonce` MUST differ — they feed two
/// independent AEAD encryptions under keys derived from the same
/// `OpenVault` (IBK for the manifest body, BCK for the block body),
/// and the helper enforces the constraint via `assert_ne!` so
/// accidental nonce reuse is caught at the call site rather than
/// silently weakening AEAD uniqueness. The check is `assert_ne!` (not
/// `debug_assert_ne!`) because the project's standard gauntlet runs
/// `cargo test --release`, where `debug_assertions = false` would
/// silently compile the check out. See the per-rewrite ChaCha20Rng
/// seeding rationale on [`rewrite_block_with_records`] and the
/// `AEAD-uniqueness` paragraph in CLAUDE.md's atomic-write section.
#[allow(dead_code)]
pub fn rewrite_block_with_records_and_update_manifest(
    folder: &Path,
    open: &secretary_core::vault::OpenVault,
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    new_records: Vec<secretary_core::vault::Record>,
    block_seed: &[u8; AEAD_NONCE_LEN],
    manifest_clock: Vec<VectorClockEntry>,
    manifest_nonce: &[u8; AEAD_NONCE_LEN],
) -> [u8; 32] {
    assert_ne!(
        block_seed, manifest_nonce,
        "block_seed and manifest_nonce must differ — sharing them would seed two AEAD \
         encryptions in the same vault with identical 24-byte material, defeating the \
         AEAD-uniqueness invariant (see CLAUDE.md atomic-write section)",
    );

    let new_fingerprint =
        rewrite_block_with_records(folder, open, block_uuid, new_records, block_seed);

    // Build the new manifest body in-process: same Manifest as the
    // cached handle, except the target block's fingerprint and the
    // top-level vector_clock are replaced.
    let mut new_manifest = open.manifest.clone();
    let idx = new_manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .unwrap_or_else(|| {
            panic!(
                "block_uuid {block_uuid:?} not present in cached manifest \
                 (rewrite_block_with_records_and_update_manifest)"
            )
        });
    new_manifest.blocks[idx].fingerprint = new_fingerprint;
    new_manifest.vector_clock = manifest_clock;

    // Re-derive owner signer keys (mirrors the [`write_manifest_at`]
    // setup but driven from the cached `OpenVault` rather than a fresh
    // [`open_vault`] call — see the helper docstring for why).
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
        &new_manifest,
        &open.identity_block_key,
        manifest_nonce,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )
    .expect("sign_manifest");

    let manifest_bytes = encode_manifest_file(&new_manifest_file).expect("encode_manifest_file");
    std::fs::write(folder.join(MANIFEST_FILENAME), &manifest_bytes).expect("write manifest");

    new_fingerprint
}

/// Per-block-divergent two-manifest fixture for C.1.1b Task 13's veto
/// tests. Writes BOTH a canonical block file (with `canonical_records`)
/// AND a sibling block file at
/// `blocks/<uuid>.cbor.enc<sibling_block_suffix>` (with `sibling_records`),
/// then re-signs the canonical manifest AND writes a sibling manifest
/// such that:
///
/// 1. The canonical manifest's `BlockEntry[block_uuid]` has
///    `fingerprint = BLAKE3(canonical_block_bytes)` and
///    `vector_clock_summary = canonical_block_clock`.
/// 2. The sibling manifest's `BlockEntry[block_uuid]` has
///    `fingerprint = BLAKE3(sibling_block_bytes)` and
///    `vector_clock_summary = sibling_block_clock`.
/// 3. Both manifests' top-level `vector_clock` are set per the
///    `*_manifest_clock` arguments.
///
/// This drives the C.1.1a ingest layer to emit a non-empty
/// `bundle.diverging_blocks` (because the canonical + sibling
/// `vector_clock_summary` for the same block_uuid are concurrent) and
/// `prepare_merge`'s [`crate::sync::parent_block_clock`] fingerprint
/// match to bind each block envelope to the correct manifest's
/// per-block clock.
///
/// The post-fixture vault opens cleanly: D6 only checks the CANONICAL
/// manifest's `BlockEntry.fingerprint` against the on-disk file at
/// `blocks/<uuid>.cbor.enc` — the sibling block file is invisible to
/// `verify_block_fingerprints`. The sibling manifest's claim of a
/// different fingerprint is fine because D6 doesn't inspect sibling
/// manifests.
///
/// Pre-condition: `block_uuid` MUST exist in `golden_vault_001`'s
/// manifest (caller obtains via [`golden_vault_001_first_block_uuid`]
/// for the single-block fixture, or knows the UUID a priori for a
/// fresh-built multi-block fixture).
///
/// Constraints on caller:
/// - `canonical_block_clock` and `sibling_block_clock` MUST be
///   concurrent (or sibling strictly dominate canonical) — otherwise
///   `ingest_block_divergence` skips this block and the bundle's
///   `diverging_blocks` is empty (same outcome as Task 9's smoke test).
/// - `canonical_manifest_clock` and `sibling_manifest_clock` MUST be
///   concurrent — otherwise `sync_once` returns a non-`ConcurrentDetected`
///   outcome and the merge pipeline never engages.
/// - `sibling_block_suffix` MUST start with a non-empty separator
///   (e.g. `".sync-conflict-from-device-bb"`) so the resulting filename
///   is recognized as a sibling by
///   [`crate::sync::enumerate_block_siblings`] (any filename strictly
///   starting with `<uuid>.cbor.enc` and not equal to it qualifies).
/// - `sibling_manifest_filename` MUST start with `"manifest.cbor.enc"`
///   for the same reason — see Task 8's existing helpers for the
///   convention.
///
/// `now_ms` is written into both blocks' `header.last_mod_ms` AND both
/// manifests' `BlockEntry.last_mod_ms` for the block_uuid (mirroring
/// `commit_with_decisions`'s step 5-6 production behavior at the
/// fixture level).
///
/// Returns `(folder, tmp)` — caller keeps `tmp` alive for the test scope.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn fresh_vault_two_concurrent_blocks(
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    canonical_records: Vec<secretary_core::vault::Record>,
    canonical_block_clock: Vec<VectorClockEntry>,
    canonical_manifest_clock: Vec<VectorClockEntry>,
    sibling_records: Vec<secretary_core::vault::Record>,
    sibling_block_clock: Vec<VectorClockEntry>,
    sibling_manifest_clock: Vec<VectorClockEntry>,
    sibling_manifest_filename: &str,
    sibling_block_suffix: &str,
    now_ms: u64,
) -> (PathBuf, tempfile::TempDir) {
    // Step 1: fresh copy of golden_vault_001 into a temp dir. The
    // canonical manifest's top-level clock is set to a placeholder
    // (we'll overwrite it in step 5); using an empty clock here means
    // the temp vault opens cleanly via the standard fresh helper.
    let (folder, tmp) = fresh_vault_with_clock(Vec::new());

    // Step 2: open the vault to cache identity material. The cached
    // handle drives both block encryptions AND both manifest re-signs
    // without ever re-reading disk during the fingerprint-inconsistent
    // window (mirrors the pattern in
    // [`rewrite_block_with_records_and_update_manifest`]).
    let password = fixtures::golden_vault_001_password();
    let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open_vault");

    // Step 3: encrypt the canonical block + sibling block in-process.
    // Both use the existing per-block name + created_at_ms from the
    // golden vault entry; the block_clock + records + AEAD seed vary
    // per envelope.
    let golden_entry = open
        .manifest
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .cloned()
        .expect("block_uuid not in golden manifest");

    let (canonical_fp, canonical_bytes) = encrypt_block_bytes_for_uuid(
        &open,
        block_uuid,
        canonical_records,
        canonical_block_clock.clone(),
        golden_entry.block_name.clone(),
        golden_entry.created_at_ms,
        now_ms,
        &BLOCK_NONCE_E,
    );
    let (sibling_fp, sibling_bytes) = encrypt_block_bytes_for_uuid(
        &open,
        block_uuid,
        sibling_records,
        sibling_block_clock.clone(),
        golden_entry.block_name.clone(),
        golden_entry.created_at_ms,
        now_ms,
        &BLOCK_NONCE_F,
    );

    // Step 4: write both block files. Canonical goes to the
    // production path; sibling goes to the suffix path.
    let canonical_path = block_file_path(&folder, &block_uuid);
    if let Some(parent) = canonical_path.parent() {
        std::fs::create_dir_all(parent).expect("create_dir_all blocks/");
    }
    std::fs::write(&canonical_path, &canonical_bytes).expect("write canonical block");

    let sibling_path = canonical_path.with_file_name(format!(
        "{stem}{suffix}",
        stem = canonical_path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("canonical path utf-8"),
        suffix = sibling_block_suffix,
    ));
    std::fs::write(&sibling_path, &sibling_bytes).expect("write sibling block");

    // Step 5: build + sign the canonical manifest. Update its
    // BlockEntry.fingerprint / vector_clock_summary / last_mod_ms for
    // block_uuid; set the manifest-level vector_clock.
    write_manifest_with_block_entry(
        &folder,
        &open,
        MANIFEST_FILENAME,
        block_uuid,
        canonical_fp,
        canonical_block_clock,
        canonical_manifest_clock,
        now_ms,
        &CANONICAL_NONCE_A,
    );

    // Step 6: build + sign the sibling manifest. Same structure as
    // canonical but with sibling fingerprint + clocks, written to the
    // sibling filename.
    write_manifest_with_block_entry(
        &folder,
        &open,
        sibling_manifest_filename,
        block_uuid,
        sibling_fp,
        sibling_block_clock,
        sibling_manifest_clock,
        now_ms,
        &SIBLING_NONCE_B,
    );

    drop(open);
    (folder, tmp)
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
fn write_manifest_with_block_entry(
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

#[cfg(test)]
mod helper_tests {
    use super::*;

    /// Smoke: rewriting a block in the temp vault produces a file
    /// that decrypts back to the supplied (here: empty) record set
    /// using the owner identity. Proves
    /// [`rewrite_block_with_records`] + [`decrypt_block_using_open`]
    /// agree on the wire format.
    ///
    /// The cached `OpenVault` handle is taken BEFORE any rewrite so
    /// that the cached manifest matches the on-disk block fingerprints
    /// at open time (C.1.1b D6 — `open_vault` rejects any vault whose
    /// manifest fingerprints disagree with the block bytes). Decryption
    /// itself only consumes the IBK / identity / owner_card on the
    /// handle, which are immune to block-byte changes.
    #[test]
    fn rewrite_block_with_records_round_trips() {
        let golden_clock = vec![VectorClockEntry {
            device_uuid: [9; SYNC_HELPERS_UUID_LEN],
            counter: 1,
        }];
        let (folder, _tmp) = fresh_vault_with_clock(golden_clock);

        let block_uuid = golden_vault_001_first_block_uuid(&folder);
        let new_records: Vec<secretary_core::vault::Record> = Vec::new();

        let password = fixtures::golden_vault_001_password();
        let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");

        let new_fingerprint = rewrite_block_with_records(
            &folder,
            &open,
            block_uuid,
            new_records.clone(),
            &BLOCK_NONCE_E,
        );
        // Fingerprint must be a real BLAKE3-256 (non-zero with high
        // probability over fresh ciphertext); cheap sanity check that
        // we didn't silently return an all-zero placeholder.
        assert_ne!(new_fingerprint, [0u8; 32]);

        let block_path = block_file_path(&folder, &block_uuid);
        let bytes = std::fs::read(&block_path).expect("read block");
        let plaintext = decrypt_block_using_open(&open, &bytes).expect("decrypt");
        assert_eq!(plaintext.records, new_records);
        assert_eq!(plaintext.block_uuid, block_uuid);
    }

    /// After [`rewrite_block_with_records_and_update_manifest`] runs
    /// once, the vault on disk opens cleanly: `verify_block_fingerprints`
    /// (the C.1.1b D6 gate inside `open_vault`) sees the manifest's new
    /// `BlockEntry.fingerprint` matches the rewritten block bytes. This
    /// proves the helper actually re-signs the manifest in-process and
    /// the canonical state is consistent post-rewrite — which is the
    /// pre-condition every downstream merge-layer integration test
    /// relies on.
    #[test]
    fn rewrite_block_and_update_manifest_round_trips_through_open_vault() {
        let initial_clock = vec![VectorClockEntry {
            device_uuid: [9; SYNC_HELPERS_UUID_LEN],
            counter: 1,
        }];
        let (folder, _tmp) = fresh_vault_with_clock(initial_clock);

        let block_uuid = golden_vault_001_first_block_uuid(&folder);
        let password = fixtures::golden_vault_001_password();
        let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");

        let device_a = [0x0A; SYNC_HELPERS_UUID_LEN];
        let post_rewrite_clock = vec![VectorClockEntry {
            device_uuid: device_a,
            counter: 2,
        }];
        let new_fp = rewrite_block_with_records_and_update_manifest(
            &folder,
            &open,
            block_uuid,
            Vec::new(),
            &BLOCK_NONCE_E,
            post_rewrite_clock.clone(),
            &CANONICAL_NONCE_A,
        );
        // Cheap sanity: BLAKE3-256 of a real encrypted block is
        // overwhelmingly unlikely to be all-zero.
        assert_ne!(new_fp, [0u8; 32]);

        // The D6 round-trip assertion: open_vault must succeed AND the
        // returned manifest must reflect both the new fingerprint and
        // the new top-level clock.
        let reopened = open_vault(&folder, Unlocker::Password(&password), None)
            .expect("post-rewrite open_vault must succeed");
        let entry = reopened
            .manifest
            .blocks
            .iter()
            .find(|b| b.block_uuid == block_uuid)
            .expect("block still in manifest");
        assert_eq!(
            entry.fingerprint, new_fp,
            "manifest BlockEntry.fingerprint must match the rewritten block fingerprint"
        );
        assert_eq!(
            reopened.manifest.vector_clock, post_rewrite_clock,
            "manifest top-level vector_clock must reflect the helper's update"
        );
    }

    /// Passing the same 24-byte value for `block_seed` and
    /// `manifest_nonce` must panic at the call site rather than silently
    /// seeding two AEAD encryptions in the same vault with identical
    /// material. The check is `assert_ne!` (not `debug_assert_ne!`) so
    /// it survives `cargo test --release` — confirmed here by running
    /// the panic-path under the project's standard release gauntlet.
    #[test]
    #[should_panic(expected = "block_seed and manifest_nonce must differ")]
    fn rewrite_block_and_update_manifest_panics_on_shared_nonce() {
        let initial_clock = vec![VectorClockEntry {
            device_uuid: [9; SYNC_HELPERS_UUID_LEN],
            counter: 1,
        }];
        let (folder, _tmp) = fresh_vault_with_clock(initial_clock);
        let block_uuid = golden_vault_001_first_block_uuid(&folder);
        let password = fixtures::golden_vault_001_password();
        let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");

        let _ = rewrite_block_with_records_and_update_manifest(
            &folder,
            &open,
            block_uuid,
            Vec::new(),
            &BLOCK_NONCE_E,
            Vec::new(),
            &BLOCK_NONCE_E,
        );
    }

    /// Two rewrites with distinct seed nonces must produce distinct
    /// on-disk bytes (and therefore distinct fingerprints). Proves
    /// the per-rewrite ChaCha20Rng seeding actually delivers distinct
    /// BCK + AEAD body nonces, so callers can rewrite multiple blocks
    /// in the same vault without AEAD key+nonce reuse.
    ///
    /// The cached `OpenVault` handle is taken before the first rewrite
    /// — see `rewrite_block_with_records_round_trips` for the same
    /// rationale (C.1.1b D6).
    #[test]
    fn rewrite_block_with_records_distinct_seeds_produce_distinct_ciphertexts() {
        let golden_clock = vec![VectorClockEntry {
            device_uuid: [9; SYNC_HELPERS_UUID_LEN],
            counter: 1,
        }];
        let (folder, _tmp) = fresh_vault_with_clock(golden_clock);
        let block_uuid = golden_vault_001_first_block_uuid(&folder);

        let password = fixtures::golden_vault_001_password();
        let open = open_vault(&folder, Unlocker::Password(&password), None).expect("open");

        let fp_e =
            rewrite_block_with_records(&folder, &open, block_uuid, Vec::new(), &BLOCK_NONCE_E);
        let bytes_after_e = std::fs::read(block_file_path(&folder, &block_uuid)).expect("read");

        let fp_f =
            rewrite_block_with_records(&folder, &open, block_uuid, Vec::new(), &BLOCK_NONCE_F);
        let bytes_after_f = std::fs::read(block_file_path(&folder, &block_uuid)).expect("read");

        assert_ne!(
            fp_e, fp_f,
            "distinct seeds must yield distinct block fingerprints"
        );
        assert_ne!(
            bytes_after_e, bytes_after_f,
            "distinct seeds must yield distinct on-disk envelopes (AEAD uniqueness proof)"
        );
    }

    /// Smoke: [`fresh_vault_two_concurrent_blocks`] produces a vault
    /// folder where:
    ///
    /// 1. The canonical manifest opens cleanly via the standard
    ///    `open_vault` path (D6 fingerprint gate sees the canonical
    ///    block file matches `BlockEntry.fingerprint`).
    /// 2. Both the canonical block file AND the sibling block file
    ///    exist on disk under the expected paths.
    /// 3. The canonical manifest's BlockEntry for `block_uuid` carries
    ///    the canonical block's fingerprint + the supplied
    ///    `canonical_block_clock`.
    /// 4. The two block files have distinct on-disk bytes (proves the
    ///    canonical vs sibling encryptions used distinct AEAD seeds).
    /// 5. The SIBLING manifest decrypts cleanly under the same identity
    ///    and carries SIBLING-side data: its `BlockEntry` references the
    ///    sibling block's fingerprint + `sibling_block_clock`, and its
    ///    top-level `vector_clock` equals `sibling_manifest_clock`. This
    ///    rules out an accidental copy of canonical data into the
    ///    sibling manifest by `write_manifest_with_block_entry` — the
    ///    downstream Task 13 tests would catch a swap via
    ///    `plan.diverging_blocks` non-empty, but the failure mode would
    ///    point at `ingest_block_divergence`, not the fixture builder.
    ///
    /// Acceptance for downstream Task 13 tests: this fixture produces
    /// a per-block-divergent state that `sync_once` will detect as
    /// concurrent AND `ingest_block_divergence` will include in
    /// `bundle.diverging_blocks`.
    #[test]
    fn fresh_vault_two_concurrent_blocks_produces_consistent_canonical_with_sibling_on_disk() {
        use secretary_core::crypto::aead::AEAD_TAG_LEN;
        use secretary_core::vault::manifest::{decode_manifest_file, decrypt_manifest_body};

        let device_a = [0x0A; SYNC_HELPERS_UUID_LEN];
        let device_b = [0x0B; SYNC_HELPERS_UUID_LEN];

        let canonical_block_clock = vec![VectorClockEntry {
            device_uuid: device_a,
            counter: 1,
        }];
        let canonical_manifest_clock = canonical_block_clock.clone();
        let sibling_block_clock = vec![VectorClockEntry {
            device_uuid: device_b,
            counter: 1,
        }];
        let sibling_manifest_clock = sibling_block_clock.clone();

        // Discover the golden vault's first block_uuid via a throwaway
        // open. Using the same UUID for both canonical + sibling is
        // the per-block-divergent shape Task 13's tests require.
        let (probe_folder, _probe_tmp) = fresh_vault_with_clock(Vec::new());
        let block_uuid = golden_vault_001_first_block_uuid(&probe_folder);

        const SIBLING_MF_FILENAME: &str = "manifest.cbor.enc.sync-conflict-from-device-bb";
        const SIBLING_BLOCK_SUFFIX: &str = ".sync-conflict-from-device-bb";

        let (folder, _tmp) = fresh_vault_two_concurrent_blocks(
            block_uuid,
            Vec::new(),
            canonical_block_clock.clone(),
            canonical_manifest_clock,
            Vec::new(),
            sibling_block_clock.clone(),
            sibling_manifest_clock.clone(),
            SIBLING_MF_FILENAME,
            SIBLING_BLOCK_SUFFIX,
            1_000_000,
        );

        // D6 round-trip: the canonical manifest must open cleanly.
        let password = fixtures::golden_vault_001_password();
        let open = open_vault(&folder, Unlocker::Password(&password), None)
            .expect("canonical manifest must open after fixture build");
        let entry = open
            .manifest
            .blocks
            .iter()
            .find(|b| b.block_uuid == block_uuid)
            .expect("block_uuid in canonical manifest");
        assert_eq!(
            entry.vector_clock_summary, canonical_block_clock,
            "canonical manifest must carry the fixture-supplied canonical_block_clock",
        );

        let canonical_path = block_file_path(&folder, &block_uuid);
        let sibling_path = canonical_path.with_file_name(format!(
            "{stem}{SIBLING_BLOCK_SUFFIX}",
            stem = canonical_path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8"),
        ));
        let canonical_bytes = std::fs::read(&canonical_path).expect("read canonical block");
        let sibling_bytes = std::fs::read(&sibling_path).expect("read sibling block");
        assert_ne!(
            canonical_bytes, sibling_bytes,
            "canonical and sibling block files must have distinct on-disk bytes",
        );

        // Decrypt + inspect the sibling manifest. Closes the gap where a
        // bug in [`write_manifest_with_block_entry`] could write
        // canonical data to both manifests — the downstream Task 13
        // tests rely on the sibling manifest carrying the sibling
        // fingerprint to drive `bundle.diverging_blocks` non-empty.
        let sibling_mf_bytes =
            std::fs::read(folder.join(SIBLING_MF_FILENAME)).expect("read sibling manifest");
        let sibling_mf =
            decode_manifest_file(&sibling_mf_bytes).expect("decode sibling manifest envelope");
        let mut ct_with_tag = Vec::with_capacity(sibling_mf.aead_ct.len() + AEAD_TAG_LEN);
        ct_with_tag.extend_from_slice(&sibling_mf.aead_ct);
        ct_with_tag.extend_from_slice(&sibling_mf.aead_tag);
        let sibling_body = decrypt_manifest_body(
            &sibling_mf.header,
            &ct_with_tag,
            &open.identity_block_key,
            &sibling_mf.aead_nonce,
        )
        .expect("decrypt sibling manifest body");

        assert_eq!(
            sibling_body.vector_clock, sibling_manifest_clock,
            "sibling manifest's top-level vector_clock must equal sibling_manifest_clock",
        );

        let sibling_entry = sibling_body
            .blocks
            .iter()
            .find(|b| b.block_uuid == block_uuid)
            .expect("block_uuid in sibling manifest");
        assert_eq!(
            sibling_entry.vector_clock_summary, sibling_block_clock,
            "sibling manifest's BlockEntry must reference sibling_block_clock, not canonical",
        );
        let sibling_fp = *secretary_core::crypto::hash::hash(&sibling_bytes).as_bytes();
        assert_eq!(
            sibling_entry.fingerprint, sibling_fp,
            "sibling manifest's BlockEntry.fingerprint must reference the sibling block file's bytes",
        );
        assert_ne!(
            sibling_entry.fingerprint, entry.fingerprint,
            "sibling manifest's BlockEntry.fingerprint must differ from canonical's",
        );
    }
}
