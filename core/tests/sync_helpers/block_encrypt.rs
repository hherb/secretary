//! Pure block encryption (no I/O) shared by the rewrite and conflict-copy fixtures.

use super::*;

/// `(block_version, schema_version)` for a v1 block plaintext (§6.3), the
/// pair every fixture block carries unless a test sets another.
#[allow(dead_code)]
pub const V1_BLOCK_VERSIONS: (u32, u32) = (1, 1);

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
/// `versions` is the plaintext `(block_version, schema_version)`; pass
/// [`V1_BLOCK_VERSIONS`] unless a test needs a later client's block.
///
/// `aead_seed` is the 24-byte rewrite seed for `ChaCha20Rng::from_seed`;
/// see [`rewrite_block_with_records`]'s docstring for the seed-vs-nonce
/// rationale and AEAD-uniqueness invariant.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(super) fn encrypt_block_bytes_for_uuid(
    open: &secretary_core::vault::OpenVault,
    block_uuid: [u8; SYNC_HELPERS_UUID_LEN],
    new_records: Vec<secretary_core::vault::Record>,
    block_clock: Vec<VectorClockEntry>,
    block_name: String,
    unknown: BTreeMap<String, secretary_core::vault::record::UnknownValue>,
    versions: (u32, u32),
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
        block_version: versions.0,
        block_uuid,
        block_name,
        schema_version: versions.1,
        records: new_records,
        unknown,
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
