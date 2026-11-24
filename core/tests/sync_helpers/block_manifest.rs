//! Rewrite a block and re-sign the canonical manifest so the vault still opens.

use super::*;

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
