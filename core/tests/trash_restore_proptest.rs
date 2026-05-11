//! Property tests for the trash → restore round-trip.
//!
//! The headline invariant: a `save_block → trash_block → restore_block`
//! sequence leaves the block file's on-disk bytes byte-identical and
//! therefore the manifest's `BlockEntry.fingerprint` (BLAKE3-256 of
//! those bytes) unchanged. This is the sync-correctness property —
//! restore is a continuation, not a fork — and it holds across the
//! input domain because `rename(2)` is a move, not a rewrite.
//!
//! Cases pinned at 16 to match `share_block_proptest`'s rationale:
//! per-case Argon2id-protected vault open dominates wall clock even at
//! the fast-KDF cost the integration fixture uses. Issue #38 tracks the
//! umbrella fix.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;

use proptest::prelude::*;
use proptest::test_runner::Config;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::unlock::{create_vault_unchecked, mnemonic::Mnemonic, vault_toml};
use secretary_core::vault::{
    encode_manifest_file, open_vault, restore_block, save_block, sign_manifest, trash_block,
    BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, Unlocker,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture (copy of trash_restore.rs::make_fast_vault) — kept inline to
// avoid a shared-fixture module that would couple unrelated integration
// test files. Issue #38 tracks the umbrella fix.
// ---------------------------------------------------------------------------

fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

fn make_fast_vault(seed: u8) -> (tempfile::TempDir, Mnemonic, SecretBytes) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let pw = SecretBytes::new(b"hunter2".to_vec());
    let created_at_ms = 1_714_060_800_000u64;
    let created =
        create_vault_unchecked(&pw, "Owner", created_at_ms, fast_kdf(), &mut rng).unwrap();

    let vt = vault_toml::decode(std::str::from_utf8(&created.vault_toml_bytes).unwrap()).unwrap();

    let pq_sk = MlDsa65Secret::from_bytes(created.identity.ml_dsa_65_sk.expose()).unwrap();
    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: created.identity.user_uuid,
        display_name: created.identity.display_name.clone(),
        x25519_pk: created.identity.x25519_pk,
        ml_kem_768_pk: created.identity.ml_kem_768_pk.clone(),
        ed25519_pk: created.identity.ed25519_pk,
        ml_dsa_65_pk: created.identity.ml_dsa_65_pk.clone(),
        created_at_ms: created.identity.created_at_ms,
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    card.sign(&created.identity.ed25519_sk, &pq_sk).unwrap();
    let owner_card_bytes = card.to_canonical_cbor().unwrap();
    let author_fp = fingerprint(&owner_card_bytes);

    let manifest_body = Manifest {
        manifest_version: 1,
        vault_uuid: vt.vault_uuid,
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        owner_user_uuid: created.identity.user_uuid,
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: KdfParamsRef {
            memory_kib: vt.kdf.memory_kib,
            iterations: vt.kdf.iterations,
            parallelism: vt.kdf.parallelism,
            salt: vt.kdf.salt,
        },
        unknown: BTreeMap::new(),
    };
    let header = ManifestHeader {
        vault_uuid: vt.vault_uuid,
        created_at_ms,
        last_mod_ms: created_at_ms,
    };
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let mf = sign_manifest(
        header,
        &manifest_body,
        &created.identity_block_key,
        &nonce,
        author_fp,
        &created.identity.ed25519_sk,
        &pq_sk,
    )
    .unwrap();
    let mf_bytes = encode_manifest_file(&mf).unwrap();

    let owner_uuid_hex = format_uuid_hyphenated(&created.identity.user_uuid);
    let contacts_dir = dir.path().join("contacts");
    fs::create_dir_all(&contacts_dir).unwrap();
    fs::write(dir.path().join("vault.toml"), &created.vault_toml_bytes).unwrap();
    fs::write(
        dir.path().join("identity.bundle.enc"),
        &created.identity_bundle_bytes,
    )
    .unwrap();
    fs::write(
        contacts_dir.join(format!("{owner_uuid_hex}.card")),
        &owner_card_bytes,
    )
    .unwrap();
    fs::write(dir.path().join("manifest.cbor.enc"), &mf_bytes).unwrap();

    (dir, created.recovery_mnemonic, pw)
}

fn format_uuid_hyphenated(uuid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn make_simple_plaintext(block_uuid: [u8; 16], block_name: String) -> BlockPlaintext {
    BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name,
        schema_version: 1,
        records: Vec::new(),
        unknown: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// proptest body
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(Config::with_cases(16))]

    /// Property: `save → trash → restore` preserves the BlockEntry's
    /// fingerprint over arbitrary block_uuid + block_name inputs. The
    /// fingerprint is BLAKE3-256 of the on-disk file bytes; `rename(2)`
    /// does not mutate file content, so the post-restore fingerprint
    /// matches the post-save fingerprint exactly.
    #[test]
    fn trash_restore_round_trip_preserves_block_fingerprint(
        block_uuid in proptest::array::uniform16(any::<u8>()),
        block_name in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let (dir, _mnemonic, pw) = make_fast_vault(0x42);
        let folder = dir.path();
        let mut rng = ChaCha20Rng::from_seed([0xc0; 32]);
        let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
        let device_uuid = [0xd0; 16];

        let plaintext = make_simple_plaintext(block_uuid, block_name);
        let recipients = vec![open.owner_card.clone()];
        save_block(folder, &mut open, plaintext, &recipients, device_uuid, 1_000, &mut rng).unwrap();
        let fp_after_save = open
            .manifest
            .blocks
            .iter()
            .find(|b| b.block_uuid == block_uuid)
            .unwrap()
            .fingerprint;

        trash_block(folder, &mut open, block_uuid, device_uuid, 2_000, &mut rng).unwrap();
        restore_block(folder, &mut open, block_uuid, device_uuid, 3_000, &mut rng).unwrap();

        let fp_after_restore = open
            .manifest
            .blocks
            .iter()
            .find(|b| b.block_uuid == block_uuid)
            .unwrap()
            .fingerprint;

        prop_assert_eq!(
            fp_after_save,
            fp_after_restore,
            "block fingerprint must be preserved across trash/restore"
        );
    }
}
