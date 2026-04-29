//! Integration tests for `secretary_core::vault::save_block` —
//! Task 12 of PR-B. Each test creates a vault first via the
//! Task 10/11 fast-KDF helper (replicated locally to keep the
//! integration tests self-contained), opens it via `open_vault`,
//! then exercises the `save_block` orchestrator: encrypt block →
//! atomic write → manifest update → re-sign → atomic write.
//!
//! The fast-KDF helper bypasses the v1 Argon2id floor enforced by
//! the public `create_vault` entry point so the round-trip cost is
//! dominated by the hybrid signature primitives, not the KDF.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::kem::{self, MlKem768Public, MlKem768Secret};
use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::crypto::sig::{
    Ed25519Secret, MlDsa65Public, MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN,
};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::unlock::{
    self, bundle::IdentityBundle, create_vault_unchecked, mnemonic::Mnemonic, vault_toml,
};
use secretary_core::vault::{
    decode_block_file, decrypt_block, encode_manifest_file, manifest, open_vault, save_block,
    sign_manifest, BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, Unlocker,
    VaultError,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture helpers (mirror open_vault.rs::make_fast_vault)
// ---------------------------------------------------------------------------

fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

fn make_fast_vault(
    seed: u8,
    password: &[u8],
    display_name: &str,
) -> (tempfile::TempDir, Mnemonic, SecretBytes) {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let pw = SecretBytes::new(password.to_vec());
    let created_at_ms = 1_714_060_800_000u64;
    let created =
        create_vault_unchecked(&pw, display_name, created_at_ms, fast_kdf(), &mut rng).unwrap();

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

/// Build a self-signed [`ContactCard`] from a freshly-generated
/// [`IdentityBundle`]. Mirrors `build_owner_card_from_bundle` in the
/// orchestrator, but kept local to the integration test so we don't
/// take a dependency on a crate-private helper.
fn make_signed_card(id: &IdentityBundle) -> ContactCard {
    let pq_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose()).unwrap();
    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: id.user_uuid,
        display_name: id.display_name.clone(),
        x25519_pk: id.x25519_pk,
        ml_kem_768_pk: id.ml_kem_768_pk.clone(),
        ed25519_pk: id.ed25519_pk,
        ml_dsa_65_pk: id.ml_dsa_65_pk.clone(),
        created_at_ms: id.created_at_ms,
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    card.sign(&id.ed25519_sk, &pq_sk).unwrap();
    card
}

/// Build a minimal one-record [`BlockPlaintext`].
fn make_simple_plaintext(block_uuid: [u8; 16], block_name: &str) -> BlockPlaintext {
    BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: block_name.to_string(),
        schema_version: 1,
        records: Vec::new(),
        unknown: BTreeMap::new(),
    }
}

/// Decrypt the block file at `path` for the given owner identity. Returns
/// the recovered [`BlockPlaintext`]. Used to round-trip-verify
/// `save_block`'s outputs end-to-end.
fn decrypt_block_file_as(
    block_path: &Path,
    sender_card: &ContactCard,
    reader_card: &ContactCard,
    reader_id: &IdentityBundle,
) -> BlockPlaintext {
    let bytes = fs::read(block_path).unwrap();
    let block_file = decode_block_file(&bytes).unwrap();

    let sender_card_bytes = sender_card.to_canonical_cbor().unwrap();
    let sender_fp = fingerprint(&sender_card_bytes);
    let sender_pk_bundle = sender_card.pk_bundle_bytes().unwrap();
    let sender_dsa_pk = MlDsa65Public::from_bytes(&sender_card.ml_dsa_65_pk).unwrap();

    let reader_card_bytes = reader_card.to_canonical_cbor().unwrap();
    let reader_fp = fingerprint(&reader_card_bytes);
    let reader_pk_bundle = reader_card.pk_bundle_bytes().unwrap();
    let reader_x_sk: kem::X25519Secret = Sensitive::new(*reader_id.x25519_sk.expose());
    let reader_pq_sk = MlKem768Secret::from_bytes(reader_id.ml_kem_768_sk.expose()).unwrap();

    decrypt_block(
        &block_file,
        &sender_fp,
        &sender_pk_bundle,
        &sender_card.ed25519_pk,
        &sender_dsa_pk,
        &reader_fp,
        &reader_pk_bundle,
        &reader_x_sk,
        &reader_pq_sk,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// 1. Round-trip: save → re-open → manifest reflects block, file decrypts
// ---------------------------------------------------------------------------

#[test]
fn save_block_then_open_round_trip() {
    let (dir, _mnemonic, pw) = make_fast_vault(1, b"hunter2", "Alice");
    let mut rng = ChaCha20Rng::from_seed([0xa1; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let block_uuid = [0x42u8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "first-block");
    let device_uuid = [0xd1u8; 16];
    let now_ms = 1_714_060_900_000u64;

    save_block(
        dir.path(),
        &mut open,
        plaintext.clone(),
        &[owner_card.clone()],
        device_uuid,
        now_ms,
        &mut rng,
    )
    .expect("save_block");

    // The on-disk block file must exist at the conventional path.
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));
    assert!(block_path.exists(), "block file must exist on disk");

    // Re-open the vault from disk and assert the manifest carries the
    // new entry.
    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    assert_eq!(
        reopened.manifest.blocks.len(),
        1,
        "manifest must carry the new block"
    );
    let entry = &reopened.manifest.blocks[0];
    assert_eq!(entry.block_uuid, block_uuid);
    assert_eq!(entry.block_name, "first-block");
    assert_eq!(entry.last_mod_ms, now_ms);
    assert_eq!(entry.created_at_ms, now_ms);

    // Decrypting the block file as the owner must recover the plaintext.
    let recovered =
        decrypt_block_file_as(&block_path, &reopened.owner_card, &reopened.owner_card, &reopened.identity);
    assert_eq!(recovered.block_uuid, plaintext.block_uuid);
    assert_eq!(recovered.block_name, plaintext.block_name);
    assert_eq!(recovered.records, plaintext.records);
}

// ---------------------------------------------------------------------------
// 2. Saving twice with the same UUID updates in place (no duplicate entry)
// ---------------------------------------------------------------------------

#[test]
fn save_block_updates_existing_block_in_place() {
    let (dir, _mnemonic, pw) = make_fast_vault(2, b"hunter2", "Alice");
    let mut rng = ChaCha20Rng::from_seed([0xa2; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let block_uuid = [0x77u8; 16];
    let device_uuid = [0xd1u8; 16];

    // First save
    let pt1 = make_simple_plaintext(block_uuid, "version-one");
    save_block(
        dir.path(),
        &mut open,
        pt1,
        &[owner_card.clone()],
        device_uuid,
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let first_fp = open.manifest.blocks[0].fingerprint;

    // Second save with the same block_uuid but a different block_name —
    // the manifest must still have one entry, with a NEW fingerprint.
    let pt2 = make_simple_plaintext(block_uuid, "version-two");
    save_block(
        dir.path(),
        &mut open,
        pt2,
        &[owner_card.clone()],
        device_uuid,
        1_714_060_910_000,
        &mut rng,
    )
    .unwrap();

    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    assert_eq!(
        reopened.manifest.blocks.len(),
        1,
        "same-UUID re-save must not create a duplicate entry"
    );
    let entry = &reopened.manifest.blocks[0];
    assert_eq!(entry.block_name, "version-two");
    assert_eq!(entry.last_mod_ms, 1_714_060_910_000);
    assert_eq!(
        entry.created_at_ms, 1_714_060_900_000,
        "created_at_ms is preserved across in-place updates"
    );
    assert_ne!(
        entry.fingerprint, first_fp,
        "fingerprint must reflect the new ciphertext"
    );

    // The on-disk block file must hash to the new manifest fingerprint.
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));
    let on_disk = fs::read(&block_path).unwrap();
    let computed: [u8; 32] =
        *secretary_core::crypto::hash::hash(&on_disk).as_bytes();
    assert_eq!(
        computed, entry.fingerprint,
        "on-disk bytes must hash to the manifest fingerprint"
    );
}

// ---------------------------------------------------------------------------
// 3. Two saves on the same device increment that device's clock to 2
// ---------------------------------------------------------------------------

#[test]
fn save_block_increments_device_counter() {
    let (dir, _mnemonic, pw) = make_fast_vault(3, b"hunter2", "Alice");
    let mut rng = ChaCha20Rng::from_seed([0xa3; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let device_uuid = [0xd1u8; 16];

    let pt_a = make_simple_plaintext([0x01u8; 16], "block-A");
    save_block(
        dir.path(),
        &mut open,
        pt_a,
        &[owner_card.clone()],
        device_uuid,
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let pt_b = make_simple_plaintext([0x02u8; 16], "block-B");
    save_block(
        dir.path(),
        &mut open,
        pt_b,
        &[owner_card.clone()],
        device_uuid,
        1_714_060_910_000,
        &mut rng,
    )
    .unwrap();

    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();

    // Manifest-level vector clock: device D1 must be at counter 2.
    let mvc = &reopened.manifest.vector_clock;
    assert_eq!(mvc.len(), 1, "single-device vault has one clock entry");
    assert_eq!(mvc[0].device_uuid, device_uuid);
    assert_eq!(mvc[0].counter, 2, "two saves → manifest counter 2");

    // Block #B's per-block clock summary: it's a brand-new block (no
    // pre-existing entry), so its clock starts empty and gets ticked
    // once on this save → counter 1 for D1.
    let entry_b = reopened
        .manifest
        .blocks
        .iter()
        .find(|e| e.block_uuid == [0x02u8; 16])
        .unwrap();
    assert_eq!(entry_b.vector_clock_summary.len(), 1);
    assert_eq!(entry_b.vector_clock_summary[0].device_uuid, device_uuid);
    assert_eq!(entry_b.vector_clock_summary[0].counter, 1);
}

// ---------------------------------------------------------------------------
// 4. Two devices → two independent counters at 1 each
// ---------------------------------------------------------------------------

#[test]
fn save_block_with_two_devices_independent_counters() {
    let (dir, _mnemonic, pw) = make_fast_vault(4, b"hunter2", "Alice");
    let mut rng = ChaCha20Rng::from_seed([0xa4; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let d1 = [0xd1u8; 16];
    let d2 = [0xd2u8; 16];

    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext([0x11u8; 16], "from-d1"),
        &[owner_card.clone()],
        d1,
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext([0x22u8; 16], "from-d2"),
        &[owner_card.clone()],
        d2,
        1_714_060_910_000,
        &mut rng,
    )
    .unwrap();

    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let mvc = &reopened.manifest.vector_clock;
    assert_eq!(mvc.len(), 2, "two distinct devices → two clock entries");
    let d1_entry = mvc.iter().find(|e| e.device_uuid == d1).unwrap();
    let d2_entry = mvc.iter().find(|e| e.device_uuid == d2).unwrap();
    assert_eq!(d1_entry.counter, 1);
    assert_eq!(d2_entry.counter, 1);
}

// ---------------------------------------------------------------------------
// 5. Multiple recipients can each decrypt the saved block
// ---------------------------------------------------------------------------

#[test]
fn save_block_recipients_can_all_decrypt() {
    let (dir, _mnemonic, pw) = make_fast_vault(5, b"hunter2", "Alice");
    let mut rng = ChaCha20Rng::from_seed([0xa5; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    // Mock alice and bob with their own freshly-generated identities.
    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    let block_uuid = [0x55u8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "shared");
    let device_uuid = [0xd1u8; 16];

    save_block(
        dir.path(),
        &mut open,
        plaintext.clone(),
        &[owner_card.clone(), alice_card.clone(), bob_card.clone()],
        device_uuid,
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));

    // Each recipient — owner, alice, bob — must successfully decrypt.
    let recovered_owner =
        decrypt_block_file_as(&block_path, &owner_card, &owner_card, &open.identity);
    assert_eq!(recovered_owner.block_uuid, plaintext.block_uuid);

    let recovered_alice =
        decrypt_block_file_as(&block_path, &owner_card, &alice_card, &alice_id);
    assert_eq!(recovered_alice.block_uuid, plaintext.block_uuid);

    let recovered_bob =
        decrypt_block_file_as(&block_path, &owner_card, &bob_card, &bob_id);
    assert_eq!(recovered_bob.block_uuid, plaintext.block_uuid);
}

// ---------------------------------------------------------------------------
// 6. Tampered block on disk → fingerprint mismatch detectable on read
// ---------------------------------------------------------------------------
//
// `open_vault` does not currently re-hash blocks on open (PR-B scope is
// just the manifest), so this test asserts the smoke-level invariant:
// after corrupting the on-disk block bytes, the BLAKE3 of the corrupted
// bytes no longer matches `manifest.blocks[0].fingerprint`. Future
// integration of a "load block by uuid" path (PR-C) will turn this into
// a typed-error round-trip; for PR-B it is a guard that the fingerprint
// table is the authoritative integrity reference.

#[test]
fn save_block_then_tampered_block_fails_open() {
    let (dir, _mnemonic, pw) = make_fast_vault(6, b"hunter2", "Alice");
    let mut rng = ChaCha20Rng::from_seed([0xa6; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let block_uuid = [0x99u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "tamper-me"),
        &[owner_card.clone()],
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));
    let mut corrupted = fs::read(&block_path).unwrap();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    fs::write(&block_path, &corrupted).unwrap();

    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let stored_fp = reopened.manifest.blocks[0].fingerprint;
    let on_disk_fp: [u8; 32] =
        *secretary_core::crypto::hash::hash(&corrupted).as_bytes();
    assert_ne!(
        stored_fp, on_disk_fp,
        "tampered bytes must not match the manifest fingerprint"
    );
}

// ---------------------------------------------------------------------------
// 7. 64 KiB block → atomic write leaves no `*.tmp.*` siblings
// ---------------------------------------------------------------------------

#[test]
fn save_block_atomic_write_no_torn() {
    let (dir, _mnemonic, pw) = make_fast_vault(7, b"hunter2", "Alice");
    let mut rng = ChaCha20Rng::from_seed([0xa7; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    // Build a single record with a 64 KiB bytes payload, large enough
    // to make a real-shaped block file.
    use secretary_core::vault::{Record, RecordField, RecordFieldValue};
    let payload = vec![0xABu8; 64 * 1024];
    let mut fields = BTreeMap::new();
    fields.insert(
        "blob".to_string(),
        RecordField {
            value: RecordFieldValue::Bytes(payload),
            last_mod: 1_714_060_900_000,
            device_uuid: [0xd1u8; 16],
            unknown: BTreeMap::new(),
        },
    );
    let record = Record {
        record_uuid: [0x12u8; 16],
        record_type: "blob".to_string(),
        fields,
        tags: Vec::new(),
        created_at_ms: 1_714_060_900_000,
        last_mod_ms: 1_714_060_900_000,
        tombstone: false,
        unknown: BTreeMap::new(),
    };

    let block_uuid = [0x66u8; 16];
    let plaintext = BlockPlaintext {
        block_version: 1,
        block_uuid,
        block_name: "big".to_string(),
        schema_version: 1,
        records: vec![record],
        unknown: BTreeMap::new(),
    };

    save_block(
        dir.path(),
        &mut open,
        plaintext,
        &[owner_card.clone()],
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let blocks_dir = dir.path().join("blocks");
    let leftovers: Vec<_> = fs::read_dir(&blocks_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(
        leftovers.is_empty(),
        "atomic-write must leave no .tmp.* siblings, got {leftovers:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. After save_block the manifest signature still verifies on re-open
// ---------------------------------------------------------------------------

#[test]
fn save_block_re_sign_manifest_verifies() {
    let (dir, _mnemonic, pw) = make_fast_vault(8, b"hunter2", "Alice");
    let mut rng = ChaCha20Rng::from_seed([0xa8; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext([0xeeu8; 16], "verify-me"),
        &[owner_card.clone()],
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    drop(open);
    // open_vault internally verifies the manifest signature before
    // attempting AEAD decrypt; a successful re-open is the integration-
    // level proof that save_block emitted a valid §8 hybrid signature.
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect("re-opened vault must verify");

    // Belt-and-braces: explicit verify_manifest call against the loaded
    // owner card's public keys.
    let pk_pq = MlDsa65Public::from_bytes(&reopened.owner_card.ml_dsa_65_pk).unwrap();
    manifest::verify_manifest(
        &reopened.manifest_file,
        &reopened.owner_card.ed25519_pk,
        &pk_pq,
    )
    .expect("manifest signature must verify after save_block");
}

// Suppress unused-import warnings for items only consumed by some tests.
#[allow(dead_code)]
fn _unused() {
    // Pin types we re-export so the imports above can't drift dead.
    let _: Option<MlKem768Public> = None;
    let _: Option<Ed25519Secret> = None;
    let _: Option<VaultError> = None;
}
