//! Integration tests for `secretary_core::vault::revoke_block_recipient`
//! — Task 3 of the D.1.10 revoke track. Each test creates a vault via
//! the fast-KDF helper (replicated from `share_block.rs` to keep the
//! integration tests self-contained), saves an initial block, shares it
//! to one or more recipients, then exercises `revoke_block_recipient`:
//! decrypt-as-author → rotate BCK → re-wrap for the REMAINING recipients
//! only → drop the target from the manifest `BlockEntry.recipients` →
//! re-sign block + manifest → atomic write.
//!
//! `revoke_block_recipient` is the inverse of `share_block`: same
//! author-only, single-owner restriction, but step 5 is inverted
//! (require the target be present rather than reject-if-present), and the
//! helper is called with `card_to_persist = None` (revoke writes no
//! contact card). These happy-path tests cover the round trip (remaining
//! recipient decrypts under the new BCK, the revoked wrap is gone, and
//! `contacts/` is untouched), the last-recipient → owner-only case,
//! re-sign verification via `open_vault`, and manifest-recipient
//! shrinkage.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::kem::{self, MlKem768Secret};
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
    decode_block_file, decrypt_block, encode_manifest_file, manifest, open_vault,
    revoke_block_recipient, save_block, sign_manifest, BlockPlaintext, BlockUuid, DeviceUuid,
    KdfParamsRef, Manifest, ManifestHeader, RecipientUuid, Unlocker,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture helpers (mirror share_block.rs::make_fast_vault)
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
/// [`IdentityBundle`].
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

/// Decrypt the block file at `path` for the given reader identity. Returns
/// the recovered [`BlockPlaintext`]. Used to round-trip-verify
/// `revoke_block_recipient`'s outputs end-to-end.
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

/// Try-decrypt: returns Result so tests can assert error variants (e.g.
/// the revoked recipient can no longer decrypt the rotated block).
fn try_decrypt_block_file_as(
    block_path: &Path,
    sender_card: &ContactCard,
    reader_card: &ContactCard,
    reader_id: &IdentityBundle,
) -> Result<BlockPlaintext, secretary_core::vault::BlockError> {
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
}

/// Read the on-wire §6.2 recipient fingerprints from the block file at
/// `block_path`.
fn block_recipient_fingerprints(block_path: &Path) -> Vec<[u8; 16]> {
    let bytes = fs::read(block_path).unwrap();
    let block_file = decode_block_file(&bytes).unwrap();
    block_file
        .recipients
        .iter()
        .map(|w| w.recipient_fingerprint)
        .collect()
}

/// Snapshot the sorted set of `contacts/*.card` filenames.
fn contacts_listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir.join("contacts"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// 1. Round-trip: share to [owner, alice, bob] → revoke bob → bob's wrap
//    gone, alice still decrypts under the new BCK, manifest shrinks,
//    contacts/ untouched.
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_round_trip() {
    let (dir, _mnemonic, pw) = make_fast_vault(1, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa1; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);
    let alice_fp = fingerprint(&alice_card.to_canonical_cbor().unwrap());

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);
    let bob_fp = fingerprint(&bob_card.to_canonical_cbor().unwrap());

    // Save block with [owner, alice, bob].
    let block_uuid = [0x42u8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "shared-secret");
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

    // Baseline: alice can decrypt the pre-revoke block.
    let pre = decrypt_block_file_as(&block_path, &owner_card, &alice_card, &alice_id);
    assert_eq!(pre.block_uuid, plaintext.block_uuid);
    assert_eq!(pre.block_name, plaintext.block_name);

    // Snapshot contacts/ before the revoke. Note: save_block does NOT
    // persist recipient cards, so only the owner card is on disk here.
    let contacts_before = contacts_listing(dir.path());

    // Author SKs (= owner SKs) for revoke_block_recipient.
    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    // Revoke bob.
    revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(block_uuid),
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone(), bob_card.clone()],
        RecipientUuid::new(bob_card.contact_uuid),
        DeviceUuid::new(device_uuid),
        1_714_060_910_000,
        &mut rng,
    )
    .expect("revoke_block_recipient");

    // (a) bob's fingerprint is GONE from the §6.2 recipient wire table;
    //     owner + alice remain.
    let fps = block_recipient_fingerprints(&block_path);
    assert!(
        !fps.contains(&bob_fp),
        "bob's wrap must be gone from the recipient table after revoke"
    );
    assert!(fps.contains(&alice_fp), "alice's wrap must remain");
    assert_eq!(fps.len(), 2, "owner + alice remain, bob removed");

    // (b) alice STILL decrypts the after-block under the new BCK and gets
    //     the original plaintext.
    let post = decrypt_block_file_as(&block_path, &owner_card, &alice_card, &alice_id);
    assert_eq!(post.block_uuid, plaintext.block_uuid);
    assert_eq!(post.block_name, plaintext.block_name);

    // bob can no longer decrypt the rotated block.
    let bob_err = try_decrypt_block_file_as(&block_path, &owner_card, &bob_card, &bob_id)
        .expect_err("revoked bob must not decrypt the rotated block");
    assert!(
        matches!(
            bob_err,
            secretary_core::vault::BlockError::NotARecipient { .. }
        ),
        "expected NotARecipient for revoked bob, got {bob_err:?}"
    );

    // (c) manifest BlockEntry.recipients no longer contains bob but still
    //     contains alice (and owner).
    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let entry = &reopened.manifest.blocks[0];
    assert!(!entry.recipients.contains(&bob_card.contact_uuid));
    assert!(entry.recipients.contains(&alice_card.contact_uuid));
    assert!(entry.recipients.contains(&owner_card.contact_uuid));
    assert_eq!(entry.recipients.len(), 2);

    // (d) contacts/ untouched: card_to_persist = None means revoke writes
    //     and deletes nothing under contacts/. The revoked recipient's
    //     card (and all other cards) is left exactly as it was; no new
    //     card appears.
    let contacts_after = contacts_listing(dir.path());
    assert_eq!(
        contacts_before, contacts_after,
        "revoke must not write or delete anything under contacts/"
    );
}

// ---------------------------------------------------------------------------
// 2. Last recipient → owner-only: share to [owner, alice], revoke alice;
//    the after-state collapses to the owner-only baseline. Owner still
//    decrypts.
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_last_recipient_returns_owner_only() {
    let (dir, _mnemonic, pw) = make_fast_vault(2, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa2; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();
    let owner_fp = fingerprint(&owner_card.to_canonical_cbor().unwrap());

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);
    let alice_fp = fingerprint(&alice_card.to_canonical_cbor().unwrap());

    // Save block with [owner, alice] — owner is the only non-revoked
    // recipient once alice is removed.
    let block_uuid = [0x77u8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "owner-only-after");
    let device_uuid = [0xd1u8; 16];

    save_block(
        dir.path(),
        &mut open,
        plaintext.clone(),
        &[owner_card.clone(), alice_card.clone()],
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

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(block_uuid),
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone()],
        RecipientUuid::new(alice_card.contact_uuid),
        DeviceUuid::new(device_uuid),
        1_714_060_910_000,
        &mut rng,
    )
    .expect("revoke last extra recipient");

    // Wire table is owner-only: alice's wrap gone, exactly the owner wrap
    // remains.
    let fps = block_recipient_fingerprints(&block_path);
    assert_eq!(fps.len(), 1, "owner-only wire table after revoke");
    assert!(fps.contains(&owner_fp), "owner wrap must remain");
    assert!(!fps.contains(&alice_fp), "alice wrap must be gone");

    // Manifest BlockEntry.recipients shrinks to owner-only.
    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let entry = &reopened.manifest.blocks[0];
    assert_eq!(entry.recipients, vec![owner_card.contact_uuid]);

    // Owner can still decrypt under the new BCK.
    let recovered =
        decrypt_block_file_as(&block_path, &owner_card, &owner_card, &reopened.identity);
    assert_eq!(recovered.block_uuid, plaintext.block_uuid);
    assert_eq!(recovered.block_name, plaintext.block_name);
}

// ---------------------------------------------------------------------------
// 3. Re-sign verifies: after revoke, open_vault (which enforces the
//    manifest's Ed25519 ∧ ML-DSA-65 hybrid signature) returns Ok, and a
//    remaining recipient decrypts the rotated block (proving the block
//    signature also verifies).
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_re_sign_verifies() {
    let (dir, _mnemonic, pw) = make_fast_vault(3, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa3; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    let block_uuid = [0xc3u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "verify-me"),
        &[owner_card.clone(), alice_card.clone(), bob_card.clone()],
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(block_uuid),
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone(), bob_card.clone()],
        RecipientUuid::new(bob_card.contact_uuid),
        DeviceUuid::new([0xd1u8; 16]),
        1_714_060_910_000,
        &mut rng,
    )
    .unwrap();

    drop(open);

    // open_vault internally verifies the manifest's §8 hybrid signature.
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect("re-open must verify the post-revoke manifest");

    // Belt-and-braces: explicit verify_manifest call.
    let pk_pq = MlDsa65Public::from_bytes(&reopened.owner_card.ml_dsa_65_pk).unwrap();
    manifest::verify_manifest(
        &reopened.manifest_file,
        &reopened.owner_card.ed25519_pk,
        &pk_pq,
    )
    .expect("manifest signature must verify after revoke");

    // Block signature + AEAD: a successful decrypt as alice (a remaining
    // recipient) proves the block was re-signed correctly.
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));
    let recovered = decrypt_block_file_as(&block_path, &owner_card, &alice_card, &alice_id);
    assert_eq!(recovered.block_uuid, block_uuid);
}

// ---------------------------------------------------------------------------
// 4. Manifest recipients shrink: share to [owner, alice, bob], revoke
//    bob, assert entry.recipients == exactly [owner, alice] (set
//    equality, accounting for canonical ordering).
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_manifest_recipients_shrink() {
    let (dir, _mnemonic, pw) = make_fast_vault(4, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa4; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    let block_uuid = [0x99u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "shrink"),
        &[owner_card.clone(), alice_card.clone(), bob_card.clone()],
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(block_uuid),
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone(), bob_card.clone()],
        RecipientUuid::new(bob_card.contact_uuid),
        DeviceUuid::new([0xd1u8; 16]),
        1_714_060_910_000,
        &mut rng,
    )
    .unwrap();

    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let entry = &reopened.manifest.blocks[0];

    // Exact set equality (sort-and-compare; the §4.2 encoder sorts on
    // emit, but compare as sets to be order-agnostic).
    let mut got = entry.recipients.clone();
    got.sort();
    let mut want = vec![owner_card.contact_uuid, alice_card.contact_uuid];
    want.sort();
    assert_eq!(
        got, want,
        "recipients must shrink to exactly [owner, alice]"
    );
    assert!(!entry.recipients.contains(&bob_card.contact_uuid));
}

// ---------------------------------------------------------------------------
// 5. Owner-revoke rejected: share to [owner, alice], attempt to revoke the
//    OWNER's uuid. Assert Err(CannotRevokeOwner) AND the block is untouched
//    (block bytes byte-identical, manifest BlockEntry.recipients unchanged,
//    contacts/ byte-identical). The guard must fail fast — no re-key, no
//    write.
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_owner_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(5, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa5; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    // Save block with [owner, alice].
    let block_uuid = [0x55u8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "owner-revoke");
    let device_uuid = [0xd1u8; 16];

    save_block(
        dir.path(),
        &mut open,
        plaintext.clone(),
        &[owner_card.clone(), alice_card.clone()],
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

    // Snapshot the on-disk state the guard must not touch.
    let block_bytes_before = fs::read(&block_path).unwrap();
    let manifest_bytes_before = fs::read(dir.path().join("manifest.cbor.enc")).unwrap();
    let contacts_before = contacts_listing(dir.path());

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    // The owner uuid the guard rejects (== owner card's contact_uuid).
    let owner_uuid = open.identity.user_uuid;

    // Attempt to revoke the OWNER (open.identity.user_uuid == owner card's
    // contact_uuid). Must be rejected up-front.
    let err = revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(block_uuid),
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone()],
        RecipientUuid::new(owner_uuid),
        DeviceUuid::new(device_uuid),
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("revoking the owner must be rejected");
    assert!(
        matches!(err, secretary_core::vault::VaultError::CannotRevokeOwner),
        "expected CannotRevokeOwner, got {err:?}"
    );

    // Block file is byte-identical — no re-key, no write.
    let block_bytes_after = fs::read(&block_path).unwrap();
    assert_eq!(
        block_bytes_before, block_bytes_after,
        "rejected owner-revoke must not rewrite the block file"
    );

    // Manifest file is byte-identical.
    let manifest_bytes_after = fs::read(dir.path().join("manifest.cbor.enc")).unwrap();
    assert_eq!(
        manifest_bytes_before, manifest_bytes_after,
        "rejected owner-revoke must not rewrite the manifest"
    );

    // Recipient wire table still holds owner + alice (both present).
    let fps = block_recipient_fingerprints(&block_path);
    assert_eq!(fps.len(), 2, "owner + alice recipients must remain");

    // Manifest BlockEntry.recipients still holds owner + alice. Re-open to
    // re-verify the (unchanged) manifest signature too.
    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let entry = &reopened.manifest.blocks[0];
    assert!(entry.recipients.contains(&owner_card.contact_uuid));
    assert!(entry.recipients.contains(&alice_card.contact_uuid));
    assert_eq!(entry.recipients.len(), 2);

    // contacts/ byte-identical (unchanged set of filenames; revoke writes
    // nothing here even on the happy path).
    let contacts_after = contacts_listing(dir.path());
    assert_eq!(
        contacts_before, contacts_after,
        "rejected owner-revoke must not touch contacts/"
    );
}

// ---------------------------------------------------------------------------
// 6. BlockNotFound: an unknown block_uuid (not in the manifest) → reject at
//    step 1, before any block file is read.
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_not_found_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(6, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa6; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    // No block with this uuid exists in the manifest → step-1 rejection.
    let bogus_uuid = [0xABu8; 16];
    let err = revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(bogus_uuid),
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone()],
        RecipientUuid::new(alice_card.contact_uuid),
        DeviceUuid::new([0xd1u8; 16]),
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("revoke with an unknown block_uuid must be rejected");

    assert!(
        matches!(
            err,
            secretary_core::vault::VaultError::BlockNotFound { block_uuid } if block_uuid == bogus_uuid
        ),
        "expected BlockNotFound for the bogus uuid, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 7. NotAuthor: a caller who is NOT the block's single-owner author attempts
//    a revoke. Passing an author_card whose contact_uuid != open.identity
//    .user_uuid (and whose fingerprint != the block's author_fingerprint)
//    trips the author check. Assert the block + manifest are UNCHANGED — the
//    guard fails fast, no re-key, no write.
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_non_author_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(7, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa7; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    // Save block authored by the owner, shared to [owner, alice].
    let block_uuid = [0x71u8; 16];
    let device_uuid = [0xd1u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "owner-authored"),
        &[owner_card.clone(), alice_card.clone()],
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

    // Snapshot the on-disk state the guard must not touch.
    let block_bytes_before = fs::read(&block_path).unwrap();
    let manifest_bytes_before = fs::read(dir.path().join("manifest.cbor.enc")).unwrap();

    // Attempt to revoke alice using author_card = alice_card (wrong author).
    // alice's fingerprint != block.author_fingerprint → NotAuthor (and her
    // contact_uuid != open.identity.user_uuid would also trip the PR-B
    // single-owner check; the fingerprint mismatch fires first). SKs are
    // still the owner's.
    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    let err = revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(block_uuid),
        &alice_card, // wrong author card!
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone()],
        RecipientUuid::new(alice_card.contact_uuid),
        DeviceUuid::new(device_uuid),
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("revoke must reject when author_card is not the block author");

    assert!(
        matches!(err, secretary_core::vault::VaultError::NotAuthor { .. }),
        "expected NotAuthor, got {err:?}"
    );

    // Block + manifest byte-identical — rejected path performs no write.
    let block_bytes_after = fs::read(&block_path).unwrap();
    assert_eq!(
        block_bytes_before, block_bytes_after,
        "rejected non-author revoke must not rewrite the block file"
    );
    let manifest_bytes_after = fs::read(dir.path().join("manifest.cbor.enc")).unwrap();
    assert_eq!(
        manifest_bytes_before, manifest_bytes_after,
        "rejected non-author revoke must not rewrite the manifest"
    );
}

// ---------------------------------------------------------------------------
// 8. RecipientNotPresent: share to [owner, alice] ONLY, then attempt to
//    revoke bob (never a recipient). Every ACTUAL wrap (owner, alice)
//    resolves to a supplied card, so the wire-table walk completes without a
//    MissingRecipientCard; bob is then found absent from the table →
//    RecipientNotPresent. (Bob's card is also supplied, but it is never
//    consulted — he has no wrap — so it is incidental to the outcome; what
//    matters is that the REAL wraps all resolve.) This PINS the ordering
//    distinction vs MissingRecipientCard (test 9), where a real wrap is left
//    unresolvable. Block left unchanged.
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_non_recipient_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(8, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa8; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    // Bob is minted but NEVER shared the block — he has no wrap.
    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    // Save block shared to [owner, alice] only.
    let block_uuid = [0x81u8; 16];
    let device_uuid = [0xd1u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "not-shared-to-bob"),
        &[owner_card.clone(), alice_card.clone()],
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
    let block_bytes_before = fs::read(&block_path).unwrap();

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    // Supply bob's card alongside the real recipients so the wire-table walk
    // resolves EVERY actual wrap (owner + alice). Bob simply never appears as
    // a wrap → RecipientNotPresent, NOT MissingRecipientCard.
    let err = revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(block_uuid),
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone(), bob_card.clone()],
        RecipientUuid::new(bob_card.contact_uuid),
        DeviceUuid::new(device_uuid),
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("revoke of a non-recipient must be rejected");

    assert!(
        matches!(err, secretary_core::vault::VaultError::RecipientNotPresent),
        "expected RecipientNotPresent (supplied-but-not-a-recipient), got {err:?}"
    );

    // Block byte-identical — rejected path performs no write.
    let block_bytes_after = fs::read(&block_path).unwrap();
    assert_eq!(
        block_bytes_before, block_bytes_after,
        "rejected non-recipient revoke must not rewrite the block file"
    );
}

// ---------------------------------------------------------------------------
// 9. MissingRecipientCard: share to [owner, alice, bob], attempt to revoke
//    bob but supply existing_recipient_cards = [bob's card] ONLY (WITHHOLD
//    alice's, and the owner's). A remaining wrap can't be resolved during
//    the wire-table walk → MissingRecipientCard. This is the ordering
//    counterpart of test 8 (the absent party's CARD is withheld here, so
//    resolution fails before the present/absent split). Block unchanged.
// ---------------------------------------------------------------------------

#[test]
fn revoke_block_missing_remaining_card_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(9, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa9; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    // Save block shared to [owner, alice, bob].
    let block_uuid = [0x91u8; 16];
    let device_uuid = [0xd1u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "withhold-alice-card"),
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
    let block_bytes_before = fs::read(&block_path).unwrap();

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    // Supply ONLY bob's card. The owner's and alice's wraps can't be
    // resolved during the wire-table walk → MissingRecipientCard fires
    // before the present/absent split that test 8 exercises.
    let err = revoke_block_recipient(
        dir.path(),
        &mut open,
        BlockUuid::new(block_uuid),
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        std::slice::from_ref(&bob_card),
        RecipientUuid::new(bob_card.contact_uuid),
        DeviceUuid::new(device_uuid),
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("revoke must reject when a remaining wrap has no supplying card");

    assert!(
        matches!(
            err,
            secretary_core::vault::VaultError::MissingRecipientCard { .. }
        ),
        "expected MissingRecipientCard (a remaining wrap is unresolved), got {err:?}"
    );

    // Block byte-identical — rejected path performs no write.
    let block_bytes_after = fs::read(&block_path).unwrap();
    assert_eq!(
        block_bytes_before, block_bytes_after,
        "rejected revoke (missing card) must not rewrite the block file"
    );
}
