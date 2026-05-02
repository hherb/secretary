//! Integration tests for `secretary_core::vault::share_block` —
//! Task 13 of PR-B. Each test creates a vault first via the
//! Task 10/11 fast-KDF helper (replicated locally to keep the
//! integration tests self-contained), saves an initial block,
//! then exercises the `share_block` orchestrator: decrypt → re-wrap
//! for the new recipient set → re-sign block → re-sign manifest →
//! atomic write block + manifest.
//!
//! `share_block` is deliberately author-only: the §6.2 recipient
//! table is inside the §6.1 signed range, so adding a recipient
//! requires a fresh author signature. The tests below cover the
//! happy-path round trip, multi-recipient fan-out, and the four
//! validation paths (`NotAuthor`, `BlockNotFound`,
//! `RecipientAlreadyPresent`, send-only-mode rejection).

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
    share_block, sign_manifest, BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, Unlocker,
    VaultError,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture helpers (mirror save_block.rs::make_fast_vault)
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
/// `share_block`'s outputs end-to-end.
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

/// Try-decrypt: returns Result so tests can assert error variants.
#[allow(clippy::too_many_arguments)]
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

// ---------------------------------------------------------------------------
// 1. Round-trip: save → share to alice → manifest carries both, alice decrypts
// ---------------------------------------------------------------------------

#[test]
fn share_block_round_trip() {
    let (dir, _mnemonic, pw) = make_fast_vault(1, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa1; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    // Alice — a fresh external identity.
    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    // Save block initially with [owner] only.
    let block_uuid = [0x42u8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "shared-secret");
    let device_uuid = [0xd1u8; 16];

    save_block(
        dir.path(),
        &mut open,
        plaintext.clone(),
        std::slice::from_ref(&owner_card),
        device_uuid,
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    // Capture author SKs (= owner SKs) for share_block.
    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    // Share to alice.
    share_block(
        dir.path(),
        &mut open,
        block_uuid,
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        std::slice::from_ref(&owner_card),
        &alice_card,
        device_uuid,
        1_714_060_910_000,
        &mut rng,
    )
    .expect("share_block");

    // Re-open vault; manifest's BlockEntry should list both recipients.
    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    assert_eq!(reopened.manifest.blocks.len(), 1);
    let entry = &reopened.manifest.blocks[0];
    assert_eq!(entry.block_uuid, block_uuid);
    assert_eq!(entry.recipients.len(), 2, "both owner + alice in recipients");
    assert!(entry.recipients.contains(&owner_card.contact_uuid));
    assert!(entry.recipients.contains(&alice_card.contact_uuid));
    assert_eq!(entry.last_mod_ms, 1_714_060_910_000);
    // created_at_ms preserved from original save.
    assert_eq!(entry.created_at_ms, 1_714_060_900_000);

    // Alice's contact card should now be on disk under contacts/.
    let alice_uuid_hex = format_uuid_hyphenated(&alice_card.contact_uuid);
    let alice_card_path = dir
        .path()
        .join("contacts")
        .join(format!("{alice_uuid_hex}.card"));
    assert!(
        alice_card_path.exists(),
        "share_block must persist the new recipient's card to contacts/"
    );

    // Alice can decrypt the block.
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));
    let recovered =
        decrypt_block_file_as(&block_path, &owner_card, &alice_card, &alice_id);
    assert_eq!(recovered.block_uuid, plaintext.block_uuid);
    assert_eq!(recovered.block_name, plaintext.block_name);
}

// ---------------------------------------------------------------------------
// 2. Pre-existing recipients preserved across share
// ---------------------------------------------------------------------------

#[test]
fn share_block_with_pre_existing_recipients_preserved() {
    let (dir, _mnemonic, pw) = make_fast_vault(2, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa2; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    // Save block with [owner, alice].
    let block_uuid = [0x77u8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "fan-out");
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

    // Share to bob — caller passes existing recipient cards explicitly.
    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    share_block(
        dir.path(),
        &mut open,
        block_uuid,
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone()],
        &bob_card,
        device_uuid,
        1_714_060_910_000,
        &mut rng,
    )
    .unwrap();

    // All three recipients on the BlockEntry.
    drop(open);
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let entry = &reopened.manifest.blocks[0];
    assert_eq!(entry.recipients.len(), 3);
    assert!(entry.recipients.contains(&owner_card.contact_uuid));
    assert!(entry.recipients.contains(&alice_card.contact_uuid));
    assert!(entry.recipients.contains(&bob_card.contact_uuid));

    // All three can decrypt the block.
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));

    let r_owner =
        decrypt_block_file_as(&block_path, &owner_card, &owner_card, &reopened.identity);
    assert_eq!(r_owner.block_uuid, plaintext.block_uuid);
    let r_alice = decrypt_block_file_as(&block_path, &owner_card, &alice_card, &alice_id);
    assert_eq!(r_alice.block_uuid, plaintext.block_uuid);
    let r_bob = decrypt_block_file_as(&block_path, &owner_card, &bob_card, &bob_id);
    assert_eq!(r_bob.block_uuid, plaintext.block_uuid);
}

// ---------------------------------------------------------------------------
// 3. NotAuthor: caller's card is NOT the block's author → reject
// ---------------------------------------------------------------------------
//
// Construction: owner saves a block authored by owner, then we attempt
// share_block with a different `author_card` (alice's card) but supplying
// owner's own SKs. The author_fingerprint check fires first because
// `fingerprint(alice_card)` ≠ `block.author_fingerprint`. This exercises
// the validation path without needing to fabricate a vault assembled
// from mismatched parts.

#[test]
fn share_block_non_author_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(3, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa3; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let mut carol_rng = ChaCha20Rng::from_seed([0xb3; 32]);
    let carol_id = unlock::bundle::generate("Carol", 1_714_060_800_000, &mut carol_rng);
    let carol_card = make_signed_card(&carol_id);

    let block_uuid = [0xa1u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "owner-authored"),
        std::slice::from_ref(&owner_card),
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    // Attempt to share with author_card = alice_card (wrong author).
    // SKs are still owner's — the fingerprint mismatch trips first.
    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    let err = share_block(
        dir.path(),
        &mut open,
        block_uuid,
        &alice_card, // wrong author card!
        &owner_sk_ed,
        &owner_sk_pq,
        std::slice::from_ref(&owner_card),
        &carol_card,
        [0xd1u8; 16],
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("share_block must reject when author_card mismatches block.author_fingerprint");

    assert!(
        matches!(err, VaultError::NotAuthor { .. }),
        "expected NotAuthor, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. BlockNotFound: arbitrary block_uuid → reject
// ---------------------------------------------------------------------------

#[test]
fn share_block_block_not_found_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(4, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa4; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    let bogus_uuid = [0xfeu8; 16];
    let err = share_block(
        dir.path(),
        &mut open,
        bogus_uuid,
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        std::slice::from_ref(&owner_card),
        &alice_card,
        [0xd1u8; 16],
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("share_block must reject unknown block_uuid");

    assert!(
        matches!(err, VaultError::BlockNotFound { block_uuid } if block_uuid == bogus_uuid),
        "expected BlockNotFound, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. RecipientAlreadyPresent: share to an existing recipient → reject
// ---------------------------------------------------------------------------

#[test]
fn share_block_duplicate_recipient_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(5, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa5; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    // Save block with [owner, alice].
    let block_uuid = [0xb1u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "with-alice"),
        &[owner_card.clone(), alice_card.clone()],
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();

    // Try to share to alice again.
    let err = share_block(
        dir.path(),
        &mut open,
        block_uuid,
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[owner_card.clone(), alice_card.clone()],
        &alice_card, // duplicate!
        [0xd1u8; 16],
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("share_block must reject a recipient that's already in the table");

    assert!(
        matches!(err, VaultError::RecipientAlreadyPresent),
        "expected RecipientAlreadyPresent, got {err:?}"
    );

    // Drop the alice id (avoid unused warning).
    let _ = alice_id;
}

// ---------------------------------------------------------------------------
// 6. Manifest + block signatures still verify after share_block
// ---------------------------------------------------------------------------

#[test]
fn share_block_re_sign_verifies() {
    let (dir, _mnemonic, pw) = make_fast_vault(6, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa6; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let block_uuid = [0xc3u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "verify-me"),
        std::slice::from_ref(&owner_card),
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    share_block(
        dir.path(),
        &mut open,
        block_uuid,
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        std::slice::from_ref(&owner_card),
        &alice_card,
        [0xd1u8; 16],
        1_714_060_910_000,
        &mut rng,
    )
    .unwrap();

    drop(open);

    // open_vault internally verifies the manifest's §8 signature.
    let reopened = open_vault(dir.path(), Unlocker::Password(&pw), None)
        .expect("re-open must verify the post-share manifest");

    // Belt-and-braces: explicit verify_manifest call.
    let pk_pq = MlDsa65Public::from_bytes(&reopened.owner_card.ml_dsa_65_pk).unwrap();
    manifest::verify_manifest(
        &reopened.manifest_file,
        &reopened.owner_card.ed25519_pk,
        &pk_pq,
    )
    .expect("manifest signature must verify after share_block");

    // Block signature: decrypting as alice exercises both the §6.1 hybrid
    // signature verify and the AEAD decrypt — a successful decrypt is the
    // proof that share_block re-signed the block correctly.
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));
    let _ = decrypt_block_file_as(&block_path, &owner_card, &alice_card, &alice_id);
}

// ---------------------------------------------------------------------------
// 7. Send-only mode: author NOT a recipient → cannot share
// ---------------------------------------------------------------------------
//
// Owner authors a block encrypted for [alice, bob] only. Owner is NOT a
// recipient — so owner cannot decrypt the block to recover the BCK,
// which means owner cannot call share_block on this block (the §6.4
// `NotARecipient` error fires inside decrypt_block, propagated through
// VaultError::Block). This is the practical restriction: send-only
// blocks cannot be later shared by their author without the
// "share-as-fork" path (a future PR).

#[test]
fn share_block_send_only_mode() {
    let (dir, _mnemonic, pw) = make_fast_vault(7, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa7; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    let mut carol_rng = ChaCha20Rng::from_seed([0xb3; 32]);
    let carol_id = unlock::bundle::generate("Carol", 1_714_060_800_000, &mut carol_rng);
    let carol_card = make_signed_card(&carol_id);

    // Owner authors block encrypted for [alice, bob] — sender-only mode.
    let block_uuid = [0x55u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "send-only"),
        &[alice_card.clone(), bob_card.clone()],
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

    // Alice + bob can decrypt.
    let r_alice = decrypt_block_file_as(&block_path, &owner_card, &alice_card, &alice_id);
    assert_eq!(r_alice.block_uuid, block_uuid);
    let r_bob = decrypt_block_file_as(&block_path, &owner_card, &bob_card, &bob_id);
    assert_eq!(r_bob.block_uuid, block_uuid);

    // Owner attempt to decrypt → NotARecipient (sanity: this is the
    // condition that blocks share_block in the next assertion).
    let owner_decrypt_err =
        try_decrypt_block_file_as(&block_path, &owner_card, &owner_card, &open.identity)
            .expect_err("owner is not a recipient of this send-only block");
    assert!(
        matches!(
            owner_decrypt_err,
            secretary_core::vault::BlockError::NotARecipient { .. }
        ),
        "expected NotARecipient, got {owner_decrypt_err:?}"
    );

    // Owner attempts share_block — fails because the orchestrator's
    // internal decrypt step (step 7) cannot recover the BCK.
    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    let err = share_block(
        dir.path(),
        &mut open,
        block_uuid,
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        &[alice_card.clone(), bob_card.clone()],
        &carol_card,
        [0xd1u8; 16],
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err("share_block must fail in send-only mode (author cannot decrypt)");

    // The error surfaces through VaultError::Block(BlockError::NotARecipient).
    match err {
        VaultError::Block(secretary_core::vault::BlockError::NotARecipient { .. }) => {}
        other => panic!("expected VaultError::Block(NotARecipient), got {other:?}"),
    }

    // Suppress unused-warning on carol_id.
    let _ = carol_id;
}

// ---------------------------------------------------------------------------
// 8. Atomic write: no leftover *.tmp.* siblings after share_block
// ---------------------------------------------------------------------------

#[test]
fn share_block_atomic_no_torn() {
    let (dir, _mnemonic, pw) = make_fast_vault(8, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa8; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let block_uuid = [0xeeu8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "atomic"),
        std::slice::from_ref(&owner_card),
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    share_block(
        dir.path(),
        &mut open,
        block_uuid,
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        std::slice::from_ref(&owner_card),
        &alice_card,
        [0xd1u8; 16],
        1_714_060_910_000,
        &mut rng,
    )
    .unwrap();

    let blocks_dir = dir.path().join("blocks");
    let block_leftovers: Vec<_> = fs::read_dir(&blocks_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(
        block_leftovers.is_empty(),
        "atomic-write must leave no .tmp.* siblings under blocks/, got {block_leftovers:?}"
    );

    let leftovers_root: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(
        leftovers_root.is_empty(),
        "atomic-write must leave no .tmp.* siblings at vault root, got {leftovers_root:?}"
    );

    // Pin types so unused-import lints don't bite if the test corpus
    // changes later.
    let _ = alice_id;
}

// ---------------------------------------------------------------------------
// 9. MissingRecipientCard: share with an `existing_recipient_cards` list
//    that does not include a card whose fingerprint is in the on-wire
//    recipient table. Catches a regression where `share_block`
//    silently drops the missing recipient (or, worse, picks an
//    unrelated card whose fingerprint happens to collide) instead of
//    failing loudly with `VaultError::MissingRecipientCard`.
// ---------------------------------------------------------------------------

#[test]
fn share_block_missing_recipient_card_rejected() {
    let (dir, _mnemonic, pw) = make_fast_vault(9, b"hunter2", "Owner");
    let mut rng = ChaCha20Rng::from_seed([0xa9; 32]);

    let mut open = open_vault(dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    let mut alice_rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);
    let alice_fp = fingerprint(&alice_card.to_canonical_cbor().unwrap());

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    // Save block with [owner, alice] — the on-wire recipient table
    // has two wraps: owner and alice.
    let block_uuid = [0x99u8; 16];
    save_block(
        dir.path(),
        &mut open,
        make_simple_plaintext(block_uuid, "missing-card"),
        &[owner_card.clone(), alice_card.clone()],
        [0xd1u8; 16],
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    // Share to bob, but DELIBERATELY OMIT alice from
    // `existing_recipient_cards`. The orchestrator must walk the
    // on-wire wrap list in step 6, fail to resolve alice's
    // fingerprint, and surface MissingRecipientCard.
    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    let err = share_block(
        dir.path(),
        &mut open,
        block_uuid,
        &owner_card,
        &owner_sk_ed,
        &owner_sk_pq,
        std::slice::from_ref(&owner_card), // alice intentionally omitted
        &bob_card,
        [0xd1u8; 16],
        1_714_060_910_000,
        &mut rng,
    )
    .expect_err(
        "share_block must reject when an on-wire recipient is missing from existing_recipient_cards",
    );

    match err {
        VaultError::MissingRecipientCard { fingerprint: fp } => {
            assert_eq!(
                fp, alice_fp,
                "the missing fingerprint must be the omitted recipient's"
            );
        }
        other => panic!("expected MissingRecipientCard, got {other:?}"),
    }

    // Suppress unused-warning on bob_id.
    let _ = bob_id;
}

// Suppress unused-import warnings for items only consumed by some tests.
#[allow(dead_code)]
fn _unused() {
    let _: Option<MlKem768Public> = None;
}
