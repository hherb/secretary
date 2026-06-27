//! Revoke re-key Known-Answer-Test fixture + deterministic generator
//! + always-run replay guard — Task 7 of the D.1.10 revoke track.
//!
//! Two entry points, mirroring `conformance_kat.rs`:
//!
//! - `generate_revoke_kat` — `#[ignore]`-marked; runs the
//!   `save_block` → `revoke_block_recipient` scenario against a freshly
//!   created fast-KDF vault under a FIXED seed (`[42u8; 32]`) and writes
//!   the three committed fixtures under `core/tests/data/revoke_kat/`:
//!   `before_block.cbor.enc` (the block shared to [owner, alice, bob]),
//!   `after_block.cbor.enc` (the same block after revoking bob), and
//!   `inputs.json` (hex-encoded keys + fingerprints + author pks + expected
//!   plaintext, in the golden_vault_001_inputs.json convention). Re-running
//!   it is byte-stable (seeded RNG, no timestamps, no HashMap iteration).
//!   Run it ONCE on an intentional change; the diff is human-reviewed before
//!   commit.
//!
//! - `revoke_kat_after_block_matches_inputs` — runs on every `cargo test`
//!   and PINS the fixture. It asserts: (a) the revoked (bob) fingerprint is
//!   ABSENT from after_block's §6.2 recipient table and the remaining (alice)
//!   fingerprint is PRESENT; (b) the remaining recipient DECRYPTS after_block
//!   under the new BCK to the committed `expected_plaintext`, reconstructing
//!   alice's reader identity entirely from the hex in inputs.json; and (c)
//!   before_block contained bob's wrap AND `before.aead_ct != after.aead_ct`
//!   — proving a real re-key (fresh BCK → different body ciphertext).
//!
//! Task 8 adds the clean-room Python equivalent (`conformance.py`, generic
//! crypto primitives via PEP 723, no dependency on `secretary-core`) against
//! this same fixture; `inputs.json` therefore
//! carries EXACTLY the §7 unwrap transcript inputs a clean-room reader needs
//! (both pk-bundles, both fingerprints, alice's x25519 + ml-kem-768 SKs, the
//! author's pks, the block_uuid).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

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
use secretary_core::unlock::{self, bundle::IdentityBundle, create_vault_unchecked, vault_toml};
use secretary_core::vault::block::encode_plaintext;
use secretary_core::vault::{
    decode_block_file, decrypt_block, encode_manifest_file, open_vault, revoke_block_recipient,
    save_block, sign_manifest, BlockFile, BlockPlaintext, BlockUuid, DeviceUuid, KdfParamsRef,
    Manifest, ManifestHeader, RecipientUuid, Unlocker,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

// ---------------------------------------------------------------------------
// Fixture paths
// ---------------------------------------------------------------------------

fn revoke_kat_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("revoke_kat")
}

fn before_block_path() -> PathBuf {
    revoke_kat_dir().join("before_block.cbor.enc")
}

fn after_block_path() -> PathBuf {
    revoke_kat_dir().join("after_block.cbor.enc")
}

fn inputs_path() -> PathBuf {
    revoke_kat_dir().join("inputs.json")
}

// ---------------------------------------------------------------------------
// Fixture helpers (mirror revoke_block.rs / share_block.rs::make_fast_vault)
// ---------------------------------------------------------------------------

fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
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

/// Build a vault on disk under `dir` from a seeded RNG. Mirrors
/// `revoke_block.rs::make_fast_vault` but takes the dir + rng explicitly so
/// the generator controls determinism end-to-end.
fn make_fast_vault_in(
    dir: &Path,
    rng: &mut ChaCha20Rng,
    password: &[u8],
    display_name: &str,
) -> SecretBytes {
    let pw = SecretBytes::new(password.to_vec());
    let created_at_ms = 1_714_060_800_000u64;
    let created =
        create_vault_unchecked(&pw, display_name, created_at_ms, fast_kdf(), rng).unwrap();

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
    let contacts_dir = dir.join("contacts");
    fs::create_dir_all(&contacts_dir).unwrap();
    fs::write(dir.join("vault.toml"), &created.vault_toml_bytes).unwrap();
    fs::write(
        dir.join("identity.bundle.enc"),
        &created.identity_bundle_bytes,
    )
    .unwrap();
    fs::write(
        contacts_dir.join(format!("{owner_uuid_hex}.card")),
        &owner_card_bytes,
    )
    .unwrap();
    fs::write(dir.join("manifest.cbor.enc"), &mf_bytes).unwrap();

    pw
}

/// Build a self-signed [`ContactCard`] from an [`IdentityBundle`].
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

/// Decrypt a block file for the given reader identity using a sender card.
/// Returns the recovered [`BlockPlaintext`]. Used both by the generator (to
/// capture `expected_plaintext`) and by the guard (to verify the after-block
/// re-key).
fn decrypt_block_file_as(
    block_path: &Path,
    sender_card: &ContactCard,
    reader_card: &ContactCard,
    reader_x_sk: &kem::X25519Secret,
    reader_pq_sk: &MlKem768Secret,
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

    decrypt_block(
        &block_file,
        &sender_fp,
        &sender_pk_bundle,
        &sender_card.ed25519_pk,
        &sender_dsa_pk,
        &reader_fp,
        &reader_pk_bundle,
        reader_x_sk,
        reader_pq_sk,
    )
    .unwrap()
}

/// The §6.2 recipient fingerprints on the wire, in encode order.
fn block_recipient_fingerprints(block: &BlockFile) -> Vec<[u8; 16]> {
    block
        .recipients
        .iter()
        .map(|w| w.recipient_fingerprint)
        .collect()
}

// ---------------------------------------------------------------------------
// Generator (#[ignore]) — writes the three committed fixtures.
// ---------------------------------------------------------------------------

/// Deterministically (seed `[42u8; 32]`) build the
/// [owner, alice, bob] → revoke bob scenario and write
/// `core/tests/data/revoke_kat/{before_block.cbor.enc,after_block.cbor.enc,
/// inputs.json}`.
///
/// Run manually only on an intentional change to the revoke re-key wire
/// format or §7 transcript:
///
///     cargo test --release --workspace --test revoke_kat -- \
///         --ignored generate_revoke_kat --nocapture
///
/// The diff is human-reviewed before commit. The fixture is byte-stable: a
/// second run produces an identical `git diff --stat` (no diff). If a diff
/// appears, the generator has acquired nondeterminism — an unseeded RNG, a
/// wall-clock timestamp, or a HashMap iteration — and must be fixed before
/// the fixture is trustworthy as a KAT.
#[test]
#[ignore]
fn generate_revoke_kat() {
    // Single seeded RNG threads the whole scenario. All per-party RNGs are
    // derived from fixed seeds below, so every byte written is reproducible.
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Build the owner vault in a tempdir (we only persist the block files +
    // inputs.json, not the whole vault).
    let vault_dir = tempfile::tempdir().unwrap();
    let pw = make_fast_vault_in(vault_dir.path(), &mut rng, b"hunter2", "Owner");

    let mut open = open_vault(vault_dir.path(), Unlocker::Password(&pw), None).unwrap();
    let owner_card = open.owner_card.clone();

    // Remaining recipient (alice) + revoked recipient (bob), each from a
    // fixed seed.
    let mut alice_rng = ChaCha20Rng::from_seed([0xa1u8; 32]);
    let alice_id = unlock::bundle::generate("Alice", 1_714_060_800_000, &mut alice_rng);
    let alice_card = make_signed_card(&alice_id);

    let mut bob_rng = ChaCha20Rng::from_seed([0xb2u8; 32]);
    let bob_id = unlock::bundle::generate("Bob", 1_714_060_800_000, &mut bob_rng);
    let bob_card = make_signed_card(&bob_id);

    let block_uuid = [0x42u8; 16];
    let plaintext = make_simple_plaintext(block_uuid, "shared-secret");
    let device_uuid = [0xd1u8; 16];

    // Save the block shared to [owner, alice, bob].
    save_block(
        vault_dir.path(),
        &mut open,
        plaintext.clone(),
        &[owner_card.clone(), alice_card.clone(), bob_card.clone()],
        device_uuid,
        1_714_060_900_000,
        &mut rng,
    )
    .unwrap();

    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let on_disk_block = vault_dir
        .path()
        .join("blocks")
        .join(format!("{block_uuid_hex}.cbor.enc"));

    // Snapshot the before-block bytes (shared to all three).
    let before_bytes = fs::read(&on_disk_block).unwrap();

    // Revoke bob: rotate BCK, re-wrap for [owner, alice], drop bob.
    let owner_sk_ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    revoke_block_recipient(
        vault_dir.path(),
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

    // Snapshot the after-block bytes (re-keyed, shared to [owner, alice]).
    let after_bytes = fs::read(&on_disk_block).unwrap();

    // Decrypt the after-block as alice (the remaining recipient) under the
    // new BCK, and canonical-CBOR-encode the recovered plaintext. This is the
    // `expected_plaintext` a clean-room reader must reproduce.
    let alice_x_sk: kem::X25519Secret = Sensitive::new(*alice_id.x25519_sk.expose());
    let alice_pq_sk = MlKem768Secret::from_bytes(alice_id.ml_kem_768_sk.expose()).unwrap();
    let recovered = decrypt_block_file_as(
        &on_disk_block,
        &owner_card,
        &alice_card,
        &alice_x_sk,
        &alice_pq_sk,
    );
    let expected_plaintext = encode_plaintext(&recovered).unwrap();

    // Assemble inputs.json (hex), mirroring golden_vault_001_inputs.json.
    let owner_card_bytes = owner_card.to_canonical_cbor().unwrap();
    let owner_fp = fingerprint(&owner_card_bytes);
    let alice_card_bytes = alice_card.to_canonical_cbor().unwrap();
    let alice_fp = fingerprint(&alice_card_bytes);
    let bob_card_bytes = bob_card.to_canonical_cbor().unwrap();
    let bob_fp = fingerprint(&bob_card_bytes);

    let inputs = serde_json::json!({
        "_format": "secretary-revoke-kat v1",
        "_doc": "D.1.10 revoke re-key conformance vector. Consumed by core/tests/revoke_kat.rs (always-run guard) and core/tests/python/conformance.py (clean-room, generic crypto primitives via PEP 723, Task 8). before_block.cbor.enc is the block shared to [owner, alice (remaining), bob (revoked)]; after_block.cbor.enc is the same block after revoke_block_recipient removes bob, re-wrapped for [owner, alice] under a fresh BCK. The remaining_recipient keys + both pk_bundles + both fingerprints + author pks + block_uuid are exactly the §7 hybrid-decap transcript inputs a clean-room reader needs to unwrap the new BCK from after_block and AEAD-decrypt the body to expected_plaintext. Generated by `cargo test --test revoke_kat -- --ignored generate_revoke_kat --nocapture` (seed 42).",
        "block_uuid": hex::encode(block_uuid),
        "remaining_recipient": {
            "_doc": "Alice — keeps access after the revoke. Her x25519 + ml-kem-768 SKs decap the new BCK; her pk_bundle is the §7 recipient-side transcript input; her fingerprint locates her wrap in after_block's §6.2 table.",
            "display_name": "Alice",
            "contact_uuid": hex::encode(alice_id.user_uuid),
            "fingerprint": hex::encode(alice_fp),
            "x25519_sk": hex::encode(alice_id.x25519_sk.expose()),
            "ml_kem_768_sk": hex::encode(alice_id.ml_kem_768_sk.expose()),
            "pk_bundle": hex::encode(alice_card.pk_bundle_bytes().unwrap()),
        },
        "revoked_recipient": {
            "_doc": "Bob — revoked. His wrap is PRESENT in before_block and ABSENT from after_block. The reader asserts his fingerprint is gone from after_block's §6.2 table.",
            "display_name": "Bob",
            "contact_uuid": hex::encode(bob_id.user_uuid),
            "fingerprint": hex::encode(bob_fp),
        },
        "author": {
            "_doc": "Owner — the block author (sender side of the §7 transcript) and the §8 block-signature signer. pk_bundle is the sender-side transcript input; ed25519_pk + ml_dsa_65_pk verify the block signature.",
            "contact_uuid": hex::encode(owner_card.contact_uuid),
            "fingerprint": hex::encode(owner_fp),
            "pk_bundle": hex::encode(owner_card.pk_bundle_bytes().unwrap()),
            "ed25519_pk": hex::encode(owner_card.ed25519_pk),
            "ml_dsa_65_pk": hex::encode(&owner_card.ml_dsa_65_pk),
        },
        "expected_plaintext": {
            "_doc": "Canonical-CBOR bytes of the BlockPlaintext the remaining recipient recovers from after_block under the new BCK. Equivalent to encode_plaintext(decrypt_block(after_block, alice_keys)).",
            "cbor": hex::encode(&expected_plaintext),
        },
    });

    let dir = revoke_kat_dir();
    fs::create_dir_all(&dir).unwrap();
    fs::write(before_block_path(), &before_bytes).unwrap();
    fs::write(after_block_path(), &after_bytes).unwrap();
    let pretty = serde_json::to_string_pretty(&inputs).unwrap() + "\n";
    fs::write(inputs_path(), pretty).unwrap();

    // Sanity: the bytes we just wrote must satisfy the guard's invariants.
    let before = decode_block_file(&before_bytes).unwrap();
    let after = decode_block_file(&after_bytes).unwrap();
    assert!(
        block_recipient_fingerprints(&before).contains(&bob_fp),
        "generator: before_block must contain bob's wrap"
    );
    assert!(
        !block_recipient_fingerprints(&after).contains(&bob_fp),
        "generator: after_block must NOT contain bob's wrap"
    );
    assert_ne!(
        before.aead_ct, after.aead_ct,
        "generator: re-key must change the body ciphertext"
    );

    eprintln!(
        "generate_revoke_kat: wrote {} ({} bytes), {} ({} bytes), {}",
        before_block_path().display(),
        before_bytes.len(),
        after_block_path().display(),
        after_bytes.len(),
        inputs_path().display(),
    );
}

// ---------------------------------------------------------------------------
// Always-run replay guard — pins the committed fixture.
// ---------------------------------------------------------------------------

/// Load inputs.json + before/after block files and assert the revoke re-key
/// invariants (see module docs (a)/(b)/(c)). Runs on every `cargo test`.
#[test]
fn revoke_kat_after_block_matches_inputs() {
    let inputs_raw =
        fs::read_to_string(inputs_path()).expect("revoke_kat/inputs.json must be readable");
    let inputs: serde_json::Value =
        serde_json::from_str(&inputs_raw).expect("inputs.json must parse");

    let before_bytes = fs::read(before_block_path()).expect("before_block.cbor.enc readable");
    let after_bytes = fs::read(after_block_path()).expect("after_block.cbor.enc readable");
    let before = decode_block_file(&before_bytes).expect("before_block decodes");
    let after = decode_block_file(&after_bytes).expect("after_block decodes");

    let alice_fp = hex16(&inputs["remaining_recipient"]["fingerprint"]);
    let bob_fp = hex16(&inputs["revoked_recipient"]["fingerprint"]);
    let block_uuid = hex16(&inputs["block_uuid"]);

    // (a) Revoked fingerprint ABSENT from after, remaining fingerprint PRESENT.
    let after_fps = block_recipient_fingerprints(&after);
    assert!(
        !after_fps.contains(&bob_fp),
        "(a) revoked recipient's wrap must be absent from after_block"
    );
    assert!(
        after_fps.contains(&alice_fp),
        "(a) remaining recipient's wrap must be present in after_block"
    );

    // (b) Remaining recipient decrypts after_block under the new BCK to the
    //     committed expected_plaintext. Reconstruct alice's reader identity
    //     and the author's verifying material entirely from the hex.
    let alice_x_bytes = hex_bytes(&inputs["remaining_recipient"]["x25519_sk"]);
    let alice_x_arr: [u8; 32] = alice_x_bytes
        .as_slice()
        .try_into()
        .expect("x25519_sk must be 32 bytes");
    let alice_x_sk: kem::X25519Secret = Sensitive::new(alice_x_arr);
    let alice_pq_sk =
        MlKem768Secret::from_bytes(&hex_bytes(&inputs["remaining_recipient"]["ml_kem_768_sk"]))
            .expect("ml_kem_768_sk must parse");
    let alice_pk_bundle = hex_bytes(&inputs["remaining_recipient"]["pk_bundle"]);

    let author_fp = hex16(&inputs["author"]["fingerprint"]);
    let author_pk_bundle = hex_bytes(&inputs["author"]["pk_bundle"]);
    let author_ed_pk: [u8; 32] = hex_bytes(&inputs["author"]["ed25519_pk"])
        .as_slice()
        .try_into()
        .expect("author ed25519_pk must be 32 bytes");
    let author_dsa_pk = MlDsa65Public::from_bytes(&hex_bytes(&inputs["author"]["ml_dsa_65_pk"]))
        .expect("author ml_dsa_65_pk must parse");

    let recovered = decrypt_block(
        &after,
        &author_fp,
        &author_pk_bundle,
        &author_ed_pk,
        &author_dsa_pk,
        &alice_fp,
        &alice_pk_bundle,
        &alice_x_sk,
        &alice_pq_sk,
    )
    .expect("(b) remaining recipient must decrypt after_block under the new BCK");

    let recovered_cbor = encode_plaintext(&recovered).expect("re-encode recovered plaintext");
    let expected_cbor = hex_bytes(&inputs["expected_plaintext"]["cbor"]);
    assert_eq!(
        recovered_cbor, expected_cbor,
        "(b) recovered plaintext must equal the committed expected_plaintext"
    );

    // Sanity: the recovered plaintext's block_uuid matches inputs.block_uuid.
    assert_eq!(
        recovered.block_uuid, block_uuid,
        "(b) recovered block_uuid must match inputs.block_uuid"
    );

    // (c) before_block contained bob's wrap AND the body ciphertext changed
    //     (real re-key under a fresh BCK).
    let before_fps = block_recipient_fingerprints(&before);
    assert!(
        before_fps.contains(&bob_fp),
        "(c) before_block must have contained the revoked recipient's wrap"
    );
    assert!(
        before_fps.contains(&alice_fp),
        "(c) before_block must have contained the remaining recipient's wrap"
    );
    assert_ne!(
        before.aead_ct, after.aead_ct,
        "(c) re-key must change the body ciphertext (fresh BCK)"
    );
}

// ---------------------------------------------------------------------------
// Small hex helpers for the JSON-string-typed fields.
// ---------------------------------------------------------------------------

fn hex_bytes(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex field must be a JSON string"))
        .expect("hex field must be valid hex")
}

fn hex16(v: &serde_json::Value) -> [u8; 16] {
    hex_bytes(v)
        .as_slice()
        .try_into()
        .expect("expected a 16-byte hex value")
}
