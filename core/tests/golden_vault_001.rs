//! `golden_vault_001/` — the §15 cross-language conformance vector
//! (Task 14 of PR-B).
//!
//! A complete v1 vault on disk: `vault.toml`, `identity.bundle.enc`,
//! `manifest.cbor.enc`, one block under `blocks/`, and three signed
//! contact cards under `contacts/`. Every byte is determined by
//! [`golden_vault_001_inputs.json`], which pins identities (raw key
//! bytes for owner, alice, bob), UUIDs, timestamps, KDF parameters,
//! the password, the AEAD-RNG seed, and the plaintext records.
//!
//! Three tests pin the contract:
//!
//! 1. [`golden_vault_001_pinned`] — rebuilds the vault from the JSON
//!    inputs and asserts the freshly-built bytes are byte-equal to the
//!    on-disk fixture under `core/tests/data/golden_vault_001/`.
//! 2. [`golden_vault_001_bootstrap_dump`] (`#[ignore]`) — same logic,
//!    but on drift prints the freshly-built hex per file to
//!    `eprintln!` for manual review. Never auto-overwrites.
//! 3. [`golden_vault_001_opens_with_password`] — calls `open_vault`
//!    against the on-disk fixture, asserts the manifest carries the
//!    one pinned block, and decrypts that block to verify it recovers
//!    the pinned plaintext records.
//!
//! The JSON inputs file plus the binary fixture is the cross-language
//! contract: a clean-room Python reader (see `core/tests/python/`)
//! reads the on-disk `golden_vault_001/` directory using only the
//! spec doc and the JSON's pinned password and recovers the same
//! plaintext records. That is the §15 AGPL clean-room reimplementation
//! property.
//!
//! ## Bootstrap workflow
//!
//! After a deliberate format change, the on-disk fixture must be
//! regenerated. Sequence:
//!
//! 1. Update inputs JSON if needed (e.g. new pinned device UUIDs).
//! 2. Run `materialize_golden_vault_001` (`#[ignore]`-marked) to
//!    write fresh bytes to `core/tests/data/golden_vault_001/`.
//! 3. Re-run `golden_vault_001_pinned` to confirm the new bytes
//!    match (it self-pins via `build_golden_vault`).
//! 4. `git add core/tests/data/golden_vault_001/` and commit.

#![forbid(unsafe_code)]

mod common;
use common::fixture_builder::{
    build_golden_vault, format_uuid_hyphenated, hex_encode, load_inputs, parse_uuid,
};

use std::path::PathBuf;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::kem::{self, MlKem768Secret};
use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::crypto::sig::MlDsa65Public;
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::unlock::{bundle, open_with_password};
use secretary_core::vault::{decode_block_file, decrypt_block, open_vault, Unlocker};

// ---------------------------------------------------------------------------
// Vault-001-specific path helpers
// ---------------------------------------------------------------------------

fn fixture_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push("golden_vault_001");
    p
}

fn inputs_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push("golden_vault_001_inputs.json");
    p
}

// ---------------------------------------------------------------------------
// Generator: derive owner/alice/bob raw key bytes from pinned RNG seeds and
// dump as hex. Used ONCE (via `cargo test ... -- --ignored
// generate_golden_inputs --nocapture`) to populate
// `golden_vault_001_inputs.json`.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "bootstrap helper; populate golden_vault_001_inputs.json via cargo test -- --ignored generate_golden_inputs --nocapture"]
fn generate_golden_inputs() {
    fn dump(label: &str, seed: [u8; 32]) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let display = match label {
            "owner" => "Owner",
            "alice" => "Alice",
            "bob" => "Bob",
            _ => "X",
        };
        let id = bundle::generate(display, 2_000_000_000_000, &mut rng);
        eprintln!("---- {label} ----");
        eprintln!("user_uuid:       {}", hex_encode(&id.user_uuid));
        eprintln!("x25519_sk:       {}", hex_encode(id.x25519_sk.expose()));
        eprintln!("x25519_pk:       {}", hex_encode(&id.x25519_pk));
        eprintln!("ml_kem_768_sk:   {}", hex_encode(id.ml_kem_768_sk.expose()));
        eprintln!("ml_kem_768_pk:   {}", hex_encode(&id.ml_kem_768_pk));
        eprintln!("ed25519_sk:      {}", hex_encode(id.ed25519_sk.expose()));
        eprintln!("ed25519_pk:      {}", hex_encode(&id.ed25519_pk));
        eprintln!("ml_dsa_65_seed:  {}", hex_encode(id.ml_dsa_65_sk.expose()));
        eprintln!("ml_dsa_65_pk:    {}", hex_encode(&id.ml_dsa_65_pk));
    }

    dump("owner", [0xA0; 32]);
    dump("alice", [0xA1; 32]);
    dump("bob", [0xA2; 32]);
}

// ---------------------------------------------------------------------------
// Materialize the on-disk fixture (run once after a deliberate format change)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Run once to materialize core/tests/data/golden_vault_001/. cargo test -- --ignored materialize_golden_vault_001 --nocapture"]
fn materialize_golden_vault_001() {
    let inputs = load_inputs(&inputs_path());
    let bytes = build_golden_vault(&inputs);
    let target_root = fixture_root();
    for (rel_path, file_bytes) in &bytes {
        let dst = target_root.join(rel_path);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(&dst, file_bytes).expect("write fixture file");
        eprintln!("wrote {} ({} bytes)", dst.display(), file_bytes.len());
    }
}

// ---------------------------------------------------------------------------
// Drift assertion: rebuild from JSON, compare to on-disk fixture
// ---------------------------------------------------------------------------

#[test]
fn golden_vault_001_pinned() {
    let inputs = load_inputs(&inputs_path());
    let actual = build_golden_vault(&inputs);
    let target_root = fixture_root();
    for (rel_path, file_bytes) in &actual {
        let on_disk_path = target_root.join(rel_path);
        let on_disk = std::fs::read(&on_disk_path).unwrap_or_else(|e| {
            panic!(
                "missing fixture file {}: {} (regenerate via `cargo test --release \
                 -p secretary-core --test golden_vault_001 -- --ignored \
                 materialize_golden_vault_001 --nocapture` after a deliberate \
                 format change)",
                on_disk_path.display(),
                e
            );
        });
        assert_eq!(
            file_bytes,
            &on_disk,
            "drift in {} — regenerate fixture via the materialize_golden_vault_001 \
             ignored test if this is a deliberate format change",
            rel_path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// Bootstrap dumper: prints freshly-built hex per file. Never auto-overwrites
// the on-disk fixture; that is the materialize test's job.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "bootstrap dumper; cargo test -- --ignored golden_vault_001_bootstrap_dump --nocapture"]
fn golden_vault_001_bootstrap_dump() {
    let inputs = load_inputs(&inputs_path());
    let actual = build_golden_vault(&inputs);
    eprintln!("---- BEGIN golden_vault_001 expected bytes per file ----");
    for (rel_path, bytes) in &actual {
        eprintln!(
            "{} ({} bytes):\n{}",
            rel_path.display(),
            bytes.len(),
            hex_encode(bytes),
        );
    }
    eprintln!("---- END ----");
}

// ---------------------------------------------------------------------------
// End-to-end open + decrypt: validity gate
// ---------------------------------------------------------------------------

#[test]
fn golden_vault_001_opens_with_password() {
    let inputs = load_inputs(&inputs_path());
    let folder = fixture_root();
    let password = SecretBytes::new(inputs.password.as_bytes().to_vec());

    let open = open_vault(&folder, Unlocker::Password(&password), None)
        .expect("open_vault must succeed against the on-disk fixture");

    // Manifest carries exactly the one pinned block.
    assert_eq!(
        open.manifest.blocks.len(),
        1,
        "manifest must carry the one pinned block"
    );
    let entry = &open.manifest.blocks[0];
    let block_uuid = parse_uuid(&inputs.block_uuid);
    assert_eq!(entry.block_uuid, block_uuid);
    assert_eq!(entry.block_name, inputs.block_plaintext.block_name);

    // Decrypt the on-disk block file as the owner. This proves the manifest
    // entry's fingerprint, the block file bytes, the recipient table, and
    // the AEAD body all line up.
    let block_uuid_hyphenated = format_uuid_hyphenated(&block_uuid);
    let block_path = folder
        .join("blocks")
        .join(format!("{block_uuid_hyphenated}.cbor.enc"));
    let block_bytes = std::fs::read(&block_path).expect("read block file");
    let block_file = decode_block_file(&block_bytes).expect("decode_block_file");

    // Sender == reader == owner for this single-recipient vector.
    let owner_card = open.owner_card.clone();
    let owner_card_bytes = owner_card
        .to_canonical_cbor()
        .expect("owner card to_canonical_cbor");
    let owner_fp = fingerprint(&owner_card_bytes);
    let owner_pk_bundle = owner_card
        .pk_bundle_bytes()
        .expect("owner pk_bundle_bytes");
    let owner_dsa_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)
        .expect("ml-dsa pk owner");
    let owner_x_sk: kem::X25519Secret = Sensitive::new(*open.identity.x25519_sk.expose());
    let owner_pq_sk = MlKem768Secret::from_bytes(open.identity.ml_kem_768_sk.expose())
        .expect("ml-kem sk owner");

    let recovered = decrypt_block(
        &block_file,
        &owner_fp,
        &owner_pk_bundle,
        &owner_card.ed25519_pk,
        &owner_dsa_pk,
        &owner_fp,
        &owner_pk_bundle,
        &owner_x_sk,
        &owner_pq_sk,
    )
    .expect("decrypt_block");

    // Cross-check plaintext shape against the JSON inputs.
    assert_eq!(recovered.block_uuid, block_uuid);
    assert_eq!(recovered.block_name, inputs.block_plaintext.block_name);
    assert_eq!(recovered.records.len(), inputs.block_plaintext.records.len());
    let recovered_record = &recovered.records[0];
    let inputs_record = &inputs.block_plaintext.records[0];
    assert_eq!(recovered_record.record_type, inputs_record.record_type);
    assert_eq!(recovered_record.tags, inputs_record.tags);
    assert_eq!(recovered_record.tombstone, inputs_record.tombstone);
    assert_eq!(recovered_record.fields.len(), inputs_record.fields.len());

    // Sanity: the IBK we recovered through `open_with_password` must match
    // the IBK derived inside `build_golden_vault` — both use the same
    // password + salt + KDF params. This is a defence-in-depth check on
    // top of the manifest verify that already ran inside `open_vault`.
    let expected = build_golden_vault(&inputs);
    let unlocked = open_with_password(
        expected
            .get(&PathBuf::from("vault.toml"))
            .expect("vault.toml in build output"),
        expected
            .get(&PathBuf::from("identity.bundle.enc"))
            .expect("identity.bundle.enc in build output"),
        &password,
    )
    .expect("open_with_password from build output");
    assert_eq!(
        unlocked.identity_block_key.expose(),
        open.identity_block_key.expose(),
        "IBK from password unlock must match IBK in OpenVault"
    );
}
