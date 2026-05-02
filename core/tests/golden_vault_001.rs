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

use std::collections::BTreeMap;
use std::path::PathBuf;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;
use serde::Deserialize;

use secretary_core::crypto::aead;
use secretary_core::crypto::hash::hash as blake3_hash;
use secretary_core::crypto::kdf::{
    derive_master_kek, derive_recovery_kek, Argon2idParams, TAG_ID_BUNDLE, TAG_ID_WRAP_PW,
    TAG_ID_WRAP_REC,
};
use secretary_core::crypto::kem::{self, MlKem768Public, MlKem768Secret};
use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::crypto::sig::{
    Ed25519Secret, MlDsa65Public, MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN,
};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::{fingerprint, Fingerprint};
use secretary_core::unlock::{
    self,
    bundle::IdentityBundle,
    bundle_file::{self, BundleFile},
    open_with_password, vault_toml,
};
use secretary_core::vault::{
    decode_block_file, decrypt_block, encode_block_file, encode_manifest_file, encrypt_block,
    open_vault, sign_manifest, BlockEntry, BlockHeader, BlockPlaintext, KdfParamsRef, Manifest,
    ManifestHeader, Record, RecordField, RecordFieldValue, RecipientPublicKeys, Unlocker,
    VectorClockEntry, FILE_KIND_BLOCK,
};
use secretary_core::version::{FORMAT_VERSION, MAGIC, SUITE_ID};

// ---------------------------------------------------------------------------
// JSON input shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // some descriptive fields are JSON-only documentation
struct Inputs {
    #[serde(rename = "_format")]
    _format: String,
    vault_uuid: String,
    block_uuid: String,
    /// Canonical device UUID for this fixture. Each per-field `device_uuid`
    /// inside `block_plaintext.records[*].fields[*]` and the `vector_clock`
    /// entries reference the same device for this single-device vector.
    /// Kept at the top level so a Python parser can cross-check.
    device_uuid: String,
    created_at_ms: u64,
    last_mod_ms: u64,
    password: String,
    kdf_params: InputsKdfParams,
    owner: InputsIdentity,
    alice: InputsIdentity,
    bob: InputsIdentity,
    block_plaintext: InputsBlockPlaintext,
    rng_seed_for_aead_nonces: String,
}

#[derive(Debug, Deserialize)]
struct InputsKdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug, Deserialize)]
struct InputsIdentity {
    user_uuid: String,
    display_name: String,
    created_at_ms: u64,
    x25519_sk: String,
    x25519_pk: String,
    ml_kem_768_sk: String,
    ml_kem_768_pk: String,
    ed25519_sk: String,
    ed25519_pk: String,
    ml_dsa_65_sk_seed: String,
    ml_dsa_65_pk: String,
}

#[derive(Debug, Deserialize)]
struct InputsBlockPlaintext {
    block_version: u32,
    block_name: String,
    schema_version: u32,
    vector_clock: Vec<InputsVectorClockEntry>,
    records: Vec<InputsRecord>,
}

#[derive(Debug, Deserialize)]
struct InputsVectorClockEntry {
    device_uuid: String,
    counter: u64,
}

#[derive(Debug, Deserialize)]
struct InputsRecord {
    record_uuid: String,
    record_type: String,
    tags: Vec<String>,
    tombstone: bool,
    #[serde(default)]
    tombstoned_at_ms: u64,
    created_at_ms: u64,
    last_mod_ms: u64,
    fields: BTreeMap<String, InputsField>,
}

#[derive(Debug, Deserialize)]
struct InputsField {
    /// "text" or "bytes"
    value_type: String,
    /// Set when value_type = "text".
    #[serde(default)]
    value_text: Option<String>,
    /// Set when value_type = "bytes" — hex.
    #[serde(default)]
    value_hex: Option<String>,
    last_mod_ms: u64,
    device_uuid: String,
}

// ---------------------------------------------------------------------------
// Hex / UUID helpers (kept local — the test crate doesn't pull in `hex`)
// ---------------------------------------------------------------------------

fn parse_hex(s: &str) -> Vec<u8> {
    if s.len() % 2 != 0 {
        panic!("odd-length hex: {s:?}");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        out.push((nib(chunk[0]) << 4) | nib(chunk[1]));
    }
    out
}

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex char {c}"),
    }
}

fn parse_hex_array<const N: usize>(s: &str, label: &str) -> [u8; N] {
    let v = parse_hex(s);
    v.as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes for {label}, got {}", v.len()))
}

/// Parse 8-4-4-4-12 hyphenated lowercase-hex UUID, OR a 32-char hex string
/// (legacy/back-compat). Returns the 16 raw bytes.
fn parse_uuid(s: &str) -> [u8; 16] {
    let stripped: String = s.chars().filter(|&c| c != '-').collect();
    parse_hex_array::<16>(&stripped, "uuid")
}

/// Format a 16-byte UUID as 8-4-4-4-12 lowercase hex, matching
/// `vault::create_vault`'s `format_uuid_hyphenated` (file paths in the vault
/// folder use this form).
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

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// ---------------------------------------------------------------------------
// Loaders
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

fn load_inputs() -> Inputs {
    let path = inputs_path();
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Identity / card construction (pinned bytes)
// ---------------------------------------------------------------------------

/// Build an [`IdentityBundle`] directly from the pinned JSON byte fields.
/// All four secret keys come straight from the JSON; the four public keys
/// also come from the JSON (we trust the JSON to be self-consistent —
/// the assertion tests will fail loudly otherwise).
fn identity_from_inputs(id: &InputsIdentity) -> IdentityBundle {
    let user_uuid = parse_uuid(&id.user_uuid);
    let x25519_sk_bytes = parse_hex_array::<32>(&id.x25519_sk, "x25519_sk");
    let x25519_pk = parse_hex_array::<32>(&id.x25519_pk, "x25519_pk");
    let ml_kem_768_sk_bytes = parse_hex(&id.ml_kem_768_sk);
    assert_eq!(
        ml_kem_768_sk_bytes.len(),
        2400,
        "ml_kem_768_sk must be 2400 bytes"
    );
    let ml_kem_768_pk = parse_hex(&id.ml_kem_768_pk);
    assert_eq!(
        ml_kem_768_pk.len(),
        1184,
        "ml_kem_768_pk must be 1184 bytes"
    );
    let ed25519_sk_bytes = parse_hex_array::<32>(&id.ed25519_sk, "ed25519_sk");
    let ed25519_pk = parse_hex_array::<32>(&id.ed25519_pk, "ed25519_pk");
    let ml_dsa_65_sk_seed = parse_hex(&id.ml_dsa_65_sk_seed);
    assert_eq!(
        ml_dsa_65_sk_seed.len(),
        32,
        "ml_dsa_65_sk_seed must be 32 bytes (FIPS 204 xi)"
    );
    let ml_dsa_65_pk = parse_hex(&id.ml_dsa_65_pk);
    assert_eq!(
        ml_dsa_65_pk.len(),
        1952,
        "ml_dsa_65_pk must be 1952 bytes"
    );

    IdentityBundle {
        user_uuid,
        display_name: id.display_name.clone(),
        x25519_sk: Sensitive::new(x25519_sk_bytes),
        x25519_pk,
        ml_kem_768_sk: Sensitive::new(ml_kem_768_sk_bytes),
        ml_kem_768_pk,
        ed25519_sk: Sensitive::new(ed25519_sk_bytes),
        ed25519_pk,
        ml_dsa_65_sk: Sensitive::new(ml_dsa_65_sk_seed),
        ml_dsa_65_pk,
        created_at_ms: id.created_at_ms,
    }
}

/// Build a self-signed [`ContactCard`] from a pinned [`IdentityBundle`].
/// Mirrors `share_block.rs::make_signed_card` but consumes a pre-built bundle.
fn signed_card_from(id: &IdentityBundle) -> ContactCard {
    let pq_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose())
        .expect("ml-dsa-65 seed length");
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
    card.sign(&id.ed25519_sk, &pq_sk).expect("card.sign");
    card
}

// ---------------------------------------------------------------------------
// Block plaintext construction (pinned)
// ---------------------------------------------------------------------------

fn build_block_plaintext(inputs: &InputsBlockPlaintext, block_uuid: [u8; 16]) -> BlockPlaintext {
    let mut records = Vec::with_capacity(inputs.records.len());
    for r in &inputs.records {
        let mut fields: BTreeMap<String, RecordField> = BTreeMap::new();
        for (name, f) in &r.fields {
            let value = match f.value_type.as_str() {
                "text" => RecordFieldValue::Text(
                    f.value_text
                        .clone()
                        .expect("value_type=text needs value_text")
                        .into(),
                ),
                "bytes" => RecordFieldValue::Bytes(
                    parse_hex(
                        f.value_hex
                            .as_ref()
                            .expect("value_type=bytes needs value_hex"),
                    )
                    .into(),
                ),
                other => panic!("unknown value_type {other:?}"),
            };
            fields.insert(
                name.clone(),
                RecordField {
                    value,
                    last_mod: f.last_mod_ms,
                    device_uuid: parse_uuid(&f.device_uuid),
                    unknown: BTreeMap::new(),
                },
            );
        }
        records.push(Record {
            record_uuid: parse_uuid(&r.record_uuid),
            record_type: r.record_type.clone(),
            fields,
            tags: r.tags.clone(),
            created_at_ms: r.created_at_ms,
            last_mod_ms: r.last_mod_ms,
            tombstone: r.tombstone,
            tombstoned_at_ms: r.tombstoned_at_ms,
            unknown: BTreeMap::new(),
        });
    }
    BlockPlaintext {
        block_version: inputs.block_version,
        block_uuid,
        block_name: inputs.block_name.clone(),
        schema_version: inputs.schema_version,
        records,
        unknown: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Identity-bundle envelope construction (pinned)
// ---------------------------------------------------------------------------
//
// We can't go through `unlock::create_vault_unchecked` because it generates
// fresh identities and a fresh recovery mnemonic. Instead we wrap the
// pinned identity bundle into the §3 envelope by hand, using the same AEAD
// primitives as `unlock::mod.rs` does. Three AEAD-encrypts: bundle (under
// IBK), wrap_pw (under master_kek), wrap_rec (under recovery_kek). The
// IBK and recovery key entropy come from the deterministic AEAD-RNG seed.

/// Build the AEAD AAD as `tag || vault_uuid` — mirrors
/// `unlock::mod.rs::compose_aad`, which is module-private.
fn compose_aad(tag: &[u8], vault_uuid: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + vault_uuid.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(vault_uuid);
    out
}

/// Outputs of [`build_identity_envelope`]: the §2 / §3 byte payloads plus
/// the IBK we derived (so the manifest AEAD step can use the same key).
struct EnvelopeOutputs {
    vault_toml_bytes: Vec<u8>,
    identity_bundle_bytes: Vec<u8>,
    identity_block_key: Sensitive<[u8; 32]>,
}

/// Wrap a pinned [`IdentityBundle`] into `vault.toml` + `identity.bundle.enc`
/// using the JSON-pinned KDF params, salt, vault UUID, password, and the
/// deterministic AEAD-RNG. Mirrors the steps in `unlock::create_vault_unchecked`
/// but without inventing fresh identities.
fn build_identity_envelope(
    inputs: &Inputs,
    rng: &mut ChaCha20Rng,
    bundle: &IdentityBundle,
) -> EnvelopeOutputs {
    let vault_uuid = parse_uuid(&inputs.vault_uuid);
    let salt = parse_hex_array::<32>(&inputs.kdf_params.salt, "kdf.salt");
    let kdf_params = Argon2idParams::new(
        inputs.kdf_params.memory_kib,
        inputs.kdf_params.iterations,
        inputs.kdf_params.parallelism,
    );
    let password = SecretBytes::new(inputs.password.as_bytes().to_vec());

    // Step 1: derive Master KEK from the pinned password + salt.
    let master_kek =
        derive_master_kek(&password, &salt, &kdf_params).expect("derive_master_kek");

    // Step 2: derive a deterministic Recovery KEK. We use the AEAD-RNG to
    // draw 32 bytes of "recovery entropy" — we don't need the BIP-39
    // mnemonic words for the cross-language vector, only the wrap_rec
    // ciphertext (which Python won't open via the recovery path in the
    // vector). Future work could pin the mnemonic words too.
    let mut recovery_entropy = [0u8; 32];
    rng.fill_bytes(&mut recovery_entropy);
    let recovery_entropy_wrapped = Sensitive::new(recovery_entropy);
    let recovery_kek = derive_recovery_kek(&recovery_entropy_wrapped);

    // Step 3: draw the IBK from the AEAD-RNG. Deterministic — the same JSON
    // seed always produces the same IBK.
    let mut ibk_bytes = [0u8; 32];
    rng.fill_bytes(&mut ibk_bytes);
    let ibk = Sensitive::new(ibk_bytes);

    // Step 4: encode the bundle plaintext, then AEAD-encrypt three payloads
    // under three independent nonces. Order of nonce draws and AEAD calls
    // matches `unlock::create_vault_unchecked` so a future audit can verify
    // the byte layout against that orchestrator's output for an equivalent
    // pinned identity.
    let bundle_plaintext = bundle.to_canonical_cbor().expect("bundle CBOR");

    let mut nonce_id = [0u8; 24];
    rng.fill_bytes(&mut nonce_id);
    let mut nonce_pw = [0u8; 24];
    rng.fill_bytes(&mut nonce_pw);
    let mut nonce_rec = [0u8; 24];
    rng.fill_bytes(&mut nonce_rec);

    let bundle_aad = compose_aad(TAG_ID_BUNDLE, &vault_uuid);
    let bundle_ct_with_tag = aead::encrypt(&ibk, &nonce_id, &bundle_aad, &bundle_plaintext)
        .expect("aead encrypt bundle");

    let wrap_pw_aad = compose_aad(TAG_ID_WRAP_PW, &vault_uuid);
    let wrap_pw_with_tag = aead::encrypt(&master_kek, &nonce_pw, &wrap_pw_aad, ibk.expose())
        .expect("aead encrypt wrap_pw");
    let wrap_pw_arr: [u8; 48] = wrap_pw_with_tag
        .as_slice()
        .try_into()
        .expect("32B IBK + 16B tag = 48B wrap_pw");

    let wrap_rec_aad = compose_aad(TAG_ID_WRAP_REC, &vault_uuid);
    let wrap_rec_with_tag =
        aead::encrypt(&recovery_kek, &nonce_rec, &wrap_rec_aad, ibk.expose())
            .expect("aead encrypt wrap_rec");
    let wrap_rec_arr: [u8; 48] = wrap_rec_with_tag
        .as_slice()
        .try_into()
        .expect("32B IBK + 16B tag = 48B wrap_rec");

    // Step 5: pack the §3 envelope.
    let bf = BundleFile {
        vault_uuid,
        created_at_ms: inputs.created_at_ms,
        wrap_pw_nonce: nonce_pw,
        wrap_pw_ct_with_tag: wrap_pw_arr,
        wrap_rec_nonce: nonce_rec,
        wrap_rec_ct_with_tag: wrap_rec_arr,
        bundle_nonce: nonce_id,
        bundle_ct_with_tag,
    };
    let identity_bundle_bytes = bundle_file::encode(&bf);

    // Step 6: emit `vault.toml` (§2) — KDF params mirror the JSON.
    let vt = vault_toml::VaultToml {
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        vault_uuid,
        created_at_ms: inputs.created_at_ms,
        kdf: vault_toml::KdfSection {
            algorithm: "argon2id".to_string(),
            version: "1.3".to_string(),
            memory_kib: kdf_params.memory_kib,
            iterations: kdf_params.iterations,
            parallelism: kdf_params.parallelism,
            salt,
        },
    };
    let vault_toml_bytes = vault_toml::encode(&vt).expect("vault_toml encode").into_bytes();

    EnvelopeOutputs {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity_block_key: ibk,
    }
}

// ---------------------------------------------------------------------------
// build_golden_vault — the deterministic generator
// ---------------------------------------------------------------------------

/// Build the complete on-disk vault deterministically from `inputs`. Returns
/// a map from relative path (under the vault root) to file bytes. Caller
/// writes those bytes to disk (or compares them against an existing layout).
fn build_golden_vault(inputs: &Inputs) -> BTreeMap<PathBuf, Vec<u8>> {
    let vault_uuid = parse_uuid(&inputs.vault_uuid);
    let block_uuid = parse_uuid(&inputs.block_uuid);

    // Build the three pinned identity bundles.
    let owner = identity_from_inputs(&inputs.owner);
    let alice = identity_from_inputs(&inputs.alice);
    let bob = identity_from_inputs(&inputs.bob);

    // Build self-signed contact cards. Sign deterministically — Ed25519 +
    // ML-DSA-65 sign paths are both deterministic so no RNG is consumed.
    let owner_card = signed_card_from(&owner);
    let alice_card = signed_card_from(&alice);
    let bob_card = signed_card_from(&bob);

    let owner_card_bytes = owner_card
        .to_canonical_cbor()
        .expect("owner card to_canonical_cbor");
    let alice_card_bytes = alice_card
        .to_canonical_cbor()
        .expect("alice card to_canonical_cbor");
    let bob_card_bytes = bob_card
        .to_canonical_cbor()
        .expect("bob card to_canonical_cbor");

    let owner_fp: Fingerprint = fingerprint(&owner_card_bytes);

    // The single AEAD-RNG for everything random downstream of identity:
    // recovery entropy, IBK, three identity-bundle AEAD nonces, manifest
    // AEAD nonce, BCK, per-recipient encap inputs (X25519 ephemeral +
    // ML-KEM message + per-wrap nonce), and the block-body AEAD nonce.
    let aead_seed = parse_hex_array::<32>(
        &inputs.rng_seed_for_aead_nonces,
        "rng_seed_for_aead_nonces",
    );
    let mut rng = ChaCha20Rng::from_seed(aead_seed);

    // Build vault.toml + identity.bundle.enc. The IBK we derive here is
    // the same one `open_vault` will recover via the password path —
    // the manifest AEAD must use exactly this IBK or open will fail.
    let envelope = build_identity_envelope(inputs, &mut rng, &owner);

    // Build the block plaintext + encrypt it to a single self-recipient
    // (the owner). The block-level vector clock is pinned via the JSON's
    // `block_plaintext.vector_clock`.
    let plaintext = build_block_plaintext(&inputs.block_plaintext, block_uuid);
    let block_header = BlockHeader {
        magic: MAGIC,
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        file_kind: FILE_KIND_BLOCK,
        vault_uuid,
        block_uuid,
        created_at_ms: inputs.created_at_ms,
        last_mod_ms: inputs.last_mod_ms,
        vector_clock: inputs
            .block_plaintext
            .vector_clock
            .iter()
            .map(|e| VectorClockEntry {
                device_uuid: parse_uuid(&e.device_uuid),
                counter: e.counter,
            })
            .collect(),
    };

    // Typed handles for the owner's signing + KEM keys.
    let owner_pq_pk =
        MlKem768Public::from_bytes(&owner.ml_kem_768_pk).expect("ml-kem pk len owner");
    let owner_ed_sk: Ed25519Secret = Sensitive::new(*owner.ed25519_sk.expose());
    let owner_pq_sk_dsa =
        MlDsa65Secret::from_bytes(owner.ml_dsa_65_sk.expose()).expect("ml-dsa sk owner");
    let owner_pk_bundle = owner_card
        .pk_bundle_bytes()
        .expect("owner pk_bundle_bytes");

    // Single recipient: owner. The §15 vector keeps the fan-out minimal so
    // the cross-language reader has the smallest possible block to parse.
    // Alice and bob are present as cards on disk (so a multi-recipient
    // round-trip is one card-list change away) but not as block recipients
    // for this vector.
    let recipients = [RecipientPublicKeys {
        fingerprint: owner_fp,
        pk_bundle: &owner_pk_bundle,
        x25519_pk: &owner.x25519_pk,
        ml_kem_768_pk: &owner_pq_pk,
    }];

    let block_file = encrypt_block(
        &mut rng,
        &block_header,
        &plaintext,
        &owner_fp,
        &owner_pk_bundle,
        &owner_ed_sk,
        &owner_pq_sk_dsa,
        &recipients,
    )
    .expect("encrypt_block");

    let block_bytes = encode_block_file(&block_file).expect("encode_block_file");
    let block_fingerprint: [u8; 32] = *blake3_hash(&block_bytes).as_bytes();

    // Build the manifest body. Single block entry referencing the encrypted
    // block. Vault-level vector clock mirrors the block's clock — this is a
    // first-write, so the only ticked counter is the block's own.
    let manifest_vector_clock: Vec<VectorClockEntry> = inputs
        .block_plaintext
        .vector_clock
        .iter()
        .map(|e| VectorClockEntry {
            device_uuid: parse_uuid(&e.device_uuid),
            counter: e.counter,
        })
        .collect();

    let block_entry = BlockEntry {
        block_uuid,
        block_name: inputs.block_plaintext.block_name.clone(),
        fingerprint: block_fingerprint,
        recipients: vec![owner.user_uuid],
        vector_clock_summary: manifest_vector_clock.clone(),
        suite_id: SUITE_ID,
        created_at_ms: inputs.created_at_ms,
        last_mod_ms: inputs.last_mod_ms,
        unknown: BTreeMap::new(),
    };

    let manifest_body = Manifest {
        manifest_version: 1,
        vault_uuid,
        format_version: FORMAT_VERSION,
        suite_id: SUITE_ID,
        owner_user_uuid: owner.user_uuid,
        vector_clock: manifest_vector_clock,
        blocks: vec![block_entry],
        trash: Vec::new(),
        kdf_params: KdfParamsRef {
            memory_kib: inputs.kdf_params.memory_kib,
            iterations: inputs.kdf_params.iterations,
            parallelism: inputs.kdf_params.parallelism,
            salt: parse_hex_array::<32>(&inputs.kdf_params.salt, "kdf.salt"),
        },
        unknown: BTreeMap::new(),
    };

    // Manifest binary header: created_at == last_mod for a first-write
    // vector. The 24-byte AEAD nonce comes from the same RNG.
    let manifest_header = ManifestHeader {
        vault_uuid,
        created_at_ms: inputs.created_at_ms,
        last_mod_ms: inputs.last_mod_ms,
    };
    let mut manifest_aead_nonce = [0u8; 24];
    rng.fill_bytes(&mut manifest_aead_nonce);

    let manifest_file = sign_manifest(
        manifest_header,
        &manifest_body,
        &envelope.identity_block_key,
        &manifest_aead_nonce,
        owner_fp,
        &owner.ed25519_sk,
        &owner_pq_sk_dsa,
    )
    .expect("sign_manifest");
    let manifest_bytes = encode_manifest_file(&manifest_file).expect("encode_manifest_file");

    // Assemble the path-to-bytes map.
    let mut out: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    out.insert(PathBuf::from("vault.toml"), envelope.vault_toml_bytes);
    out.insert(
        PathBuf::from("identity.bundle.enc"),
        envelope.identity_bundle_bytes,
    );
    out.insert(PathBuf::from("manifest.cbor.enc"), manifest_bytes);

    let block_uuid_hyphenated = format_uuid_hyphenated(&block_uuid);
    out.insert(
        PathBuf::from(format!("blocks/{block_uuid_hyphenated}.cbor.enc")),
        block_bytes,
    );

    let owner_uuid_hyphenated = format_uuid_hyphenated(&owner.user_uuid);
    let alice_uuid_hyphenated = format_uuid_hyphenated(&alice.user_uuid);
    let bob_uuid_hyphenated = format_uuid_hyphenated(&bob.user_uuid);
    out.insert(
        PathBuf::from(format!("contacts/{owner_uuid_hyphenated}.card")),
        owner_card_bytes,
    );
    out.insert(
        PathBuf::from(format!("contacts/{alice_uuid_hyphenated}.card")),
        alice_card_bytes,
    );
    out.insert(
        PathBuf::from(format!("contacts/{bob_uuid_hyphenated}.card")),
        bob_card_bytes,
    );

    out
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
        let id = unlock::bundle::generate(display, 2_000_000_000_000, &mut rng);
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
    let inputs = load_inputs();
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
    let inputs = load_inputs();
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
    let inputs = load_inputs();
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
    let inputs = load_inputs();
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

