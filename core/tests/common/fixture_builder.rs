//! Pure-function fixture builders for the `golden_vault_NNN` integration tests.
//!
//! Parameterized over `(inputs_path, fixture_root)` so a single implementation
//! produces both `golden_vault_001/` and `golden_vault_002/` from their
//! respective `_inputs.json` files.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;
use serde::Deserialize;

use secretary_core::crypto::aead;
use secretary_core::crypto::hash::hash as blake3_hash;
use secretary_core::crypto::kdf::{
    derive_master_kek, derive_recovery_kek, Argon2idParams, TAG_ID_BUNDLE, TAG_ID_WRAP_PW,
    TAG_ID_WRAP_REC,
};
use secretary_core::crypto::kem::MlKem768Public;
use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::crypto::sig::{
    Ed25519Secret, MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN,
};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::{fingerprint, Fingerprint};
use secretary_core::unlock::{
    bundle::IdentityBundle,
    bundle_file::{self, BundleFile},
    vault_toml,
};
use secretary_core::vault::{
    encode_block_file, encode_manifest_file, encrypt_block, sign_manifest, BlockEntry, BlockHeader,
    BlockPlaintext, KdfParamsRef, Manifest, ManifestHeader, RecipientPublicKeys, Record,
    RecordField, RecordFieldValue, VectorClockEntry, FILE_KIND_BLOCK,
};
use secretary_core::version::{FORMAT_VERSION, MAGIC, SUITE_ID};

// ---------------------------------------------------------------------------
// JSON input shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // some descriptive fields are JSON-only documentation
pub struct Inputs {
    #[serde(rename = "_format")]
    pub _format: String,
    pub vault_uuid: String,
    pub block_uuid: String,
    /// Canonical device UUID for this fixture. Each per-field `device_uuid`
    /// inside `block_plaintext.records[*].fields[*]` and the `vector_clock`
    /// entries reference the same device for this single-device vector.
    /// Kept at the top level so a Python parser can cross-check.
    pub device_uuid: String,
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
    pub password: String,
    pub kdf_params: InputsKdfParams,
    pub owner: InputsIdentity,
    pub alice: InputsIdentity,
    pub bob: InputsIdentity,
    pub block_plaintext: InputsBlockPlaintext,
    pub rng_seed_for_aead_nonces: String,
}

#[derive(Debug, Deserialize)]
pub struct InputsKdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, Deserialize)]
pub struct InputsIdentity {
    pub user_uuid: String,
    pub display_name: String,
    pub created_at_ms: u64,
    pub x25519_sk: String,
    pub x25519_pk: String,
    pub ml_kem_768_sk: String,
    pub ml_kem_768_pk: String,
    pub ed25519_sk: String,
    pub ed25519_pk: String,
    pub ml_dsa_65_sk_seed: String,
    pub ml_dsa_65_pk: String,
}

#[derive(Debug, Deserialize)]
pub struct InputsBlockPlaintext {
    pub block_version: u32,
    pub block_name: String,
    pub schema_version: u32,
    pub vector_clock: Vec<InputsVectorClockEntry>,
    pub records: Vec<InputsRecord>,
}

#[derive(Debug, Deserialize)]
pub struct InputsVectorClockEntry {
    pub device_uuid: String,
    pub counter: u64,
}

#[derive(Debug, Deserialize)]
pub struct InputsRecord {
    pub record_uuid: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub tombstone: bool,
    #[serde(default)]
    pub tombstoned_at_ms: u64,
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
    pub fields: BTreeMap<String, InputsField>,
}

#[derive(Debug, Deserialize)]
pub struct InputsField {
    /// "text" or "bytes"
    pub value_type: String,
    /// Set when value_type = "text".
    #[serde(default)]
    pub value_text: Option<String>,
    /// Set when value_type = "bytes" — hex.
    #[serde(default)]
    pub value_hex: Option<String>,
    pub last_mod_ms: u64,
    pub device_uuid: String,
}

// ---------------------------------------------------------------------------
// Hex / UUID helpers (kept local — the test crate doesn't pull in `hex`)
// ---------------------------------------------------------------------------

pub fn parse_hex(s: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) {
        panic!("odd-length hex: {s:?}");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        out.push((nib(chunk[0]) << 4) | nib(chunk[1]));
    }
    out
}

// Test-fixture nibble decoder: panics on malformed input (acceptable for
// KAT-pinned hex strings). See `common::nib` for the Result-returning
// variant used by the serde-driven JSON KAT loader.
fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex char {c}"),
    }
}

pub fn parse_hex_array<const N: usize>(s: &str, label: &str) -> [u8; N] {
    let v = parse_hex(s);
    v.as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes for {label}, got {}", v.len()))
}

/// Parse 8-4-4-4-12 hyphenated lowercase-hex UUID, OR a 32-char hex string
/// (legacy/back-compat). Returns the 16 raw bytes.
pub fn parse_uuid(s: &str) -> [u8; 16] {
    let stripped: String = s.chars().filter(|&c| c != '-').collect();
    parse_hex_array::<16>(&stripped, "uuid")
}

/// Format a 16-byte UUID as 8-4-4-4-12 lowercase hex, matching
/// `vault::create_vault`'s `format_uuid_hyphenated` (file paths in the vault
/// folder use this form).
pub fn format_uuid_hyphenated(uuid: &[u8; 16]) -> String {
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

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// ---------------------------------------------------------------------------
// Loaders
// ---------------------------------------------------------------------------

pub fn load_inputs(inputs_path: &Path) -> Inputs {
    let bytes = std::fs::read(inputs_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", inputs_path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", inputs_path.display()))
}

// ---------------------------------------------------------------------------
// Identity / card construction (pinned bytes)
// ---------------------------------------------------------------------------

/// Build an [`IdentityBundle`] directly from the pinned JSON byte fields.
/// All four secret keys come straight from the JSON; the four public keys
/// also come from the JSON (we trust the JSON to be self-consistent —
/// the assertion tests will fail loudly otherwise).
pub fn identity_from_inputs(id: &InputsIdentity) -> IdentityBundle {
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
    assert_eq!(ml_dsa_65_pk.len(), 1952, "ml_dsa_65_pk must be 1952 bytes");

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
pub fn signed_card_from(id: &IdentityBundle) -> ContactCard {
    let pq_sk = MlDsa65Secret::from_bytes(id.ml_dsa_65_sk.expose()).expect("ml-dsa-65 seed length");
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

pub fn build_block_plaintext(
    inputs: &InputsBlockPlaintext,
    block_uuid: [u8; 16],
) -> BlockPlaintext {
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
pub fn compose_aad(tag: &[u8], vault_uuid: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + vault_uuid.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(vault_uuid);
    out
}

/// Outputs of [`build_identity_envelope`]: the §2 / §3 byte payloads plus
/// the IBK we derived (so the manifest AEAD step can use the same key).
pub struct EnvelopeOutputs {
    pub vault_toml_bytes: Vec<u8>,
    pub identity_bundle_bytes: Vec<u8>,
    pub identity_block_key: Sensitive<[u8; 32]>,
}

/// Wrap a pinned [`IdentityBundle`] into `vault.toml` + `identity.bundle.enc`
/// using the JSON-pinned KDF params, salt, vault UUID, password, and the
/// deterministic AEAD-RNG. Mirrors the steps in `unlock::create_vault_unchecked`
/// but without inventing fresh identities.
pub fn build_identity_envelope(
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
    let master_kek = derive_master_kek(&password, &salt, &kdf_params).expect("derive_master_kek");

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
    let wrap_rec_with_tag = aead::encrypt(&recovery_kek, &nonce_rec, &wrap_rec_aad, ibk.expose())
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
    let vault_toml_bytes = vault_toml::encode(&vt)
        .expect("vault_toml encode")
        .into_bytes();

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
pub fn build_golden_vault(inputs: &Inputs) -> BTreeMap<PathBuf, Vec<u8>> {
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
    let aead_seed =
        parse_hex_array::<32>(&inputs.rng_seed_for_aead_nonces, "rng_seed_for_aead_nonces");
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
    let owner_pk_bundle = owner_card.pk_bundle_bytes().expect("owner pk_bundle_bytes");

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
