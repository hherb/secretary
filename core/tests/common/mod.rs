//! Shared helpers for integration tests — KAT loader and hex utilities.
//!
//! Each `tests/*.rs` is its own crate; this module is included via
//! `mod common;` and is *not* picked up as a separate test target by Cargo
//! (the `common/mod.rs` layout is the conventional way to share test code).
//!
//! The on-disk JSON KAT files in `tests/data/*.json` are the
//! cross-language conformance contract from `docs/crypto-design.md` §15.
//! Each KAT family has a typed `*Kat` struct here; tests load with
//! [`load_kat`].

#![allow(dead_code)] // not every test consumes every helper.

use std::fs;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/// Decode a hex string to `Vec<u8>`. Lowercase or uppercase; rejects
/// odd-length or non-hex characters with a descriptive error.
pub fn hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex string ({} chars)", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        out.push((nib(chunk[0])? << 4) | nib(chunk[1])?);
    }
    Ok(out)
}

fn nib(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(format!("non-hex character: {:#04x}", other)),
    }
}

/// Serde adapter for hex-encoded byte strings. Use as
/// `#[serde(deserialize_with = "de_hex")]` on `Vec<u8>` fields.
pub fn de_hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = Deserialize::deserialize(d)?;
    hex(&s).map_err(serde::de::Error::custom)
}

/// Serde adapter for hex-encoded byte strings of fixed length `N`.
pub fn de_hex_array<'de, const N: usize, D: Deserializer<'de>>(d: D) -> Result<[u8; N], D::Error> {
    let v = de_hex(d)?;
    v.try_into().map_err(|v: Vec<u8>| {
        serde::de::Error::custom(format!("expected {} bytes, got {}", N, v.len()))
    })
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

/// Path to a file under `core/tests/data/`. Resolved relative to
/// `CARGO_MANIFEST_DIR` so the tests are reproducible regardless of which
/// directory `cargo test` is invoked from.
pub fn data_path(filename: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push(filename);
    p
}

/// Load and deserialize a JSON KAT file from `tests/data/`. Panics with
/// an explicit message if the file is missing or malformed — KAT loading
/// is part of the test contract, not something a test can recover from.
pub fn load_kat<T: DeserializeOwned>(filename: &str) -> T {
    let path = data_path(filename);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read KAT file {}: {}", path.display(), e));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse KAT file {}: {}", path.display(), e))
}

// ---------------------------------------------------------------------------
// Typed KAT structs — one per `tests/data/*.json` file.
//
// Field layout matches the JSON 1:1; hex fields go through `de_hex` so test
// code receives `Vec<u8>` ready to feed into the crypto APIs.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Argon2idKat {
    pub vectors: Vec<Argon2idVector>,
}

#[derive(Debug, Deserialize)]
pub struct Argon2idVector {
    pub name: String,
    #[serde(deserialize_with = "de_hex")]
    pub password: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub salt: Vec<u8>,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub out_len: usize,
    #[serde(deserialize_with = "de_hex")]
    pub expected: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct XChaCha20Poly1305Kat {
    pub vectors: Vec<XChaCha20Poly1305Vector>,
}

#[derive(Debug, Deserialize)]
pub struct XChaCha20Poly1305Vector {
    pub name: String,
    #[serde(deserialize_with = "de_hex")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub nonce: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub aad: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub plaintext: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub ciphertext: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub tag: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct X25519Kat {
    pub vectors: Vec<X25519Vector>,
}

#[derive(Debug, Deserialize)]
pub struct X25519Vector {
    pub name: String,
    #[serde(deserialize_with = "de_hex")]
    pub k: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub u: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub expected: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct Ed25519Kat {
    pub vectors: Vec<Ed25519Vector>,
}

#[derive(Debug, Deserialize)]
pub struct Ed25519Vector {
    pub name: String,
    #[serde(deserialize_with = "de_hex")]
    pub sk: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub pk: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub sig: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct HkdfSha256Kat {
    pub vectors: Vec<HkdfSha256Vector>,
}

#[derive(Debug, Deserialize)]
pub struct HkdfSha256Vector {
    pub name: String,
    #[serde(deserialize_with = "de_hex")]
    pub ikm: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub salt: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub info: Vec<u8>,
    pub okm_len: usize,
    #[serde(deserialize_with = "de_hex")]
    pub okm: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct CardFingerprintKat {
    pub card_fingerprint: CardFingerprintCardEntry,
    pub presentations: Vec<CardFingerprintPresentation>,
}

#[derive(Debug, Deserialize)]
pub struct CardFingerprintCardEntry {
    pub name: String,
    pub card_cbor_file: String,
    #[serde(deserialize_with = "de_hex")]
    pub expected: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct CardFingerprintPresentation {
    pub name: String,
    #[serde(deserialize_with = "de_hex")]
    pub fp: Vec<u8>,
    #[serde(default)]
    pub hex_form: Option<String>,
    #[serde(default)]
    pub mnemonic_form: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HybridKemKat {
    #[serde(deserialize_with = "de_hex")]
    pub sender_seed: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub recipient_seed: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub encap_seed: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub sender_fp: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub recipient_fp: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub sender_bundle: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub recipient_bundle: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub block_uuid: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub bck: Vec<u8>,
    pub expected_wire: HybridKemWire,
}

#[derive(Debug, Deserialize)]
pub struct HybridKemWire {
    #[serde(deserialize_with = "de_hex")]
    pub ct_x: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub ct_pq: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub nonce_w: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub ct_w: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct HybridSigKat {
    #[serde(deserialize_with = "de_hex")]
    pub identity_seed: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub ed_pk: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub ml_dsa_65_pk: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub msg: Vec<u8>,
    pub vectors: Vec<HybridSigVector>,
}

#[derive(Debug, Deserialize)]
pub struct HybridSigVector {
    pub role: String,
    #[serde(deserialize_with = "de_hex")]
    pub sig_ed: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub sig_pq: Vec<u8>,
}

// ---------------------------------------------------------------------------
// NIST ACVP vectors (FIPS 203 / FIPS 204)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MlKem768Kat {
    pub keygen_vectors: Vec<MlKem768KeygenVector>,
    pub encap_vectors: Vec<MlKem768EncapVector>,
}

#[derive(Debug, Deserialize)]
pub struct MlKem768KeygenVector {
    #[serde(rename = "tcId")]
    pub tc_id: u32,
    #[serde(deserialize_with = "de_hex")]
    pub d: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub z: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub ek: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub dk: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct MlKem768EncapVector {
    #[serde(rename = "tcId")]
    pub tc_id: u32,
    #[serde(deserialize_with = "de_hex")]
    pub ek: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub m: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub c: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub k: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct MlDsa65Kat {
    pub keygen_vectors: Vec<MlDsa65KeygenVector>,
    pub sigver_vectors: Vec<MlDsa65SigverVector>,
}

#[derive(Debug, Deserialize)]
pub struct MlDsa65KeygenVector {
    #[serde(rename = "tcId")]
    pub tc_id: u32,
    #[serde(deserialize_with = "de_hex")]
    pub seed: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub pk: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct MlDsa65SigverVector {
    #[serde(rename = "tcId")]
    pub tc_id: u32,
    #[serde(deserialize_with = "de_hex")]
    pub pk: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub ctx: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub sig: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct Bip39RecoveryKat {
    pub vectors: Vec<Bip39RecoveryVector>,
}

#[derive(Debug, Deserialize)]
pub struct Bip39RecoveryVector {
    pub name: String,
    pub mnemonic: String,
    #[serde(deserialize_with = "de_hex_array::<32, _>")]
    pub entropy: [u8; 32],
    #[serde(deserialize_with = "de_hex")]
    pub info_tag: Vec<u8>,
    #[serde(deserialize_with = "de_hex_array::<32, _>")]
    pub expected_recovery_kek: [u8; 32],
}

// ---------------------------------------------------------------------------
// Block KAT — vault-format §6.1 / crypto-design §15
// ---------------------------------------------------------------------------
//
// Pins the on-disk byte sequence of a complete `BlockFile` (header,
// recipient table, AEAD body, hybrid-signature suffix) for a fully
// specified set of inputs (RNG seed, identity bundle, plaintext records).
// Each vector is a self-contained closed-loop fixture: a clean-room
// reader can use only `docs/vault-format.md` and `docs/crypto-design.md`
// to parse `expected.block_file_hex`, locate the recipient entry by
// fingerprint, hybrid-decap, AEAD-decrypt, and recover the plaintext.

#[derive(Debug, Deserialize)]
pub struct BlockKat {
    pub version: u32,
    #[serde(default)]
    pub comment: String,
    pub vectors: Vec<BlockKatVector>,
}

#[derive(Debug, Deserialize)]
pub struct BlockKatVector {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub inputs: BlockKatInputs,
    pub expected: BlockKatExpected,
}

#[derive(Debug, Deserialize)]
pub struct BlockKatInputs {
    /// 32-byte ChaCha20 seed driving identity-bundle generation.
    #[serde(deserialize_with = "de_hex_array::<32, _>")]
    pub identity_seed: [u8; 32],
    /// 32-byte ChaCha20 seed driving block-encryption RNG (BCK, encap
    /// ephemerals, AEAD nonce).
    #[serde(deserialize_with = "de_hex_array::<32, _>")]
    pub encrypt_seed: [u8; 32],
    /// 16-byte vault UUID stamped in the header.
    #[serde(deserialize_with = "de_hex_array::<16, _>")]
    pub vault_uuid: [u8; 16],
    /// 16-byte block UUID stamped in both the header and the plaintext.
    #[serde(deserialize_with = "de_hex_array::<16, _>")]
    pub block_uuid: [u8; 16],
    /// 16-byte recipient fingerprint (here, the self-recipient = author).
    /// Pinned because Task 6 fingerprints are opaque test handles —
    /// real fingerprints from the §6 contact card land with PR-B.
    #[serde(deserialize_with = "de_hex_array::<16, _>")]
    pub author_fingerprint: [u8; 16],
    /// Header `created_at_ms`.
    pub created_at_ms: u64,
    /// Header `last_mod_ms`.
    pub last_mod_ms: u64,
    /// Display-name fed into `bundle::generate`. The bundle's
    /// `display_name` is part of the IdentityBundle envelope (§5) but
    /// NOT serialized into the block bytes; pinned here so the
    /// generator is fully deterministic.
    pub display_name: String,
    /// Vector-clock entries (in input order; encoder sorts ascending by
    /// device_uuid before emission).
    pub vector_clock: Vec<BlockKatVectorClockEntry>,
    /// Plaintext metadata: the §6.3 `block_name`.
    pub block_name: String,
    /// Plaintext metadata: the §6.3 `block_version`.
    pub block_version: u32,
    /// Plaintext metadata: the §6.3 `schema_version`.
    pub schema_version: u32,
    /// Plaintext records (§6.3).
    pub records: Vec<BlockKatRecord>,
}

#[derive(Debug, Deserialize)]
pub struct BlockKatVectorClockEntry {
    #[serde(deserialize_with = "de_hex_array::<16, _>")]
    pub device_uuid: [u8; 16],
    pub counter: u64,
}

#[derive(Debug, Deserialize)]
pub struct BlockKatRecord {
    #[serde(deserialize_with = "de_hex_array::<16, _>")]
    pub record_uuid: [u8; 16],
    pub record_type: String,
    pub fields: Vec<BlockKatField>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
    #[serde(default)]
    pub tombstone: bool,
}

#[derive(Debug, Deserialize)]
pub struct BlockKatField {
    pub name: String,
    /// One of `"text"` or `"bytes"`. The companion field
    /// (`value_text` or `value_hex`) carries the payload.
    pub value_type: String,
    #[serde(default)]
    pub value_text: Option<String>,
    /// Hex-encoded bytes; used when `value_type == "bytes"`.
    #[serde(default)]
    pub value_hex: Option<String>,
    pub last_mod: u64,
    #[serde(deserialize_with = "de_hex_array::<16, _>")]
    pub device_uuid: [u8; 16],
}

#[derive(Debug, Deserialize)]
pub struct BlockKatExpected {
    /// Full encoded `BlockFile` bytes per §6.1 (header → signature
    /// suffix), hex-encoded.
    #[serde(deserialize_with = "de_hex")]
    pub block_file: Vec<u8>,
    /// Sentinel: total file size in bytes. Lets a clean-room reader
    /// sanity-check up-front (matches `block_file.len()`).
    pub size_bytes: usize,
    /// Number of recipients in the recipient table.
    pub recipients_count: usize,
    /// Number of records in the decrypted plaintext.
    pub records_count: usize,
    /// `record_type` of records[0], to pin the expected post-decrypt
    /// shape against an independent assertion.
    pub first_record_type: String,
}
