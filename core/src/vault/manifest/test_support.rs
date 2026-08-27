//! Shared fixtures for the manifest layer's unit tests (#564).
//!
//! Every fixture used by more than one of the seven `tests.rs` files lives
//! here exactly once — duplicating one into two test modules is what this
//! module exists to prevent. Items are `pub(super)`, i.e. `pub(in
//! crate::vault::manifest)`, so the whole manifest subtree can reach them
//! and nothing outside it can.
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs`; the only edit
//! is the `pub(super)` prefix each fixture needed once its callers moved
//! into sibling modules.

use std::collections::BTreeMap;

use ciborium::Value;

use crate::crypto::aead::{AeadKey, AeadNonce};
use crate::crypto::secret::Sensitive;
use crate::vault::canonical::encode_canonical_map;

use super::encode::kdf_params_to_value;
use super::*;

pub(super) fn dummy_kdf_params() -> KdfParamsRef {
    KdfParamsRef {
        memory_kib: 262_144,
        iterations: 3,
        parallelism: 1,
        salt: [0x11; SALT_LEN],
    }
}

pub(super) fn minimal_manifest() -> Manifest {
    Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x01; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x02; UUID_LEN],
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: dummy_kdf_params(),
        unknown: BTreeMap::new(),
    }
}

pub(super) fn populated_manifest() -> Manifest {
    let vc = vec![
        VectorClockEntry {
            device_uuid: [0xaa; UUID_LEN],
            counter: 7,
        },
        VectorClockEntry {
            device_uuid: [0x55; UUID_LEN],
            counter: 3,
        },
    ];
    let block_a = BlockEntry {
        block_uuid: [0xb1; UUID_LEN],
        block_name: "logins".to_string(),
        fingerprint: [0xff; BLOCK_FINGERPRINT_LEN],
        recipients: vec![[0xc1; UUID_LEN], [0xc2; UUID_LEN]],
        vector_clock_summary: vec![
            VectorClockEntry {
                device_uuid: [0xaa; UUID_LEN],
                counter: 4,
            },
            VectorClockEntry {
                device_uuid: [0x55; UUID_LEN],
                counter: 2,
            },
        ],
        suite_id: SUITE_ID_V1,
        created_at_ms: 1_714_060_800_000,
        last_mod_ms: 1_714_060_800_010,
        unknown: BTreeMap::new(),
    };
    let block_b = BlockEntry {
        block_uuid: [0xa2; UUID_LEN],
        block_name: "notes".to_string(),
        fingerprint: [0xee; BLOCK_FINGERPRINT_LEN],
        recipients: vec![[0xc1; UUID_LEN], [0xc3; UUID_LEN]],
        vector_clock_summary: vec![
            VectorClockEntry {
                device_uuid: [0x55; UUID_LEN],
                counter: 1,
            },
            VectorClockEntry {
                device_uuid: [0xaa; UUID_LEN],
                counter: 5,
            },
        ],
        suite_id: SUITE_ID_V1,
        created_at_ms: 1_714_060_800_001,
        last_mod_ms: 1_714_060_800_011,
        unknown: BTreeMap::new(),
    };
    let trash = vec![TrashEntry {
        block_uuid: [0xde; UUID_LEN],
        tombstoned_at_ms: 1_714_060_900_000,
        tombstoned_by: [0xaa; UUID_LEN],
        fingerprint: Some([0xcd; BLOCK_FINGERPRINT_LEN]),
        purged_at_ms: None,
        unknown: BTreeMap::new(),
    }];
    Manifest {
        manifest_version: MANIFEST_VERSION_V1,
        vault_uuid: [0x42; UUID_LEN],
        format_version: FORMAT_VERSION_V1,
        suite_id: SUITE_ID_V1,
        owner_user_uuid: [0x99; UUID_LEN],
        vector_clock: vc,
        blocks: vec![block_a, block_b],
        trash,
        kdf_params: KdfParamsRef {
            memory_kib: 524_288,
            iterations: 4,
            parallelism: 2,
            salt: [0x22; SALT_LEN],
        },
        unknown: BTreeMap::new(),
    }
}

/// Re-parse encoded bytes to a `ciborium::Value` map for raw
/// inspection of array order.
pub(super) fn parse_to_value_map(bytes: &[u8]) -> Vec<(Value, Value)> {
    match ciborium::de::from_reader(bytes).expect("ciborium parse") {
        Value::Map(m) => m,
        _ => panic!("manifest is not a map"),
    }
}

pub(super) fn find_array<'a>(map: &'a [(Value, Value)], key: &str) -> &'a [Value] {
    for (k, v) in map {
        if let Value::Text(s) = k {
            if s == key {
                return match v {
                    Value::Array(a) => a.as_slice(),
                    _ => panic!("{key} is not an array"),
                };
            }
        }
    }
    panic!("key {key} not present in manifest map");
}

pub(super) fn entry_bytes_field(entry: &Value, key: &str) -> Vec<u8> {
    match entry {
        Value::Map(m) => {
            for (k, v) in m {
                if let Value::Text(s) = k {
                    if s == key {
                        return match v {
                            Value::Bytes(b) => b.clone(),
                            _ => panic!("{key} is not bytes"),
                        };
                    }
                }
            }
            panic!("entry missing key {key}");
        }
        _ => panic!("entry is not a map"),
    }
}

/// Build a top-level manifest CBOR map by hand. Useful for negative
/// tests where we want to mutate one key away from canonical.
pub(super) fn build_manifest_map_with_overrides(
    manifest_version: Option<u8>,
    vault_uuid_present: bool,
) -> Vec<u8> {
    let mut entries: Vec<(Value, Value)> = Vec::new();
    if let Some(mv) = manifest_version {
        entries.push((
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(mv).into()),
        ));
    }
    if vault_uuid_present {
        entries.push((
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ));
    }
    entries.push((
        Value::Text(KEY_FORMAT_VERSION.into()),
        Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
    ));
    entries.push((
        Value::Text(KEY_SUITE_ID.into()),
        Value::Integer(u64::from(SUITE_ID_V1).into()),
    ));
    entries.push((
        Value::Text(KEY_OWNER_USER_UUID.into()),
        Value::Bytes([0x02; UUID_LEN].to_vec()),
    ));
    entries.push((
        Value::Text(KEY_VECTOR_CLOCK.into()),
        Value::Array(Vec::new()),
    ));
    entries.push((Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())));
    entries.push((Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())));
    entries.push((
        Value::Text(KEY_KDF_PARAMS.into()),
        kdf_params_to_value(&dummy_kdf_params()).expect("kdf_params"),
    ));
    encode_canonical_map(&entries).expect("encode_canonical_map")
}

// ---- Binary header / envelope fixtures (§4.1) ------------------------

/// Pinned 32-byte test IBK. The `Sensitive` wrapper zeroizes on drop,
/// so each test gets a fresh instance — we don't share one across
/// tests. Same fixture style as PR-A's block.rs tests.
pub(super) fn test_ibk(byte: u8) -> AeadKey {
    Sensitive::new([byte; 32])
}

pub(super) fn test_nonce() -> AeadNonce {
    // Deterministic 24-byte nonce for fixture stability. NOT
    // representative of production: real callers must source nonces
    // from `crypto::rand` (or pinned KAT inputs in tests).
    let mut n = [0u8; 24];
    for (i, b) in n.iter_mut().enumerate() {
        *b = i as u8;
    }
    n
}

pub(super) fn fixed_manifest_header() -> ManifestHeader {
    ManifestHeader {
        vault_uuid: [0x42; UUID_LEN],
        created_at_ms: 1_714_060_800_000,
        last_mod_ms: 1_714_060_900_000,
    }
}
