//! Shared fixtures for the manifest layer's unit tests (#564).
//!
//! Every fixture used by more than one of the seven `tests.rs` files lives
//! here exactly once — duplicating one into two test modules is what this
//! module exists to prevent. Items are `pub(super)`, i.e. `pub(in
//! crate::vault::manifest)`, so the whole manifest subtree can reach them
//! and nothing outside it can.
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs`; the only edit
//! at that point was the `pub(super)` prefix each fixture needed once its
//! callers moved into sibling modules.
//!
//! **Three additions since** (recorded so "moved verbatim" is not read as
//! still describing the whole file). Two are from #569 path 2:
//! [`dummy_kdf_params_value`], which replaced six inline
//! `kdf_params_to_value(&dummy_kdf_params())` call sites when that encode
//! helper stopped producing an owned `Value`; and this module's own
//! `#[cfg(test)] mod tests`, which pins that fixture's key order to the
//! bytes the deleted helper emitted. A fixture module with a test of its
//! own is unusual — the justification is in that test's doc comment. The
//! third is [`UNKNOWN_MAP_NONCANONICAL`], which #572 moved here from
//! `encode/tests.rs` on acquiring a second consumer in `decode/tests.rs`.

use std::collections::BTreeMap;

use ciborium::Value;

use crate::crypto::aead::{AeadKey, AeadNonce};
use crate::crypto::secret::Sensitive;
use crate::vault::canonical::encode_canonical_map;

use super::*;

pub(super) fn dummy_kdf_params() -> KdfParamsRef {
    KdfParamsRef {
        memory_kib: 262_144,
        iterations: 3,
        parallelism: 1,
        salt: [0x11; SALT_LEN],
    }
}

/// The `kdf_params` sub-map as an OWNED [`Value`], for the hand-built
/// non-canonical entry lists the decode negatives need.
///
/// Deliberately NOT `encode::kdf_params_to_canonical`. That helper returns
/// a borrowing `CanonicalMap`, and #569 path 2 is precisely the change that
/// stopped the encode path materialising an owned `Value` tree at all — so
/// there is no longer a production function whose output these tests could
/// reuse. Their whole purpose is to construct owned, deliberately
/// NON-canonical `Vec<(Value, Value)>` trees (a wrong-typed field, an
/// integer map key, a spliced float) and assert what `decode_manifest`
/// does with them; routing that through the borrowing encoder would defeat
/// the tests rather than serve them.
///
/// One shared copy, not six: this exact expression stood inline at six
/// call sites (this file plus `decode::tests` and four in
/// `decode::extract::tests`) as `kdf_params_to_value(&dummy_kdf_params())`.
pub(super) fn dummy_kdf_params_value() -> Value {
    let k = dummy_kdf_params();
    // Emitted in RFC 8949 §4.2.1 key order — sorted by (byte length,
    // bytes): "salt"(4), "iterations"(10), "memory_kib"(10),
    // "parallelism"(11). Written out rather than sorted, because the
    // deleted `kdf_params_to_value` reached the same order through a
    // `canonical_sort_entries` call, and these fixtures must feed the
    // decoder byte-identical input to what they fed it before #569 path 2.
    // A nested `Value::Map` is emitted by `ciborium` in ITERATION order —
    // `encode_canonical_map` sorts only the top level — so push order here
    // is on the wire, unlike in the borrowing encoder where `CanonicalMap`
    // sorts recursively at serialise time. `dummy_kdf_params_value_is_in_
    // canonical_key_order` below pins it.
    Value::Map(vec![
        (Value::Text(KEY_SALT.into()), Value::Bytes(k.salt.to_vec())),
        (
            Value::Text(KEY_ITERATIONS.into()),
            Value::Integer(u64::from(k.iterations).into()),
        ),
        (
            Value::Text(KEY_MEMORY_KIB.into()),
            Value::Integer(u64::from(k.memory_kib).into()),
        ),
        (
            Value::Text(KEY_PARALLELISM.into()),
            Value::Integer(u64::from(k.parallelism).into()),
        ),
    ])
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

/// A forward-compat unknown subtree that can DETECT a re-ordering: a
/// 2-key CBOR map whose keys are in NON-canonical order.
///
/// ```text
/// A2                 map(2)
///   62 7A 7A  01     "zz" => 1     <- 2-byte key FIRST
///   61 61     02     "a"  => 2     <- 1-byte key SECOND
/// ```
///
/// RFC 8949 §4.2.1 orders text keys by `(byte length, bytes)`, so the
/// canonical order is `"a"` then `"zz"` and these bytes are deliberately
/// the other way round. That asymmetry is the whole point: until #569
/// path 2 the only forward-compat fixture in the encode tests was the
/// 3-byte array `[1, 2]` (`0x82 0x01 0x02`), which has no key order to
/// preserve and therefore could not tell "emitted verbatim" apart from
/// "re-sorted on the way out".
///
/// `UnknownValue::from_canonical_cbor` accepts this despite its name: it
/// validates only the no-float / no-tag rules, never key order (see its
/// own doc comment, which says so outright).
///
/// **Moved here from `encode/tests.rs` by #572**, which needed the same
/// asymmetry on the DECODE side: `decode_manifest`'s new
/// re-encode-and-compare must not reject a forward-compat subtree whose
/// key order this version would not itself have chosen. Two test modules,
/// one fixture — the reason this module exists.
pub(super) const UNKNOWN_MAP_NONCANONICAL: &[u8] =
    &[0xA2, 0x62, b'z', b'z', 0x01, 0x61, b'a', 0x02];

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
    entries.push((Value::Text(KEY_KDF_PARAMS.into()), dummy_kdf_params_value()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::canonical::canonical_sort_entries;

    /// [`dummy_kdf_params_value`] must emit its keys in RFC 8949 §4.2.1
    /// order, hand-written rather than sorted.
    ///
    /// This is a fixture, not production code, and it would be easy to
    /// treat the order as cosmetic — it is not. Six decode-negative tests
    /// splice this sub-map into a hand-built top-level entry list and hand
    /// the result to `decode_manifest`; a nested `Value::Map` reaches the
    /// wire in ITERATION order (`encode_canonical_map` sorts only the top
    /// level), so the push order below IS the input those negatives feed
    /// the decoder. Until #569 path 2 they got it from `encode`'s
    /// `kdf_params_to_value`, which sorted via `canonical_sort_entries`.
    /// The oracle here is that same function, so the fixture is pinned to
    /// the bytes it produced rather than to a re-derivation of the rule.
    #[test]
    fn dummy_kdf_params_value_is_in_canonical_key_order() {
        let k = dummy_kdf_params();
        // The pre-#569 `kdf_params_to_value` body, verbatim apart from the
        // sort call being spelled out here.
        let unsorted: Vec<(Value, Value)> = vec![
            (
                Value::Text(KEY_MEMORY_KIB.into()),
                Value::Integer(u64::from(k.memory_kib).into()),
            ),
            (
                Value::Text(KEY_ITERATIONS.into()),
                Value::Integer(u64::from(k.iterations).into()),
            ),
            (
                Value::Text(KEY_PARALLELISM.into()),
                Value::Integer(u64::from(k.parallelism).into()),
            ),
            (Value::Text(KEY_SALT.into()), Value::Bytes(k.salt.to_vec())),
        ];
        let expected = Value::Map(canonical_sort_entries(&unsorted).expect("sort"));

        assert_eq!(
            dummy_kdf_params_value(),
            expected,
            "fixture must match what the deleted kdf_params_to_value emitted"
        );

        // And byte-identically, which is the property the six negatives
        // actually depend on.
        let mut mine = Vec::new();
        ciborium::ser::into_writer(&dummy_kdf_params_value(), &mut mine).expect("encode mine");
        let mut theirs = Vec::new();
        ciborium::ser::into_writer(&expected, &mut theirs).expect("encode expected");
        assert_eq!(mine, theirs, "fixture bytes must be unchanged by #569");
    }
}
