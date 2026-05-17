//! `SyncState` — per-vault sync orchestration state, caller-persisted.
//!
//! Holds the `vault_uuid` (binding the state to one specific vault) and
//! `highest_vector_clock_seen` (per `docs/crypto-design.md` §10).
//!
//! Invariant on `highest_vector_clock_seen`: entries sorted ascending by
//! `device_uuid` and no duplicate `device_uuid`. The constructor
//! `SyncState::new` and the CBOR decoder enforce this in both
//! directions (per the design spec — both paths validate so a
//! programmer-error path produces a typed error rather than corrupting
//! merge dispatch).

use crate::sync::error::SyncError;
use crate::vault::block::VectorClockEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub vault_uuid: [u8; 16],
    pub highest_vector_clock_seen: Vec<VectorClockEntry>,
}

impl SyncState {
    /// Fresh state for a vault we've never synced on this device.
    /// First `sync_once` call will produce `AppliedAutomatically` for
    /// any non-empty disk clock (the empty vector clock is the lattice
    /// bottom).
    pub fn empty(vault_uuid: [u8; 16]) -> Self {
        Self {
            vault_uuid,
            highest_vector_clock_seen: Vec::new(),
        }
    }

    /// Construct with explicit clock entries; validates the sorted +
    /// deduped invariant.
    pub fn new(
        vault_uuid: [u8; 16],
        highest_vector_clock_seen: Vec<VectorClockEntry>,
    ) -> Result<Self, SyncError> {
        validate_clock_canonical(&highest_vector_clock_seen)?;
        Ok(Self {
            vault_uuid,
            highest_vector_clock_seen,
        })
    }
}

/// Shared validator used by `SyncState::new` and the CBOR decoder.
/// Returns `InvalidArgument` if entries are unsorted or duplicated.
pub(crate) fn validate_clock_canonical(
    entries: &[VectorClockEntry],
) -> Result<(), SyncError> {
    for pair in entries.windows(2) {
        match pair[0].device_uuid.cmp(&pair[1].device_uuid) {
            std::cmp::Ordering::Less => continue,
            std::cmp::Ordering::Equal => {
                return Err(SyncError::InvalidArgument {
                    detail: "duplicate device_uuid in highest_vector_clock_seen".into(),
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(SyncError::InvalidArgument {
                    detail:
                        "highest_vector_clock_seen entries not sorted ascending by device_uuid"
                            .into(),
                });
            }
        }
    }
    Ok(())
}

// --- CBOR codec ---

const SYNC_STATE_KEY_VAULT_UUID: &str = "vault_uuid";
const SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN: &str = "highest_vector_clock_seen";
const VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID: &str = "device_uuid";
const VECTOR_CLOCK_ENTRY_KEY_COUNTER: &str = "counter";

const VAULT_UUID_LEN: usize = 16;
const DEVICE_UUID_LEN: usize = 16;

impl SyncState {
    /// Canonical-CBOR encoding suitable for OS-keystore persistence.
    /// Map keys sorted via `core::vault::canonical::encode_canonical_map`
    /// (the same helper the rest of the codebase uses), bytes for
    /// `vault_uuid` and entry `device_uuid`, integer for entry `counter`.
    /// Forward-compat: a future C.1.x adding new keys uses the same
    /// `unknown` opaque round-trip pattern as `Record`/`Manifest`.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SyncError> {
        use ciborium::value::Value;

        use crate::vault::canonical::{canonical_sort_entries, encode_canonical_map};

        let entries_value: Result<Vec<Value>, SyncError> = self
            .highest_vector_clock_seen
            .iter()
            .map(|e| {
                let inner = vec![
                    (
                        Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                        Value::Bytes(e.device_uuid.to_vec()),
                    ),
                    (
                        Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                        Value::Integer(e.counter.into()),
                    ),
                ];
                let sorted = canonical_sort_entries(&inner).map_err(|err| {
                    SyncError::StateEncodeFailed {
                        detail: format!("{err}"),
                    }
                })?;
                Ok(Value::Map(sorted))
            })
            .collect();

        let outer = vec![
            (
                Value::Text(SYNC_STATE_KEY_VAULT_UUID.into()),
                Value::Bytes(self.vault_uuid.to_vec()),
            ),
            (
                Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
                Value::Array(entries_value?),
            ),
        ];

        encode_canonical_map(&outer).map_err(|err| SyncError::StateEncodeFailed {
            detail: format!("{err}"),
        })
    }

    /// Decode canonical CBOR. Validates the sorted/deduped invariant
    /// on `highest_vector_clock_seen` symmetrically with `SyncState::new`.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SyncError> {
        use ciborium::value::Value;

        let value: Value = ciborium::de::from_reader(bytes).map_err(|e| {
            SyncError::StateDecodeFailed {
                detail: format!("CBOR parse: {e}"),
            }
        })?;
        let map = match value {
            Value::Map(m) => m,
            _ => {
                return Err(SyncError::StateDecodeFailed {
                    detail: "root value is not a CBOR map".into(),
                })
            }
        };

        let mut vault_uuid: Option<[u8; VAULT_UUID_LEN]> = None;
        let mut entries: Option<Vec<VectorClockEntry>> = None;

        for (k, v) in map {
            let key = match k {
                Value::Text(t) => t,
                _ => continue, // forward-compat: ignore non-text keys
            };
            match key.as_str() {
                SYNC_STATE_KEY_VAULT_UUID => {
                    let b = match v {
                        Value::Bytes(b) => b,
                        _ => {
                            return Err(SyncError::StateDecodeFailed {
                                detail: "vault_uuid is not a CBOR byte string".into(),
                            })
                        }
                    };
                    if b.len() != VAULT_UUID_LEN {
                        return Err(SyncError::StateDecodeFailed {
                            detail: format!(
                                "vault_uuid must be {VAULT_UUID_LEN} bytes, got {}",
                                b.len()
                            ),
                        });
                    }
                    let mut arr = [0u8; VAULT_UUID_LEN];
                    arr.copy_from_slice(&b);
                    vault_uuid = Some(arr);
                }
                SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN => {
                    let arr = match v {
                        Value::Array(a) => a,
                        _ => {
                            return Err(SyncError::StateDecodeFailed {
                                detail: "highest_vector_clock_seen is not a CBOR array".into(),
                            })
                        }
                    };
                    let mut out = Vec::with_capacity(arr.len());
                    for entry_val in arr {
                        out.push(decode_vector_clock_entry(entry_val)?);
                    }
                    entries = Some(out);
                }
                _ => continue, // forward-compat: ignore unknown keys
            }
        }

        let vault_uuid = vault_uuid.ok_or_else(|| SyncError::StateDecodeFailed {
            detail: "missing vault_uuid key".into(),
        })?;
        let entries = entries.unwrap_or_default();
        validate_clock_canonical(&entries)?;
        Ok(Self {
            vault_uuid,
            highest_vector_clock_seen: entries,
        })
    }
}

fn decode_vector_clock_entry(
    value: ciborium::value::Value,
) -> Result<VectorClockEntry, SyncError> {
    use ciborium::value::Value;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(SyncError::StateDecodeFailed {
                detail: "vector clock entry is not a CBOR map".into(),
            })
        }
    };

    let mut device_uuid: Option<[u8; DEVICE_UUID_LEN]> = None;
    let mut counter: Option<u64> = None;

    for (k, v) in map {
        let key = match k {
            Value::Text(t) => t,
            _ => continue,
        };
        match key.as_str() {
            VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID => {
                let b = match v {
                    Value::Bytes(b) => b,
                    _ => {
                        return Err(SyncError::StateDecodeFailed {
                            detail: "device_uuid is not a CBOR byte string".into(),
                        })
                    }
                };
                if b.len() != DEVICE_UUID_LEN {
                    return Err(SyncError::StateDecodeFailed {
                        detail: format!(
                            "device_uuid must be {DEVICE_UUID_LEN} bytes, got {}",
                            b.len()
                        ),
                    });
                }
                let mut arr = [0u8; DEVICE_UUID_LEN];
                arr.copy_from_slice(&b);
                device_uuid = Some(arr);
            }
            VECTOR_CLOCK_ENTRY_KEY_COUNTER => {
                let n: u64 = match v {
                    Value::Integer(i) => i.try_into().map_err(|_| SyncError::StateDecodeFailed {
                        detail: "counter does not fit in u64".into(),
                    })?,
                    _ => {
                        return Err(SyncError::StateDecodeFailed {
                            detail: "counter is not a CBOR integer".into(),
                        })
                    }
                };
                counter = Some(n);
            }
            _ => continue,
        }
    }

    Ok(VectorClockEntry {
        device_uuid: device_uuid.ok_or_else(|| SyncError::StateDecodeFailed {
            detail: "vector clock entry missing device_uuid".into(),
        })?,
        counter: counter.ok_or_else(|| SyncError::StateDecodeFailed {
            detail: "vector clock entry missing counter".into(),
        })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(b: u8, counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [b; 16],
            counter,
        }
    }

    #[test]
    fn empty_constructor_produces_empty_clock() {
        let s = SyncState::empty([0u8; 16]);
        assert_eq!(s.vault_uuid, [0u8; 16]);
        assert!(s.highest_vector_clock_seen.is_empty());
    }

    #[test]
    fn new_accepts_sorted_unique_entries() {
        let s = SyncState::new([7u8; 16], vec![entry(1, 5), entry(2, 3), entry(3, 9)])
            .expect("sorted unique entries must be accepted");
        assert_eq!(s.highest_vector_clock_seen.len(), 3);
    }

    #[test]
    fn new_accepts_empty_clock() {
        let s = SyncState::new([7u8; 16], vec![]).expect("empty clock must be accepted");
        assert!(s.highest_vector_clock_seen.is_empty());
    }

    #[test]
    fn new_rejects_unsorted_entries() {
        let err = SyncState::new([0u8; 16], vec![entry(2, 1), entry(1, 1)]).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("not sorted ascending"));
    }

    #[test]
    fn new_rejects_duplicate_device_uuid() {
        let err = SyncState::new([0u8; 16], vec![entry(1, 1), entry(1, 2)]).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("duplicate device_uuid"));
    }
}

#[cfg(test)]
mod cbor_tests {
    use super::*;

    fn entry(b: u8, counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [b; 16],
            counter,
        }
    }

    #[test]
    fn empty_state_round_trip() {
        let original = SyncState::empty([0xABu8; 16]);
        let bytes = original.to_canonical_cbor().unwrap();
        let decoded = SyncState::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn three_entry_state_round_trip() {
        let original = SyncState::new(
            [0x42u8; 16],
            vec![entry(1, 5), entry(2, 17), entry(0xAA, 1)],
        )
        .unwrap();
        let bytes = original.to_canonical_cbor().unwrap();
        let decoded = SyncState::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn malformed_cbor_rejects_with_typed_error() {
        let bytes = b"not actually cbor at all";
        let err = SyncState::from_canonical_cbor(bytes).unwrap_err();
        assert!(matches!(err, SyncError::StateDecodeFailed { .. }));
    }

    #[test]
    fn decoder_rejects_unsorted_clock_entries() {
        // Hand-craft a CBOR payload with entries in DESCENDING order.
        // The encoder always emits canonical sorted order, so we have
        // to bypass it. Construct via ciborium directly.
        use ciborium::value::Value;
        let bad_entries = vec![
            Value::Map(vec![
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                    Value::Bytes(vec![0x02u8; 16]),
                ),
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                    Value::Integer(1i64.into()),
                ),
            ]),
            Value::Map(vec![
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                    Value::Bytes(vec![0x01u8; 16]),
                ),
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                    Value::Integer(1i64.into()),
                ),
            ]),
        ];
        let root = Value::Map(vec![
            (
                Value::Text(SYNC_STATE_KEY_VAULT_UUID.into()),
                Value::Bytes(vec![0u8; 16]),
            ),
            (
                Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
                Value::Array(bad_entries),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&root, &mut bytes).unwrap();

        let err = SyncState::from_canonical_cbor(&bytes).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("not sorted ascending"));
    }

    #[test]
    fn decoder_rejects_duplicate_device_uuid() {
        use ciborium::value::Value;
        let dup_entries = vec![
            Value::Map(vec![
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                    Value::Bytes(vec![0xCC; 16]),
                ),
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                    Value::Integer(1i64.into()),
                ),
            ]),
            Value::Map(vec![
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                    Value::Bytes(vec![0xCC; 16]),
                ),
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                    Value::Integer(2i64.into()),
                ),
            ]),
        ];
        let root = Value::Map(vec![
            (
                Value::Text(SYNC_STATE_KEY_VAULT_UUID.into()),
                Value::Bytes(vec![0u8; 16]),
            ),
            (
                Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
                Value::Array(dup_entries),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&root, &mut bytes).unwrap();

        let err = SyncState::from_canonical_cbor(&bytes).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("duplicate device_uuid"));
    }

    #[test]
    fn decoder_rejects_missing_vault_uuid() {
        use ciborium::value::Value;
        let root = Value::Map(vec![(
            Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
            Value::Array(vec![]),
        )]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&root, &mut bytes).unwrap();

        let err = SyncState::from_canonical_cbor(&bytes).unwrap_err();
        assert!(matches!(err, SyncError::StateDecodeFailed { .. }));
        assert!(format!("{err}").contains("missing vault_uuid"));
    }

    #[test]
    fn decoder_ignores_unknown_keys_for_forward_compat() {
        use ciborium::value::Value;
        let root = Value::Map(vec![
            (
                Value::Text(SYNC_STATE_KEY_VAULT_UUID.into()),
                Value::Bytes(vec![0x11u8; 16]),
            ),
            (
                Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
                Value::Array(vec![]),
            ),
            (
                Value::Text("future_c1_1_field".into()),
                Value::Integer(42i64.into()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&root, &mut bytes).unwrap();

        let decoded = SyncState::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded.vault_uuid, [0x11u8; 16]);
        assert!(decoded.highest_vector_clock_seen.is_empty());
    }
}
