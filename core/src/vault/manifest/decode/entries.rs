//! Per-array / per-entry parsers for the manifest body
//! (`docs/vault-format.md` §4.2).

use std::collections::BTreeMap;

use ciborium::Value;

use crate::vault::record::UnknownValue;

use crate::vault::manifest::{
    BlockEntry, KdfParamsRef, ManifestError, TrashEntry, VectorClockEntry, BLOCK_FINGERPRINT_LEN,
    KEY_BLOCKS, KEY_BLOCK_NAME, KEY_BLOCK_UUID, KEY_COUNTER, KEY_CREATED_AT_MS, KEY_DEVICE_UUID,
    KEY_FINGERPRINT, KEY_ITERATIONS, KEY_KDF_PARAMS, KEY_LAST_MOD_MS, KEY_MEMORY_KIB,
    KEY_PARALLELISM, KEY_PURGED_AT_MS, KEY_RECIPIENTS, KEY_SALT, KEY_SUITE_ID,
    KEY_TOMBSTONED_AT_MS, KEY_TOMBSTONED_BY, KEY_TRASH, KEY_VECTOR_CLOCK, KEY_VECTOR_CLOCK_SUMMARY,
    SALT_LEN, UUID_LEN,
};

use super::extract::{
    take_fixed_bytes, take_text, take_text_key, take_u16, take_u32, take_u64, value_to_unknown,
};

pub(super) fn parse_vector_clock(
    v: &Value,
    field: &'static str,
) -> Result<Vec<VectorClockEntry>, ManifestError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(ManifestError::WrongType {
                field,
                expected: "array of vector_clock entries",
            })
        }
    };
    let mut out: Vec<VectorClockEntry> = Vec::with_capacity(items.len());
    for item in items {
        out.push(parse_vector_clock_entry(item)?);
    }
    // Reject duplicate device_uuids in either of the two vector_clock
    // arrays. Sort a copy of the device_uuids and check adjacent equality
    // — O(n log n) and avoids allocating a HashSet for what is typically
    // a handful of entries.
    let mut ids: Vec<[u8; UUID_LEN]> = out.iter().map(|e| e.device_uuid).collect();
    ids.sort();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(ManifestError::VectorClockDuplicateDevice);
    }
    Ok(out)
}

fn parse_vector_clock_entry(v: &Value) -> Result<VectorClockEntry, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_VECTOR_CLOCK,
                expected: "map (vector_clock entry)",
            })
        }
    };
    let mut device_uuid: Option<[u8; UUID_LEN]> = None;
    let mut counter: Option<u64> = None;
    // #573: reject a repeated key rather than last-wins, mirroring
    // `parse_manifest_map`'s top-level check (#568). Written out per arm
    // rather than factored into a helper/macro — see that function's own
    // comment for why: every hygiene guard in this repo reads TEXT, not
    // expanded macros, so an error construction inside a macro body is
    // invisible to any future rule that inspects one.
    for (index, (k, val)) in entries.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_DEVICE_UUID => {
                if device_uuid.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_DEVICE_UUID,
                        index,
                    });
                }
                device_uuid = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_DEVICE_UUID)?);
            }
            KEY_COUNTER => {
                if counter.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_COUNTER,
                        index,
                    });
                }
                counter = Some(take_u64(val, KEY_COUNTER)?);
            }
            // Vector clock entries don't carry an unknown bag in v1 —
            // they're a fixed two-field shape per §4.2. Unknown keys here
            // would be out of scope for the spec and must not be silently
            // absorbed, so we take the conservative path and REJECT, as
            // WrongType-equivalent (§6.3.2's forward-compat principle: no
            // extension surface here means strict). This comment carried a
            // contradictory "treat as a missing-field semantic by ignoring"
            // clause until the #584 review — the code has always rejected,
            // and a future editor reconciling the code to that clause would
            // have converted a rejection into a silent absorb.
            _ => {
                return Err(ManifestError::WrongType {
                    field: KEY_VECTOR_CLOCK,
                    expected: "map with only device_uuid and counter keys",
                })
            }
        }
    }
    Ok(VectorClockEntry {
        device_uuid: device_uuid.ok_or(ManifestError::MissingField {
            field: KEY_DEVICE_UUID,
        })?,
        counter: counter.ok_or(ManifestError::MissingField { field: KEY_COUNTER })?,
    })
}

pub(super) fn parse_blocks(v: &Value) -> Result<Vec<BlockEntry>, ManifestError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_BLOCKS,
                expected: "array of block entries",
            })
        }
    };
    let mut out: Vec<BlockEntry> = Vec::with_capacity(items.len());
    for item in items {
        out.push(parse_block_entry(item)?);
    }
    let mut ids: Vec<[u8; UUID_LEN]> = out.iter().map(|b| b.block_uuid).collect();
    ids.sort();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(ManifestError::DuplicateBlockUuid);
    }
    Ok(out)
}

fn parse_block_entry(v: &Value) -> Result<BlockEntry, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_BLOCKS,
                expected: "map (block entry)",
            })
        }
    };
    let mut block_uuid: Option<[u8; UUID_LEN]> = None;
    let mut block_name: Option<String> = None;
    let mut fingerprint: Option<[u8; BLOCK_FINGERPRINT_LEN]> = None;
    let mut recipients: Option<Vec<[u8; UUID_LEN]>> = None;
    let mut vector_clock_summary: Option<Vec<VectorClockEntry>> = None;
    let mut suite_id: Option<u16> = None;
    let mut created_at_ms: Option<u64> = None;
    let mut last_mod_ms: Option<u64> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();

    // #573: reject a repeated key rather than last-wins, mirroring
    // `parse_manifest_map`'s top-level check (#568). Written out per arm
    // rather than factored into a helper/macro — see that function's own
    // comment for why. The unknown-bag arm detects its duplicate via
    // `BTreeMap::insert`'s own "previous value" return, same as the top
    // level's unknown arm; `field` is the literal `"<unknown>"`, never the
    // repeated key itself (#474 — that text is attacker-influenced content
    // from inside the encrypted manifest).
    for (index, (k, val)) in entries.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_BLOCK_UUID => {
                if block_uuid.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_BLOCK_UUID,
                        index,
                    });
                }
                block_uuid = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_BLOCK_UUID)?);
            }
            KEY_BLOCK_NAME => {
                if block_name.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_BLOCK_NAME,
                        index,
                    });
                }
                // #547 Task 7b: `block_name` is user-visible plaintext
                // within the encrypted manifest (see the doc comment on
                // `BlockEntry::block_name`) — the exact content this task
                // exists to cover; the design spec's "manifest.rs carries
                // no decrypted user content" premise was false precisely
                // because of this field (see the corrected "Scope note").
                // `take_text` clones it out of the borrowed tree into a
                // PLAIN, non-zeroizing `String` — `BlockEntry::block_name`'s
                // own type, the same class of destination
                // `block::parse_plaintext_map` uses for the block-layer
                // `block_name` field. The SOURCE `Value::Text` inside the
                // tree stays covered by `decode_manifest`'s
                // `SecretValueTree` until it drops; this clone is not
                // additionally wiped — no regression, since a plain
                // `String` destination was never wiped before this task
                // either.
                block_name = Some(take_text(val, KEY_BLOCK_NAME)?);
            }
            KEY_FINGERPRINT => {
                if fingerprint.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_FINGERPRINT,
                        index,
                    });
                }
                fingerprint = Some(take_fixed_bytes::<BLOCK_FINGERPRINT_LEN>(
                    val,
                    KEY_FINGERPRINT,
                )?);
            }
            KEY_RECIPIENTS => {
                if recipients.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_RECIPIENTS,
                        index,
                    });
                }
                recipients = Some(parse_recipients(val)?);
            }
            KEY_VECTOR_CLOCK_SUMMARY => {
                if vector_clock_summary.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_VECTOR_CLOCK_SUMMARY,
                        index,
                    });
                }
                vector_clock_summary = Some(parse_vector_clock(val, KEY_VECTOR_CLOCK_SUMMARY)?);
            }
            KEY_SUITE_ID => {
                if suite_id.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_SUITE_ID,
                        index,
                    });
                }
                suite_id = Some(take_u16(val, KEY_SUITE_ID)?);
            }
            KEY_CREATED_AT_MS => {
                if created_at_ms.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_CREATED_AT_MS,
                        index,
                    });
                }
                created_at_ms = Some(take_u64(val, KEY_CREATED_AT_MS)?);
            }
            KEY_LAST_MOD_MS => {
                if last_mod_ms.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_LAST_MOD_MS,
                        index,
                    });
                }
                last_mod_ms = Some(take_u64(val, KEY_LAST_MOD_MS)?);
            }
            _ => {
                if unknown.insert(key, value_to_unknown(val)?).is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: "<unknown>",
                        index,
                    });
                }
            }
        }
    }

    Ok(BlockEntry {
        block_uuid: block_uuid.ok_or(ManifestError::MissingField {
            field: KEY_BLOCK_UUID,
        })?,
        block_name: block_name.ok_or(ManifestError::MissingField {
            field: KEY_BLOCK_NAME,
        })?,
        fingerprint: fingerprint.ok_or(ManifestError::MissingField {
            field: KEY_FINGERPRINT,
        })?,
        recipients: recipients.ok_or(ManifestError::MissingField {
            field: KEY_RECIPIENTS,
        })?,
        vector_clock_summary: vector_clock_summary.ok_or(ManifestError::MissingField {
            field: KEY_VECTOR_CLOCK_SUMMARY,
        })?,
        suite_id: suite_id.ok_or(ManifestError::MissingField {
            field: KEY_SUITE_ID,
        })?,
        created_at_ms: created_at_ms.ok_or(ManifestError::MissingField {
            field: KEY_CREATED_AT_MS,
        })?,
        last_mod_ms: last_mod_ms.ok_or(ManifestError::MissingField {
            field: KEY_LAST_MOD_MS,
        })?,
        unknown,
    })
}

fn parse_recipients(v: &Value) -> Result<Vec<[u8; UUID_LEN]>, ManifestError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_RECIPIENTS,
                expected: "array of contact_uuids",
            })
        }
    };
    items
        .iter()
        .map(|item| take_fixed_bytes::<UUID_LEN>(item, KEY_RECIPIENTS))
        .collect()
}

pub(super) fn parse_trash(v: &Value) -> Result<Vec<TrashEntry>, ManifestError> {
    let items = match v {
        Value::Array(a) => a,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_TRASH,
                expected: "array of trash entries",
            })
        }
    };
    let out: Vec<TrashEntry> = items
        .iter()
        .map(parse_trash_entry)
        .collect::<Result<_, _>>()?;
    let mut ids: Vec<[u8; UUID_LEN]> = out.iter().map(|t| t.block_uuid).collect();
    ids.sort();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(ManifestError::DuplicateTrashUuid);
    }
    Ok(out)
}

fn parse_trash_entry(v: &Value) -> Result<TrashEntry, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_TRASH,
                expected: "map (trash entry)",
            })
        }
    };
    let mut block_uuid: Option<[u8; UUID_LEN]> = None;
    let mut tombstoned_at_ms: Option<u64> = None;
    let mut tombstoned_by: Option<[u8; UUID_LEN]> = None;
    let mut fingerprint: Option<[u8; BLOCK_FINGERPRINT_LEN]> = None;
    let mut purged_at_ms: Option<u64> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();

    // #573: reject a repeated key rather than last-wins, mirroring
    // `parse_manifest_map`'s top-level check (#568). Written out per arm
    // rather than factored into a helper/macro — see that function's own
    // comment for why. The unknown-bag arm detects its duplicate via
    // `BTreeMap::insert`'s own "previous value" return, same as the top
    // level's unknown arm; `field` is the literal `"<unknown>"`, never the
    // repeated key itself (#474 — that text is attacker-influenced content
    // from inside the encrypted manifest).
    for (index, (k, val)) in entries.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_BLOCK_UUID => {
                if block_uuid.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_BLOCK_UUID,
                        index,
                    });
                }
                block_uuid = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_BLOCK_UUID)?);
            }
            KEY_TOMBSTONED_AT_MS => {
                if tombstoned_at_ms.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_TOMBSTONED_AT_MS,
                        index,
                    });
                }
                tombstoned_at_ms = Some(take_u64(val, KEY_TOMBSTONED_AT_MS)?);
            }
            KEY_TOMBSTONED_BY => {
                if tombstoned_by.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_TOMBSTONED_BY,
                        index,
                    });
                }
                tombstoned_by = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_TOMBSTONED_BY)?);
            }
            KEY_FINGERPRINT => {
                if fingerprint.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_FINGERPRINT,
                        index,
                    });
                }
                fingerprint = Some(take_fixed_bytes::<BLOCK_FINGERPRINT_LEN>(
                    val,
                    KEY_FINGERPRINT,
                )?);
            }
            KEY_PURGED_AT_MS => {
                if purged_at_ms.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_PURGED_AT_MS,
                        index,
                    });
                }
                purged_at_ms = Some(take_u64(val, KEY_PURGED_AT_MS)?);
            }
            _ => {
                if unknown.insert(key, value_to_unknown(val)?).is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: "<unknown>",
                        index,
                    });
                }
            }
        }
    }

    Ok(TrashEntry {
        block_uuid: block_uuid.ok_or(ManifestError::MissingField {
            field: KEY_BLOCK_UUID,
        })?,
        tombstoned_at_ms: tombstoned_at_ms.ok_or(ManifestError::MissingField {
            field: KEY_TOMBSTONED_AT_MS,
        })?,
        tombstoned_by: tombstoned_by.ok_or(ManifestError::MissingField {
            field: KEY_TOMBSTONED_BY,
        })?,
        fingerprint,
        purged_at_ms,
        unknown,
    })
}

pub(super) fn parse_kdf_params(v: &Value) -> Result<KdfParamsRef, ManifestError> {
    let entries = match v {
        Value::Map(m) => m,
        _ => {
            return Err(ManifestError::WrongType {
                field: KEY_KDF_PARAMS,
                expected: "map",
            })
        }
    };
    let mut memory_kib: Option<u32> = None;
    let mut iterations: Option<u32> = None;
    let mut parallelism: Option<u32> = None;
    let mut salt: Option<[u8; SALT_LEN]> = None;

    // #573: reject a repeated key rather than last-wins, mirroring
    // `parse_manifest_map`'s top-level check (#568). Written out per arm
    // rather than factored into a helper/macro — see that function's own
    // comment for why.
    for (index, (k, val)) in entries.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_MEMORY_KIB => {
                if memory_kib.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_MEMORY_KIB,
                        index,
                    });
                }
                memory_kib = Some(take_u32(val, KEY_MEMORY_KIB)?);
            }
            KEY_ITERATIONS => {
                if iterations.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_ITERATIONS,
                        index,
                    });
                }
                iterations = Some(take_u32(val, KEY_ITERATIONS)?);
            }
            KEY_PARALLELISM => {
                if parallelism.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_PARALLELISM,
                        index,
                    });
                }
                parallelism = Some(take_u32(val, KEY_PARALLELISM)?);
            }
            KEY_SALT => {
                if salt.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_SALT,
                        index,
                    });
                }
                salt = Some(take_fixed_bytes::<SALT_LEN>(val, KEY_SALT)?);
            }
            // kdf_params has a fixed shape in v1; reject unknown keys
            // here for the same reason as vector_clock entries.
            _ => {
                return Err(ManifestError::WrongType {
                    field: KEY_KDF_PARAMS,
                    expected: "map with only memory_kib/iterations/parallelism/salt keys",
                })
            }
        }
    }

    Ok(KdfParamsRef {
        memory_kib: memory_kib.ok_or(ManifestError::MissingField {
            field: KEY_MEMORY_KIB,
        })?,
        iterations: iterations.ok_or(ManifestError::MissingField {
            field: KEY_ITERATIONS,
        })?,
        parallelism: parallelism.ok_or(ManifestError::MissingField {
            field: KEY_PARALLELISM,
        })?,
        salt: salt.ok_or(ManifestError::MissingField { field: KEY_SALT })?,
    })
}

#[cfg(test)]
mod tests;
