//! Per-array / per-entry parsers for the manifest body
//! (`docs/vault-format.md` §4.2).

use ciborium::Value;

use crate::vault::manifest::uniqueness::{device_uuids, has_repeat};

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
use super::slot::{Once, UnknownBag};

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
    // arrays (§4.2). The scan itself lives in `manifest::uniqueness`,
    // shared with the WRITER: `encode_manifest` enforces the same rule
    // as of #600, and this was one of three hand-copies of it. Sharing
    // is what stops the two directions drifting — which is exactly what
    // #600 was, and what #594 had already had to repair once between
    // this decoder and the clean-room one.
    if has_repeat(device_uuids(&out)) {
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
    let mut device_uuid: Once<[u8; UUID_LEN]> = Once::default();
    let mut counter: Once<u64> = Once::default();
    // #573: reject a repeated key rather than last-wins, mirroring
    // `parse_manifest_map`'s top-level check (#568). The rejection is a
    // TYPE invariant since #589 — `Once`'s inner `Option` is private to
    // `slot.rs`, so an arm cannot fill a slot except through `Once::set`
    // — where it used to be a hand-copied `is_some()` guard per arm. The
    // macro objection that kept them inline still holds and is satisfied
    // by a helper TYPE: every hygiene guard in this repo reads TEXT, not
    // expanded macros, and a function body is ordinary text.
    for (index, (k, val)) in entries.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_DEVICE_UUID => device_uuid.set(KEY_DEVICE_UUID, index, || {
                take_fixed_bytes::<UUID_LEN>(val, KEY_DEVICE_UUID)
            })?,
            KEY_COUNTER => counter.set(KEY_COUNTER, index, || take_u64(val, KEY_COUNTER))?,
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
        device_uuid: device_uuid.require(KEY_DEVICE_UUID)?,
        counter: counter.require(KEY_COUNTER)?,
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
    if has_repeat(out.iter().map(|b| b.block_uuid).collect()) {
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
    let mut block_uuid: Once<[u8; UUID_LEN]> = Once::default();
    let mut block_name: Once<String> = Once::default();
    let mut fingerprint: Once<[u8; BLOCK_FINGERPRINT_LEN]> = Once::default();
    let mut recipients: Once<Vec<[u8; UUID_LEN]>> = Once::default();
    let mut vector_clock_summary: Once<Vec<VectorClockEntry>> = Once::default();
    let mut suite_id: Once<u16> = Once::default();
    let mut created_at_ms: Once<u64> = Once::default();
    let mut last_mod_ms: Once<u64> = Once::default();
    let mut unknown = UnknownBag::default();

    // #573: reject a repeated key rather than last-wins, mirroring
    // `parse_manifest_map`'s top-level check (#568). Since #589 the
    // rejection is a TYPE invariant — see `parse_vector_clock_entry`'s
    // comment. The unknown-bag arm routes through `UnknownBag::insert`,
    // which still detects its duplicate via `BTreeMap::insert`'s own
    // "previous value" return, same as the top level's unknown arm;
    // `field` is `UNKNOWN_FIELD`, private to `slot.rs`, never the
    // repeated key itself
    // (#474 — that text is attacker-influenced content from inside the
    // encrypted manifest).
    for (index, (k, val)) in entries.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_BLOCK_UUID => block_uuid.set(KEY_BLOCK_UUID, index, || {
                take_fixed_bytes::<UUID_LEN>(val, KEY_BLOCK_UUID)
            })?,
            KEY_BLOCK_NAME => {
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
                block_name.set(KEY_BLOCK_NAME, index, || take_text(val, KEY_BLOCK_NAME))?;
            }
            KEY_FINGERPRINT => fingerprint.set(KEY_FINGERPRINT, index, || {
                take_fixed_bytes::<BLOCK_FINGERPRINT_LEN>(val, KEY_FINGERPRINT)
            })?,
            KEY_RECIPIENTS => recipients.set(KEY_RECIPIENTS, index, || parse_recipients(val))?,
            KEY_VECTOR_CLOCK_SUMMARY => {
                vector_clock_summary.set(KEY_VECTOR_CLOCK_SUMMARY, index, || {
                    parse_vector_clock(val, KEY_VECTOR_CLOCK_SUMMARY)
                })?
            }
            KEY_SUITE_ID => suite_id.set(KEY_SUITE_ID, index, || take_u16(val, KEY_SUITE_ID))?,
            KEY_CREATED_AT_MS => created_at_ms.set(KEY_CREATED_AT_MS, index, || {
                take_u64(val, KEY_CREATED_AT_MS)
            })?,
            KEY_LAST_MOD_MS => {
                last_mod_ms.set(KEY_LAST_MOD_MS, index, || take_u64(val, KEY_LAST_MOD_MS))?
            }
            _ => {
                unknown.insert(key, value_to_unknown(val)?, index)?;
            }
        }
    }

    Ok(BlockEntry {
        block_uuid: block_uuid.require(KEY_BLOCK_UUID)?,
        block_name: block_name.require(KEY_BLOCK_NAME)?,
        fingerprint: fingerprint.require(KEY_FINGERPRINT)?,
        recipients: recipients.require(KEY_RECIPIENTS)?,
        vector_clock_summary: vector_clock_summary.require(KEY_VECTOR_CLOCK_SUMMARY)?,
        suite_id: suite_id.require(KEY_SUITE_ID)?,
        created_at_ms: created_at_ms.require(KEY_CREATED_AT_MS)?,
        last_mod_ms: last_mod_ms.require(KEY_LAST_MOD_MS)?,
        unknown: unknown.into_map(),
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
    if has_repeat(out.iter().map(|t| t.block_uuid).collect()) {
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
    let mut block_uuid: Once<[u8; UUID_LEN]> = Once::default();
    let mut tombstoned_at_ms: Once<u64> = Once::default();
    let mut tombstoned_by: Once<[u8; UUID_LEN]> = Once::default();
    let mut fingerprint: Once<[u8; BLOCK_FINGERPRINT_LEN]> = Once::default();
    let mut purged_at_ms: Once<u64> = Once::default();
    let mut unknown = UnknownBag::default();

    // #573: reject a repeated key rather than last-wins, mirroring
    // `parse_manifest_map`'s top-level check (#568). Since #589 the
    // rejection is a TYPE invariant — see `parse_vector_clock_entry`'s
    // comment. The unknown-bag arm routes through `UnknownBag::insert`,
    // which still detects its duplicate via `BTreeMap::insert`'s own
    // "previous value" return, same as the top level's unknown arm;
    // `field` is `UNKNOWN_FIELD`, private to `slot.rs`, never the
    // repeated key itself
    // (#474 — that text is attacker-influenced content from inside the
    // encrypted manifest).
    for (index, (k, val)) in entries.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_BLOCK_UUID => block_uuid.set(KEY_BLOCK_UUID, index, || {
                take_fixed_bytes::<UUID_LEN>(val, KEY_BLOCK_UUID)
            })?,
            KEY_TOMBSTONED_AT_MS => tombstoned_at_ms.set(KEY_TOMBSTONED_AT_MS, index, || {
                take_u64(val, KEY_TOMBSTONED_AT_MS)
            })?,
            KEY_TOMBSTONED_BY => tombstoned_by.set(KEY_TOMBSTONED_BY, index, || {
                take_fixed_bytes::<UUID_LEN>(val, KEY_TOMBSTONED_BY)
            })?,
            KEY_FINGERPRINT => fingerprint.set(KEY_FINGERPRINT, index, || {
                take_fixed_bytes::<BLOCK_FINGERPRINT_LEN>(val, KEY_FINGERPRINT)
            })?,
            KEY_PURGED_AT_MS => {
                purged_at_ms.set(KEY_PURGED_AT_MS, index, || take_u64(val, KEY_PURGED_AT_MS))?
            }
            _ => {
                unknown.insert(key, value_to_unknown(val)?, index)?;
            }
        }
    }

    Ok(TrashEntry {
        block_uuid: block_uuid.require(KEY_BLOCK_UUID)?,
        tombstoned_at_ms: tombstoned_at_ms.require(KEY_TOMBSTONED_AT_MS)?,
        tombstoned_by: tombstoned_by.require(KEY_TOMBSTONED_BY)?,
        fingerprint: fingerprint.into_option(),
        purged_at_ms: purged_at_ms.into_option(),
        unknown: unknown.into_map(),
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
    let mut memory_kib: Once<u32> = Once::default();
    let mut iterations: Once<u32> = Once::default();
    let mut parallelism: Once<u32> = Once::default();
    let mut salt: Once<[u8; SALT_LEN]> = Once::default();

    // #573: reject a repeated key rather than last-wins, mirroring
    // `parse_manifest_map`'s top-level check (#568). Since #589 the
    // rejection is a TYPE invariant — see `parse_vector_clock_entry`'s
    // comment.
    for (index, (k, val)) in entries.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_MEMORY_KIB => {
                memory_kib.set(KEY_MEMORY_KIB, index, || take_u32(val, KEY_MEMORY_KIB))?
            }
            KEY_ITERATIONS => {
                iterations.set(KEY_ITERATIONS, index, || take_u32(val, KEY_ITERATIONS))?
            }
            KEY_PARALLELISM => {
                parallelism.set(KEY_PARALLELISM, index, || take_u32(val, KEY_PARALLELISM))?
            }
            KEY_SALT => salt.set(KEY_SALT, index, || {
                take_fixed_bytes::<SALT_LEN>(val, KEY_SALT)
            })?,
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
        memory_kib: memory_kib.require(KEY_MEMORY_KIB)?,
        iterations: iterations.require(KEY_ITERATIONS)?,
        parallelism: parallelism.require(KEY_PARALLELISM)?,
        salt: salt.require(KEY_SALT)?,
    })
}

#[cfg(test)]
mod tests;
