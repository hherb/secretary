//! Strict canonical CBOR decode path for the manifest body
//! (`docs/vault-format.md` §4.2).

mod entries;
mod extract;

pub(super) use extract::record_error_to_cbor_fault;

use std::collections::BTreeMap;

use ciborium::Value;

use crate::cbor::SecretValueTree;
use crate::vault::canonical::reject_floats_and_tags;
use crate::vault::record::UnknownValue;

use self::entries::{parse_blocks, parse_kdf_params, parse_trash, parse_vector_clock};
use self::extract::{take_fixed_bytes, take_text_key, take_u16, take_u8, value_to_unknown};
use super::{
    BlockEntry, KdfParamsRef, Manifest, ManifestError, TrashEntry, VectorClockEntry,
    FORMAT_VERSION_V1, KEY_BLOCKS, KEY_FORMAT_VERSION, KEY_KDF_PARAMS, KEY_MANIFEST_VERSION,
    KEY_OWNER_USER_UUID, KEY_SUITE_ID, KEY_TRASH, KEY_VAULT_UUID, KEY_VECTOR_CLOCK,
    MANIFEST_VERSION_V1, SUITE_ID_V1, UUID_LEN,
};

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Strict canonical-CBOR decoder for a manifest body (§4.2).
///
/// Validates:
/// 1. Top-level item is a map.
/// 2. All map keys are text strings.
/// 3. No floats, no tags anywhere in the tree (canonical CBOR rule).
/// 4. All required §4.2 fields are present with their spec types.
/// 5. Every byte-string field has the expected length (UUIDs, fingerprint,
///    salt).
/// 6. Every integer fits its declared width (u8 / u16 / u32 / u64).
/// 7. `manifest_version`, `format_version`, `suite_id` match v1 sentinels.
/// 8. `vector_clock` and every `vector_clock_summary` have no duplicate
///    `device_uuid`.
/// 9. `blocks` has no duplicate `block_uuid`.
/// 10. `trash` has no duplicate `block_uuid` (§7 tracks the most-recent
///     tombstone per block only).
/// 11. The top-level map itself has no duplicate key (RFC 8949 §5.4).
///     Scoped to this one level only: `parse_vector_clock_entry`,
///     `parse_block_entry`, `parse_trash_entry` and `parse_kdf_params`
///     have no equivalent check of their own nested maps, and no decoder
///     in the crate looks inside a forward-compat `unknown` subtree at
///     all (#573 — see [`ManifestError::DuplicateKey`]'s doc, which
///     corrects what `record.rs` / `block.rs` actually cover).
///
/// Forward-compat unknown keys are preserved into the relevant `unknown`
/// bag verbatim.
pub fn decode_manifest(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    // `from_secret_reader`, not `from_reader` (#561): the parser stages
    // every payload through a 4 KiB scratch buffer, and this input's
    // payloads include every `block_name` — user-visible plaintext inside
    // the encrypted manifest.
    let parsed: Value =
        crate::cbor::from_secret_reader(bytes).map_err(ManifestError::CborDecode)?;
    // The parsed tree owns a copy of every decrypted plaintext value in
    // `bytes` — including every `block_name` (user-visible, plaintext
    // within the encrypted manifest — see `BlockEntry::block_name`'s own
    // doc comment) and every forward-compat `unknown` value. #547 Task 6
    // wrapped `record::decode` / `block::decode_plaintext` in exactly this
    // type; `manifest.rs` was excluded from that task on the premise that
    // it "carries no decrypted user content" — false, contradicted by
    // `block_name`'s own doc comment, which predates the exclusion (see
    // the design spec's corrected "Scope note", #547 Task 7b). Wrapping
    // means `Drop` wipes this copy on every exit from this function —
    // including the `?` early returns below and inside every nested
    // `parse_*` helper `parse_manifest_map` calls, and an unwinding panic
    // — where the pre-Task-7b code left it unwiped on every one of those
    // paths. The tree is BORROWED from here on; nothing moves out of it.
    let parsed = SecretValueTree::new(parsed);

    // Walk the tree once up front to enforce no-float / no-tag everywhere
    // (including inside forward-compat unknown values).
    reject_floats_and_tags(parsed.as_value(), "<root>")?;

    let Value::Map(entries) = parsed.as_value() else {
        return Err(ManifestError::NotAMap);
    };

    parse_manifest_map(entries)
}

/// Takes `&[(Value, Value)]` rather than owning the entry list:
/// [`decode_manifest`] borrows from a [`SecretValueTree`] it holds and
/// cannot hand over ownership without first cloning the whole entry list,
/// which would reintroduce the unwiped copy this design removes (#547
/// Task 7b, mirroring Task 6's `record::parse_record_map` /
/// `block::parse_plaintext_map`). Every nested `parse_*` helper below
/// (`parse_vector_clock`, `parse_blocks` / `parse_block_entry`,
/// `parse_trash` / `parse_trash_entry`, `parse_kdf_params`) and every
/// `take_*` helper is converted the same way, all the way down, for the
/// same reason.
///
/// Unlike `unlock::bundle::from_canonical_cbor`'s `SecretEntries`-based
/// field loop (#548), nothing is ever moved OUT of the tree here — `k`/`v`
/// stay references into the caller's still-alive `SecretValueTree` for the
/// full duration of this call, including every nested helper it invokes.
/// A `?` anywhere below therefore does not need a `wipe_leaked_value` call
/// the way `bundle.rs`'s `take_next`-yielded entries do: there is no
/// "yielded, now-unprotected" value to leak, because nothing is ever taken
/// out of the tree by value. (Checked deliberately, per #547 Task 7b's
/// brief, against the same fall-through shape Task 7 found in
/// `bundle.rs` — it does not recur here, for the reason just given.)
/// Whatever this function — or any callee — returns early from,
/// `decode_manifest`'s `SecretValueTree` still covers everything, wherever
/// in the tree it sits, the moment it drops.
fn parse_manifest_map(map: &[(Value, Value)]) -> Result<Manifest, ManifestError> {
    let mut manifest_version: Option<u8> = None;
    let mut vault_uuid: Option<[u8; UUID_LEN]> = None;
    let mut format_version: Option<u16> = None;
    let mut suite_id: Option<u16> = None;
    let mut owner_user_uuid: Option<[u8; UUID_LEN]> = None;
    let mut vector_clock: Option<Vec<VectorClockEntry>> = None;
    let mut blocks: Option<Vec<BlockEntry>> = None;
    let mut trash: Option<Vec<TrashEntry>> = None;
    let mut kdf_params: Option<KdfParamsRef> = None;
    let mut unknown: BTreeMap<String, UnknownValue> = BTreeMap::new();

    // RFC 8949 §5.4: reject a repeated key rather than last-wins.
    //
    // Every known key already has an `Option` slot above and `unknown` is a
    // `BTreeMap`, so both halves of the check are free: `slot.is_some()`
    // for the nine known keys, and `BTreeMap::insert`'s own "previous
    // value" return for the unknown bag. The first version of this check
    // carried a separate `BTreeSet<String>` plus a `key.clone()` per entry
    // — one extra unwiped heap allocation per key, in a slice whose whole
    // subject is eliminating copies — and reported the constant placeholder
    // `"<manifest>"` for every duplicate. This shape allocates nothing and
    // names the key that was actually repeated (#575 review).
    //
    // Written out per arm rather than factored into a local `macro_rules!`
    // — which is what the first draft of this fix did. Every hygiene guard
    // in this repo reads TEXT, not expanded macros (CLAUDE.md says so of
    // the payload guard explicitly), so an error CONSTRUCTION inside a
    // macro body is invisible to any future rule that inspects one. Nine
    // repetitions is a cheap price for staying greppable.
    //
    // `field` stays `&'static str` either way: for a known key it is the
    // §4.2 `KEY_*` constant, and for an unknown key it is the literal
    // `"<unknown>"` — never the repeated key itself, which is
    // attacker-influenced text from inside the encrypted manifest and
    // exactly the class `RecordError::DuplicateKey` once leaked (#474).
    for (index, (k, v)) in map.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_MANIFEST_VERSION => {
                if manifest_version.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_MANIFEST_VERSION,
                        index,
                    });
                }
                manifest_version = Some(take_u8(v, KEY_MANIFEST_VERSION)?);
            }
            KEY_VAULT_UUID => {
                if vault_uuid.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_VAULT_UUID,
                        index,
                    });
                }
                vault_uuid = Some(take_fixed_bytes::<UUID_LEN>(v, KEY_VAULT_UUID)?);
            }
            KEY_FORMAT_VERSION => {
                if format_version.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_FORMAT_VERSION,
                        index,
                    });
                }
                format_version = Some(take_u16(v, KEY_FORMAT_VERSION)?);
            }
            KEY_SUITE_ID => {
                if suite_id.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_SUITE_ID,
                        index,
                    });
                }
                suite_id = Some(take_u16(v, KEY_SUITE_ID)?);
            }
            KEY_OWNER_USER_UUID => {
                if owner_user_uuid.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_OWNER_USER_UUID,
                        index,
                    });
                }
                owner_user_uuid = Some(take_fixed_bytes::<UUID_LEN>(v, KEY_OWNER_USER_UUID)?);
            }
            KEY_VECTOR_CLOCK => {
                if vector_clock.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_VECTOR_CLOCK,
                        index,
                    });
                }
                vector_clock = Some(parse_vector_clock(v, KEY_VECTOR_CLOCK)?);
            }
            KEY_BLOCKS => {
                if blocks.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_BLOCKS,
                        index,
                    });
                }
                blocks = Some(parse_blocks(v)?);
            }
            KEY_TRASH => {
                if trash.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_TRASH,
                        index,
                    });
                }
                trash = Some(parse_trash(v)?);
            }
            KEY_KDF_PARAMS => {
                if kdf_params.is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: KEY_KDF_PARAMS,
                        index,
                    });
                }
                kdf_params = Some(parse_kdf_params(v)?);
            }
            _ => {
                // Unlike the nine arms above, the duplicate is detected
                // AFTER `value_to_unknown` has re-encoded and re-parsed the
                // value — `BTreeMap::insert` is what reports it. That
                // ordering difference is not observable: the returned error
                // is the same, and `value_to_unknown`'s own failure would
                // have to be raised before a duplicate could be reported by
                // any ordering.
                if unknown.insert(key, value_to_unknown(v)?).is_some() {
                    return Err(ManifestError::DuplicateKey {
                        field: "<unknown>",
                        index,
                    });
                }
            }
        }
    }

    let manifest_version = manifest_version.ok_or(ManifestError::MissingField {
        field: KEY_MANIFEST_VERSION,
    })?;
    if manifest_version != MANIFEST_VERSION_V1 {
        return Err(ManifestError::UnsupportedManifestVersion(manifest_version));
    }
    let format_version = format_version.ok_or(ManifestError::MissingField {
        field: KEY_FORMAT_VERSION,
    })?;
    if format_version != FORMAT_VERSION_V1 {
        return Err(ManifestError::UnsupportedFormatVersion(format_version));
    }
    let suite_id = suite_id.ok_or(ManifestError::MissingField {
        field: KEY_SUITE_ID,
    })?;
    if suite_id != SUITE_ID_V1 {
        return Err(ManifestError::UnsupportedSuiteId(suite_id));
    }

    Ok(Manifest {
        manifest_version,
        vault_uuid: vault_uuid.ok_or(ManifestError::MissingField {
            field: KEY_VAULT_UUID,
        })?,
        format_version,
        suite_id,
        owner_user_uuid: owner_user_uuid.ok_or(ManifestError::MissingField {
            field: KEY_OWNER_USER_UUID,
        })?,
        vector_clock: vector_clock.ok_or(ManifestError::MissingField {
            field: KEY_VECTOR_CLOCK,
        })?,
        blocks: blocks.ok_or(ManifestError::MissingField { field: KEY_BLOCKS })?,
        trash: trash.ok_or(ManifestError::MissingField { field: KEY_TRASH })?,
        kdf_params: kdf_params.ok_or(ManifestError::MissingField {
            field: KEY_KDF_PARAMS,
        })?,
        unknown,
    })
}

#[cfg(test)]
mod tests;
