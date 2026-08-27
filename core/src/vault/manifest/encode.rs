//! Canonical CBOR encode path for the manifest body (`docs/vault-format.md` §4.2).

use ciborium::Value;

use crate::crypto::secret::SecretBytes;
use crate::vault::canonical::{canonical_sort_entries, encode_canonical_map};
use crate::vault::record::UnknownValue;

use super::decode::record_error_to_cbor_fault;
use super::{
    BlockEntry, KdfParamsRef, Manifest, ManifestError, TrashEntry, VectorClockEntry, KEY_BLOCKS,
    KEY_BLOCK_NAME, KEY_BLOCK_UUID, KEY_COUNTER, KEY_CREATED_AT_MS, KEY_DEVICE_UUID,
    KEY_FINGERPRINT, KEY_FORMAT_VERSION, KEY_ITERATIONS, KEY_KDF_PARAMS, KEY_LAST_MOD_MS,
    KEY_MANIFEST_VERSION, KEY_MEMORY_KIB, KEY_OWNER_USER_UUID, KEY_PARALLELISM, KEY_PURGED_AT_MS,
    KEY_RECIPIENTS, KEY_SALT, KEY_SUITE_ID, KEY_TOMBSTONED_AT_MS, KEY_TOMBSTONED_BY, KEY_TRASH,
    KEY_VAULT_UUID, KEY_VECTOR_CLOCK, KEY_VECTOR_CLOCK_SUMMARY, UUID_LEN,
};

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Canonical CBOR encoding of a manifest body (§4.2). Output is
/// deterministic: any conformant RFC 8949 §4.2.1 encoder produces the
/// same bytes.
///
/// All arrays (`vector_clock`, every `vector_clock_summary`, `blocks`,
/// `trash`, every block's `recipients`) are sorted on output per the
/// §4.2 sort disciplines. Forward-compat unknown keys are spliced in
/// alongside known keys at the canonical-sort step.
///
/// Returns [`SecretBytes`], not `Vec<u8>`: the output is the decrypted
/// canonical form of a manifest body. Returning the wrapper rather than
/// leaving each caller to apply one means the wrap cannot be deleted
/// without a compile error, which is the difference between this and the
/// deletable `SecretBytes::new(..)` call sites #558 and #565 record.
///
/// **That covers the OUTPUT only, and the input side is still open**
/// (#575 review — worth stating here, because the paragraph above
/// otherwise reads as if this whole path were covered).
/// `manifest_to_entries` below (private, hence not linked — the #92
/// rustdoc gate rejects an intra-doc link from a public item to a private
/// one) builds an owned `Vec<(Value, Value)>`
/// containing `Value::Text(entry.block_name.clone())` for every block —
/// user-authored plaintext, the same field `BlockEntry::block_name`'s own
/// doc flags, and the very field #547 Task 7b cited to justify wrapping
/// the manifest DECODE side. That vector is dropped unwiped on every
/// manifest write. It is **#569's path 2**, unrelated to and not closed
/// by this return-type change; the fix is to migrate `manifest_to_entries`
/// to the borrowing `CanonicalMap` mirror the way `bundle.rs` was
/// migrated (path 1), since elimination is strictly stronger than a wrap.
pub fn encode_manifest(manifest: &Manifest) -> Result<SecretBytes, ManifestError> {
    let entries = manifest_to_entries(manifest)?;
    Ok(SecretBytes::new(encode_canonical_map(&entries)?))
}

pub(super) fn manifest_to_entries(m: &Manifest) -> Result<Vec<(Value, Value)>, ManifestError> {
    let mut entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(m.manifest_version).into()),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes(m.vault_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(m.format_version).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(m.suite_id).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes(m.owner_user_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            vector_clock_to_value(&m.vector_clock)?,
        ),
        (Value::Text(KEY_BLOCKS.into()), blocks_to_value(&m.blocks)?),
        (Value::Text(KEY_TRASH.into()), trash_to_value(&m.trash)?),
        (
            Value::Text(KEY_KDF_PARAMS.into()),
            kdf_params_to_value(&m.kdf_params)?,
        ),
    ];

    for (k, v) in &m.unknown {
        entries.push((Value::Text(k.clone()), unknown_value_inner(v)?));
    }

    Ok(entries)
}

/// Encode a vector clock array sorted ascending by `device_uuid`.
fn vector_clock_to_value(vc: &[VectorClockEntry]) -> Result<Value, ManifestError> {
    let mut sorted: Vec<&VectorClockEntry> = vc.iter().collect();
    sorted.sort_by_key(|e| e.device_uuid);

    let items: Result<Vec<Value>, ManifestError> = sorted
        .into_iter()
        .map(|entry| {
            let inner = vec![
                (
                    Value::Text(KEY_DEVICE_UUID.into()),
                    Value::Bytes(entry.device_uuid.to_vec()),
                ),
                (
                    Value::Text(KEY_COUNTER.into()),
                    Value::Integer(entry.counter.into()),
                ),
            ];
            let sorted_inner = canonical_sort_entries(&inner)?;
            Ok(Value::Map(sorted_inner))
        })
        .collect();
    Ok(Value::Array(items?))
}

fn blocks_to_value(blocks: &[BlockEntry]) -> Result<Value, ManifestError> {
    let mut sorted: Vec<&BlockEntry> = blocks.iter().collect();
    sorted.sort_by_key(|e| e.block_uuid);

    let items: Result<Vec<Value>, ManifestError> =
        sorted.into_iter().map(block_entry_to_value).collect();
    Ok(Value::Array(items?))
}

fn block_entry_to_value(entry: &BlockEntry) -> Result<Value, ManifestError> {
    // Recipients sorted ascending by 16-byte lex compare.
    let mut recipients: Vec<&[u8; UUID_LEN]> = entry.recipients.iter().collect();
    recipients.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    let recipients_value = Value::Array(
        recipients
            .into_iter()
            .map(|r| Value::Bytes(r.to_vec()))
            .collect(),
    );

    let mut inner: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_BLOCK_UUID.into()),
            Value::Bytes(entry.block_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_BLOCK_NAME.into()),
            Value::Text(entry.block_name.clone()),
        ),
        (
            Value::Text(KEY_FINGERPRINT.into()),
            Value::Bytes(entry.fingerprint.to_vec()),
        ),
        (Value::Text(KEY_RECIPIENTS.into()), recipients_value),
        (
            Value::Text(KEY_VECTOR_CLOCK_SUMMARY.into()),
            vector_clock_to_value(&entry.vector_clock_summary)?,
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(entry.suite_id).into()),
        ),
        (
            Value::Text(KEY_CREATED_AT_MS.into()),
            Value::Integer(entry.created_at_ms.into()),
        ),
        (
            Value::Text(KEY_LAST_MOD_MS.into()),
            Value::Integer(entry.last_mod_ms.into()),
        ),
    ];
    for (k, v) in &entry.unknown {
        inner.push((Value::Text(k.clone()), unknown_value_inner(v)?));
    }
    let sorted = canonical_sort_entries(&inner)?;
    Ok(Value::Map(sorted))
}

fn trash_to_value(trash: &[TrashEntry]) -> Result<Value, ManifestError> {
    let mut sorted: Vec<&TrashEntry> = trash.iter().collect();
    sorted.sort_by_key(|e| e.block_uuid);

    let items: Result<Vec<Value>, ManifestError> =
        sorted.into_iter().map(trash_entry_to_value).collect();
    Ok(Value::Array(items?))
}

pub(super) fn trash_entry_to_value(entry: &TrashEntry) -> Result<Value, ManifestError> {
    let mut inner: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_BLOCK_UUID.into()),
            Value::Bytes(entry.block_uuid.to_vec()),
        ),
        (
            Value::Text(KEY_TOMBSTONED_AT_MS.into()),
            Value::Integer(entry.tombstoned_at_ms.into()),
        ),
        (
            Value::Text(KEY_TOMBSTONED_BY.into()),
            Value::Bytes(entry.tombstoned_by.to_vec()),
        ),
    ];
    // #293: optional content commitment. Reuses the "fingerprint" key
    // (separate map from BlockEntry, so no collision). Omitted when None so
    // legacy-shaped entries stay byte-identical (no format bump).
    if let Some(fp) = entry.fingerprint {
        inner.push((
            Value::Text(KEY_FINGERPRINT.into()),
            Value::Bytes(fp.to_vec()),
        ));
    }
    // #399: optional purge commitment. Omitted when None so legacy-shaped
    // (still-restorable) entries stay byte-identical (no format bump).
    if let Some(purged_at_ms) = entry.purged_at_ms {
        inner.push((
            Value::Text(KEY_PURGED_AT_MS.into()),
            Value::Integer(purged_at_ms.into()),
        ));
    }
    for (k, v) in &entry.unknown {
        inner.push((Value::Text(k.clone()), unknown_value_inner(v)?));
    }
    let sorted = canonical_sort_entries(&inner)?;
    Ok(Value::Map(sorted))
}

pub(super) fn kdf_params_to_value(k: &KdfParamsRef) -> Result<Value, ManifestError> {
    let inner = vec![
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
    let sorted = canonical_sort_entries(&inner)?;
    Ok(Value::Map(sorted))
}

/// Extract the underlying CBOR `Value` from an [`UnknownValue`] for
/// splicing into a parent map. We round-trip via canonical CBOR bytes so
/// the call site does not need access to `UnknownValue`'s inner field.
///
/// `from_reader` here is a production parse of forward-compat plaintext
/// (#547 Task 7b, the second `from_reader` site the task's brief names
/// alongside `decode_manifest`'s own): the caller is the ENCODE path,
/// re-materialising an already-decrypted `UnknownValue` for splicing into
/// the manifest body about to be serialised.
///
/// This function has TWO intermediate plaintext copies, not the one an
/// earlier version of this comment named (#547 Task 8 review — corrected
/// here rather than silently reworded, per this doc's own discipline):
/// `bytes`, the `to_canonical_cbor` serialisation, and `v`, the
/// freshly-parsed tree. **`bytes` is the one that is covered**, and the
/// #560 review is what swapped them round, because Task 7b had it exactly
/// backwards:
///
/// - `bytes` has a genuine early-return window — the `?` on the
///   `from_reader` line below sits between its fill and the end of the
///   function — so wrapping it in [`SecretBytes`] makes `Drop` cover an
///   exit that a trailing statement would miss. That is the whole
///   justification for a wrapper, and it applies here.
/// - `v` has **no** such window. Nothing fallible or panicking sits
///   between the parse and the return, so a [`SecretValueTree`] wrap
///   covered no exit that was not already covered. Task 7b wrapped it
///   anyway, and because that type deliberately has no consuming accessor,
///   the wrap FORCED a `.clone()` — a full deep copy of the forward-compat
///   subtree — to get the value back out. The residue was unchanged (one
///   unwiped `Value` escaped into the caller's plain, non-zeroizing
///   `Vec<(Value, Value)>` either way), so the wrap bought nothing and
///   cost a deep clone of decrypted content per unknown per manifest
///   encode. It is removed; `v` moves straight into the return value as it
///   did before Task 7b.
///
/// The `SecretBytes` wrap on `bytes` is not observable from a test — it
/// does not tick `cbor::wipe_calls()`, which only `secret_tree`'s three
/// entry points do — so reverting it would leave the suite green. That is
/// the class **#558** already tracks for the AEAD plaintext buffers, and
/// this site now joins it rather than pretending to a coverage it lacks.
/// The counter-based test Task 7b wrote for the removed `SecretValueTree`
/// wrap is retired with the wrap it pinned.
pub(super) fn unknown_value_inner(u: &UnknownValue) -> Result<Value, ManifestError> {
    let bytes = SecretBytes::new(
        u.to_canonical_cbor()
            .map_err(|e| ManifestError::CborEncode(record_error_to_cbor_fault(e)))?,
    );
    // `from_secret_reader`, not `from_reader` (#561): `bytes` is a
    // re-encode of a forward-compat unknown subtree from inside the
    // encrypted manifest — plaintext this version cannot interpret but
    // must still not leave staged in `ciborium`'s own frame.
    let v: Value =
        crate::cbor::from_secret_reader(bytes.expose()).map_err(ManifestError::CborDecode)?;
    Ok(v)
}

#[cfg(test)]
mod tests;
