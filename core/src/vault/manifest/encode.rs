//! Canonical CBOR encode path for the manifest body (`docs/vault-format.md` §4.2).

use crate::crypto::secret::SecretBytes;
use crate::vault::canonical::{to_canonical_vec, CanonicalMap, CanonicalValue};
use crate::vault::manifest::uniqueness::check_no_repeated_array_values;

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
/// alongside known keys; `CanonicalMap`'s own `Serialize` imposes the
/// RFC 8949 §4.2.1 key order, recursively, at serialise time. (Plain
/// backticks, not an intra-doc link: `CanonicalMap` is `pub(crate)` while
/// this item is `pub`, and the #92 rustdoc gate rejects a public item
/// linking to a private one.)
///
/// Returns [`SecretBytes`], not `Vec<u8>`: the output is the decrypted
/// canonical form of a manifest body. Returning the wrapper rather than
/// leaving each caller to apply one means the wrap cannot be deleted
/// without a compile error, which is the difference between this and the
/// deletable `SecretBytes::new(..)` call sites #558 and #565 record.
///
/// **The input side is now covered too (#569 path 2).** The paragraph
/// that stood here through #575 recorded the gap: `manifest_to_entries`
/// built an owned `Vec<(Value, Value)>` holding
/// `Value::Text(entry.block_name.clone())` for every block — user-authored
/// plaintext, the field [`BlockEntry::block_name`]'s own doc flags as
/// such — and `canonical_sort_entries` then `pair.clone()`d the whole
/// entry list, so a manifest save dropped *two* unwiped copies of every
/// block name. `manifest_to_canonical` replaces it: every value BORROWS
/// out of the [`Manifest`], so neither copy is made at all. Elimination
/// rather than a wrap, which is strictly stronger — there is no buffer
/// left for a future caller to forget to wipe. Same migration
/// `record::record_to_canonical` (#547) and
/// `unlock::bundle::IdentityBundle::to_canonical_cbor` (#569 path 1)
/// already made.
pub fn encode_manifest(manifest: &Manifest) -> Result<SecretBytes, ManifestError> {
    check_no_repeated_array_values(manifest)?;
    Ok(SecretBytes::new(to_canonical_vec(&manifest_to_canonical(
        manifest,
    ))?))
}

/// Build the borrowed canonical map for a manifest body (§4.2).
///
/// **Infallible.** Every fallible step the owned encoder had came from one
/// of the two constructs #569 path 2 removed: `canonical_sort_entries`
/// (which could fail encoding a key, and no longer runs — [`CanonicalMap`]
/// sorts through the borrowed `&str`s without encoding one) and
/// `unknown_value_inner` (which re-encoded and re-parsed each unknown
/// subtree, and is deleted — [`CanonicalValue::Borrowed`] emits it
/// verbatim). What is left cannot fail, so no helper below returns a
/// `Result`; [`encode_manifest`]'s only error source is the shared
/// canonical encoder's own CBOR-encode / capacity-bound checks, lifted by
/// `ManifestError`'s `From<CanonicalError>` impl.
///
/// **Push order is irrelevant** — [`CanonicalMap`]'s `Serialize` imposes
/// RFC 8949 §4.2.1 order recursively at serialise time. The *array* sort
/// disciplines are NOT irrelevant and are preserved exactly; each helper
/// below states the one it applies.
///
/// # Integer equivalence (`Value::Integer` → [`CanonicalValue::Uint`])
///
/// The owned encoder emitted every numeric field as
/// `Value::Integer(x.into())`, whose `Serialize` impl covers CBOR major
/// types 0 and 1 plus `ciborium`'s bignum tag arms.
/// [`CanonicalValue::Uint`] calls `serialize_u64`, i.e. major type 0 in
/// shortest form and nothing else. The substitution is therefore only
/// sound where the source value is unsigned AND fits `u64` **over its
/// whole declared domain** — not merely for the fixtures the tests
/// happen to use. Justified per field by its declared type
/// (`manifest/types.rs`, and `block::VectorClockEntry` for `counter`):
///
/// | Field | Declared type | Conversion |
/// |---|---|---|
/// | `manifest_version` | `u8` | `Uint(u64::from(..))` |
/// | `format_version` | `u16` | `Uint(u64::from(..))` |
/// | `suite_id` (manifest + block entry) | `u16` | `Uint(u64::from(..))` |
/// | `counter` (vector-clock entry) | `u64` | `Uint(..)` |
/// | `created_at_ms`, `last_mod_ms` (block entry) | `u64` | `Uint(..)` |
/// | `tombstoned_at_ms` (trash entry) | `u64` | `Uint(..)` |
/// | `purged_at_ms` (trash entry) | `Option<u64>` | conditional push, `Uint` inside |
/// | `memory_kib`, `iterations`, `parallelism` | `u32` | `Uint(u64::from(..))` |
///
/// Eight rows, covering **12 production `CanonicalValue::Uint` sites**
/// over **11 distinct field names** (`suite_id` appears at both manifest
/// and block-entry level; three rows group same-typed siblings). The row
/// count is stated because a bare number here has already been written
/// wrong once — count the `CanonicalValue::Uint` occurrences in the body
/// below, not the rows above, if you need the site figure.
///
/// Every one is an unsigned integer type no wider than `u64`, so the
/// negative arm and both bignum arms of `Value::Integer` are
/// structurally unreachable and the two encodings agree over the entire
/// domain of each field — not just where a test exercises them. The
/// `u64::from` conversions are widening and infallible; there is no
/// `as` cast anywhere on this path.
///
/// **Unreachability is necessary but NOT sufficient, and the missing link
/// is worth spelling out** — the argument above stops one step short of
/// the one `unlock::bundle` had to make. `ciborium` does not send a
/// `Value::Integer` straight to `serialize_u64`: `value/ser.rs:34-58`
/// (ciborium 0.2.2, exact-pinned as `ciborium = "=0.2.2"` in
/// `core/Cargo.toml` — the manifest itself; there is no `core/Cargo.lock`,
/// the workspace lockfile being at the repo root) is a
/// TRY-LADDER — `u8`, `i8`, `u16`, `i16`, `u32`, `i32`, `u64`, `i64`,
/// `u128`, `i128` — so most values in this table select `serialize_u8` /
/// `u16` / `u32`, not `serialize_u64` at all. Byte identity therefore
/// needs those to agree with `serialize_u64`, and they do:
/// `ser/mod.rs:104-121` defines `serialize_u8`/`u16`/`u32` as
/// `self.serialize_u64(v.into())`, and `serialize_u64` as the single
/// `Header::Positive(v)` push — the same head [`CanonicalValue::Uint`]
/// reaches directly. The signed rungs are unreachable for this table's
/// domain anyway (each `uN` is tried before the `iN` of the same width,
/// and every non-negative value that fits `iN` fits `uN`), but even if
/// one were taken the conclusion holds: `ser/mod.rs:55-69` forwards
/// `serialize_i8`/`i16`/`i32` to `serialize_i64`, which emits
/// `Header::Positive(v as u64)` for non-negative input.
///
/// The execution half of this already exists and is cited rather than
/// duplicated: `canonical::value`'s
/// `uint_is_byte_identical_across_every_head_boundary`
/// (`core/src/vault/canonical/value.rs:374`) encodes
/// `Value::Integer(u.into())` and `CanonicalValue::Uint(u)` at all 11
/// CBOR head boundaries through `u64::MAX` and asserts the bytes are
/// equal. It runs on every `cargo test`.
fn manifest_to_canonical(m: &Manifest) -> CanonicalMap<'_> {
    // 9 known top-level keys + one slot per forward-compat unknown. A size
    // hint only — `push` is correct either way.
    let mut map = CanonicalMap::with_capacity(9 + m.unknown.len());

    map.push(
        KEY_MANIFEST_VERSION,
        CanonicalValue::Uint(u64::from(m.manifest_version)),
    );
    map.push(KEY_VAULT_UUID, CanonicalValue::Bytes(&m.vault_uuid));
    map.push(
        KEY_FORMAT_VERSION,
        CanonicalValue::Uint(u64::from(m.format_version)),
    );
    map.push(KEY_SUITE_ID, CanonicalValue::Uint(u64::from(m.suite_id)));
    map.push(
        KEY_OWNER_USER_UUID,
        CanonicalValue::Bytes(&m.owner_user_uuid),
    );
    map.push(KEY_VECTOR_CLOCK, vector_clock_to_canonical(&m.vector_clock));
    map.push(KEY_BLOCKS, blocks_to_canonical(&m.blocks));
    map.push(KEY_TRASH, trash_to_canonical(&m.trash));
    map.push(
        KEY_KDF_PARAMS,
        CanonicalValue::Map(kdf_params_to_canonical(&m.kdf_params)),
    );

    // Forward-compat: splice unknowns alongside known keys, emitted
    // verbatim as a BORROW. The deleted `unknown_value_inner` re-encoded
    // each subtree to CBOR and re-parsed it — an allocation, a
    // `SecretBytes` and a `from_secret_reader` call per unknown per
    // manifest write, all of a v2 client's content a v1 client cannot
    // interpret and must not copy. `UnknownValue::as_value` is
    // `pub(crate)` for exactly this, and `record.rs`'s encoder already
    // borrows through it.
    for (k, v) in &m.unknown {
        map.push(k, CanonicalValue::Borrowed(v.as_value()));
    }

    map
}

/// Encode a vector clock array sorted ascending by `device_uuid`.
///
/// The sort is over a `Vec<&VectorClockEntry>` — borrows, not owned
/// copies — so reordering moves 8-byte pointers, never entry contents.
fn vector_clock_to_canonical(vc: &[VectorClockEntry]) -> CanonicalValue<'_> {
    let mut sorted: Vec<&VectorClockEntry> = vc.iter().collect();
    sorted.sort_by_key(|e| e.device_uuid);

    CanonicalValue::Array(
        sorted
            .into_iter()
            .map(|entry| {
                let mut inner = CanonicalMap::with_capacity(2);
                inner.push(KEY_DEVICE_UUID, CanonicalValue::Bytes(&entry.device_uuid));
                inner.push(KEY_COUNTER, CanonicalValue::Uint(entry.counter));
                CanonicalValue::Map(inner)
            })
            .collect(),
    )
}

/// Encode the `blocks` array sorted ascending by `block_uuid`.
fn blocks_to_canonical(blocks: &[BlockEntry]) -> CanonicalValue<'_> {
    let mut sorted: Vec<&BlockEntry> = blocks.iter().collect();
    sorted.sort_by_key(|e| e.block_uuid);

    CanonicalValue::Array(
        sorted
            .into_iter()
            .map(|e| CanonicalValue::Map(block_entry_to_canonical(e)))
            .collect(),
    )
}

/// One `blocks` entry.
///
/// `block_name` is the field #569 path 2 exists for: user-authored
/// plaintext living inside the encrypted manifest (see
/// [`BlockEntry::block_name`]'s own doc). It is BORROWED here — the owned
/// encoder cloned it into a `Value::Text` and `canonical_sort_entries`
/// cloned that again, two unwiped copies per manifest save on a path all
/// four production `sign_manifest` sites reach.
fn block_entry_to_canonical(entry: &BlockEntry) -> CanonicalMap<'_> {
    // 8 known keys + one slot per forward-compat unknown.
    let mut map = CanonicalMap::with_capacity(8 + entry.unknown.len());

    map.push(KEY_BLOCK_UUID, CanonicalValue::Bytes(&entry.block_uuid));
    map.push(KEY_BLOCK_NAME, CanonicalValue::Text(&entry.block_name));
    map.push(KEY_FINGERPRINT, CanonicalValue::Bytes(&entry.fingerprint));

    // Recipients sorted ascending by 16-byte bytewise compare, over
    // borrows of the uuid arrays rather than copies of them.
    let mut recipients: Vec<&[u8; UUID_LEN]> = entry.recipients.iter().collect();
    recipients.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    map.push(
        KEY_RECIPIENTS,
        CanonicalValue::Array(
            recipients
                .into_iter()
                .map(|r| CanonicalValue::Bytes(r))
                .collect(),
        ),
    );

    map.push(
        KEY_VECTOR_CLOCK_SUMMARY,
        vector_clock_to_canonical(&entry.vector_clock_summary),
    );
    map.push(
        KEY_SUITE_ID,
        CanonicalValue::Uint(u64::from(entry.suite_id)),
    );
    map.push(KEY_CREATED_AT_MS, CanonicalValue::Uint(entry.created_at_ms));
    map.push(KEY_LAST_MOD_MS, CanonicalValue::Uint(entry.last_mod_ms));

    for (k, v) in &entry.unknown {
        map.push(k, CanonicalValue::Borrowed(v.as_value()));
    }

    map
}

/// Encode the `trash` array sorted ascending by `block_uuid`.
fn trash_to_canonical(trash: &[TrashEntry]) -> CanonicalValue<'_> {
    let mut sorted: Vec<&TrashEntry> = trash.iter().collect();
    sorted.sort_by_key(|e| e.block_uuid);

    CanonicalValue::Array(
        sorted
            .into_iter()
            .map(|e| CanonicalValue::Map(trash_entry_to_canonical(e)))
            .collect(),
    )
}

/// One `trash` entry.
///
/// Both optional fields keep their ABSENT-on-the-wire semantics exactly:
/// a `None` pushes no key at all (not an explicit CBOR null), so a
/// legacy-shaped entry stays byte-identical and neither field needed a
/// format bump. `trash_entry_purged_at_ms_none_roundtrips_byte_identical`
/// and `trash_entry_fingerprint_none_omits_key` pin this.
fn trash_entry_to_canonical(entry: &TrashEntry) -> CanonicalMap<'_> {
    // 3 always-pushed keys + up to 2 conditional ones (`fingerprint`,
    // `purged_at_ms`) + one slot per forward-compat unknown.
    let mut map = CanonicalMap::with_capacity(5 + entry.unknown.len());

    map.push(KEY_BLOCK_UUID, CanonicalValue::Bytes(&entry.block_uuid));
    map.push(
        KEY_TOMBSTONED_AT_MS,
        CanonicalValue::Uint(entry.tombstoned_at_ms),
    );
    map.push(
        KEY_TOMBSTONED_BY,
        CanonicalValue::Bytes(&entry.tombstoned_by),
    );

    // #293: optional content commitment. Reuses the "fingerprint" key
    // (separate map from BlockEntry, so no collision). Omitted when None so
    // legacy-shaped entries stay byte-identical (no format bump).
    if let Some(fp) = &entry.fingerprint {
        map.push(KEY_FINGERPRINT, CanonicalValue::Bytes(fp));
    }
    // #399: optional purge commitment. Omitted when None so legacy-shaped
    // (still-restorable) entries stay byte-identical (no format bump).
    if let Some(purged_at_ms) = entry.purged_at_ms {
        map.push(KEY_PURGED_AT_MS, CanonicalValue::Uint(purged_at_ms));
    }

    for (k, v) in &entry.unknown {
        map.push(k, CanonicalValue::Borrowed(v.as_value()));
    }

    map
}

/// The `kdf_params` sub-map mirrored from `vault.toml` (§4.2 line 205).
fn kdf_params_to_canonical(k: &KdfParamsRef) -> CanonicalMap<'_> {
    let mut map = CanonicalMap::with_capacity(4);
    map.push(
        KEY_MEMORY_KIB,
        CanonicalValue::Uint(u64::from(k.memory_kib)),
    );
    map.push(
        KEY_ITERATIONS,
        CanonicalValue::Uint(u64::from(k.iterations)),
    );
    map.push(
        KEY_PARALLELISM,
        CanonicalValue::Uint(u64::from(k.parallelism)),
    );
    map.push(KEY_SALT, CanonicalValue::Bytes(&k.salt));
    map
}

#[cfg(test)]
mod tests;
