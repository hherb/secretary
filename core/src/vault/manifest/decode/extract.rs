//! Typed-extract helpers shared by the manifest decode path.

use ciborium::Value;

use crate::cbor::{classify_ser, CborErrorKind, CborFault};
use crate::crypto::secret::SecretBytes;
use crate::vault::canonical::cbor_size_bound;
use crate::vault::manifest::ManifestError;
use crate::vault::record::{RecordError, UnknownValue};

// ---------------------------------------------------------------------------
// Typed-extract helpers (manifest-local; per the brief, do NOT extract
// these into a shared canonical helper module — duplication is the right
// call until a fourth caller materialises).
// ---------------------------------------------------------------------------

/// Borrows rather than consumes throughout this whole helper family (#547
/// Task 7b): every caller holds `v`/`k` as a reference into the
/// [`SecretValueTree`] `decode_manifest` **itself** holds — not one of
/// `decode_manifest`'s callers, as an earlier version of this comment
/// said (#547 Task 8 review — corrected here rather than silently
/// reworded). No caller of `decode_manifest` holds a `SecretValueTree` at
/// all; `manifest.rs` has exactly one root, owned by `decode_manifest`
/// (see `parse_manifest_map`'s doc). That phrasing was carried over from
/// `record.rs`, which genuinely has two `SecretValueTree`-related sites
/// across its decode call chain — `manifest.rs` does not share that
/// shape. Every scalar `take_*` clones out of the
/// borrowed tree into a genuinely OWNED, plain (non-zeroizing) return
/// value — `String`, `[u8; N]`, `u8`/`u16`/`u32`/`u64` — one added copy
/// per call relative to the pre-Task-7b owning version, which moved the
/// value out instead. The SOURCE is covered from that point on (the
/// enclosing `SecretValueTree` wipes it on drop); the destination here is
/// not — no regression, since none of these destinations (`Manifest`,
/// `BlockEntry`, `TrashEntry`, `KdfParamsRef`, `VectorClockEntry` fields)
/// was ever wrapped in a zeroizing type before this task either. See
/// `parse_block_entry`'s `KEY_BLOCK_NAME` arm for the one call here that
/// clones genuinely user-authored plaintext.
pub(super) fn take_text_key(v: &Value) -> Result<String, ManifestError> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(ManifestError::NonTextKey),
    }
}

pub(super) fn take_text(v: &Value, field: &'static str) -> Result<String, ManifestError> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(ManifestError::WrongType {
            field,
            expected: "text string",
        }),
    }
}

pub(super) fn take_fixed_bytes<const N: usize>(
    v: &Value,
    field: &'static str,
) -> Result<[u8; N], ManifestError> {
    let bytes = match v {
        Value::Bytes(b) => b,
        _ => {
            return Err(ManifestError::WrongType {
                field,
                expected: "byte string",
            })
        }
    };
    let length = bytes.len();
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_: std::array::TryFromSliceError| {
        ManifestError::InvalidByteLength {
            field,
            expected: N,
            length,
        }
    })
}

pub(super) fn take_u8(v: &Value, field: &'static str) -> Result<u8, ManifestError> {
    let i = take_integer_i128(v, field)?;
    if !(0..=u8::MAX as i128).contains(&i) {
        return Err(ManifestError::IntegerOutOfRange { field, value: i });
    }
    Ok(i as u8)
}

pub(super) fn take_u16(v: &Value, field: &'static str) -> Result<u16, ManifestError> {
    let i = take_integer_i128(v, field)?;
    if !(0..=u16::MAX as i128).contains(&i) {
        return Err(ManifestError::IntegerOutOfRange { field, value: i });
    }
    Ok(i as u16)
}

pub(super) fn take_u32(v: &Value, field: &'static str) -> Result<u32, ManifestError> {
    let i = take_integer_i128(v, field)?;
    if !(0..=u32::MAX as i128).contains(&i) {
        return Err(ManifestError::IntegerOutOfRange { field, value: i });
    }
    Ok(i as u32)
}

pub(super) fn take_u64(v: &Value, field: &'static str) -> Result<u64, ManifestError> {
    let i = take_integer_i128(v, field)?;
    if !(0..=u64::MAX as i128).contains(&i) {
        return Err(ManifestError::IntegerOutOfRange { field, value: i });
    }
    Ok(i as u64)
}

/// Decode a CBOR integer as i128 so all of [u8 .. u64] fit a single
/// accessor. `ciborium::value::Integer` → `i128` is infallible, and
/// `Integer` is `Copy`, so borrowing costs nothing extra here — unlike
/// every other `take_*` above, there is no added clone at this specific
/// site.
fn take_integer_i128(v: &Value, field: &'static str) -> Result<i128, ManifestError> {
    match v {
        Value::Integer(i) => Ok(i128::from(*i)),
        _ => Err(ManifestError::WrongType {
            field,
            expected: "unsigned integer",
        }),
    }
}

/// Wrap a raw `Value` (from an unknown top-level / per-entry key) into
/// an [`UnknownValue`] for round-trip preservation. We re-encode and
/// re-decode through `UnknownValue::from_canonical_cbor` so any future
/// tightening of the unknown-value invariant fires here too.
///
/// Borrows rather than consumes (#547 Task 7b): every caller now holds
/// `v` as a reference into a [`SecretValueTree`] (directly for
/// `parse_manifest_map`, or transitively via a parent entry map for
/// `parse_block_entry` / `parse_trash_entry`) and cannot hand over
/// ownership without first cloning the whole subtree. Unlike every
/// `take_*` helper above, this conversion needs NO added clone at all:
/// serialising only ever needed a borrow — `ciborium::ser::into_writer`'s
/// `value` parameter is `&T` — so the pre-Task-7b `Value` parameter was
/// already only used as `&v`. `UnknownValue::from_canonical_cbor` below
/// still allocates its own fresh `Value` by re-parsing `buf`, exactly as
/// it always has; that allocation is `UnknownValue`'s own, not a copy
/// this function introduces.
///
/// The output buffer is pre-reserved (#560 review). Task 7b removed the
/// added CLONE from this function but left `buf` a bare `Vec::new()`, which
/// grows by doubling and frees each old buffer unwiped — and `v` borrows
/// from `decode_manifest`'s `SecretValueTree`, so this is the same content
/// the wrap exists to protect. Reserving is what `to_canonical_vec` and
/// `encode_canonical_map` already do; this site and its two siblings in
/// `record.rs` / `block.rs` were missed by that pass.
/// `buf` is wrapped in [`SecretBytes`], not left a bare `Vec<u8>` (#575
/// review). Pre-reserving stops it REALLOCATING and freeing unwiped
/// prefixes; it does nothing about the final buffer, which is a complete
/// CBOR re-encoding of a decrypted forward-compat subtree and was dropped
/// intact on both the success and error paths. Its encode-side twin,
/// `unknown_value_inner`, already wrapped its equivalent buffer, so the two
/// were treating the same content class oppositely. **That twin no longer
/// exists**, and it was never in this file: #564 put it in `encode.rs`
/// (an earlier version of this sentence said "in this same file", which
/// was already wrong at the split), and #569 path 2 deleted it outright
/// once the encode path began borrowing the subtree rather than
/// re-encoding and re-parsing it.
pub(super) fn value_to_unknown(v: &Value) -> Result<UnknownValue, ManifestError> {
    let mut buf = Vec::with_capacity(cbor_size_bound(v));
    ciborium::ser::into_writer(v, &mut buf)
        .map_err(|e| ManifestError::CborEncode(classify_ser(&e)))?;
    let buf = SecretBytes::new(buf);
    UnknownValue::from_canonical_cbor(buf.expose())
        .map_err(|e| ManifestError::CborDecode(record_error_to_cbor_fault(e)))
}

/// Collapse a [`RecordError`] raised by [`UnknownValue::from_canonical_cbor`]
/// into a [`CborFault`].
///
/// That call — ONE, not the two this doc named until #569 path 2 deleted
/// `unknown_value_inner`, which was this module's only
/// [`UnknownValue::to_canonical_cbor`] caller — is the only place
/// `ManifestError`'s CBOR variants are sourced from a lower-layer
/// `RecordError` rather than a raw
/// `ciborium::{de,ser}::Error` directly — `RecordError` itself has no
/// `#[from]`-worthy conversion to `ManifestError` (unlike `BlockError`,
/// which has a dedicated `Record(#[from] RecordError)` variant), so there is
/// no raw ciborium error left to hand to [`crate::cbor::classify_de`] / [`classify_ser`]
/// at this call site.
///
/// `RecordError::CborEncode` / `CborDecode` already carry a `CborFault`
/// (post-#474), so those two arms just unwrap it losslessly. The other
/// `RecordError` arms reachable here are `FloatRejected` / `TagRejected`
/// (raised by `reject_floats_and_tags` inside `from_canonical_cbor`) — a
/// well-formed CBOR item rejected on semantic (policy) grounds, which is
/// exactly what [`CborErrorKind::Semantic`] denotes. Every `RecordError`
/// variant is itself data-free (§474), so no branch here can leak content;
/// this only narrows the *type* to match `ManifestError`'s classified
/// payload.
///
/// The second arm is spelled out variant by variant rather than as a `_ =>`
/// wildcard, on the same exhaustive-match discipline the rest of #474
/// follows: a wildcard would silently classify a NEW `RecordError` variant
/// as [`CborErrorKind::Semantic`], which is a correctness question a human
/// should answer once rather than a default that answers itself. Nothing
/// here reads a variant's fields, so this is a diagnostics-accuracy gate,
/// not a leak gate.
fn record_error_to_cbor_fault(e: RecordError) -> CborFault {
    match e {
        RecordError::CborEncode(fault) | RecordError::CborDecode(fault) => fault,
        RecordError::NotAMap
        | RecordError::NonTextKey
        | RecordError::MissingField { .. }
        | RecordError::WrongType { .. }
        | RecordError::InvalidUuid { .. }
        | RecordError::IntegerOverflow { .. }
        | RecordError::DuplicateKey { .. }
        | RecordError::FloatRejected { .. }
        | RecordError::TagRejected
        | RecordError::NonCanonicalEncoding
        | RecordError::CanonicalSizeBoundExceeded { .. } => CborFault {
            kind: CborErrorKind::Semantic,
            offset: None,
        },
    }
}

#[cfg(test)]
mod tests;
