//! Strict canonical CBOR decode path for the manifest body
//! (`docs/vault-format.md` §4.2).

// Every `Once::set` / `UnknownBag::insert` call in this subtree must
// propagate its `Result` — that Result IS the duplicate-key rejection. A
// bare `slot.set(..);` is already caught, because `Result` is `#[must_use]`
// and CI runs `-D warnings`; `let _ = slot.set(..)` is NOT, because that is
// the sanctioned way to discard a must-use value and rustc deliberately
// stays quiet. This lint is the only thing that closes it, and it is a
// `restriction`-group lint, so it is off unless asked for.
//
// The consequence of dropping one is fail-CLOSED but not free: the #572
// re-encode still rejects the body (a dropped duplicate leaves the two
// values un-merged, so the re-encode diverges), but the precise
// `DuplicateKey { field, index }` degrades to a generic
// `NonCanonicalEncoding { cause: Unclassified }` — on the path every vault
// open takes, which is the diagnostic regression #590 exists to prevent.
#![deny(clippy::let_underscore_must_use)]

mod classify;
mod entries;
mod extract;
mod slot;

// `pub(super) use extract::record_error_to_cbor_fault;` stood here from the
// #564 split until #569 path 2. It existed for exactly one cross-boundary
// caller — `encode::unknown_value_inner`, which re-encoded a forward-compat
// unknown subtree through `UnknownValue::to_canonical_cbor` and had to
// classify the resulting `RecordError`. That function is deleted (the encode
// path borrows the subtree instead), so the re-export had no users left and
// the helper is now file-private to `extract.rs`, its one remaining caller
// (`value_to_unknown`) being in that same file. Task 1's own report
// anticipated this: the widening to `pub(in crate::vault::manifest)` was
// recorded there as existing solely for `encode.rs`.

use ciborium::Value;

use crate::cbor::SecretValueTree;
use crate::vault::canonical::reject_floats_and_tags;

use self::classify::classify_non_canonical;
use self::entries::{parse_blocks, parse_kdf_params, parse_trash, parse_vector_clock};
use self::extract::{take_fixed_bytes, take_text_key, take_u16, take_u8, value_to_unknown};
use self::slot::{Once, UnknownBag};
use super::encode::encode_manifest;
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
/// 11. No CBOR map anywhere in the manifest body has a duplicate key
///     (RFC 8949 §5.4): the top-level map (#568) AND each of the four
///     nested per-entry maps — `parse_vector_clock_entry`,
///     `parse_block_entry`, `parse_trash_entry`, `parse_kdf_params`
///     (#573) — reject their own repeated key rather than silently
///     last-winning. **Residual, not closed by any of the fixes here**:
///     no DUPLICATE-KEY check looks inside a forward-compat `unknown`
///     subtree, at any level. Scope that precisely — other checks DO
///     walk in: this function's own tree-wide `reject_floats_and_tags`
///     call below covers every unknown subtree for floats and tags, and
///     item 12 catches encoding-level non-canonicality inside one (see
///     the check site). What survives is a duplicate key, and map key
///     ORDER, inside such a subtree. See
///     [`ManifestError::DuplicateKey`]'s doc for the full account,
///     including what a prior version of both this item and that variant's
///     doc got wrong about `record.rs` / `block.rs`'s own coverage.
/// 12. The input is canonical: re-encoding the parsed [`Manifest`]
///     reproduces `bytes` exactly (#572). Same backstop `record::decode`
///     and `block::decode_plaintext` have applied since the format was
///     frozen, and it is what enforces vault-format §4.2's map-key
///     order, definite lengths, shortest-form prefixes and array sort
///     disciplines (§4.3 step 4). Runs LAST, after every check above, so
///     a precise typed error always wins over the generic
///     [`ManifestError::NonCanonicalEncoding`] — see the check site for
///     what that ordering buys and for the exact, narrow set it does not
///     catch.
///
/// Forward-compat unknown KEYS are preserved into the relevant `unknown`
/// bag. Their VALUES are preserved up to CBOR-encoding normalisation, not
/// byte-verbatim: `ciborium`'s `Value` reader normalises the whole body
/// on parse, so a subtree's entry order and repeated keys survive while
/// its indefinite-length and non-shortest-form encodings do not (and, as
/// of item 12, are rejected outright).
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

    let manifest = parse_manifest_map(entries)?;

    // Strict canonical-input check: re-encode the parsed representation
    // and require a byte-identical match (#572). Exactly what
    // `record::decode` and `block::decode_plaintext` do; this decoder
    // was the odd one out, and #575's design spec asserted otherwise.
    //
    // `parsed` is still alive here — `entries` borrows out of it and
    // `manifest` is fully owned — so its `SecretValueTree::drop` still
    // covers the whole tree past this point, on all THREE exits below:
    // the `?` on `encode_manifest`, the `NonCanonicalEncoding` return,
    // and the `Ok`.
    //
    // Catches: indefinite-length items (which `ciborium`'s `Value`
    // reader normalises on parse, so a diverging re-encode is the only
    // signal), map keys out of RFC 8949 §4.2.1 order, non-shortest-form
    // integer and length prefixes, and — specific to this layer — any
    // array that did not arrive in the sort order vault-format §4.2
    // ("Array element order is normative") fixes for it, because
    // `encode_manifest` sorts all five on output.
    //
    // It does NOT catch §4.2's OTHER array-level rule — the four
    // repeated-value prohibitions — and the sort clause above is exactly
    // the sentence that invites the opposite inference. Sortedness and
    // distinctness are independent (`[x, x]` IS sorted), and a body
    // carrying a repeat re-encodes to itself byte for byte, so this
    // comparison never fires on one. They are enforced EARLIER, by the
    // adjacent-equality scans in `entries.rs`
    // (`DuplicateBlockUuid` / `DuplicateTrashUuid` /
    // `VectorClockDuplicateDevice`) — the same standing-apart-from-the-
    // re-encode arrangement `reject_floats_and_tags` has for rule 4. Do
    // not delete one of those scans as redundant with this check; the
    // clean-room Python reader made precisely that inference and accepted
    // four bodies this decoder rejects (#594).
    //
    // What this does NOT catch, stated exactly, because the obvious
    // wider claim is FALSE: **duplicate keys and map key ORDER** inside
    // a forward-compat `unknown` subtree. Nothing else — of what still
    // REACHES this comparison. A tag or a float inside such a subtree is
    // not caught by the comparison either (a normalising parse preserves
    // both and re-encodes them identically), but neither ever gets here:
    // `reject_floats_and_tags` above walks the whole body, subtrees
    // included, and has already rejected them. The residual is therefore
    // the decoder's, not merely this check's — which is the claim that
    // matters, and the one the paragraph below spells out. An earlier
    // version of this comment said "a duplicate key — or any other
    // non-canonical shape — … the comparison is equal no matter what is
    // inside them", which is wrong, and wrong in the direction that
    // matters (it promises a v2 author more latitude than they have).
    //
    // The reason is the `from_secret_reader` call at the TOP of this
    // function, not anything the unknown-key path does. `ciborium`'s
    // `Value` reader collapses indefinite lengths and non-shortest-form
    // heads on parse, so by the time any subtree is examined it is
    // ALREADY the normalisation of the wire bytes; re-encoding emits
    // that normalisation and the comparison diverges. Only properties
    // `ciborium::Value` can still represent survive — and `Value::Map`
    // is an ordered `Vec` of pairs, so entry order and repeats do, while
    // encoding-level choices do not.
    //
    // Do NOT attribute this to `extract::value_to_unknown`'s
    // re-serialise/re-parse hop, as an earlier version of this comment
    // did. That hop is an IDENTITY on an already-parsed `Value`:
    // measured, `value_to_unknown(v).as_value() == &v` for all eight
    // shapes below. Two further measurements pin the real cause —
    // `ciborium` parse-then-serialise alone changes the bytes for every
    // encoding-level shape and for neither order-carrying one, and
    // `record.rs`, which has NO such hop (it stores
    // `UnknownValue(v.clone())` directly), gives identical results on
    // all eight. `RecordError::NonCanonicalEncoding`'s own
    // doc has said this correctly all along: "`ciborium`'s `Value`
    // reader normalises these to definite-length **on parse**".
    //
    // Measured, not argued (#572 review rounds 1-2): splicing a subtree
    // into an otherwise-valid manifest, `BF..FF` (indefinite map),
    // `18 01` (non-shortest int), `7F..FF` (indefinite text), `5F..FF`
    // (indefinite bytes), `9F..FF` (indefinite array) and `B8 01`
    // (non-shortest map length) each yield `NonCanonicalEncoding`; only
    // a duplicate key and a disordered key pair still decode `Ok`.
    //
    // **Forward-compat consequence, which is a real constraint on future
    // format extensions**: a v2 client that writes ANY indefinite-length
    // or non-shortest-form item inside an unknown subtree produces a
    // vault a v1 client cannot open at all. Unknown subtrees must stay
    // inside the deterministic profile (crypto-design §6.2), exactly
    // like the rest of the body. What is genuinely unpoliced is narrow:
    // a duplicate key or a disordered key pair inside one.
    // `UnknownValue`'s only validation is `reject_floats_and_tags`
    // (which DOES walk inside — as does this function's own tree-wide
    // `reject_floats_and_tags` call above; the residual is that no
    // DUPLICATE-KEY check does, #573's residual, not that nothing walks
    // in at all).
    //
    // `encode_manifest` returns `SecretBytes`, so this full re-encoding
    // of the decrypted manifest body — every `block_name` included — is
    // wrapped BY CONSTRUCTION; there is no separate `SecretBytes::new`
    // call here for a future edit to drop (#558, #565).
    let re_encoded = encode_manifest(&manifest)?;
    if re_encoded.expose() != bytes {
        // The comparison above is the whole verdict. `classify_non_canonical`
        // runs only once it has already decided to reject, and turns the two
        // buffers plus the parsed manifest into a cause and a byte locator
        // (#590) — a diagnostic, never an acceptance decision. Before #590
        // this was a fieldless variant naming four candidate causes with
        // "e.g." and no position at all.
        //
        // The cause is DECISIVE, not positional: it comes from the parsed
        // manifest's array order or from a walk of the whole input, never
        // from the byte at the divergence. Reading that byte as a CBOR head
        // — the first version of `classify` — is unsound whenever the
        // divergence lands inside a string payload, which is exactly where
        // map-key disorder puts it, and `unknown` keys are peer-supplied.
        let (cause, at) = classify_non_canonical(&manifest, bytes, re_encoded.expose());
        return Err(ManifestError::NonCanonicalEncoding { cause, at });
    }

    Ok(manifest)
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
    let mut manifest_version: Once<u8> = Once::default();
    let mut vault_uuid: Once<[u8; UUID_LEN]> = Once::default();
    let mut format_version: Once<u16> = Once::default();
    let mut suite_id: Once<u16> = Once::default();
    let mut owner_user_uuid: Once<[u8; UUID_LEN]> = Once::default();
    let mut vector_clock: Once<Vec<VectorClockEntry>> = Once::default();
    let mut blocks: Once<Vec<BlockEntry>> = Once::default();
    let mut trash: Once<Vec<TrashEntry>> = Once::default();
    let mut kdf_params: Once<KdfParamsRef> = Once::default();
    let mut unknown = UnknownBag::default();

    // RFC 8949 §5.4: reject a repeated key rather than last-wins.
    //
    // The check is no longer written out per arm. Each known key holds a
    // [`Once`] slot whose inner `Option` is private to `slot.rs`, so an
    // arm CANNOT fill one except through `Once::set` — the rejection is a
    // type invariant rather than nine hand-copied `slot.is_some()` guards
    // a new arm could forget (#589). The unknown bag gets the same
    // treatment via [`UnknownBag`].
    //
    // The macro objection that kept the guards inline (#575) is unchanged
    // and is *satisfied* by this, not traded away: every hygiene guard in
    // this repo reads TEXT, not expanded macros, so an error construction
    // inside a `macro_rules!` body would be invisible to any future rule
    // that inspects one. A function body is ordinary text —
    // `ManifestError::DuplicateKey` and `ManifestError::MissingField` are
    // now each constructed exactly once in the whole decoder, in
    // `slot.rs`, instead of 31 and 26 near-identical copies.
    //
    // `field` stays `&'static str` throughout: for a known key it is the
    // §4.2 `KEY_*` constant the arm passes, and for an unknown key it is
    // `UNKNOWN_FIELD`, private to `slot.rs` — never the repeated key
    // itself, which is
    // attacker-influenced text from inside the encrypted manifest and
    // exactly the class `RecordError::DuplicateKey` once leaked (#474).
    //
    // `Once::set` takes a CLOSURE, so the fill runs only on a vacant slot.
    // That preserves the pre-#589 ordering exactly: a duplicate key whose
    // second copy is malformed still reports `DuplicateKey`, not
    // `WrongType` (`tests::top_level_duplicate_key_outranks_a_malformed_second_copy`).
    for (index, (k, v)) in map.iter().enumerate() {
        let key = take_text_key(k)?;
        match key.as_str() {
            KEY_MANIFEST_VERSION => manifest_version.set(KEY_MANIFEST_VERSION, index, || {
                take_u8(v, KEY_MANIFEST_VERSION)
            })?,
            KEY_VAULT_UUID => vault_uuid.set(KEY_VAULT_UUID, index, || {
                take_fixed_bytes::<UUID_LEN>(v, KEY_VAULT_UUID)
            })?,
            KEY_FORMAT_VERSION => format_version.set(KEY_FORMAT_VERSION, index, || {
                take_u16(v, KEY_FORMAT_VERSION)
            })?,
            KEY_SUITE_ID => suite_id.set(KEY_SUITE_ID, index, || take_u16(v, KEY_SUITE_ID))?,
            KEY_OWNER_USER_UUID => owner_user_uuid.set(KEY_OWNER_USER_UUID, index, || {
                take_fixed_bytes::<UUID_LEN>(v, KEY_OWNER_USER_UUID)
            })?,
            KEY_VECTOR_CLOCK => vector_clock.set(KEY_VECTOR_CLOCK, index, || {
                parse_vector_clock(v, KEY_VECTOR_CLOCK)
            })?,
            KEY_BLOCKS => blocks.set(KEY_BLOCKS, index, || parse_blocks(v))?,
            KEY_TRASH => trash.set(KEY_TRASH, index, || parse_trash(v))?,
            KEY_KDF_PARAMS => kdf_params.set(KEY_KDF_PARAMS, index, || parse_kdf_params(v))?,
            _ => {
                // Unlike the nine arms above, the value is taken
                // EAGERLY: `value_to_unknown` has already re-encoded and
                // re-parsed it by the time `UnknownBag::insert` can report
                // the duplicate. `UnknownBag::insert` therefore takes a
                // value where `Once::set` takes a closure — deliberately,
                // to preserve this ordering unchanged.
                //
                // It is unobservable, but NOT for the reason an earlier
                // version of this comment gave ("the returned error is the
                // same, and `value_to_unknown`'s own failure would have to
                // be raised first by any ordering") — that is circular,
                // and lazily a repeated key whose second copy failed
                // `value_to_unknown` would report `DuplicateKey` instead.
                // The real reason is `reject_floats_and_tags` above: it
                // walks the whole body before this loop runs, so the only
                // failures `value_to_unknown` has are already gone. That
                // is an invariant of THIS function, not of the parsers —
                // see `slot::UnknownBag::insert` for the full statement.

                unknown.insert(key, value_to_unknown(v)?, index)?;
            }
        }
    }

    let manifest_version = manifest_version.require(KEY_MANIFEST_VERSION)?;
    if manifest_version != MANIFEST_VERSION_V1 {
        return Err(ManifestError::UnsupportedManifestVersion(manifest_version));
    }
    let format_version = format_version.require(KEY_FORMAT_VERSION)?;
    if format_version != FORMAT_VERSION_V1 {
        return Err(ManifestError::UnsupportedFormatVersion(format_version));
    }
    let suite_id = suite_id.require(KEY_SUITE_ID)?;
    if suite_id != SUITE_ID_V1 {
        return Err(ManifestError::UnsupportedSuiteId(suite_id));
    }

    Ok(Manifest {
        manifest_version,
        vault_uuid: vault_uuid.require(KEY_VAULT_UUID)?,
        format_version,
        suite_id,
        owner_user_uuid: owner_user_uuid.require(KEY_OWNER_USER_UUID)?,
        vector_clock: vector_clock.require(KEY_VECTOR_CLOCK)?,
        blocks: blocks.require(KEY_BLOCKS)?,
        trash: trash.require(KEY_TRASH)?,
        kdf_params: kdf_params.require(KEY_KDF_PARAMS)?,
        unknown: unknown.into_map(),
    })
}

#[cfg(test)]
mod tests;
