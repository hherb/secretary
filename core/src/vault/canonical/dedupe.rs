//! RFC 8949 §5.4 duplicate-map-key rejection for the `ciborium::Value`
//! encode paths, which do not funnel through [`super::value::to_canonical_vec`]
//! (#602).
//!
//! # Why this exists as its own module
//!
//! #586 made a repeated map key a rejection at `to_canonical_vec`, the choke
//! point the four VAULT-BODY encoders (manifest, record, block, bundle) share.
//! Three encoders sat outside it, and one of them is **signed**:
//! `identity::card`'s `signed_bytes` is the byte string the §8 hybrid
//! self-signature commits to. A caller could therefore build an *ambiguous*
//! signed document — one two conformant readers may resolve differently while
//! both accepting the signature.
//!
//! Nothing was exposed, because all the production call sites build their keys
//! from fixed `&'static str` literals. But that is a property of today's call
//! sites rather than of the encoder, which is the posture #586 exists to
//! replace, so the rule lives here once and [`super::legacy`]'s two entry
//! points call it. Seven hand-copies of one sentence from a frozen spec is how
//! two directions drift — see `vault::manifest::uniqueness`, the array-element
//! twin of this module (#600), for the same shape.
//!
//! # It makes an existing rule enforced, not a new rule
//!
//! No frozen-spec edit was needed, and that was checked rather than assumed.
//! `docs/crypto-design.md` §6.2 rule 5 forbids duplicate map keys flatly, and
//! §6.2's opening sentence binds "the §6 self-signed message, the §6.1
//! fingerprint input, … and `sender_pk_bundle` / `recipient_pk_bundle` in §7"
//! — which is exactly `ContactCard::signed_bytes`, `to_canonical_cbor` and
//! `pk_bundle_bytes`. Rule 5 also states outright that its reader-side scoping
//! is "not a licence for an encoder". The encoder was simply non-conformant.
//!
//! `sync::state::SyncState` is **not** in that enumeration — it is
//! OS-keystore persistence, not a `canonical_cbor(...)` byte string the spec
//! names — so it gains this check by sharing the helper, not by spec
//! obligation. Do not cite §6.2 for it.
//!
//! # The walk is unconditional, unlike #586's
//!
//! [`super::value::CanonicalMap`]'s check deliberately does **not** descend
//! into a `CanonicalValue::Borrowed` — a forward-compat `unknown` subtree,
//! where a repeated key is the documented v1 residual (§6.2 rules 1 and 5 are
//! scoped to material the reader *interprets*). That carve-out has no analogue
//! here, and the reason is structural rather than a judgement call: neither
//! production caller can carry such a subtree. `ContactCard` **rejects**
//! unknown fields outright (`CardError::UnknownField`), and `SyncState` has
//! two typed fields and no `unknown` bag. There is no v1-residual to narrow,
//! so this walk descends through every map and array it is given.
//!
//! # On materialising key bytes
//!
//! [`check_no_duplicate_keys`] encodes each key to sort it, so it allocates
//! key buffers — which [`super::value::to_canonical_vec`] pointedly does not,
//! because record field names are decrypted plaintext and a buffer that is
//! never built needs no wipe. That is fine here and must stay checked: both
//! production callers' keys are fixed literals, and each caller's own sort
//! already materialises the identical bytes, so this adds no new *class* of
//! exposure. A future production caller whose keys are plaintext belongs on
//! `CanonicalMap` / `to_canonical_vec`, not here.

use ciborium::Value;

use super::CanonicalError;

/// Reject `entries`, or any map nested below it, that carries the same key
/// twice (RFC 8949 §5.4, crypto-design §6.2 rule 5).
///
/// Keys are compared by their **encoded CBOR form**, the same basis
/// [`super::canonical_sort_entries`] and [`super::encode_canonical_map`] sort
/// on, so "adjacent after sorting" means "equal" and one pass over
/// consecutive pairs is exhaustive — there is no need to compare every pair.
///
/// The returned `index` is the ordinal of the **second** of the two equal
/// keys in canonical order, **within the map it was found in** — not a
/// running count across the walk. That matches
/// [`super::value::to_canonical_vec`] exactly, so one
/// [`CanonicalError::DuplicateKey`] means one thing whichever encoder raised
/// it.
///
/// Callers do **not** need to have sorted first: this sorts its own copy of
/// the keys. Requiring a pre-sorted input would split one rule into a
/// precondition and a sweep, which is the drift this module exists to
/// prevent.
pub(crate) fn check_no_duplicate_keys(entries: &[(Value, Value)]) -> Result<(), CanonicalError> {
    let mut keys: Vec<Vec<u8>> = entries
        .iter()
        .map(|(key, _)| {
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(key, &mut encoded)
                .map_err(|e| CanonicalError::CborEncode(crate::cbor::classify_ser(&e)))?;
            Ok(encoded)
        })
        .collect::<Result<_, CanonicalError>>()?;
    keys.sort();

    for (position, pair) in keys.windows(2).enumerate() {
        if pair[0] == pair[1] {
            // The SECOND of the two, so the ordinal names the entry that
            // made the map ambiguous rather than the one that was there
            // first.
            return Err(CanonicalError::DuplicateKey {
                index: position + 1,
            });
        }
    }

    for (_, value) in entries {
        check_value(value)?;
    }
    Ok(())
}

/// Recurse [`check_no_duplicate_keys`] through the arms that can contain a
/// map.
///
/// `Value::Tag` is walked even though [`super::reject_floats_and_tags`] means
/// no vault path should ever present one: an arm that silently skipped a
/// container would make the walk complete only for today's inputs, which is
/// the same "property of the call sites, not of the code" this module exists
/// to remove. `ciborium::Value` is `#[non_exhaustive]`, so the wildcard is
/// forced by the upstream type rather than chosen — a future container
/// variant would be skipped, which is why `reject_floats_and_tags` and the
/// typed decoders remain the primary constraint on what may appear at all.
fn check_value(value: &Value) -> Result<(), CanonicalError> {
    match value {
        Value::Map(entries) => check_no_duplicate_keys(entries),
        Value::Array(items) => items.iter().try_for_each(check_value),
        Value::Tag(_, inner) => check_value(inner),
        _ => Ok(()),
    }
}

/// The pre-#602 `identity::card::encode_map` body: sort by encoded key
/// bytes, emit an owned `Value::Map`, **without** the duplicate-key check.
///
/// Test-only, and it exists for the two jobs a checked encoder structurally
/// cannot do:
///
/// 1. **Hostile-peer fixtures.** A decoder test that proves a repeated key is
///    rejected needs bytes carrying one, and a sanctioned encoder must not be
///    able to produce them. Callers today:
///    `identity::card`'s `duplicate_field_names_the_spec_key_as_a_static_str`
///    and `vault::manifest::decode`'s `manifest_bytes_with_duplicate_nested_key`.
/// 2. **The byte-identity oracle** for the #602 migration — `signed_bytes`,
///    `to_canonical_cbor` and `pk_bundle_bytes` are each asserted equal to
///    this, so "the delegation changed no byte" is measured rather than
///    argued.
///
/// It is one function rather than a copy per test module deliberately: a
/// hand-copied encoder is exactly the drift this module exists to remove, and
/// a single `#[cfg(test)]` definition is greppable in a way three are not.
///
/// **It must never gain a production caller.** `#[cfg(test)]` is what keeps
/// it out of shipped artifacts; that is a build-configuration guarantee, not
/// a language one, so treat adding a caller outside a test module as the
/// security decision it is.
#[cfg(test)]
pub(crate) fn encode_map_allowing_duplicates(entries: &[(Value, Value)]) -> Vec<u8> {
    let mut sorted: Vec<(Vec<u8>, (Value, Value))> = entries
        .iter()
        .map(|pair| {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(&pair.0, &mut key_bytes).expect("encode key");
            (key_bytes, pair.clone())
        })
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let value = Value::Map(sorted.into_iter().map(|(_, pair)| pair).collect());
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf).expect("encode map");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Value {
        Value::Text(s.into())
    }

    fn uint(n: u64) -> Value {
        Value::Integer(n.into())
    }

    /// The core rejection, and the ordinal contract: `index` names the
    /// SECOND of the two equal keys in CANONICAL order, matching
    /// `to_canonical_vec`'s behaviour exactly (#586) so one
    /// `CanonicalError::DuplicateKey` means one thing whichever encoder
    /// produced it.
    #[test]
    fn a_map_repeating_a_key_is_rejected() {
        let entries = vec![
            (text("a"), uint(1)),
            (text("b"), uint(2)),
            (text("a"), uint(3)),
        ];
        match check_no_duplicate_keys(&entries) {
            // Canonical order is a, a, b — the second "a" sits at 1.
            Err(CanonicalError::DuplicateKey { index }) => {
                assert_eq!(index, 1, "the ordinal must name the SECOND occurrence");
            }
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    /// The duplicate need not be adjacent in ENTRY order — the check sorts
    /// first, which is the only reason a single adjacent-pair sweep is
    /// exhaustive. A checker comparing consecutive entries as given would
    /// pass this.
    #[test]
    fn a_duplicate_separated_in_entry_order_is_still_caught() {
        let entries = vec![
            (text("zz"), uint(1)),
            (text("a"), uint(2)),
            (text("yy"), uint(3)),
            (text("a"), uint(4)),
        ];
        match check_no_duplicate_keys(&entries) {
            // Canonical order is a, a, yy, zz — the second "a" sits at 1.
            // Asserted rather than `{ .. }`-waved so a checker reporting an
            // ENTRY-order ordinal (3) reds here.
            Err(CanonicalError::DuplicateKey { index }) => assert_eq!(index, 1),
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    /// Recursion through `Value::Map`. A top-level-only check encodes this
    /// happily — and a duplicate one level down is exactly as ambiguous to
    /// a reader as one at the top.
    #[test]
    fn a_duplicate_in_a_nested_map_is_caught() {
        let inner = Value::Map(vec![(text("k"), uint(1)), (text("k"), uint(2))]);
        let entries = vec![(text("outer"), inner)];
        match check_no_duplicate_keys(&entries) {
            // Scoped to the map it was FOUND in, per `DuplicateKey`'s doc —
            // not a running count across the walk.
            Err(CanonicalError::DuplicateKey { index }) => assert_eq!(index, 1),
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    /// Recursion through `Value::Array`. This is precisely
    /// `SyncState::to_canonical_cbor`'s shape — an array of per-device
    /// vector-clock entry maps — so a walk that stopped at `Map` would
    /// leave the one production caller with a nested map uncovered.
    #[test]
    fn a_duplicate_in_a_map_inside_an_array_is_caught() {
        let entry = Value::Map(vec![
            (text("device_uuid"), Value::Bytes(vec![0xAB; 16])),
            (text("device_uuid"), Value::Bytes(vec![0xCD; 16])),
        ]);
        let entries = vec![(text("highest_vector_clock_seen"), Value::Array(vec![entry]))];
        match check_no_duplicate_keys(&entries) {
            Err(CanonicalError::DuplicateKey { index }) => assert_eq!(index, 1),
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    /// Keys are compared by their ENCODED bytes, not by a text-only
    /// special case, so a repeated non-text key is caught too. `card.rs`
    /// and `sync::state` use text keys exclusively today; this pins that
    /// the rule does not silently become text-only if that changes.
    #[test]
    fn a_repeated_non_text_key_is_caught() {
        let entries = vec![
            (Value::Bytes(vec![1, 2]), uint(1)),
            (Value::Bytes(vec![1, 2]), uint(2)),
        ];
        match check_no_duplicate_keys(&entries) {
            Err(CanonicalError::DuplicateKey { index }) => assert_eq!(index, 1),
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    /// Two keys that share a PREFIX but differ are not a duplicate — the
    /// comparison is on the whole encoded key, not a prefix or a length.
    #[test]
    fn distinct_keys_sharing_a_prefix_are_accepted() {
        let entries = vec![
            (text("device"), uint(1)),
            (text("device_uuid"), uint(2)),
            (text("d"), uint(3)),
        ];
        assert!(check_no_duplicate_keys(&entries).is_ok());
    }

    /// The same key at two DIFFERENT levels is not a duplicate — the check
    /// is per-map, not a global key census. A card nests nothing today, but
    /// a walk that pooled keys across levels would reject legitimate
    /// documents.
    #[test]
    fn the_same_key_in_two_different_maps_is_accepted() {
        let inner = Value::Map(vec![(text("counter"), uint(1))]);
        let entries = vec![(text("counter"), uint(0)), (text("nested"), inner)];
        assert!(check_no_duplicate_keys(&entries).is_ok());
    }
}
