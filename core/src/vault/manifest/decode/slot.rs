//! Single-assignment slots for the manifest decoder's per-map key loops.
//!
//! RFC 8949 §5.4 forbids a repeated map key, and `docs/vault-format.md`
//! §4.2 lists the required keys of each of the manifest's five maps. Both
//! rules used to be hand-copied runtime idioms — one
//! `if slot.is_some() { return Err(DuplicateKey { .. }) }` per known key
//! and one `.ok_or(MissingField { .. })` per required field, 57 of them
//! across `decode/mod.rs` and `decode/entries.rs` (#568, #573).
//!
//! Nothing about `Option<T>` forced either. A new match arm writing
//! `slot = Some(take_u64(..)?)` directly compiled cleanly and silently
//! last-won.
//!
//! [`Once`] makes that unrepresentable rather than merely discouraged: its
//! field is private to this module, so no sibling can fill a slot except
//! through [`Once::set`], and no sibling can read one out except through
//! [`Once::require`] or [`Once::into_option`]. The same move
//! [`super::super::uniqueness`] makes for §4.2's repeated-value rules —
//! express it once, and deleting the one implementation reds every caller.
//!
//! State that scope exactly, because the wider claim is false: Rust
//! privacy is module-SUBTREE scoped, not file-scoped, so a DESCENDANT of
//! this module could write `Once(Some(v))` directly and bypass
//! [`Once::set`]. Only `tests` is declared here, and it is `#[cfg(test)]`.
//! The parsers this type exists to constrain — `decode/mod.rs` and
//! `decode/entries.rs` — are siblings, and for them the invariant is
//! absolute. #515 had to make the same distinction about `Detail`'s
//! private field in the FFI bridge; there it warranted a guard rule,
//! because that field is a security boundary. This one is a correctness
//! invariant on an already-trusted decoder, so the note is the control.
//!
//! ## Why a type and not a macro
//!
//! The idiom was deliberately *not* factored into a `macro_rules!` when it
//! was written (see the comments this module replaced). That reasoning was
//! sound and is unchanged: every hygiene guard in this repo reads TEXT,
//! not expanded macros, so an error construction inside a macro body is
//! invisible to any future rule that inspects one.
//!
//! A function body is ordinary text, so this satisfies that constraint
//! *better* than the status quo, not worse. After this module,
//! [`ManifestError::DuplicateKey`] and [`ManifestError::MissingField`] are
//! each constructed exactly once in the whole decoder, in plain source, in
//! one greppable file — instead of 31 and 26 near-identical copies.
//!
//! ## What this does not close
//!
//! The forward-compat `unknown`-subtree residual is untouched: no
//! duplicate-key check looks *inside* an [`UnknownValue`], at any level,
//! and that is deliberate (crypto-design §6.2 rules 1 and 5 are scoped to
//! material the reader interprets). [`UnknownBag`] rejects a repeat of the
//! bag's OWN key; it says nothing about the subtree hanging off it.

use std::collections::BTreeMap;

use crate::vault::manifest::ManifestError;
use crate::vault::record::UnknownValue;

/// The `field` reported when a forward-compat unknown key is repeated.
///
/// Never the repeated key itself: that text is attacker-influenced content
/// from inside the encrypted manifest, and `RecordError::DuplicateKey`
/// once leaked exactly this class (#474). A `&'static str` here keeps
/// [`ManifestError::DuplicateKey`] data-free by construction.
pub(super) const UNKNOWN_FIELD: &str = "<unknown>";

/// The one place a repeated manifest map key becomes an error.
///
/// Both slot types below reject a repeat, so without this the decoder
/// would hold two [`ManifestError::DuplicateKey`] construction sites
/// rather than one. Keeping it at one is the point of this module: it is
/// what makes "grep the decoder for where a duplicate key is rejected"
/// answer with a single line.
fn duplicate_key(field: &'static str, index: usize) -> ManifestError {
    ManifestError::DuplicateKey { field, index }
}

/// A decode slot that can be filled at most once.
///
/// Construct with [`Once::default`] (vacant); fill with [`Once::set`];
/// unwrap with [`Once::require`] for a §4.2-required field or
/// [`Once::into_option`] for an optional one.
pub(super) struct Once<T>(Option<T>);

// Hand-written rather than `#[derive(Default)]`: the derive would generate
// an `impl<T: Default> Default for Once<T>` bound, and none of the slot
// types this decoder uses (`[u8; 16]`, `Vec<BlockEntry>`, `KdfParamsRef`,
// ...) is required to implement `Default` for a slot to start out vacant.
impl<T> Default for Once<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T> Once<T> {
    /// Fill a vacant slot with `f()`, or reject `field` as a repeat.
    ///
    /// `index` is the ordinal of the repeated entry within the CBOR map,
    /// as reported by the caller's `enumerate()`.
    ///
    /// **`f` is evaluated only when the slot is vacant**, and that is the
    /// observable contract, not an implementation detail. The hand-copied
    /// guards this replaces checked `slot.is_some()` *before* parsing the
    /// second value, so a duplicate key whose second copy is malformed
    /// reported [`ManifestError::DuplicateKey`] and not
    /// [`ManifestError::WrongType`]. Taking the value eagerly — by
    /// parameter rather than by closure — would silently reverse that for
    /// a v1-frozen decoder, and no test in the tree caught it: every
    /// duplicate fixture repeats a well-typed pair.
    /// `set_does_not_evaluate_the_value_on_a_repeat` pins it here, and
    /// `entries::tests::a_duplicate_key_outranks_a_malformed_second_copy`
    /// pins it through the real parsers.
    pub(super) fn set<F>(
        &mut self,
        field: &'static str,
        index: usize,
        f: F,
    ) -> Result<(), ManifestError>
    where
        F: FnOnce() -> Result<T, ManifestError>,
    {
        if self.0.is_some() {
            return Err(duplicate_key(field, index));
        }
        self.0 = Some(f()?);
        Ok(())
    }

    /// Unwrap a §4.2-required field, or report it missing.
    pub(super) fn require(self, field: &'static str) -> Result<T, ManifestError> {
        self.0.ok_or(ManifestError::MissingField { field })
    }

    /// Unwrap an optional §4.2 field.
    ///
    /// Two fields in the manifest body are genuinely optional —
    /// `TrashEntry`'s `fingerprint` and `purged_at_ms` — and an absent key
    /// decodes to `None` and re-encodes to absent. They still get a
    /// [`Once`] slot, because optionality says nothing about repetition:
    /// a key that may be absent must still not appear twice.
    pub(super) fn into_option(self) -> Option<T> {
        self.0
    }
}

/// The forward-compat `unknown` bag of one manifest map.
///
/// A `BTreeMap` whose `insert` is wrapped so a repeated key is rejected
/// rather than silently last-winning, for the same reason [`Once`] exists:
/// `BTreeMap::insert` returns the displaced value, and three call sites
/// each remembered to check it by hand.
#[derive(Default)]
pub(super) struct UnknownBag(BTreeMap<String, UnknownValue>);

impl UnknownBag {
    /// Insert an unknown key, or reject it as a repeat.
    ///
    /// `value` is taken **eagerly**, unlike [`Once::set`]'s closure. That
    /// is deliberate and preserves the pre-existing ordering exactly: the
    /// caller's `value_to_unknown(v)?` has always run before
    /// `BTreeMap::insert` could report the duplicate, and `decode/mod.rs`
    /// documents that ordering as unobservable — `value_to_unknown`'s own
    /// failure would have to be raised before a duplicate could be
    /// reported by any ordering.
    pub(super) fn insert(
        &mut self,
        key: String,
        value: UnknownValue,
        index: usize,
    ) -> Result<(), ManifestError> {
        if self.0.insert(key, value).is_some() {
            return Err(duplicate_key(UNKNOWN_FIELD, index));
        }
        Ok(())
    }

    /// The accumulated bag, for the parsed entry's `unknown` field.
    pub(super) fn into_map(self) -> BTreeMap<String, UnknownValue> {
        self.0
    }
}

#[cfg(test)]
mod tests;
