//! `SecretValueTree` / `SecretEntries` (#547 / #548, audit C-4): a
//! zeroize-on-drop wrapper for what `ciborium::de::from_reader` itself
//! allocates while parsing.
//!
//! `from_reader` builds a `ciborium::Value` tree that owns a copy of every
//! payload in the input — decrypted user plaintext on the record path
//! (#547), the four long-term secret keys on the identity-bundle path
//! (#548). That allocation belongs to the parser, not to any caller here,
//! and cannot be eliminated — only wiped before drop, which is what the two
//! types in this file do. Split out of `cbor/mod.rs` (#547 Task 3) once the
//! combined file passed the project's 500-line split threshold; see the
//! parent module's doc comment for how the two files divide the concern.
//!
//! **Why `SecretValueTree` / `SecretEntries` are declared `pub` rather than
//! `pub(crate)`, even though nothing outside this crate is meant to use
//! them.** Task 3 ships this mechanism with no production consumer — Task 6
//! wires up `SecretValueTree`, Task 7 wires up `SecretEntries` — so, for the
//! span of this one commit, nothing anywhere in `core/src/**` calls `new`,
//! `as_value`, `len`, `is_empty`, `as_slice`, or `take_next`. A `pub(crate)` item with no
//! caller reachable from within the SAME compilation is exactly what
//! `dead_code` is designed to flag, and it does: verified by execution,
//! `cargo build --release -p secretary-core` reds with six warnings — five
//! `dead_code` (both structs never constructed, `wipe_value` never used, and
//! the two structs' associated functions never used, one grouped warning
//! each) plus one `unused_imports` for a `pub(crate) use` re-export at the
//! top of [`super`] — the moment these are `pub(crate)` with that re-export
//! narrowed to match. Declaring them `pub` and exposing them
//! through [`super::cbor_test_api`] — a second, genuinely-`pub` re-export
//! chain reachable from the crate root, `#[doc(hidden)]` so it does not
//! appear in rendered docs — resolves it: a `pub` item reachable from the
//! crate root is a possible callee for a downstream crate the compiler
//! cannot see into, so `dead_code` does not fire regardless of whether
//! anything in THIS crate calls it. This is the exact pattern
//! `vault::canonical_test_api` used for `CanonicalMap`/`CanonicalValue` in
//! Task 2 of this same build sequence, for the identical reason: a type
//! shipped ahead of its first caller. [`super`] does **not** also carry a
//! `pub(crate) use secret_tree::{SecretValueTree, SecretEntries};` for the
//! same reason: nothing in `core/src/**` names `crate::cbor::SecretValueTree`
//! yet either, so that re-export would itself be flagged `unused_imports`
//! today — it is Task 6/7's to add, alongside their first real call site.
//! `core/tests/secret_value_tree_black_box.rs` is a genuine external caller
//! through the [`super::cbor_test_api`] path (not merely an unused
//! re-export sitting there for the lint's benefit); the wipe itself cannot
//! be observed from outside the crate, since `--cfg test` is not propagated
//! to dependent crates and `wipe_for_test`/`wipe_calls` are `#[cfg(test)]`
//! — that half stays covered by the unit tests below instead.

use ciborium::Value;

#[cfg(test)]
thread_local! {
    /// Counts wipe invocations so a test can prove `Drop` calls one.
    ///
    /// Without this, `impl Drop` can be DELETED with every test still
    /// passing — verified by mutation on the `ZeroizingEntries` predecessor
    /// (#546), where the only thing that noticed was an incidental
    /// `dead_code` lint that evaporates the moment the wipe gains a second
    /// caller. The security claim is specifically that `Drop` covers the
    /// unwinding and early-return paths, so `Drop` is what needs pinning.
    static WIPE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Number of wipes performed so far on this thread. Test-only.
#[cfg(test)]
pub(crate) fn wipe_calls() -> usize {
    WIPE_CALLS.with(std::cell::Cell::get)
}

/// Recursively zeroize every `Bytes` and `Text` payload in a `Value` tree.
///
/// Walks `Array` and `Map` (both keys and values — a forward-compat map could
/// in principle key on a byte string, and `record.fields` keys are
/// user-authored field names living *inside* an encrypted record, i.e.
/// decrypted plaintext per the #474 section of `CLAUDE.md` — the key side is
/// not a lower-value recursion to skip). Scalars carry no heap payload.
///
/// `ciborium::Value` is `#[non_exhaustive]`, so the wildcard arm below is
/// mandatory and will never warn when a new variant appears. The test
/// `every_ciborium_value_variant_is_accounted_for` pins the current variant
/// count as a hand-maintained tripwire for a *removed or renamed* variant
/// (that fails to compile); it does **not** detect an *added* one — see that
/// test's doc comment for why, stated precisely rather than implied.
///
/// Recurses without an explicit depth bound, for the same reason
/// [`crate::vault::canonical::reject_floats_and_tags`] does: `ciborium`'s
/// default `from_reader` recursion limit (256) has already capped the depth of
/// any parsed tree. Raising that limit requires adding a `depth` parameter
/// here too.
fn wipe_value(value: &mut Value) {
    use zeroize::Zeroize as _;
    match value {
        Value::Bytes(b) => b.zeroize(),
        Value::Text(t) => t.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_value),
        Value::Map(entries) => entries.iter_mut().for_each(|(k, v)| {
            wipe_value(k);
            wipe_value(v);
        }),
        // Integer / Float / Bool / Null carry no heap payload; `Tag`'s only
        // heap content is its boxed child, covered by recursing into it.
        Value::Tag(_, inner) => wipe_value(inner),
        _ => {}
    }
}

/// A parsed CBOR tree whose byte-string and text payloads are zeroized on
/// drop.
///
/// `ciborium::de::from_reader` returns a `Value` tree that owns copies of
/// every payload in the input. On the record path that is decrypted user
/// plaintext (#547); on the identity-bundle path it is the four long-term
/// secret keys (#548). Neither allocation can be eliminated — the parser owns
/// it — so it is wiped instead.
///
/// `Drop` is the mechanism, deliberately: it covers an unwinding panic and
/// every `?` early return, which a trailing wipe statement does not. #548 is
/// exactly that gap on the bundle read side, where an early `?` inside the
/// field loop freed up to three not-yet-consumed secret keys unwiped.
///
/// # What this does not claim
///
/// A wipe of freed heap is not observable from safe Rust, and neither is a
/// reallocation `ciborium`'s parser performed before we ever saw the value.
/// This covers the buffer the tree points at when it drops.
///
/// # Why there is no `&mut` or consuming accessor
///
/// There is deliberately no way to get the inner `Value` out by value or by
/// `&mut`. `.clear()`, `.drain(..)`, `mem::take` and whole-field reassignment
/// each free the element buffers unwiped, and
/// `scripts/check-secret-slot-hygiene.sh` matches `mem::*` and `ManuallyDrop`
/// but not the first two. The API shape is the enforcement — same reasoning as
/// `ZeroizingEntries` (#542) and the FFI bridge's `Detail` newtype
/// (#500/#515).
pub struct SecretValueTree(Value);

impl SecretValueTree {
    /// Take ownership of a parsed tree.
    pub fn new(value: Value) -> Self {
        Self(value)
    }

    /// Read-only view. Deliberately the only way out — see the type docs.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// Wipe now, without waiting for the drop. Test-only: production code
    /// relies on `Drop` precisely because it cannot be skipped.
    #[cfg(test)]
    pub(crate) fn wipe_for_test(&mut self) {
        self.wipe();
    }

    fn wipe(&mut self) {
        #[cfg(test)]
        WIPE_CALLS.with(|c| c.set(c.get() + 1));
        wipe_value(&mut self.0);
    }
}

impl Drop for SecretValueTree {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// A parsed CBOR map's entry list, wiped on drop.
///
/// Same contract as [`SecretValueTree`], for the shape decoders actually
/// consume: they destructure the top-level `Value::Map` into its
/// `Vec<(Value, Value)>` and iterate. [`Self::take_next`] hands out one
/// entry at a time so the decoder can move values out, while everything
/// NOT yet consumed stays under this type's `Drop`.
pub struct SecretEntries(Vec<(Value, Value)>);

impl SecretEntries {
    /// Take ownership of an entry list.
    pub fn new(entries: Vec<(Value, Value)>) -> Self {
        Self(entries)
    }

    /// Number of entries currently held (shrinks as [`Self::take_next`]
    /// drains the front).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether every entry has been drained. Required by
    /// `clippy::len_without_is_empty` once [`Self::len`] is `pub`; also the
    /// check [`Self::take_next`] itself uses.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Read-only view of every entry currently held.
    pub fn as_slice(&self) -> &[(Value, Value)] {
        &self.0
    }

    /// Yield entries one at a time. Wiping each as it is handed out is NOT
    /// what happens — the consumer needs the value intact. What this
    /// guarantees is that every entry NOT yet yielded remains owned by
    /// `self`, so an early `?` in the consumer's loop drops `self` and wipes
    /// the remainder. That is precisely #548.
    ///
    /// Implemented as an index-0 removal rather than `Vec::drain` because
    /// `drain` borrows the whole vec for the iterator's lifetime, which
    /// prevents `self` from being dropped mid-iteration.
    ///
    /// `remove(0)` shifts every remaining element down, so draining the
    /// whole list is O(n²) rather than the O(n) a `VecDeque::pop_front`
    /// would give. Left as `Vec` deliberately: the call sites this backs
    /// (Task 6/7) drain an identity bundle's ~9 top-level fields or one
    /// record's field map, both small enough that the difference is
    /// immaterial, and `swap_remove(0)` was rejected because it would
    /// reorder the remaining entries, destabilising the `enumerate()`
    /// indices some error messages cite. Revisit if a future caller ever
    /// drains a map whose size is not bounded by ordinary vault content.
    pub fn take_next(&mut self) -> Option<(Value, Value)> {
        if self.is_empty() {
            return None;
        }
        Some(self.0.remove(0))
    }
}

impl Drop for SecretEntries {
    fn drop(&mut self) {
        #[cfg(test)]
        WIPE_CALLS.with(|c| c.set(c.get() + 1));
        for (k, v) in &mut self.0 {
            wipe_value(k);
            wipe_value(v);
        }
    }
}

#[cfg(test)]
mod tests;
