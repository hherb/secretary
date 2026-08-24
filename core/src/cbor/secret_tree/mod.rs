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
//! Both types are `pub(crate)`, per the brief. Through Task 3 (fix round 1,
//! controller ruling R12) this whole module was declared `#[cfg(test)]` at
//! `super::secret_tree`, because it shipped with no production consumer at
//! all — `#[cfg(test)]` means an item simply does not exist in `cargo build
//! --release` or in `cargo clippy --workspace` without `--tests`, so there
//! is nothing for `dead_code` to flag; under `--tests` it is compiled and
//! fully exercised by the unit tests in `tests.rs`. An earlier version of
//! this module made both types fully `pub` instead, with a `#[doc(hidden)]
//! pub` re-export reachable from the crate root (the same
//! `dead_code`-avoidance pattern `vault::canonical_test_api` uses for
//! `CanonicalMap` / `CanonicalValue`) — reverted because it put a
//! third-party `#[non_exhaustive]` enum (`ciborium::Value`) into three
//! public function signatures of a crate whose stated purpose is
//! decades-long readability; `#[doc(hidden)]` hides an item from rendered
//! docs, not from the semver surface, so a `ciborium` 0.3 would have become
//! a breaking change to `secretary-core`. `#[cfg(test)]` adds no such
//! surface.
//!
//! Task 6 (#547) gives `SecretValueTree` its first real production caller
//! (`record::decode` / `block::decode_plaintext`), so the module-level gate
//! moved up one level to `cbor/mod.rs`'s `mod secret_tree;` line, and this
//! file's `SecretValueTree` definition is unconditionally compiled.
//! `SecretEntries` still has no production caller — Task 7 wires it in —
//! so its struct/impl/`Drop` definitions below stay individually
//! `#[cfg(test)]`-gated instead: same reasoning as the module-level gate
//! this paragraph describes, just scoped to the one type that still needs
//! it. Task 7 deletes that narrower gate at the point `SecretEntries`
//! gains a real call site.

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
/// any tree that came from a parse. Raising that limit requires adding a
/// `depth` parameter here too.
///
/// [`SecretValueTree::new`] does not itself enforce that limit — it accepts
/// any hand-built `Value`, parsed or not — but this is not a NEW hazard this
/// function introduces: `ciborium::Value`'s own `Drop` recurses the same
/// tree to the same depth to free it (a `Vec`/`Box`/`String` inside a
/// `Value` is dropped by walking into it), so a tree deep enough to blow the
/// stack here was already deep enough to blow it on the ordinary drop path,
/// with or without this wrapper.
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
/// This covers the buffer the tree points at when it drops. Concretely, that
/// bounds the claim in two more ways worth naming rather than leaving
/// implicit: an inline scalar (`Integer` / `Float` / `Bool` / `Null`) is
/// never overwritten, because it carries no heap payload to begin with —
/// nothing to wipe, not a gap; and the `Vec` SPINES of an `Array` / `Map`
/// (the buffer holding the element pointers themselves, as opposed to the
/// `Bytes`/`Text` payloads those elements point to) are freed unwiped when
/// `Vec::drop` runs — again correct behaviour, not a residual, because a
/// spine holds pointers and lengths, not secret bytes.
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
pub(crate) struct SecretValueTree(Value);

impl SecretValueTree {
    /// Take ownership of a parsed tree.
    pub(crate) fn new(value: Value) -> Self {
        Self(value)
    }

    /// Read-only view. Deliberately the only way out — see the type docs.
    pub(crate) fn as_value(&self) -> &Value {
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
/// Same allocation-source and `Drop`-is-the-mechanism rationale as
/// [`SecretValueTree`] (see that type's doc comment), for the shape
/// decoders actually consume: they destructure the top-level `Value::Map`
/// into its `Vec<(Value, Value)>` and iterate. [`Self::take_next`] hands out
/// one entry at a time so the decoder can move values out, while everything
/// NOT yet consumed stays under this type's `Drop`.
///
/// Unlike `SecretValueTree`, this type DOES have a consuming accessor —
/// [`Self::take_next`] — because the decoder genuinely needs to move each
/// entry's key/value out to build its result. That is a real, deliberate
/// gap in wipe coverage, not an oversight: **a yielded entry leaves this
/// type's protection entirely** the moment `take_next` returns it, and nothing
/// wipes it from that point on. Task 7, which consumes this, must fold a
/// yielded value straight into a `SecretBytes`/`SecretString` (or discard
/// it) rather than clone it into some other unwiped local first — cloning
/// would recreate exactly the residue this type exists to avoid.
///
/// `#[cfg(test)]`-gated (struct, impl, and `Drop` below — not the whole
/// module; see the module doc): Task 6 (#547) gives `SecretValueTree` its
/// first production caller but leaves this type's own with none, so an
/// unconditional build would flag every method here `dead_code` under
/// `-D warnings`. Task 7 deletes this gate at the point it gains one.
#[cfg(test)]
pub(crate) struct SecretEntries(Vec<(Value, Value)>);

#[cfg(test)]
impl SecretEntries {
    /// Take ownership of an entry list.
    pub(crate) fn new(entries: Vec<(Value, Value)>) -> Self {
        Self(entries)
    }

    /// Number of entries currently held (shrinks as [`Self::take_next`]
    /// drains the front).
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether every entry has been drained. Required by
    /// `clippy::len_without_is_empty` once [`Self::len`] exists; also the
    /// check [`Self::take_next`] itself uses.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Read-only view of every entry currently held.
    pub(crate) fn as_slice(&self) -> &[(Value, Value)] {
        &self.0
    }

    /// Yield entries one at a time. Wiping each as it is handed out is NOT
    /// what happens — the consumer needs the value intact, and once yielded
    /// it is the CALLER's responsibility (see the type doc's note on
    /// `SecretBytes`/`SecretString`). What this guarantees is that every
    /// entry NOT yet yielded remains owned by `self`, so an early `?` in the
    /// consumer's loop drops `self` and wipes the remainder. That is
    /// precisely #548.
    ///
    /// Implemented as an index-0 removal rather than `Vec::drain` because
    /// `drain` borrows the whole vec for the iterator's lifetime, which
    /// prevents `self` from being dropped mid-iteration.
    ///
    /// `remove(0)` shifts every remaining element down, so draining the
    /// whole list is O(n²) rather than the O(n) a `VecDeque::pop_front`
    /// would give. Left as `Vec` deliberately, but the "bounded" claim needs
    /// stating precisely: an identity bundle's ~9 top-level fields (#548)
    /// are owner-authored and genuinely small, but a record's field map
    /// (#547) is decoded from a BLOCK — and a block can be shared with
    /// multiple recipients who each have write access, with their edits
    /// reaching the vault's owner via sync/CRDT merge. So a record's field
    /// count is, in general, authored by whichever contact last wrote to
    /// that block, not necessarily the vault's owner, and this type cannot
    /// assume it is small. A maliciously large field map here is a HANG
    /// (CPU time), not a plaintext leak — the O(n²) cost is paid before any
    /// secret escapes this type's protection — but that is a real
    /// availability concern a future task should confirm is bounded
    /// elsewhere (a record field-count limit, if one exists) before relying
    /// on "ordinary vault content" as an implicit size cap. `swap_remove(0)`
    /// was rejected because it would reorder the remaining entries,
    /// destabilising the `enumerate()` indices some error messages cite.
    pub(crate) fn take_next(&mut self) -> Option<(Value, Value)> {
        if self.is_empty() {
            return None;
        }
        Some(self.0.remove(0))
    }

    /// Wipe now, without waiting for the drop. Test-only, same reasoning as
    /// [`SecretValueTree::wipe_for_test`]: production code relies on `Drop`
    /// precisely because it cannot be skipped.
    #[cfg(test)]
    pub(crate) fn wipe_for_test(&mut self) {
        self.wipe();
    }

    fn wipe(&mut self) {
        #[cfg(test)]
        WIPE_CALLS.with(|c| c.set(c.get() + 1));
        for (k, v) in &mut self.0 {
            wipe_value(k);
            wipe_value(v);
        }
    }
}

#[cfg(test)]
impl Drop for SecretEntries {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests;
