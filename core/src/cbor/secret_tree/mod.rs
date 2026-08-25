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
//! pub` re-export reachable from the crate root — at the time this
//! paragraph was written, the same `dead_code`-avoidance pattern
//! `vault::canonical_test_api` used for `CanonicalMap` / `CanonicalValue` —
//! reverted because it put a third-party `#[non_exhaustive]` enum
//! (`ciborium::Value`) into three public function signatures of a crate
//! whose stated purpose is decades-long readability; `#[doc(hidden)]` hides
//! an item from rendered docs, not from the semver surface, so a `ciborium`
//! 0.3 would have become a breaking change to `secretary-core`.
//! `#[cfg(test)]` adds no such surface. The final whole-branch review of
//! #547 later reached the same conclusion for `CanonicalMap` /
//! `CanonicalValue` themselves and retired `canonical_test_api` — see
//! `vault::canonical::value`'s module doc — so this is no longer a
//! divergence between the two modules, only a description of one that used
//! to exist.
//!
//! Task 6 (#547) gave `SecretValueTree` its first real production caller
//! (`record::decode` / `block::decode_plaintext`), so the module-level gate
//! moved up one level to `cbor/mod.rs`'s `mod secret_tree;` line, and this
//! file's `SecretValueTree` definition became unconditionally compiled.
//! Task 7 (#548) does the same for `SecretEntries`: its first production
//! caller is `unlock::bundle::IdentityBundle::from_canonical_cbor`, so its
//! struct/impl/`Drop` definitions below are no longer individually
//! `#[cfg(test)]`-gated either — same reasoning as the module-level gate
//! this paragraph describes, now applied to the one type that used to need
//! the narrower version of it. `wipe_for_test` stays `#[cfg(test)]`:
//! production code relies on `Drop` precisely because it cannot be skipped,
//! so a way to skip it is deliberately test-only.

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

/// Bump the shared wipe counter from a sibling module in `cbor`.
///
/// `WIPE_CALLS` is private to this module, but `scratch::CborScratch`
/// (#561) needs to record its own wipe against the same counter so a
/// caller's test can pin it through `crate::cbor::wipe_calls()`. Exposing
/// one `pub(super)` bump function is a smaller change than relocating the
/// counter into `cbor/mod.rs`, which would touch all three existing
/// bump sites — frozen-adjacent code this task has no reason to churn.
///
/// `#[cfg(test)]`-gated like every other bump site: zero production cost.
#[cfg(test)]
pub(super) fn note_wipe() {
    WIPE_CALLS.with(|c| c.set(c.get() + 1));
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

/// Wipe a single, already-`take_next`-yielded `Value` in place before
/// dropping it on a path that folds it into nothing.
///
/// [`SecretEntries::take_next`] documents the seam this exists for: a
/// yielded `(key, value)` pair leaves `SecretEntries`' own protection the
/// moment it is handed out, and it is the CALLER's job to either fold it
/// into a zeroizing wrapper (`Sensitive`/`SecretBytes`) or wipe it before
/// dropping it. A caller that does neither — because the value was never
/// examined at all, e.g. an unrecognised map key, or a key that failed a
/// shape check before any recognised-field arm ran — leaves it to a bare
/// `ciborium::Value` drop, unwiped. This is that second option, exposed so
/// a caller does not have to hand-roll the same recursive walk
/// [`wipe_value`] already performs (`unlock::bundle::from_canonical_cbor`'s
/// non-string-key and unknown-field early returns, #548 fix-round-1 G1).
///
/// Increments the same `WIPE_CALLS` counter [`SecretValueTree::wipe`] /
/// [`SecretEntries::wipe`] use, so a caller's test can pin that this ran
/// through `wipe_calls()` (test-only) — the same handle those two types'
/// own tests use, since a wipe of a soon-to-be-dropped local is not
/// otherwise observable from safe Rust.
pub(crate) fn wipe_leaked_value(value: &mut Value) {
    #[cfg(test)]
    WIPE_CALLS.with(|c| c.set(c.get() + 1));
    wipe_value(value);
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
/// field loop freed up to ALL FOUR not-yet-consumed secret keys unwiped —
/// canonical key order (RFC 8949 §4.2.1: shorter key first) puts
/// `user_uuid` and `x25519_pk` ahead of every secret key, so `Malformed` or
/// `UnknownField` on either of those two fires while none of the four
/// secret keys has been consumed yet. "Up to three" stood here until
/// fix-round-1 (this section's own review), an undercount inherited from
/// the memo on `main` — Task 8 owns correcting the memo itself.
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
/// Two more gaps in the same "not covered" family, named explicitly rather
/// than left inside the general reallocation clause above:
///
/// - **The parser's scratch buffer.** `ciborium::de::from_reader` stages
///   every payload of 4096 bytes or fewer through a `[0u8; 4096]` in its
///   own stack frame. That buffer is not part of the tree this type
///   wraps, so `Drop` here never reached it. As of #561 the secret-bearing
///   decode paths do not use `from_reader` at all — they route through
///   [`crate::cbor::from_secret_reader`], which owns that buffer and wipes
///   it. See `super::scratch`'s module doc for the mechanism.
/// - **Reallocation inside the parser's visitor, which is ROUTINE above
///   4 KiB, not an edge case.** The general reallocation clause above
///   already names this class; the threshold is the part a reader needs.
///   `ciborium`'s `deserialize_byte_buf` / `deserialize_string` build the
///   final payload with `Vec::new()` / `String::new()` plus per-chunk
///   `extend_from_slice`, so a payload larger than the parser's scratch
///   buffer still grows by doubling and frees an unwiped prefix at each
///   step — measured, by execution (`Vec<u8>::extend_from_slice` in
///   4096-byte chunks to 100,000 bytes total), at 6 allocation events and
///   5 reallocations, final capacity 131072 grown from 0. For an
///   attachment, a long note or a stored key file that is the normal case,
///   not the exception. This happens inside the parser's visitor, before
///   any wrapper here sees the value, and there is no public hook for it.
///   Tracked as **#570**.
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
/// type's protection entirely** the moment `take_next` returns it, and
/// NOTHING WIPES IT AUTOMATICALLY from that point on — the caller must.
/// [`wipe_leaked_value`] exists for exactly this: a caller that examines a
/// yielded value has two honest choices, fold it into a zeroizing wrapper
/// (`Sensitive`/`SecretBytes`) on success, or call `wipe_leaked_value`
/// before an early return that never examines it at all.
///
/// Task 7's consumer, `unlock::bundle::IdentityBundle::from_canonical_cbor`,
/// does both, and an earlier version of this doc comment claimed only the
/// first half — found wrong in fix-round-1 G1, because two of its loop's
/// early-return arms (an entry whose KEY fails the `Value::Text` shape
/// check; an entry whose key does not match any recognised §5 field) never
/// reach a wrapper at all. Cloning a yielded value into some other unwiped
/// local would recreate exactly the residue this type exists to avoid;
/// dropping it unwiped by falling through to neither choice does the same
/// thing more quietly.
///
/// No longer `#[cfg(test)]`-gated (struct, impl, and `Drop` below): Task 7
/// (#548) gives this its first production caller, the same reasoning that
/// un-gated `SecretValueTree` in Task 6 (#547) — see the module doc.
pub(crate) struct SecretEntries(Vec<(Value, Value)>);

impl SecretEntries {
    /// Take ownership of an entry list.
    pub(crate) fn new(entries: Vec<(Value, Value)>) -> Self {
        Self(entries)
    }

    /// Number of entries currently held (shrinks as [`Self::take_next`]
    /// drains the front). Test-only: `unlock::bundle`'s production caller
    /// never needs it (`take_next` alone drives the decode loop, and
    /// [`Self::is_empty`] is what `take_next` itself checks), so an
    /// unconditional build flags it `dead_code` under `-D warnings`
    /// (verified by execution). `tests.rs` still exercises it directly, and
    /// both this and [`Self::is_empty`] compile together under `--tests`,
    /// which is what `clippy::len_without_is_empty` (a type with `len()` but
    /// no `is_empty()`) wants to see whenever `len()` exists at all.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether every entry has been drained. Not itself required by
    /// `clippy::len_without_is_empty` (that lint fires the other direction —
    /// `len()` without a matching `is_empty()` — and does not object to
    /// `is_empty()` existing alone); kept alongside [`Self::len`] so the two
    /// pair up whenever `len()` compiles (see that method's doc). Also the
    /// check [`Self::take_next`] itself uses.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Read-only view of every entry currently held. Test-only as of #569:
    /// `unlock::bundle::to_canonical_cbor` was this method's only production
    /// caller (it fed `entries.as_slice()` into
    /// `crate::vault::canonical::encode_canonical_map`), and #569 replaced
    /// that whole encode path with the borrowing `CanonicalMap` mirror,
    /// which never constructs a `SecretEntries` at all. `tests.rs` still
    /// exercises this directly, so — same reasoning as [`Self::len`] above —
    /// it is `#[cfg(test)]`-gated rather than left to trip `dead_code` under
    /// `-D warnings` (verified by execution).
    #[cfg(test)]
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

impl Drop for SecretEntries {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests;
