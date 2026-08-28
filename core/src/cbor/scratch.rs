//! `CborScratch` / `from_secret_reader` (#561): a zeroize-on-drop wrapper
//! for the scratch buffer `ciborium`'s parser uses, and the one sanctioned
//! parse entry point for CBOR that may hold decrypted plaintext.
//!
//! `ciborium::de::from_reader` allocates `[0u8; 4096]` in its own stack
//! frame and `read_exact`s **every definite-length** byte-string and text
//! payload of that size or smaller straight into it before the visitor
//! copies out; larger payloads — and INDEFINITE-length items of any size,
//! which take `deserialize_byte_buf` / `deserialize_string` rather than the
//! `read_exact` fast path — stream through it 4 KiB at a time. Either way
//! the payload transits this buffer, so the claim below is unaffected; the
//! word read a bare "**every**" until the #575 review, and the
//! indefinite-length path is reachable because this input is untrusted and
//! parsed BEFORE any canonicality check. That buffer therefore holds
//! decrypted record fields, block plaintext, `block_name`s and the identity
//! bundle's four long-term secret keys, and it is left intact when the
//! parser returns.
//!
//! `SecretValueTree` (see `super::secret_tree`) cannot reach it: that type
//! wraps the parsed `Value` **tree**, and this buffer is not part of the
//! tree — it is the staging area the tree was built from.
//!
//! The fix is to own the buffer ourselves. `ciborium::de::from_reader` is
//! literally
//!
//! ```ignore
//! let mut scratch = [0; 4096];
//! from_reader_with_buffer(reader, &mut scratch)
//! ```
//!
//! (`ciborium-0.2.2/src/de/mod.rs:825-851`), and `from_reader_with_buffer`
//! sets the identical `recurse: 256`, so passing our own buffer of the same
//! length is **behaviour-identical** — verified against the vendored source,
//! not inferred from the docs.
//!
//! # Why `from_secret_reader` takes `&[u8]` rather than a generic
//! `ciborium_io::Read`
//!
//! The design that motivated this module named a generic signature over
//! `R: ciborium_io::Read`. `ciborium_io` is not a dependency of this crate
//! (`core/Cargo.toml` depends only on `ciborium = "=0.2.2"`, which does not
//! re-export it), so that signature does not compile as written. All six
//! production call sites this function replaces already do
//! `.map_err(|e| XError::CborDecode(classify_de(&e)))` verbatim, and every
//! one of them parses from an owned `&[u8]` (never a streaming reader).
//! [`classify_de`](crate::cbor::classify_de) is already generic over the
//! reader's error type and projects it down to the non-generic
//! [`CborFault`](crate::cbor::CborFault) per the #474 discipline (see the
//! parent module's doc comment) — discarding any upstream message before it
//! can carry decrypted plaintext into an error variant. Taking `&[u8]` and
//! classifying internally therefore avoids adding a dependency for a type
//! *name* that no call site needs, and it funnels every secret-bearing
//! parse through that classification rather than merely allowing a caller
//! to opt in.
//!
//! # What this does not claim
//!
//! This closes the parser's *scratch* buffer only. `ciborium`'s
//! `deserialize_byte_buf` / `deserialize_string` build the final payload
//! with `Vec::new()` / `String::new()` plus a per-chunk grow-and-copy
//! (`extend_from_slice` and `push_str` respectively — this named only the
//! former for both until the #575 review; `push_str` delegates to
//! `extend_from_slice` internally, so the growth behaviour is the same, but
//! this comment asserts it was verified against the vendored source),
//! so a payload larger than [`CBOR_SCRATCH_LEN`] still grows by doubling
//! and frees an unwiped prefix at each reallocation — routinely, for any
//! attachment, long note or stored key file. That happens inside the
//! parser's visitor, before any wrapper here sees the value, and there is
//! no public hook for it. Tracked as **#570**.

use ciborium::value::Value;
use zeroize::Zeroize;

/// Length of the parser scratch buffer, in bytes.
///
/// Deliberately equal to `ciborium`'s own default (`de/mod.rs:829`). A
/// different value would be sound but would change how payloads are
/// chunked, and this module's whole claim is that routing through it
/// changes no parsing behaviour. That equality is pinned by the `const _`
/// assertion immediately below, not merely asserted in prose — a bare doc
/// comment does not stop a future edit from changing this value while
/// every existing test stays green (mutation-proven: setting it to `64`
/// during review left all four `cbor::scratch` tests passing — the
/// count read "three" until the #575 review, having been written in the
/// same commit that added the fourth).
pub(crate) const CBOR_SCRATCH_LEN: usize = 4096;

// Pins `CBOR_SCRATCH_LEN` to `ciborium`'s own hardcoded default
// (`de/mod.rs:829`), which is the fact this whole module's
// behaviour-identical claim rests on. Nothing else enforces this: no test
// here fails if the two values diverge, since a smaller or larger scratch
// buffer still parses every fixture correctly (it only changes how a
// payload larger than the buffer gets chunked internally by `ciborium`,
// which is invisible to `Value`-level equality assertions). A version pin
// on `ciborium` (`=0.2.2` in `core/Cargo.toml`) is what would need
// re-verifying against `de/mod.rs:829` on any future bump; this assertion
// only guards against an edit to the constant on *this* side drifting from
// that pinned value.
const _: () = assert!(
    CBOR_SCRATCH_LEN == 4096,
    "must equal ciborium 0.2.2's own de/mod.rs default scratch length (4096) — \
     changing this constant changes ciborium's internal chunking behaviour, \
     which this module's doc claims does not happen"
);

/// A parser scratch buffer that is zeroized when it drops.
///
/// The field is module-private, and the only PRODUCTION code that can hand
/// the buffer to `ciborium` is [`from_secret_reader`] below. Two boundaries
/// on that, both narrower than the unqualified "no `&mut` accessor escapes
/// this file" this said until the #575 review:
///
/// - `scratch_wipe_is_not_vacuous` in this file's own test module does pass
///   `&mut scratch.0` to `from_reader_with_buffer` directly. That is the
///   point of the test — it inspects the buffer after a parse, which going
///   through `from_secret_reader` cannot do.
/// - Rust privacy is module-SUBTREE scoped, not file-scoped, so a `mod
///   ext;` declared HERE would inherit access to `self.0` from an
///   unreviewed file (the same property #515 added guard rule E6 for, on
///   the bridge's `Detail`). No guard covers this one, deliberately: the
///   severity is not comparable. Minting a `Detail` forges a claim of
///   gatedness that 27 error payloads and two platforms rely on; reaching
///   `&mut CborScratch.0` yields a byte array whose owner still wipes it on
///   drop. What WOULD make the wipe vacuous — `mem::swap`/`take`/`forget`,
///   `ManuallyDrop` — is already denied tree-wide by
///   `scripts/check-secret-slot-hygiene.sh` (#521).
struct CborScratch([u8; CBOR_SCRATCH_LEN]);

impl CborScratch {
    /// Wipe now, without waiting for the drop. Test-only: production code
    /// relies on `Drop` precisely because it cannot be skipped. Same name
    /// and shape as `secret_tree::SecretValueTree::wipe_for_test` /
    /// `SecretEntries::wipe_for_test` — see [`Self::wipe`]'s doc for why
    /// the split exists.
    #[cfg(test)]
    fn wipe_for_test(&mut self) {
        self.wipe();
    }

    /// The actual wipe, shared by [`Drop::drop`] and, in tests,
    /// [`Self::wipe_for_test`].
    ///
    /// Split out rather than inlined into `Drop::drop`, mirroring
    /// `secret_tree`'s `SecretValueTree` / `SecretEntries` (`6ac4cfed`
    /// finding I3): a counter bump alone proves only that *some* code ran
    /// on drop, not that the bump is coupled to the zeroize it claims to
    /// accompany — a mutation that deletes `self.0.zeroize()` leaves a
    /// counter-only test green (confirmed by mutation on this exact type;
    /// the conclusion is inlined here rather than pointed at, because the
    /// per-task SDD reports live under a gitignored `.superpowers/` and
    /// are not in the repo — this cited `task-1-report.md` until the #575
    /// review, the same dangling-citation class #560 fixed in four
    /// sibling sites). `scratch_wipe_is_not_vacuous` below calls
    /// this method directly, bypassing `Drop` entirely, so it isolates the
    /// wipe's *effect* (bytes actually cleared) from the fact that `Drop`
    /// *invokes* something (`scratch_is_wiped_on_the_success_path` /
    /// `..._on_the_error_path` above cover that half).
    fn wipe(&mut self) {
        #[cfg(test)]
        super::secret_tree::note_wipe();
        self.0.zeroize();
    }
}

impl Drop for CborScratch {
    /// Hand-written rather than `#[derive(ZeroizeOnDrop)]`, deliberately.
    ///
    /// A derived `Drop` bumps no counter, so a test cannot observe it, and
    /// a wipe nothing observes can be deleted with the whole suite green —
    /// which is exactly the complaint #557 and #558 record against two
    /// mechanisms that shipped that way. Writing `Drop` by hand lets this
    /// one be pinned by test from the moment it lands.
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Parse CBOR that may contain decrypted plaintext.
///
/// Behaviourally identical to [`ciborium::de::from_reader`] (see the module
/// doc for why), but the scratch buffer the parser stages payloads through
/// is owned here and wiped on **every** exit — a normal return, an early
/// `?`, or an unwinding panic — rather than left intact in `ciborium`'s
/// frame.
///
/// This is the sanctioned entry point for every secret-bearing parse in the
/// crate. As of Task 1 (#561) it had **zero** production callers; Task 2
/// wired in the first ones. `grep -rn "cbor::from_secret_reader(" core/src`
/// now shows five production call sites routed through this function
/// (`unlock/bundle.rs`, `vault/block.rs`, `vault/manifest/decode/mod.rs`,
/// `vault/record.rs` x2) — the grep itself returns six rows, the sixth
/// being this very doc comment, so count call sites rather than rows. It
/// was SIX production sites until #569 path 2 deleted
/// `manifest::encode::unknown_value_inner`, whose encode-side re-parse was
/// the manifest module's second — note that's a grep for the NEW call, not the old
/// `ciborium::de::from_reader` one: none of the six spell that anymore, so
/// that grep now shows only the two sites that deliberately stay on plain
/// `from_reader`, each carrying a comment saying why its input provably
/// holds no secret (`identity/card.rs`, `sync/state.rs`), plus test code
/// and prose.
///
/// Takes an already-materialized `&[u8]` rather than a generic
/// `ciborium_io::Read` — see the module doc's "Why `&[u8]`" section — and
/// classifies any decode failure through [`crate::cbor::classify_de`]
/// immediately, so the caller never sees `ciborium`'s own error type (and
/// so it never risks the #474 upstream-message leak that type carries).
pub(crate) fn from_secret_reader(bytes: &[u8]) -> Result<Value, crate::cbor::CborFault> {
    let mut scratch = CborScratch([0u8; CBOR_SCRATCH_LEN]);
    // `scratch` drops at the end of this function on every path, including
    // the implicit early exit inside `from_reader_with_buffer`'s `?`.
    ciborium::de::from_reader_with_buffer(bytes, &mut scratch.0)
        .map_err(|e| crate::cbor::classify_de(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::wipe_calls;

    /// The scratch buffer must be wiped on the SUCCESS path. A caller's
    /// happy-path parse is the common case, so a wipe that only fired on
    /// error would cover almost nothing.
    #[test]
    fn scratch_is_wiped_on_the_success_path() {
        let bytes = canonical_text_item("hello");
        let before = wipe_calls();
        let v = from_secret_reader(bytes.as_slice()).expect("parse");
        assert_eq!(v, Value::Text("hello".to_string()));
        assert_eq!(
            wipe_calls(),
            before + 1,
            "exactly one scratch wipe per successful parse"
        );
    }

    /// ...and on the `?` path. `Drop` is the mechanism precisely because
    /// an early return cannot skip it; a trailing statement could.
    #[test]
    fn scratch_is_wiped_on_the_error_path() {
        // 0x9f = indefinite-length array head, then EOF: a parse error.
        let bytes = [0x9fu8];
        let before = wipe_calls();
        let err = from_secret_reader(bytes.as_slice());
        assert!(err.is_err(), "truncated input must fail to parse");
        assert_eq!(
            wipe_calls(),
            before + 1,
            "the scratch wipe must fire on the `?` path too"
        );
    }

    /// Proves the wipe is not vacuous. The two tests above prove `Drop`
    /// *runs* on both exit paths (via the counter); they do NOT prove the
    /// buffer's bytes are actually cleared — a mutation deleting
    /// `self.0.zeroize()` from [`CborScratch::wipe`] leaves both counter
    /// tests green, confirmed by mutation during review (see
    /// the conclusion is inlined rather than cited — see
    /// [`CborScratch::wipe`] for why there is no report to point at).
    /// This test closes that gap directly: it parses a
    /// distinctive marker payload short enough that `ciborium`
    /// `read_exact`s it straight into the scratch buffer (see the module
    /// doc), confirms the marker actually landed there (so the "before"
    /// state isn't vacuously already-zero), calls `wipe_for_test` —
    /// bypassing `Drop` so this test isolates the wipe's EFFECT from the
    /// fact that something invokes it — and confirms the marker is gone
    /// afterward. Mirrors `secret_tree::tests::wipe_is_not_vacuous` /
    /// `secret_entries_wipe_reaches_every_entry_including_keys`: same
    /// structure, same `wipe`/`wipe_for_test` split, same naming.
    #[test]
    fn scratch_wipe_is_not_vacuous() {
        const MARKER: &str = "amex-cvv-4111111111111111-marker";
        assert!(
            MARKER.len() <= CBOR_SCRATCH_LEN,
            "fixture setup: marker must fit in one scratch-buffered read"
        );

        // BOTH payload arms, not just `Value::Bytes` (#575 review). The
        // module doc above names "decrypted record fields, block
        // plaintext, `block_name`s" as what this buffer holds, and those
        // are CBOR TEXT — `ciborium`'s `deserialize_string` is a separate
        // code path from `deserialize_byte_buf`, so a `Bytes`-only fixture
        // does not travel the route the threat actually takes.
        for (label, item) in [
            ("bytes", Value::Bytes(MARKER.as_bytes().to_vec())),
            ("text", Value::Text(MARKER.to_string())),
        ] {
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&item, &mut encoded).expect("encode");

            // Construct the scratch buffer directly and hand it to
            // `from_reader_with_buffer` ourselves, rather than going through
            // `from_secret_reader` — that call's `CborScratch` would already
            // have dropped (and wiped) by the time control returns here, so
            // there would be nothing left to inspect.
            let mut scratch = CborScratch([0u8; CBOR_SCRATCH_LEN]);
            let parsed: Value =
                ciborium::de::from_reader_with_buffer(encoded.as_slice(), &mut scratch.0)
                    .expect("parse");
            assert_eq!(parsed, item, "fixture setup ({label})");
            assert!(
                scratch
                    .0
                    .windows(MARKER.len())
                    .any(|window| window == MARKER.as_bytes()),
                "fixture setup: {label} marker did not land in the scratch buffer"
            );

            scratch.wipe_for_test();

            assert!(
                !scratch
                    .0
                    .windows(MARKER.len())
                    .any(|window| window == MARKER.as_bytes()),
                "{label} marker still present after wipe — the wipe is a no-op"
            );
        }
    }

    /// `from_secret_reader` must agree with `ciborium::de::from_reader`
    /// byte-for-byte across the scratch-length boundary. `from_reader` IS
    /// `from_reader_with_buffer(r, &mut [0; 4096])` with the same
    /// `recurse: 256`, so any disagreement means this wrapper changed
    /// parsing behaviour, which it must not.
    /// Widened in the #575 review. The first version tested `Value::Bytes`
    /// at six lengths and `.expect()`ed BOTH sides, which made it
    /// structurally incapable of comparing REJECTION behaviour — a
    /// divergence in *which* inputs fail, or in the recursion limit, could
    /// not have been expressed by it. This version compares at `Result`
    /// level over text, nesting and malformed input as well.
    ///
    /// This test is the tripwire for a future `ciborium` bump. The version
    /// is pinned at `=0.2.2`, and the equality currently holds by
    /// construction (`from_reader` delegates to `from_reader_with_buffer`
    /// with the same `recurse: 256`) — but that is a property of the
    /// pinned source, not of the API contract, so it is checked rather
    /// than assumed.
    #[test]
    fn agrees_with_ciborium_from_reader_across_the_scratch_boundary() {
        let mut fixtures: Vec<(String, Vec<u8>)> = Vec::new();

        // Definite-length byte and text payloads across the scratch
        // boundary. `deserialize_byte_buf` and `deserialize_string` are
        // separate code paths in ciborium, so both are swept.
        for len in [
            0,
            1,
            CBOR_SCRATCH_LEN - 1,
            CBOR_SCRATCH_LEN,
            CBOR_SCRATCH_LEN + 1,
            CBOR_SCRATCH_LEN * 3,
        ] {
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&Value::Bytes(vec![0xA5u8; len]), &mut encoded)
                .expect("encode");
            fixtures.push((format!("bytes/{len}"), encoded));

            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&Value::Text("a".repeat(len)), &mut encoded)
                .expect("encode");
            fixtures.push((format!("text/{len}"), encoded));
        }

        // A map whose KEYS straddle the boundary — record field names are
        // decrypted plaintext, so this is the shape that matters most.
        for key_len in [1, CBOR_SCRATCH_LEN - 1, CBOR_SCRATCH_LEN + 1] {
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(
                &Value::Map(vec![(
                    Value::Text("k".repeat(key_len)),
                    Value::Bytes(vec![0x11; 8]),
                )]),
                &mut encoded,
            )
            .expect("encode");
            fixtures.push((format!("map-key/{key_len}"), encoded));
        }

        // Nesting either side of ciborium's `recurse: 256` limit. If the
        // two entry points ever set different limits, these disagree.
        for depth in [8usize, 255, 256, 257, 400] {
            let mut encoded = vec![0x81u8; depth]; // `depth` nested 1-element arrays
            encoded.push(0x00); // innermost: integer 0
            fixtures.push((format!("nest/{depth}"), encoded));
        }

        // Malformed input: both entry points must REJECT identically.
        // `.expect()` on both sides could never have covered this.
        fixtures.push(("truncated-indefinite-array".into(), vec![0x9f]));
        fixtures.push((
            "overlong-bstr-header".into(),
            vec![0x5a, 0xff, 0xff, 0xff, 0xff],
        ));
        fixtures.push(("invalid-utf8-tstr".into(), vec![0x62, 0xff, 0xfe]));
        fixtures.push(("truncated-map".into(), vec![0xa1, 0x61, b'k']));
        fixtures.push(("empty".into(), Vec::new()));

        for (label, encoded) in fixtures {
            let ours = from_secret_reader(encoded.as_slice());
            let theirs: Result<Value, _> = ciborium::de::from_reader(encoded.as_slice());
            match (&ours, &theirs) {
                (Ok(o), Ok(t)) => assert_eq!(o, t, "value disagreement at {label}"),
                (Err(_), Err(_)) => {}
                _ => panic!(
                    "accept/reject disagreement at {label}: ours={:?}, ciborium ok={}",
                    ours.as_ref().err(),
                    theirs.is_ok()
                ),
            }
        }
    }

    /// Helper: canonical CBOR for a text item.
    fn canonical_text_item(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Text(s.to_string()), &mut buf).expect("encode");
        buf
    }
}
