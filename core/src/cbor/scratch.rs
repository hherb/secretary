//! `CborScratch` / `from_secret_reader` (#561): a zeroize-on-drop wrapper
//! for the scratch buffer `ciborium`'s parser uses, and the one sanctioned
//! parse entry point for CBOR that may hold decrypted plaintext.
//!
//! `ciborium::de::from_reader` allocates `[0u8; 4096]` in its own stack
//! frame and `read_exact`s **every** byte-string and text payload of that
//! size or smaller straight into it before the visitor copies out; larger
//! payloads stream through it 4 KiB at a time. That buffer therefore holds
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
//! with `Vec::new()` / `String::new()` plus per-chunk `extend_from_slice`,
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
/// changes no parsing behaviour.
pub(crate) const CBOR_SCRATCH_LEN: usize = 4096;

/// A parser scratch buffer that is zeroized when it drops.
///
/// The field is module-private and no `&mut` accessor escapes this file:
/// the only code that can hand the buffer to `ciborium` is
/// [`from_secret_reader`] below.
struct CborScratch([u8; CBOR_SCRATCH_LEN]);

impl Drop for CborScratch {
    /// Hand-written rather than `#[derive(ZeroizeOnDrop)]`, deliberately.
    ///
    /// A derived `Drop` bumps no counter, so a test cannot observe it, and
    /// a wipe nothing observes can be deleted with the whole suite green —
    /// which is exactly the complaint #557 and #558 record against two
    /// mechanisms that shipped that way. Writing `Drop` by hand lets this
    /// one be pinned by test from the moment it lands.
    fn drop(&mut self) {
        #[cfg(test)]
        super::secret_tree::note_wipe();
        self.0.zeroize();
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
/// crate. `grep -rn "ciborium::de::from_reader" core/src` shows the
/// remaining plain-`from_reader` sites; each carries a comment saying why
/// it provably holds no secret.
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

    /// `from_secret_reader` must agree with `ciborium::de::from_reader`
    /// byte-for-byte across the scratch-length boundary. `from_reader` IS
    /// `from_reader_with_buffer(r, &mut [0; 4096])` with the same
    /// `recurse: 256`, so any disagreement means this wrapper changed
    /// parsing behaviour, which it must not.
    #[test]
    fn agrees_with_ciborium_from_reader_across_the_scratch_boundary() {
        for len in [
            0,
            1,
            CBOR_SCRATCH_LEN - 1,
            CBOR_SCRATCH_LEN,
            CBOR_SCRATCH_LEN + 1,
            CBOR_SCRATCH_LEN * 3,
        ] {
            let payload = vec![0xA5u8; len];
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&Value::Bytes(payload.clone()), &mut encoded)
                .expect("encode");

            let ours = from_secret_reader(encoded.as_slice()).expect("ours");
            let theirs: Value = ciborium::de::from_reader(encoded.as_slice()).expect("ciborium");
            assert_eq!(ours, theirs, "disagreement at payload length {len}");
        }
    }

    /// Helper: canonical CBOR for a text item.
    fn canonical_text_item(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Text(s.to_string()), &mut buf).expect("encode");
        buf
    }
}
