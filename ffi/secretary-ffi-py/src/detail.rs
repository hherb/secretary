//! The ONLY place in this crate permitted to build a `PyErr` detail string
//! via `format!` (rule E5, #486).
//!
//! Rule E3 gates GATED-FIELD INITIALIZERS in the bridge and, as of #486
//! task 9, in this crate too — but this crate's platform sink is not a
//! gated-field initializer:
//!
//! ```ignore
//! FfiVaultError::NotAuthor { expected_fingerprint_hex, got_fingerprint_hex }
//!     => VaultNotAuthor::new_err(format!("expected={expected_fingerprint_hex}, ...")),
//! ```
//!
//! `format!(...)` there is a function ARGUMENT to `PyErr::new_err`, not an
//! initializer E3's model can see. So rule E5 gates the SOURCE instead of
//! the sink: `format!` — today the only construct in this crate that
//! composes a new string from runtime parts, a CENSUS finding rather than a
//! structural one (`push_str`, `write!`/`writeln!`, `+` on an owned
//! `String` and `.join()` would all do the same and none is inspected; see
//! `scripts/payload_guard/rules/e5.py`, which retracts this exact
//! phrasing at length) — is confined to this one file. Same move
//! `ffi/secretary-ffi-uniffi/src/detail.rs` makes for uniffi (#486 task 10),
//! `error/detail.rs` for the bridge (#480), `SecretaryLog` for Android
//! logcat (#472), and `diagnosticDetail` for iOS `privacy: .public` (#467):
//! do not police call sites, make the unsafe call unrepresentable and
//! review the one file that defines what safe means.
//!
//! Every constructor below takes `&'static str`, an integer, `Detail`, or
//! `&Detail` (#500/#504) — never a bare runtime `&str`.
//! [`fingerprint_mismatch`] and [`uuid_prefixed`] are the two that take
//! `&Detail`: their inputs are not authored here, they are already
//! bridge-owned values this crate only COMBINES into one message, never
//! authoring new runtime content into either.
//! Before #504 both took `&str` and were admitted only by a
//! review-only, point-in-time claim pinned by name in
//! `STR_PARAM_CTOR_EXCEPTIONS` (`scripts/payload_guard/rules/e3.py`) —
//! nothing verified what a given call site actually passed there. Taking
//! `&Detail` converts that claim into a compile-time fact: `Detail`'s inner
//! field is private to the bridge's own `error/detail.rs`, so a value of
//! that type can only have come from a sanctioned constructor there, and
//! the exception set is now empty. Every other constructor's inputs are
//! authored by THIS crate (a field name, a byte-length count, a bounds
//! value), so they stay `&'static str`/integer-only, holding the line
//! `ffi/secretary-ffi-uniffi/src/detail.rs` set in task 10.
//!
//! Guard rule E5 enforces that this module is the only source of these
//! strings (`scripts/check-error-payload-hygiene.py`); a missing/unreadable
//! file is not this rule's fail-closed hinge (that is E3's
//! `sanctioned_constructor_names`) — E5 instead denies EVERY `format!`
//! outside this file, so an author cannot route around it by deleting the
//! file, only by adding an unreviewed `format!` call site directly, which
//! is exactly what this rule exists to catch.

use secretary_ffi_bridge::Detail;

/// `<field> must be <expected> bytes, got <got>`.
pub(crate) fn arg_len(field: &'static str, expected: usize, got: usize) -> String {
    format!("{field} must be {expected} bytes, got {got}")
}

/// [`arg_len`] for an element of a caller-supplied list: `<field>[<index>]
/// must be <expected> bytes, got <got>`. The INDEX is an integer this crate
/// computed while iterating (`added_recipients`'s `enumerate()`), never
/// caller-supplied text.
pub(crate) fn indexed_arg_len(
    field: &'static str,
    index: usize,
    expected: usize,
    got: usize,
) -> String {
    format!("{field}[{index}] must be {expected} bytes, got {got}")
}

/// `<context>: [<min>, <max>]` — a bounds violation carrying only integers
/// (`SettingsBoundsError::min`/`::max`, both `u64`).
pub(crate) fn range(context: &'static str, min: u64, max: u64) -> String {
    format!("{context}: [{min}, {max}]")
}

/// `expected=<a>, got=<b>` — both arguments are `&Detail` (#504):
/// `FfiVaultError::NotAuthor`'s two fingerprint hexes. A `Detail` is
/// constructible only inside the bridge's own `error/detail.rs`, so
/// provenance is gated by TYPE, not by a review claim about what this
/// crate happens to pass. This crate composes the two values; it does not
/// author them.
pub(crate) fn fingerprint_mismatch(expected: &Detail, got: &Detail) -> String {
    format!("expected={}, got={}", expected.as_str(), got.as_str())
}

/// `<uuid_part>: <detail_part>` — the collapsed `RepairRejected` message
/// this crate's `create_exception!` convention requires (the bridge's two
/// structured fields collapse into one message; uniffi/desktop keep them
/// separate). Python callers split on the first `": "`; a hyphenated UUID
/// has no embedded `": "`, so that split is exact.
///
/// Both parameters are `&Detail` (#504). Before #504 this comment had to
/// trace each parameter's provenance by hand — `uuid_part` via a
/// sanctioned E3 constructor call, `detail_part` via rule E2 plus core's
/// own E1 rather than E3, because rule E3 cannot see a bare field-init
/// shorthand re-wrap — since both arrived as unadorned `&str` and nothing
/// but that hand trace backed the claim. `Detail`'s inner field is private
/// to the bridge's own `error/detail.rs`, so a value of that type can only
/// have come from a sanctioned constructor there regardless of which
/// syntactic shape produced it; provenance is now a compile-time fact, not
/// a hand-traced one.
pub(crate) fn uuid_prefixed(uuid_part: &Detail, detail_part: &Detail) -> String {
    format!("{}: {}", uuid_part.as_str(), detail_part.as_str())
}

/// Project a bridge-gated [`Detail`] into the owned `String` this crate's
/// error surface requires (#500).
///
/// The bridge declares every gated payload field as `Detail`, whose private
/// inner field means the value can only have come out of a sanctioned
/// constructor in `ffi/secretary-ffi-bridge/src/error/detail.rs`. PyO3 exceptions take a message `String`, so the newtype cannot cross this
/// seam intact.
///
/// This is a PROJECTION, not a gate: it re-derives nothing and vouches for
/// nothing. It exists so the unwrap has ONE named home per wrapper crate
/// rather than 2 inline `.into_string()` call sites — the same reason rule
/// E5 confines `format!` to this file. Guard rule E3 accepts a call to it
/// because `Detail` sits in `SAFE_PARAM_TYPES`; the inline spelling
/// (`detail: detail.into_string()`) matches none of E3's accepted shapes and
/// denies.
pub(crate) fn project(d: Detail) -> String {
    d.into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_len_renders_field_and_both_lengths() {
        assert_eq!(
            arg_len("device_uuid", 16, 3),
            "device_uuid must be 16 bytes, got 3"
        );
    }

    #[test]
    fn indexed_arg_len_renders_the_index() {
        assert_eq!(
            indexed_arg_len("added_recipients", 2, 16, 5),
            "added_recipients[2] must be 16 bytes, got 5"
        );
    }

    #[test]
    fn range_renders_both_bounds() {
        assert_eq!(
            range("settings out of range", 1, 90),
            "settings out of range: [1, 90]"
        );
    }

    #[test]
    fn fingerprint_mismatch_renders_expected_then_got() {
        assert_eq!(
            fingerprint_mismatch(&Detail::for_test("aabb"), &Detail::for_test("ccdd")),
            "expected=aabb, got=ccdd"
        );
    }

    #[test]
    fn fingerprint_mismatch_distinguishes_expected_from_got() {
        // A regression this constructor exists to prevent: swapping the two
        // hexes must produce a DIFFERENT string, not silently collapse two
        // distinct mismatches to the same message.
        let a = fingerprint_mismatch(&Detail::for_test("aabb"), &Detail::for_test("ccdd"));
        let b = fingerprint_mismatch(&Detail::for_test("ccdd"), &Detail::for_test("aabb"));
        assert_ne!(a, b);
    }

    #[test]
    fn uuid_prefixed_renders_uuid_then_colon_space_detail() {
        assert_eq!(
            uuid_prefixed(
                &Detail::for_test("11223344-5566-7788-99aa-bbccddeeff00"),
                &Detail::for_test("stale consent")
            ),
            "11223344-5566-7788-99aa-bbccddeeff00: stale consent"
        );
    }

    #[test]
    fn uuid_prefixed_split_on_first_colon_space_recovers_both_halves() {
        // Pins the Python-caller contract stated on the constructor: a
        // hyphenated UUID never embeds ": ", so splitting on the FIRST
        // occurrence recovers exactly the two original fields.
        let rendered = uuid_prefixed(
            &Detail::for_test("11223344-5566-7788-99aa-bbccddeeff00"),
            &Detail::for_test("clock relation Concurrent: widening not approved"),
        );
        let (uuid_part, detail_part) = rendered.split_once(": ").expect("contains \": \"");
        assert_eq!(uuid_part, "11223344-5566-7788-99aa-bbccddeeff00");
        assert_eq!(
            detail_part,
            "clock relation Concurrent: widening not approved"
        );
    }

    #[test]
    fn fingerprint_mismatch_puts_expected_before_got() {
        let expected = Detail::for_test("aaaa");
        let got = Detail::for_test("bbbb");
        let msg = fingerprint_mismatch(&expected, &got);
        assert_eq!(msg, "expected=aaaa, got=bbbb");
        assert!(msg.find("aaaa").unwrap() < msg.find("bbbb").unwrap());
    }

    #[test]
    fn uuid_prefixed_puts_the_uuid_first() {
        let uuid = Detail::for_test("11223344-5566-7788-99aa-bbccddeeff00");
        let detail = Detail::for_test("residue rejected");
        let msg = uuid_prefixed(&uuid, &detail);
        assert_eq!(
            msg,
            "11223344-5566-7788-99aa-bbccddeeff00: residue rejected"
        );
    }
}
