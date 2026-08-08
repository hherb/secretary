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
//! the sink: `format!` — the only construct in this crate that COMPOSES a
//! new string from runtime parts — is confined to this one file. Same move
//! `ffi/secretary-ffi-uniffi/src/detail.rs` makes for uniffi (#486 task 10),
//! `error/detail.rs` for the bridge (#480), `SecretaryLog` for Android
//! logcat (#472), and `diagnosticDetail` for iOS `privacy: .public` (#467):
//! do not police call sites, make the unsafe call unrepresentable and
//! review the one file that defines what safe means.
//!
//! Every constructor below takes `&'static str` and integers only, WITH ONE
//! DELIBERATE EXCEPTION: [`fingerprint_mismatch`] and [`uuid_prefixed`] each
//! take `&str`, because their inputs are not authored here — they are
//! already-gated bridge fields (`FfiVaultError::NotAuthor`'s two fingerprint
//! hexes; `FfiVaultError::RepairRejected`'s `block_uuid_hex` and `detail`),
//! gated by rules E2/E3 at their construction site in the bridge crate. This
//! crate COMBINES those two already-gated `String`s into one message; it
//! does not author new runtime content. Every other constructor's inputs
//! are authored by THIS crate (a field name, a byte-length count, a bounds
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

/// `expected=<a>, got=<b>` — both arguments are already-gated bridge fields
/// (`FfiVaultError::NotAuthor`'s two fingerprint hexes, gated by rules
/// E2/E3 in the bridge). This crate composes them; it does not author them.
pub(crate) fn fingerprint_mismatch(expected_hex: &str, got_hex: &str) -> String {
    format!("expected={expected_hex}, got={got_hex}")
}

/// `<uuid_part>: <detail_part>` — the collapsed `RepairRejected` message
/// this crate's `create_exception!` convention requires (the bridge's two
/// structured fields collapse into one message; uniffi/desktop keep them
/// separate). Python callers split on the first `": "`; a hyphenated UUID
/// has no embedded `": "`, so that split is exact. Both inputs are
/// already-gated bridge fields (`FfiVaultError::RepairRejected`'s
/// `block_uuid_hex` and `detail`, gated by rules E2/E3 in the bridge). This
/// crate composes them; it does not author them.
///
/// Parameters are deliberately NOT named `block_uuid_hex` / `detail` — both
/// are themselves members of `GATED_FIELD_NAMES`
/// (`scripts/payload_guard/config.py`), and rule E3's `GATED_INIT_RE` reads
/// ANY `<gated-name>:` text tree-wide, including a plain function
/// PARAMETER declaration, not only a struct/enum field initializer. Naming
/// a parameter here after the field it receives would make this file's own
/// declaration look like an unsanctioned construction site of a gated
/// field and deny — verified by execution during this rule's own
/// development.
pub(crate) fn uuid_prefixed(uuid_part: &str, detail_part: &str) -> String {
    format!("{uuid_part}: {detail_part}")
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
            fingerprint_mismatch("aabb", "ccdd"),
            "expected=aabb, got=ccdd"
        );
    }

    #[test]
    fn fingerprint_mismatch_distinguishes_expected_from_got() {
        // A regression this constructor exists to prevent: swapping the two
        // hexes must produce a DIFFERENT string, not silently collapse two
        // distinct mismatches to the same message.
        let a = fingerprint_mismatch("aabb", "ccdd");
        let b = fingerprint_mismatch("ccdd", "aabb");
        assert_ne!(a, b);
    }

    #[test]
    fn uuid_prefixed_renders_uuid_then_colon_space_detail() {
        assert_eq!(
            uuid_prefixed("11223344-5566-7788-99aa-bbccddeeff00", "stale consent"),
            "11223344-5566-7788-99aa-bbccddeeff00: stale consent"
        );
    }

    #[test]
    fn uuid_prefixed_split_on_first_colon_space_recovers_both_halves() {
        // Pins the Python-caller contract stated on the constructor: a
        // hyphenated UUID never embeds ": ", so splitting on the FIRST
        // occurrence recovers exactly the two original fields.
        let rendered = uuid_prefixed(
            "11223344-5566-7788-99aa-bbccddeeff00",
            "clock relation Concurrent: widening not approved",
        );
        let (uuid_part, detail_part) = rendered.split_once(": ").expect("contains \": \"");
        assert_eq!(uuid_part, "11223344-5566-7788-99aa-bbccddeeff00");
        assert_eq!(
            detail_part,
            "clock relation Concurrent: widening not approved"
        );
    }
}
