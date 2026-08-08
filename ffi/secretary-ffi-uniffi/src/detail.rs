//! The ONLY place in this crate permitted to build an `InvalidArgument`
//! detail string.
//!
//! #480 pinned the BRIDGE's detail strings to one reviewed file. This crate
//! sat outside that gate: `uuid_from_vec(bytes: &[u8], field: &str)` took a
//! `&str`, so its ~45 call sites could hand it any runtime value, and one
//! caller ([`crate::namespace::repair::convert_approvals`]) already passed a
//! `format!(...)`. Nothing leaked — the interpolated values were loop
//! indices — but the SIGNATURE admitted a decrypted field name, which is
//! structurally what #481 was, one layer out from where #480 closed it.
//!
//! Every constructor here takes `&'static str` and integers only; there is
//! no parameter through which a runtime string can enter. Guard rule E3
//! enforces that this module is the only source of these strings
//! (`scripts/check-error-payload-hygiene.py`); a missing/unreadable file
//! yields an EMPTY sanctioned set, so every `detail::*` call denies until
//! this module exists — the guard's fail-closed hinge, not an oversight.

/// `<field> must be <expected> bytes, got <got>`.
pub(crate) fn arg_len(field: &'static str, expected: usize, got: usize) -> String {
    format!("{field} must be {expected} bytes, got {got}")
}

/// [`arg_len`] for an element of a caller-supplied list: `<field>[<index>]
/// must be <expected> bytes, got <got>`. The INDEX is an integer this crate
/// computed while iterating, never caller-supplied text.
pub(crate) fn indexed_arg_len(
    field: &'static str,
    index: usize,
    expected: usize,
    got: usize,
) -> String {
    format!("{field}[{index}] must be {expected} bytes, got {got}")
}

/// Two-index sibling of [`indexed_arg_len`], for a caller-supplied list
/// nested inside another caller-supplied list (`approvals[i].
/// added_recipients[j]`): `<field>[<outer>][<inner>] must be <expected>
/// bytes, got <got>`.
///
/// The original plan for this task proposed dropping the outer index at
/// this one call site, calling it an acceptable "diagnostic reduction"
/// since recovering it seemingly needed a runtime-built field string. That
/// framing was wrong: `outer` and `inner` are both integers this crate
/// already has in hand from the enclosing `enumerate()`s, so a two-index
/// constructor carries both without reintroducing any runtime string —
/// every parameter here is still `&'static str` or `usize`.
pub(crate) fn nested_indexed_arg_len(
    field: &'static str,
    outer: usize,
    inner: usize,
    expected: usize,
    got: usize,
) -> String {
    format!("{field}[{outer}][{inner}] must be {expected} bytes, got {got}")
}

/// `<context>: [<min>, <max>]` — a bounds violation carrying only integers.
pub(crate) fn range(context: &'static str, min: u64, max: u64) -> String {
    format!("{context}: [{min}, {max}]")
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
            indexed_arg_len("approvals.block_uuid", 2, 16, 5),
            "approvals.block_uuid[2] must be 16 bytes, got 5"
        );
    }

    #[test]
    fn nested_indexed_arg_len_renders_both_indices() {
        assert_eq!(
            nested_indexed_arg_len("approvals.added_recipients", 1, 3, 16, 17),
            "approvals.added_recipients[1][3] must be 16 bytes, got 17"
        );
    }

    #[test]
    fn nested_indexed_arg_len_distinguishes_outer_from_inner() {
        // A regression this constructor exists to prevent: swapping outer
        // and inner (or losing one) must produce a DIFFERENT string, not
        // silently collapse two distinct failures to the same message.
        let a = nested_indexed_arg_len("approvals.added_recipients", 0, 1, 16, 5);
        let b = nested_indexed_arg_len("approvals.added_recipients", 1, 0, 16, 5);
        assert_ne!(a, b);
        assert_eq!(
            a,
            "approvals.added_recipients[0][1] must be 16 bytes, got 5"
        );
        assert_eq!(
            b,
            "approvals.added_recipients[1][0] must be 16 bytes, got 5"
        );
    }

    #[test]
    fn range_renders_both_bounds() {
        assert_eq!(
            range("settings out of range", 1, 90),
            "settings out of range: [1, 90]"
        );
    }
}
