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
//! Every constructor here takes `&'static str`, an integer, or a `Detail`
//! — so there is no parameter through which an UNGATED runtime string can
//! enter (a `Detail` is one the bridge already vouched for, and its inner
//! field is private to the bridge's own `detail.rs`). This said
//! "`&'static str` and integers only" until #515, which #500 had already
//! falsified by adding `project(d: Detail) -> String` to this very module;
//! the ffi-py twin was updated in #500 and this one was missed. That is
//! a property of the signatures below, and guard rule E3 checks it as of
//! #496 (`SAFE_PARAM_TYPES`): a constructor with a parameter outside the
//! reviewed set is DROPPED from the sanctioned set and its call sites deny.
//! Note `&'static str` discourages rather than forbids: safe Rust can mint
//! one from runtime data with `Box::leak` / `String::leak`, so this remains
//! a review surface, not a proof. See the entry point's LIMITS.
//!
//! Rule **E5** is what makes this module the only SOURCE of composed
//! strings — `format!` is confined here (#486 task 11). Rule E3 gates the
//! gated-field INITIALIZERS that consume them, and accepts a bare string
//! literal just as readily, so E3 alone never established confinement; this
//! paragraph credited it until #496. E3 does own the fail-closed hinge: a
//! missing/unreadable file yields an EMPTY sanctioned set, so every
//! `detail::*` call denies until this module exists.

use secretary_ffi_bridge::Detail;

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

/// Project a bridge-gated [`Detail`] into the owned `String` this crate's
/// error surface requires (#500).
///
/// The bridge declares every gated payload field as `Detail`, whose private
/// inner field means the value can only have come out of a sanctioned
/// constructor in `ffi/secretary-ffi-bridge/src/error/detail.rs`. uniffi's
/// `VaultError` variants must carry a UDL `string`, so the newtype cannot
/// cross this seam intact.
///
/// This is a PROJECTION, not a gate: it re-derives nothing and vouches for
/// nothing. It exists so the unwrap has ONE named home per wrapper crate
/// rather than 25 inline `.into_string()` call sites — the same reason rule
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
