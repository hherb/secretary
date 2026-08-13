//! Record title / subtitle derivation for the three-pane record list (#526).
//!
//! # Security contract
//!
//! Deriving a row label means calling `expose_text` on fields that
//! `project_record` previously never read, so *which* fields are eligible is
//! a security decision, enforced here and nowhere else.
//!
//! The rule is an **allowlist**, not a denylist: a field name absent from
//! TITLE_NAMES is never rendered, so `password`, `totp_seed`, freeform
//! `notes`/`body`, and every name nobody has thought of yet are excluded by
//! construction rather than by enumeration. A denylist would be the only gate
//! in this repository that fails open.
//!
//! labels_for_record applies the gate **before** `expose_text` is ever
//! called, so a non-allowlisted field's plaintext is never materialised at
//! all — not even into a discarded local.
//!
//! Values are truncated to [`MAX_LABEL_CHARS`] here, in Rust, so an oversized
//! field never reaches the webview.

use secretary_ffi_bridge::Record;

/// Field names eligible to become a row's title, in priority order.
///
/// Adding a name here is a **security decision**: it asserts the field's
/// value is safe to display persistently in a list, unmasked, for as long as
/// the list is on screen. Unlike a revealed field it does not auto-hide.
const TITLE_NAMES: [&str; 6] = ["title", "name", "service", "username", "url", "key_id"];

/// Maximum characters of a field value that may reach the frontend as a label.
pub const MAX_LABEL_CHARS: usize = 120;

/// A record's derived row labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLabels {
    /// Always populated — falls back to the record type when no allowlisted
    /// field carries a usable value.
    pub title: String,
    /// `"<field name>: <value>"`, or `None` when there is no second distinct
    /// allowlisted field.
    pub subtitle: Option<String>,
}

/// Priority rank of `name` within TITLE_NAMES, or `None` if it is not
/// allowlisted. Lower rank wins. Matching is exact and case-sensitive —
/// `vault-format.md` §6.3.1 field names are lowercase, and accepting case
/// variants would widen the gate on names nobody reviewed.
pub fn allowlist_rank(name: &str) -> Option<usize> {
    TITLE_NAMES.iter().position(|candidate| *candidate == name)
}

/// Truncate to [`MAX_LABEL_CHARS`] on a character boundary.
fn truncate(value: &str) -> String {
    value.chars().take(MAX_LABEL_CHARS).collect()
}

/// Pick title and subtitle from already-gated candidates.
///
/// `candidates` is `(rank, field name, value)`, in whatever order the record
/// yielded them; this function sorts by rank. Empty values are skipped so a
/// present-but-blank field cannot produce a blank row. The subtitle comes from
/// the first candidate whose *name* differs from the title's, so a record with
/// two same-named fields yields one label, not two.
pub fn select_labels(
    record_type: &str,
    mut candidates: Vec<(usize, String, String)>,
) -> RecordLabels {
    candidates.retain(|(_, _, value)| !value.is_empty());
    candidates.sort_by_key(|(rank, _, _)| *rank);

    let Some((_, title_name, title_value)) = candidates.first() else {
        return RecordLabels {
            title: record_type.to_owned(),
            subtitle: None,
        };
    };
    let title = truncate(title_value);

    let subtitle = candidates
        .iter()
        .find(|(_, name, _)| name != title_name)
        .map(|(_, name, value)| format!("{name}: {}", truncate(value)));

    RecordLabels { title, subtitle }
}

/// Derive a record's row labels, gating **before** any plaintext is exposed.
///
/// The ordering in the loop body is the security property: `allowlist_rank`
/// and `is_text` are both checked before `expose_text` is called, so a
/// non-allowlisted or binary field's plaintext is never materialised — not
/// even into a local that is immediately dropped.
///
/// **What is and isn't tested.** `title_path` in `tests/ipc_integration.rs`
/// pins the OUTPUT half of this property black-box: a non-allowlisted
/// field's plaintext never reaches the serialized DTO. It cannot pin the
/// ORDERING half — that the value is never materialised in the first place,
/// as opposed to materialised-then-discarded — because materialisation is
/// invisible from the wire: moving `expose_text` above the `allowlist_rank`
/// check, or deleting the `is_text` guard, would produce byte-identical
/// output (the value is dropped by `continue` either way) and every existing
/// test would still pass. That half is enforced by code structure and by
/// review, not by a test. Do not reorder.
///
/// Not unit-testable either way: `Record` cannot be constructed outside the
/// bridge (`Record::new` is `pub(crate)`), so `title_path` drives the real
/// read path over a real vault instead of calling this function directly.
pub fn labels_for_record(record: &Record) -> RecordLabels {
    let mut candidates: Vec<(usize, String, String)> = Vec::new();
    for i in 0..record.field_count() {
        let Some(handle) = record.field_at(i) else {
            continue;
        };
        let name = handle.name();
        // GATE — both checks precede expose_text. Do not reorder.
        let Some(rank) = allowlist_rank(&name) else {
            continue;
        };
        if !handle.is_text() {
            continue;
        }
        let Some(value) = handle.expose_text() else {
            continue;
        };
        candidates.push((rank, name, value));
    }
    select_labels(&record.record_type(), candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- allowlist_rank: the security gate ----

    #[test]
    fn every_allowlisted_name_ranks_in_declaration_order() {
        assert_eq!(allowlist_rank("title"), Some(0));
        assert_eq!(allowlist_rank("name"), Some(1));
        assert_eq!(allowlist_rank("service"), Some(2));
        assert_eq!(allowlist_rank("username"), Some(3));
        assert_eq!(allowlist_rank("url"), Some(4));
        assert_eq!(allowlist_rank("key_id"), Some(5));
    }

    #[test]
    fn secret_bearing_names_are_not_allowlisted() {
        for name in [
            "password",
            "key_secret",
            "private_key",
            "passphrase",
            "totp_seed",
        ] {
            assert_eq!(
                allowlist_rank(name),
                None,
                "{name} must never be title-eligible"
            );
        }
    }

    #[test]
    fn freeform_names_are_not_allowlisted() {
        // `notes` / `body` can hold anything the user typed.
        assert_eq!(allowlist_rank("notes"), None);
        assert_eq!(allowlist_rank("body"), None);
    }

    #[test]
    fn unknown_names_default_deny() {
        assert_eq!(allowlist_rank("recovery_code"), None);
        assert_eq!(allowlist_rank(""), None);
        assert_eq!(allowlist_rank("USERNAME"), None, "match is case-sensitive");
    }

    // ---- select_labels ----

    #[test]
    fn empty_candidates_fall_back_to_record_type() {
        let out = select_labels("login", vec![]);
        assert_eq!(out.title, "login");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn lowest_rank_wins_regardless_of_field_order() {
        let out = select_labels(
            "login",
            vec![
                (3, "username".into(), "alice".into()),
                (0, "title".into(), "Bank".into()),
            ],
        );
        assert_eq!(out.title, "Bank");
        assert_eq!(out.subtitle.as_deref(), Some("username: alice"));
    }

    #[test]
    fn subtitle_uses_a_different_name_not_a_repeat_of_the_title_field() {
        // Two fields both named `username` yield one subtitle candidate, not two,
        // and the name used for the title is never reused.
        let out = select_labels(
            "login",
            vec![
                (3, "username".into(), "alice".into()),
                (3, "username".into(), "bob".into()),
            ],
        );
        assert_eq!(out.title, "alice");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn single_candidate_yields_no_subtitle() {
        let out = select_labels("login", vec![(4, "url".into(), "https://x.test".into())]);
        assert_eq!(out.title, "https://x.test");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn values_are_truncated_to_the_cap() {
        let long = "a".repeat(MAX_LABEL_CHARS + 50);
        let out = select_labels("login", vec![(1, "name".into(), long)]);
        assert_eq!(out.title.chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn truncation_is_char_safe_for_multibyte_values() {
        // Slicing by byte index would panic mid-codepoint.
        let long = "é".repeat(MAX_LABEL_CHARS + 10);
        let out = select_labels("login", vec![(1, "name".into(), long)]);
        assert_eq!(out.title.chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn subtitle_is_also_truncated() {
        let long = "b".repeat(MAX_LABEL_CHARS + 50);
        let out = select_labels(
            "login",
            vec![
                (0, "title".into(), "T".into()),
                (3, "username".into(), long),
            ],
        );
        let subtitle = out.subtitle.expect("subtitle present");
        // "username: " prefix is not part of the value cap.
        assert_eq!(
            subtitle,
            format!("username: {}", "b".repeat(MAX_LABEL_CHARS))
        );
    }

    #[test]
    fn empty_value_is_ignored_and_falls_through() {
        // A present-but-empty allowlisted field must not produce a blank row.
        let out = select_labels(
            "login",
            vec![
                (0, "title".into(), "".into()),
                (3, "username".into(), "alice".into()),
            ],
        );
        assert_eq!(out.title, "alice");
        assert_eq!(out.subtitle, None);
    }
}
