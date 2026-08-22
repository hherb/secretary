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
//! construction rather than by enumeration. A denylist here would fail open —
//! it would ship a title for every name nobody thought to exclude — and that
//! is not how the gates in this repository are built. (`check-public-log-
//! hygiene.sh`'s rule 3 is a denylist, but an explicitly-labelled best-effort
//! one backing two default-deny rules, not a gate standing on its own.)
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
///
/// Which makes it a **test** edit too — `title_names_are_pinned` asserts this
/// exact array. Without that pin, appending a seventh entry passed every test
/// in the tree, and this doc comment was the only thing standing between a new
/// name and a persistent, unmasked render of its plaintext (#526 review).
///
/// # `url` was considered and deliberately kept (#526 review, #532)
///
/// A URL can embed credentials in its authority — `https://admin:pw@host` —
/// so an allowlisted `url` field can put a password on screen persistently,
/// where the same bytes read through `reveal_field` would re-mask after
/// `REVEAL_AUTO_HIDE_MS`. Stripping the userinfo component was weighed and
/// **rejected**: a secrets manager cannot protect a user who stores a secret
/// in a field not meant to hold one, and a URL is the single most useful
/// row label for the login records that dominate a vault. Silently rewriting
/// what the user typed would also make the row disagree with the record.
/// Decision recorded here rather than in the issue so the next person to read
/// this array does not have to re-derive it.
const TITLE_NAMES: [&str; 6] = ["title", "name", "service", "username", "url", "key_id"];

/// Maximum characters of a field value that may reach the frontend as a label.
pub const MAX_LABEL_CHARS: usize = 120;

/// Last-resort row label when a record has neither an allowlisted value nor a
/// record type. `record_type` is genuinely optional in the editor ("Type
/// (optional)"), so this is reachable in ordinary use, not just under a wiped
/// handle — and an empty title renders as a blank, unidentifiable row and a
/// blank detail-pane heading (#526 review).
const UNTITLED_LABEL: &str = "Untitled record";

/// A record's derived row labels.
///
/// Secret-bearing → redacted `Debug`: both fields hold a decrypted field
/// value. See `dtos::browse`'s module doc.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordLabels {
    /// Never empty. Falls back to the record type, then to a fixed
    /// `UNTITLED_LABEL` constant.
    pub title: String,
    /// `"<field name>: <value>"`, or `None` when there is no second distinct
    /// allowlisted field.
    pub subtitle: Option<String>,
}

impl std::fmt::Debug for RecordLabels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordLabels")
            .field("title", &format_args!("<redacted>"))
            .field(
                "subtitle",
                &format_args!(
                    "{}",
                    if self.subtitle.is_some() {
                        "<redacted>"
                    } else {
                        "None"
                    }
                ),
            )
            .finish()
    }
}

/// One allowlisted field that cleared the gate, with its priority.
///
/// A named struct rather than the `(usize, String, String)` this used to be:
/// the two `String`s are adjacent and same-typed, so `push((rank, value,
/// name))` compiled cleanly and silently swapped the label with the field
/// name. `labels_for_record` — the only production producer — is not
/// unit-testable (see its doc), so nothing but the integration test's exact
/// title string would have caught it (#526 review).
pub(crate) struct Candidate {
    pub(crate) rank: usize,
    pub(crate) name: String,
    pub(crate) value: String,
}

/// Priority rank of `name` within TITLE_NAMES, or `None` if it is not
/// allowlisted. Lower rank wins. Matching is exact and case-sensitive —
/// `vault-format.md` §6.3.1 field names are lowercase, and accepting case
/// variants would widen the gate on names nobody reviewed.
pub(crate) fn allowlist_rank(name: &str) -> Option<usize> {
    TITLE_NAMES.iter().position(|candidate| *candidate == name)
}

/// Truncate to [`MAX_LABEL_CHARS`] on a character boundary.
fn truncate(value: &str) -> String {
    value.chars().take(MAX_LABEL_CHARS).collect()
}

/// The label shown when no allowlisted field yielded a usable value.
///
/// Truncated like any other label — `record_type` is user-authored and
/// unbounded — and never empty, so a row always has something to identify it.
fn fallback_title(record_type: &str) -> String {
    let trimmed = record_type.trim();
    if trimmed.is_empty() {
        UNTITLED_LABEL.to_owned()
    } else {
        truncate(trimmed)
    }
}

/// Pick title and subtitle from already-gated candidates.
///
/// Candidates arrive in whatever order the record yielded them; this function
/// sorts by rank. Values that are empty **or whitespace-only** are skipped, so
/// a present-but-blank field cannot produce a blank row — `is_empty()` alone
/// let a lone `" "` through and rendered an unidentifiable row (#526 review).
/// Surviving values are trimmed for display for the same reason.
///
/// The subtitle comes from the first candidate whose *name* differs from the
/// title's. In production, names are unique — `core`'s `Record` stores fields
/// in a `BTreeMap` keyed by name — so this is simply "the next-ranked
/// candidate"; the distinct-name check is defence-in-depth for direct callers
/// of this function, which the unit tests are.
pub(crate) fn select_labels(record_type: &str, mut candidates: Vec<Candidate>) -> RecordLabels {
    candidates.retain(|c| !c.value.trim().is_empty());
    candidates.sort_by_key(|c| c.rank);

    let Some(first) = candidates.first() else {
        return RecordLabels {
            title: fallback_title(record_type),
            subtitle: None,
        };
    };
    let title = truncate(first.value.trim());

    let subtitle = candidates
        .iter()
        .find(|c| c.name != first.name)
        .map(|c| format!("{}: {}", c.name, truncate(c.value.trim())));

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
    let mut candidates: Vec<Candidate> = Vec::new();
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
        candidates.push(Candidate { rank, name, value });
    }
    select_labels(&record.record_type(), candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(rank: usize, name: &str, value: &str) -> Candidate {
        Candidate {
            rank,
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    // ---- allowlist_rank: the security gate ----

    #[test]
    fn title_names_are_pinned() {
        // The allowlist's CONTENTS, not just its behaviour. Every other test
        // here is satisfied by a SUPERSET: appending "recovery_phrase" leaves
        // all six existing ranks unchanged, is absent from every deny list,
        // and passes the whole suite — while rendering that field's plaintext
        // persistently and unmasked in the record list. Widening the gate must
        // cost a deliberate edit here, where the security claim is reviewed.
        assert_eq!(
            TITLE_NAMES,
            ["title", "name", "service", "username", "url", "key_id"],
            "TITLE_NAMES changed — is every name still safe to render \
             persistently and unmasked? See this module's doc comment."
        );
    }

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
            vec![cand(3, "username", "alice"), cand(0, "title", "Bank")],
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
            vec![cand(3, "username", "alice"), cand(3, "username", "bob")],
        );
        assert_eq!(out.title, "alice");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn single_candidate_yields_no_subtitle() {
        let out = select_labels("login", vec![cand(4, "url", "https://x.test")]);
        assert_eq!(out.title, "https://x.test");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn values_are_truncated_to_the_cap() {
        let long = "a".repeat(MAX_LABEL_CHARS + 50);
        let out = select_labels("login", vec![cand(1, "name", &long)]);
        assert_eq!(out.title.chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn truncation_is_char_safe_for_multibyte_values() {
        // Slicing by byte index would panic mid-codepoint.
        let long = "é".repeat(MAX_LABEL_CHARS + 10);
        let out = select_labels("login", vec![cand(1, "name", &long)]);
        assert_eq!(out.title.chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn subtitle_is_also_truncated() {
        let long = "b".repeat(MAX_LABEL_CHARS + 50);
        let out = select_labels(
            "login",
            vec![cand(0, "title", "T"), cand(3, "username", &long)],
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
            vec![cand(0, "title", ""), cand(3, "username", "alice")],
        );
        assert_eq!(out.title, "alice");
        assert_eq!(out.subtitle, None);
    }

    // ---- blank / missing values (#526 review) ----

    #[test]
    fn whitespace_only_value_is_ignored_like_an_empty_one() {
        // `is_empty()` alone let these through and rendered a blank row that
        // the user could neither identify nor distinguish from its neighbours.
        for blank in [" ", "\t", "\n", "   \t\n "] {
            let out = select_labels(
                "login",
                vec![cand(0, "title", blank), cand(3, "username", "alice")],
            );
            assert_eq!(out.title, "alice", "blank {blank:?} won the title");
            assert_eq!(out.subtitle, None);
        }
    }

    #[test]
    fn a_lone_whitespace_value_falls_back_rather_than_blanking_the_row() {
        let out = select_labels("login", vec![cand(0, "title", "   ")]);
        assert_eq!(out.title, "login");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn surviving_values_are_trimmed_for_display() {
        let out = select_labels(
            "login",
            vec![
                cand(0, "title", "  Bank  "),
                cand(3, "username", "\talice\n"),
            ],
        );
        assert_eq!(out.title, "Bank");
        assert_eq!(out.subtitle.as_deref(), Some("username: alice"));
    }

    #[test]
    fn a_typeless_record_with_no_candidates_still_gets_a_title() {
        // `record_type` is "Type (optional)" in the editor, so an empty one is
        // ordinary use — not merely a wiped-handle artefact. An empty title
        // renders as a blank row AND a blank detail-pane heading.
        for record_type in ["", "   ", "\t"] {
            let out = select_labels(record_type, vec![]);
            assert_eq!(out.title, UNTITLED_LABEL);
            assert_eq!(out.subtitle, None);
        }
    }

    #[test]
    fn record_type_fallback_is_trimmed_and_truncated() {
        let out = select_labels("  login  ", vec![]);
        assert_eq!(out.title, "login");

        let long = "t".repeat(MAX_LABEL_CHARS + 50);
        let out = select_labels(&long, vec![]);
        assert_eq!(out.title.chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn title_is_never_empty_for_any_input_combination() {
        // The invariant RecordLabels.title's doc comment claims, over every
        // shape that reaches it: no candidates, blank candidates, blank type.
        for record_type in ["", " ", "login"] {
            for candidates in [
                vec![],
                vec![cand(0, "title", "")],
                vec![cand(0, "title", "  ")],
                vec![cand(0, "title", "Bank")],
            ] {
                let out = select_labels(record_type, candidates);
                assert!(
                    !out.title.is_empty(),
                    "empty title for type {record_type:?}"
                );
            }
        }
    }

    // ---- redacted Debug ----

    #[test]
    fn debug_redacts_both_labels() {
        let labels = select_labels(
            "login",
            vec![cand(0, "title", "Bank"), cand(3, "username", "alice")],
        );
        let rendered = format!("{labels:?}");
        assert!(!rendered.contains("Bank"), "{rendered}");
        assert!(!rendered.contains("alice"), "{rendered}");
    }
}
