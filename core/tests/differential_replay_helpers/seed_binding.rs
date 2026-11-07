//! Committed seeds bound by their LABEL to the one rule token both decoders
//! must name (#721).
//!
//! Each `manifest_body` seed the canonicality and uniqueness KATs generated
//! breaks exactly one rule by construction, so there is no report-order
//! question. Both sides must name that rule, whatever `tokens_agree` would
//! tolerate. Without the binding, the 17 seeds whose token is re-encode-visible
//! (`array_sort_order`, §6.2 rules 2-3, `non_canonical_unclassified`) were
//! scored by vault-format §4.2's pair relation, which excuses a re-encode-visible
//! token against most other manifest rules. So a raise site moved onto another
//! freely ordered rule passed, and none of them counted as strict.
//!
//! The canonicality rows are read from the FIXTURE that generated each seed
//! (its `expect_cause` column, through [`canonicality_token`]'s cause table);
//! the uniqueness fixture has no cause column, so every rejecting row there is
//! bound to [`UNIQUENESS_TOKEN`]. A new KAT row is bound without an edit here,
//! but the exact census in `every_binding_names_a_committed_seed` and the
//! `MIN_STRICT_COMPARISONS` floor still ask for one, deliberately. Only files
//! under `fuzz/seeds/manifest_body/` are bound: the multi-fault witnesses under
//! `tests/data/diff_regressions/` are committed too, but they break two rules,
//! so they stay scored by the pair relation even if one reused a KAT label.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use secretary_core::crypto::secret::SecretBytes;
use serde_json::Value;

use super::corpus::CorpusInput;
use super::python_bridge::PyOutcome;
use super::rust_decoder::RustRejection;

/// The one target whose seeds the two manifest KATs write.
const BOUND_TARGET: &str = "manifest_body";
/// The directory both generators write into, relative to the package root.
const SEED_DIR: &str = "fuzz/seeds/manifest_body";
const CANONICALITY_KAT: &str = "tests/data/manifest_canonicality_kat.json";
const UNIQUENESS_KAT: &str = "tests/data/manifest_uniqueness_kat.json";
/// `manifest_uniqueness_kat`'s generator writes row `L` as `uniq__L.bin`;
/// the canonicality generator writes it as `L.bin`.
const UNIQUENESS_SEED_PREFIX: &str = "uniq__";
const SEED_EXTENSION: &str = ".bin";
/// Every rejecting uniqueness row is a repeated array value (§4.2).
const UNIQUENESS_TOKEN: &str = "repeated_array_value";

/// The token for a rejecting canonicality row, from its `expect_cause`.
///
/// `null` on a rejecting row means the body was refused before the §4.3
/// step-4 re-encode, which in this corpus is only the `rule4_float` rows. An
/// unknown cause name panics rather than leaving its seed unbound.
fn canonicality_token(label: &str, expect_cause: Option<&str>) -> &'static str {
    match expect_cause {
        None => "rule4_tag_or_float",
        Some("ArraySortOrder") => "array_sort_order",
        Some("IndefiniteLength") => "rule2_indefinite_length",
        Some("NonShortestForm") => "rule3_non_shortest_form",
        Some("Unclassified") => "non_canonical_unclassified",
        Some(other) => panic!("row {label:?}: unknown expect_cause {other:?}; bind it here"),
    }
}

/// Seed file name -> the token both decoders must name, plus the names
/// [`SeedBindings::expected`] has matched so far, so the replay can prove it
/// judged every bound seed ([`SeedBindings::assert_every_seed_was_judged`]).
#[derive(Debug, Default)]
pub struct SeedBindings(BTreeMap<String, &'static str>, RefCell<BTreeSet<String>>);

impl SeedBindings {
    /// Read both fixtures under the secretary-core package root.
    pub fn load() -> Self {
        let read = |rel: &str| -> Value {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
        };
        Self::from_fixtures(&read(CANONICALITY_KAT), &read(UNIQUENESS_KAT))
    }

    /// Pure: the bindings the two parsed fixtures declare. Accepting rows
    /// bind nothing (both sides must accept them, which `judge` already
    /// checks byte for byte).
    pub fn from_fixtures(canonicality: &Value, uniqueness: &Value) -> Self {
        let mut map = BTreeMap::new();
        for (fixture, prefix) in [(canonicality, ""), (uniqueness, UNIQUENESS_SEED_PREFIX)] {
            let rows = fixture["rows"]
                .as_array()
                .expect("fixture has a `rows` array");
            for row in rows {
                let label = row["label"].as_str().expect("row has a string `label`");
                let accepts = row["expect_accept"]
                    .as_bool()
                    .unwrap_or_else(|| panic!("row {label:?}: `expect_accept` must be a bool"));
                if accepts {
                    continue;
                }
                let token = if prefix.is_empty() {
                    canonicality_token(label, expect_cause(label, row))
                } else {
                    UNIQUENESS_TOKEN
                };
                let name = format!("{prefix}{label}{SEED_EXTENSION}");
                assert!(
                    map.insert(name.clone(), token).is_none(),
                    "{name} is bound twice"
                );
            }
        }
        Self(map, RefCell::default())
    }

    /// The token `input` is bound to, if it is a committed seed in
    /// [`SEED_DIR`] that one of the fixtures generated. Records the match.
    pub fn expected(&self, target: &str, input: &CorpusInput) -> Option<&'static str> {
        let in_seed_dir = input.path.parent().is_some_and(|d| d.ends_with(SEED_DIR));
        if target != BOUND_TARGET || !input.committed || !in_seed_dir {
            return None;
        }
        let name = input.path.file_name()?.to_str()?;
        let token = self.0.get(name).copied()?;
        self.1.borrow_mut().insert(name.to_owned());
        Some(token)
    }

    /// Panic naming every bound seed [`Self::expected`] never matched. The
    /// strict floor would red too, but not for the seven bound seeds whose
    /// token is not re-encode-visible (they count as strict unbound), and
    /// without naming a file.
    pub fn assert_every_seed_was_judged(&self) {
        let seen = self.1.borrow();
        let missed: Vec<_> = self.0.keys().filter(|k| !seen.contains(*k)).collect();
        assert!(
            missed.is_empty(),
            "label-bound seed(s) never judged against their token: {missed:?}"
        );
    }
}

/// A canonicality row's `expect_cause`: `None` for an explicit `null`. A
/// missing key or a non-string panics, since `row["expect_cause"]` would read
/// both as `null`, and `null` binds rule 4 (`manifest_canonicality_kat.rs`
/// reads the column the same way, for the same reason).
fn expect_cause<'a>(label: &str, row: &'a Value) -> Option<&'a str> {
    let v = row
        .get("expect_cause")
        .unwrap_or_else(|| panic!("row {label:?}: no `expect_cause` key"));
    if v.is_null() {
        return None;
    }
    Some(
        v.as_str()
            .unwrap_or_else(|| panic!("row {label:?}: `expect_cause` must be a string or null")),
    )
}

/// Did both sides reject, each naming exactly `want`?
pub fn both_reject_naming(
    want: &str,
    rust: &Result<SecretBytes, RustRejection>,
    python: &PyOutcome,
) -> bool {
    matches!(rust, Err(RustRejection { token: Some(r), .. }) if *r == want)
        && matches!(python, PyOutcome::Reject { rule: Some(p), .. } if p == want)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn seed(name: &str, committed: bool) -> CorpusInput {
        CorpusInput {
            path: PathBuf::from(SEED_DIR).join(name),
            committed,
        }
    }

    fn fixtures() -> SeedBindings {
        let canonicality = json!({"rows": [
            {"label": "top__control_canonical", "expect_accept": true, "expect_cause": null},
            {"label": "top__rule4_float", "expect_accept": false, "expect_cause": null},
            {"label": "arraysort__blocks", "expect_accept": false, "expect_cause": "ArraySortOrder"},
            {"label": "keyorder__top", "expect_accept": false, "expect_cause": "Unclassified"},
        ]});
        let uniqueness = json!({"rows": [
            {"label": "control__all_distinct", "expect_accept": true},
            {"label": "blocks__duplicate_block_uuid", "expect_accept": false},
        ]});
        SeedBindings::from_fixtures(&canonicality, &uniqueness)
    }

    #[test]
    fn each_rejecting_row_binds_its_seed_to_one_token() {
        let b = fixtures();
        let want = [
            ("top__rule4_float.bin", "rule4_tag_or_float"),
            ("arraysort__blocks.bin", "array_sort_order"),
            ("keyorder__top.bin", "non_canonical_unclassified"),
            (
                "uniq__blocks__duplicate_block_uuid.bin",
                "repeated_array_value",
            ),
        ];
        for (name, token) in want {
            assert_eq!(
                b.expected(BOUND_TARGET, &seed(name, true)),
                Some(token),
                "{name}"
            );
        }
        assert_eq!(b.0.len(), want.len(), "accepting rows bind nothing");
    }

    #[test]
    fn only_a_committed_seed_of_the_bound_target_is_bound() {
        let b = fixtures();
        assert_eq!(
            b.expected(BOUND_TARGET, &seed("arraysort__blocks.bin", false)),
            None
        );
        assert_eq!(
            b.expected("record", &seed("arraysort__blocks.bin", true)),
            None
        );
        assert_eq!(
            b.expected(BOUND_TARGET, &seed("arraysort_plus_indefinite.bin", true)),
            None
        );
        // A committed witness reusing a KAT label outside the seed dir.
        let witness = CorpusInput {
            path: PathBuf::from("tests/data/diff_regressions/manifest_body")
                .join("arraysort__blocks.bin"),
            committed: true,
        };
        assert_eq!(b.expected(BOUND_TARGET, &witness), None);
    }

    #[test]
    fn every_bound_seed_must_be_judged() {
        let b = fixtures();
        let all: Vec<String> = b.0.keys().cloned().collect();
        for name in &all[1..] {
            assert!(b.expected(BOUND_TARGET, &seed(name, true)).is_some());
        }
        let missed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b.assert_every_seed_was_judged()
        }));
        assert!(missed.is_err(), "one seed was never judged");
        b.expected(BOUND_TARGET, &seed(&all[0], true));
        b.assert_every_seed_was_judged();
    }

    #[test]
    #[should_panic(expected = "unknown expect_cause")]
    fn an_unknown_cause_is_refused_not_left_unbound() {
        let canonicality = json!({"rows": [
            {"label": "x", "expect_accept": false, "expect_cause": "SomeFutureCause"}]});
        SeedBindings::from_fixtures(&canonicality, &json!({"rows": []}));
    }

    /// `row["expect_cause"]` reads a missing key and a number as `null`,
    /// which would bind rule 4; both are refused instead.
    #[test]
    fn a_missing_or_non_string_cause_is_refused() {
        for row in [
            json!({"label": "x", "expect_accept": false}),
            json!({"label": "x", "expect_accept": false, "expect_cause": 7}),
        ] {
            let r = std::panic::catch_unwind(|| {
                SeedBindings::from_fixtures(&json!({"rows": [row.clone()]}), &json!({"rows": []}))
            });
            assert!(r.is_err(), "{row}");
        }
    }

    /// The census over the real fixtures, both directions. Every bound name
    /// is a committed seed on disk, and every seed carrying a KAT generator's
    /// prefix is a row of its fixture: a seed orphaned by a renamed row would
    /// otherwise stay unbound and be scored by the pair relation. For the 17
    /// re-encode-visible seeds the strict floor would red too, later and
    /// without naming the file; for the other 7 this census alone does,
    /// since they count as strict unbound.
    #[test]
    fn every_binding_names_a_committed_seed() {
        let b = SeedBindings::load();
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(SEED_DIR);
        for name in b.0.keys() {
            assert!(
                dir.join(name).is_file(),
                "bound seed {name} is not in {}",
                dir.display()
            );
        }
        let rows = |rel: &str, prefix: &str| -> BTreeSet<String> {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
            let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            v["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| format!("{prefix}{}{SEED_EXTENSION}", r["label"].as_str().unwrap()))
                .collect()
        };
        let mut known = rows(CANONICALITY_KAT, "");
        known.extend(rows(UNIQUENESS_KAT, UNIQUENESS_SEED_PREFIX));
        // `manifest_canonicality_kat`'s level and mutation prefixes, and
        // `manifest_uniqueness_kat`'s.
        const KAT_PREFIXES: [&str; 6] = [
            "top__",
            "block__",
            "trash__",
            "arraysort__",
            "keyorder__",
            UNIQUENESS_SEED_PREFIX,
        ];
        for entry in std::fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if KAT_PREFIXES.iter().any(|p| name.starts_with(p)) {
                assert!(
                    known.contains(&name),
                    "seed {name} is a row of neither KAT fixture"
                );
            }
        }
        let reencode_visible =
            b.0.values()
                .filter(|t| {
                    secretary_core::vault::manifest::RuleToken::ALL
                        .iter()
                        .any(|r| r.as_str() == **t && r.is_phase_dependent())
                })
                .count();
        const WANT_REENCODE_VISIBLE: usize = 17;
        const WANT_BOUND: usize = 24;
        assert_eq!(reencode_visible, WANT_REENCODE_VISIBLE);
        assert_eq!(b.0.len(), WANT_BOUND);
    }

    #[test]
    fn both_sides_must_name_the_bound_token() {
        let err = |t| -> Result<SecretBytes, RustRejection> {
            Err(RustRejection {
                token: Some(t),
                detail: String::new(),
            })
        };
        let rej = |t: &str| PyOutcome::Reject {
            rule: Some(t.into()),
            detail: String::new(),
        };
        let want = "array_sort_order";
        assert!(both_reject_naming(want, &err(want), &rej(want)));
        assert!(!both_reject_naming(
            want,
            &err("rule2_indefinite_length"),
            &rej(want)
        ));
        assert!(!both_reject_naming(
            want,
            &err(want),
            &rej("repeated_array_value")
        ));
        assert!(!both_reject_naming(
            want,
            &Ok(SecretBytes::new(vec![])),
            &rej(want)
        ));
        assert!(!both_reject_naming(
            want,
            &err(want),
            &PyOutcome::Accept(vec![])
        ));
    }
}
