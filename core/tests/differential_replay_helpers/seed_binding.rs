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
//! The expectation is read from the FIXTURE that generated each seed, not
//! restated here, so a new KAT row is bound without an edit. The multi-fault
//! witnesses under `tests/data/diff_regressions/` are in neither fixture and
//! stay scored by the pair relation.

use std::collections::BTreeMap;
use std::path::Path;

use secretary_core::crypto::secret::SecretBytes;
use serde_json::Value;

use super::corpus::CorpusInput;
use super::python_bridge::PyOutcome;
use super::rust_decoder::RustRejection;

/// The one target whose seeds the two manifest KATs write.
const BOUND_TARGET: &str = "manifest_body";
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

/// Seed file name -> the token both decoders must name.
#[derive(Debug, Default)]
pub struct SeedBindings(BTreeMap<String, &'static str>);

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
                    canonicality_token(label, row["expect_cause"].as_str())
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
        Self(map)
    }

    /// The token `input` is bound to, if it is a committed seed of a bound
    /// target that one of the fixtures generated.
    pub fn expected(&self, target: &str, input: &CorpusInput) -> Option<&'static str> {
        if target != BOUND_TARGET || !input.committed {
            return None;
        }
        let name = input.path.file_name()?.to_str()?;
        self.0.get(name).copied()
    }
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
            path: PathBuf::from("fuzz/seeds/manifest_body").join(name),
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
    }

    #[test]
    #[should_panic(expected = "unknown expect_cause")]
    fn an_unknown_cause_is_refused_not_left_unbound() {
        let canonicality = json!({"rows": [
            {"label": "x", "expect_accept": false, "expect_cause": "SomeFutureCause"}]});
        SeedBindings::from_fixtures(&canonicality, &json!({"rows": []}));
    }

    /// The census over the real fixtures: every bound name is a committed
    /// seed on disk, and the re-encode-visible ones #721 is about are all
    /// there. A seed renamed away from its label would otherwise drop out of
    /// the binding silently (the strict floor would red too, but later and
    /// without naming the file).
    #[test]
    fn every_binding_names_a_committed_seed() {
        let b = SeedBindings::load();
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/seeds")
            .join(BOUND_TARGET);
        for name in b.0.keys() {
            assert!(
                dir.join(name).is_file(),
                "bound seed {name} is not in {}",
                dir.display()
            );
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
