"""Rules E2/E3/E4's self-test control corpus (#480, #486):
`BRIDGE_POSITIVE_CONTROLS` / `BRIDGE_NEGATIVE_CONTROLS`, run through
`payload_guard.selftest.scan_bridge_control`, plus `SELF_TEST_DETAIL_SRC`,
the `detail.rs` stand-in rule E3's sanctioned-constructor lookup and rule
E4's scanned-type registry resolve against for every bridge control.

Moved out of the former single-file `scripts/check-error-payload-hygiene.py`
in #486 (task 5). Mirrors `payload_guard.controls.core`'s self-contained-
fixture design. Read the entry point's module docstring first for the WHY.
"""

from __future__ import annotations

from payload_guard.config import DETAIL_MODULE_REL
from payload_guard.rules.e4 import (
    E4_BARE, E4_GENERIC, E4_NONPATH, E4_OUTSIDE, E4_ROOT, E4_UNSCANNED,
)

# Rules E2/E3/E4 (#480) — mirrors `POSITIVE_CONTROLS` / `NEGATIVE_CONTROLS`,
# run through `scan_bridge_control` (every bridge producer) instead of
# `scan_control`.
#
# POSITIVE entries are `(label, source)`, `(label, source, expectation)`, or
# `(label, source, expectation, options)`; NEGATIVE entries are
# `(label, source)` or `(label, source, options)`. `options` is passed as
# **kwargs to `scan_bridge_control` — today only `path_label`, which rule E4
# needs because its verdict DEPENDS on whether the file being scanned is
# `detail.rs` (the one file permitted to declare an impl) or any other.
# A positive entry needing options but making no finding-shape claim passes
# `None` for the expectation.
BRIDGE_POSITIVE_CONTROLS: list[tuple] = [
    (
        "BP1 String field under an unsanctioned name in a thiserror enum",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("bad version")]
            UnknownVersion { version: String },
        }
        ''',
    ),
    (
        "BP2 String field under an unsanctioned name, interpolated (E1 path "
        "still denies in bridge_mode)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("bad: {version}")]
            UnknownVersion { version: String },
        }
        ''',
    ),
    (
        "BP3 non-thiserror *Error enum with a stray String field",
        '''
        pub enum SettingsParseError {
            UnknownVersion { version: String },
        }
        ''',
    ),
    (
        "BP4 Vec<u8> under a gated name still denies (type must be exactly "
        "String)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("x")]
            V { detail: Vec<u8> },
        }
        ''',
    ),
    (
        "BP5 a raw-identifier variant name defeats VARIANT_RE and must fail "
        "closed as UNPARSED rather than silently drop the field it "
        "declares — the r#Match witness (#480 review finding 1)",
        '''
        pub enum FooError {
            r#Match { leak: String },
        }
        ''',
        {"unparsed": True},
    ),
    (
        "BP6 plain-derive STRUCT ending in Error with a stray String field "
        "(#480 review finding 3)",
        '''
        pub struct FooError { pub leak: String }
        ''',
    ),
    (
        "BP7 a raw string inside a #[doc = ...] attribute desyncs the naive "
        "attribute scanner (skip_attributes has no raw-string awareness) "
        "and must fail closed as UNPARSED rather than silently drop the "
        "field — rustc-verified witness W1 (#480 review round 2, finding 1)",
        '''
        pub enum FooError {
            #[doc = r#"a " b"#]
            Leaky { leak: String },
        }
        ''',
        {"unparsed": True},
    ),
    (
        "BP8 a } inside a #[doc = ...] string desyncs split_top_level's "
        "bracket-depth tracking, merging two variants into one part and "
        "discarding the second — must fail closed as UNPARSED rather than "
        "silently drop the field — rustc-verified witness W2 (#480 review "
        "round 2, finding 1)",
        '''
        pub enum BazError {
            #[doc = "}"]
            A { x: usize },
            B { leak: String },
        }
        ''',
        {"unparsed": True},
    ),
    (
        "BP9 a same-named sibling struct in a DIFFERENT module must not be "
        "treated as the SAME already-swept declaration — a bare-NAME "
        "'already swept' check is fail-open here — rustc-verified witness "
        "(#480 review round 2, NEW-1a)",
        '''
        mod a {
            #[derive(thiserror::Error)]
            #[error("x")]
            pub struct DupError { pub detail: String }
        }
        mod b {
            #[derive(Debug)]
            pub struct DupError { pub leak: String }
        }
        ''',
        {"variant": "DupError", "field": "leak"},
    ),
    (
        "BP10 self-authorisation: a fake #[error(...)] struct written "
        "INSIDE a raw-string const's value must not suppress the sweep of "
        "a real, separate struct of the same name elsewhere in the file — "
        "rustc-verified witness (#480 review round 2, NEW-1b)",
        '''
        const FAKE: &str = r#"#[error("x")] pub struct LeakError {}"#;
        pub struct LeakError { pub leak: String }
        ''',
        {"variant": "LeakError", "field": "leak"},
    ),
    (
        "BP11 format! initializer on a gated field (brief BP5)",
        ''' fn f() -> E { E::V { detail: format!("x: {}", leak()) } } ''',
        {"field": "detail"},
    ),
    (
        "BP12 method-call initializer (e.to_string()) denies (brief BP6)",
        ''' fn f(e: X) -> E { E::V { detail: e.to_string() } } ''',
        {"field": "detail"},
    ),
    (
        "BP13 hex::encode initializer denies — only detail::uuid_hex is "
        "sanctioned (brief BP7)",
        ''' fn f(u: [u8; 16]) -> E { E::V { uuid_hex: hex::encode(u) } } ''',
        {"field": "uuid_hex"},
    ),
    (
        "BP14 unqualified constructor call denies — must be detail::-qualified "
        "(brief BP8)",
        ''' fn f(e: X) -> E { E::V { detail: gated(&e) } } ''',
        {"field": "detail"},
    ),
    (
        "BP15 String::new() denies — only the bare declaration token String "
        "passes (brief BP9)",
        ''' fn f() -> E { E::V { detail: String::new() } } ''',
        {"field": "detail"},
    ),
    (
        "BP16 impl GatedDetail outside detail.rs (brief BP10)",
        ''' impl GatedDetail for SomeType {} ''',
        {"field": "SomeType", "field_type_prefix": E4_OUTSIDE},
    ),
    (
        "BP17 impl GatedDetail in detail.rs for an unregistered type "
        "(brief BP11; the brief's `totally::ForeignType` is rooted at an "
        "unscanned crate, so it can never REACH the registry check — the "
        "root is `crate` here so the registry check is the only arm left)",
        ''' impl GatedDetail for crate::totally::ForeignType {} ''',
        {"field": "crate::totally::ForeignType", "field_type_prefix": E4_UNSCANNED},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP18 identifier passthrough under a DIFFERENT name denies "
        "(brief BP12)",
        ''' fn f(s: String) -> E { E::V { detail: s } } ''',
        {"field": "detail"},
    ),
    (
        "BP19 self-authorisation: a fake #[error(...)] struct written INSIDE "
        "a raw-string const's value must not register its name in "
        "scanned_error_type_names and thereby authorise an E4 impl for a "
        "same-named type (Task 3's mandated registry hardening)",
        '''
        const FAKE: &str = r#"#[error("x")] pub struct LeakError {}"#;
        impl GatedDetail for crate::x::LeakError {}
        ''',
        {"field": "crate::x::LeakError", "field_type_prefix": E4_UNSCANNED},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP20 a FOREIGN-rooted impl target must deny even when some scanned "
        "crate declares a same-named error type — the LIVE std::io::Error vs "
        "core/src/error.rs `pub enum Error` witness",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum Error {
            #[error("x")]
            V,
        }
        impl GatedDetail for std::io::Error {}
        ''',
        {"field": "std::io::Error", "field_type_prefix": E4_ROOT},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP21 a BARE impl target denies even when registered — a bare name "
        "names no crate, so it cannot be told apart from a use-imported "
        "foreign type of the same name",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum FfiVaultError {
            #[error("x")]
            V,
        }
        impl GatedDetail for FfiVaultError {}
        ''',
        {"field": "FfiVaultError", "field_type_prefix": E4_BARE},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP22 two struct declarations on ONE line: the already-swept span of "
        "the first must not swallow the second (deferred minor from Task 2's "
        "review — the span ended at end-of-line)",
        '''
#[derive(thiserror::Error, Debug)]
#[error("x")] pub struct AError { detail: String } pub struct BError { leak: String }
''',
        {"variant": "BError", "field": "leak"},
    ),
    (
        "BP23 a sanctioned call must consume the WHOLE expression — "
        "`detail::gated(&e) + <anything>` starts with one too",
        ''' fn f(e: X) -> E { E::V { detail: detail::gated(&e) + &leak() } } ''',
        {"field": "detail"},
    ),
    # ---- CRITICAL 1 (#480 task-3 review): the impl-matching regex missed
    # every generic impl, every non-path target and every qualified trait
    # path. All five sources below are rustc-compiled and produced ZERO
    # findings before `IMPL_GATED_ANCHOR_RE` replaced `IMPL_GATED_RE`.
    (
        "BP24 BLANKET impl inside detail.rs — `impl<T: Display> GatedDetail "
        "for T {}` hands the trait to every Display type in one line and was "
        "INVISIBLE to the old `impl\\s+GatedDetail` regex",
        ''' impl<T: Display> GatedDetail for T {} ''',
        {"field": "T", "field_type_prefix": E4_GENERIC},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP25 the same BLANKET impl OUTSIDE detail.rs must fire on the "
        "file arm — proves the anchor sees it wherever it is written",
        ''' impl<T: Display> GatedDetail for T {} ''',
        {"field": "T", "field_type_prefix": E4_OUTSIDE},
    ),
    (
        "BP26 `impl<'a> GatedDetail for &'a str {}` — a lifetime parameter "
        "defeats `impl\\s+`, and `&`/`'` are outside the old target class",
        """ impl<'a> GatedDetail for &'a str {} """,
        {"field": "&'a str", "field_type_prefix": E4_GENERIC},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP27 `impl GatedDetail for &Plain {}` — a REFERENCE target with no "
        "generics at all; isolates the non-path arm",
        ''' impl GatedDetail for &Plain {} ''',
        {"field": "&Plain", "field_type_prefix": E4_NONPATH},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP28 `impl<T: Display> GatedDetail for Wrap<T> {}` — a generic "
        "application, the shape the reviewer drove end-to-end into an "
        "ACCEPTED `detail: detail::gated(&Wrap(decrypted_key))`",
        ''' impl<T: Display> GatedDetail for Wrap<T> {} ''',
        {"field": "Wrap<T>", "field_type_prefix": E4_GENERIC},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP29 a FULLY-QUALIFIED trait path — `impl crate::error::detail::"
        "GatedDetail for SomeType {}` — was invisible too, because the old "
        "regex demanded the bare trait name straight after `impl `",
        ''' impl crate::error::detail::GatedDetail for SomeType {} ''',
        {"field": "SomeType", "field_type_prefix": E4_OUTSIDE},
    ),
    # ---- QUEUED ADJUDICATION: E3 detection moved to the literal-blanked
    # view, which makes THIS pass fail-OPEN on a lexer desync. Each control
    # below puts a REAL construction site immediately after a literal shape
    # that has historically desynced a scanner; all four must still fire.
    (
        "BP30 a real construction site immediately after a RAW STRING with "
        "a # run must still be detected (E3 detection is the one fail-OPEN "
        "view choice in this file)",
        '''
        const A: &str = r#"a " b"#;
        fn f() -> E { E::V { detail: leak() } }
        ''',
        {"field": "detail", "rule": "E3"},
    ),
    (
        "BP31 ... immediately after an ESCAPED QUOTE inside an ordinary "
        "string",
        '''
        const A: &str = "quote \\" inside";
        fn f() -> E { E::V { detail: leak() } }
        ''',
        {"field": "detail", "rule": "E3"},
    ),
    (
        "BP32 ... immediately after a BYTE STRING",
        '''
        const A: &[u8] = b"bytes \\x00";
        fn f() -> E { E::V { detail: leak() } }
        ''',
        {"field": "detail", "rule": "E3"},
    ),
    (
        "BP33 ... immediately after a LIFETIME / char-literal ambiguity "
        "(`&'static str` is code, `'\"'` is a literal holding a quote)",
        '''
        fn g<'a>(x: &'a str) -> &'static str { x }
        fn q() -> char { '"' }
        fn f() -> E { E::V { detail: leak() } }
        ''',
        {"field": "detail", "rule": "E3"},
    ),
    # ---- IMPORTANT 3: a #[cfg(test)]-gated constructor in detail.rs must
    # not be sanctioned. `SELF_TEST_DETAIL_SRC` declares `test_only_helper`
    # behind `#[cfg(test)]`; a shipped call to it must DENY.
    (
        "BP34 a #[cfg(test)]-gated `pub(crate) fn` in detail.rs must NOT "
        "sanction a shipped call to it",
        ''' fn f(e: X) -> E { E::V { detail: detail::test_only_helper(&e) } } ''',
        {"field": "detail", "rule": "E3"},
    ),
    (
        "BP35 a `GatedDetail for` anchor with no `impl` keyword in front of "
        "it fails closed as UNPARSED rather than being classified as though "
        "the guard knew what declared it",
        ''' const S: &str = "GatedDetail for Foo"; ''',
        {"unparsed": True, "rule": "E4"},
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BP36 #488 shape 2/3: a `let` binding to a gated name launders any "
        "expression through E3's arm 4. The `let` is ITSELF a construction "
        "of a gated value, so it is a candidate in its own right — no "
        "dataflow needed",
        ''' fn f(e: &std::io::Error) -> String { let detail = format!("{e}"); detail } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "BP37 #488 shape 2/3 with `mut` — the binding form must not be a "
        "bypass",
        ''' fn f(e: &std::io::Error) -> String { let mut detail = format!("{e}"); detail } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "BP38 #488 shape 1: post-construction assignment is a WRITE, which "
        "the initializer-position rule never saw",
        ''' fn f(x: &mut E, e: &std::io::Error) { x.detail = format!("{e}"); } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "BP39 review finding: compound assignment (`+=`) is a WRITE too, "
        "and the base pattern's bare `=` never matched the two-character "
        "compound forms at all — `x.detail += &format!(...)` is a "
        "build-then-mutate write that GATED_ASSIGN_RE must also catch",
        ''' fn f(x: &mut E, e: &std::io::Error) { x.detail += &format!("{e}"); } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "BP40 review finding: `let detail: String = <ungated>` IS caught, "
        "but not by GATED_LET_RE — the type annotation sits between the "
        "name and `=`, so GATED_LET_RE never matches it. It is caught "
        "coincidentally by GATED_INIT_RE reading the `detail:` as a "
        "field-initializer colon and extracting `String = <expr>`, which "
        "matches none of initializer_is_gated's four accepted shapes. "
        "Fail-closed, but luck, not design — pinned so a future "
        "GATED_INIT_RE edit cannot silently drop it",
        ''' fn f(e: &std::io::Error) -> String { let detail: String = format!("{e}"); detail } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "BP41 #487: `io::Error` is E4-allowlisted as a CARRIER — its Display "
        "renders whatever it was built with. A bridge site can mint one from "
        "a format!, hand it to core's VaultError::Io { source }, and reach a "
        "gated field through the allowlisted impl, bypassing E3 entirely "
        "because E3 gated the BRIDGE's initializer, not what feeds core's",
        ''' fn f(p: &std::path::Path) -> std::io::Error {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}", p.display()))
            } ''',
        {"rule": "E3", "field": "<io::Error payload>"},
    ),
    (
        "BP42 #487: the `other` constructor takes the payload as its FIRST "
        "argument — a distinct argument position from `new`",
        ''' fn f(e: &SomeError) -> std::io::Error { std::io::Error::other(e.to_string()) } ''',
        {"rule": "E3", "field": "<io::Error payload>"},
    ),
    (
        "BP43 #486: E3 shape 5 (field access) is scoped to the WRAPPER roots "
        "and must still DENY in the bridge, where nothing needs it. A new "
        "acceptance granted where it is not required is a laundering door "
        "for free",
        ''' fn f(a: A) -> E { E::V { uuid_hex: a.uuid_hex } } ''',
        {"rule": "E3", "field": "uuid_hex"},
    ),
    (
        "BP44 final-review regression: a DEFERRED-INIT `let` with no "
        "initializer (`let detail: String;`, value written on a LATER "
        "statement with no receiver dot) reads to GATED_INIT_RE exactly "
        "like a declaration and, after #488 added `;` as a terminator, "
        "extracted a clean bare `String` that arm 3 waved through — this "
        "control DENIED at merge-base 7fa210c (garbled slice, matched no "
        "accepted shape) and produced ZERO findings on this branch before "
        "the terminator-aware fix; must deny again",
        ''' fn f(e: &SomeErr) -> FfiVaultError {
                let detail: String;
                detail = format!("{e}");
                FfiVaultError::Boom { detail }
            } ''',
        {"rule": "E3", "field": "detail"},
    ),
]

BRIDGE_NEGATIVE_CONTROLS: list[tuple] = [
    (
        "BN1 detail: String under a gated name passes the declaration scan",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("sync failed: {detail}")]
            SyncFailed { detail: String },
        }
        ''',
    ),
    (
        "BN2 data-free payloads pass untouched",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("at #{index}")]
            V { index: usize },
        }
        ''',
    ),
    (
        "BN3 *Error enum inside cfg(test) is not swept",
        '''
        #[cfg(test)]
        mod tests {
            pub enum FakeError {
                V { leak: String },
            }
        }
        ''',
    ),
    (
        "BN4 *Error STRUCT inside cfg(test) is not swept (struct symmetry "
        "of BN3, #480 review finding 3)",
        '''
        #[cfg(test)]
        mod tests {
            pub struct FakeStructError {
                pub leak: String,
            }
        }
        ''',
    ),
    (
        "BN5 literal initializer (brief BN4)",
        ''' fn f() -> E { E::V { detail: "fixed" } } ''',
    ),
    (
        "BN6 literal .into() (brief BN5)",
        ''' fn f() -> E { E::V { detail: "fixed".into() } } ''',
    ),
    (
        "BN7 literal .to_string() (brief BN6)",
        ''' fn f() -> E { E::V { detail: "fixed".to_string() } } ''',
    ),
    (
        "BN8 sanctioned qualified call (brief BN7)",
        ''' fn f(e: X) -> E { E::V { detail: detail::gated(&e) } } ''',
    ),
    (
        "BN9 declaration shape `detail: String` is not an E3 finding — E2 "
        "owns declarations (brief BN8)",
        ''' pub enum E { #[error("x: {detail}")] V { detail: String } } ''',
    ),
    (
        "BN10 detail: detail passthrough (brief BN9)",
        ''' fn f(detail: String) -> E { E::V { detail: detail } } ''',
    ),
    (
        "BN11 module path detail::x( is not an initializer (brief BN10)",
        ''' fn f() -> String { detail::uuid_hex(&[0u8; 16]) } ''',
    ),
    (
        "BN12 record_uuid_hex is NOT a gated name (brief BN11)",
        ''' fn f(u: [u8; 16]) -> D { D { record_uuid_hex: hex::encode(u) } } ''',
    ),
    (
        "BN13 cfg(test) construction is skipped (brief BN12)",
        ''' #[cfg(test)] mod tests { fn f() -> E { E::V { detail: format!("{}", x()) } } } ''',
    ),
    (
        "BN14 fully-qualified crate::error::detail::gated( passes "
        "(brief BN13)",
        ''' fn f(e: X) -> E { E::V { detail: crate::error::detail::gated(&e) } } ''',
    ),
    (
        "BN15 a crate-rooted impl target whose last segment is a scanned "
        "error type passes inside detail.rs",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum FfiVaultError {
            #[error("x")]
            V,
        }
        impl GatedDetail for crate::error::FfiVaultError {}
        ''',
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BN16 a secretary_core-rooted impl target whose last segment is a "
        "scanned error type passes inside detail.rs",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum VaultError {
            #[error("x")]
            V,
        }
        impl GatedDetail for secretary_core::vault::VaultError {}
        ''',
        {"path_label": DETAIL_MODULE_REL},
    ),
    (
        "BN17 a COMMA inside the literal must not truncate the expression — "
        "this is what pins `initializer_end` to the DISCOVERY view",
        ''' fn f() -> E { E::V { detail: "fixed, with a comma" } } ''',
    ),
    (
        "BN18 a `detail:` sequence written INSIDE a string literal is not a "
        "construction site — the queued adjudication that moved E3 DETECTION "
        "to the literal-blanked view (removed 3 live false positives in "
        "error/vault/tests.rs)",
        '''
        fn f(ok: bool, rendered: String) {
            assert!(ok, "Display did not include detail: {rendered}");
        }
        ''',
    ),
    (
        "BN19 #488: a `let` bound to a SANCTIONED constructor call is the "
        "legitimate shape and must not fire",
        ''' fn f(e: &impl GatedDetail) -> String { let detail = detail::gated(e); detail } ''',
    ),
    (
        "BN20 #488: a PATTERN binding is the legitimate re-wrap the design "
        "mandates — it is not a `let`, and arm 4 keeps serving it",
        '''
        fn f(e: FfiVaultError) -> FfiVaultError {
            match e {
                FfiVaultError::CorruptVault { detail } => FfiVaultError::CorruptVault { detail },
            }
        }
        ''',
    ),
    (
        "BN21 #488: `==` is not an assignment — the assign rule must not "
        "match a comparison",
        ''' fn f(x: &E, s: &str) -> bool { x.detail == s } ''',
    ),
    (
        "BN22 review finding: `!=` is not an assignment either — `!` is "
        "not one of the admitted compound-operator characters, so the "
        "required `=` never lines up with it; unlike BN21 this was already "
        "true of the base pattern, and was previously unstated by any "
        "control",
        ''' fn f(x: &E, s: &str) -> bool { x.detail != s } ''',
    ),
    (
        "BN23 #487: a LITERAL payload is the shape the four production "
        "io::Error sites already use and must not fire",
        ''' fn f() -> std::io::Error { std::io::Error::new(std::io::ErrorKind::NotFound, "missing") } ''',
    ),
    (
        "BN24 #487: a payload built through a sanctioned constructor passes, "
        "which is what makes the rewrite of repair/orchestration.rs possible",
        ''' fn f(e: &impl GatedDetail) -> std::io::Error {
                std::io::Error::new(std::io::ErrorKind::InvalidData, detail::gated(e))
            } ''',
    ),
]

# The `detail.rs` stand-in every self-test control's rule-E3 sanctioned-
# constructor lookup resolves against. Deliberately a SEPARATE fixture from
# the real file: a control asserting "only `detail::gated` / `detail::uuid_hex`
# are sanctioned" must not silently change meaning when someone adds a
# constructor to the real `error/detail.rs`. `test_only_helper` is
# `#[cfg(test)]`-gated and must NOT be sanctioned (`BP34`).
SELF_TEST_DETAIL_SRC = '''
pub(crate) trait GatedDetail: std::fmt::Display {}

pub(crate) fn gated(e: &impl GatedDetail) -> String {
    e.to_string()
}

pub(crate) fn uuid_hex(uuid: &[u8; 16]) -> String {
    hex::encode(uuid)
}

#[cfg(test)]
pub(crate) fn test_only_helper(e: &impl GatedDetail) -> String {
    e.to_string()
}
'''
