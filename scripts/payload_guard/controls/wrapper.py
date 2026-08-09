"""The wrapper-root self-test control corpus (#486):
`WRAPPER_POSITIVE_CONTROLS` / `WRAPPER_NEGATIVE_CONTROLS`, run through
`payload_guard.selftest.scan_wrapper_control` — the wrapper-root rule set
(`bridge_mode=True` plus E2/E3, no E4; rule E5 runs separately, over
`path_label` + `raw` + the root's `detail_module_rel`, since it needs the
WHOLE FILE TEXT rather than a single self-contained fixture string — see
`WP4`/`WN2`/`WN3` below and `payload_guard.scan.run_real_scan`'s
`format_confinement` wiring).

Written for rule E3's shape 5, which #497/#500 RETIRED on every root once
its four DTO pass-through sites moved onto `detail::project(...)`;
`allow_field_access` is False everywhere now and `WP7` pins the denial. E5
is the rule the wrapper roots take and the bridge does not.

Mirrors `payload_guard.controls.bridge`'s self-contained-fixture design.
`BP43` lives in the BRIDGE corpus rather than here because it asserts what
the bridge root does, not what a wrapper root does — it used to be the
bridge half of shape 5's per-root SCOPING story, and with the flag off
everywhere it and `WP7` now simply pin the same expression denying on both
sides. Read the entry point's module docstring first for the WHY.

A fixture asserting a construct MUST DENY (produce a finding) is a
POSITIVE control here, matching `WP1`'s own precedent ("... is not a
pass-through and must deny") — `WRAPPER_NEGATIVE_CONTROLS` fails the
self-test the moment its fixture produces ANY finding
(`payload_guard.selftest.run_self_test`'s `if found: failures.append(...)`),
so a "must deny" claim can only be encoded as a POSITIVE entry regardless of
how the English reads. `WP3` (task 9 review finding) is placed accordingly.

`WP4`/`WN2`/`WN3` (task 11, rule E5) were labelled `WP3`/`WN2`/`WN3` in the
task brief; `WP3` was already taken by the task 9 review finding above by
the time task 11 landed, so the new positive control is `WP4` instead — the
NEGATIVE numbering (`WN2`/`WN3`) matched the brief as written, since only
`WN1` existed before this task. Label TEXT is otherwise verbatim from the
brief.
"""

from __future__ import annotations

# A wrapper `detail.rs` stand-in that declares the #500 projection constructor.
# `project`'s only parameter is a `Detail`, which sits in rule E3's
# `SAFE_PARAM_TYPES` — so unlike `passthrough(&str)` (BP49) the constructor
# survives the signature gate and its call sites are sanctioned.
SELF_TEST_WRAPPER_DETAIL_SRC_WITH_PROJECT = '''
pub(crate) fn arg_len(field: &'static str, n: usize) -> String {
    format!("{field}: {n}")
}

pub(crate) fn project(d: Detail) -> String {
    d.into_string()
}
'''

# A wrapper `detail.rs` stand-in carrying a DECOY type called `Detail` (#500
# fix round 1). `SAFE_PARAM_TYPES` matches the spelling, not the resolved
# type, so before the fix this sanctioned `detail::launder(<anything>)`.
SELF_TEST_WRAPPER_DETAIL_SRC_WITH_DECOY = '''
pub(crate) struct Detail(pub String);

pub(crate) fn launder(d: Detail) -> String {
    d.0
}
'''

WRAPPER_POSITIVE_CONTROLS: list[tuple] = [
    (
        "WP1 a field access whose last segment is NOT the gated field's own "
        "name is not a DTO pass-through and must deny. This was shape 5's "
        "final-segment test; with `allow_field_access` OFF (#497/#500) it "
        "denies one step earlier, at the flag. Kept because it must STILL "
        "deny if the acceptance is ever re-enabled — re-enabling it and "
        "re-running is the check a future author owes this control",
        ''' fn f(a: &A) -> E { E::V { uuid_hex: a.some_other_field } } ''',
        {"rule": "E3", "field": "uuid_hex"},
    ),
    (
        "WP2 a hand-rolled format! into a gated field denies in a wrapper "
        "root exactly as it does in the bridge — a per-root E3 acceptance "
        "widens the accepted set, it never disables the rule",
        ''' fn f(n: usize) -> E { E::V { detail: format!("got {n}") } } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "WP3 review finding (task 9): a depth-2 chain `a.b.uuid_hex` is a "
        "claim about an intermediate value (`a.b`) this rule has no way to "
        "vouch for, and must DENY even though its final segment is the "
        "gated name. An earlier, unbounded-depth version of "
        "`FIELD_ACCESS_RE` accepted this — wider than the shape it was "
        "written to recognise, and untested in the extra width. Like `WP1` "
        "this now denies at the `allow_field_access` flag (#497/#500) "
        "rather than at the depth test; both must still hold if shape 5 is "
        "re-enabled",
        ''' fn f(a: A) -> E { E::V { uuid_hex: a.b.uuid_hex } } ''',
        {"rule": "E3", "field": "uuid_hex"},
    ),
    (
        "WP4 rule E5: a hand-rolled format! anywhere in a wrapper crate "
        "outside its sanctioned detail.rs is a finding. This is the class E3 "
        "structurally CANNOT see — ffi-py's platform sink is "
        "`VaultNotAuthor::new_err(format!(...))`, a function ARGUMENT, not a "
        "gated-field initializer, so no extension of E3's initializer model "
        "reaches it. 30/30 production format! sites in these crates are "
        "error-bound, which is what makes confinement cost zero legitimate-"
        "use allowlist entries",
        ''' fn f(a: &str, b: &str) -> PyErr { VaultNotAuthor::new_err(format!("{a}/{b}")) } ''',
        {"rule": "E5"},
    ),
    (
        "WP5 #496: rule E5 consumes the cfg spans as a SKIP LIST too, so the "
        "permissive `\\btest\\b` matcher let `#[cfg(not(test))]` — a "
        "PRODUCTION marker — silence a wrapper `format!`. The E3 half of this "
        "class is BP47/BP48; this is the E5 half, and it is a separate "
        "consumer that would not have been covered by those",
        ''' #[cfg(not(test))]
            fn f(a: &str) -> PyErr { VaultNotAuthor::new_err(format!("{a}")) } ''',
        {"rule": "E5"},
    ),
    (
        "WP6 #500: the INLINE unwrap `detail: detail.into_string()` still "
        "DENIES. Adding `Detail` to SAFE_PARAM_TYPES sanctions a CALL to a "
        "wrapper detail.rs constructor that takes one; it must not also make "
        "a trailing transform legal in a gated initializer. This is the "
        "shape all ~27 wrapper projection arms took before they were routed "
        "through `detail::project`, and it matches neither arm 4 (the "
        "expression is not the bare field name) nor arm 5 (shape 5 is a "
        "single-hop field access, nothing appended)",
        ''' fn f(e: FfiVaultError) -> E { E::V { detail: detail.into_string() } } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "WP7 #497/#500: the single-hop DTO pass-through `uuid_hex: "
        "a.uuid_hex` now DENIES on a wrapper root. It was E3 shape 5's whole "
        "purpose and this control was `WN1`, asserting the opposite; #500 "
        "moved all four live sites onto `detail::project(...)`, so the "
        "acceptance had ZERO users, and shape 5 admits an ARBITRARY "
        "single-hop receiver — a local of any type, including one declared "
        "outside every scan root — which is wider than the four DTOs that "
        "justified it. `ScanRoot.allow_field_access`'s own docstring says an "
        "acceptance granted where nothing needs it is a laundering door for "
        "free, so it was switched off. Flipping either wrapper root back to "
        "True must make this control stop firing",
        ''' fn f(a: A) -> E { E::V { uuid_hex: a.uuid_hex } } ''',
        {"rule": "E3", "field": "uuid_hex"},
    ),
    (
        "WP8 #500 fix round 1: a LOCALLY-DECLARED decoy type named `Detail` "
        "in a wrapper's own detail.rs must NOT satisfy SAFE_PARAM_TYPES' "
        "spelling test. The set matches the TEXT `Detail`, not the resolved "
        "type, and only the BRIDGE declares the authentic newtype — so "
        "`pub(crate) struct Detail(pub String)` plus `launder(d: Detail)` "
        "made `detail::launder(Detail(anything))` scan OK (verified by "
        "execution). The constructor must now be DROPPED from the "
        "sanctioned set, so its call site denies. Setting "
        "`owns_detail_type=True` on a wrapper root must make this stop firing",
        ''' fn f(x: String) -> E { E::V { detail: detail::launder(Detail(x)) } } ''',
        {"rule": "E3", "field": "detail"},
        {"detail_src": SELF_TEST_WRAPPER_DETAIL_SRC_WITH_DECOY},
    ),
]

WRAPPER_NEGATIVE_CONTROLS: list[tuple] = [
    (
        "WN2 rule E5: format! INSIDE the sanctioned detail module is the "
        "whole point of having one",
        ''' pub(crate) fn arg_len(field: &'static str, n: usize) -> String { format!("{field}: {n}") } ''',
        {"path_label": "ffi/secretary-ffi-py/src/detail.rs"},
    ),
    (
        "WN3 rule E5: a #[cfg(test)] format! never reaches a platform — the "
        "10 `let rendered = format!(\"{err}\")` assertion sites in the uniffi "
        "errors/ modules are exactly this shape",
        '''
        #[cfg(test)]
        mod tests {
            #[test]
            fn renders() { let rendered = format!("{err}"); assert!(!rendered.is_empty()); }
        }
        ''',
    ),
    (
        "WN4 #500: `uuid_hex: detail::project(a.uuid_hex)` — the shape every "
        "wrapper projection arm takes once the bridge's gated fields are "
        "`Detail`. Accepted as E3 shape 2 (a sanctioned call consuming the "
        "WHOLE initializer), which requires `project` to survive the #496 "
        "signature gate; that in turn requires `Detail` in SAFE_PARAM_TYPES. "
        "Removing `Detail` from that set must make this control FIRE — and "
        "reds the real scan at 27 sites",
        ''' fn f(a: A) -> E { E::V { uuid_hex: detail::project(a.uuid_hex) } } ''',
        {"detail_src": SELF_TEST_WRAPPER_DETAIL_SRC_WITH_PROJECT},
    ),
]
