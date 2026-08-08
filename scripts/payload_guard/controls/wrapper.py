"""Rule E3 shape 5's, and rule E5's, self-test control corpus (#486):
`WRAPPER_POSITIVE_CONTROLS` / `WRAPPER_NEGATIVE_CONTROLS`, run through
`payload_guard.selftest.scan_wrapper_control` — the wrapper-root rule set
(`bridge_mode=True` plus E2/E3, E3's `allow_field_access` ON, no E4; rule E5
runs separately, over `path_label` + `raw` + the root's
`detail_module_rel`, since it needs the WHOLE FILE TEXT rather than a single
self-contained fixture string — see `WP4`/`WN2`/`WN3` below and
`payload_guard.scan.run_real_scan`'s `format_confinement` wiring).

Mirrors `payload_guard.controls.bridge`'s self-contained-fixture design.
The BRIDGE-scoping half of shape 5's story is NOT here: it is a BRIDGE
control (`BP43` in `payload_guard.controls.bridge`), because it asserts what
the bridge root does, not what a wrapper root does. Read the entry point's
module docstring first for the WHY.

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

WRAPPER_POSITIVE_CONTROLS: list[tuple] = [
    (
        "WP1 shape 5 trusts the FINAL SEGMENT only: a field access whose "
        "last segment is NOT the gated field's own name is not a "
        "pass-through and must deny",
        ''' fn f(a: &A) -> E { E::V { uuid_hex: a.some_other_field } } ''',
        {"rule": "E3", "field": "uuid_hex"},
    ),
    (
        "WP2 a hand-rolled format! into a gated field denies in a wrapper "
        "root exactly as it does in the bridge — shape 5 widens the accepted "
        "set, it does not disable the rule",
        ''' fn f(n: usize) -> E { E::V { detail: format!("got {n}") } } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "WP3 review finding (task 9): shape 5 is SINGLE-HOP only — a "
        "depth-2 chain `a.b.uuid_hex` is a claim about an intermediate "
        "value (`a.b`) this rule has no way to vouch for, is not the shape "
        "any live site takes, and must DENY even though its final segment "
        "is the gated name. An earlier, unbounded-depth version of "
        "`FIELD_ACCESS_RE` accepted this — wider than the shape it was "
        "written to recognise, and untested in the extra width",
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
]

WRAPPER_NEGATIVE_CONTROLS: list[tuple] = [
    (
        "WN1 shape 5: the DTO pass-through `uuid_hex: a.uuid_hex` is the "
        "shape all four live sites take. It is arm 4's name-trust one level "
        "deeper — it trusts that a field named `uuid_hex` was gated where "
        "ITS type declared it, which rules E2/E3 in the bridge do establish "
        "for these four",
        ''' fn f(a: A) -> E { E::V { uuid_hex: a.uuid_hex } } ''',
    ),
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
]
