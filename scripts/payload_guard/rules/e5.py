"""Rule E5 (#486): the binding wrappers may not author error strings.

Rule E3 gates GATED-FIELD INITIALIZERS. The binding wrappers' platform sink
is not one:

    FfiVaultError::NotAuthor { expected_fingerprint_hex, got_fingerprint_hex }
        => VaultNotAuthor::new_err(format!("expected={expected_fingerprint_hex}, ...")),

That is a function ARGUMENT. No extension of E3's initializer model reaches
it, and modelling "which function arguments become platform errors" is the
dataflow problem #488 was reframed to avoid.

So gate the SOURCE instead of the sink: `format!` — the only construct in
these crates that COMPOSES a new string from runtime parts — is confined to
each crate's sanctioned `detail.rs`. Same move `SecretaryLog` makes for
logcat (#472), `diagnosticDetail` for `privacy: .public` (#467) and
`error/detail.rs` for the bridge (#480): do not police call sites, make the
unsafe call unrepresentable and review the one file that defines what safe
means.

WHY THE BRIDGE IS EXCLUDED. The asymmetry is empirical. In the wrapper
crates 100% of production `format!` is error-bound, so confinement costs
nothing (census: `docs/superpowers/sdd/2026-08-08-486-guard-residual-
closeout/task-11-report.md`, `.to_string()` census in this rule's own
commit — every receiver in an error-mapping path is an already-scanned
bridge error type, `e: &FfiVaultError`/`&FfiUnlockError` and friends). In
the bridge it is not: the majority of its 24 `format!` sites build
FILENAMES — `format!("{}.cbor.enc", ...)`, `format!("{}.card", ...)` in
`record/`, `contacts/` (x5), `trash/`, `share/`, `sync/` — a legitimate,
non-error use. Confining `format!` there would buy one rule at the price of
~9 allowlist entries for path building, diluting exactly the signal the
allowlist's highest-weight sections exist to carry. The bridge's error
strings are already gated at their initializers by E3.

SCOPE: `format!`, not `.to_string()`. `format!` COMPOSES a new string from
runtime parts; `.to_string()` only ever RENDERS one value, never combines
several. Censused across every production (non-`#[cfg(test)]`) `.to_string()`
receiver in both wrapper crates (`.superpowers/sdd/2026-08-08-486-guard-
residual-closeout/task-11-report.md`), the receiver is always one of exactly
two shapes, neither of which can carry runtime secret content: (1) an
already-gated bridge error type's `Display` — `e: &FfiVaultError` /
`&FfiUnlockError` in ffi-py's `errors.rs`, whose payloads rules E1-E3
already gate at their bridge construction sites; or (2) a compile-time
STRING LITERAL, rendered through `.to_string()` either directly or via a
`&str` closure/function parameter every call site instantiates with a
literal (ffi-py's `sync.rs::outcome_from_bridge`; every
`"folder path contained invalid UTF-8".to_string()` /
`"source_block_uuid and target_block_uuid must differ".to_string()` site in
ffi-uniffi's `namespace/`). Shape (2) is the same "string literal, optionally
`.to_string()`" acceptance rule E3's own arm 1 already grants a gated field —
a literal is a compile-time constant, not a runtime composition, regardless
of how many hops of `.to_string()` it passes through. If that census ever
stops holding — a `.to_string()` receiver appears that is neither an
already-gated error type nor a literal — this rule widens to cover it.

DETECTION runs on the DISCOVERY view (comments and string CONTENTS blanked),
so a `format!` written inside a string literal or a comment is not a site.
Like every rule here it reads TEXT: a `format!` produced by another macro is
invisible.
"""
from __future__ import annotations

import re

from payload_guard.discovery import _inside, discovery_cfg_test_spans
from payload_guard.lexer import discovery_view, strip_comments
from payload_guard.types import Finding

FORMAT_MACRO_RE = re.compile(r"\bformat\s*!\s*[\(\[\{]")


def scan_wrapper_format_confinement(
    path_label: str, raw: str, detail_module_rel: str | None
) -> list[Finding]:
    """Every `format!` outside this root's sanctioned detail module."""
    if detail_module_rel and path_label.replace("\\", "/") == detail_module_rel:
        return []
    depth_view = discovery_view(raw)
    src = strip_comments(raw)
    excluded = discovery_cfg_test_spans(raw)
    findings: list[Finding] = []
    for m in FORMAT_MACRO_RE.finditer(depth_view):
        if _inside(m.start(), excluded):
            continue
        line_start = src.rfind("\n", 0, m.start()) + 1
        line_end = src.find("\n", m.start())
        line_end = len(src) if line_end == -1 else line_end
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, m.start()) + 1,
                source_line=" ".join(src[line_start:line_end].split()),
                variant="<format! outside detail.rs>",
                field="format!",
                field_type=f"must be built in {detail_module_rel}",
                rule="E5",
            )
        )
    return findings
