r"""Rule E5 (#486): the binding wrappers may not author error strings.

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

SCOPE: `format!` ONLY — and that scope is a CENSUS FINDING, not a claim that
`format!` is the only construct CAPABLE of composing a runtime string from
several parts. It is not: `String::push_str`, `write!`/`writeln!` into a
`String` buffer, the `+` operator on an owned `String`, and `.join()` on a
`Vec<&str>`/`Vec<String>` can all do the same thing, and NONE of them is a
site this rule inspects. A future producer using any of them to build a
gated-field argument would pass silently. The earlier draft of this
docstring justified the scope with "`format!` COMPOSES ...; `.to_string()`
only ever RENDERS ..." — true as a comparison of exactly those two
constructs, but reviewed language that reads as a dichotomy between "can
combine" and "can only render" wrongly implies every OTHER combining
construct is covered by the same argument. It is not; the four named above
are covered by nothing but this census, re-run and quoted here (2026-08-09).

Two further evasions of this rule were found in #496's review and are NOT
`format!`-alternatives but `format!` ITSELF, spelled so the matcher misses
it. Both compile; both produce zero findings today; neither has a live
producer:

    use std::format as fmt2;                       // macro RENAME
    ... fmt2!("{e}")
    std::fmt::format(format_args!("{e}"))          // what format! expands to

The first is structurally the same blind spot rule E4 discloses for
`use detail::GatedDetail as GD;` — a text matcher cannot see through an
alias. Closing either is cheap (both are zero-false-positive greps today)
and deliberately deferred rather than silently omitted.

    $ grep -rnE "push_str|write!\s*\(|\.join\s*\(|String::from\s*\(" \
        ffi/secretary-ffi-py/src ffi/secretary-ffi-uniffi/src
    ffi/secretary-ffi-py/src/save.rs:47: ... SecretString::from(s) ...
    ffi/secretary-ffi-py/src/detail.rs:17: //! ... (`push_str`, `write!`/`writeln!`, `+` on an owned
    ffi/secretary-ffi-py/src/detail.rs:18: //! `String` and `.join()` ...
    ffi/secretary-ffi-uniffi/src/namespace/record_edit.rs:33: ... SecretString::from(text) ...
    ffi/secretary-ffi-uniffi/src/namespace/sync.rs:181: ... core_test_data_dir().join("golden_vault_001") ...
    ffi/secretary-ffi-uniffi/src/namespace/block_crud.rs:162: ... core_test_data_dir().join("golden_vault_001") ...
    ffi/secretary-ffi-uniffi/src/namespace/mod.rs:750: ... SecretString::from(text) ...
    ffi/secretary-ffi-uniffi/src/namespace/mod.rs:967: ... core_test_data_dir().join("golden_vault_001") ...
    ffi/secretary-ffi-uniffi/src/namespace/mod.rs:991: ... core_test_data_dir().join("golden_vault_001") ...

NINE hits, zero live composition sites. (This block said SEVEN, with three
stale `namespace/mod.rs` line numbers and the two `ffi-py/detail.rs` hits
absent, until the #500 final whole-branch review re-ran the grep. The
SUBSTANCE — zero live composition sites — is unchanged; only the transcript
was stale, and it is quoted here precisely so a re-reviewer can reproduce
it.) Three `String::from\s*\(` hits are the pattern matching as a SUBSTRING
of `SecretString::from(` (not a bare `String::from` call). Four `.join(`
hits are all
`secretary_test_utils::core_test_data_dir().join(...)` — `std::path::Path::join`,
not a `str`/`String` `.join()`, and every one of the four call sites sits
inside a `#[cfg(test)]` module (`sync_commit_decisions_bad_manifest_hash_len_is_sync_failed`,
`open_writable_vault`, `read_block_wrong_length_returns_invalid_argument`,
`write_settings_out_of_range_returns_invalid_argument`). The remaining two
are `ffi-py/src/detail.rs`'s own DOC COMMENT naming these very constructs —
the census matching its own prose, which is noise rather than a site.
`push_str` and
`write!`/`writeln!` do not appear at all. The `+` string-concatenation
operator is not census-able by a simple grep (indistinguishable from
arithmetic `+` without a real parser) and is named here on its construction
merits alone, not a census claim — it is exactly as capable of combining
runtime `String` values as `format!` is.

Separately, `.to_string()` — which by itself only ever RENDERS one value and
cannot combine several — IS additionally censused across every production
(non-`#[cfg(test)]`) receiver in both wrapper crates (`.superpowers/sdd/2026-08-08-486-guard-
residual-closeout/task-11-report.md`); the receiver is always one of exactly
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
already-gated error type nor a literal — this rule widens to cover it. The
same is true, and re-verification is equally required, for `push_str` /
`write!` / `writeln!` / `+` / `.join()`: if any of them ever gains a live
production site in either wrapper crate, this rule does NOT catch it until
someone widens it.

DETECTION runs on the DISCOVERY view (comments and string CONTENTS blanked),
so a `format!` written inside a string literal or a comment is not a site.
Like every rule here it reads TEXT: a `format!` produced by another macro is
invisible.
"""
from __future__ import annotations

import re

from payload_guard.discovery import _inside, discovery_cfg_test_spans_strict
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
    # STRICT: a skip here means the `format!` is not scanned (#496).
    excluded = discovery_cfg_test_spans_strict(raw)
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
