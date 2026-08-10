"""Rule E6: the `Detail` TUPLE-STRUCT CONSTRUCTOR may be written only in the
one reviewed file that declares it (`DETAIL_MODULE_REL`). The exact analogue
of rule E4 for `impl GatedDetail`, and it exists because the property #500's
whole design rests on is narrower than the design documents said (#515 I5).

WHY THIS IS NOT ALREADY TRUE BY CONSTRUCTION
--------------------------------------------
`error/detail.rs` declares `pub struct Detail(String)` with a PRIVATE inner
field, and both that file and CLAUDE.md described the consequence as "a
`Detail` is constructible only from inside `detail.rs`".

Rust privacy is not file-scoped. A private field is visible to the defining
module AND EVERY DESCENDANT MODULE, and a descendant can live in its own
file. Proven by execution on a minimal crate:

    src/outer.rs          pub struct Detail(String);   pub mod ext;
    src/outer/ext.rs      pub fn launder(s: String) -> Detail { Detail(s) }   // COMPILES
    src/lib.rs            mod sibling { ... Detail(s) ... }                   // E0423

So a SIBLING module is genuinely denied by the compiler — the newtype works
as designed for the case it was built for — but one line appended to
`detail.rs` (`mod ext;`) relocates the minting capability into a file the
chokepoint review never opens. That defeats the module docstring's actual
claim, which is not "the type is safe" but "keeping all of them here means
ONE FILE REVIEW covers the entire allowlist".

Neither the compiler nor any other rule here says a word about it: verified
by execution, the three-line exploit above plus an E3 arm-4 same-name
re-wrap scanned with ZERO findings before this rule existed.

WHAT THIS RULE DOES
-------------------
Denies the token `Detail(` — a tuple-struct construction or pattern — in any
scanned bridge file other than `DETAIL_MODULE_REL`. That is deliberately
cruder than resolving the name: like E4, it is a PLACEMENT rule, and its
whole value is that the reviewed set lives in one place.

`mod` DECLARATIONS inside the sanctioned file are denied by the same
reasoning, and this is the half that actually closes the hole: `Detail(` is
legal inside `detail.rs`, so a descendant module declared THERE but defined
ELSEWHERE would inherit the privilege while escaping the review. Only the
two modules the file legitimately carries are permitted.

LIMITS
------
* Textual, like every rule here. A `macro_rules!`-generated construction is
  invisible, and so is a renaming import (`use ... as Detail`) — the same
  #512 blind spot E2/E3/E4 all carry.
* Scoped to roots that set `ScanRoot.gated_detail_impls` (the bridge). The
  wrapper crates cannot name the type's private field at all, so there is
  nothing to pin there.
* `#[cfg(test)]` spans are NOT skipped. A test-only construction still
  proves the capability exists in that file, and `detail.rs`'s own tests are
  inside the sanctioned file anyway — so skipping would only ever create a
  hole.
"""

from __future__ import annotations

import re

from payload_guard.config import DETAIL_MODULE_REL
from payload_guard.lexer import strip_comments
from payload_guard.types import Finding

# `Detail(` as a tuple-struct construction or pattern. Anchored on a word
# boundary so `GatedDetail(` / `MyDetail(` do not match, and allowing an
# optional qualifying path so `detail::Detail(x)` and
# `crate::error::detail::Detail(x)` are caught too — a qualified spelling is
# the FIRST thing a laundering site would reach for from another module.
DETAIL_CTOR_RE = re.compile(r"(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_]*::)*Detail\s*\(")

# A `mod name;` or `mod name {` declaration.
MOD_DECL_RE = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]")

# The only modules `detail.rs` may declare. `private` carries the sealing
# marker trait; `tests` is the file's own `#[cfg(test)]` module. Both are in
# the reviewed file and neither mints a `Detail` from caller-supplied text.
# Adding a name here is a SECURITY DECISION of the same weight as adding an
# `impl GatedDetail` — it hands the private-field capability to another file.
SANCTIONED_DETAIL_SUBMODULES = frozenset({"private", "tests"})

E6_FOREIGN_CTOR = "foreign-construction: "
E6_SUBMODULE = "submodule: "


def scan_bridge_detail_construction(path_label: str, raw: str) -> list[Finding]:
    """Rule E6 (#515 I5): pin the `Detail` tuple-struct constructor to one file.

    Two checks:

    1. `Detail(` written in any file OTHER than `DETAIL_MODULE_REL`. There is
       no allowlist story — move the construction into a sanctioned
       constructor in `detail.rs`.
    2. A `mod` declaration INSIDE `DETAIL_MODULE_REL` naming anything outside
       `SANCTIONED_DETAIL_SUBMODULES`. This is the arm that closes the
       descendant-module hole: a child module inherits the private field's
       visibility, so declaring one is exactly as load-bearing as writing the
       constructor call itself, and `#[path = "..."]` lets its source live
       anywhere.
    """
    normalized = path_label.replace("\\", "/")
    src = strip_comments(raw)
    findings: list[Finding] = []

    if normalized == DETAIL_MODULE_REL:
        for m in MOD_DECL_RE.finditer(src):
            name = m.group(1)
            if name in SANCTIONED_DETAIL_SUBMODULES:
                continue
            findings.append(
                Finding(
                    path=path_label,
                    line=src.count("\n", 0, m.start()) + 1,
                    source_line=f"{E6_SUBMODULE}mod {name}",
                    variant="<mod in detail.rs>",
                    field=name,
                    field_type=(
                        f"a `mod {name}` inside {DETAIL_MODULE_REL} gives a "
                        f"DESCENDANT module access to `Detail`'s private inner "
                        f"field — Rust privacy is module-SUBTREE scoped, not "
                        f"file scoped, so `{name}` can mint a `Detail` from an "
                        f"arbitrary runtime String in its OWN file, which the "
                        f"one-file review of this module never opens. "
                        f"Permitted: "
                        f"{', '.join(sorted(SANCTIONED_DETAIL_SUBMODULES))}"
                    ),
                    rule="E6",
                )
            )
        return findings

    for m in DETAIL_CTOR_RE.finditer(src):
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, m.start()) + 1,
                source_line=f"{E6_FOREIGN_CTOR}{m.group(0).strip()}",
                variant="<Detail construction>",
                field="Detail",
                field_type=(
                    f"the `Detail` tuple-struct constructor may only be "
                    f"written in {DETAIL_MODULE_REL}. Constructing one "
                    f"elsewhere means the private inner field is reachable "
                    f"from this file — either through a descendant module of "
                    f"`error::detail`, or because the newtype's guarantee has "
                    f"been weakened. Build the value through a sanctioned "
                    f"`detail::*` constructor instead"
                ),
                rule="E6",
            )
        )
    return findings
