"""Rule E3: every CONSTRUCTION SITE of a bridge or wrapper error's gated
field must build its value from a sanctioned source — the other half of rule
E2's carve-out (such a type may carry prose under a `GATED_FIELD_NAMES` name
instead of denying it by type; this rule gates what that field is actually
set to). Moved out of the former single-file
`scripts/check-error-payload-hygiene.py` in #486 (task 4). Read the entry
point's module docstring first for the WHY and THE BRIDGE RULES.

WHAT THIS RULE IS, PER ROOT (#500) — the two are NOT the same and flattening
them is the specific overclaim this branch exists to avoid:

* **Bridge (`ffi/secretary-ffi-bridge/src/**`) — DEFENCE IN DEPTH.** All 27
  gated fields there are the `Detail` newtype (`error/detail.rs`), whose
  private inner field makes a `String` fail to TYPECHECK in the position.
  Rule E2's accepted set for this root was narrowed to `{Detail}` to match
  (`ScanRoot.gated_field_types`), so the bridge permits NO `String` under a
  gated name and a new error type cannot opt back out by declaring the old
  spelling — `BP51` pins that denial, `BN28` the acceptance.
  The compiler, not this rule, is the enforcement: it covers the four
  laundering shapes the entry point's LIMITS enumerate as unwatched
  (pattern-destructuring bind, build-then-mutate, function parameter,
  dotless local reassignment) AND every shape nobody has enumerated,
  because it constrains the TYPE rather than the syntax that reaches it.
  E3 still earns its keep here: it produces a legible, allowlistable
  FINDING with a file and line instead of a type error, it is what catches
  a violation in a file that does not compile yet, and it is the only check
  on the hint-literal requirement (#498) — which is about a constructor's
  ARGUMENTS, a position the newtype says nothing about. The same
  demotion-not-retirement E4 took when `GatedDetail` was sealed in #496.
* **Wrapper roots (`ffi/secretary-ffi-py/src/**`, `ffi/secretary-ffi-uniffi/
  src/**`) — STILL THE ENFORCEMENT, and the only one alongside E2/E5.**
  Their own error types keep `detail: String`: uniffi's UDL must project a
  `string`, PyO3 exceptions take a message, and making them `Detail` would
  need a `custom_type!` conversion adding UDL surface for a type unwrapped
  one line later (design §4). Every limit this rule records applies to them
  at full strength. Their posture is UNCHANGED by #500, not improved — the
  one unwrap each pass-through arm gained sits immediately beside the
  wrapper's own construction site, so it is a PROJECTION, not a gate. Its
  SPELLING is not free: every gated-field initializer THAT UNWRAPS A BRIDGE
  PAYLOAD routes through `detail::project(d)`, whose whole body is the
  single `Detail::into_string()` — 25 such sites in ffi-uniffi, 2 in ffi-py
  (`repair_preview.rs:45,83`) — because the inline
  `detail: detail.into_string()` matches none of THIS rule's accepted shapes
  and denies (`WP6`). `project` is NOT a fourth shape: it is a call into the
  crate's sanctioned module — `initializer_is_gated`'s arm 2, below, the
  same shape any other `detail::*` call takes. The wrapper's OWN authored
  diagnostics never held a `Detail` and take the other shapes — ffi-uniffi
  has 19 such production initializers, 13 string literals plus 6 further
  `detail::*` constructor calls. ffi-py's 17 BARE `.into_string()` calls in
  `errors.rs` are all `new_err(...)` ARGUMENTS, a position this rule does
  not read at all. RECEIVER CENSUS, corrected in final review (this text
  and the entry point's twin both said "17 bare `detail.into_string()`",
  right about the count and the position, wrong about the receiver): 11
  have receiver `detail`, and SIX carry another gated name — 4 `uuid_hex`,
  1 `recipient_fingerprint_hex`, 1 `block_uuid_hex`. An 18th
  `.into_string()` in the crate is `detail.rs:126`, the whole body of
  `project`, and is not one of the 17.

The bridge's guarantee is also per DECLARATION rather than per root: it
covers the 27 fields that hold the real type. A NEW bridge error type
declaring its gated field through a renaming import (`use
std::string::String as Detail;`) compiles, and passes both E2 and this rule
— verified by execution, and tracked by #512. See
`payload_guard/discovery.py`'s `discover_local_detail_decoys` residual 5.
"""

from __future__ import annotations

import re

from payload_guard.config import GATED_FIELD_NAMES
from payload_guard.discovery import (
    LOCAL_DETAIL_TYPE_RE, LOCAL_GATED_DETAIL_TRAIT_RE, _inside,
    discovery_cfg_test_spans, discovery_cfg_test_spans_strict,
)
from payload_guard.lexer import (
    balanced_slice, discovery_view, strip_comments, string_literal_token_ends,
)
from payload_guard.parsing import split_top_level
from payload_guard.types import Finding

# `pub(crate) fn name(` in `error/detail.rs` — the sanctioned detail
# constructors rule E3 accepts a call to. Private-to-the-crate by design: a
# `pub fn` would be callable from outside the bridge, and a bare `fn` is not
# reachable from the call sites this rule gates.
SANCTIONED_CTOR_RE = re.compile(r"pub\(crate\)\s+fn\s+([a-z_][a-z0-9_]*)\s*\(")

# Parameter types a sanctioned constructor may take (#496).
#
# Until #496 this registry captured the constructor's NAME and never looked
# at its SIGNATURE, which made it self-authorising in a way nothing recorded:
# `detail.rs` granted acceptance for whatever it declared, and E3 re-verified
# nothing about the arguments. Appending
#
#     pub(crate) fn passthrough(anything: &str) -> String { anything.to_owned() }
#
# to any root's sanctioned module made `detail::passthrough(<any runtime
# string>)` legal in a gated field at every call site, with the whole guard
# reporting OK (verified by execution).
#
# Every type here is one that cannot carry runtime secret content: a
# compile-time string, an integer, a fixed-size byte array (rendered as hex
# by the constructor), a filesystem path (the ALREADY-DISCLOSED class — see
# allowlist Section 1), an `ErrorKind` discriminant, or an
# `impl GatedDetail`, whose impl set rule E4 pins to one reviewed file.
#
# A constructor with ANY parameter outside this set is DROPPED from the
# sanctioned set, so its call sites deny — the same fail-closed direction a
# missing `detail.rs` takes.
#
# `Detail` (#500) is the STRONGEST entry in this set, not a relaxation of it.
# Every other member is a claim about a SHAPE that happens not to carry runtime
# content (`&'static str` is a compile-time string — though `String::leak` can
# mint one, which is why the entry point's LIMITS calls it "discourages, not
# forbids"); `Detail` is a claim the TYPE SYSTEM enforces. Its inner field is
# private to `ffi/secretary-ffi-bridge/src/error/detail.rs`, so a value of this
# type can only have come out of a sanctioned constructor in that one reviewed
# file — the same property rules E2/E3 exist to establish textually, here
# established by construction.
#
# It is what lets each WRAPPER crate's `detail.rs` declare the projection
# `pub(crate) fn project(d: Detail) -> String` that unwraps a bridge payload
# into the `String` uniffi's UDL and PyO3's exceptions require. Without it that
# constructor is dropped from the sanctioned set and all ~27 wrapper projection
# arms deny — while the alternative spelling (`detail: detail.into_string()`
# inline) denies too, being neither shape 4 nor shape 5. Routing the unwrap
# through the crate's own sanctioned module is the same sink-pinning move E5
# makes for `format!`.
#
# QUALIFIED, because this membership is matched by SPELLING and the rule does
# NOT resolve the name: the structural guarantee holds only while `Detail` in
# that position IS `secretary_ffi_bridge::Detail`. A locally-DECLARED decoy
# (`pub(crate) struct Detail(pub String);` in a wrapper's own detail.rs, which
# once made `detail::launder(Detail(anything))` scan OK — verified by
# execution) is now REJECTED on any root whose `ScanRoot.owns_detail_type` is
# False; see `LOCAL_DETAIL_TYPE_RE`, pinned by `WP8`. An IMPORT is still
# invisible in BOTH forms — the renaming `use other_crate::X as Detail;` and
# the plain `use crate::evil::Detail;` naming a same-named decoy in a sibling
# file — since neither DECLARES anything in the sanctioned module. Same blind
# spot rule E4 records for `GatedDetail`.
#
# `&secretary_core::vault::VaultError` (#500 fix round 1) grants NOTHING the
# set did not already admit: `&impl GatedDetail` is below, and `VaultError` is
# one of the E4-reviewed `GatedDetail` impls, so every existing constructor
# taking `&impl GatedDetail` can already be called with one. Naming the
# concrete type only lets `detail::repair_rejection` DESTRUCTURE it and lift
# out core's `RepairRejected { detail }` — a payload core's own rule E1 entry
# reviews. Its predecessor took a bare `String`, which made that provenance a
# comment: E3's allowlist keys on exact text per FILE, so a SECOND unreviewed
# call in `error/vault/mod.rs` — the very `From<VaultError>` match block where
# a new arm gets written — passed silently (verified by execution).
SAFE_PARAM_TYPES = frozenset(
    {
        "Detail",
        "&Detail",
        "&secretary_core::vault::VaultError",
        "&'static str",
        "usize", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64",
        "&[u8; 16]", "&[u8; 32]",
        "&Path", "&std::path::Path",
        "&impl GatedDetail",
        "std::io::ErrorKind", "io::ErrorKind", "ErrorKind",
    }
)

# #504: EMPTY. Both entries (`fingerprint_mismatch`, `uuid_prefixed`) took
# `&str` and were pinned here as a point-in-time review claim the guard could
# not verify. They now take `&Detail`, so their inputs are gated by TYPE — a
# `Detail` is constructible only inside the bridge's own `detail.rs`. Any
# `&str`-taking constructor added to a `detail.rs` from here on fails the
# guard until someone deliberately re-populates this set, which is the review
# checkpoint the bare-name registry never had.
STR_PARAM_CTOR_EXCEPTIONS: frozenset[str] = frozenset()


# A LOCAL declaration of a type called `Detail` (#500 fix round 1).
#
# `SAFE_PARAM_TYPES` matches the SPELLING `Detail`; it does not resolve the
# name. In the BRIDGE that is exactly right — `pub struct Detail(String)` is
# declared in the very file this registry reads, and it is the authentic type.
# In a WRAPPER crate it is a decoy: adding
#
#     pub(crate) struct Detail(pub String);              // NOT the bridge's
#     pub(crate) fn launder(d: Detail) -> String { d.0 }
#
# to `ffi/secretary-ffi-uniffi/src/detail.rs` made
# `detail: detail::launder(Detail(anything))` scan OK (verified by execution).
# So on any root that does NOT own the type, a local declaration withdraws
# `Detail` from the accepted parameter types, dropping every constructor that
# takes one — the same fail-closed direction a missing `detail.rs` takes.
#
# RESIDUAL: this catches a local DECLARATION only. An IMPORT evades it in both
# forms — the renaming `use other_crate::X as Detail;` and the plain
# `use crate::evil::Detail;` pulling a same-named decoy in from a sibling file
# — because neither declares a type HERE. That is the same aliasing blind spot
# rule E4 records for `GatedDetail`, and it is why the LIMITS section states
# the structural guarantee as conditional on the name resolving to
# `secretary_ffi_bridge::Detail`.
#
# `LOCAL_DETAIL_TYPE_RE` itself now lives in `discovery.py` (#500 fix round
# 2, review finding "Important 2"), imported back from there: rule E2's
# gated-field carve-out (`is_bridge_field_safe`, via
# `discover_local_detail_decoys`) needed the identical match — a decoy
# `Detail` declared OUTSIDE the sanctioned module shadows the spelling for
# E2 exactly as it withdraws a parameter type for E3 here — and a second,
# independently-maintained copy is how these two checks would drift apart
# again, the same way E3's own copy of this hole outlived E2's for one full
# review round.


# Every PascalCase identifier NAMED by a `SAFE_PARAM_TYPES` member, derived
# from the set rather than hand-listed (#515 C3).
#
# The withdrawal machinery below used to close over exactly TWO spellings,
# `Detail`/`&Detail` and `&impl GatedDetail`, and CLAUDE.md described the
# residual as "two `SAFE_PARAM_TYPES` members are matched by SPELLING". That
# was wrong in the direction that matters: EVERY member is matched by
# spelling and none is resolved, so a wrapper root could decoy any of the
# others just as easily. Verified by execution against the real scan —
#
#     pub(crate) struct Path(pub String);
#     pub(crate) fn launder(p: &Path) -> String { p.0.clone() }
#     ...
#     detail: detail::launder(&detail::Path(x)),   // x: arbitrary String
#
# — scanned with ZERO findings, because `&Path` sat in `SAFE_PARAM_TYPES`
# with no withdrawal behind it. Deriving the identifier set from
# `SAFE_PARAM_TYPES` is what stops that recurring: a future member brings
# its own identifiers with it and cannot be forgotten here.
#
# Lowercase primitives (`u8`, `usize`, `i32`, `str`) are deliberately NOT
# included. Shadowing one needs a non-camel-case type declaration that
# rustc warns about, and including them would make the derived regex match
# ordinary prose; the PascalCase set is the reviewable, live-risk half.
SHADOWABLE_PARAM_IDENTS: frozenset[str] = frozenset(
    ident
    for ty in SAFE_PARAM_TYPES
    for ident in re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", ty)
)

# A LOCAL declaration of any of those identifiers, as a type OR a trait.
# `trait` is in the alternation because `&impl GatedDetail`'s decoy is a
# trait rather than a type — one matcher covering both keeps the two
# withdrawals from drifting apart the way #504's did.
LOCAL_SAFE_PARAM_DECOY_RE = re.compile(
    r"\b(?:struct|enum|union|trait)\s+(" + "|".join(sorted(SHADOWABLE_PARAM_IDENTS))
    + r")\b|\btype\s+(" + "|".join(sorted(SHADOWABLE_PARAM_IDENTS)) + r")\s*[=<]"
)


def discover_shadowed_param_idents(view: str) -> frozenset[str]:
    """Identifiers from `SHADOWABLE_PARAM_IDENTS` locally declared in `view`.

    Returned set is withdrawn from `SAFE_PARAM_TYPES` by
    `_ctor_params_are_safe`, so a constructor whose signature leans on a
    decoy spelling stops being sanctioned. Fail-closed by construction: an
    identifier this misses simply keeps its (possibly decoyed) credit,
    which is the pre-#515 behaviour, and an identifier it over-matches only
    ever REMOVES a credit.
    """
    found: set[str] = set()
    for m in LOCAL_SAFE_PARAM_DECOY_RE.finditer(view):
        found.add(m.group(1) or m.group(2))
    return frozenset(found)


def _ctor_params_are_safe(
    name: str,
    params_text: str,
    *,
    detail_param_ok: bool = True,
    gated_detail_param_ok: bool = True,
    shadowed_idents: frozenset[str] = frozenset(),
) -> bool:
    """Every parameter of a candidate sanctioned constructor must carry a
    type from `SAFE_PARAM_TYPES` (or be one of the reviewed `&str`
    exceptions named in `STR_PARAM_CTOR_EXCEPTIONS` — currently EMPTY, see
    there, #504). An unparseable parameter is NOT safe — default-deny.

    `detail_param_ok=False` withdraws every `Detail`-NAMING spelling in
    `allowed`, matched by `\\bDetail\\b` rather than hand-listed (#504
    review R1 fix): a hand-maintained literal (the original fix's
    `allowed - {"Detail", "&Detail"}`) is the IDENTICAL drift risk #504
    itself just closed one level up — someone adds a `Detail`-naming member
    to `SAFE_PARAM_TYPES` (a future `&'static Detail`, `Option<&Detail>`,
    …), forgets to also list the new spelling here, and the wrapper-decoy
    hole reopens with `--self-test` green, because `WP8`/`WP10` only pin the
    two spellings that exist today. The derived form cannot drift from
    `SAFE_PARAM_TYPES` because there is no second list to forget.

    `\\bDetail\\b` matches `Detail` and `&Detail` but NOT `&impl
    GatedDetail` — there is no word boundary between `Gated` and `Detail`
    (verified by execution) — so `&impl GatedDetail` is untouched by THIS
    withdrawal. That is deliberate scope, not an oversight: `&impl
    GatedDetail` is the SAME class of decoy hole one level over (#504
    review R3), closed by the SEPARATE `gated_detail_param_ok` withdrawal
    below rather than folded into this one via a wider regex — the two
    decoys (`struct/enum/union/type Detail` vs `trait GatedDetail`) are
    independent local declarations, so keeping their withdrawals
    independent means a decoy of one kind can never accidentally paper
    over a missing withdrawal for the other. See `LOCAL_DETAIL_TYPE_RE`.

    `gated_detail_param_ok=False` withdraws every `GatedDetail`-NAMING
    spelling the same way — matched by `\\bGatedDetail\\b`, currently just
    `&impl GatedDetail`. A wrapper crate cannot implement the BRIDGE's
    `pub(crate)` (sealed) `GatedDetail`, but nothing stops one declaring its
    OWN local `trait GatedDetail`, implementing it for e.g. `String`, and
    writing `pub(crate) fn launder(d: &impl GatedDetail) -> String` — which
    reproduces the exact `Detail`/`&Detail` decoy bypass one type over
    (verified by execution; zero live wrapper constructors take `&impl
    GatedDetail` today, so this closes with no call-site fallout — `WP11`
    pins the denial). See `LOCAL_GATED_DETAIL_TRAIT_RE`."""
    allowed = SAFE_PARAM_TYPES | ({"&str"} if name in STR_PARAM_CTOR_EXCEPTIONS else set())
    if not detail_param_ok:
        allowed = allowed - {t for t in allowed if re.search(r"\bDetail\b", t)}
    if not gated_detail_param_ok:
        allowed = allowed - {t for t in allowed if re.search(r"\bGatedDetail\b", t)}
    # #515 C3: the GENERAL form of the two withdrawals above. Any
    # `SAFE_PARAM_TYPES` member naming a locally-declared identifier loses
    # its credit, so `&Path`, `ErrorKind`, `&secretary_core::vault::
    # VaultError` and every future member are covered by the same rule
    # rather than by two hand-written special cases. The two specific
    # withdrawals are KEPT rather than folded in: they are pinned by
    # `WP8`/`WP10`/`WP11` and they carry `owns_detail_type`, which this
    # general form deliberately does not consult (see the caller).
    for ident in shadowed_idents:
        allowed = allowed - {
            t for t in allowed if re.search(rf"\b{re.escape(ident)}\b", t)
        }
    inner = params_text.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1]
    if not inner.strip():
        return True
    for part in split_top_level(inner):
        part = part.strip()
        if not part:
            continue
        # `name: Type` — a parameter with no `:` is unparseable, hence unsafe.
        if ":" not in part:
            return False
        ty = " ".join(part.split(":", 1)[1].split())
        if ty not in allowed:
            return False
    return True


def _static_str_param_indexes(params_text: str) -> frozenset[int]:
    """The 0-based positional indexes of `params_text`'s `&'static str`
    parameters — #498's HINT positions: the argument slots a call site must
    fill with a string LITERAL, not merely an expression of that type (see
    `_hint_args_are_literal` below).

    Reuses the exact same parenthesis-stripping and `split_top_level` parse
    `_ctor_params_are_safe` uses on the same `params_text`, so an index
    returned here always lines up with the parameter
    `_ctor_params_are_safe` validated the TYPE of — two independently
    written parses over the same text would risk drifting apart on a
    future edit to either.
    """
    inner = params_text.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1]
    if not inner.strip():
        return frozenset()
    indexes: set[int] = set()
    for i, part in enumerate(split_top_level(inner)):
        part = part.strip()
        if not part or ":" not in part:
            continue
        ty = " ".join(part.split(":", 1)[1].split())
        if ty == "&'static str":
            indexes.add(i)
    return frozenset(indexes)


def _ctor_arity(params_text: str) -> int:
    """How many parameters a sanctioned constructor declares (#515 I8).

    `_hint_args_are_literal` indexes a call's arguments POSITIONALLY, so any
    mis-split of the argument list silently moves the hint check onto a
    different argument. Requiring the split to produce exactly this many
    arguments makes such a shift unrepresentable rather than merely
    unlikely: whatever the splitter does wrong, the count stops matching and
    the call DENIES.

    Same parenthesis-stripping and `split_top_level` parse as its two
    siblings above, for the same anti-drift reason.
    """
    inner = params_text.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1]
    if not inner.strip():
        return 0
    return len([p for p in split_top_level(inner) if p.strip()])


def sanctioned_constructor_names(
    detail_src: str | None, *, owns_detail_type: bool = False
) -> dict[str, tuple[frozenset[int], int]]:
    """The set of `detail::<name>(...)` constructors rule E3 accepts a call
    to — every `pub(crate) fn` declared in `error/detail.rs` (#480).

    A MISSING file (or an empty/unreadable one) yields the EMPTY set, which
    denies every constructor call rather than accepting any: if the one file
    that defines what "sanctioned" means cannot be read, nothing is
    sanctioned. That is the whole rule's fail-closed hinge — the alternative
    (treat "no constructor list" as "no restriction") would silently disable
    E3 the moment someone moved or renamed the module.

    `owns_detail_type` says this root DECLARES the authentic `Detail`
    newtype (the bridge, and only the bridge). Everywhere else a local
    `struct Detail` in the sanctioned module is a decoy that would satisfy
    `SAFE_PARAM_TYPES`' spelling test, so it withdraws the `Detail` parameter
    type — see `LOCAL_DETAIL_TYPE_RE`. Defaults to `False`, the fail-closed
    reading for a caller that forgets to pass it.

    The SAME flag also gates a `GatedDetail`-naming decoy (#504 review R3):
    only the bridge declares the authentic `GatedDetail` trait, in the same
    file, so `owns_detail_type` is reused rather than adding a second,
    independent `ScanRoot` flag that would agree with it at every one of
    today's four roots anyway — see `LOCAL_GATED_DETAIL_TRAIT_RE`.

    Read from the DISCOVERY VIEW (comments AND string CONTENTS blanked), not
    `strip_comments`. This registry GRANTS acceptance, so its fail-closed
    direction is to find FEWER names: a `pub(crate) fn evil(` written inside
    a string literal in `detail.rs` must not sanction `detail::evil(...)` at
    a call site, which is the same self-authorisation class
    `discovery_view`'s own docstring records for `#[error("...")]` messages.
    A lexer desync that HID a real constructor would instead cost a
    fail-closed E3 finding at each of its call sites.

    The constructor's SIGNATURE is checked, not just its name (#496): every
    parameter type must sit in `SAFE_PARAM_TYPES`, or the constructor is
    dropped from the set and its call sites deny. Without that check this
    registry was self-authorising — it derived its allowlist from the very
    file it constrains and read only the name, so one `pub(crate) fn
    passthrough(anything: &str) -> String` added to `detail.rs` sanctioned an
    arbitrary runtime string at every call site. Any reviewed `&str`
    exception is pinned by name in `STR_PARAM_CTOR_EXCEPTIONS`, currently
    EMPTY (#504) — see there for why.

    `#[cfg(test)]`-gated declarations are excluded, like every other
    discovery walk in this file. This one was missed on the first pass, and
    it is a GRANT: a `#[cfg(test)] pub(crate) fn evil_toplevel(...)` added to
    `detail.rs` registered as sanctioned and authorised `detail::evil_toplevel(..)`
    at SHIPPED call sites — verified by execution. A test-only declaration is
    not part of the shipped crate and must not vouch for shipped code, which
    is the same rule `discover_declarations` applies to its own three
    registries.

    RETURN SHAPE, changed by #498: a `dict[str, frozenset[int]]`, not a bare
    `frozenset[str]`. The value is the constructor's HINT positions — the
    0-based indexes of its `&'static str` parameters, from
    `_static_str_param_indexes` — which `initializer_is_gated`'s arm 2 uses
    to require a string LITERAL at each of them (see `_hint_args_are_literal`
    and this module's #498 docstring block above `_hint_args_are_literal`
    for the honest limit). `name in sanctioned` still works unchanged for a
    plain membership test — a dict's `in` reads its keys — so this is
    additive for every call site that only ever checked membership. A
    MISSING/unreadable file still yields the EMPTY dict, the same
    fail-closed hinge as before.
    """
    if not detail_src:
        return {}
    view = discovery_view(detail_src)
    # A root that does not own the newtype must not let a locally-declared
    # decoy called `Detail` satisfy `SAFE_PARAM_TYPES`' spelling test.
    detail_param_ok = owns_detail_type or not LOCAL_DETAIL_TYPE_RE.search(view)
    # Same reasoning, independent match, for a `trait GatedDetail` decoy
    # (#504 review R3) — see `_ctor_params_are_safe`'s docstring.
    gated_detail_param_ok = owns_detail_type or not LOCAL_GATED_DETAIL_TRAIT_RE.search(
        view
    )
    # #515 C3: the same reasoning for every OTHER `SAFE_PARAM_TYPES`
    # identifier. `Detail`/`GatedDetail` are dropped from this general set
    # because the two specific flags above already handle them AND carry
    # the `owns_detail_type` exemption — the bridge's own `detail.rs`
    # legitimately declares `struct Detail`, so a general withdrawal that
    # ignored ownership would deny the real tree. No root legitimately
    # declares a `Path` / `ErrorKind` / `VaultError` inside its sanctioned
    # detail module, so those need no such exemption.
    shadowed_idents = discover_shadowed_param_idents(view) - {"Detail", "GatedDetail"}
    excluded = discovery_cfg_test_spans(detail_src)
    names: dict[str, frozenset[int]] = {}
    for m in SANCTIONED_CTOR_RE.finditer(view):
        if _inside(m.start(), excluded):
            continue
        name = m.group(1)
        # SIGNATURE gate (#496): the match ends just past the `(`, so
        # `m.end() - 1` is the opening paren `balanced_slice` needs.
        params_text, _ = balanced_slice(view, m.end() - 1)
        if not _ctor_params_are_safe(
            name,
            params_text,
            detail_param_ok=detail_param_ok,
            gated_detail_param_ok=gated_detail_param_ok,
            shadowed_idents=shadowed_idents,
        ):
            continue
        names[name] = (_static_str_param_indexes(params_text), _ctor_arity(params_text))
    return names


# A gated field name in INITIALIZER position: `<name>:` not followed by a
# second `:`. The negative lookahead excludes the MODULE PATH `detail::` (as
# in `detail::gated(...)`, which is a call, not a field), and `\b` excludes a
# gated name that is merely the TAIL of a longer field name — `record_uuid_hex:`
# must not match on `uuid_hex:`, since the DTO-carrying names are deliberately
# NOT members of `GATED_FIELD_NAMES` (see there).
GATED_INIT_RE = re.compile(
    r"\b(" + "|".join(sorted(GATED_FIELD_NAMES)) + r")\s*:(?!:)"
)
# #488 shapes 2 and 3: a `let` binding to a gated name. E3's arm 4 accepts an
# initializer that is the field's own name, which means
# `let detail = format!("{x}"); E::V { detail: detail }` — and the shorthand
# `E::V { detail }`, which produces no `detail:` token at all — launder any
# expression through a local variable.
#
# The closure needs no dataflow: a `let` binding to a gated name IS a
# construction of a gated value, so its initializer is gated by the same test
# as a field's. The launder becomes the candidate. Pattern bindings
# (`FfiVaultError::X { detail } =>`) and function parameters produce no `let`
# and are untouched — which is what lets arm 4 stay as it is.
#
# `(?!=)` excludes `==`; `let` cannot introduce a comparison, but the same
# guard on GATED_ASSIGN_RE below genuinely matters, so both carry it for
# symmetry and to keep a future edit from splitting the behaviour.
GATED_LET_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(" + "|".join(sorted(GATED_FIELD_NAMES)) + r")\s*=(?!=)"
)
# #488 shape 1: post-construction assignment. `e.detail = format!("{x}")` is a
# WRITE, and the initializer-position rule never saw a write. The optional
# `(?:[+\-*/%^&|]|<<|>>)?` admits every Rust COMPOUND assignment operator
# (`+=`, `-=`, `*=`, `/=`, `%=`, `^=`, `&=`, `|=`, `<<=`, `>>=`) as well as
# plain `=` — `x.detail += &format!("{e}")` is exactly the class this rule
# exists to catch (a build-then-mutate write), and the base pattern's bare
# `=` never matched the two-character forms at all; review caught this gap
# after the initial #488 landing, before it shipped.
# `(?!=)` is still load-bearing on the trailing `=` — `x.detail == s` is a
# comparison, not a construction, and matching it would produce a false
# positive on every equality test; `x.detail != s` was already excluded
# without help (`!` is not one of the admitted operator characters, so the
# required literal `=` never lines up with the `!`), and is now pinned by a
# control rather than left as an unstated fact about the regex.
GATED_ASSIGN_RE = re.compile(
    r"\.\s*("
    + "|".join(sorted(GATED_FIELD_NAMES))
    + r")\s*(?:[+\-*/%^&|]|<<|>>)?=(?!=)"
)
# A call whose path ENDS in `detail::<name>(`. The leading segments are
# unconstrained so both the in-module spelling (`detail::gated(`) and the
# fully-qualified one (`crate::error::detail::gated(`) match; what is pinned
# is that the immediately-enclosing module segment is literally `detail`, so
# a same-named local function (`gated(&e)`) does not pass.
DETAIL_CALL_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*detail\s*::\s*([a-z_][a-z0-9_]*)\s*\("
)

# #487: `std::io::Error` is E4-allowlisted as a CARRIER — unlike ParseIntError,
# its Display renders whatever it was CONSTRUCTED with, so its safety is a
# claim about producers, not about the type. A bridge site can mint one from a
# runtime string, fold it into core's `VaultError::Io { source }`, and reach a
# gated field via that impl — a path E3's initializer rule never crossed,
# because it gates the BRIDGE's own `detail:` expression, not what feeds
# core's.
#
# The payload argument therefore becomes a candidate position in its own
# right. `new` takes it SECOND (after the ErrorKind); `other` takes it FIRST.
#
# LIMIT, inherited from every rule here: this matches the trait/type spelled
# out. `use std::io::Error;` followed by a bare `Error::new(...)` is invisible,
# the same aliasing blind spot rule E4 records for `GatedDetail`.
IO_ERROR_NEW_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*io\s*::\s*Error\s*::\s*new\s*\("
)
IO_ERROR_OTHER_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*io\s*::\s*Error\s*::\s*other\s*\("
)
# The synthetic `field` name reported for an io payload finding. Deliberately
# NOT a valid Rust identifier: `initializer_is_gated`'s arm 4 (and shape 5)
# compare the expression against the field NAME, and an io payload has no
# field name to re-wrap, so a name no expression can equal keeps those arms
# structurally unreachable here rather than relying on them happening not to
# match.
IO_PAYLOAD_FIELD = "<io::Error payload>"

# Rule E3 shape 5 (#486). CURRENTLY OFF ON EVERY ROOT (#497/#500) — see
# `ScanRoot.allow_field_access`. A SINGLE-HOP field access whose final segment
# is the gated field's own name — `uuid_hex: a.uuid_hex`. The regex is kept so
# the acceptance can be re-enabled with a fresh review if a future DTO needs
# it; nothing reaches it today, and `WP7` pins the denial.
#
# EXACTLY ONE DOT, on purpose (review finding, task 9): the four sites that
# once justified it were single-hop (`a.uuid_hex`, `w.block_uuid_hex`) — all
# four moved to `detail::project(...)` in #500 — arm 5's own docstring
# describes a single hop, and an earlier unbounded-depth version of this
# regex accepted `a.b.uuid_hex` / `a.b.c.uuid_hex` too — wider than the
# shape it was written to recognise, and untested in the extra width. A
# multi-hop chain is not the DTO pass-through this arm exists to serve; it
# is a claim about an intermediate value this rule has no way to vouch for,
# and granting it anyway would be exactly the "new acceptance nothing
# needs" laundering door this task's own commit message warns against.
# `WP3` pins a depth-2 chain (`a.b.uuid_hex`) denying.
FIELD_ACCESS_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*\.\s*[A-Za-z_][A-Za-z0-9_]*$")


def io_payload_candidates(depth_view: str) -> list[tuple[int, int, str]]:
    """`(match_start, payload_start, IO_PAYLOAD_FIELD)` for every
    `io::Error::new(kind, PAYLOAD)` and `io::Error::other(PAYLOAD)` in
    `depth_view` (#487).

    For `new`, the payload begins after the first top-level comma inside the
    call — located with `initializer_end`, which stops at exactly that comma.
    A call with no top-level comma (a macro-built argument list, a `new` with
    one argument that does not compile) yields NO candidate rather than a
    mis-sliced one; that is the fail-closed reading for a helper whose job is
    to find a slice, since a wrong slice would be classified as some OTHER
    expression and could be accepted.

    LIMIT, undocumented until now: `initializer_end` tracks `(`/`[`/`{`
    nesting, not `<`/`>` — a turbofish or a generic type in the `ErrorKind`
    argument (`io::Error::new(SomeEnum::<A, B>::Kind, real_payload)`) has a
    comma the depth counter reads as top-level, so the located "comma" is the
    one INSIDE the angle brackets, not the one separating the two `new`
    arguments. The extracted payload span is then garbled — it starts
    mid-way through the `ErrorKind` expression instead of at `real_payload`.
    This is still ALWAYS fail-closed: the mis-sliced text is not one of
    `initializer_is_gated`'s four accepted shapes (a construction a reviewer
    could actually compile does not happen to read as a literal, a sanctioned
    `detail::` call, the bare token `String`, or the field's own name), so it
    still DENIES — just with a `field_type` in the finding that does not
    describe the real payload expression. No live `io::Error::new` call site
    in the tree takes a generic/turbofish `ErrorKind` argument today.
    """
    out: list[tuple[int, int, str]] = []
    for m in IO_ERROR_OTHER_RE.finditer(depth_view):
        out.append((m.start(), m.end(), IO_PAYLOAD_FIELD))
    for m in IO_ERROR_NEW_RE.finditer(depth_view):
        comma = initializer_end(depth_view, m.end())
        if comma >= len(depth_view) or depth_view[comma] != ",":
            continue
        out.append((m.start(), comma + 1, IO_PAYLOAD_FIELD))
    return out


def initializer_end(view: str, start: int) -> int:
    """The offset at which the initializer expression beginning at `start`
    ends: the first `,` or `;` at top-level nesting, or the first `)`, `]`
    or `}` that CLOSES the construct the initializer sits in (i.e. appears
    at depth zero). `(`, `[` and `{` open a nesting level.

    `view` must be the DISCOVERY VIEW: with string contents blanked, a comma,
    semicolon or brace inside a literal (`format!("a, b")`, `"}"`) cannot end
    the expression early. That choice is fail-closed in both directions —
    every view here only ever BLANKS, and blanking can neither introduce a
    `,`/`;` that truncates an expression nor remove one in a way that
    shortens it, so a lexer desync can only ever make the extracted
    expression LONGER, which makes it LESS likely to match one of the narrow
    accepted shapes.

    Closing delimiters at depth zero are genuine terminators, not a
    heuristic: they are the `)` of `fn f(detail: String)`, the `}` of
    `E::V { detail: x }`. Without them a function parameter's type would run
    on into the function BODY and every such parameter would produce a
    spurious finding.

    The `;` terminator (#488) is what makes this function usable for
    `GATED_LET_RE`'s candidates too: a `let` statement's initializer ends at
    its own `;`, not at any enclosing `)`/`]`/`}` — `let detail =
    detail::gated(e); detail` must stop at the `;`, or the extracted
    "initializer" swallows the trailing `detail` expression-statement too and
    a legitimate re-wrap misreads as an unrecognised shape.

    It is true that a bare `;` cannot legally appear inside a
    field-initializer or fn-parameter expression at depth zero — but that
    does NOT mean the terminator "changes nothing" for `GATED_INIT_RE`
    candidates, because `GATED_INIT_RE` fires on any `<name>:` sequence, not
    only on those two shapes. A type-annotated `let` with NO initializer —
    `let detail: String;` — reads to `GATED_INIT_RE` exactly like a field or
    parameter declaration (`detail:` followed by a type), and its `;`
    terminator IS legal Rust at depth zero: `let` always ends in `;`,
    initializer or not. Adding the `;` terminator therefore changes the
    SLICE this shape extracts — from "everything up to whatever brace
    happened to enclose it" (previously, typically garbled and denied by
    accident) to exactly `String` (now cleanly extracted) — and it is
    `initializer_is_gated`'s job, not this function's, to tell that
    terminator apart from a genuine declaration's `)`/`,`/`}` before trusting
    the bare-`String` shape it now yields. See its terminator-aware arm 3.
    """
    depth = 0
    i, n = start, len(view)
    while i < n:
        ch = view[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch in ",;" and depth == 0:
            break
        i += 1
    return i


# #498's cheaper half — the LITERAL check on a sanctioned call's HINT-
# POSITION arguments (`_hint_args_are_literal` and its helper
# `_split_call_arg_spans`, both used from `initializer_is_gated`'s arm 2
# below).
#
# Every sanctioned constructor's `&'static str` parameter (`context`,
# `field`, `advice`, …) is a HINT: a fixed sentence or name meant to be
# written at the call site, never runtime content. #498 demonstrated by
# EXECUTION that this is not enforced by the parameter's TYPE alone —
# `Box::leak(format!(…).into_boxed_str())` mints a `&'static str` from
# RUNTIME data in safe, stable Rust, `#![forbid(unsafe_code)]` does not stop
# it, and the resulting call (`detail::gated_with_context(leaked, e)`)
# scanned CLEAN before this fix, because `SAFE_PARAM_TYPES`
# (`_ctor_params_are_safe`) only ever checked the constructor's declared
# parameter TYPE, never what a given CALL SITE actually passes there.
#
# From here on, every hint-position argument at a sanctioned call site must
# itself be a string-literal TOKEN — a plain `"…"` or a raw `r"…"` /
# `r#"…"#` — not merely an expression of type `&'static str`.
#
# HONEST LIMIT (spec `docs/superpowers/specs/2026-08-09-500-detail-newtype-
# design.md` §6.1, stated here in substance): this watches the door, it
# does not remove it. Unlike the `Detail` newtype (#500), which makes an
# ungated `String` a TYPE ERROR at every call site, a text rule cannot make
# a leaked `&'static str` unrepresentable — it can only require that the
# TOKEN written at a hint position look like a literal. #498's structural
# option — a closed `enum Context` that only fixed, named variants could
# construct — remains the only fix that would remove the door rather than
# watch it, and #498 STAYS OPEN recording that.
# The enclosing `fn` name for an offset, used to SCOPE an E3 allowlist key
# (#515 C1). Scans backwards for the nearest `fn <name>` and returns it, or
# `"<toplevel>"` when there is none.
ENCLOSING_FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")


def enclosing_fn_name(src: str, offset: int) -> str:
    """Name of the nearest `fn` declared before `offset`.

    An E3 allowlist row is keyed on `path \t rule \t "<field>: <expr>"`,
    and NOTHING in that key identifies where in the file the expression sat
    — while every Section 5 row's justification is a property of its
    ENCLOSING FUNCTION ("`field` is `uuid_from_vec`'s own `&'static str`
    parameter, forwarded one hop"). A row therefore exempted its expression
    TEXT anywhere in the file, and the shapes involved are idiomatic and
    copy-pasteable in a 1000+-line module. Verified by execution: a SECOND
    producer in the same file, minting a runtime `&'static str` via
    `Box::leak` and calling `detail::arg_len(field, 16, bytes.len())` — the
    precise `BP52` attack — scanned with ZERO findings, because an existing
    row's key collided with it exactly.

    Putting the enclosing item into the key turns each row from "this text,
    anywhere in this file" into "this text, in this function". Approximate
    by construction — it does not model nested items or `impl` blocks — but
    it only ever NARROWS an exemption, so a wrong answer costs a re-review,
    never a silent pass.
    """
    last = "<toplevel>"
    for m in ENCLOSING_FN_RE.finditer(src, 0, offset):
        last = m.group(1)
    return last


def _split_call_arg_spans(
    view: str, start: int, end: int, literal_ends: dict[int, int]
) -> list[tuple[int, int]]:
    """The `(start, end)` offset of each top-level, comma-separated argument
    in the call-argument text `view[start:end]`.

    Not `split_top_level` (bracket-depth only, no string awareness): a comma
    INSIDE a hint literal is a real, live shape —
    `io_gated_with_path_and_advice`'s production `advice` argument
    (`ffi/secretary-ffi-bridge/src/repair/orchestration.rs`) is a sentence
    containing several commas — and `split_top_level` would mis-split on
    every one of them, exactly the failure mode `initializer_end`'s own
    docstring already warns a DISCOVERY-view caller about for `,`/`;`
    inside a literal. Any offset that is the START of a complete string
    literal (per `literal_ends`, `string_literal_token_ends`'s EXACT-match
    map — the same one arm 1 uses) is skipped in one jump to that literal's
    OWN end, so nothing inside a string can register as a top-level
    separator or change bracket depth.

    `view` must therefore be a LITERAL-INTACT view (`strip_comments`'s
    output, not `discovery_view`'s) — the same `view`
    `initializer_is_gated` already receives as `src`.
    """
    spans: list[tuple[int, int]] = []
    depth = 0
    angle_depth = 0
    i = start
    arg_start = start
    while i < end:
        lit_end = literal_ends.get(i)
        if lit_end is not None and lit_end <= end:
            i = lit_end
            continue
        ch = view[i]
        # #515 I8: `<`/`>` are counted as brackets ONLY inside a generic
        # context, which in an EXPRESSION is introduced by a turbofish
        # (`::<`). Counting every `<`/`>` unconditionally was the actual
        # defect: `mk(z >= 1, y, "lit", w)` drove the counter down on the
        # `>` of `>=`, so the commas INSIDE `mk(...)` read as top-level and
        # the argument list mis-split 6 ways instead of 3 — shifting the
        # hint position onto a different argument, which is exactly the
        # index shift the #498 literal check exists to prevent. A closure's
        # `-> T` and any ordinary comparison did the same. Clamping at zero
        # (below) bounded the damage but did not remove it.
        if ch == "<" and (angle_depth > 0 or view[max(0, i - 2) : i] == "::"):
            angle_depth += 1
        elif ch == ">" and angle_depth > 0:
            angle_depth -= 1
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            # Clamped, unlike `initializer_end`'s unclamped `depth -= 1`
            # (that function instead BREAKS at `depth == 0` before ever
            # decrementing, which has no equivalent here — this loop must
            # keep scanning past a top-level `>`, not stop). `<`/`>` are
            # counted for generics/turbofish, but an UNPAIRED `>` — a
            # comparison inside a hint argument, e.g. `if k > 1 { p } else
            # { q }` — would otherwise drive `depth` negative, and a
            # top-level `,` right after would then read `depth == 0` as
            # false and stop registering as a separator: a review finding
            # (fix round 1), fail-CLOSED (a literal hint got misread as
            # part of a longer, unrecognised argument and denied) but the
            # only way this function's depth tracking could shift a real
            # argument into the wrong index.
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            spans.append((arg_start, i))
            i += 1
            arg_start = i
            continue
        i += 1
    spans.append((arg_start, end))
    return spans


def _hint_args_are_literal(
    view: str,
    args_start: int,
    args_end: int,
    hint_indexes: frozenset[int],
    literal_ends: dict[int, int],
    *,
    expected_arity: int | None = None,
) -> bool:
    """#498: every one of a sanctioned call's HINT-POSITION arguments
    (`hint_indexes`, from `sanctioned_constructor_names`) must be a string
    literal, checked the SAME way arm 1 checks the whole gated-field value:
    an EXACT offset match against `literal_ends`, not a prefix test on the
    argument's rendered text. `string_literal_token_ends`'s own docstring
    states why exact-match is the safer choice ("If a lexer desync ever
    swallowed half a file into one 'literal', the expression span would not
    coincide with that token's span and the acceptance would fail rather
    than widen") — the same reasoning applies here, and it is what denies
    an argument like `"a" + leak()`, which STARTS with a quote but is not,
    in its entirety, a literal token, unlike a bare `^r?#*"` prefix test
    would.

    `hint_indexes` empty (`gated`, `uuid_hex`, … — no `&'static str`
    parameter at all) is vacuously safe: nothing to check.

    A hint index with no corresponding argument — fewer top-level commas
    than the constructor's own signature promises, a call that could not
    have compiled — DENIES rather than being skipped: default-deny, the
    same direction every other unparseable shape in this file takes.
    """
    if not hint_indexes:
        return True
    spans = _split_call_arg_spans(view, args_start, args_end, literal_ends)
    # #515 I8: an ARITY gate, so a mis-split cannot silently move the hint
    # check onto a different argument. `_split_call_arg_spans` is a textual
    # bracket counter, and its `<`/`>` handling was demonstrably shiftable;
    # the counter is fixed, but "the splitter is correct" is a claim about
    # code, whereas this is a claim the guard re-checks on every call. If
    # the split does not produce exactly the number of arguments the
    # constructor's own signature declares, DENY — default-deny, the
    # direction every other unparseable shape here takes.
    #
    # A TRAILING COMMA is the one benign shape that changes the count, so a
    # single trailing all-whitespace span is dropped before comparing
    # (`BN32`'s fixture is exactly that).
    if expected_arity is not None:
        effective = list(spans)
        if len(effective) > 1 and not view[effective[-1][0] : effective[-1][1]].strip():
            effective.pop()
        if len(effective) != expected_arity:
            return False
    for idx in hint_indexes:
        if idx >= len(spans):
            return False
        a, b = spans[idx]
        while a < b and view[a] in " \t\r\n":
            a += 1
        while b > a and view[b - 1] in " \t\r\n":
            b -= 1
        if literal_ends.get(a) != b:
            return False
    return True


def initializer_is_gated(
    view: str,
    start: int,
    end: int,
    name: str,
    literal_ends: dict[int, int],
    sanctioned: dict[str, tuple[frozenset[int], int]],
    allow_field_access: bool,
    terminator: str,
) -> bool:
    """Rule E3's ACCEPT test for the (already whitespace-trimmed) expression
    `view[start:end]` assigned to gated field `name` (#480).

    FOUR shapes are accepted everywhere, plus a FIFTH gated behind
    `allow_field_access` — which is `False` on every root as of #497/#500, so
    in the tree as it stands only four are reachable — and nothing else: this
    is a default-DENY predicate, so a construct this function does not
    recognise is a finding.

    1. A single STRING LITERAL, optionally followed by exactly `.into()` or
       `.to_string()`. The literal is identified by an exact offset match
       against `string_literal_token_ends` (see there), not by a `"` prefix
       test, so a desynced lexer widens rather than admits. The `.into()` /
       `.to_string()` tail is matched with ALL whitespace removed, so
       `"x" . into ()` passes and `"x".into().unwrap()` does not — the point
       is that the value is still exactly the literal.
    2. A call whose path ends `detail::<name>(`, with `<name>` in the
       `sanctioned` set (`sanctioned_constructor_names`) AND the call
       consuming the WHOLE expression. Requiring the whole expression is
       deliberately stricter than "starts with a sanctioned call":
       `detail::gated(&e) + leak()` starts with one too.

       #498: AND every one of the constructor's own HINT-POSITION
       arguments — `sanctioned[<name>]`, the 0-based indexes of its
       `&'static str` parameters — must itself be a string-literal TOKEN
       (`_hint_args_are_literal`). A `&'static str`-typed variable at that
       position (a leaked one via `Box::leak`, demonstrated by #498; or,
       more mundanely, a forwarded function parameter) is not a literal and
       DENIES this arm, even though the call is otherwise shape-2-accepted.
    3. The exact token `String` OR `Detail` (#500) — a DECLARATION's type
       position (a struct field, an enum variant field, a function
       parameter), not a value. Rule E2 already decides whether a `String`
       or `Detail` DECLARATION under a gated name is acceptable (per-root,
       `ScanRoot.gated_field_types`); E3 is about construction, and a
       declaration is not a construction. `String::new()` / `Detail::new()`
       are NOT this shape and deny, which is what keeps the acceptance from
       becoming "any expression starting with String/Detail".

       `Detail` joins this arm UNCONDITIONALLY, not read from
       `ScanRoot.gated_field_types` or threaded per-root: unlike E2, this arm
       makes no claim about which TYPES are policy-acceptable under a gated
       name on a given root — it only tells a declaration's type position
       apart from a construction expression, and `GATED_INIT_RE` matches
       `<name>:` regardless of root. E2 remains the sole per-root gate
       (wrapper roots' `gated_field_types` stays `{"String"}`, never
       `Detail`, so a wrapper declaration reading `field: Detail` still
       produces an E1/E2 finding — this arm merely keeps E3 from ALSO
       misreporting that same declaration as an unsanctioned construction
       site). Found live: without this, `pub enum FooError { #[error("boom:
       {detail}")] Boom { detail: Detail }, }` — an ordinary DECLARATION,
       the exact shape Task 3 (#500) is about to introduce across the bridge
       — read to `GATED_INIT_RE` identically to a construction site and
       produced a spurious E3 finding (`BN28`), which would have reddened
       the real scan the moment Task 3 landed a single `Detail`-typed field.

       GATED BEHIND THE TERMINATOR (regression fix, found in final review):
       a genuine declaration's type position is always closed by `)` (a
       function parameter), `,` (a non-last struct/enum field), or `}` (the
       last field before the closing brace) — never by a depth-zero `;`,
       because none of those three constructs is itself terminated by one.
       The ONE construct that reads identically to `GATED_INIT_RE` (a
       `<name>:` token) and IS terminated by `;` is a type-annotated `let`
       with NO initializer — `let detail: String;` — which is not a
       declaration this arm exists to serve; it is a value-less binding
       whose value is written on a LATER, separate statement
       (`detail = format!(...);`) that neither `GATED_LET_RE` (no `=` on
       the `let` itself) nor `GATED_ASSIGN_RE` (no receiver dot on a bare
       local) can see. Before this fix, that shape's initializer slice ran
       on into the enclosing block and typically stopped on an unrelated
       `}`, producing a garbled expression that matched no accepted shape
       and DENIED by accident; adding `;` as a terminator in
       `initializer_end` (#488) cleanly extracts `String` instead — which
       then hit this arm's bare-token acceptance and produced ZERO findings,
       a real regression against the pre-#488 guard (see `BP44`). Denying
       arm 3 whenever `terminator == ";"` closes it: a `String` extracted up
       to a depth-zero `;` is never a struct field, enum field, or function
       parameter, so refusing it there costs none of the three legitimate
       declaration shapes arm 3 exists to serve.
    4. The exact same identifier as the field name — the `detail: detail`
       re-wrap. THIS ARM TRUSTS THE NAME, NOT THE VALUE'S PROVENANCE, and
       saying otherwise would be a false claim about a security control. An
       earlier version of this docstring asserted the value "is gated where
       it was built"; that is only true for the shape this arm exists to
       serve (re-wrapping a field of an already-gated error).

       #488 closed the plainest counterexample: a SIMPLE `let` binding is
       now itself a candidate (`GATED_LET_RE`), so

           fn f() -> E { let detail = format!("{}", leak());
                         E::V { detail: detail } }

       now produces ONE finding — from the `let`, not from this arm — where
       it used to produce zero (verified by execution; pinned by
       `BP36`/`BP37`). The trust this arm places in the NAME is still real,
       though, for any binding shape that produces no `let ... =` token and
       no `.name =` write, because those are the only two positions this
       rule watches. A PATTERN-DESTRUCTURING bind is one such shape,
       verified by execution to still produce zero findings:

           fn f(e: SomeErr) -> E { let SomeErr { detail } = e;
                                    E::V { detail: detail } }   // zero findings

       Tuple (`let (a, detail) = ...`), tuple-struct (`let Wrap(detail) =
       ...`), slice (`let [detail] = ...`) patterns, and `if let` / `while
       let` / `for` bindings share the same gap — none produce the
       `let <name> =` token `GATED_LET_RE` matches. A function PARAMETER of
       the same name (`fn f(detail: String) -> E { E::V { detail: detail }
       }`, `BN10`) shares it too, and is the legitimate shape every shipped
       re-wrap site today actually is. The rule keeps the arm because the
       approved plan mandates the re-wrap form and because the alternative
       — denying every re-wrap — would flag the legitimate sites and teach
       reviewers to wave E3 findings through. It is an explicit, named
       ACCEPT with a stated gap, recorded in the module docstring's LIMITS
       beside the other two.

       Field shorthand (`E::V { detail }`) has no `:` at all and never
       becomes a candidate AT THIS POSITION — but where the value feeding
       it comes from a SIMPLE `let`, that `let`'s own initializer is now the
       candidate that catches it (`BP36`); only a pattern bind or a
       parameter still reaches the shorthand door unwatched.
    5. GATED BEHIND `allow_field_access`, WHICH IS NOW `False` ON EVERY
       ROOT (#486, retired #497/#500): a SINGLE-HOP field access —
       `receiver.field`, EXACTLY ONE DOT — whose field segment is the gated
       field's own name — `uuid_hex: a.uuid_hex`. This was the DTO
       pass-through shape of four wrapper sites; #500 moved all four onto
       `detail::project(...)` (E3 shape 2, a sanctioned call), leaving this
       arm with ZERO live sites, and an acceptance nothing needs is a
       laundering door for free — the exact rule this arm's own scoping
       paragraph states — so it was switched off rather than left dormant.
       `WP7` pins that a wrapper single-hop access now DENIES. The rest of
       this entry describes the behaviour if it is ever re-enabled.

       THIS ARM TRUSTS THE NAME TOO, one level deeper than arm 4: it claims
       that a field named `uuid_hex` on some OTHER type was gated where
       THAT type declared it. For the four sites that once justified it
       that claim held — the source was a bridge DTO whose fields rules
       E2/E3 already gate, and all four now go through
       `detail::project(...)` instead — but it is a trust RELATION, not
       provenance, the same honesty arm 4's docstring insists on.

       It was granted to the WRAPPER roots only, never the bridge, because
       nothing in the bridge needed it and an acceptance granted where it
       is not required is a laundering door for free. That asymmetry is
       gone: with the flag off everywhere, `BP43` (bridge) and `WP7`
       (wrapper) pin the SAME expression denying on their own root, and
       neither contrasts with a grant on the other.

       If re-enabled, two narrowings apply. A field access whose LAST
       segment is NOT the gated name — `uuid_hex: a.some_other_field` — is
       not this shape and denies (`WP1`). ONE HOP ONLY, not an
       arbitrary-depth chain: `a.b.uuid_hex` is a claim about an
       INTERMEDIATE value (`a.b`) this rule has no way to vouch for, is not
       a shape any site ever took, and denies (`WP3`) — a review finding on
       the first version of this arm, which accepted any depth. Both
       controls deny at the FLAG today rather than at the test they name;
       see #508.

    Note what is NOT covered, and cannot be by a construction-site matcher:
    a value reaching a gated field through a PATTERN bind (tuple,
    tuple-struct, struct, slice, `if let`, `while let`, `for`) or through a
    function PARAMETER is not checked — see arm 4 above. #488 closed the
    shape this note used to name here, PLAIN post-construction assignment
    (`x.detail = format!(...)`, now `GATED_ASSIGN_RE`, pinned by `BP38`);
    that is no longer a blind spot. The remaining gaps are recorded in the
    module docstring's LIMITS.
    """
    if start >= end:
        return False
    stripped = view[start:end].strip()
    # (4) the same-name re-wrap — trusted regardless of terminator, since a
    # `let detail = detail;` or `x.detail = detail` is not a declaration.
    if stripped == name:
        return True
    # (3) declaration type position — DENIED when `terminator` is `;`: the
    # only construct that extracts a bare `String`/`Detail` up to a
    # depth-zero `;` is a type-annotated `let` with NO initializer (`let
    # detail: String;`, #488/regression fix, `BP44`), never a struct field,
    # enum field, or function parameter — those are always closed by `)`,
    # `,`, or `}`. `Detail` (#500) is accepted alongside `String`
    # unconditionally, not per-root — see the docstring's arm 3 for why.
    if stripped in ("String", "Detail") and terminator != ";":
        return True
    # (1) a single string literal, optionally `.into()` / `.to_string()`.
    lit_end = literal_ends.get(start)
    if lit_end is not None and lit_end <= end:
        tail = "".join(view[lit_end:end].split())
        if tail in ("", ".into()", ".to_string()"):
            return True
    # (2) a sanctioned `detail::<name>(...)` call consuming the expression,
    #     with every one of its HINT-POSITION arguments a string literal
    #     (#498 — see this module's docstring block above
    #     `_hint_args_are_literal`).
    cm = DETAIL_CALL_RE.match(view, start)
    if cm and cm.end() <= end and cm.group(1) in sanctioned:
        _, after = balanced_slice(view, cm.end() - 1)
        if (
            after <= end
            and not view[after:end].strip()
            and _hint_args_are_literal(
                view,
                cm.end(),
                after - 1,
                sanctioned[cm.group(1)][0],
                literal_ends,
                expected_arity=sanctioned[cm.group(1)][1],
            )
        ):
            return True
    # (5) a SINGLE-HOP field access ending in the gated name — the DTO
    #     pass-through (#486). UNREACHABLE TODAY: `allow_field_access` is
    #     False on EVERY root (#497/#500), so this arm never runs; both
    #     `WP7` (wrapper) and `BP43` (bridge) pin the expression
    #     `E::V { uuid_hex: a.uuid_hex }` DENYING, on their own root, with
    #     no acceptance anywhere to contrast against. Everything below
    #     describes the behaviour if the flag is ever turned back on.
    #
    #     It was granted to the WRAPPER roots only, and retired once its
    #     four DTO pass-through sites moved to `detail::project(...)` —
    #     an acceptance with no users is a laundering door for free.
    #     `FIELD_ACCESS_RE` accepts EXACTLY ONE DOT, not an arbitrary-depth
    #     chain: `a.b.uuid_hex` is a claim about an intermediate value this
    #     rule cannot vouch for, and no site ever took that shape. (`WP3`
    #     pins that chain denying, though today it denies at the flag
    #     rather than at the depth test — see #508.)
    #
    #     THIS ARM TRUSTS A NAME, one level deeper than arm 4 does: it claims
    #     that a field spelled `uuid_hex` on some OTHER type was gated where
    #     THAT type declared it. For the four sites that once justified it
    #     that claim held — the source was a bridge DTO whose field rules
    #     E2/E3 gate — but it is a trust RELATION, not provenance, and this
    #     comment says so rather than dressing it up.
    if allow_field_access and FIELD_ACCESS_RE.match(stripped):
        if stripped.split(".")[-1].strip() == name:
            return True
    return False


def scan_bridge_construction_sites(
    path_label: str,
    raw: str,
    sanctioned: dict[str, tuple[frozenset[int], int]],
    allow_field_access: bool = False,
) -> list[Finding]:
    """Rule E3 (#480): every CONSTRUCTION SITE of a gated field must build
    its value from a sanctioned source.

    `allow_field_access` (#486) enables shape 5 — a SINGLE-HOP field access
    ending in the gated name (`uuid_hex: a.uuid_hex`, not `a.b.uuid_hex`) —
    and defaults to `False`, which is now also the value EVERY root passes
    (#497/#500: its four wrapper DTO sites moved to `detail::project(...)`,
    so the acceptance had none left). See `initializer_is_gated`'s shape 5
    and `payload_guard.roots.ScanRoot.allow_field_access`.

    Rule E2 lets a bridge error carry a `String` under one of the six
    `GATED_FIELD_NAMES` instead of denying it by TYPE. That carve-out is only
    sound if something checks what those fields are actually SET TO — which
    is what this rule does, and why E2 without E3 would be a hole rather than
    a design.

    Candidates are DETECTED on the DISCOVERY view (comments and string
    CONTENTS blanked) and CLASSIFIED against the comments-blanked view, where
    literals are intact. The split is deliberate and the two halves have
    opposite needs:

    - DETECTION on the discovery view means a `detail:` sequence written
      inside a string — `assert!(ok, "Display did not include detail: {r}")`
      — is not a construction site and does not produce a finding. Three
      such false positives existed in `error/vault/tests.rs` before this.
      The cost is real and is stated plainly: this is the ONE place in this
      file where a lexer desync is fail-OPEN, because text the lexer
      wrongly calls a literal stops being a candidate. `BP30`-`BP33` are the
      negative-direction controls for exactly that — a real `detail: leak()`
      placed immediately after a raw string with a `#` run, an escaped
      quote, a byte string, and a lifetime/loop-label shape must still fire.
    - CLASSIFICATION reads the literal-intact view, because deciding whether
      an expression IS a string literal is impossible on a view where the
      literal has been blanked to spaces.

    `#[cfg(test)]`-gated items are skipped (`discovery_cfg_test_spans`): a
    detail string built by a test never reaches a platform.

    Like rule E1's, an E3 allowlist key is the normalized text of the site,
    so two textually IDENTICAL construction sites in one file share a key.
    That is the same characteristic the two shell guards' exact-trimmed-line
    keys have, and it is why the intended remedy for an E3 finding is to
    rewrite the site through `detail::*` (Tasks 4-7), not to allowlist it.
    """
    src = strip_comments(raw)
    depth_view = discovery_view(raw)
    # STRICT: a skip here means the construction site is not scanned
    # (#496). `sanctioned_constructor_names` above keeps the PERMISSIVE
    # matcher on purpose — it GRANTS acceptance, so over-matching there
    # finds fewer sanctioned names, which is fail-closed.
    excluded = discovery_cfg_test_spans_strict(raw)
    literal_ends = string_literal_token_ends(raw)
    findings: list[Finding] = []
    # FOUR candidate forms, one shared gate (#480 initializer, #488 let and
    # assignment, #487 the io::Error payload argument). Ordering is by match
    # offset so findings stay in source order regardless of which form
    # produced them.
    candidates = sorted(
        [
            (m.start(), m.end(), m.group(1))
            for regex in (GATED_INIT_RE, GATED_LET_RE, GATED_ASSIGN_RE)
            for m in regex.finditer(depth_view)
        ]
        + io_payload_candidates(depth_view)
    )
    for m_start, m_end, name in candidates:
        if _inside(m_start, excluded):
            continue
        start, end = m_end, initializer_end(depth_view, m_end)
        # Captured BEFORE the trailing-whitespace trim below moves `end`:
        # `initializer_end` returns the offset of the terminator itself (or
        # `len(depth_view)` if none was found before EOF), so this is the
        # literal character that closed the expression — `)`/`,`/`}` for a
        # genuine declaration or top-level comma/assignment, `;` ONLY for a
        # `let` statement (with or without initializer). Threaded into
        # `initializer_is_gated` so its arm 3 (bare `String`) can tell a
        # real declaration apart from a deferred-init `let`'s empty type
        # position — see that function's regression-fix note and `BP44`.
        terminator = depth_view[end] if end < len(depth_view) else ""
        while start < end and src[start] in " \t\r\n":
            start += 1
        while end > start and src[end - 1] in " \t\r\n":
            end -= 1
        if initializer_is_gated(
            src,
            start,
            end,
            name,
            literal_ends,
            sanctioned,
            allow_field_access,
            terminator,
        ):
            continue
        expr = " ".join(src[start:end].split()) or "<empty>"
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, m_start) + 1,
                source_line=" ".join(
                    f"{enclosing_fn_name(src, m_start)}::{name}: {expr}".split()
                ),
                variant="<construction site>",
                field=name,
                field_type=expr,
                rule="E3",
            )
        )
    return findings
