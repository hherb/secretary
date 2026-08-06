#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
r"""Fail-closed guard: no error payload crossing the FFI may carry a runtime
String that nobody has vouched for — in `core/src/**` OR in the FFI bridge.

WHY THIS EXISTS (#474, extended by #480)
----------------------------------------
`RecordError::DuplicateKey` formatted a decrypted CBOR field name into its
message. That string reached iOS as `VaultAccessError.corruptVault` and Android
as `VaultBrowseError.SaveCryptoFailure`, which is why both platforms redacted
those arms WHOLESALE — losing the detail for every corruption diagnostic, not
just the leaking one.

The payload types are now data-free by construction. This guard keeps them that
way: a new variant carrying a runtime `String` into its `#[error]` message fails
CI in the Rust author's own pull request, rather than silently degrading a
platform two layers away. That drift — a Rust edit with no platform diff and no
failing test anywhere — is exactly how the original leak shipped.

#480 closes the other half. `core` being data-free is worthless if the FFI
bridge is free to hand-roll `format!("{e}")` into a `detail` field at ~110 call
sites, because the platforms cannot tell a core-authored payload from a
bridge-authored one — both arrive as the same `String` on the same error arm.
The bridge's error types genuinely NEED prose (`detail`, `uuid_hex`, ...), so
denying them by TYPE the way `core` is denied would be unimplementable. Instead
the bridge's `String` payloads are allowed under a PINNED SET OF FIELD NAMES
(rule E2) and their CONSTRUCTION SITES are gated instead (rule E3): every one
must be a literal, or a call into `ffi/secretary-ffi-bridge/src/error/detail.rs`.
That module's constructors take `&impl GatedDetail`, and rule E4 pins every
`impl GatedDetail for X` to that one file — so THE SET OF TYPES A DETAIL STRING
CAN BE BUILT FROM IS EXACTLY THE SET OF IMPLS IN ONE REVIEWED FILE. That is the
same sink-pinning move `SecretaryLog` makes for Android's logcat (#472): do not
try to police ~110 call sites, make the unsafe call unrepresentable at all of
them and review the one file that defines what "safe" means.

THE RULE
--------
For every `#[error("...")]` attribute under `core/src/`, resolve the field types
of the variant (or struct — see below) it is attached to. If the message (or a
trailing format argument) interpolates a field whose declared type is not
provably data-free, fail — unless the attribute's exact normalized text is
allowlisted.

A field type is data-free when it is one of three things: a literal type in
`DATA_FREE_TYPES` (or a fixed-size numeric array / `Option<T>` of one); a
`thiserror`-derived enum THIS GUARD ITSELF SCANS somewhere under `core/src/**`
(see `discover_declarations`) — forwarding such an enum's `Display` via `{0}`
adds no new leak surface, because this same guard already fails at THAT enum's
own definition if any of its variants interpolates a non-data-free field; or a
one-level `type X = Y;` alias whose right-hand side clears one of the first two
checks (`pub type Fingerprint = [u8; 16];` is exactly as data-free as the array
it names).

The recursion argument is deliberately narrow: a nested error type from OUTSIDE
`core/src/**` — `std::io::Error`, `toml::de::Error`, any third-party crate's
error type — is NOT scanned by this guard, so it is NOT covered by the
recursion argument and MUST still deny. `std::io::Error` renders a filesystem
path; that is exactly the kind of payload a human should sign off on via the
allowlist, not something this guard should wave through because a same-named
local type happens to be safe.

`#[error(transparent)]` delegates `Display` WHOLESALE to its (thiserror-
required) sole field — that field is exactly as interpolated as if it were
named in a `{placeholder}`, even though the attribute text itself has none, so
it is classified the same way, recursion tier included.

`#[error("...")]` can decorate a STRUCT directly (`pub struct E { ... }`), not
only an enum variant — thiserror supports both shapes, and this guard scans
both.

DEFAULT-DENY covers STRUCTURE, not just TYPE: an unrecognised type name is a
FAILURE, not a pass, and so is a construct this guard cannot even locate or
resolve — an attribute whose variant/struct can't be found, or a placeholder
that doesn't match any parsed field, produces an `UNPARSED` finding rather
than being silently skipped. If the guard cannot understand a construct, a
human must look at it; "we didn't understand this" is not a pass.

THE BRIDGE RULES (#480: E2, E3, E4)
-----------------------------------
Everything above is rule `E1`, and it applies to BOTH scan roots. Three more
rules apply to `ffi/secretary-ffi-bridge/src/**` only. The rule id is the
allowlist's second column, so an exception is scoped to the rule that raised
it.

`E2` — DECLARATIONS. Every field of a bridge error declaration must be
data-free by `E1`'s tiers, OR be declared EXACTLY `String` under one of the
six names in `GATED_FIELD_NAMES`. The sweep covers EVERY field, not just the
interpolated ones, because uniffi and PyO3 project every field regardless of
what `Display` renders — a `String` the message never mentions still crosses
to the platform. It also covers PLAIN-derive `enum`/`struct` declarations
whose name ends `Error`/`Warning`, found by naming convention because such a
type has no `#[error(` attribute to anchor on. That convention is a
HEURISTIC, and the only one in this file: a plain-derive error type named
against the convention is not swept at all. (`SettingsWarning`,
`SettingsParseError` and `SettingsBoundsError` are why it exists.)

The six gated names are PINNED (see `GATED_FIELD_NAMES`), not inferred from a
suffix pattern: `record_uuid_hex` / `device_uuid_hex` are deliberately NOT
members, because those are DTO payload fields that merely LOOK like the
diagnostic-hex convention, and admitting them by pattern would launder real
record data through a name.

`E3` — CONSTRUCTION SITES, the other half of E2's carve-out. Wherever a gated
name appears in initializer position (`detail: <expr>`), the expression must
be a string LITERAL (optionally `.into()` / `.to_string()`), a call into
`detail::*`, the exact token `String`, or the field's own name. The
`String`-token acceptance is what keeps a DECLARATION (`detail: String` in an
enum body, or a function parameter) from being read as a construction: E2
already decides whether that declaration is acceptable, and a declaration
declares no value. `String::new()` is NOT that shape and denies.

`E4` — THE IMPL ALLOWLIST. `impl GatedDetail for X` is a security decision:
it claims `X`'s `Display` output carries no secret. Every such impl must live
in `DETAIL_MODULE_REL`, must be NON-GENERIC, and must name a plain type path
rooted in a crate this guard scans whose last segment is a type this guard
scans. Anything else is an allowlist entry a human signed. The generic and
non-path arms are not fussiness: `impl<T: Display> GatedDetail for T {}` is
one line, compiles beside the real impls, and hands the trait to every
`Display` type — after which E3 accepts `detail::gated(&anything)` and both
rules mean nothing. Like E1, this reads TEXT: a `macro_rules!`-generated
impl is invisible, so "every impl must live in that file" is a claim about
impls this guard can SEE. The same TEXT-only reading has a second blind
spot: the anchor matches literal `GatedDetail for` text, so
`use detail::GatedDetail as GD;` followed by `impl GD for X {}` spells the
trait under an alias and is invisible the same way — the anchor's scope is
impls that spell the trait's real name, not every impl of the trait.

LIMITS (stated, not hidden)
---------------------------
- Rule E1 sees DECLARATIONS, not construction sites, and under `core/src/**`
  that is all it sees. A variant whose payload is `&'static str` is provably
  safe; a `core` variant allowlisted because "its producers all pass
  literals" is a point-in-time claim this guard cannot verify. Those entries
  say so in the allowlist. Rule E3 DOES read construction sites, but only
  under `ffi/secretary-ffi-bridge/src/**` and only for the six gated field
  names.
- It covers `core/src/**` AND `ffi/secretary-ffi-bridge/src/**` (#480), with
  separate discovery per root — a bridge-local alias/const/enum must not
  vouch for a `core` field, or vice versa. Nothing ELSE is scanned: the
  uniffi and PyO3 binding crates each build their own error values from the
  bridge's, and `secretary-cli` / `desktop/src-tauri` build theirs
  independently. A `String` authored in one of those and handed to a
  platform is gated by review alone.
- RULE E3 IS A SYNTACTIC MATCH ON INITIALIZER POSITION AND ON THE FIELD'S
  NAME, so a value that reaches a gated field without passing through an
  initializer — or that passes through one under the right name — is not
  checked. THREE shapes do exactly that, all of them ordinary Rust, and all
  three were verified by execution rather than assumed:
    1. POST-CONSTRUCTION ASSIGNMENT. `e.detail = format!("{x}");` is a
       write, not an initializer, and this rule never sees a write.
    2. LOCAL BINDING PLUS FIELD SHORTHAND.
       `let detail = format!("{x}"); E::V { detail }` never produces a
       `detail:` token at all.
    3. LOCAL BINDING PLUS THE `detail: detail` ACCEPT. E3 accepts an
       initializer that is the field's own name, so
       `let detail = format!("{x}"); E::V { detail: detail }` passes — as
       does a function parameter of the same name. That arm trusts the NAME,
       not where the value came from; it exists because the approved design
       mandates the re-wrap form, and its gap is stated here rather than
       dressed up as a provenance argument (see `initializer_is_gated`).
  The three re-wrap sites in the tree today ARE re-wraps of an already-gated
  payload, but "a value named `detail` was gated where it was built" is a
  convention this guard does not establish. Closing any of the three needs
  dataflow, which is a different kind of tool.
- `#[cfg(test)]` exclusion is PER FILE. A module whose `mod` declaration is
  gated in its PARENT (`#[cfg(test)] mod tests;` in `error/vault/mod.rs`)
  is a whole test-only FILE this guard has no way to recognise from inside,
  so its construction sites are scanned like shipped ones. That is the
  fail-closed direction — findings in test code, never a missed shipped
  one — and the remedy is an allowlist entry naming the parent's gate.
- Rust is parsed by pattern, not by a real parser. The shapes in this codebase
  are regular (thiserror derives); an exotic macro-generated error enum would
  be invisible. `--self-test` pins the shapes that do occur.
- The local-error-enum and type-alias recognition in `discover_declarations`
  matches by NAME (bare, `<parent-module>::Name`, or `crate::<path>::Name`),
  not by real `use`-import / path resolution. A BARE spelling is therefore a
  tree-global claim, and `foreign_use_names` withdraws it per-file for every
  name that file `use`s from outside the crate — which is what stops
  `use std::io::Error; ... Io(#[from] Error)` from riding on
  `core/src/error.rs`'s local `pub enum Error` (it did, silently, until this
  was added). That is evidence-based, not a resolver: it can only react to a
  `use` statement it can read. A GLOB (`use some_crate::*;`) binds names it
  cannot enumerate, and a name that reaches a file some other way is
  likewise invisible. Every glob under `core/src/**` today is an intra-crate
  `use super::*;` inside `#[cfg(test)] mod tests`, plus
  `use proptest::prelude::*;`.
- Name resolution stops at the type name as written, so a `type X = Y;`
  alias that SHADOWS a name some other tier already trusts is a real hazard.
  One half of it is closed, one half is not, and the difference is worth
  stating precisely.
    CLOSED: a shadow whose name IS in a trusted set. `type CborFault =
  String;` (tier 1) or `type RecordError = String;` beside another module's
  real `enum RecordError` (tier 2) used to be a one-line, single-file,
  lint-clean pass — the tier-1/2 lookup answered "safe" before the alias
  table was ever consulted, and the guard reported ZERO findings.
  `alias_shadowed_names` now DROPS any spelling a discovered alias shadows
  out of tier 1 or tier 2, on `run_real_scan`'s existing collision-drop
  discipline. Note that rustc closed only the `type usize = String;` costume
  of this (`non_camel_case_types`, a `-D warnings` error here); `CborFault`
  is already CamelCase and compiled clean. P34-P36 pin all three.
    STILL OPEN: a shadow whose name is in NO trusted set, i.e. one that gets
  its credit from the alias tier itself. Such a name is believed at its
  single declaration, because one-level alias resolution IS tier 3, and this
  guard has no notion of the SCOPE that declaration is visible in — an alias
  declared inside `mod inner { }` registers its bare spelling tree-globally,
  so a field written `x: Fingerprint` in a DIFFERENT file rides on it even
  though `Fingerprint` means something else there. The partial mitigation is
  `run_real_scan`'s cross-file drop: two files declaring the same spelling
  with DIFFERENT right-hand sides (`type Fingerprint = [u8; 16];` in
  `identity/fingerprint.rs` and `type Fingerprint = String;` elsewhere)
  collide and are dropped rather than guessed. What is left — telling a
  single-declaration shadow apart from the thing it shadows, in the scope
  the reference site actually sits in — is name resolution, and closing it
  requires a real type resolver, which is out of scope for a pattern-based
  guard. `--self-test` pins the shapes that DO occur, not every shape that
  could be contrived to evade it.
- `find_type_aliases` drops any spelling that resolves to DIFFERENT
  right-hand sides across files rather than guessing which one is "real" —
  see `run_real_scan`. `resolve_consts` drops a `const` spelling on the same
  discipline: more than one module-scope declaration, or any `static` /
  excluded-scope declaration of that name, and the spelling is not credited.
  An earlier round unioned const names tree-wide on the argument that "a
  const's safety comes from the compiler, not its value"; the premise is
  true but the conclusion does not follow, because the claim being made is
  "this placeholder RESOLVES TO a const", and `static` is exactly the
  same-convention collision partner that breaks it.
  `local_error_enums` still does NOT get the collision-drop: it is a pure
  membership set, not a name -> value map, and any enum whose name is
  registered is by construction a real `thiserror`-derived enum this guard
  independently scans somewhere under `core/src/**` — two DIFFERENT local
  enums sharing a bare name are both still soundly "safe by recursion."
  Its bare-name exposure is to a FOREIGN collision, which is what
  `foreign_use_names` addresses instead.
- Every view comes from ONE lexical pass (`lex_spans`), which handles line
  comments, NESTED block comments, ordinary and byte strings with escapes and
  `\` + newline continuations, RAW strings with a variable `#` run, char and
  byte-char literals, and the lifetime-vs-char ambiguity. It is a LEXER, not
  a parser: it knows where literals and comments are, and nothing else. It
  does not expand macros, so a `#[error(...)]` produced by a macro — or a
  declaration produced by one — is invisible to every registry here.
- `lex_spans` treats an UNTERMINATED literal or block comment as running to
  end-of-input. That is the conservative reading for the credit registries
  (the tail stops being code, so declarations in it stop being credited) and
  it is why `foreign_use_names` does not read those views — see the next
  point.
- THE FAIL-CLOSED ARGUMENT IS PER-PASS, NOT GLOBAL, and stating it globally
  was itself a defect. "Blanking can only HIDE text, so a view bug loses a
  credit and therefore only produces findings" is true for the three
  CREDIT-GRANTING registries (local error enums, type aliases, consts) and
  false for the two CREDIT-WITHDRAWING passes: hiding a `use` in
  `foreign_use_names`, or revealing an extra `mod` in `top_level_mod_names`,
  RESTORES a credit. Those two are wired to read the views whose failure
  direction matches their own polarity (raw + comments-blanked for the
  withdrawal; the fully blanked discovery view for the local-root grant).
  A correctness claim that does not hold for every consumer is worse than
  none, because it stops the next reader from checking.
- `scan_source` locates `#[error(` on the comments-blanked view, with string
  contents INTACT, deliberately. Hiding an attribute would be fail-open, so
  that pass does not trust the lexer's literal classification at all. The
  price is that an `#[error(` sequence written INSIDE another attribute's
  message text is visited as though it were an attribute, and may produce an
  extra finding with its own (different) allowlist key. That is noise in the
  safe direction: it can never hide a real attribute, and the spurious key
  does not match the real one, so allowlisting one does not silence the
  other. Rule E4 locates its anchors the same way and inherits the same
  trade. RULE E3 IS THE ONE EXCEPTION IN THIS FILE, and it is a deliberate,
  adjudicated one: it DETECTS candidates on the literal-blanked discovery
  view, so a `detail:` written inside an `assert!` message is not a
  construction site (it removed three such false positives in
  `error/vault/tests.rs`). That makes E3 detection the single pass here
  where a lexer desync is fail-OPEN rather than fail-closed, which is why
  `BP30`-`BP33` pin a real `detail: leak()` still firing immediately after
  a raw string with a `#` run, an escaped quote, a byte string, and a
  lifetime. E3's CLASSIFICATION still reads the literal-intact view, since
  "is this expression a string literal" is undecidable on a view where the
  literal has been blanked.
- `discover_declarations` credits only MODULE-SCOPE declarations: anything
  inside a brace block that is not a `mod name { ... }` block is skipped
  (`non_module_block_spans`), which covers a trait's or an `impl`'s
  ASSOCIATED `type` / `const` (a per-impl binding, e.g. `type Ek = ...;` in a
  KEM trait impl), and anything local to a `fn` body. `const` discovery
  additionally skips `#[cfg(test)]`-gated items (`cfg_test_spans`): six of
  the 134 bare const names the round-3 rule harvested tree-wide came from
  test modules, one of them named `SECRET_FIELD_NAME`. (An earlier draft
  of this comment said 136; that measurement was taken with two of the
  measuring session's own throwaway attack files still in the tree. 134
  is the clean-tree figure.) Block kind is decided from
  the item's header text, so a `mod` declared through a macro would not be
  recognised as one — the fail-CLOSED direction (its contents lose credit).
- Declaration discovery runs over `discovery_view` — comments AND string
  literal contents blanked. Without the second half, text inside an
  `#[error("...")]` message registered as a declaration, letting an author
  self-authorise the very placeholder under test
  (`#[error("... {SELF_AUTH} const SELF_AUTH: usize = 1;")]` passed
  silently). Locating `#[error(` attributes still uses the un-blanked text,
  deliberately: blanking can only HIDE, which loses a credit (fail-closed)
  during discovery but would lose a whole ATTRIBUTE (fail-open) if the
  string scanner ever desynced. A `#[error(` written inside another
  attribute's message text is therefore still visited as if it were an
  attribute; that produces noise or nothing, never a missed real attribute.
- The recursion tier's soundness claim is "this guard fails at that enum's
  own definition." Once a leaf variant there is ALLOWLISTED — a human
  decision, not this guard's — the honest statement becomes "fails OR IS
  ALLOWLISTED at that enum's own definition." This guard does not re-verify
  that an allowlisted leaf stays sound as the type evolves; see
  `docs/superpowers/specs/2026-08-05-474-error-payload-hygiene-design.md` §4.
"""

from __future__ import annotations

import bisect
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "core" / "src"
# #480: the FFI bridge builds its own detail strings with `format!` and was,
# until rules E2/E3/E4, entirely unscanned. Bridge files get their OWN
# discovery pass (`bridge_mode`) rather than being folded into `SCAN_ROOT`'s:
# a bridge-local alias/const/enum must not vouch for a core field, or vice
# versa.
BRIDGE_SCAN_ROOT = REPO_ROOT / "ffi" / "secretary-ffi-bridge" / "src"
# #480 rule E4: the ONE file permitted to declare `impl GatedDetail for X`.
# Repo-relative and POSIX-spelled, matching `run_real_scan`'s `path_label`
# (`str(path.relative_to(REPO_ROOT))`); compared via `is_detail_module`.
DETAIL_MODULE_REL = "ffi/secretary-ffi-bridge/src/error/detail.rs"
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "error-payload-hygiene-allowlist.txt"

# Types whose every value is a compile-time constant or a pure number, and so
# cannot carry runtime content. Everything else denies.
DATA_FREE_TYPES: frozenset[str] = frozenset(
    {
        "&'static str",
        "bool",
        "char",
        "usize",
        "isize",
        "u8", "u16", "u32", "u64", "u128",
        "i8", "i16", "i32", "i64", "i128",
        # The #474 classification type: a fieldless kind plus a byte offset.
        "CborFault",
        "crate::cbor::CborFault",
    }
)

# #480/rule E2: field NAMES whose construction site rule E3 gates. A bridge
# field under one of these names, declared EXACTLY `String`,
# is not a structural finding — its VALUE is checked at the construction
# site instead of being denied outright by TYPE. Pinned to this exact set
# (spec §3.2): `record_uuid_hex` / `device_uuid_hex` are deliberately NOT
# members — those are DTO-carrying fields (sync/dto.rs, sync/status.rs), not
# diagnostic text, and gating them here would launder real payload data
# through a name that merely LOOKS like the diagnostic-hex convention.
GATED_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "detail",
        "uuid_hex",
        "block_uuid_hex",
        "recipient_fingerprint_hex",
        "expected_fingerprint_hex",
        "got_fingerprint_hex",
    }
)

# `[u8; 16]`, `[u8; RECORD_UUID_LEN]` — fixed-size numeric arrays.
ARRAY_RE = re.compile(r"^\[[ui](?:8|16|32|64|128|size);[^\]]+\]$")
# `Option<T>` is data-free exactly when `T` is.
OPTION_RE = re.compile(r"^Option<(.+)>$")
# A field-level attribute prefix (`#[from]`, `#[source]`) glued onto the raw
# type text by `parse_fields`, which does not separate attributes from types.
FIELD_ATTR_RE = re.compile(r"^#\[[^\]]*\]\s*")
# A field-level VISIBILITY modifier: `pub`, `pub(crate)`, `pub(super)`,
# `pub(self)`, `pub(in some::path)`. Requires either a parenthesised
# restriction or trailing whitespace, so it never bites an identifier that
# merely STARTS with `pub` (`pub_key`, `published`).
VISIBILITY_RE = re.compile(r"^pub(?:\s*\([^)]*\))?(?:\s+|(?=\s*$))")


def strip_visibility(text: str) -> str:
    """Strip a leading field-level visibility modifier.

    A `thiserror` error's fields may be `pub` — nothing in the language or
    in `thiserror` forbids it, and a struct-shaped error whose fields the
    crate exposes is ordinary Rust. `parse_fields` split on the first `:`
    and took the name side verbatim, so `pub struct X { pub index: usize }`
    produced a field literally named `"pub index"`; the `{index}` capture
    then matched nothing and the attribute fell through to a spurious
    `UNPARSED`. Fail-closed, so not a leak — but a guard that cries wolf on
    valid code is a guard whose findings get waved through.
    """
    text = text.strip()
    m = VISIBILITY_RE.match(text)
    return text[m.end() :].strip() if m else text


def normalize_type(ty: str) -> str:
    """Collapse whitespace and strip a leading field-level attribute, then a
    leading visibility modifier.

    `parse_fields` hands back the raw text after the field's `:` — for
    `Record(#[from] RecordError)` that is `"#[from] RecordError"`, not
    `"RecordError"`. A TUPLE field's visibility lands on the same side
    (`pub struct E(pub String)` -> `"pub String"`), so it is stripped here;
    a STRUCT field's lands on the name side and is stripped by `parse_fields`
    instead. Path qualification (`crate::unlock::UnlockError`,
    `device_file::DeviceFileError`) is deliberately left untouched: it is
    exactly the signal `discover_declarations`'s spellings rely on to tell a
    `core`-local reference from a foreign one (`std::io::Error`) apart —
    collapsing to the bare final segment would make the two indistinguishable
    and let a foreign type piggyback on a same-named local one.
    """
    ty = " ".join(ty.split())
    m = FIELD_ATTR_RE.match(ty)
    if m:
        ty = ty[m.end() :]
    return strip_visibility(ty)


def strip_field_attrs(text: str) -> str:
    """Strip any number of leading `#[...]` field-level attributes (and
    surrounding whitespace) from `text`.

    A struct field's attribute precedes its NAME (`#[source]\\n source: T`);
    a tuple field's attribute precedes its TYPE (`#[from] T`, handled by
    `normalize_type` instead). `parse_fields` calls this on the NAME side of
    a struct field — CRITICAL round-2 finding 1: `parse_fields` used to split
    on the first `:` and take the name side VERBATIM, so
    `#[source]\\n    source: std::io::Error` produced a field literally named
    `"#[source]\\n    source"`. The placeholder `{source}` then never matched
    any parsed field name, and the whole variant silently passed — live at
    `core/src/vault/mod.rs:157` and `core/src/sync/error.rs:35`.
    """
    text = text.strip()
    while True:
        m = FIELD_ATTR_RE.match(text)
        if not m:
            return text
        text = text[m.end() :].strip()


def _is_data_free_core(
    ty: str,
    local_error_enums: frozenset[str],
    denied: frozenset[str] = frozenset(),
) -> bool:
    """Tiers 1 and 2 only: literal data-free types, and `core`-local error
    enums this guard itself scans. Deliberately excludes tier 3 (alias
    resolution) — it is the target `is_data_free` calls an alias's
    right-hand side through, so an alias chain (`type A = B; type B = C;`)
    gets exactly one hop of credit, not an unbounded one.

    `denied` is checked FIRST and denies unconditionally, at EVERY tier and
    through the `Option<T>` recursion. Two independent sources feed it, both
    of which mean "this spelling does not resolve to the thing the tier
    below assumes":

    1. `foreign_use_names` — a bare spelling this file `use`s from outside
       the crate is not the local type that happens to share its name.
    2. `alias_shadowed_names` — a spelling a discovered `type X = Y;` alias
       shadows out of tier 1 or tier 2.
    """
    ty = normalize_type(ty)
    if ty in denied:
        return False
    if ty in DATA_FREE_TYPES:
        return True
    if ARRAY_RE.match(ty.replace(" ", "")):
        return True
    inner = OPTION_RE.match(ty)
    if inner:
        return _is_data_free_core(inner.group(1), local_error_enums, denied)
    return ty in local_error_enums


def alias_shadowed_names(
    aliases: dict[str, str] | None, local_error_enums: frozenset[str]
) -> frozenset[str]:
    """Spellings that a discovered `type X = Y;` alias SHADOWS out of an
    independent credit tier, and which must therefore stop being trusted.

    `DATA_FREE_TYPES` (tier 1) and `local_error_enums` (tier 2) are keyed on
    the type name AS WRITTEN. `is_data_free` consults them BEFORE the alias
    table, so a `type` alias that reuses one of their names was — until this
    drop existed — invisible: the tier-1/2 hit answered "safe" and the alias
    was never looked up.

        type CborFault = String;          // one file, no collision, no
        ...                               // ordering dependence
        Bad { fault: CborFault },         // credited by tier 1. Zero findings.

    That is a one-line, single-file, lint-clean bypass of the whole guard.
    `type usize = String;` is the same shape, and it is the ONLY half rustc
    happens to catch for us (`non_camel_case_types`, a `-D warnings` error in
    this workspace); `CborFault` is already CamelCase and compiles silently.
    Tier 2 has the identical hole (`type RecordError = String;` beside some
    other module's real `enum RecordError`), so both sets are intersected.

    Dropping — rather than resolving through the alias — is the same
    collision-drop discipline `run_real_scan` applies to a spelling with two
    different right-hand sides and `resolve_consts` applies to a colliding
    `const`: a name that means two things has not been RESOLVED, and a guard
    that guesses which meaning is "real" is a guard that can be aimed.
    Dropping costs a fail-closed finding a human then reads.
    """
    if not aliases:
        return frozenset()
    return frozenset(
        name
        for name in aliases
        if name in DATA_FREE_TYPES or name in local_error_enums
    )


def is_data_free(
    ty: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    foreign_names: frozenset[str] = frozenset(),
) -> bool:
    """True when a value of `ty` provably cannot carry runtime content.

    Three tiers, all fail-closed — see the module docstring's THE RULE
    section for the design rationale:

    1. A literal entry in `DATA_FREE_TYPES`, a fixed-size numeric array, or
       an `Option<T>` of one.
    2. A `thiserror`-derived enum this guard itself scans somewhere under
       `core/src/**` (recognised by name via `discover_declarations` —
       bare, `<parent-module>::Name`, or `crate::<path>::Name`).
    3. A one-level `type X = Y;` alias whose RHS clears tier 1 or 2. An alias
       to something unresolvable — including a chain through a SECOND alias
       — still denies; see `_is_data_free_core`'s docstring.

    Two independent DENY sets are unioned and applied before any tier:

    - `foreign_names` — tiers 2 and 3 recognise BARE spellings tree-globally,
      so any bare name the SCANNED FILE imports from outside the crate denies
      outright, whichever tier would otherwise have credited it
      (`foreign_use_names`).
    - `alias_shadowed_names` — a name in tier 1's or tier 2's set that a
      discovered `type` alias also declares is a SHADOW, and is dropped
      rather than resolved. Note this denies even when the alias's own RHS
      would have cleared a tier: the claim being made is a name-resolution
      claim, and the shadow is the evidence that it does not hold.
    """
    denied = foreign_names | alias_shadowed_names(aliases, local_error_enums)
    if _is_data_free_core(ty, local_error_enums, denied):
        return True
    if aliases:
        base = normalize_type(ty)
        if base in denied:
            return False
        if base in aliases:
            return _is_data_free_core(aliases[base], local_error_enums, denied)
    return False


def is_bridge_field_safe(
    name: str,
    ty: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    foreign_names: frozenset[str] = frozenset(),
) -> bool:
    """True when a BRIDGE field is safe under rule E2's carve-out (#480).

    Either it independently clears `is_data_free` — the ordinary tiers,
    data-free by TYPE, exactly as core requires — or its declared type is
    EXACTLY `String` under a name in `GATED_FIELD_NAMES`: data-free by
    CONSTRUCTION SITE instead, which rule E3 gates. `normalize_type`
    is applied to `ty` for the exact-`String` comparison so a field-level
    `#[from]` / visibility prefix does not defeat the match; `Option<String>`,
    `&str`, or any other near-miss spelling still denies — the carve-out is
    for the literal named type, not "close enough."

    Shared by BOTH of rule E2's uses: the `bridge_mode` carve-out on the
    ordinary interpolated-field scan (`scan_source`), and the structural
    all-fields sweep (`bridge_declaration_findings`) that also checks fields
    the `#[error(...)]` message never mentions.
    """
    if is_data_free(ty, local_error_enums, aliases, foreign_names):
        return True
    return normalize_type(ty) == "String" and name in GATED_FIELD_NAMES


# `enum Name` — used only to find enum bodies for `discover_declarations`;
# whether it's actually thiserror-derived is decided by whether its body
# contains `#[error(`, not by this regex.
ENUM_RE = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)")
# `type Name = ` — only the head. The right-hand side is NOT `[^;]+` up to
# the next `;`: a fixed-size array alias like `type Fingerprint = [u8; 16];`
# has a `;` INSIDE the brackets (separating element type from length), so a
# naive "stop at the first semicolon" regex truncates the RHS to `[u8`. See
# `find_type_aliases`, which tracks bracket depth instead.
TYPE_ALIAS_HEAD_RE = re.compile(r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*")
# A `mod name {` block header, anchored at the END of the text preceding a
# `{`. `non_module_block_spans` uses it to tell the ONE kind of brace block
# that does not change an item's "is this declared at module scope?" status
# from every other kind (fn body, impl body, trait body, struct/enum body,
# match arm, closure, ...).
MOD_HEADER_RE = re.compile(r"(?:^|[^A-Za-z0-9_])mod\s+[A-Za-z_][A-Za-z0-9_]*\s*$")
# `#[cfg(test)]` and friends (`#[cfg(all(test, ...))]`, `#[cfg_attr(test, ...)]`).
# Matching on `\btest\b` inside the attribute's parentheses is safe on the
# DISCOVERY VIEW specifically: string literals are blanked there, so a
# `#[cfg(feature = "test-utils")]` does not match. There is no
# `#[cfg(not(test))]` under `core/src/**` today; were one added, this would
# over-match it and drop a declaration — the fail-CLOSED direction.
CFG_TEST_RE = re.compile(r"#\[cfg(?:_attr)?\s*\([^\]]*\btest\b[^\]]*\)\s*\]")


def non_module_block_spans(src: str) -> list[tuple[int, int]]:
    """Character-offset `[start, end)` ranges of every brace block in the
    DISCOVERY VIEW that is NOT a `mod name { ... }` block.

    A declaration is at MODULE SCOPE — the only scope from which a bare name
    can be referenced by a sibling item, and the only scope a `{NAME}` format
    capture in a `thiserror`-generated `Display` impl can reach — exactly
    when it sits inside no such span. One mechanism therefore excludes every
    non-module scope at once: `fn` bodies, `trait` bodies, `impl` bodies
    (this subsumes and replaces the earlier impl-block-only exclusion),
    `struct`/`enum` bodies, blocks, closures and `match` arms.

    Block kind is decided by the text between the previous `{`/`}`/`;` and
    the opening brace — the item's header — matched against `MOD_HEADER_RE`.
    """
    spans: list[tuple[int, int]] = []
    stack: list[tuple[int, bool]] = []
    header_start = 0
    for i, ch in enumerate(src):
        if ch == "{":
            stack.append((i, bool(MOD_HEADER_RE.search(src[header_start:i]))))
            header_start = i + 1
        elif ch == "}":
            if stack:
                start, is_mod = stack.pop()
                if not is_mod:
                    spans.append((start, i + 1))
            header_start = i + 1
        elif ch == ";":
            header_start = i + 1
    return spans


def cfg_test_spans(src: str) -> list[tuple[int, int]]:
    """Character-offset `[start, end)` ranges of every `#[cfg(test)]`-gated
    item in the DISCOVERY VIEW, attribute included.

    A test-only declaration is not part of the shipped crate and must not
    vouch for a name a shipped `#[error("...")]` message captures. Six of the
    134 bare `const` names the round-3 rule harvested tree-wide came from
    `#[cfg(test)] mod tests { ... }` blocks — one of them literally named
    `SECRET_FIELD_NAME`.
    """
    spans: list[tuple[int, int]] = []
    n = len(src)
    for m in CFG_TEST_RE.finditer(src):
        i = m.end()
        # Skip whitespace and any further attributes stacked on the item.
        while i < n:
            while i < n and src[i] in " \t\r\n":
                i += 1
            if i + 1 < n and src[i] == "#" and src[i + 1] == "[":
                depth, j = 0, i + 1
                while j < n:
                    if src[j] == "[":
                        depth += 1
                    elif src[j] == "]":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
                i = j
                continue
            break
        # The gated item runs to its balanced `{...}` body, or to the `;`
        # that ends a body-less item (`#[cfg(test)] mod tests;`).
        depth, j, end = 0, i, n
        while j < n:
            c = src[j]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            elif depth == 0 and c == "{":
                body, _ = balanced_braces(src[j:])
                end = j + len(body)
                break
            elif depth == 0 and c == ";":
                end = j + 1
                break
            j += 1
        spans.append((m.start(), end))
    return spans


def _inside(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in spans)


def find_type_aliases(
    src: str, excluded_spans: list[tuple[int, int]] | None = None
) -> dict[str, str]:
    """Map alias name -> right-hand-side text for every module-scope `type X
    = Y;` in the DISCOVERY VIEW, respecting `[`/`(`/`{`/`<` nesting so a `;`
    inside e.g. `[u8; 16]` doesn't end the match early. A `type X = Y;` whose
    match START falls inside `excluded_spans` — most importantly a trait's or
    an `impl`'s ASSOCIATED type, which is a per-impl binding rather than a
    free-standing alias any field elsewhere could reference by that name — is
    skipped.
    """
    excluded_spans = excluded_spans or []
    aliases: dict[str, str] = {}
    for m in TYPE_ALIAS_HEAD_RE.finditer(src):
        if _inside(m.start(), excluded_spans):
            continue
        i, n = m.end(), len(src)
        depth = 0
        start = i
        while i < n:
            ch = src[i]
            if ch in "([{<":
                depth += 1
            elif ch in ")]}>":
                depth -= 1
            elif ch == ";" and depth == 0:
                break
            i += 1
        aliases[m.group(1)] = " ".join(src[start:i].split())
    return aliases


# `const NAME: Type = ` — requires the literal `const` keyword (never matches
# `static`, on purpose — see `find_consts`) and a `:` immediately after the
# name (never matches `const fn name(...)`, since `fn` there is followed by
# an argument list, not a colon).
CONST_RE = re.compile(r"\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=;]+=")
# `static NAME:` / `static mut NAME:` — never a credit, always a SHADOW; see
# `find_const_shadows`.
STATIC_RE = re.compile(r"\bstatic\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:")


def find_consts(
    src: str, excluded_spans: list[tuple[int, int]] | None = None
) -> list[str]:
    """Bare names of every MODULE-SCOPE `const NAME: Type = value;` in the
    DISCOVERY VIEW, one entry per declaration (repeats are meaningful — see
    `resolve_consts`).

    Only `const`, never `static` — a Rust `const` is required by the
    compiler to be evaluable at COMPILE TIME (a non-const-evaluable
    initializer is a compile error), so it cannot carry runtime content
    regardless of its declared type: that guarantee is stronger than, and
    independent of, `DATA_FREE_TYPES`. A `static` (even an immutable one, let
    alone `static mut`) does not carry the same guarantee — a
    `static X: LazyLock<String>` is a perfectly ordinary way to hold runtime
    data behind a SCREAMING_SNAKE_CASE name — so `CONST_RE` is deliberately
    anchored on the literal `const` keyword, and `find_const_shadows` treats
    every `static` as actively DISQUALIFYING the name. `const fn name(...)`
    (a function, not a value) is also excluded: the regex requires a `:`
    immediately after the captured name, which a function's argument list
    never has.

    `excluded_spans` carries every scope a bare `{NAME}` capture cannot
    reach — non-module blocks (`fn` bodies, `trait` bodies, `impl` bodies:
    an ASSOCIATED const is a per-impl binding, not a free name) and
    `#[cfg(test)]`-gated items (not part of the shipped crate). See
    `non_module_block_spans` / `cfg_test_spans`.

    The anonymous `const _: () = ...;` form is dropped: `_` is not a name any
    placeholder can capture.

    Unlike `find_type_aliases` / the enum spellings in `discover_declarations`,
    only the BARE name is ever registered: a format-string placeholder
    `{NAME}` can only capture a bare, unqualified identifier — Rust's
    captured-identifier syntax does not accept a path — so a qualified
    spelling would never be looked up. That is also why consts get
    `resolve_consts`'s collision-drop instead: with no qualified spelling to
    disambiguate on, a bare name is all there is.
    """
    excluded_spans = excluded_spans or []
    names: list[str] = []
    for m in CONST_RE.finditer(src):
        if _inside(m.start(), excluded_spans):
            continue
        if m.group(1) == "_":
            continue
        names.append(m.group(1))
    return names


def find_const_shadows(
    src: str, excluded_spans: list[tuple[int, int]] | None = None
) -> set[str]:
    """Bare names that DISQUALIFY themselves from the const tier.

    Two kinds, both of which mean "a `{NAME}` capture of this spelling is not
    demonstrably a module-scope `const`":

    1. Every `static NAME: ...` — anywhere, at any scope. `static` is the
       other thing a bare SCREAMING_SNAKE_CASE identifier commonly resolves
       to, and it carries no compile-time-evaluation guarantee. This is the
       concrete counter-witness that killed the previous round's tree-global
       bare-name const union: a file declaring
       `pub static LEAKY_NAME: LazyLock<String> = ...` and capturing
       `{LEAKY_NAME}` correctly denied ON ITS OWN, but an unrelated,
       later-sorted file adding `pub const LEAKY_NAME: usize = 16;` made the
       finding DISAPPEAR. The guard's claim is "this placeholder RESOLVES TO
       a const", which is a name-resolution claim; a union over bare names
       does not establish it, and `static` is exactly the collision partner
       that proves so.
    2. Every `const NAME: ...` declared inside `excluded_spans` — a `fn`
       body, a `trait` body, an `impl` body, or a `#[cfg(test)]` item. Such a
       declaration is not a credit (see `find_consts`), and its EXISTENCE is
       evidence that this spelling means more than one thing in this tree.
    """
    excluded_spans = excluded_spans or []
    names: set[str] = set()
    for m in STATIC_RE.finditer(src):
        names.add(m.group(1))
    for m in CONST_RE.finditer(src):
        if m.group(1) != "_" and _inside(m.start(), excluded_spans):
            names.add(m.group(1))
    return names


def resolve_consts(declared: list[str], shadows: frozenset[str]) -> frozenset[str]:
    """The const tier's credited name set: a bare name is credited only when
    the guard saw EXACTLY ONE module-scope `const` declaration of it across
    everything it scanned, and saw nothing that disqualifies the spelling.

    This is the same collision-drop discipline `find_type_aliases` already
    gets in `run_real_scan`, for the same reason: a spelling that resolves to
    more than one declaration has not been RESOLVED, and a guard that guesses
    which one is "real" is a guard that can be aimed. Dropping costs nothing
    but a fail-closed `UNPARSED` finding a human then reads; guessing costs a
    silent pass.
    """
    counts: dict[str, int] = {}
    for name in declared:
        counts[name] = counts.get(name, 0) + 1
    return frozenset(
        name for name, count in counts.items() if count == 1 and name not in shadows
    )


# `use ...;` — the per-file name bindings that make a BARE spelling mean
# something other than what tree-global discovery assumed. Roots that stay
# inside this crate; anything else (`std`, `core`, a third-party crate) binds
# a name this guard does not scan and therefore cannot vouch for.
LOCAL_USE_ROOTS: frozenset[str] = frozenset({"crate", "super", "self"})
USE_HEAD_RE = re.compile(r"\buse\s+")
# `mod name;` / `mod name { ... }`. Rust 2018 UNIFORM PATHS let a `use` start
# at a module declared in the CURRENT module, with no `crate::`/`self::`
# prefix — `core/src/vault/mod.rs` really does write `pub use block::{...};`
# beside its `pub mod block;`. Such a root is intra-crate, so it must not be
# mistaken for a third-party crate name.
MOD_DECL_RE = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]")


def top_level_mod_names(view: str) -> set[str]:
    """Names of the modules this file declares AT ITS TOP LEVEL (brace depth
    0 in the discovery view).

    Only a top-level `mod name;` / `mod name { }` puts `name` in scope as the
    first segment of a uniform-path `use`. A NESTED one does not, and treating
    it as though it did is a bypass rather than a nicety:
    `mod outer { pub mod std { } }` compiles happily alongside
    `use std::io::Error;` (no E0659 — the nested `std` is not in scope here),
    and an unscoped harvest would then read that `use` as intra-crate and stop
    withdrawing the bare `Error` credit. `mod thiserror;` and a `mod std;`
    written textually AFTER the `use` are the same class.

    Reads the DISCOVERY VIEW, not raw: this function GRANTS local-ness, i.e.
    it suppresses a withdrawal, so its failure mode must be to find FEWER
    modules, not more. See `foreign_use_names`.
    """
    opens = [i for i, c in enumerate(view) if c == "{"]
    closes = [i for i, c in enumerate(view) if c == "}"]
    names: set[str] = set()
    for m in MOD_DECL_RE.finditer(view):
        depth = bisect.bisect_left(opens, m.start()) - bisect.bisect_left(
            closes, m.start()
        )
        if depth == 0:
            names.add(m.group(1))
    return names


def _use_bound_names(tree: str, parent_last: str | None = None) -> set[str]:
    """Every name a `use` tree binds into its file's namespace.

    Handles `a::b::C`, `a::b::C as D`, `a::{B, c::{D, self}}` and `a::*`
    (which binds nothing this function can enumerate — see
    `foreign_use_names`).
    """
    tree = tree.strip()
    if not tree:
        return set()
    brace = tree.find("{")
    if brace != -1:
        prefix = tree[:brace].strip().rstrip(":").strip()
        close = tree.rfind("}")
        inner = tree[brace + 1 : close if close > brace else len(tree)]
        segs = [s.strip() for s in prefix.split("::") if s.strip()]
        last = segs[-1] if segs else parent_last
        out: set[str] = set()
        for part in split_top_level(inner):
            out |= _use_bound_names(part, last)
        return out
    if " as " in tree:
        alias = tree.split(" as ")[-1].strip()
        return {alias} if alias and alias != "_" else set()
    segs = [s.strip() for s in tree.split("::") if s.strip()]
    if not segs:
        return set()
    leaf = segs[-1]
    if leaf == "*":
        return set()
    if leaf == "self":
        if len(segs) >= 2:
            return {segs[-2]}
        return {parent_last} if parent_last else set()
    return {leaf}


def foreign_use_names(raw: str) -> frozenset[str]:
    """Bare names this FILE binds to something OUTSIDE the crate.

    Tree-global discovery registers a BARE spelling for every `core`-local
    thiserror enum, type alias and const it finds, and `is_data_free` then
    credits that spelling anywhere in the tree. That is a name-resolution
    claim, and a `use` statement is the one piece of evidence a
    pattern-matcher can actually read that CONTRADICTS it:

        use std::io::Error;          // in this file, `Error` is std's
        ...
        K1BareIoError(#[from] Error) // NOT crate::error::Error

    `core/src/error.rs` declares `pub enum Error` with `#[error(` in its
    body, so the bare spelling `Error` is registered tree-wide — which made
    that variant pass silently even though `std::io::Error` renders a
    filesystem path. Every name bound here is removed from the BARE-name
    credits when this file is scanned; qualified spellings
    (`crate::unlock::UnlockError`, `device_file::DeviceFileError`) are
    untouched, since a path cannot be shadowed by a `use`.

    Roots `crate` / `super` / `self` are intra-crate and are skipped: those
    resolve to items this guard does scan. So is a root naming a TOP-LEVEL
    module of the same file (`top_level_mod_names`) — Rust 2018 uniform paths
    make `pub use block::{BlockError, ...};` beside `pub mod block;` an
    ordinary intra-crate re-export, and treating it as a third-party crate
    named `block` produced four spurious findings in `core/src/vault/mod.rs`.
    TOP-LEVEL is load-bearing and was not always so: harvesting every
    `mod NAME` at any depth meant `mod outer { pub mod std { } }` — which
    compiles, because the nested `mod std` is not in scope at file top level —
    silently reclassified `use std::io::Error;` as intra-crate and handed the
    bypass back. Nothing under `core/src/**` collides today; the narrowing is
    for the code that has not been written yet.

    THIS PASS DELIBERATELY READS THE RAW SOURCE, not `discovery_view`.
    Everywhere else, a lexer bug that HIDES text loses a credit and so
    produces a finding — the fail-closed direction. This pass is the
    inversion: it WITHDRAWS credits, so hiding a `use` here would RESTORE
    one. Round 5's review demonstrated exactly that against the round-4
    scanner — `fn zz_q() -> char { '"' }` desynced the string state across the
    following `use std::io::Error;`, the `use` was blanked, the withdrawal
    never happened, and the bypass round 4 closed came back. Reading raw means
    the failure mode is OVER-withdrawal (a `use` written inside a comment or a
    string costs that file a bare-name credit it may not have needed), which
    is noise in the safe direction and cannot resurrect a credit. The
    `local_roots` half — which RESTORES credit — reads `discovery_view`
    instead, for the mirror-image reason.

    LIMIT: a glob (`use some_crate::*;`) binds names this function cannot
    enumerate. Every glob under `core/src/**` today is an intra-crate
    `use super::*;` inside a `#[cfg(test)] mod tests`, plus
    `use proptest::prelude::*;`. A future foreign glob would leave the
    bare-name credit in place — the same residual "not a real import
    resolver" risk the module docstring's LIMITS already records.
    """
    local_roots = LOCAL_USE_ROOTS | top_level_mod_names(discovery_view(raw))
    # Two independent reads, unioned. Neither is trusted alone:
    #   RAW  — nothing can hide a `use` from it, which is the property this
    #          pass needs; but `use` is also an ordinary English word, so
    #          every doc comment saying "we use the manifest" would bind
    #          nonsense. `_looks_like_use_tree` filters those out. It is a
    #          NOISE filter, not a security control: everything it rejects is
    #          recovered by the second read whenever it was really code.
    #   COMMENTS-BLANKED — no prose, so no filter needed. Catches the shapes
    #          the filter rejects, e.g. `use std::/*why*/io::Error;`.
    # Union, so a `use` has to escape BOTH to escape the withdrawal.
    names = _scan_use_bindings(raw, local_roots, require_use_tree=True)
    names |= _scan_use_bindings(
        strip_comments(raw), local_roots, require_use_tree=False
    )
    return frozenset(names)


# A `use` tree is punctuation and identifiers, never prose. Both checks are
# needed: the character class alone still admits "the manifest", and the
# adjacency check alone still admits "`Foo` here".
#
# `|` is in the class ONLY because `_looks_like_use_tree` substitutes it for
# the ` as ` renaming keyword before matching. Omitting it made the
# normalisation defeat the very check it exists to enable — see there.
USE_TREE_CHARS_RE = re.compile(r"^[A-Za-z0-9_:{}*,|\s]+$")
USE_TREE_PROSE_RE = re.compile(r"[A-Za-z0-9_]\s+[A-Za-z0-9_]")


def _looks_like_use_tree(tree: str) -> bool:
    """Whether `tree` could be a Rust use tree rather than English prose.

    Two identifier-ish words separated by whitespace never occur in a use
    tree — except across the ` as ` renaming keyword, which is normalised
    away first. `use std :: io :: Error;` (spaces around `::`) is valid Rust
    and still passes, because a colon is not an identifier character.

    The `|` substituted for ` as ` MUST be a member of `USE_TREE_CHARS_RE`,
    or the normalisation inverts its own purpose: it was not, so EVERY
    `use foo::Bar as Baz;` failed the character-class check and this
    function returned False — the exact opposite of what the paragraph above
    claims. Measured over `core/src/**`, that left the raw read withdrawing
    52 names against the blanked read's 61 (union 67), so 15 withdrawals —
    every `use ... as ...` in the tree — rested on the blanked read ALONE.
    That read is the one a lexer desync can silently disarm, and the whole
    point of the union in `foreign_use_names` is that no single read is
    trusted. With `|` in the class the raw read withdraws all 67, a strict
    superset of the union, and the real scan's verdict is unchanged.
    """
    collapsed = " ".join(tree.split()).replace(" as ", "|")
    if not collapsed or not USE_TREE_CHARS_RE.match(collapsed):
        return False
    return not USE_TREE_PROSE_RE.search(collapsed)


def _scan_use_bindings(
    src: str, local_roots: frozenset[str], require_use_tree: bool
) -> set[str]:
    """Every foreign name bound by a `use` in `src` — see `foreign_use_names`."""
    names: set[str] = set()
    n = len(src)
    for m in USE_HEAD_RE.finditer(src):
        depth, j = 0, m.end()
        while j < n:
            c = src[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth < 0:
                    break
            elif c == ";" and depth == 0:
                break
            j += 1
        tree = src[m.end() : j]
        if require_use_tree and not _looks_like_use_tree(tree):
            continue
        root = tree.lstrip().lstrip(":").split("::")[0].split("{")[0].strip()
        if not root or root in local_roots:
            continue
        names |= _use_bound_names(tree)
    return names


def module_path_segments(path_label: str) -> list[str]:
    """The Rust module path implied by a file's location under `core/src/`.

    `core/src/unlock/device_file.rs` -> `["unlock", "device_file"]`;
    `core/src/unlock/mod.rs` -> `["unlock"]` (a `mod.rs` names its PARENT
    module, not a `mod` submodule of itself); `core/src/error.rs` ->
    `["error"]`. Returns `[]` for anything outside `core/src/` (e.g. a
    `--self-test` control, which has no real file path at all).
    """
    p = Path(path_label)
    try:
        rel = p.relative_to(Path("core") / "src")
    except ValueError:
        return []
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "mod":
        parts = parts[:-1]
    return parts


def discover_declarations(
    raw: str, path_label: str | None = None
) -> tuple[frozenset[str], dict[str, str], list[str], frozenset[str]]:
    """Four textual facts this guard can prove about a chunk of Rust source
    without a real parser — the tier-2/3/4 inputs `is_data_free` and
    `scan_source`'s placeholder resolution need.

    1. Which `enum`s it defines that are THEMSELVES scanned by this guard,
       i.e. contain at least one `#[error(...)]` attribute in their body. A
       field naming one of these is data-free BY RECURSION (see THE RULE in
       the module docstring) — this guard will already fail at that enum's
       own definition if any of ITS variants interpolates a non-data-free
       field, so re-flagging the forward adds no signal, only allowlist
       noise the approved design explicitly wants to avoid.
    2. Which `type X = Y;` aliases it declares, one level deep. Declarations
       found inside a NON-MODULE block (a trait's or an `impl`'s associated
       type, an alias local to a `fn` body) are excluded — see
       `find_type_aliases` / `non_module_block_spans`.
    3. Which module-scope `const NAME: Type = value;` declarations it has,
       one entry per declaration — see `find_consts` for why `static` is
       deliberately excluded, why non-module scopes and `#[cfg(test)]` items
       are excluded, and `resolve_consts` for the collision-drop the repeats
       feed.
    4. Which bare names DISQUALIFY themselves from (3) — every `static`, and
       every `const` in an excluded scope. See `find_const_shadows`.

    EVERY one of these runs over `discovery_view(raw)`, in which string
    literal CONTENTS are blanked as well as comments. Text inside an
    `#[error("...")]` message is not a declaration, and treating it as one
    let an author self-authorise their own placeholder from inside the very
    message under test — see `discovery_view` and `lex_spans`.

    For each discovered enum/alias name, three spellings are registered so a
    reference site is recognised regardless of how it's qualified: the bare
    name (works for a same-module or `use`-imported reference, and is the
    ONLY spelling available when `path_label` is `None`, e.g. a self-test
    control that defines-and-uses a nested type in one string); the
    immediate parent module segment (`device_file::DeviceFileError` — the
    relative sibling-module spelling this codebase actually uses); and the
    full `crate::`-rooted path (`crate::unlock::UnlockError`). This is NOT a
    `use`-import resolver (see LIMITS): a bare or aliased reference to a
    type from OUTSIDE `core/src/**` is never registered here, so
    `std::io::Error` cannot collide with a same-named local type UNLESS the
    reference site itself drops the `std::` qualification down to a bare
    name that happens to match a local one — an acknowledged, narrow
    residual risk, not something this function tries to close.

    `const` names are registered BARE ONLY (see `find_consts`) — no
    qualified spellings, since a format-string capture can never be
    qualified.

    `run_real_scan` aggregates the RESULT of this function across every file
    under `core/src/**` — see that function's docstring for how a bare-name
    alias or `const` COLLISION across files is dropped rather than resolved,
    and why `local_error_enums` does not need the same treatment. Per-file
    `use`-shadowing is applied separately, at scan time — see
    `foreign_use_names`.
    """
    src = discovery_view(raw)
    segments = module_path_segments(path_label) if path_label else []
    # ONE exclusion set for ALL THREE registries. Round 4 applied the
    # `#[cfg(test)]` half to consts only, which left the enum and alias
    # registries able to be vouched for by test-only code: a
    # `#[cfg(test)] mod tests { enum ZzShared { #[error("code {0}")] A(u32) } }`
    # registered `ZzShared` tree-wide, and a SHIPPED `pub struct ZzShared {
    # pub raw: String }` in another file then rode on it. A test-only
    # declaration is not part of the shipped crate and must not vouch for
    # anything a shipped `#[error("...")]` renders — that is a property of the
    # DECLARATION, not of which registry happens to hold it.
    excluded = non_module_block_spans(src) + cfg_test_spans(src)

    def spellings(name: str) -> list[str]:
        out = [name]
        if segments:
            out.append(f"{segments[-1]}::{name}")
            out.append("crate::" + "::".join(segments) + f"::{name}")
        return out

    local_error_enums: set[str] = set()
    for m in ENUM_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        name = m.group(1)
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        body, _ = balanced_braces(src[brace:])
        if "#[error(" in body:
            local_error_enums.update(spellings(name))

    aliases: dict[str, str] = {}
    for alias_name, rhs in find_type_aliases(src, excluded).items():
        for spelling in spellings(alias_name):
            aliases[spelling] = rhs

    consts = find_consts(src, excluded)
    const_shadows = find_const_shadows(src, excluded)

    return frozenset(local_error_enums), aliases, consts, frozenset(const_shadows)


# ---------------------------------------------------------------------------
# ONE lexical pass. Every view below is derived from it.
# ---------------------------------------------------------------------------
#
# Rounds 1-4 grew a family of hand-rolled scanners, each patched for the shape
# that had just defeated it. Round 5's review broke four of them at once, and
# every break was the same bug in a different costume: the scanner did not
# actually know where Rust literals begin and end.
#
#   - `r#"a" const ZZ: usize = 1; "b"#` -- a raw string with an odd number of
#     internal quotes re-exposed its own contents as code, so an author could
#     self-authorise a placeholder from inside a message again (the CRITICAL
#     this branch supposedly closed in round 4).
#   - `let c = '}';` inside a `fn` popped the function's own brace, promoting
#     every following declaration in that body to "module scope".
#   - `fn q() -> char { '"' }` desynced the string scanner across the next
#     `use` statement, which RESTORED a withdrawn credit (see
#     `foreign_use_names` for why that direction is the dangerous one).
#
# So: classify every byte ONCE, correctly, and derive the views from that.
# Anything a future round needs is a new view over the same classification,
# never a fifth bespoke scanner.

KIND_COMMENT = "#"
KIND_DELIM = "d"  # a literal's delimiter bytes (quotes, `r##` prefix, ...)
KIND_LITERAL = "s"  # a literal's CONTENT bytes

# `r"`, `r#"`, `r##"`, and the byte-string forms `br"`, `br#"`, ...
RAW_STRING_START_RE = re.compile(r"(?:b?r)(?P<hashes>#*)\"")
# `'x'`, `'\n'`, `'\''`, `'\\'`, `'\u{1F600}'`, and the byte forms `b'x'`.
# Deliberately NOT matched: `'static` / `'a` / `'outer` -- a `'` that is not
# closed by a matching `'` two-ish characters later is a LIFETIME or a loop
# label, not a char literal. `&'static str` is the shape that makes this
# ambiguity unavoidable, and it is everywhere in this codebase.
CHAR_LITERAL_RE = re.compile(r"b?'(?:\\u\{[0-9a-fA-F_]{1,6}\}|\\.|[^\\'\n])'")


def _ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def lex_spans(src: str) -> list[tuple[int, int, str]]:
    r"""Classify `src` into ordered, non-overlapping, non-CODE spans.

    Returns `(start, end, kind)` for every comment and every string / char
    literal, in source order; anything not covered is code. Handles:

    - line comments, and block comments WITH NESTING (Rust's `/* /* */ */`
      nests, unlike C's -- an inner `/*` that a non-nesting scanner ignores
      makes the outer comment end early);
    - ordinary and byte strings with escapes, including the `\` + newline
      line continuation;
    - RAW strings with a variable `#` run (`r"..."`, `r#"..."#`, `r##"..."##`,
      `br#"..."#`), where `"` inside the body is an ordinary character;
    - char and byte-char literals, including `'"'`, `'{'`, `'}'`, `'\''`,
      `'\\'`;
    - the lifetime-vs-char ambiguity (`&'static str` is code, not a literal).

    Unterminated constructs run to end-of-input, which is the conservative
    reading: the tail is classified as literal/comment rather than code, so
    discovery loses credits (a finding) rather than gaining them.
    """
    spans: list[tuple[int, int, str]] = []
    n = len(src)
    i = 0
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            end = src.find("\n", i)
            end = n if end == -1 else end
            spans.append((i, end, KIND_COMMENT))
            i = end
            continue

        if ch == "/" and nxt == "*":
            depth, j = 0, i
            while j < n:
                if src[j] == "/" and j + 1 < n and src[j + 1] == "*":
                    depth += 1
                    j += 2
                    continue
                if src[j] == "*" and j + 1 < n and src[j + 1] == "/":
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                    continue
                j += 1
            j = min(j, n)
            spans.append((i, j, KIND_COMMENT))
            i = j
            continue

        # `r` / `b` / `br` are literal prefixes only when they are not the
        # tail of a longer identifier (`membr"` is not a thing in valid Rust,
        # but refusing to guess costs nothing).
        if ch in "rb" and (i == 0 or not _ident_char(src[i - 1])):
            m = RAW_STRING_START_RE.match(src, i)
            if m:
                closer = '"' + m.group("hashes")
                body = m.end()
                j = src.find(closer, body)
                if j == -1:
                    spans.append((i, body, KIND_DELIM))
                    spans.append((body, n, KIND_LITERAL))
                    i = n
                    continue
                spans.append((i, body, KIND_DELIM))
                spans.append((body, j, KIND_LITERAL))
                spans.append((j, j + len(closer), KIND_DELIM))
                i = j + len(closer)
                continue
            if ch == "b":
                m = CHAR_LITERAL_RE.match(src, i)
                if m:
                    spans.append((i, i + 2, KIND_DELIM))
                    spans.append((i + 2, m.end() - 1, KIND_LITERAL))
                    spans.append((m.end() - 1, m.end(), KIND_DELIM))
                    i = m.end()
                    continue
                if nxt == '"':
                    i, added = _lex_quoted(src, i, 2, spans)
                    if added:
                        continue

        if ch == '"':
            i, added = _lex_quoted(src, i, 1, spans)
            if added:
                continue

        if ch == "'":
            m = CHAR_LITERAL_RE.match(src, i)
            if m:
                spans.append((i, i + 1, KIND_DELIM))
                spans.append((i + 1, m.end() - 1, KIND_LITERAL))
                spans.append((m.end() - 1, m.end(), KIND_DELIM))
                i = m.end()
                continue
            # A lifetime or a loop label. Code.

        i += 1
    return spans


def _lex_quoted(
    src: str, start: int, prefix_len: int, spans: list[tuple[int, int, str]]
) -> tuple[int, bool]:
    r"""Lex an ordinary (or byte) string literal at `src[start]`, appending its
    spans. `\` consumes the next character whatever it is, which is what makes
    both `\"` and the `\` + newline continuation come out right.
    """
    n = len(src)
    body = start + prefix_len
    j = body
    while j < n:
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == '"':
            break
        j += 1
    body_end = min(j, n)
    spans.append((start, body, KIND_DELIM))
    spans.append((body, body_end, KIND_LITERAL))
    if body_end < n:
        spans.append((body_end, body_end + 1, KIND_DELIM))
        return body_end + 1, True
    return n, True


def render_view(src: str, blank_kinds: str) -> str:
    r"""Blank the requested span kinds, preserving LENGTH and LINE COUNT.

    Every blanked byte becomes a space, except a newline which stays a
    newline. Both invariants are structural here rather than a special case
    that has to be remembered -- an earlier round shipped a `\` + newline
    continuation that emitted a space for the newline and silently shifted
    every subsequent reported line number in the file.
    """
    out: list[str] = []
    pos = 0
    for start, end, kind in lex_spans(src):
        if kind not in blank_kinds:
            continue
        out.append(src[pos:start])
        out.append("".join("\n" if c == "\n" else " " for c in src[start:end]))
        pos = end
    out.append(src[pos:])
    return "".join(out)


def strip_comments(src: str) -> str:
    """Blank `//` and `/* */` comments; leave literals verbatim.

    This is the view `scan_source` reads: locating `#[error(` attributes and
    extracting their message text needs the strings INTACT.
    """
    return render_view(src, KIND_COMMENT)


def discovery_view(raw: str) -> str:
    """The DECLARATION-DISCOVERY view: comments AND literal contents blanked,
    delimiters left in place.

    This is a security control. `find_consts`, `find_type_aliases` and
    `ENUM_RE` all answer "what names may this file vouch for?", and text
    inside an `#[error("...")]` MESSAGE declares nothing. Reading declarations
    from a view with string contents intact let an author self-authorise the
    very placeholder under test:

        #[error("leaked field name: {SELF_AUTH} const SELF_AUTH: usize = 1;")]
        SelfAuthorised,

    passed silently, in one file, with no collision and no file-ordering
    dependence. So did the raw-string form `r#"a" const ... "b"#`, which
    survived round 4 because that round blanked strings with a scanner that
    did not know what a raw string was.

    Char literal CONTENTS are blanked for the same reason braces matter:
    `let c = '}';` inside a `fn` body used to pop that function's own brace in
    `non_module_block_spans`, promoting the rest of the body to module scope.

    FAIL-CLOSED ONLY FOR CREDIT-GRANTING PASSES. Blanking can only ever HIDE
    text. For the three registries this view feeds -- local error enums, type
    aliases, consts -- hiding a declaration LOSES a credit, which produces a
    finding, so a lexer bug there degrades toward noise. That argument does
    NOT transfer to a WITHDRAWAL pass: `foreign_use_names` removes credits, so
    hiding a `use` there would RESTORE one. It therefore does not read this
    view at all -- see its docstring. Getting this backwards is exactly the
    kind of unchecked correctness claim this guard exists to eliminate.
    """
    return render_view(raw, KIND_COMMENT + KIND_LITERAL)



@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    source_line: str
    variant: str
    field: str
    field_type: str
    # The allowlist's rule column. `E1` (interpolated-field scan, `core/src/**`
    # and — under `bridge_mode` — the FFI bridge) is the default; rule `E2`
    # (#480: the bridge's structural all-fields declaration sweep) is set
    # explicitly by its two producers, `bridge_declaration_findings`. The
    # column exists so the file format is byte-identical to the two shell
    # guards' allowlists, which lets `scripts/lib/hygiene-allowlist.sh
    # ::allowlisted` parse this file unchanged —
    # `core/tests/error_payload_hygiene_parity.rs` exercises exactly that
    # claim.
    rule: str = "E1"


ERROR_ATTR_RE = re.compile(r"#\[error\(", re.MULTILINE)
# `.index` in a trailing format argument, e.g. `, .index + 1)`.
ARG_FIELD_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)")
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s*(\{|\(|,|$)")
# A `thiserror` error can also be a STRUCT — one shape, not an enum with
# variants — with `#[error("...")]` attached directly to `pub struct Name {
# ... }` / `pub struct Name(...);` rather than to a variant. Not used in
# `core/src` today, but nothing in the language prevents it.
STRUCT_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)")


def balanced_slice(src: str, start: int) -> tuple[str, int]:
    """Return the `(...)`-balanced text starting at `src[start] == '('`."""
    depth, i, in_string = 0, start, False
    while i < len(src):
        ch = src[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return src[start : i + 1], i + 1
        i += 1
    return src[start:], len(src)


def skip_attributes(text: str) -> str:
    """Skip leading whitespace and any number of `#[...]`-attribute spans at
    the front of `text`.

    Without this, an intervening attribute between `#[error(...)]` and the
    variant/struct it decorates defeats the guard entirely: `VARIANT_RE`
    cannot match a line starting with `#`, and the old code only ever looked
    at the FIRST non-blank line after the `#[error(...)]` attribute, so

        #[error("leak: {detail}")]
        #[cfg(all())]
        Leaky { detail: String },

    found no variant at all and silently skipped — proven live for
    `#[cfg(...)]`, `#[allow(...)]`, and `#[doc = "..."]`. Brackets are
    balanced so a multi-line or argument-bearing attribute is consumed as a
    unit, not just cut off at its own first `]`.
    """
    i, n = 0, len(text)
    while True:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i + 1 < n and text[i] == "#" and text[i + 1] == "[":
            depth, j, in_string = 0, i + 1, False
            while j < n:
                ch = text[j]
                if in_string:
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == '"':
                        in_string = False
                elif ch == '"':
                    in_string = True
                elif ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                j += 1
            i = j
            continue
        break
    return text[i:]


def parse_fields(body: str) -> dict[str, str]:
    """Map field name -> declared type for a variant (or struct) body.

    Handles both struct-shaped bodies (`{ field: &'static str, index: usize
    }`) and tuple bodies (`(String)` -> `{"0": "String"}`). A struct field's
    `#[from]`/`#[source]` attribute precedes its NAME
    (`#[source]\\n source: T`), so the name side is run through
    `strip_field_attrs` — see that function's docstring for the bug this
    fixes — and then through `strip_visibility`, since a struct field's
    `pub` / `pub(crate)` lands on the name side too. The type side (tuple
    fields: `#[from] T`, `pub T`) is left as-is here; `normalize_type`
    strips both later, at classification time.
    """
    body = body.strip()
    fields: dict[str, str] = {}
    if body.startswith("{"):
        inner = body[1 : body.rindex("}")] if "}" in body else body[1:]
        for part in split_top_level(inner):
            if ":" not in part:
                continue
            name, ty = part.split(":", 1)
            name = strip_visibility(strip_field_attrs(name))
            if name.startswith("///") or not name:
                continue
            fields[name] = " ".join(ty.split())
    elif body.startswith("("):
        inner = body[1 : body.rindex(")")] if ")" in body else body[1:]
        for idx, part in enumerate(split_top_level(inner)):
            if part.strip():
                fields[str(idx)] = " ".join(part.split())
    return fields


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not nested inside <>, (), [] or {}."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in text:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def extract_placeholders(text: str) -> list[str | None]:
    """Every genuine `{name}` / `{name:?}` / `{}` placeholder in a Rust
    format string, in left-to-right order, with `None` standing in for a
    positional `{}`.

    Consumes `{{` / `}}` (escaped braces) as 2-character units in a single
    linear left-to-right pass, rather than using a regex negative-lookbehind
    to reject a `{` immediately preceded by another `{`. The lookbehind
    approach cannot tell an escape's SECOND brace from a genuine
    placeholder's OPENING one, so it silently drops a real placeholder that
    immediately follows an escape: `{{{name}}}` is valid Rust (`{{` literal +
    `{name}` real + `}}` literal), but a lookbehind rejects the `{` at the
    real placeholder's start because the character before it is also `{`. A
    scan that eats `{{`/`}}` FIRST, before ever trying to start a placeholder
    match, has no such blind spot.
    """
    names: list[str | None] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "{" and i + 1 < n and text[i + 1] == "{":
            i += 2
            continue
        if text[i] == "}" and i + 1 < n and text[i + 1] == "}":
            i += 2
            continue
        if text[i] == "{":
            j = text.find("}", i)
            if j == -1:
                break
            inner = text[i + 1 : j]
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*|\d+)?", inner)
            names.append(m.group(1) if m else None)
            i = j + 1
            continue
        i += 1
    return names


def scan_source(
    path_label: str,
    raw: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    consts: frozenset[str] = frozenset(),
    foreign_names: frozenset[str] = frozenset(),
    bridge_mode: bool = False,
) -> list[Finding]:
    """Find every `#[error]` variant/struct that interpolates a non-data-free
    field, PLUS every `#[error(...)]` attribute whose structure this guard
    could not resolve (an `UNPARSED` finding: an unrecognised STRUCTURE
    fails closed exactly like an unrecognised TYPE does, rather than
    silently passing via a bare `continue`).

    `local_error_enums` / `aliases` are the tier-2 / tier-3 inputs to
    `is_data_free` (see `discover_declarations`) — callers that skip real
    cross-file discovery (i.e. pass nothing) still get tier 1 (literal
    `DATA_FREE_TYPES` / arrays / `Option<T>`), just not the recursion or
    alias tiers.

    `consts` is a DIFFERENT kind of input: it is not a field TYPE tier at
    all (nothing goes through `is_data_free` for it), because a `const`
    capture is not a field in the first place. A NAMED placeholder that
    resolves to neither a parsed field name NOR a discovered `const` name
    still produces an `UNPARSED` finding — the const tier is an ADDITIONAL
    way to be recognised safe, never a fallback that accepts an unknown
    name. See `find_consts` for why only `const` (never `static`) qualifies.

    `foreign_names` is this FILE's `use`-bound foreign spellings
    (`foreign_use_names`); every bare-name credit — tier 2, tier 3 and the
    const tier — is withdrawn for those spellings while this file is
    scanned.

    `bridge_mode` (#480, rule E2) does TWO things, both scoped to
    `ffi/secretary-ffi-bridge/src/**` — core behaviour (the default,
    `bridge_mode=False`) is byte-identical to before this parameter existed:

    1. Rule E2's carve-out on the ordinary interpolated-field check below:
       `is_bridge_field_safe` replaces the bare `is_data_free` call, so a
       `String` field named in `GATED_FIELD_NAMES` is not a finding here
       (rule E3 gates its construction site instead). Everything
       else still denies exactly as core's `E1` does.
    2. A STRUCTURAL sweep (`bridge_declaration_findings`, rule `E2`) over
       EVERY parsed field of the declaration — interpolated or not — since
       uniffi/PyO3 project every field regardless of what the `#[error(...)]`
       message actually renders. This is what catches a platform-projected
       `String` the `Display` text never mentions.

    Note `strip_comments`, NOT `discovery_view`: locating `#[error(`
    attributes and reading their message text needs the strings INTACT.
    Blanking is used only where it can only ever hide a credit, which is the
    fail-closed direction — see `discovery_view`.
    """
    src = strip_comments(raw)
    # Only computed in bridge_mode — see the call site's comment (#480
    # review finding 2) and `enclosing_enum_names`'s own docstring. Core
    # behaviour (`bridge_mode=False`) never reads this.
    enum_spans = enclosing_enum_names(raw) if bridge_mode else []
    findings: list[Finding] = []

    for m in ERROR_ATTR_RE.finditer(src):
        attr_text, after = balanced_slice(src, m.end() - 1)
        attr_line_no = src.count("\n", 0, m.start()) + 1

        # The allowlist key AND the human-facing "source line" are the same
        # thing: the WHOLE `#[error(...)]` attribute's RAW text (character
        # offsets are 1:1 between `src` and `raw` — `strip_comments` never
        # changes length), whitespace-collapsed to one line. Not just the
        # attribute's first source line: a multi-line attribute
        # (`sync/error.rs:9`) would otherwise key on literally `#[error(`,
        # which is NOT unique — two different multi-line attributes in the
        # same file share that "line," so an entry meant to allowlist one
        # would silently also allowlist the other. That is the exact
        # "substring exempts everything" failure the exact-line convention
        # is supposed to prevent, one level up. Collapsing to one line also
        # keeps the key free of raw tabs/newlines, since the allowlist file
        # is TAB-delimited.
        tail_raw = src[after:]
        if tail_raw.lstrip().startswith("]"):
            close_off = tail_raw.find("]") + 1
            attr_end = after + close_off
            tail = tail_raw[close_off:]
        else:
            attr_end = after
            tail = tail_raw
        key_text = " ".join(raw[m.start() : attr_end].split())

        def emit_unparsed(
            reason: str, variant: str = "<unparsed>", field: str = "<unparsed>"
        ) -> None:
            findings.append(
                Finding(
                    path=path_label,
                    line=attr_line_no,
                    source_line=key_text,
                    variant=variant,
                    field=field,
                    field_type=f"UNPARSED: {reason}",
                )
            )

        # Locate the variant/struct this attribute decorates. Done
        # UNCONDITIONALLY (not only when there's a placeholder to resolve):
        # `#[error(transparent)]` (below) needs the field list to know what
        # it implicitly interpolates, and default-deny wants an
        # unrecognisable STRUCTURE to fail closed even when the attribute's
        # OWN text happens to have nothing to interpolate — being unable to
        # locate the variant at all is itself suspicious.
        tail = skip_attributes(tail)
        vm = None
        for line in tail.splitlines():
            if line.strip():
                vm = VARIANT_RE.match(line) or STRUCT_RE.match(line)
                break
        if not vm:
            emit_unparsed(
                "could not locate the variant/struct declaration following "
                "this #[error(...)] attribute"
            )
            continue
        variant = vm.group(1)

        rest = tail[tail.find(variant) + len(variant) :].lstrip()
        if rest.startswith("{"):
            body, _ = balanced_braces(rest)
        elif rest.startswith("("):
            body, _ = balanced_slice(rest, 0)
        else:
            body = ""
        fields = parse_fields(body)
        ordered = list(fields.items())

        # Rule E2, sweep 1 (#480): every PARSED field of a bridge
        # declaration, interpolated or not — see `bridge_declaration_findings`.
        # Runs UNCONDITIONALLY once fields are known, independent of whether
        # the message below interpolates anything, is `transparent`, or is
        # itself UNPARSED for an unrelated reason.
        #
        # #480 review finding 2: the key must include the OWNING type name,
        # not just the variant's own — `SettingsWarning::Corrupt` and
        # `SettingsParseError::Corrupt` are the LIVE instance of two
        # DIFFERENT types sharing a variant name, which collided on the bare
        # key `Corrupt { ... }` before `enum_spans` existed. A STRUCT-shaped
        # error's `variant` IS already the owning type's own name (no
        # enclosing enum), so `owner` is `None` and no prefix is added.
        if bridge_mode:
            owner = _owning_enum_name(enum_spans, m.start())
            prefix = f"{owner}::" if owner else ""
            decl_text = " ".join(f"{prefix}{variant} {body}".split())
            findings.extend(
                bridge_declaration_findings(
                    path_label,
                    attr_line_no,
                    variant,
                    decl_text,
                    fields,
                    local_error_enums,
                    aliases,
                    foreign_names,
                )
            )

        # `#[error(transparent)]` delegates Display WHOLESALE to its (sole,
        # thiserror-required) field — that field is what gets interpolated
        # even though the attribute itself has zero `{...}` placeholders, so
        # it needs its own name-resolution path instead of falling into the
        # "nothing to interpolate" skip below.
        is_transparent = attr_text.strip().strip("()").strip() == "transparent"

        names: set[str] = set()
        if is_transparent:
            if len(fields) == 1:
                names.add(next(iter(fields)))
            else:
                emit_unparsed(
                    f"#[error(transparent)] on {variant} does not have "
                    f"exactly one field ({len(fields)} found) — thiserror "
                    "requires exactly one",
                    variant=variant,
                )
                continue
        else:
            # A non-transparent `#[error(...)]` is only understood when its
            # body is a STRING-LITERAL format ( `"..."` / `r"..."` / `r#"..."#`
            # ). thiserror 2.x also accepts `#[error(fmt = <path>)]`, whose
            # named formatter is handed EVERY field and can render any of them
            # — there is no format string to extract placeholders from, so the
            # `if not names: continue` skip below would wave it through as
            # "nothing interpolated" (it is not: the formatter sees the whole
            # variant). Default-deny on STRUCTURE, per the module docstring:
            # a body this guard cannot model as a format string fails closed as
            # UNPARSED, forcing a human (and an allowlist entry) rather than a
            # silent pass. Covers `fmt = ...` and any future `key = value` form.
            inner = attr_text[1:-1].strip() if len(attr_text) >= 2 else ""
            if not (inner.startswith('"') or re.match(r'r#*"', inner)):
                emit_unparsed(
                    f"{variant} has an #[error(...)] body this guard cannot "
                    "model as a string-literal format — e.g. thiserror's "
                    "`fmt = <path>` custom-formatter form, whose formatter can "
                    "render any field. Deny by default; allowlist after review",
                    variant=variant,
                )
                continue
            # Every placeholder name in the format string, plus every
            # `.field` referenced by a trailing format argument (the
            # mnemonic.rs shape).
            positional = 0
            for token in extract_placeholders(attr_text):
                if not token:
                    names.add(f"__positional_{positional}")
                    positional += 1
                else:
                    names.add(token)
            arg_split = attr_text.find(",")
            if arg_split != -1:
                for am in ARG_FIELD_RE.finditer(attr_text[arg_split:]):
                    names.add(am.group(1))
            if not names:
                # Nothing is interpolated — provably nothing to check, not a
                # parse failure (see N4). Distinct from `not vm` above: THAT
                # means "we don't even know what this decorates"; this means
                # "we know, and it interpolates nothing."
                continue

        # Positional `{}` placeholders bind to fields in declaration order.
        # `seen_fields` dedupes the case where the SAME field is reachable
        # two ways in one attribute (a positional `{}` plus an explicit
        # `.field` argument for that field) — cosmetic only, but there is no
        # reason to report one leak twice.
        seen_fields: set[str] = set()
        for name in sorted(names):
            if name.startswith("__positional_"):
                idx = int(name.rsplit("_", 1)[1])
                if idx < len(ordered):
                    fname, ftype = ordered[idx]
                else:
                    emit_unparsed(
                        f"positional placeholder #{idx} in {variant} has no "
                        f"corresponding field ({len(ordered)} declared)",
                        variant=variant,
                    )
                    continue
            elif name in fields:
                fname, ftype = name, fields[name]
            elif name in consts and name not in foreign_names:
                # A `const` capture, not a field — Rust requires a `const`'s
                # initializer to be compile-time evaluable, so it cannot
                # carry runtime content regardless of its declared type.
                # Nothing further to classify; this is not a field lookup.
                # `foreign_names` withdraws the credit when THIS file binds
                # the spelling to something outside the crate.
                continue
            else:
                emit_unparsed(
                    f"{variant} interpolates `{{{name}}}`, which does not "
                    "match any field or discovered const this guard could "
                    "parse — it cannot verify what is being rendered",
                    variant=variant,
                    field=name,
                )
                continue
            if fname in seen_fields:
                continue
            seen_fields.add(fname)
            # Rule E2 item 1 (#480): in bridge_mode, an interpolated field
            # gets the SAME carve-out the structural sweep above uses —
            # `String` under a `GATED_FIELD_NAMES` name is not a finding
            # HERE (rule E3 gates its construction site instead).
            # Everything else denies exactly as core's E1 does today.
            field_is_safe = (
                is_bridge_field_safe(fname, ftype, local_error_enums, aliases, foreign_names)
                if bridge_mode
                else is_data_free(ftype, local_error_enums, aliases, foreign_names)
            )
            if not field_is_safe:
                findings.append(
                    Finding(
                        path=path_label,
                        line=attr_line_no,
                        source_line=key_text,
                        variant=variant,
                        field=fname,
                        field_type=ftype,
                    )
                )
    return findings


def enclosing_enum_names(raw: str) -> list[tuple[int, int, str]]:
    """`[(body_start, body_end, enum_name)]` for every `enum NAME { ... }`
    body span in `raw` (#480 review finding 2).

    Recovers the OWNING enum's name for a variant `scan_source` locates via
    `VARIANT_RE`, so rule E2's allowlist key can include it —
    `SettingsWarning::Corrupt` and `SettingsParseError::Corrupt` are the
    LIVE instance of two DIFFERENT types sharing a same-named,
    same-shaped variant, and collided on the bare key `Corrupt { ... }`
    before this existed: one allowlist entry would have silenced both,
    exactly the cross-exemption failure the whole-attribute key convention
    exists to prevent (see `scan_source`'s `key_text` comment).

    Computed over the DISCOVERY VIEW (`discovery_view(raw)`, comments AND
    string contents blanked) rather than `strip_comments` — the same
    self-authorisation concern `discover_declarations`'s own `ENUM_RE` walk
    guards against (P22): an `#[error("... enum Fake { ... } ...")]`
    message must not be read as a real enum declaration. Character offsets
    are valid against ANY of this module's views regardless
    (`check_view_invariants` pins that every view preserves length and line
    count), so the spans this returns are directly usable against
    `scan_source`'s own `strip_comments`-based `m.start()` positions.

    A WRONG owner name here can only ever produce a MISLEADING allowlist
    key — unlike `local_error_enums` (tier 2), this registry grants no
    safety credit; `is_bridge_field_safe` never consults it. The
    discovery-view choice is therefore belt-and-braces, not a soundness
    requirement, but it costs nothing and keeps the key accurate.
    """
    view = discovery_view(raw)
    spans: list[tuple[int, int, str]] = []
    for m in ENUM_RE.finditer(view):
        brace = view.find("{", m.end())
        if brace == -1:
            continue
        body, _ = balanced_braces(view[brace:])
        spans.append((brace, brace + len(body), m.group(1)))
    return spans


def _owning_enum_name(spans: list[tuple[int, int, str]], pos: int) -> str | None:
    """The name of the enum span containing `pos`, or `None` if `pos` is not
    inside any (a struct-shaped error, whose `STRUCT_RE` match already
    carries its own name — no owner lookup needed). Rust does not allow one
    `enum` to be declared inside another's body, so `pos` is inside at most
    one span; the first (only) match wins."""
    for start, end, name in spans:
        if start <= pos < end:
            return name
    return None


def bridge_declaration_findings(
    path_label: str,
    line_no: int,
    variant: str,
    decl_text: str,
    fields: dict[str, str],
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
) -> list[Finding]:
    """Rule E2's structural sweep (#480): every PARSED field of a bridge
    declaration — interpolated or not, since uniffi/PyO3 project every field
    regardless of what `#[error(...)]`'s message actually mentions — must
    independently satisfy `is_bridge_field_safe`.

    Shared by both of rule E2's producers: `scan_source`'s `bridge_mode`
    sweep 1 (thiserror-derived declarations, anchored on their own
    `#[error(` attribute) and `scan_bridge_plain_declarations`'s sweep 2
    (plain-derive `*Error`/`*Warning` enums with no such attribute to anchor
    on). Both callers precompute `decl_text` — the whitespace-collapsed
    `"<variant/struct name> <body>"` text — themselves, since sweep 1 has an
    `#[error(...)]` attribute's surrounding context to draw on and sweep 2
    does not.
    """
    out: list[Finding] = []
    for fname, ftype in fields.items():
        if is_bridge_field_safe(fname, ftype, local_error_enums, aliases, foreign_names):
            continue
        out.append(
            Finding(
                path=path_label,
                line=line_no,
                source_line=decl_text,
                variant=variant,
                field=fname,
                field_type=ftype,
                rule="E2",
            )
        )
    return out


# `enum Name` / `struct Name` where NAME ends `Error` or `Warning` — rule
# E2's SECOND sweep target (#480): a bridge declaration following this
# codebase's own error/warning naming convention but carrying NO
# `#[error(...)]` attribute anywhere — a plain `#[derive(Debug, ...)]`, not
# thiserror (e.g. `SettingsWarning`, `SettingsParseError`,
# `SettingsBoundsError`). uniffi/PyO3 project every field of such a type
# regardless of derive shape, so it needs the same all-fields sweep a
# thiserror declaration gets via `scan_source`'s `#[error(` anchor; this
# shape has no such anchor, so it is found by NAME instead. A heuristic, not
# a language guarantee — see the module docstring's LIMITS on pattern-based
# discovery generally.
BRIDGE_PLAIN_ENUM_RE = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*(?:Error|Warning))\b")
BRIDGE_PLAIN_STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*(?:Error|Warning))\b")


def _bridge_plain_enum_variant_findings(
    path_label: str,
    line_no: int,
    owner_name: str,
    body: str,
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
) -> list[Finding]:
    """Rule E2 sweep 2's per-variant walk for a plain-derive enum BODY
    (`{...}`, outer braces included) — #480 review finding 1.

    Mirrors `scan_source`'s own single-variant parse (`VARIANT_RE` + a
    balanced field body + `parse_fields`), applied once per TOP-LEVEL
    comma-separated member instead of once per `#[error(...)]` attribute:
    this shape has no attribute to anchor on (that is the whole reason it
    needed its own discovery pass), so it must walk every variant in the
    body itself. `skip_attributes` handles a variant carrying its own
    attribute (e.g. `#[non_exhaustive]`) the same way `scan_source` does.

    Three outcomes per part, all fail-closed on STRUCTURE the same way
    `scan_source`'s own attribute walk is — and two of the three were
    proven reachable BY EXECUTION during review round 2, not merely
    reasoned about, after an earlier version of this comment claimed (by
    reasoning alone) that only the harmless case could occur:

    - The RAW part (before `skip_attributes` even runs) is EMPTY once
      whitespace is stripped: `split_top_level`'s trailing tail after a
      body's closing (near-universal, rustfmt-default) trailing comma —
      Rust does not allow two consecutive top-level commas in COMPILING
      source, so an empty RAW part can only ever be that harmless tail,
      never a dropped declaration. Skipped silently, mirroring
      `scan_source`'s OWN identical "nothing is interpolated — provably
      nothing to check, not a parse failure" distinction (see its `if not
      names: continue`, comment tag N4).
    - The RAW part is non-empty, but `skip_attributes` reduces it to
      nothing anyway: `skip_attributes` has no raw-string awareness — a
      raw string inside a field-level attribute
      (`#[doc = r#"a " b"#]`) desyncs its naive quote-toggle, which
      swallows the attribute's closing `]` and everything after it,
      including the variant it was meant to skip PAST. Rustc-verified
      witness (`--crate-type lib --edition 2021`):
      `pub enum FooError { #[doc = r#"a " b"#] Leaky { leak: String }, }`
      — `leak: String` was dropped with ZERO findings before this branch
      existed. `scan_source` itself has no equivalent silent branch (an
      empty `tail` there just fails to match `VARIANT_RE`/`STRUCT_RE`,
      which its EXISTING `if not vm: emit_unparsed(...)` already catches
      unconditionally) — this branch restores that same coverage here.
    - A non-empty, successfully-`skip_attributes`d part still does not
      match `VARIANT_RE` — e.g. a raw-identifier variant name
      (`r#Match { leak: String }`) — IS a genuine parse failure.
    - AFTER a field body is extracted (`balanced_braces`/`balanced_slice`),
      anything left over in `rest` is a sign `split_top_level` itself
      mis-split: it has no string-literal awareness, so a `}` inside a
      field-level attribute's string content (`#[doc = "}"]`) drives its
      bracket-depth tracking negative, which suppresses the NEXT real
      top-level comma from splitting — merging TWO variants into one
      `part` and silently discarding the second. Rustc-verified witness:
      `pub enum BazError { #[doc = "}"] A { x: usize }, B { leak: String },
      }` — `B`'s `leak: String` was dropped with ZERO findings (only `A`,
      data-free, was ever seen) before this check existed.
    """
    inner = body[1 : body.rindex("}")] if "}" in body else body[1:]
    findings: list[Finding] = []
    for part in split_top_level(inner):
        if not part.strip():
            continue
        text = skip_attributes(part.strip())
        if not text:
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"{owner_name} {{ {' '.join(part.strip().split())} }}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=(
                        "UNPARSED: skip_attributes could not locate content "
                        f"past this part's attributes in {owner_name}'s body "
                        "(e.g. a raw string inside an attribute desyncing "
                        "the naive #[...] scanner)"
                    ),
                    rule="E2",
                )
            )
            continue
        vm = VARIANT_RE.match(text)
        if not vm:
            collapsed = " ".join(part.strip().split())
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"{owner_name} {{ {collapsed} }}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=(
                        f"UNPARSED: could not locate a variant declaration "
                        f"in {owner_name}'s body"
                    ),
                    rule="E2",
                )
            )
            continue
        name = vm.group(1)
        rest = text[len(name) :].lstrip()
        if rest.startswith("{"):
            fbody, _ = balanced_braces(rest)
        elif rest.startswith("("):
            fbody, _ = balanced_slice(rest, 0)
        else:
            fbody = ""
        remainder = rest[len(fbody) :]
        if remainder.strip():
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"{owner_name} {{ {' '.join(remainder.split())} }}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=(
                        f"UNPARSED: unconsumed content after {owner_name}::"
                        f"{name}'s declaration — split_top_level likely "
                        "mis-split on a string-embedded bracket character"
                    ),
                    rule="E2",
                )
            )
        decl_text = " ".join(f"{owner_name}::{name} {fbody}".split())
        findings.extend(
            bridge_declaration_findings(
                path_label,
                line_no,
                name,
                decl_text,
                parse_fields(fbody),
                local_error_enums,
                aliases,
                foreign_names,
            )
        )
    return findings


def _bridge_plain_struct_findings(
    path_label: str,
    line_no: int,
    name: str,
    body: str,
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
) -> list[Finding]:
    """Rule E2 sweep 2's struct counterpart (#480 review finding 3): a
    plain-derive `*Error`/`*Warning` STRUCT (`SettingsBoundsError`) has no
    variants to walk — its own field list IS the declaration, so this is a
    thin wrapper around `bridge_declaration_findings`, not a walk. `body` is
    the struct's already-located `{...}` or `(...)` text; a unit struct
    (`;`, no body) never reaches this function — see
    `scan_bridge_plain_declarations`.
    """
    decl_text = " ".join(f"{name} {body}".split())
    return bridge_declaration_findings(
        path_label,
        line_no,
        name,
        decl_text,
        parse_fields(body),
        local_error_enums,
        aliases,
        foreign_names,
    )


def discovery_cfg_test_spans(raw: str) -> list[tuple[int, int]]:
    r"""`cfg_test_spans`, computed over the DISCOVERY VIEW rather than
    `strip_comments`.

    `CFG_TEST_RE`'s own docstring states its `\btest\b` match is safe "on
    the DISCOVERY VIEW specifically: string literals are blanked there" —
    over `strip_comments` alone, a hypothetical
    `#[cfg(feature = "test-utils")]` would false-positive-match and exclude
    a SHIPPED declaration from a sweep, which is the fail-OPEN direction for
    a discovery pass that only ever REMOVES a candidate from being checked.
    `scan_bridge_plain_declarations` and `discover_error_struct_names`
    locate their own candidates on `strip_comments` (matching the module
    docstring's "comments-blanked view" — the same view `scan_source` uses
    to locate `#[error(`), but every span this module computes preserves
    LENGTH and LINE COUNT (`check_view_invariants` pins that), so an offset
    valid against ONE view is valid against ANY of them; there is no need
    to re-derive a candidate's own match against `discovery_view`, only to
    compute the EXCLUSION spans against it.

    Despite the name, this is general-purpose — not bridge-specific — and
    is used for BOTH scan roots wherever a `#[cfg(test)]` exclusion is
    needed against test-only content vouching for something shipped.
    """
    return cfg_test_spans(discovery_view(raw))


def scan_bridge_plain_declarations(
    path_label: str,
    raw: str,
    local_error_enums: frozenset[str] = frozenset(),
    aliases: dict[str, str] | None = None,
    foreign_names: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Rule E2's second sweep (#480) — bridge `enum`/`struct` declarations
    named `*Error`/`*Warning` (see `BRIDGE_PLAIN_ENUM_RE` /
    `BRIDGE_PLAIN_STRUCT_RE`) carrying NO `#[error(...)]` attribute at all:
    a PLAIN derive (`SettingsWarning`, `SettingsParseError`,
    `SettingsBoundsError` — #480 review finding 3), not a thiserror one.
    thiserror-derived declarations are swept by `scan_source`'s own
    `bridge_mode` sweep 1 via its `#[error(` attribute anchor; a plain
    derive has no such attribute to anchor on, so this function
    re-discovers candidates by NAME CONVENTION instead.

    An ENUM candidate is "already swept" (skip, avoid double-reporting
    under the same rule) when `#[error(` appears ANYWHERE in its body
    (decorating a variant). A STRUCT's `#[error(...)]`, if any, decorates
    the STRUCT ITSELF — preceding it, not living inside a body — so the
    equivalent check instead consults the POSITIONS reported by
    `discover_error_struct_declarations`, the same walk
    `scanned_error_type_names` (rule E4) takes its names from. Position, not
    name: see that function's docstring for the two rustc-verified witnesses
    a bare-name check was fail-open to.

    Both candidate kinds skip a match starting inside a `#[cfg(test)]`-
    gated item (`discovery_cfg_test_spans`) — a test-only declaration is
    not part of the shipped crate and must not be swept, mirroring
    `discover_declarations`'s identical exclusion for the E1 tiers.

    Genuinely UNPARSEABLE structure fails closed as an `UNPARSED` finding
    rather than being silently dropped (#480 review finding 1): an enum
    name matched but no `{` found anywhere after it, or a struct whose
    continuation after its name is none of `{`, `(`, or `;`.
    """
    src = strip_comments(raw)
    excluded = discovery_cfg_test_spans(raw)
    findings: list[Finding] = []

    for m in BRIDGE_PLAIN_ENUM_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        name = m.group(1)
        line_no = src.count("\n", 0, m.start()) + 1
        brace = src.find("{", m.end())
        if brace == -1:
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"enum {name}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=f"UNPARSED: could not locate a body for enum {name}",
                    rule="E2",
                )
            )
            continue
        body, _ = balanced_braces(src[brace:])
        if "#[error(" in body:
            continue  # thiserror-derived; already swept by scan_source's sweep 1
        findings.extend(
            _bridge_plain_enum_variant_findings(
                path_label, line_no, name, body, local_error_enums, aliases, foreign_names
            )
        )

    # POSITION-keyed, not name-keyed (#480 review round 2, NEW-1): a
    # bare-name check here is fail-open to a same-named sibling struct in a
    # different module AND to a self-authorised fake occurrence inside a
    # string literal — see `discover_error_struct_declarations`'s
    # docstring for both rustc-verified witnesses.
    already_swept_struct_spans = [
        (start, end) for _, start, end in discover_error_struct_declarations(raw)
    ]
    for m in BRIDGE_PLAIN_STRUCT_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        if _inside(m.start(), already_swept_struct_spans):
            continue  # thiserror-decorated; already swept by scan_source's sweep 1
        name = m.group(1)
        line_no = src.count("\n", 0, m.start()) + 1
        tail = src[m.end() :].lstrip()
        if tail.startswith("{"):
            body, _ = balanced_braces(tail)
        elif tail.startswith("("):
            body, _ = balanced_slice(tail, 0)
        elif tail.startswith(";"):
            continue  # unit struct — no fields, provably nothing to check
        else:
            findings.append(
                Finding(
                    path=path_label,
                    line=line_no,
                    source_line=f"struct {name}",
                    variant="<unparsed>",
                    field="<unparsed>",
                    field_type=(
                        f"UNPARSED: struct {name} has a body shape this guard "
                        "cannot model (expected `{...}`, `(...)`, or `;`)"
                    ),
                    rule="E2",
                )
            )
            continue
        findings.extend(
            _bridge_plain_struct_findings(
                path_label, line_no, name, body, local_error_enums, aliases, foreign_names
            )
        )
    return findings


# `pub(crate) fn name(` in `error/detail.rs` — the sanctioned detail
# constructors rule E3 accepts a call to. Private-to-the-crate by design: a
# `pub fn` would be callable from outside the bridge, and a bare `fn` is not
# reachable from the call sites this rule gates.
SANCTIONED_CTOR_RE = re.compile(r"pub\(crate\)\s+fn\s+([a-z_][a-z0-9_]*)")


def sanctioned_constructor_names(detail_src: str | None) -> frozenset[str]:
    """The set of `detail::<name>(...)` constructors rule E3 accepts a call
    to — every `pub(crate) fn` declared in `error/detail.rs` (#480).

    A MISSING file (or an empty/unreadable one) yields the EMPTY set, which
    denies every constructor call rather than accepting any: if the one file
    that defines what "sanctioned" means cannot be read, nothing is
    sanctioned. That is the whole rule's fail-closed hinge — the alternative
    (treat "no constructor list" as "no restriction") would silently disable
    E3 the moment someone moved or renamed the module.

    Read from the DISCOVERY VIEW (comments AND string CONTENTS blanked), not
    `strip_comments`. This registry GRANTS acceptance, so its fail-closed
    direction is to find FEWER names: a `pub(crate) fn evil(` written inside
    a string literal in `detail.rs` must not sanction `detail::evil(...)` at
    a call site, which is the same self-authorisation class
    `discovery_view`'s own docstring records for `#[error("...")]` messages.
    A lexer desync that HID a real constructor would instead cost a
    fail-closed E3 finding at each of its call sites.

    `#[cfg(test)]`-gated declarations are excluded, like every other
    discovery walk in this file. This one was missed on the first pass, and
    it is a GRANT: a `#[cfg(test)] pub(crate) fn evil_toplevel(...)` added to
    `detail.rs` registered as sanctioned and authorised `detail::evil_toplevel(..)`
    at SHIPPED call sites — verified by execution. A test-only declaration is
    not part of the shipped crate and must not vouch for shipped code, which
    is the same rule `discover_declarations` applies to its own three
    registries.
    """
    if not detail_src:
        return frozenset()
    view = discovery_view(detail_src)
    excluded = discovery_cfg_test_spans(detail_src)
    return frozenset(
        m.group(1)
        for m in SANCTIONED_CTOR_RE.finditer(view)
        if not _inside(m.start(), excluded)
    )


# A gated field name in INITIALIZER position: `<name>:` not followed by a
# second `:`. The negative lookahead excludes the MODULE PATH `detail::` (as
# in `detail::gated(...)`, which is a call, not a field), and `\b` excludes a
# gated name that is merely the TAIL of a longer field name — `record_uuid_hex:`
# must not match on `uuid_hex:`, since the DTO-carrying names are deliberately
# NOT members of `GATED_FIELD_NAMES` (see there).
GATED_INIT_RE = re.compile(
    r"\b(" + "|".join(sorted(GATED_FIELD_NAMES)) + r")\s*:(?!:)"
)
# A call whose path ENDS in `detail::<name>(`. The leading segments are
# unconstrained so both the in-module spelling (`detail::gated(`) and the
# fully-qualified one (`crate::error::detail::gated(`) match; what is pinned
# is that the immediately-enclosing module segment is literally `detail`, so
# a same-named local function (`gated(&e)`) does not pass.
DETAIL_CALL_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*detail\s*::\s*([a-z_][a-z0-9_]*)\s*\("
)


def string_literal_token_ends(raw: str) -> dict[int, int]:
    r"""Map the START offset of every complete STRING literal token in `raw`
    to the offset just past its closing delimiter.

    Built from `lex_spans`, which emits a terminated literal as exactly three
    contiguous spans — opening `KIND_DELIM`, `KIND_LITERAL` content, closing
    `KIND_DELIM`. Three properties are load-bearing for rule E3:

    - An UNTERMINATED literal emits no closing delimiter span, so it is
      absent from this map and every acceptance test against it fails
      closed.
    - A CHAR literal (`'x'`) has the same three-span shape, so the opening
      delimiter's text must END in `"` — that admits `"`, `r#"`, `b"`,
      `br##"` and rejects `'`.
    - The map is keyed on the literal's own start, so "the expression IS a
      single string literal" is decided by an EXACT offset match, not by a
      prefix test. If a lexer desync ever swallowed half a file into one
      "literal", the expression span would not coincide with that token's
      span and the acceptance would fail rather than widen.
    """
    ends: dict[int, int] = {}
    spans = lex_spans(raw)
    for i in range(len(spans) - 2):
        (s0, e0, k0) = spans[i]
        (s1, e1, k1) = spans[i + 1]
        (s2, e2, k2) = spans[i + 2]
        if (k0, k1, k2) != (KIND_DELIM, KIND_LITERAL, KIND_DELIM):
            continue
        if e0 != s1 or e1 != s2:
            continue
        if not raw[s0:e0].endswith('"'):
            continue
        ends[s0] = e2
    return ends


def initializer_end(view: str, start: int) -> int:
    """The offset at which the initializer expression beginning at `start`
    ends: the first `,` at top-level nesting, or the first `)`, `]` or `}`
    that CLOSES the construct the initializer sits in (i.e. appears at depth
    zero). `(`, `[` and `{` open a nesting level.

    `view` must be the DISCOVERY VIEW: with string contents blanked, a comma
    or brace inside a literal (`format!("a, b")`, `"}"`) cannot end the
    expression early. That choice is fail-closed in both directions — every
    view here only ever BLANKS, and blanking can neither introduce a `,` that
    truncates an expression nor remove one in a way that shortens it, so a
    lexer desync can only ever make the extracted expression LONGER, which
    makes it LESS likely to match one of the narrow accepted shapes.

    Closing delimiters at depth zero are genuine terminators, not a
    heuristic: they are the `)` of `fn f(detail: String)`, the `}` of
    `E::V { detail: x }`. Without them a function parameter's type would run
    on into the function BODY and every such parameter would produce a
    spurious finding.
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
        elif ch == "," and depth == 0:
            break
        i += 1
    return i


def initializer_is_gated(
    view: str,
    start: int,
    end: int,
    name: str,
    literal_ends: dict[int, int],
    sanctioned: frozenset[str],
) -> bool:
    """Rule E3's ACCEPT test for the (already whitespace-trimmed) expression
    `view[start:end]` assigned to gated field `name` (#480).

    FOUR shapes are accepted, and nothing else — this is a default-DENY
    predicate, so a construct this function does not recognise is a finding:

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
    3. The exact token `String` — a DECLARATION's type position (a struct
       field, an enum variant field, a function parameter), not a value.
       Rule E2 already decides whether a `String` DECLARATION under a gated
       name is acceptable; E3 is about construction, and a declaration is
       not a construction. `String::new()` is NOT this shape and denies,
       which is what keeps the acceptance from becoming "any expression
       starting with String".
    4. The exact same identifier as the field name — the `detail: detail`
       re-wrap. THIS ARM TRUSTS THE NAME, NOT THE VALUE'S PROVENANCE, and
       saying otherwise would be a false claim about a security control. An
       earlier version of this docstring asserted the value "is gated where
       it was built"; that is only true for the shape this arm exists to
       serve (re-wrapping a field of an already-gated error), and it is
       FALSE in general — verified by execution:

           fn f() -> E { let detail = format!("{}", leak());
                         E::V { detail: detail } }      // zero findings

       A local binding (or a function parameter) named `detail` launders any
       expression through this arm. The rule keeps the form because the
       approved plan mandates it and because the alternative — denying every
       re-wrap — would flag the legitimate sites and teach reviewers to wave
       E3 findings through. It is an explicit, named ACCEPT with a stated
       gap, recorded in the module docstring's LIMITS beside the other two.
       Field shorthand (`E::V { detail }`) has no `:` at all and never
       becomes a candidate in the first place — same gap, different door.

    Note what is NOT covered, and cannot be by a construction-site matcher:
    a field assigned AFTER construction (`x.detail = format!(...)`) is a
    write this rule never sees. That is a real blind spot, recorded in the
    module docstring's LIMITS.
    """
    if start >= end:
        return False
    stripped = view[start:end].strip()
    # (3) declaration type position, and (4) the same-name re-wrap.
    if stripped == "String" or stripped == name:
        return True
    # (1) a single string literal, optionally `.into()` / `.to_string()`.
    lit_end = literal_ends.get(start)
    if lit_end is not None and lit_end <= end:
        tail = "".join(view[lit_end:end].split())
        if tail in ("", ".into()", ".to_string()"):
            return True
    # (2) a sanctioned `detail::<name>(...)` call consuming the expression.
    cm = DETAIL_CALL_RE.match(view, start)
    if cm and cm.end() <= end and cm.group(1) in sanctioned:
        _, after = balanced_slice(view, cm.end() - 1)
        if after <= end and not view[after:end].strip():
            return True
    return False


def scan_bridge_construction_sites(
    path_label: str, raw: str, sanctioned: frozenset[str]
) -> list[Finding]:
    """Rule E3 (#480): every CONSTRUCTION SITE of a gated field must build
    its value from a sanctioned source.

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
    excluded = discovery_cfg_test_spans(raw)
    literal_ends = string_literal_token_ends(raw)
    findings: list[Finding] = []
    for m in GATED_INIT_RE.finditer(depth_view):
        if _inside(m.start(), excluded):
            continue
        name = m.group(1)
        start, end = m.end(), initializer_end(depth_view, m.end())
        while start < end and src[start] in " \t\r\n":
            start += 1
        while end > start and src[end - 1] in " \t\r\n":
            end -= 1
        if initializer_is_gated(src, start, end, name, literal_ends, sanctioned):
            continue
        expr = " ".join(src[start:end].split()) or "<empty>"
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, m.start()) + 1,
                source_line=" ".join(f"{name}: {expr}".split()),
                variant="<construction site>",
                field=name,
                field_type=expr,
                rule="E3",
            )
        )
    return findings


# Rule E4's anchor: the TRAIT NAME plus `for`, and nothing else.
#
# FOR A VIOLATION-FINDING REGEX, MATCHING LESS IS FAIL-OPEN. The first version
# of this rule spelled it `impl\s+GatedDetail\s+for\s+([A-Za-z0-9_:<>]+)` and
# called matching more text "the fail-closed direction" — the claim was right
# and the regex did the opposite of it. `impl\s+` REQUIRES whitespace after
# `impl`, so `impl<T: Display> GatedDetail for T {}` — a one-line blanket impl
# that hands the trait to EVERY `Display` type and collapses the premise both
# E3 and E4 rest on — never matched, in `detail.rs` or anywhere else. Neither
# did `impl crate::error::detail::GatedDetail for X {}`, and the target class
# excluded `&`, `(`, `[` and `'`, so `impl<'a> GatedDetail for &'a str {}` and
# `impl GatedDetail for &Plain {}` were invisible too. All six shapes were
# rustc-compiled and confirmed to produce ZERO findings, with E3 then happily
# accepting `detail: detail::gated(&Wrap(decrypted_key))`.
#
# Anchoring on `GatedDetail for` alone removes every one of those degrees of
# freedom: whatever precedes the trait name (generic parameters, a qualified
# trait path, line breaks) cannot hide the anchor, because the anchor does not
# look at it. The `impl` header is then recovered BACKWARDS, and failing to
# recover it is an `UNPARSED` finding rather than a skip.
IMPL_GATED_ANCHOR_RE = re.compile(r"\bGatedDetail\s+for\b")
IMPL_KW_RE = re.compile(r"\bimpl\b")
# How far back to look for the `impl` keyword introducing an anchor. Generic
# parameter lists in this codebase are a few dozen characters; 512 is slack.
# Coming up empty is a FINDING (`UNPARSED`), not a skip, so the bound cannot
# hide an impl — only mislabel one.
IMPL_HEADER_WINDOW = 512
# A plain type PATH: `::`-separated plain identifiers, nothing else. Rule E4
# accepts no other target shape. A reference (`&Plain`), a lifetime-bearing
# type (`&'a str`), a tuple, an array, `dyn Trait`, a generic application
# (`Wrap<T>`) and `()` all fail this and DENY, because each is a claim about
# something other than one named type this guard can look up.
PLAIN_TYPE_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
# The path roots that name a crate THIS GUARD SCANS. `crate` / `self` /
# `super` resolve inside `secretary-ffi-bridge` itself (BRIDGE_SCAN_ROOT),
# `secretary_core` is SCAN_ROOT's crate, and `secretary_ffi_bridge` is the
# bridge spelled by its own crate name. Anything else — `std`, `secretary_cli`,
# any third-party crate — names a type no registry here has scanned.
SCANNED_IMPL_ROOTS: frozenset[str] = frozenset(
    {"crate", "self", "super", "secretary_core", "secretary_ffi_bridge"}
)
# Short, stable REASON CODES prefixing each of rule E4's six denial arms.
# Their purpose is mutation-verifiability, not display: the arms OVERLAP —
# a bare target also fails the root check, a blanket `impl<T> ... for T` also
# has a bare target, an impl outside detail.rs would also fail several of the
# in-file checks — so a control asserting only "a finding fired" cannot tell
# an arm's removal from its presence. Controls assert `field_type_prefix`
# against these codes, which makes each arm independently mutatable; three
# mutation checks came back GREEN before they existed.
E4_OUTSIDE = "outside-detail-module: "
E4_GENERIC = "generic-impl: "
E4_NONPATH = "non-path-target: "
E4_BARE = "bare-target: "
E4_ROOT = "foreign-crate-root: "
E4_UNSCANNED = "unscanned-type: "


def is_detail_module(path_label: str) -> bool:
    """Whether `path_label` names the one file permitted to declare an
    `impl GatedDetail` (`DETAIL_MODULE_REL`). Separator-normalized so a
    Windows-spelled `path_label` compares equal."""
    return path_label.replace("\\", "/") == DETAIL_MODULE_REL


def impl_header_before(src: str, anchor_start: int) -> tuple[int, str] | None:
    """`(impl_keyword_start, text between `impl` and the anchor)` for the
    nearest `impl` keyword preceding a `GatedDetail for` anchor, or `None`.

    The between-text is what tells a GENERIC impl from a plain one: it holds
    the generic parameter list (`<T: Display>`) and/or a qualified trait path
    prefix (`crate::error::detail::`). Searching BACKWARDS from the anchor —
    rather than matching the header forwards — is the whole point: a forward
    match has to model everything that may sit between `impl` and the trait
    name, and every one of those things was a bypass (see
    `IMPL_GATED_ANCHOR_RE`).
    """
    matches = list(
        IMPL_KW_RE.finditer(src, max(0, anchor_start - IMPL_HEADER_WINDOW), anchor_start)
    )
    if not matches:
        return None
    m = matches[-1]
    return m.start(), src[m.end() : anchor_start]


def impl_target_text(src: str, start: int) -> tuple[str, int]:
    """`(whitespace-collapsed self type, end offset)` for the impl target
    beginning at `start` (just past a `GatedDetail for` anchor).

    Ends at the first `{` or `;` outside `()`/`<>`/`[]` nesting, or at a
    `where` clause, whichever comes first. Nesting is tracked so
    `Wrap<Vec<u8>>` and `(u8, u8)` come out whole — this function does not
    judge the shape, it only delimits it; `PLAIN_TYPE_PATH_RE` judges.
    """
    depth = 0
    i, n = start, len(src)
    while i < n:
        ch = src[i]
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            if depth > 0:
                depth -= 1
        elif depth == 0 and ch in "{;":
            break
        i += 1
    text = src[start:i]
    wm = re.search(r"\bwhere\b", text)
    if wm:
        i = start + wm.start()
        text = text[: wm.start()]
    return " ".join(text.split()), i


def scan_bridge_gated_detail_impls(
    path_label: str, raw: str, scanned_error_type_names: frozenset[str]
) -> list[Finding]:
    """Rule E4 (#480): `impl GatedDetail for X` is a SECURITY DECISION — a
    claim that `X`'s `Display` output carries no vault plaintext, password,
    mnemonic or key bytes — so every one of them must sit in the single
    reviewed file `error/detail.rs`, and each must name a type whose payloads
    something has actually checked.

    This is the Rust analogue of iOS's `SecretFreeError` conformance and
    Android's `SecretFreeThrowable` declaration (#467/#472), with one
    difference the two platforms could not have: because the trait is
    `pub(crate)` and its constructors take `&impl GatedDetail`, the set of
    types a detail string can be built from is exactly the set of impls —
    so PINNING THE IMPLS TO ONE FILE pins the whole allowlist to one review.

    SIX checks, in order — each with its own reason code so a control can
    pin WHICH one fired (they overlap heavily; see the reason-code comment):

    1. Any impl in a file OTHER than `DETAIL_MODULE_REL` is a finding. There
       is no allowlist story for this arm — move the impl.
    2. A GENERIC impl (`impl<...>`) is a finding. Generic parameters are how
       a claim gets made about types the author has not enumerated, and
       enumerability is the entire premise: `impl<T: Display> GatedDetail
       for T {}` would hand the trait to every `Display` type in one line.
       This arm has no allowlist story either.
    3. A target that is not a plain `::`-separated type path is a finding
       (`&Plain`, `&'a str`, `(u8, u8)`, `[u8; 4]`, `dyn Foo`, `Wrap<T>`,
       `()`): each is a claim about something other than one named type this
       guard can look up.
    4. A BARE (single-segment) target is a finding: a bare name states no
       crate, so it cannot be told apart from a `use`-imported foreign type
       of the same name — write the path.
    5. The path must be ROOTED IN A SCANNED CRATE (`SCANNED_IMPL_ROOTS`).
    6. Its LAST SEGMENT must be a type this guard itself scans
       (`scanned_error_type_names`) — the same "safe by recursion" argument
       tier 2 of `is_data_free` makes for a field referencing a local error
       enum: this guard already fails at that type's own definition if one
       of its payloads is not data-free.

    Arms 5 and 6 are allowlistable after human review (`std::io::Error`'s
    path + errno is already-disclosed under the threat model, and so on).

    THE ROOT CHECK IS LOAD-BEARING AND IS NOT REDUNDANT WITH THE REGISTRY
    CHECK. `scanned_error_type_names` holds BARE names, and `core/src/error.rs`
    declares a `thiserror` enum literally called `Error` — so a last-segment-
    only test accepts `impl GatedDetail for std::io::Error {}`, crediting a
    FOREIGN type for a same-named local one. That is the exact collision
    `foreign_use_names` exists to withdraw for field references, arriving
    here by a different door; it is live in the tree today, and `BP20` pins
    it.

    LIMIT, same class as E1's: this reads TEXT, not expanded macros. An
    `impl GatedDetail for ...` produced by a `macro_rules!` expansion is
    invisible here, exactly as a macro-generated `#[error(...)]` is invisible
    to `scan_source` — the module docstring's LIMITS records the general
    form. "Any impl outside detail.rs is a finding" is therefore a claim
    about impls this guard can SEE, and the honest scope of arm 1.
    """
    src = strip_comments(raw)
    in_detail = is_detail_module(path_label)
    findings: list[Finding] = []
    for m in IMPL_GATED_ANCHOR_RE.finditer(src):
        header = impl_header_before(src, m.start())
        target, target_end = impl_target_text(src, m.end())
        if header is None:
            # A `GatedDetail for` anchor with no `impl` keyword in front of
            # it is a construct this guard does not model. Fail closed on
            # STRUCTURE, exactly as `scan_source` does for an attribute whose
            # variant it cannot locate.
            findings.append(
                Finding(
                    path=path_label,
                    line=src.count("\n", 0, m.start()) + 1,
                    source_line=" ".join(src[m.start() : target_end].split()),
                    variant="<impl GatedDetail>",
                    field=target or "<unparsed>",
                    field_type=(
                        "UNPARSED: found a `GatedDetail for` anchor with no "
                        "`impl` keyword in front of it — this guard cannot "
                        "tell what declares it"
                    ),
                    rule="E4",
                )
            )
            continue
        impl_start, between = header
        has_generics = between.lstrip().startswith("<")
        segments = [seg for seg in target.split("::") if seg]
        reason: str | None = None
        if not in_detail:
            reason = (
                f"{E4_OUTSIDE}declared outside {DETAIL_MODULE_REL} — every "
                "impl of this trait is a secret-freedom claim and must sit "
                "in that one reviewed file"
            )
        elif has_generics:
            reason = (
                f"{E4_GENERIC}the impl declares generic parameters, so it "
                "claims secret-freedom for a FAMILY of types rather than one "
                "named type — the set of impls would stop being enumerable, "
                "which is the premise rules E3 and E4 rest on"
            )
        elif not PLAIN_TYPE_PATH_RE.match(target):
            reason = (
                f"{E4_NONPATH}target `{target or '<empty>'}` is not a plain "
                "type path (reference, lifetime, tuple, array, `dyn`, "
                "generic application or unit), so there is no single named "
                "type to look up"
            )
        elif len(segments) < 2:
            reason = (
                f"{E4_BARE}target is a BARE name, which states no crate and "
                "so cannot be distinguished from a use-imported foreign type "
                "of the same name — write the full path"
            )
        elif segments[0] not in SCANNED_IMPL_ROOTS:
            reason = (
                f"{E4_ROOT}target is rooted at `{segments[0]}`, a crate this "
                "guard does not scan, so its payloads are not checked "
                "anywhere — allowlist after review"
            )
        elif segments[-1] not in scanned_error_type_names:
            reason = (
                f"{E4_UNSCANNED}target's last path segment `{segments[-1]}` "
                "is not an error type this guard scans, so the "
                "safe-by-recursion argument does not cover it — allowlist "
                "after review"
            )
        if reason is None:
            continue
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, impl_start) + 1,
                source_line=" ".join(src[impl_start:target_end].split()),
                variant="<impl GatedDetail>",
                field=target,
                field_type=reason,
                rule="E4",
            )
        )
    return findings


def discover_error_struct_declarations(raw: str) -> list[tuple[str, int, int]]:
    """`[(name, attr_start, decl_end)]` for every `#[error("...")]`-
    decorated STRUCT (thiserror's other error shape — the attribute
    decorates the struct declaration ITSELF, not a variant inside a body)
    in `raw`. `attr_start`/`decl_end` are character offsets spanning from
    the `#[error(` attribute through the END OF THE STRUCT'S NAME.

    `discover_declarations`'s `local_error_enums` tier does not see these —
    it only walks `ENUM_RE` bodies. This is a second, narrow pass reusing
    the exact `#[error(` + `STRUCT_RE` recognition `scan_source` itself
    performs. `discovery_cfg_test_spans` excludes a match starting inside a
    `#[cfg(test)]`-gated item — a test-only thiserror struct must not vouch
    for a SHIPPED plain struct sharing its name.

    RUNS OVER THE DISCOVERY VIEW (comments AND string contents blanked).
    ONE walk feeds TWO consumers with DIFFERENT keying needs (#480 review
    round 2, NEW-1), and the two need different things from the view:

    - `scan_bridge_plain_declarations`'s "already swept" struct check wants
      POSITIONS. A bare-name registry there was proven fail-open by two
      rustc-verified witnesses: (a) two DIFFERENT structs sharing a bare
      name in different modules — `mod a`'s real thiserror `DupError`
      incorrectly vouched for `mod b`'s real, DIFFERENT, plain `DupError`,
      letting its `leak: String` field escape; (b) self-authorisation — an
      `#[error("x")] pub struct LeakError {}` written INSIDE a raw-string
      `const`'s VALUE. Positions alone close BOTH, so this consumer does
      not depend on which view discovers the declaration.
    - `scanned_error_type_names` (rule E4, via `discover_error_struct_names`
      below) wants bare NAMES, and a name registry IS spoofable by witness
      (b): the fake declaration's NAME is indistinguishable from a real
      one's once the position is discarded, so an author could authorise
      `impl GatedDetail for crate::x::LeakError` from inside a string
      literal. Task 2 flagged this as an inert residual because E4 had no
      consumer yet; E4 now has one, so the walk moved to `discovery_view`,
      where a declaration written inside a literal simply is not there.
      `BP19` pins it.

    Blanking string contents can only ever REMOVE a declaration from this
    registry, and both consumers fail closed on a missing entry: the sweep
    consumer double-reports a struct (noise), and E4 denies an impl
    (finding). There is no direction in which the narrower view grants
    anything.

    One walk means both consumers see the identical set of REAL
    declarations, rather than two independently-maintained (and
    independently-buggable) scans of the same shape — the #475 lesson
    this file's own docstring already cites for `is_comment_line`.

    The span ENDS AT THE STRUCT NAME, not at end-of-line: two declarations
    written on ONE line (`#[error("x")] pub struct AError { .. } pub struct
    BError { .. }`) would otherwise put the SECOND one inside the FIRST's
    "already swept" span, silently exempting it from the sweep. `BP22`
    pins it.
    """
    src = discovery_view(raw)
    excluded = discovery_cfg_test_spans(raw)
    out: list[tuple[str, int, int]] = []
    for m in ERROR_ATTR_RE.finditer(src):
        if _inside(m.start(), excluded):
            continue
        _, after = balanced_slice(src, m.end() - 1)
        tail_raw = src[after:]
        if tail_raw.lstrip().startswith("]"):
            close_off = tail_raw.find("]") + 1
            tail = tail_raw[close_off:]
            tail_start = after + close_off
        else:
            tail = tail_raw
            tail_start = after
        skipped = skip_attributes(tail)
        skipped_start = tail_start + (len(tail) - len(skipped))
        line_start = 0
        for line in skipped.splitlines(keepends=True):
            if line.strip():
                sm = STRUCT_RE.match(line)
                if sm:
                    line_abs_start = skipped_start + line_start
                    out.append((sm.group(1), m.start(), line_abs_start + sm.end()))
                break
            line_start += len(line)
    return out


def discover_error_struct_names(raw: str) -> frozenset[str]:
    """Bare names of every `#[error("...")]`-decorated STRUCT in `raw` —
    feeds `scanned_error_type_names` (rule E4's registry — see
    `discover_scanned_error_type_names`) alongside the bare spellings of
    `local_error_enums`. See `discover_error_struct_declarations`, this
    function's shared producer, for the position-vs-name keying rationale
    and for why that producer moved to the DISCOVERY VIEW once this
    NAME-only projection acquired a security-relevant consumer.
    """
    return frozenset(name for name, _, _ in discover_error_struct_declarations(raw))


def balanced_braces(src: str) -> tuple[str, int]:
    """Return the `{...}`-balanced text starting at `src[0] == '{'`."""
    depth, i, in_string = 0, 0, False
    while i < len(src):
        ch = src[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[: i + 1], i + 1
        i += 1
    return src, len(src)


def load_allowlist(path: Path) -> set[str]:
    """Parse the allowlist into a set of `path\\trule\\tnormalized attribute
    text` keys.

    Format, one per line, TAB-separated — IDENTICAL to the two shell guards'
    allowlists so that `scripts/lib/hygiene-allowlist.sh::allowlisted` can parse
    this same file:

        <repo-relative-path><TAB><rule><TAB><normalized #[error(...)] text><TAB><reason>

    The third column is the ENTIRE `#[error(...)]` attribute — not just its
    first source line — whitespace-collapsed to one line (`scan_source`'s
    `key_text`). Keying on just the first line would give a multi-line
    attribute (`sync/error.rs:9`) the literal key `#[error(`, which is not
    unique: any other multi-line attribute in the same file collides on it,
    so one reviewed entry would silently also exempt an unreviewed one. That
    is the exact "substring exempts everything" failure the exact-match
    convention exists to prevent, one level up. Matching is on the EXACT
    normalized text, never a substring, for the same reason #467/#475
    established it for the shell guards.
    """
    entries: set[str] = set()
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        entries.add(f"{parts[0].strip()}\t{parts[1].strip()}\t{parts[2].strip()}")
    return entries


def _discover_tier_inputs(
    sources: list[tuple[str, str]],
) -> tuple[frozenset[str], dict[str, str], frozenset[str]]:
    """`run_real_scan`'s Pass 1, factored out so it can run ONCE PER SCAN
    ROOT (#480): discover every thiserror enum, type alias, and const across
    THE WHOLE `sources` list before classifying anything — a field in
    vault/mod.rs can reference an enum defined in vault/record.rs, and a
    format string in vault/block.rs can capture a const imported from
    crypto/kem.rs, so a per-file-only discovery pass would miss the
    cross-file case entirely.

    Aliases are aggregated defensively: a bare (or qualified) spelling that
    resolves to DIFFERENT right-hand sides in different files is a name
    COLLISION, not one alias, and a plain last-write-wins dict.update merge
    means an unrelated, later-sorted file adding e.g. `type Foo = [u8; 16];`
    can silently launder an EXISTING, unsafe `type Foo = String;` defined
    elsewhere into a pass — proven live in review. A colliding spelling is
    dropped from the resolvable set entirely, so a lookup against it
    default-denies instead of guessing which definition was "real."

    `const` names get the SAME collision-drop, applied by `resolve_consts`
    over the flat cross-file declaration list: a bare spelling this guard
    saw declared more than once, or saw disqualified by a `static` /
    excluded-scope declaration anywhere, is not credited. An earlier round
    unioned them instead, on the argument that "a const's safety comes from
    the compiler, not its value." The premise is true; the conclusion does
    not follow, because the guard's operative claim is not "consts are
    safe" but "this placeholder RESOLVES TO a const" — a name-resolution
    claim a bare-name union does not establish. `static` is the concrete
    counter-witness (`find_const_shadows`), and it was reproduced
    end-to-end: a `static LEAKY_NAME: LazyLock<String>` capture that
    correctly denied on its own went silent the moment an unrelated,
    later-sorted file added `pub const LEAKY_NAME: usize = 16;`.

    `local_error_enums` still does NOT get the treatment, for the reason
    the LIMITS block records: it is a pure membership set, and any enum
    registered in it is by construction a real thiserror enum this guard
    scans, so two same-named local enums are both soundly "safe by
    recursion." Its bare-name risk is a FOREIGN collision, and that is
    handled per-file by `foreign_use_names` in Pass 2.

    CALLED ONCE PER ROOT (core, bridge) — never merged: a bridge-local alias
    or const must not vouch for a core field, or vice versa. Core's own
    call site passes exactly the same `sources` list it always has, so core
    findings stay byte-identical to before this function existed.
    """
    local_error_enum_names: set[str] = set()
    alias_candidates: dict[str, set[str]] = {}
    declared_consts: list[str] = []
    const_shadow_names: set[str] = set()
    for label, raw in sources:
        enums, file_aliases, file_consts, file_shadows = discover_declarations(
            raw, label
        )
        local_error_enum_names.update(enums)
        for spelling, rhs in file_aliases.items():
            alias_candidates.setdefault(spelling, set()).add(rhs)
        declared_consts.extend(file_consts)
        const_shadow_names.update(file_shadows)
    local_error_enums: frozenset[str] = frozenset(local_error_enum_names)
    aliases = {
        spelling: next(iter(rhs_set))
        for spelling, rhs_set in alias_candidates.items()
        if len(rhs_set) == 1
    }
    consts = resolve_consts(declared_consts, frozenset(const_shadow_names))
    return local_error_enums, aliases, consts


def discover_scanned_error_type_names(
    core_sources: list[tuple[str, str]],
    bridge_sources: list[tuple[str, str]],
    core_enums: frozenset[str],
    bridge_enums: frozenset[str],
) -> frozenset[str]:
    """Every `#[error]`-bearing ENUM or STRUCT name this guard scans, under
    EITHER root (#480) — the registry rule E4 uses to verify
    that an `impl GatedDetail for X` in `error/detail.rs` names a type this
    guard itself independently checks (X's last path segment must be a
    member): the same "safe by recursion" argument tier 2 of `is_data_free`
    already makes for a FIELD reference to a local error enum.

    ENUM names come from `core_enums` / `bridge_enums` — already computed by
    `_discover_tier_inputs` (`discover_declarations`'s `local_error_enums`
    tier) — filtered down to BARE spellings only: a qualified spelling like
    `crate::vault::VaultError` names the SAME type as `VaultError`, and this
    registry is meant to be checked against a bare LAST PATH SEGMENT, so the
    qualified duplicates add nothing. STRUCT names are NOT part of that
    tier at all (`discover_declarations` only walks `ENUM_RE` bodies) and
    come from `discover_error_struct_names` instead, run over every file
    under both roots.

    Consumed by rule E4 only (`scan_bridge_gated_detail_impls`), never by
    E1/E2/E3 — an impl's target is a TYPE, not a field, so none of the
    field-classification tiers ever look here.
    """
    names = {n for n in core_enums if "::" not in n}
    names |= {n for n in bridge_enums if "::" not in n}
    for _, raw in core_sources:
        names |= discover_error_struct_names(raw)
    for _, raw in bridge_sources:
        names |= discover_error_struct_names(raw)
    return frozenset(names)


def run_real_scan() -> int:
    allowlist = load_allowlist(ALLOWLIST_PATH)
    core_sources = [
        (str(rs.relative_to(REPO_ROOT)), rs.read_text(encoding="utf-8"))
        for rs in sorted(SCAN_ROOT.rglob("*.rs"))
    ]
    bridge_sources = [
        (str(rs.relative_to(REPO_ROOT)), rs.read_text(encoding="utf-8"))
        for rs in sorted(BRIDGE_SCAN_ROOT.rglob("*.rs"))
    ]

    # Pass 1, once per root — core's tier inputs come from ONLY core
    # sources, bridge's from ONLY bridge sources; see `_discover_tier_inputs`.
    core_enums, core_aliases, core_consts = _discover_tier_inputs(core_sources)
    bridge_enums, bridge_aliases, bridge_consts = _discover_tier_inputs(bridge_sources)

    # Rule E4's registry (#480): every `#[error]`-bearing enum/struct name
    # this guard scans under EITHER root. Cross-root on purpose — the impls
    # in `error/detail.rs` name core types (`secretary_core::vault::VaultError`)
    # far more often than bridge-local ones.
    scanned_error_type_names = discover_scanned_error_type_names(
        core_sources, bridge_sources, core_enums, bridge_enums
    )

    # Rule E3's sanctioned-constructor set, read from the ONE detail module.
    # If that file is missing from the scanned sources the set is EMPTY and
    # every `detail::*` call denies — see `sanctioned_constructor_names`.
    detail_src = next(
        (raw for label, raw in bridge_sources if is_detail_module(label)), None
    )
    sanctioned = sanctioned_constructor_names(detail_src)

    # Pass 2: the actual scan, now with tiers 2, 3, and 4 available — each
    # file's own foreign `use` bindings withdrawing the bare-name credits
    # that file's namespace contradicts. Core files scan EXACTLY as before
    # this function grew a bridge half: same sources, same discovery inputs,
    # same `scan_source` call (`bridge_mode` defaults False).
    violations: list[Finding] = []
    for label, raw in core_sources:
        foreign = foreign_use_names(raw)
        for f in scan_source(label, raw, core_enums, core_aliases, core_consts, foreign):
            if f"{f.path}\t{f.rule}\t{f.source_line}" in allowlist:
                continue
            violations.append(f)

    # Bridge files: rule E1's interpolated-field scan runs in `bridge_mode`
    # (the carve-out — item 1), PLUS rule E2's two structural sweeps (items
    # 2 and 3) — `scan_source` itself (sweep 1, thiserror-derived
    # declarations) and `scan_bridge_plain_declarations` (sweep 2, plain-derive
    # `*Error`/`*Warning` enums with no `#[error(...)]` attribute at all) —
    # PLUS rule E3 (the construction sites E2's gated-name carve-out defers
    # to) and rule E4 (the `impl GatedDetail` allowlist itself).
    for label, raw in bridge_sources:
        foreign = foreign_use_names(raw)
        findings = scan_source(
            label,
            raw,
            bridge_enums,
            bridge_aliases,
            bridge_consts,
            foreign,
            bridge_mode=True,
        )
        findings += scan_bridge_plain_declarations(
            label, raw, bridge_enums, bridge_aliases, foreign
        )
        findings += scan_bridge_construction_sites(label, raw, sanctioned)
        findings += scan_bridge_gated_detail_impls(
            label, raw, scanned_error_type_names
        )
        for f in findings:
            if f"{f.path}\t{f.rule}\t{f.source_line}" in allowlist:
                continue
            violations.append(f)

    if violations:
        print("error-payload hygiene: FAIL\n", file=sys.stderr)
        for v in violations:
            if v.field_type.startswith("UNPARSED:"):
                detail = f"{v.field_type} (variant hint: {v.variant}, field hint: {v.field})"
            elif v.rule == "E2":
                # Rule E2 findings come from the STRUCTURAL sweep
                # (`bridge_declaration_findings`) — the field need not be
                # interpolated into any message at all (uniffi/PyO3 project
                # every field regardless of `Display`), so "interpolates"
                # would misdescribe it.
                detail = f"variant {v.variant} declares `{v.field}: {v.field_type}` (not gated)"
            elif v.rule == "E3":
                detail = (
                    f"gated field `{v.field}` is built from an unsanctioned "
                    f"expression: {v.field_type}"
                )
            elif v.rule == "E4":
                detail = f"impl GatedDetail for `{v.field}`: {v.field_type}"
            else:
                detail = f"variant {v.variant} interpolates `{v.field}: {v.field_type}`"
            print(
                f"  {v.path}:{v.line}\n"
                f"    {detail}\n"
                f"    {v.source_line}",
                file=sys.stderr,
            )
        print(
            f"\n{len(violations)} violation(s). A `core` or bridge error "
            "payload must not carry an ungated runtime String — it reaches "
            "both platform UIs and their logs (#474/#480). Carry a "
            "&'static str hint plus an ordinal (E1/E2), build the value "
            "through a `detail::*` constructor (E3), move the impl into "
            f"{DETAIL_MODULE_REL} (E4), or record a reviewed exception in"
            "\n  "
            f"{ALLOWLIST_PATH.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1
    print("error-payload hygiene: OK")
    return 0


# `(label, source)` or `(label, source, expectation)`. The optional third
# element is a `ControlExpectation` (below) asserting WHICH finding the
# control must produce — see its comment for why "something fired" is not a
# strong enough assertion for a control that pins a parser fix.
POSITIVE_CONTROLS: list[tuple] = [
    (
        "P1 struct variant with a String payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate map key: {key}")]
            DuplicateKey { key: String },
        }
        ''',
    ),
    (
        "P2 tuple variant with a String payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR decode error: {0}")]
            CborDecode(String),
        }
        ''',
    ),
    (
        "P3 Vec<u8> payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("bad bytes: {raw:?}")]
            BadBytes { raw: Vec<u8> },
        }
        ''',
    ),
    (
        "P4 unrecognised type denies by default",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("wrapped: {inner}")]
            Wrapped { inner: SomeFutureType },
        }
        ''',
    ),
    (
        "P5 trailing format argument referencing a field that is NOT "
        "positionally first (the mnemonic.rs shape) — proves ARG_FIELD_RE "
        "is load-bearing, not just positional-index luck",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("word #{} is unknown", .word)]
            UnknownWord { index: usize, word: String },
        }
        ''',
    ),
    (
        "P6 multi-line attribute",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(
                "a long message that wraps: {detail}"
            )]
            Wrapped { detail: String },
        }
        ''',
    ),
    (
        "P7 PathBuf payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("no such folder: {path}")]
            Missing { path: PathBuf },
        }
        ''',
    ),
    (
        "P8 third-party nested error must still deny (proves the recursion "
        "tier isn't over-relaxed — std::io::Error is not scanned by this "
        "guard, so it gets no credit from being a nested #[from] error)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io failure: {0}")]
            Io(#[from] std::io::Error),
        }
        ''',
        # Not merely "something fired": the finding must be the TYPE verdict
        # on the io field. An UNPARSED here would mean the guard lost track
        # of the structure and passed the control for the wrong reason.
        {"field": "0", "field_type": "#[from] std::io::Error"},
    ),
    (
        "P9 alias to String is not data-free (aliasing doesn't launder a "
        "runtime string into something the guard trusts)",
        '''
        type DetailText = String;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {detail}")]
            Leaky { detail: DetailText },
        }
        ''',
    ),
    (
        "P10 struct-shaped thiserror error (not an enum variant) is scanned",
        '''
        #[derive(thiserror::Error, Debug)]
        #[error("leak: {detail}")]
        pub struct E {
            detail: String,
        }
        ''',
    ),
    (
        "P11 a real placeholder immediately after an escaped brace "
        "({{{name}}}) must still resolve — the triple-brace shape a "
        "lookbehind-based matcher misses",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("{{{secret}}}")]
            Wrapped { secret: String },
        }
        ''',
    ),
    (
        "P12 #[source] on a STRUCT-variant field — the live vault/mod.rs "
        "and sync/error.rs shape; the attribute lands on the NAME side, "
        "not the type side",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io error ({context}): {source}")]
            Wrapped {
                context: &'static str,
                #[source]
                source: std::io::Error,
            },
        }
        ''',
        # THE control for `strip_field_attrs`, so it must assert on the
        # RESULT, not on non-emptiness. Reverting that fix (dropping back to
        # a bare `.strip()` on the name side) leaves the field named
        # `#[source] source`, `{source}` matches nothing, and the attribute
        # falls through to UNPARSED — which is still a finding, so a
        # non-emptiness assertion stayed green and the control stopped
        # pinning its own mechanism. Naming the field and type here is what
        # makes reverting the fix break THIS control.
        {"variant": "Wrapped", "field": "source", "field_type": "std::io::Error"},
    ),
    (
        "P13 #[error(transparent)] over a third-party source must still "
        "deny — the live sync/error.rs:24 shape, with a non-core source",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(transparent)]
            Wrapped(#[from] std::io::Error),
        }
        ''',
        {"variant": "Wrapped", "field": "0", "field_type": "#[from] std::io::Error"},
    ),
    (
        "P14 an intervening #[allow(...)] attribute between #[error] and "
        "the variant must not hide it",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {detail}")]
            #[allow(dead_code)]
            Leaky { detail: String },
        }
        ''',
        # THE control for `skip_attributes`, so — exactly as with P12 — it
        # asserts on the verdict. Reverting that fix (making
        # `skip_attributes` the identity) leaves the guard unable to locate
        # the variant at all, which now emits UNPARSED rather than silently
        # passing; a non-emptiness assertion could not tell the two apart.
        {"variant": "Leaky", "field": "detail", "field_type": "String"},
    ),
    (
        "P15 an unrecognisable construct after #[error(...)] must fail "
        "closed as UNPARSED, not silently pass",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {detail}")]
            !!!not_a_valid_variant_shape!!!
        }
        ''',
    ),
    (
        "P16 a placeholder that matches no parsed field name must fail "
        "closed as UNPARSED, not silently pass",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {nonexistent}")]
            Leaky { detail: String },
        }
        ''',
    ),
    (
        "P17 a positional placeholder with no corresponding declared field "
        "must fail closed as UNPARSED, not silently pass",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak #{}")]
            Empty,
        }
        ''',
    ),
    (
        "P18 a placeholder naming something that is neither a parsed field "
        "NOR a discovered const must still fail closed as UNPARSED — proves "
        "the const tier is an ADDITIONAL recognised-safe category, not a "
        "fallback that accepts any unknown name (a real const is present "
        "in this same snippet, so discovery genuinely ran)",
        '''
        pub const KNOWN_CONST: usize = 16;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {totally_unknown_name}")]
            Leaky { detail: String },
        }
        ''',
    ),
    (
        "P19 a placeholder naming a `static`, not a `const`, must still "
        "fail closed as UNPARSED — a static (even immutable) does not "
        "carry the same compile-time-evaluated guarantee",
        '''
        pub static NOT_A_CONST: usize = 16;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("leak: {NOT_A_CONST}")]
            Leaky { detail: String },
        }
        ''',
        {"unparsed": True, "field": "NOT_A_CONST"},
    ),
    # P20-P22 are deliberately STRUCT-shaped errors at module scope, not
    # enum variants. In an enum, the injected text lands inside the enum's
    # own braces, which `non_module_block_spans` already excludes — so an
    # enum-shaped control fires whether or not string blanking works, and
    # pins nothing. Mutating `discovery_view` back to `strip_comments`
    # (no blanking) must break exactly these three.
    (
        "P20 a `const` declaration written INSIDE the #[error] message text "
        "must not self-authorise its own placeholder — declaration "
        "discovery runs over a view with string literals blanked",
        '''
        #[derive(thiserror::Error, Debug)]
        #[error("leaked field name: {SELF_AUTH} const SELF_AUTH: usize = 1;")]
        pub struct SelfAuthorised;
        ''',
        {"unparsed": True, "field": "SELF_AUTH"},
    ),
    (
        "P21 a `type` alias written INSIDE the #[error] message text must "
        "not launder the field it names (same root cause as P20, tier 3)",
        '''
        #[derive(thiserror::Error, Debug)]
        #[error("x type ZzFakeAlias = usize; leak {detail}")]
        pub struct AliasInjected {
            detail: ZzFakeAlias,
        }
        ''',
        {"variant": "AliasInjected", "field": "detail", "field_type": "ZzFakeAlias"},
    ),
    (
        "P22 a thiserror-shaped `enum` written INSIDE the #[error] message "
        "text must not earn the recursion tier (same root cause as P20, "
        "tier 2)",
        '''
        #[derive(thiserror::Error, Debug)]
        #[error("x enum ZzFakeEnum { #[error(\\"y\\")] Aaa, } leak {0}")]
        pub struct EnumInjected(ZzFakeEnum);
        ''',
        {"variant": "EnumInjected", "field": "0", "field_type": "ZzFakeEnum"},
    ),
    (
        "P23 a `static` of the same name DISQUALIFIES a const spelling — the "
        "cross-module shape that made a real `static LazyLock<String>` "
        "capture go silent once an unrelated const of that name existed",
        '''
        mod a {
            pub static LEAKY_NAME: LazyLock<String> =
                LazyLock::new(|| std::env::var("SECRET_FIELD").unwrap_or_default());
        }

        mod b {
            pub const LEAKY_NAME: usize = 16;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate key: {LEAKY_NAME}")]
            LeakViaStatic,
        }
        ''',
        {"unparsed": True, "field": "LEAKY_NAME"},
    ),
    (
        "P24 two module-scope consts of the same bare name are a COLLISION, "
        "not a resolution — the spelling is dropped, same discipline as a "
        "colliding type alias",
        '''
        mod a {
            pub const DUP_LEN: usize = 16;
        }

        mod b {
            pub const DUP_LEN: usize = 32;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {DUP_LEN} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "DUP_LEN"},
    ),
    (
        "P25 a #[cfg(test)] const does not vouch for a shipped message — "
        "six of the tree's 134 harvested const names came from test "
        "modules, one literally named SECRET_FIELD_NAME",
        '''
        #[cfg(test)]
        mod tests {
            pub const SECRET_FIELD_NAME: usize = 16;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {SECRET_FIELD_NAME} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "SECRET_FIELD_NAME"},
    ),
    (
        "P26 a const declared inside a fn body is not a module-scope name a "
        "format capture could reach",
        '''
        fn helper() {
            const INNER_LEN: usize = 16;
            let _ = INNER_LEN;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {INNER_LEN} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "INNER_LEN"},
    ),
    (
        "P27 a trait's associated const is a per-impl binding, not a free "
        "name (the associated-`type` exclusion, applied to consts)",
        '''
        pub trait Sized2 {
            const TRAIT_LEN: usize = 16;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {TRAIT_LEN} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "TRAIT_LEN"},
    ),
    (
        "P28 a bare name this file `use`s from OUTSIDE the crate is not the "
        "core-local enum that shares its spelling — core/src/error.rs's "
        "`pub enum Error` made `use std::io::Error;` pass silently",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        use std::io::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
    (
        "P29 a RAW string with an odd number of internal quotes must not "
        "re-expose its contents as code — the round-4 blanker had no notion "
        "of `r#\"...\"#`, so this walked straight through the fix that was "
        "supposed to have closed self-authorisation",
        '''
        const ZZ_HELP: &str = r#"a" const RAW_INJECTED: usize = 1; "b"#;

        #[derive(thiserror::Error, Debug)]
        #[error("expected {RAW_INJECTED} bytes")]
        pub struct Bad;
        ''',
        {"unparsed": True, "field": "RAW_INJECTED"},
    ),
    (
        "P30 a char literal holding a brace must not move the braces — "
        "`let c = '}';` in a fn body popped that function's own block and "
        "promoted every following declaration to module scope",
        '''
        fn zz_helper() -> char {
            let c = '}';
            const FN_LOCAL_LEN: usize = 1;
            let _ = FN_LOCAL_LEN;
            c
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {FN_LOCAL_LEN} bytes")]
            Bad,
        }
        ''',
        {"unparsed": True, "field": "FN_LOCAL_LEN"},
    ),
    (
        "P31 a char literal holding a QUOTE must not desync the string "
        "state across the following `use` — that inverted the withdrawal "
        "pass and handed back the bare-name enum bypass",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        fn zz_q() -> char { '"' }

        use std::io::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
    (
        "P32 a NESTED `mod std` must not make `use std::…` look intra-crate "
        "— `mod outer { pub mod std { } }` compiles beside the import, so an "
        "unscoped harvest of every `mod NAME` reopened the bypass",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        mod outer { pub mod std { } }

        use std::io::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
    (
        "P33 a #[cfg(test)] ENUM must not vouch for a shipped message "
        "either — round 4 applied the test exclusion to consts only, so a "
        "test-only error enum still registered its bare name tree-wide and "
        "a shipped struct of the same name rode on it",
        '''
        #[cfg(test)]
        mod tests {
            #[derive(thiserror::Error, Debug)]
            pub enum ZzShared {
                #[error("code {0}")]
                A(u32),
            }
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("shared: {0}")]
            Wrapped(ZzShared),
        }
        ''',
        {"variant": "Wrapped", "field": "0", "field_type": "ZzShared"},
    ),
    # P34-P36 pin `alias_shadowed_names`. Before it existed, EVERY one of
    # these reported ZERO findings: `is_data_free` consulted tier 1 (a name
    # match against `DATA_FREE_TYPES`) before it ever looked at the alias
    # table, so a `type` alias that reused a trusted name was invisible. One
    # file, no collision, no ordering dependence, no `#[allow]` — the same
    # reachability as the round-4 string-literal self-authorisation CRITICAL.
    (
        "P34 `type CborFault = String;` must not launder a String through "
        "tier 1 — the shape rustc does NOT catch (already CamelCase, so "
        "`non_camel_case_types` never fires) and the reason this drop is a "
        "CRITICAL rather than a tidy-up",
        '''
        type CborFault = String;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR fault: {fault}")]
            Bad { fault: CborFault },
        }
        ''',
        {"variant": "Bad", "field": "fault", "field_type": "CborFault"},
    ),
    (
        "P35 `type usize = String;` must not launder a String through tier 1 "
        "— the shape the module docstring used to name as the WHOLE limit, "
        "and the only one this repo's -D warnings gate happens to reject on "
        "its own",
        '''
        type usize = String;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("length {length}")]
            Bad { length: usize },
        }
        ''',
        {"variant": "Bad", "field": "length", "field_type": "usize"},
    ),
    (
        "P36 `type bool = String;` — the shadow must deny through the "
        "`Option<T>` recursion too, not only at the top level",
        '''
        type bool = String;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("flag {flag:?}")]
            Bad { flag: Option<bool> },
        }
        ''',
        {"variant": "Bad", "field": "flag", "field_type": "Option<bool>"},
    ),
    (
        "P37 Rust block comments NEST — `/* a /* b */ const … */` is comment "
        "all the way to the LAST `*/`, so the const inside it declares "
        "nothing. A C-style (non-nesting) scanner ends the comment at the "
        "FIRST `*/`, promotes the const to code, and hands back the round-4 "
        "self-authorisation CRITICAL in a new costume. `LEXER_SAMPLE` "
        "carries a nested comment but only feeds the length/line invariants, "
        "which C semantics preserve — nothing pinned the SEMANTICS until "
        "this control",
        '''
        /* outer /* inner */ pub const NESTED_INJECTED: usize = 1; */

        #[derive(thiserror::Error, Debug)]
        #[error("expected {NESTED_INJECTED} bytes")]
        pub struct Bad;
        ''',
        {"unparsed": True, "field": "NESTED_INJECTED"},
    ),
    (
        "P38 an UNTERMINATED block comment must not hide a `use` from the "
        "withdrawal pass — `lex_spans` deliberately runs such a construct to "
        "end-of-input, which is fail-CLOSED for the credit registries and "
        "fail-OPEN for `foreign_use_names`. THE control for round 5's "
        "headline fix (that pass reading RAW, unioned with the blanked "
        "read): pointing it at the blanked view alone leaves P31 green, "
        "because the lexer handles `'\\\"'` correctly today, and leaves this "
        "one RED",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }

        /* this block comment is never closed, so every view derived from the
           lexer blanks the `use` below — but the raw text still carries it
        use std::io::Error;
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
    (
        "P39 P38's shape written as a RENAMING import. This is the control "
        "`_looks_like_use_tree`'s ` as ` -> `|` normalisation has to survive: "
        "with `|` absent from USE_TREE_CHARS_RE every `use … as …;` failed "
        "the raw read's prose filter, so all 15 renaming imports under "
        "core/src/** rested on the blanked read alone — and the blanked read "
        "is exactly what an unterminated comment disarms. Breaks under "
        "EITHER mutation (drop `|` from the class, or point the withdrawal "
        "pass back at the blanked view); P38 breaks only under the second, "
        "which is what separates the two",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum ZzRenamedError {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] ZzRenamedError),
        }

        /* never closed, so the blanked view cannot see the rename below
        use std::io::Error as ZzRenamedError;
        ''',
        {
            "variant": "BareIoError",
            "field": "0",
            "field_type": "#[from] ZzRenamedError",
        },
    ),
    (
        "P40 thiserror 2.x `#[error(fmt = <path>)]` — a custom formatter is "
        "handed EVERY field and can render a `String` into `Display`, but the "
        "attribute has no format string, so placeholder extraction yields "
        "nothing and the `if not names` skip once waved it through (#485). It "
        "compiles clean and passes clippy, so nothing else catches it. Must "
        "now fail closed as UNPARSED — an #[error(...)] body this guard cannot "
        "model as a string-literal format",
        '''
        fn render(_detail: &String, _f: &mut std::fmt::Formatter<'_>)
            -> std::fmt::Result { Ok(()) }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(fmt = render)]
            Leak(String),
        }
        ''',
        {"unparsed": True, "variant": "Leak"},
    ),
]

NEGATIVE_CONTROLS: list[tuple[str, str]] = [
    (
        "N1 &'static str hint plus an ordinal — the #474 fix shape",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate map key at entry #{} of {field}", .index + 1)]
            DuplicateKey { field: &'static str, index: usize },
        }
        ''',
    ),
    (
        "N2 CborFault payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR decode error: {0}")]
            CborDecode(CborFault),
        }
        ''',
    ),
    (
        "N3 fixed-size byte array",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("block {block_uuid:02x?} failed")]
            Failed { block_uuid: [u8; 16] },
        }
        ''',
    ),
    (
        "N4 message interpolates nothing",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected top-level CBOR map")]
            NotAMap,
        }
        ''',
    ),
    (
        "N5 Option<usize>",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("failed at {offset:?}")]
            At { offset: Option<usize> },
        }
        ''',
    ),
    (
        "N6 a commented-out #[error(...)] above a LIVE, unattributed "
        "variant must not fire — proves comment-stripping is load-bearing "
        "(without it, VARIANT_RE would happily match the real variant text "
        "that follows the fake attribute)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            // #[error("leaky: {key}")]
            Leaky { key: String },
            #[error("fine")]
            Fine,
        }
        ''',
    ),
    (
        "N7 the whole violation is inside a block comment",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            /* #[error("leaky: {key}")]
               Leaky { key: String }, */
            #[error("fine")]
            Fine,
        }
        ''',
    ),
    (
        "N8 escaped braces are not placeholders, even with a String field "
        "present to catch a phantom match",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {{ }} shape")]
            Shape { secret: String },
        }
        ''',
    ),
    (
        "N9 nested core-local error type is data-free by recursion (this "
        "guard already scans InnerError's own definition below, so the "
        "forward through Wrapped's {0} adds no new leak surface)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum InnerError {
            #[error("inner failure code {code}")]
            Failure { code: u32 },
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("outer: {0}")]
            Wrapped(#[from] InnerError),
        }
        ''',
    ),
    (
        "N10 alias to a fixed-size byte array resolves data-free",
        '''
        type BlockUuid = [u8; 16];

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("block {block_uuid:02x?} failed")]
            Failed { block_uuid: BlockUuid },
        }
        ''',
    ),
    (
        "N11 #[error(transparent)] over a core-local, already-scanned "
        "error type is data-free by recursion",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum Inner {
            #[error("inner failure code {code}")]
            Failure { code: u32 },
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(transparent)]
            Wrapped(#[from] Inner),
        }
        ''',
    ),
    (
        "N12 a placeholder capturing a real module-level `const` is "
        "data-free by definition — compile-time evaluated, so it cannot "
        "carry runtime content regardless of its declared type (the live "
        "vault/record.rs:155 shape: one placeholder is a genuine field, "
        "the other is a const)",
        '''
        pub const RECORD_UUID_LEN: usize = 16;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("invalid UUID: expected {RECORD_UUID_LEN} bytes, got {length}")]
            InvalidUuid { length: usize },
        }
        ''',
    ),
    (
        "N13 an INTRA-crate `use` of a core-local error type keeps the "
        "recursion tier — P28's foreign-import drop must be about the "
        "import's ROOT, not about `use` statements in general",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        use crate::local::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("wrapped: {0}")]
            Wrapped(#[from] Error),
        }
        ''',
    ),
    (
        "N14 a const declared at module scope INSIDE a `mod` block is still "
        "module scope — the non-module-block exclusion must exempt exactly "
        "`mod { }` and nothing else, or every const in the tree vanishes",
        '''
        mod inner {
            pub const INNER_CONST: usize = 16;
        }

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {INNER_CONST} bytes, got {length}")]
            Bad { length: usize },
        }
        ''',
    ),
    (
        "N15 a Rust-2018 UNIFORM-PATH re-export (`use inner::X;` beside "
        "`mod inner;`, no crate:: prefix) is intra-crate — the live "
        "core/src/vault/mod.rs shape; misreading `inner` as a third-party "
        "crate name produced four spurious findings there",
        '''
        mod inner {
            #[derive(thiserror::Error, Debug)]
            pub enum InnerError {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        pub use inner::InnerError;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("wrapped: {0}")]
            Wrapped(#[from] InnerError),
        }
        ''',
    ),
    (
        "N16 a raw string must END where Rust says it ends — a scanner that "
        "over-consumes hides every declaration after it, so the const "
        "DELIBERATELY sits below the raw string",
        '''
        pub const HELP: &str = r#"usage: thing "quoted" here"#;
        pub const REAL_LEN: usize = 16;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {REAL_LEN} bytes, got {length}")]
            Bad { length: usize },
        }
        ''',
    ),
    (
        "N17 a LIFETIME is not a char literal — `&'static str` is the shape "
        "that makes the apostrophe ambiguous, and a scanner that opens a "
        "char literal there runs to end-of-file swallowing the const below",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("field {field}: expected {LIFE_LEN}")]
            Bad { field: &'static str, length: usize },
        }

        pub const LIFE_LEN: usize = 16;
        ''',
    ),
    (
        "N18 a field-level VISIBILITY modifier is not part of the field's "
        "name (or of its type) — `parse_fields` split on the first `:` and "
        "took the name side verbatim, so `pub index: usize` became a field "
        "literally named `pub index`, `{index}` matched nothing, and valid "
        "code produced a spurious UNPARSED. Covers all three shapes: a `pub` "
        "struct field, a `pub(crate)` one, and a `pub` TUPLE field (whose "
        "modifier lands on the TYPE side instead, hence a second strip in "
        "`normalize_type`)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("entry #{index} of {field}")]
            Bad {
                pub field: &'static str,
                pub(crate) index: usize,
            },
            #[error("length {0}")]
            Len(pub usize),
        }
        ''',
    ),
]


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
]


# `(variant, field, field_type, field_type_prefix)` claims a POSITIVE control
# makes about the finding it expects, beyond "something fired". `unparsed`
# asserts the finding IS (or is not) the default-deny-on-structure kind;
# `field_type_prefix` asserts WHICH denial arm produced it (rule E4's reason
# codes).
#
# Non-emptiness alone is not enough for a control that pins a PARSER fix:
# once an unresolvable construct became an `UNPARSED` finding rather than a
# silent skip, reverting such a fix left the control green — the guard still
# reported something, just not the thing the control existed to prove. P12
# and P14 were both in that state.
ControlExpectation = dict[str, object]


def _finding_matches(f: Finding, expect: ControlExpectation) -> bool:
    is_unparsed = f.field_type.startswith("UNPARSED:")
    if "unparsed" in expect and bool(expect["unparsed"]) is not is_unparsed:
        return False
    if "variant" in expect and f.variant != expect["variant"]:
        return False
    if "field" in expect and f.field != expect["field"]:
        return False
    if "field_type" in expect and f.field_type != expect["field_type"]:
        return False
    # `field_type_prefix` exists for rule E4's reason codes (see `E4_OUTSIDE`
    # and friends): an exact `field_type` match would pin a whole paragraph
    # of prose, so editing the wording would break the control rather than
    # the logic it guards.
    prefix = expect.get("field_type_prefix")
    if prefix is not None and not f.field_type.startswith(str(prefix)):
        return False
    # `rule` pins WHICH rule produced the finding — a control that must fire
    # under E3 is not satisfied by an unrelated E2 finding in the same
    # fixture, which matters for the multi-declaration fixtures.
    if "rule" in expect and f.rule != expect["rule"]:
        return False
    return True


#  A synthetic source carrying every lexical shape the guard has ever been
#  broken by, plus the ones it has not: nested block comments, a `\` + newline
#  continuation, raw strings with a `#` run and internal quotes, byte and raw
#  byte strings, char literals holding a quote / a brace / an escaped quote,
#  and a lifetime. Used by `check_view_invariants` — see there.
LEXER_SAMPLE = (
    '#[error("continued \\\n        message: {a}")]\n'
    "/* block\n   comment /* nested */ still comment */ const A: usize = 1;\n"
    "// line comment\n"
    'let s = "quote \\" inside";\n'
    'let r = r#"raw " with quote and /* not a comment */"#;\n'
    'let r2 = r##"raw "# inner"##;\n'
    'let b = b"bytes \\x00";\n'
    'let br = br#"raw " bytes"#;\n'
    "let q = '\"';\n"
    "let ob = '{';\n"
    "let cb = '}';\n"
    "let esc = '\\'';\n"
    "let bs = '\\\\';\n"
    "let bc = b'x';\n"
    "fn f<'a>(x: &'a str) -> &'static str { x }\n"
)


def check_view_invariants() -> list[str]:
    r"""The lexer and both views it feeds are indexed into by CHARACTER
    OFFSET — the reported line number, every `_inside(...)` span check and the
    raw-text allowlist key all assume a view lines up with its source
    byte-for-byte and line-for-line.

    An earlier round shipped a violation of exactly this: a `\` + newline
    string continuation emitted a space for the newline, so every subsequent
    line number in the file was reported low. Three properties are asserted
    over every self-test control plus `LEXER_SAMPLE`:

    1. `lex_spans` returns spans that are ordered, non-overlapping and inside
       the source. A classification that overlaps itself is a classification
       that has lost track of where it is, which is the single root cause
       behind every view bug this guard has had.
    2. Both views preserve LENGTH.
    3. Both views preserve LINE COUNT.
    """
    samples = [src for _, src, *_ in POSITIVE_CONTROLS]
    samples += [src for _, src in NEGATIVE_CONTROLS]
    samples += [src for _, src, *_ in BRIDGE_POSITIVE_CONTROLS]
    samples += [src for _, src, *_ in BRIDGE_NEGATIVE_CONTROLS]
    samples.append(SELF_TEST_DETAIL_SRC)
    samples.append(LEXER_SAMPLE)
    failures: list[str] = []
    for i, src in enumerate(samples):
        prev_end = 0
        for start, end, kind in lex_spans(src):
            if not (0 <= start <= end <= len(src)):
                failures.append(
                    f"LEXER INVARIANT: span ({start},{end},{kind}) out of "
                    f"range on sample #{i} (len {len(src)})"
                )
            if start < prev_end:
                failures.append(
                    f"LEXER INVARIANT: span ({start},{end},{kind}) overlaps "
                    f"the previous span on sample #{i}"
                )
            prev_end = max(prev_end, end)
        for name, view in (
            ("strip_comments", strip_comments(src)),
            ("discovery_view", discovery_view(src)),
        ):
            if len(view) != len(src):
                failures.append(
                    f"VIEW INVARIANT: {name} changed length on sample #{i} "
                    f"({len(view)} != {len(src)})"
                )
            if view.count("\n") != src.count("\n"):
                failures.append(
                    f"VIEW INVARIANT: {name} changed line count on sample "
                    f"#{i} ({view.count(chr(10))} != {src.count(chr(10))})"
                )
    return failures


def check_key_shape(label: str, findings: list[Finding]) -> list[str]:
    """The allowlist key (`Finding.source_line`) must contain no TAB and no
    newline.

    `scripts/lib/hygiene-allowlist.sh::allowlisted` — the shared parser this
    file's allowlist format exists to stay compatible with — splits entries
    on TAB, and reads them one line at a time. A key carrying either
    character could not be written as an entry at all, or worse could be
    written in a way that silently truncates and matches more than it names.
    `scan_source` builds the key with `" ".join(text.split())`, which
    collapses both; this asserts the property rather than trusting it.
    """
    failures: list[str] = []
    for f in findings:
        if "\t" in f.source_line or "\n" in f.source_line:
            failures.append(
                f"ALLOWLIST KEY SHAPE: {label} produced a key containing a "
                f"TAB or newline: {f.source_line!r}"
            )
    return failures


def scan_control(src: str) -> list[Finding]:
    """Run the FULL pipeline over a self-test control string.

    Each control is self-contained (it declares any nested enum / alias /
    const / `use` it references in the same string), so a per-control
    discovery pass — no real file path, hence no `path_label` — exercises the
    real discovery, collision-drop and import-shadow code paths rather than a
    hardcoded name list.
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    return scan_source(
        "<self-test>", src, enums, aliases, consts, foreign_use_names(src)
    )


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


def scan_bridge_control(
    src: str,
    path_label: str = "<self-test-bridge>",
    detail_src: str = SELF_TEST_DETAIL_SRC,
) -> list[Finding]:
    """`scan_control`, run in `bridge_mode` PLUS rules E2/E3/E4 (#480) —
    mirrors `scan_control`'s self-contained-fixture design (no real file path,
    hence no qualified spellings; see `module_path_segments`).

    Runs EVERY bridge producer, exactly as `run_real_scan` does for a real
    bridge file: `scan_source(..., bridge_mode=True)` (rule E2 sweep 1,
    thiserror-derived declarations), `scan_bridge_plain_declarations` (rule E2
    sweep 2, plain-derive `*Error`/`*Warning` declarations),
    `scan_bridge_construction_sites` (rule E3) and
    `scan_bridge_gated_detail_impls` (rule E4).

    `path_label` defaults to a label that is NOT the detail module, so a
    control exercises rule E4's "impl outside detail.rs" arm by default; a
    control that needs the OTHER arm (an impl INSIDE detail.rs, checked
    against the scanned-type registry) passes `path_label=DETAIL_MODULE_REL`
    via its options dict.

    `scanned_error_type_names` is derived from the CONTROL ITSELF (both the
    "core" and "bridge" halves collapse to this one source), so a control
    that wants a name registered declares the `#[error]`-bearing type in the
    same string — the same self-contained design every other control uses.
    """
    enums, aliases, declared_consts, shadows = discover_declarations(src)
    consts = resolve_consts(declared_consts, shadows)
    foreign = foreign_use_names(src)
    found = scan_source(
        path_label, src, enums, aliases, consts, foreign, bridge_mode=True
    )
    found += scan_bridge_plain_declarations(path_label, src, enums, aliases, foreign)
    found += scan_bridge_construction_sites(
        path_label, src, sanctioned_constructor_names(detail_src)
    )
    found += scan_bridge_gated_detail_impls(
        path_label,
        src,
        discover_scanned_error_type_names([], [(path_label, src)], enums, enums),
    )
    return found


def _check_distinct_e2_keys(label: str, src: str, variant: str) -> list[str]:
    """Shared assertion for `check_bridge_key_distinctness`: scanning `src`
    must produce exactly two rule-E2 findings for `variant`, with two
    DISTINCT `source_line` keys."""
    found = [f for f in scan_bridge_control(src) if f.rule == "E2" and f.variant == variant]
    keys = {f.source_line for f in found}
    if len(found) != 2 or len(keys) != 2:
        return [
            f"BRIDGE KEY DISTINCTNESS ({label}): two different types' "
            f"same-named variants must produce two DISTINCT E2 keys, got "
            f"{len(found)} finding(s) with {len(keys)} distinct key(s): "
            f"{[f.source_line for f in found]}"
        ]
    return []


def check_bridge_key_distinctness() -> list[str]:
    """Rule E2's allowlist key must include the OWNING type name, not just
    the variant/struct's own name (#480 review finding 2): two DIFFERENT
    types in ONE file with a same-named, same-shaped variant must not
    collide on the same key. `SettingsWarning::Corrupt` and
    `SettingsParseError::Corrupt` (settings/parse.rs:24, :39) are the LIVE
    instance of exactly this shape — before `enclosing_enum_names` existed,
    both produced the bare key `Corrupt { detail: String, }`, so one
    allowlist entry would have silently exempted both.

    A dedicated check rather than a `BRIDGE_POSITIVE_CONTROLS` entry: this
    makes a claim ACROSS two findings from ONE scan (their keys must
    DIFFER), not a per-control fired-or-not verdict `ControlExpectation`
    can express. Both messages are deliberately NOT interpolated (`"bad"`,
    no `{leak}`) so only rule E2's structural sweep fires — an interpolated
    message would ALSO produce rule-E1 findings keyed on the (identical,
    for both types) ATTRIBUTE TEXT, which is a separate, pre-existing E1
    characteristic this check is not about.

    Covers BOTH of rule E2's producers, since they thread the owning name
    through independently and a fix (or regression) in one does not imply
    the other: `scan_source`'s `bridge_mode` sweep 1 (thiserror-derived,
    via `enclosing_enum_names`) and `scan_bridge_plain_declarations`'s
    sweep 2 (plain-derive, via its own regex-captured enum name) — a
    mutation dropping ONLY the sweep-2 prefix was caught live during this
    fix's own review: self-test stayed green with a THISERROR-only version
    of this check while the plain-derive path — the shape the real
    `SettingsWarning`/`SettingsParseError` collision actually takes —
    silently regressed.
    """
    failures = _check_distinct_e2_keys(
        "sweep 1, thiserror",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum TypeA {
            #[error("bad")]
            Bad { leak: String },
        }

        #[derive(thiserror::Error, Debug)]
        pub enum TypeB {
            #[error("bad")]
            Bad { leak: String },
        }
        ''',
        "Bad",
    )
    failures += _check_distinct_e2_keys(
        "sweep 2, plain-derive",
        '''
        pub enum TypeCWarning {
            Bad { leak: String },
        }

        pub enum TypeDWarning {
            Bad { leak: String },
        }
        ''',
        "Bad",
    )
    return failures


def run_self_test() -> int:
    failures: list[str] = check_view_invariants()
    for entry in POSITIVE_CONTROLS:
        label, src = entry[0], entry[1]
        expect: ControlExpectation | None = entry[2] if len(entry) > 2 else None
        found = scan_control(src)
        failures += check_key_shape(label, found)
        if not found:
            failures.append(f"POSITIVE control did not fire: {label}")
        elif expect and not any(_finding_matches(f, expect) for f in found):
            failures.append(
                f"POSITIVE control fired for the WRONG REASON: {label} -> "
                f"expected {expect}, got "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    for label, src in NEGATIVE_CONTROLS:
        found = scan_control(src)
        if found:
            failures.append(
                f"NEGATIVE control fired: {label} -> "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    for entry in BRIDGE_POSITIVE_CONTROLS:
        label, src = entry[0], entry[1]
        bridge_expect: ControlExpectation | None = entry[2] if len(entry) > 2 else None
        opts: dict = entry[3] if len(entry) > 3 else {}
        found = scan_bridge_control(src, **opts)
        failures += check_key_shape(label, found)
        if not found:
            failures.append(f"POSITIVE control did not fire: {label}")
        elif bridge_expect and not any(_finding_matches(f, bridge_expect) for f in found):
            failures.append(
                f"POSITIVE control fired for the WRONG REASON: {label} -> "
                f"expected {bridge_expect}, got "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    for entry in BRIDGE_NEGATIVE_CONTROLS:
        label, src = entry[0], entry[1]
        neg_opts: dict = entry[2] if len(entry) > 2 else {}
        found = scan_bridge_control(src, **neg_opts)
        if found:
            failures.append(
                f"NEGATIVE control fired: {label} -> "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    failures += check_bridge_key_distinctness()
    if failures:
        print("self-test: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"self-test: OK ({len(POSITIVE_CONTROLS)} positive / "
        f"{len(NEGATIVE_CONTROLS)} negative / "
        f"{len(BRIDGE_POSITIVE_CONTROLS)} bridge positive / "
        f"{len(BRIDGE_NEGATIVE_CONTROLS)} bridge negative)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(run_self_test())
    sys.exit(run_real_scan())
