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

import sys
from pathlib import Path

# `core/tests/error_payload_hygiene_parity.rs` loads this file directly via
# `importlib.util.spec_from_file_location`, which does NOT add this file's
# own directory to `sys.path` the way running it as a script does. Without
# this line the `payload_guard` import below raises `ModuleNotFoundError`
# under that loader while both documented `uv run` invocations stay green —
# a split that would be invisible to this task's own verification commands.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from payload_guard.config import DETAIL_MODULE_REL
from payload_guard.lexer import LEXER_SAMPLE, discovery_view, lex_spans, strip_comments
from payload_guard.types import Finding

from payload_guard.allowlist import load_allowlist
from payload_guard.discovery import (
    discover_declarations, discover_scanned_error_type_names, foreign_use_names,
    resolve_consts,
)

from payload_guard.rules.e1 import scan_source
from payload_guard.rules.e2 import scan_bridge_plain_declarations
from payload_guard.rules.e3 import (
    sanctioned_constructor_names, scan_bridge_construction_sites,
)
from payload_guard.rules.e4 import (
    E4_BARE, E4_GENERIC, E4_NONPATH, E4_OUTSIDE, E4_ROOT, E4_UNSCANNED,
    scan_bridge_gated_detail_impls,
)
from payload_guard.scan import run_real_scan


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
