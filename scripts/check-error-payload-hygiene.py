#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
r"""Fail-closed guard: no error payload crossing the FFI may carry a runtime
String that nobody has vouched for — in `core/src/**`, in the FFI bridge, or
in either binding wrapper crate (`ffi/secretary-ffi-py`, `ffi/secretary-ffi-uniffi`).

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

THE BRIDGE RULES (#480: E2, E3, E4; #486 extends E2/E3 to the wrapper crates
and adds a wrapper-only E5)
------------------------------------------------------------------------------
Everything above is rule `E1`, and it applies to ALL FOUR scan roots
(`payload_guard/roots.py`'s `SCAN_ROOTS`). Three more rules apply to
`ffi/secretary-ffi-bridge/src/**`; as of #486, E2 and E3 ALSO apply to the
two binding wrapper crates (`ffi/secretary-ffi-py/src/**`,
`ffi/secretary-ffi-uniffi/src/**`) — E4 does not (see `ScanRoot.
gated_detail_impls`'s docstring for why). The rule id is the allowlist's
second column, so an exception is scoped to the rule that raised it.

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
declares no value. `String::new()` is NOT that shape and denies. On the two
WRAPPER roots only (#486), a FIFTH shape is also accepted: a SINGLE-HOP
field access ending in the gated name (`uuid_hex: a.uuid_hex`, not a
multi-hop `a.b.uuid_hex`) — the DTO pass-through all four live wrapper
sites use. See `ScanRoot.allow_field_access` and `rules/e3.py`'s
`initializer_is_gated` for why it is scoped out of the
bridge root.

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

`E5` — FORMAT! CONFINEMENT (#486, wrapper roots only). E3 gates GATED-FIELD
INITIALIZERS; a binding wrapper's platform sink is not one — ffi-py's
`VaultNotAuthor::new_err(format!("expected={a}, got={b}"))` hands `format!`'s
result to a function ARGUMENT, a shape no extension of E3's initializer model
reaches. E5 gates the SOURCE instead of the sink: `format!` is confined to
each wrapper crate's own sanctioned `detail.rs`, the same sink-pinning move
`error/detail.rs` makes for the bridge (E3/E4). Viable because, censused,
100% of production `format!` in the wrapper crates is error-bound — zero
legitimate-use allowlist entries. The bridge is deliberately EXCLUDED: most
of its `format!` sites build filenames, a legitimate non-error use that would
cost ~9 allowlist entries for path building if confined the same way. See
`payload_guard/rules/e5.py` for the full rationale and the scope decision
around `.to_string()` (which E5 does NOT cover).

LIMITS (stated, not hidden — each one points at the module that owns it)
--------------------------------------------------------------------------
- Rule E1 (`payload_guard/rules/e1.py`) sees DECLARATIONS, not construction
  sites, and under `core/src/**` that is all it sees. A variant whose
  payload is `&'static str` is provably safe; a `core` variant allowlisted
  because "its producers all pass literals" is a point-in-time claim this
  guard cannot verify. Those entries say so in the allowlist. Rule E3
  (`payload_guard/rules/e3.py`) DOES read construction sites, under
  `ffi/secretary-ffi-bridge/src/**` and, as of #486, `ffi/secretary-ffi-py/src/**`
  and `ffi/secretary-ffi-uniffi/src/**` too, and only for the six gated field
  names.
- It covers `core/src/**`, `ffi/secretary-ffi-bridge/src/**` (#480), and, as
  of #486, the two binding wrapper crates (`ffi/secretary-ffi-py/src/**`,
  `ffi/secretary-ffi-uniffi/src/**`) — four roots, each described as data by
  `payload_guard/roots.py`'s `SCAN_ROOTS`, with separate discovery per root
  (`payload_guard/scan.py`'s `run_real_scan` walks them independently) — a
  wrapper-local (or bridge-local) alias/const/enum must not vouch for a
  field in a DIFFERENT root. The wrapper roots take rules E1/E2/E3, plus an
  E3 ACCEPTANCE the bridge does not (`ScanRoot.allow_field_access`, rule
  E3's "shape 5" — a SINGLE-HOP field access ending in the gated name, the
  DTO pass-through `uuid_hex: a.uuid_hex`, not a multi-hop `a.b.uuid_hex`),
  and rule E5 (#486 task 11, `payload_guard/rules/e5.py`), which the bridge
  does NOT take either — every `format!` in a wrapper crate outside its own
  `detail.rs` is a finding, gating the SOURCE (a hand-rolled `format!`)
  rather than the SINK (E3's gated-field initializer), since a wrapper's
  platform sink hands `format!`'s result to a function ARGUMENT, not an
  initializer. The wrapper roots do NOT take rule E4: `GatedDetail` is
  `pub(crate)` in the bridge crate, so no wrapper crate can implement it,
  and E4's premise is unaffected by scanning these roots at all. Nothing
  ELSE is scanned: `secretary-cli` / `desktop/src-tauri` build their own
  error values independently. A `String` authored in one of those and
  handed to a platform is gated by review alone.
- RULE E3 READS FOUR CANDIDATE POSITIONS — a gated field's INITIALIZER
  (`detail: <expr>`), a `let` BINDING to a gated name
  (`let detail = <expr>`), an ASSIGNMENT to one, including every Rust
  COMPOUND form (`x.detail = <expr>`, `x.detail += <expr>`, `-=`, `*=`,
  `/=`, `%=`, `^=`, `&=`, `|=`, `<<=`, `>>=`), and the `io::Error` payload
  ARGUMENT of `io::Error::new(kind, PAYLOAD)` / `io::Error::other(PAYLOAD)`
  (#487 — `payload_guard/rules/e3.py`'s `IO_ERROR_NEW_RE` / `IO_ERROR_OTHER_RE`
  and `io_payload_candidates`; that position has its own LIMIT, a turbofish
  or generic comma in the `ErrorKind` argument mis-slicing the payload span,
  documented there and always fail-closed). #488's three laundering shapes
  are closed by the second and third, but only for the SIMPLE forms of each: a plain
  `let <name> = <expr>` or a plain `<recv>.<name> <op>= <expr>` is ITSELF
  a construction of a gated value, so gating its initializer/RHS catches
  the launder where it happens, and no dataflow is required for those two
  shapes.
  WHAT REMAINS is everything that reaches a gated field through NEITHER
  syntactic form — verified by execution, not assumed:
    (a) PATTERN-DESTRUCTURING binds of the same name: tuple
        (`let (a, detail) = ..`), tuple-struct (`let Wrap(detail) = ..`),
        struct (`let SomeErr { detail } = ..`), slice
        (`let [detail] = ..`), and `if let` / `while let` / `for`. None of
        these produce the `let <name> =` token `GATED_LET_RE` matches.
    (b) BUILD-THEN-MUTATE through a method call, e.g. `let mut detail =
        "".to_string(); detail.push_str(&format!("{e}"));` — the `let`
        initializer is the accepted literal-plus-`.to_string()` shape
        (arm 1), and `push_str` is a method call on the receiver
        `detail`, not an assignment TO a field named `detail`, so
        `GATED_ASSIGN_RE` — which matches `.<name> <op>=`, name AFTER the
        dot — never sees it: the dot in `detail.push_str(` precedes the
        method name, not the gated name.
    (c) arm 4's PARAMETER case: `fn f(detail: String) -> E { E::V { detail }
        }` trusts the name of a value this guard never watched being
        built.
    (d) DOTLESS LOCAL REASSIGNMENT: `detail = <expr>;` in statement
        position, reassigning a local that was bound WITHOUT a `let` this
        rule can see — a function PARAMETER (`fn f(mut detail: String) {
        detail = format!("{e}"); ... }`) or a type-less `let detail;`
        (valid Rust; the type is inferred from later use, and produces no
        `:` for `GATED_INIT_RE` to match at all). `GATED_ASSIGN_RE`
        requires a RECEIVER DOT before the name (`\.\s*(name)…=`) — it
        exists to catch `x.detail = <expr>`, a WRITE to a FIELD, and a bare
        local name has no receiver to put before the dot. `GATED_LET_RE`
        requires the `let` keyword, which a reassignment is not. Neither
        regex was ever meant to cover this shape; it is unrelated to
        `GATED_ASSIGN_RE`'s own scope, not a bug in it.
  The design mandates the re-wrap form, and pattern bindings
  (`FfiVaultError::X { detail } =>`) take it legitimately, so arm 4 stays
  as an explicit, named ACCEPT. Closing (a), (b) or (d) needs pattern-
  matching / local dataflow analysis this text-based, construction-site
  guard does not do; closing (c) needs interprocedural analysis for the
  same reason. None of (a)/(b)/(c)/(d) has a live producer in
  `ffi/secretary-ffi-bridge/src/` today (verified by reading every current
  producer, the same discipline the allowlist's Section 3 claims rest on)
  — a disclosed gap, not a silent one.
  A related coincidence, stated for completeness rather than danger: a
  TYPE-ANNOTATED `let` (`let detail: String = <expr>`) IS caught, but not
  by `GATED_LET_RE` — the type annotation sits between the name and `=`,
  so that regex never matches it. `GATED_INIT_RE` catches it instead,
  reading the `detail:` as a field-initializer colon and denying the
  `String = <expr>` tail as an unrecognised shape (`BP40` pins this).
  Fail-closed, but a coincidence of two rules interacting, not a designed
  property — and the same coincidence produces a FALSE POSITIVE on the
  legitimate annotated re-wrap `let detail: String = detail::gated(e);`
  (`GATED_INIT_RE` extracts `String = detail::gated(e)`, which also
  matches none of `initializer_is_gated`'s four accepted shapes). No such
  site exists in the tree today.
  A FIFTH shape, DEFERRED-INIT (`let detail: String;` with NO initializer,
  its value written on a later, separate `detail = <expr>;` statement), was
  a real REGRESSION caught in this branch's final whole-branch review, not
  a pre-existing disclosed gap: `GATED_INIT_RE` matches its `detail:` the
  same way it matches a genuine declaration, and once #488 added `;` as an
  `initializer_end` terminator (needed for the SIMPLE `let <name> = <expr>;`
  shape above), the deferred-init form's extracted slice went from a
  garbled, accidentally-denied mess to a clean bare `String` — which arm
  3's declaration-type-position acceptance then waved through, producing
  ZERO findings where the pre-#488 guard had denied (garbled, unrecognised
  shape) at merge-base `7fa210c`. THIS IS NOW CLOSED: `initializer_is_gated`
  denies the bare-`String` shape whenever its terminator is `;`, since none
  of the three genuine declaration positions (struct field, enum field, fn
  parameter) is ever itself terminated by a depth-zero `;` — only a `let`
  statement is, initializer or not. Pinned by `BP44`
  (`payload_guard/controls/bridge.py`). The deferred-init `let` is denied at
  its OWN line regardless of what the later `detail = <expr>;` assigns,
  which is a stricter (never weaker) reading than tracing that expression
  would give. That later assignment itself is exactly shape (d) above —
  dotless local reassignment — and closing THAT gap does not depend on
  closing this one: this fix denies the declaration outright; it does not
  make the subsequent bare reassignment visible to any regex.
- RULE E5's SCOPE IS `format!` ONLY, and that scope is a CENSUS FINDING, not
  a claim that `format!` is the only construct CAPABLE of composing a
  runtime string from several parts (`payload_guard/rules/e5.py`'s own
  docstring makes the same correction, at length, after this exact
  overclaim was caught in final review). `String::push_str`, `write!` /
  `writeln!` into a `String` buffer, the `+` operator on an owned `String`,
  and `.join()` on a `Vec<&str>`/`Vec<String>` can all compose several
  runtime values into one, and none of them is a site E5 inspects — a
  producer using any of them to build a gated-field argument passes
  silently. Verified by execution:
  `grep -rnE "push_str|write!\s*\(|\.join\s*\(|String::from\s*\(" \
  ffi/secretary-ffi-py/src ffi/secretary-ffi-uniffi/src` returns seven
  hits and zero live composition sites today (three are `String::from\s*\(`
  matching as a substring of `SecretString::from(`; four are
  `core_test_data_dir().join(...)` — `Path::join`, not `str`/`String`
  `.join()`, all four `#[cfg(test)]`-only). `push_str` and `write!` /
  `writeln!` do not appear at all; `+` string concatenation is not
  census-able by grep (indistinguishable from arithmetic `+`) and is named
  as uncovered on its construction merits alone. Separately, `.to_string()`
  IS censused (every production receiver in both wrapper crates is either
  an already-gated bridge error type's `Display` or a compile-time string
  literal — see `rules/e5.py`), which is the ONE construct this rule's name
  ("format! confinement") explicitly contrasts itself against; the other
  four are simply not mentioned by the contrast and must not be assumed
  covered by it. Leaving all five out of E5's scope is a reviewed,
  point-in-time decision, not a structural guarantee — if any census stops
  holding, E5 widens to cover it.
- `#[cfg(test)]` exclusion is PER FILE. A module whose `mod` declaration is
  gated in its PARENT (`#[cfg(test)] mod tests;` in `error/vault/mod.rs`)
  is a whole test-only FILE this guard has no way to recognise from inside,
  so its construction sites — `payload_guard/rules/e3.py`'s
  `scan_bridge_construction_sites`, via `discovery_cfg_test_spans` in
  `payload_guard/discovery.py` — are scanned like shipped ones. That is the
  fail-closed direction — findings in test code, never a missed shipped
  one — and the remedy is an allowlist entry naming the parent's gate.
- Rust is parsed by pattern, not by a real parser (the one lexical pass
  lives in `payload_guard/lexer.py`). The shapes in this codebase are
  regular (thiserror derives); an exotic macro-generated error enum would
  be invisible. `--self-test` (`payload_guard/selftest.py`, driven off the
  corpora in `payload_guard/controls/`) pins the shapes that do occur.
- The local-error-enum and type-alias recognition in `discover_declarations`
  (`payload_guard/discovery.py`) matches by NAME (bare,
  `<parent-module>::Name`, or `crate::<path>::Name`), not by real
  `use`-import / path resolution. A BARE spelling is therefore a
  tree-global claim, and
  `foreign_use_names` (same module) withdraws it per-file for every name
  that file `use`s from outside the crate — which is what stops
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
  `alias_shadowed_names` (`payload_guard/types.py`) now DROPS any spelling a
  discovered alias shadows out of tier 1 or tier 2, on `run_real_scan`'s
  (`payload_guard/scan.py`) existing collision-drop discipline.
  Note that rustc closes only the LOWERCASE costumes of this:
  `type usize = String;` and `type bool = String;` both trip
  `non_camel_case_types` (a `-D warnings` error here). A CamelCase shadow
  — `type CborFault = String;` — is lint-invisible and compiled clean,
  which is the shape that matters. P34-P36
  (`payload_guard/controls/core.py`) pin all three.
    STILL OPEN: a shadow whose name is in NO trusted set, i.e. one that gets
  its credit from the alias tier itself. Such a name is believed at its
  single declaration, because one-level alias resolution IS tier 3, and this
  guard has no notion of the SCOPE that declaration is visible in — an alias
  declared inside `mod inner { }` registers its bare spelling tree-globally,
  so a field written `x: Fingerprint` in a DIFFERENT file rides on it even
  though `Fingerprint` means something else there. The partial mitigation is
  `run_real_scan`'s (`payload_guard/scan.py`) cross-file drop: two files
  declaring the same spelling with DIFFERENT right-hand sides
  (`type Fingerprint = [u8; 16];` in `identity/fingerprint.rs` and
  `type Fingerprint = String;` elsewhere) collide and are dropped rather
  than guessed. What is left — telling a single-declaration shadow apart
  from the thing it shadows, in the scope the reference site actually sits
  in — is name resolution, and closing it requires a real type resolver,
  which is out of scope for a pattern-based guard. `--self-test` pins the
  shapes that DO occur, not every shape that could be contrived to evade it.
- `find_type_aliases` (`payload_guard/discovery.py`) drops any spelling that
  resolves to DIFFERENT right-hand sides across files rather than guessing
  which one is "real" — see `run_real_scan` (`payload_guard/scan.py`).
  `resolve_consts` (`payload_guard/discovery.py`) drops a `const` spelling
  on the same discipline: more than one module-scope declaration, or any
  `static` / excluded-scope declaration of that name, and the spelling is
  not credited. An earlier round unioned const names tree-wide on the
  argument that "a const's safety comes from the compiler, not its value";
  the premise is true but the conclusion does not follow, because the claim
  being made is "this placeholder RESOLVES TO a const", and `static` is
  exactly the same-convention collision partner that breaks it.
  `local_error_enums` (computed by `discover_declarations` in
  `payload_guard/discovery.py`, consulted by `payload_guard/types.py`'s
  `is_data_free`) still does NOT get the collision-drop: it is a pure
  membership set, not a name -> value map, and any enum whose name is
  registered is by construction a real `thiserror`-derived enum this guard
  independently scans somewhere under `core/src/**` — two DIFFERENT local
  enums sharing a bare name are both still soundly "safe by recursion."
  Its bare-name exposure is to a FOREIGN collision, which is what
  `foreign_use_names` (`payload_guard/discovery.py`) addresses instead.
- Every view comes from ONE lexical pass (`lex_spans`, in
  `payload_guard/lexer.py`), which handles line comments, NESTED block
  comments, ordinary and byte strings with escapes and `\` + newline
  continuations, RAW strings with a variable `#` run, char and byte-char
  literals, and the lifetime-vs-char ambiguity. It is a LEXER, not a
  parser: it knows where literals and comments are, and nothing else. It
  does not expand macros, so a `#[error(...)]` produced by a macro — or a
  declaration produced by one — is invisible to every registry here.
- `lex_spans` (`payload_guard/lexer.py`) treats an UNTERMINATED literal or
  block comment as running to end-of-input. That is the conservative
  reading for the credit registries (the tail stops being code, so
  declarations in it stop being credited) and it is why `foreign_use_names`
  (`payload_guard/discovery.py`) does not read those views — see the next
  point.
- THE FAIL-CLOSED ARGUMENT IS PER-PASS, NOT GLOBAL, and stating it globally
  was itself a defect. "Blanking can only HIDE text, so a view bug loses a
  credit and therefore only produces findings" is true for the three
  CREDIT-GRANTING registries (local error enums, type aliases, consts) and
  false for the two CREDIT-WITHDRAWING passes: hiding a `use` in
  `foreign_use_names`, or revealing an extra `mod` in `top_level_mod_names`
  (both in `payload_guard/discovery.py`), RESTORES a credit. Those two are
  wired to read the views whose failure direction matches their own
  polarity (raw + comments-blanked for the withdrawal; the fully blanked
  discovery view for the local-root grant). A correctness claim that does
  not hold for every consumer is worse than none, because it stops the next
  reader from checking.
- `scan_source` (`payload_guard/rules/e1.py`) locates `#[error(` on the
  comments-blanked view, with string contents INTACT, deliberately. Hiding
  an attribute would be fail-open, so that pass does not trust the lexer's
  literal classification at all. The price is that an `#[error(` sequence
  written INSIDE another attribute's message text is visited as though it
  were an attribute, and may produce an extra finding with its own
  (different) allowlist key. That is noise in the safe direction: it can
  never hide a real attribute, and the spurious key does not match the
  real one, so allowlisting one does not silence the other. Rule E4
  (`payload_guard/rules/e4.py`) locates its anchors the same way and
  inherits the same trade. RULE E3 (`payload_guard/rules/e3.py`) IS THE ONE
  EXCEPTION IN THIS FILE, and it is a deliberate, adjudicated one: it
  DETECTS candidates on the literal-blanked discovery view, so a `detail:`
  written inside an `assert!` message is not a construction site (it
  removed three such false positives in `error/vault/tests.rs`). That makes
  E3 detection the single pass here where a lexer desync is fail-OPEN
  rather than fail-closed, which is why `BP30`-`BP33`
  (`payload_guard/controls/bridge.py`) pin a real `detail: leak()` still
  firing immediately after a raw string with a `#` run, an escaped quote, a
  byte string, and a lifetime. E3's CLASSIFICATION still reads the
  literal-intact view, since "is this expression a string literal" is
  undecidable on a view where the literal has been blanked.
- `discover_declarations` (`payload_guard/discovery.py`) credits only
  MODULE-SCOPE declarations: anything inside a brace block that is not a
  `mod name { ... }` block is skipped (`non_module_block_spans`, same
  module), which covers a trait's or an `impl`'s ASSOCIATED `type` /
  `const` (a per-impl binding, e.g. `type Ek = ...;` in a KEM trait impl),
  and anything local to a `fn` body. `const` discovery additionally skips
  `#[cfg(test)]`-gated items (`cfg_test_spans`, same module): six of the
  134 bare const names the round-3 rule harvested tree-wide came from test
  modules, one of them named `SECRET_FIELD_NAME`. (An earlier draft of this
  comment said 136; that measurement was taken with two of the measuring
  session's own throwaway attack files still in the tree. 134 is the
  clean-tree figure.) Block kind is decided from the item's header text, so
  a `mod` declared through a macro would not be recognised as one — the
  fail-CLOSED direction (its contents lose credit).
- Declaration discovery runs over `discovery_view`
  (`payload_guard/lexer.py`) — comments AND string literal contents
  blanked. Without the second half, text inside an `#[error("...")]`
  message registered as a declaration, letting an author self-authorise
  the very placeholder under test
  (`#[error("... {SELF_AUTH} const SELF_AUTH: usize = 1;")]` passed
  silently). Locating `#[error(` attributes still uses the un-blanked text,
  deliberately: blanking can only HIDE, which loses a credit (fail-closed)
  during discovery but would lose a whole ATTRIBUTE (fail-open) if the
  string scanner ever desynced. A `#[error(` written inside another
  attribute's message text is therefore still visited as if it were an
  attribute; that produces noise or nothing, never a missed real attribute.
- The recursion tier's soundness claim is "this guard fails at that enum's
  own definition" — `payload_guard/rules/e1.py`'s `scan_source`, backed by
  the tier-2 check in `payload_guard/types.py`'s `is_data_free`. Once a
  leaf variant there is ALLOWLISTED — a human decision, not this guard's —
  the honest statement becomes "fails OR IS ALLOWLISTED at that enum's own
  definition." This guard does not re-verify that an allowlisted leaf stays
  sound as the type evolves; see
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

# Re-exported (not called in this file): `core/tests/error_payload_hygiene_
# parity.rs` loads this module via `importlib.util.spec_from_file_location`
# + `exec_module`, then reaches `load_allowlist` as `mod.load_allowlist(...)`
# by attribute — an import-only binding still creates that module attribute
# with zero in-file call sites.
from payload_guard.allowlist import load_allowlist
from payload_guard.scan import run_real_scan
from payload_guard.selftest import run_self_test

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(run_self_test())
    sys.exit(run_real_scan())
