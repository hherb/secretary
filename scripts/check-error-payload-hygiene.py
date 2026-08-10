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
data-free by `E1`'s tiers, OR be declared EXACTLY one of `ScanRoot.
gated_field_types` under one of the six names in `GATED_FIELD_NAMES` — a
PER-ROOT set (#500), not a single hardcoded spelling: the two wrapper roots
accept `String` only (uniffi's UDL must project a `string`, PyO3 exceptions
take a message), while the BRIDGE accepts `Detail` ALONE. #500 moved all 27
of the bridge's gated fields to that newtype and then NARROWED the root's
accepted set to it, so a new bridge error type cannot opt back out by
declaring the old `String` spelling (`BP51` pins the denial, `BN28` the
acceptance). That spelling-based acceptance is guarded on its own side by
`discover_local_detail_decoys` (`payload_guard/discovery.py`), which
WITHDRAWS the `Detail` spelling from this carve-out on any root where a
second, same-spelled `struct`/`enum`/`union`/`type Detail` is DECLARED
outside the root's sanctioned module — see that function's own LIMITS for
the five shapes it does not catch, and the "THE #500 NEWTYPE" section below
for the precise scope of what the compiler (rather than this text) enforces.
The sweep covers EVERY field, not just the
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
`detail::*`, the exact token `String` OR `Detail` (#500), or the field's own
name. The bare-token acceptance is what keeps a DECLARATION (`detail: String`
/ `detail: Detail` in an enum body, or a function parameter) from being read
as a construction: E2 already decides whether that declaration is acceptable
PER ROOT (`ScanRoot.gated_field_types`), and a declaration declares no value.
Unlike E2, this acceptance is NOT read per-root — `Detail` is recognised as a
declaration-position token on every `bridge_mode` root, wrapper roots
included, because it is a purely structural distinction (declaration vs.
construction) and E2 remains the sole gate on which TYPES are policy-
acceptable where. `String::new()` / `Detail::new()` are NOT that shape and
deny. A FIFTH shape — a
SINGLE-HOP field access ending in the gated name (`uuid_hex: a.uuid_hex`) —
exists in the code but is now switched OFF on every root (#497/#500): it was
granted for four wrapper DTO pass-throughs, all four of which moved onto
`detail::project(...)`, so it had zero live sites and the acceptance was
retired rather than left dormant. See `ScanRoot.allow_field_access`.

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

BOTH of those blind spots are closed IN THE COMPILER as of #496, and E4 is
now defence in depth rather than the sole enforcement: `GatedDetail` is a
SEALED trait (`detail.rs`'s `private::Sealed`, nameable only from inside
that file), so an impl anywhere else in the crate fails to compile with
"the trait bound `X: Sealed` is not satisfied" — whether it was written by
hand, generated by a macro, or spelled through an alias. Verified by
execution. E4 still earns its keep: it produces a legible, reviewable
finding rather than a trait-bound error, and it checks the SECOND half of
the rule — that an impl inside `detail.rs` names a type the guard scans.

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

THE #500 NEWTYPE — WHAT THE COMPILER ENFORCES, AND WHERE THAT STOPS
--------------------------------------------------------------------
All 27 gated payload fields in `ffi/secretary-ffi-bridge` are declared
`Detail` (`error/detail.rs`'s `pub struct Detail(String)`), whose inner
field is PRIVATE to that one file. A `String` therefore does not TYPECHECK
in any of those 27 positions, however it was produced — including through
every E3 laundering shape the LIMITS below enumerate as unwatched, and
through shapes nobody has enumerated. For those declarations this is a
compiler guarantee, not a text one, and E3 is defence in depth over it.

THE SENTENCE THIS INVITES AND WHICH IS WRONG IS "laundering is fixed".
Four boundaries, each stated as a boundary rather than a caveat, because
"documentation claiming more coverage than the code delivers" was the most
repeated review finding of the predecessor branch (#496):

  1. THE TWO WRAPPER ROOTS ARE UNCHANGED. `ffi/secretary-ffi-py` and
     `ffi/secretary-ffi-uniffi` keep `detail: String` on their OWN error
     types — uniffi's UDL must project a `string`, PyO3 exceptions take a
     message. Rules E2/E3/E5 remain their ONLY enforcement, at exactly the
     strength they had before #500. Each pass-through arm gains one unwrap
     where a bridge payload becomes a wrapper `String`, sitting immediately
     beside the wrapper's own construction site, so it is a PROJECTION, not
     a gate (design §4). Mind the SPELLING, because the obvious one denies:
     every gated-field initializer THAT UNWRAPS A BRIDGE PAYLOAD routes
     through `detail::project(d)`, whose whole body is the single
     `Detail::into_string()` — 25 such sites in ffi-uniffi, 2 in ffi-py
     (`repair_preview.rs:45,83`) — because the inline
     `detail: detail.into_string()` matches no E3 arm (`WP6`). `project` is
     NOT a fourth shape: it is a call into the crate's sanctioned module,
     the same `detail::*` shape listed in E3 above. The wrapper's OWN
     authored diagnostics never held a `Detail` and take the other shapes
     — ffi-uniffi has 19 such production initializers, 13 string literals
     plus 6 further `detail::*` constructor calls. ffi-py's 17 BARE
     `.into_string()` calls in `errors.rs` are all `new_err(...)`
     ARGUMENTS, a position E3 does not read at all. RECEIVER CENSUS,
     re-derived in final review, where the earlier wording ("17 bare
     `detail.into_string()` calls") was wrong about the RECEIVER though
     not about the count or the position: 11 of the 17 have receiver
     `detail`; the other SIX carry a different gated name — 4 `uuid_hex`
     (`errors.rs:135,140,180,183`), 1 `recipient_fingerprint_hex` (`:163`)
     and 1 `block_uuid_hex` (`:208`). An 18th `.into_string()` exists and
     is NOT one of these: `detail.rs:126`, the whole body of `project`.
  2. THE GUARANTEE IS PER DECLARATION, NOT PER ROOT. It covers the 27
     fields that ARE declared with the bridge's real `Detail`. A NEW bridge
     error type can still declare its gated field as a RENAMING IMPORT of
     `String` — `use std::string::String as Detail;` — which compiles, and
     which BOTH E2 and E3 pass (verified by execution: that declaration
     plus an E3 arm-4 parameter re-wrap `fn f(detail: Detail) -> E { E::V {
     detail: detail } }` scans with ZERO findings — and so does the FIELD
     SHORTHAND spelling `E::V { detail }`, by a DIFFERENT route: shorthand
     produces no `detail:` token, so it is never a candidate at all, where
     the explicit spelling IS a candidate that arm 4 then accepts. Earlier
     drafts of this paragraph showed the shorthand while attributing it to
     arm 4; the zero-findings result is right either way, the attribution
     was not). `discover_local_detail_decoys`
     catches a local DECLARATION of a decoy `Detail`, never an IMPORT of
     one; this is the same aliasing blind spot E4 records for `GatedDetail`,
     reached here through E2's carve-out. The cause is that `Detail` is
     matched by SPELLING everywhere in this guard — nothing resolves the
     name to `secretary_ffi_bridge::Detail`. TRACKED BY #512, which covers
     this and its `GatedDetail` twin as one root cause.
  3. `Detail` IS NOT A SECRET-FREEDOM CLAIM ABOUT ITS NEIGHBOURS. It claims
     one thing: this string came out of a reviewed constructor. E2's
     declaration sweep covers `#[error(`-attributed types plus PLAIN-derive
     types whose name ends `Error`/`Warning`; `FfiAddedRecipient` and
     `FfiWideningReport` (`repair/preview.rs`) are NEITHER, so E2 does not
     sweep them at all and for their `uuid_hex` / `block_uuid_hex` fields
     the newtype is the ONLY declaration-level enforcement. Their sibling
     `display_name` / `block_name` fields deliberately carry DECRYPTED
     PLAINTEXT and stay `String` — a `Detail` beside a plaintext `String`
     is correct there, not an inconsistency to "clean up".
  4. IT IS A CLAIM ABOUT THE ASSIGNMENT, NOT ABOUT REACHABILITY OF EVERY
     RUNTIME STRING. "A `String` does not typecheck in the position" does
     NOT mean "no runtime text reaches a gated field". No sanctioned
     constructor accepts a caller-supplied `String`/`&str`, but `gated` and
     its siblings take `&impl GatedDetail`, and one allowlisted impl —
     `std::io::Error` — is a CARRIER whose `Display` renders whatever it
     was built from, so `detail::gated(&io::Error::other(runtime))` still
     reaches a gated field FROM INSIDE THE BRIDGE CRATE. That is the
     documented, control-corpus-ACCEPTED class, not a hole this newtype
     claims to close; what it closes is the far larger surface of a bare
     `String` arriving from anywhere, and for DOWNSTREAM crates it closes
     that completely, since they cannot name `GatedDetail` (`pub(crate)`
     and sealed). The `test-support` hatch is the other in-crate way to
     mint a `Detail` from runtime text — see its own LIMITS bullet below.
     `error/detail.rs`'s `Detail` doc comment states this same scope.

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
  field in a DIFFERENT root. The wrapper roots take rules E1/E2/E3 and rule
  E5 (#486 task 11, `payload_guard/rules/e5.py`), which the bridge
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
  WHERE THIS WHOLE SUB-LIST APPLIES, as of #500: the shapes below are
  what E3's TEXT does not see, and they remain exactly that on the TWO
  WRAPPER ROOTS, whose error types keep `detail: String`. On the BRIDGE
  they no longer reach a gated field at all — those 27 fields are the
  `Detail` newtype, so every shape here fails to TYPECHECK rather than
  merely evading a regex (see "THE #500 NEWTYPE" above, including the
  renaming-import boundary on that guarantee). Read the list as
  "wrapper-root gaps, plus bridge defence-in-depth", not as "tree-wide
  gaps"; and note that E3 still RUNS on the bridge, so a finding here is
  still a legible finding rather than a trait-bound error.
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
    (c) arm 4's PARAMETER case: `fn f(detail: String) -> E { E::V {
        detail: detail } }` trusts the name of a value this guard never
        watched being built. MIND THE SPELLING — earlier drafts wrote this
        example with FIELD SHORTHAND (`E::V { detail }`), which arm 4 never
        sees: shorthand has no `:` and therefore produces no candidate at
        all, so it evades this rule at the DETECTION step rather than being
        accepted at the classification step. Both scan clean, so the gap is
        real under either spelling; only the attribution differed.
        `rules/e3.py`'s arm-4 docstring has always used the correct
        `detail: detail` spelling — this text is what drifted from it.
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
  same reason.
  LIVE PRODUCERS, corrected in #496 and RE-CENSUSED in #500 — an earlier
  version of this paragraph claimed "none of (a)/(b)/(c)/(d) has a live
  producer today", which was wrong for two of the four and is exactly the
  overclaim class this branch kept re-finding. Shapes (b) and (d) still
  have none anywhere. The #500 census (`grep -rnE '\{\s*(detail|uuid_hex|
  …)\s*(,|\}|\.\.)'` over all three FFI roots):
    - Shape (a) on the BRIDGE has THREE production sites, CORRECTED in
      final review from a "two" this branch itself made stale:
      `error/conversions.rs:25` and `:27` (`FfiUnlockError::X { detail } =>
      FfiVaultError::X { detail }`), plus `error/detail.rs:285`
      (`VaultError::RepairRejected { detail, .. } => Detail(detail
      .clone())`). That third site is SHIPPED code — `detail.rs`'s
      `#[cfg(test)]` begins at line 387 — and #500's own fix round
      introduced it, in the commit that REPLACED the `error/vault/mod.rs:
      558` site this paragraph used to name with a `detail::
      repair_rejection(e)` call. The bind moved INTO the sanctioned module;
      it did not disappear. It is not a leak: it destructures a `core`
      payload that core's OWN rule-E1 entry gates (allowlist Section 3,
      `vault/mod.rs — RepairRejected`), and it sits inside `detail.rs`,
      where building a `Detail` is the file's entire job. Every OTHER
      bridge match of the census grep is test code, an `#[error(...)]`
      attribute, a COMMENT of either form — four plain `//` LINE comments
      (`repair/orchestration.rs:133`, `error/vault/mod.rs:493`, `:501`,
      `:511`) plus one `///` DOC comment (`error/unlock.rs:57`), all five
      shipped rather than test code — or a `{detail}` interpolation in an
      assertion message. None of which is a pattern bind. ("a doc comment"
      alone was wrong for four of the five, and is corrected here rather
      than generalised away, since naming the two forms is what lets a
      re-reviewer reproduce the split.)
    - Shape (a) on the WRAPPER roots, counted exactly rather than sampled:
      34 production binds, ALL of them destructuring a BRIDGE `Ffi*` error,
      so all 34 bind a `Detail` and not a `String`. Binds of a wrapper's
      OWN `String`-typed gated field number 37 and are ALL inside
      `#[cfg(test)]` — production count ZERO.
    - Shape (c) is the form EVERY shipped re-wrap site takes (`rules/e3.py`'s
      arm-4 docstring says so directly).
  Every one of them re-wraps an already-gated value — verified by reading
  each — so none is a leak. What #500 CHANGED about the risk posture is
  narrow and worth stating exactly: on the bridge these positions now carry
  a `Detail`, so a future producer adopting the shape for an ungated value
  fails to COMPILE rather than being invisible. On the two wrapper roots
  nothing changed — the position stays unwatched and in daily use, which is
  a materially different risk posture from "theoretical".
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
  ffi/secretary-ffi-py/src ffi/secretary-ffi-uniffi/src` returns NINE
  hits and zero live composition sites today (three are `String::from\s*\(`
  matching as a substring of `SecretString::from(`; four are
  `core_test_data_dir().join(...)` — `Path::join`, not `str`/`String`
  `.join()`, all four `#[cfg(test)]`-only; and TWO — re-derived in final
  review, where this count still read "seven" — are
  `ffi/secretary-ffi-py/src/detail.rs:17-18`, the doc comment that NAMES
  these very constructs, i.e. the census matching its own prose). The
  SUBSTANCE is unchanged by the correction: zero live composition sites
  either way. `push_str` and `write!` /
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
  Two MORE evasions of the same rule were found in #496's review and are
  not in that census: `use std::format as fmt2;` then `fmt2!(...)` — the
  macro-RENAME blind spot, structurally identical to the `use
  detail::GatedDetail as GD;` one rule E4 discloses — and
  `std::fmt::format(format_args!("{e}"))`, which is literally what
  `format!` expands to. Both compile and both pass E5 today. Neither has a
  live producer.
- RULE E5's `#[cfg(test)]` CARVE-OUT is not visible from the rule's summary
  above (#496). E5 skips any `format!` inside a `#[cfg(test)]` span, and
  ten live sites depend on it — the `let rendered = format!("{err}")`
  assertions in `ffi/secretary-ffi-uniffi/src/errors/vault.rs` (9) and
  `errors/unlock.rs` (1). `WN3` is the only thing pinning it.
- RULE E3's SANCTIONED-CONSTRUCTOR REGISTRY reads SIGNATURES as of #496.
  Before #496 the registry captured a constructor's NAME and nothing else,
  which made it SELF-AUTHORISING: it derives its allowlist from the very
  file it constrains, so `pub(crate) fn passthrough(x: &str) -> String`
  added to any root's `detail.rs` sanctioned an arbitrary runtime string at
  every call site, with the whole guard green (verified by execution; `BP49`
  pins the fix). Every parameter type must now sit in `SAFE_PARAM_TYPES`.
  ITS TWO `&str` EXCEPTIONS ARE CLOSED, not a residual any more (#504,
  closed the same way SHAPE 5 below was). `STR_PARAM_CTOR_EXCEPTIONS` used
  to pin two ffi-py constructors (`fingerprint_mismatch`, `uuid_prefixed`)
  that legitimately took `&str` because they only COMBINE already-gated
  bridge values — a point-in-time review claim of exactly the kind
  allowlist Section 3 holds, verified by reading the two constructors but
  not enforced: nothing checked what a given call site actually passed
  there. Both now take `&Detail` instead, so `STR_PARAM_CTOR_EXCEPTIONS` is
  EMPTY and a future `&str`-taking constructor fails this guard until
  someone deliberately re-populates the set — the review checkpoint the
  bare-name registry never had.
  `Detail` joined `SAFE_PARAM_TYPES` in #500 and is the one member that is
  NOT a residual of this kind: its inner field is private to the bridge's
  `error/detail.rs`, so the type system — not a review claim — establishes
  that a value in the position came out of a sanctioned constructor. It is
  what admits each wrapper crate's `pub(crate) fn project(d: Detail) ->
  String`, the single named home for the unwrap uniffi's UDL `string` and
  PyO3's exception messages require. `WN4` pins the acceptance (removing
  `Detail` from the set fires it AND reds the real scan at 27 sites); `WP6`
  pins that the widening did NOT also legalise the inline spelling
  `detail: detail.into_string()`, which matches no accepted shape.
  QUALIFIED: "structural" holds only while `Detail` in that position RESOLVES
  to `secretary_ffi_bridge::Detail`. The rule compares the SPELLING. A local
  decoy declaration in a wrapper's own `detail.rs`
  (`pub(crate) struct Detail(pub String);` beside
  `fn launder(d: Detail) -> String`) once made
  `detail::launder(Detail(anything))` scan OK — verified by execution — and is
  now rejected wherever `ScanRoot.owns_detail_type` is False (only the bridge
  declares the real type), pinned by `WP8`. An IMPORT remains invisible in
  BOTH its forms — the renaming `use other_crate::X as Detail;` and the plain
  `use crate::evil::Detail;` that pulls a same-named decoy in from a sibling
  file. Neither declares anything in the sanctioned module, so
  `LOCAL_DETAIL_TYPE_RE` cannot see them; this is the same aliasing blind spot
  `E4` records for `GatedDetail`.
  `&impl GatedDetail` IS THE SAME DECOY HOLE ONE TYPE OVER, and it is closed
  the same way and carries the same residual (#504 review R3). A wrapper
  crate cannot implement the BRIDGE's `GatedDetail` — it is `pub(crate)` and
  sealed — but nothing stops one DECLARING its own `trait GatedDetail`,
  implementing it for `String`, and writing `pub(crate) fn launder(d: &impl
  GatedDetail) -> String`, reproducing the bypass exactly. A separate
  withdrawal (`_ctor_params_are_safe`'s `gated_detail_param_ok`, driven by
  `LOCAL_GATED_DETAIL_TRAIT_RE`) drops every `GatedDetail`-naming spelling on
  any root that does not own the type; `WP11` pins it, and zero live wrapper
  constructors take `&impl GatedDetail` today, so it closed with no call-site
  fallout. It is kept SEPARATE from the `Detail` withdrawal rather than folded
  into one wider regex so a decoy of one kind can never paper over a missing
  withdrawal for the other. RESIDUAL, verified by execution and identical to
  `LOCAL_DETAIL_TYPE_RE`'s: an IMPORT evades it in both forms —
  `use crate::zz_evil::GatedDetail;` written INSIDE the wrapper's own
  `detail.rs`, with the decoy trait declared in a SIBLING FILE of the same
  crate, leaves `launder(d: &impl GatedDetail)` sanctioned and the whole scan
  green. That is parity with a disclosed blind spot, not a regression, but it
  is an unstated limit on an otherwise brand-new control unless recorded here.
  BOTH withdrawals are suppressed by the SAME flag, `ScanRoot.
  owns_detail_type` — so setting it `True` on a wrapper root re-opens TWO
  decoy classes, not one.
  The same spelling caveat applies to `&secretary_core::vault::VaultError`,
  added in the #500 fix round for `detail::repair_rejection`. It grants
  nothing new — `&impl GatedDetail` is already in the set and `VaultError` is
  one of the E4-reviewed impls — but naming the concrete type lets that one
  constructor destructure core's `RepairRejected { detail }` inside
  `detail.rs`, which is what made its predecessor's `String` parameter (and
  the per-file allowlist row it needed) unnecessary.
- RULE E3's SHAPE 5 is CLOSED, not a limit any more (#497, closed by #500).
  It accepted an ARBITRARY single-hop receiver (`<anything>.detail`) on the
  wrapper roots, not just a bridge DTO: the justification recorded for
  granting it — "the source is a bridge DTO whose fields rules E2/E3 gate" —
  was a property of the four LIVE sites, not of the shape the rule accepts,
  and a local of any type, including one declared outside every scan root,
  satisfied it. #500 moved all four sites onto `detail::project(...)`, a
  sanctioned-constructor call, leaving the acceptance with ZERO users;
  `ScanRoot.allow_field_access` is now `False` on every root, so the shape
  denies everywhere. `WP7` pins the denial and fires the moment either
  wrapper root turns it back on. The regex and the arm are retained so a
  future DTO can re-enable them WITH live sites and a fresh review.
- RULE E2's GATED-FIELD CARVE-OUT MATCHES A TYPE SPELLING, and the decoy
  withdrawal that guards it (`discover_local_detail_decoys`,
  `payload_guard/discovery.py`) sees DECLARATIONS ONLY. It scans the whole
  root EXCEPT the root's own sanctioned module, so a second
  `struct|enum|union|type Detail` anywhere else withdraws the spelling from
  the carve-out entirely (`BP54`/`BP55` pin the struct and enum forms,
  `BN29` pins that the bridge's own declaration does not shadow itself).
  Its FIVE uncaught shapes are enumerated in its own docstring; the one
  worth repeating here because it bears directly on the newtype claim is
  the IMPORT — `use std::string::String as Detail;` in a bridge file makes a
  NEW gated field declared `detail: Detail` a plain `String`, and that
  declaration plus an E3 arm-4 parameter re-wrap scans with ZERO findings
  (verified by execution; tracked by #512). See "THE #500 NEWTYPE"
  boundary 2 above: the compiler guarantee is per DECLARATION, and this
  guard resolves no names.
- THE `test-support` FEATURE IS A BUILD-CONFIGURATION GUARANTEE, NOT A
  LANGUAGE ONE (#500). `Detail::for_test` (`ffi/secretary-ffi-bridge/src/
  error/detail.rs`) mints a `Detail` from arbitrary runtime text, and it is
  absent from shipped artifacts ONLY because Cargo's resolver v2 declines to
  unify a DEV-dependency's requested features into a non-test build.
  Enabling the feature on a normal dependency line — or through a feature
  ALIAS that transitively reaches it — puts the hatch back.
  `scripts/check-test-support-placement.py` denies that line, and
  `cargo build --release --workspace` in CI catches a PRODUCTION CALL to a
  hatch that should not exist. Neither is the compiler refusing to express
  the thing. WHICH GATES ARE BLIND, measured on this workspace rather than
  assumed (#500 Task 3 Step 6b; `detail.rs`'s `for_test` docstring records
  the run, design §5.1 the table): with a production call to the hatch
  planted in the bridge, `cargo test --release --workspace` reported **0**
  errors and `cargo clippy --release --workspace --tests` **0** — those two
  are blind, and they are the two a contributor runs by habit. The three
  that caught it: `cargo build --release --workspace` (2),
  `cargo clippy --release --workspace` with no `--tests` (2), and the
  rustdoc gate (4). The RUSTDOC row does not generalise and must not be
  quoted without its condition: rustdoc does not type-check the bodies of
  the crate it is DOCUMENTING, and catches this only because `ffi-py`,
  `ffi-uniffi` and `desktop/src-tauri` depend on the bridge, so documenting
  them builds its rmeta. The same leak in a LEAF crate — which both wrapper
  crates are — scans clean (design §5.1.1). `cargo build` is therefore the
  gate that has to exist for this to be enforced anywhere.
- `&'static str` IS NOT LEAK-PROOF, and several rules lean on it. Safe,
  stable Rust can mint one from runtime data via `Box::leak(s.into_
  boxed_str())` or `String::leak()`; `#![forbid(unsafe_code)]` does not
  stop either. So a `&'static str` parameter — in `SAFE_PARAM_TYPES`, in
  a sanctioned constructor's `context`/`field`/`advice` position, or in a
  `core` payload's map-level hint — DISCOURAGES a runtime string rather
  than making one unrepresentable.
  BOTH HALVES of this bullet's closing sentence used to be FALSE, and both
  are corrected here rather than softened (#498's cheaper half, #500 Task
  5). It read "Every live site passes a literal … and nothing enforces
  that."
    * "NOTHING ENFORCES IT" is now wrong for ONE position: rule E3
      requires every HINT-POSITION argument at a sanctioned `detail::*`
      call site to be a string-literal TOKEN, not merely an expression of
      `&'static str` type. Hint positions are derived from each
      constructor's OWN signature, so the check cannot drift from a
      hand-maintained name list. `BP52` pins the `Box::leak` attack,
      `BN30`/`BN31`/`BN32` pin that a plain, a RAW-string and a
      multi-line literal still pass. It is still nothing at all for the
      other two positions: a `core` payload's map-level hint (E1 sees
      only the DECLARATION `&'static str`, never the producer) and a
      `SAFE_PARAM_TYPES` parameter reached any way other than a gated
      construction site.
    * "EVERY LIVE SITE PASSES A LITERAL" is wrong by SIX THAT RULE E3
      CAN SEE — and by NINE in the tree, once the three E3 cannot see
      are counted too (both figures re-derived by grep in final review;
      the bare "six" was a scope error, stating an E3-visible subtotal
      as if it were the tree total, in the one bullet this branch
      rewrote BECAUSE both its halves were previously false).
      The SIX E3 SEES, all pre-dating this branch (`git show 3775ef5:`
      confirms): `error/detail.rs`'s own internal re-forward, plus five
      in `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`
      (`uuid_from_vec`, `array32_from_vec_into`, `uuid_from_vec_at`,
      `array32_from_vec_at`, `uuid_from_vec_nested_at`). Each forwards
      its OWN `&'static str` parameter one hop. All 54 production call
      sites across those six enclosing functions were read and do pass a
      literal, and the six are recorded as individually justified
      allowlist entries (Section 5) rather than waved through by
      widening the rule — an "any function forwarding its own
      `&'static str`" shape rule is not enforcement but a strictly WIDER
      acceptance, and would delete the checkpoint a new direct forwarder
      currently trips.
      THE THREE E3 CANNOT SEE are in `ffi/secretary-ffi-py/src/errors.rs`
      — `:231`, `:249-254` and `:265` (`uuid_array_or_value_error`,
      `indexed_uuid_array_or_value_error`, `array32_or_value_error`) —
      each forwarding its own `field: &'static str` one hop into
      `crate::detail::arg_len` / `indexed_arg_len`, the IDENTICAL shape
      the six Section 5 rows exist for. They sit in
      `PyValueError::new_err(...)` ARGUMENT position, and
      `_hint_args_are_literal` is reachable only from
      `initializer_is_gated`, so E3 never inspects them: no finding, no
      Section 5 row, and their 43 call sites (40 + 1 + 2, by grep) fall
      OUTSIDE the "54 call sites were read" claim above. The source
      comments at `errors.rs:224-228` and `:237-242` do record a by-hand
      review, so this is a SCOPE error rather than an unreviewed hole —
      but the same argument-position blindness that hides them is what
      **#498** owns structurally: an `enum ArgField` replacing the
      `&'static str` parameter removes the shape on both sides of the
      E3 visibility line at once.
  This WATCHES the door; it does not remove it. Unlike the `Detail`
  newtype, a text rule cannot make a leaked `&'static str`
  unrepresentable. The structural fix — a closed `enum Context`, or for
  the five uniffi cases a closed `enum ArgField` in that crate's own
  `detail.rs` — is the only thing that would, and **#498 stays OPEN**
  recording exactly that.
- RULE E3's SECTION-5 ENTRIES HAVE TWO EVASIONS THAT SCAN CLEAN, and no
  mechanical re-verification hook (#498, both verified by execution).
    (i) CALLER-SIDE LEAK: `uuid_from_vec(bytes, e.to_string().leak())` at
        ANY caller of an allowlisted helper reaches the same hint position
        the Section 5 entry vouches for. There is no `format!` anywhere in
        it, so rule E5 has nothing to say either. Confirmed: zero findings.
    (ii) CHAIN: a new pass-through wrapper — `fn uuid_for(b: &[u8], field:
        &'static str) -> X { uuid_from_vec(b, field) }` — creates NO
        gated-field construction site of its own (its body is a plain
        function call, not a `detail:`-named initializer), so it produces
        NO FINDING AT ALL, not even one Section 5 could allowlist. Each
        entry covers only the FIRST hop out of the allowlisted helper.
  The "re-verify on any edit" instruction on those entries has NO
  MECHANICAL HOOK: E3 keys an allowlist entry on the exact construction-
  site text INSIDE the allowlisted helper, which does not change when a
  caller in ANOTHER FILE is added, removed, or starts building the
  forwarded argument at runtime. Re-verification there is purely human-
  review discipline — a materially weaker claim than "this file changed
  and the diff was reviewed."
- `#[cfg(test)]` exclusion is PER FILE. A module whose `mod` declaration is
  gated in its PARENT (`#[cfg(test)] mod tests;` in `error/vault/mod.rs`)
  is a whole test-only FILE this guard has no way to recognise from inside,
  so its construction sites — `payload_guard/rules/e3.py`'s
  `scan_bridge_construction_sites`, via `discovery_cfg_test_spans_strict`
  in `payload_guard/discovery.py` — are scanned like shipped ones. That is
  the fail-closed direction — findings in test code, never a missed shipped
  one — and the remedy is an allowlist entry naming the parent's gate.
  The `_strict` matcher is #496's split: these spans are consumed in TWO
  opposite polarities, and one matcher cannot serve both. For the CREDIT
  registries (`discover_declarations`, `sanctioned_constructor_names`) an
  over-match drops a declaration, so fewer names vouch for anything —
  fail-closed, and the permissive `\btest\b` form is right. For the SKIP
  LISTS (rules E2/E3/E5, `discover_error_struct_declarations`) an
  over-match means NOT SCANNING a shipped item — fail-OPEN, and under the
  permissive form `#[cfg(not(test))]`, any `#[cfg_attr(test, ...)]`, and
  `#[cfg(all(feature = "x", not(test)))]` each silenced a real violation
  with one attribute line (verified by execution; `BP47`/`BP48`/`WP5` pin
  the fix, `BN25`/`BN26` prove it did not over-tighten). This is the
  "the fail-closed argument is per-PASS, not global" lesson recurring.
- SCAN ROOTS ARE VALIDATED before the scan (#496). `Path.rglob` on a
  non-existent directory returns an empty generator rather than raising,
  so a root that moved used to contribute zero files and the guard printed
  OK with a whole crate unscanned — fail-open for the bridge and both
  wrapper roots (only `core` failed closed, and only incidentally, because
  rule E4's registry is built from core types). `run_real_scan` now fails
  hard if any root is not a directory or holds no `.rs` file, and
  `--self-test` pins the per-root RULE MATRIX (`_EXPECTED_ROOT_FLAGS`)
  plus dispatches its own controls off the same flags, so switching a rule
  off in `roots.py` breaks controls instead of passing silently.
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

OPEN ISSUES AGAINST THIS GUARD (#500 Task 8)
----------------------------------------------
Every gap above that has a tracker number, in one place, so a reader of THIS
file — the one CLAUDE.md calls authoritative — does not have to reconstruct
the register from prose. CLAUDE.md's guard section carries the same list;
the two are a DELIBERATE two-site register and must be edited together.
Filing a new one means adding it here AND there.

- #494  An `io::Error` minted from a runtime string at
        `cli/src/daemon.rs:424`, in a tree no scan root covers. The shape
        is `std::io::Error::other(err.to_string())` over a
        `notify::Error` — NOT a `format!`, as this line and CLAUDE.md's
        twin both said until final review re-read it (`cli/src/daemon.rs`
        contains zero `format!`). The gap is the same either way: rule E3
        gates the io payload ARGUMENT, and nothing gates it out of root.
        Not reachable from the bridge today.
- #495  `payload_guard/discovery.py` is two unrelated parsers in one file.
- #498  STRUCTURAL half only. Its cheaper half (E3's string-literal hint
        rule) landed in #500; a closed `enum Context` / `enum ArgField` is
        what would make a leaked `&'static str` unrepresentable. See the
        `&'static str` bullet above — do not write #498 as closed.
- #499  E5 misses two spellings of `format!` itself: a macro RENAME
        (`use std::format as fmt2;`) and `std::fmt::format(format_args!(…))`.
- #501  ffi-py's pytest suite never runs in CI.
- #502  `desktop/src-tauri` builds its own `AppError { detail: String }`
        outside every scan root.
- #505  `check-test-support-placement.py`'s `DEFAULT_ROOTS` completeness is
        unproven — a manifest under an unlisted root is unscanned.
- #506  That same script is 1253 lines and wants this package's treatment.
- #507  `payload_guard/lexer.py` cites a control `BP46` that has never
        existed, so one of its C-string claims is pinned by nothing.
- #508  E3 shape 5's internals are unpinned while `allow_field_access` is
        `False` everywhere — re-enabling it would restore untested code.
- #509  E3 arm 3 accepts a bare `String` token on the WRAPPER roots, where
        `String` is still the declared gated type — a let-binding laundering
        shape the bridge no longer has.
- #510  `Path.rglob` does not recurse SYMLINKED directories, so a symlinked
        source tree is invisible to EVERY rule here.
- #511  The control corpora have no uniqueness check over labels; a
        duplicate is caught only by grep. Not hypothetical — a `WP9`
        collision during #500 was found by an implementer running grep.
- #512  A RENAMING IMPORT defeats the `Detail` newtype's E2 credit: the
        compiler guarantee is per DECLARATION, not per root. Covers the
        `GatedDetail` trait twin as the same root cause — this guard matches
        by spelling and never resolves a name. See "THE #500 NEWTYPE"
        boundary 2.
- #514  `check-test-support-placement.py`'s manifest discovery has the
        SAME `Path.rglob` symlink gap #510 records for this package, plus
        a `target` path-COMPONENT exclusion that drops a legitimately-named
        subtree. #510 is scoped to `payload_guard`, so nothing tracked the
        placement guard's copies until this. Latent, not live: no directory
        symlink and no non-build `target` directory on the workspace path
        today.

CLOSED IN CODE by #500, and described above as closed: #497 (E3 shape 5
retired), #503, #504 (`STR_PARAM_CTOR_EXCEPTIONS` emptied). Their GitHub
issues may still read OPEN — this repo cites fixes as `(#N)`, never
`Closes #N`, so an issue outlives its fix until a human closes it.
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
