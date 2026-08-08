"""Rule E1's self-test control corpus (#474, #486): `POSITIVE_CONTROLS` /
`NEGATIVE_CONTROLS`, run through `payload_guard.selftest.scan_control`.

Moved out of the former single-file `scripts/check-error-payload-hygiene.py`
in #486 (task 5). Each control is self-contained Rust source text (declares
any nested enum / alias / const / `use` it references in the same string),
so the harness exercises the real discovery, collision-drop and
import-shadow code paths rather than a hardcoded name list. Read the entry
point's module docstring first for the WHY.
"""

from __future__ import annotations

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
