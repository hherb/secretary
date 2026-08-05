# Design — #474: secret-free error payloads in `core`, enforced

**Issue:** #474 — `RecordError::DuplicateKey` embeds a decrypted field name in its message.
**Scope agreed with the user:** the whole class, plus enforcement (option "C").
**Branch:** `feature/474-error-payload-hygiene`.

## Problem

`core/src/vault/record.rs:661` formats a decrypted CBOR field name into an error
message:

```rust
return Err(RecordError::DuplicateKey { key: fname });   // #[error("duplicate map key: {key}")]
```

That string reaches both platform UIs verbatim. On iOS it lands in
`VaultAccessError.corruptVault(String)`, which is logged at `privacy: .public`;
on Android it lands in `VaultBrowseError.SaveCryptoFailure(detail)`, which reaches
logcat, where there is no redaction concept at all. A user's field name —
`"amex-cvv"`, `"ex-wife-lawyer-password"` — is exactly the content both
`SecretFreeError` (#467) and `SecretFreeThrowable` (#472) promise never to emit.

Both platforms currently defend by **redacting the whole arm**:

```swift
case .corruptVault: return "corruptVault(<redacted>)"          // SecretFreeError.swift:112
```
```kotlin
is SaveCryptoFailure -> "SaveCryptoFailure(<redacted>)"        // VaultBrowseError.kt:78
```

That is the fail-closed side of a bad trade. It costs the detail string for
*every* corruption and save-crypto diagnostic, not just the duplicate-key case,
because the payload is Rust-authored and therefore unreviewable at the platform
boundary.

### The issue understates the surface by an order of magnitude

The issue names one site. A sweep of every `#[error(...)]` attribute in
`core/src/**/*.rs` finds **129 variants that interpolate anything** and
**23 that interpolate a runtime `String`**. Of those 23:

- `RecordError::DuplicateKey` has **three** construction sites
  (`record.rs:587`, `:661`, `:692`), not one.
- **`BlockError::DuplicateKey` (`block.rs:313`, built at `:1008`) is the
  identical leak, and is not mentioned in the issue.** It carries a decrypted
  block-plaintext map key.
- **`BundleError::UnknownField(String)` (`bundle.rs:116`, built at `:406`)**
  carries an arbitrary map key read from the decrypted identity bundle.
- Six variants stringify a `ciborium` error.

### The `ciborium` family is safe today only by a traced upstream claim

`ciborium::de::Error<T>` implements `Display` as `write!(f, "{:?}", self)` — the
**Debug** rendering. One of its variants is `Semantic(Option<usize>, String)`,
whose `String` is a `serde::de::Error::custom` message. Serde's standard
`invalid_type` / `invalid_value` messages embed the offending value
(`invalid type: string "hunter2", expected u64`).

Every production `from_reader` call in `core` deserializes into
`ciborium::value::Value`, whose `Deserialize` impl accepts any CBOR item and so
cannot raise a value-bearing `Semantic`. Verified across all seven production
call sites (`record.rs:250,531`, `block.rs:914,927,963`, `manifest.rs:632,662`,
`card.rs:284`, `bundle.rs:339`, `sync/state.rs:136`).

**That is a content-traced claim about a third-party crate.** A `ciborium`
version bump, or one future `from_reader::<SomeStruct, _>` call, invalidates it
with no diff anywhere near the error definitions and no failing test. It is the
same drift class that made `SaveCryptoFailure` unsafe, and it is why option "A"
(fix `DuplicateKey`, narrow the iOS redaction) cannot honestly deliver its own
second acceptance bullet: narrowing `.corruptVault` while six ciborium
passthroughs remain would trade a fail-closed redaction for a plausibility
argument.

## Approach

Three moves, in order:

1. **Make the plaintext-bearing payloads structurally impossible** — replace the
   `String` with a compile-time-constant hint plus an ordinal.
2. **Make the ciborium passthrough structurally impossible** — classify the
   upstream error into a data-free discriminant at the boundary and never carry
   its message.
3. **Make regression loud on the Rust side** — a fail-closed CI guard that flags
   any new `#[error]` variant interpolating a runtime `String`, so the failure
   lands in the pull request of the author who introduced it rather than
   silently degrading a platform two layers away.

Only then do the platform redactions come off. The sequence matters: the
narrowing is sound *because* of steps 1–3, not alongside them.

### Why an index and not a hash

A truncated hash of the key would let a reader correlate the two duplicate
occurrences. It is rejected: CBOR field names are extremely low-entropy
(`password`, `username`, `totp`, `notes`), so a hash is invertible by a rainbow
table of a few thousand candidates. It would *look* secret-free while still
disclosing the field name — worse than an index, because it invites false
confidence.

## Components

### 1. Group 1 — plaintext-bearing payloads

| Variant | Today | Becomes |
|---|---|---|
| `RecordError::DuplicateKey` (`record.rs:163`) | `{ key: String }` | `{ field: &'static str, index: usize }` |
| `BlockError::DuplicateKey` (`block.rs:313`) | `{ key: String }` | `{ field: &'static str, index: usize }` |
| `BundleError::UnknownField` (`bundle.rs:116`) | `(String)` | `{ index: usize }` |

**Addition (final review): two `CardError` changes this section omitted.**
Task 5 shipped them and they are Group-1-class, not Group-2 — this section
previously mentioned `CardError` only for its `CborEncode` / `CborDecode`
arms, so a reader working from this doc alone would not know they exist.

| Variant | Today | Becomes |
|---|---|---|
| `CardError::UnknownField` | folded into `CborDecode(format!("unknown card field: {other}"))` (`card.rs:349-351` on `main`) | `{ index: usize }` |
| `CardError::DuplicateField` | *(did not exist — `set_once` had no dedicated arm)* | `{ field: &'static str }` |

`UnknownField` is the sharper of the two: a Contact Card is public by design,
so its keys are not vault plaintext, but the key is arbitrary text from an
**untrusted party**, and formatting untrusted text into a diagnostic that
reaches a log is its own hazard. It carries the entry's 0-based ordinal
instead, rendered 1-based — the same shape as `RecordError::DuplicateKey`.
`DuplicateField` is raised from `set_once`, reached only after the
unknown-key arm has rejected everything outside the §6 set, so its payload is
always one of the fixed `KEY_*` constants: `&'static str`, no information
lost. (Note the shape asymmetry with `BundleError::DuplicateField(&'static str)`,
which is a tuple: `CardError`'s is a named-field struct. Deliberately left
alone — the two enums are independent surfaces and churning one to match the
other buys nothing.)

New message: `"duplicate map key at entry #3 of fields"`.

`field` is a `&'static str` naming the map level, taken from the convention
already established by `RecordError::FloatRejected { field: &'static str }`
(`"<root>"` / `"<unknown>"`):

| Construction site | `field` |
|---|---|
| `record.rs:587` — record-level map | `"<record>"` |
| `record.rs:661` — the `fields` map | `"fields"` |
| `record.rs:692` — field-level map | `"<field>"` |
| `block.rs:1008` — block plaintext map | `"<block>"` |

This is **strictly more diagnostic information than today's message**: a reader
learns which of the four map levels raised the error, which the raw key name does
not reliably convey. And a `&'static str` is a compile-time constant — it cannot
carry runtime data, the same argument `SecretFreeThrowable`'s cause-chain
type-name rendering rests on.

`index` is the 0-based ordinal of the offending entry within its map, rendered
1-based in the message. This mirrors `MnemonicError::UnknownWord { index }`
(`mnemonic.rs:55`, `#[error("recovery-phrase word #{} …", .index + 1)]`), which
the issue itself cites as the right pattern.

`BundleError::DuplicateField(String)` gets a free structural win. Its only
producer is `set_once` (`bundle.rs:503`), which is reached only after the
`other => return Err(UnknownField(...))` arm has rejected unrecognised keys — so
its payload is always one of the fixed `KEY_*` constants. It becomes
`DuplicateField(&'static str)`, no information lost.

### 2. Group 2 — the ciborium passthrough

New module `core/src/cbor.rs` (pure functions, no I/O, per the project's
reusable-module convention):

```rust
pub enum CborErrorKind { Io, Syntax, RecursionLimit, Semantic, Serialization }

pub struct CborFault { pub kind: CborErrorKind, pub offset: Option<usize> }

pub fn classify_de<E>(e: &ciborium::de::Error<E>) -> CborFault;
pub fn classify_ser<E>(e: &ciborium::ser::Error<E>) -> CborFault;
```

`classify_de` maps `Io → Io`, `Syntax(off) → { Syntax, Some(off) }`,
`Semantic(off, _msg) → { Semantic, off }` **discarding the message**, and
`RecursionLimitExceeded → RecursionLimit`. `classify_ser` maps
`Io → Io` and `Value(_msg) → Serialization`, likewise discarding.

Six variants change payload type from `String` to `CborFault`:

- `RecordError::CborEncode` / `CborDecode`
- `BlockError::CborEncode` / `CborDecode`
- `ManifestError::CborEncode` / `CborDecode`
- `CardError::CborEncode` / `CborDecode`
- `CanonicalError::CborEncode`
- `BundleError::CborError`

**Correction (final review).** An earlier revision of this paragraph read
"`SyncError::StateDecodeFailed` / `StateEncodeFailed` join this group — their
`detail: String` is built from `ciborium` at `sync/state.rs:136`." They did
**not** join it. Both still carry `detail: String` (`sync/error.rs:19`, `:22`)
and both are Section-3 **allowlist entries**, not payload-type changes. What
DID change is one layer down: `sync/state.rs:136` no longer stringifies the
`ciborium` error, it passes `format!("CBOR parse: {}", crate::cbor::classify_de(&e))`
— the classified, data-free `CborFault`. So the leak is closed at the producer
while the declared field type stayed `String`, which is exactly why the guard
(which sees declarations, not producers) still reports these two and a human
had to sign the allowlist entry.

The generic `E` parameter is why these were stringified originally: the doc
comment at `record.rs:110` explains that `ciborium::ser::Error<E>` is generic over
the writer's I/O error and so cannot be captured uniformly as a `#[from]` source.
`classify_ser<E>` sidesteps that by projecting to a non-generic type.

#### The deliberate residual disclosures

An earlier revision of this section was headed "The **one** deliberate residual
disclosure." There are at least **five**, all of the same kind — a position or a
length measured over decrypted plaintext — and two of them are introduced by this
work. Listing them all is the point of the section; naming only one made the
accepted trade look narrower than it is.

Introduced here:

- **`CborFault.offset`** — a byte offset into decrypted plaintext.
- **`RecordError::DuplicateKey.index` / `BlockError::DuplicateKey.index`** — the
  ordinal of the offending entry within its map. Strictly less than the key it
  replaces, but it is still positional metadata over plaintext.

Pre-existing, and reaching a log for the first time BECAUSE of this branch —
these three have been in `core` all along, but iOS's `.corruptVault` and
Android's `CorruptVault` / `SaveCryptoFailure` arms were redacted wholesale, so
nothing carrying them ever reached the unified log or logcat. §5 removes those
redactions, so they are now in scope and belong here:

- **`RecordError::InvalidUuid { length }`** (`record.rs:155`) — a byte count from
  decrypted record plaintext.
- **`BlockError::InvalidUuid { length }`** (`block.rs:307`) — the same, from
  decrypted block plaintext.
- **`ManifestError::InvalidByteLength { length }`** (`manifest.rs:170`) — the
  same, from the decrypted manifest body (`manifest.cbor.enc` is encrypted per
  vault-format §4).

All five are kept, on one argument. Vault file sizes are already visible on disk
to anyone who can read the folder, so the threat model already treats plaintext
*size* as disclosed; an offset, an ordinal, or a field's byte length is a weaker
signal than the file length an attacker with folder access reads for free. And
each is the single most useful datum when debugging a genuinely corrupt vault —
"duplicate at entry #3 of `fields`" is actionable in a way that "some map has a
duplicate" is not. Recorded so the decision is explicit rather than assumed away,
and so a future reviewer weighing a sixth has the list to weigh it against.

### 3. Group 3 — reviewed allowlist, no code change

| Variant | Why it is safe |
|---|---|
| `VaultTomlError::MalformedToml` / `UnknownKdfKey` / `UnsupportedKdfAlgorithm` / `UnsupportedKdfVersion` | `vault.toml` is **unencrypted on disk** — `docs/vault-format.md` §2 is titled "`vault.toml` — cleartext metadata" and the file's own header comment reads "cleartext; not secret". Its bytes are disclosed to anyone with the vault folder; the threat model treats them as public. `MalformedToml` needs the `toml` crate's message to be debuggable at all. |
| `VaultError::RestoreVerificationFailed { detail }` / `RepairRejected { detail }` | `detail` is built only from fixed string literals (`orchestrators.rs:2512`) and `format!("{e}")` over other `core` errors (`:2522`, `:2553`) — all of which this work gates. |

**Correction (final review).** An earlier revision of this paragraph read
"`SyncError::InvalidArgument { detail: String }` gets a free structural win
rather than an allowlist entry: all three producers (`sync/error.rs:111`,
`sync/state.rs:56`, `:61`) pass fixed literals, so it becomes
`{ detail: &'static str }`." That is wrong on every count, and the producer
survey behind it was not exhaustive. As shipped, `InvalidArgument` is still
`{ detail: String }` (`sync/error.rs:28`) and **is** a Section-3 allowlist
entry. It has **ten** construction sites across **four** files
(`sync/error.rs:110` test, `sync/prepare.rs:237,294,394,449`,
`sync/state.rs:55,60`, `sync/commit/write.rs:311,318,333`), and
`prepare.rs:449` passes `format!("merge_block: {e}")` over a `ConflictError`
— not a literal, so the `&'static str` rewrite was never available. The
allowlist entry carries the full survey and the reasoning for why that
`ConflictError` fold is safe (both of its variants carry only `[u8; 16]`
fields, and this same guard scans it).

Expected allowlist size: **six entries**, all in one reviewed section. Keeping it
that small is what keeps each entry meaningful — the same reasoning recorded for
the two log-hygiene allowlists.

**Post-implementation update (round 2 review, #474 guard PR).** The guard's
RED landing after round 2's fixes reported **17** violations, not 6, and not
all of them were Group 3 candidates in the sense above:

- The 9 sites originally scoped here, unchanged.
- **2 more `String`/nested-third-party sites the original review missed**:
  `VaultError::Io { source: std::io::Error, .. }` (`vault/mod.rs:157`) and
  `SyncError::ConflictCopyScanIoFailed { source: std::io::Error }`
  (`sync/error.rs:35`). Both use `#[source]`, not `#[from]` — the review that
  produced this doc's Group 1/2/3 split checked `#[from]` sites only, so
  these were never classified at all. `source: std::io::Error` is squarely
  "not provably data-free" (a raw OS error can carry a filesystem path); it
  needs the SAME `&'static str` + `CborFault`-style treatment as Group 1, not
  a bare allowlist entry, unless review concludes the path text is
  acceptable to disclose here specifically.
- **6 `UNPARSED` findings** — a placeholder referencing a module-level
  `pub const NAME: usize = N;` / `pub const NAME: u8 = N;` via Rust's
  captured-identifier format syntax (`{CARD_VERSION_V1}`,
  `{MAX_DISPLAY_NAME_BYTES}`, `{ML_KEM_768_CT_LEN}`, `{BLOCK_UUID_LEN}`,
  `{ED25519_SIG_LEN}`, `{RECORD_UUID_LEN}` — in `identity/card.rs`,
  `vault/block.rs` x3, `vault/record.rs`). Each was verified data-free by
  inspection (a numeric compile-time constant, not a field), and round 2 left
  these as a real gap: the guard had no field-based model for "this
  identifier resolves to an in-scope `const`, not `self.<field>`."

**Post-implementation update (round 3 review): a fourth tier, not six more
allowlist entries.** Round 2's own reasoning already established that
allowlisting a whole CLASS of provably-safe finding is worse than teaching the
guard to recognise the class: 6 entries all reading "this is a const" is
exactly the noise that erodes a reviewer's attention on the entries that
matter. And the const argument is, if anything, STRONGER than the recursion
or alias tiers it sits alongside: a Rust `const`'s initializer is REQUIRED by
the compiler to be evaluable at compile time — a non-const-evaluable
initializer is a compile error — so a `const` capture cannot carry runtime
content for ANY declared type, not just the numeric ones this codebase
happens to use today. `discover_declarations` now also harvests bare `const`
names (`find_consts`, §4), and a placeholder resolving to one of them is
treated as data-free without going through `is_data_free` at all — it isn't
a field-type question, it's "does this name resolve to a field, or to a
const," and a const answers it before any type ever enters the picture.

With the const tier in place, the true violation count is **11**: the 9
original Group 3 sites plus the 2 `#[source] std::io::Error` sites. All 6
`UNPARSED` const-capture findings are gone — resolved by a rule addition, not
by 6 allowlist entries. The "six entries, one reviewed section" framing above
is now much closer to accurate again: **9 of the 11** are still genuinely
Group-3-shaped (a `&'static str`/ordinal rewrite or a reviewed allowlist
entry), and the 2 `std::io::Error` sites need the Group 1 treatment described
above, not an allowlist entry. Task 9 inherits an 11-site review — 9 in the
original spirit of this section, 2 that need a code change first.

### 4. The guard — `scripts/check-error-payload-hygiene.py`

Run via `uv` (repo precedent: `core/tests/python/spec_test_name_freshness.py`),
wired into `test.yml` on ubuntu.

**Rule.** For every `#[error("…")]` attribute in `core/src/**/*.rs`, resolve the
field types of the variant it is attached to. If the format string interpolates a
field whose declared type is not in the provably-data-free set, and the
attribute's exact trimmed source line is not allowlisted, fail.

**Post-implementation update (rounds 1–4 review).** The rule as actually
implemented resolves a placeholder through up to FOUR recognised-safe
categories, not the single flat type set this section originally described —
the flat set alone made the real scan report 24 false-shaped violations that
were really just the guard not knowing three legitimate patterns. The first
three are genuinely tiers of `is_data_free` (a field-TYPE question); the
fourth (round 3) is answered BEFORE type classification ever runs, because a
`const` capture isn't a field at all — see its own entry below.

1. **Literal types**: `&'static str`, all integer primitives, `bool`,
   `[u8; N]`, `Option<T>` of one of these, and `CborFault`. Everything else —
   `String`, `Vec<u8>`, `PathBuf`, `Box<dyn …>`, any unrecognised type —
   denies, as originally specified.
2. **Recursion**: a field naming a `thiserror`-derived enum THIS SAME GUARD
   ALSO SCANS somewhere under `core/src/**` is data-free, because the guard
   already fails at that enum's own definition if any of its variants
   interpolates a non-data-free field — re-flagging a `#[from]`/`#[source]`
   forward to it adds no signal, only allowlist noise. **The caveat that
   matters**: this soundness argument is "the guard fails at that enum's own
   definition." Once a leaf variant there is ALLOWLISTED — a human decision,
   made once, that does not automatically re-verify as the type evolves —
   the honest statement becomes "fails OR IS ALLOWLISTED at that enum's own
   definition." Concretely: allowlisting the four `VaultTomlError` `String`
   variants (Group 3, above) means `VaultTomlError` is no longer "safe by an
   enforced guarantee" so much as "safe by a reviewed exception" — and
   `VaultError::Unlock(#[from] crate::unlock::UnlockError)` /
   `UnlockError::MalformedVaultToml(#[from] VaultTomlError)` mean that
   exception reaches `VaultError`, the type the FFI bridge folds into
   `FfiVaultError` and projects to both platform UIs. The recursion tier is
   sound; it is sound *through* an allowlist entry, not despite one, and that
   is a materially different claim than "provably data-free."
3. **One-level alias resolution**: a field whose declared type is a
   `type X = Y;` alias resolves through ONE hop before classification
   (`pub type Fingerprint = [u8; 16];` is exactly as data-free as the array
   it names). An alias to something unresolvable, including a second alias
   hop, still denies. Alias discovery is cross-file (an alias can be declared
   in a different file than the field that uses it) but is restricted to
   MODULE SCOPE, which excludes a trait's or an `impl`'s associated type
   (`type Ek = …;` inside a trait impl is a per-impl binding, not a
   free-standing alias) and anything local to a `fn` body; and a
   bare/qualified spelling that resolves to DIFFERENT right-hand sides in
   different files is dropped from the resolvable set entirely rather than
   guessed at (last-write-wins across files was proven to silently launder an
   unsafe alias into a pass depending on file sort order).
4. **`const` capture (round 3).** A NAMED placeholder that does not match any
   parsed field is checked against every bare `const NAME: Type = value;`
   declared under `core/src/**` (`find_consts`) before falling through to
   `UNPARSED`. This is not a type-tier at all — a `const` capture is
   resolved at the NAME level, before `is_data_free` is ever called, because
   there is no field to look a type up for. The soundness argument is
   STRONGER than tiers 2 and 3: Rust requires a `const`'s initializer to be
   compile-time evaluable (a non-const-evaluable initializer is a compiler
   error), so the guarantee holds for ANY declared type, not just the
   `usize`/`u8` ones this codebase happens to use today — unlike the
   recursion tier, there is no "sound through an allowlist entry" caveat,
   because nothing about a `const` can ever be allowlisted into unsoundness.
   Deliberately **excludes `static`** (even an immutable one is a different
   guarantee — Rust does not require a `static`'s initializer to be free of
   interior mutability or runtime-observable identity the way it does for
   `const`), restricted to MODULE SCOPE the same way tier 3 is, and further
   excluding `#[cfg(test)]`-gated declarations: a test-only const is not part
   of the shipped crate and must not vouch for a shipped message. Discovery
   is cross-file (the live shape: `crypto/kem.rs`'s `ML_KEM_768_CT_LEN`
   captured in `vault/block.rs`'s format string), and — **corrected in round
   4** — it carries the SAME collision-drops-to-deny treatment as tier 3's
   aliases. Round 3 argued it did not need to, on the grounds that a
   `const`'s safety comes from the compiler rather than its value. That
   premise is true, but the conclusion does not follow: the claim the guard
   actually makes is *"this placeholder RESOLVES TO a const"*, which is a
   name-resolution claim, and a bare-name union over the whole tree does not
   establish it. `static` is the counter-witness — it shares the
   SCREAMING_SNAKE_CASE convention, it is the other thing a bare captured
   identifier resolves to, and the guard deliberately denies it — so a union
   silently converted that correct deny into a pass as soon as any unrelated
   file declared a same-named const. A spelling is therefore credited only
   when the guard saw exactly one module-scope `const` declaration of it and
   saw nothing (a `static`, or a `const` in an excluded scope) that
   contradicts the reading.

**Default-deny covers STRUCTURE, not just TYPE.** The original design left
silent `continue`s in the scanner for "we couldn't figure out what this
attribute decorates" and "this placeholder doesn't match any field we
parsed." Both are now `UNPARSED` findings instead — an unrecognised construct
fails closed the same way an unrecognised type does, rather than silently
passing. Review found this had hidden two real classes: an intervening
attribute between `#[error(...)]` and its variant (`#[cfg(...)]`,
`#[allow(...)]`) defeated variant-lookup entirely, and `#[error(transparent)]`
(live at `sync/error.rs:24`) has zero `{...}` placeholders yet delegates
`Display` wholesale to its sole field. Both are now handled explicitly (skip
intervening attributes; treat `transparent`'s sole field as interpolated),
and everything else unrecognised is `UNPARSED` rather than skipped. A
struct-shaped `thiserror` error (`#[error("...")] pub struct E { .. }`, not
an enum variant) is also now scanned — not used in `core/src` today, but
nothing in the language prevented it, and the original scanner only ever
looked for enum variants.

**Post-implementation update (round 4 review): declarations are read from a
view with STRING LITERALS blanked, and bare names are resolved per-file.**
Rounds 1–3 built three cross-file "recognised-safe" registries (local error
enums, type aliases, consts) by pattern-matching over comment-stripped
source. Two structural holes followed from that, both proven by execution:

1. **String-literal injection self-authorised a placeholder.** Comment
   stripping does not blank string CONTENTS, so text inside an `#[error]`
   *message* registered as a declaration. A single line —
   `#[error("leaked field name: {SELF_AUTH} const SELF_AUTH: usize = 1;")]` —
   passed silently, in one file, with no collision and no file-ordering
   dependence, authored by exactly the person whose code the guard checks.
   The same trick reached the alias tier (a `type … = usize;` written into
   the message, plus a field of that type) and the recursion tier (a
   `enum … { #[error("x")] A }` written into the message). Declaration
   discovery now runs over `discovery_view` — comments blanked, then string
   literal contents blanked, both length- and line-preserving. Locating the
   `#[error(` attributes themselves deliberately still uses the un-blanked
   text: blanking can only ever HIDE, which costs a credit (fail-closed)
   during discovery, but would cost a whole attribute (fail-open) if the
   string scanner ever desynced.
2. **A bare name is a claim about resolution, and a `use` can refute it.**
   `core/src/error.rs` declares `pub enum Error`, so the bare spelling
   `Error` was trusted tree-wide; `use std::io::Error; … K1BareIoError(#[from]
   Error)` therefore passed, and `std::io::Error` renders a filesystem path.
   Each file's own `use` statements are now read (`foreign_use_names`), and
   every name a file binds from OUTSIDE the crate is withdrawn from that
   file's bare-name credits across all three registries. Roots `crate` /
   `super` / `self`, and Rust-2018 uniform-path roots naming a module
   declared in the same file (`pub use block::{…};` beside `pub mod block;`,
   which `core/src/vault/mod.rs` really writes), stay intra-crate. This is
   evidence-based rather than a resolver: it reacts to `use` statements it
   can read, and a foreign GLOB import would still be invisible.

Declaration discovery is also now restricted to MODULE SCOPE generally — a
single brace-nesting pass replaces the earlier impl-block-only exclusion and
covers `fn` bodies, `trait` bodies, `struct`/`enum` bodies and blocks — and
discovery skips `#[cfg(test)]` items. Of the **134** bare const names the
round-3 rule harvested tree-wide, 6 came from test modules, one named
`SECRET_FIELD_NAME`; the credited set is now 109. (A round-4 draft of this
paragraph said 136. That measurement was taken with two of the measuring
session's own throwaway attack files still in the tree; 134 is the clean-tree
figure.)

None of this changed the real scan's verdict: still exactly the same 11
sites. That is the intended result — these fixes close paths that only a
deliberately-crafted declaration could have walked.

**Post-implementation update (round 5 review): one lexer, and the fail-closed
argument is per-pass.** Round 5 broke four of the round-4 views at once, and
every break was the same defect wearing a different shape: the scanners were
patched per-shape and did not actually know where Rust literals begin and end.

- `r#"a" const ZZ: usize = 1; "b"#` — a RAW string with an odd number of
  internal quotes re-exposed its own contents as code, so the round-4 CRITICAL
  (self-authorising a placeholder from inside a message) was only partially
  closed. All three tiers were reachable this way.
- `let c = '}';` inside a `fn` body popped that function's own brace, so every
  declaration after it in the body was credited as module scope — defeating
  exactly what the new scope restriction was for.
- `fn q() -> char { '"' }` desynced the string scanner across the following
  `use std::io::Error;`, blanking the `use` — which RESTORED the bare-name
  enum credit and handed back the bypass round 4 had just closed.
- `mod outer { pub mod std { } }` beside `use std::io::Error;` compiles (the
  nested `mod std` is not in scope at file top level), and the uniform-path
  fix harvested `mod NAME` at any depth, so the import was misread as
  intra-crate.
- The `#[cfg(test)]` exclusion had been wired to the const registry only, so a
  test-only `enum` still registered its bare name tree-wide and a shipped type
  of the same name rode on it.

The fix is a single lexical pass (`lex_spans`) classifying every byte as code,
comment, literal-delimiter or literal-content — line comments, NESTED block
comments (Rust's nest, unlike C's), ordinary and byte strings with escapes and
`\` + newline continuations, raw strings with a variable `#` run
(`r"…"` / `r#"…"#` / `r##"…"##` / `br#"…"#`), char and byte-char literals
including `'"'` `'{'` `'}'` `'\''` `'\\'`, and the lifetime-vs-char ambiguity
that `&'static str` forces. Every view is `render_view` over that one
classification; length and line-count preservation are structural rather than
remembered, and both — plus span ordering and non-overlap — are asserted in
`--self-test`.

**The fail-closed argument is now stated per-pass, because stating it globally
was itself a defect.** "Blanking can only HIDE text, so a view bug loses a
credit and therefore only produces findings" is true for the three
CREDIT-GRANTING registries and **false** for the two CREDIT-WITHDRAWING
passes: hiding a `use` in `foreign_use_names`, or revealing an extra `mod` in
`top_level_mod_names`, restores a credit. Each pass is therefore wired to the
view whose failure direction matches its own polarity — `foreign_use_names`
reads the RAW source (unioned with the comments-blanked view, so a `use` must
escape both), `top_level_mod_names` reads the fully blanked discovery view.
A claim that does not hold for every consumer is worse than no claim, because
it stops the next reader from checking.

Reading raw for the withdrawal pass has one cost worth recording: `use` is
also an ordinary English word, and an unfiltered raw scan bound nonsense from
every doc comment saying "we use the manifest", which surfaced as **9 spurious
findings** on the first run. A use-tree shape filter (identifier/punctuation
characters only, and no two identifier words separated by whitespace outside
` as `) removes the prose without weakening the pass: anything it rejects is
recovered by the comments-blanked read whenever it was really code.

**What round 5 deliberately did NOT close**, stated rather than papered over:

- **`lex_spans` is a lexer, not a parser, and expands no macros.** An
  `#[error(...)]` attribute — or a `const` / `type` / `enum` declaration —
  produced by a macro is invisible to every registry. Closing this needs a
  real Rust front end; a lexical guard cannot.
- **`scan_source` locates `#[error(` with string contents INTACT, on purpose.**
  Hiding an attribute is the one fail-OPEN direction available, so that pass
  does not trust the lexer's literal classification at all. The price is that
  an `#[error(` sequence written inside another attribute's *message* is
  visited as though it were an attribute and may produce an extra finding
  under its own, different allowlist key. It cannot hide a real attribute, and
  allowlisting the real one does not silence the spurious one.
- **A foreign GLOB import (`use some_crate::*;`) still binds names the
  withdrawal pass cannot enumerate.** Every glob under `core/src/**` today is
  an intra-crate `use super::*;` inside `#[cfg(test)] mod tests`, plus
  `use proptest::prelude::*;`.
- **`type usize = String;`-style shadowing of a `DATA_FREE_TYPES` primitive**
  remains open, unchanged since round 1, for the same reason: it needs a type
  resolver, not a lexer.

**Why Python rather than bash.** Associating an attribute with the following
variant's *field types* requires reading a structure that spans lines. A
line-based matcher structurally cannot do it — the same argument #477 makes
against the Kotlin grep rules. Python also removes the need for an
`is_comment_line` heuristic entirely: it strips comments by tokenizing, so the
control that has had two bugs on the shell side (`/* */ <code>` in round 1 of
#472, and `*/ <code>` in #475) has no analogue here to get wrong.

**Allowlist.** `scripts/error-payload-hygiene-allowlist.txt`, keyed on the exact
trimmed source line — never a substring, for the reason recorded in CLAUDE.md: a
substring entry exempts every future line in the same file containing it, which
was demonstrably exploitable.

**Post-implementation update (round 2 review): the key is the whole attribute,
not one line.** "Exact trimmed source line" turned out not to be unique for a
multi-line `#[error(...)]` attribute (live at `sync/error.rs:9`): keying on
just the first physical line gives every such attribute the literal key
`#[error(`, which any OTHER multi-line attribute in the same file shares —
proven end-to-end in review, where one allowlist entry silently exempted two
different, only-one-of-them-reviewed variants. That is the exact "a substring
exempts every future match" failure the exact-line convention exists to
prevent, recurring one level up. The key is now the ENTIRE `#[error(...)]`
attribute's text, whitespace-collapsed to one line (still TAB-safe, still no
embedded newlines, still matched as an exact string never a substring) —
unique per attribute regardless of how many source lines it spans.

**Matcher parity.** The two shell guards share one matcher via
`scripts/lib/hygiene-allowlist.sh`; a Python guard cannot source it. Rather than
a two-language pipeline, the Python guard implements the same exact-match
convention itself (strip, skip blanks and `#` comments, set membership) reusing
the same **file format**, and a test feeds one shared fixture through both the
bash and the Python parser and asserts identical accept/reject sets. The
duplication is therefore non-silent. This is a deliberate departure from #475's
extract-don't-duplicate rule, justified by what that rule was protecting: the
subtle, twice-buggy control was `is_comment_line`, and it has no counterpart in a
tokenizing parser.

**`--self-test`.** Two-sided, as on both platforms, and materially larger than
first scoped: **33 positive / 17 negative** controls, up from the original
4-ish sketch. Round 2 review mutation-tested the original set and found three
were vacuous (didn't actually exercise the mechanism they claimed to — e.g. a
control for "escaped braces aren't placeholders" whose variant had no fields,
so removing the escape-handling code couldn't possibly make it fire); those
were rebuilt so the underlying mechanism is provably load-bearing, not just
plausible-looking. The round-2 controls cover, per finding: a `#[source]`
attribute on a STRUCT field (not just a tuple field); a third-party nested
error (`std::io::Error`) that must still deny through BOTH `#[from]` and
`#[error(transparent)]`, proving the recursion tier isn't over-relaxed; a
struct-shaped (non-enum-variant) error; an intervening `#[allow(...)]`
attribute between `#[error(...)]` and its variant; a triple-brace
`{{{name}}}` placeholder; and three `UNPARSED`-triggering shapes (an
unrecognisable construct, an unresolvable placeholder name, an out-of-range
positional placeholder). Round 3 added: a negative control for a genuine
`const` capture; a positive control for a placeholder that is neither a
field NOR a discovered const (proving the const tier is an ADDITIONAL
recognised-safe category, not a fallback that accepts any unknown name); and
a positive control for a `static` capture (proving requirement 3 — `static`
is never treated as `const`). Both round-3 additions were mutation-tested by
hand beyond the normal `--self-test` run: disabling the const tier entirely
breaks EXACTLY the negative control (nothing else), and making the const
check accept any unknown name breaks the "neither field nor const" positive
control (along with two others that share its shape) — proof the tier is
additive, not a laundering fallback.

Round 4 added nine positive controls (string-literal injection of a `const`,
of a `type` alias and of a thiserror `enum`; a `static` disqualifying a const
spelling; two same-named module-scope consts colliding; a `#[cfg(test)]`
const; a `fn`-body const; a trait associated const; and a foreign `use`
shadowing a core-local enum name) and three negative ones (an intra-crate
`use`, a Rust-2018 uniform-path re-export, and a const declared inside a
`mod` block, which must all still be credited). Two structural checks run
alongside the controls: the comment- and string-blanking views must preserve
both length and line count over every control plus a synthetic sample, and no
finding's allowlist key may contain a TAB or a newline.

Round 4 also found that two controls **no longer pinned their own
mechanisms**. Once an unresolvable construct became an `UNPARSED` finding
rather than a silent skip, reverting the fix a control was written for still
produced *a* finding, so an assertion of "the scan returned something" stayed
green. Positive controls may therefore now carry an expectation naming the
variant, field and field type (or asserting the finding is/is not `UNPARSED`)
that the control must produce; the two affected controls assert on the
verdict, and reverting either fix now breaks its own control.

Round 5 added five positive controls (a raw string self-authorising a const; a
char literal holding a brace inside a `fn` body; a char literal holding a
quote across a following `use`; a nested `mod std` beside `use std::…`; a
`#[cfg(test)]` error enum vouching for a shipped type) and two negative ones
(a raw string must END where Rust says it does, with the const it could
swallow placed deliberately below it; and `&'static str` must lex as a
lifetime, not as a char literal that runs to end-of-file). The lexer sample
used by the invariant checks carries every shape the guard has been broken by
plus the ones it has not — nested block comments, `r##"…"##`, `b"…"`,
`br#"…"#`, `'\''`, `'\\'`, `b'x'`.

Every round-4 and round-5 fix is mutation-proven the same way: each mechanism
is disabled in turn and the controls re-run, with each mutation breaking
exactly the control(s) written for it and nothing else.

**Correction (final review): the round-5 headline fix had NO control until
now.** An earlier revision of this paragraph offered a designed experiment —
"crippling char-literal lexing alone breaks the brace control but NOT the
`use`-desync control, because the withdrawal pass reads raw; crippling
char-literal lexing *and* pointing that pass back at the blanked view breaks
both. That is the defence-in-depth claim, demonstrated rather than asserted."
The second half of that sentence was false as written. The single mutation
that matters — pointing `foreign_use_names` at the blanked view **instead of**
the raw ∪ blanked union, i.e. reverting round 5's headline fix on its own —
left BOTH `--self-test` and the real scan at exit 0. P31 could not catch it,
because the lexer handles `'"'` correctly *today*: the desync P31 is named
after no longer happens, so the blanked view still shows P31's `use`. The
claim was demonstrated only in combination with a second, independent break.

Two controls now pin it individually, using the shape that defeats the blanked
view under a **correct** lexer — an unterminated block comment, which
`lex_spans` deliberately runs to end-of-input (fail-closed for the credit
registries, fail-OPEN for the withdrawal pass):

- **P38** — a plain `use std::io::Error;` below an unterminated comment.
- **P39** — the same as a renaming import (`use std::io::Error as …;`). This
  one also pins `_looks_like_use_tree`'s ` as ` → `|` normalisation, which was
  substituting a character absent from `USE_TREE_CHARS_RE` and so made the raw
  read reject **every** renaming import in the tree: 52 names withdrawn by the
  raw read against the blanked read's 61 (union 67), leaving all 15 renames
  resting on the single read a lexer desync disarms. Fixed; the raw read now
  withdraws all 67, a strict superset of the union, real-scan verdict unchanged.

Verified: the blanked-view-only mutation breaks exactly P38 and P39 and leaves
P28 / P31 / P32 green; the `|`-removal mutation breaks exactly P39.
`--self-test` runs first in CI so a green guard is never vacuous — and that
claim is now backed by a mutation pass over each mechanism individually, not
by inspection and not only in combination.

### 5. Platform narrowing

- **iOS** — delete the `case .corruptVault: return "corruptVault(<redacted>)"`
  arm from `VaultAccessError.diagnosticDescription`
  (`SecretFreeError.swift:112`). Rewrite the doc comment: its stated
  justification, quoting `record.rs:660` by line, ceases to exist.
- **Android** — delete the `CorruptVault` and `SaveCryptoFailure` arms from
  `VaultBrowseError.diagnosticDescription` (`VaultBrowseError.kt:76-79`).
  *(Correction, final review: an earlier revision added "and drop
  `BrowseMapping.kt`'s explicit redaction of the same." There is no such
  redaction and there never was. `BrowseMapping.kt` — which lives in
  `android/kit/`, not `android/vault-access/` — MAPS both arms verbatim
  (`CorruptVault(e.detail)`, `SaveCryptoFailure(e.detail)`); the redaction was
  only ever in `diagnosticDescription`. The file is untouched on this branch,
  and diffing it against `main` is the check.)*
- **`CLAUDE.md`** — the *"`VaultBrowseError.SaveCryptoFailure` must stay
  redacted … Do not 'align the platforms' by deleting the redaction"* section is
  replaced by the new invariant. That instruction was correct when written and
  becomes actively wrong once the payload is gated at source.

`.invalidArgument` (iOS) and `InvalidArgument` (Android) **stay redacted, on both
platforms.** Their payloads are platform-authored, not Rust-authored:
`RecordEditModel.kt:179` builds `"field '${f.name}' is not valid hex"` and `:193`
builds `"duplicate field name: ${v.name}"` from a decrypted record, and iOS's
`RecordEditViewModel` does the same in Swift. Different class, different fix.
**No issue tracks that platform-authored payload class itself**; #473 / #476
track the separate question of these carried diagnostics being rendered as
on-screen copy. (An earlier revision called this "#473 / #476 territory," which
reads as though the class were owned. Commit `b3f4243` corrected exactly that
wording at four other sites; this was the missed fifth.) This must not be swept
into "align the platforms".

## What does not change

- **No on-disk format change.** Error messages are not part of the vault format;
  neither `docs/vault-format.md` nor `docs/crypto-design.md` specifies any of
  these strings, and `conformance.py` raises its own exceptions rather than
  comparing Rust error text.
- **No `FfiVaultError` variant change and no `.udl` change.** The ~20
  `format!("{e}")` folds in the bridge stay exactly as they are; they become safe
  because their *sources* are. This satisfies the issue's "no new
  `FfiVaultError` variant" acceptance bullet.
- **No differential-replay change.** `docs/manual/contributors/differential-replay-protocol.md`
  §"error_class is informational and currently NOT compared" — the protocol
  accepts any `(Err, Err)` pair, so a reshaped Rust error class cannot desync it.

## Testing

Test-driven throughout.

1. **Group 1.** For each of the four `DuplicateKey` construction sites and the
   `UnknownField` site, a test asserting the *new* `field` hint and `index`
   lands before the variant changes shape. `record.rs:1597`'s existing
   `matches!(err, RecordError::DuplicateKey { ref key } if key == KEY_RECORD_TYPE)`
   is rewritten to assert the index and hint.
2. **Group 2.** Unit tests for `classify_de` / `classify_ser` covering every
   upstream variant, including an explicit test that a `Semantic` message
   containing a marker string does **not** appear in the resulting `Display`
   output. That test is the whole point of the module and must be
   mutation-proven by restoring the passthrough.
3. **The guard.** Lands RED — committed with its positive controls before the
   allowlist is populated — then goes green. Every rule is mutation-proven
   individually: deleting a rule must fail exactly its own controls and no
   others.
4. **Matcher parity.** One fixture allowlist file, both parsers, identical
   accept/reject sets.
5. **Platform narrowing.** Each removal gets a test asserting the detail now
   **survives** the render, mutation-proven by re-adding the redaction and
   watching that test fail. #475's lesson applies directly: assert on message
   **content**, never on type — the pre-existing Android mirror tests asserted
   only on exception type, which is precisely why an entire failure path
   collapsed to `<undisclosed …>` unnoticed.

**Gates.** `cargo test --release --workspace`;
`cargo clippy --release --workspace --tests -- -D warnings`;
`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`;
`uv run core/tests/python/conformance.py`;
`uv run core/tests/python/spec_test_name_freshness.py` (renamed tests may be
cited in `docs/`); both uniffi conformance runners — `FfiVaultError` is untouched
but `CardError` / `BundleError` shape changes could reach the KAT harnesses, and
per `project_secretary_ffivaulterror_workspace_match` those harnesses are
invisible to `cargo`; `bash ffi/scripts/check-lean-binding.sh`; the two existing
log-hygiene guards plus the new one, each `--self-test` first;
`(cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest)`;
`swift test` for the iOS packages.

## Sequencing

One branch, ordered so it is coherent if the session ends early:

1. `core/src/cbor.rs` + tests (self-contained, no callers yet).
2. Group 1 variant changes + call sites + tests.
3. Group 2 variant changes + call sites + tests.
4. `BundleError::DuplicateField` static-str win. *(Correction, final review:
   this step also listed `SyncError::InvalidArgument`. That win never
   happened and was never available — see §3's correction: it has ten
   producers across four files, one of which passes `format!("merge_block:
   {e}")`. It shipped as a Section-3 allowlist entry instead.)*
5. The guard, landed RED, then the allowlist, then GREEN. CI wiring.
6. **← natural stop point. The branch is shippable here.**
7. iOS narrowing + tests.
8. Android narrowing + tests.
9. `CLAUDE.md`, README/ROADMAP check, handoff.

## Risks

- **The `&'static str` field hint must not drift into a runtime string.** If a
  future edit makes `field` a `String` to carry something richer, the guard
  catches it — that is exactly what the guard is for. Noted so the guard's value
  is understood rather than experienced as friction.
- **`CborFault.offset` is a weak length oracle** (see §2). Accepted and
  documented, not hidden.
- **The Group 3 allowlist is a point-in-time claim for two of its six entries.**
  `RestoreVerificationFailed` / `RepairRejected` are safe because their `detail`
  is built from literals and other core errors. A future producer passing
  something else would not be caught by the guard, which sees the *declaration*,
  not the construction sites. This is the same limit the Kotlin payload-origin
  audit has, and it is stated in the allowlist entry rather than assumed.
- **A parallel Python allowlist parser can drift from the bash one.** Mitigated
  by the parity test, not by argument.
- **`:app:assembleDebug` takes ~10 minutes** on this host (cargo-ndk, four
  ABIs). Use `:vault-access:test` + `compileDebugKotlin` for iteration; save the
  full assemble for acceptance.
- **This branch touches `core/`**, unlike the last three sessions. The full
  `cargo test --release --workspace` and both conformance runners are mandatory,
  not optional.

## Non-goals

- `.invalidArgument` / `InvalidArgument` on either platform (see §5). No issue
  tracks that platform-authored payload class itself; #473 / #476 track only
  the separate on-screen-copy question.
- `VaultSyncError.Failed`'s content-traced safety claim — a separate Rust/FFI
  boundary issue, filed separately this session as #478. Note #478 is scoped
  to `VaultSyncError.Failed` / `FfiVaultError::SyncFailed`, NOT to the whole
  "the bridge builds its own `format!` detail strings and this guard does not
  scan them" gap: only one of the two alternatives its acceptance offers
  (extending the guard to `ffi/secretary-ffi-bridge/src/**`) would close that
  broadly. If it closes the other way, the bridge half of `CorruptVault` /
  `SaveCryptoFailure` — the arms §5 un-redacts — is owned by nobody.
- Retiring the Kotlin grep rules for a type-aware detekt rule — #477.
- Any change to the on-disk vault format, the FFI surface, or the CRDT merge.
