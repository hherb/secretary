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

`SyncError::StateDecodeFailed` / `StateEncodeFailed` join this group — their
`detail: String` is built from `ciborium` at `sync/state.rs:136`.

The generic `E` parameter is why these were stringified originally: the doc
comment at `record.rs:110` explains that `ciborium::ser::Error<E>` is generic over
the writer's I/O error and so cannot be captured uniformly as a `#[from]` source.
`classify_ser<E>` sidesteps that by projecting to a non-generic type.

#### The one deliberate residual disclosure

`CborFault.offset` is a byte offset into decrypted plaintext. It is positional
metadata, not content, but it is a weak length oracle: "duplicate at offset 41"
narrows the possible lengths of preceding field names.

It is kept. Vault file sizes are already visible on disk to anyone who can read
the folder, so the threat model already treats plaintext *size* as disclosed, and
the offset is the single most useful datum when debugging a genuinely corrupt
vault. Recorded here so the decision is explicit rather than assumed away.

### 3. Group 3 — reviewed allowlist, no code change

| Variant | Why it is safe |
|---|---|
| `VaultTomlError::MalformedToml` / `UnknownKdfKey` / `UnsupportedKdfAlgorithm` / `UnsupportedKdfVersion` | `vault.toml` is **unencrypted on disk** — `docs/vault-format.md` §2 is titled "`vault.toml` — cleartext metadata" and the file's own header comment reads "cleartext; not secret". Its bytes are disclosed to anyone with the vault folder; the threat model treats them as public. `MalformedToml` needs the `toml` crate's message to be debuggable at all. |
| `VaultError::RestoreVerificationFailed { detail }` / `RepairRejected { detail }` | `detail` is built only from fixed string literals (`orchestrators.rs:2512`) and `format!("{e}")` over other `core` errors (`:2522`, `:2553`) — all of which this work gates. |

`SyncError::InvalidArgument { detail: String }` gets a free structural win rather
than an allowlist entry: all three producers (`sync/error.rs:111`,
`sync/state.rs:56`, `:61`) pass fixed literals, so it becomes
`{ detail: &'static str }`.

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

**Post-implementation update (rounds 1–3 review).** The rule as actually
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
   in a different file than the field that uses it) but explicitly excludes
   `impl`-block associated types (`type Ek = …;` inside a trait impl is a
   per-impl binding, not a free-standing alias), and a bare/qualified
   spelling that resolves to DIFFERENT right-hand sides in different files is
   dropped from the resolvable set entirely rather than guessed at
   (last-write-wins across files was proven to silently launder an unsafe
   alias into a pass depending on file sort order).
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
   `const`) and excludes associated consts declared inside `impl ... { }`
   blocks, the same way tier 3 excludes associated types. Discovery is
   cross-file (the live shape: `crypto/kem.rs`'s `ML_KEM_768_CT_LEN` captured
   in `vault/block.rs`'s format string) but, unlike tier 3's aliases, does
   NOT need the same collision-drops-to-deny treatment: an alias's safety
   depends on its right-hand-side VALUE, which genuinely can conflict between
   two same-named aliases in different files, but a `const`'s safety is the
   compiler's guarantee alone — two different files each declaring their own
   `const LEN: usize = ...;` are both still soundly "compile-time constant,"
   with no "wrong value" to collide on.

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
first scoped: **19 positive / 12 negative** controls, up from the original
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
additive, not a laundering fallback. `--self-test` runs first in CI so a
green guard is never vacuous — and now that claim is backed by a mutation
pass, not just inspection.

### 5. Platform narrowing

- **iOS** — delete the `case .corruptVault: return "corruptVault(<redacted>)"`
  arm from `VaultAccessError.diagnosticDescription`
  (`SecretFreeError.swift:112`). Rewrite the doc comment: its stated
  justification, quoting `record.rs:660` by line, ceases to exist.
- **Android** — delete the `CorruptVault` and `SaveCryptoFailure` arms from
  `VaultBrowseError.diagnosticDescription` (`VaultBrowseError.kt:76-79`), and
  drop `BrowseMapping.kt`'s explicit redaction of the same.
- **`CLAUDE.md`** — the *"`VaultBrowseError.SaveCryptoFailure` must stay
  redacted … Do not 'align the platforms' by deleting the redaction"* section is
  replaced by the new invariant. That instruction was correct when written and
  becomes actively wrong once the payload is gated at source.

`.invalidArgument` (iOS) and `InvalidArgument` (Android) **stay redacted, on both
platforms.** Their payloads are platform-authored, not Rust-authored:
`RecordEditModel.kt:179` builds `"field '${f.name}' is not valid hex"` and `:193`
builds `"duplicate field name: ${v.name}"` from a decrypted record, and iOS's
`RecordEditViewModel` does the same in Swift. Different class, different fix
(#473 / #476 territory). This must not be swept into "align the platforms".

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
4. `SyncError::InvalidArgument` / `BundleError::DuplicateField` static-str wins.
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

- `.invalidArgument` / `InvalidArgument` on either platform (see §5) — #473/#476.
- `VaultSyncError.Failed`'s content-traced safety claim — a separate Rust/FFI
  boundary issue, filed separately this session.
- Retiring the Kotlin grep rules for a type-aware detekt rule — #477.
- Any change to the on-disk vault format, the FFI surface, or the CRDT merge.
