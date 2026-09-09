# Design: cross-language agreement on WHICH rule a rejecting decoder reports (#634, #621)

**Date:** 2026-09-10
**Branch:** `feature/rule-token-agreement`
**Base:** `a6db0e80` (`main`, immediately after PR #636 merged)
**Addresses:** #634, #621 — cited as `(#N)`, never `Closes #N`, per this repo's
convention that a human closes the issue after verifying against the code.

---

## 1. The defect

`core/tests/differential_replay.rs` exists to prove the Rust and Python decoders
agree. Its agreement matrix has four cells, and one of them is a constant:

```rust
// Both reject → agreement (don't compare error classes for now;
// can tighten later if we standardize them).
(Err(_), PyOutcome::Reject(_)) => true,
```

So the harness cannot see a divergence in **which rule** the two implementations
name for the same bytes. That is not a hypothetical class:

- **#618** found two such divergences, live on `main`, and fixed them. The
  harness was green throughout.
- **#621** is a third, still live: for a body that is both out of array sort
  order and carries an indefinite-length item, Rust reports `ArraySortOrder` and
  Python reports crypto-design §6.2 rule 2. Same bytes, same byte offset.

`docs/manual/contributors/differential-replay-protocol.md` already anticipates
the fix and names its precondition: *"This looseness is intentional but
temporary: when we standardise error taxonomies between the two
implementations, we'll tighten the comparison."* This design standardises that
taxonomy and tightens the comparison.

The second half of the work is #621 itself. Tightening the comparison is only
possible once `docs/` says which divergences are legitimate — otherwise the
harness's tolerance list is a record of what today's code happens to do, rather
than a consequence of the spec.

---

## 2. What is measured, and what that settles

Every claim below was produced by execution on `a6db0e80`, not by reading.

### 2.1 The whole rejecting corpus breaks exactly one rule per input

The `manifest_body` target has 38 committed seeds; `manifest_file` has 1.
Running Python's `--diff-replay` over all 38 gives 24 rejects, in four classes:

| Python exception today | seeds | what it means |
|---|---|---|
| `ArraySortOrderViolation` | 7 | a §4.2 array sort discipline |
| `NonCanonicalItem` (`rule` = 2, 3, 4) | 9 | §6.2 rules 2 / 3 / 4, three each |
| `NonCanonicalBody` | 4 | re-encode differs, no cause named |
| bare `ValueError` | 4 | a §4.2 repeated array value |

Three of those four classes are already typed, and `NonCanonicalItem` already
carries a structured `rule` attribute. So the Python side is three-quarters of
the way to a token vocabulary, and only the repeated-value arm is bare.

**Consequence for this design:** because every corpus row breaks exactly one
rule, the token comparison is expected to be GREEN on the entire existing corpus
the day it lands. It therefore proves nothing by passing, and the design must
carry its own non-vacuity evidence (§6).

### 2.2 #621's divergent input is not in the corpus

The issue constructs it by splicing the `rule2_indefinite_map` subtree over the
`arraysort__vector_clock` body's placeholder. Both are built from one baseline,
which is why both report offset 929. The splice itself is not committed
anywhere, so no corpus input exhibits a multi-rule body at all.

### 2.3 Rust cannot name the rule from an integration test

`vault::canonical` is `pub(crate)`, so `differential_replay.rs` can match
`ManifestError::Canonical(_)` but cannot distinguish `FloatRejected` (§6.2
rule 4) from `CanonicalError::DuplicateKey` (§6.2 rule 5). This is #635, already
filed, and it decides where the Rust mapping lives (§4.1).

---

## 3. The spec change (#621)

`docs/vault-format.md` §4.2 already carries a paragraph declaring the relative
order of §6.2 rules 1, 2 and 3 against the two fixed orderings **unspecified**,
with an architectural justification: this section admits two reader designs, and
each necessarily detects those rules at a different point.

That justification applies unchanged to §4.2's own **array sort disciplines**,
which is what #621 is about:

- **Rust** detects array disorder at the §4.3 step-4 re-encode comparison — i.e.
  *after* interpretation — because `encode_manifest` sorts all five arrays on
  output. `classify_non_canonical` then names `ArraySortOrder` off the parsed
  `Manifest`.
- **A byte-retaining reader** re-emits its input unconditionally, so its
  re-encode can never see array disorder. It must check the discipline directly,
  *during* its scan — before interpretation.

So the paragraph widens from "§6.2 rules 1, 2 and 3" to "§6.2 rules 1, 2 and 3
**and this section's five array sort disciplines**".

### 3.1 The repeated-value rules are deliberately NOT included

§4.2 forbids a repeated value in four of the five sorted arrays. Those are
**not** phase-dependent and must not be swept into the widened sentence:

- Rust enforces them by explicit adjacent-equality scans in
  `manifest/decode/entries.rs`, during interpretation — deliberately standing
  apart from the re-encode, because `[x, x]` is sorted and re-encodes to itself.
- Python enforces them in `_check_sorted_and_distinct`, also during
  interpretation.

Both designs see them at the same point, so both can be required to report them
consistently. Widening the sentence to cover them would give away an ordering
that is currently free of charge — the same over-broad-claim failure this repo's
handoffs keep re-finding.

### 3.2 What the widened sentence still does not do

It does not order the array sort disciplines against rule 4 or against the
repeated-key rule. Ordering 1 in §4.2 already says rule 4 outranks "every check
below it", which covers it. No new ordering is asserted by this slice.

---

## 4. The token vocabulary

A `RuleToken` is a short, fieldless, language-neutral name for the rule a
rejecting decoder is reporting. It is **coarser** than either implementation's
error enum on purpose: it needs to be fine enough to have caught #618's and
#621's divergences and no finer, because every distinction it draws is a
distinction both implementations must then maintain forever.

### 4.1 Rust side — an exhaustive method on `ManifestError`

New module `core/src/vault/manifest/token.rs` (with a sibling `tests.rs`,
per the repo's directory-module convention):

```rust
pub enum RuleToken { /* fieldless */ }

impl RuleToken {
    pub fn as_str(&self) -> &'static str;
    /// True when the two reader designs §4.2 admits detect this rule at
    /// DIFFERENT points, so §4.2 declares its order against other rules
    /// unspecified.
    pub fn is_phase_dependent(&self) -> bool;
}

impl ManifestError {
    pub fn rule_token(&self) -> RuleToken;   // exhaustive match
}
```

Three properties make this the right home rather than a table in the test:

1. **It is inside the crate**, so it can read `CanonicalError`'s variants and
   `NonCanonicalCause`'s, which an integration test cannot (§2.3 / #635). Rule 4
   stays distinguishable from rule 5.
2. **The match is exhaustive**, so adding a `ManifestError` variant without
   classifying it is a compile error. This is the same "make the invariant a
   type obligation rather than a convention" move as #589's `Once` and #608's
   `Verdict`.
3. **It is unit-testable** in the `--lib` target, where a mutation can be scoped
   and measured without an integration build.

It is ordinary public API in the same advisory-diagnostic family as #590's
`NonCanonicalCause`: it classifies a rejection for a human or a harness and is
never consulted in an acceptance decision.

### 4.2 Python side — a `token` on a typed exception

New module `core/tests/python/conformance_lib/codec/manifest_rules.py` holding a
base `ManifestRejection(ValueError)` with a `token` class attribute, and one
subclass per token that the manifest decoder can raise. Every raise site
reachable from `py_decode_manifest` is converted to one, **message-preserving** —
several conformance sections match on message fragments (Section MUQ names the
repeated id; Section MSH does `if want not in str(e)`), so a changed message is a
silently broken section. #618 set the precedent when it introduced
`DuplicateMapKey` the same way.

`scanner.py`'s existing `NonCanonicalItem` and `DuplicateMapKey` gain tokens
rather than being moved.

### 4.3 The mapping

| token | Rust | Python | phase-dependent |
|---|---|---|---|
| `rule2_indefinite_length` | `NonCanonicalEncoding{cause: IndefiniteLength}` | `NonCanonicalItem(rule=2)` | **yes** |
| `rule3_non_shortest_form` | `NonCanonicalEncoding{cause: NonShortestForm}` | `NonCanonicalItem(rule=3)` | **yes** |
| `rule4_tag_or_float` | `Canonical(FloatRejected \| TagRejected)` | `NonCanonicalItem(rule=4)` | no |
| `non_canonical_unclassified` | `NonCanonicalEncoding{cause: Unclassified}` | `NonCanonicalBody` | **yes** |
| `array_sort_order` | `NonCanonicalEncoding{cause: ArraySortOrder}` | `ArraySortOrderViolation` | **yes** |
| `repeated_array_value` | `DuplicateBlockUuid`, `DuplicateTrashUuid`, `VectorClockDuplicateDevice` | new subclass | no |
| `duplicate_map_key` | `DuplicateKey{..}`, `Canonical(CanonicalError::DuplicateKey{..})` | `DuplicateMapKey` | no |
| `missing_field` | `MissingField{..}` | new subclass | no |
| `wrong_type` | `NotAMap`, `NonTextKey`, `WrongType{..}`, `InvalidByteLength{..}` | new subclass | no |
| `integer_out_of_range` | `IntegerOutOfRange{..}` | new subclass | no |
| `unsupported_version` | `UnsupportedManifestVersion`, `UnsupportedFormatVersion`, `UnsupportedSuiteId` | new subclass | no |
| `malformed_cbor` | `CborDecode(..)` | `cbor2.CBORDecodeError` | no |
| `container_malformed` | `BadMagic`, `UnsupportedFileKind`, `HeaderTruncated`, `SectionTruncated`, `AeadCtLenMismatch`, `TrailingBytes`, `SigEdWrongLength`, `SigPqWrongLength` | `ParseError` | no |
| `aead_failure` | `AeadFailure` | n/a | no |
| `signature_invalid` | `Ed25519SignatureInvalid`, `MlDsa65SignatureInvalid` | n/a | no |
| `encoder_refusal` | the six `Encode*` variants | `ENCODER_REFUSAL_PREFIX` raisers | no |
| `internal_error` | `CborEncode`, `Canonical(CborEncode \| CapacityBoundExceeded)`, `SignInternal` | n/a | no |

**`non_canonical_unclassified` is honest silence on both sides, not "rule 1".**
Rust's `Unclassified` cause exists precisely because map-key disorder leaves
nothing in the body to point at (#590), and Python's `NonCanonicalBody` is the
same outcome reached the other way. Naming it `rule1` would assert a
classification neither implementation performed.

**`manifest_file` is NOT token-compared, and the reason is measured.** Python
*does* have a manifest-file decoder (`py_decode_manifest_file` over
`wire/envelopes.py::parse_manifest_file`), and every rejection it can produce is
a single `ParseError` class — verified by execution on a truncated seed, a
bad-magic seed and a bad-`format_version` seed. Rust's eight container variants
map to `container_malformed` and agree, but `header.rs` also raises
`UnsupportedFormatVersion` / `UnsupportedSuiteId`, which map to
`unsupported_version`. Measured on one file with `format_version = 0x0099`:

| | reports | token |
|---|---|---|
| Rust | `UnsupportedFormatVersion(153)` | `unsupported_version` |
| Python | `ParseError("manifest format_version 0x0099")` | `container_malformed` |

**The mapping cannot fix this.** `UnsupportedFormatVersion` is the same variant
the *body* sentinel check raises, so a per-variant token cannot tell header-level
from body-level; and `ParseError` is one class shared by every target's wire
decoder, so refining it means either message matching — which this repo's
recorded lessons forbid — or a typed wire-error hierarchy touching all seven
targets. See §5.1.

The `n/a` rows are Rust-only because they arise inside the crate's own encode and
signature paths, which Python's diff-replay arms never reach.

**Token resolution is by attribute, not by class hierarchy.** The Python side
reads `getattr(exc, "token", None)`, so `ManifestRejection` subclasses,
`scanner.py`'s `NonCanonicalItem` / `DuplicateMapKey`, and `cursor.py`'s
`ParseError` all participate uniformly without being forced into one base class —
`ParseError` is shared with every other target's wire decoder and must not be
reparented.

### 4.4 Trailing bytes: measured, and it decides a vocabulary rule

The spec draft left this open. It is now measured, on identical bytes (the
`top__control_canonical` seed with one `0x00` appended):

| | reports |
|---|---|
| Rust `decode_manifest` | `NonCanonicalEncoding { cause: Unclassified, at: None }` |
| `py_decode_manifest` | `ValueError("trailing bytes after manifest map: 1")` |

Both reject, so this is not an acceptance divergence. It is a **granularity**
divergence, and it is structural rather than incidental: `from_reader_with_buffer`
reads one item and performs no EOF check, so Rust's parse discards the trailing
byte before the §4.3 step-4 comparison ever runs. That comparison then sees only
"the re-encoded value is shorter than the input" and `classify_non_canonical`
finds nothing in the body to point at. **Rust cannot distinguish trailing bytes
from any other re-encode divergence**, however the mapping is written.

So `trailing_bytes` is deliberately **not** a token, and Python's raise carries
`non_canonical_unclassified`. That is coarsening, which §4 already sanctions
(`container_malformed` merges eight Rust variants), not a lie: the token's
meaning is *"the input is not the canonical encoding of the value this reader
parsed, with no finer classification the two implementations agree on"*, which
is true of both sides. Python's `detail` still carries its specific message, so
no diagnostic quality is lost to a human reader.

**This is NOT the #621 pattern and must not be swept into §3's widened
sentence.** #621 is about the ORDER in which two rules are reported; this is one
fact that one reader can name and the other cannot. Declaring it
phase-dependent would invent a spec sentence to describe a granularity limit.

**The generalisable rule this produced:** a token may only draw a distinction
BOTH implementations can actually make. Where one is structurally blind, the
token coarsens to what they share.

---

## 5. The comparison

### 5.1 Which targets

A table in `differential_replay.rs` classifies every target as token-compared or
not, and is **checked against `TARGETS`** so a new target must be classified
rather than silently defaulting to the loose behaviour. This is the same
"coverage checked against the manifest" treatment `check-secret-slot-hygiene.sh`
gives its scan roots.

- **Token-compared:** `manifest_body`, and only that.
- **Not token-compared:** `vault_toml`, `record`, `contact_card`, `bundle_file`,
  `block_file`, `manifest_file` — six of the seven. The first five each need
  their own Rust taxonomy and a typed Python exception hierarchy for their
  decoder, and `vault_toml` is crash-only so its token would be near-meaningless.
  `manifest_file` is blocked for the different, measured reason in §4.3 (**#640**):
  its two decoders have incompatible error granularity that no mapping can
  reconcile. It
  costs nothing today — the target has ONE seed and that seed accepts — so the
  target contributes no evidence either way. Two issues are filed: **#641** for the
  five, **#640** for `manifest_file`'s granularity mismatch.

**This reverses an earlier scoping decision, deliberately.** `manifest_file` was
included on the argument that it shares the Rust enum and is therefore nearly
free. Measurement falsified that: sharing an enum is not sharing a granularity.
The `RuleToken` mapping still covers every `ManifestError` variant exhaustively,
including the file-level ones, because the match must be total for the compiler
to enforce classification — those tokens simply never reach a comparison.

### 5.2 The rule

For a token-compared target where both sides rejected:

```
tokens equal                         -> agreement
either token is phase-dependent      -> agreement (§4.2 leaves the order free)
otherwise                            -> DISAGREEMENT
```

The tolerance is a **predicate derived from the spec sentence**, not a
hand-maintained list of pairs. That matters: a pair list would have to be
re-derived every time a token is added, and would drift from §4.2 silently. The
predicate cannot, because `is_phase_dependent` is the sentence.

A **missing** token on a token-compared target is a harness failure, not a pass —
the default-deny posture `_REJECTION_EXCEPTIONS` and the hygiene guards already
take. It fails loudly, naming the exception class that needs typing.

### 5.3 Protocol change

The reject shape gains one field:

```json
{"status": "reject", "error_class": "...", "detail": "...", "rule": "array_sort_order"}
```

`error_class` and `detail` are unchanged, so nothing that reads them moves.
`docs/manual/contributors/differential-replay-protocol.md` is updated in the same
commit, per its own "extend both sides in lockstep" rule. Two stale facts in that
document are corrected while it is open: it says "six fuzz target names" and omits
`manifest_body`, and its reject-shape section says `error_class` is "currently NOT
compared", which this slice changes.

---

## 6. Proving it is not decorative

§2.1 establishes that the comparison passes vacuously on today's corpus. Four
independent pieces of evidence close that.

1. **A committed positive control for the tolerance.** #621's splice becomes
   `core/tests/data/diff_regressions/manifest_body/arraysort_plus_indefinite.bin`
   — exactly the artefact the protocol doc prescribes for a sticky divergence.
   Its two tokens genuinely differ (`array_sort_order` vs
   `rule2_indefinite_length`), so it exercises the tolerance rule on every run.
   Delete the tolerance and the differential test reds.
2. **A negative control that cannot be a corpus input.** Nothing else in the tree
   diverges, so "tokens differ and it is NOT tolerated" has no witness among real
   bytes. It is a unit test on the predicate instead. This follows #618's own
   recorded lesson: a cross-language corpus is the wrong home for an invariant
   only one implementation owes, and a corpus row asserting an order §4.2 leaves
   free would fail a conformant reader.
3. **A shared vocabulary fixture.** `core/tests/data/rule_token_vocabulary.json`
   lists every token with its phase classification. A Rust unit test asserts
   `RuleToken`'s image is exactly the fixture's key set and the phase flags
   match; a new conformance Section asserts the same of the Python side. Without
   it the two languages could drift onto different spellings and every
   comparison would silently become a mismatch — or, worse, a tolerated one.
   REG goes 28 → 29.
4. **Mutation.** Every new assertion is mutated and watched to red, with the
   harness clearing `__pycache__` and setting `PYTHONDONTWRITEBYTECODE` — the
   trap the previous slice hit, where a size-preserving Python mutation reported
   a false green because CPython invalidates bytecode on `(mtime, size)` with
   whole-second mtime.

The mutation set must include at minimum: deleting the tolerance predicate;
inverting it; deleting the token comparison entirely; changing one Rust arm to a
neighbouring token; changing one Python subclass's token; removing a token from
the vocabulary fixture; and removing a target from the token-compared table.

---

## 7. Files

| File | Change |
|---|---|
| `docs/vault-format.md` | §4.2 unspecified sentence widened (#621) |
| `docs/manual/contributors/differential-replay-protocol.md` | reject shape gains `rule`; two stale facts corrected |
| `core/src/vault/manifest/token.rs` (+ `token/tests.rs`) | new: `RuleToken`, `ManifestError::rule_token()` |
| `core/src/vault/manifest/mod.rs` | wire the module, re-export |
| `core/tests/differential_replay.rs` | classification table, token comparison, tolerance |
| `core/tests/data/rule_token_vocabulary.json` | new: the shared vocabulary |
| `core/tests/data/diff_regressions/manifest_body/arraysort_plus_indefinite.bin` | new: #621's splice |
| `core/tests/python/conformance_lib/codec/manifest_rules.py` | new: typed exception hierarchy |
| `core/tests/python/conformance_lib/codec/manifest_decode.py` | raise sites typed, messages preserved |
| `core/tests/python/conformance_lib/codec/scanner.py` | tokens on the two existing typed classes |
| `core/tests/python/conformance_lib/diff_replay.py` | emit `rule` |
| `core/tests/python/conformance_lib/sections/rule_token_vocabulary.py` | new Section |
| `core/tests/python/conformance_lib/sections/registry.py` | register it |

Every new file is designed as a directory module where it would otherwise pass
500 lines, per the repo's standing guideline.

---

## 8. What this slice does NOT claim

- **It does not make the two implementations agree on every multi-violation
  body.** §4.2 declares several orders free, and the tolerance rule honours that
  rather than removing it. A divergence inside a tolerated pair remains
  invisible to the harness — by design, and now stated in `docs/` rather than
  implied by a comment.
- **It does not cover six of the seven targets.** That is recorded in the
  classification table and filed, not left to inference. `manifest_file` is
  excluded for a measured structural reason (§4.3), not merely for effort.
- **It does not close #635.** The Rust mapping lives inside the crate precisely
  to work around `pub(crate)`; the integration-test corpora that assert only a
  variant FAMILY are untouched.
- **The token vocabulary is coarse on purpose.** `container_malformed` merges
  eight `manifest_file` variants. Refining it later is additive; over-refining it
  now creates distinctions both languages must maintain with no divergence to
  catch.
- **The Rust mapping's file-level arms are never exercised by a comparison.**
  They exist so the exhaustive match compiles and so a new file-level variant is
  still forced through classification. Do not read a `container_malformed` arm as
  a claim that anything checks it cross-language.
