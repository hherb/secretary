# Design: the byte-level well-formedness walk on the manifest and block-plaintext paths (#666, #685)

Branch `feature/well-formedness-walk-manifest-block`, worktree
`.worktrees/wellformed-walk`, base `bf63cc39` (`main`, immediately after
PR #684 merged).

#641 added `cbor::well_formed::walk_first_item` and wired it into
`record::decode` alone. `decode_manifest` and `block::decode_plaintext` parse
through the same `from_secret_reader`, so the same `ciborium` leniencies reach
them. This slice wires the walk into both, and gives the Python manifest and
trash-entry decoders the precedence `docs/vault-format.md` §4.2 already
requires.

**No frozen-spec edit.** §4.2's well-formedness precondition is already
normative and already names these cases by hand ("a truncated head, a length
that overruns the buffer, a text string that is not valid UTF-8, a major-7
value outside `false`/`true`/`null`, a chain of arrays, maps and tags nested
more than 256 deep"). This is code catching up to a frozen spec, the posture
of #586 and #602 — not a ruling, the posture of #667 and #670. The one place
report order is still parity rather than spec is `record` and block plaintext
(§6.1 / §6.3), and that text is **#668**, deliberately not this slice.

---

## 1. What was measured before designing

A throwaway probe wrote eleven `manifest_body` bodies to a scratch directory:
the committed accepting base `manifest_body/uniq__control__all_distinct.bin`
with one entry `("zz_future", <value>)` spliced in at its canonical position
(length-first, so *between* `suite_id` and `vault_uuid` — appending it instead
makes the body non-canonical, which the control row caught). The Rust column
is `decode_manifest(..).rule_token()` run from a temporary `#[ignore]`d test in
this worktree, deleted before the first commit. The Python column is
`conformance_lib.diff_replay.replay_bytes("manifest_body", ..)`.

| Planted value | Rust today | Python today | Agree today? |
| --- | --- | --- | --- |
| `00` (control) | accept | accept | yes |
| `f7` (`undefined`) | `non_canonical_unclassified` | `malformed_cbor` | **no — never tolerated** |
| `f8 15` (two-byte simple) | `non_canonical_unclassified` | `malformed_cbor` | **no — never tolerated** |
| `5f 5f 41 61 ff ff` (nested chunk) | `rule2_indefinite_length` | `malformed_cbor` | **no — never tolerated** |
| `61 ff` (invalid UTF-8) | `malformed_cbor` | `malformed_cbor` | yes |
| `c2 41 01` (bignum, fits 64 bits) | `non_canonical_unclassified` | `rule4_tag_or_float` | no — tolerated |
| `c2 49 01*9` (bignum, 9 bytes) | `rule4_tag_or_float` | `rule4_tag_or_float` | yes |
| `d8 1c 81 d8 1d 00` (tags 28/29) | `rule4_tag_or_float` | `rule4_tag_or_float` | yes |
| `82 c2 41 01 f7` (tag, then `undefined`) | `non_canonical_unclassified` | `rule4_tag_or_float` | no — tolerated |
| `82 f7 c2 41 01` (`undefined`, then tag) | `non_canonical_unclassified` | `rule4_tag_or_float` | no — tolerated |
| `82 f9 00 00 f7` (float, then `undefined`) | `rule4_tag_or_float` | `rule4_tag_or_float` | yes — **both non-conformant** |

Three conclusions, each of which changed this design:

1. **Three live divergences are in the never-tolerated class.** CLAUDE.md
   records that a pair naming `malformed_cbor` is never tolerated, because
   §4.2 makes well-formedness the precondition for both orderings. So these
   are not "a diagnostic that could be better": a committed seed for any of
   them reds `differential_replay` today. None exists, which is why the replay
   reports full agreement. #666 describes the class as reporting-only; that is
   true of the manifest's *acceptance* and not of its *agreement*.
2. **#666's Python claim is stale.** It says the Python manifest path "checks
   neither UTF-8 nor simple values". It does — #641 moved those predicates to
   `codec/cbor_faults.py` and `scanner._scan_item` calls them, which the
   `undefined`, two-byte-simple, nested-chunk and invalid-UTF-8 rows all show.
   What Python actually lacks is **precedence**: the last three rows are bodies
   that are not well-formed, and it reports rule 4 for them, which §4.2's
   precondition forbids.
3. **Agreement is not conformance.** `82 f9 00 00 f7` is the row that matters
   most for the slice's justification: both implementations say
   `rule4_tag_or_float`, both are wrong, and no cross-language gate can see it
   because they are wrong in the same direction. Only the spec sentence
   distinguishes them.

After this slice every row in that table agrees strictly, and the last one is
conformant on both sides.

**Not yet measured, and owned by Task 1 of the plan:** the same eleven shapes
against `block::decode_plaintext`, and whether any of the 47 committed
`manifest_body` seeds changes its token. Task 1 re-runs the table above from
the branch and records both. A token that moves on an existing seed is a STOP:
it means the walk is rejecting something a corpus row asserts is rejected
otherwise, and the design is revisited before any seed is regenerated.

### 1.1 Baseline measured on the branch

Measured on this branch, commit `bf63cc39` base, via the temporary
`#[ignore]`d probe `core/tests/zz_baseline_probe.rs` (Rust) and
`conformance_lib.diff_replay.replay_bytes` (Python), deleted / left
unmodified respectively before this task's commit. Raw output archived
under the git-ignored `.superpowers/sdd/2026-09-22-well-formedness-walk-manifest-block/`
workspace as `baseline-rust.txt`, `baseline-py.txt` and `baseline-block.txt`
(the eleven block bodies themselves are under `block_bodies/`, kept for
Task 4).

**All 47 committed `manifest_body` seeds, both languages, today:**

| Seed | Rust token | Python status | Python rule | Agree? |
| --- | --- | --- | --- | --- |
| `arraysort__block1_recipients` | `ArraySortOrder` | reject | `array_sort_order` | yes |
| `arraysort__block1_vector_clock_summary` | `ArraySortOrder` | reject | `array_sort_order` | yes |
| `arraysort__block_recipients` | `ArraySortOrder` | reject | `array_sort_order` | yes |
| `arraysort__block_vector_clock_summary` | `ArraySortOrder` | reject | `array_sort_order` | yes |
| `arraysort__blocks` | `ArraySortOrder` | reject | `array_sort_order` | yes |
| `arraysort__trash` | `ArraySortOrder` | reject | `array_sort_order` | yes |
| `arraysort__vector_clock` | `ArraySortOrder` | reject | `array_sort_order` | yes |
| `block__control_array` | ACCEPT | accept | — | yes |
| `block__control_canonical` | ACCEPT | accept | — | yes |
| `block__rule1_key_order` | ACCEPT | accept | — | yes |
| `block__rule2_indefinite_map` | `Rule2IndefiniteLength` | reject | `rule2_indefinite_length` | yes |
| `block__rule3_non_shortest_int` | `Rule3NonShortestForm` | reject | `rule3_non_shortest_form` | yes |
| `block__rule4_float` | `Rule4TagOrFloat` | reject | `rule4_tag_or_float` | yes |
| `block__rule5_duplicate_key` | ACCEPT | accept | — | yes |
| `keyorder__block` | `NonCanonicalUnclassified` | reject | `non_canonical_unclassified` | yes |
| `keyorder__kdf_params` | `NonCanonicalUnclassified` | reject | `non_canonical_unclassified` | yes |
| `keyorder__top` | `NonCanonicalUnclassified` | reject | `non_canonical_unclassified` | yes |
| `keyorder__trash` | `NonCanonicalUnclassified` | reject | `non_canonical_unclassified` | yes |
| `nesting__2048_unknown` | `MalformedCbor` | reject | `malformed_cbor` | yes |
| `nesting__256_unknown` | ACCEPT | accept | — | yes |
| `nesting__257_unknown` | `MalformedCbor` | reject | `malformed_cbor` | yes |
| `top__control_array` | ACCEPT | accept | — | yes |
| `top__control_canonical` | ACCEPT | accept | — | yes |
| `top__rule1_key_order` | ACCEPT | accept | — | yes |
| `top__rule2_indefinite_map` | `Rule2IndefiniteLength` | reject | `rule2_indefinite_length` | yes |
| `top__rule3_non_shortest_int` | `Rule3NonShortestForm` | reject | `rule3_non_shortest_form` | yes |
| `top__rule4_float` | `Rule4TagOrFloat` | reject | `rule4_tag_or_float` | yes |
| `top__rule5_duplicate_key` | ACCEPT | accept | — | yes |
| `trash__control_array` | ACCEPT | accept | — | yes |
| `trash__control_canonical` | ACCEPT | accept | — | yes |
| `trash__rule1_key_order` | ACCEPT | accept | — | yes |
| `trash__rule2_indefinite_map` | `Rule2IndefiniteLength` | reject | `rule2_indefinite_length` | yes |
| `trash__rule3_non_shortest_int` | `Rule3NonShortestForm` | reject | `rule3_non_shortest_form` | yes |
| `trash__rule4_float` | `Rule4TagOrFloat` | reject | `rule4_tag_or_float` | yes |
| `trash__rule5_duplicate_key` | ACCEPT | accept | — | yes |
| `uniq__blocks__duplicate_block_uuid` | `RepeatedArrayValue` | reject | `repeated_array_value` | yes |
| `uniq__control__all_distinct` | ACCEPT | accept | — | yes |
| `uniq__recipients__duplicate_contact_uuid` | ACCEPT | accept | — | yes |
| `uniq__trash__duplicate_block_uuid` | `RepeatedArrayValue` | reject | `repeated_array_value` | yes |
| `uniq__vector_clock__duplicate_device_uuid` | `RepeatedArrayValue` | reject | `repeated_array_value` | yes |
| `uniq__vector_clock_summary__duplicate_device_uuid` | `RepeatedArrayValue` | reject | `repeated_array_value` | yes |
| `valuetype__trash_fingerprint_bool` | `WrongType` | reject | `wrong_type` | yes |
| `valuetype__trash_fingerprint_short` | `WrongType` | reject | `wrong_type` | yes |
| `valuetype__trash_fingerprint_text` | `WrongType` | reject | `wrong_type` | yes |
| `valuetype__trash_purged_bool` | `WrongType` | reject | `wrong_type` | yes |
| `valuetype__trash_purged_negative` | `IntegerOutOfRange` | reject | `integer_out_of_range` | yes |
| `valuetype__trash_purged_text` | `WrongType` | reject | `wrong_type` | yes |

Every one of the 47 rows agrees **strictly** — token-for-token, not merely
under §4.2's phase-dependent tolerance — between the two languages today.
(21 of the 47 tokens are themselves in the phase-dependent-tolerant set
`{array_sort_order, rule2_indefinite_length, rule3_non_shortest_form,
non_canonical_unclassified}` — the 7 `arraysort__*` plus the 4 `keyorder__*`
plus the 3 `rule2` and 3 `rule3` rows at each of the `block`/`top`/`trash`
levels — but every one of those 21 also happens to land on the *same*
token in both languages today, so the tolerance is not doing any work in
this baseline.) `block__`/`top__`/`trash__rule1_key_order` and
`*_rule5_duplicate_key` correctly ACCEPT at all three levels, matching
crypto-design §6.2 rules 1 and 5 being scoped to material the reader
interprets (unenforced inside the manifest's forward-compat `unknown`
subtree); `uniq__recipients__duplicate_contact_uuid` correctly ACCEPTs as
the documented `recipients` exception to the repeated-array-value rule. No
seed's Rust token is inconsistent with what its name asserts — **the STOP
condition in Step 5 does not fire.**

**The eleven shapes against `block::decode_plaintext`**, using a minimal
single-key block-plaintext map (`{"zz_future": <planted value>}`, Step 2's
script) rather than the manifest's full accepting body, because `BlockError`
has no `rule_token()` (no block target is token-compared in the differential
replay), the table reports the error's `Display` plus the variant it comes
from:

| Planted value | Manifest answer (§1) | Block answer today | Block variant |
| --- | --- | --- | --- |
| `00` (control) | accept | `missing required field in block plaintext: block_version` | `MissingField { field: "block_version" }` |
| `f7` (`undefined`) | `non_canonical_unclassified` | `missing required field in block plaintext: block_version` | `MissingField { field: "block_version" }` |
| `f8 15` (two-byte simple) | `non_canonical_unclassified` | `missing required field in block plaintext: block_version` | `MissingField { field: "block_version" }` |
| `5f 5f 41 61 ff ff` (nested chunk) | `rule2_indefinite_length` | `missing required field in block plaintext: block_version` | `MissingField { field: "block_version" }` |
| `61 ff` (invalid UTF-8) | `malformed_cbor` | `CBOR decode error: CBOR syntax error at byte offset 11` | `CborDecode(CborFault)` |
| `c2 41 01` (bignum, fits 64 bits) | `non_canonical_unclassified` | `missing required field in block plaintext: block_version` | `MissingField { field: "block_version" }` |
| `c2 49 01*9` (bignum, 9 bytes) | `rule4_tag_or_float` | `CBOR tags are not permitted in v1 block plaintext` | `TagRejected` |
| `d8 1c 81 d8 1d 00` (tags 28/29) | `rule4_tag_or_float` | `CBOR tags are not permitted in v1 block plaintext` | `TagRejected` |
| `82 c2 41 01 f7` (tag, then `undefined`) | `non_canonical_unclassified` | `missing required field in block plaintext: block_version` | `MissingField { field: "block_version" }` |
| `82 f7 c2 41 01` (`undefined`, then tag) | `non_canonical_unclassified` | `missing required field in block plaintext: block_version` | `MissingField { field: "block_version" }` |
| `82 f9 00 00 f7` (float, then `undefined`) | `rule4_tag_or_float` | `float values are not permitted in v1 block plaintext (in field <root>)` | `FloatRejected { field: "<root>" }` |

Seven of the eleven shapes report `MissingField { field: "block_version" }`
on the block path today rather than anything related to the planted
leniency — a consequence of the probe body's construction (Step 2's script,
matching this design's own §1 note that the manifest bodies "are
manifest-shaped and will fail block decode for an unrelated reason"): a
minimal one-key map has no `block_version`, `block_uuid` or any other
required field, so `block::decode_plaintext`'s required-field check fires
before the value under `zz_future` is ever examined for canonicality. The
four shapes that are **not** masked agree with the manifest column in
substance: `invalid_utf8_text` fails the raw `ciborium` parse in both
decoders before any required-field check can run (`CborDecode`/
`malformed_cbor` are the same error class), and the three rule-4 shapes
(`bignum_wide`, `shareable_cycle`, `float_then_undefined`) are already caught
by block's own pre-existing tree-wide `reject_floats_and_tags` call — the
same defence-in-depth call `decode_manifest` already has — which runs ahead
of required-field parsing on both paths today, independently of this
slice's walk. No block answer contradicts anything a reader would call
"wrong"; the divergence is fully explained by the probe body shape, not by
a decoder inconsistency, so it does not trigger the Step 5 STOP condition
either.

---

## 2. Decisions

1. **One generic helper, three call sites** (§3), not three copies of
   `walk_fault_to_record_error`. Thirty-one hand-copied duplicate-key guards
   (#589), seven hand-copied required-key checks (#597), and several copies of
   the `isinstance(x, int)` rule (#669) are this repo's standing evidence that
   a rule written once per call site drifts. Three is where that starts.
2. **The helper lives in `vault/canonical/walk.rs`, not in `cbor`.** Its
   rule-4 arm must name `CanonicalError`, which lives under `vault`, so putting
   it in `cbor` would invert the layering. A NEW file rather than an existing
   one: the crate's other rule-4 entry point, `reject_floats_and_tags`, is in
   `canonical/legacy.rs`, and a helper this slice introduces should not be
   filed under "legacy".
3. **Python's manifest and trash-entry decoders call `walk_body`**, replacing
   `reject_excessive_nesting` (both) and the scanner's `reject_floats_and_tags`
   (manifest). One traversal with content checks on, which is what gives the
   §4.2 precedence: `walk_body` parks the first rule-4 fault and raises it only
   once the whole item has proven well-formed.
4. **`record::decode_value` gets nothing.** There are no bytes at that level.
   The block's own walk covers every nested record, exactly as the block's
   re-encode already subsumes the per-record byte check (#547 Task 6).
5. **No proptest.** #666's acceptance asks for a legacy-oracle proptest per
   decoder; the controller declined it. §7 states what stands in its place and
   what that substitution does not cover.

---

## 3. Rust

### 3.1 The helper

In a new `core/src/vault/canonical/walk.rs`, re-exported from that module's
`mod.rs` (see decision 2 for why not `legacy.rs`, where
`reject_floats_and_tags` lives):

```rust
/// Walk the first CBOR item in `bytes` before any parse, projecting a
/// [`WalkFault`] onto the caller's error type: a well-formedness fault
/// through `cbor_decode`, a §6.2 rule-4 fault through the caller's
/// `From<CanonicalError>`.
pub(crate) fn walk_first_item_checked<E>(
    bytes: &[u8],
    cbor_decode: fn(CborFault) -> E,
) -> Result<usize, E>
where
    E: From<CanonicalError>,
```

The rule-4 arms construct `CanonicalError::{TagRejected, FloatRejected}` with
`field: "<root>"` — the same hint the tree-wide `reject_floats_and_tags` call
already passes at each of these three sites, so the reported message does not
move.

**Why this subsumes `record`'s private copy exactly, and not merely
equivalently.** `From<CanonicalError> for RecordError` maps `FloatRejected {
field }` to `RecordError::FloatRejected { field }` and `TagRejected { .. }` to
`RecordError::TagRejected` — which is `walk_fault_to_record_error`'s body,
term for term. `walk_fault_to_record_error` is therefore **deleted**, not left
beside the helper. `From<CanonicalError> for BlockError` has the same shape;
`ManifestError` carries `Canonical(#[from] CanonicalError)`.

### 3.2 The three call sites

| Decoder | Change | `cbor_decode` |
| --- | --- | --- |
| `record::decode` | swap the private fn for the helper | `RecordError::CborDecode` |
| `manifest::decode_manifest` | new first statement, ahead of `from_secret_reader` | `ManifestError::CborDecode` |
| `block::decode_plaintext` | new first statement, ahead of `from_secret_reader` | `BlockError::CborDecode` |

Each keeps its existing tree-wide `reject_floats_and_tags` call, which becomes
defence in depth on that path — the wording `record.rs` already uses. The
returned end offset is discarded at all three, and each says so in one line:
trailing bytes are judged by the re-encode comparison, where `record::decode`
already judges them, because `ciborium` performs no EOF check.

### 3.3 The ciborium pins move

`core/tests/nesting_depth_seeds.rs`'s
`every_decode_path_enforces_exactly_the_v1_limit` today pins `ciborium`'s
recursion limit on four paths and the walk on one (`record::decode`). After
this slice the manifest and block-plaintext rows pin **the walk**, and
`ContactCard::from_canonical_cbor` and `IdentityBundle::from_canonical_cbor`
are the only remaining `ciborium` pins. That is a narrowing of what the test
proves about `ciborium`, so it must be stated in the test's own doc rather than
left for a reader to infer from the row list: a `ciborium` upgrade that changed
the limit would now be caught by two paths, not four.

### 3.4 Rule tokens

No new `RuleToken` variant and no change to `manifest/token.rs`'s exhaustive
match: `CborDecode` already maps to `malformed_cbor` and
`Canonical(TagRejected | FloatRejected)` to `rule4_tag_or_float`. What moves is
which variant a body reaches, which is the point.

---

## 4. Python

### 4.1 `py_decode_manifest`

Replace

```python
reject_excessive_nesting(data, later_phases_scan_in_byte_order=True)
reject_floats_and_tags(data)
```

with a single `walk_body(data)`.

`walk_body` is a superset of both: it enforces rule 6 (the whole reason
`reject_excessive_nesting` was the first statement), it raises rule 4 for the
first tag or float, and it parks that fault until the item has proven
well-formed — which is the precedence the measurement in §1 shows is missing.
The content checks it adds over `reject_excessive_nesting` (UTF-8, simple
values) are already performed later by `_scan_item`; what changes is that they
now run **before** rule 4 rather than after it.

`reject_excessive_nesting`'s `later_phases_scan_in_byte_order` parameter exists
for callers whose next phase is not a byte-order well-formedness check. The
manifest passed `True`, meaning "return at a structural fault and let
`_scan_item` report it". `walk_body` raises instead. Those faults are the same
fault at the same byte — both walks are byte-order — so what changes is the
exception's identity, not the verdict or the offset. Task 2 measures that
across the 47 committed seeds rather than assuming it.

### 4.2 `py_decode_trash_entry` — #685

Replace `reject_excessive_nesting(data, later_phases_scan_in_byte_order=False)`
with `walk_body(data)`.

#685: `cbor2.loads` resolves tag 28 (shareable) and tag 29 (sharedref) into a
genuinely **cyclic** Python list and strips both tags, so `d8 1c 81 d8 1d 00`
under an unknown key makes the recursive `_reject_floats_and_tags_py` raise
`RecursionError` — a harness failure, not a verdict — and tag 28 alone is
stripped before rule 4 can see it at all. `walk_body` reads the tag off the
bytes and raises rule 4 before `cbor2` is ever called, so neither can happen.
This is the fix #685 itself proposes.

The recursive `_reject_floats_and_tags_py(decoded)` call after `cbor2.loads`
stays, as defence in depth, with a line saying why it can no longer meet a
cycle.

**Why the manifest path was immune.** It never calls `cbor2.loads` on the whole
body — it scans spans and retains unknown subtrees as raw bytes — which is why
the `d8 1c 81 d8 1d 00` row in §1 returns a verdict rather than raising.
`py_decode_trash_entry` is standalone: no replay target reaches it, so CI never
saw this.

### 4.3 What is deliberately NOT changed

`codec/card.py` has the same shape as `trash_entry` and the same gap. It is
#641's next target, with its own acceptance criteria (a token taxonomy,
`CardError` → `RuleToken` totality, a `contact_card/nesting__257_*` seed), and
doing its walk here would split that slice's evidence across two PRs. Stated in
the module rather than only here, so the asymmetry does not read as an
oversight.

---

## 5. Committed seeds

Nine new `manifest_body` seeds, in two families, because they bind different
things. The committed corpus goes 131 → 140; `MIN_CORPUS_INPUTS` and Section
RTV's `_CORPUS_TOKENS` are both re-measured rather than predicted.

### 5.1 `core/tests/well_formed_seeds.rs` — a new generator, prefix `wellformed__`

Seven rows, each a single fault planted under `zz_future` in
`uniq__control__all_distinct.bin` at its canonical position, each binding a
**token**:

| Row | Planted | Token after |
| --- | --- | --- |
| `wellformed__undefined` | `f7` | `malformed_cbor` |
| `wellformed__two_byte_simple` | `f8 15` | `malformed_cbor` |
| `wellformed__nested_indefinite_chunk` | `5f 5f 41 61 ff ff` | `malformed_cbor` |
| `wellformed__invalid_utf8` | `61 ff` | `malformed_cbor` |
| `wellformed__bignum_narrow` | `c2 41 01` | `rule4_tag_or_float` |
| `wellformed__tag_then_malformed` | `82 c2 41 01 f7` | `malformed_cbor` |
| `wellformed__float_then_malformed` | `82 f9 00 00 f7` | `malformed_cbor` |

The last two are the **precedence** rows: they are the only seeds that would
red a walk which reported a parked rule-4 fault instead of the well-formedness
fault it met later. Without them the parking behaviour — the one piece of
§4.2's precondition that is not merely "reject it somehow" — is asserted by
Rust unit tests alone and by nothing cross-language.

`wellformed__invalid_utf8` already agrees today. It is committed anyway: it is
the only UTF-8 pin on the manifest path, and a row that agrees is still a
regression pin.

**Why not `rule_token_seeds.rs`.** That file's census owns *every* labelled
file in a seeded target's directory (`SEEDED_TARGETS = ["block_file",
"record"]`). Adding `manifest_body` would make it claim all 47 existing seeds —
`arraysort__`, `keyorder__`, `uniq__`, `valuetype__`, `top__`, `block__`,
`trash__`, `nesting__` — which is exactly the trap `nesting__`'s by-name
exclusion already documents. A separate generator with its own prefix and its
own two-way census is the shape #667 established for the same reason.

The generator follows the house discipline established by
`nesting_depth_seeds.rs` and `manifest_canonicality_kat.rs`: it asserts every
row against the real decoder **before** writing any file (so a wrong row panics
with the corpus untouched), it requires every row to plant distinct bytes, its
census is two-way and scoped to its prefix, and its base must still accept.

### 5.2 `core/tests/nesting_depth_seeds.rs` — two rows

`NestingCase` gains a dimension for what sits at the deepest level. Today every
row nests one-element arrays; the two new rows put a bignum at level 257, at
**both** widths (`c2 41 01` and `c2 49 01*9`), because they take different
`ciborium` paths: the narrow one folds to an integer, the wide one stays a
`Value::Tag`. That is the edge the last handoff's §(2) measured and left open,
and it is the one place where wiring the walk changes a **depth** verdict's
token rather than a content fault's.

Both rows are `Verdict::TooDeep`. Their file names derive from the new
dimension, so a row whose name disagrees with what it plants is
unconstructible — the rule `manifest_canonicality_kat`'s `SortedArray` enum
established.

---

## 6. Python sections

No new conformance section. Section **RTV**'s corpus-token set equality and
Section **RTS**'s label binding already cover the new seeds by construction,
and Section **NDL**'s check 6 covers the two `nesting__` rows. What each needs
is re-measurement, not new code:

- RTV's `_CORPUS_TOKENS` — the new seeds reach `malformed_cbor` and
  `rule4_tag_or_float`, both already in the set, so the expectation is that it
  does **not** move. Task 5 measures it; RTV's failure message asks for the
  edit by name if it does.
- NDL's check 6 spells seed names from the constant; the two new `nesting__`
  rows must appear there.

Section **CS** (`cbor_scanner`) gains one check: `walk_body` parks a rule-4
fault behind a later well-formedness fault. That is the Python twin of the two
precedence seed rows, and it belongs in CS because it is a property of *this*
implementation's traversal, not a claim about every conformant reader — the
distinction #618's review drew when it moved a scope claim out of a corpus row
and into a local assertion.

---

## 7. Proving it is not decorative

`git grep` cannot show that a check is load-bearing, so each of the following
is measured with `scripts/mutate.py`, spec written to the session scratchpad
(#516), each row naming its gate (#651):

| Mutation | Expected red |
| --- | --- |
| `decode_manifest`'s walk call deleted | the four `wellformed__` `malformed_cbor` seeds, via `differential_replay` |
| `block::decode_plaintext`'s walk call deleted | block unit tests (no replay target reaches block plaintext) |
| The helper's `Malformed` arm pointed at the rule-4 arm | `wellformed__` precedence rows |
| `walk_first_item`'s rule-4 parking made eager | `wellformed__tag_then_malformed`, `wellformed__float_then_malformed`, Section CS |
| Python's `walk_body` call in `py_decode_manifest` reverted to the two old calls | the same seeds, from the other side |
| Python's `walk_body` call in `py_decode_trash_entry` reverted | the #685 regression test |
| `V1_MAX_NESTING_DEPTH` 256 → 257 | NDL check 6 (as at #667) |

### What replaces the proptest #666 asked for

#666's acceptance asks for a legacy-oracle proptest per decoder showing the
accepted set does not move. It is not in this slice. In its place:

- **The walk cannot widen acceptance.** It runs before the parse and only
  returns `Ok` or an error; no path through it makes a previously-rejected body
  accepted. So the claim reduces to one direction: no previously-**accepted**
  body is now rejected.
- **`record`:** the full local fuzz corpus (≈7,495 inputs) replayed base
  against branch, requiring 0 verdicts to move. This is the strong evidence,
  and it covers the helper — the code path all three decoders now share.
- **`block_file` plaintext:** the workspace suite, which opens vaults on
  essentially every integration test, plus the golden vault.
- **`manifest_body`:** the 47 committed seeds (their accepting rows included),
  the golden vault's manifest, and `manifest_canonicality_kat`'s accepting
  rows.

**The residual, stated rather than dropped:** `manifest_body` has no fuzz
corpus, so its breadth evidence is a few dozen hand-built bodies where
`record`'s is thousands of fuzzer-found ones. "Acceptance unchanged" is
corpus-proven for `record` and argued-plus-spot-checked for the manifest. A
future `manifest_body` fuzz target would close that; it is not this slice.

---

## 8. What this slice does NOT do

- **`contact_card`'s Python pre-pass** (§4.3) — #641's next target.
- **`bundle_file` and `manifest_file`** — #677 and #640.
- **§6.1 / §6.3 report-order spec text** — #668. The record and block-plaintext
  orders remain parity.
- **The writer half of rule 6** — #681, untouched.
- **Narrowing the per-token tolerance** — #646. This slice removes three
  never-tolerated divergences and three tolerated ones by making both sides
  agree, which reduces how much the tolerance is hiding; it does not change the
  predicate.

---

## 9. Files

**Rust, changed:** `core/src/vault/canonical/mod.rs` (declare and re-export
`walk`), `core/src/vault/record.rs` (swap, delete the private fn),
`core/src/vault/manifest/decode/mod.rs`, `core/src/vault/block.rs`,
`core/tests/nesting_depth_seeds.rs` and its `_helpers/`.

**Rust, new:** `core/src/vault/canonical/walk.rs` (the helper and its tests),
`core/tests/well_formed_seeds.rs` plus a `_helpers/` module for its table,
split from the start so neither passes 500 lines.

**Python, changed:** `conformance_lib/codec/manifest_decode.py`,
`conformance_lib/codec/trash_entry.py`,
`conformance_lib/sections/cbor_scanner.py`.

**Seeds, new:** 7 `core/fuzz/seeds/manifest_body/wellformed__*.bin`, 2
`core/fuzz/seeds/manifest_body/nesting__*bignum*.bin`.

**Docs:** `CLAUDE.md` (the manifest decoder's leniency paragraph and the
ciborium-pin count), `ROADMAP.md` if the slice state moves, and the handoff.
No normative doc under `docs/` changes — see the header.
