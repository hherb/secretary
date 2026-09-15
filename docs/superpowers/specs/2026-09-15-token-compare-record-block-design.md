# Design: token-compare `block_file` and `record` in the differential replay (#641)

Status: approved in brainstorming, 2026-09-14/15. Branch
`feature/token-compare-record-block`, base `4f350d64`.

#634 made `differential_replay.rs` compare WHICH rule each decoder names, for
`manifest_body` only. #641 asks for the other targets, ordered by value:
`record` and `block_file` first, since they carry decrypted user content. This
slice does those two. `contact_card`, `bundle_file` and `vault_toml` stay under
#641, and `manifest_file` stays blocked by #640.

Five decisions were taken in brainstorming, each by options plus a
recommendation:

| # | Decision | Chosen |
|---|---|---|
| D1 | Scope | Both targets on one branch, `block_file` first |
| D2 | How `block_file` avoids the manifest's phase-dependent tolerance | Make the tolerance **target-aware** |
| D3 | Where the ciborium well-formedness leniencies are fixed | A Rust **byte-level pre-walk**, wired into `record::decode` only |
| D4 | Spec text for §6.1/§6.3 report order | **None**: strict parity, and file an issue |
| D5 | How CI gets rejecting inputs | **Generated single-fault seeds**, label-bound |

---

## 1. What was measured before designing

A throwaway probe (outside the tree) decoded every `record` and `block_file`
input through both implementations and tabulated each (Rust variant, Python
raise site) pair. The inputs were the committed seeds plus the main checkout's
gitignored runtime corpus: **7,454 `record`** inputs (3 seeds, 7,451 runtime)
and **118 `block_file`** inputs (1 seed, 117 runtime).

**No acceptance diverges.** The status pairs are accept/accept 3 and
reject/reject 7,451 for `record`, and 1 and 117 for `block_file`. Everything
below is about WHICH rule is named, never about WHETHER an input is accepted.

### 1.1 `block_file` is aligned by construction

Every one of the 117 rejecting inputs pairs one Rust variant with exactly one
Python raise site. Both parsers walk the §6.1 layout in the same order. The only
granularity gap is Python's `prev >= nxt` check, which merges "unsorted" and
"repeated", where Rust's `match cmp` separates them. There were 22
`VectorClockNotSorted`, 10 `RecipientsNotSorted`, 1 `VectorClockDuplicateDevice`
and 1 `DuplicateRecipient`, each against the one merged Python message.

The target is envelope-only: it round-trips `decode_block_file` →
`encode_block_file` and never decrypts. So no plaintext CBOR rule is reachable
from it, whatever `BlockError`'s plaintext variants suggest.

### 1.2 `record` diverges on ORDER, in the #618 shape

Under provisional token mappings, the current Python order gives **4,385
agree, 2,949 disagree and 120 tolerated**. The dominant classes:

| Pairs | Rust | Python | Cause |
|---|---|---|---|
| 2,847 | `malformed_cbor` | `wrong_type` | Python reads the top-level head ("expected a CBOR map") before establishing that the body is well-formed; ciborium parses the whole item first |
| 101 | `rule4_tag_or_float` | `wrong_type` | Rust's rule-4 walk runs before interpretation; Python has none |
| ~120 | a schema fault | trailing bytes | ciborium performs no EOF check, so Rust sees trailing bytes only at the re-encode |

Three Python orderings were then prototyped in scratch:

| Variant | Python order | Agree | Tolerated | Disagree |
|---|---|---|---|---|
| A | today's | 4,385 | 120 | 2,949 |
| B | whole-body well-formedness + rule-4 walk first | 7,284 | 80 | 90 |
| C | B, plus trailing bytes after the schema | 7,363 | 1 | 90 |

### 1.3 The 90 that remain are ciborium laxer than the spec

| Finding | Inputs | Mechanism |
|---|---|---|
| F1 | 57 | `undefined` (`0xf7`) is read as `null`. vault-format §4.2's well-formedness precondition names "a major-7 value outside false/true/null" as malformed; Rust parses on and names a later rule |
| F2 | 28 | Bignum tags 2/3 become integers inside ciborium, so Rust's parsed-tree rule-4 walk never sees a tag (27 inputs say `wrong_type` for a top-level `c2 …`). One more, a tag-3 bignum too wide for ciborium, fails its parse as `malformed_cbor` where Python says rule 4 |
| F3 | 4 | Nested indefinite-length string chunks are accepted, though RFC 8949 §3.2.3 forbids them |
| — | 1 | Invalid UTF-8 inside a chunk: a gap in the prototype's walk, not a finding |

Every F1–F3 input is still rejected by Rust, by the §4.3-style re-encode
comparison at the latest, because none of these forms is canonical. Fixing
them changes a reported error, never a verdict.

F1 also falsifies a claim in `codec/scanner.py`'s `_check_canonical_item`
docstring: that `ciborium::Value` has no generic simple value, so "`record.rs`/
`block.rs`/manifest decode all reject the other six major-7 shapes wholesale".
ciborium accepts `undefined`. The docstring is corrected in this slice.

---

## 2. Target-aware tolerance (D2)

`tokens_agree(rust, python)` tolerates a mismatch whenever either token is
phase-dependent. That licence is derived from vault-format §4.2's two manifest
reader designs. Applied globally, it would score a `block_file` pair such as
`array_sort_order` vs `container_malformed` as agreement. That would hide
exactly the Python sort/repeat split this slice adds, and later any `record`
ordering regression.

- `tolerance.rs`: `tokens_agree(target: &str, rust: &str, python: &str)`.
  Equal tokens always agree. Unequal tokens agree only if
  `PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(target)` and either token is
  phase-dependent.
- `targets.rs`: `pub const PHASE_DEPENDENT_TOLERANCE_TARGETS: &[&str] =
  &["manifest_body"];` with a doc saying why the licence is per section.
- `every_target_is_classified` additionally requires that list to be a subset
  of `TOKEN_COMPARED_TARGETS`.
- `agreement::judge` passes its target through.
- `tolerance_admits_only_phase_dependent_pairs` keeps its name and pins breadth
  **per target**: 58 of 136 unequal pairs on `manifest_body` (unchanged), and 0
  of 136 on every other target in `TARGETS`.

No behaviour changes for `manifest_body`. `RuleToken::is_phase_dependent` keeps
its meaning, "phase-dependent under §4.2"; where that meaning applies is now
decided by the harness.

---

## 3. Rust tokens (no new vocabulary)

`RuleToken` stays in `core/src/vault/manifest/token.rs`, since #648 owns its
public home, so no path moves and no citation goes stale. The two new impls
live in a new small directory module rather than in `record.rs` (3,037 lines)
or `block.rs` (3,222 lines):

- `core/src/vault/rule_tokens/mod.rs`: declares the two submodules and explains
  why `RuleToken` itself is not here.
- `core/src/vault/rule_tokens/record.rs`: `impl RecordError { pub fn
  rule_token(&self) -> RuleToken }`.
- `core/src/vault/rule_tokens/block.rs`: `impl BlockError { pub fn
  rule_token(&self) -> RuleToken }`.
- `core/src/vault/rule_tokens/tests/{record.rs,block.rs}`: a second,
  independent variant→token declaration per enum (the
  `manifest/token/tests/mapping.rs` pattern), so repointing an arm reds a test.

Both matches are exhaustive with no wildcard, so a new variant is a compile
error until it is classified. The token docs in `token.rs` are generalised from
"§4.2" to name the section per target where a variant's wording was
manifest-only. `rule_token_vocabulary.json` is unchanged: every mapping below
uses the existing 17 tokens.

### 3.1 `RecordError`

| Token | Variants |
|---|---|
| `malformed_cbor` | `CborDecode` (every `CborErrorKind`, including `RecursionLimit`; see §7) |
| `wrong_type` | `NotAMap`, `NonTextKey`, `WrongType`, `InvalidUuid` |
| `integer_out_of_range` | `IntegerOverflow` |
| `missing_field` | `MissingField` |
| `duplicate_map_key` | `DuplicateKey`, `CanonicalDuplicateKey` (the manifest's choice for the canonical encoder's twin) |
| `rule4_tag_or_float` | `FloatRejected`, `TagRejected` |
| `non_canonical_unclassified` | `NonCanonicalEncoding` |
| `internal_error` | `CborEncode`, `CanonicalSizeBoundExceeded` |

### 3.2 `BlockError`

| Token | Variants |
|---|---|
| `container_malformed` | `Truncated`, `BadMagic`, `WrongFileKind`, `EmptyRecipientList`, `SigEdWrongLength`, `SigPqWrongLength`, `TrailingBytes`, `VectorClockCountMismatch` |
| `unsupported_version` | `UnsupportedFormatVersion`, `UnsupportedSuiteId` |
| `array_sort_order` | `VectorClockNotSorted`, `RecipientsNotSorted` |
| `repeated_array_value` | `VectorClockDuplicateDevice`, `DuplicateRecipient` |
| `encoder_refusal` | `TooManyRecipients`, `RecipientCtPqWrongLength`, `RecipientCtWrongLength`, `SigPqTooLong` |
| plaintext, as §3.1 | `CborDecode`, `NotAMap`, `NonTextKey`, `WrongType`, `InvalidUuid`, `MissingField`, `DuplicateKey`, `CanonicalDuplicateKey`, `FloatRejected`, `TagRejected`, `NonCanonicalEncoding`, `IntegerOverflow`, `CborEncode`, `CanonicalSizeBoundExceeded` |
| delegated | `Record(e)` → `e.rule_token()` |
| diagnostics only | `Aead`, `Kem`, `NotARecipient` → `aead_failure`; `Sig`, `AuthorFingerprintMismatch` → `signature_invalid`; `BlockUuidMismatch` → `container_malformed` |

`TooManyRecipients` also has a decode-side producer (`count * 1208` overflowing
`usize`), which is unreachable on any 64-bit target, so the encode reading
decides its token. The "diagnostics only" row is unreachable from
`decode_block_file`/`encode_block_file`. Each is the nearest existing token, and
the arm comment says so.

### 3.3 Wiring

`differential_replay_helpers/rust_decoder.rs` fills `token` for the `record`
and `block_file` arms. Each target moves from `NOT_TOKEN_COMPARED_TARGETS` to
`TOKEN_COMPARED_TARGETS` only in the commit that completes its Python half and
its seeds, so no intermediate commit fails.

---

## 4. `block_file`

No Rust decoder change: §1.1 shows the order already agrees.

**Python.** A new module, `conformance_lib/wire/envelope_rules.py`, holds three
subclasses of `cursor.ParseError`. Subclassing keeps every existing
`except ParseError` (`block_kat`, `revoke`, the golden-vault verifier) and
`_REJECTION_EXCEPTIONS` unchanged.

| Class | `token` |
|---|---|
| `UnsupportedEnvelopeVersion` | `unsupported_version` |
| `EnvelopeSortOrder` | `array_sort_order` |
| `EnvelopeRepeatedValue` | `repeated_array_value` |

In `wire/block_file.py`:

- The `format_version` and `suite_id` raises become `UnsupportedEnvelopeVersion`,
  with their messages unchanged.
- The vector-clock and recipient-table `prev >= nxt` checks split at the FIRST
  out-of-place adjacent pair, exactly like Rust's `match cmp`. `==` raises
  `EnvelopeRepeatedValue` with a new message naming the repeat; `>` raises
  `EnvelopeSortOrder` with the existing message.
- Every other raise stays a plain `ParseError` (`container_malformed`).

`manifest_file` and `bundle_file` parsers are untouched, and #640 is unchanged.

**Expected.** `block_file` compares strictly with 0 tolerated pairs, and all
117 rejecting runtime inputs agree. This is measured in the slice, not assumed
from the spike.

---

## 5. `record`

### 5.1 Rust: a byte-level pre-walk (D3)

**New module `core/src/cbor/well_formed.rs`.** One pure `pub(crate)` function
walks the FIRST CBOR item of a byte slice. It is iterative, with an explicit
stack, so it has no recursion and no depth cap of its own. It returns
`Ok(end_offset)` or a fault carrying the offset of the offending head.

Well-formedness, meaning RFC 8949 plus vault-format §4.2's precondition list:

- a truncated head, argument or payload;
- reserved additional-info 28–30;
- the indefinite form on majors 0, 1 or 6, or a break outside an indefinite
  container;
- an indefinite-string chunk that is not a definite string of the same major,
  which covers F3;
- text that is not valid UTF-8, checked per definite string and per chunk;
- a major-7 simple value other than `false`/`true`/`null`, which covers F1 and
  also `ai = 24`.

Rule 4 at byte level:

- a tag of any number, including bignum tags 2 and 3, which covers F2;
- a float (major 7 with additional-info 25–27).

**Precedence.** A well-formedness fault anywhere in the item outranks a rule-4
fault anywhere. The walk records the first tag or float and keeps going, and
reports it only once the whole item has proven well-formed. That is §4.2's
precondition, which puts well-formedness ahead of rule 4, stated for the whole
item.

**`record::decode` becomes:**

1. The walk. A well-formedness fault becomes the existing
   `RecordError::CborDecode(CborFault { kind, offset: Some(off) })`. The kind is
   `Io` when the input ends first (a truncated head, argument or payload, or an
   indefinite item with no break), mirroring ciborium's end-of-input reading,
   and `Syntax` for every other fault. A tag becomes `TagRejected`; a float
   becomes `FloatRejected { field: "<root>" }`.
2. `from_secret_reader`, unchanged. After a clean walk it can only fail on
   ciborium's recursion limit.
3. The parsed-tree `reject_floats_and_tags`, unchanged and kept as defence in
   depth. Its comment says the walk now answers first.
4. `decode_value` and the re-encode comparison, unchanged.

No `RecordError` variant, no public signature and no FFI mapping changes.
`block.rs`'s nested `decode_value` path is untouched (see §7).

**The acceptance set must not move.** Two pieces of evidence:

- A unit-test oracle, `legacy_decode`: steps 2–4 without the walk, which is
  byte-for-byte the pre-slice pipeline. A proptest over byte-level mutations of
  valid records (bit flips, insertions and truncations of `login.cbor`-shaped
  bodies, plus planted F1/F2/F3 shapes) asserts
  `legacy_decode(b).is_ok() == record::decode(b).is_ok()`.
- The scratch probe, re-run over all 7,454 corpus inputs before and after:
  identical per-input accept/reject status, and the same 3 accepts.

The walk's own tests: one positive and one negative case per rule above,
precedence in both directions (a tag before a malformed item reports malformed;
a malformed item before a tag reports malformed), a chunked text string whose
UTF-8 sequence is split across chunks (the behaviour pinned against ciborium's,
measured rather than assumed), and a depth-300 well-formed array accepted by the
walk.

### 5.2 Python: typed faults, a twin walk, Rust's phase order

**`MalformedCbor`.** A new module, `codec/cbor_faults.py`, defines
`MalformedCbor(ValueError)` with `token = "malformed_cbor"`. Every structural
`ValueError` raise in `codec/scanner.py` becomes `MalformedCbor`, messages
unchanged:

- truncation and buffer overrun;
- reserved additional-info, and the indefinite form on a disallowed major;
- an unexpected break;
- an unterminated item or a bad chunk;
- invalid UTF-8;
- a bad simple value.

That also closes a latent gap on `manifest_body`, whose malformed rejections
carry no token today. The replay would score one as a harness failure the first
time the committed corpus held such an input. `scanner.py` is at 484 lines, so
the shared predicates move out rather than grow it.

**`walk_body(buf)`.** A new module, `codec/well_formed.py`, holds the twin of
the Rust walk: iterative, the same checks, the same well-formed-first
precedence. The UTF-8 and simple-value predicates become shared helpers called
by both `walk_body` and `_check_canonical_item` (the `_reject_rule4_head` move),
so the two copies cannot drift.

**`codec/record_rules.py`.** Typed, message-preserving classes:

| Class | Base | `token` |
|---|---|---|
| `RecordWrongType` | `ValueError` | `wrong_type` |
| `RecordIntegerOutOfRange` | `ValueError` | `integer_out_of_range` |
| `RecordDuplicateKey` | `ValueError` | `duplicate_map_key` |
| `RecordMissingField` | `KeyError` (so `str()` renders as today) | `missing_field` |
| `RecordNonCanonical` | `ValueError` | `non_canonical_unclassified` |

`RecordNonCanonical` is deliberately COARSE. Rust's fieldless
`NonCanonicalEncoding` cannot tell rule 1, 2, 3 or trailing bytes apart, and the
vocabulary's standing rule is that a token may only draw a distinction both
implementations can make. Its message keeps the specific text ("rule 2: …",
"trailing bytes after record map: N", "record is not in canonical CBOR form"),
which Section RC's content check reads.

**`py_decode_record` in Rust's phase order:**

1. `walk_body(data)`: `MalformedCbor`, or `NonCanonicalItem(4)` for rule 4.
2. The top-level item must be a map: `RecordWrongType`.
3. Entries in wire order. For each: key type (`RecordWrongType`), then repeat
   (`RecordDuplicateKey`), then the value interpreted and type- and
   range-checked immediately (`RecordWrongType` / `RecordIntegerOutOfRange`).
   `fields` recurses in the same per-entry order, with each field's missing keys
   (`RecordMissingField`) raised at the end of THAT field's map, mirroring
   `parse_field_map`. Unknown keys are retained verbatim, as today.
4. Missing required top-level keys, through the unchanged
   `first_missing_key_in_sorted_order`, so Section DET is unaffected.
5. Canonical form, last: rules 2/3 per value (`_check_canonical_item`; a
   `NonCanonicalItem` of rule 2 or 3 is re-raised as `RecordNonCanonical` with its
   message preserved, and every other exception it could raise is unreachable
   after step 1), then trailing bytes, then the re-encode comparison.

Negative integers become `RecordIntegerOutOfRange`, where Rust's `take_u64`
reports `IntegerOverflow`. A non-integer becomes `RecordWrongType`.

**Expected.** 0 disagreements and 0 tolerated pairs over all 7,454 `record`
inputs. Any residual is resolved in the slice, never allowlisted.

---

## 6. Committed seeds and their Python check (D5)

### 6.1 Rust generator and label binding

A new integration test, `core/tests/rule_token_seeds.rs`, with
`core/tests/rule_token_seeds_helpers/{mod.rs,record.rs,block_file.rs}`.

- **Bases** are committed files, so no hand-written byte literals are needed:
  `core/fuzz/seeds/block_file/golden.bin` (1 vector-clock entry, 1 recipient,
  5,090 bytes) and `core/fuzz/seeds/record/login.cbor` (fields `username`,
  `totp_seed`).
- **A closed case table** of `(target, token, shape)`, with a pure planting
  function per case. The file name `core/fuzz/seeds/<target>/<token>__<shape>.bin`
  is DERIVED from the row, so a file's label and its bytes cannot disagree.
- **`#[ignore]` `generate_rule_token_seeds`** builds every case, asserts every
  one rejects with its row's token, and only then writes. A mid-table failure
  therefore leaves every file untouched (the #614 lesson).
- **`rule_token_seeds_are_committed_and_label_bound`** (not ignored) runs three
  checks. For every case it regenerates the bytes and requires byte identity with
  the committed file; it requires the Rust decoder to reject with exactly the
  file name's token; and a two-way census over `*__*.bin` in both directories
  fails any stray, stale or missing seed. Accepting base files are not matched
  by the pattern.

**Planned `block_file` shapes, one fault each:**

| Token | Shapes |
|---|---|
| `container_malformed` | bad magic; wrong file kind; truncated header; truncated recipient table; zero recipients; wrong `sig_ed_len`; wrong `sig_pq_len`; truncated signature suffix; trailing bytes |
| `unsupported_version` | `format_version`; `suite_id` |
| `array_sort_order` | vector clock, 2 entries descending; recipients, 2 entries descending |
| `repeated_array_value` | vector clock, 2 equal device ids; recipients, 2 equal fingerprints |

The sort and repeat shapes splice in a second entry, with the count prefix
updated. The AAD and signature go stale, which neither decoder checks on this
target.

**Planned `record` shapes, one fault each:**

| Token | Shapes |
|---|---|
| `malformed_cbor` | truncated; `undefined` value (F1); nested indefinite chunk (F3); invalid UTF-8 text |
| `rule4_tag_or_float` | float value; tag value; bignum tag (F2) |
| `wrong_type` | top-level array; non-text key; `record_uuid` as text; short `record_uuid`; `fields` not a map |
| `integer_out_of_range` | negative `created_at_ms` |
| `missing_field` | top-level `record_uuid`; per-field `value` |
| `duplicate_map_key` | record level; `fields` level; field level |
| `non_canonical_unclassified` | map-key order; indefinite-length map (rule 2); non-shortest integer (rule 3); trailing bytes |

The exact counts are whatever the generator's table holds, and the handoff
quotes them measured.

`MIN_CORPUS_INPUTS` rises to the new committed counts. With zero tolerance on
these two targets, every rejecting committed input reaches a STRICT comparison,
so for them the input floor already is a strict-comparison floor. That covers
#658 for these two targets without new machinery; `manifest_body`'s #658 stays
open.

### 6.2 Python: Section RTS

A new registered section, `sections/rule_token_seeds.py` (Section **RTS**),
takes REG from 30/30 to 31/31. Section RTV is at 263 lines and is not grown.
RTS runs four checks:

1. **Identity:** each new typed class carries exactly its expected token
   (`MalformedCbor`, the five record classes, the three envelope classes).
2. **Label binding:** every `core/fuzz/seeds/{record,block_file}/<token>__<shape>.bin`
   is rejected by Python's decoder with exactly `<token>` (via `token_for`). It
   must be a verdict, never an `error`.
3. **Floors:** a per-target minimum seed count, so an emptied directory cannot
   pass vacuously.
4. **Coverage:** per target, the set of tokens observed equals the set of tokens
   the file names name.
5. **Local parity-order assertions for `record`.** These are two-fault bodies
   built in-section, never committed seeds, because they pin an order vault-format
   §6.3 does not state: the #618 rule is that an invariant only our own
   implementation owes belongs in a local assertion, not in a cross-language row.
   Each one reds if Python's order drifts from §5.2's:
   - a wrong-typed present key with a missing required key reports `wrong_type`;
   - a repeated key whose second copy is a float reports rule 4;
   - a malformed tail behind a non-text first key reports `malformed_cbor`;
   - a schema fault followed by trailing bytes reports the schema fault.

A malformed or missing directory yields a `FAIL:` line, never a traceback out of
`main()`.

---

## 7. What this slice does NOT do, and what gets filed

- **The walk is wired into `record::decode` only.** `decode_manifest` and
  block-plaintext decode (including `block.rs`'s nested `decode_value`) keep
  ciborium's F1–F3 leniencies in both languages. Filed as a follow-up with the
  measurement that the same parse reaches them.
- **ciborium's depth limit.** A well-formed body nested deeper than 256 levels
  is `malformed_cbor` to Rust only. No corpus input reaches it once the walk
  runs first, but nothing pins that. Filed.
- **No report-order text for vault-format §6.1/§6.3 (D4).** Strict comparison on
  these two targets pins parity between OUR two implementations. Each committed
  seed plants exactly one fault, so no committed row pins an order the spec
  leaves open; the orders that are pinned are pinned by Section RTS check 5 and
  the local full-corpus run, both named as parity. (A planted fault can have a
  downstream consequence, such as an F1 seed also failing the re-encode, but
  both implementations meet the planted fault first by construction of §5.)
  Filed, cross-referenced to #646.
- **#641 stays open** for `contact_card`, `bundle_file` and `vault_toml`.
- **The runtime corpus is still not replayed in CI.** CI has no
  `core/fuzz/corpus/`, so the full-corpus agreement is a local measurement,
  recorded in the handoff.

---

## 8. Proving it is not decorative

Mutation rows run through `scripts/mutate.py`, with scoped probes for
`core/tests/**` and each row naming its gate. Every row is expected
`RED_AS_EXPECTED` unless stated:

| Mutation | Expected red |
|---|---|
| One `RecordError` arm repointed | `rule_tokens` mapping test; `rule_token_seeds_are_committed_and_label_bound` |
| One `BlockError` arm repointed | as above |
| Tolerance loses target-awareness | `tolerance_admits_only_phase_dependent_pairs` (breadth 0 on `block_file`) |
| Walk accepts `undefined` | walk unit test; label binding on the F1 seed; `differential_replay_full_corpus` |
| Walk accepts a nested chunk | as above, for F3 |
| Walk reports rule 4 before well-formedness | walk precedence test |
| `record::decode` skips the walk | label binding on the F1/F2/F3 seeds |
| Python `>=` merge restored | Section RTS label binding; replay disagreement on the repeat seeds |
| Python type checks moved behind the missing-key check | Section RTS check 5 (the wrong-type-plus-missing case) |
| Python UTF-8 check removed from `walk_body` | Section RTS on the invalid-UTF-8 seed |
| `RecordNonCanonical` token set to `rule2_indefinite_length` | Section RTS identity; replay disagreement on the rule-2 seed |
| One committed seed's bytes swapped for another's | `rule_token_seeds_are_committed_and_label_bound` |
| `MalformedCbor` loses its token | Section RTS identity; replay harness failure on a malformed seed |

---

## 9. Files

**Rust:**

- `core/src/cbor/well_formed.rs` (new)
- `core/src/cbor/mod.rs` (declares the module)
- `core/src/vault/record.rs` (decode wiring only)
- `core/src/vault/rule_tokens/{mod.rs,record.rs,block.rs,tests/}` (new)
- `core/src/vault/mod.rs`
- `core/src/vault/manifest/token.rs` (doc wording)
- `core/tests/differential_replay_helpers/{tolerance,targets,agreement,rust_decoder}.rs`
- `core/tests/differential_replay.rs`
- `core/tests/rule_token_seeds.rs` and `core/tests/rule_token_seeds_helpers/` (new)
- `core/fuzz/seeds/{record,block_file}/*__*.bin` (generated)

**Python:**

- `codec/cbor_faults.py`, `codec/well_formed.py`, `codec/record_rules.py` (new)
- `codec/scanner.py`, `codec/record.py`
- `wire/envelope_rules.py` (new), `wire/block_file.py`
- `sections/rule_token_seeds.py` (new), `sections/registry.py`

**Docs:**

- this spec
- `CLAUDE.md` (the #634 bullets: which targets are compared, target-aware tolerance)
- `docs/manual/contributors/differential-replay-protocol.md`
- `ROADMAP.md`
- `core/fuzz/README.md` (the generated seeds)
- README only if it names the comparison

Every new file stays under 500 lines. `record.py` (355) and `scanner.py` (484)
are split rather than grown past it.
