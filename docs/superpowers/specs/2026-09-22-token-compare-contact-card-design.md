# Design: token-compare `contact_card` in the differential replay (#641), closing #691

Status: approved in brainstorming, 2026-09-22. Branch
`feature/token-compare-contact-card`, base `c98e932d`.

#634 made `differential_replay.rs` compare WHICH rule each decoder names, for
`manifest_body` only. #641 asks for the rest, ordered by value; #673 did
`record` and `block_file`. This slice does `contact_card`, the next in that
order and the one the #689 handoff names. `bundle_file` and `vault_toml` stay
under #641; `manifest_file` stays blocked by #640.

It also closes **#691**, which says in as many words that it belongs with
whichever slice takes `contact_card` into the token comparison: `codec/card.py`
is the last decoder still running the content-blind `reject_excessive_nesting`
pass rather than `walk_body`.

Five decisions were taken in brainstorming, each by options plus a
recommendation:

| # | Decision | Chosen |
|---|---|---|
| D1 | The `display_name` cap, which `docs/` does not state | Rule it **normative in crypto-design §6**, then mirror it in `conformance.py` |
| D2 | Whether the cap binds writers too | **Both**: writers MUST NOT emit, readers MUST reject |
| D3 | The token for `CardError::UnknownField` | A **new 18th** `RuleToken::UnknownField` |
| D4 | Scope: the well-formedness walk on the card path (#691) | **In scope** — both languages, this slice |
| D5 | `reject_excessive_nesting` once the card is its last caller | **Delete it** |

---

## 1. What was measured before designing

Two measurements, both outside the tree (#516), both reproducible from §9.

### 1.1 The full corpus: 92 of 6,398 disagree

Every `contact_card` input was decoded through both implementations and each
(Rust variant, Python raise) pair tabulated: the 4 committed seeds plus the
main checkout's gitignored runtime corpus, **6,398 inputs**. Under the
provisional token mapping of §4.3:

```
inputs=6398  agree=6306  DISAGREE=92
```

**Acceptance does not diverge on this corpus** — one accept on each side, the
same input (`with_sigs.cbor`). Everything below is about WHICH rule is named.
The four disagreeing classes, and what closes each:

| Pairs | Rust | Python | Cause | Closed by |
|---|---|---|---|---|
| 48 | `wrong_type` | `malformed_cbor` | `ciborium` parses the whole item before `from_canonical_cbor`'s shape check runs, so Rust answers "not a map" / "non-string map key" for a body that is not well-formed | §4.2, the Rust walk |
| 39 | `wrong_type` | `unknown_field` | a non-text map key: Rust tests `Value::Text` first, Python's unknown-key sweep reaches it first and calls it an unknown field | §5.2, Python's key-type check moves into the entry loop |
| 4 | `malformed_cbor` | `wrong_type` | the mirror — `ciborium` rejects an unassigned simple value (`e4`) or a top-level tag (`ca f8 ff`) that `cbor2` decodes, after which Python's shape check fires | §5.2, the Python walk |
| 1 | `wrong_type` | `unsupported_version` | `card_version` of the wrong TYPE: Rust says "expected unsigned integer", Python's `cv != 1` test conflates a wrong type with a wrong value | §5.2, split the two checks |

No class needs a tolerance, and none is allowlisted — #641's acceptance
criterion in full.

### 1.2 The planted probe: two ACCEPTANCE divergences

A corpus of pseudo-random bytes cannot reach a well-shaped card (every valid
body carries a 1184-byte ML-KEM key, a 1952-byte ML-DSA key and a 3309-byte
signature), which is why §1.1 shows none. So 32 single-fault bodies were
spliced into the committed accepting base, one planted value each — #669's
substitution method. Two of them are accepted by one implementation and
rejected by the other:

| Planted | Rust | Python |
|---|---|---|
| `display_name` of 4097 bytes | `DisplayNameTooLong` | **ACCEPT** |
| `created_at` = `c2 49 01×9` (9-byte bignum) | `Malformed("expected unsigned integer")` | **ACCEPT** |

The second is #669's **M2** shape — "the type check was never written" — on a
position no census had looked at. `cbor2` folds tag 2 into a Python `int`, so
`is_integer` is satisfied; `cbor2.dumps(..., canonical=True)` re-emits that int
as a bignum, so the re-encode comparison round-trips and never fires. The tag
is invisible end to end, although crypto-design §6.2 rule 4 forbids tags and
§6.2's opening sentence names "the §6 self-signed message, the §6.1 fingerprint
input" — the card — among the byte strings it binds. The **narrow** bignum
(`c2 41 01`) is caught, but only because `cbor2` folds it to a small int that
re-encodes shorter; that is an accident of width, not a check.

### 1.3 Three rows where both agree on an answer §4.2 forbids

The sharpest argument for the slice, and the one no cross-language gate can
ever make on its own — #689's `82 f9 00 00 f7` row restated:

| Planted `created_at` | Rust | Python | What §4.2/§6.2 require |
|---|---|---|---|
| `f7` (`undefined`) | `wrong_type` | `wrong_type` | `malformed_cbor` — not well-formed canonical CBOR |
| `f9 00 00` (float) | `wrong_type` | `wrong_type` | `rule4_tag_or_float` |
| `c2 41 01` (narrow bignum) | `non_canonical_unclassified` | `non_canonical_unclassified` | `rule4_tag_or_float` |

Both sides reach rejection through the *type* check, so neither names
well-formedness or rule 4. Agreement is not conformance.

---

## 2. The spec edit (D1, D2)

`docs/crypto-design.md` §6 gains one normative paragraph: `display_name` is at
most **4096 bytes of UTF-8**; writers MUST NOT emit a longer one and readers
MUST reject one.

Worded on §6.2 rule 6's own template, because the same three facts hold:

- **It narrows nothing a v1 reader accepts.** `from_canonical_cbor` has
  enforced exactly this since PR #11.
- **The writer half is already true of this codebase.** `to_canonical_cbor`
  and `signed_bytes` both enforce the cap (`validate_invariants`), so stating
  it costs nothing and closes the asymmetry #600 had to go back and fix for
  the repeated-array-value rule: a reader-only rule would leave a conformant
  clean-room writer able to emit a card it could not itself read back.
- **It is a v1 profile bound, not a canonical-form rule.** It bounds the
  memory a reader commits to attacker-supplied text from the
  attacker-writable vault folder — `threat-model.md`'s "Display-name DoS cap"
  row, which until now cited only Rust test names.

This is the #667/#670 procedure: a spec silence is ruled in `docs/` before any
code moves. No byte on disk changes.

---

## 3. Rust

### 3.1 `CardError` gains rule-4 arms

`canonical_error_to_card_error` folds `CanonicalError::{FloatRejected,
TagRejected}` onto `CardError::Malformed(&'static str)`. That is fine while
nothing reads the distinction and wrong the moment a token does: rule 4 would
report as `wrong_type` against a Python side that can name it, manufacturing a
divergence out of a mapping choice. So `CardError` gains `FloatRejected` and
`TagRejected`, mirroring `RecordError`, and that one function keeps being the
only place the mapping is written.

11 variants become 13.

### 3.2 `impl From<CanonicalError> for CardError`

`walk_first_item_checked`'s bound is `E: From<CanonicalError>`, and
`canonical/walk.rs`'s module doc already names `CardError` as one of the two
types that "convert through the free functions … and implement no such `From`,
so neither would satisfy the bound without one being added first". The impl
delegates to `canonical_error_to_card_error`; there is still one
implementation of the mapping.

### 3.3 The walk runs first

`from_canonical_cbor`'s first statement becomes
`canonical::walk_first_item_checked(bytes, CardError::CborDecode)?`, ahead of
`ciborium::de::from_reader`. This single change closes §1.2's bignum
acceptance divergence, §1.1's 48- and 4-pair classes, and all three of §1.3's
agreed-but-non-conformant rows.

It also gives the card path the §6.2 rule 6 depth semantics the manifest,
record and block paths already have: the walk answers before `ciborium`, so
the short-bignum edge CLAUDE.md records for "the ciborium-only paths" stops
applying to this one. `IdentityBundle::from_canonical_cbor` remains the last
ciborium-only path; that is #677's territory, not this slice's.

### 3.4 `CardError::rule_token()`

A new `core/src/vault/rule_tokens/card.rs`, beside `record.rs` and
`block.rs` and for the reason that module's doc already gives — `card.rs` is
1264 lines and an inherent `impl` may live anywhere in the crate. Exhaustive,
so a 14th `CardError` variant cannot be added without classifying it. A second,
independent declaration of the mapping goes in `rule_tokens/tests/card.rs`.

### 3.5 The 18th token (D3)

`RuleToken::UnknownField`, `phase_dependent: false`, added to
`core/tests/data/rule_token_vocabulary.json`, which both languages read.

The card is the only decoder in the tree that rejects an unrecognised key
outright — the manifest, record and block plaintext all carry forward-compat
`unknown` bags. Both implementations make the distinction cleanly, which is the
vocabulary's admission test. Collapsing it into `wrong_type` would have scored
§1.1's 39-pair class as agreement.

Two mappings are deliberately COARSE instead, and are recorded here so the
choice is reviewable rather than inferred:

- `DisplayNameTooLong` → `wrong_type`, whose doc already reads "a field's
  CBOR major type, **or a byte string's length**". The doc widens to name a
  text string's length too. A 19th token for one length bound would draw a
  distinction that carries no evidence.
- `SigVerifyFailed` → `signature_invalid` and `CborEncode` → `internal_error`,
  both unreachable from the replay target (`from_canonical_cbor` does not
  verify), classified as diagnostics exactly as `BlockError`'s AEAD and
  signature arms are.

---

## 4. Python

### 4.1 `codec/card_rules.py` — typed rejections

New sibling module holding the exception classes with `token` class
attributes, the shape `record_rules.py` established: `CardWrongType`,
`CardIntegerOutOfRange`, `CardDuplicateKey`, `CardMissingField` (a `KeyError`,
so `str()` renders as the bare `KeyError` it replaces), `CardUnknownField`,
`CardUnsupportedVersion`, `CardNonCanonical`, `CardDisplayNameTooLong`. A
sibling module rather than more of `codec/card.py`, so both stay well under
the 500-line threshold.

### 4.2 `codec/card.py` — Rust's phase order

Five changes, each answering a measured class:

1. **`walk_body` replaces `reject_excessive_nesting`** (D4, #691). Content-
   aware: UTF-8, simple values and rule 4, not depth alone. Closes §1.1's
   4-pair class and §1.2's bignum acceptance divergence on this side.
2. **The value check moves into the entry loop, in wire order**, and a missing
   key is reported only after it — verbatim `record_rules.py`'s documented
   #641 lesson. The probe measured the pre-fix behaviour: a body missing
   `x25519_pk` and carrying a wrong-typed `self_sig_pq` is `wrong_type` in
   Rust and `missing_field` in Python.
3. **A non-text key is a wrong TYPE, tested before the unknown-key test.**
   Closes the 39-pair class. §6's schema has text keys only, so a non-text key
   is not an unknown field.
4. **The `card_version` checks split**: a non-integer is `CardWrongType`, an
   integer that is not 1 is `CardUnsupportedVersion`. Closes the 1-pair class.
5. **The `display_name` cap** from §2.

**Items 2, 3 and 5 together mean the decoder stops iterating a `cbor2` dict.**
A dict destroys repeats, so it cannot see a duplicate key at all — Rust's
`set_once` reports `DuplicateField` where Python currently reaches the
re-encode and says `non_canonical_unclassified`. And a duplicate check cannot
be a PRE-PASS: Rust interleaves, so a wrong-typed key at entry 0 and a repeat
at entry 5 is `wrong_type`, and a pre-pass would answer `duplicate_map_key` —
a NEW divergence introduced by the fix. The card therefore adopts
`codec/manifest_decode.py`'s existing shape verbatim: `walk_body`, then
`scanner._scan_map_entries` for `((key_start, key_end), (value_start,
value_end))` spans, then one wire-order loop doing key-type check → duplicate
check → value check per entry. That loop is where items 2, 3 and 5 all live,
and `scanner.DuplicateMapKey` is raised from it as the manifest raises it.

### 4.3 The provisional mapping §1.1 was measured under

Recorded so the implementation can reproduce the table rather than re-derive
it: `CborDecode/*` and `NestingTooDeep` → `malformed_cbor`; `UnknownField` →
`unknown_field`; `MissingField`/`KeyError` → `missing_field`;
`DuplicateField` → `duplicate_map_key`; `NonCanonicalCbor` →
`non_canonical_unclassified`; `InvalidVersion` → `unsupported_version`;
`Malformed("integer outside u64 range")` → `integer_out_of_range`; every other
`Malformed(..)`, `InvalidFieldLength` and `DisplayNameTooLong` →
`wrong_type`.

### 4.4 Deleting `reject_excessive_nesting` (D5)

After §4.2 the card is its last caller, so the function is dead. It is
deleted, not kept with a note.

#689 retired that same function's `later_phases_scan_in_byte_order` flag for
exactly this reason: "a documented fail-open defended solely by its own test is
how the next decoder gets wired onto it on the strength of a caller list that
no longer holds". With zero callers the whole function is that hazard. Deleting
it leaves `conformance_lib` with one traversal and one entry point, which is
the property #666 argued for.

---

## 5. Replay wiring

`contact_card` moves from `NOT_TOKEN_COMPARED_TARGETS` to
`TOKEN_COMPARED_TARGETS` in `differential_replay_helpers/targets.rs`, gains a
`rust_decode` arm in `rust_decoder`, and its `MIN_CORPUS_INPUTS` floor rises
from 4 to whatever §6 commits.

It does **NOT** join `PHASE_DEPENDENT_TOLERANCE_TARGETS`. That licence is
`docs/vault-format.md` §4.2's, and §4.2 is the manifest body's section: it
admits two reader designs that detect §6.2 rules 1-3 at different points.
Nothing gives a §6 contact card that freedom, so every compared pair must be
strictly EQUAL — the same call #641 made for `record` and `block_file`.

---

## 6. Committed seeds

The existing generator extends; no new test binary and no new conformance
section. `core/tests/rule_token_seeds_helpers/` gains `contact_card.rs`,
`SEEDED_TARGETS` gains `"contact_card"`, `rust_rejection` gains an arm, and
Section RTS's `_TARGETS` dict gains a row. Both halves are already keyed by
target.

Seeds are single-fault, label-bound and regenerated-and-compared on every run,
for the reasons that module's doc gives. The rows are drawn from §1's measured
classes, at least one per token the card path can produce, including the two
acceptance divergences of §1.2 and the three non-conformant rows of §1.3 —
those five are the ones a future regression would otherwise reach silently.
The accepting base stays `with_sigs.cbor`; `pre_sig.cbor` keeps rejecting as
`missing_field`, which is what it has always done.

**The census must be prefix-scoped.** `contact_card/` already holds two
`valuetype__` seeds from #669's generator, and `rule_token_seeds.rs`'s "every
file containing `__`" rule would claim them. The same exclusion
`nesting__` needed, through one constant per language.

---

## 7. What this slice does NOT do

- **`IdentityBundle` is untouched.** It stays the last ciborium-only decode
  path, with the short-bignum depth split CLAUDE.md records. #677 owns it.
- **`card.rs` is not split.** It is 1264 lines and #625 owns that. Folding a
  behaviour-preserving move into the same diff as a semantic change is what
  #686/#688 were filed rather than done for.
- **`bundle_file` and `vault_toml` stay under #641**, and `manifest_file`
  stays blocked by #640.
- **No proptest.** As in #689: the walk can only narrow, never widen
  acceptance, so the direction worth proving is "nothing previously accepted
  is now rejected", and §8's full-corpus replay proves it by execution over
  6,398 inputs.

---

## 8. Proving it is not decorative

Re-running §1.1's tabulation after the change is the slice's primary
acceptance evidence: **6,398 inputs, 0 disagreements, and the same single
accept**. A moved acceptance verdict is a STOP condition, not a finding to
write up.

Mutation rows, spec to the session scratchpad (#516), `--self-test` first:

| # | Mutation | Expected |
|---|---|---|
| C1 | `from_canonical_cbor`'s walk call deleted | RED |
| C2 | `CardError::rule_token`'s `UnknownField` arm repointed at `WrongType` | RED |
| C3 | `py_decode_contact_card`'s key-type check removed from the entry loop | RED |
| C4 | Python's `card_version` type/value split collapsed back into one test | RED |
| C5 | The `display_name` cap removed from `codec/card.py` | RED |
| C6 | `contact_card` removed from `TOKEN_COMPARED_TARGETS` | RED |

C6 is the negative control #647's CI step needed: a target that is compared
and catches nothing is #546 restated.

---

## 9. Reproducing §1

Inputs: `core/fuzz/seeds/contact_card/` (4, committed) plus the main
checkout's `core/fuzz/corpus/contact_card/` (6,394, gitignored).

- **Rust** — a temporary `#[ignore]`d integration test reading both
  directories and writing `<path>\t<variant>` per input, where `<variant>` is
  a hand-written projection of `CardError` (the `CborFault` arms carry
  `kind`, nothing else carries a payload). Run with
  `cargo test --release --locked -p secretary-core --test <probe> -- --ignored`.
  Note the working directory: cargo runs an integration test from the PACKAGE
  root (`core/`), so every path handed to it must be absolute.
- **Python** — `py_decode_contact_card` over the same two directories,
  writing `<path>\t<type>: <message>`.
- **Join** on basename, project both sides through §4.3's mapping, and count
  agreeing and disagreeing pairs.

The probe is deliberately not committed: it names no invariant the seeds do
not, and a probe in the tree is a second corpus definition to keep in step.
§1.1's numbers are a point-in-time reading of a gitignored corpus and must be
re-measured, never quoted.

---

## 10. Files

**Spec:** `docs/crypto-design.md` (§6).

**Rust:** `core/src/identity/card.rs` (two variants, one `From`, the walk
call), `core/src/vault/rule_tokens/{mod.rs,card.rs}`,
`core/src/vault/rule_tokens/tests/{mod.rs,card.rs}`,
`core/src/vault/manifest/token.rs` (+ its `tests/`),
`core/tests/data/rule_token_vocabulary.json`,
`core/tests/differential_replay_helpers/{targets.rs,rust_decoder.rs}`,
`core/tests/rule_token_seeds.rs`,
`core/tests/rule_token_seeds_helpers/{mod.rs,contact_card.rs}`.

**Python:** `core/tests/python/conformance_lib/codec/{card.py,card_rules.py,
well_formed.py}`, `core/tests/python/conformance_lib/sections/
{rule_token_seeds.py,rule_token_vocabulary.py}`.

**Seeds:** `core/fuzz/seeds/contact_card/cardtoken__*.bin`.
