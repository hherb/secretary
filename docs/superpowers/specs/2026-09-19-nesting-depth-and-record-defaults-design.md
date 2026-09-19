# Design: a normative CBOR nesting limit (#667) and default omission in records (#670)

Branch `feature/nesting-depth-and-record-defaults`, worktree
`.worktrees/nesting-depth-defaults`, base `db6b1f5b` (`main`, immediately after
PR #679 merged).

These are the last two known **acceptance divergences** between
`record::decode` / `decode_manifest` and `conformance_lib`: bodies one decoder
accepts and the other rejects. Neither is reachable from any committed or
corpus input, which is why the differential replay reports full agreement.
Both are spec silences rather than bugs on one side, so each needed a ruling
before any code could change. Both rulings were made up front, and this
document records them with the design that follows from them.

---

## 1. What was measured before designing

A throwaway probe crate (outside the repo, `secretary-core` as a path
dependency) ran the real Rust decoders. `conformance_lib.diff_replay.replay_bytes`
ran the Python ones. `T` is the total number of nested containers, **counting
the document's own root map as 1**. Every body is one committed accepting base
(`record/login.cbor`, `manifest_body/uniq__control__all_distinct.bin`,
`contact_card/with_sigs.cbor`) with one value replaced by `[[…[0]…]]`, re-encoded
with `cbor2.dumps(..., canonical=True)`. For each base, that round trip is a
byte identity with nothing replaced.

### 1.1 #667 — depth

| Body | Rust | Python |
|---|---|---|
| `record`, unknown key, T=256 | accept | accept |
| `record`, unknown key, T=257 … 2000 | **reject**, `CborDecode(RecursionLimit)` | **accept** through T=995; `RecursionError` at T=2000 |
| `record`, `tags` (known), T≤256 | reject, `WrongType` | reject, `wrong_type` |
| `record`, `tags`, T=257 … 300 | reject, `malformed_cbor` | reject, `wrong_type` — **token disagreement** |
| `record`, `tags`, T=993 / 995 | reject, `malformed_cbor` | reject, `CBORDecodeError` with **no token** (cbor2's own 400 limit) — harness failure |
| `record`, `tags`, T=2000 | reject | `RecursionError` — harness failure |
| `manifest_body`, unknown key, T=256 | accept | accept |
| `manifest_body`, unknown key, T=257 … 993 | **reject**, `CborDecode(RecursionLimit)` | **accept** |
| `manifest_body`, unknown key, T≥995 | reject | `RecursionError` — harness failure |
| `contact_card`, any key, T=256 / 257 / 2000 | reject | reject — verdicts agree at every depth (not token-compared) |

- **Rust's boundary is exactly 256 accepted / 257 rejected on both paths.**
  It is ciborium 0.2.2's default recursion limit (`from_reader_with_buffer`
  starts `recurse: 256`), which `from_secret_reader` and every
  `ciborium::de::from_reader` call site inherit. ciborium charges one level per
  array, map and tag, **except** a bignum tag (2/3) over a definite byte string
  of at most 16 bytes, which it decodes as an integer without recursing.
- **#667 is not record-only.** `manifest_body` carries the same acceptance
  divergence and the same harness failure, and it is a token-compared target
  that CI replays. The issue named only the record path.
- Python's `RecursionError` comes from the recursive `scanner._scan_item`,
  reached through `reject_floats_and_tags` (manifest) and `_scan_map_entries`
  (record). `walk_body` is already iterative.

### 1.2 #670 — a record optional key present at its default

Re-measured from the issue's table: `tags: []`, `tombstone: false` and
`tombstoned_at_ms: 0` are each accepted by Python and rejected by Rust as
`NonCanonicalEncoding` (token `non_canonical_unclassified`). `record_to_canonical`
omits all three defaults, so the re-encode differs from the input.
`py_encode_record` re-emits whatever keys it decoded.

**The class is confined to `record`.** Checked by reading every encoder:
`block.rs`'s plaintext encoder omits no default, `identity/card.rs` none, and
the manifest's two optional `TrashEntry` keys are `Option`-typed and pushed
whenever `Some` (`manifest/encode.rs:313-319`), so a present value always
round-trips. The plan confirms the manifest half by execution, as #670 asks.
`py_encode_record` has two callers: `diff_replay.py` and Section RC's baseline.

---

## 2. Decisions

| # | Decision | Chosen | Why |
|---|---|---|---|
| D1 | #670's §6.3 ruling | **Absent is the only canonical spelling of a default**; writers MUST omit, readers MUST reject the present form | What Rust has done since v1 and what every record this codebase has written looks like, so no Rust behaviour moves; keeps §6.2's one-value-one-encoding property |
| D2 | #667's ruling | **A normative v1 nesting limit of 256, for every canonical-CBOR document** | Every Rust reader has enforced exactly this since v1, so it narrows nothing a shipped reader accepts. It also bounds parser stack use on input from the attacker-writable folder (contact cards) |
| D3 | Implementation shape | **Depth checked inside both walks, plus a depth-only first pass for Python's other CBOR decoders** | Folding in #666's full manifest walk would move the tokens of ciborium's four leniencies on a frozen decoder, and would need measuring first on a target with no fuzz corpus. A depth-aware recursive scanner raises depth interleaved in byte order with the rule-4 pass, which produces the rule-4 / `malformed_cbor` disagreement this slice exists to remove |
| D4 | Pins | Label-bound committed seeds through generators, both verdicts at the boundary | A limit set too LOW is as wrong as none, so the accepting depth-256 body is as load-bearing as the rejecting 257 |
| D5 | #670's Python mechanism | `py_encode_record` omits the three defaults; the existing re-encode comparison rejects | Rust's rejection IS its re-encode comparison, so the same mechanism gives the same phase and the same token. See §5.3 for why this does not recreate #608's backstop trap |

---

## 3. Spec text

### 3.1 crypto-design §6.2 — rule 6

After rule 5, set apart from rules 1–5 because it is not part of RFC 8949's
deterministic profile:

> Every such byte string is also bound by one limit that is not part of RFC
> 8949 §4.2.1's profile:
>
> 6. **Nesting depth is at most 256.** No chain of arrays, maps and tags,
>    each held directly inside the one before it, may be longer than 256.
>    The chain starts at the outermost item of the byte string being
>    decoded, when that item is itself an array, map or tag. A scalar is
>    not a level: an integer inside 256 nested arrays is within the limit,
>    and a 257th array around it is not. Unlike rules 1 and 5, this limit
>    is **not** scoped to interpreted material: it binds inside a
>    forward-compat unknown subtree exactly as elsewhere, because a reader
>    must walk a subtree's structure before it can retain it. Writers MUST
>    NOT emit a longer chain, and readers MUST reject one. A tag is
>    counted although rule 4 forbids tags, so that a body breaking both
>    rules is reported the same way by every reader (vault-format §4.2's
>    well-formedness precondition). This is a v1 profile bound, not a
>    canonical-form rule. The reference implementation's readers have
>    enforced exactly this limit since v1, so stating it narrows nothing a
>    v1 reader accepts, and it bounds the stack a parser needs on input
>    taken from the attacker-writable vault folder (§6 contact cards).
>    Depth is counted from the root of the byte string being decoded, so a
>    record inside a block plaintext is measured from the block's root.

Note on scope: depth is counted from the root of the byte string being
decoded. A record inside a block plaintext is therefore measured from the
block's root. The standalone `record` replay target measures from the
record's own root, because that is the byte string it is given. That target is
a test construct, not a wire document, and the spec needs no sentence about
it.

### 3.2 vault-format §4.2 — the well-formedness precondition

The list after "A reader must first be able to determine the body's item
boundaries, and one that cannot —" gains one entry: *an item nested more than
256 levels deep (crypto-design §6.2 rule 6)*. Depth therefore outranks rule 4
on the manifest. This is what Rust's manifest path already does: ciborium's
parse, which enforces the limit, runs before `reject_floats_and_tags`.

### 3.3 vault-format §6.3 — default omission

After the schema block:

> **A default value is written by omission.** `tags`, `tombstone` and
> `tombstoned_at_ms` each have a default — the empty array, `false` and `0`.
> The canonical encoding of a record whose value for one of them equals its
> default is the encoding that omits that key. A writer MUST omit `tags` when
> the record carries no label, `tombstone` when the record is live, and
> `tombstoned_at_ms` when the record has never been tombstoned. A reader MUST
> reject a record carrying any of the three present at its default value, as
> non-canonical. Any other value is written in full, and the three are
> independent: `tombstoned_at_ms` non-zero with `tombstone` absent is the
> resurrection shape crypto-design §11.3 describes, and is canonical. (One
> value, one encoding: crypto-design §6.2 admits exactly one byte string per
> record, and a present default would be a second spelling of the absent one.)

The two existing schema comments ("absent or false = live", "absent or 0 =
never tombstoned") stay. They state what the values MEAN, which the new
paragraph does not repeat.

### 3.4 What is deliberately not edited

- **vault-format §11.** Its checklist lists capabilities ("generate, sign,
  encrypt, decrypt, and verify a v1 Manifest file matching §4"), not rules. The
  two rules sit inside §4/§6 and crypto-design §6.2, which items 5–7 already
  bind, so a rule-level line would be the only one of its kind.
- **§6.3 report order (#668).** Rule 6's precedence is normative on the
  manifest through §4.2. On `record`, the order this slice pins is parity
  between our two implementations, as every other record order is.

---

## 4. Rust

Production change on the `record` path only. No error enum, public signature,
FFI mapping or rule token changes.

- **`secretary_core::cbor::V1_MAX_NESTING_DEPTH: usize = 256`**, public and
  re-exported at the `cbor` module root, so integration tests name the
  constant and never write 256.
- **`walk_first_item` enforces it.** Before each container or tag push, if the
  stack already holds `V1_MAX_NESTING_DEPTH` frames, it returns
  `WalkFault::Malformed(CborFault { kind: CborErrorKind::RecursionLimit,
  offset: Some(pos) })`. The fault is raised at once, like every other
  well-formedness fault, so it outranks a rule-4 tag the walk has already
  remembered. `walk_fault_to_record_error` maps it to `RecordError::CborDecode`,
  whose token is `malformed_cbor`: the variant and token ciborium already
  produced here, now with an offset. On the record path the walk now answers
  before ciborium can, and ciborium never sees a body deeper than the limit.
- **No verdict moves.** ciborium already rejected every such body. Two-fault
  bodies, excess depth plus a tag the walk would have reported as rule 4, move
  from `TagRejected` to `CborDecode`. The plan measures this over the full
  local corpus: statuses moved (expected 0) and variants moved.
- **ciborium's limit is pinned to the constant on every public CBOR decode
  path.** A new test asserts that ciborium still gives a depth-256 body some
  verdict other than `RecursionLimit`, and still rejects a depth-257 body with
  `RecursionLimit`, through `decode_manifest`, `block::decode_plaintext`,
  `ContactCard::from_canonical_cbor` and `IdentityBundle::from_canonical_cbor`.
  The bodies need not be valid documents: nested arrays under a one-entry map
  suffice, because the depth-256 body only has to fail for some reason *other
  than* `RecursionLimit` and the depth-257 body only has to fail *with* it. No
  bundle or block-plaintext fixture is needed. `record::decode` is covered by
  the walk and by the seeds. A ciborium upgrade
  that moved its default would otherwise change the spec's limit silently on
  four paths. `sync::state` is not pinned: OS-keystore state is not one of the
  byte strings §6.2 enumerates, so rule 6 does not bind it.

Doc comments to correct: `cbor/well_formed.rs`'s module doc ("no depth cap of
its own") and `record::decode`'s rule list.

---

## 5. Python

### 5.1 One traversal, two entry points

`codec/well_formed.py` gains `V1_MAX_NESTING_DEPTH = 256` and
`NestingTooDeep(MalformedCbor)`, whose token is inherited, `malformed_cbor`.

- **`walk_body`** checks the limit at its container and tag pushes and raises
  `NestingTooDeep` at once, the same precedence as its Rust twin.
- **`reject_excessive_nesting(buf)`** is new. It walks item boundaries only and
  raises **only** `NestingTooDeep`. At anything it cannot walk past (a
  truncated head, a bad chunk, a stray break) it stops and returns, leaving that
  fault for the decoder's existing phases to report as they do today. It
  reports no content-level fault (invalid UTF-8, a disallowed simple value, a
  tag or float as rule 4), since none of those moves an item boundary. A tag
  still counts as a level. This guarantees that any recursive phase
  running after it meets at most 256 levels before it reaches the point where
  the pass stopped. That point is a fault the recursive phase meets first,
  because both scan in byte order.
- **Both entry points share one frame machine.** `walk_body`'s traversal is
  split into a boundary core that the content checks hook into, so the depth
  check exists once and a mutation to it reds both paths (§9). A second copy of
  the traversal is the #618 shape this repo keeps retiring.

### 5.2 Where the pass runs

It becomes the **first statement** of every `codec/` decoder that parses a
whole CBOR document:

| Decoder | Today's first step | Effect |
|---|---|---|
| `py_decode_manifest` | recursive `reject_floats_and_tags` | closes the manifest divergence and its `RecursionError` |
| `py_decode_contact_card` | `cbor2.loads` (400-level limit) | verdicts unchanged; brings the rule to cards (`contact_card` is not yet token-compared, #641) |
| `py_decode_trash_entry` | `cbor2.loads` | verdicts unchanged; no replay target reaches it |
| `py_decode_record` | `walk_body` | none: `walk_body` already enforces the limit |

The other four `codec/` decoders parse no CBOR document: `py_decode_bundle_file`,
`py_decode_block_file` and `py_decode_manifest_file` read binary envelopes, and
`py_decode_vault_toml` reads TOML. `wire/` is out of scope, as Section VT's
check 3 already rules: it enforces no acceptance set.

### 5.3 #670

`py_encode_record` omits `tags` when `[]`, `tombstone` when `False` and
`tombstoned_at_ms` when `0`, mirroring `record_to_canonical` line for line. The
re-encode comparison in `py_decode_record` then rejects a present default as
`RecordNonCanonical`, at the same phase and with the same token as Rust.

**This is not #608's backstop trap, and the reason is worth stating.** At #608 a
reader rule that §4.2 states independently (distinctness) was being satisfied
by an encoder refusal, so deleting the reader's own check left the tests green.
Here §6.3 states no reader check separate from canonical form, and Rust has
none: its reader rejection *is* the re-encode comparison. The Python reader
gets the same mechanism, so nothing is being answered by the wrong layer. The
writer half is still asserted on its own (§7.2 check 3), so a reader-side
special case cannot stand in for the encoder.

---

## 6. Committed seeds

### 6.1 #670 — three rows in `rule_token_seeds.rs`

`non_canonical_unclassified__present_default_tags.bin`,
`…_tombstone.bin` and `…_tombstoned_at_ms.bin`, each planted into
`record/login.cbor`. Each row names Rust's exact variant
(`NonCanonicalEncoding`), and Section RTS binds Python's class
(`RecordNonCanonical`). They are generated **before** the Python fix, so the
replay and RTS are red first.

### 6.2 #667 — a new generator, `nesting_depth_seeds.rs`

It owns the `nesting__` prefix under `record/` and `manifest_body/`, with an
`Accept` / `Reject(variant)` verdict per row, so an accepting row is
representable. `rule_token_seeds`' two-way census claims every `__` file under
`record/`, so it is narrowed to exclude `nesting__`. That exclusion is spelled
as a constant the new generator exports, so the two generators cannot drift
onto two ideas of who owns which file.

| Target | Row | Verdict |
|---|---|---|
| `record` | `nesting__256_unknown` | accept |
| `record` | `nesting__257_unknown` | reject, `CborDecode(RecursionLimit)` |
| `record` | `nesting__257_known_tags` | reject, same, where the value would otherwise be a `WrongType` |
| `record` | `nesting__2048_unknown` | reject, same — Python must return a verdict at this depth |
| `manifest_body` | `nesting__256_unknown` | accept |
| `manifest_body` | `nesting__257_unknown` | reject, `CborDecode(RecursionLimit)` |
| `manifest_body` | `nesting__2048_unknown` | reject, same |

Seven files, each built from a committed accepting base by replacing one value,
and each proven to be the base plus exactly that replacement. The generator
asserts every row before writing any file, the committed-bytes test requires
byte identity, and each target plants distinct bytes: the preconditions
`acceptance_seeds.rs` already tests.

**Consequences, all expected edits:**
- Committed replay inputs go from 121 to **131**.
- `MIN_CORPUS_INPUTS`: `record` 37 → **44**, `manifest_body` 45 → **48**.
- Section RTV's `_CORPUS_TOKENS` gains `malformed_cbor` (8 → **9**), because the
  manifest depth seeds are the first committed manifest bodies to reach it. RTV's
  failure message asks for exactly this edit.

---

## 7. Python sections

Both sections report what they RAN on their PASS lines, counts included,
because a PASS line computed from a declaration was the #679 review's lead
finding.

### 7.1 Section NDL — nesting depth limit (`sections/nesting_depth.py`)

1. **Boundary, per CBOR decoder** (the four in §5.2):
   - depth 256 is not rejected for depth. `record` and `manifest` accept it,
     with the depth inside an unknown value. `card` and `trash_entry` reject it,
     but for their schema and not as `NestingTooDeep`.
   - depth 257 raises `NestingTooDeep`.
2. **A verdict at every depth.** Depths 257, 1,000 and 10,000, per decoder,
   raise `NestingTooDeep`. No `RecursionError` and no untokened exception
   escapes.
3. **Tags are levels.** A body whose 257th level is a tag raises
   `NestingTooDeep`, not rule 4. Its control, the same tag at level 256,
   raises rule 4 and not depth.
4. **Depth outranks a shallow tag.** A tag early in byte order plus excess
   depth later raises `NestingTooDeep` on `record` (the walk) and on the
   manifest (the pass). A control for the pass's silence: a truncated body with
   no depth problem makes the pass return, and the decoder reports the
   truncation as it does today.
5. **Census, both ways, default-deny.** Every top-level `py_decode_*` under
   `codec/` is classified as either a CBOR-document decoder (and must appear in
   checks 1–2) or a non-CBOR decoder with a stated reason. An unclassified
   decoder fails the census, as does a classified name that no longer exists.
   This is the "has no check to find" search #669 recorded, applied up front.
6. **Seed binding.** Every committed `nesting__` seed replays with the verdict
   its row states. The table is read from the generator's naming rule, not
   restated.

### 7.2 Section RDO — record default omission (`sections/record_defaults.py`)

1. Each of the three present-default bodies is rejected as
   `RecordNonCanonical`.
2. **Controls, per key:** the same body with the key absent is accepted, and
   the key at a non-default value (`tags: ["x"]`, `tombstone: true`,
   `tombstoned_at_ms: 5`) is accepted. Without them, a reader that rejects the
   key outright would pass check 1.
3. **Writer half:** `py_encode_record` of a dict carrying each default equals
   `py_encode_record` of the dict without it.

Section RC is left alone. Its title and docstring scope it to unknown-subtree
canonicality, and #670 is a different rule. **REG goes 33 → 35.**

---

## 8. What this slice does NOT do

- **The bignum edge on the manifest path.** ciborium does not charge a level
  for a bignum tag over ≤16 bytes. A manifest body whose 257th level is such a
  tag gives `non_canonical_unclassified` in Rust (the bignum is folded to an
  integer and the re-encode differs) and `NestingTooDeep` in Python. That pair
  is never tolerated. It is a two-fault body (rule 4 and rule 6) that no input
  reaches, and it is #666's ciborium-leniency class. Wiring the walk into
  `decode_manifest` closes it. It gets a comment on #666, not a fix here.
- **`contact_card` token comparison (#641)** will have to put depth first.
  That goes in a comment on #641.
- **Python's block-plaintext reading** stays inspection-only
  (`wire/golden_vault_verify.py`). No strict decoder exists to guard, and the
  Rust side is pinned by §4's path test.
- **The four ciborium leniencies on the manifest and block paths** (#666), and
  every report order §6.1/§6.3 leaves open (#668), are untouched.
- **Not a proof of absence.** The #670 class was found by reading every
  encoder. The depth measurements cover the three CBOR replay targets at the
  depths in §1.1.
- **Rule 6's writer half is not enforced by any encoder, in either
  language.** No production path can emit a longer chain from decoded input:
  a decoded subtree has already been limit-checked, and every re-emission
  (block save, merge, repair, manifest re-sign) puts it back at the same depth
  relative to the same root. An `UnknownValue` built in memory can still be
  deeper, which is the #586/#600 writer-half shape. Filed as its own issue in
  Task 8 rather than widening this slice into every encoder.

---

## 9. Proving it is not decorative

Mutation rows through `scripts/mutate.py`, `--self-test` first, gate named per
row, spec written to the session scratchpad:

| Mutation | Expected red |
|---|---|
| Rust `V1_MAX_NESTING_DEPTH` 256 → 255 | nesting seeds (the 256 rows), the ciborium path pin, the walk's unit tests |
| Rust walk's depth check removed | walk unit tests (the offset and the shallow-tag precedence); the seed rows' exact variant (ciborium's offset is `None`) |
| Python `V1_MAX_NESTING_DEPTH` 256 → 257 | NDL check 1; the replay on the `nesting__257_*` seeds |
| Python depth check removed from the shared traversal | NDL checks 1–2 on `record` AND the manifest (one machine, two entry points); the replay on the 2,048-deep seeds |
| The pass's call removed from `py_decode_manifest` | NDL check 1 (manifest); the replay on `manifest_body/nesting__257_unknown` |
| `py_encode_record` re-emits `tags: []` | RDO checks 1 and 3; RTS; the replay on the `tags` seed |
| An unclassified `py_decode_*` added under `codec/` | NDL check 5 |
| NDL or RDO left out of `registry.py` | Section REG |

Plus the full gate set from the baton's §(5), and a full-corpus replay with the
runtime corpus symlinked in and removed afterwards, recorded beside CI's finish
lines.

---

## 10. Files

New:
- `core/tests/nesting_depth_seeds.rs`
- `core/tests/python/conformance_lib/sections/nesting_depth.py`
- `core/tests/python/conformance_lib/sections/record_defaults.py`
- 3 files under `core/fuzz/seeds/record/` (`non_canonical_unclassified__present_default_*`)
- 7 files under `core/fuzz/seeds/{record,manifest_body}/` (`nesting__*`)

Changed:
- `docs/crypto-design.md` §6.2; `docs/vault-format.md` §4.2 and §6.3
- `core/src/cbor/{mod,well_formed}.rs`, `core/src/cbor/well_formed/tests.rs`,
  `core/src/vault/record.rs` (doc comment)
- `core/tests/rule_token_seeds.rs` + helpers (three rows, the census exclusion)
- `core/tests/differential_replay_helpers/targets.rs` (`MIN_CORPUS_INPUTS`)
- `conformance_lib/codec/{well_formed,record,manifest_decode,card,trash_entry}.py`
- `conformance_lib/sections/{registry,rule_token_vocabulary}.py`
- `CLAUDE.md`, `ROADMAP.md`, the handoff

Not changed: `docs/manual/contributors/differential-replay-protocol.md`, which
states no depth limit (checked). Every new source file stays under 500 lines;
`nesting_depth_seeds.rs` splits into a `_helpers/` directory, as its two
siblings do, if it would pass that.
