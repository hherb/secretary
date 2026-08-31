# Design — pin the #572 manifest canonicality contract

**Date:** 2026-08-31
**Issues closed:** #578, #585, #583, #592
**Issues deliberately NOT closed:** #589, #590, #586, #587 (diagnostics / type-invariant
work, not coverage — see §8)
**Base:** `e29cb216` (`main`), i.e. immediately after PR #584.

---

## 1. What is unpinned, and why it matters now

PR #584 (`a2da3d24`, #572) made `decode_manifest` re-encode the parsed `Manifest`
and require its input bytes back, and wrote two normative claims into the frozen
spec to match:

- `docs/vault-format.md` §4.2 — a five-row per-rule table against crypto-design
  §6.2's five rules (2, 3, 4 enforced inside an `unknown` subtree; 1 and 5 not),
  plus a **two-part reader obligation**: reproduce the subtree's entry order and
  repeated entries, **and** reject violations of rules 2, 3, 4.
- `docs/vault-format.md` §4.3 step 4 — the re-encode-and-compare is dispositive.

**Nothing executable checks any of it.**

| Would-be gate | Why it is blind |
|---|---|
| `golden_vault_001_pinned` | The fixture contains **zero** `unknown` subtrees. Vacuous here. |
| Property F (`manifest_props::manifest_roundtrip`) | All three strategies hardcode `unknown: BTreeMap::new()` (#578). |
| `conformance.py` | Has no `py_decode_manifest` at all — only the §4.1 envelope, then a bare `cbor2.loads` on the body (`conformance.py:1577`). (#585) |
| The `--diff-replay` protocol | Its `manifest_file` target is the §4.1 **envelope** (`decode_manifest_file`/`encode_manifest_file`). The §4.2/§4.3 **body** has no target on either side. |

This is the reader-side half of a change that genuinely **narrowed** the accepted
manifest set (`main` had no `NonCanonicalEncoding` variant, no re-encode, no
array-order check). A narrowing on the path every vault open takes, with no
randomized and no clean-room coverage, is the gap the #584 baton nominated as
"the real coverage gap".

## 2. The finding that reshapes the work (#592)

Measured by execution on both sides while scoping this slice.

**Rust ACCEPTS** a duplicate key and a non-canonical key order inside an
`unknown` subtree — pinned by the committed test
`unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`
(`core/src/vault/manifest/decode/tests.rs:901`). `ciborium::Value::Map` is an
ordered `Vec` of pairs, so both survive the parse that normalises everything else
and re-encode byte-identically.

```
duplicate key                A2 61 61 01 61 61 02    ({"a":1,"a":2})   -> Ok
keys out of canonical order  A2 62 7A 7A 01 61 61 02 ({"zz":1,"a":2})  -> Ok
```

**A `cbor2.loads` reader REJECTS the first.** `cbor2.loads` returns a `dict`:

```
cbor2.loads(A2 61 61 01 61 61 02)  ->  {"a": 2}      # len 1: the duplicate is COLLAPSED
cbor2.dumps({"a": 2}) == input     ->  False         # so §4.3 step 4 fails -> reject
```

Key *order* is fine (`dict` preserves insertion order; `cbor2.dumps` without
`canonical=True` re-emits it). **Repeated entries are not, and cannot be made
so:** the only knob is `allow_duplicate_keys` — `True` collapses, `False` raises;
both non-conformant, in opposite directions. `object_hook` fires *after* the
collapse. There is no pair-list output mode.

Two readers following `docs/` alone, **different acceptance sets** — the exact
interoperability failure §4.2 was written to prevent.

**Consequence for this design, and it makes the work cheaper rather than
dearer.** #583 sized its option (b) at "days, not an hour" because it treated the
byte-retaining reader as a *second* implementation built for comparison. It is
not optional: **byte retention is the only conformant strategy available in
Python**, so #585 must build it regardless. #583(b)'s "two conformant readers
accept the same set" then costs little beyond the corpus.

**The spec text itself is correct.** A `cbor2.loads`-to-`dict` reader simply
violates the part-(1) MUST. What is missing is any warning that the obvious
Python idiom is non-conformant — and crypto-design §6.2 actively recommends
`cbor2.dumps(record, canonical=True)`, which is worse: it re-sorts keys, so it
breaks re-emission of an out-of-order subtree too (verified:
`cbor2.dumps(d, canonical=True) != input` for the `{"zz":1,"a":2}` case).

## 3. Architecture — one new differential-replay target

`conformance.py`'s `--diff-replay <target> <input-path>` protocol already carries
six targets, each a `py_decode_<target>` / `py_encode_<target>` pair returning
`{"status": "accept", "reencoded_b64": ...}` or `{"status": "reject",
"error_class": ...}`. The Rust side mirrors them in
`core/tests/differential_replay.rs`.

This slice adds a **seventh target, `manifest_body`**:

| Side | Decode | Encode |
|---|---|---|
| Rust | `vault::manifest::decode_manifest` | `vault::manifest::encode_manifest` |
| Python | `py_decode_manifest` (new) | `py_encode_manifest` (new) |

One addition serves all four issues: #585 gets its clean-room decoder, #583(b)
gets its agreement harness, #592 becomes a test row, and the target joins the
machinery the fuzz harness already drives.

### Data flow

```
manifest body bytes
   |
   +-- Rust:   decode_manifest -> Manifest -> encode_manifest -> bytes'
   |
   +-- Python: py_decode_manifest -> ParsedManifest -> py_encode_manifest -> bytes''
   |
   accept/reject verdict AND bytes' == bytes'' == bytes, asserted row by row
```

## 4. The Python reader — approach (a), span-recording scanner

### 4.1 Approaches considered

**(a) Span-recording scanner + selective `cbor2` dispatch — CHOSEN.**
A minimal CBOR item scanner walks the body recording byte spans. Known keys
dispatch to `cbor2.loads` on their value span; **unknown keys retain their value
span's raw bytes verbatim**. Re-encode emits known values via `cbor2.dumps` and
splices the retained bytes back. Retention applies at **every level that carries
an `unknown` bag**, not only the body's top level — see the correction under
§4.2.

Rationale: it is the only one of the three that satisfies both halves of the
§4.2 obligation, it keeps `cbor2` doing the leaf work it does correctly, and the
entry-list intermediate gives duplicate detection at the known levels for free —
which is needed anyway, because Rust *rejects* duplicates there (#568/#573).

**(b) Hand-roll the whole §6.2 codec in Python, no `cbor2` for the body.**
Rejected. It duplicates work `cbor2` does correctly, and it **weakens** the
clean-room claim rather than strengthening it: a real clean-room implementer
would reach for a CBOR library, so proving the spec implementable *without* one
proves the wrong proposition. `conformance.py`'s whole premise is
"generic primitives declared in a PEP 723 header", and `cbor2` is one of them.

**(c) `cbor2.loads` everywhere plus a separate order/duplicate pre-check pass.**
Rejected, and recorded here **because it is the turn an implementer naturally
takes**. A pre-check can *detect* a duplicate, but the reader still cannot
**re-emit** one, so §4.2's part (1) stays unsatisfiable and §4.3 step 4 still
fails. Detection is not reproduction.

### 4.2 Components

Each is a pure function; I/O stays at the edges, matching the repo's convention.

| Component | Purpose | Depends on |
|---|---|---|
| `_decode_head(buf, pos) -> tuple[int, int, int \| None, int]` | Decode one CBOR head (RFC 8949 §3) into `(major, ai, arg, head_len)`; `arg` is `None` for the indefinite form. The shared primitive under the three below. | nothing |
| `_scan_item(buf, pos) -> int` | Return the end offset of the single CBOR item at `pos`. Recurses through arrays/maps/tags; handles indefinite-length forms by scanning to the break. | `_decode_head` |
| `_scan_map_entries(buf, pos) -> tuple[list[tuple[Span, Span]], int]` | Entry list of `(key_span, value_span)` for the map at `pos`, plus its end offset. A `Span` is a `(start, end)` offset pair into `buf` — never a copy, so a retained subtree is exhibited as `buf[start:end]` at re-encode time. **Preserves order and repeats** — this is the whole point. | `_scan_item` |
| `_check_canonical_item(buf, pos) -> int` | Rules 2/3/4 over the item at `pos`: no indefinite length, shortest-form heads, no floats, no tags. Recursive. **Raises `ValueError` naming the rule and the byte offset** rather than returning a bool — the corpus needs the locator, and a bare `False` would be exactly the undiagnosable failure #590 records. Returns the end offset. | `_decode_head` |
| `py_decode_manifest(data) -> dict` | Strict §4.2/§4.3 body decoder. Known keys via `cbor2.loads`; unknown keys keep raw bytes **at all three levels that have an `unknown` bag** (body, `blocks[i]`, `trash[i]`). Requires all 9 known top-level keys; rejects duplicates at known levels; enforces the five array sort disciplines; ends with the §4.3 step-4 re-encode-and-compare against its own input. | all of the above |
| `_decode_manifest_entry_map(...) -> dict` | One `blocks[i]` / `trash[i]` entry map. Known keys via `cbor2.loads`, **its own `unknown` bag byte-retained**, required fields enforced. | `_scan_map_entries` |
| `_decode_strict_entry_map(...) -> dict` | One fixed-shape map with **no** `unknown` bag — `kdf_params`, and each `vector_clock` / `vector_clock_summary` entry. **Rejects** any key outside the known set, matching Rust's catch-all `WrongType` arm. Opposite polarity to the row above. | `_scan_map_entries` |
| `py_encode_manifest(parsed) -> bytes` | Canonical re-encode; splices retained unknown bytes verbatim. | `encode_canonical_map_raw` |
| `encode_canonical_map_raw(entries: list[tuple[str, bytes]]) -> bytes` | Canonical map from **pre-encoded** value bytes. Sorts keys by `(len, bytes)` on their encoded form; writes the map header by hand. | nothing |

`encode_canonical_map_raw` is a new sibling of the existing
`encode_canonical_map` (`conformance.py:944`), which cannot be reused: it builds
a `dict` and calls `cbor2.dumps(d, canonical=True)`, so it re-sorts and cannot
carry pre-encoded values.

**Correction, recorded because the original scoping was the defect (Ruling 5).**
As first written, this table scoped byte retention to the manifest body's
**top-level** `unknown` bag only. That was wrong, and it cost Task 3 two fix
rounds to discover: `BlockEntry` and `TrashEntry` each carry their **own**
forward-compat `unknown` bag one level deeper (`core/src/vault/manifest/types.rs`),
so an entry routed wholesale through `cbor2.loads`/`dumps` collapses a duplicate
key that Rust accepts — the exact #592 divergence, one nesting level down. The
rule is level-independent: §4.2's rules-1/5 exemption for unknown subtrees
applies **wherever an `unknown` bag exists**, so retention must be implemented
at every such level. As shipped, that is three levels in the manifest (body,
`blocks[i]`, `trash[i]`) and — applying the same lesson prospectively under
Ruling 12 — **two levels in the record decoder** (`py_decode_record`: the
record-level `unknown` and each `RecordField`'s own `unknown`). The reviewer
found the manifest case by execution, not by reading the design; the record case
was scoped correctly from the start because this correction was already known.

Two further shape checks were added for the same reason — a Python decoder whose
accepted set differs from Rust's in *either* direction is a divergence:
`py_decode_manifest` requires all 9 known top-level keys (Rust's `Manifest` has
no `Option` among them; Ruling 6), and `kdf_params` / `vector_clock` /
`vector_clock_summary` entries **reject** forward-compat keys, because those
Rust parsers have no `unknown` bag and end in a catch-all `WrongType` arm
(Ruling 7).

### 4.3 Interface contract

`py_decode_manifest` returns a dict whose `unknown` entries map key -> **raw
`bytes`**, never a decoded object — at each of the three levels named above, and
likewise for `py_decode_record`'s two. That asymmetry is the design, and it is
stated in the function's own docstring: a decoded object cannot reproduce what
the spec requires reproducing.

### 4.4 Error handling

Every rejection raises `ValueError` with a message naming the rule and the
locator, matching the existing `py_decode_trash_entry` idiom. `run_diff_replay`
maps that to `{"status": "reject", "error_class": ...}`. No silent fallbacks: an
unrecognised shape is a raise, never a default.

## 5. The corpus and the agreement property (#583(b))

New fixture `core/tests/data/manifest_canonicality_kat.json`, generated by an
`#[ignore]` Rust test in the established `generate_conformance_kat` idiom
(`core/tests/conformance_kat.rs:317`), replayed by both languages.

**Seven subtree shapes** — one per crypto-design §6.2 rule, each violating that
rule inside an `unknown` subtree, plus two acceptable controls so the corpus
cannot pass by rejecting everything — each carrying the §4.2 table's expected
verdict.

| Shape | Subtree bytes | §4.2 table says | Rust today |
|---|---|---|---|
| `control_canonical` | `A1 61 61 01` — `{"a":1}` | — | accept |
| `control_array` | `82 01 02` — `[1,2]` | — | accept |
| `rule1_key_order` | `{"zz":1,"a":2}` | not enforced | accept |
| `rule2_indefinite_map` | `BF 61 61 01 FF` | enforced | reject |
| `rule3_non_shortest_int` | `A1 61 61 18 01` | enforced | reject |
| `rule4_float` | `A1 61 61 FA 3F C0 00 00` | enforced | reject |
| `rule5_duplicate_key` | `{"a":1,"a":2}` | not enforced | accept |

**Each shape is spliced at all THREE levels that carry an `unknown` bag — the
manifest body, a `blocks[i]` entry, and a `trash[i]` entry — so the fixture is
7 x 3 = 21 rows** (`top__*`, `block__*`, `trash__*`), not the 7 an earlier
version of this section described. The reason is Ruling 11, which is §4.2's
correction applied to the corpus: a corpus splicing only at top level would miss
exactly the nested divergence Task 3 spent two fix rounds closing, and the
agreement assertion below would pass while blind to it.

The agreement assertion: **Rust's verdict, and the Python byte-retaining
reader's verdict, must agree row for row — all 21.** A third column replays each
row through a deliberately naive `cbor2.loads`-based reader and asserts it
**diverges on all three `*__rule5_duplicate_key` rows** — #592 pinned as a
positive control, so the corpus proves it can tell the two strategies apart, at
every level, rather than passing vacuously. The naive reader also diverges on
the three `*__rule1_key_order` rows (`canonical=True` re-sorts the subtree's
keys); the assertion is membership, not set equality, so that is expected and
does not weaken the control.

**Seeds, not just a fixture.** `differential_replay.rs`'s `corpus_dirs()` reads
`core/fuzz/{corpus,seeds}/<target>` and treats an absent directory as an empty
list, so the new `manifest_body` target would pass **vacuously** with no seeds
(Ruling 10). The generator therefore also writes
`core/fuzz/seeds/manifest_body/` — 21 inputs, the same rows.

**Fixture-diff note.** The baton's standing check `git diff main...HEAD --stat --
core/tests/data/` must be **EMPTY** is about not changing the on-disk format.
This slice adds exactly one new file there and changes no existing one; the
check becomes "exactly one added path, zero modified".

## 6. #578 — the randomized corpus

`unknown_bag_strategy()` folded into `manifest_strategy`, `block_entry_strategy`
and `trash_entry_strategy` (`core/tests/proptest.rs`), per #578's own acceptance:
1..=3 entries, values drawn from five subtree shapes, **at least one a map in
non-canonical key order** (a canonically-ordered fixture cannot distinguish
"emitted verbatim" from "re-sorted on the way out"). A positive probe test
asserts the generated bags are genuinely non-empty at all three levels — without
it a strategy bug silently restores the status quo ante and Property F goes green
having tested nothing.

Two constraints #578 does not name, added here:

1. **Generated unknown keys must not collide with any known key name.** A
   collision makes `encode_manifest` emit a signed, ambiguous manifest — that is
   #586, and Property F is not the place to trip it.
2. **Every generated shape must be an *acceptable* one.** Property F is a
   round-trip property; rejected shapes belong in §5's corpus. Mixing them would
   force `prop_assume` noise into a property that should hold unconditionally.

## 7. The spec note and the sweep (#592)

Two edits, neither changing a byte on disk:

1. `docs/vault-format.md` §4.2 — an implementation note: a reader MUST NOT decode
   an unknown subtree into a mapping type that collapses duplicate keys, and the
   conformant strategy is to retain the subtree's bytes. Names `cbor2`'s
   `dict` as the concrete trap.
2. `docs/crypto-design.md` §6.2 — scope the `canonical=True` recommendation to
   **authoring your own bytes**, explicitly not to re-emitting someone else's.

**These are frozen-spec edits and get the sweep, not a spot fix.** The #584 slice
hit **seven** instances of the two-audience pattern (a sentence true for "this
reader" being false for "a future writer"), and **five of the seven were created
by the fix for the previous one**. Procedure: after editing, re-read the
neighbours in *both* documents for the other audience, and **tabulate every hit
with its verdict**. An untabulated "found nothing" is not a result.

## 8. Out of scope, stated so it is not mistaken for covered

- **#589** (the 21 duplicate-key guards are hand-copied, not a type invariant) and
  **#590** (`NonCanonicalEncoding` collapses five causes with no locator) are
  diagnostics and type-design work. This slice makes #590 more visible by adding
  a corpus that fires it five ways, which is an argument for doing it next, not
  here.
- **#586** / **#587** (the encoder can emit or sign a body its own decoder
  rejects) are encode-side invariants. §6's constraint 1 avoids *tripping* #586;
  it does not fix it.
- **#569 path 3** (`identity/card.rs`) is untouched. #569 stays open.
- A `manifest_body` **fuzz target** is a natural eighth target but is not built
  here; the `--diff-replay` wiring is what makes it cheap later.

## 9. Testing strategy

TDD throughout: each component's test is written first and observed to fail.

- **Unit** — `_scan_item` / `_scan_map_entries` / `_is_canonical_item` against
  hand-built byte fixtures, including every indefinite-length and
  non-shortest-form head.
- **Integration** — `py_decode_manifest` must first re-derive
  `golden_vault_001`'s manifest body, **replacing the bare `cbor2.loads` at
  `conformance.py:1577`**, before any corpus row is trusted. That is the
  ordering constraint: a new clean-room decoder asserting equality with a frozen
  format is only credible once it agrees with the frozen vault.
- **Property** — Property F with unknown bags at all three levels (§6).
- **Cross-language** — the §5 corpus, replayed both sides.
- **Mutation** — every new pin is mutation-verified: deleting the mechanism it
  claims to cover must red it. A green test that survives deletion of its own
  subject is not a pin.

## 10. Risks

| Risk | Mitigation |
|---|---|
| `py_decode_manifest` is new clean-room code asserting equality with a frozen format; if wrong it reds the conformance gate for reasons that are not the code's fault | §9's ordering constraint — golden vault first, corpus second |
| `golden_vault_001` has **zero** unknown subtrees, so it validates the known-field path and nothing else | Stated plainly; the §5 corpus carries the entire weight of the unknown-subtree claims, and §5's naive-reader column proves it is not vacuous |
| Frozen-spec edits re-trigger the two-audience pattern | §7's tabulated two-document sweep |
| `cargo` mtime trap during mutation verification: a mutation applied by a **backdating** operation (`mv`, `cp -p`, `rsync -a`, `touch -t/-r`) is never compiled, so the suite passes and the verifier wrongly concludes the mechanism is unpinned | Mutations applied by **in-place edit only** (a write stamps "now"); the literal command recorded in each task's report |
| `conformance.py` grows past a reviewable size (4303 lines today) | The new code is one cohesive block with pure-function boundaries; if it lands over ~400 lines, file a split issue rather than inlining it awkwardly |
