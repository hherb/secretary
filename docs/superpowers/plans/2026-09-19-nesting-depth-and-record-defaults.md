# Nesting-depth limit (#667) and record default omission (#670) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the last two known acceptance divergences between the Rust decoders and `conformance_lib`. A 256-level CBOR nesting limit becomes normative (crypto-design §6.2 rule 6) and is enforced explicitly in both languages. Absence becomes the only canonical spelling of a record optional key's default (vault-format §6.3).

**Architecture:** Rust's byte walk (`cbor/well_formed.rs`) enforces the limit on the `record` path. ciborium already enforces the identical limit on every other path, and a test pins that equality. Python's iterative walk enforces it, and a depth-only first pass built on the same traversal guards the manifest, card and trash-entry decoders. `py_encode_record` omits the three defaults, as Rust's encoder does, so the existing re-encode comparison rejects a present default. Every rule gets label-bound committed seeds, so CI compares both decoders on it.

**Tech Stack:** Rust 1.97.0 (stable, pinned), ciborium 0.2.2, Python via `uv` only (cbor2), `scripts/mutate.py` for mutation evidence.

**Spec:** `docs/superpowers/specs/2026-09-19-nesting-depth-and-record-defaults-design.md`

## Global Constraints

- Work ONLY in the worktree `/Users/hherb/src/secretary/.worktrees/nesting-depth-defaults`, branch `feature/nesting-depth-and-record-defaults`. Every file path handed to the Edit/Write tools must start with that prefix, because a bare `secretary/...` path writes to the MAIN checkout. Chain `cd` into it in every Bash call.
- `V1_MAX_NESTING_DEPTH = 256` exactly, in both languages. It counts arrays, maps and tags on one chain, the outermost included. A scalar is not a level: 256 nested arrays around an integer is WITHIN the limit.
- Every cargo command uses `--release --locked`.
- Clippy (`-D warnings`), rustdoc (`RUSTDOCFLAGS="-D warnings"`) and `cargo fmt --all --check` must stay clean.
- Python runs through `uv` only. Never pip.
- No magic numbers: every byte and count gets a named constant.
- Every source file stays under 500 lines.
- TDD: each behaviour's test is written and seen failing before the code that satisfies it.
- Commit messages end with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Fixes are cited as `(#N)`, never `Closes #N`.
- Mutation specs go in the session scratchpad (`$SCRATCH`), never the tree. `git status --short` must be empty after every mutation run.
- A `core/fuzz/corpus` symlink, if created, is removed after each use. `.gitignore` does not cover a symlink.

## File Structure

| File | Responsibility |
|---|---|
| `docs/crypto-design.md` §6.2 | rule 6, normative |
| `docs/vault-format.md` §4.2, §6.3 | depth in the well-formedness precondition; default omission |
| `core/src/cbor/mod.rs` | `pub const V1_MAX_NESTING_DEPTH` |
| `core/src/cbor/well_formed.rs` (+ `well_formed/tests.rs`) | `open_level`: the walk refuses the 257th level |
| `core/src/vault/record_walk_tests.rs` | the limit, end to end through `record::decode` |
| `core/tests/rule_token_seeds_helpers/record/{mod,plants}.rs` | three #670 seed rows |
| `core/tests/rule_token_seeds.rs` | census excludes the `nesting__` prefix |
| `core/tests/nesting_depth_seeds.rs` (NEW) | nesting seed generator + label binding + ciborium path pin |
| `core/tests/nesting_depth_seeds_helpers/{mod,prefix}.rs` (NEW) | the case table, the body builder, the shared prefix |
| `core/tests/differential_replay_helpers/targets.rs` | `MIN_CORPUS_INPUTS` |
| `conformance_lib/codec/cbor_faults.py` | `V1_MAX_NESTING_DEPTH`, `NestingTooDeep`, `require_room_for_another_level` |
| `conformance_lib/codec/well_formed.py` | one traversal `_walk`, two entry points: `walk_body`, `reject_excessive_nesting` |
| `conformance_lib/codec/{manifest_decode,card,trash_entry}.py` | call `reject_excessive_nesting` first |
| `conformance_lib/codec/record.py` | `py_encode_record` omits defaults |
| `conformance_lib/sections/record_defaults.py` (NEW) | Section RDO |
| `conformance_lib/sections/nesting_depth_bodies.py` (NEW) | pure body builders and seed-name constants for NDL and RTS |
| `conformance_lib/sections/nesting_depth.py` (NEW) | Section NDL |
| `conformance_lib/sections/{registry,well_formed_walk,rule_token_seeds,rule_token_vocabulary}.py` | register, twin rows, class list + prefix exclusion + floor, corpus tokens |

---

### Task 1: Normative spec text, and one correction to the design spec

**Files:**
- Modify: `docs/crypto-design.md` (§6.2, after rule 5)
- Modify: `docs/vault-format.md` (§4.2 precondition list; §6.3 after its schema block)
- Modify: `docs/superpowers/specs/2026-09-19-nesting-depth-and-record-defaults-design.md` (§3.1 wording, §8 residual)

**Interfaces:**
- Produces: the normative text every later task cites (crypto-design §6.2 rule 6; vault-format §6.3 "A default value is written by omission").

- [ ] **Step 1: Add rule 6 to crypto-design §6.2.** Insert immediately after rule 5's paragraph (the one ending "vault-format §4.2 states the per-rule split and the preservation requirement in full."), before the paragraph beginning "A clean-room implementation passing the equivalent of":

```markdown
Every such byte string is also bound by one limit that is not part of RFC 8949 §4.2.1's profile:

6. **Nesting depth is at most 256.** No chain of arrays, maps and tags, each held directly inside the one before it, may be longer than 256. The chain starts at the outermost item of the byte string being decoded, when that item is itself an array, map or tag. A scalar is not a level: an integer inside 256 nested arrays is within the limit, and a 257th array around it is not. Unlike rules 1 and 5, this limit is **not** scoped to interpreted material: it binds inside a forward-compat unknown subtree exactly as elsewhere, because a reader must walk a subtree's structure before it can retain it. Writers MUST NOT emit a longer chain, and readers MUST reject one. A tag is counted although rule 4 forbids tags, so that a body breaking both rules is reported the same way by every reader (vault-format §4.2's well-formedness precondition). This is a v1 profile bound, not a canonical-form rule. The reference implementation's readers have enforced exactly this limit since v1, so stating it narrows nothing a v1 reader accepts, and it bounds the stack a parser needs on input taken from the attacker-writable vault folder (§6 contact cards). Depth is counted from the root of the byte string being decoded, so a record inside a block plaintext is measured from the block's root.
```

- [ ] **Step 2: Add depth to vault-format §4.2's well-formedness precondition.** In the paragraph under ordering 1 that reads "a truncated head, a length that overruns the buffer, a text string that is not valid UTF-8, a major-7 value outside `false`/`true`/ `null` — reports that instead", insert one item so it reads:

```markdown
   that cannot — a truncated head, a length that overruns the buffer, a text
   string that is not valid UTF-8, a major-7 value outside `false`/`true`/
   `null`, a chain of arrays, maps and tags nested more than 256 deep
   (crypto-design §6.2 rule 6) — reports that instead, whatever else the body
   also breaks.
```

(Keep the rest of the paragraph byte-identical. The only change is the new list item before "— reports".)

- [ ] **Step 3: Add default omission to vault-format §6.3.** Insert immediately after the closing ```` ``` ```` of the §6.3 CBOR schema block and before `#### 6.3.1`:

```markdown
**A default value is written by omission.** `tags`, `tombstone` and `tombstoned_at_ms` each have a default — the empty array, `false` and `0` — and the canonical encoding of a record whose value for one of them equals its default is the encoding that omits that key. A writer MUST omit `tags` when the record carries no label, `tombstone` when the record is live, and `tombstoned_at_ms` when the record has never been tombstoned. A reader MUST reject a record carrying any of the three present at its default value, as non-canonical. Every other value is written in full, and the three are independent: `tombstoned_at_ms` non-zero with `tombstone` absent is the resurrection shape crypto-design §11.3 describes, and is canonical. (One value, one encoding: crypto-design §6.2 admits exactly one byte string per record, and a present default would be a second spelling of the absent one.)
```

- [ ] **Step 4: Correct the design spec's rule-6 wording.** In the design spec §3.1, replace the quoted rule-6 paragraph with the text from Step 1. The approved wording ("No item may sit more than 256 levels deep … each enclosing array, map or tag as one further level") put a scalar inside 256 nested arrays at level 257, one level stricter than every shipped reader. The measurement in §1.1 accepts exactly that body (T=256).

- [ ] **Step 5: Record the writer-half residual in the design spec §8.** Append this bullet to §8:

```markdown
- **Rule 6's writer half is not enforced by any encoder, in either
  language.** No production path can emit a longer chain from decoded input:
  a decoded subtree has already been limit-checked, and every re-emission
  (block save, merge, repair, manifest re-sign) puts it back at the same depth
  relative to the same root. An `UnknownValue` built in memory can still be
  deeper, which is the #586/#600 writer-half shape. Filed as its own issue in
  Task 8 rather than widening this slice into every encoder.
```

- [ ] **Step 6: Verify the docs reference nothing stale.**

Run: `cd /Users/hherb/src/secretary && uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -1; cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -1`
Expected: both exit 1 with the SAME count. The first run is the `main` checkout's baseline (read-only), the second is this branch. These edits cite no test names, so no new unresolved citation may appear.

- [ ] **Step 7: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
git add docs/crypto-design.md docs/vault-format.md docs/superpowers/specs/2026-09-19-nesting-depth-and-record-defaults-design.md
git commit -m "$(cat <<'EOF'
Spec: crypto-design §6.2 rule 6 (nesting depth <= 256) and §6.3 default omission (#667, #670)

Rule 6 counts arrays, maps and tags on one chain, the outermost included; a
scalar is not a level. That matches ciborium 0.2.2's recursion limit exactly,
which every v1 reader of this crate has enforced, so it narrows nothing. The
design spec's approved wording counted the scalar and was one level stricter
than every shipped reader; corrected here.

vault-format §4.2 lists depth among the well-formedness preconditions, so it
outranks rule 4. §6.3 makes absence the only canonical spelling of tags: [],
tombstone: false and tombstoned_at_ms: 0.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: #670 end to end — seeds, the Python writer, Section RDO

**Files:**
- Modify: `core/tests/rule_token_seeds_helpers/record/plants.rs`
- Modify: `core/tests/rule_token_seeds_helpers/record/mod.rs`
- Create: `core/fuzz/seeds/record/non_canonical_unclassified__present_default_{tags,tombstone,tombstoned_at_ms}.bin` (generated)
- Modify: `core/tests/python/conformance_lib/codec/record.py` (`py_encode_record`)
- Create: `core/tests/python/conformance_lib/sections/record_defaults.py`
- Modify: `core/tests/python/conformance_lib/sections/registry.py`
- Modify: `core/tests/python/conformance_lib/sections/rule_token_seeds.py` (`_TARGETS["record"]` floor 34 → 37)
- Modify: `core/tests/differential_replay_helpers/targets.rs` (`record` 37 → 40)

**Interfaces:**
- Consumes: `surgery::{entries, inserted, map, text}`, `plants.rs`' `ARRAY_EMPTY` and `UINT_ZERO` constants.
- Produces: `RECORD_OPTIONAL_DEFAULTS: dict[str, object]` and `_is_omitted_default(key: str, value: object) -> bool` in `codec/record.py`; `section_record_default_omission() -> tuple[bool, list[str]]`.

- [ ] **Step 1: Add the three plants.** In `plants.rs`, add a constant beside `TRUE`:

```rust
/// A CBOR `false`: `tombstone`'s default.
const FALSE: u8 = 0xf4;
```

and append three plant functions at the end of the file:

```rust
// vault-format §6.3 (#670): a default value is written by omission, so each of
// these is the base plus one optional key PRESENT at its default. Rust's
// encoder omits all three, so the re-encode comparison rejects the body.

pub(super) fn present_default_tags(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), text("tags"), vec![ARRAY_EMPTY]))
}

pub(super) fn present_default_tombstone(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), text("tombstone"), vec![FALSE]))
}

pub(super) fn present_default_tombstoned_at_ms(base: &[u8]) -> Vec<u8> {
    map(&inserted(
        &entries(base),
        text("tombstoned_at_ms"),
        vec![UINT_ZERO],
    ))
}
```

- [ ] **Step 2: Add the three rows.** In `record/mod.rs`, append to the `vec![...]` after the `trailing_bytes` row:

```rust
        case(
            NonCanonicalUnclassified,
            "present_default_tags",
            "NonCanonicalEncoding",
            present_default_tags,
        ),
        case(
            NonCanonicalUnclassified,
            "present_default_tombstone",
            "NonCanonicalEncoding",
            present_default_tombstone,
        ),
        case(
            NonCanonicalUnclassified,
            "present_default_tombstoned_at_ms",
            "NonCanonicalEncoding",
            present_default_tombstoned_at_ms,
        ),
```

- [ ] **Step 3: Run the seed test and watch it fail.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --test rule_token_seeds 2>&1 | tail -15`
Expected: FAIL in `rule_token_seeds_are_committed_and_label_bound` with "seed …present_default_tags.bin is not committed". `assert_rust_names_its_token` has already passed for the row, which proves Rust rejects each body as `NonCanonicalEncoding`.

- [ ] **Step 4: Generate, then re-run.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --test rule_token_seeds -- --ignored generate_rule_token_seeds && cargo test --release --locked -p secretary-core --test rule_token_seeds 2>&1 | tail -5 && git status --short core/fuzz/seeds`
Expected: `3 passed; 0 failed; 1 ignored`. Exactly three new untracked files under `core/fuzz/seeds/record/`.

- [ ] **Step 5: Watch Python fail on the new seeds (the divergence, measured).**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/conformance.py 2>&1 | grep -E "FAIL|present_default" | head`
Expected: `FAIL: rule-token seeds are rejected with the rule their file names`, plus three issue lines "record/non_canonical_unclassified__present_default_*.bin: expected a rejection naming 'non_canonical_unclassified', got {'status': 'accept', …}".

- [ ] **Step 6: Write Section RDO (the failing test for the writer).** Create `core/tests/python/conformance_lib/sections/record_defaults.py`:

```python
"""Section RDO -- vault-format §6.3: a default value is written by omission
(#670).

`tags`, `tombstone` and `tombstoned_at_ms` each have a default (the empty
array, `false`, `0`), and the canonical encoding of a record holding a
default leaves the key out. `record.rs`'s `record_to_canonical` has always
omitted all three, so `record::decode`'s re-encode comparison rejects a body
that spells one out. `py_encode_record` used to re-emit whatever it decoded,
so this reader ACCEPTED those bodies: an acceptance divergence no corpus
input reached.

THE MECHANISM IS THE RE-ENCODE, ON BOTH SIDES, DELIBERATELY.  §6.3 states no
reader check separate from canonical form, and Rust has none: its rejection
IS the comparison.  So this is not #608's backstop trap, where an encoder
refusal answered for a reader check §4.2 states on its own.  The writer half
is still asserted separately (check 3), so a reader-side special case cannot
stand in for the encoder.

Three checks, each reporting what it RAN:
  1. each key present at its default is rejected as `RecordNonCanonical`;
  2. controls: the same key absent, and the key at a non-default value, are
     each ACCEPTED -- without them a reader rejecting the key outright passes 1;
  3. the writer omits each default and keeps each non-default.
"""

from __future__ import annotations

from conformance_lib import fixtures
from conformance_lib.codec.record import py_decode_record, py_encode_record
from conformance_lib.codec.record_rules import RecordNonCanonical

# The accepting base every body is built from: no optional key present.
_BASE_SEED = "login.cbor"
# Each optional key's default, and one value that is not its default.
_DEFAULTS: tuple[tuple[str, object], ...] = (
    ("tags", []),
    ("tombstone", False),
    ("tombstoned_at_ms", 0),
)
_NON_DEFAULTS: tuple[tuple[str, object], ...] = (
    ("tags", ["x"]),
    ("tombstone", True),
    ("tombstoned_at_ms", 5),
)


def _base_bytes() -> bytes:
    return (fixtures.fuzz_seed_dir("record") / _BASE_SEED).read_bytes()


def _with_key(key: str, value: object) -> bytes:
    """The base with `key` set to `value`, in canonical key order.

    `cbor2`'s canonical mode reproduces the base byte for byte with nothing
    added (checked below), so the body differs from it by exactly one entry.
    """
    import cbor2

    record = cbor2.loads(_base_bytes())
    record[key] = value
    return cbor2.dumps(record, canonical=True)


def _base_round_trip_issue() -> str | None:
    import cbor2

    base = _base_bytes()
    if cbor2.dumps(cbor2.loads(base), canonical=True) != base:
        return f"{_BASE_SEED}: cbor2's canonical re-encode is not byte-identical, so a body would carry faults nobody planted"
    return None


def _reader_issues() -> tuple[list[str], int]:
    issues = []
    for key, value in _DEFAULTS:
        try:
            py_decode_record(_with_key(key, value))
        except RecordNonCanonical:
            continue
        except Exception as exc:  # noqa: BLE001 -- the wrong rejection is an issue too
            issues.append(f"{key}={value!r}: raised {type(exc).__name__}, expected RecordNonCanonical ({exc})")
            continue
        issues.append(f"{key}={value!r}: ACCEPTED; vault-format §6.3 requires the default to be omitted")
    return issues, len(_DEFAULTS)


def _control_issues() -> tuple[list[str], int]:
    issues = []
    bodies = [("absent (the base)", _base_bytes())]
    bodies.extend((f"{key}={value!r}", _with_key(key, value)) for key, value in _NON_DEFAULTS)
    for label, body in bodies:
        try:
            py_decode_record(body)
        except Exception as exc:  # noqa: BLE001 -- any rejection fails a control
            issues.append(f"control {label}: must be ACCEPTED, raised {type(exc).__name__}: {exc}")
    return issues, len(bodies)


def _writer_issues() -> tuple[list[str], int]:
    issues = []
    decoded = py_decode_record(_base_bytes())
    omitted = py_encode_record(decoded)
    for key, value in _DEFAULTS:
        if py_encode_record({**decoded, key: value}) != omitted:
            issues.append(f"writer: {key}={value!r} was emitted; §6.3 requires it omitted")
    for key, value in _NON_DEFAULTS:
        if py_encode_record({**decoded, key: value}) == omitted:
            issues.append(f"writer: {key}={value!r} was dropped; only a default is omitted")
    return issues, len(_DEFAULTS) + len(_NON_DEFAULTS)


def section_record_default_omission() -> tuple[bool, list[str]]:
    issues = []
    if (issue := _base_round_trip_issue()) is not None:
        return False, [f"  ISSUE: {issue}"]
    reader, n_reader = _reader_issues()
    controls, n_controls = _control_issues()
    writer, n_writer = _writer_issues()
    issues = reader + controls + writer
    lines = [
        f"PASS 1: {n_reader - len(reader)}/{n_reader} present-default bodies rejected as RecordNonCanonical",
        f"PASS 2: {n_controls - len(controls)}/{n_controls} controls accepted (absent, and each non-default)",
        f"PASS 3: {n_writer - len(writer)}/{n_writer} writer cases (defaults omitted, non-defaults kept)",
    ]
    lines.extend(f"  ISSUE: {issue}" for issue in issues)
    return (not issues, lines)
```

- [ ] **Step 7: Register it.** In `sections/registry.py`, add the import beside the other section imports:

```python
from conformance_lib.sections.record_defaults import section_record_default_omission
```

and add the row immediately before the `# Last on purpose:` comment above `Section("REG", ...)`:

```python
    Section("RDO", "record optional keys: a default is written by omission",
            " (vault-format §6.3, #670)", section_record_default_omission),
```

- [ ] **Step 8: Run it and watch it fail.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/conformance.py 2>&1 | grep -A8 "Section RDO"`
Expected: `PASS 1: 0/3 …`, `PASS 3: 3/6 …` plus ISSUE lines "ACCEPTED; vault-format §6.3 requires the default to be omitted" and "writer: … was emitted". `FAIL: record optional keys: a default is written by omission`. REG passes (the section is registered).

- [ ] **Step 9: Make the writer omit defaults.** In `codec/record.py`, add below `RECORD_FIELD_KNOWN_KEYS`:

```python
# vault-format §6.3 (#670): a default value is written by omission. The three
# optional keys and their defaults, exactly as `record.rs`'s
# `record_to_canonical` omits them (`tags` when empty, `tombstone` when false,
# `tombstoned_at_ms` when 0).
RECORD_OPTIONAL_DEFAULTS: dict[str, object] = {
    "tags": [],
    "tombstone": False,
    "tombstoned_at_ms": 0,
}


def _is_omitted_default(key: str, value: object) -> bool:
    """True when `key` is an optional record key holding its default.

    The TYPE is compared as well as the value: in Python `False == 0`, so a
    value-only test would drop a (wrong-typed) `tombstoned_at_ms: False` and
    silently change what the encoder was asked to emit.
    """
    if key not in RECORD_OPTIONAL_DEFAULTS:
        return False
    default = RECORD_OPTIONAL_DEFAULTS[key]
    return type(value) is type(default) and value == default
```

In `py_encode_record`, change the loop's skip test from `if k == "unknown":` to:

```python
        if k == "unknown" or _is_omitted_default(k, v):
            continue
```

and replace the docstring's paragraph that begins "`record` is expected to carry exactly the shape `py_decode_record` produces:" through "the pre-#592 shape this function used to require)." with:

```python
    `record` is expected to carry the shape `py_decode_record` produces, with
    `"unknown"` mapping to `{key: raw_bytes}` rather than flattened into the
    known keys (the pre-#592 shape). The three optional keys are omitted when
    they hold their defaults (vault-format §6.3, #670), as
    `record_to_canonical` omits them, so a decoded body that spelled a default
    out fails the re-encode comparison in `py_decode_record` -- the same phase
    and the same token (`non_canonical_unclassified`) as `record::decode`.
```

- [ ] **Step 10: Raise the two floors.** In `sections/rule_token_seeds.py`, change `_TARGETS["record"]`'s floor from `34` to `37`. In `core/tests/differential_replay_helpers/targets.rs`, change `("record", 37)` to `("record", 40)`.

- [ ] **Step 11: Run everything this task touched.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/conformance.py 2>&1 | grep -E "^FAIL|Section RDO|PASS [123]:.*(present|controls|writer)|REG|RTS" ; echo "exit ${pipestatus[1]}"`
Expected: no `FAIL:` line; RDO reads `3/3`, `4/4`, `6/6`; REG reads `34/34`.

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay 2>&1 | grep -E "test result|record:|disagree|harness"`
Expected: `test result: ok. 46 passed`, and the finish line `record: 40 of 40 input(s) compared, 40 committed`.

- [ ] **Step 12: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
git add core/tests/rule_token_seeds_helpers/record core/fuzz/seeds/record/non_canonical_unclassified__present_default_*.bin \
  core/tests/python/conformance_lib/codec/record.py core/tests/python/conformance_lib/sections/record_defaults.py \
  core/tests/python/conformance_lib/sections/registry.py core/tests/python/conformance_lib/sections/rule_token_seeds.py \
  core/tests/differential_replay_helpers/targets.rs
git commit -m "$(cat <<'EOF'
Reject a record optional key present at its default in conformance_lib (#670)

vault-format §6.3 now makes absence the only canonical spelling of tags: [],
tombstone: false and tombstoned_at_ms: 0. record_to_canonical has always
omitted them; py_encode_record re-emitted whatever it decoded, so Python
ACCEPTED all three bodies. It now omits them too, so the existing re-encode
comparison rejects at the same phase and token as record::decode.

Three single-fault seeds make CI compare both decoders on each key (committed
replay inputs 121 -> 124), and Section RDO pins reader, controls and writer.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Rust — the walk enforces `V1_MAX_NESTING_DEPTH`

**Files:**
- Modify: `core/src/cbor/mod.rs` (new pub const; `CborErrorKind::RecursionLimit` doc)
- Modify: `core/src/cbor/well_formed.rs` (`open_level`, two call sites, module doc)
- Modify: `core/src/cbor/well_formed/tests.rs` (replace the no-cap test)
- Modify: `core/src/vault/record_walk_tests.rs` (end-to-end tests)
- Modify: `core/src/vault/record.rs` (`decode`'s rule list doc)

**Interfaces:**
- Produces: `pub const secretary_core::cbor::V1_MAX_NESTING_DEPTH: usize = 256`. The walk returns `WalkFault::Malformed(CborFault { kind: CborErrorKind::RecursionLimit, offset: Some(head_at) })` for the head that would open level 257. That surfaces from `record::decode` as `RecordError::CborDecode(..)`, token `malformed_cbor`.

- [ ] **Step 1: Add the constant.** In `core/src/cbor/mod.rs`, immediately before the `/// Which upstream codec failure occurred` doc comment of `CborErrorKind`, add:

```rust
/// crypto-design §6.2 rule 6: the longest chain of arrays, maps and tags a
/// canonical-CBOR document may hold, its outermost item included (#667). A
/// scalar is not a level.
///
/// It is exactly the recursion limit `ciborium` 0.2.2 applies to every
/// parse, which every reader in this crate has enforced since v1, so stating
/// it narrowed nothing. The byte walk `record::decode` runs first enforces it
/// itself; `core/tests/nesting_depth_seeds.rs` fails if `ciborium`'s limit
/// ever stops equalling it on the paths that still rely on `ciborium` for it.
pub const V1_MAX_NESTING_DEPTH: usize = 256;
```

and change the `RecursionLimit` variant's doc from `/// Nesting exceeded `ciborium`'s recursion limit.` to:

```rust
    /// Nesting exceeded crypto-design §6.2 rule 6 ([`V1_MAX_NESTING_DEPTH`]):
    /// reported by the byte walk on the record path, and by `ciborium`'s
    /// equal recursion limit on every other path.
```

- [ ] **Step 2: Write the failing walk tests.** In `core/src/cbor/well_formed/tests.rs`:
  - change the import line to `use crate::cbor::{CborErrorKind, CborFault, V1_MAX_NESTING_DEPTH};`;
  - delete the constant `DEPTH_BEYOND_CIBORIUM_LIMIT` (and its doc line) and the test `nesting_has_no_depth_cap_of_its_own`;
  - add, in the same place as the deleted test:

```rust
fn too_deep(offset: usize) -> WalkFault {
    WalkFault::Malformed(CborFault {
        kind: CborErrorKind::RecursionLimit,
        offset: Some(offset),
    })
}

/// `levels` one-element arrays around a `0`: one byte per level.
fn nested_arrays(levels: usize) -> Vec<u8> {
    let mut body = vec![ARRAY_1; levels];
    body.push(UINT_0);
    body
}

/// crypto-design §6.2 rule 6: 256 levels around a scalar are within the limit.
#[test]
fn nesting_to_the_v1_limit_is_well_formed() {
    assert_eq!(
        walk_first_item(&nested_arrays(V1_MAX_NESTING_DEPTH)),
        Ok(V1_MAX_NESTING_DEPTH + 1)
    );
}

/// The 257th array's head sits at offset 256, one byte per array before it.
#[test]
fn one_level_past_the_limit_is_malformed_at_that_level() {
    assert_eq!(
        walk_first_item(&nested_arrays(V1_MAX_NESTING_DEPTH + 1)),
        Err(too_deep(V1_MAX_NESTING_DEPTH))
    );
}

/// The walk stops at the first excess level, whatever lies beyond it.
#[test]
fn nesting_far_past_the_limit_stops_at_the_first_excess_level() {
    assert_eq!(
        walk_first_item(&nested_arrays(2 * V1_MAX_NESTING_DEPTH)),
        Err(too_deep(V1_MAX_NESTING_DEPTH))
    );
}

/// Maps are levels too: `{"a": {"a": … 0}}`, three bytes per level.
#[test]
fn maps_are_nesting_levels() {
    let level = [MAP_1, TEXT_1, ASCII_A];
    let nested = |levels: usize| {
        let mut body = level.repeat(levels);
        body.push(UINT_0);
        body
    };
    assert_eq!(
        walk_first_item(&nested(V1_MAX_NESTING_DEPTH)),
        Ok(level.len() * V1_MAX_NESTING_DEPTH + 1)
    );
    assert_eq!(
        walk_first_item(&nested(V1_MAX_NESTING_DEPTH + 1)),
        Err(too_deep(level.len() * V1_MAX_NESTING_DEPTH))
    );
}

/// An indefinite container is a level; the walk refuses the 257th before it
/// needs any break.
#[test]
fn indefinite_containers_are_nesting_levels() {
    assert_eq!(
        walk_first_item(&vec![ARRAY_INDEFINITE; V1_MAX_NESTING_DEPTH + 1]),
        Err(too_deep(V1_MAX_NESTING_DEPTH))
    );
}

/// Rule 6 counts a tag as a level, so a tag that would be level 257 is a depth
/// fault, not a rule-4 one.
#[test]
fn a_tag_is_a_nesting_level() {
    let mut body = vec![ARRAY_1; V1_MAX_NESTING_DEPTH];
    body.extend([TAG_1, UINT_0]);
    assert_eq!(walk_first_item(&body), Err(too_deep(V1_MAX_NESTING_DEPTH)));
}

/// The control: the same tag one level shallower is within the limit, so
/// rule 4 answers.
#[test]
fn a_tag_at_the_limit_is_still_rule_4() {
    let mut body = vec![ARRAY_1; V1_MAX_NESTING_DEPTH - 1];
    body.extend([TAG_1, UINT_0]);
    assert_eq!(
        walk_first_item(&body),
        Err(WalkFault::Tag {
            offset: V1_MAX_NESTING_DEPTH - 1
        })
    );
}

/// Depth is a well-formedness fault (vault-format §4.2's precondition), so it
/// outranks a tag the walk has already remembered.
#[test]
fn excess_depth_outranks_an_earlier_tag() {
    let tag_first = [ARRAY_2, TAG_1, UINT_0];
    let mut body = tag_first.to_vec();
    body.extend(nested_arrays(V1_MAX_NESTING_DEPTH));
    // `ARRAY_2` is level 1, so the chain after the tag starts at level 2 and
    // its `V1_MAX_NESTING_DEPTH`-th array is level 257.
    assert_eq!(
        walk_first_item(&body),
        Err(too_deep(tag_first.len() + V1_MAX_NESTING_DEPTH - 1))
    );
}
```

- [ ] **Step 3: Run them and watch the right ones fail.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --lib cbor::well_formed 2>&1 | grep -E "^test |test result"`
Expected: FAIL for `one_level_past_the_limit_is_malformed_at_that_level`, `nesting_far_past_the_limit_stops_at_the_first_excess_level`, `maps_are_nesting_levels`, `indefinite_containers_are_nesting_levels` (the walk has no cap yet, so it runs out of input: an `Io` fault, not `RecursionLimit`), `a_tag_is_a_nesting_level` and `excess_depth_outranks_an_earlier_tag` (rule 4 answers). PASS for `nesting_to_the_v1_limit_is_well_formed` and `a_tag_at_the_limit_is_still_rule_4`.

- [ ] **Step 4: Implement `open_level`.** In `core/src/cbor/well_formed.rs`, change the import to `use crate::cbor::{CborErrorKind, CborFault, V1_MAX_NESTING_DEPTH};` and add after `open_container`:

```rust
/// Open one more nesting level for the head at `head_at`, refusing the one
/// past crypto-design §6.2 rule 6. Returned at once, like every
/// well-formedness fault, so it outranks a rule-4 fault already remembered —
/// vault-format §4.2's precondition.
fn open_level(stack: &mut Vec<Frame>, head_at: usize, frame: Frame) -> Result<(), WalkFault> {
    if stack.len() >= V1_MAX_NESTING_DEPTH {
        return Err(WalkFault::Malformed(CborFault {
            kind: CborErrorKind::RecursionLimit,
            offset: Some(head_at),
        }));
    }
    stack.push(frame);
    Ok(())
}
```

In `walk_first_item`, replace the two push arms with:

```rust
            MAJOR_ARRAY | MAJOR_MAP => {
                open_level(&mut stack, pos, open_container(&head))?;
                pos += head.len;
            }
            MAJOR_TAG => {
                open_level(&mut stack, pos, Frame::Definite { left: 1 })?;
                first_rule4.get_or_insert((Rule4::Tag, pos));
                pos += head.len;
            }
```

Replace the module doc's `**Iterative.**` paragraph with:

```rust
//! **Iterative, and bounded by crypto-design §6.2 rule 6.** An explicit stack,
//! no recursion. The stack is also the depth count: a head that would open a
//! level past [`V1_MAX_NESTING_DEPTH`] (arrays, maps and tags alike; a scalar
//! is not a level) is `Malformed` with kind `RecursionLimit`, reported at once
//! like every well-formedness fault. It is the limit `ciborium`'s parse
//! applies afterwards, so on the record path the walk now answers before
//! `ciborium` can (#667).
```

and add `(depth past crypto-design §6.2 rule 6)` to the `**What it checks.**` list, after "a major-7 simple value other than false/true/null".

- [ ] **Step 5: Run the walk tests again.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --lib cbor::well_formed 2>&1 | tail -3`
Expected: `test result: ok.` with 0 failed.

- [ ] **Step 6: Write the end-to-end record tests.** In `core/src/vault/record_walk_tests.rs`, extend the `use crate::cbor::{…}` import with `V1_MAX_NESTING_DEPTH`, add constants beside the existing ones:

```rust
const ARRAY_1: u8 = 0x81;
const ARRAY_2: u8 = 0x82;
const TAG_1: u8 = 0xc1;
/// The largest one-byte map head: a map of 23 entries.
const MAP_SMALL_MAX: u8 = 0xb7;
/// The one-byte head of an empty map; with `MAP_SMALL_MAX`, the range of
/// one-byte map heads.
const MAP_EMPTY: u8 = 0xa0;
/// A one-letter forward-compat key, `"a"`. It is shorter than every v1 key, so
/// canonical order puts it first and it can be spliced in right after the map
/// head.
const FIRST_KEY: [u8; 2] = [TEXT_1, ASCII_A];
```

and append these helpers and tests at the end of the file:

```rust
/// `levels` one-element arrays around a `0`.
fn nested_arrays(levels: usize) -> Vec<u8> {
    let mut body = vec![ARRAY_1; levels];
    body.push(UINT_0);
    body
}

/// `LOGIN_RECORD` with a first entry `"a"` holding `value`.
fn login_with_first_entry(value: &[u8]) -> Vec<u8> {
    let (&head, rest) = LOGIN_RECORD.split_first().expect("the seed is not empty");
    assert!(
        (MAP_EMPTY..MAP_SMALL_MAX).contains(&head),
        "the seed must be a small map with room for one more entry"
    );
    let mut body = vec![head + 1];
    body.extend(FIRST_KEY);
    body.extend(value);
    body.extend(rest);
    body
}

/// crypto-design §6.2 rule 6, end to end: the record's own map is level 1, so
/// an unknown value holding 255 arrays takes it to exactly the limit.
#[test]
fn a_record_nested_to_the_v1_limit_decodes() {
    let body = login_with_first_entry(&nested_arrays(V1_MAX_NESTING_DEPTH - 1));
    if let Err(e) = decode(&body) {
        panic!("a record at the v1 nesting limit must decode: {e:?}");
    }
}

/// One level past it, the WALK answers, not ciborium. The walk's fault carries
/// the offset of the head that would open level 257, where ciborium's carries
/// none, and that difference is what this test pins.
#[test]
fn a_record_one_level_past_the_limit_is_rejected_by_the_walk() {
    let body = login_with_first_entry(&nested_arrays(V1_MAX_NESTING_DEPTH));
    // The map head, the key, then the chain: its (V1_MAX_NESTING_DEPTH)-th
    // array is level 257.
    let level_257_at = 1 + FIRST_KEY.len() + V1_MAX_NESTING_DEPTH - 1;
    let got = decode(&body);
    assert!(
        matches!(
            got,
            Err(RecordError::CborDecode(CborFault {
                kind: CborErrorKind::RecursionLimit,
                offset: Some(at),
            })) if at == level_257_at
        ),
        "expected the walk's RecursionLimit at {level_257_at}, got {:?}",
        got.err()
    );
}

/// A tag early in the body is remembered by the walk, and excess depth later
/// still outranks it: before #667 this record said `TagRejected`.
#[test]
fn excess_depth_outranks_an_earlier_tag_in_a_record() {
    let mut value = vec![ARRAY_2, TAG_1, UINT_0];
    value.extend(nested_arrays(V1_MAX_NESTING_DEPTH));
    let got = decode(&login_with_first_entry(&value));
    assert!(
        matches!(
            got,
            Err(RecordError::CborDecode(CborFault {
                kind: CborErrorKind::RecursionLimit,
                ..
            }))
        ),
        "expected RecursionLimit, got {:?}",
        got.err()
    );
}
```

If `UINT_0`, `TEXT_1` or `ASCII_A` are not already defined in this file, they are (checked: lines 32-46 define `UINT_0`, `TEXT_1`, `ASCII_A`). Do not redefine them.

- [ ] **Step 7: Run the record walk tests.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --lib vault::record_walk_tests 2>&1 | grep -E "nest|depth|test result"`
Expected: all pass, including the proptest that pins "the walk never changes acceptance". Confirm the new tests are genuinely red-first by temporarily reverting `open_level`'s body to `stack.push(frame); Ok(())`: `a_record_one_level_past_the_limit_is_rejected_by_the_walk` and `excess_depth_outranks_an_earlier_tag_in_a_record` must fail. Restore it, then check with `git diff core/src/cbor/well_formed.rs` that only the intended change remains.

- [ ] **Step 8: Update `record::decode`'s rule list.** In `core/src/vault/record.rs`, change rule 1 of the `decode` doc comment to:

```rust
/// 1. The FIRST CBOR item in the bytes is well-formed, nests no deeper than
///    crypto-design §6.2 rule 6 allows, and carries no tag or float, checked
///    on the raw bytes before any parse (#641, #667). Bytes after that item
///    are not examined here; rule 8's re-encode comparison rejects them.
```

- [ ] **Step 9: Full Rust gate for this task.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core 2>&1 | grep -E "test result|FAILED|panicked" | sort | uniq -c | head; cargo clippy --release --locked --workspace --tests -- -D warnings 2>&1 | tail -2; RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -2; cargo fmt --all --check && echo FMT-OK`
Expected: every `test result: ok`; clippy and rustdoc finish with no warning; `FMT-OK`.

- [ ] **Step 10: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
git add core/src/cbor/mod.rs core/src/cbor/well_formed.rs core/src/cbor/well_formed/tests.rs core/src/vault/record_walk_tests.rs core/src/vault/record.rs
git commit -m "$(cat <<'EOF'
The record byte walk enforces crypto-design §6.2 rule 6 itself (#667)

V1_MAX_NESTING_DEPTH = 256 is public in secretary_core::cbor. The walk refuses
the head that would open level 257 (arrays, maps and tags; a scalar is not a
level) as Malformed/RecursionLimit, at once, so it outranks a remembered
rule-4 tag. On the record path the walk now answers before ciborium, whose
equal limit it used to rely on; no verdict moves, only a tag-plus-depth body's
reported variant (TagRejected -> CborDecode).

The old test asserting the walk had NO cap is inverted, not deleted.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Python — one traversal, two entry points, and Section WF's twin rows

**Files:**
- Modify: `core/tests/python/conformance_lib/codec/cbor_faults.py`
- Modify: `core/tests/python/conformance_lib/codec/well_formed.py`
- Modify: `core/tests/python/conformance_lib/sections/well_formed_walk.py`
- Modify: `core/tests/python/conformance_lib/sections/rule_token_seeds.py` (`_TOKENED_CLASSES`)

**Interfaces:**
- Consumes: `_decode_head`, `CBOR_AI_INDEFINITE`, `CBOR_BREAK`, `NonCanonicalItem`, `_reject_rule4_head` (unchanged, from `scanner`).
- Produces: in `cbor_faults`: `V1_MAX_NESTING_DEPTH = 256`, `class NestingTooDeep(MalformedCbor)` with `token = "malformed_cbor"` declared in its own body, `require_room_for_another_level(open_levels: int, head_at: int) -> None`. In `well_formed`: `walk_body(buf: bytes, pos: int = 0) -> int` (unchanged signature), `reject_excessive_nesting(buf: bytes) -> None`. The `NestingTooDeep` message is `"crypto-design §6.2 rule 6: nesting past 256 levels at offset N"`.

- [ ] **Step 1: Rewrite Section WF's depth rows (the failing test).** In `sections/well_formed_walk.py`:
  - add to the imports: `from conformance_lib.codec.cbor_faults import MalformedCbor, NestingTooDeep, V1_MAX_NESTING_DEPTH` (replacing the existing `MalformedCbor` import);
  - delete the `DEPTH_BEYOND_CIBORIUM_LIMIT` constant and the comment above it, and keep `DEPTH_BEYOND_PYTHON_RECURSION_LIMIT`;
  - add these byte constants beside the other RFC 8949 constants if absent: `MAP_1 = 0xA1` (present), `ARRAY_INDEFINITE = 0x9F` (present), `TEXT_1`/`ASCII_A` (present);
  - replace the two rows `("deep nesting", …)` and `("nesting past Python's recursion limit", …)` with:

```python
    # -- crypto-design §6.2 rule 6 (#667), row for row the Rust twin's.  A
    # "too_deep" row's value is the offset of the head that would open level
    # 257; the walk raises `NestingTooDeep` there, at once. --
    ("nesting to the v1 limit",
     bytes([ARRAY_1] * V1_MAX_NESTING_DEPTH + [UINT_0]), "end", V1_MAX_NESTING_DEPTH + 1),
    ("one level past the limit",
     bytes([ARRAY_1] * (V1_MAX_NESTING_DEPTH + 1) + [UINT_0]), "too_deep", V1_MAX_NESTING_DEPTH),
    ("nesting far past the limit",
     bytes([ARRAY_1] * (2 * V1_MAX_NESTING_DEPTH) + [UINT_0]), "too_deep", V1_MAX_NESTING_DEPTH),
    ("maps to the limit",
     bytes([MAP_1, TEXT_1, ASCII_A] * V1_MAX_NESTING_DEPTH + [UINT_0]), "end",
     _MAP_LEVEL_LEN * V1_MAX_NESTING_DEPTH + 1),
    ("maps one past the limit",
     bytes([MAP_1, TEXT_1, ASCII_A] * (V1_MAX_NESTING_DEPTH + 1) + [UINT_0]), "too_deep",
     _MAP_LEVEL_LEN * V1_MAX_NESTING_DEPTH),
    ("indefinite containers are levels",
     bytes([ARRAY_INDEFINITE] * (V1_MAX_NESTING_DEPTH + 1)), "too_deep", V1_MAX_NESTING_DEPTH),
    ("a tag is a nesting level",
     bytes([ARRAY_1] * V1_MAX_NESTING_DEPTH + [TAG_1, UINT_0]), "too_deep", V1_MAX_NESTING_DEPTH),
    ("a tag at the limit is still rule 4",
     bytes([ARRAY_1] * (V1_MAX_NESTING_DEPTH - 1) + [TAG_1, UINT_0]), "tag", V1_MAX_NESTING_DEPTH - 1),
    ("excess depth outranks an earlier tag",
     _b(ARRAY_2, TAG_1, UINT_0) + bytes([ARRAY_1] * V1_MAX_NESTING_DEPTH + [UINT_0]), "too_deep",
     _TAG_FIRST_LEN + V1_MAX_NESTING_DEPTH - 1),
    # No Rust twin: a recursive walk raises `RecursionError` here, which is a
    # harness failure, not a verdict.  The iterative walk refuses level 257.
    ("nesting past Python's recursion limit",
     bytes([ARRAY_1] * DEPTH_BEYOND_PYTHON_RECURSION_LIMIT + [UINT_0]), "too_deep", V1_MAX_NESTING_DEPTH),
```

and add the two length constants beside `DEPTH_BEYOND_PYTHON_RECURSION_LIMIT`:

```python
# `{"a": …}`: a one-entry map head, a one-byte text head, the letter.
_MAP_LEVEL_LEN = 3
# `[<tag 1> 0, …]`: a two-item array head, a tag head, the tagged 0.
_TAG_FIRST_LEN = 3
```

  - in `_case_issue`, add an `except NestingTooDeep` clause BEFORE `except MalformedCbor`, and add a message regex beside `_RULE4_MESSAGE`:

```python
# `cbor_faults.require_room_for_another_level` composes this; the offset is
# read back and compared for equality, as the Rust twin asserts `Some(offset)`.
_DEPTH_MESSAGE = re.compile(r"crypto-design §6\.2 rule 6: nesting past \d+ levels at offset (?P<offset>\d+)")
```

```python
    except NestingTooDeep as exc:
        match = _DEPTH_MESSAGE.fullmatch(str(exc))
        if outcome != "too_deep":
            return f"{label}: raised NestingTooDeep ({exc}), expected {outcome}"
        if match is None or int(match["offset"]) != value:
            return f"{label}: raised {exc!r}, expected nesting past the limit at offset {value}"
        return None
```

  - update the module docstring's depth sentence (the one ending "which is the only row a recursive walk fails") to: "and crypto-design §6.2 rule 6 (#667): the v1 limit of 256 levels, row for row the Rust twin's, plus one row past Python's own recursion limit, which has no Rust twin because the Rust walk cannot recurse." Also add `"too_deep"` to the description of `outcome` values: "`"too_deep"` (it raises `NestingTooDeep` at offset `value`)".

- [ ] **Step 2: Run WF and watch it fail.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/conformance.py 2>&1 | grep -A14 "Section WF"`
Expected: an `ImportError` traceback naming `NestingTooDeep` or `V1_MAX_NESTING_DEPTH`. That is the red for this step, since `cbor_faults` does not define them yet.

- [ ] **Step 3: Add the shared rule to `cbor_faults.py`.** Append:

```python
# crypto-design §6.2 rule 6 (#667): the longest chain of arrays, maps and tags
# a canonical-CBOR document may hold, its outermost item included; a scalar is
# not a level.  The Rust twin is `secretary_core::cbor::V1_MAX_NESTING_DEPTH`.
V1_MAX_NESTING_DEPTH = 256


class NestingTooDeep(MalformedCbor):
    """crypto-design §6.2 rule 6: a chain of arrays, maps and tags longer than
    `V1_MAX_NESTING_DEPTH`.

    Rust reports it as `CborDecode` with kind `RecursionLimit`, whose token is
    `malformed_cbor`, and vault-format §4.2 lists it among the well-formedness
    preconditions, so it is a `MalformedCbor`.  The token is declared here, not
    inherited: Section RTS requires every verdict class to name its own."""

    token = "malformed_cbor"


def require_room_for_another_level(open_levels: int, head_at: int) -> None:
    """Refuse to open a level past crypto-design §6.2 rule 6.

    `open_levels` counts the arrays, maps and tags already open around the head
    at `head_at`, which would open one more."""
    if open_levels >= V1_MAX_NESTING_DEPTH:
        raise NestingTooDeep(
            f"crypto-design §6.2 rule 6: nesting past {V1_MAX_NESTING_DEPTH} levels "
            f"at offset {head_at}"
        )
```

- [ ] **Step 4: Split `walk_body` into one traversal with two entry points.** In `codec/well_formed.py`:
  - change the import to `from conformance_lib.codec.cbor_faults import MalformedCbor, NestingTooDeep, require_false_true_or_null, require_room_for_another_level, require_utf8`;
  - give `_string_end` a `check_utf8` parameter, used only where text is checked:

```python
def _string_end(buf: bytes, pos: int, major: int, arg: int | None, head: int, check_utf8: bool) -> int:
    text = major == MAJOR_TEXT and check_utf8
```

  (the rest of the function is unchanged: `text` is only passed on to `_payload_end`).
  - replace `walk_body` with `_walk`, `walk_body` and `reject_excessive_nesting`:

```python
def _walk(buf: bytes, pos: int, *, check_content: bool) -> int:
    """The one traversal both entry points share: item boundaries, crypto-design
    §6.2 rule 6 always, and -- when `check_content` -- UTF-8, simple values and
    rule 4.  The depth check lives here once, so it cannot drift between them."""
    stack: list[_Frame] = []
    first_rule4: NonCanonicalItem | None = None
    started = False
    while True:
        pos = _close_finished(buf, pos, stack)
        if started and not stack:
            if first_rule4 is not None:
                raise first_rule4
            return pos
        started = True
        _count_one_item(stack)
        major, ai, arg, head = _decode_head(buf, pos)
        if major in (MAJOR_UINT, MAJOR_NINT):
            pos += head
        elif major in (MAJOR_BYTES, MAJOR_TEXT):
            pos = _string_end(buf, pos, major, arg, head, check_utf8=check_content)
        elif major in (MAJOR_ARRAY, MAJOR_MAP):
            require_room_for_another_level(len(stack), pos)
            is_map = major == MAJOR_MAP
            left = None if arg is None else arg * (ITEMS_PER_MAP_ENTRY if is_map else 1)
            stack.append(_Frame(definite_left=left, is_map=is_map))
            pos += head
        elif major == MAJOR_TAG:
            require_room_for_another_level(len(stack), pos)
            if check_content:
                first_rule4 = first_rule4 or _rule4_at(major, ai, pos)
            stack.append(_Frame(definite_left=1))
            pos += head
        else:
            if ai == CBOR_AI_INDEFINITE:
                raise MalformedCbor(f"unexpected break at offset {pos}")
            if check_content:
                rule4 = _rule4_at(major, ai, pos)
                if rule4 is None:
                    require_false_true_or_null(ai, pos)
                first_rule4 = first_rule4 or rule4
            pos += head


def walk_body(buf: bytes, pos: int = 0) -> int:
    """Walk the CBOR item at `pos`; return the offset one past it.

    Raises `MalformedCbor` for a well-formedness fault anywhere in the item --
    `NestingTooDeep`, a subclass, for a level past crypto-design §6.2 rule 6,
    at once -- else `NonCanonicalItem` (rule 4) for the first tag or float.
    """
    return _walk(buf, pos, check_content=True)


def reject_excessive_nesting(buf: bytes) -> None:
    """crypto-design §6.2 rule 6 over a whole document, and nothing else (#667).

    The first statement of every `codec/` decoder that has no `walk_body` of its
    own (the manifest, the contact card, the trash entry), so a document nested
    past the limit is refused before any RECURSIVE phase runs -- which is what
    turned a 995-level manifest into a `RecursionError` harness failure.

    It walks item boundaries only.  It reports no content-level fault (invalid
    UTF-8, a disallowed simple value, a tag or float as rule 4), since none of
    those moves a boundary; a tag still counts as a level.  At a fault it cannot
    walk past -- a truncated head, an overrun, a bad chunk -- it stops and
    returns, leaving that fault to the decoder's own phases to report as they
    always have.  Every recursive phase after it scans in byte order, so it
    meets that same fault before it could nest past 256 levels.
    """
    try:
        _walk(buf, 0, check_content=False)
    except NestingTooDeep:
        raise
    except MalformedCbor:
        return
```

  - update the module docstring: replace the `ITERATIVE on purpose.` paragraph with:

```
ITERATIVE on purpose, and bounded by crypto-design §6.2 rule 6 (#667).
`scanner._scan_item` recurses, so a deeply nested body used to raise
`RecursionError` -- a harness failure, not a verdict.  This walk keeps an
explicit stack, and the stack is the depth count: a head that would open level
257 raises `NestingTooDeep` at once, like every well-formedness fault, so no
recursive phase after it ever sees more than 256 levels.  `reject_excessive_nesting`
is the same traversal with the content checks off, for the decoders that have
no `walk_body` of their own.
```

- [ ] **Step 5: List the new class in Section RTS.** In `sections/rule_token_seeds.py`'s `_TOKENED_CLASSES`, add after `(cbor_faults.MalformedCbor, "malformed_cbor"),`:

```python
    (cbor_faults.NestingTooDeep, "malformed_cbor"),
```

- [ ] **Step 6: Run the verifier.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/conformance.py 2>&1 | grep -E "^FAIL|Section WF|walk cases|Section RTS|Section CS" ; echo "exit ${pipestatus[1]}"`
Expected: no `FAIL:`. WF reads `PASS: <n>/<n> walk cases` (n = the previous 52, minus 2, plus 10 = 60). Exit 0. If Section RTV or CS names `NestingTooDeep` as an unlisted class, add it to that section's class table in the same way and re-run.

- [ ] **Step 7: Prove the depth check is live in both entry points.** Temporarily change `require_room_for_another_level`'s comparison to `open_levels >= V1_MAX_NESTING_DEPTH + 1` and re-run Step 6's command: WF must report the three limit rows failing. Restore it, re-run Step 6, and confirm with `git diff core/tests/python/conformance_lib/codec/cbor_faults.py` that the file holds only the intended additions.

- [ ] **Step 8: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
git add core/tests/python/conformance_lib/codec/cbor_faults.py core/tests/python/conformance_lib/codec/well_formed.py \
  core/tests/python/conformance_lib/sections/well_formed_walk.py core/tests/python/conformance_lib/sections/rule_token_seeds.py
git commit -m "$(cat <<'EOF'
conformance_lib's walk enforces crypto-design §6.2 rule 6; one traversal, two entry points (#667)

cbor_faults gains V1_MAX_NESTING_DEPTH, NestingTooDeep(MalformedCbor) and the
shared predicate. walk_body and the new reject_excessive_nesting are the same
iterative traversal (_walk), the second with content checks off and silent at
any fault but depth, so the depth rule exists once. Section WF's depth rows now
mirror the Rust twin's, and the row past Python's recursion limit expects a
verdict instead of a walk to the end.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Python decoders call the depth pass first — Section NDL checks 1-5

**Files:**
- Create: `core/tests/python/conformance_lib/sections/nesting_depth_bodies.py`
- Create: `core/tests/python/conformance_lib/sections/nesting_depth.py`
- Modify: `core/tests/python/conformance_lib/sections/registry.py`
- Modify: `core/tests/python/conformance_lib/codec/manifest_decode.py`, `codec/card.py`, `codec/trash_entry.py`

**Interfaces:**
- Consumes: `reject_excessive_nesting`, `NestingTooDeep`, `V1_MAX_NESTING_DEPTH` (Task 4); `encode_canonical_map_raw(entries: list[tuple[str, bytes]]) -> bytes`; `_scan_map_entries(buf, pos)`; `fixtures.fuzz_seed_dir(target)`.
- Produces: in `nesting_depth_bodies`: `NESTING_SEED_PREFIX = "nesting__"`, `FAR_PAST_THE_LIMIT = 2048`, `FUTURE_KEY`, byte constants, `nested_value(levels: int, innermost: bytes = bytes([UINT_0])) -> bytes`, `with_top_level_entry(base: bytes, key: str, value: bytes) -> bytes`, `document_nested_to(base: bytes, depth: int) -> bytes`, `expected_nesting_seeds() -> dict[str, frozenset[str]]`. In `nesting_depth`: `section_nesting_depth() -> tuple[bool, list[str]]`.

- [ ] **Step 1: Write the body builders.** Create `sections/nesting_depth_bodies.py`:

```python
"""Bodies and seed names for Section NDL (crypto-design §6.2 rule 6, #667).

Pure builders, split out of `nesting_depth.py` before either was written, so
each file holds one job.  Section RTS imports `NESTING_SEED_PREFIX` from here
to exclude the nesting seeds from its own census, as `rule_token_seeds.rs`
does on the Rust side.

DEPTH ARITHMETIC.  A document's own root map is level 1, so a value holding
`d - 1` one-element arrays around a scalar takes the document to exactly `d`
levels.  A scalar is not a level.
"""

from __future__ import annotations

from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.cbor_faults import V1_MAX_NESTING_DEPTH
from conformance_lib.codec.scanner import _scan_map_entries

ARRAY_1 = 0x81
ARRAY_2 = 0x82
TEXT_1 = 0x61
TAG_1 = 0xC1
UINT_0 = 0x00
INVALID_UTF8 = 0xFF

# A key no v1 document defines, so it lands in a forward-compat unknown bag
# where the schema accepts one.
FUTURE_KEY = "zz_future"
# Far past the limit and past Python's default recursion limit (~1,000), so a
# reader that recursed there would fail with `RecursionError` instead of a verdict.
FAR_PAST_THE_LIMIT = 2048
# The file-name prefix `core/tests/nesting_depth_seeds.rs` owns in
# `core/fuzz/seeds/{record,manifest_body}/`.  Mirrors that file's `SEED_PREFIX`.
NESTING_SEED_PREFIX = "nesting__"
SEED_EXTENSION = ".bin"


def nested_value(levels: int, innermost: bytes = bytes([UINT_0])) -> bytes:
    """`levels` one-element arrays around `innermost`."""
    return bytes([ARRAY_1]) * levels + innermost


def with_top_level_entry(base: bytes, key: str, value: bytes) -> bytes:
    """`base`, a canonical map, with one more entry `key: value` in canonical
    order.  Every existing entry keeps its own bytes, and `value` is spliced
    raw, so it may be deeper than any parser here would build."""
    import cbor2

    entries, _ = _scan_map_entries(base, 0)
    pairs = [(cbor2.loads(base[ks:ke]), base[vs:ve]) for (ks, ke), (vs, ve) in entries]
    return encode_canonical_map_raw(pairs + [(key, value)])


def document_nested_to(base: bytes, depth: int) -> bytes:
    """`base` with `FUTURE_KEY` holding a value that takes it to `depth` levels."""
    return with_top_level_entry(base, FUTURE_KEY, nested_value(depth - 1))


def expected_nesting_seeds() -> dict[str, frozenset[str]]:
    """The committed `nesting__` seed file names per target, spelled from the
    constants, as `nesting_depth_seeds_helpers::all_cases` builds them."""
    limit, past = V1_MAX_NESTING_DEPTH, V1_MAX_NESTING_DEPTH + 1

    def names(*shapes: str) -> frozenset[str]:
        return frozenset(f"{NESTING_SEED_PREFIX}{shape}{SEED_EXTENSION}" for shape in shapes)

    return {
        "record": names(
            f"{limit}_unknown", f"{past}_unknown", f"{past}_known_tags", f"{FAR_PAST_THE_LIMIT}_unknown"
        ),
        "manifest_body": names(f"{limit}_unknown", f"{past}_unknown", f"{FAR_PAST_THE_LIMIT}_unknown"),
    }
```

- [ ] **Step 2: Write Section NDL, checks 1-5 (the failing test).** Create `sections/nesting_depth.py`:

```python
"""Section NDL -- crypto-design §6.2 rule 6: no canonical-CBOR document nests
deeper than 256 (#667).

Before #667 the Rust decoders rejected past 256 (ciborium's recursion limit)
and this verifier did not: a record or manifest nested 257-993 deep was
ACCEPTED here, and past ~995 the recursive scanner raised `RecursionError`,
a harness failure rather than a verdict.  `manifest_body` is token-compared
and replayed in CI, and no corpus input reached either.

Checks, each reporting what it RAN:
  1. BOUNDARY, per CBOR decoder: depth 256 is not refused for depth (the
     decoders with an unknown bag accept it); depth 257 raises NestingTooDeep.
  2. A VERDICT AT EVERY DEPTH: 257, 1,000 and 10,000 each raise NestingTooDeep,
     never `RecursionError` or an untokened exception.
  3. TAGS ARE LEVELS: a tag at level 257 is NestingTooDeep, not rule 4; the
     same tag at level 256 is rule 4 (the control).
  4. DEPTH OUTRANKS A SHALLOW TAG, and the depth pass is content-blind.  A tag
     earlier in byte order is only REMEMBERED by both mechanisms, so depth
     wins on the record (walk) and the manifest (pass).  Invalid UTF-8 earlier
     in byte order is a well-formedness fault the record WALK raises at once,
     in byte order, exactly as its Rust twin does, so that case runs on the
     manifest's content-blind pass only, which must still report the depth.
     The control for the pass's silence: a truncated body with no depth
     problem makes `reject_excessive_nesting` return, and the decoder reports
     what it always did.
  5. CENSUS, both ways, default-deny: every top-level `py_decode_*` under
     `codec/` is either a CBOR-document decoder in `_DECODERS` or named in
     `_NOT_CBOR_DOCUMENTS` with its reason.  A new decoder nobody classified
     fails -- "has no check to find" is its own search (#669).

LIMITS.  The census reads top-level `def py_decode_*` names in `codec/*.py`
and nothing else: a decoder under another name, or one nested in a class, is
invisible to it.  The depth pass protects the decoders that call it; a
`wire/` inspector enforces no acceptance set and is out of scope, as Section
VT's check 3 already rules.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from conformance_lib import fixtures
from conformance_lib.codec.card import py_decode_contact_card
from conformance_lib.codec.cbor_faults import NestingTooDeep, V1_MAX_NESTING_DEPTH
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.record import py_decode_record
from conformance_lib.codec.scanner import NonCanonicalItem
from conformance_lib.codec.trash_entry import py_decode_trash_entry
from conformance_lib.codec.well_formed import reject_excessive_nesting
from conformance_lib.sections.nesting_depth_bodies import (
    ARRAY_2, INVALID_UTF8, TAG_1, TEXT_1, UINT_0, FUTURE_KEY,
    document_nested_to, nested_value, with_top_level_entry,
)

_CODEC_DIR = Path(__file__).resolve().parent.parent / "codec"
# The census must see at least this many decoders, or it scanned the wrong
# directory and would pass having read nothing (#669's MIN_SCANNED_CODEC_MODULES lesson).
_MIN_DISCOVERED_DECODERS = 8
_DEEP_DEPTHS = (V1_MAX_NESTING_DEPTH + 1, 1_000, 10_000)
# The trash-entry base Section VT's check 2b uses: every key valid.
_TRASH_BASE = {
    "block_uuid": bytes(16),
    "tombstoned_at_ms": 5,
    "tombstoned_by": bytes(16),
    "fingerprint": bytes(32),
    "purged_at_ms": 7,
}


@dataclass(frozen=True)
class _Decoder:
    decode: Callable[[bytes], object]
    base: Callable[[], bytes]
    # True when the schema keeps an unknown key, so a depth-256 body is ACCEPTED;
    # False when it rejects one for its schema (the contact card).
    keeps_unknown_keys: bool


def _seed(target: str, name: str) -> Callable[[], bytes]:
    return lambda: (fixtures.fuzz_seed_dir(target) / name).read_bytes()


def _trash_base() -> bytes:
    import cbor2

    return cbor2.dumps(_TRASH_BASE, canonical=True)


_DECODERS: tuple[_Decoder, ...] = (
    _Decoder(py_decode_record, _seed("record", "login.cbor"), True),
    _Decoder(py_decode_manifest, _seed("manifest_body", "uniq__control__all_distinct.bin"), True),
    _Decoder(py_decode_contact_card, _seed("contact_card", "with_sigs.cbor"), False),
    _Decoder(py_decode_trash_entry, _trash_base, True),
)
_NOT_CBOR_DOCUMENTS: dict[str, str] = {
    "py_decode_bundle_file": "a binary envelope read by offset",
    "py_decode_block_file": "a binary envelope read by offset",
    "py_decode_manifest_file": "a binary envelope read by offset",
    "py_decode_vault_toml": "TOML, not CBOR",
}


def _outcome(decode: Callable[[bytes], object], body: bytes) -> str:
    """'accept', 'too_deep', 'rule4', or the exception class name."""
    try:
        decode(body)
    except NestingTooDeep:
        return "too_deep"
    except NonCanonicalItem as exc:
        return "rule4" if exc.rule == 4 else type(exc).__name__
    except Exception as exc:  # noqa: BLE001 -- the class name IS the finding
        return type(exc).__name__
    return "accept"


def _boundary_issues() -> tuple[list[str], int]:
    issues = []
    for d in _DECODERS:
        name = d.decode.__name__
        at_limit = _outcome(d.decode, document_nested_to(d.base(), V1_MAX_NESTING_DEPTH))
        if at_limit == "too_deep" or (d.keeps_unknown_keys and at_limit != "accept"):
            issues.append(f"{name} at depth {V1_MAX_NESTING_DEPTH}: {at_limit}; rule 6 allows exactly this depth")
        past = _outcome(d.decode, document_nested_to(d.base(), V1_MAX_NESTING_DEPTH + 1))
        if past != "too_deep":
            issues.append(f"{name} at depth {V1_MAX_NESTING_DEPTH + 1}: {past}, expected NestingTooDeep")
    return issues, 2 * len(_DECODERS)


def _every_depth_issues() -> tuple[list[str], int]:
    issues = []
    for d in _DECODERS:
        for depth in _DEEP_DEPTHS:
            got = _outcome(d.decode, document_nested_to(d.base(), depth))
            if got != "too_deep":
                issues.append(f"{d.decode.__name__} at depth {depth}: {got}, expected NestingTooDeep")
    return issues, len(_DECODERS) * len(_DEEP_DEPTHS)


def _tag_level_issues() -> tuple[list[str], int]:
    """A tag as the last level: 257 is depth, 256 is rule 4.  Run on the two
    decoders with different mechanisms: the record walk and the manifest pass."""
    issues = []
    for d in _DECODERS[:2]:
        for level, want in ((V1_MAX_NESTING_DEPTH + 1, "too_deep"), (V1_MAX_NESTING_DEPTH, "rule4")):
            # Root map is level 1, `level - 2` arrays, then the tag at `level`.
            value = nested_value(level - 2, innermost=bytes([TAG_1, UINT_0]))
            got = _outcome(d.decode, with_top_level_entry(d.base(), FUTURE_KEY, value))
            if got != want:
                issues.append(f"{d.decode.__name__}: a tag at level {level} gave {got}, expected {want}")
    return issues, 4


def _precedence_issues() -> tuple[list[str], int]:
    issues = []
    # A two-item array whose SECOND item is the chain: the first item sits
    # earlier in byte order, and the chain takes the document past the limit.
    deep = nested_value(V1_MAX_NESTING_DEPTH)
    record, manifest = _DECODERS[0], _DECODERS[1]
    # (decoder, label, the shallow first item): a tag is only remembered, by
    # the walk AND the pass; invalid UTF-8 is raised at once by the record walk
    # (in byte order, as its Rust twin does), so it runs on the pass only.
    cases = (
        (record, "a tag", bytes([ARRAY_2, TAG_1, UINT_0])),
        (manifest, "a tag", bytes([ARRAY_2, TAG_1, UINT_0])),
        (manifest, "invalid utf-8", bytes([ARRAY_2, TEXT_1, INVALID_UTF8])),
    )
    for d, label, prefix in cases:
        got = _outcome(d.decode, with_top_level_entry(d.base(), FUTURE_KEY, prefix + deep))
        if got != "too_deep":
            issues.append(f"{d.decode.__name__}: {label} before excess depth gave {got}, expected NestingTooDeep")
    truncated = manifest.base()[:-1]
    try:
        reject_excessive_nesting(truncated)
    except Exception as exc:  # noqa: BLE001 -- any raise breaks the pass's silence
        issues.append(f"reject_excessive_nesting raised {type(exc).__name__} on a truncated body with no depth fault")
    got = _outcome(manifest.decode, truncated)
    if got in ("too_deep", "accept"):
        issues.append(f"py_decode_manifest on a truncated body gave {got}; the decoder must report the truncation")
    return issues, len(cases) + 2


def _discovered_decoders() -> set[str]:
    names = set()
    for path in sorted(_CODEC_DIR.glob("*.py")):
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("py_decode_"):
                names.add(node.name)
    return names


def _census_issues() -> tuple[list[str], int]:
    found = _discovered_decoders()
    if len(found) < _MIN_DISCOVERED_DECODERS:
        return [f"census found {len(found)} decoders under {_CODEC_DIR}, floor is {_MIN_DISCOVERED_DECODERS}"], 0
    classified = {d.decode.__name__ for d in _DECODERS} | set(_NOT_CBOR_DOCUMENTS)
    issues = [f"codec decoder {n} is unclassified: add it to _DECODERS or _NOT_CBOR_DOCUMENTS" for n in sorted(found - classified)]
    issues += [f"classified decoder {n} no longer exists under codec/" for n in sorted(classified - found)]
    return issues, len(found)


def section_nesting_depth() -> tuple[bool, list[str]]:
    boundary, n1 = _boundary_issues()
    every, n2 = _every_depth_issues()
    tags, n3 = _tag_level_issues()
    order, n4 = _precedence_issues()
    census, n5 = _census_issues()
    issues = boundary + every + tags + order + census
    lines = [
        f"PASS 1: {n1 - len(boundary)}/{n1} boundary cases across {len(_DECODERS)} CBOR decoders",
        f"PASS 2: {n2 - len(every)}/{n2} deep bodies refused with a verdict (depths {', '.join(map(str, _DEEP_DEPTHS))})",
        f"PASS 3: {n3 - len(tags)}/{n3} tag-level cases",
        f"PASS 4: {n4 - len(order)}/{n4} precedence and pass-silence cases",
        f"PASS 5: {n5} codec decoders censused, {len(census)} unclassified or missing",
    ]
    lines.extend(f"  ISSUE: {issue}" for issue in issues)
    return (not issues, lines)
```

- [ ] **Step 3: Register it.** In `sections/registry.py`, import `from conformance_lib.sections.nesting_depth import section_nesting_depth` and add, immediately before the RDO row:

```python
    Section("NDL", "CBOR nesting depth: the v1 limit of 256, in every CBOR decoder",
            " (crypto-design §6.2 rule 6, #667)", section_nesting_depth),
```

- [ ] **Step 4: Run it and watch it fail.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/conformance.py 2>&1 | grep -A25 "Section NDL"`
Expected: `FAIL: CBOR nesting depth: the v1 limit of 256, in every CBOR decoder`, with ISSUE lines including:
- "py_decode_manifest at depth 257: accept, expected NestingTooDeep";
- "py_decode_manifest at depth 10000: RecursionError";
- a 257 row for `py_decode_contact_card` (a schema `ValueError`: unknown field);
- a 257 row for `py_decode_trash_entry` (`accept`: it keeps unknown keys);
- the manifest's two check-4 cases.

`py_decode_record`'s rows pass (Task 4's walk). PASS 5 reports 8 decoders and 0 unclassified.

- [ ] **Step 5: Call the pass first in the three decoders.**
  - `codec/manifest_decode.py`: add `from conformance_lib.codec.well_formed import reject_excessive_nesting` to the imports; in `py_decode_manifest`, immediately after `import cbor2` and before the `# §6.2 rule 4 over the WHOLE body` comment, insert:

```python
    # crypto-design §6.2 rule 6 FIRST (#667): `decode_manifest`'s ciborium parse
    # enforces the same limit before it interprets anything, and vault-format
    # §4.2 lists depth among the well-formedness preconditions, so it outranks
    # rule 4.  It must also run before `reject_floats_and_tags` below, which
    # recurses and would otherwise raise RecursionError on a deep body.
    reject_excessive_nesting(data)
```

  - `codec/card.py`: add the same import; in `py_decode_contact_card`, immediately after `import cbor2`, insert:

```python
    # crypto-design §6.2 rule 6 before cbor2 parses anything (#667).
    reject_excessive_nesting(data)
```

  - `codec/trash_entry.py`: the same import and the same two lines, immediately after `import cbor2` in `py_decode_trash_entry`.

- [ ] **Step 6: Run the verifier.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/conformance.py 2>&1 | grep -E "^FAIL|Section NDL|PASS [1-5]: .*(boundary|deep bodies|tag-level|precedence|censused)|REG"; echo "exit ${pipestatus[1]}"`
Expected: no `FAIL:`. NDL reads `8/8`, `12/12`, `4/4`, `5/5`, `8 codec decoders censused, 0 unclassified`. REG reads `35/35`. Exit 0.

- [ ] **Step 7: Confirm no other manifest token moved.** Run the replay in CI shape. It replays every committed `manifest_body` seed through the new first statement.

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay 2>&1 | grep -E "test result|manifest_body:|contact_card:|disagree|harness"`
Expected: `46 passed`; finish lines `manifest_body: 45 of 45` and `contact_card: 4 of 4`; no disagreement or harness-failure line.

- [ ] **Step 8: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
git add core/tests/python/conformance_lib/sections/nesting_depth.py core/tests/python/conformance_lib/sections/nesting_depth_bodies.py \
  core/tests/python/conformance_lib/sections/registry.py core/tests/python/conformance_lib/codec/manifest_decode.py \
  core/tests/python/conformance_lib/codec/card.py core/tests/python/conformance_lib/codec/trash_entry.py
git commit -m "$(cat <<'EOF'
Every conformance_lib CBOR decoder refuses nesting past 256 before it recurses (#667)

py_decode_manifest, py_decode_contact_card and py_decode_trash_entry now open
with reject_excessive_nesting; py_decode_record already opens with walk_body.
The manifest accepted depth 257-993 where decode_manifest rejects from 257,
and raised RecursionError from ~995 -- on a token-compared, CI-replayed target.

Section NDL pins the boundary per decoder, a verdict at 257 / 1,000 / 10,000,
tags as levels, depth over an earlier tag or bad UTF-8, the pass's silence on
a non-depth fault, and a two-way census of every codec/ py_decode_* function.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Committed nesting seeds, the ciborium path pin, and both censuses

**Files:**
- Create: `core/tests/nesting_depth_seeds_helpers/prefix.rs`
- Create: `core/tests/nesting_depth_seeds_helpers/mod.rs`
- Create: `core/tests/nesting_depth_seeds.rs`
- Modify: `core/tests/rule_token_seeds.rs` (census exclusion)
- Modify: `core/tests/python/conformance_lib/sections/rule_token_seeds.py` (`_labelled_seeds` exclusion)
- Modify: `core/tests/python/conformance_lib/sections/nesting_depth.py` (check 6)
- Modify: `core/tests/python/conformance_lib/sections/rule_token_vocabulary.py` (`_CORPUS_TOKENS` += `malformed_cbor`)
- Modify: `core/tests/differential_replay_helpers/targets.rs` (`record` 40 → 44, `manifest_body` 45 → 48)
- Create (generated): 7 files `core/fuzz/seeds/{record,manifest_body}/nesting__*.bin`

**Interfaces:**
- Consumes: `secretary_core::cbor::{CborErrorKind, CborFault, V1_MAX_NESTING_DEPTH}`; `vault::record::{decode, encode, RecordError}`; `vault::manifest::{decode_manifest, encode_manifest, ManifestError}`; `vault::block::{decode_plaintext, BlockError}`; `identity::card::{ContactCard, CardError}`; `unlock::bundle::{IdentityBundle, BundleError}`; Python `expected_nesting_seeds()`, `NESTING_SEED_PREFIX` (Task 5).
- Produces: `SEED_PREFIX: &str = "nesting__"` (Rust, shared file); seed files named `nesting__<depth>_<unknown|known_tags>.bin`.

- [ ] **Step 1: Exclude the prefix from both existing censuses FIRST**, so that generating the seeds cannot turn them red.
  - Create `core/tests/nesting_depth_seeds_helpers/prefix.rs`:

```rust
//! The file-name prefix `nesting_depth_seeds.rs` owns under
//! `core/fuzz/seeds/{record,manifest_body}/`.
//!
//! Its own file so `rule_token_seeds.rs`, whose census claims every labelled
//! file under `record/`, can exclude exactly this prefix by NAMING it. Both
//! test targets compile this one declaration (the second through `#[path]`),
//! so the two generators cannot drift onto two ideas of who owns a file.

pub const SEED_PREFIX: &str = "nesting__";
```

  - In `core/tests/rule_token_seeds.rs`, add after `mod rule_token_seeds_helpers;`:

```rust
#[path = "nesting_depth_seeds_helpers/prefix.rs"]
mod nesting_depth_seed_prefix;
```

  and change the census filter to:

```rust
            // `nesting__` files belong to `nesting_depth_seeds.rs` (#667).
            .filter(|name| {
                name.contains(LABEL_SEPARATOR)
                    && !name.starts_with(nesting_depth_seed_prefix::SEED_PREFIX)
            })
```

  - In `sections/rule_token_seeds.py`, import `from conformance_lib.sections.nesting_depth_bodies import NESTING_SEED_PREFIX` and change `_labelled_seeds` to:

```python
def _labelled_seeds(target: str) -> list[Path]:
    directory = fixtures.fuzz_seed_dir(target)
    # `nesting__` seeds belong to Section NDL and `nesting_depth_seeds.rs` (#667).
    return sorted(
        p for p in directory.iterdir()
        if p.is_file() and LABEL_SEPARATOR in p.name and not p.name.startswith(NESTING_SEED_PREFIX)
    )
```

- [ ] **Step 2: Write the helper module.** Create `core/tests/nesting_depth_seeds_helpers/mod.rs`:

```rust
//! Committed seeds for crypto-design §6.2 rule 6, the v1 nesting limit
//! (#667), and the one table the generator and the label-binding check read.
//!
//! **Why both verdicts.** A limit set too LOW is as wrong as none, so each
//! target commits an ACCEPTING body at exactly the limit beside the rejecting
//! one past it. A body far past the limit makes CI prove the Python reader
//! returns a verdict there, where a recursive reader raised `RecursionError`.
//!
//! **Why a separate generator.** `rule_token_seeds.rs` binds a rule TOKEN and
//! can hold no accepting row; this table binds a VERDICT. Its census is
//! scoped to [`SEED_PREFIX`], which that file excludes by name.
//!
//! **Depth arithmetic.** The base's own root map is level 1, so a value
//! holding `d - 1` one-element arrays around a scalar takes the document to
//! exactly `d` levels; a scalar is not a level.

mod prefix;

use std::path::PathBuf;

use ciborium::Value;
pub use prefix::SEED_PREFIX;
use secretary_core::cbor::{CborErrorKind, CborFault, V1_MAX_NESTING_DEPTH};
use secretary_core::vault::manifest::{decode_manifest, encode_manifest, ManifestError};
use secretary_core::vault::record::{self, RecordError};

pub const SEEDED_TARGETS: &[&str] = &["manifest_body", "record"];
/// How many rows the table holds; a row and its seed deleted together are
/// invisible to the two-way census, so the count is pinned separately.
pub const EXPECTED_CASE_COUNT: usize = 7;
/// Past Python's default recursion limit (~1,000), so a recursive reader
/// would fail there with `RecursionError` instead of returning a verdict.
const FAR_PAST_THE_LIMIT: usize = 2048;
/// A key no v1 document defines, so it lands in a forward-compat bag.
const FUTURE_KEY: &str = "zz_future";
const ARRAY_1: u8 = 0x81;
const UINT_0: u8 = 0x00;
const MAP_SMALL_BASE: u8 = 0xa0;
/// The largest count a one-byte map head can carry.
const SMALL_COUNT_MAX: usize = 23;
const SEED_EXTENSION: &str = "bin";

/// Where the deep value is planted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Under [`FUTURE_KEY`], in the forward-compat bag.
    Unknown,
    /// Under `tags`, a known key whose value would otherwise be a type error.
    KnownTags,
}

impl Placement {
    fn key(self) -> &'static str {
        match self {
            Placement::Unknown => FUTURE_KEY,
            Placement::KnownTags => "tags",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Placement::Unknown => "unknown",
            Placement::KnownTags => "known_tags",
        }
    }
}

/// What both decoders must answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    TooDeep,
}

/// What the Rust decoder answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Observed {
    Accepted,
    /// `RecursionLimit`, with the fault's offset (`Some` only from the byte walk).
    TooDeep { offset: Option<usize> },
    Other(String),
}

pub struct NestingCase {
    pub target: &'static str,
    pub depth: usize,
    pub placement: Placement,
}

impl NestingCase {
    /// Derived, never declared, so a row cannot claim a verdict its depth
    /// contradicts.
    pub fn verdict(&self) -> Verdict {
        if self.depth > V1_MAX_NESTING_DEPTH {
            Verdict::TooDeep
        } else {
            Verdict::Accept
        }
    }

    pub fn file_name(&self) -> String {
        format!(
            "{SEED_PREFIX}{}_{}.{SEED_EXTENSION}",
            self.depth,
            self.placement.label()
        )
    }

    pub fn path(&self) -> PathBuf {
        seed_dir(self.target).join(self.file_name())
    }

    pub fn bytes(&self) -> Vec<u8> {
        with_top_level_entry(
            &base(self.target),
            self.placement.key(),
            nested_value(self.depth - 1),
        )
    }
}

pub fn all_cases() -> Vec<NestingCase> {
    use Placement::{KnownTags, Unknown};
    let row = |target, depth, placement| NestingCase {
        target,
        depth,
        placement,
    };
    vec![
        row("record", V1_MAX_NESTING_DEPTH, Unknown),
        row("record", V1_MAX_NESTING_DEPTH + 1, Unknown),
        row("record", V1_MAX_NESTING_DEPTH + 1, KnownTags),
        row("record", FAR_PAST_THE_LIMIT, Unknown),
        row("manifest_body", V1_MAX_NESTING_DEPTH, Unknown),
        row("manifest_body", V1_MAX_NESTING_DEPTH + 1, Unknown),
        row("manifest_body", FAR_PAST_THE_LIMIT, Unknown),
    ]
}

/// `core/fuzz/seeds/<target>/`.
pub fn seed_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target)
}

/// The committed ACCEPTING document each target's seeds extend.
pub fn base(target: &str) -> Vec<u8> {
    let name = match target {
        "record" => "login.cbor",
        "manifest_body" => "uniq__control__all_distinct.bin",
        other => panic!("no seed base for target {other}"),
    };
    let path = seed_dir(target).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read seed base {}: {e}", path.display()))
}

/// `levels` one-element arrays around a `0`.
fn nested_value(levels: usize) -> Vec<u8> {
    let mut value = vec![ARRAY_1; levels];
    value.push(UINT_0);
    value
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("a seed value encodes");
    out
}

/// The `(key bytes, value bytes)` entries of the definite map `bytes`.
pub fn entries(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Value::Map(pairs) = ciborium::de::from_reader(bytes).expect("a seed base parses") else {
        panic!("a seed base is not a map")
    };
    pairs.iter().map(|(k, v)| (cbor(k), cbor(v))).collect()
}

/// A definite map of `entries`, in the order given.
pub fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    assert!(entries.len() <= SMALL_COUNT_MAX, "seed maps stay in the one-byte head form");
    let count = u8::try_from(entries.len()).expect("a small count fits a byte");
    let mut out = vec![MAP_SMALL_BASE | count];
    for (k, v) in entries {
        out.extend(k);
        out.extend(v);
    }
    out
}

/// `base` with `key: value` inserted where RFC 8949's length-first canonical
/// order puts it. `value` is spliced raw, so it can be deeper than any parser
/// here would build.
pub fn with_top_level_entry(base: &[u8], key: &str, value: Vec<u8>) -> Vec<u8> {
    let key = cbor(&Value::Text(key.to_owned()));
    let mut out = entries(base);
    let at = out
        .iter()
        .position(|(k, _)| (k.len(), k.as_slice()) > (key.len(), key.as_slice()))
        .unwrap_or(out.len());
    out.insert(at, (key, value));
    map(&out)
}

/// The decode → re-encode pipeline the differential replay runs for `target`.
pub fn observe(target: &str, bytes: &[u8]) -> Observed {
    let too_deep = |fault: CborFault| match fault.kind {
        CborErrorKind::RecursionLimit => Observed::TooDeep {
            offset: fault.offset,
        },
        _ => Observed::Other(format!("{fault:?}")),
    };
    match target {
        "record" => match record::decode(bytes).and_then(|r| record::encode(&r)) {
            Ok(_) => Observed::Accepted,
            Err(RecordError::CborDecode(fault)) => too_deep(fault),
            Err(e) => Observed::Other(format!("{e:?}")),
        },
        "manifest_body" => match decode_manifest(bytes).and_then(|m| encode_manifest(&m)) {
            Ok(_) => Observed::Accepted,
            Err(ManifestError::CborDecode(fault)) => too_deep(fault),
            Err(e) => Observed::Other(format!("{e:?}")),
        },
        other => panic!("no Rust decoder for target {other}"),
    }
}
```

- [ ] **Step 3: Write the test target.** Create `core/tests/nesting_depth_seeds.rs`:

```rust
//! Committed seeds for crypto-design §6.2 rule 6 (#667): the generator, the
//! check that binds every committed seed to its row, and the pin that keeps
//! `ciborium`'s recursion limit equal to the spec's on every decode path that
//! still relies on it. See `nesting_depth_seeds_helpers` for the table.
//!
//! The Python half of the binding is conformance Section NDL, check 6.

mod nesting_depth_seeds_helpers;

use std::collections::{BTreeMap, BTreeSet};

use nesting_depth_seeds_helpers::{
    all_cases, base, entries, map, observe, seed_dir, NestingCase, Observed, Placement, Verdict,
    EXPECTED_CASE_COUNT, SEEDED_TARGETS, SEED_PREFIX,
};
use secretary_core::cbor::{CborErrorKind, CborFault, V1_MAX_NESTING_DEPTH};

/// How to regenerate, quoted in every failure that needs it.
const REGENERATE: &str = "cargo test --release --locked -p secretary-core --test \
                          nesting_depth_seeds -- --ignored generate_nesting_depth_seeds";
/// Major 5 with one entry, the one-byte text `"k"`: the head of the document
/// the path pin nests below.
const ONE_ENTRY_MAP_AND_KEY: [u8; 3] = [0xa1, 0x61, b'k'];
const ARRAY_1: u8 = 0x81;
const UINT_0: u8 = 0x00;

fn assert_rust_answers_its_verdict(case: &NestingCase, bytes: &[u8]) {
    let got = observe(case.target, bytes);
    let ok = match (case.verdict(), &got) {
        (Verdict::Accept, Observed::Accepted) => true,
        // On the record path the byte walk must answer (it reports an offset;
        // ciborium does not), so the Rust walk's enforcement is pinned here too.
        (Verdict::TooDeep, Observed::TooDeep { offset }) => {
            case.target != "record" || offset.is_some()
        }
        _ => false,
    };
    assert!(
        ok,
        "seed {} for {}: Rust answered {got:?}, the row expects {:?}",
        case.file_name(),
        case.target,
        case.verdict()
    );
}

fn assert_each_target_plants_distinct_bytes<'a>(
    built: impl Iterator<Item = (&'a NestingCase, &'a [u8])>,
) {
    let mut planted: BTreeMap<(&str, &[u8]), String> = BTreeMap::new();
    for (case, bytes) in built {
        if let Some(other) = planted.insert((case.target, bytes), case.file_name()) {
            panic!(
                "target {}: seeds {other} and {} plant identical bytes",
                case.target,
                case.file_name()
            );
        }
    }
}

#[test]
fn the_case_table_holds_every_expected_row() {
    assert_eq!(all_cases().len(), EXPECTED_CASE_COUNT);
}

/// Every target commits the boundary PAIR (accept at the limit, refuse one
/// past it), and a known-key row only past the limit, where it cannot be
/// answered by the type check.
#[test]
fn every_target_carries_the_boundary_pair() {
    let cases = all_cases();
    for target in SEEDED_TARGETS {
        for depth in [V1_MAX_NESTING_DEPTH, V1_MAX_NESTING_DEPTH + 1] {
            assert!(
                cases.iter().any(|c| c.target == *target
                    && c.depth == depth
                    && c.placement == Placement::Unknown),
                "{target} has no unknown-key row at depth {depth}"
            );
        }
    }
    for case in cases.iter().filter(|c| c.placement == Placement::KnownTags) {
        assert_eq!(case.verdict(), Verdict::TooDeep, "{}", case.file_name());
    }
}

#[test]
fn reassembling_each_base_is_byte_identical() {
    for target in SEEDED_TARGETS {
        let bytes = base(target);
        assert_eq!(map(&entries(&bytes)), bytes, "{target}: the entry split must round-trip");
    }
}

#[test]
fn every_seed_label_is_unique() {
    let cases = all_cases();
    let labels: BTreeSet<(&str, String)> =
        cases.iter().map(|c| (c.target, c.file_name())).collect();
    assert_eq!(labels.len(), cases.len(), "two rows share a target and file name");
}

#[test]
fn nesting_depth_seeds_are_committed_and_label_bound() {
    let cases = all_cases();
    let built: Vec<Vec<u8>> = cases.iter().map(NestingCase::bytes).collect();
    assert_each_target_plants_distinct_bytes(cases.iter().zip(built.iter().map(Vec::as_slice)));
    for (case, want) in cases.iter().zip(&built) {
        assert!(SEEDED_TARGETS.contains(&case.target), "{} names an unowned target", case.file_name());
        assert_rust_answers_its_verdict(case, want);
        let committed = std::fs::read(case.path()).unwrap_or_else(|e| {
            panic!("seed {} is not committed ({e}); run `{REGENERATE}`", case.path().display())
        });
        assert!(
            committed == *want,
            "seed {} differs from what its row plants: regenerate deliberately with `{REGENERATE}`",
            case.path().display()
        );
    }
    for target in SEEDED_TARGETS {
        let on_disk: BTreeSet<String> = std::fs::read_dir(seed_dir(target))
            .unwrap_or_else(|e| panic!("list seeds for {target}: {e}"))
            .map(|entry| entry.expect("a directory entry").file_name().into_string().expect("UTF-8"))
            .filter(|name| name.starts_with(SEED_PREFIX))
            .collect();
        let declared: BTreeSet<String> = cases
            .iter()
            .filter(|c| c.target == *target)
            .map(NestingCase::file_name)
            .collect();
        assert_eq!(on_disk, declared, "target {target}: committed `{SEED_PREFIX}` seeds and the table disagree");
    }
}

/// Writes every seed, after every row has been built and asserted (#614).
#[test]
#[ignore]
fn generate_nesting_depth_seeds() {
    let cases = all_cases();
    let built: Vec<Vec<u8>> = cases.iter().map(NestingCase::bytes).collect();
    assert_each_target_plants_distinct_bytes(cases.iter().zip(built.iter().map(Vec::as_slice)));
    for (case, bytes) in cases.iter().zip(&built) {
        assert_rust_answers_its_verdict(case, bytes);
    }
    for (case, bytes) in cases.iter().zip(built) {
        let path = case.path();
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }
}

/// A `depth`-level document: a one-entry map whose value holds `depth - 1`
/// one-element arrays. It need not be a valid document of any kind.
fn nested_document(depth: usize) -> Vec<u8> {
    let mut body = ONE_ENTRY_MAP_AND_KEY.to_vec();
    body.extend(std::iter::repeat_n(ARRAY_1, depth - 1));
    body.push(UINT_0);
    body
}

/// `ciborium` 0.2.2's recursion limit IS crypto-design §6.2 rule 6 on every
/// path that does not run the byte walk. An upgrade that moved it would move
/// the spec's limit silently on four decode paths; this is what reds.
///
/// A depth-256 body must fail for any reason other than `RecursionLimit` (it
/// is not a valid document), and a depth-257 body must fail with it.
#[test]
fn ciborium_enforces_exactly_the_v1_limit_on_every_decode_path() {
    use secretary_core::identity::card::{CardError, ContactCard};
    use secretary_core::unlock::bundle::{BundleError, IdentityBundle};
    use secretary_core::vault::block::{decode_plaintext, BlockError};
    use secretary_core::vault::manifest::{decode_manifest, ManifestError};
    use secretary_core::vault::record::{decode, RecordError};

    type FaultOf = fn(&[u8]) -> Option<CborFault>;
    let paths: [(&str, FaultOf); 5] = [
        ("decode_manifest", |b| match decode_manifest(b) {
            Err(ManifestError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        ("block::decode_plaintext", |b| match decode_plaintext(b) {
            Err(BlockError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        ("ContactCard::from_canonical_cbor", |b| match ContactCard::from_canonical_cbor(b) {
            Err(CardError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        ("IdentityBundle::from_canonical_cbor", |b| {
            match IdentityBundle::from_canonical_cbor(b) {
                Err(BundleError::CborFault(f)) => Some(f),
                _ => None,
            }
        }),
        ("record::decode", |b| match decode(b) {
            Err(RecordError::CborDecode(f)) => Some(f),
            _ => None,
        }),
    ];
    let limit_kind = Some(CborErrorKind::RecursionLimit);
    for (name, fault_of) in paths {
        assert_ne!(
            fault_of(&nested_document(V1_MAX_NESTING_DEPTH)).map(|f| f.kind),
            limit_kind,
            "{name} refuses depth {V1_MAX_NESTING_DEPTH}, which rule 6 allows"
        );
        assert_eq!(
            fault_of(&nested_document(V1_MAX_NESTING_DEPTH + 1)).map(|f| f.kind),
            limit_kind,
            "{name} does not refuse depth {} with RecursionLimit",
            V1_MAX_NESTING_DEPTH + 1
        );
    }
}
```

(If `std::iter::repeat_n` is flagged by the pinned toolchain, use `std::iter::repeat(ARRAY_1).take(depth - 1)`. The existing `well_formed/tests.rs` already uses `repeat_n`, so it should compile.)

- [ ] **Step 4: Run it and watch it fail.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --test nesting_depth_seeds 2>&1 | grep -E "^test |test result"`
Expected: `nesting_depth_seeds_are_committed_and_label_bound` FAILS with "seed …nesting__256_unknown.bin is not committed". The path pin and the other four tests PASS; the path pin passing is the measurement that ciborium's limit equals the constant today.

- [ ] **Step 5: Generate the seeds, then re-run this target and the rule-token target.**

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --test nesting_depth_seeds -- --ignored generate_nesting_depth_seeds && cargo test --release --locked -p secretary-core --test nesting_depth_seeds --test rule_token_seeds --no-fail-fast 2>&1 | grep -E "test result" && ls core/fuzz/seeds/record/nesting__* core/fuzz/seeds/manifest_body/nesting__*`
Expected: both targets `ok`. Seven files: four under `record/`, three under `manifest_body/`.

- [ ] **Step 6: Add check 6 to Section NDL.** In `sections/nesting_depth.py`, extend the bodies import with `NESTING_SEED_PREFIX, expected_nesting_seeds`, add `from conformance_lib.diff_replay import replay_bytes`, update the docstring's check list with:

```
  6. SEED BINDING: the committed `nesting__` seeds, two-way against
     `expected_nesting_seeds()`, each replayed with the verdict its depth
     states -- accept at or under the limit, `NestingTooDeep` past it.
```

and add the check and wire it into `section_nesting_depth`:

```python
_DEPTH_IN_NAME = re.compile(rf"^{NESTING_SEED_PREFIX}(?P<depth>\d+)_")


def _seed_issues() -> tuple[list[str], int]:
    issues, checked = [], 0
    for target, want in expected_nesting_seeds().items():
        directory = fixtures.fuzz_seed_dir(target)
        on_disk = {p.name for p in directory.iterdir() if p.name.startswith(NESTING_SEED_PREFIX)}
        issues += [f"{target}: committed seed {n} is not expected" for n in sorted(on_disk - want)]
        issues += [f"{target}: expected seed {n} is not committed" for n in sorted(want - on_disk)]
        for name in sorted(on_disk & want):
            checked += 1
            depth = int(_DEPTH_IN_NAME.match(name)["depth"])
            verdict = replay_bytes(target, (directory / name).read_bytes()).verdict
            if depth <= V1_MAX_NESTING_DEPTH:
                if verdict.get("status") != "accept":
                    issues.append(f"{target}/{name}: expected accept, got {verdict}")
            elif (verdict.get("status"), verdict.get("error_class"), verdict.get("rule")) != (
                "reject", "NestingTooDeep", "malformed_cbor"
            ):
                issues.append(f"{target}/{name}: expected NestingTooDeep (malformed_cbor), got {verdict}")
    return issues, checked
```

(add `import re` at the top), and in `section_nesting_depth`:

```python
    seeds, n6 = _seed_issues()
    issues = boundary + every + tags + order + census + seeds
```

with the PASS line:

```python
        f"PASS 6: {n6 - len(seeds)}/{n6} committed nesting seeds replay with the verdict their depth states",
```

- [ ] **Step 7: Raise the floors and the corpus token set.**
  - `core/tests/differential_replay_helpers/targets.rs`: `("record", 40)` → `("record", 44)`, `("manifest_body", 45)` → `("manifest_body", 48)`. If the doc comment above `MIN_CORPUS_INPUTS` states a total or a per-target figure, update it to match.
  - `sections/rule_token_vocabulary.py`: add `"malformed_cbor",` to `_CORPUS_TOKENS` in sorted position. The manifest nesting seeds are the first committed manifest bodies to reach it.

- [ ] **Step 8: Run both verifiers.** (#679's lesson: after changing a corpus, run BOTH.)

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && uv run core/tests/python/conformance.py 2>&1 | grep -E "^FAIL|PASS 6|distinct tokens|labelled seeds|REG"; echo "exit ${pipestatus[1]}"`
Expected: no `FAIL:`; NDL `PASS 6: 7/7`; RTV reports `9 distinct tokens`; RTS `record: 37 labelled seeds`; exit 0.

Run: `cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults && cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay 2>&1 | grep -E "test result|record:|manifest_body:|disagree|harness"`
Expected: `46 passed`; `record: 44 of 44 input(s) compared, 44 committed`; `manifest_body: 48 of 48 input(s) compared, 48 committed`; no disagreement or harness line.

- [ ] **Step 9: Commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
git add core/tests/nesting_depth_seeds.rs core/tests/nesting_depth_seeds_helpers core/tests/rule_token_seeds.rs \
  core/fuzz/seeds/record/nesting__*.bin core/fuzz/seeds/manifest_body/nesting__*.bin \
  core/tests/differential_replay_helpers/targets.rs core/tests/python/conformance_lib/sections/nesting_depth.py \
  core/tests/python/conformance_lib/sections/rule_token_seeds.py core/tests/python/conformance_lib/sections/rule_token_vocabulary.py
git commit -m "$(cat <<'EOF'
Commit the nesting boundary as seeds, and pin ciborium's limit to rule 6 (#667)

nesting_depth_seeds.rs owns nesting__* under record/ and manifest_body/: an
ACCEPTING body at exactly 256 beside the refused 257 (a limit set too low is as
wrong as none), a 257 under a known key, and 2,048 so CI proves Python returns
a verdict there. Both existing censuses exclude the prefix by naming one shared
constant. A second test pins ciborium 0.2.2's recursion limit to
V1_MAX_NESTING_DEPTH on decode_manifest, block plaintext, card, bundle and
record. Committed replay inputs 124 -> 131.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Measure — full corpus, reported-variant drift, mutation evidence, full gate set

**Files:** none in the tree. Everything is written to `$SCRATCH` (`/private/tmp/claude-501/-Users-hherb-src-secretary/b639dea2-bb03-407d-8b6f-31854b2891c2/scratchpad`).

- [ ] **Step 1: Full-corpus replay with the runtime corpus.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay -- differential_replay_full_corpus 2>&1 | grep -E "\[differential_replay\].*compared|test result|disagree|harness"
rm core/fuzz/corpus && git status --short   # MUST be empty
```

Expected: every target `N of N input(s) compared`, no disagreement. Record all seven finish lines verbatim for the handoff.

- [ ] **Step 2: Measure what Task 3 moved on the record path.** Build the scratch probe (`$SCRATCH/depthprobe`) twice, against the base and against the branch, and diff its output over every `record` input:

```bash
S=/private/tmp/claude-501/-Users-hherb-src-secretary/b639dea2-bb03-407d-8b6f-31854b2891c2/scratchpad
mkdir -p $S/base && git -C /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults archive db6b1f5b core | tar -x -C $S/base
for side in base branch; do
  mkdir -p $S/variants-$side/src && cp $S/depthprobe/rust-toolchain.toml $S/depthprobe/Cargo.lock $S/variants-$side/
  core=$([ $side = base ] && echo $S/base/core || echo /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults/core)
  printf '[package]\nname = "variants"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[dependencies]\nsecretary-core = { path = "%s" }\n\n[workspace]\n' "$core" > $S/variants-$side/Cargo.toml
  cat > $S/variants-$side/src/main.rs <<'EOF'
//! Throwaway: print record::decode's Debug verdict per file.
fn main() {
    for dir in std::env::args().skip(1) {
        let mut paths: Vec<_> = std::fs::read_dir(&dir).expect("dir").map(|e| e.expect("entry").path()).collect();
        paths.sort();
        for p in paths {
            let bytes = std::fs::read(&p).expect("read");
            match secretary_core::vault::record::decode(&bytes) {
                Ok(_) => println!("{}\tACCEPT", p.display()),
                Err(e) => println!("{}\t{e:?}", p.display()),
            }
        }
    }
}
EOF
  (cd $S/variants-$side && CARGO_TARGET_DIR=$S/variants-$side/target cargo build --release --offline -q)
  $S/variants-$side/target/release/variants /Users/hherb/src/secretary/core/fuzz/corpus/record /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults/core/fuzz/seeds/record > $S/variants-$side.txt
done
wc -l $S/variants-base.txt $S/variants-branch.txt
diff $S/variants-base.txt $S/variants-branch.txt | grep -c '^>' ; diff $S/variants-base.txt $S/variants-branch.txt | head -20
awk -F'\t' '{print $2=="ACCEPT"}' $S/variants-base.txt | sort | uniq -c
awk -F'\t' '{print $2=="ACCEPT"}' $S/variants-branch.txt | sort | uniq -c
```

Expected: the same ACCEPT count on both sides (**0 statuses moved**). The only diff lines are the branch's committed `nesting__257_*` / `nesting__2048_*` seeds, which gain `offset: Some(..)`, and any runtime input carrying depth past 256, which moves from `offset: None` to `Some(..)` or from `TagRejected` to `CborDecode`. Record the counts for the handoff. Note that the base tree has no `nesting__` files, but the branch's seed directory is read on both sides, so those files show up in both outputs.

- [ ] **Step 3: Mutation evidence.** Write `$S/ndl.toml` (never in the tree):

```toml
[[mutation]]
id = "N1"
lang = "rust"
path = "core/src/cbor/mod.rs"
old = "pub const V1_MAX_NESTING_DEPTH: usize = 256;"
new = "pub const V1_MAX_NESTING_DEPTH: usize = 255;"
gate = "cargo test --release --locked -p secretary-core --test nesting_depth_seeds"
expect = "red"
expect_red = ["ciborium_enforces_exactly_the_v1_limit_on_every_decode_path", "nesting_depth_seeds_are_committed_and_label_bound"]
note = "A limit one lower than ciborium's: the path pin and the 256 accept rows red"
probe = { package = "secretary-core" }

[[mutation]]
id = "N2"
lang = "rust"
path = "core/src/cbor/well_formed.rs"
old = "    if stack.len() >= V1_MAX_NESTING_DEPTH {"
new = "    if stack.len() >= V1_MAX_NESTING_DEPTH + 1 {"
gate = "cargo test --release --locked -p secretary-core --lib cbor::well_formed"
expect = "red"
expect_red = ["one_level_past_the_limit_is_malformed_at_that_level", "a_tag_is_a_nesting_level"]
note = "The walk's own check is off by one; ciborium would still reject, so only the walk tests see it"
probe = { package = "secretary-core" }

[[mutation]]
id = "N3"
lang = "python"
path = "core/tests/python/conformance_lib/codec/cbor_faults.py"
old = "V1_MAX_NESTING_DEPTH = 256"
new = "V1_MAX_NESTING_DEPTH = 257"
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["CBOR nesting depth: the v1 limit of 256, in every CBOR decoder", "well-formedness walk, the twin of cbor::well_formed"]
note = "Python's limit one higher: NDL and WF red"
probe = { module = "conformance_lib.codec.cbor_faults", expr = "str(V1_MAX_NESTING_DEPTH)", equals = "257", syspath = "core/tests/python" }

[[mutation]]
id = "N4"
lang = "python"
path = "core/tests/python/conformance_lib/codec/well_formed.py"
old = "            require_room_for_another_level(len(stack), pos)\n            is_map = major == MAJOR_MAP"
new = "            is_map = major == MAJOR_MAP"
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["CBOR nesting depth: the v1 limit of 256, in every CBOR decoder", "well-formedness walk, the twin of cbor::well_formed"]
note = "The shared traversal loses its container check: record (walk) AND manifest (pass) red together -- one machine"
probe = { module = "conformance_lib.codec.well_formed", expr = "str('require_room_for_another_level(len(stack), pos)\\n            is_map' in __import__('inspect').getsource(_walk))", equals = "False", syspath = "core/tests/python" }

[[mutation]]
id = "N5"
lang = "python"
path = "core/tests/python/conformance_lib/codec/manifest_decode.py"
old = "    reject_excessive_nesting(data)\n"
new = "\n"
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "The manifest pass removed: nesting__257_unknown is accepted by Python, refused by Rust -- the CI-visible catch"
probe = { module = "conformance_lib.codec.manifest_decode", expr = "str('reject_excessive_nesting(data)' in __import__('inspect').getsource(py_decode_manifest))", equals = "False", syspath = "core/tests/python" }

[[mutation]]
id = "N6"
lang = "python"
path = "core/tests/python/conformance_lib/codec/record.py"
old = "        if k == \"unknown\" or _is_omitted_default(k, v):"
new = "        if k == \"unknown\":"
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["record optional keys: a default is written by omission", "rule-token seeds are rejected with the rule their file names"]
note = "#670 reverted: RDO and RTS red"
probe = { module = "conformance_lib.codec.record", expr = "str('_is_omitted_default(k, v)' in __import__('inspect').getsource(py_encode_record))", equals = "False", syspath = "core/tests/python" }

[[mutation]]
id = "N7"
lang = "python"
path = "core/tests/python/conformance_lib/codec/record.py"
old = "        if k == \"unknown\" or _is_omitted_default(k, v):"
new = "        if k == \"unknown\":"
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "#670 reverted, seen by the CI replay through the three committed seeds"
probe = { module = "conformance_lib.codec.record", expr = "str('_is_omitted_default(k, v)' in __import__('inspect').getsource(py_encode_record))", equals = "False", syspath = "core/tests/python" }

[[mutation]]
id = "N8"
lang = "python"
path = "core/tests/python/conformance_lib/codec/trash_entry.py"
old = "def py_decode_trash_entry(data: bytes) -> dict:"
new = "def py_decode_unclassified(data: bytes) -> dict:\n    return {}\n\n\ndef py_decode_trash_entry(data: bytes) -> dict:"
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["CBOR nesting depth: the v1 limit of 256, in every CBOR decoder"]
note = "A new codec decoder nobody classified: NDL check 5 reds"
probe = { module = "conformance_lib.codec.trash_entry", expr = "str('py_decode_unclassified' in globals())", equals = "True", syspath = "core/tests/python" }

[[mutation]]
id = "N9"
lang = "python"
path = "core/tests/python/conformance_lib/sections/registry.py"
old = "    Section(\"NDL\", \"CBOR nesting depth: the v1 limit of 256, in every CBOR decoder\",\n            \" (crypto-design §6.2 rule 6, #667)\", section_nesting_depth),\n"
new = ""
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["section registry completeness"]
note = "NDL left out of the table: it would run nowhere, and REG must notice"
probe = { module = "conformance_lib.sections.registry", expr = "str(any(s.id == 'NDL' for s in SECTIONS))", equals = "False", syspath = "core/tests/python" }
```

(If `mutate.py` refuses an empty `new`, use `new = "\n"`.)

Run:

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
uv run scripts/mutate.py --self-test                      # all checks pass
uv run --with cryptography --with pynacl --with "pqcrypto<1" --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py $S/ndl.toml
git status --short                                        # MUST be empty
```

Expected: exit 0, every row `RED_AS_EXPECTED`. If a row reads `NOT_LIVE` or `UNEXPECTED_GREEN`, read its DIAGNOSTIC block and fix the ROW (its `old` string or its probe), not the code. Paste the table into the handoff.

- [ ] **Step 4: The full gate set.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
cargo test --release --locked --workspace 2>&1 | grep -E "test result" | awk '{p+=$4; f+=$6} END {print "passed", p, "failed", f}'
cargo clippy --release --locked --workspace --tests -- -D warnings 2>&1 | tail -1
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings 2>&1 | tail -1
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -1
cargo fmt --all --check && echo FMT-OK
uv run core/tests/python/conformance.py > /dev/null; echo "conformance exit $?"
uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4" 2>&1 | tail -1
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

Expected: 0 failed; clippy, rustdoc and fmt clean; conformance exit 0; pytest all passed; every guard exits 0. Run each guard command SEPARATELY. A zsh loop over them mis-reports (memory: shell invocation traps).

---

### Task 8: Documentation, issues, and the handoff

**Files:**
- Modify: `CLAUDE.md`, `ROADMAP.md`, `README.md` (only if its "Project status" names conformance coverage at this grain)
- Create: `docs/handoffs/2026-09-19-nesting-depth-and-record-defaults-shipped.md`
- Modify: `NEXT_SESSION.md` (symlink retarget)

- [ ] **Step 1: Re-measure every number CLAUDE.md quotes that this slice moved.** Run each and use its output, never a figure from this plan:

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
find core/tests/python/conformance_lib -name '*.py' | wc -l                     # was 75
find core/tests/python/conformance_lib -name '*.py' -exec wc -l {} + | sort -rn | sed -n '2,8p'
ls core/fuzz/seeds/*/* core/tests/data/diff_regressions/*/* | grep -v gitkeep | wc -l   # committed replay inputs, was 121
```

- [ ] **Step 2: Update CLAUDE.md.**
  - The layout block's conformance_lib file count and the "**75**-file package" sentence.
  - The largest-module ranking paragraph, if the top five moved.
  - "**33/33** since #669 added Section VT" becomes 35/35 (NDL and RDO, #667/#670).
  - The replay paragraph's "121 inputs today" and the `manifest_body` strict-comparison figure: re-measure how many committed `manifest_body` rejecting seeds reach a strict comparison. The three nesting seeds reach `malformed_cbor`, which is never tolerated.
  - Add ONE new paragraph under "Spec is normative" recording the load-bearing facts, each stated once:
    - rule 6 counts containers, not scalars, because the approved wording was one level stricter than every shipped reader;
    - ciborium's limit is pinned to the constant by `ciborium_enforces_exactly_the_v1_limit_on_every_decode_path`, and the record walk answers first;
    - Python has ONE traversal and two entry points, and the pass is content-blind and silent at non-depth faults;
    - the bignum-tag edge on the manifest path is #666's;
    - the writer half is unenforced, with the new issue number;
    - #670's rejection IS the re-encode on both sides, deliberately, and why that is not #608's backstop.

- [ ] **Step 3: ROADMAP.md.** Add the slice to the conformance/differential-replay track, in the same style as the #669 entry. Check README.md's "Project status": it is brief and audience-facing (memory: README style), so edit it only if it already enumerates acceptance divergences.

- [ ] **Step 4: Issues.** Standing authorization; file without asking.
  - File `[core] crypto-design §6.2 rule 6's writer half: no encoder refuses a document nested past 256`. Cite the design spec §8 bullet.
  - Comment on #666: the manifest-path bignum edge (ciborium does not charge a level for a bignum tag over ≤16 bytes; a 257th-level bignum is `non_canonical_unclassified` in Rust and `NestingTooDeep` in Python; no input reaches it; wiring the walk into `decode_manifest` closes it).
  - Comment on #641: `contact_card` token comparison must place depth first (Rust: `CborDecode(RecursionLimit)`; Python: `NestingTooDeep`, both `malformed_cbor`).
  - Comment on #667 and #670: closed in code by this branch, per the `(#N)` convention. Name the seeds and sections.

- [ ] **Step 5: The handoff.** Write `docs/handoffs/2026-09-19-nesting-depth-and-record-defaults-shipped.md` with sections (0)–(6) in the shape of the previous baton:
  - (1) what shipped, with every commit SHA from `git log --oneline main..HEAD`;
  - (1e) measured results: Task 7's corpus lines, variant drift and mutation table;
  - (2) what the slice does not claim: design spec §8, plus the writer-half issue;
  - (3) what is next, with acceptance criteria:
    - #677, the offset sweep of `bundle_file` / `manifest_file`;
    - #641's remaining targets, `contact_card` first, now that it has seeds;
    - #666;
    - #678;
    - #668 / #646;
    - the new writer-half issue;
    - #657, #612, #660, #671, #672, #676;
  - (4) open decisions and risks;
  - (5) exact resume commands: `cd`, branch, and the test commands from Task 7;
  - (6) where the document lives.

  Then:

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
ln -snf docs/handoffs/2026-09-19-nesting-depth-and-record-defaults-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

- [ ] **Step 6: Commit the docs, and the handoff with its symlink as one commit.**

```bash
cd /Users/hherb/src/secretary/.worktrees/nesting-depth-defaults
git add CLAUDE.md ROADMAP.md README.md && git commit -m "Docs: rule 6 and §6.3 default omission in CLAUDE.md and ROADMAP (#667, #670)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
git add docs/handoffs/2026-09-19-nesting-depth-and-record-defaults-shipped.md NEXT_SESSION.md
git commit -m "Handoff: nesting depth (#667) and record default omission (#670) shipped

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Review, fix wave, PR

- [ ] **Step 1: Before review, check whether `main` moved.** Run `git fetch origin && git log --oneline main..origin/main`. If it is not empty, `git merge origin/main`. Where the handoff doc conflicts, the branch version wins (`git checkout --ours <path>`). Re-run Task 7 Step 4.
- [ ] **Step 2: Request review** (superpowers:requesting-code-review, or the pr-review-toolkit agents). Every finding is verified by execution, in a scratch copy, never by mutating the shared worktree (memory: parallel review agents corrupt measurements).
- [ ] **Step 3: Fix every finding, one commit per issue** (memory: fix every review issue before merging). Re-run the affected gates after each fix.
- [ ] **Step 4: Update the handoff** for the fix wave (a review section with before → after mutation evidence), and commit it.
- [ ] **Step 5: Push and open the PR** (durably authorized; the user merges). Title: `Normative CBOR nesting limit (#667) and record default omission (#670)`. The body ends with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`. Then read the `cargo test (ubuntu-latest)` job's replay finish lines, not just the green tick: `record: 44 of 44` and `manifest_body: 48 of 48` must appear.
