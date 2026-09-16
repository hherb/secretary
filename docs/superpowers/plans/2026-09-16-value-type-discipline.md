# Value-type discipline in `conformance_lib` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all 16 measured acceptance divergences where `conformance.py` accepts a body the Rust decoder rejects, and replace the hand-copied rule that produced them with one shared predicate plus two structural rules.

**Architecture:** One new `codec/integer_rules.py` owns the single bool-excluding integer predicate; all 12 integer-position sites call it. `codec/manifest_decode.py` gains the two type checks its trash loop never had. A new two-module conformance section (`value_type_discipline.py` + `value_type_structure.py`) holds the behavioural cases and the two structural rules. A new `core/tests/acceptance_seeds.rs` generator commits 14 label-bound seeds so CI compares both decoders on each body.

**Tech Stack:** Python 3.12 (`uv`, stdlib + the PEP 723 deps), Rust (stable, `cargo test --release --locked`), `cbor2`, `tomllib`, `ciborium`.

**Spec:** [docs/superpowers/specs/2026-09-16-value-type-discipline-design.md](../specs/2026-09-16-value-type-discipline-design.md)

## Global Constraints

- **Do not add a `pyproject.toml`.** `conformance.py`'s PEP 723 header is the sole dependency declaration, and no new dependency is needed.
- **`uv run core/tests/python/conformance.py` must keep working verbatim from any working directory.** Three callers depend on that exact invocation.
- **No `docs/` change.** `vault-format.md` already types every affected field; Rust implements the spec and Python does not. If any task appears to need a spec edit, STOP — that is a design change, not an implementation detail.
- **Every new source file stays under 500 lines.** The section is two modules for this reason before it is written.
- **Message text and exception TYPES at existing raise sites do not change.** Sections MUQ, MSH, MCC and MPR discriminate on message fragments or typed classes. Only the *predicate* is shared. Changing a message is a silent break of another section.
- **`manifest_body` is token-compared**, so any new raise there must carry a token equal to Rust's. Measured: Rust `WrongType` and `InvalidByteLength` → `wrong_type`; Rust `IntegerOutOfRange` → `integer_out_of_range`. Python's `WrongFieldType` → `wrong_type` and `IntegerOutOfRange` → `integer_out_of_range` already match, so **no new class and no new token**.
- **Python's `bool` is an `int` subclass.** That is the whole of M1. `isinstance(True, int)` is `True`.
- Never `pip`; always `uv`. Never run `cargo`/`git` from the main checkout — this work is in `.worktrees/bool-as-integer`.

## Verified facts this plan is built on

Each was established by execution, not by reading. Re-derive rather than trusting if something looks wrong.

- The 16 divergences and their positions: spec §1.1.
- Rust rejects all 10 positions; Python accepts all 10 (spec §1, probe output).
- `record` swept clean (52 bodies, 0 divergences) — do not "fix" anything in `codec/record.py` or `codec/record_rules.py` beyond routing its private `_is_integer` through the shared module.
- `TrashEntry` has exactly two `Option` fields; `BlockEntry` has none.
- Optional-key census (`KNOWN − REQUIRED`) is **7 keys**: `TRASH_ENTRY_*` 2, `RECORD_KNOWN_KEYS` 3, `trash_entry.py KNOWN_KEYS` 2. All other key sets are empty.
- `codec/vault_toml.py` declares `KNOWN_KDF_KEYS` and **no required set**.
- The five files use five different KNOWN/REQUIRED naming conventions; a stem heuristic mis-paired 6 of 10 sets. The pairing must be a declared table.
- `core/fuzz/seeds/manifest_body/` already holds 38 seeds from three other generators, none of which censuses the directory. A new generator MUST scope its two-way census to a filename prefix it owns.
- Free seed-name prefixes in `manifest_body/`: existing ones are `arraysort__`, `block__`, `keyorder__`, `top__`, `trash__`, `uniq__`. This plan uses `valuetype__`.

## File Structure

**Create:**
- `core/tests/python/conformance_lib/codec/integer_rules.py` — the single bool-excluding integer predicate. ~40 lines.
- `core/tests/python/conformance_lib/sections/value_type_discipline.py` — Section VT driver plus checks 1 and 2 (behavioural). ~230 lines.
- `core/tests/python/conformance_lib/sections/value_type_structure.py` — checks 3, 4 and 4b plus the LIMITS block and the declared KNOWN/REQUIRED pairing table. ~220 lines.
- `core/tests/acceptance_seeds.rs` — generator + label binder. ~150 lines.
- `core/tests/acceptance_seeds_helpers/mod.rs` — the case table and shared helpers. ~200 lines.
- 14 seed files under `core/fuzz/seeds/{contact_card,vault_toml,manifest_body}/`.

**Modify:**
- `codec/card.py` (2 sites), `codec/vault_toml.py` (6 sites + `REQUIRED_KDF_KEYS`), `codec/trash_entry.py` (2 sites), `codec/record_rules.py` (`_is_integer` → delegate), `codec/manifest_decode.py` (`_check_uint` → delegate, plus the two new trash checks).
- `wire/vault_toml.py` — the bool-permissive equality and coercion sites.
- `sections/registry.py` — one `Section(...)` row.
- `core/tests/differential_replay_helpers/targets.rs` — `MIN_CORPUS_INPUTS`.
- `CLAUDE.md`, `ROADMAP.md`, the handoff.

---

### Task 1: The shared predicate, and the behavioural section that fails without it

**Files:**
- Create: `core/tests/python/conformance_lib/codec/integer_rules.py`
- Create: `core/tests/python/conformance_lib/sections/value_type_discipline.py`
- Modify: `core/tests/python/conformance_lib/sections/registry.py`

**Interfaces:**
- Produces: `conformance_lib.codec.integer_rules.is_integer(value: object) -> bool`
- Produces: `conformance_lib.sections.value_type_discipline.section_value_type_discipline() -> tuple[bool, list[str]]`
- Produces: `DIVERGENCE_CASES: tuple[Case, ...]` where `Case` is a frozen dataclass with fields `target: str`, `position: str`, `substitution: str`, `plant: Callable[[], bytes]`, `token: str | None`. `token` is the rule BOTH decoders must name, or `None` for a target with no token taxonomy (`contact_card`, `vault_toml`).
- Consumes: `conformance_lib.diff_replay.replay_bytes(target, body)`, whose `.verdict` is a dict with `status`, `error_class`, `detail`, `rule`.

- [ ] **Step 1: Write `integer_rules.py`**

```python
"""The one place `conformance_lib` decides whether a decoded value is an
integer (#669).

WHY A MODULE FOR ONE PREDICATE.  Python's `bool` subclasses `int`, so
`isinstance(True, int)` is `True`, while `ciborium` decodes a CBOR bool to
`Value::Bool` and `toml` to `Value::Boolean` -- neither of which any Rust
`take_u*` or `as_integer` accepts.  Before this module the exclusion was
hand-copied: FOUR independent spellings across five files, of which two were
right (`codec/record_rules.py`, `codec/manifest_decode.py`, both #641) and
two were missing entirely, which let ten integer positions accept a boolean
the Rust decoder rejects.  That is the #597 shape -- not one rule with a gap,
several copies of one sentence of which some are wrong -- and the same
remedy: name the rule once so a caller list does not have to remember it.

Section VT's check 3 denies `isinstance(..., int)` anywhere else under
`codec/`, so a fifth copy cannot be written.
"""

from __future__ import annotations


def is_integer(value: object) -> bool:
    """True iff `value` is a CBOR/TOML integer.

    A `bool` is NOT an integer here, though Python says `isinstance(True, int)`
    is `True`. Every integer-position check under `codec/` routes through this.
    """
    return isinstance(value, int) and not isinstance(value, bool)
```

- [ ] **Step 2: Write the failing section**

Create `sections/value_type_discipline.py`. It must:
1. Build one body per row of `DIVERGENCE_CASES` (the 16 from spec §1.1) from the committed accepting base for its target.
2. Assert `replay_bytes(target, body).verdict["status"] == "reject"`, and where `token is not None`, that `verdict["rule"] == token`.
3. Report every failure as an `ISSUE:` line and return `(not issues, lines)`.

The plant helpers, verbatim:

```python
def _cbor_sub(base: bytes, path: tuple[str | int, ...], value: object) -> bytes:
    """Return `base` with `path` replaced by `value`, re-encoded canonically."""
    import cbor2
    root = cbor2.loads(base)
    node = root
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    return cbor2.dumps(root, canonical=True)


def _toml_sub(base: str, key: str, literal: str) -> bytes:
    """Return `base` with the assignment to `key` replaced by `key = literal`."""
    out = []
    replaced = False
    for line in base.splitlines():
        if not replaced and line.split("=", 1)[0].strip() == key:
            out.append(f"{key} = {literal}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        raise ValueError(f"no assignment to {key!r} in the base vault.toml")
    return ("\n".join(out) + "\n").encode()
```

The 16 rows. `TRASH_BASE` is `uniq__control__all_distinct.bin` with `trash[0]["fingerprint"] = bytes(32)` and `trash[0]["purged_at_ms"] = 7` added, so both optional keys are reachable:

| target | position | substitutions | token |
|---|---|---|---|
| `contact_card` | `card_version`, `created_at` | bool | `None` |
| `vault_toml` | `format_version`, `suite_id`, `created_at_ms`, `memory_kib`, `iterations`, `parallelism` | bool (`true`) | `None` |
| `manifest_body` | `trash[0].fingerprint` | bool → `wrong_type`; text → `wrong_type`; `b"\x00"` → `wrong_type` | as shown |
| `manifest_body` | `trash[0].purged_at_ms` | bool → `wrong_type`; text → `wrong_type`; `-1` → `integer_out_of_range` | as shown |

That is 2 + 6 + 3 + 3 = **14 rows**; the remaining 2 of the 16 are `trash[0].fingerprint` / `trash[0].purged_at_ms` under the fourth substitution measured in the sweep (`-1` for `fingerprint`, `b"\x00"` for `purged_at_ms`), both `wrong_type`. Include them: **16 rows total.**

- [ ] **Step 3: Register the section**

In `sections/registry.py`, add the import beside the others and this row immediately before the `REG` row (REG is last on purpose):

```python
    Section("VT", "value-type discipline: no bool in an integer position, and every optional key checked",
            " (#669)", section_value_type_discipline),
```

- [ ] **Step 4: Run it and verify it FAILS with 16 issues**

```bash
cd /Users/hherb/src/secretary/.worktrees/bool-as-integer
uv run core/tests/python/conformance.py 2>&1 | grep -E "Section VT|ISSUE|FAIL: value-type"
```

Expected: `FAIL: value-type discipline …` and 16 `ISSUE:` lines, each reporting `got accept`. **If fewer than 16 fail, a row is wrong — fix the row before proceeding.** This step is the whole point of the task: it proves the cases discriminate.

- [ ] **Step 5: Commit**

```bash
git add core/tests/python/conformance_lib/codec/integer_rules.py \
        core/tests/python/conformance_lib/sections/value_type_discipline.py \
        core/tests/python/conformance_lib/sections/registry.py
git commit -m "test(conformance): Section VT, 16 failing acceptance-divergence cases (#669)"
```

---

### Task 2: Close M1 — the bool-as-integer class, at all 12 sites

**Files:**
- Modify: `core/tests/python/conformance_lib/codec/record_rules.py:74-76`
- Modify: `core/tests/python/conformance_lib/codec/manifest_decode.py:283-297`
- Modify: `core/tests/python/conformance_lib/codec/card.py:64,92`
- Modify: `core/tests/python/conformance_lib/codec/vault_toml.py:65,70,81,103,107,111`
- Modify: `core/tests/python/conformance_lib/codec/trash_entry.py:71,92`

**Interfaces:**
- Consumes: `is_integer` from Task 1.

- [ ] **Step 1: Route the two already-correct copies through the shared module**

In `record_rules.py`, delete the private `_is_integer` body and import instead. Keep the name so its call sites are untouched:

```python
from conformance_lib.codec.integer_rules import is_integer as _is_integer
```

In `manifest_decode.py`, change the first line of `_check_uint` from
`if isinstance(value, bool) or not isinstance(value, int):` to
`if not is_integer(value):`, adding `from conformance_lib.codec.integer_rules import is_integer`. **Leave the docstring's explanation in place** — it is the best statement of the rule in the tree — but retarget its last sentence to name `integer_rules`.

- [ ] **Step 2: Fix the ten broken sites**

Each is a minimal edit that changes ONLY the type test. Message text stays byte-identical.

`card.py`:
```python
    if not is_integer(cv) or cv != 1:
    ...
    if not is_integer(cat) or cat < 0:
```

`vault_toml.py` — all six, e.g.:
```python
    if not is_integer(fv) or fv != 1:
    ...
    if not is_integer(mem_kib) or mem_kib < 0 or mem_kib > 0xFFFFFFFF:
```

`trash_entry.py`:
```python
    if not is_integer(tombstoned_at_ms) or tombstoned_at_ms < 0:
    ...
        if not is_integer(purged_at_ms) or purged_at_ms < 0:
```

- [ ] **Step 3: Run the section — the 8 M1 rows must now pass**

```bash
uv run core/tests/python/conformance.py 2>&1 | grep -E "Section VT|ISSUE" | head -20
```

Expected: exactly **8** remaining `ISSUE:` lines, all `manifest_body trash[0].*`. The two `contact_card` and six `vault_toml` rows now pass. (The `trash_entry.py` sites have no VT row — that decoder is on no replay path — so they are covered by Task 6's census, not here.)

- [ ] **Step 4: Run the FULL verifier to prove no other section moved**

```bash
uv run core/tests/python/conformance.py; echo "exit=$?"
```

Expected: no section other than VT reports `FAIL:`. **If any other section fails, a message or exception type changed — revert and redo the edit as a pure predicate swap.**

- [ ] **Step 5: Commit**

```bash
git add core/tests/python/conformance_lib/codec/
git commit -m "fix(conformance): a CBOR/TOML bool is not an integer, at all 12 sites (#669)"
```

---

### Task 3: Close M2 — the two unvalidated manifest optional keys

**Files:**
- Modify: `core/tests/python/conformance_lib/codec/manifest_decode.py:374-377` (the trash loop in `_validate_manifest_shape`)

**Interfaces:**
- Consumes: `_check_uint`, `_check_fixed_bytes`, `BLOCK_FINGERPRINT_LEN` — all already in that module.

- [ ] **Step 1: Add the two presence-guarded checks**

Append inside the existing `for i, t in enumerate(out["trash"]):` loop, after the `tombstoned_by` line:

```python
        # `TrashEntry`'s two OPTIONAL keys (§4.2). Absent decodes to `None` and
        # re-encodes to absent, so they are checked only when present -- but
        # when present they are checked, which until #669 they were not: both
        # accepted ANY CBOR value while `entries.rs` routes them through
        # `take_fixed_bytes::<32>` and `take_u64`. `manifest_body` is
        # token-compared, and these two helpers already raise the classes whose
        # tokens equal Rust's (`wrong_type`, `integer_out_of_range`), so no new
        # class and no new token is needed.
        if "fingerprint" in t:
            _check_fixed_bytes(
                t["fingerprint"], f"trash[{i}].fingerprint", BLOCK_FINGERPRINT_LEN
            )
        if "purged_at_ms" in t:
            _check_uint(t["purged_at_ms"], f"trash[{i}].purged_at_ms", 64)
```

- [ ] **Step 2: Run the section — all 16 rows must pass**

```bash
uv run core/tests/python/conformance.py 2>&1 | grep -E "Section VT|ISSUE|FAIL:"
```

Expected: Section VT passes, zero `ISSUE:` lines, and no other `FAIL:`.

- [ ] **Step 3: Prove the check is not vacuous, by reverting it**

```bash
git stash push -u -m "vt-vacuity-check-$$" -- core/tests/python/conformance_lib/codec/manifest_decode.py
uv run core/tests/python/conformance.py 2>&1 | grep -c "ISSUE"   # expect 8
git stash list --format='%H %gs' | head -3
```
Restore with `git stash apply <sha>` then drop that entry by tag. **Do not use bare `git stash pop`** — the stash stack is shared with other worktrees and parallel sessions.

- [ ] **Step 4: Commit**

```bash
git add core/tests/python/conformance_lib/codec/manifest_decode.py
git commit -m "fix(conformance): check TrashEntry's two optional keys, which accepted any CBOR value (#669)"
```

---

### Task 4: Check 2 — an ambiguity control per case

**Files:**
- Modify: `core/tests/python/conformance_lib/sections/value_type_discipline.py`

**Interfaces:**
- Produces: `_control_issues() -> list[str]`, called by `section_value_type_discipline`.

- [ ] **Step 1: Write the control**

For every row, rebuild the body with the ORIGINAL value in that position and require the decoder to **accept**. Without this a row passes against a decoder that rejects the base body too, so the fixture's discrimination would be asserted by its table rather than demonstrated by the decoder — the defect Section DET was built to avoid.

```python
def _control_issues() -> list[str]:
    """Each case's position, restored to its base value, must ACCEPT.

    Without this, a row proves only that SOMETHING was rejected. A decoder
    that rejects the base body satisfies all 16 rows and this section would
    report PASS on a verifier that accepts nothing at all.
    """
    issues: list[str] = []
    for case in DIVERGENCE_CASES:
        verdict = replay_bytes(case.target, case.base_body()).verdict
        if verdict.get("status") != "accept":
            issues.append(
                f"{case.target} {case.position}: the CONTROL body (base value restored) "
                f"must be accepted, got {verdict.get('status')} "
                f"({verdict.get('error_class')}: {verdict.get('detail')})"
            )
    return issues
```

- [ ] **Step 2: Verify the control is live**

Temporarily point one case's `base_body()` at its mutated body; the control must red. Restore, then re-run and confirm green.

- [ ] **Step 3: Run and commit**

```bash
uv run core/tests/python/conformance.py 2>&1 | grep -E "Section VT|PASS|ISSUE"
git add core/tests/python/conformance_lib/sections/value_type_discipline.py
git commit -m "test(conformance): Section VT check 2, an ambiguity control per case (#669)"
```

---

### Task 5: Check 3 — `isinstance(…, int)` is confined to `integer_rules.py`

**Files:**
- Create: `core/tests/python/conformance_lib/sections/value_type_structure.py`
- Modify: `core/tests/python/conformance_lib/sections/value_type_discipline.py` (call into it)

**Interfaces:**
- Produces: `sanctioned_module_issues() -> list[str]`

- [ ] **Step 1: Write the rule**

Walk every `*.py` under `codec/` with `ast`, find every `ast.Call` to the name `isinstance` whose second argument names `int` (directly, or as an element of a tuple), and report any outside `integer_rules.py`. Default-deny.

```python
SANCTIONED = "integer_rules.py"

def _names_int(node: ast.expr) -> bool:
    if isinstance(node, ast.Name) and node.id == "int":
        return True
    if isinstance(node, ast.Tuple):
        return any(_names_int(e) for e in node.elts)
    return False


def sanctioned_module_issues() -> list[str]:
    issues: list[str] = []
    for path in sorted(CODEC_ROOT.rglob("*.py")):
        if path.name == SANCTIONED:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == "isinstance"
                    and len(node.args) == 2 and _names_int(node.args[1])):
                issues.append(
                    f"{path.name}:{node.lineno} tests `isinstance(..., int)` directly; "
                    f"call `integer_rules.is_integer` instead -- a bare isinstance "
                    f"accepts a bool, which is what #669 was"
                )
    return issues
```

- [ ] **Step 2: Verify it is live and currently clean**

```bash
uv run core/tests/python/conformance.py 2>&1 | grep "Section VT" -A3
```
Expected: clean. Then plant `isinstance(x, int)` in `codec/card.py`, re-run, confirm it reds, and remove it.

- [ ] **Step 3: Write the LIMITS block**

At the top of `value_type_structure.py`, state exactly what check 3 does NOT cover: it reads TEXT, so `from builtins import isinstance as _ii` evades it, as does any metaprogrammed call; it scans `codec/` and nowhere else; it resolves no names, so `int` is whatever a module binds to that identifier.

- [ ] **Step 4: Commit**

```bash
git add core/tests/python/conformance_lib/sections/
git commit -m "test(conformance): Section VT check 3, isinstance(..., int) confined to integer_rules (#669)"
```

---

### Task 6: Check 4 — the optional-key census, and 4b — dispatch totality

**Files:**
- Modify: `core/tests/python/conformance_lib/sections/value_type_structure.py`
- Modify: `core/tests/python/conformance_lib/codec/vault_toml.py` (add `REQUIRED_KDF_KEYS`)
- Modify: `core/tests/python/conformance_lib/sections/value_type_discipline.py` (2 new `trash_entry.py` cases)

**Interfaces:**
- Produces: `optional_key_issues() -> list[str]`, `dispatch_totality_issues() -> list[str]`
- Produces: `KEY_SET_PAIRS: tuple[tuple[str, str, str | None], ...]` — `(file, known_name, required_name)`, declared explicitly.

- [ ] **Step 1: Declare the pairing table**

The five files use five naming conventions, and a stem heuristic mis-paired 6 of 10 sets when prototyped. Declare it:

```python
KEY_SET_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("manifest_schema.py", "MANIFEST_KNOWN_KEYS",           "MANIFEST_REQUIRED_KEYS"),
    ("manifest_schema.py", "BLOCK_ENTRY_KNOWN_KEYS",        "BLOCK_ENTRY_REQUIRED_KEYS"),
    ("manifest_schema.py", "TRASH_ENTRY_KNOWN_KEYS",        "TRASH_ENTRY_REQUIRED_KEYS"),
    ("manifest_schema.py", "KDF_PARAMS_KNOWN_KEYS",         "KDF_PARAMS_REQUIRED_KEYS"),
    ("manifest_schema.py", "VECTOR_CLOCK_ENTRY_KNOWN_KEYS", "VECTOR_CLOCK_ENTRY_REQUIRED_KEYS"),
    ("record.py",          "RECORD_KNOWN_KEYS",             "RECORD_REQUIRED_KEYS"),
    ("record.py",          "RECORD_FIELD_KNOWN_KEYS",       "REQUIRED_FIELD_KEYS"),
    ("card.py",            "KNOWN_CARD_KEYS",               "REQUIRED_CARD_FIELDS"),
    ("trash_entry.py",     "KNOWN_KEYS",                    "REQUIRED"),
    ("vault_toml.py",      "KNOWN_KDF_KEYS",                "REQUIRED_KDF_KEYS"),
)
```

- [ ] **Step 2: Add the missing required set**

`codec/vault_toml.py` declares `KNOWN_KDF_KEYS` and no required set. Every field of Rust's `KdfSectionWire` is non-`Option`, so all six are required. Beside `KNOWN_KDF_KEYS`:

```python
    # Every field of Rust's `KdfSectionWire` is non-`Option`, so the whole
    # known set is required. Declared so Section VT's optional-key census has
    # a pairing for this map rather than skipping it (#669).
    REQUIRED_KDF_KEYS = KNOWN_KDF_KEYS
```

- [ ] **Step 3: Write the census, both directions**

Evaluate each named constant by `ast.literal_eval` over the module's AST (no import, no decoder execution; follow a plain `X = Y` alias). Then:
1. Every key in `known − required` must appear in `DIVERGENCE_CASES` or in the mechanism-A covered set. Missing → issue.
2. Every `codec/` key set discovered by name shape (`KNOWN`/`REQUIRED`) must appear in `KEY_SET_PAIRS`. Missing → issue. This is what stops a NEW key set being silently skipped.
3. A pairing naming a constant that does not exist → issue.

Expected population: **7 optional keys**. Print it, so a change of population is visible in the run output.

- [ ] **Step 4: Add the two `trash_entry.py` cases to check 1**

`codec/trash_entry.py`'s two optional keys are on no replay path, so they cannot be VT check-1 rows in the `replay_bytes` sense. Call `py_decode_trash_entry` directly and require a raise:

```python
def _trash_entry_issues() -> list[str]:
    """`codec/trash_entry.py` is a standalone decoder -- Section PRG and the
    required-key probe are its only callers, so the differential replay cannot
    see it and no committed seed can pin it. Its two optional keys are checked
    here, directly, for exactly that reason (#669).
    """
```

- [ ] **Step 5: Write check 4b — mechanism-A dispatch totality**

`record.py` checks values in WIRE order through `check_record_value` / `check_field_value`, whose `else` raises `UncheckedKnownKey` (#641's M8). That already makes a missing check unrepresentable there. Call each dispatch once per declared key with a deliberately wrong value and require it NOT to raise `UncheckedKnownKey`:

```python
def dispatch_totality_issues() -> list[str]:
    """Mechanism A: a wire-order decoder's dispatch must be TOTAL.

    Behavioural, not textual, so an aliased or restructured dispatch cannot
    evade it. `record.py` is NOT refactored by #669 -- this check starts
    enforcing what #641 already built.
    """
```

- [ ] **Step 6: Verify both directions**

Plant a new key in `RECORD_KNOWN_KEYS` with no arm in `check_record_value` → 4b must red. Remove `tombstone` from `RECORD_REQUIRED_KEYS`' complement coverage → check 4 must red. Restore both.

- [ ] **Step 7: Run and commit**

```bash
uv run core/tests/python/conformance.py; echo "exit=$?"
git add core/tests/python/conformance_lib/
git commit -m "test(conformance): Section VT checks 4 and 4b, the optional-key census and dispatch totality (#669)"
```

---

### Task 7: `wire/vault_toml.py`

**Files:**
- Modify: `core/tests/python/conformance_lib/wire/vault_toml.py:36-39,60-68`

- [ ] **Step 1: Census the sites**

```bash
grep -n "!= 1\|int(" core/tests/python/conformance_lib/wire/vault_toml.py
```
Record the actual count in the commit message — the spec deliberately does not assert one.

- [ ] **Step 2: Fix them**

`data.get("format_version") != 1` accepts `True` because `True != 1` is `False`. Require the type first:

```python
    if not is_integer(data.get("format_version")) or data["format_version"] != 1:
        raise ParseError(f"vault.toml format_version {data.get('format_version')!r}")
```

Same for `suite_id`. For the four bare `int(...)` coercions in the constructor call, validate before coercing.

- [ ] **Step 3: Note the scope in a comment**

`wire/` parses to INSPECT the committed golden vault and enforces no acceptance set, so it has no Rust counterpart to diverge from and check 3 deliberately does not scan it. Say so where the fix lands.

- [ ] **Step 4: Run and commit**

```bash
uv run core/tests/python/conformance.py; echo "exit=$?"    # Section 2 exercises this path
git add core/tests/python/conformance_lib/wire/vault_toml.py
git commit -m "fix(conformance): wire/vault_toml accepted a TOML bool for two pinned integers (#669)"
```

---

### Task 8: The committed seeds and their Rust generator

**Files:**
- Create: `core/tests/acceptance_seeds.rs`, `core/tests/acceptance_seeds_helpers/mod.rs`
- Create: 14 files under `core/fuzz/seeds/{contact_card,vault_toml,manifest_body}/`

**Interfaces:**
- Produces: `AcceptanceCase { target, prefix, shape, variant, plant }`, `all_cases()`, `SEED_PREFIX = "valuetype__"`.

- [ ] **Step 1: Mirror `rule_token_seeds_helpers`, with two deliberate differences**

Read `core/tests/rule_token_seeds_helpers/mod.rs` first. Differences:
1. **Bind a Rust error VARIANT and the verdict, not a token.** `contact_card` and `vault_toml` have no token taxonomy (#641 open), so the row's contract is "Rust rejects, with this variant".
2. **Scope the two-way census to `SEED_PREFIX`.** `core/fuzz/seeds/manifest_body/` already holds 38 seeds from three other generators, and `rule_token_seeds.rs`'s census — "every file containing `__`" — would claim all of them. Census only files starting with `valuetype__`.

- [ ] **Step 2: The 14 rows**

| target | shape | Rust variant |
|---|---|---|
| `contact_card` | `card_version_bool`, `created_at_bool` | `Malformed` |
| `vault_toml` | `format_version_bool`, `suite_id_bool`, `created_at_ms_bool`, `memory_kib_bool`, `iterations_bool`, `parallelism_bool` | `MissingField` |
| `manifest_body` | `trash_fingerprint_bool`, `trash_fingerprint_text`, `trash_fingerprint_short` | `WrongType`, `WrongType`, `InvalidByteLength` |
| `manifest_body` | `trash_purged_bool`, `trash_purged_text`, `trash_purged_negative` | `WrongType`, `WrongType`, `IntegerOutOfRange` |

The three-per-manifest-key split is load-bearing: a bool-only fix reds the `_text` row, and a type-but-not-length/range fix reds `_short` / `_negative`. Each of the three checks is pinned independently.

- [ ] **Step 3: Generator and binder, following the #614 lesson**

Assert EVERY row before writing ANY file, so a failing row leaves every seed untouched. Then the always-on test regenerates, requires byte identity, requires the named variant, requires distinct bytes per target, and censuses both directions over the prefix.

- [ ] **Step 4: Generate, then verify**

```bash
cargo test --release --locked -p secretary-core --test acceptance_seeds -- --ignored generate_acceptance_seeds
git status --short core/fuzz/seeds/    # expect exactly 14 new files
cargo test --release --locked -p secretary-core --test acceptance_seeds
```

- [ ] **Step 5: Prove the binding is live**

Overwrite one seed with a sibling's bytes; the byte-identity check must red. Restore by regenerating and confirm `git diff` is empty.

- [ ] **Step 6: Commit**

```bash
git add core/tests/acceptance_seeds.rs core/tests/acceptance_seeds_helpers/ core/fuzz/seeds/
git commit -m "test: 14 label-bound acceptance seeds so CI compares both decoders (#669)"
```

---

### Task 9: Raise the corpus floors, and prove the replay sees the new seeds

**Files:**
- Modify: `core/tests/differential_replay_helpers/targets.rs` (`MIN_CORPUS_INPUTS`)

- [ ] **Step 1: Raise the three floors by the seeds added**

`contact_card` +2, `vault_toml` +6, `manifest_body` +6. Read the current values rather than trusting this line; the floor counts COMMITTED inputs only.

- [ ] **Step 2: Run the replay in CI shape**

```bash
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```
Expected: the finish lines show the raised counts, and **no disagreement**. Before Task 2/3 these 14 bodies would each have been an accept/reject mismatch — that is what the slice fixed.

- [ ] **Step 3: Commit**

```bash
git add core/tests/differential_replay_helpers/targets.rs
git commit -m "test: raise MIN_CORPUS_INPUTS for the 14 new committed seeds (#669)"
```

---

### Task 10: Mutation evidence

**Files:** none committed; the spec is written to the session scratchpad, never the tree (#516).

- [ ] **Step 1: `--self-test` first**

```bash
uv run scripts/mutate.py --self-test     # expect 20/20
```

- [ ] **Step 2: Write the spec to `$SCRATCH` and run it**

Rows, each naming its gate (#651):

| # | Mutation | Gate |
|---|---|---|
| V1 | `is_integer` drops `and not isinstance(value, bool)` | `conformance.py` |
| V2 | one `codec/` site reverts to a bare `isinstance(…, int)` | `conformance.py` (check 3) |
| V3 | the `fingerprint` check deleted | `conformance.py` |
| V4 | the `purged_at_ms` check deleted | `conformance.py` |
| V5 | `_check_fixed_bytes` checks type but not length | `conformance.py` (the `_short` row alone) |
| V6 | `check_record_value`'s `UncheckedKnownKey` → `pass` | `conformance.py` (check 4b) |
| V7 | a seed's plant collapses onto a sibling's bytes | `cargo test … --test acceptance_seeds` |

Python probes need the verifier's deps:
```bash
uv run --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/vt.toml"
```

- [ ] **Step 3: Confirm the tree is clean**

```bash
git status --short     # MUST be empty
```

---

### Task 11: The full gate set, docs, and the baton

**Files:**
- Modify: `CLAUDE.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-09-16-value-type-discipline-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget the symlink)

- [ ] **Step 1: Run every gate, as literal commands**

```bash
cargo test --release --locked --workspace
cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay
cargo clippy --release --locked --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo fmt --all --check
uv run core/tests/python/conformance.py
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

- [ ] **Step 2: Full-corpus replay, and remove the symlink afterwards**

```bash
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay -- differential_replay_full_corpus
rm core/fuzz/corpus && git status --short    # no corpus entry
```
`.gitignore`'s `corpus/` rule matches directories only, so a symlink shows as untracked.

- [ ] **Step 3: Update `CLAUDE.md`**

Re-measure every number rather than quoting: the `conformance_lib` file count, the largest-module ranking, and the REG count (32 → 33). Add a short subsection under the conformance heading recording M1, M2, the two structural rules, and — most importantly — **that M2 was invisible to the grep that found M1**, with the generalisation: a census keyed on a check can only find positions that have one.

```bash
find core/tests/python/conformance_lib -name '*.py' | wc -l
```

- [ ] **Step 4: Update `ROADMAP.md`** with the slice and the three filed issues (#677, #678, and #669's widening).

- [ ] **Step 5: Write the handoff and retarget the symlink**

```bash
ln -snf docs/handoffs/2026-09-16-value-type-discipline-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
git add docs/handoffs/ NEXT_SESSION.md CLAUDE.md ROADMAP.md
git commit -m "docs: value-type discipline slice, handoff and baton retarget (#669)"
```

The handoff must carry: what shipped with SHAs, what is next with acceptance criteria, open decisions and risks, and the exact resume commands.

- [ ] **Step 6: Push and open the PR**

```bash
git push -u origin feature/bool-as-integer
gh pr create --fill
```

---

## Self-Review

**Spec coverage.** §1.1 M1 → Tasks 2, 7. §1.1 M2 → Task 3. §1.2 (no spec edit) → Global Constraints. §1.3 (tokens align) → Task 3. §3 shared predicate → Task 1. §4 the two checks → Task 3. §5 check 1 → Task 1; check 2 → Task 4; check 3 → Task 5; check 4/4b → Task 6. §5.1 LIMITS → Task 5 step 3 and Task 6. §6 seeds → Tasks 8, 9. §7 (what this does not do) → carried into the handoff, Task 11. §8 mutation rows → Task 10. §9 files → File Structure.

**Placeholder scan.** No TBD/TODO. Every code step carries real code or an exact command. Task 6's three check bodies give docstrings and contracts rather than full implementations — deliberate, because the census logic depends on the AST shapes the implementer will read in `required_key_structure.py`, and the spec fixes the contract precisely (two directions, 7 expected optional keys, explicit pairing). The expected population is stated as a number so a wrong implementation is visible.

**Type consistency.** `is_integer` is the single name throughout (Task 1 defines it; Tasks 2, 6, 7 consume it). `DIVERGENCE_CASES` / `Case` are defined in Task 1 and consumed in Tasks 4 and 6. `KEY_SET_PAIRS` is defined and consumed in Task 6. `SEED_PREFIX` / `AcceptanceCase` / `all_cases()` are defined and consumed in Task 8. `section_value_type_discipline` is defined in Task 1 and registered in the same task.

**One correction made during review:** Task 1's row table originally summed to 14 while the spec says 16; the two missing rows are `trash[0].fingerprint` under `-1` and `trash[0].purged_at_ms` under `b"\x00"`, both measured in the sweep and both `wrong_type`. Fixed inline.
