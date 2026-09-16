# Design: value-type discipline in `conformance_lib` (#669, widened)

Branch `feature/bool-as-integer`, worktree `.worktrees/bool-as-integer`, base
`2e1e63d3` (`main`, immediately after PR #673 merged).

`conformance.py` exists to prove that `docs/` alone is sufficient to build a
conformant reader. Where it accepts a body the Rust decoder rejects, that claim
is false in the direction that matters least dramatically and most durably: a
clean-room implementer following it builds a reader that is wrong, and the
differential replay cannot tell them, because no corpus input reaches the
position.

This slice closes every such divergence that a systematic wrong-type sweep can
find in the four replayed CBOR/TOML schema decoders, and replaces the
hand-copied rule that produced them with one shared predicate plus two
structural rules.

---

## 1. What was measured before designing

Not read, not reasoned about from the issue text — executed. 439 bodies, each
one substitution away from a committed accepting base, run through Rust's real
decoder and through `conformance_lib.diff_replay.replay_bytes`, verdicts
compared.

| Target | Base | Bodies | Divergences |
|---|---|---|---|
| `manifest_body` | `seeds/manifest_body/uniq__control__all_distinct.bin` | 326 (shared with `contact_card`) | **8** |
| `contact_card` | `seeds/contact_card/with_sigs.cbor` | (above) | **2** |
| `vault_toml` | `seeds/vault_toml/golden.toml` | 61 | **6** |
| `record` | `seeds/record/login.cbor` | 52 | **0** |

Substitutions: `True`, `"x"`, `b"\x00"`, `-1` for CBOR; those plus a float, an
array and a datetime for TOML. Every divergence is the same direction —
**Python accepts, Rust rejects**. None is reachable from any committed or
runtime corpus input, which is why the replay reports full agreement today.

`record`'s zero is a negative control, and it is load-bearing twice: it shows
the method finds divergences where they exist rather than everywhere, and it
shows #641's record work holds under structured wrong-type input and not only
under fuzz.

### 1.1 The 16 divergences, and the two mechanisms behind them

**M1 — `isinstance(x, int)` with no bool exclusion.** Python's `bool`
subclasses `int`, so `isinstance(True, int)` is `True`, while `ciborium`
decodes a CBOR bool to `Value::Bool` and `toml` gives `Value::Boolean`, neither
of which any `take_u*` / `as_integer` accepts.

Eight M1 positions are among the 16 measured divergences — they sit on a
replayed target, so the sweep reached them:

| File | Position | Rust rejection |
|---|---|---|
| `codec/card.py:64` | `card_version` | `Malformed("expected unsigned integer")` |
| `codec/card.py:92` | `created_at` | `Malformed("expected unsigned integer")` |
| `codec/vault_toml.py:65` | `format_version` | `MissingField("format_version")` |
| `codec/vault_toml.py:70` | `suite_id` | `MissingField("suite_id")` |
| `codec/vault_toml.py:81` | `created_at_ms` | `MissingField("created_at_ms")` |
| `codec/vault_toml.py:103` | `kdf.memory_kib` | `MissingField("memory_kib")` |
| `codec/vault_toml.py:107` | `kdf.iterations` | `MissingField("iterations")` |
| `codec/vault_toml.py:111` | `kdf.parallelism` | `MissingField("parallelism")` |

Two further M1 sites carry the same defect on decoders **no replay target
reaches**, so they are not among the 16 and were measured by calling the
decoder directly rather than by the sweep: `codec/trash_entry.py:71,92`
(`tombstoned_at_ms`, `purged_at_ms` — both confirmed ACCEPT for a CBOR bool).
`codec/trash_entry.py` is a standalone decoder serving Section PRG and the
required-key probe; the manifest replay path goes through
`codec/manifest_decode.py` instead.

`wire/vault_toml.py` carries a third spelling of M1 — `data.get("format_version") != 1`,
where `True != 1` is `False` — plus bare `int(...)` coercions on four more
fields, for which `int(True)` is `1`. `wire/` parses to inspect the committed
golden vault and enforces no acceptance set, so it has no Rust counterpart to
diverge from; its exact site count is established during implementation rather
than asserted here.

All three groups are fixed in this slice. Only the eight replay-visible ones
can be pinned by a seed, and §7 says so.

Two sites in the tree already carry the correct guard — `codec/record_rules.py:76`
and `codec/manifest_decode.py:294`, both written in #641. So this is not one
rule with a gap; it is **four independent copies of one sentence, of which two
are right**. That is the #597 shape exactly, and it is why the fix is a shared
predicate rather than eight edits.

**M2 — the type check was never written.** `TrashEntry` has exactly two
`Option` fields, and `manifest_decode.py`'s trash loop validates neither.

| Position | Diverging substitutions | Rust rejection |
|---|---|---|
| `trash[].fingerprint` | bool, text, `b"\x00"`, `-1` | `WrongType` / `InvalidByteLength` |
| `trash[].purged_at_ms` | bool, text, `b"\x00"`, `-1` | `WrongType` / `IntegerOutOfRange` |

These two accept **any CBOR value at all**, on `manifest_body` — a target that
is token-compared and replayed in CI. `BlockEntry` has no `Option` fields and
the top-level `unknown` bag is deliberately uninterpreted, so these two are the
whole of the class in the manifest schema; that was checked against
`manifest/types.rs`, not assumed.

**M2 was invisible to the grep that found M1**, and the reason generalises:
a census keyed on `isinstance(…, int)` can only find positions that have a
check. "Has no check to find" is its own search. The memory-hygiene memo
records the identical failure for a `.zeroize()` grep; this is that lesson
arriving in a different file.

### 1.2 No frozen-spec edit

`docs/vault-format.md` types every affected CBOR field — `<u64>` for the two
timestamps, `u16` for the version sentinels, a 32-byte BLAKE3 digest for
`fingerprint`. §2 gives `vault.toml`'s fields as TOML integers by example.
Rust implements the spec; Python does not. Per CLAUDE.md a divergence is a Rust
bug, a Python bug or a spec ambiguity — this one is squarely the second, so no
`docs/` change is in scope and none is made.

### 1.3 The tokens already line up

`manifest_body` is token-compared, so M2's new raises must name the rule Rust
names. Checked against `manifest/token.rs` and `codec/manifest_rules.py`:

| Rust variant | Rust token | Python class | Python token |
|---|---|---|---|
| `WrongType` | `wrong_type` | `WrongFieldType` | `wrong_type` |
| `InvalidByteLength` | `wrong_type` | `WrongFieldType` | `wrong_type` |
| `IntegerOutOfRange` | `integer_out_of_range` | `IntegerOutOfRange` | `integer_out_of_range` |

`_check_fixed_bytes` raises `WrongFieldType` for both a non-bstr and a wrong
length, which matches Rust folding `WrongType` and `InvalidByteLength` onto one
token. So M2 needs **no new class and no new token** — only the two calls.
That is a measured convenience, not a design choice, and the seeds pin it.

---

## 2. Decisions

| # | Decision | Chosen | Why |
|---|---|---|---|
| D1 | Enforcement strength | Sanctioned module + structural section | Four hand-copies of one sentence, two of them wrong, is the #597 shape; point fixes leave the fifth copy free to be written |
| D2 | Cross-language pin | Label-bound committed seeds via a generator | A hand-committed fixture is self-certifying; the generator is reusable by #641's remaining targets |
| D3 | `wire/` | Fix, but scan `codec/` only | `wire/` enforces no acceptance set, so a default-deny scan there polices code the rule does not govern |
| D4 | Scope after the sweep | Both mechanisms in one slice | One symptom, one audience; M2 is the more serious and splitting means writing the section package twice |
| D5 | M2's raise classes | Reuse `WrongFieldType` / `IntegerOutOfRange` | Their tokens already equal Rust's (§1.3); inventing classes would add vocabulary for no distinction |
| D6 | M2's structural rule | Make it unrepresentable (two sanctioned mechanisms), not detected by AST | The AST census was prototyped and failed: 1 true positive, 39 false positives, **and it missed `trash[].fingerprint`** — see §5 check 4 |

---

## 3. The shared predicate

New `core/tests/python/conformance_lib/codec/integer_rules.py`, one public
function:

```python
def is_integer(value: object) -> bool:
    """True iff `value` is a CBOR/TOML integer.

    `bool` subclasses `int` in Python, so `isinstance(True, int)` is True,
    while `ciborium` decodes a CBOR bool to `Value::Bool` and `toml` to
    `Value::Boolean` — neither of which any `take_u*` or `as_integer` accepts.
    Every integer-position check in `codec/` routes through this function so
    the exclusion is written once rather than per site (#669).
    """
```

Every caller keeps its own exception type and message text. That is deliberate:
Sections MUQ, MSH, MCC and MPR discriminate on message fragments or on typed
classes, and a shared *raiser* would move them. Only the predicate is shared —
the narrowest thing that makes the rule single-sourced.

Callers after this slice: `record_rules.py` (replacing its private
`_is_integer`), `manifest_decode.py::_check_uint`, `card.py` ×2,
`vault_toml.py` ×6, `trash_entry.py` ×2.

---

## 4. The two missing checks

`manifest_decode.py`'s trash loop gains, presence-guarded so an absent optional
key stays absent:

```python
if "fingerprint" in t:
    _check_fixed_bytes(t["fingerprint"], f"trash[{i}].fingerprint", BLOCK_FINGERPRINT_LEN)
if "purged_at_ms" in t:
    _check_uint(t["purged_at_ms"], f"trash[{i}].purged_at_ms", 64)
```

`_check_uint` will call `is_integer` by then, so the bool arm of M2 is closed by
M1's fix and the other three arms by these two lines. A seed per arm keeps the
two mechanisms separately pinned rather than collapsing onto one.

---

## 5. Structural enforcement

A section package, mirroring `required_key_determinism.py` +
`required_key_structure.py` so each rule and its LIMITS live in one file:

- `sections/value_type_discipline.py` — the behavioural half and the section
  driver.
- `sections/value_type_structure.py` — the two structural rules and their
  LIMITS block.

**Check 1 — every divergence rejects.** One case per (position, substitution)
pair from §1.1, asserting the decoder rejects and, where the target is
token-compared, that the token equals Rust's.

**Check 2 — ambiguity control per case.** Restoring the correct value must make
the decoder accept. Without it a case passes against a decoder that rejects the
base body too, and the fixture's discrimination would be asserted by its table
rather than demonstrated by the decoder — the defect #597's Section DET was
built to avoid.

**Check 3 — M1, default-deny.** No `isinstance(…, int)` anywhere under `codec/`
outside `integer_rules.py`. Keyed on the construct that *imposes* the
exclusion, not on statement form, per the #605 lesson.

**Check 4 — M2, coverage by a sanctioned mechanism.**

The first version of this check was an AST census: discover `*_KNOWN_KEYS`
constants by name shape, then require each declared key to reach a type-check
call. **It was prototyped against the real tree before this spec was approved,
and it does not work** — 40 findings: **1 true positive, 39 false positives,
and 1 false negative.** The false negative is disqualifying on its own: it
missed `trash[].fingerprint`, one of the two gaps this slice exists to close,
because a package-global key set sees `fingerprint` checked under `blocks[]`
and credits `trash[]` with it.

Four structural causes, none of them tuning: keys are not scoped to their map;
checks reach values through local bindings (`cv = decoded["card_version"]`,
then `isinstance(cv, int)`); checks are loop-mediated
(`for name in (...): _check_uint(kdf[name], ...)`, which has no literal
subscript at all); and not every check is a `_check_*` call. A guard that
misses the defect it was written for, at a 97% false-positive rate, gets
allowlisted into silence.

**So the rule does not detect the invalid state — it makes it unrepresentable.**
Two mechanisms are sanctioned, because the package has two check ORDERS and one
shape does not fit both:

- **Mechanism A — a total dispatch with a loud fall-through.** For decoders
  that check values in **wire order**, a single `check_*_value(key, value)`
  dispatch whose `else` raises `UncheckedKnownKey` — a `RuntimeError`,
  deliberately outside `conformance_lib.rejection`'s verdict allowlist, so the
  replay scores it a harness failure rather than a rejection. `record.py`
  already works this way (#641's M8 fix); this slice does not refactor it, it
  starts *enforcing* it.
- **Mechanism B — a declared `*_VALUE_CHECKS` table the decoder iterates.** For
  decoders that check in **schema order**. Declared beside its `*_KNOWN_KEYS`
  constant so the two cannot drift, as an ordered tuple of pairs rather than a
  dict — order becomes a declared property instead of an incidental one.

Check 4 is then exact, with no AST analysis, no allowlist and no false
positives:

- For every `*_KNOWN_KEYS` constant under `codec/`, exactly one mechanism must
  cover it. Covered by neither is a FAILURE — default-deny, so a new schema map
  cannot arrive uncovered.
- **Mechanism B is a two-way set comparison:** `{k for k, _ in TABLE} ==
  KNOWN_KEYS`. A declared key missing from the table fails; a table entry for a
  key not declared fails.
- **Mechanism A is a behavioural totality probe:** call the dispatch once per
  declared key and require it not to raise `UncheckedKnownKey`. Behavioural,
  not textual, so an aliased or restructured dispatch cannot evade it.

A key cannot be skipped under either mechanism, because the decoder cannot
iterate past a table row and cannot fall through a total dispatch.

**The cost, stated rather than discovered later.** Under mechanism B the check
order becomes table order. `manifest_body` is token-compared, so for a body
with two faults in one map, which key is reported is observable. The tables
must therefore reproduce today's order exactly for every existing key, with the
two new optional-key checks appended where the source already put optional
handling — and that must be proven by execution (the whole suite, the committed
seeds and a full-corpus replay), not by reading. This is the #589 `Once::set`
lesson: changing the control flow around a check changes which error a
multi-fault body reports, silently, on a v1-frozen decoder.

Which mechanism each map takes:

| Map | Mechanism | Change |
|---|---|---|
| `RECORD_KNOWN_KEYS`, `RECORD_FIELD_KNOWN_KEYS` | A | none — already total; now enforced |
| `MANIFEST_KNOWN_KEYS`, `BLOCK_ENTRY_*`, `TRASH_ENTRY_*`, `KDF_PARAMS_*`, `VECTOR_CLOCK_ENTRY_*` | B | new tables; this is where the defect was |
| `KNOWN_CARD_KEYS` | B | new table |
| `codec/vault_toml.py` | B | new table, plus a top-level key constant it currently lacks |
| `codec/trash_entry.py` | B | new table |

**Check 5 — the seed files are present and label-bound on the Python side**,
the counterpart of the Rust generator in §6.

Section registered once in `sections/registry.py`; Section REG discovers it by
shape and the count moves 32 → 33.

### 5.1 Stated limits

The LIMITS block lives in `value_type_structure.py` rather than here, so the
rules and their limits cannot drift apart. The two rules have **different**
limits, and flattening them into one sentence is the failure mode this repo
keeps re-finding:

- **Check 3 reads TEXT.** `isinstance` is matched by spelling, so
  `from builtins import isinstance as _ii` evades it, as does any
  metaprogrammed call. This is the same limit every hygiene guard here carries.
- **Check 4 does not read text at all**, so it has none of those limits.
  Mechanism B is a set comparison over an evaluated constant and mechanism A is
  a behavioural probe — an alias or a restructured dispatch changes neither.
  Its limit is different and narrower: it governs only key sets it can
  *discover*, and discovery is by name shape. A schema map whose key set is
  built dynamically, or named outside the `KNOWN`/`REQUIRED` shape, is invisible
  to it — not mis-reported, simply not covered. The two-way comparison also
  says nothing about whether a table row's check is the *right* check; that is
  what the behavioural cases and the seeds are for.

---

## 6. Committed seeds

New `core/tests/acceptance_seeds.rs` plus a helpers directory, mirroring
`rule_token_seeds.rs`'s discipline but binding a **verdict and Rust error
variant** rather than a token, because `contact_card` and `vault_toml` have no
token taxonomy yet (#641).

Each seed is one fault planted into a committed accepting base. The `#[ignore]`
generator asserts every case before writing any file; the always-on test
regenerates, requires byte identity, requires the Rust variant the row names,
and censuses the directory against the table in both directions.

| Target | Seeds | Positions |
|---|---|---|
| `contact_card` | 2 | `card_version`, `created_at` — bool |
| `vault_toml` | 6 | the six §1.1 fields — bool |
| `manifest_body` | 6 | `trash[].fingerprint` and `trash[].purged_at_ms`, each bool / wrong-type / right-type-wrong-value |

**14 seeds.** The three-per-key split on `manifest_body` is the load-bearing
part: a bool-only fix reds the wrong-type and wrong-value rows, and a fix that
checks the type but not the length or range reds the third. Each of the three
checks is pinned independently rather than by one row that any partial fix
would satisfy.

`MIN_CORPUS_INPUTS` rises for all three targets. Committed replay inputs go
107 → 121.

---

## 7. What this slice does NOT do

- **It does not close #641.** `contact_card`, `bundle_file` and `vault_toml`
  remain un-token-compared; this slice compares their verdicts, not their
  rules.
- **It does not pin `codec/trash_entry.py` or `wire/vault_toml.py`
  cross-language.** Neither is on a replay path, so both get in-section cases
  only.
- **The sweep is not a proof of absence.** It varies one leaf at a time from
  one base per target, with a fixed substitution set. A divergence needing two
  simultaneous faults, or a value shape outside that set, is outside what was
  measured. Say "the sweep found none", never "there are none".
- **`bundle_file` and `manifest_file` were not swept.** Both are binary
  envelopes whose fields are read by offset rather than by schema key, so the
  substitution method does not apply; whether they carry an analogous class is
  untested and gets filed.
- **No `docs/` change** (§1.2).

---

## 8. Proving it is not decorative

Mutation rows, gate named per row, `scripts/mutate.py`, `--self-test` first:

| Mutation | Expected red |
|---|---|
| `is_integer` drops its bool exclusion | check 1 (every M1 case) |
| One `codec/` site reverts to a bare `isinstance(…, int)` | check 3 |
| The `fingerprint` check deleted | check 1, check 4, the three `manifest_body` fingerprint seeds |
| The `purged_at_ms` check deleted | check 1, check 4, its three seeds |
| `_check_fixed_bytes` checks type but not length | the wrong-value fingerprint seed only |
| A seed's planted bytes collapse onto a sibling's | the generator's byte-identity + distinctness test |
| Check 2's ambiguity control removed | its own negative control |
| The section left out of `registry.py` | Section REG |
| A key removed from a `*_VALUE_CHECKS` table | check 4, mechanism B, both directions |
| `check_record_value`'s `UncheckedKnownKey` fall-through replaced by a silent `pass` | check 4, mechanism A |
| A `*_VALUE_CHECKS` table reordered | the existing order tests and RTS check 5 — the §5 order cost, demonstrated rather than asserted |

Plus the full gate set from the baton's §(5), and a full-corpus differential
replay with the runtime corpus symlinked in and removed afterwards.

---

## 9. Files

New:
- `core/tests/python/conformance_lib/codec/integer_rules.py`
- `core/tests/python/conformance_lib/sections/value_type_discipline.py`
- `core/tests/python/conformance_lib/sections/value_type_structure.py`
- `core/tests/acceptance_seeds.rs` + `core/tests/acceptance_seeds_helpers/`
- 14 files under `core/fuzz/seeds/{contact_card,vault_toml,manifest_body}/`

Changed:
- `codec/{card,vault_toml,trash_entry,manifest_decode,record_rules}.py`
- `codec/manifest_schema.py` (the five `*_VALUE_CHECKS` tables, beside their
  key constants)
- `wire/vault_toml.py`
- `sections/registry.py`
- `core/tests/differential_replay_helpers/targets.rs` (`MIN_CORPUS_INPUTS`)
- `CLAUDE.md`, `ROADMAP.md`, the handoff

Every new source file stays under 500 lines; the section package is split in
two for that reason before it is written, not after.
