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

All three groups are fixed in this slice. **Correction (#679 review): that sentence was true of `wire/vault_toml.py` and false of `wire/` as a whole — `wire/card.py` carried both mechanisms (a bare `card_version != 1`, and no check at all on `created_at`) and was missed. Fixed, with behavioural cover, in the review round.** Only the eight replay-visible ones
can be pinned by a seed, and §7 says so.

Two sites in the tree already carry the correct guard — `codec/record_rules.py:76`
and `codec/manifest_decode.py:294`. (#679 review: the latter was written in **#595**, not #641 — `git log -S` puts it at `7fa4ddb3`, two weeks earlier. The copies span three PRs, not one.) So this is not one
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
| D6 | M2's structural rule | A two-way census over `KNOWN − REQUIRED`, satisfied by the behavioural cases; **not** an AST census and **not** a table-driven refactor | Both alternatives were prototyped against the real tree and rejected on measurement — see §5 check 4 |

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

**A table-driven refactor was the second candidate, and it was rejected on
measurement too.** Having each schema map declare a `*_VALUE_CHECKS` table that
its decoder iterates would make a skipped key unrepresentable, and check 4
would reduce to `{k for k, _ in TABLE} == KNOWN_KEYS`. But
`_validate_manifest_shape` **interleaves** type and sentinel checks today —
`_check_uint(manifest_version)`, then `!= V1`, then `_check_uint(format_version)`,
then `!= V1` — and Rust's `parse_manifest_map` interleaves the same way by
construction (#587 records exactly this). A table of type checks separates
them, so a body with a bad `manifest_version` *sentinel* and a bad
`format_version` *type* would flip which fault is reported. On a token-compared
target that is a **new cross-language divergence, introduced by the guard meant
to prevent divergences** — the #589 `Once::set` lesson arriving from the other
direction. Deferred to #678 as hardening against a class no measurement has
observed; not built here on spec.

**What check 4 actually is: the defect was about OPTIONAL keys, so the rule is
about optional keys.** `TrashEntry`'s two `Option` fields were declared in
`TRASH_ENTRY_KNOWN_KEYS` and excluded from `TRASH_ENTRY_REQUIRED_KEYS` — the
presence census honoured that and the type check never followed. So:

> Every key in `KNOWN − REQUIRED`, for every key set under `codec/`, must have a
> wrong-type behavioural case. Two-way census.

Measured across the real tree — **7 optional keys**, which is the entire
population the rule governs:

| Key set | `KNOWN − REQUIRED` |
|---|---|
| `TRASH_ENTRY_*` | `fingerprint`, `purged_at_ms` ← **the defect** |
| `RECORD_KNOWN_KEYS` | `tags`, `tombstone`, `tombstoned_at_ms` (already checked, via mechanism A) |
| `trash_entry.py` `KNOWN_KEYS` | `fingerprint`, `purged_at_ms` |
| `MANIFEST_*`, `BLOCK_ENTRY_*`, `KDF_PARAMS_*`, `VECTOR_CLOCK_ENTRY_*`, `RECORD_FIELD_*`, `KNOWN_CARD_KEYS` | none |

The cases that satisfy it are the §5 check 1 cases, so the rule costs almost
nothing beyond the census itself. It has no AST analysis, no allowlist, no
false positives and no order risk — and, unlike the AST version, **it would
have caught this defect**, which is the bar any replacement had to clear.

**Companion — mechanism A totality.** For a decoder that checks in wire order
through a `check_*_value(key, value)` dispatch, the guarantee is that the
dispatch is TOTAL: `record.py`'s `else` raises `UncheckedKnownKey`, a
`RuntimeError` deliberately outside `conformance_lib.rejection`'s verdict
allowlist so the replay scores it a harness failure rather than a rejection
(#641's M8 fix). Check 4b calls the dispatch once per declared key and requires
it not to raise that. Behavioural, not textual, so an aliased or restructured
dispatch cannot evade it. `record.py` is **not refactored** — the rule starts
enforcing what it already does.

**The pairing must be DECLARED, not inferred**, and that is a measured finding
rather than a preference: the five files use five different naming conventions
(`*_KNOWN_KEYS`/`*_REQUIRED_KEYS`, `KNOWN_CARD_KEYS`/`REQUIRED_CARD_FIELDS`,
`RECORD_FIELD_KNOWN_KEYS`/`REQUIRED_FIELD_KEYS`, `KNOWN_KEYS`/`REQUIRED`, and
`KNOWN_KDF_KEYS` with no required set at all). A stem heuristic mis-paired six
of ten sets when prototyped. The section therefore carries an explicit pairing
table, censused two ways against the key sets discovered under `codec/`, so a
new key set with no declared pairing FAILS rather than being skipped.

**One gap the census surfaced:** `codec/vault_toml.py` declares
`KNOWN_KDF_KEYS` and no required set. Every field of Rust's `KdfSectionWire` is
non-`Option`, so all six are required; the slice adds
`REQUIRED_KDF_KEYS = KNOWN_KDF_KEYS` to make the pairing total and the claim
explicit.

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
- **Check 4 does not read text at all**, so it has none of those limits: it is
  a set comparison over AST-evaluated literal constants plus a behavioural
  probe. Its limits are different, narrower, and must be named rather than left
  to be inferred from "structural rule":
  - **It governs OPTIONAL keys only.** A *required* key losing its type check
    is a real defect this rule does not see. No measurement has observed one —
    the sweep found zero — and #678 is where that class is addressed if it ever
    is. Do not describe check 4 as covering "every key".
  - **It governs only key sets it can discover**, and discovery is by name
    shape (`KNOWN`/`REQUIRED`). A key set built dynamically, or named outside
    that shape, is invisible — not mis-reported, simply not covered. The
    two-way pairing census is what stops a *newly added* set being silently
    skipped.
  - **It says nothing about whether a case asserts the RIGHT thing.** That is
    what check 2's ambiguity control and the committed seeds are for.

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
| An optional key's behavioural case deleted | check 4, the `KNOWN − REQUIRED` census |
| A key moved from `*_REQUIRED_KEYS` into optional with no case added | check 4, the same census, the other direction |
| `check_record_value`'s `UncheckedKnownKey` fall-through replaced by a silent `pass` | check 4b, the mechanism-A totality probe |
| A `codec/` key set renamed outside the pairing table | check 4's pairing census |

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
- `codec/manifest_schema.py` (unchanged constants; read by check 4's census)
- `codec/vault_toml.py` gains `REQUIRED_KDF_KEYS` so its pairing is total
- `wire/vault_toml.py`
- `sections/registry.py`
- `core/tests/differential_replay_helpers/targets.rs` (`MIN_CORPUS_INPUTS`)
- `CLAUDE.md`, `ROADMAP.md`, the handoff

Every new source file stays under 500 lines; the section package is split in
two for that reason before it is written, not after.
