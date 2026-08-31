# Manifest Canonicality Pin — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `docs/vault-format.md` §4.2's per-rule table and two-part reader obligation executable — in the randomized Rust suite, in the clean-room Python verifier, and as a cross-language corpus — closing #578, #585, #583 and #592.

**Architecture:** One new `--diff-replay` target, `manifest_body`, mirrored on both sides (Rust `decode_manifest`/`encode_manifest`; Python new `py_decode_manifest`/`py_encode_manifest`). The Python decoder is built on a **span-recording CBOR scanner** that retains an `unknown` subtree's raw bytes instead of decoding it, because `cbor2.loads` collapses duplicate map keys and cannot reproduce them. A generated JSON corpus replays the five §6.2 rules through both languages and asserts their verdicts agree.

**Tech Stack:** Rust (stable, pinned 1.97.0) + `proptest` + `ciborium`; Python via `uv` only (never `pip`), `cbor2` from `conformance.py`'s PEP 723 header.

**Spec:** `docs/superpowers/specs/2026-08-31-manifest-canonicality-pin-design.md`

## Global Constraints

- **Worktree:** `/Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin`, branch `feature/manifest-canonicality-pin`. Run `pwd && git branch --show-current` before any `cargo`/`git` command — parallel sessions switch branches.
- **Shell state does not persist between Bash calls.** Chain `cd` in one command or use absolute paths.
- **Python is `uv` only.** Never `pip` / `pip3` / `python -m pip`.
- **`#![forbid(unsafe_code)]`** is a workspace lint. Do not introduce `unsafe`.
- **Clippy must stay clean** with `cargo clippy --release --workspace --tests -- -D warnings`.
- **Rustdoc must stay clean** with `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`. Force a non-cached run; a 5s finish is a cache hit, not a pass.
- **`conformance.py` depends on NO `secretary` code** — only the generic primitives in its PEP 723 header (`cryptography`, `pynacl`, `pqcrypto`, `argon2-cffi`, `blake3`, `cbor2`). Adding a `secretary` import destroys the property the file exists to prove. Top-level imports stay stdlib-only; these six are lazy-imported inside functions.
- **Mutation verification is mandatory for every new pin, and mutations are applied by IN-PLACE EDIT ONLY.** `cargo` compares source mtime against the artifact, so a mutation applied by a backdating operation (`mv`, `cp -p`, `rsync -a`, `touch -t/-r`) is never compiled — the suite passes and you wrongly conclude the mechanism is unpinned. Record the literal command used.
- **No magic numbers.** Every byte-length, offset and CBOR constant gets a named constant or an inline comment naming the RFC 8949 section.
- **Files stay under 500 lines where reasonable.** `conformance.py` is already 4303; if this slice's additions push a cohesive block past ~400 lines, file a split issue rather than inlining awkwardly.
- **Do not close any GitHub issue.** The repo cites fixes as `(#N)`, never `Closes #N`. Closing is a separate, human-verified step.

---

## File map

| File | Responsibility | Task |
|---|---|---|
| `core/tests/proptest.rs` | `unknown_bag_strategy()` + the three manifest strategies | T1 |
| `core/tests/python/conformance.py` | scanner primitives, `py_decode_manifest`/`py_encode_manifest`, `encode_canonical_map_raw`, corpus replay, record fix | T2, T3, T4, T6, T7 |
| `core/tests/differential_replay.rs` | Rust half of the `manifest_body` target | T4 |
| `core/tests/manifest_canonicality_kat.rs` | **new** — `#[ignore]` corpus generator + Rust replay | T5 |
| `core/tests/data/manifest_canonicality_kat.json` | **new** — the corpus fixture | T5 |
| `core/src/vault/record/…` (tests only) | permanent record-side polarity test | T7 |
| `docs/vault-format.md`, `docs/crypto-design.md` | the two frozen-spec edits | T8 |
| `README.md`, `ROADMAP.md`, `NEXT_SESSION.md` + `docs/handoffs/` | closeout | T9 |

---

## Task 1: Fold unknown bags into the three manifest proptest strategies (#578)

**Files:**
- Modify: `core/tests/proptest.rs` (`mod manifest_props`, lines ~1384-1500)
- Test: same file — `manifest_roundtrip` (existing, gains coverage) + one new probe test

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `unknown_bag_strategy() -> impl Strategy<Value = BTreeMap<String, UnknownValue>>`, used only within `mod manifest_props`.

**Why a probe test is mandatory:** without it, a strategy bug that silently produces empty bags leaves `manifest_roundtrip` green having tested nothing — which is exactly the status quo #578 records.

- [ ] **Step 1: Write the failing probe test**

Add to `mod manifest_props` in `core/tests/proptest.rs`:

```rust
    /// Positive control for Property F's forward-compat coverage (#578).
    ///
    /// `manifest_roundtrip` cannot distinguish "the unknown bags round-trip
    /// correctly" from "the strategy generated no unknown bags at all" — the
    /// exact failure #578 records, where all three strategies hardcoded
    /// `BTreeMap::new()` and the property passed for two years having never
    /// exercised the subtree path. This test asserts the corpus is
    /// non-degenerate at ALL THREE levels that carry a bag.
    #[test]
    fn unknown_bag_strategy_is_non_degenerate_at_all_three_levels() {
        use proptest::strategy::{Strategy, ValueTree};
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::deterministic();
        let (mut top, mut block, mut trash) = (0usize, 0usize, 0usize);
        const CASES: usize = 256;

        for _ in 0..CASES {
            let m = manifest_strategy()
                .new_tree(&mut runner)
                .expect("new_tree")
                .current();
            if !m.unknown.is_empty() {
                top += 1;
            }
            if m.blocks.iter().any(|b| !b.unknown.is_empty()) {
                block += 1;
            }
            if m.trash.iter().any(|t| !t.unknown.is_empty()) {
                trash += 1;
            }
        }

        assert!(top > 0, "no generated manifest carried a top-level unknown bag");
        assert!(block > 0, "no generated block entry carried an unknown bag");
        assert!(trash > 0, "no generated trash entry carried an unknown bag");
    }
```

- [ ] **Step 2: Run it and watch it fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
cargo test --release -p secretary-core --test proptest \
  unknown_bag_strategy_is_non_degenerate -- --nocapture
```

Expected: FAIL — `no generated manifest carried a top-level unknown bag` (all three
strategies still hardcode `BTreeMap::new()`).

- [ ] **Step 3: Add `unknown_bag_strategy`**

Add to `mod manifest_props`, near the other strategies. `UnknownValue` is already
re-exported from `secretary_core::vault`; add it to the module's `use` list.

```rust
    /// Five forward-compat subtree shapes, all of which a v1 decoder must
    /// ACCEPT and re-emit verbatim (`docs/vault-format.md` §4.2).
    ///
    /// Shape 5 is deliberately in NON-CANONICAL key order (`{"zz":1,"a":2}`).
    /// A canonically-ordered fixture cannot tell "emitted verbatim" apart
    /// from "re-sorted on the way out", which is the whole property #572's
    /// v2 soundness rests on — see `test_support::UNKNOWN_MAP_NONCANONICAL`.
    ///
    /// Every shape is an ACCEPTABLE one on purpose: Property F is a
    /// round-trip property and must hold unconditionally. Rejected shapes
    /// (indefinite lengths, non-shortest heads, floats, tags) belong in the
    /// `manifest_canonicality_kat` corpus, not here.
    const UNKNOWN_SUBTREE_SHAPES: [&[u8]; 5] = [
        &[0x01],                                            // uint 1
        &[0x41, 0xAA],                                      // bstr h'AA'
        &[0x62, b'h', b'i'],                                // tstr "hi"
        &[0x82, 0x01, 0x02],                                // array [1, 2]
        &[0xA2, 0x62, b'z', b'z', 0x01, 0x61, b'a', 0x02],  // {"zz":1,"a":2}
    ];

    /// Unknown-key names. The `zzz_` prefix keeps them clear of every known
    /// key at every level, which matters: a collision would make
    /// `encode_manifest` emit a signed, ambiguous manifest (#586), and
    /// Property F is not the place to trip that.
    const UNKNOWN_KEY_NAMES: [&str; 3] = ["zzz_future_a", "zzz_future_b", "zzz_future_c"];

    fn unknown_bag_strategy() -> impl Strategy<Value = BTreeMap<String, UnknownValue>> {
        prop::collection::vec(
            (0..UNKNOWN_KEY_NAMES.len(), 0..UNKNOWN_SUBTREE_SHAPES.len()),
            0..=3,
        )
        .prop_map(|picks| {
            let mut bag = BTreeMap::new();
            for (name_idx, shape_idx) in picks {
                bag.insert(
                    UNKNOWN_KEY_NAMES[name_idx].to_string(),
                    UnknownValue::from_canonical_cbor(UNKNOWN_SUBTREE_SHAPES[shape_idx])
                        .expect("UNKNOWN_SUBTREE_SHAPES entries are all valid"),
                );
            }
            bag
        })
    }
```

- [ ] **Step 4: Wire it into all three strategies**

In `block_entry_strategy`, `trash_entry_strategy` and `manifest_strategy`, replace
each `unknown: BTreeMap::new(),` with the generated bag. Each strategy's tuple
gains `unknown_bag_strategy()` as a trailing element and its `prop_map` closure
gains a matching trailing binding named `unknown`; the struct literal becomes
`unknown,`.

Note `block_entry_strategy` already has a 7-element tuple and a `prop_filter`
before its `prop_map` — the filter's closure pattern gains a trailing `_`.
`manifest_strategy` has a 6-element tuple and no filter.

- [ ] **Step 5: Run the probe and Property F**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
cargo test --release -p secretary-core --test proptest \
  unknown_bag_strategy_is_non_degenerate -- --nocapture
cargo test --release -p secretary-core --test proptest manifest_roundtrip -- --nocapture
```

Expected: both PASS.

- [ ] **Step 6: Mutation-verify the new coverage**

In-place edit only. Temporarily change `manifest_strategy`'s `unknown` back to
`BTreeMap::new()` and re-run the probe: it MUST fail with "no generated manifest
carried a top-level unknown bag". Restore by in-place edit (never `mv`/`cp -p` —
see Global Constraints). Record the command used in the commit message.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git add core/tests/proptest.rs
git commit -m "test(core): Property F generates forward-compat unknown bags (#578)"
```

---

## Task 2: Span-recording CBOR scanner primitives in conformance.py

**Files:**
- Modify: `core/tests/python/conformance.py` (new block in the differential-replay
  helpers region, after `_reject_floats_and_tags_py`)

**Interfaces:**
- Consumes: nothing.
- Produces, used by T3/T4/T6/T7:
  - `_decode_head(buf: bytes, pos: int) -> tuple[int, int, int | None, int]` — `(major, ai, arg, head_len)`; `arg` is `None` for the indefinite form.
  - `_scan_item(buf: bytes, pos: int) -> int` — offset one past the item at `pos`.
  - `_scan_map_entries(buf: bytes, pos: int) -> tuple[list[tuple[tuple[int,int], tuple[int,int]]], int]` — `((key_start,key_end),(val_start,val_end))` pairs **in wire order, repeats preserved**, plus the end offset.
  - `_check_canonical_item(buf: bytes, pos: int) -> int` — raises `ValueError` on a §6.2 rule 2/3/4 violation; returns the end offset.

**This code is already prototyped and passes 25 checks** covering every CBOR major type, all four indefinite-length forms, both non-shortest-form classes, floats and tags. Transcribe it as given.

- [ ] **Step 1: Write the failing unit tests**

Add a new section to `conformance.py`. Follow the file's existing
`section*() -> tuple[bool, list[str]]` convention so `main()` can register it.

```python
def section_cbor_scanner_units() -> tuple[bool, list[str]]:
    """Unit coverage for the span-recording CBOR scanner (§4.2 support).

    The scanner exists because `cbor2.loads` collapses duplicate map keys
    into a `dict` and therefore cannot reproduce them, while
    `docs/vault-format.md` §4.2 part (1) requires a reader to reproduce an
    unknown subtree's entry order AND its repeated entries. See #592.
    """
    import cbor2

    issues: list[str] = []

    # --- _scan_item consumes exactly one item, for every shape cbor2 emits
    for label, value in [
        ("uint", 1),
        ("large uint", 10**12),
        ("negative", -5000),
        ("bstr", b"\xaa" * 300),
        ("tstr", "hello" * 100),
        ("array", [1, [2, 3], "x"]),
        ("map", {"a": 1, "b": [1, 2]}),
        ("nested map", {"a": {"b": {"c": [1, 2, 3]}}}),
        ("simple values", [True, False, None]),
    ]:
        enc = cbor2.dumps(value)
        end = _scan_item(enc, 0)
        if end != len(enc):
            issues.append(f"_scan_item {label}: consumed {end} of {len(enc)} bytes")

    # --- indefinite-length forms SCAN (structure); canonicality is a
    # --- separate rule checked by _check_canonical_item below.
    for label, raw in [
        ("indefinite map", bytes([0xBF, 0x61, 0x61, 0x01, 0xFF])),
        ("indefinite array", bytes([0x9F, 0x01, 0x02, 0xFF])),
        ("indefinite tstr", bytes([0x7F, 0x61, 0x78, 0xFF])),
        ("indefinite bstr", bytes([0x5F, 0x41, 0xAA, 0xFF])),
    ]:
        end = _scan_item(raw, 0)
        if end != len(raw):
            issues.append(f"_scan_item {label}: consumed {end} of {len(raw)} bytes")

    # --- THE point: duplicates and wire order survive the scan
    dup = bytes([0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02])   # {"a":1,"a":2}
    entries, end = _scan_map_entries(dup, 0)
    if len(entries) != 2:
        issues.append(f"duplicate-key map: {len(entries)} entries, expected 2 (a dict gives 1)")
    if end != len(dup):
        issues.append(f"duplicate-key map: end {end}, expected {len(dup)}")

    noncanon = bytes([0xA2, 0x62, 0x7A, 0x7A, 0x01, 0x61, 0x61, 0x02])  # {"zz":1,"a":2}
    entries, _ = _scan_map_entries(noncanon, 0)
    keys = [noncanon[ks:ke] for (ks, ke), _ in entries]
    if keys != [b"\x62zz", b"\x61a"]:
        issues.append(f"wire order not preserved: {keys!r}")

    # --- _check_canonical_item: the §4.2 five-rule table, row by row.
    # Rules 1 and 5 are NOT enforced inside an unknown subtree; 2, 3, 4 are.
    for label, raw in [("rule 1 key order", noncanon), ("rule 5 duplicate key", dup)]:
        try:
            _check_canonical_item(raw, 0)
        except ValueError as e:
            issues.append(f"{label} must be ACCEPTED inside an unknown subtree, got: {e}")

    for label, raw in [
        ("rule 2 indefinite map", bytes([0xBF, 0x61, 0x61, 0x01, 0xFF])),
        ("rule 2 indefinite tstr", bytes([0xA1, 0x61, 0x61, 0x7F, 0x61, 0x78, 0xFF])),
        ("rule 2 indefinite bstr", bytes([0xA1, 0x61, 0x61, 0x5F, 0x41, 0xAA, 0xFF])),
        ("rule 2 indefinite array", bytes([0xA1, 0x61, 0x61, 0x9F, 0x01, 0xFF])),
        ("rule 3 non-shortest int", bytes([0xA1, 0x61, 0x61, 0x18, 0x01])),
        ("rule 3 non-shortest map length", bytes([0xB8, 0x01, 0x61, 0x61, 0x01])),
        ("rule 4 float", cbor2.dumps({"a": 1.5})),
        ("rule 4 tag", cbor2.dumps(cbor2.CBORTag(24, b"x"))),
    ]:
        try:
            _check_canonical_item(raw, 0)
            issues.append(f"{label} must be REJECTED, was accepted")
        except ValueError:
            pass

    return (not issues), issues
```

Register it in `main()` alongside the other sections, following the existing
registration pattern in that function.

- [ ] **Step 2: Run it and watch it fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/conformance.py
```

Expected: FAIL with `NameError: name '_scan_item' is not defined`.

- [ ] **Step 3: Add the scanner primitives**

Insert before `section_cbor_scanner_units`. This is the prototyped, tested code.

```python
# ---------------------------------------------------------------------------
# Span-recording CBOR scanner (§4.2 forward-compat subtree support)
# ---------------------------------------------------------------------------
# `cbor2.loads` decodes a CBOR map into a `dict`, which COLLAPSES duplicate
# keys and cannot reproduce them.  `docs/vault-format.md` §4.2 makes it a
# reader MUST to reproduce an unknown subtree's entry order *and* its
# repeated entries, so a `dict`-based reader is structurally non-conformant:
# it rejects (via the §4.3 step-4 byte comparison) manifests the Rust
# decoder accepts.  See #592, and `core/src/vault/manifest/decode/tests.rs`'s
# `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`.
#
# These four functions are the conformant alternative: they record BYTE
# SPANS into the input rather than decoding, so a subtree can be re-emitted
# verbatim.  A `Span` is a `(start, end)` offset pair -- never a copy.

CBOR_BREAK = 0xFF          # RFC 8949 §3.2.1: the "break" stop code.
CBOR_AI_INDEFINITE = 31    # RFC 8949 §3: additional info 31 == indefinite.


def _decode_head(buf: bytes, pos: int) -> tuple[int, int, int | None, int]:
    """Decode the CBOR head at `pos` (RFC 8949 §3).

    Returns `(major, ai, arg, head_len)`.  `arg` is None for the
    indefinite-length form; `head_len` counts the initial byte plus any
    argument bytes.
    """
    if pos >= len(buf):
        raise ValueError(f"truncated CBOR head at offset {pos}")
    ib = buf[pos]
    major, ai = ib >> 5, ib & 0x1F
    if ai < 24:
        return major, ai, ai, 1
    if ai == 24:
        n = 1
    elif ai == 25:
        n = 2
    elif ai == 26:
        n = 4
    elif ai == 27:
        n = 8
    elif ai == CBOR_AI_INDEFINITE:
        return major, ai, None, 1
    else:
        raise ValueError(f"reserved additional-info {ai} at offset {pos}")
    if pos + 1 + n > len(buf):
        raise ValueError(f"truncated {n}-byte argument at offset {pos}")
    return major, ai, int.from_bytes(buf[pos + 1 : pos + 1 + n], "big"), 1 + n


def _scan_item(buf: bytes, pos: int) -> int:
    """Return the offset one past the single CBOR item starting at `pos`.

    Structure only -- indefinite-length forms scan successfully here and are
    rejected by `_check_canonical_item`, because the two are different rules
    (§4.2 table rows 2 and 5 have opposite verdicts).
    """
    major, ai, arg, head = _decode_head(buf, pos)
    p = pos + head

    if major in (0, 1):                       # uint / negative int
        return p
    if major == 7:                            # simple value / float
        if ai == CBOR_AI_INDEFINITE:
            raise ValueError(f"unexpected break at offset {pos}")
        return p
    if major in (2, 3):                       # byte string / text string
        if arg is None:                       # indefinite: definite chunks to break
            while True:
                if p >= len(buf):
                    raise ValueError("unterminated indefinite-length string")
                if buf[p] == CBOR_BREAK:
                    return p + 1
                cmaj, _, carg, chead = _decode_head(buf, p)
                if cmaj != major or carg is None:
                    raise ValueError(f"bad chunk in indefinite-length string at {p}")
                p += chead + carg
        if p + arg > len(buf):
            raise ValueError(f"string length {arg} overruns buffer at offset {pos}")
        return p + arg
    if major in (4, 5):                       # array / map
        per = 1 if major == 4 else 2
        if arg is None:
            while True:
                if p >= len(buf):
                    raise ValueError("unterminated indefinite-length array/map")
                if buf[p] == CBOR_BREAK:
                    return p + 1
                for _ in range(per):
                    p = _scan_item(buf, p)
        for _ in range(arg * per):
            p = _scan_item(buf, p)
        return p
    if major == 6:                            # tag
        if arg is None:
            raise ValueError(f"indefinite-length tag at offset {pos}")
        return _scan_item(buf, p)
    raise ValueError(f"unreachable CBOR major type {major}")


def _scan_map_entries(
    buf: bytes, pos: int
) -> tuple[list[tuple[tuple[int, int], tuple[int, int]]], int]:
    """Entry spans for the CBOR map at `pos`, plus the offset one past it.

    Each element is `((key_start, key_end), (value_start, value_end))`.
    Entry ORDER and REPEATED entries are preserved -- the two properties a
    `dict` destroys and §4.2 part (1) requires a reader to reproduce.
    """
    major, _, arg, head = _decode_head(buf, pos)
    if major != 5:
        raise ValueError(f"expected a CBOR map at offset {pos}, got major type {major}")
    p = pos + head
    out: list[tuple[tuple[int, int], tuple[int, int]]] = []
    if arg is None:
        while True:
            if p >= len(buf):
                raise ValueError("unterminated indefinite-length map")
            if buf[p] == CBOR_BREAK:
                return out, p + 1
            ks = p
            ke = _scan_item(buf, p)
            ve = _scan_item(buf, ke)
            out.append(((ks, ke), (ke, ve)))
            p = ve
    for _ in range(arg):
        ks = p
        ke = _scan_item(buf, p)
        ve = _scan_item(buf, ke)
        out.append(((ks, ke), (ke, ve)))
        p = ve
    return out, p


def _shortest_ai(arg: int) -> int:
    """The additional-info value RFC 8949 §4.2.1 requires for `arg`."""
    if arg < 24:
        return arg
    if arg < 0x100:
        return 24
    if arg < 0x10000:
        return 25
    if arg < 0x100000000:
        return 26
    return 27


def _check_canonical_item(buf: bytes, pos: int) -> int:
    """Enforce crypto-design §6.2 rules 2, 3 and 4 over the item at `pos`.

    Rule 2 (definite lengths), rule 3 (shortest-form heads), rule 4 (no
    floats, no tags).  Returns the offset one past the item; raises
    `ValueError` naming the rule and offset on any violation.

    Rules 1 and 5 -- map-key order and duplicate keys -- are deliberately
    NOT checked.  `docs/vault-format.md` §4.2's table marks both unenforced
    inside a forward-compat `unknown` subtree, and the Rust decoder accepts
    both (`decode/tests.rs`'s
    `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`).
    Checking them here would reintroduce exactly the #592 divergence this
    scanner exists to remove.
    """
    major, ai, arg, head = _decode_head(buf, pos)
    if ai == CBOR_AI_INDEFINITE:
        raise ValueError(f"rule 2: indefinite-length item at offset {pos}")
    if major == 6:
        raise ValueError(f"rule 4: CBOR tag at offset {pos}")
    if major == 7:
        if ai in (25, 26, 27):        # float16 / float32 / float64
            raise ValueError(f"rule 4: float at offset {pos}")
        if ai > 24:
            raise ValueError(f"rule 3: non-shortest simple value at offset {pos}")
        return pos + head
    if ai != _shortest_ai(arg):
        raise ValueError(f"rule 3: non-shortest-form head at offset {pos} (ai={ai})")
    p = pos + head
    if major in (0, 1):
        return p
    if major in (2, 3):
        return p + arg
    per = 1 if major == 4 else 2
    for _ in range(arg * per):
        p = _check_canonical_item(buf, p)
    return p
```

- [ ] **Step 4: Run the unit section**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/conformance.py
```

Expected: PASS, with the new section reported alongside the others.

- [ ] **Step 5: Mutation-verify**

In-place edit only. Make `_check_canonical_item` return early without checking
`ai == CBOR_AI_INDEFINITE`; the four rule-2 rows MUST fail. Restore in place.
Then make `_scan_map_entries` build a `dict` instead of a list; the duplicate-key
row MUST fail. Restore in place.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git add core/tests/python/conformance.py
git commit -m "test(conformance): span-recording CBOR scanner for §4.2 subtrees (#585, #592)"
```

---

## Task 3: py_decode_manifest / py_encode_manifest, anchored on the golden vault (#585)

**Files:**
- Modify: `core/tests/python/conformance.py` — new decoder/encoder pair, plus the
  golden-vault call site at `conformance.py:1577`

**Interfaces:**
- Consumes: T2's `_scan_map_entries`, `_check_canonical_item`, `_scan_item`, `_decode_head`.
- Produces:
  - `encode_canonical_map_raw(entries: list[tuple[str, bytes]]) -> bytes`
  - `py_decode_manifest(data: bytes) -> dict` — `unknown` maps key -> **raw `bytes`**
  - `py_encode_manifest(parsed: dict) -> bytes`

**Ordering constraint from the spec (§9), and it is not negotiable:** the new
decoder must re-derive `golden_vault_001`'s manifest body BEFORE any corpus row
in T5/T6 is trusted. New clean-room code asserting equality with a frozen format
is only credible once it agrees with the frozen vault.

`encode_canonical_map` (`conformance.py:944`) cannot be reused: it builds a
`dict` and calls `cbor2.dumps(d, canonical=True)`, so it re-sorts and cannot
carry pre-encoded value bytes.

- [ ] **Step 1: Write the failing test — golden vault first**

Replace the bare decode at `conformance.py:1577`:

```python
        manifest_pt = cbor2.loads(manifest_pt_bytes)
```

with:

```python
        # §4.2/§4.3 strict decode, not a bare `cbor2.loads` (#585). The
        # strict decoder enforces the five array sort disciplines, rejects
        # duplicate keys at every KNOWN level, and retains each unknown
        # subtree's raw bytes so it can be re-emitted verbatim (#592).
        manifest_pt = py_decode_manifest(manifest_pt_bytes)
```

Then add a re-encode assertion immediately after the existing field
cross-checks in `section2_golden_vault_001`:

```python
    # The §4.3 step-4 obligation, exercised against the frozen fixture:
    # re-encoding the parsed manifest must reproduce the input byte for byte.
    reencoded = py_encode_manifest(manifest_pt)
    if reencoded != manifest_pt_bytes:
        issues.append(
            "manifest body re-encode is not byte-identical: "
            f"{len(reencoded)} bytes out vs {len(manifest_pt_bytes)} in"
        )
```

- [ ] **Step 2: Run it and watch it fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/conformance.py
```

Expected: FAIL with `NameError: name 'py_decode_manifest' is not defined`.

- [ ] **Step 3: Add `encode_canonical_map_raw`**

Place beside `encode_canonical_map` (`conformance.py:944`).

```python
def encode_canonical_map_raw(entries: list[tuple[str, bytes]]) -> bytes:
    """Encode a canonical CBOR map from PRE-ENCODED value bytes.

    `encode_canonical_map` cannot serve this: it builds a `dict` and hands
    it to `cbor2.dumps(..., canonical=True)`, which re-sorts every nested
    map.  A retained forward-compat subtree must be emitted EXACTLY as it
    arrived (§4.2 part 1), so its bytes are spliced rather than re-encoded.

    Keys are text strings sorted by RFC 8949 §4.2.1 order -- length first,
    then bytewise -- computed on the encoded key, which for a text key is
    equivalent to `(len(utf8), utf8)`.
    """
    import cbor2

    encoded = [(cbor2.dumps(k), v) for k, v in entries]
    encoded.sort(key=lambda kv: (len(kv[0]), kv[0]))

    n = len(encoded)
    if n < 24:
        head = bytes([0xA0 | n])
    elif n < 0x100:
        head = bytes([0xB8, n])
    elif n < 0x10000:
        head = bytes([0xB9]) + n.to_bytes(2, "big")
    else:
        head = bytes([0xBA]) + n.to_bytes(4, "big")

    out = bytearray(head)
    for k, v in encoded:
        out += k
        out += v
    return bytes(out)
```

- [ ] **Step 4: Add the decoder and encoder**

```python
# Known top-level manifest body keys (§4.2). Anything else is a
# forward-compat unknown and is retained as raw bytes.
MANIFEST_KNOWN_KEYS = frozenset({
    "manifest_version", "vault_uuid", "format_version", "suite_id",
    "owner_user_uuid", "vector_clock", "blocks", "trash", "kdf_params",
})


def py_decode_manifest(data: bytes) -> dict:
    """Strict §4.2/§4.3 manifest BODY decoder matching
    `manifest/decode/mod.rs::decode_manifest`.

    Validates:
    - Top level is a CBOR map with text-string keys.
    - No duplicate key at the top level or in any nested KNOWN map (#568,
      #573) -- checked on the SPAN list, so a repeat is visible.
    - No float and no CBOR tag anywhere (§6.2 rule 4).
    - Known values are canonical per §6.2 rules 2 and 3.
    - Unknown subtrees are checked for rules 2, 3 and 4 only, and their raw
      bytes are RETAINED so they can be re-emitted verbatim (rules 1 and 5
      are unenforced there -- §4.2's table).

    The returned dict maps `"unknown"` to `{key: raw_bytes}`.  That
    asymmetry is the design: a decoded object cannot reproduce what §4.2
    requires reproducing (#592).
    """
    import cbor2

    entries, end = _scan_map_entries(data, 0)
    if end != len(data):
        raise ValueError(f"trailing bytes after manifest map: {len(data) - end}")

    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()

    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != 3:
            raise ValueError(f"manifest map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise ValueError(f"duplicate manifest key: {key!r}")
        seen.add(key)

        # Rules 2/3/4 apply to every value, known or unknown.
        _check_canonical_item(data, vs)

        if key in MANIFEST_KNOWN_KEYS:
            out[key] = cbor2.loads(data[vs:ve])
        else:
            unknown[key] = data[vs:ve]

    for required in ("manifest_version", "vault_uuid", "owner_user_uuid"):
        if required not in out:
            raise KeyError(f"manifest missing required field: {required!r}")

    # The five §4.2 array sort disciplines. `encode_manifest` sorts all five
    # on output, so an array arriving out of order is rejected -- a WIDER
    # rejection surface than plain canonical CBOR, and deliberate.
    _check_sorted(out.get("vector_clock", []), "device_uuid", "vector_clock")
    _check_sorted(out.get("blocks", []), "block_uuid", "blocks")
    _check_sorted(out.get("trash", []), "block_uuid", "trash")
    for i, blk in enumerate(out.get("blocks", [])):
        recips = blk.get("recipients", [])
        if recips != sorted(recips):
            raise ValueError(f"blocks[{i}].recipients is not sorted")
        _check_sorted(
            blk.get("vector_clock_summary", []),
            "device_uuid",
            f"blocks[{i}].vector_clock_summary",
        )

    out["unknown"] = unknown
    return out


def _check_sorted(rows: list, key: str, label: str) -> None:
    """Assert `rows` is sorted ascending by `row[key]` (§4.2)."""
    ids = [r[key] for r in rows]
    if ids != sorted(ids):
        raise ValueError(f"{label} is not sorted by {key}")


def py_encode_manifest(parsed: dict) -> bytes:
    """Re-encode a `py_decode_manifest` result to canonical CBOR.

    Known values go through `cbor2.dumps(..., canonical=True)`; unknown
    subtrees are spliced from their retained bytes, never re-encoded.
    """
    import cbor2

    entries: list[tuple[str, bytes]] = [
        (k, cbor2.dumps(v, canonical=True))
        for k, v in parsed.items()
        if k != "unknown"
    ]
    entries.extend(parsed.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)
```

- [ ] **Step 5: Run against the golden vault**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/conformance.py
```

Expected: PASS, including the new byte-identical re-encode assertion. **If this
fails, stop and fix before proceeding** — every later task depends on this
decoder being right.

- [ ] **Step 6: Mutation-verify**

In-place edit only. Delete the `_check_sorted(out.get("blocks", ...))` call and
confirm nothing reds (the golden vault's arrays have ≤1 element, so they are only
*vacuously* sorted — this is expected and is exactly why T5's corpus exists).
**Record that result**: it is evidence for the spec's §10 risk row, not a
failure. Restore in place.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git add core/tests/python/conformance.py
git commit -m "test(conformance): strict §4.2/§4.3 manifest body decoder (#585)"
```

---

## Task 4: Wire the `manifest_body` differential-replay target

**Files:**
- Modify: `core/tests/python/conformance.py` — `run_diff_replay` (line ~4103)
- Modify: `core/tests/differential_replay.rs` — the target list (line ~30) and the
  dispatch match (line ~92)

**Interfaces:**
- Consumes: T3's `py_decode_manifest` / `py_encode_manifest`.
- Produces: the `"manifest_body"` target name, used by T6.

Note the existing `manifest_file` target is the §4.1 **envelope**
(`decode_manifest_file`/`encode_manifest_file`). This adds the §4.2/§4.3 **body**,
which no target covers on either side.

- [ ] **Step 1: Add the Python arm**

In `run_diff_replay`, after the `manifest_file` arm:

```python
        elif target == "manifest_body":
            parsed = py_decode_manifest(data)
            reencoded = py_encode_manifest(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
```

- [ ] **Step 2: Add the Rust arm**

In `core/tests/differential_replay.rs`, add `"manifest_body"` to the target list
constant, and to the dispatch match:

```rust
        "manifest_body" => vault::manifest::decode_manifest(bytes)
            .and_then(|m| vault::manifest::encode_manifest(&m))
            .map(|b| b.expose().to_vec()),
```

Match the surrounding arms' exact error-mapping shape; `encode_manifest` returns
`SecretBytes`, so `.expose().to_vec()` is required where `manifest_file`'s
`encode_manifest_file` returns a plain `Vec<u8>`.

- [ ] **Step 3: Verify the target round-trips**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
cargo check --release --features differential-replay --tests -p secretary-core
cargo test --release --workspace --features differential-replay
```

Expected: both clean. Note `--workspace` alone builds **neither** — the feature is
off by default and no CI job enables it.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git add core/tests/python/conformance.py core/tests/differential_replay.rs
git commit -m "test(core): add manifest_body differential-replay target (#585, #583)"
```

---

## Task 5: The five-rule corpus and its Rust replay (#583)

**Files:**
- Create: `core/tests/manifest_canonicality_kat.rs`
- Create: `core/tests/data/manifest_canonicality_kat.json` (generated)

**Interfaces:**
- Consumes: nothing from other tasks (uses `encode_manifest`/`decode_manifest` directly).
- Produces: the fixture, consumed by T6.

**Fixture-diff note:** the standing check `git diff main...HEAD --stat --
core/tests/data/` must be EMPTY is about not changing the on-disk format. This
task adds exactly one new path and modifies none; the check becomes "exactly one
added path, zero modified".

- [ ] **Step 1: Write the failing replay test**

Create `core/tests/manifest_canonicality_kat.rs` with a replay test that loads the
(not-yet-existing) fixture and asserts each row's verdict:

```rust
//! Cross-language corpus for `docs/vault-format.md` §4.2's per-rule table.
//!
//! Each row splices one subtree into a manifest's top-level `unknown` bag
//! and records the verdict `decode_manifest` gives it. The same fixture is
//! replayed by `core/tests/python/conformance.py`, so the two
//! implementations' acceptance sets are compared row by row rather than
//! asserted to match in prose (#583, #592).

use std::collections::BTreeMap;
use std::path::PathBuf;

use secretary_core::vault::manifest::{decode_manifest, encode_manifest, Manifest};
use secretary_core::vault::UnknownValue;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/manifest_canonicality_kat.json")
}

#[test]
fn manifest_canonicality_kat_replays() {
    let raw = std::fs::read_to_string(fixture_path()).expect("fixture must exist -- generate it with:\n  cargo test --release --workspace -- --ignored generate_manifest_canonicality_kat --nocapture");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture JSON");
    let rows = doc["rows"].as_array().expect("rows array");
    assert!(!rows.is_empty(), "corpus must not be empty");

    let mut accepted = 0usize;
    for row in rows {
        let label = row["label"].as_str().expect("label");
        let body = hex::decode(row["manifest_body_hex"].as_str().expect("body")).expect("hex");
        let expect_accept = row["expect_accept"].as_bool().expect("expect_accept");
        let got = decode_manifest(&body).is_ok();
        assert_eq!(
            got, expect_accept,
            "row {label:?}: expected accept={expect_accept}, got accept={got}"
        );
        if expect_accept {
            accepted += 1;
        }
    }
    assert!(
        accepted > 0,
        "corpus has no ACCEPT rows -- it would pass by rejecting everything"
    );
}
```

Decode the hex with `hex::decode` (the `hex = "0.4"` dev-dependency the sibling
KAT tests already use — see `core/tests/sync_kat.rs:166`); do **not** hand-roll a
helper. Add the `#[ignore]` generator in the same file, following
`core/tests/conformance_kat.rs:317`'s idiom. `serde_json` is a dev-dependency
with `preserve_order` enabled, so the generated JSON keeps a stable key order and
its diff stays reviewable. The generator builds a
`minimal` manifest, splices each of the seven subtrees (the five rule rows plus
two canonical controls) into the top-level `unknown` bag by the
splice-over-a-needle technique used in
`decode/tests.rs::unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`,
records the resulting body as hex plus the observed verdict, and writes the JSON.

Rows, with the verdicts already measured against this decoder:

| label | subtree bytes | expect_accept |
|---|---|---|
| `control_canonical` | `A1 61 61 01` | true |
| `control_array` | `82 01 02` | true |
| `rule1_key_order` | `A2 62 7A 7A 01 61 61 02` | true |
| `rule5_duplicate_key` | `A2 61 61 01 61 61 02` | true |
| `rule2_indefinite_map` | `BF 61 61 01 FF` | false |
| `rule3_non_shortest_int` | `A1 61 61 18 01` | false |
| `rule4_float` | `A1 61 61 FA 3F C0 00 00` | false |

- [ ] **Step 2: Run it and watch it fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
cargo test --release -p secretary-core --test manifest_canonicality_kat
```

Expected: FAIL — `fixture must exist`.

- [ ] **Step 3: Generate the fixture**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
cargo test --release -p secretary-core --test manifest_canonicality_kat -- \
  --ignored generate_manifest_canonicality_kat --nocapture
```

- [ ] **Step 4: Human-review the generated JSON, then re-run the replay**

Read the fixture. Every `expect_accept` must match the table above. A generator
that writes whatever the decoder happens to do would make the replay vacuous —
the table is the specification, the generator is not.

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
cargo test --release -p secretary-core --test manifest_canonicality_kat
```

Expected: PASS.

- [ ] **Step 5: Mutation-verify**

In-place edit only. Flip `rule5_duplicate_key`'s `expect_accept` to `false` in the
fixture; the replay MUST fail. Restore in place.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git add core/tests/manifest_canonicality_kat.rs core/tests/data/manifest_canonicality_kat.json
git commit -m "test(core): five-rule manifest canonicality corpus (#583)"
```

---

## Task 6: Python corpus replay + the naive-reader positive control (#583, #592)

**Files:**
- Modify: `core/tests/python/conformance.py` — new section

**Interfaces:**
- Consumes: T3's `py_decode_manifest`, T5's fixture.
- Produces: nothing downstream.

**The positive control is the point.** Replaying the corpus through the strict
reader alone proves it agrees with Rust. Replaying it *also* through a
deliberately naive `cbor2.loads` reader, and asserting that one **diverges on the
rule-5 row**, proves the corpus can tell the two strategies apart rather than
passing vacuously.

- [ ] **Step 1: Write the failing section**

```python
def section_manifest_canonicality_kat() -> tuple[bool, list[str]]:
    """Replay `manifest_canonicality_kat.json` -- the §4.2 per-rule table.

    Two readers, one corpus:

    1. `py_decode_manifest` (byte-retaining) MUST agree with the recorded
       Rust verdict on every row.  That is the "two conformant readers
       accept the same set" property §4.2 states in prose (#583).
    2. A deliberately naive `cbor2.loads` reader MUST DIVERGE on the
       duplicate-key row.  This is a POSITIVE CONTROL: without it, a corpus
       that happened to contain no discriminating row would pass and prove
       nothing (#592).
    """
    import cbor2

    path = Path(__file__).resolve().parents[1] / "data" / "manifest_canonicality_kat.json"
    doc = load_json_fixture(path, "manifest_canonicality_kat.json")
    rows = doc["rows"]
    issues: list[str] = []
    if not rows:
        return False, ["corpus is empty"]

    def naive_accepts(body: bytes) -> bool:
        """The reader crypto-design §6.2 currently points an implementer at."""
        try:
            decoded = cbor2.loads(body)
            return cbor2.dumps(decoded, canonical=True) == body
        except Exception:
            return False

    divergences: list[str] = []
    for row in rows:
        label, body = row["label"], bytes.fromhex(row["manifest_body_hex"])
        expected = row["expect_accept"]

        try:
            py_decode_manifest(body)
            strict = True
        except Exception:
            strict = False
        if strict != expected:
            issues.append(
                f"row {label!r}: strict reader accept={strict}, Rust recorded {expected}"
            )

        if naive_accepts(body) != expected:
            divergences.append(label)

    if "rule5_duplicate_key" not in divergences:
        issues.append(
            "positive control failed: the naive cbor2.loads reader did NOT diverge "
            "on rule5_duplicate_key, so this corpus cannot distinguish a "
            "byte-retaining reader from a dict-based one (#592)"
        )

    return (not issues), issues
```

Register it in `main()`.

- [ ] **Step 2: Run it and watch it fail before T5's fixture is present**

If T5 is already committed the section should pass; to see it fail, temporarily
rename the fixture in place, run, then restore.

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/conformance.py
```

- [ ] **Step 3: Run the full verifier**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/conformance.py
```

Expected: PASS, all sections.

- [ ] **Step 4: Mutation-verify the control**

In-place edit only. Change `naive_accepts` to call `py_decode_manifest` instead;
the positive control MUST fail with "the naive cbor2.loads reader did NOT
diverge". Restore in place. This proves the control is live rather than
tautological.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git add core/tests/python/conformance.py
git commit -m "test(conformance): replay the §4.2 corpus through both reader strategies (#583, #592)"
```

---

## Task 7: Close the LIVE divergence in the shipped record decoder (#592)

**Files:**
- Modify: `core/tests/python/conformance.py` — `py_decode_record`, `py_encode_record`,
  and delete the no-op `_check_no_duplicate_keys`
- Modify: `core/src/vault/record.rs` (its `mod tests`) — permanent polarity test

**Interfaces:**
- Consumes: T2's scanner primitives.
- Produces: nothing downstream.

**This task exists because of a measurement, not a hunch.** Against the shipped
`conformance.py` at `e29cb216`, with a subtree spliced into a record's `unknown` bag:

| subtree | Rust `record::decode` | shipped `py_decode_record` |
|---|---|---|
| `A2 61 61 01 61 61 02` (`{"a":1,"a":2}`) | **ACCEPT** | **REJECT** |
| `A2 62 7A 7A 01 61 61 02` (`{"zz":1,"a":2}`) | **ACCEPT** | **REJECT** |
| `A1 61 61 01` (control) | accept | accept |

Both rows diverge for records — the order row too, because `py_encode_record`
re-sorts the subtree through the canonical-map path. The `record` target is driven
by the fuzz harness's differential replay, so this is a false finding waiting to
happen.

`_check_no_duplicate_keys` is a **no-op whose body is `pass`**, and its docstring
argues that the canonical re-encode check provides the protection. Every sentence
is true and the conclusion is still wrong for `unknown` subtrees: collapse-then-
mismatch is a **rejection** mechanism, while §4.2 requires **acceptance plus
verbatim reproduction**. Delete it rather than leave a no-op asserting a guarantee
it does not provide.

- [ ] **Step 1: Write the failing Rust polarity test**

Add to `core/src/vault/record.rs`'s `mod tests` — the record-side twin of
`unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`. Model it on
that test's structure (splice over a needle in the encoded bytes; assert the six
encoding-level shapes REJECT and the two order-carrying shapes ACCEPT), and give
it a doc comment saying it is the ground truth the Python decoder is matched
against, citing #592.

- [ ] **Step 2: Run it**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
cargo test --release -p secretary-core --lib record::tests
```

Expected: PASS (this documents existing Rust behaviour; it is the Python side that
is wrong).

- [ ] **Step 3: Write the failing Python test**

Add to `conformance.py` a section asserting `py_decode_record` accepts both
order-carrying subtrees inside an `unknown` bag, built by the same splice
technique.

- [ ] **Step 4: Run it and watch it fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/conformance.py
```

Expected: FAIL — `record is not in canonical CBOR form` on both rows.

- [ ] **Step 5: Retain unknown-subtree bytes in the record decoder**

Rework `py_decode_record` to scan the top-level map with `_scan_map_entries`,
dispatching known keys to `cbor2.loads` and retaining unknown values as raw
bytes; check rules 2/3/4 on every value with `_check_canonical_item`. Rework
`py_encode_record` to splice those retained bytes via `encode_canonical_map_raw`.
Delete `_check_no_duplicate_keys` and its single call site, replacing the
guarantee it claimed with the span-list duplicate check.

- [ ] **Step 6: Run the full verifier and the differential replay**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/conformance.py
cargo test --release --workspace --features differential-replay
```

Expected: both PASS, including `differential_replay_full_corpus`.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git add core/tests/python/conformance.py core/src/vault/record.rs
git commit -m "fix(conformance): retain unknown-subtree bytes in the record decoder (#592)"
```

---

## Task 8: The two frozen-spec edits, with a tabulated two-document sweep (#592)

**Files:**
- Modify: `docs/vault-format.md` §4.2
- Modify: `docs/crypto-design.md` §6.2

**Interfaces:** none — documentation only. **No byte on disk changes.**

**Read `docs/handoffs/2026-08-29-manifest-closeout-shipped.md` §3 before starting.**
The previous slice hit **seven** instances of the two-audience pattern (a sentence
true for "this reader" being false for "a future writer"), and **five of the seven
were created by the fix for the previous one**. A spot fix here is how instance
eight gets made.

- [ ] **Step 1: Add the §4.2 implementation note**

State: a reader MUST NOT decode an unknown subtree into a mapping type that
collapses duplicate keys; the conformant strategy is to retain the subtree's
bytes and re-emit them. Name the concrete trap (`cbor2.loads` returning a `dict`)
so a clean-room implementer meets it in the document rather than in a failing
gate. Keep it short — this is a note, not a new normative rule; the MUST it
explains is already there.

- [ ] **Step 2: Scope the §6.2 `canonical=True` recommendation**

crypto-design §6.2 recommends `cbor2.dumps(record, canonical=True)`. Scope it to
**authoring your own bytes**, explicitly not to re-emitting someone else's:
`canonical=True` re-sorts nested maps, so it breaks verbatim re-emission of an
out-of-order subtree. Verified: `cbor2.dumps(d, canonical=True) != input` for
`{"zz":1,"a":2}`.

- [ ] **Step 3: Run the sweep and TABULATE it**

Sweep both frozen documents plus `docs/threat-model.md` and all eleven ADRs for
terms touching this seam: `canonical=True`, `duplicate`, `key order`, `re-emit`,
`retain`, `raw input bytes`, `unknown`, `forward-compat`, `verbatim`.

Produce a table of **every hit with its verdict** — including the negatives. An
untabulated "found nothing" is not a result; it is indistinguishable from not
having looked. Put the table in the commit message.

- [ ] **Step 4: Re-read the neighbours for the OTHER audience**

For each passage edited, re-read its neighbours in **both** documents asking
whether the sentence is still true for a future *writer* as well as for *this
reader*. Instance 6 of the previous slice was the overshoot of a retraction, and
was invisible to a sweep scoped to one polarity.

- [ ] **Step 5: Verify no on-disk change**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git diff main...HEAD --stat -- core/tests/data/
uv run core/tests/python/conformance.py
```

Expected: exactly one added path (`manifest_canonicality_kat.json` from T5), zero
modified; conformance PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git add docs/vault-format.md docs/crypto-design.md
git commit   # paste the sweep table into the message
```

---

## Task 9: Closeout — gates, docs, baton

**Files:**
- Modify: `README.md`, `ROADMAP.md` (only if this slice changed something they state)
- Create: `docs/handoffs/2026-08-31-manifest-canonicality-pin-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget the symlink)

- [ ] **Step 1: Run the full gate set**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
pwd && git branch --show-current
cargo fmt --all --check
cargo build --release --workspace          # separate from the test run ON PURPOSE
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace   # confirm it is not a cache hit
uv run core/tests/python/conformance.py
```

- [ ] **Step 2: Run the two gates no CI job covers**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
cargo check --release --features differential-replay --tests -p secretary-core
cargo test  --release --workspace --features differential-replay
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
```

- [ ] **Step 3: Run all six hygiene guards, `--self-test` FIRST**

Run each as a literal command. zsh does not word-split unquoted variables, so a
`for g in "bash x.sh"; do $g; done` loop reports FAIL on all of them.

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
bash ffi/scripts/check-lean-binding.sh --self-test        && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test  && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test     && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test     && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

- [ ] **Step 4: Check spec-citation freshness**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
uv run core/tests/python/spec_test_name_freshness.py
```

Expected baseline is **90** with a member set identical to `main`'s (#574 tracks
the backlog). If the count moved, `comm` the member sets in both directions and
account for every difference — a new citation this slice added that does not
resolve is a real finding, not noise.

- [ ] **Step 5: Update README.md / ROADMAP.md only if warranted**

This slice adds test and verifier coverage; it changes no public API and no
on-disk format. Check whether either document makes a claim this slice falsifies
(in particular, anything about what `conformance.py` covers). Edit only what is
now wrong — do not add a changelog entry for its own sake.

- [ ] **Step 6: Write the handoff and retarget the symlink**

Author `docs/handoffs/2026-08-31-manifest-canonicality-pin-shipped.md` covering:
what shipped with commit SHAs; what is next with acceptance criteria; open
decisions and risks; the exact resume commands. Then:

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
ln -snf docs/handoffs/2026-08-31-manifest-canonicality-pin-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

Commit BOTH the handoff and the retargeted symlink as one commit on the feature
branch, so the baton rides inside the PR.

- [ ] **Step 7: Push and open the PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-canonicality-pin
git push -u origin feature/manifest-canonicality-pin
gh pr create --fill      # the user merges; do NOT auto-merge
```
