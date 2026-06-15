# C.4 Python Clean-Room Convergence Mirror — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, inside the stdlib-only clean-room verifier `conformance.py`, that the four CRDT-pure C.4 convergence scenarios converge to identical logical state independent of merge order, agreeing with the real Rust merge.

**Architecture:** A new `#[ignore]` Rust generator emits `core/tests/data/convergence_kat.json` (two concurrent device sides + golden converged block, golden = real `merge_block` output). An always-run Rust guard replays the fixture both ways. A new `section_convergence_kat()` in `conformance.py` reuses the existing `py_merge_block` engine to merge both orderings and assert order-independence + golden-match. Additive test-only; no `core/src` / crypto / format / CRDT change.

**Tech Stack:** Rust (stable, `secretary-core` integration tests, `serde_json`), Python 3 stdlib via `uv`.

**Spec:** `docs/superpowers/specs/2026-06-15-c4-python-convergence-mirror-design.md`

**Worktree:** `/Users/hherb/src/secretary/.worktrees/c4-python-convergence-mirror` (branch `feature/c4-python-convergence-mirror`). Run all commands from there.

---

## File Structure

| File | Responsibility |
|---|---|
| `core/tests/convergence_kat_gen.rs` (new) | (a) `Record`/`BlockPlaintext`/clock → JSON serializers (inverse of `conflict.rs` parsers); (b) the four scenario builders; (c) `#[ignore]` generator `generate_convergence_kat` that writes the fixture; (d) always-run guard `convergence_kat_replays_are_order_independent` |
| `core/tests/data/convergence_kat.json` (new) | The 4 scenario vectors + goldens (generated, human-reviewed) |
| `core/tests/python/conformance.py` (modify) | New `section_convergence_kat()` + `main()` wiring |
| `README.md`, `ROADMAP.md` (modify) | C.4 Python clean-room convergence mirror ✅ |

**Scenario data shape (all four are single-record on record `X`, to avoid record-ordering concerns):**

| Scenario | device_a | device_b | relation | golden (converged) |
|---|---|---|---|---|
| `auto_apply` | X live `{f1:"alice"}`, clock `[{A,1}]` | empty block, clock `[]` | dominating | X live `{f1:"alice"}` |
| `concurrent_disjoint` | X `{f1:"alice"@100}`, clock `[{A,1}]` | X `{f2:"bob"@101}`, clock `[{B,1}]` | Concurrent | X `{f1,f2}` |
| `lww_collision` | X `{k:"alice-loses"@100}`, clock `[{A,1}]` | X `{k:"bob-wins"@101}`, clock `[{B,1}]` | Concurrent | X `{k:"bob-wins"}` |
| `tombstone_accept` | X live `{k:"alice-live"@100}`, clock `[{A,1}]` | X tombstoned `@200` (`last_mod_ms=200`, `tombstoned_at_ms=200`), clock `[{B,1}]` | Concurrent | X tombstoned, no fields |

`A = [0x0A;16]`, `B = [0x0B;16]`, `X_BLOCK = [0xBB;16]`, `X_RECORD = [0xAA;16]` (matching `convergence.rs`).

---

## Task 1: Rust serializers + scenario builders (self-contained)

**Files:**
- Create: `core/tests/convergence_kat_gen.rs`

- [ ] **Step 1: Write the failing unit test**

Create `core/tests/convergence_kat_gen.rs` with this content (test + the helpers it needs will be filled in the next step; write the TEST first so it fails to compile):

```rust
//! C.4 — Python clean-room convergence mirror: Rust fixture generator +
//! always-run guard. Emits `core/tests/data/convergence_kat.json` (two
//! concurrent device sides + the real `merge_block` golden) and replays it
//! both ways to assert order-independence. The Python sibling
//! (`core/tests/python/conformance.py` `section_convergence_kat`) re-runs the
//! merge from spec docs only and asserts the same convergence.
//!
//! See docs/superpowers/specs/2026-06-15-c4-python-convergence-mirror-design.md.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use secretary_core::vault::{
    merge_block, BlockPlaintext, Record, RecordField, RecordFieldValue, VectorClockEntry,
};

const A: u8 = 0x0A;
const B: u8 = 0x0B;
const X_BLOCK: u8 = 0xBB;
const X_RECORD: u8 = 0xAA;

#[test]
fn serializes_a_text_field_record_to_kat_shape() {
    let rec = record_live(
        X_RECORD,
        &[("f1", text_field("alice", 100, A))],
        100,
    );
    let block = block_of(X_BLOCK, vec![rec]);
    let got = block_to_json(&block);
    let expected = serde_json::json!({
        "block_version": 1,
        "block_uuid_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "block_name": "vault",
        "schema_version": 1,
        "records": [{
            "record_uuid_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "record_type": "login",
            "fields": [{
                "name": "f1",
                "value_type": "text",
                "value_text": "alice",
                "last_mod": 100,
                "device_uuid_hex": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
            }],
            "tags": [],
            "created_at_ms": 1000,
            "last_mod_ms": 100,
            "tombstone": false,
            "tombstoned_at_ms": 0,
            "unknown_hex": {}
        }],
        "unknown_hex": {}
    });
    assert_eq!(got, expected);
}
```

- [ ] **Step 2: Run the test to verify it fails (does not compile)**

Run: `cd /Users/hherb/src/secretary/.worktrees/c4-python-convergence-mirror && cargo test --release --test convergence_kat_gen serializes_a_text_field_record_to_kat_shape`
Expected: FAIL — `cannot find function block_to_json` / builders not defined.

- [ ] **Step 3: Add the builders + serializers**

Append to `core/tests/convergence_kat_gen.rs` (above or below the test — order doesn't matter):

```rust
// ---------------------------------------------------------------------------
// Builders (mirror conflict.rs's pt/record/rfield/vc)
// ---------------------------------------------------------------------------

fn vc(d: u8, c: u64) -> VectorClockEntry {
    VectorClockEntry { device_uuid: [d; 16], counter: c }
}

fn text_field(value: &str, last_mod: u64, dev: u8) -> RecordField {
    RecordField {
        value: RecordFieldValue::Text(value.into()),
        last_mod,
        device_uuid: [dev; 16],
        unknown: BTreeMap::new(),
    }
}

fn record_live(uuid: u8, fields: &[(&str, RecordField)], last_mod_ms: u64) -> Record {
    let mut map = BTreeMap::new();
    for (name, field) in fields {
        map.insert((*name).to_string(), field.clone());
    }
    Record {
        record_uuid: [uuid; 16],
        record_type: "login".to_string(),
        fields: map,
        tags: Vec::new(),
        created_at_ms: 1_000,
        last_mod_ms,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

/// A tombstoned record: no live fields, death clock = `at_ms`.
fn record_tombstoned(uuid: u8, at_ms: u64) -> Record {
    Record {
        record_uuid: [uuid; 16],
        record_type: "login".to_string(),
        fields: BTreeMap::new(),
        tags: Vec::new(),
        created_at_ms: 1_000,
        last_mod_ms: at_ms,
        tombstone: true,
        tombstoned_at_ms: at_ms,
        unknown: BTreeMap::new(),
    }
}

fn block_of(block_uuid: u8, records: Vec<Record>) -> BlockPlaintext {
    BlockPlaintext {
        block_version: 1,
        block_uuid: [block_uuid; 16],
        block_name: "vault".to_string(),
        schema_version: 1,
        records,
        unknown: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Serializers — inverse of conflict.rs's parse_block/parse_record/parse_field.
// Scenarios carry NO `unknown` maps; we assert that and emit empty unknown_hex
// (fail-loud if a future scenario adds one rather than silently dropping it).
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn field_to_json(name: &str, f: &RecordField) -> serde_json::Value {
    assert!(
        f.unknown.is_empty(),
        "convergence scenarios carry no record-field unknown keys"
    );
    let mut obj = serde_json::Map::new();
    obj.insert("name".into(), name.into());
    match &f.value {
        RecordFieldValue::Text(s) => {
            obj.insert("value_type".into(), "text".into());
            obj.insert("value_text".into(), s.expose().into());
        }
        RecordFieldValue::Bytes(b) => {
            obj.insert("value_type".into(), "bytes".into());
            obj.insert("value_hex".into(), hex(b.expose()).into());
        }
    }
    obj.insert("last_mod".into(), f.last_mod.into());
    obj.insert("device_uuid_hex".into(), hex(&f.device_uuid).into());
    serde_json::Value::Object(obj)
}

fn record_to_json(r: &Record) -> serde_json::Value {
    assert!(
        r.unknown.is_empty(),
        "convergence scenarios carry no record-level unknown keys"
    );
    // BTreeMap iteration is sorted by name → matches py_merge_record's
    // `sorted(set(...))` field order, so the golden compares equal to the
    // Python merge output field-for-field.
    let fields: Vec<serde_json::Value> =
        r.fields.iter().map(|(n, f)| field_to_json(n, f)).collect();
    serde_json::json!({
        "record_uuid_hex": hex(&r.record_uuid),
        "record_type": r.record_type,
        "fields": fields,
        "tags": r.tags,
        "created_at_ms": r.created_at_ms,
        "last_mod_ms": r.last_mod_ms,
        "tombstone": r.tombstone,
        "tombstoned_at_ms": r.tombstoned_at_ms,
        "unknown_hex": serde_json::Map::new(),
    })
}

fn block_to_json(b: &BlockPlaintext) -> serde_json::Value {
    assert!(
        b.unknown.is_empty(),
        "convergence scenarios carry no block-level unknown keys"
    );
    let records: Vec<serde_json::Value> = b.records.iter().map(record_to_json).collect();
    serde_json::json!({
        "block_version": b.block_version,
        "block_uuid_hex": hex(&b.block_uuid),
        "block_name": b.block_name,
        "schema_version": b.schema_version,
        "records": records,
        "unknown_hex": serde_json::Map::new(),
    })
}

fn clock_to_json(clock: &[VectorClockEntry]) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = clock
        .iter()
        .map(|e| {
            serde_json::json!({
                "device_uuid_hex": hex(&e.device_uuid),
                "counter": e.counter,
            })
        })
        .collect();
    serde_json::Value::Array(entries)
}
```

> Note on `s.expose()`: `RecordFieldValue::Text` holds a `SecretString`; `.expose()` returns the `&str` (same accessor `core/tests/convergence_helpers/assert.rs::digest_field_value` uses). `RecordFieldValue::Bytes` holds `SecretBytes`; `.expose()` returns `&[u8]`. These are merge-layer test fixtures (cleartext, like `conflict_kat.json`), not real secrets.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --release --test convergence_kat_gen serializes_a_text_field_record_to_kat_shape`
Expected: PASS (1 passed).

- [ ] **Step 5: Lint + format**

Run: `cargo clippy --release --test convergence_kat_gen -- -D warnings && cargo fmt --all`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add core/tests/convergence_kat_gen.rs
git commit -m "test(c4): convergence-KAT serializers + scenario builders

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Rust generator + always-run order-independence guard

**Files:**
- Modify: `core/tests/convergence_kat_gen.rs`
- Create (via generator): `core/tests/data/convergence_kat.json`

- [ ] **Step 1: Add the scenario table + the always-run guard test (fails: no fixture yet)**

Append to `core/tests/convergence_kat_gen.rs`:

```rust
// ---------------------------------------------------------------------------
// The four CRDT-pure convergence scenarios (single record X each).
// ---------------------------------------------------------------------------

struct Scenario {
    name: &'static str,
    a_block: BlockPlaintext,
    a_clock: Vec<VectorClockEntry>,
    b_block: BlockPlaintext,
    b_clock: Vec<VectorClockEntry>,
}

fn scenarios() -> Vec<Scenario> {
    vec![
        // 1. auto-apply: A live, B behind (empty block + empty clock).
        Scenario {
            name: "auto_apply",
            a_block: block_of(X_BLOCK, vec![record_live(X_RECORD, &[("f1", text_field("alice", 100, A))], 100)]),
            a_clock: vec![vc(A, 1)],
            b_block: block_of(X_BLOCK, vec![]),
            b_clock: vec![],
        },
        // 2. concurrent disjoint fields.
        Scenario {
            name: "concurrent_disjoint",
            a_block: block_of(X_BLOCK, vec![record_live(X_RECORD, &[("f1", text_field("alice", 100, A))], 100)]),
            a_clock: vec![vc(A, 1)],
            b_block: block_of(X_BLOCK, vec![record_live(X_RECORD, &[("f2", text_field("bob", 101, B))], 101)]),
            b_clock: vec![vc(B, 1)],
        },
        // 3. LWW collision on field "k": later last_mod (101 > 100) wins.
        Scenario {
            name: "lww_collision",
            a_block: block_of(X_BLOCK, vec![record_live(X_RECORD, &[("k", text_field("alice-loses", 100, A))], 100)]),
            a_clock: vec![vc(A, 1)],
            b_block: block_of(X_BLOCK, vec![record_live(X_RECORD, &[("k", text_field("bob-wins", 101, B))], 101)]),
            b_clock: vec![vc(B, 1)],
        },
        // 4. tombstone AcceptTombstone: B's death clock (200) > A's edit (100).
        Scenario {
            name: "tombstone_accept",
            a_block: block_of(X_BLOCK, vec![record_live(X_RECORD, &[("k", text_field("alice-live", 100, A))], 100)]),
            a_clock: vec![vc(A, 1)],
            b_block: block_of(X_BLOCK, vec![record_tombstoned(X_RECORD, 200)]),
            b_clock: vec![vc(B, 1)],
        },
    ]
}

/// Merge a scenario in one ordering. `merger` syncs: its own side is `local`,
/// the canonical side is `remote`, and the merge ticks `merger`'s clock entry.
fn merge_ordering(
    local: &BlockPlaintext,
    local_clock: &[VectorClockEntry],
    remote: &BlockPlaintext,
    remote_clock: &[VectorClockEntry],
    merger: [u8; 16],
) -> BlockPlaintext {
    merge_block(local, local_clock, remote, remote_clock, merger)
        .expect("merge_block")
        .merged
}

#[test]
fn convergence_kat_replays_are_order_independent() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("convergence_kat.json");
    let raw = std::fs::read_to_string(&path).expect("read convergence_kat.json");
    let kat: serde_json::Value = serde_json::from_str(&raw).expect("parse convergence_kat.json");
    assert_eq!(kat["version"], 1);

    let scenarios = scenarios();
    let vectors = kat["scenarios"].as_array().expect("scenarios[]");
    assert_eq!(
        vectors.len(),
        scenarios.len(),
        "fixture scenario count must match the in-Rust scenario table"
    );

    for sc in &scenarios {
        // Ordering AB: A canonical, B merges (B=local, A=remote, merger=B).
        let ab = merge_ordering(&sc.b_block, &sc.b_clock, &sc.a_block, &sc.a_clock, [B; 16]);
        // Ordering BA: B canonical, A merges (A=local, B=remote, merger=A).
        let ba = merge_ordering(&sc.a_block, &sc.a_clock, &sc.b_block, &sc.b_clock, [A; 16]);
        assert_eq!(
            block_to_json(&ab),
            block_to_json(&ba),
            "scenario {}: orderings diverged (order-independence violated)",
            sc.name
        );

        // Golden in the fixture must equal the converged block.
        let vector = vectors
            .iter()
            .find(|v| v["name"] == sc.name)
            .unwrap_or_else(|| panic!("fixture missing scenario {}", sc.name));
        assert_eq!(
            block_to_json(&ab),
            vector["golden"]["block"],
            "scenario {}: golden does not match converged block",
            sc.name
        );
    }
}
```

- [ ] **Step 2: Run the guard to verify it fails (fixture absent)**

Run: `cargo test --release --test convergence_kat_gen convergence_kat_replays_are_order_independent`
Expected: FAIL — `read convergence_kat.json` panics (file not found). This is the red state; Step 4's generator produces the fixture.

- [ ] **Step 3: Add the `#[ignore]` generator**

Append to `core/tests/convergence_kat_gen.rs`:

```rust
/// Regenerate the committed fixture. Run explicitly; review the diff before
/// commit:
///   cargo test --release --workspace -- --ignored generate_convergence_kat --nocapture
#[test]
#[ignore]
fn generate_convergence_kat() {
    let scenarios = scenarios();
    let mut out_scenarios: Vec<serde_json::Value> = Vec::new();
    for sc in &scenarios {
        // Golden = real merge_block output, ordering AB (golden is
        // order-independent; the always-run guard proves AB == BA).
        let golden = merge_ordering(&sc.b_block, &sc.b_clock, &sc.a_block, &sc.a_clock, [B; 16]);
        out_scenarios.push(serde_json::json!({
            "name": sc.name,
            "device_a": { "block": block_to_json(&sc.a_block), "vector_clock": clock_to_json(&sc.a_clock) },
            "device_b": { "block": block_to_json(&sc.b_block), "vector_clock": clock_to_json(&sc.b_clock) },
            "merging_device_a_hex": hex(&[A; 16]),
            "merging_device_b_hex": hex(&[B; 16]),
            "golden": { "block": block_to_json(&golden) },
        }));
    }
    let doc = serde_json::json!({
        "version": 1,
        "_doc": "C.4 convergence conformance vectors. Each scenario carries two \
concurrent device sides (block plaintext + vector clock) plus the golden \
converged block produced by the real Rust merge_block. Replayed by \
core/tests/convergence_kat_gen.rs (always-run guard) and \
core/tests/python/conformance.py (clean-room, stdlib only): both merge BOTH \
orderings and assert order-independence + golden-match. The vector clock is \
intentionally absent from `golden` (it differs by which device was the merger; \
convergence is logical, on records not clocks). Regenerate with: cargo test \
--release --workspace -- --ignored generate_convergence_kat --nocapture",
        "scenarios": out_scenarios,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("convergence_kat.json");
    let pretty = serde_json::to_string_pretty(&doc).expect("serialize");
    std::fs::write(&path, format!("{pretty}\n")).expect("write convergence_kat.json");
    eprintln!("generate_convergence_kat: wrote {} ({} scenarios)", path.display(), scenarios.len());
}
```

- [ ] **Step 4: Generate the fixture, then verify the guard passes**

Run:
```bash
cargo test --release --test convergence_kat_gen -- --ignored generate_convergence_kat --nocapture
cargo test --release --test convergence_kat_gen convergence_kat_replays_are_order_independent
```
Expected: generator prints `wrote .../convergence_kat.json (4 scenarios)`; the guard then PASSES.

- [ ] **Step 5: Eyeball the generated fixture**

Run: `python3 -c "import json; d=json.load(open('core/tests/data/convergence_kat.json')); print([s['name'] for s in d['scenarios']]); print(json.dumps(d['scenarios'][3]['golden'], indent=1))"`
Expected: names `['auto_apply','concurrent_disjoint','lww_collision','tombstone_accept']`; the `tombstone_accept` golden shows the X record with `"tombstone": true` and `"fields": []`.

- [ ] **Step 6: Lint + format + whole-suite smoke**

Run:
```bash
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
cargo test --release --test convergence_kat_gen
```
Expected: clippy clean, fmt clean, 2 passed (`serializes_...`, `convergence_kat_replays_...`); the `#[ignore]` generator is skipped.

- [ ] **Step 7: Commit**

```bash
git add core/tests/convergence_kat_gen.rs core/tests/data/convergence_kat.json
git commit -m "test(c4): generate convergence_kat.json + always-run order-independence guard

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Python `section_convergence_kat()` + main wiring

**Files:**
- Modify: `core/tests/python/conformance.py`

- [ ] **Step 1: Add the section function**

Insert a new section function after `section5_unknown_map_case_insensitivity` (i.e. after its `return`, around line 2903+). It reuses the existing `py_merge_block`, `_normalise_block`, and `load_json_fixture`:

```python
# ---------------------------------------------------------------------------
# Section C — convergence_kat.json: two-client CRDT convergence (C.4)
# ---------------------------------------------------------------------------


def convergence_kat_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "convergence_kat.json"


def _converged_block(side_local: dict, side_remote: dict, merger_hex: str) -> dict:
    """Merge one ordering: `side_local` is the merger's own side, `side_remote`
    the canonical side; the merge ticks `merger_hex`. Returns the merged block
    plaintext (vector clock discarded — it differs by merger and is not part of
    the converged logical state)."""
    return py_merge_block(
        side_local["block"],
        side_local["vector_clock"],
        side_remote["block"],
        side_remote["vector_clock"],
        merger_hex,
    )["block"]


def section_convergence_kat() -> tuple[bool, list[str]]:
    """Clean-room two-client convergence (C.4). For each scenario, merge BOTH
    orderings via the spec-derived py_merge_block and assert (a) the converged
    logical blocks are order-independent and (b) they match the Rust-generated
    golden. KeepLocal veto is intentionally out of scope (sync-orchestration,
    not in the frozen merge spec) — see the design doc §2."""
    lines: list[str] = []
    path = convergence_kat_path()
    if not path.exists():
        print(f"MISSING: convergence_kat.json at {path}", file=sys.stderr)
        sys.exit(2)
    try:
        kat = load_json_fixture(path, "convergence_kat.json")
    except (json.JSONDecodeError, OSError):
        sys.exit(2)
    if kat.get("version") != 1:
        lines.append(f"FAIL  convergence_kat.json version={kat.get('version')}, expected 1")
        return False, lines
    scenarios = kat.get("scenarios") or []
    if not scenarios:
        lines.append("FAIL  convergence_kat.json has no scenarios")
        return False, lines

    all_ok = True
    for sc in scenarios:
        name = sc["name"]
        a, b = sc["device_a"], sc["device_b"]
        a_hex, b_hex = sc["merging_device_a_hex"], sc["merging_device_b_hex"]
        try:
            # Ordering AB: A canonical, B merges (B local, A remote, merger=B).
            ab = _normalise_block(_converged_block(b, a, b_hex))
            # Ordering BA: B canonical, A merges (A local, B remote, merger=A).
            ba = _normalise_block(_converged_block(a, b, a_hex))
        except Exception as exc:  # noqa: BLE001 — surface any merge error as a FAIL line
            lines.append(f"FAIL  scenario {name!r}: merge raised {exc!r}")
            all_ok = False
            continue

        if ab != ba:
            lines.append(f"FAIL  scenario {name!r}: orderings diverged (not order-independent)")
            lines.append(f"  AB: {json.dumps(ab, sort_keys=True)}")
            lines.append(f"  BA: {json.dumps(ba, sort_keys=True)}")
            all_ok = False
            continue

        golden = _normalise_block(sc["golden"]["block"])
        if ab != golden:
            lines.append(f"FAIL  scenario {name!r}: converged block != Rust golden")
            lines.append(f"  got:    {json.dumps(ab, sort_keys=True)}")
            lines.append(f"  golden: {json.dumps(golden, sort_keys=True)}")
            all_ok = False
            continue

        lines.append(f"PASS  convergence_kat.json {name!r}: order-independent + golden-match")

    return all_ok, lines
```

- [ ] **Step 2: Wire the section into `main()`**

In `conformance.py`, after the Section S block (around line 2734, just before `print()` then the aggregate `if`), add:

```python
    print()
    print("--- Section C: convergence_kat.json two-client convergence (C.4) ---")
    convergence_ok, convergence_lines = section_convergence_kat()
    for ln in convergence_lines:
        print(ln)
```

Then extend the aggregate pass condition (the `if section1_ok and ... and sync_pass_ok:` around line 3737) to include `and convergence_ok`, and add the matching failure line near the other `if not ...:` blocks:

```python
    if not convergence_ok:
        print("FAIL: convergence_kat.json two-client convergence", file=sys.stderr)
```

- [ ] **Step 3: Run the full clean-room verifier — expect PASS**

Run: `uv run core/tests/python/conformance.py`
Expected: all existing sections PASS; new block prints:
```
--- Section C: convergence_kat.json two-client convergence (C.4) ---
PASS  convergence_kat.json 'auto_apply': order-independent + golden-match
PASS  convergence_kat.json 'concurrent_disjoint': order-independent + golden-match
PASS  convergence_kat.json 'lww_collision': order-independent + golden-match
PASS  convergence_kat.json 'tombstone_accept': order-independent + golden-match
```
final line `PASS`.

- [ ] **Step 4: Prove the test is real (mutation check)**

Temporarily corrupt one golden value and confirm Section C fails, then revert:
```bash
python3 - <<'PY'
import json, pathlib
p = pathlib.Path("core/tests/data/convergence_kat.json")
d = json.loads(p.read_text())
# Flip the lww golden field's value_text to the loser.
for s in d["scenarios"]:
    if s["name"] == "lww_collision":
        s["golden"]["block"]["records"][0]["fields"][0]["value_text"] = "alice-loses"
p.write_text(json.dumps(d, indent=2) + "\n")
PY
uv run core/tests/python/conformance.py; echo "exit=$?"
git checkout core/tests/data/convergence_kat.json   # revert the corruption
```
Expected: run prints `FAIL  convergence_kat.json 'lww_collision': converged block != Rust golden` and exits non-zero (`exit=1`); the `git checkout` restores the real fixture.

- [ ] **Step 5: Confirm the fixture is back to the real one**

Run: `cargo test --release --test convergence_kat_gen convergence_kat_replays_are_order_independent && uv run core/tests/python/conformance.py | tail -1`
Expected: Rust guard passes; Python prints `PASS`.

- [ ] **Step 6: Commit**

```bash
git add core/tests/python/conformance.py
git commit -m "test(c4): clean-room two-client convergence section in conformance.py

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Full gauntlet + docs

**Files:**
- Modify: `README.md`, `ROADMAP.md`

- [ ] **Step 1: Run the whole-workspace gauntlet**

Run:
```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
```
Expected: all green. If `spec_test_name_freshness.py` flags a citation, resolve it (add the test-name citation or allowlist per that script's `--audit-allowlist` guidance).

- [ ] **Step 2: Update README + ROADMAP**

In `README.md`, find the C.4 convergence status line/section (added by #235) and extend it to note the Python clean-room mirror (brief, dot-point, per the README style preference — no test-count walls). In `ROADMAP.md`, mark "C.4 Python clean-room convergence mirror ✅" alongside the existing C.4 entry. Read both files first to match their existing phrasing.

- [ ] **Step 3: Verify the additive-only guardrails**

Run:
```bash
git fetch origin
git diff origin/main...HEAD --name-only | grep -vE '^(core/tests/|docs/|README.md|ROADMAP.md)' || echo "OK: only test+docs touched"
git diff origin/main...HEAD --name-only | grep -E 'core/src|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data/(conflict_kat|conformance_kat)' || echo "OK: no production/spec/CRDT/existing-KAT change"
```
Expected: both print their `OK: ...` line (greps empty). Note `core/tests/data/convergence_kat.json` is the only `core/tests/data` addition and is intentionally NOT matched by the second grep.

- [ ] **Step 4: Commit docs**

```bash
git add README.md ROADMAP.md
git commit -m "docs(c4): note Python clean-room convergence mirror in README + ROADMAP

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Handoff baton + PR

This is the `/nextsession` closeout (handoff symlink model). Do this after Tasks 1–4 are green.

- [ ] **Step 1: Write the handoff doc**

Create `docs/handoffs/2026-06-15-c4-python-convergence-mirror-shipped.md` capturing: (1) what shipped + commit SHAs, (2) what's next (the deferred veto mirror; C.3 Android; 3+ device topologies) with acceptance criteria, (3) open decisions/risks (veto out-of-scope, golden-is-clockless, single-record scenarios), (4) exact resume commands (cd, branch, the gauntlet from Task 4 Step 1).

- [ ] **Step 2: Retarget the NEXT_SESSION.md symlink**

```bash
ln -snf docs/handoffs/2026-06-15-c4-python-convergence-mirror-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows -> target
head -3 NEXT_SESSION.md  # reads handoff content transparently
```

- [ ] **Step 3: Commit handoff + symlink, push, open PR**

```bash
git add docs/handoffs/2026-06-15-c4-python-convergence-mirror-shipped.md NEXT_SESSION.md
git commit -m "docs: handoff baton for C.4 Python convergence mirror

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push -u origin feature/c4-python-convergence-mirror
gh pr create --title "C.4 Python clean-room convergence mirror" --body "<summary + acceptance + 'additive test-only' note>"
```

- [ ] **Step 4: Confirm PR is mergeable**

Run: `gh pr view --json mergeable,mergeStateStatus`
Expected: `MERGEABLE` / `CLEAN` (no add/add conflict on the handoff path; `main` did not move during this session — if it did, follow the fixup-time merge discipline in the /nextsession instructions).

---

## Self-Review (author checklist — completed)

- **Spec coverage:** §2 scope (4 CRDT-pure scenarios, veto excluded) → Task 2 scenario table + Task 3 doc-comment; §3 fixture (Rust-generated, schema, generator, always-run guard) → Tasks 1–2; §4 Python replay (both orderings, order-independence + golden, reuses `py_merge_block`/`_normalise_block`) → Task 3; §6 TDD → red/green steps throughout + Task 3 mutation check; §7 acceptance → Task 4 gauntlet; §8 files → File Structure table. All covered.
- **Placeholders:** none — every code step shows full code; the only `<...>` are in the PR body / README phrasing, which require reading current file content first (called out explicitly).
- **Type consistency:** `block_to_json` / `record_to_json` / `field_to_json` / `clock_to_json` / `merge_ordering` / `scenarios()` / `Scenario` used consistently across Tasks 1–2; Python `section_convergence_kat` / `_converged_block` / `convergence_kat_path` consistent in Task 3; merger mapping (local=merger side, remote=canonical, tick=merger) identical in Rust guard, Rust generator, and Python section.
