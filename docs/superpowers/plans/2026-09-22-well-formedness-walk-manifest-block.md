# Well-formedness walk on the manifest and block-plaintext paths — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `cbor::well_formed::walk_first_item` into `decode_manifest` and `block::decode_plaintext` through one shared helper, and give the Python manifest and trash-entry decoders the report precedence `docs/vault-format.md` §4.2 already requires — closing three never-tolerated and three tolerated cross-language divergences, plus #685.

**Architecture:** One new `pub(crate)` helper in `core/src/vault/canonical/walk.rs` projects a `WalkFault` onto any error type that has a `CborDecode`-shaped constructor and a `From<CanonicalError>`; `record::decode`, `decode_manifest` and `block::decode_plaintext` all call it as their first statement. On the Python side `py_decode_manifest` and `py_decode_trash_entry` each replace their existing pre-pass with the single `walk_body`, which parks a rule-4 fault until the item has proven well-formed. Nine new committed `manifest_body` seeds make CI compare both decoders on every shape.

**Tech Stack:** Rust (stable, pinned 1.97.0), `ciborium` 0.2.2, Python 3.11+ via `uv` (PEP 723 header in `conformance.py` is the sole dependency declaration).

**Spec:** `docs/superpowers/specs/2026-09-22-well-formedness-walk-manifest-block-design.md`

## Global Constraints

- **Worktree:** `/Users/hherb/src/secretary/.worktrees/wellformed-walk`, branch `feature/well-formedness-walk-manifest-block`, base `bf63cc39`. Run every command from there. Verify with `pwd && git branch --show-current` before anything path-sensitive.
- **No frozen-spec edit.** Nothing under `docs/*.md` changes. §4.2's well-formedness precondition is already normative and already names these cases. If a task appears to need a normative edit, STOP and report — that is a design error, not a task detail.
- **`#![forbid(unsafe_code)]`** workspace-wide. No `unsafe`.
- **Always `--release`.** The crypto crates are unusably slow in debug.
- **Always `--locked`.** A task that changes `Cargo.lock` is out of scope.
- **500-line split threshold.** Design new files as directory modules or split from the start.
- **No magic numbers.** Every CBOR head byte, depth and length gets a named constant.
- **Python is `uv` only.** Never `pip` / `pip3` / `python -m pip`.
- **Probes and scratch files go to the session scratchpad**, never the source tree (#516). A temporary `.rs` file inside `core/tests/` is permitted only within a single task and must be deleted before that task's commit.
- **Test-count verification:** judge a command by its EXIT CODE, not by grepping its output. `cargo test | grep` returns grep's status.
- **Attribution:** every commit message ends with `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

### Names this plan fixes (used across tasks)

| Name | Where | Signature / value |
| --- | --- | --- |
| `walk_first_item_checked` | `core/src/vault/canonical/walk.rs` | `pub(crate) fn walk_first_item_checked<E: From<CanonicalError>>(bytes: &[u8], cbor_decode: fn(CborFault) -> E) -> Result<usize, E>` |
| `WALK_ROOT_HINT` | same file | `const WALK_ROOT_HINT: &str = "<root>";` (the `field` hint both rule-4 arms pass) |
| `SEED_PREFIX` | `core/tests/well_formed_seeds_helpers/prefix.rs` | `pub const SEED_PREFIX: &str = "wellformed__";` |
| `WellFormedCase` | `core/tests/well_formed_seeds_helpers/mod.rs` | `pub struct WellFormedCase { pub label: &'static str, pub planted: &'static [u8], pub token: &'static str }` |
| `Chain::BignumNarrowLast` / `Chain::BignumWideLast` | `core/tests/nesting_depth_seeds.rs` | new `Chain` variants, used only by the new walk-path test |
| `walk_body` | `conformance_lib/codec/well_formed.py` | existing; `walk_body(buf: bytes, pos: int = 0) -> int` |

---

## Task 1: Baseline measurement on the branch

Nothing is implemented in this task. It produces the numbers every later task compares against, and it can STOP the slice.

**Files:**
- Create (temporary, deleted in Step 6): `core/tests/zz_baseline_probe.rs`
- Modify: `docs/superpowers/specs/2026-09-22-well-formedness-walk-manifest-block-design.md` (append §1.1)

**Interfaces:**
- Consumes: nothing.
- Produces: a committed §1.1 table giving, for each of the 47 committed `manifest_body` seeds, its Rust `RuleToken` and its Python `rule` **before** any change; and the eleven-body table of §1 re-run against `block::decode_plaintext`.

- [ ] **Step 1: Write the probe**

Create `core/tests/zz_baseline_probe.rs`:

```rust
//! TEMPORARY baseline probe (plan Task 1). Deleted in this task's Step 6.
use std::fs;

use secretary_core::vault::block::decode_plaintext;
use secretary_core::vault::manifest::decode_manifest;

fn token_of_manifest(bytes: &[u8]) -> String {
    match decode_manifest(bytes) {
        Ok(_) => "ACCEPT".to_owned(),
        Err(e) => format!("{:?}", e.rule_token()),
    }
}

#[test]
#[ignore]
fn baseline_committed_manifest_seeds() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds/manifest_body");
    let mut paths: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "bin").unwrap_or(false))
        .collect();
    paths.sort();
    for path in paths {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        println!("{name:46} {}", token_of_manifest(&fs::read(&path).unwrap()));
    }
}

#[test]
#[ignore]
fn baseline_block_plaintext_shapes() {
    let dir = std::env::var("PROBE_BODIES").expect("set PROBE_BODIES");
    let mut paths: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "bin").unwrap_or(false))
        .collect();
    paths.sort();
    for path in paths {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let bytes = fs::read(&path).unwrap();
        match decode_plaintext(&bytes) {
            Ok(_) => println!("{name:24} ACCEPT"),
            Err(e) => println!("{name:24} {e}"),
        }
    }
}
```

- [ ] **Step 2: Build the eleven bodies for the block path**

The `manifest_body` bodies from spec §1 are manifest-shaped and will fail block decode for an unrelated reason, so build block-shaped ones. Write this to the SCRATCHPAD as `block_bodies.py` and run it with `uv run`:

```python
# /// script
# requires-python = ">=3.11"
# dependencies = ["cbor2"]
# ///
"""Block-plaintext bodies carrying each ciborium leniency under an unknown key."""
import pathlib, cbor2

OUT = pathlib.Path("BLOCK_BODIES_DIR"); OUT.mkdir(parents=True, exist_ok=True)
KEY = "zz_future"
SHAPES = {
    "control_uint":          bytes([0x00]),
    "undefined":             bytes([0xf7]),
    "two_byte_simple_true":  bytes([0xf8, 0x15]),
    "nested_indef_chunk":    bytes([0x5f, 0x5f, 0x41, 0x61, 0xff, 0xff]),
    "invalid_utf8_text":     bytes([0x61, 0xff]),
    "bignum_narrow":         bytes([0xc2, 0x41, 0x01]),
    "bignum_wide":           bytes([0xc2, 0x49]) + bytes([0x01] * 9),
    "shareable_cycle":       bytes([0xd8, 0x1c, 0x81, 0xd8, 0x1d, 0x00]),
    "tag_then_undefined":    bytes([0x82, 0xc2, 0x41, 0x01, 0xf7]),
    "undefined_then_tag":    bytes([0x82, 0xf7, 0xc2, 0x41, 0x01]),
    "float_then_undefined":  bytes([0x82, 0xf9, 0x00, 0x00, 0xf7]),
}

def canonical_order(k: bytes):
    return (len(k), k)

for name, val in SHAPES.items():
    # A block plaintext is a CBOR map; the real required keys are irrelevant
    # here because the walk runs BEFORE any key is interpreted. A map with
    # only the unknown key exercises exactly the path under test.
    key_enc = cbor2.dumps(KEY, canonical=True)
    body = bytes([0xa1]) + key_enc + val
    (OUT / f"{name}.bin").write_bytes(body)
print(f"wrote {len(SHAPES)} bodies to {OUT}")
```

Replace `BLOCK_BODIES_DIR` with `$SCRATCH/block_bodies` before running.

- [ ] **Step 3: Run both probes**

```bash
cargo test --release --locked -p secretary-core --test zz_baseline_probe \
  -- --ignored --nocapture baseline_committed_manifest_seeds
PROBE_BODIES="$SCRATCH/block_bodies" cargo test --release --locked -p secretary-core \
  --test zz_baseline_probe -- --ignored --nocapture baseline_block_plaintext_shapes
```

Expected: 47 lines from the first, 11 from the second. Save both outputs to `$SCRATCH/baseline.txt`.

- [ ] **Step 4: Run the Python baseline over the same 47 seeds**

```bash
uv run --with cbor2 --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 python3 - <<'PY'
import pathlib, sys
ROOT = pathlib.Path("core/tests/python").resolve()
sys.path.insert(0, str(ROOT))
from conformance_lib.diff_replay import replay_bytes
seeds = sorted((ROOT.parent.parent / "fuzz" / "seeds" / "manifest_body").glob("*.bin"))
for p in seeds:
    v = replay_bytes("manifest_body", p.read_bytes()).verdict
    print(f"{p.stem:46} {v.get('status'):7} {str(v.get('rule'))}")
PY
```

Append to `$SCRATCH/baseline.txt`.

- [ ] **Step 5: Append §1.1 to the spec**

Add a `### 1.1 Baseline measured on the branch` subsection recording:

1. The per-seed Rust and Python tokens for all 47 committed `manifest_body` seeds, as a table. This is the **regression baseline**: Tasks 3 and 6 require every one of these to be unchanged.
2. The eleven-shape table for `block::decode_plaintext`, in the same columns as §1's manifest table.
3. One sentence naming any shape whose block answer differs from its manifest answer, and why.

**STOP CONDITION.** If any committed seed's Rust token is something other than what a single-fault seed of that name should report — that is, if the corpus is already inconsistent before any change — stop and report rather than proceeding. The design assumes today's 47 tokens are the contract.

- [ ] **Step 6: Delete the probe and commit**

```bash
rm core/tests/zz_baseline_probe.rs
git status --short   # MUST show only the spec file
git add docs/superpowers/specs/2026-09-22-well-formedness-walk-manifest-block-design.md
git commit -m "docs: baseline token measurements for the walk slice (#666)

Records the Rust and Python token for each of the 47 committed
manifest_body seeds before any change, and the eleven leniency shapes
against block::decode_plaintext. Tasks 3 and 6 require the 47 to be
unchanged.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: The shared helper, and `record::decode` adopts it

**Files:**
- Create: `core/src/vault/canonical/walk.rs`
- Modify: `core/src/vault/canonical/mod.rs` (declare `mod walk;`, re-export)
- Modify: `core/src/vault/record.rs` (call the helper; delete `walk_fault_to_record_error`)

**Interfaces:**
- Consumes: `crate::cbor::{walk_first_item, WalkFault, CborFault}` (already `pub(crate)`), `super::CanonicalError`.
- Produces: `walk_first_item_checked` with the signature in the Global Constraints table, re-exported as `crate::vault::canonical::walk_first_item_checked`. Tasks 3 and 4 call it.

- [ ] **Step 1: Write the failing tests**

Create `core/src/vault/canonical/walk.rs` with ONLY the test module and a stub, so the tests compile and fail:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::CborErrorKind;
    use crate::vault::record::RecordError;

    /// A well-formedness fault goes through the caller's own constructor,
    /// carrying the fault verbatim.
    #[test]
    fn a_malformed_body_reaches_the_callers_cbor_decode_arm() {
        // 0x82 opens a 2-element array; the input ends after one element.
        let err = walk_first_item_checked(&[0x82, 0x00], RecordError::CborDecode).unwrap_err();
        match err {
            RecordError::CborDecode(fault) => {
                assert_eq!(fault.kind, CborErrorKind::Io);
                assert!(fault.offset.is_some(), "the walk always reports an offset");
            }
            other => panic!("expected CborDecode, got {other:?}"),
        }
    }

    /// A tag goes through `From<CanonicalError>`, with the root hint.
    #[test]
    fn a_tag_reaches_the_callers_canonical_arm() {
        // c2 41 01 = bignum tag 2 over a 1-byte string.
        let err = walk_first_item_checked(&[0xc2, 0x41, 0x01], RecordError::CborDecode).unwrap_err();
        assert!(matches!(err, RecordError::TagRejected), "got {err:?}");
    }

    /// A float likewise, and the hint is the one the tree-wide walk passes.
    #[test]
    fn a_float_reaches_the_callers_canonical_arm_with_the_root_hint() {
        // f9 00 00 = half-precision 0.0
        let err = walk_first_item_checked(&[0xf9, 0x00, 0x00], RecordError::CborDecode).unwrap_err();
        match err {
            RecordError::FloatRejected { field } => assert_eq!(field, WALK_ROOT_HINT),
            other => panic!("expected FloatRejected, got {other:?}"),
        }
    }

    /// A well-formedness fault LATER in the body outranks a rule-4 fault
    /// EARLIER in it. This is `vault-format.md` §4.2's precondition, and it
    /// is the one property a caller cannot restore for itself.
    #[test]
    fn a_later_malformed_fault_outranks_an_earlier_tag() {
        // 82 c2 41 01 f7 = [bignum, undefined]
        let err = walk_first_item_checked(
            &[0x82, 0xc2, 0x41, 0x01, 0xf7],
            RecordError::CborDecode,
        )
        .unwrap_err();
        assert!(matches!(err, RecordError::CborDecode(_)), "got {err:?}");
    }

    /// The accepted body's end offset is returned, so a caller can judge
    /// trailing bytes if it wants to.
    #[test]
    fn an_accepted_body_returns_its_end_offset() {
        let ok = walk_first_item_checked::<RecordError>(&[0x81, 0x00, 0xff], RecordError::CborDecode);
        assert_eq!(ok, Ok(2), "the walk consumes only the first item");
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test --release --locked -p secretary-core --lib canonical::walk
```

Expected: a compile error naming `walk_first_item_checked` and `WALK_ROOT_HINT`.

- [ ] **Step 3: Write the implementation**

Prepend to `core/src/vault/canonical/walk.rs`:

```rust
//! The byte-level well-formedness walk, projected onto each vault-body
//! decoder's own error type (#666).
//!
//! `cbor::well_formed::walk_first_item` answers in its own vocabulary
//! ([`WalkFault`]); every caller must turn that into its layer's error enum.
//! `record::decode` did it with a private function. `decode_manifest` and
//! `block::decode_plaintext` need the same projection, and three hand-copies
//! of one rule is where this repo's duplicated-rule failures start (#589's
//! 31 duplicate-key guards, #597's seven required-key checks, #669's
//! `isinstance` copies). So the rule lives here once.
//!
//! **Why here and not in `cbor`.** The rule-4 arms must name
//! [`CanonicalError`], which lives under `vault`; putting this in `cbor`
//! would invert the layering. Not `legacy.rs`, which holds the pre-split
//! helpers.
//!
//! **What each caller still supplies.** Only its own `CborDecode`
//! constructor. The rule-4 arms go through the caller's
//! `From<CanonicalError>`, which every vault-body error enum already has and
//! which already maps these two variants — so this function introduces no
//! new mapping for a future variant to disagree with.

use crate::cbor::{walk_first_item, CborFault, WalkFault};

use super::CanonicalError;

/// The `field` hint both rule-4 arms pass.
///
/// The same hint each caller's tree-wide `reject_floats_and_tags` call
/// already passes at the same site, so wiring this walk in front of it does
/// not move the reported message.
const WALK_ROOT_HINT: &str = "<root>";

/// Walk the first CBOR item in `bytes` before anything is parsed, projecting
/// the outcome onto the caller's error type.
///
/// Returns the offset one past the first item. Callers discard it: trailing
/// bytes are judged by the §4.3 step-4 re-encode comparison, where
/// `record::decode` has always judged them, because `ciborium` performs no
/// EOF check.
///
/// A well-formedness fault anywhere outranks a rule-4 fault anywhere —
/// `docs/vault-format.md` §4.2's precondition. That precedence is
/// [`walk_first_item`]'s, not this function's; this function only routes.
pub(crate) fn walk_first_item_checked<E>(
    bytes: &[u8],
    cbor_decode: fn(CborFault) -> E,
) -> Result<usize, E>
where
    E: From<CanonicalError>,
{
    walk_first_item(bytes).map_err(|fault| match fault {
        WalkFault::Malformed(fault) => cbor_decode(fault),
        WalkFault::Tag { .. } => CanonicalError::TagRejected {
            field: WALK_ROOT_HINT,
        }
        .into(),
        WalkFault::Float { .. } => CanonicalError::FloatRejected {
            field: WALK_ROOT_HINT,
        }
        .into(),
    })
}
```

In `core/src/vault/canonical/mod.rs`, add `mod walk;` beside the other `mod` lines and `pub(crate) use walk::walk_first_item_checked;` beside the other `pub(crate) use` lines.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --release --locked -p secretary-core --lib canonical::walk
```

Expected: 5 passed.

- [ ] **Step 5: Swap `record::decode` onto the helper**

In `core/src/vault/record.rs`:

1. Replace `walk_first_item(bytes).map_err(walk_fault_to_record_error)?;` with
   `crate::vault::canonical::walk_first_item_checked(bytes, RecordError::CborDecode)?;`
2. **Delete** `fn walk_fault_to_record_error` entirely.
3. Fix the `use` line: `walk_first_item` and `WalkFault` are no longer used here.
4. Add one sentence to the call-site comment: the mapping now lives in
   `canonical::walk`, and `From<CanonicalError> for RecordError` is what makes
   the rule-4 arms land on the same variants the deleted function named.

- [ ] **Step 6: Prove the swap moved nothing**

```bash
cargo test --release --locked -p secretary-core --lib record
cargo test --release --locked -p secretary-core --test record_walk_tests 2>/dev/null || \
  cargo test --release --locked -p secretary-core record_walk
```

Expected: all green, with no test edited. `record_walk_tests` is the file that pins the four leniencies on the record path; it must pass **unmodified**. If any assertion there needs changing, STOP — the swap was supposed to be behaviour-identical.

- [ ] **Step 7: Lint and commit**

```bash
cargo clippy --release --locked -p secretary-core --tests -- -D warnings
cargo fmt --all
git add core/src/vault/canonical/walk.rs core/src/vault/canonical/mod.rs core/src/vault/record.rs
git commit -m "refactor(core): one WalkFault projection for every vault-body decoder (#666)

record::decode's private walk_fault_to_record_error becomes
canonical::walk_first_item_checked, which routes the rule-4 arms through
each caller's existing From<CanonicalError>. Behaviour-identical for
record: that impl already maps FloatRejected/TagRejected onto exactly the
variants the deleted function named, and record_walk_tests passes
unmodified.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `decode_manifest` runs the walk first

**Files:**
- Modify: `core/src/vault/manifest/decode/mod.rs`
- Modify: `core/src/vault/manifest/decode/tests.rs`

**Interfaces:**
- Consumes: `walk_first_item_checked` (Task 2).
- Produces: `decode_manifest` reporting `ManifestError::CborDecode` for a body that is not well-formed and `ManifestError::Canonical(..)` for a rule-4 fault, both before any parse.

- [ ] **Step 1: Write the failing tests**

Add to `core/src/vault/manifest/decode/tests.rs`. Build each body from the committed accepting seed the test module already uses for valid-manifest fixtures; if it has no such helper, use `test_support`'s manifest builder and encode it, then splice.

```rust
/// One canonical accepting manifest body with `("zz_future", planted)`
/// spliced in at its canonical key position (length-first, RFC 8949
/// §4.2.1), so the planted value reaches the decoder rather than a
/// key-order rejection.
fn manifest_with_unknown_value(planted: &[u8]) -> Vec<u8> {
    // Major 3 (text), length 9, "zz_future" — a key no v1 manifest defines,
    // so it lands in the forward-compat bag rather than a schema check.
    const UNKNOWN_KEY: &[u8] = b"\x69zz_future";
    // Major 3, length 10, "vault_uuid". `zz_future` is 9 bytes and
    // `suite_id` is 8, so RFC 8949 §4.2.1's length-first key order puts the
    // new entry immediately BEFORE this one. Appending it at the end
    // instead makes the body non-canonical and every test below then
    // rejects for the wrong reason — which is what the control test
    // catches.
    const VAULT_UUID_KEY: &[u8] = b"\x6avault_uuid";

    // Build a valid body with the module's own fixture builder and encode
    // it, rather than reading a committed seed: this keeps the test
    // independent of `core/fuzz/seeds/`, which a unit test should not reach
    // into.
    let base = encode_manifest(&test_support::valid_manifest())
        .expect("the fixture manifest encodes")
        .expose()
        .to_vec();

    // Surgery, not re-encoding: `encode_manifest` would re-sort and
    // re-canonicalise the planted value away, which is the whole point of
    // what is being tested. Same reason `manifest_uniqueness_kat.rs` plants
    // its repeats by surgery.
    let at = {
        let hits: Vec<usize> = base
            .windows(VAULT_UUID_KEY.len())
            .enumerate()
            .filter(|(_, w)| *w == VAULT_UUID_KEY)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1, "the vault_uuid key must occur exactly once");
        hits[0]
    };

    let head = base[0];
    assert!(
        (0xa0..=0xb7).contains(&head),
        "the fixture's top-level map must have a one-byte head; got {head:#04x}"
    );

    let mut out = Vec::with_capacity(base.len() + UNKNOWN_KEY.len() + planted.len());
    out.push(head + 1); // one more entry
    out.extend_from_slice(&base[1..at]);
    out.extend_from_slice(UNKNOWN_KEY);
    out.extend_from_slice(planted);
    out.extend_from_slice(&base[at..]);
    out
}

/// crypto-design §6.2's profile and §4.2's precondition: a body that is not
/// well-formed CBOR is reported AS THAT, before any key is interpreted.
/// Before #666 ciborium read `undefined` as `null` and these bodies were
/// reported by the re-encode comparison instead — a different rule, and one
/// `conformance.py` never agreed with.
#[test]
fn a_body_that_is_not_well_formed_is_reported_as_malformed_cbor() {
    for (label, planted) in [
        ("undefined", &[0xf7u8][..]),
        ("two-byte simple", &[0xf8, 0x15][..]),
        ("nested indefinite chunk", &[0x5f, 0x5f, 0x41, 0x61, 0xff, 0xff][..]),
        ("invalid UTF-8 text", &[0x61, 0xff][..]),
    ] {
        let body = manifest_with_unknown_value(planted);
        match decode_manifest(&body) {
            Err(ManifestError::CborDecode(_)) => {}
            other => panic!("{label}: expected CborDecode, got {other:?}"),
        }
    }
}

/// A bignum whose value fits 64 bits is folded to an integer by ciborium, so
/// the parsed-tree rule-4 walk never sees the tag. The byte walk does.
#[test]
fn a_narrow_bignum_is_reported_as_a_rule_4_tag() {
    let body = manifest_with_unknown_value(&[0xc2, 0x41, 0x01]);
    match decode_manifest(&body) {
        Err(ManifestError::Canonical(_)) => {}
        other => panic!("expected Canonical(TagRejected), got {other:?}"),
    }
}

/// §4.2: the precondition outranks rule 4 whatever the byte order. Both
/// bodies carry a rule-4 fault BEFORE the well-formedness fault, so a walk
/// that reported the first fault it met would red exactly here.
#[test]
fn a_well_formedness_fault_outranks_an_earlier_rule_4_fault() {
    for (label, planted) in [
        ("tag then undefined", &[0x82u8, 0xc2, 0x41, 0x01, 0xf7][..]),
        ("float then undefined", &[0x82, 0xf9, 0x00, 0x00, 0xf7][..]),
    ] {
        let body = manifest_with_unknown_value(planted);
        match decode_manifest(&body) {
            Err(ManifestError::CborDecode(_)) => {}
            other => panic!("{label}: expected CborDecode, got {other:?}"),
        }
    }
}

/// The control: the same splice with a benign value still ACCEPTS. Without
/// it the four tests above pass on a decoder that rejects every spliced
/// body for an unrelated reason.
#[test]
fn the_same_splice_with_a_benign_value_is_accepted() {
    let body = manifest_with_unknown_value(&[0x00]);
    assert!(decode_manifest(&body).is_ok(), "the splice itself must be canonical");
}
```

Two details the builder depends on, both worth checking before running: the module's fixture builder may not be called `test_support::valid_manifest` — use whatever the file's existing valid-manifest tests use — and the one-byte map head assertion fails if the fixture ever grows past 23 top-level keys, which would need the two-byte form. Both are asserted rather than assumed, so a wrong guess fails loudly rather than producing a body that rejects for an unrelated reason.

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test --release --locked -p secretary-core --lib manifest::decode::tests
```

Expected: `the_same_splice_with_a_benign_value_is_accepted` PASSES (the splice is right) and the other three FAIL with the tokens Task 1's §1.1 recorded — `NonCanonicalEncoding` for the `undefined`, two-byte-simple and both precedence bodies, `NonCanonicalEncoding` for the narrow bignum, and `CborDecode` already for invalid UTF-8. If the control fails, the splice is wrong; fix it before touching `decode_manifest`.

- [ ] **Step 3: Wire the walk in**

In `core/src/vault/manifest/decode/mod.rs`, make this the first statement of `decode_manifest`, above the `from_secret_reader` call:

```rust
    // Byte-level well-formedness, then crypto-design §6.2 rule 4, BEFORE
    // ciborium (#666) — the same pre-pass `record::decode` has run since
    // #641. ciborium reads `undefined` and the two-byte simple forms as
    // ordinary simple values, folds a bignum that fits 64 bits into an
    // integer and accepts nested indefinite chunks, so without this the
    // re-encode comparison below reported those bodies under a DIFFERENT
    // rule than `conformance.py` did — three of them in the `malformed_cbor`
    // class the differential replay never tolerates.
    //
    // It also gives `docs/vault-format.md` §4.2's well-formedness
    // precondition its precedence: a body that is not well-formed is
    // reported as that, whatever else it also breaks. The `?` discards the
    // returned end offset; trailing bytes are judged by the re-encode
    // comparison below, as they always have been.
    crate::vault::canonical::walk_first_item_checked(bytes, ManifestError::CborDecode)?;
```

Then extend the existing `reject_floats_and_tags` comment: it is now defence in depth on this path, exactly as `record.rs` words it.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --release --locked -p secretary-core --lib manifest
```

Expected: all green, including the pre-existing manifest tests.

- [ ] **Step 5: Prove no committed seed's token moved**

Re-run Task 1's manifest-seed probe (re-create the temporary probe file, run, delete) and diff against `$SCRATCH/baseline.txt`.

```bash
diff <(sort "$SCRATCH/baseline.txt") <(sort "$SCRATCH/after_task3.txt")
```

Expected: **no differences** among the 47 seeds. A moved token is a STOP: report which seed, its before and after token, and why, before continuing.

- [ ] **Step 6: Run the whole workspace**

```bash
cargo test --release --locked --workspace
```

Expected: exit 0. Record the test count.

- [ ] **Step 7: Lint and commit**

```bash
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo fmt --all
git add core/src/vault/manifest/
git commit -m "fix(core): decode_manifest walks the bytes for well-formedness first (#666)

Closes three cross-language divergences in the never-tolerated
malformed_cbor class (undefined, the two-byte simple form, a nested
indefinite chunk), one tolerated one (a bignum that fits 64 bits), and
gives vault-format §4.2's well-formedness precondition its precedence: a
body that is not well-formed is reported as that even when a tag or float
sits earlier in it. No committed seed's token moves; acceptance is
unchanged.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `block::decode_plaintext` runs the walk first

**Files:**
- Modify: `core/src/vault/block.rs`

**Interfaces:**
- Consumes: `walk_first_item_checked` (Task 2).
- Produces: the same precedence on the block-plaintext path. No replay target reaches it, so its only cover is these tests.

- [ ] **Step 1: Write the failing tests**

Add to `block.rs`'s test module, mirroring Task 3's five tests with a block-plaintext body builder. The body is a CBOR map carrying one unknown key — the walk runs before any key is interpreted, so a minimal map exercises the path:

```rust
/// A block plaintext carrying one unknown key whose value is `planted`.
/// The walk runs before any key is interpreted, so the map needs no valid
/// block fields for these tests; the control below proves the SPLICE is
/// what the other tests exercise, not the missing fields.
fn block_plaintext_with_unknown_value(planted: &[u8]) -> Vec<u8> {
    let mut body = vec![0xa1];
    ciborium::ser::into_writer(&ciborium::Value::Text("zz_future".into()), &mut body).unwrap();
    body.extend_from_slice(planted);
    body
}

#[test]
fn a_block_plaintext_that_is_not_well_formed_is_reported_as_malformed_cbor() {
    for (label, planted) in [
        ("undefined", &[0xf7u8][..]),
        ("two-byte simple", &[0xf8, 0x15][..]),
        ("nested indefinite chunk", &[0x5f, 0x5f, 0x41, 0x61, 0xff, 0xff][..]),
        ("invalid UTF-8 text", &[0x61, 0xff][..]),
    ] {
        let body = block_plaintext_with_unknown_value(planted);
        match decode_plaintext(&body) {
            Err(BlockError::CborDecode(_)) => {}
            other => panic!("{label}: expected CborDecode, got {other:?}"),
        }
    }
}

#[test]
fn a_narrow_bignum_in_a_block_plaintext_is_reported_as_a_rule_4_tag() {
    let body = block_plaintext_with_unknown_value(&[0xc2, 0x41, 0x01]);
    assert!(
        matches!(decode_plaintext(&body), Err(BlockError::TagRejected)),
        "expected TagRejected"
    );
}

#[test]
fn a_block_plaintext_well_formedness_fault_outranks_an_earlier_rule_4_fault() {
    for (label, planted) in [
        ("tag then undefined", &[0x82u8, 0xc2, 0x41, 0x01, 0xf7][..]),
        ("float then undefined", &[0x82, 0xf9, 0x00, 0x00, 0xf7][..]),
    ] {
        let body = block_plaintext_with_unknown_value(planted);
        match decode_plaintext(&body) {
            Err(BlockError::CborDecode(_)) => {}
            other => panic!("{label}: expected CborDecode, got {other:?}"),
        }
    }
}

/// The control. A benign value makes the SAME body fail on a missing
/// required block field, NOT on CBOR structure — which is what shows the
/// tests above are exercising the walk rather than the schema.
#[test]
fn the_same_block_splice_with_a_benign_value_fails_on_schema_not_structure() {
    let body = block_plaintext_with_unknown_value(&[0x00]);
    match decode_plaintext(&body) {
        Err(BlockError::CborDecode(_)) => panic!("a benign body must not be a CBOR fault"),
        Err(_) => {}
        Ok(_) => panic!("a body with no required fields must not decode"),
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test --release --locked -p secretary-core --lib block
```

Expected: the control passes; the well-formedness and precedence tests fail with the errors Task 1's §1.1 recorded for the block path.

- [ ] **Step 3: Wire the walk in**

Make this the first statement of `decode_plaintext`, above `from_secret_reader`, with a comment that (a) points at `record::decode` and `decode_manifest` as the sibling call sites, (b) says the returned offset is discarded because the re-encode comparison judges trailing bytes, and (c) notes that **no differential-replay target reaches this decoder** — `block_file` is the envelope — so these unit tests are its only cover, unlike the manifest path:

```rust
    crate::vault::canonical::walk_first_item_checked(bytes, BlockError::CborDecode)?;
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --release --locked -p secretary-core --lib block
```

Expected: all green.

- [ ] **Step 5: Run the whole workspace**

```bash
cargo test --release --locked --workspace
```

Expected: exit 0, the same count as Task 3 plus the new tests. Every vault-opening integration test exercises this path, so a green workspace here is the block half of the "acceptance unchanged" evidence.

- [ ] **Step 6: Lint and commit**

```bash
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo fmt --all
git add core/src/vault/block.rs
git commit -m "fix(core): block::decode_plaintext walks the bytes for well-formedness first (#666)

Same pre-pass as record::decode and decode_manifest, through the same
helper. No differential-replay target reaches this decoder, so the unit
tests added here are its only cover; the workspace suite, which opens
vaults throughout, is the evidence that acceptance did not move.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: The ciborium path pin narrows, and the bignum edge gets a Rust pin

**Files:**
- Modify: `core/tests/nesting_depth_seeds.rs`

**Interfaces:**
- Consumes: the wiring from Tasks 3 and 4.
- Produces: `Chain::BignumNarrowLast` and `Chain::BignumWideLast`, used only by the new test.

- [ ] **Step 1: Correct the existing test's doc**

`every_decode_path_enforces_exactly_the_v1_limit`'s doc currently says "the four paths that do not run the byte walk" and that the bignum edge "is #666's and is deliberately not a shape here". Both sentences are now wrong. Rewrite it to say: **two** paths still pin `ciborium` 0.2.2's limit (`ContactCard::from_canonical_cbor`, `IdentityBundle::from_canonical_cbor`); the other three pin the walk, which answers before ciborium runs. Say explicitly that this NARROWS what the test proves about ciborium — an upgrade moving the limit is now caught by two paths, not four — so a future reader does not read the row count as unchanged coverage.

The assertions themselves do not change: they compare `CborErrorKind::RecursionLimit`, and both mechanisms produce it.

- [ ] **Step 2: Write the failing test**

```rust
/// ciborium charges NO nesting level for a bignum tag over a definite-length
/// byte string of at most 16 bytes, so before #666 a document whose 257th
/// level was one slipped past the limit on every path that relied on
/// ciborium: the narrow form (value fits 64 bits) was folded to an integer
/// and reported by the re-encode, the wide form stayed a `Value::Tag` and
/// was reported as rule 4. Both are depth faults, and the byte walk charges
/// a level for a tag like any other container.
///
/// Scoped to the three WALK paths on purpose. `ContactCard` and
/// `IdentityBundle` still rely on ciborium and still do NOT refuse these
/// bodies for depth; that is #641's and #677's, not a gap this test hides.
#[test]
fn the_walk_paths_charge_a_level_for_a_short_bignum() {
    use secretary_core::vault::block::{decode_plaintext, BlockError};
    use secretary_core::vault::manifest::{decode_manifest, ManifestError};
    use secretary_core::vault::record::{decode, RecordError};

    type FaultOf = fn(&[u8]) -> Option<CborFault>;
    let paths: [(&str, FaultOf); 3] = [
        ("decode_manifest", |b| match decode_manifest(b) {
            Err(ManifestError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        ("block::decode_plaintext", |b| match decode_plaintext(b) {
            Err(BlockError::CborDecode(f)) => Some(f),
            _ => None,
        }),
        ("record::decode", |b| match decode(b) {
            Err(RecordError::CborDecode(f)) => Some(f),
            _ => None,
        }),
    ];
    for (name, fault_of) in paths {
        for shape in [Chain::BignumNarrowLast, Chain::BignumWideLast] {
            assert_ne!(
                fault_of(&nested_document(V1_MAX_NESTING_DEPTH, shape)).map(|f| f.kind),
                Some(CborErrorKind::RecursionLimit),
                "{name} refuses a {shape:?} chain of depth {V1_MAX_NESTING_DEPTH}, which rule 6 allows"
            );
            assert_eq!(
                fault_of(&nested_document(V1_MAX_NESTING_DEPTH + 1, shape)).map(|f| f.kind),
                Some(CborErrorKind::RecursionLimit),
                "{name} does not refuse a {shape:?} chain of depth {} with RecursionLimit",
                V1_MAX_NESTING_DEPTH + 1
            );
        }
    }
}
```

Extend `Chain` and `nested_document` to build the two shapes: the chain's last level is a bignum tag rather than an array, over a 1-byte string (`c2 41 01`) for `BignumNarrowLast` and a 9-byte one (`c2 49 01*9`) for `BignumWideLast`. Name the head bytes as constants beside the existing `TAG_1` / `ARRAY_1`.

- [ ] **Step 3: Run it to verify it fails on a reverted wiring**

The test should PASS with Tasks 3 and 4 in place. To show it is not vacuous, temporarily revert `decode_manifest`'s walk call, run, and confirm it reds; then restore.

```bash
cargo test --release --locked -p secretary-core --test nesting_depth_seeds
```

Expected after restore: green.

- [ ] **Step 4: Commit**

```bash
git add core/tests/nesting_depth_seeds.rs
git commit -m "test(core): pin the short-bignum depth edge on the three walk paths (#666)

ciborium charges no level for a bignum over a definite byte string of at
most 16 bytes, so that edge escaped the limit on every ciborium-backed
path. The walk charges it. Also corrects the sibling test's doc: two
paths still pin ciborium's limit, not four, which narrows what that test
proves about a ciborium upgrade.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: `py_decode_manifest` adopts `walk_body`, and Section CS pins the parking

**Files:**
- Modify: `core/tests/python/conformance_lib/codec/manifest_decode.py`
- Modify: `core/tests/python/conformance_lib/sections/cbor_scanner.py`
- Modify: `core/tests/python/conformance_lib/sections/nesting_depth.py` — this
  file is missing from the list above as originally written; the edit was
  necessary and was verified correct in the Task 6 review. NDL check 4 had
  hard-asserted the PRE-fix asymmetry (that `py_decode_manifest`'s depth
  pass and its rule-4 walk were two separate calls, in a specific order) as
  a deliberate property, and once `walk_body` replaced both with one call
  that assertion had to move with it or it would have reported a false
  divergence against the code it was written to describe.

**Interfaces:**
- Consumes: `walk_body` from `conformance_lib.codec.well_formed`.
- Produces: a Python manifest decoder whose rejection for a not-well-formed body is `MalformedCbor` (token `malformed_cbor`) even when a tag or float sits earlier.

- [ ] **Step 1: Write the failing Section CS check**

Add to `section_cbor_scanner_units` in `sections/cbor_scanner.py`, before the `if issues:` tail:

```python
    # --- walk_body PARKS a rule-4 fault behind a later well-formedness
    # --- fault. `docs/vault-format.md` §4.2 makes well-formedness the
    # --- precondition for both report orderings, so a body that is not
    # --- well-formed is reported as that "whatever else the body also
    # --- breaks" -- including a tag or float EARLIER in byte order. This is
    # --- a property of this implementation's traversal, asserted locally
    # --- rather than through a corpus row, because a corpus row would claim
    # --- it of every conformant reader (#618's review drew that line).
    parked = 0
    for label, raw in [
        ("tag then undefined", bytes([0x82, 0xC2, 0x41, 0x01, 0xF7])),
        ("float then undefined", bytes([0x82, 0xF9, 0x00, 0x00, 0xF7])),
        ("tag then bad chunk", bytes([0x82, 0xC2, 0x41, 0x01, 0x5F, 0x5F, 0x41, 0x61, 0xFF, 0xFF])),
    ]:
        try:
            walk_body(raw)
        except MalformedCbor:
            parked += 1
        except NonCanonicalItem as e:
            issues.append(f"walk_body {label}: reported rule {e.rule} where §4.2 requires the well-formedness fault")
        else:
            issues.append(f"walk_body {label}: accepted a body that is not well-formed")

    # --- and it still reports rule 4 when the body IS well-formed, so the
    # --- check above cannot pass by rejecting everything.
    rule4_seen = 0
    for label, raw in [
        ("tag alone", bytes([0xC2, 0x41, 0x01])),
        ("float alone", bytes([0xF9, 0x00, 0x00])),
    ]:
        try:
            walk_body(raw)
        except NonCanonicalItem:
            rule4_seen += 1
        except MalformedCbor as e:
            issues.append(f"walk_body {label}: reported {e} where rule 4 is the only fault")
        else:
            issues.append(f"walk_body {label}: accepted a rule-4 body")
```

and change the PASS return to report both counts:

```python
    return True, [f"PASS  CBOR scanner unit coverage ({parked} parked, {rule4_seen} rule-4)"]
```

Import `walk_body`, `MalformedCbor` and `NonCanonicalItem` at the top of the file.

- [ ] **Step 2: Run the verifier to see CS pass already**

```bash
uv run core/tests/python/conformance.py
```

Expected: **CS passes**, because `walk_body` already parks — the parking is `_walk`'s, and Task 6 does not change it. This check is a REGRESSION pin for `walk_body`, not a red-then-green step. Confirm it is not vacuous by temporarily making `_walk` raise `first_rule4` eagerly, re-running (CS must red), and restoring.

- [ ] **Step 3: Write the failing manifest-decoder check**

The decoder-level property is what is actually missing. Add a probe to the same section — or run it by hand and record the output — showing that `py_decode_manifest` today reports rule 4 for `82 c2 41 01 f7` spliced under an unknown key. Use the body files Task 1 wrote to `$SCRATCH/bodies`.

```bash
uv run --with cbor2 --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 python3 - <<'PY'
import pathlib, sys
ROOT = pathlib.Path("core/tests/python").resolve(); sys.path.insert(0, str(ROOT))
from conformance_lib.diff_replay import replay_bytes
for name in ["tag_then_undefined", "undefined_then_tag", "float_then_undefined", "undefined"]:
    p = pathlib.Path("SCRATCH/bodies") / f"{name}.bin"
    v = replay_bytes("manifest_body", p.read_bytes()).verdict
    print(f"{name:24} {v.get('rule')}")
PY
```

Expected BEFORE: `rule4_tag_or_float` for the first three, `malformed_cbor` for the last.

- [ ] **Step 4: Make the change**

In `codec/manifest_decode.py`, replace

```python
    reject_excessive_nesting(data, later_phases_scan_in_byte_order=True)
    ...
    reject_floats_and_tags(data)
```

with a single

```python
    walk_body(data)
```

Keep and rewrite the comment block: `walk_body` is a superset of both calls — it enforces rule 6 (what `reject_excessive_nesting` was there for), it raises rule 4 for the first tag or float (what `reject_floats_and_tags` was there for), and it parks that fault until the item has proven well-formed, which is the §4.2 precedence neither call gave. Note that the UTF-8 and simple-value checks it adds were already performed by `_scan_item` later in the function; what changes is that they now run BEFORE rule 4.

Fix the imports: drop `reject_excessive_nesting` and `reject_floats_and_tags` if nothing else in the file uses them; add `walk_body`.

- [ ] **Step 5: Re-run the probe and the verifier**

Expected AFTER: `malformed_cbor` for all four.

```bash
uv run core/tests/python/conformance.py
```

Expected: 0 FAIL, every section's counts as before, REG 35/35.

- [ ] **Step 6: Prove no committed seed's Python token moved except the intended ones**

Re-run Task 1 Step 4's Python baseline over the 47 seeds and diff.

```bash
diff <(sort "$SCRATCH/baseline_py.txt") <(sort "$SCRATCH/after_task6_py.txt")
```

Expected: **no differences**. A moved token is a STOP.

- [ ] **Step 7: Run the differential replay**

```bash
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

Expected: exit 0, and the finish lines still report every target's full input count.

- [ ] **Step 8: Commit**

```bash
git add core/tests/python/conformance_lib/codec/manifest_decode.py \
        core/tests/python/conformance_lib/sections/cbor_scanner.py
git commit -m "fix(conformance): py_decode_manifest reports the well-formedness fault first (#666)

Replaces reject_excessive_nesting + reject_floats_and_tags with the
single walk_body, which parks a rule-4 fault until the item has proven
well-formed -- vault-format §4.2's precondition, which the two separate
passes did not give. Section CS gains the parking pin. #666's claim that
this path checks neither UTF-8 nor simple values is stale: _scan_item has
checked both since #641; what was missing was precedence.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: `py_decode_trash_entry` adopts `walk_body` (#685)

**Files:**
- Modify: `core/tests/python/conformance_lib/codec/trash_entry.py`
- Modify: `core/tests/python/conformance_lib/sections/value_type_discipline.py` (one row)

**Interfaces:**
- Consumes: `walk_body`.
- Produces: `py_decode_trash_entry` returning a rule-4 verdict for a shareable-tag body instead of raising `RecursionError`.

- [ ] **Step 1: Reproduce #685**

```bash
uv run --with cbor2 --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 python3 - <<'PY'
import pathlib, sys, cbor2
ROOT = pathlib.Path("core/tests/python").resolve(); sys.path.insert(0, str(ROOT))
from conformance_lib.codec.trash_entry import py_decode_trash_entry
# A valid-shaped entry plus an unknown key holding tag28([tag29(0)]).
body = bytes([0xA1]) + cbor2.dumps("zz_future", canonical=True) + bytes([0xD8, 0x1C, 0x81, 0xD8, 0x1D, 0x00])
try:
    py_decode_trash_entry(body)
except RecursionError as e:
    print("REPRODUCED: RecursionError")
except Exception as e:
    print(f"{type(e).__name__}: {e}")
PY
```

Expected: `REPRODUCED: RecursionError` — a harness failure, not a verdict.

- [ ] **Step 2: Write the failing check**

Add a row to Section VT's case table (the section that already covers `codec/trash_entry.py`, which no replay target reaches) asserting that the shareable-tag body is REJECTED with a rule-4 rejection naming the tag — not a `RecursionError`, and not an encoder refusal. Follow the section's existing row shape; its PASS line is derived from the case table, so the count updates itself.

- [ ] **Step 3: Run the verifier to verify it fails**

```bash
uv run core/tests/python/conformance.py
```

Expected: Section VT FAILs on the new row. If instead the whole run aborts with a traceback, that is #682's missing per-section guard showing up — record it, and still proceed; the row must red either way once the guard exists.

- [ ] **Step 4: Make the change**

In `codec/trash_entry.py`, replace
`reject_excessive_nesting(data, later_phases_scan_in_byte_order=False)`
with `walk_body(data)`, and fix the import.

Add a comment saying: `walk_body` reads the tag off the BYTES, so `cbor2.loads`
below can no longer build a cyclic value from tags 28/29 — which is what made
the recursive `_reject_floats_and_tags_py` raise `RecursionError` (#685). The
`later_phases_scan_in_byte_order=False` argument is gone because `walk_body`
always raises; that was the same behaviour this caller asked for.

Keep the `_reject_floats_and_tags_py(decoded)` call as defence in depth, with
one line saying why it can no longer meet a cycle.

- [ ] **Step 5: Run the verifier to verify it passes**

```bash
uv run core/tests/python/conformance.py
```

Expected: 0 FAIL. Re-run Step 1's reproduction: it must now print a rule-4 rejection.

- [ ] **Step 6: Commit**

```bash
git add core/tests/python/conformance_lib/codec/trash_entry.py \
        core/tests/python/conformance_lib/sections/value_type_discipline.py
git commit -m "fix(conformance): walk trash-entry bytes before cbor2 resolves shareable tags (#685)

cbor2 resolves tags 28/29 into a genuinely cyclic list and strips both,
so a shareable-tag body made the recursive rule-4 walk raise
RecursionError -- a harness failure, not a verdict -- and tag 28 alone
never reached rule 4 at all. walk_body reads the tag off the bytes first.
The manifest path was immune because it never cbor2.loads the whole body.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: The `wellformed__` seed family

**Files:**
- Create: `core/tests/well_formed_seeds.rs`
- Create: `core/tests/well_formed_seeds_helpers/mod.rs`
- Create: `core/tests/well_formed_seeds_helpers/prefix.rs`
- Create: 7 × `core/fuzz/seeds/manifest_body/wellformed__*.bin`
- Modify: `core/tests/rule_token_seeds.rs` (nothing — see Step 1's note)

**Interfaces:**
- Consumes: `decode_manifest(..).rule_token()`.
- Produces: 7 committed seeds that CI replays through both decoders with a strict token comparison.

- [ ] **Step 1: Confirm no existing census claims the new prefix**

```bash
grep -n "SEEDED_TARGETS" core/tests/rule_token_seeds.rs core/tests/nesting_depth_seeds_helpers/mod.rs
```

Expected: `rule_token_seeds` owns `["block_file", "record"]` and `nesting_depth_seeds` owns `["manifest_body", "record"]` scoped to `SEED_PREFIX = "nesting__"`. So `manifest_body/wellformed__*` is claimed by nobody and **no exclusion needs adding anywhere**. Record that in the new helper's module doc — a future reader will ask.

- [ ] **Step 2: Write the helper table**

`core/tests/well_formed_seeds_helpers/prefix.rs`:

```rust
/// The file-name prefix this generator owns in `manifest_body/`.
///
/// Its own file so another test binary can `#[path]`-share it if it ever
/// needs to EXCLUDE this family, the way `rule_token_seeds.rs` shares
/// `nesting_depth_seeds_helpers/prefix.rs`. Nothing does today.
pub const SEED_PREFIX: &str = "wellformed__";
```

`core/tests/well_formed_seeds_helpers/mod.rs` holds:

- `pub struct WellFormedCase { pub label: &'static str, pub planted: &'static [u8], pub token: &'static str }`
- `pub fn all_cases() -> Vec<WellFormedCase>` with the seven rows from spec §5.1, each `planted` value written as named byte constants (`UNDEFINED`, `SIMPLE_TRUE_TWO_BYTE`, `NESTED_INDEFINITE_CHUNK`, `INVALID_UTF8_TEXT`, `BIGNUM_NARROW`, `TAG_THEN_MALFORMED`, `FLOAT_THEN_MALFORMED`) — no magic numbers.
- `pub const EXPECTED_CASE_COUNT: usize = 7;`
- `pub fn base() -> Vec<u8>` reading `manifest_body/uniq__control__all_distinct.bin`.
- `pub fn body_for(case: &WellFormedCase) -> Vec<u8>` performing the canonical-position splice of `("zz_future", planted)`. **The canonical position matters**: `zz_future` is 9 bytes, so RFC 8949 §4.2.1's length-first order puts it between `suite_id` (8) and `vault_uuid` (10). Appending it instead makes the body non-canonical and every row rejects for the wrong reason — the control row exists to catch exactly that.
- `pub fn file_name(case: &WellFormedCase) -> String` deriving the name from `SEED_PREFIX` and `label`, so a row whose name disagrees with what it plants is unconstructible.

- [ ] **Step 3: Write the tests**

`core/tests/well_formed_seeds.rs` holds five tests plus the `#[ignore]`d
generator — this said "four" while the code block below it defines five
(`the_case_table_holds_every_expected_row`, `every_row_plants_distinct_bytes`,
`the_base_and_a_benign_splice_are_both_accepted`,
`every_committed_seed_matches_its_row`, `the_prefix_census_is_two_way`),
which is what shipped:

```rust
#[test]
fn the_case_table_holds_every_expected_row() {
    assert_eq!(all_cases().len(), EXPECTED_CASE_COUNT);
}

/// Every row plants DIFFERENT bytes. Without it, three rows pointed at one
/// plant keep every name, token and census green while testing one shape —
/// the floor `rule_token_seeds.rs` added after the PR #673 review measured
/// exactly that.
#[test]
fn every_row_plants_distinct_bytes() {
    let mut planted: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    for case in all_cases() {
        let name = file_name(&case);
        if let Some(other) = planted.insert(body_for(&case), name.clone()) {
            panic!("seeds {other} and {name} plant identical bytes");
        }
    }
}

/// The base still ACCEPTS, and the splice with a benign value still
/// accepts. Without this the seven rows could all be rejecting because the
/// splice itself is malformed rather than because of what they plant.
#[test]
fn the_base_and_a_benign_splice_are_both_accepted() {
    assert!(
        decode_manifest(&base()).is_ok(),
        "the committed base must decode; the corpus row it comes from says so"
    );
    let benign = WellFormedCase {
        label: "benign_control",
        planted: &BENIGN_UINT,
        token: "",
    };
    assert!(
        decode_manifest(&body_for(&benign)).is_ok(),
        "the splice itself must be canonical: zz_future is 9 bytes, so RFC 8949 \
         §4.2.1 length-first order puts it between suite_id and vault_uuid"
    );
}

/// Each committed seed is on disk, byte-identical to the body its row
/// builds, and rejected by the real decoder with the row's token.
#[test]
fn every_committed_seed_matches_its_row() {
    for case in all_cases() {
        let name = file_name(&case);
        let path = seed_dir().join(&name);
        let on_disk = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("{name}: {e}. Regenerate with: {REGENERATE}"));
        assert_eq!(
            on_disk,
            body_for(&case),
            "{name}: committed bytes differ from the row's body. {REGENERATE}"
        );
        let got = match decode_manifest(&on_disk) {
            Ok(_) => panic!("{name}: accepted, its row expects token {}", case.token),
            Err(e) => format!("{:?}", e.rule_token()),
        };
        assert_eq!(
            got.to_lowercase().replace('_', ""),
            case.token.replace('_', ""),
            "{name}: decoder said {got}, its row says {}",
            case.token
        );
    }
}

/// The two-way census: every row has a file, and every file carrying this
/// generator's prefix has a row. A row and its seed deleted together are
/// invisible to it, which is what `EXPECTED_CASE_COUNT` pins separately.
#[test]
fn the_prefix_census_is_two_way() {
    let want: BTreeSet<String> = all_cases().iter().map(file_name).collect();
    let got: BTreeSet<String> = std::fs::read_dir(seed_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with(SEED_PREFIX))
        .collect();
    assert_eq!(got, want, "committed {SEED_PREFIX} seeds differ from the table. {REGENERATE}");
}

#[test]
#[ignore]
fn generate_well_formed_seeds() {
    // Assert EVERY row against the real decoder FIRST, buffering the bytes,
    // and only then write any file — so a wrong row panics with the corpus
    // untouched. This is the ordering #614's review had to fix in
    // manifest_canonicality_kat.rs, where the seed write sat INSIDE the
    // per-row loop while the fixture was written after it, so a mid-loop
    // panic left the two outputs disagreeing.
    let mut pending: Vec<(String, Vec<u8>)> = Vec::new();
    for case in all_cases() {
        let name = file_name(&case);
        let bytes = body_for(&case);
        let got = match decode_manifest(&bytes) {
            Ok(_) => panic!("{name}: accepted; its row expects token {}", case.token),
            Err(e) => format!("{:?}", e.rule_token()),
        };
        assert_eq!(
            got.to_lowercase().replace('_', ""),
            case.token.replace('_', ""),
            "{name}: decoder said {got}, its row says {}",
            case.token
        );
        pending.push((name, bytes));
    }
    for (name, bytes) in pending {
        std::fs::write(seed_dir().join(&name), &bytes).unwrap();
    }
}
```

- [ ] **Step 4: Run to verify they fail**

```bash
cargo test --release --locked -p secretary-core --test well_formed_seeds
```

Expected: `every_committed_seed_matches_its_row` FAILS (no files yet); the other three PASS.

- [ ] **Step 5: Generate the seeds**

```bash
cargo test --release --locked -p secretary-core --test well_formed_seeds \
  -- --ignored generate_well_formed_seeds
cargo test --release --locked -p secretary-core --test well_formed_seeds
ls core/fuzz/seeds/manifest_body/wellformed__*.bin | wc -l   # 7
```

Expected: 4 passed, 1 ignored.

- [ ] **Step 6: Regenerate and confirm byte-identical**

```bash
cargo test --release --locked -p secretary-core --test well_formed_seeds \
  -- --ignored generate_well_formed_seeds
git status --short   # the 7 seeds must show as ADDED, never as MODIFIED
```

- [ ] **Step 7: Replay them cross-language**

```bash
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

Expected: exit 0, `manifest_body` count up by 7, all agreeing. A disagreement here means Task 3 and Task 6 landed different precedence — report it with both tokens.

- [ ] **Step 8: Re-measure RTV's corpus-token set**

```bash
uv run core/tests/python/conformance.py 2>&1 | grep -i "RTV"
```

Expected: `_CORPUS_TOKENS` unchanged (both new tokens were already in the set). If RTV reds, it names the edit it wants — make it.

- [ ] **Step 9: Commit**

```bash
git add core/tests/well_formed_seeds.rs core/tests/well_formed_seeds_helpers/ \
        core/fuzz/seeds/manifest_body/wellformed__*.bin
git commit -m "test(core): seven committed manifest_body seeds for the ciborium leniencies (#666)

Four malformed_cbor shapes, one narrow-bignum rule-4 shape, and two
precedence rows (a rule-4 fault BEFORE the well-formedness fault) that are
the only cross-language pin on the walk's parking behaviour. A separate
generator rather than rule_token_seeds.rs, whose census owns every
labelled file in a seeded target's directory and would claim all 47
existing manifest_body seeds.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Two bignum depth seeds

**Files:**
- Modify: `core/tests/nesting_depth_seeds_helpers/mod.rs`
- Modify: `core/tests/nesting_depth_seeds.rs`
- Create: 2 × `core/fuzz/seeds/manifest_body/nesting__*.bin`

**Interfaces:**
- Consumes: the `NestingCase` table.
- Produces: two `Verdict::TooDeep` seeds whose 257th level is a bignum, at both widths.

- [ ] **Step 1: Extend the table**

Add a `DeepestLevel` dimension to `NestingCase`. The `Array` variant must render the file name **exactly as today**, or the seven existing seeds show as renamed:

```rust
/// What sits at the deepest level of the chain.
///
/// `Array` is every pre-#666 row. The two bignum variants exist because
/// `ciborium` charges NO level for a bignum tag over a definite-length byte
/// string of at most 16 bytes, and takes a DIFFERENT path for each width:
/// a value that fits 64 bits is folded to an integer, a 9-16-byte one stays
/// a `Value::Tag`. The byte walk charges a level for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeepestLevel {
    Array,
    BignumNarrow,
    BignumWide,
}

impl DeepestLevel {
    /// The EMPTY string for `Array`, so every pre-existing seed keeps its
    /// name byte for byte. A renamed seed would show as a delete plus an
    /// add and lose its history.
    fn label_suffix(self) -> &'static str {
        match self {
            DeepestLevel::Array => "",
            DeepestLevel::BignumNarrow => "_bignum_narrow",
            DeepestLevel::BignumWide => "_bignum_wide",
        }
    }

    /// The bytes that close the chain: one more array level, or a bignum
    /// tag over a byte string of the stated width.
    fn closing_bytes(self) -> Vec<u8> {
        match self {
            DeepestLevel::Array => vec![ARRAY_1, UINT_0],
            DeepestLevel::BignumNarrow => vec![BIGNUM_TAG, BYTES_1, 0x01],
            DeepestLevel::BignumWide => {
                let mut v = vec![BIGNUM_TAG, BYTES_9];
                v.extend(std::iter::repeat_n(0x01u8, BIGNUM_WIDE_LEN));
                v
            }
        }
    }
}
```

with the new byte constants named beside the existing `ARRAY_1` / `UINT_0`:

```rust
/// Tag 2, the unsigned-bignum tag (RFC 8949 §3.4.3).
const BIGNUM_TAG: u8 = 0xc2;
/// Major 2 (byte string), length 1.
const BYTES_1: u8 = 0x41;
/// Major 2, length 9 — one byte past the 8 that fit in a `u64`, which is
/// what makes `ciborium` keep a `Value::Tag` instead of folding to an int.
const BYTES_9: u8 = 0x49;
const BIGNUM_WIDE_LEN: usize = 9;
```

Add the two rows to `all_cases()` — `target: "manifest_body"`, `depth: V1_MAX_NESTING_DEPTH + 1`, `placement: Placement::Unknown`, one per bignum variant — extend `file_name` with `label_suffix`, extend `bytes()` to use `closing_bytes`, and bump `EXPECTED_CASE_COUNT` 7 → 9.

- [ ] **Step 2: Run to verify the count assertion fails first**

```bash
cargo test --release --locked -p secretary-core --test nesting_depth_seeds
```

Expected: `the_case_table_holds_every_expected_row` and the census FAIL (two rows with no files).

- [ ] **Step 3: Generate and verify**

```bash
cargo test --release --locked -p secretary-core --test nesting_depth_seeds \
  -- --ignored generate_nesting_depth_seeds
git status --short
```

Expected: exactly **two** new files, and **no existing seed modified**. A modified existing seed means the `Array` name or bytes moved — STOP and fix the derivation.

- [ ] **Step 4: Run the suite and the replay**

```bash
cargo test --release --locked -p secretary-core --test nesting_depth_seeds
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py 2>&1 | grep -iE "NDL|REG"
```

Expected: all green; NDL's check 6 now spells nine `nesting__` names; REG 35/35.

- [ ] **Step 5: Commit**

```bash
git add core/tests/nesting_depth_seeds.rs core/tests/nesting_depth_seeds_helpers/ \
        core/fuzz/seeds/manifest_body/nesting__*.bin
git commit -m "test(core): commit the short-bignum depth edge at both widths (#666)

ciborium folds a bignum of at most 8 bytes to an integer and keeps a
9-16-byte one as a Value::Tag, so the two took different paths and
neither was a depth fault before the walk. Both are now, in both
languages.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Mutation evidence, docs, and the full gate set

**Files:**
- Modify: `CLAUDE.md`, `README.md` (only if a stated fact moved), `ROADMAP.md`
- Create: the handoff at `docs/handoffs/2026-09-22-well-formedness-walk-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget the symlink)

- [ ] **Step 1: Write and run the mutation spec**

Write the spec from the design's §7 table to `$SCRATCH/wellformed.toml` — **never** the source tree (#516). Each row names its gate (#651). A Rust row whose mutation lives in an integration test needs a scoped probe (`probe = { package = "secretary-core", test = "<target>", features = [..] }`), and its gate must spell that scope out or the harness refuses the spec.

```bash
uv run scripts/mutate.py --self-test          # 20/20
uv run --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/wellformed.toml"
git status --short                            # MUST be empty
```

Expected: every row as declared. Paste the table into the handoff.

- [ ] **Step 2: Update CLAUDE.md**

Three paragraphs carry facts this slice moved. Edit each, and **re-measure rather than quoting**:

1. The manifest-module section's account of what `decode_manifest` catches — it now walks the bytes first, and the three never-tolerated divergences are closed.
2. The differential-replay section's committed-corpus count. Re-measure: `ls core/fuzz/seeds/*/* core/tests/data/diff_regressions/*/* | grep -v gitkeep | wc -l`. It said 131 before this slice.
3. The nesting-depth section's claim that the path pin covers "five paths" of which "only the first four pin CIBORIUM" — now two pin ciborium and three pin the walk.

- [ ] **Step 3: Update ROADMAP.md**

Move #666 and #685 to their closed state under the convention this repo uses (`(#N)`, never `Closes #N`).

- [ ] **Step 4: Run the whole gate set**

```bash
uv run core/tests/python/conformance.py
cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay
cargo test --release --locked --workspace
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo fmt --all --check
uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4"
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

Each guard's `--self-test` runs FIRST and as a LITERAL command — a zsh loop over them fails all of them.

- [ ] **Step 5: Replay the real fuzz corpus**

```bash
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core --features differential-replay \
  --test differential_replay -- differential_replay_full_corpus
rm core/fuzz/corpus && git status --short    # no corpus entry
```

Expected: full agreement over the ≈7,495 `record` inputs. This is the breadth evidence for "acceptance unchanged" that replaces #666's proptest.

- [ ] **Step 6: Write the handoff and retarget the symlink**

Author `docs/handoffs/2026-09-22-well-formedness-walk-shipped.md` covering: what shipped with commit SHAs; what is next with acceptance criteria; open decisions and risks; the exact resume commands; and — because this slice's central claim is a negative — the measurement tables from Task 1 and the mutation table from Step 1.

```bash
ln -snf docs/handoffs/2026-09-22-well-formedness-walk-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md ROADMAP.md README.md docs/handoffs/ NEXT_SESSION.md
git commit -m "docs: record the well-formedness walk slice (#666, #685)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Self-review notes

**Spec coverage.** §2 decision 1 → Task 2. Decision 2 → Task 2 Step 3. Decision 3 → Tasks 6 and 7. Decision 4 → no task, by construction (nothing touches `decode_value`). Decision 5 → Task 10 Step 5. §3.1 → Task 2. §3.2 → Tasks 2–4. §3.3 → Task 5. §3.4 → verified by Task 3 Step 5 and Task 8 Step 8. §4.1 → Task 6. §4.2 → Task 7. §4.3 → no code; Task 7 Step 4's comment states it. §5.1 → Task 8. §5.2 → Task 9. §6 → Task 6 Step 1 (CS), Task 8 Step 8 (RTV), Task 9 Step 4 (NDL). §7 → Task 10 Steps 1 and 5. §8 → no task, by construction. §9 → the file lists above.

**Placeholder scan: clean.** No `TBD`, no `unimplemented!`, no "similar to Task N", no "add appropriate error handling". The one construct an implementer must still resolve by reading the tree is the NAME of the fixture builder in Task 3 Step 1 (`test_support::valid_manifest` is a guess); the code around it is complete and asserts every assumption it makes, so a wrong name is a compile error rather than a body that silently rejects for the wrong reason.

**Type consistency.** `walk_first_item_checked(bytes, <Enum>::CborDecode)` is spelled identically in Tasks 2, 3 and 4. `WellFormedCase { label, planted, token }` is constructed in Task 8 Steps 2 and 3 with the same three fields. `file_name` is a free function taking `&WellFormedCase` throughout Task 8; `NestingCase::file_name` stays a method in Task 9, matching the file it already lives in. `Chain::BignumNarrowLast`/`BignumWideLast` (Task 5, a path-pin shape) and `DeepestLevel::BignumNarrow`/`BignumWide` (Task 9, a seed-table dimension) are deliberately different types in different files — they are not the same enum under two names.
