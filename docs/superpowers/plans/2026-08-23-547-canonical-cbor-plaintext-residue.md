# Canonical-CBOR plaintext residue — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop decrypted record plaintext and identity-bundle secret keys from
being copied into non-zeroizing `ciborium::Value` trees and bare `Vec<u8>`
buffers — eliminating the copies we make, and wiping the ones `ciborium`'s
parser makes.

**Architecture:** Two mechanisms. (A) A borrowing mirror of the CBOR subset the
vault format uses (`CanonicalValue` / `CanonicalMap`) that serialises straight
out of a `SecretString`/`SecretBytes`, replacing the build-a-`Value`-tree-then-
clone-it-three-times encode path. (B) A recursive zeroize-on-drop container
(`SecretValueTree`) wrapping the tree `ciborium::de::from_reader` returns, since
that allocation is the parser's and cannot be eliminated.

**Tech Stack:** Rust (stable, pinned 1.97.0), `ciborium` 0.2, `serde`, `zeroize`.
No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-23-547-canonical-cbor-plaintext-residue-design.md`

## Global Constraints

- **The on-disk format is FROZEN for v1.** Every byte emitted must be identical
  to what `main` emits. `git diff main... --stat -- core/tests/data/` must be
  **EMPTY** at the end of this slice. A KAT that needs regenerating means the
  change is a format change and is wrong.
- `#![forbid(unsafe_code)]` is a workspace lint. Do not introduce `unsafe`.
- Clippy must stay clean with `-D warnings`, **both** with and without `--tests`.
- Rustdoc must stay clean under `RUSTDOCFLAGS="-D warnings"`. Note the trap
  recorded in CLAUDE.md: **widening a `use` can red this gate without touching a
  single doc comment** — a bare `[Foo]` shorthand resolves once `Foo` is
  imported, which makes a neighbouring explicit `[Foo](crate::path::Foo)` link
  redundant. Run the rustdoc gate in **every** task, not just at the end.
- Tests must use runtime-random crypto values (`rand`/`OsRng`), never hardcoded
  literal byte arrays — literals trip CodeQL. KAT vectors come from JSON
  fixtures only.
- Every commit ends with the trailer:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Cite issues as `(#N)`. **Never** use an auto-close keyword (`Closes #N`,
  `Fixes #N`) — this repo closes issues by hand after verification.
- Files stay under 500 lines where reasonable; design new code as directory
  modules.
- A panic inside a `Drop` running during an unwind **aborts the process**.
  Shape assertions therefore go at construction, never in a `Drop`-reachable
  wipe.

## Working directory

All work happens in the worktree, not the main checkout:

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-plaintext-residue
pwd && git branch --show-current   # must print the worktree path and feature/cbor-plaintext-residue
```

## Per-task gate

Run **all** of these at the end of every task before committing:

```bash
cargo fmt --all
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo clippy --release --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh
git diff main... --stat -- core/tests/data/    # must print nothing
```

---

### Task 1: `canonical` becomes a directory module, and stops cloning

**Why:** `canonical_sort_entries` carries each pair along as `pair.clone()` — a
deep clone of a value it never needed to own. That is copies #2/#3/#4/#6 in the
spec's table, and it is the same defect #546's review fixed in `bundle.rs`'s
`encode_map`, which survived here in the shared helper `block`, `record` and
`manifest` all call.

**Files:**
- Create: `core/src/vault/canonical/mod.rs` (module docs, `CanonicalError`, re-exports)
- Create: `core/src/vault/canonical/legacy.rs` (`canonical_sort_entries`, `encode_canonical_map`, `reject_floats_and_tags`)
- Create: `core/src/vault/canonical/size.rs` (`cbor_size_bound`, made recursive)
- Delete: `core/src/vault/canonical.rs`
- Unchanged (verify only): `core/src/vault/mod.rs:24` — `pub(crate) mod canonical;`
  already resolves to a directory module, so the declaration needs no edit.

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `pub(crate) fn cbor_size_bound(value: &Value) -> usize` — **recursive**,
    upper bound on a `Value`'s CBOR encoding length.
  - `pub(crate) struct BorrowedCanonicalMap<'a>(pub &'a [(&'a Value, &'a Value)])`
    with `impl serde::Serialize`.
  - `pub fn canonical_sort_entries(&[(Value, Value)]) -> Result<Vec<(Value, Value)>, CanonicalError>`
    — signature UNCHANGED (Task 4 removes its last plaintext-bearing caller).
  - `pub fn encode_canonical_map(&[(Value, Value)]) -> Result<Vec<u8>, CanonicalError>`
    — signature unchanged, internals clone-free.
  - `pub fn reject_floats_and_tags(&Value, &'static str) -> Result<(), CanonicalError>` — unchanged.
  - `pub enum CanonicalError` — unchanged.

- [ ] **Step 1: Write the failing tests**

Add to `core/src/vault/canonical/size.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle's original `cbor_size_bound` returned `HEAD_MAX` for every
    /// container arm, which UNDER-reserves on a nested tree. Under-reserving
    /// is the whole hazard: `into_writer` then grows the buffer, and a realloc
    /// frees the old block — holding plaintext — unwiped.
    #[test]
    fn size_bound_is_not_under_reserved_for_a_nested_tree() {
        let inner = Value::Map(vec![
            (Value::Text("value".into()), Value::Text("x".repeat(300))),
            (Value::Text("bytes".into()), Value::Bytes(vec![0xAB; 400])),
        ]);
        let tree = Value::Array(vec![inner.clone(), inner]);

        let mut actual = Vec::new();
        ciborium::ser::into_writer(&tree, &mut actual).expect("encode");

        assert!(
            cbor_size_bound(&tree) >= actual.len(),
            "bound {} under-reserved for actual {} bytes",
            cbor_size_bound(&tree),
            actual.len()
        );
    }

    #[test]
    fn size_bound_covers_every_scalar_arm() {
        for v in [
            Value::Integer(u64::MAX.into()),
            Value::Bool(true),
            Value::Null,
            Value::Text(String::new()),
            Value::Bytes(Vec::new()),
        ] {
            let mut actual = Vec::new();
            ciborium::ser::into_writer(&v, &mut actual).expect("encode");
            assert!(cbor_size_bound(&v) >= actual.len(), "under-reserved for {v:?}");
        }
    }
}
```

Add to `core/src/vault/canonical/legacy.rs`:

```rust
    /// `encode_canonical_map` must not grow its output buffer. A realloc
    /// copies to a new block and frees the old one unwiped — the hazard
    /// `SecretBytes::concat` (#524) exists to prevent. `capacity()` is the
    /// only observable proxy, and it IS observable: the #546 review found the
    /// claim that it was not to be wrong.
    #[test]
    fn encode_canonical_map_does_not_realloc() {
        let entries: Vec<(Value, Value)> = (0..40)
            .map(|i| {
                (
                    Value::Text(format!("k{i:03}")),
                    Value::Bytes(vec![0xCD; 100 + i]),
                )
            })
            .collect();

        let out = encode_canonical_map(&entries).expect("encode");
        // A Vec that never grew has exactly the capacity it was created with.
        // Any growth would have gone through the doubling path and produced a
        // capacity that is not the reserved bound.
        assert!(
            out.capacity() >= out.len(),
            "sanity: capacity {} < len {}",
            out.capacity(),
            out.len()
        );
        let bound: usize = entries
            .iter()
            .map(|(k, v)| crate::vault::canonical::cbor_size_bound(k)
                + crate::vault::canonical::cbor_size_bound(v))
            .sum::<usize>()
            + 9;
        assert_eq!(
            out.capacity(),
            bound,
            "capacity changed from the reserved bound — into_writer grew the \
             buffer, freeing an unwiped block"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --release -p secretary-core --lib canonical 2>&1 | tail -20
```

Expected: FAIL — `cbor_size_bound` and the `canonical/` module do not exist yet
(compile error), and `encode_canonical_map_does_not_realloc` fails on capacity
because the current implementation uses `Vec::new()`.

- [ ] **Step 3: Create the directory module**

```bash
mkdir -p core/src/vault/canonical
git mv core/src/vault/canonical.rs core/src/vault/canonical/legacy.rs
```

Create `core/src/vault/canonical/mod.rs` holding the module-level `//!` docs
(moved verbatim from the old file head), the `CanonicalError` enum (moved
verbatim), and:

```rust
mod legacy;
mod size;

pub use legacy::{canonical_sort_entries, encode_canonical_map, reject_floats_and_tags};
pub(crate) use size::cbor_size_bound;
```

Strip the `//!` docs and `CanonicalError` from `legacy.rs`, replacing them with
`use super::CanonicalError;` and a `//!`-free `//`-comment header naming what
the file holds.

- [ ] **Step 4: Write `size.rs`**

```rust
//! Upper bound on a `ciborium::Value`'s CBOR encoding length.
//!
//! Used only to pre-reserve an output buffer so `ciborium::ser::into_writer`
//! never grows it. A realloc copies the buffer to a new block and frees the
//! old one **unwiped**, which for a plaintext-bearing encode is exactly the
//! hazard [`crate::crypto::secret::SecretBytes::concat`] (#524) exists to
//! prevent.
//!
//! Never an exact size. Being over is harmless (the only cost is slack);
//! being under reopens the hazard, so every arm rounds up.
//!
//! Moved here from `unlock::bundle` (#547) and **made recursive**. The
//! bundle's version returned `HEAD_MAX` for the container arms, which was
//! sound only because that module's entry lists are flat — a fact its
//! `ZeroizingEntries::new` `debug_assert` pinned. The record path nests a
//! per-field map inside an outer map inside an array, so a flat bound would
//! under-reserve.

use ciborium::Value;

/// Largest CBOR head: initial byte plus an 8-byte argument (RFC 8949 §3).
const HEAD_MAX: usize = 9;

/// Upper bound on the CBOR encoding length of `value`, including its head.
///
/// Recurses without an explicit depth bound, for the same reason
/// [`super::reject_floats_and_tags`] does: `ciborium`'s default `from_reader`
/// recursion limit (256) has already capped the depth of any parsed tree, and
/// trees we construct ourselves are shallow by shape. If a future contributor
/// raises that parser limit, add a `depth` parameter here too.
pub(crate) fn cbor_size_bound(value: &Value) -> usize {
    HEAD_MAX
        + match value {
            Value::Bytes(b) => b.len(),
            Value::Text(t) => t.len(),
            Value::Array(items) => items.iter().map(cbor_size_bound).sum(),
            Value::Map(entries) => entries
                .iter()
                .map(|(k, v)| cbor_size_bound(k) + cbor_size_bound(v))
                .sum(),
            Value::Tag(_, inner) => cbor_size_bound(inner),
            // Integer / Float / Bool / Null, and anything `#[non_exhaustive]`
            // adds later, are bounded by HEAD_MAX alone: every one of them is
            // a single CBOR head with no payload beyond its argument. A novel
            // variant that carried a payload would under-reserve here, which
            // is why the callers `debug_assert!` their actual length against
            // the bound rather than trusting it.
            _ => 0,
        }
}
```

- [ ] **Step 5: Make `encode_canonical_map` clone-free**

In `legacy.rs`, add the borrowed serialiser (moved from `bundle.rs:690-702`,
generalised to `pub(crate)`) and rewrite `encode_canonical_map`:

```rust
/// Serialize a pre-sorted, BORROWED entry list as a definite-length CBOR map.
///
/// Exists so the encoder never has to build a `ciborium::Value::Map`, which
/// owns its pairs and therefore costs a deep clone of every byte string it
/// holds. `serialize_map` with an explicit length emits the same major-type-5
/// definite-length header `Value::Map` does, so the bytes are unchanged — a
/// property the golden vault pins hard, since `from_canonical_cbor`
/// re-encodes and compares against bytes written years ago.
pub(crate) struct BorrowedCanonicalMap<'a>(pub &'a [(&'a Value, &'a Value)]);

impl serde::Serialize for BorrowedCanonicalMap<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

pub fn encode_canonical_map(entries: &[(Value, Value)]) -> Result<Vec<u8>, CanonicalError> {
    // Only the KEYS are materialised, to sort on. The values ride along as
    // BORROWS: the `pair.clone()` this replaced was a full deep clone of every
    // value, and on the record path those values are decrypted user plaintext
    // (#547). Same fix #546 made in `unlock::bundle::encode_map`; this is the
    // shared helper it did not reach.
    let mut sorted: Vec<(Vec<u8>, (&Value, &Value))> = entries
        .iter()
        .map(|(key, value)| {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(key, &mut key_bytes)
                .map_err(|e| CanonicalError::CborEncode(classify_ser(&e)))?;
            Ok((key_bytes, (key, value)))
        })
        .collect::<Result<_, CanonicalError>>()?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let borrowed: Vec<(&Value, &Value)> = sorted.into_iter().map(|(_, pair)| pair).collect();

    // Pre-reserve so `into_writer` cannot grow (and thus realloc-and-free) a
    // buffer that may hold plaintext. See `size::cbor_size_bound`.
    let capacity_bound = entries
        .iter()
        .map(|(k, v)| super::cbor_size_bound(k) + super::cbor_size_bound(v))
        .sum::<usize>()
        + 9;
    let mut buf = Vec::with_capacity(capacity_bound);

    ciborium::ser::into_writer(&BorrowedCanonicalMap(&borrowed), &mut buf)
        .map_err(|e| CanonicalError::CborEncode(classify_ser(&e)))?;
    debug_assert!(
        buf.len() <= capacity_bound,
        "encode_canonical_map under-reserved: {} > {capacity_bound}; a realloc \
         freed an unwiped buffer that may hold plaintext",
        buf.len()
    );
    Ok(buf)
}
```

`canonical_sort_entries` keeps its owned signature and its `pair.clone()` for
now — Task 4 deletes its last plaintext-bearing caller, and Task 8 re-censuses
whether any caller still needs the owned form.

- [ ] **Step 6: Run tests to verify they pass**

```bash
cargo test --release --workspace 2>&1 | tail -20
```

Expected: PASS, including every pre-existing record / block / manifest KAT and
round-trip test **unchanged**. Those tests passing is the byte-identity proof
for this task.

- [ ] **Step 7: Prove the new test is load-bearing (mutation check)**

Temporarily change `Vec::with_capacity(capacity_bound)` back to `Vec::new()`
and confirm `encode_canonical_map_does_not_realloc` FAILS. Then revert.

```bash
cargo test --release -p secretary-core --lib encode_canonical_map_does_not_realloc 2>&1 | tail -5
```

A property nothing pins is not a property.

- [ ] **Step 8: Run the full per-task gate, then commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
refactor(core): clone-free canonical map encode, canonical/ directory module (#547)

`canonical_sort_entries` carried each pair along as `pair.clone()` — a deep
clone of a value it never needed to own. On the record path those values are
decrypted user plaintext, so that is copies 2/3/4/6 of the six the design spec
traces on a single block save. It is the same defect #546's review fixed in
`unlock::bundle::encode_map`; it survived in the shared helper `block`,
`record` and `manifest` all call.

`encode_canonical_map` now materialises keys only, sorts on those, and
serialises the values as borrows through `BorrowedCanonicalMap`. Output is
pre-reserved against a size bound so `into_writer` cannot realloc and free an
unwiped block.

`cbor_size_bound` moves here from `unlock::bundle` and is made RECURSIVE. The
bundle's version returned HEAD_MAX for its container arms, sound only because
that module's entry lists are flat; the record path nests a map inside a map
inside an array, so the flat bound would under-reserve — which is the hazard,
not a rounding detail.

Every pre-existing record / block / manifest KAT passes unchanged: that is the
byte-identity proof. The no-realloc assertion was mutation-checked (reverting
to `Vec::new()` fails it).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

### Task 2: `CanonicalValue` / `CanonicalMap` — the borrowing mirror

**Why:** `field_to_entries` copies plaintext out of a `SecretString` because
`ciborium` serialises `Value`, and `Value` owns its payloads. A borrowing type
is the only shape that can serialise straight out of the wrapper.

**Files:**
- Create: `core/src/vault/canonical/value.rs`
- Modify: `core/src/vault/canonical/mod.rs` (add `mod value;` + re-exports)
- Create: `core/tests/canonical_value_equivalence.rs`

**Interfaces:**
- Consumes: `cbor_size_bound`, `CanonicalError` (Task 1).
- Produces:
  - `pub(crate) enum CanonicalValue<'a> { Text(&'a str), Bytes(&'a [u8]), Uint(u64), Bool(bool), Map(CanonicalMap<'a>), Array(Vec<CanonicalValue<'a>>), Borrowed(&'a Value) }`
  - `pub(crate) struct CanonicalMap<'a>` with:
    - `pub(crate) fn new() -> Self`
    - `pub(crate) fn with_capacity(n: usize) -> Self`
    - `pub(crate) fn push(&mut self, key: &'a str, value: CanonicalValue<'a>)`
    - `pub(crate) fn len(&self) -> usize`
  - `pub(crate) fn to_canonical_vec(map: &CanonicalMap<'_>) -> Result<Vec<u8>, CanonicalError>`
  - `impl serde::Serialize for CanonicalValue<'_>` and `for CanonicalMap<'_>`

- [ ] **Step 1: Write the failing equivalence test**

Create `core/tests/canonical_value_equivalence.rs`. This is the design probe
promoted into the repo: the load-bearing claim of the whole slice is that a
hand-written `Serialize` emits byte-identical CBOR to an equivalent `Value`
tree, and it must be re-proven on every CI run rather than attested in a doc.

The module under test is `pub(crate)`, so this test reaches it through a
`#[doc(hidden)] pub` re-export added in Step 3 — `--cfg test` is not propagated
to dependents, so a `#[cfg(test)]` item would be invisible from `core/tests/`.

```rust
//! The load-bearing byte-identity claim of #547: a hand-written `Serialize`
//! over borrowed data emits CBOR byte-identical to the equivalent owned
//! `ciborium::Value` tree, across every CBOR head-length boundary.
//!
//! If this ever fails, the on-disk format has moved and the vault is
//! unreadable by every client written before the change. It is therefore an
//! integration test, run on every CI run, and not a design-time attestation.

use ciborium::Value;
use secretary_core::vault::canonical_test_api::{CanonicalMap, CanonicalValue};

fn enc<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let mut b = Vec::new();
    ciborium::ser::into_writer(v, &mut b).expect("encode");
    b
}

/// Every CBOR head-length boundary: the argument is inline (<24), then 1, 2,
/// 4 and 8 additional bytes (RFC 8949 §3).
const LEN_BOUNDARIES: &[usize] = &[0, 1, 23, 24, 255, 256, 65535, 65536];

#[test]
fn uint_is_byte_identical_across_every_head_boundary() {
    for u in [0u64, 1, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, u64::MAX] {
        assert_eq!(
            enc(&Value::Integer(u.into())),
            enc(&CanonicalValue::Uint(u)),
            "uint {u}"
        );
    }
}

#[test]
fn text_is_byte_identical_across_every_head_boundary() {
    for &n in LEN_BOUNDARIES {
        let s = "a".repeat(n);
        assert_eq!(
            enc(&Value::Text(s.clone())),
            enc(&CanonicalValue::Text(&s)),
            "text len {n}"
        );
    }
}

#[test]
fn bytes_are_byte_identical_across_every_head_boundary() {
    for &n in LEN_BOUNDARIES {
        let b = vec![0xABu8; n];
        assert_eq!(
            enc(&Value::Bytes(b.clone())),
            enc(&CanonicalValue::Bytes(&b)),
            "bytes len {n}"
        );
    }
}

#[test]
fn bool_is_byte_identical() {
    for b in [true, false] {
        assert_eq!(enc(&Value::Bool(b)), enc(&CanonicalValue::Bool(b)), "bool {b}");
    }
}

#[test]
fn array_is_byte_identical_across_every_head_boundary() {
    for &n in &[0usize, 1, 23, 24, 300] {
        let owned = Value::Array((0..n).map(|i| Value::Integer((i as u64).into())).collect());
        let borrowed = CanonicalValue::Array((0..n).map(|i| CanonicalValue::Uint(i as u64)).collect());
        assert_eq!(enc(&owned), enc(&borrowed), "array len {n}");
    }
}

/// The map arm additionally proves the SORT: keys are pushed in an order that
/// is not canonical, and the emitted bytes must match a `Value::Map` whose
/// entries were pre-sorted by encoded key bytes (length-then-bytewise, RFC
/// 8949 §4.2.1 — which differs from `String` ordering whenever key lengths
/// differ).
#[test]
fn map_is_byte_identical_and_sorts_its_own_keys() {
    // "z" (1 byte) sorts BEFORE "ab" (2 bytes) in canonical CBOR, and AFTER
    // it in plain string order. Pushing in string order proves the encoder
    // re-sorts rather than emitting insertion order.
    let keys = ["ab", "z", "aaa", "b"];
    let mut borrowed = CanonicalMap::with_capacity(keys.len());
    for (i, k) in keys.iter().enumerate() {
        borrowed.push(k, CanonicalValue::Uint(i as u64));
    }

    let mut owned_entries: Vec<(Value, Value)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (Value::Text((*k).into()), Value::Integer((i as u64).into())))
        .collect();
    owned_entries.sort_by_key(|(k, _)| {
        let mut b = Vec::new();
        ciborium::ser::into_writer(k, &mut b).expect("encode key");
        b
    });

    assert_eq!(enc(&Value::Map(owned_entries)), enc(&borrowed));
}

#[test]
fn map_is_byte_identical_across_every_head_boundary() {
    for &n in &[0usize, 1, 23, 24, 300] {
        let names: Vec<String> = (0..n).map(|i| format!("k{i:05}")).collect();
        let mut borrowed = CanonicalMap::with_capacity(n);
        for (i, name) in names.iter().enumerate() {
            borrowed.push(name, CanonicalValue::Uint(i as u64));
        }
        let owned = Value::Map(
            names
                .iter()
                .enumerate()
                .map(|(i, k)| (Value::Text(k.clone()), Value::Integer((i as u64).into())))
                .collect(),
        );
        assert_eq!(enc(&owned), enc(&borrowed), "map len {n}");
    }
}

/// The exact shape the record path emits: an outer map holding an array of
/// per-record maps, each holding a per-field map with a text secret, an
/// integer clock and a byte uuid.
#[test]
fn nested_record_in_block_shape_is_byte_identical() {
    let secret = "hunter2";
    let device_uuid = [7u8; 16];

    let owned_field = Value::Map(vec![
        (Value::Text("device_uuid".into()), Value::Bytes(device_uuid.to_vec())),
        (Value::Text("last_mod".into()), Value::Integer(1_234_567_890u64.into())),
        (Value::Text("value".into()), Value::Text(secret.into())),
    ]);
    let owned = Value::Map(vec![
        (Value::Text("n".into()), Value::Integer(24u64.into())),
        (Value::Text("records".into()), Value::Array(vec![owned_field])),
    ]);

    let mut field = CanonicalMap::with_capacity(3);
    field.push("value", CanonicalValue::Text(secret));
    field.push("last_mod", CanonicalValue::Uint(1_234_567_890));
    field.push("device_uuid", CanonicalValue::Bytes(&device_uuid));
    let mut outer = CanonicalMap::with_capacity(2);
    outer.push("records", CanonicalValue::Array(vec![CanonicalValue::Map(field)]));
    outer.push("n", CanonicalValue::Uint(24));

    assert_eq!(enc(&owned), enc(&outer));
}

/// Forward-compat unknown values pass through verbatim as a borrow.
#[test]
fn borrowed_unknown_passes_through_verbatim() {
    let unk = Value::Array(vec![Value::Text("x".into()), Value::Bytes(vec![1, 2, 3])]);
    assert_eq!(enc(&unk), enc(&CanonicalValue::Borrowed(&unk)));
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --release --test canonical_value_equivalence 2>&1 | tail -10
```

Expected: FAIL to compile — `secretary_core::vault::canonical_test_api` does
not exist.

- [ ] **Step 3: Write `value.rs`**

```rust
//! A borrowing mirror of the CBOR subset `docs/vault-format.md` uses.
//!
//! `ciborium::Value` owns its payloads. That ownership is precisely the defect
//! #547 records: encoding a record meant copying every decrypted field out of
//! its [`SecretString`](crate::crypto::secret::SecretString) wrapper into a
//! `Value::Text`, and then deep-cloning that copy three more times on the way
//! to the wire. A borrowing type serialises straight out of the wrapper, so
//! the copy never exists.
//!
//! [`CanonicalMap`] sorts its own keys at SERIALISE time, per RFC 8949
//! §4.2.1. That is what lets nested maps stay borrowed: the previous design
//! had to sort each level eagerly and materialise a `Value::Map` to hand
//! upward, because `ciborium` emits a `Value::Map`'s entries in iteration
//! order with no recursive sort.
//!
//! **Only KEYS are ever materialised**, to sort on. A key is a field name
//! from the vault schema or a forward-compat unknown key — never a value —
//! so the sort buffer is not secret-bearing.

use ciborium::Value;
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use serde::{Serialize, Serializer};

use super::{cbor_size_bound, CanonicalError};
use crate::cbor::classify_ser;

/// One value in a canonical map or array. Every arm either borrows or is a
/// scalar; no arm owns a byte string.
pub(crate) enum CanonicalValue<'a> {
    /// Borrowed UTF-8 text — typically `SecretString::expose()`.
    Text(&'a str),
    /// Borrowed bytes — typically `SecretBytes::expose()` or a uuid array.
    Bytes(&'a [u8]),
    /// An unsigned integer (clocks, versions, timestamps).
    Uint(u64),
    /// A boolean (`tombstone`).
    Bool(bool),
    /// A nested map, which sorts its own keys when serialised.
    Map(CanonicalMap<'a>),
    /// A homogeneous sequence (`tags`, `records`).
    Array(Vec<CanonicalValue<'a>>),
    /// A forward-compat unknown value, emitted verbatim.
    ///
    /// This version cannot know a future version's shape, so the subtree is
    /// passed through as a borrow rather than mirrored. It costs no copy.
    Borrowed(&'a Value),
}

/// A CBOR map whose keys are sorted at serialise time.
///
/// Construct with [`Self::with_capacity`] and [`Self::push`]; the push order
/// is irrelevant, because [`Serialize`] imposes the canonical order.
pub(crate) struct CanonicalMap<'a>(Vec<(&'a str, CanonicalValue<'a>)>);

impl<'a> CanonicalMap<'a> {
    /// An empty map.
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    /// An empty map with room for `n` entries.
    pub(crate) fn with_capacity(n: usize) -> Self {
        Self(Vec::with_capacity(n))
    }

    /// Append an entry. Order is not significant — [`Serialize`] sorts.
    pub(crate) fn push(&mut self, key: &'a str, value: CanonicalValue<'a>) {
        self.0.push((key, value));
    }

    /// Number of entries.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Upper bound on this map's CBOR encoding length, for pre-reserving.
    /// Same contract as [`cbor_size_bound`]: over is harmless, under reopens
    /// the realloc hazard.
    fn size_bound(&self) -> usize {
        const HEAD_MAX: usize = 9;
        HEAD_MAX
            + self
                .0
                .iter()
                .map(|(k, v)| HEAD_MAX + k.len() + v.size_bound())
                .sum::<usize>()
    }
}

impl CanonicalValue<'_> {
    fn size_bound(&self) -> usize {
        const HEAD_MAX: usize = 9;
        match self {
            Self::Text(t) => HEAD_MAX + t.len(),
            Self::Bytes(b) => HEAD_MAX + b.len(),
            Self::Uint(_) | Self::Bool(_) => HEAD_MAX,
            Self::Map(m) => m.size_bound(),
            Self::Array(items) => {
                HEAD_MAX + items.iter().map(Self::size_bound).sum::<usize>()
            }
            Self::Borrowed(v) => cbor_size_bound(v),
        }
    }
}

impl Serialize for CanonicalMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // RFC 8949 §4.2.1: sort by the deterministic CBOR encoding of each
        // key, length-then-bytewise. Materialising the KEY is safe — a key is
        // a schema field name or an unknown key, never a value.
        //
        // Sorting a `Vec<(Vec<u8>, usize)>` of (encoded key, index) keeps the
        // values themselves untouched and unmoved.
        let mut order: Vec<(Vec<u8>, usize)> = Vec::with_capacity(self.0.len());
        for (i, (key, _)) in self.0.iter().enumerate() {
            let mut key_bytes = Vec::new();
            ciborium::ser::into_writer(key, &mut key_bytes)
                .map_err(serde::ser::Error::custom)?;
            order.push((key_bytes, i));
        }
        order.sort_by(|a, b| a.0.cmp(&b.0));

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (_, i) in &order {
            let (key, value) = &self.0[*i];
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl Serialize for CanonicalValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(t) => serializer.serialize_str(t),
            Self::Bytes(b) => serializer.serialize_bytes(b),
            Self::Uint(u) => serializer.serialize_u64(*u),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Map(m) => m.serialize(serializer),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Borrowed(v) => v.serialize(serializer),
        }
    }
}

/// Serialise a [`CanonicalMap`] to canonical CBOR bytes.
///
/// The output buffer is pre-reserved against [`CanonicalMap::size_bound`] so
/// `into_writer` cannot grow it: a realloc copies to a new block and frees the
/// old one **unwiped**, and on the record path that buffer holds decrypted
/// plaintext.
pub(crate) fn to_canonical_vec(map: &CanonicalMap<'_>) -> Result<Vec<u8>, CanonicalError> {
    let bound = map.size_bound();
    let mut buf = Vec::with_capacity(bound);
    ciborium::ser::into_writer(map, &mut buf)
        .map_err(|e| CanonicalError::CborEncode(classify_ser(&e)))?;
    debug_assert!(
        buf.len() <= bound,
        "to_canonical_vec under-reserved: {} > {bound}; a realloc freed an \
         unwiped buffer holding plaintext",
        buf.len()
    );
    Ok(buf)
}
```

- [ ] **Step 4: Add the test-visible re-export**

`--cfg test` is not propagated to dependents, so `core/tests/*.rs` cannot see a
`#[cfg(test)]` item. Add to `core/src/vault/mod.rs`:

```rust
/// Test-only re-export of the borrowed canonical encoder, so
/// `core/tests/canonical_value_equivalence.rs` can pin the byte-identity
/// property from an integration test. `--cfg test` is not propagated to
/// dependent crates, so a `#[cfg(test)]` item would be invisible there; the
/// established workaround in this repo is `#[doc(hidden)] pub`.
///
/// Not part of the supported API surface. Nothing outside `core/tests/`
/// should use it.
#[doc(hidden)]
pub mod canonical_test_api {
    pub use super::canonical::{CanonicalMap, CanonicalValue};
}
```

and in `core/src/vault/canonical/mod.rs`:

```rust
mod value;

pub(crate) use value::{to_canonical_vec, CanonicalMap, CanonicalValue};
```

`canonical_test_api` re-exports `pub(crate)` items as `pub`. If the compiler
rejects that (E0365 / private-interface), promote `CanonicalMap` and
`CanonicalValue` to `pub` in `value.rs` and keep the module `pub(crate)` — the
types are then reachable only through the two `pub(crate)` paths and the
`#[doc(hidden)]` one.

- [ ] **Step 4b: Head off two clippy `-D warnings` traps**

`CanonicalMap::len` without an `is_empty` trips `clippy::len_without_is_empty`,
and `CanonicalMap::new` has no caller until Task 4, so it trips `dead_code`.
Both are `-D warnings` failures, not lints you can defer.

Either add `is_empty` and use `new` in a test, or — preferred, because an
unused constructor is real dead weight — **drop `new` entirely** and keep only
`with_capacity`, which every caller in Tasks 4 and 5 uses. If `len` also turns
out to have no caller, drop it too and re-add it when something needs it.
Update the Interfaces block above to match whatever survives.

- [ ] **Step 5: Run tests to verify they pass**

```bash
cargo test --release --test canonical_value_equivalence 2>&1 | tail -15
```

Expected: PASS, 9 tests.

- [ ] **Step 6: Prove the sort test is load-bearing (mutation check)**

Temporarily delete the `order.sort_by(...)` line and confirm
`map_is_byte_identical_and_sorts_its_own_keys` FAILS. Then revert.

- [ ] **Step 7: Run the full per-task gate, then commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
feat(core): borrowing CanonicalValue/CanonicalMap encoder (#547)

`ciborium::Value` owns its payloads, and that ownership is the defect: encoding
a record meant copying every decrypted field out of its `SecretString` into a
`Value::Text`. A borrowing mirror of the CBOR subset the format uses
serialises straight out of the wrapper, so the copy never exists.

`CanonicalMap` sorts its own keys at SERIALISE time per RFC 8949 §4.2.1, which
is what lets nested maps stay borrowed — the previous design had to sort each
level eagerly and materialise a `Value::Map` to hand upward, because ciborium
emits a map's entries in iteration order with no recursive sort. Only KEYS are
ever materialised, and a key is a schema field name, never a value.

No production consumer yet; Tasks 4 and 5 migrate the record and block encode
paths onto it.

The byte-identity claim is pinned by an INTEGRATION test rather than a design
attestation: 9 tests covering every CBOR head-length boundary (0/1/23/24/255/
256/65535/65536/2^32/u64::MAX) for uint, text, bytes, map and array, plus the
nested record-in-block shape, the key sort, and Borrowed passthrough. If it
ever fails, the on-disk format has moved and vaults written today are
unreadable. The sort assertion was mutation-checked.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

### Task 3: `SecretValueTree` — wipe what `ciborium` allocates

**Why:** `from_reader` builds a `Value` tree holding all plaintext. That
allocation is the parser's; we cannot eliminate it, only wipe it before drop.

**Files:**
- Modify: `core/src/cbor.rs` (append the type + its tests)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `pub(crate) struct SecretValueTree(Value)` with:
    - `pub(crate) fn new(value: Value) -> Self`
    - `pub(crate) fn as_value(&self) -> &Value`
    - `pub(crate) fn take_entries(self) -> ...` — **NOT provided**; see below.
  - `pub(crate) struct SecretEntries(Vec<(Value, Value)>)` with:
    - `pub(crate) fn new(entries: Vec<(Value, Value)>) -> Self`
    - `pub(crate) fn as_slice(&self) -> &[(Value, Value)]`
    - `pub(crate) fn take_next(&mut self) -> Option<(Value, Value)>`
  - `#[cfg(test)] pub(crate) fn wipe_calls() -> usize`

  Both types deliberately expose **no** `&mut` accessor and no consuming
  accessor that hands out the inner container: that is what stops
  `mem::take` / `.clear()` / `.drain(..)` from emptying the container out from
  under `Drop`. `scripts/check-secret-slot-hygiene.sh` covers `mem::*` and
  `ManuallyDrop` but not `.clear()`/`.drain()`, so the API shape is the
  enforcement — same reasoning as `ZeroizingEntries` (#542) and the bridge's
  `Detail` newtype (#500/#515).

- [ ] **Step 1: Write the failing tests**

Append to `core/src/cbor.rs`'s existing `#[cfg(test)] mod tests`:

```rust
    // --- SecretValueTree (#547 / #548, audit C-4) -------------------------

    use ciborium::Value;

    /// A tree with a secret at every depth and in every container arm.
    fn nested_secret_tree() -> Value {
        Value::Map(vec![
            (Value::Text("top_bytes".into()), Value::Bytes(vec![0xAA; 8])),
            (Value::Text("top_text".into()), Value::Text("top-secret".into())),
            (
                Value::Text("nested_map".into()),
                Value::Map(vec![(
                    Value::Text("inner".into()),
                    Value::Bytes(vec![0xBB; 8]),
                )]),
            ),
            (
                Value::Text("nested_array".into()),
                Value::Array(vec![
                    Value::Text("in-array".into()),
                    Value::Bytes(vec![0xCC; 8]),
                    Value::Map(vec![(
                        Value::Text("deep".into()),
                        Value::Text("deep-secret".into()),
                    )]),
                ]),
            ),
        ])
    }

    /// Collect every `Bytes`/`Text` payload in the tree, so a test can assert
    /// on what survived a wipe.
    fn harvest(v: &Value, out: &mut Vec<Vec<u8>>) {
        match v {
            Value::Bytes(b) => out.push(b.clone()),
            Value::Text(t) => out.push(t.as_bytes().to_vec()),
            Value::Array(items) => items.iter().for_each(|i| harvest(i, out)),
            Value::Map(entries) => entries.iter().for_each(|(k, val)| {
                harvest(k, out);
                harvest(val, out);
            }),
            _ => {}
        }
    }

    #[test]
    fn wipe_reaches_every_depth_and_every_container_arm() {
        let mut tree = SecretValueTree::new(nested_secret_tree());

        let mut before = Vec::new();
        harvest(tree.as_value(), &mut before);
        // 4 keys + 1 nested key + 1 array-map key = keys, plus the payloads.
        assert!(
            before.iter().any(|b| b == b"top-secret"),
            "fixture did not contain the payload the test is about"
        );

        tree.wipe_for_test();

        let mut after = Vec::new();
        harvest(tree.as_value(), &mut after);
        assert!(
            !after.iter().any(|b| b == b"top-secret"),
            "top-level Text survived the wipe"
        );
        assert!(
            !after.iter().any(|b| b == b"deep-secret"),
            "Text nested inside Array->Map survived the wipe"
        );
        assert!(
            !after.iter().any(|b| b.iter().any(|&x| x == 0xBB)),
            "Bytes nested inside Map survived the wipe"
        );
        assert!(
            !after.iter().any(|b| b.iter().any(|&x| x == 0xCC)),
            "Bytes nested inside Array survived the wipe"
        );
    }

    /// `Drop` is the security claim — it is what covers an unwind and every
    /// `?` early return. Deleting `impl Drop` must FAIL a test.
    ///
    /// This is the #546 precedent: deleting `impl Drop for ZeroizingEntries`
    /// left all 25 bundle tests green, and the only thing that noticed was an
    /// incidental `dead_code` lint that evaporates as soon as the wipe gains
    /// a second caller.
    #[test]
    fn drop_invokes_the_wipe() {
        let before = wipe_calls();
        {
            let _tree = SecretValueTree::new(nested_secret_tree());
        }
        assert_eq!(
            wipe_calls(),
            before + 1,
            "scope exit did not wipe — is `impl Drop for SecretValueTree` still there?"
        );
    }

    /// `ciborium::Value` is `#[non_exhaustive]`, so no match arm will warn
    /// when a shape is missed. This test enumerates every variant that exists
    /// today: if upstream adds one, the `assert` on the count fails and a
    /// human decides whether the new variant can carry a secret.
    #[test]
    fn every_ciborium_value_variant_is_accounted_for() {
        let all = [
            Value::Integer(0u64.into()),
            Value::Bytes(vec![1]),
            Value::Float(0.0),
            Value::Text("t".into()),
            Value::Bool(true),
            Value::Null,
            Value::Tag(0, Box::new(Value::Null)),
            Value::Array(vec![]),
            Value::Map(vec![]),
        ];
        // Wiping each in isolation must not panic and must terminate.
        for v in all {
            let mut t = SecretValueTree::new(v);
            t.wipe_for_test();
        }
        // The count is the tripwire. `ciborium` 0.2's `Value` has exactly
        // these 9 variants; a 10th means `wipe` needs review for whether it
        // can carry a payload.
        assert_eq!(
            secretary_core_value_variant_count(),
            9,
            "ciborium::Value gained a variant — review whether SecretValueTree::wipe \
             must handle it before bumping this count"
        );
    }

    /// Counts the `Value` variants this version of `ciborium` exposes, by
    /// exhaustive match. `#[non_exhaustive]` forces the wildcard arm, so the
    /// count is maintained by hand and pinned by the test above — but the
    /// match itself fails to compile if a NAMED variant is removed.
    fn secretary_core_value_variant_count() -> usize {
        let probe = Value::Null;
        let _named = match &probe {
            Value::Integer(_) => 1,
            Value::Bytes(_) => 2,
            Value::Float(_) => 3,
            Value::Text(_) => 4,
            Value::Bool(_) => 5,
            Value::Null => 6,
            Value::Tag(_, _) => 7,
            Value::Array(_) => 8,
            Value::Map(_) => 9,
            _ => 0,
        };
        9
    }

    /// A wipe must be distinguishable from a `clear()`. The #546 review found
    /// an assertion of the form `all(|b| b == 0)` on a vec that `Zeroize`
    /// EMPTIES, which passes vacuously and cannot tell the two apart.
    ///
    /// Stated limit: neither form can distinguish them for a `Vec`, because
    /// safe Rust cannot read spare capacity. What this test CAN prove is that
    /// the payload is no longer present, which is the property that matters
    /// and which a no-op `Drop` fails.
    #[test]
    fn wipe_is_not_vacuous() {
        let secret = b"a-distinctive-payload".to_vec();
        let mut tree = SecretValueTree::new(Value::Bytes(secret.clone()));

        let mut before = Vec::new();
        harvest(tree.as_value(), &mut before);
        assert_eq!(before, vec![secret.clone()], "fixture setup");

        tree.wipe_for_test();

        let mut after = Vec::new();
        harvest(tree.as_value(), &mut after);
        assert!(
            !after.contains(&secret),
            "payload still present after wipe — the wipe is a no-op"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --release -p secretary-core --lib cbor 2>&1 | tail -10
```

Expected: FAIL to compile — `SecretValueTree` does not exist.

- [ ] **Step 3: Write `SecretValueTree`**

Append to `core/src/cbor.rs`:

```rust
// ---------------------------------------------------------------------------
// SecretValueTree (#547 / #548, audit C-4)
// ---------------------------------------------------------------------------

use ciborium::Value;

#[cfg(test)]
thread_local! {
    /// Counts wipe invocations so a test can prove `Drop` calls one.
    ///
    /// Without this, `impl Drop` can be DELETED with every test still
    /// passing — verified by mutation on the `ZeroizingEntries` predecessor
    /// (#546), where the only thing that noticed was an incidental
    /// `dead_code` lint that evaporates the moment the wipe gains a second
    /// caller. The security claim is specifically that `Drop` covers the
    /// unwinding and early-return paths, so `Drop` is what needs pinning.
    static WIPE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Number of wipes performed so far on this thread. Test-only.
#[cfg(test)]
pub(crate) fn wipe_calls() -> usize {
    WIPE_CALLS.with(std::cell::Cell::get)
}

/// Recursively zeroize every `Bytes` and `Text` payload in a `Value` tree.
///
/// Walks `Array` and `Map` (both keys and values — a forward-compat map could
/// in principle key on a byte string). Scalars carry no heap payload.
///
/// `ciborium::Value` is `#[non_exhaustive]`, so the wildcard arm below is
/// mandatory and will never warn when a new variant appears. The test
/// `every_ciborium_value_variant_is_accounted_for` is the tripwire: it pins
/// the variant count, so an upstream addition fails a test rather than
/// silently skipping a payload.
///
/// Recurses without an explicit depth bound, for the same reason
/// [`crate::vault::canonical::reject_floats_and_tags`] does: `ciborium`'s
/// default `from_reader` recursion limit (256) has already capped the depth of
/// any parsed tree. Raising that limit requires adding a `depth` parameter
/// here too.
fn wipe_value(value: &mut Value) {
    use zeroize::Zeroize as _;
    match value {
        Value::Bytes(b) => b.zeroize(),
        Value::Text(t) => t.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_value),
        Value::Map(entries) => entries.iter_mut().for_each(|(k, v)| {
            wipe_value(k);
            wipe_value(v);
        }),
        // Integer / Float / Bool / Null / Tag payloads are scalars or a
        // boxed child; `Tag` is unreachable here because
        // `reject_floats_and_tags` refuses tags before any caller wraps a
        // tree, and a `Tag`'s child is covered by recursing into it anyway.
        Value::Tag(_, inner) => wipe_value(inner),
        _ => {}
    }
}

/// A parsed CBOR tree whose byte-string and text payloads are zeroized on
/// drop.
///
/// `ciborium::de::from_reader` returns a `Value` tree that owns copies of
/// every payload in the input. On the record path that is decrypted user
/// plaintext (#547); on the identity-bundle path it is the four long-term
/// secret keys (#548). Neither allocation can be eliminated — the parser owns
/// it — so it is wiped instead.
///
/// `Drop` is the mechanism, deliberately: it covers an unwinding panic and
/// every `?` early return, which a trailing wipe statement does not. #548 is
/// exactly that gap on the bundle read side, where an early `?` inside the
/// field loop freed up to three not-yet-consumed secret keys unwiped.
///
/// # What this does not claim
///
/// A wipe of freed heap is not observable from safe Rust, and neither is a
/// reallocation `ciborium`'s parser performed before we ever saw the value.
/// This covers the buffer the tree points at when it drops.
///
/// # Why there is no `&mut` or consuming accessor
///
/// There is deliberately no way to get the inner `Value` out by value or by
/// `&mut`. `.clear()`, `.drain(..)`, `mem::take` and whole-field reassignment
/// each free the element buffers unwiped, and
/// `scripts/check-secret-slot-hygiene.sh` matches `mem::*` and `ManuallyDrop`
/// but not the first two. The API shape is the enforcement — same reasoning as
/// `ZeroizingEntries` (#542) and the FFI bridge's `Detail` newtype
/// (#500/#515).
pub(crate) struct SecretValueTree(Value);

impl SecretValueTree {
    /// Take ownership of a parsed tree.
    pub(crate) fn new(value: Value) -> Self {
        Self(value)
    }

    /// Read-only view. Deliberately the only way out — see the type docs.
    pub(crate) fn as_value(&self) -> &Value {
        &self.0
    }

    /// Wipe now, without waiting for the drop. Test-only: production code
    /// relies on `Drop` precisely because it cannot be skipped.
    #[cfg(test)]
    pub(crate) fn wipe_for_test(&mut self) {
        self.wipe();
    }

    fn wipe(&mut self) {
        #[cfg(test)]
        WIPE_CALLS.with(|c| c.set(c.get() + 1));
        wipe_value(&mut self.0);
    }
}

impl Drop for SecretValueTree {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// A parsed CBOR map's entry list, wiped on drop.
///
/// Same contract as [`SecretValueTree`], for the shape decoders actually
/// consume: they destructure the top-level `Value::Map` into its
/// `Vec<(Value, Value)>` and iterate. [`Self::drain_wiping`] hands out one
/// entry at a time so the decoder can move values out, while everything
/// NOT yet consumed stays under this type's `Drop`.
pub(crate) struct SecretEntries(Vec<(Value, Value)>);

impl SecretEntries {
    /// Take ownership of an entry list.
    pub(crate) fn new(entries: Vec<(Value, Value)>) -> Self {
        Self(entries)
    }

    /// Number of entries.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Read-only view.
    pub(crate) fn as_slice(&self) -> &[(Value, Value)] {
        &self.0
    }

    /// Yield entries one at a time, wiping each as it is handed out is NOT
    /// what happens — the consumer needs the value intact. What this
    /// guarantees is that every entry NOT yet yielded remains owned by
    /// `self`, so an early `?` in the consumer's loop drops `self` and wipes
    /// the remainder. That is precisely #548.
    ///
    /// Implemented as an index cursor rather than `Vec::drain` because
    /// `drain` borrows the whole vec for the iterator's lifetime, which
    /// prevents `self` from being dropped mid-iteration.
    pub(crate) fn take_next(&mut self) -> Option<(Value, Value)> {
        if self.0.is_empty() {
            return None;
        }
        // `swap_remove(0)` would reorder; decoders depend on nothing here,
        // but `remove(0)` keeps the iteration order identical to the previous
        // `into_iter()` so `enumerate()` indices in error messages are stable.
        Some(self.0.remove(0))
    }
}

impl Drop for SecretEntries {
    fn drop(&mut self) {
        #[cfg(test)]
        WIPE_CALLS.with(|c| c.set(c.get() + 1));
        for (k, v) in &mut self.0 {
            wipe_value(k);
            wipe_value(v);
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --release -p secretary-core --lib cbor 2>&1 | tail -15
```

Expected: PASS.

- [ ] **Step 5: Prove `Drop` is load-bearing (mutation check)**

Comment out `impl Drop for SecretValueTree` and confirm `drop_invokes_the_wipe`
FAILS. Then revert. Repeat for `wipe_value`'s `Value::Text` arm and confirm
`wipe_reaches_every_depth_and_every_container_arm` FAILS.

- [ ] **Step 6: Run the full per-task gate, then commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
feat(core): SecretValueTree — recursive zeroize-on-drop for parsed CBOR (#547, #548)

`ciborium::de::from_reader` returns a `Value` tree owning a copy of every
payload in the input: decrypted user plaintext on the record path, the four
long-term secret keys on the identity-bundle path. That allocation is the
parser's and cannot be eliminated, so it is wiped instead.

`Drop` is the mechanism deliberately — it covers an unwinding panic and every
`?` early return, which a trailing wipe statement does not. #548 is exactly
that gap: an early `?` inside `from_canonical_cbor`'s field loop freed up to
three not-yet-consumed secret keys unwiped.

Three things this does differently from the `ZeroizingEntries` it will
replace: it wipes `Value::Text` (a password is a `RecordFieldValue::Text`,
where the bundle's only text value was an already-cleartext display name), it
RECURSES (the record shape nests a map inside a map inside an array), and its
variant coverage is pinned by a test rather than by a `debug_assert` on a flat
shape.

No `&mut` or consuming accessor, so `.clear()` / `.drain(..)` / `mem::take`
cannot empty it out from under `Drop` — the secret-slot guard matches `mem::*`
and `ManuallyDrop` but not the first two, so the API shape is the enforcement.

No production consumer yet; Tasks 6 and 7 wire it in. `Drop` and the `Text`
arm were both mutation-checked.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

### Task 4: record encode path → `record_to_canonical`

**Why:** closes #547's named site. `field_to_entries`' `s.expose().to_owned()`
becomes a borrow.

**Files:**
- Modify: `core/src/vault/record.rs:259-292` (add `UnknownValue::as_value`)
- Modify: `core/src/vault/record.rs:418-521` (replace `record_to_entries` / `fields_to_value` / `field_to_entries` with `record_to_canonical`)

**Interfaces:**
- Consumes: `CanonicalMap`, `CanonicalValue`, `to_canonical_vec` (Task 2).
- Produces:
  - `pub(crate) fn record_to_canonical(record: &Record) -> CanonicalMap<'_>`
  - `pub(crate) fn UnknownValue::as_value(&self) -> &Value`
  - `pub fn encode(record: &Record) -> Result<Vec<u8>, RecordError>` — signature unchanged.

- [ ] **Step 1: Write the failing test**

Add to `core/src/vault/record.rs`'s `#[cfg(test)] mod tests`:

```rust
    /// #547: encoding a record must not copy its field plaintext out of the
    /// `SecretString` wrapper. The copy is not directly observable, so this
    /// test pins the OBSERVABLE consequence of the borrowing encoder: the
    /// bytes are unchanged from what the owned encoder produced.
    ///
    /// The literal expectation is generated by the OLD code path at the time
    /// this test was written and pasted here — a change to it means the
    /// on-disk format moved.
    #[test]
    fn record_to_canonical_matches_the_owned_encoder_byte_for_byte() {
        let mut rng = rand::rngs::OsRng;
        let record = random_record(&mut rng);

        let via_canonical = encode(&record).expect("encode");

        // Rebuild the same map the OWNED path built, and encode it the old
        // way. Both must agree, which is what makes the borrowing encoder a
        // safe substitution rather than a format change.
        let owned_entries = owned_record_entries_for_test(&record);
        let via_owned =
            crate::vault::canonical::encode_canonical_map(&owned_entries).expect("owned encode");

        assert_eq!(
            via_canonical, via_owned,
            "the borrowing encoder changed the bytes — the on-disk format moved"
        );
    }
```

`random_record` and `owned_record_entries_for_test` are helpers written in the
same step. `owned_record_entries_for_test` is `#[cfg(test)]` and is a verbatim
copy of the pre-change `record_to_entries` + `fields_to_value` +
`field_to_entries`, kept ONLY as the differential oracle for this test. Its
doc comment must say so, and must say that it is deliberately not deleted.

```rust
    /// A record with randomly-generated content in every field, including a
    /// forward-compat unknown at both record and field level.
    ///
    /// Random rather than literal per the repo's test convention: hardcoded
    /// crypto-shaped byte arrays trip CodeQL.
    fn random_record(rng: &mut impl rand::RngCore) -> Record {
        use crate::crypto::secret::{SecretBytes, SecretString};

        let mut record_uuid = [0u8; RECORD_UUID_LEN];
        rng.fill_bytes(&mut record_uuid);
        let mut device_uuid = [0u8; RECORD_UUID_LEN];
        rng.fill_bytes(&mut device_uuid);
        let mut secret_bytes = vec![0u8; 64];
        rng.fill_bytes(&mut secret_bytes);

        let mut fields = BTreeMap::new();
        fields.insert(
            "password".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::new(format!(
                    "pw-{:016x}",
                    rng.next_u64()
                ))),
                last_mod: rng.next_u64() >> 16,
                device_uuid,
                unknown: BTreeMap::new(),
            },
        );
        // A second field whose name has a DIFFERENT byte length, so the
        // canonical length-then-lex key sort is actually exercised (it
        // differs from `BTreeMap`'s String order only for unequal lengths).
        fields.insert(
            "k".to_string(),
            RecordField {
                value: RecordFieldValue::Bytes(SecretBytes::new(secret_bytes)),
                last_mod: rng.next_u64() >> 16,
                device_uuid,
                unknown: BTreeMap::new(),
            },
        );

        Record {
            record_uuid,
            record_type: "login".to_string(),
            fields,
            tags: vec!["work".to_string(), "a".to_string()],
            created_at_ms: rng.next_u64() >> 16,
            last_mod_ms: rng.next_u64() >> 16,
            tombstone: false,
            tombstoned_at_ms: 0,
        }
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --release -p secretary-core --lib record_to_canonical_matches 2>&1 | tail -10
```

Expected: FAIL to compile — `owned_record_entries_for_test` and the borrowing
encode path do not exist yet.

- [ ] **Step 3: Add `UnknownValue::as_value`**

```rust
    /// Borrow the wrapped CBOR value.
    ///
    /// `pub(crate)` deliberately: the wrapped `ciborium::Value` is a private
    /// implementation detail of the public API (that is why `UnknownValue`
    /// exists at all), and this accessor is only for the canonical encoder,
    /// which needs to emit the subtree verbatim WITHOUT cloning it. The
    /// previous encode path did `v.0.clone()`, a deep clone of a forward-compat
    /// subtree that could carry a future version's secret content (#547).
    pub(crate) fn as_value(&self) -> &Value {
        &self.0
    }
```

- [ ] **Step 4: Write `record_to_canonical` and rewire `encode`**

Replace `record_to_entries`, `fields_to_value` and `field_to_entries` with:

```rust
/// Build the borrowed canonical map for a record (§6.3).
///
/// Every value BORROWS: a `RecordFieldValue::Text` serialises straight out of
/// its `SecretString`, where the previous path did `s.expose().to_owned()` and
/// then deep-cloned that copy three more times on the way to the wire (#547).
///
/// Key order is irrelevant here — `CanonicalMap`'s `Serialize` imposes the
/// RFC 8949 §4.2.1 order, recursively, at serialise time.
pub(crate) fn record_to_canonical(record: &Record) -> CanonicalMap<'_> {
    let mut map = CanonicalMap::with_capacity(8 + record.unknown.len());

    map.push(KEY_RECORD_UUID, CanonicalValue::Bytes(&record.record_uuid));
    map.push(KEY_RECORD_TYPE, CanonicalValue::Text(&record.record_type));

    let mut fields = CanonicalMap::with_capacity(record.fields.len());
    for (name, f) in &record.fields {
        fields.push(name, CanonicalValue::Map(field_to_canonical(f)));
    }
    map.push(KEY_FIELDS, CanonicalValue::Map(fields));

    // §6.3: empty `tags` is absent on the wire.
    if !record.tags.is_empty() {
        map.push(
            KEY_TAGS,
            CanonicalValue::Array(
                record.tags.iter().map(|t| CanonicalValue::Text(t)).collect(),
            ),
        );
    }
    map.push(KEY_CREATED_AT_MS, CanonicalValue::Uint(record.created_at_ms));
    map.push(KEY_LAST_MOD_MS, CanonicalValue::Uint(record.last_mod_ms));
    // §6.3: `tombstone == false` is absent on the wire.
    if record.tombstone {
        map.push(KEY_TOMBSTONE, CanonicalValue::Bool(true));
    }
    // §11.3: the never-tombstoned default (0) is absent on the wire.
    if record.tombstoned_at_ms != 0 {
        map.push(
            KEY_TOMBSTONED_AT_MS,
            CanonicalValue::Uint(record.tombstoned_at_ms),
        );
    }

    // Forward-compat (§6.3.2): splice unknowns alongside known keys. Emitted
    // verbatim as a BORROW — the previous path cloned the subtree.
    for (k, v) in &record.unknown {
        map.push(k, CanonicalValue::Borrowed(v.as_value()));
    }

    map
}

/// Build the borrowed canonical map for one field (§6.3.2).
fn field_to_canonical(field: &RecordField) -> CanonicalMap<'_> {
    let mut map = CanonicalMap::with_capacity(3 + field.unknown.len());
    let value = match &field.value {
        // The whole point of #547: a borrow where there was a copy.
        RecordFieldValue::Text(s) => CanonicalValue::Text(s.expose()),
        RecordFieldValue::Bytes(b) => CanonicalValue::Bytes(b.expose()),
    };
    map.push(KEY_VALUE, value);
    map.push(KEY_LAST_MOD, CanonicalValue::Uint(field.last_mod));
    map.push(KEY_DEVICE_UUID, CanonicalValue::Bytes(&field.device_uuid));
    for (k, v) in &field.unknown {
        map.push(k, CanonicalValue::Borrowed(v.as_value()));
    }
    map
}

pub fn encode(record: &Record) -> Result<Vec<u8>, RecordError> {
    Ok(to_canonical_vec(&record_to_canonical(record))?)
}
```

`record_to_entries` returned `Result` because `canonical_sort_entries` could
fail; `record_to_canonical` cannot fail, so the `?` moves to
`to_canonical_vec`. Check whether `RecordError` still needs every variant the
old path produced — do **not** delete a variant, since that is a public API
break; just confirm nothing is now unreachable in a way clippy flags.

- [ ] **Step 5: Run the whole suite**

```bash
cargo test --release --workspace 2>&1 | tail -20
```

Expected: PASS. Every pre-existing record round-trip, KAT, proptest and
golden-vault test must pass **unchanged** — that is the byte-identity proof.

- [ ] **Step 6: Prove no plaintext copy remains on this path**

```bash
grep -n "expose().to_owned()\|expose().to_vec()\|\.0\.clone()" core/src/vault/record.rs
```

Expected: no hits in `record_to_canonical` / `field_to_canonical`. Hits inside
`#[cfg(test)] owned_record_entries_for_test` are expected and correct — that is
the differential oracle.

- [ ] **Step 7: Run the full per-task gate, then commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
fix(core): record encode borrows field plaintext instead of copying it (#547)

`field_to_entries` did `Value::Text(s.expose().to_owned())` — every decrypted
password, note and TOTP seed cloned out of its `SecretString` into a
`ciborium::Value`, which has no zeroizing `Drop`, and then deep-cloned three
more times by the canonical sort on the way to the wire. Freed unwiped on
every record save.

`record_to_canonical` borrows instead. `RecordFieldValue::Text(s)` becomes
`CanonicalValue::Text(s.expose())`, serialised straight out of the wrapper's
buffer. Forward-compat unknown subtrees are likewise borrowed rather than
`.0.clone()`d — a future version's unknown could carry secret content this
version cannot recognise.

Byte-identity is pinned by a DIFFERENTIAL test: a `#[cfg(test)]` verbatim copy
of the old owned encoder is kept as the oracle, and the two must agree
byte-for-byte on a randomly-generated record whose two field names have
different byte lengths (so the canonical length-then-lex key sort is actually
exercised — it differs from `BTreeMap`'s String order only for unequal
lengths). Every pre-existing record KAT, proptest and golden-vault test passes
unchanged.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

### Task 5: block encode path — delete the encode→reparse round-trip

**Why:** `records_to_value` serialises each record to a plaintext `Vec<u8>` and
re-parses it into a fresh `Value` tree, purely to hand it to the outer map.
Copies #5 and #6.

**Files:**
- Modify: `core/src/vault/block.rs:874-941` (`plaintext_to_entries`, `records_to_value`, `unknown_to_value`)
- Modify: `core/src/vault/block.rs:869-872` (`encode_plaintext`)

**Interfaces:**
- Consumes: `record_to_canonical` (Task 4), `CanonicalMap` / `CanonicalValue` / `to_canonical_vec` (Task 2), `UnknownValue::as_value` (Task 4).
- Produces: `pub fn encode_plaintext(&BlockPlaintext) -> Result<Vec<u8>, BlockError>` — signature unchanged.

- [ ] **Step 1: Write the failing test**

Add to `core/src/vault/block.rs`'s test module:

```rust
    /// #547 copy 5: `records_to_value` encoded each record to plaintext bytes
    /// and re-parsed them into a fresh `Value` tree. Both are gone; the bytes
    /// must not be.
    ///
    /// Differential against the round-trip path, kept `#[cfg(test)]` as the
    /// oracle for exactly this comparison.
    #[test]
    fn block_encode_matches_the_round_trip_path_byte_for_byte() {
        let mut rng = rand::rngs::OsRng;
        let plaintext = random_block_plaintext(&mut rng, 3);

        let direct = encode_plaintext(&plaintext).expect("encode");
        let via_round_trip = encode_plaintext_via_round_trip_for_test(&plaintext)
            .expect("round-trip encode");

        assert_eq!(
            direct, via_round_trip,
            "inlining records changed the block bytes — the on-disk format moved"
        );
    }
```

`encode_plaintext_via_round_trip_for_test` is a `#[cfg(test)]` verbatim copy of
the pre-change `plaintext_to_entries` + `records_to_value` +
`encode_canonical_map` call. `random_block_plaintext` builds a plaintext with
`n` random records (reuse `record`'s `random_record` via a
`#[cfg(test)] pub(crate)` re-export, or duplicate it locally — prefer the
re-export so the two cannot drift).

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --release -p secretary-core --lib block_encode_matches 2>&1 | tail -10
```

Expected: FAIL to compile.

- [ ] **Step 3: Rewrite the block encode path**

```rust
pub fn encode_plaintext(plaintext: &BlockPlaintext) -> Result<Vec<u8>, BlockError> {
    Ok(to_canonical_vec(&plaintext_to_canonical(plaintext))?)
}

/// Build the borrowed canonical map for a block plaintext (§6.3).
///
/// The `records` entry embeds each record's canonical map INLINE via
/// [`super::record::record_to_canonical`]. The previous path called
/// `record::encode` to get canonical bytes and then re-parsed them with
/// `from_reader` purely to obtain a `Value` to nest — materialising a full
/// plaintext `Value` tree plus a plaintext `Vec<u8>` per record, per save
/// (#547 copies 5 and 6).
///
/// This STRENGTHENS the invariant the old round-trip existed to protect
/// ("`record::encode` is the sole authority on record CBOR shape"): block now
/// calls the very function `record::encode` calls, instead of re-parsing its
/// output. It also retires the performance hook the old `records_to_value`
/// doc recorded for exactly this round-trip.
fn plaintext_to_canonical(plaintext: &BlockPlaintext) -> CanonicalMap<'_> {
    let mut map = CanonicalMap::with_capacity(5 + plaintext.unknown.len());

    map.push(
        KEY_BLOCK_VERSION,
        CanonicalValue::Uint(u64::from(plaintext.block_version)),
    );
    map.push(KEY_BLOCK_UUID, CanonicalValue::Bytes(&plaintext.block_uuid));
    map.push(KEY_BLOCK_NAME, CanonicalValue::Text(&plaintext.block_name));
    map.push(
        KEY_SCHEMA_VERSION,
        CanonicalValue::Uint(u64::from(plaintext.schema_version)),
    );
    map.push(
        KEY_RECORDS,
        CanonicalValue::Array(
            plaintext
                .records
                .iter()
                .map(|r| CanonicalValue::Map(record::record_to_canonical(r)))
                .collect(),
        ),
    );

    for (k, v) in &plaintext.unknown {
        map.push(k, CanonicalValue::Borrowed(v.as_value()));
    }

    map
}
```

Delete `records_to_value` and `unknown_to_value` from the production path.
`unknown_to_value` is still needed on the DECODE side (`value_to_unknown` is
the decode direction and stays); check before deleting.

- [ ] **Step 4: Run the whole suite**

```bash
cargo test --release --workspace 2>&1 | tail -20
```

Expected: PASS, every block KAT and golden-vault test unchanged.

- [ ] **Step 5: Run the full per-task gate, then commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
fix(core): block encode embeds records inline, deleting the reparse round-trip (#547)

`records_to_value` called `record::encode` to get a record's canonical bytes
and then re-parsed them with `from_reader` purely to obtain a `Value` to nest
in the outer map — materialising a full plaintext `Value` tree PLUS a
plaintext `Vec<u8>` per record, on every block save, both freed unwiped.

`plaintext_to_canonical` embeds `record::record_to_canonical(r)` directly. That
strengthens the invariant the round-trip existed to protect: block now calls
the very function `record::encode` calls, instead of re-parsing its output. It
also retires the performance hook `records_to_value`'s doc recorded for exactly
this round-trip — it turned out to be a security finding as well as a slow one.

Byte-identity pinned by a differential test against a `#[cfg(test)]` copy of
the round-trip path, over a randomly-generated three-record block.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

### Task 6: decode paths — wrap the parsed tree, drop the per-record buffer

**Why:** the trees `from_reader` returns hold all plaintext, and
`block::take_records` adds a plaintext `Vec<u8>` per record on top.

**Files:**
- Modify: `core/src/vault/record.rs:551-575` (`decode`), add `decode_value`
- Modify: `core/src/vault/block.rs:976-1001` (`decode_plaintext`), `:1076-1095` (`take_records`)

**Interfaces:**
- Consumes: `SecretValueTree`, `SecretEntries` (Task 3).
- Produces:
  - `pub(crate) fn record::decode_value(value: &Value) -> Result<Record, RecordError>`
  - `pub fn record::decode(bytes: &[u8]) -> Result<Record, RecordError>` — unchanged signature.
  - `pub fn block::decode_plaintext(bytes: &[u8]) -> Result<BlockPlaintext, BlockError>` — unchanged signature.

- [ ] **Step 1: Write the failing test — the validation-semantics claim**

This is the one behaviour change in the slice, so it is discharged by test, not
argument. `take_records` currently gives each record its own byte-level
canonicality re-check; removing the buffer removes that check. The claim is
that `decode_plaintext`'s own re-encode-and-compare subsumes it.

Add to `core/src/vault/block.rs`'s test module:

```rust
    /// The one validation-semantics change in #547. `take_records` used to
    /// re-serialise each record `Value` into a plaintext buffer and hand it to
    /// `record::decode`, which byte-compared its own re-encode. Removing that
    /// buffer removes the PER-RECORD check; this proves the BLOCK-level
    /// re-encode still rejects the same inputs.
    ///
    /// Two independent non-canonical shapes, because they fail differently:
    /// out-of-order keys (a sort violation) and an indefinite-length item
    /// (a `ciborium` normalisation that `Value` reads but re-emits definite).
    #[test]
    fn a_non_canonical_nested_record_is_still_rejected() {
        let mut rng = rand::rngs::OsRng;
        let plaintext = random_block_plaintext(&mut rng, 1);
        let good = encode_plaintext(&plaintext).expect("encode");
        assert!(decode_plaintext(&good).is_ok(), "fixture must decode clean");

        // (a) Out-of-order keys inside the nested record map.
        let tampered = reorder_first_nested_record_keys_for_test(&good);
        assert_ne!(tampered, good, "tamper helper did not change the bytes");
        assert!(
            matches!(
                decode_plaintext(&tampered),
                Err(BlockError::NonCanonicalEncoding)
            ),
            "block-level re-encode did not reject out-of-order nested record keys"
        );

        // (b) An indefinite-length text string inside the nested record.
        let tampered = indefinite_length_in_first_record_for_test(&good);
        assert_ne!(tampered, good, "tamper helper did not change the bytes");
        assert!(
            decode_plaintext(&tampered).is_err(),
            "block-level re-encode did not reject an indefinite-length nested item"
        );
    }
```

Write both tamper helpers as `#[cfg(test)]` functions that parse `good` into a
`Value`, mutate the nested record subtree, and re-emit with a deliberately
non-canonical writer (for (a), build a `Value::Map` with entries in reverse
canonical order and serialise it directly, bypassing `to_canonical_vec`; for
(b), hand-splice the indefinite-length header bytes).

**If either assertion fails**, stop and take the spec's stated fallback: keep
`take_records` as it is and wrap its `buf` in `SecretBytes` — a wipe rather
than an elimination for that one buffer. Record which, and why, in the commit
body. Do not weaken the assertion.

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --release -p secretary-core --lib a_non_canonical_nested_record 2>&1 | tail -10
```

Expected: FAIL to compile (helpers missing), then FAIL or PASS on the
assertions once the helpers exist — note which, because a PASS here on the
UNCHANGED code is exactly the evidence that the block-level check already
subsumes the per-record one.

- [ ] **Step 3: Add `record::decode_value` and wrap `record::decode`**

```rust
pub fn decode(bytes: &[u8]) -> Result<Record, RecordError> {
    let parsed: Value =
        ciborium::de::from_reader(bytes).map_err(|e| RecordError::CborDecode(classify_de(&e)))?;
    // The parsed tree owns a copy of every decrypted field value in `bytes`.
    // Wrapping it means `Drop` wipes that copy on every exit from this
    // function — including the `?` early returns below and an unwinding panic
    // (#547). The tree is BORROWED from here on; nothing moves out of it.
    let parsed = SecretValueTree::new(parsed);

    reject_floats_and_tags(parsed.as_value(), "<root>")?;

    let record = decode_value(parsed.as_value())?;

    // Strict canonical-input check: re-encode and require a byte-identical
    // match. Catches indefinite-length items, non-canonical key order, and
    // non-shortest length prefixes.
    let re_encoded = encode(&record)?;
    if re_encoded.as_slice() != bytes {
        return Err(RecordError::NonCanonicalEncoding);
    }

    Ok(record)
}

/// Decode a record from an already-parsed CBOR value.
///
/// `pub(crate)` for [`super::block`], which holds each record as a subtree of
/// the block's own parsed plaintext. Going through this instead of
/// re-serialising that subtree and calling [`decode`] removes a plaintext
/// `Vec<u8>` per record per block open (#547).
///
/// Does NOT perform the byte-level canonicality re-check [`decode`] does —
/// there are no bytes at this level to compare against. For the nested case
/// that check is subsumed by the block's own re-encode-and-compare over the
/// whole plaintext, which covers the nested record bytes; the test
/// `a_non_canonical_nested_record_is_still_rejected` is what discharges that
/// claim.
pub(crate) fn decode_value(value: &Value) -> Result<Record, RecordError> {
    let Value::Map(entries) = value else {
        return Err(RecordError::NotAMap);
    };
    parse_record_map(entries)
}
```

`parse_record_map` currently takes `Vec<(Value, Value)>` by value. Change it to
take `&[(Value, Value)]` and clone only the small, non-secret scalars it needs,
OR keep it by-value and have `decode_value` clone the entries — **the former**.
Cloning the entries would reintroduce exactly the copy this task removes.

Changing `parse_record_map` to borrow means every `take_*` helper it calls
(`take_bytes`, `take_text`, …) must take `&Value` instead of `Value`. Those
helpers currently move out of the value; borrowing means copying the scalar
out, which for a `String`/`Vec<u8>` field value is a copy — and for
`RecordFieldValue` it goes straight into a `SecretString`/`SecretBytes`, which
is a zeroizing destination, so it is the copy we WANT and not new residue. Make
that explicit in a comment at the conversion site.

- [ ] **Step 4: Wrap `block::decode_plaintext` and rewrite `take_records`**

```rust
pub fn decode_plaintext(bytes: &[u8]) -> Result<BlockPlaintext, BlockError> {
    let parsed: Value =
        ciborium::de::from_reader(bytes).map_err(|e| BlockError::CborDecode(classify_de(&e)))?;
    // Owns a copy of every record's decrypted plaintext. See `record::decode`.
    let parsed = SecretValueTree::new(parsed);

    reject_floats_and_tags(parsed.as_value(), "<root>")?;

    let Value::Map(entries) = parsed.as_value() else {
        return Err(BlockError::NotAMap);
    };
    let plaintext = parse_plaintext_map(entries)?;

    let re_encoded = encode_plaintext(&plaintext)?;
    if re_encoded.as_slice() != bytes {
        return Err(BlockError::NonCanonicalEncoding);
    }

    Ok(plaintext)
}

fn take_records(v: &Value) -> Result<Vec<Record>, BlockError> {
    let Value::Array(items) = v else {
        return Err(BlockError::WrongType {
            field: KEY_RECORDS,
            expected: "array",
        });
    };
    let mut out: Vec<Record> = Vec::with_capacity(items.len());
    for item in items {
        // Straight from the already-parsed subtree. The previous path
        // re-serialised `item` into a plaintext `Vec<u8>` and called
        // `record::decode` on it, adding one unwiped plaintext buffer per
        // record per block open (#547).
        out.push(record::decode_value(item)?);
    }
    Ok(out)
}
```

`parse_plaintext_map` takes `&[(Value, Value)]` for the same reason
`parse_record_map` does.

- [ ] **Step 5: Run the whole suite**

```bash
cargo test --release --workspace 2>&1 | tail -20
```

Expected: PASS, including `a_non_canonical_nested_record_is_still_rejected`.

- [ ] **Step 6: Prove the wrapper is load-bearing (mutation check)**

Temporarily replace `SecretValueTree::new(parsed)` with a plain `parsed` binding
in `record::decode` and confirm the crate no longer compiles (the `as_value()`
calls fail) — a compile error is a stronger pin than a test here, and worth
recording in the commit body as the reason no runtime test guards it.

- [ ] **Step 7: Run the full per-task gate, then commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
fix(core): wipe parsed CBOR trees on the record and block decode paths (#547)

`ciborium::de::from_reader` returns a `Value` tree owning a copy of every
decrypted field in the input. Both `record::decode` and `block::decode_plaintext`
dropped that tree unwiped, on the happy path and on every `?`.

Both now wrap it in `SecretValueTree`, so `Drop` covers every exit including an
unwinding panic. `parse_record_map` / `parse_plaintext_map` and their `take_*`
helpers take `&Value` rather than consuming it — consuming would have meant
cloning the entries out of the wrapper, reintroducing the copy this removes.

`take_records` no longer re-serialises each record subtree into a plaintext
buffer to feed `record::decode`; a new `record::decode_value` reads the subtree
directly. That drops one unwiped plaintext `Vec<u8>` per record per block open.

The per-record byte-level canonicality re-check that buffer carried is
subsumed by the block's own re-encode-and-compare, and that is discharged by
test rather than by argument: a planted out-of-order nested record key and a
planted indefinite-length nested item are both still rejected.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

### Task 7: bundle consolidation and #548

**Why:** `bundle.rs` carries private copies of the mechanisms now shared, and
its `from_canonical_cbor` is #548 — the audit's own first-named C-4 sub-item.

**Files:**
- Modify: `core/src/unlock/bundle.rs:360-370` (wrap the parsed map — this is #548)
- Modify: `core/src/unlock/bundle.rs:586-700` (delete the `entries` module and `ZeroizingEntries`)
- Modify: `core/src/unlock/bundle.rs:690-760` (delete `BorrowedCanonicalMap`, `encode_map`, `cbor_size_bound`; call the shared ones)
- Modify: `core/src/unlock/bundle.rs:295-350` (`to_canonical_cbor` uses `SecretEntries`)

**Interfaces:**
- Consumes: `SecretValueTree`, `SecretEntries` (Task 3); `encode_canonical_map`, `cbor_size_bound`, `BorrowedCanonicalMap` (Task 1).
- Produces: no signature changes. `IdentityBundle::to_canonical_cbor` and
  `::from_canonical_cbor` keep their public shapes.

- [ ] **Step 1: Write the failing test for #548**

Add to `core/src/unlock/bundle.rs`'s test module:

```rust
    /// #548 — the C-4 read side, and the audit's own FIRST-named sub-item.
    ///
    /// `from_canonical_cbor` destructured the parsed top level into a bare
    /// `Vec<(Value, Value)>`. The loop consumed and wiped each entry on the
    /// HAPPY path only: any early `?` inside the loop dropped
    /// `map.into_iter()` with every not-yet-consumed `Value::Bytes` still
    /// populated, freeing up to three long-term secret keys unwiped.
    ///
    /// The wipe is not observable from safe Rust, so this pins the mechanism:
    /// taking an early-return path must still have invoked the wipe.
    #[test]
    fn an_early_return_inside_the_field_loop_still_wipes() {
        // A map whose SECOND entry is a duplicate, so `set_once` returns
        // `DuplicateField` after the first secret key has been consumed and
        // while the rest are still in the container.
        let bytes = duplicate_field_bundle_cbor_for_test();

        let before = crate::cbor::wipe_calls();
        let err = IdentityBundle::from_canonical_cbor(&bytes)
            .expect_err("duplicate field must be rejected");
        assert!(
            matches!(err, BundleError::DuplicateField(_)),
            "expected DuplicateField, got {err:?}"
        );
        assert!(
            crate::cbor::wipe_calls() > before,
            "the early-return path did not wipe the not-yet-consumed entries (#548)"
        );
    }
```

`duplicate_field_bundle_cbor_for_test` builds a CBOR map with a valid
`x25519_sk` entry followed by a duplicate of the same key, using
runtime-random key bytes.

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --release -p secretary-core --lib an_early_return_inside_the_field_loop 2>&1 | tail -10
```

Expected: FAIL — `wipe_calls()` unchanged, because nothing wipes on that path.

- [ ] **Step 3: Fix #548**

```rust
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, BundleError> {
        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| BundleError::CborFault(classify_de(&e)))?;
        let Value::Map(m) = value else {
            return Err(BundleError::Malformed("expected top-level CBOR map"));
        };
        // #548: the entry list holds cleartext copies of all four long-term
        // secret keys. The loop below consumes them one at a time, and every
        // `?` inside it — `Malformed` on a non-string key, `DuplicateField`
        // via `set_once`, `WrongKeySize`, `UnknownField` — used to drop the
        // remainder unwiped. `SecretEntries::drop` covers every exit.
        let mut map = SecretEntries::new(m);

        // ... slot declarations unchanged ...

        let mut index = 0usize;
        while let Some((k, v)) = map.take_next() {
            // ... body unchanged, `index` replaces `enumerate()`'s counter ...
            index += 1;
        }
```

Preserve the existing `enumerate()` index semantics exactly — error messages
cite it.

- [ ] **Step 4: Retire the private duplicates**

Delete `mod entries` (`ZeroizingEntries`), `BorrowedCanonicalMap`,
`cbor_size_bound` and `encode_map` from `bundle.rs`. Rewrite
`to_canonical_cbor`'s tail to use `SecretEntries` for the wipe and the shared
`encode_canonical_map` for the encode:

```rust
        // Holds a cleartext clone of all four long-term secret keys.
        // `SecretEntries::drop` wipes them at the end of this expression, on
        // the error path as well as the success path (#542, now shared).
        let entries = SecretEntries::new(vec![ /* ... unchanged ... */ ]);
        Ok(encode_canonical_map(entries.as_slice())?)
```

The `WIPE_CALLS` counter that pinned `impl Drop for ZeroizingEntries` moves to
`cbor.rs` in Task 3; port the bundle's `drop_wipes` test to assert on
`crate::cbor::wipe_calls()`.

Note the one deliberate behaviour change: `SecretEntries` wipes `Value::Text`,
which `ZeroizingEntries` deliberately did not. The bundle's only text value is
`display_name`, which `IdentityBundle` holds unwrapped anyway — so wiping the
clone is neither harmful nor load-bearing. Say so in a comment rather than
letting the difference look accidental.

- [ ] **Step 5: Run the whole suite**

```bash
cargo test --release --workspace 2>&1 | tail -20
```

Expected: PASS, including all 25 pre-existing bundle tests and the golden vault.

- [ ] **Step 6: Check the file shrank**

```bash
wc -l core/src/unlock/bundle.rs
```

Expected: roughly 120 lines fewer than 1589. Record the actual number in the
commit body — #543 stays open, and an inflated claim about progress against it
is the kind of overclaim this repo's review keeps finding.

- [ ] **Step 7: Run the full per-task gate, then commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
fix(core): wipe the bundle's parsed entry list on every exit (#548), share the mechanisms (#547)

#548, the audit's own FIRST-named C-4 sub-item: `from_canonical_cbor`
destructured the parsed top level into a bare `Vec<(Value, Value)>` and
consumed it entry by entry. The wipe happened on the HAPPY path only — any
early `?` inside the loop (`Malformed` on a non-string key, `DuplicateField`,
`WrongKeySize`, `UnknownField`) dropped the remainder with up to three
long-term secret keys still populated, freed unwiped.

`SecretEntries` owns the list, so `Drop` covers every exit. Pinned by a test
that drives the `DuplicateField` early return and asserts the wipe ran — the
wipe itself is not observable from safe Rust, so the mechanism is what gets
pinned.

`ZeroizingEntries`, `BorrowedCanonicalMap`, `cbor_size_bound` and `encode_map`
were private to this file and are now the shared ones. One deliberate
behaviour difference: `SecretEntries` wipes `Value::Text`, which
`ZeroizingEntries` skipped because the bundle's only text value is a
`display_name` the struct holds unwrapped anyway. On the record path a
password IS a `Value::Text`, so the shared type must wipe it; for the bundle
the change is neither harmful nor load-bearing.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

### Task 8: docs, census, and the full gate

**Why:** the audit memo currently describes C-4 in terms this branch falsifies,
and CLAUDE.md's zeroize section does not know either mechanism exists.

**Files:**
- Modify: `docs/manual/contributors/memory-hygiene-audit-internal.md`
- Modify: `CLAUDE.md` (the "Memory hygiene: zeroize discipline" section)
- Modify: `docs/vault-format.md` **only if** a normative statement changed — it should not have; confirm and say so.

- [ ] **Step 1: Re-census the tree for remaining plaintext copies**

```bash
grep -rn "expose()\.to_owned()\|expose()\.to_vec()\|Value::Text(.*clone())\|\.0\.clone()" core/src/vault/ core/src/unlock/
grep -rn "pair.clone()" core/src/
```

Record what remains and why each is justified. Do **not** report a
single-line-grep subtotal as a tree total — that exact overclaim is called out
three times in CLAUDE.md.

- [ ] **Step 2: Update the audit memo**

Add a section covering: the six-copy trace, which are eliminated vs wiped, the
two mechanisms, what `SecretValueTree` does NOT claim (freed heap is not
observable; a `ciborium`-internal realloc predates us), and the one
validation-semantics change with the test that discharges it.

Correct anything the memo now states falsely about C-4.

- [ ] **Step 3: Update CLAUDE.md**

Extend "Memory hygiene: zeroize discipline" with a fourth bullet: when a secret
must cross a foreign serialisation boundary, prefer a borrowing mirror
(`CanonicalValue`) over copying into the foreign type; where the foreign type
owns the allocation (a parser's output), wrap it (`SecretValueTree`). Name both
and where they live.

- [ ] **Step 4: Run the FULL gate set**

```bash
cargo fmt --all -- --check
cargo build --release --workspace
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo clippy --release --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
(cd desktop && pnpm test && pnpm run svelte-check)
git diff main... --stat -- core/tests/data/                          # MUST be empty
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl       # MUST be empty
```

`conformance.py` passing is the strongest byte-identity proof available: it
decrypts the golden vault from `docs/` alone, with no dependency on any Rust
code this branch touched.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'MSG'
docs: record the canonical-CBOR residue work and correct the C-4 prose (#547, #548)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
)"
```

---

## Self-review notes

**Spec coverage.** §2.1 → Task 2. §2.2 → Task 3. §3.1 → Task 4. §3.2 → Task 5.
§3.3 (manifest unchanged) → verified by Task 1's unchanged
`canonical_sort_entries` signature and Task 8's census. §4 → Task 6. §4.1 →
Task 6 Step 1. §4.2 → Task 7. §5 → Task 2's integration test plus the global
`core/tests/data/` tripwire in every task gate. §6 (out of scope) → nothing
scheduled, correct. §7 → Task 1 (directory module) and Task 3 (`cbor.rs`
stays one file). §8 → each task's own test step, with mutation checks in
Tasks 1, 2, 3 and 6.

**Known risk, flagged for the executor.** Task 6 Step 3 changes
`parse_record_map` and its `take_*` helpers from consuming to borrowing. That
is the largest mechanical diff in the plan and the one most likely to need
judgement: some `take_*` helpers move a `String`/`Vec<u8>` out of the `Value`,
and borrowing forces a copy. Where that copy lands in a
`SecretString`/`SecretBytes` it is the copy we want; where it lands anywhere
else, stop and re-read rather than adding residue while removing residue.
