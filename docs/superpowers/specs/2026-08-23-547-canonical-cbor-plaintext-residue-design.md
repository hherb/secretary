# Design — canonical-CBOR plaintext residue (#547, #548)

**Date:** 2026-08-23 · **Branch:** `feature/cbor-plaintext-residue` · **Base:** `main` @ `0116cd2e`

Closes **#547** (`[audit][High]` — record field plaintext cloned into bare
`ciborium::Value` on every save) and **#548** (`[audit][Medium]` — the C-4 read
side: `from_canonical_cbor`'s map frees secret keys unwiped on every error
path).

---

## 1. The problem, measured rather than described

#547 names one site. Tracing one block save of a record carrying a single
`RecordFieldValue::Text` field, the same plaintext is materialised **six**
times, every copy in a `ciborium::Value` or a bare `Vec<u8>`, none of which is
`ZeroizeOnDrop`:

| # | Site | What it copies |
|---|---|---|
| 1 | `vault/record.rs:504` `field_to_entries` | `s.expose().to_owned()` — the site #547 names |
| 2 | `vault/canonical.rs:115` `pair.clone()`, via `record.rs:492` inner-field sort | deep clone of #1 |
| 3 | `vault/canonical.rs:115`, via `record.rs:495` outer sort | deep clone of the whole field map |
| 4 | `vault/canonical.rs:115`, via `record.rs:420` `encode_canonical_map` | again |
| 5 | `vault/block.rs:925` `records_to_value` | `record::encode` → plaintext `Vec<u8>`, **re-parsed** into a fresh `Value` tree |
| 6 | `vault/canonical.rs:115`, via `block.rs:871` `encode_canonical_map` | clone of the records array |

Plus the intermediate `Vec<u8>` buffers at #5 and the final block-plaintext
buffer, each of which may `realloc` and free its old block unwiped — the
hazard `SecretBytes::concat` (#524) exists to prevent.

**Copy #2/#3/#4/#6 are the same defect the #546 review found and fixed in
`bundle.rs`'s `encode_map`.** It survived in `canonical.rs`, the shared helper
that `block`, `record` and `manifest` all call. `canonical_sort_entries`
materialises each key's CBOR bytes to sort on — correct — and then carries the
pair along as `pair.clone()`, a deep clone of the *value* it never needed to
own.

The decode path is symmetric and worse. `block::decode_plaintext` parses the
whole block into a `Value` tree holding every record's plaintext; `take_records`
(`block.rs:1076`) re-serialises each record `Value` into a plaintext `buf` and
calls `record::decode(&buf)`, which parses *another* tree and then re-encodes
the record in full for its canonicality check; and `decode_plaintext` finally
re-encodes the entire block for its own check. Opening a block with N records
runs the complete encode pipeline N+1 times.

### Scope note

`manifest.rs` and `block.rs`'s own header fields carry no decrypted user
content. Only the record path and the identity bundle are plaintext-bearing.
The eliminations below nevertheless benefit all three callers, because they
remove work rather than adding a guard.

---

## 2. Two mechanisms, because there are two problems

**(A) Copies we make** — #1 through #6. These need not exist. **Eliminate them.**

**(B) Copies `ciborium` makes** — the `Value` tree `from_reader` returns. We
cannot prevent those; the parser owns that allocation. **Wipe them.**

This is the division the repo already draws: `SecretBytes::concat` eliminates a
realloc, `ZeroizingEntries` wipes what remains. Elimination is strictly
stronger — a copy that never exists needs no wipe, cannot be missed by a future
author, and is provable by reading the source. A wipe is only as good as the
next call site remembering the wrapper.

### 2.1 Mechanism A — `core/src/vault/canonical/` (directory module)

A **borrowing mirror** of the CBOR subset `docs/vault-format.md` actually uses:

```rust
pub(crate) enum CanonicalValue<'a> {
    Text(&'a str),                    // borrows SecretString's buffer — no copy
    Bytes(&'a [u8]),                  // borrows SecretBytes / a uuid array
    Uint(u64),
    Bool(bool),
    Map(CanonicalMap<'a>),            // sorts its own keys at serialise time
    Array(Vec<CanonicalValue<'a>>),
    Borrowed(&'a Value),              // forward-compat unknowns, verbatim
}

pub(crate) struct CanonicalMap<'a>(Vec<(CanonicalKey<'a>, CanonicalValue<'a>)>);
```

`CanonicalMap`'s `serde::Serialize` impl materialises **keys only** — never a
value — sorts on the encoded key bytes per RFC 8949 §4.2.1, and emits via
`serialize_map(Some(n))`. Because nested `Map`s serialise themselves, the eager
per-level sort disappears: `record.rs` no longer builds `Value::Map(sorted_inner)`
to hand upward.

`Borrowed` is the escape hatch for forward-compat `unknown` values, whose shape
is by definition not known to this version. It is a borrow, so it costs nothing;
`UnknownValue`'s inner `Value` is reached through a `pub(crate)` accessor rather
than by cloning.

**Why not extend `ciborium::Value`?** It owns its payloads by construction —
that ownership *is* the defect. A borrowing type is the only shape that can
serialise straight out of a `SecretString` without a copy.

### 2.2 Mechanism B — `SecretValueTree`, in `core/src/cbor.rs`

Owns a parsed `Value` (or a `Vec<(Value, Value)>` entry list) and recursively
zeroizes `Bytes` and `Text` payloads through `Array` and `Map` on `Drop`.

`cbor.rs` is the home because both `vault::{record, block}` and `unlock::bundle`
need it, and that module is already the single place that owns this crate's
`ciborium` boundary (`classify_de` / `classify_ser`, #474).

Three properties carried over from `ZeroizingEntries` (#542) and its own review:

1. **`Value::Text` IS wiped here**, unlike in `ZeroizingEntries`. The bundle
   deliberately skipped `Text` because its only text value is `display_name`,
   which `IdentityBundle` holds unwrapped anyway — wiping the clone while the
   original stays in the clear is theatre. On the record path the opposite
   holds: `RecordFieldValue::Text` is a `SecretString`, so a password is
   precisely the `Value::Text` case.
2. **Recursion, not top-level-only.** `ZeroizingEntries::wipe` walks top-level
   `Value::Bytes` only, which was sound for the bundle's flat §5 map and is
   wrong for the nested record shape (`record.rs:493` nests a per-field map
   inside an outer map inside the records array).
3. **`ciborium::Value` is `#[non_exhaustive]`**, so no match arm will ever warn
   when a shape is missed. The catch-all arm is therefore explicit and
   documented, and a test enumerates every variant the walker can encounter.
   The shape assertion goes at **construction**, not in `wipe`: `wipe` is
   reachable from `Drop`, and a panic in a `Drop` running during an unwind
   aborts the process.

**What this does not claim.** A wipe of freed heap is not observable from safe
Rust; neither is a `String`/`Vec` reallocation that happened inside `ciborium`'s
parser before we ever saw the value. `SecretValueTree` covers the buffer the
tree points at when it drops. This boundary is stated in the code, not only
here.

---

## 3. What the encode path becomes

### 3.1 `record.rs`

`record_to_canonical(&Record) -> CanonicalMap<'_>` replaces
`record_to_entries` + `fields_to_value` + `field_to_entries`. The field value
arm becomes:

```rust
RecordFieldValue::Text(s)  => CanonicalValue::Text(s.expose()),
RecordFieldValue::Bytes(b) => CanonicalValue::Bytes(b.expose()),
```

— a borrow where there was a copy. `record::encode` serialises that map once,
into a buffer pre-reserved against a size bound so `into_writer` cannot realloc
(the `encode_map` precedent, `bundle.rs:746`). **Copies #1–#4 gone.**

### 3.2 `block.rs`

`plaintext_to_entries`' `records` entry becomes
`CanonicalValue::Array(records.iter().map(record_to_canonical).collect())` —
embedded inline. `records_to_value`'s encode → `Vec<u8>` → `from_reader`
round-trip is deleted. **Copies #5–#6 gone.**

This *strengthens* the invariant `records_to_value`'s doc comment was protecting
("keeping `record::encode` as the sole authority on record CBOR shape"): block
now calls the same `record_to_canonical` that `record::encode` calls, instead of
re-parsing its output. It also retires the performance hook `block.rs:917-924`
recorded for exactly this round-trip.

### 3.3 `manifest.rs`

Unchanged. It carries no plaintext, and `canonical_sort_entries` /
`encode_canonical_map` remain for it — with `pair.clone()` replaced by a
borrow, which is a pure win and no behaviour change.

---

## 4. What the decode path becomes

All three parse entry points wrap the tree the parser hands back:

- `record::decode` (`record.rs:551`)
- `block::decode_plaintext` (`block.rs:976`)
- `bundle::from_canonical_cbor` (`bundle.rs:360`) — **this is the whole of #548.**
  `Drop` then covers every `?` inside the field loop: `Malformed` on a
  non-string key, `DuplicateField` via `set_once`, `WrongKeySize`,
  `UnknownField`.

### 4.1 The one validation-semantics change

`block::take_records` re-serialises each record `Value` into a plaintext `buf`
and calls `record::decode(&buf)`. A `pub(crate) fn record::decode_value(&Value)`
removes that buffer entirely.

What is lost is the **per-record** byte-level canonicality re-check. The claim
is that it is **subsumed** by `decode_plaintext`'s own re-encode-and-compare,
which covers the nested record bytes as part of the whole block. That is a
claim about frozen-format validation, so it is discharged by a test that plants
a non-canonical nested record (out-of-order field keys, and separately an
indefinite-length item) inside an otherwise-valid block and proves
`decode_plaintext` still rejects it — not by argument.

If the test fails, the fallback is to keep `take_records` as it is and wrap
`buf` in `SecretBytes` — a wipe rather than an elimination for that one buffer.

### 4.2 `bundle.rs` consolidation

`ZeroizingEntries`, `BorrowedCanonicalMap` and `cbor_size_bound` are private to
`bundle.rs` today. `BorrowedCanonicalMap` and `cbor_size_bound` move to the
shared `canonical` module (generalised); `ZeroizingEntries` is replaced by
`SecretValueTree`. Roughly −120 lines from a 1589-line file — partial credit
against #543, which stays open.

The `WIPE_CALLS` counter that pins `impl Drop` (added in the #546 review, after
mutation showed deleting the `Drop` left all 25 bundle tests green) moves with
the mechanism and covers `SecretValueTree`.

---

## 5. How byte-identity is guaranteed

The on-disk format is **frozen for v1**. Every byte this change touches is
covered by at least one of:

1. **A promoted equivalence test** (task 1, written before any production
   change). The throwaway probe run during design compared a hand-written
   `Serialize` against a `Value` tree across every CBOR head-length boundary
   — 0, 1, 23, 24, 255, 256, 65535, 65536, 2³², `u64::MAX` — for uint, text,
   bytes, map and array, plus the nested record-in-block shape and `Borrowed`
   passthrough: **41 comparisons, 0 differences**. That probe becomes a real
   test in `core/tests/`, so the property is re-proven on every CI run rather
   than attested here.
2. **The golden vault** (`core/tests/data/golden_vault_001/`). `from_canonical_cbor`
   re-encodes and compares against bytes written before this branch existed.
3. **`record::decode`'s own re-encode-and-byte-compare invariant**
   (`decode` re-encodes the parsed `Record` via `encode` and requires an
   exact match against the input bytes, or returns a typed
   `NonCanonicalEncoding` error) **driven over the frozen golden-vault
   fixture by `core/tests/golden_vault_001.rs`** — specifically
   `golden_vault_001_pinned`, which rebuilds the vault from
   `golden_vault_001_inputs.json` using the CURRENT Rust encoder and
   asserts the freshly-built bytes are byte-equal to the on-disk fixture,
   and `golden_vault_001_opens_with_password`, which decrypts and decodes
   the fixture's real block records. This is the check that would actually
   fail if today's record encoder stopped reproducing those bytes.
   `core/tests/data/fuzz_regressions/record/` replays the same `decode`
   path over a corpus of previously crash-inducing byte sequences as
   defense in depth; its formal contract is panic-freedom (`Result` is
   discarded), not byte-identity, so it does not substitute for the
   `golden_vault_001.rs` check above — a regression that turned a
   previously-canonical input into a clean `Err(NonCanonicalEncoding)`
   would not panic and would pass it silently.
4. ~~`conformance.py`, the clean-room verifier~~ — **this item was wrong and
   is corrected, not merely reworded.** A prior version of this list named
   `conformance.py` as byte-identity proof for the *Rust* encoder ("a byte
   change that the Rust tests happen to agree with still reds it"). That is
   false for this change class: `conformance.py` contains no reference to
   `secretary_core`, `cargo`, or `subprocess` — it invokes no Rust at all.
   It is a pure-Python implementation that reads the static
   `golden_vault_001/` fixture directly and proves the fixture agrees with
   `docs/` (the clean-room-implementability property, #546's actual scope).
   It would pass identically whether or not the Rust encoder in this crate
   still produces those bytes; it says nothing about that question. It
   remains valuable evidence that the *docs* stayed correct, and running it
   is still part of this slice's verification — but item 3 above, not this
   one, is what actually gates Rust byte-identity.
5. **The existing record / block / manifest KATs and round-trip tests.**

A diff of `core/tests/data/` must be **empty** at the end of this slice. If a
KAT needs regenerating, the change is a format change and the slice is wrong.

---

## 6. What is NOT in scope

- **`record::decode`'s own re-encode canonicality check.** It re-runs the
  encode pipeline on every decode. With the new encoder that is now cheap and
  copy-free, so it stays — it is a correctness gate, not a residue.
- **`manifest.rs` migration to `CanonicalValue`.** No plaintext; churn on
  frozen-adjacent code for no security gain.
- **#519** (ffi-uniffi accessors), **#551** (`Sensitive::<Vec<u8>>::try_build`
  reaches the realloc hazard), **#543** (the `bundle.rs` split). Each tracked
  separately; #543 gets partial relief here as a side effect, not as a goal.
- **The `unknown` map's `Value`s.** Forward-compat values from a future
  version could in principle carry secret content, but this version cannot know
  their shape, and they are already covered on the decode side by
  `SecretValueTree`'s recursion. On the encode side they are borrowed, not
  cloned, so no new copy is created.

---

## 7. File layout and line budget

`canonical.rs` is 260 lines and would land near 550 with the new type. It
becomes a **directory module** per the 500-line guideline:

```
core/src/vault/canonical/
    mod.rs        — re-exports, module docs, CanonicalError  (~120)
    value.rs      — CanonicalValue / CanonicalMap + Serialize (~220)
    legacy.rs     — canonical_sort_entries / encode_canonical_map /
                    reject_floats_and_tags, for manifest + block headers (~200)
    size.rs       — cbor_size_bound, moved from bundle.rs      (~80)
```

`core/src/cbor.rs` is 221 lines and gains `SecretValueTree` (~150 with docs),
landing near 370 — under the guideline, so it stays a single file.

## 8. Testing

Per the repo's TDD discipline, each task's tests are written before its
production change.

- **Equivalence**: the promoted probe (§5.1), extended to the exact shapes
  `record` and `block` emit.
- **Byte-identity**: existing record/block/manifest round-trip and KAT tests
  must pass **unchanged**; golden vault (`golden_vault_001.rs`'s
  rebuild-and-compare plus `record::decode`'s own re-encode-and-compare —
  see §5 item 3, the check that actually gates the Rust encoder);
  `conformance.py` (proves `docs/`/fixture agreement, not Rust-encoder
  behaviour — see §5 item 4).
- **Wipe-on-drop**: a `#[cfg(test)]` counter proving `Drop` calls the walker
  (the #546 precedent — without it, deleting `impl Drop` left every test
  green). Assertions must distinguish a wipe from a `clear()`: the #546 review
  found `all(|b| b == 0)` on a vec that `Zeroize` empties passes vacuously.
- **Recursion coverage**: a tree with secrets at every depth and in every
  container arm; a test enumerating every `ciborium::Value` variant so a new
  upstream variant is a visible failure rather than a silent skip.
- **No-realloc**: `capacity()` assertions on the pre-reserved output buffers
  (the #546 precedent — the doc there had claimed this was not observable,
  which was wrong).
- **Nested non-canonical rejection** (§4.1): the test that discharges the one
  validation-semantics change.
- **Mutation checks**: for each new guard-like property, delete the mechanism
  and confirm a test fails. A property nothing pins is not a property.
