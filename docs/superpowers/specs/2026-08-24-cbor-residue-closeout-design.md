# Canonical-CBOR residue closeout — design

**Date:** 2026-08-24 · **Branch:** `feature/cbor-residue-closeout` · **Base:** `main` @ `467c7072`

Closes **#561**, **#565**, **#566**, **#567**, **#568**, **#569** (bundle half), **#570** (doc half), and
**#558** (structurally, via T4). Continues the mechanism landed in #560 (`(#547, #548)`).

**Not in scope:** #562 (regenerating `golden_vault_001` is a human-reviewed fixture diff that also
feeds `conformance.py` — its own slice, its own review), #519 (see §7), #563/#564/#556/#543 (file splits).

---

## 1. The invariant every task is held to

`core/tests/data/` diff stays **EMPTY** and `golden_vault_001_pinned` stays green. No on-disk format
change; no `.udl` change; no FFI surface change. `golden_vault_001_pinned` rebuilds every vault file
with today's encoder and byte-compares against the frozen fixture **without round-tripping**, so it is
the gate that would catch a compensating encoder/decoder pair. T3 is the only task that can move bytes;
§3 says why and how that is contained.

## 2. Three census corrections, established before the spec was written

Each of the three issues this slice draws on carries a factual claim that does not survive re-running its
own census. Recorded here rather than silently worked around, because #560's single most repeated defect
was a claim asserted in prose that the code beside it did not support.

| Issue | Its claim | Verified reality |
|---|---|---|
| #558 | "six `aead::encrypt` call sites in `core/src` … all six already pass `.expose()`, so the type change may be nearly free" | **Seven.** The seventh is `manifest.rs:1552`, which passes `manifest_bytes: &[u8]` — a parameter of the **public** `encrypt_manifest_body`, re-exported at `core/src/vault/mod.rs:50`. Beyond `core/src` a `&SecretBytes` signature would also break **15** test call sites, including `core/tests/aead.rs:149`, which replays published RFC vectors. "Nearly free" is false. |
| #569 | "`core/src/identity/card.rs` — same shape" | `grep -c "Sensitive\|SecretBytes\|SecretString" core/src/identity/card.rs` returns **0**. `ContactCard`'s fields are `card_version`, `contact_uuid`, `display_name`, four **public** keys, `created_at_ms`, and two self-signatures. The contact card is the artifact handed to other users. Migrating it reduces no secret residue. **Dropped from scope.** |
| #561 | lists 5–6 sites | There are **8** production `ciborium::de::from_reader` calls in `core/src`. Six are secret-bearing and are exactly the issue's list; the two it omits (`card.rs:320`, `sync/state.rs:136`) are correctly omitted but the issue never states that secrecy is the filter, so the list reads as incomplete rather than as scoped. |

**Consequence for #558.** Because the "nearly free" premise is false, the pin does **not** go on
`aead::encrypt`. Its plaintext genuinely is not always secret — that is what the RFC-vector KATs encrypt —
and forcing `&SecretBytes` there would conflate "this primitive encrypts" with "this input is secret".
The pin goes at the body boundary instead (T4).

## 3. Task-by-task design

### T1 — `core/src/cbor/scratch.rs`: one sanctioned secret-bearing parse entry point

`ciborium::de::from_reader` allocates a 4 KiB stack scratch buffer and `read_exact`s **every**
`Bytes`/`Text` payload ≤ 4096 bytes straight into it before the visitor copies out. `SecretValueTree`
cannot reach it: it lives in the parser's frame, not in the tree.

Verified against `ciborium-0.2.2/src/de/mod.rs:825-851` — `from_reader` **is literally**:

```rust
let mut scratch = [0; 4096];
from_reader_with_buffer(reader, &mut scratch)
```

and `from_reader_with_buffer` sets the identical `recurse: 256`. Passing our own 4096-byte buffer is
therefore **behaviour-identical**, not merely believed to be.

New module `core/src/cbor/scratch.rs`:

- `const CBOR_SCRATCH_LEN: usize = 4096;` — named, matching ciborium's own default so the swap changes
  no chunking behaviour. Not a magic number at any call site.
- `struct CborScratch([u8; CBOR_SCRATCH_LEN]);` — field module-private; **no** `&mut` accessor escapes
  the module.
- A **hand-written** `impl Drop` that zeroizes and, under `#[cfg(test)]`, bumps the shared `WIPE_CALLS`
  counter. Hand-written is the point: a derived `ZeroizeOnDrop` is invisible to `wipe_calls()`, which is
  the entire substance of #557/#558. This mechanism is therefore **pinnable by test from the moment it
  lands**, unlike the two it sits beside.
- `pub(crate) fn from_secret_reader<R>(reader: R) -> Result<Value, Error<R::Error>>` — allocates the
  scratch, calls `from_reader_with_buffer`, drops the scratch on every exit (return, `?`, unwind).

`WIPE_CALLS` is a `thread_local!` private to `secret_tree/mod.rs`. T1 adds `pub(super) fn note_wipe()`
there rather than relocating the counter — minimal diff, no churn on the three existing frozen-adjacent
bump sites (`secret_tree/mod.rs:138,207,335`, all already `#[cfg(test)]`-gated, so production cost is zero).

This is the sink-pinning move `SecretaryLog` (#472), `diagnosticDetail` (#467) and `detail::*` (#500)
each make for their own platform: policy applied once, in one place.

**Tests (written first):** the scratch is wiped on the success path; wiped on the `?` path (malformed
input); `from_secret_reader` and `ciborium::de::from_reader` agree byte-for-byte on a corpus spanning
payloads below, at, and above `CBOR_SCRATCH_LEN`.

### T2 — route the six secret-bearing sites onto it (#561)

| Site | Carries |
|---|---|
| `core/src/unlock/bundle.rs:388` | four long-term secret keys |
| `core/src/vault/block.rs:1032` | the entire decrypted block plaintext |
| `core/src/vault/manifest.rs:730` | forward-compat plaintext inside the encrypted manifest |
| `core/src/vault/manifest.rs:760` | `block_name`, user-authored plaintext |
| `core/src/vault/record.rs:299` | forward-compat unknown record subtree |
| `core/src/vault/record.rs:607` | decrypted record field plaintext |

`card.rs:320` (public contact card) and `sync/state.rs:136` stay on plain `from_reader`, **with a comment
at each saying why**. #561's own list read as incomplete precisely because its filter was unstated; not
repeating that.

**Test:** each converted path bumps `wipe_calls()` — pinning the composition, not just the mechanism.

### T3 — `bundle::to_canonical_cbor` → `CanonicalMap` (#569, bundle half)

`core/src/unlock/bundle.rs:292-340` builds 11 owned `ciborium::Value` entries, of which four are
cleartext copies of long-term secret keys pulled out of their `Sensitive` wrappers on **every** encode:
the ML-KEM-768 decapsulation key (2400 B), the ML-DSA-65 seed, the X25519 secret key and the Ed25519
secret key. `SecretEntries` wipes them — but wiping is the mechanism CLAUDE.md now records as the
**fallback**; elimination is strictly stronger wherever achievable, and here it is achievable: every
value is already a borrowable `&[u8]` / `&str` / `u64`.

`SecretEntries` disappears from the encode side. It stays on the decode side (`from_canonical_cbor`),
where the parser owns the allocation and elimination is not available.

**This is the slice's only byte-identity risk.** `Value::Integer(self.created_at_ms.into())` becomes
`CanonicalValue::Uint(self.created_at_ms)`. `record.rs` already ships that exact pairing for
`created_at_ms` / `last_mod_ms` and is covered by the golden vault, so the encoding equivalence is
already exercised — but for the bundle it is newly exercised, and `golden_vault_001_pinned` rebuilds
`identity.bundle.enc`, so a divergence fails loudly. **Acceptance: `core/tests/data/` diff EMPTY.**

### T4 — the encoders return `SecretBytes` (#558 + #565)

#558 and #565 are one complaint — *the mechanism is right, nothing would notice if it were removed* —
and both dissolve if the **encoder returns the wrapper** rather than each caller wrapping its output:

```rust
pub fn encode(record: &Record)            -> Result<SecretBytes, RecordError>    // was Vec<u8>
pub fn encode_plaintext(p: &BlockPlaintext) -> Result<SecretBytes, BlockError>   // was Vec<u8>
pub fn encode_manifest(m: &Manifest)      -> Result<SecretBytes, ManifestError>  // was Vec<u8>
pub fn encrypt_manifest_body(h: &ManifestHeader, body: &SecretBytes, ..)         // was &[u8]
```

What that buys, per site:

- `block.rs:1788` — `pt_bytes` becomes `SecretBytes` **by construction**. #558's block half is now a
  compiler check; the `SecretBytes::new(...)` wrapper call it currently relies on can no longer be
  deleted, because a `Vec<u8>` would not typecheck.
- `block.rs:1058` and `record.rs:629` — `re_encoded` likewise. #565 is closed by **elimination of the
  opportunity**, not by adding a wrap. The comparison becomes `re_encoded.expose() != bytes`.
- `manifest.rs:1943/1946` — `body_bytes` likewise, and `encrypt_manifest_body`'s `&SecretBytes`
  parameter closes the seventh `aead::encrypt` site §2 found.

`aead::encrypt` is deliberately **left alone**, per §2.

**Blast radius, measured:** `cli/src`, `ffi/*/src`, `desktop/src-tauri/src` and `browser/` call none of
the four functions (verified by grep; the single apparent hit is a doc comment naming the different
function `encode_manifest_file`). So this is a public-API change with **no external consumer**. Inside
`core` it is ~30 mechanical `.expose()` edits at test call sites, plus `core/tests/revoke_kat.rs`,
which writes encoder output into a KAT JSON — that one must be checked to still emit identical bytes.

**Test:** a compile-fail expectation is not available without a `trybuild` dep; instead the pin is the
signature itself, and the task asserts the byte-identity of every converted site.

### T5 — `set_once` duplicate-field temps (#566)

`core/src/unlock/bundle.rs`'s `set_once` returns `Err(BundleError::DuplicateField)` **after** its `v`
argument has already been evaluated. For the `Sensitive`-returning helpers the temp wipes on drop; for
the plain `String` / `Vec<u8>` / `[u8; N]` returns it does not.

Two shapes, and the implementer picks with the tradeoff written into the commit:

- **(a)** a `T: Zeroize` bound on `set_once`, wiping `v` on the duplicate path. Touches every call site's
  type obligation but is one edit and cannot be forgotten at a future call site.
- **(b)** wrapping each non-secret-typed return at its own call site. No signature change; a new call
  site can silently omit it.

**(a) is the default** — it is the same "make it unrepresentable" instinct as T4, and this slice should
not close one unpinned-mechanism complaint while opening another. Reject (a) only if a call site's `T`
genuinely cannot implement `Zeroize`.

Severity note carried from the issue: post-AEAD, so the content is not attacker-chosen.

### T6 — `parse_manifest_map` duplicate-key detection (#568)

`manifest.rs` is the last of four decoders that silently last-wins on a repeated CBOR map key;
`record.rs`, `block.rs` and `bundle.rs` all reject. Silent acceptance is the wrong direction.

Mirrors `block.rs:1087-1099` exactly: a `BTreeSet<String> seen_keys`, an enumerate over the map, and a
new `ManifestError::DuplicateKey { field: &'static str, index: usize }` — **data-free by construction**
per #474, so the payload guard's E1 rule passes without an allowlist entry.

~~Defence-in-depth, not a live hole: the manifest body is covered by the hybrid signature (Ed25519 **AND**
ML-DSA-65), and `decode_manifest`'s re-encode-and-compare canonicality check would reject the resulting
non-canonical bytes anyway.~~ **CORRECTION (controller ruling T6-A, found by Task 6's implementer and
verified independently): the second half of that sentence is FALSE.** `decode_manifest`
(`core/src/vault/manifest.rs:780`) has **no** re-encode-and-compare canonicality check — unlike
`record::decode` and `block::decode_plaintext`, which both have one. Its body ends
`reject_floats_and_tags(...)` -> destructure -> `parse_manifest_map(entries)`. Nothing re-encodes.

The correct framing: the manifest body is covered by the hybrid signature, and that is the **only**
backstop — there is no second, independent check the way the record and block paths have one. That makes
this fix **more** valuable than the original text implied, not less, and it makes the "the signature
covers it stops being true after an unrelated refactor" argument load-bearing rather than rhetorical.
The missing canonicality check is filed separately as **#572**.

I wrote the false half of that claim into this spec without checking it, and it propagated into the
plan and into Task 6's brief. It is corrected in place rather than silently edited, per this project's
convention — see §2's own note on census claims that do not survive re-running.

Note: `take_text_key` already clones the key, so `seen_keys` adds one more `String` clone per key. These
are top-level manifest keys (`manifest_version`, `vault_uuid`, …) plus forward-compat unknown keys —
structural, not user content. `block_name` is a **value** inside the blocks array, not a key here.

### T7 — proptest for the key-order equivalence (#567)

`CanonicalMap::serialize` sorts text keys on `(key.len(), key.as_bytes())` and claims that is exactly
RFC 8949 §4.2.1 order. That claim is what lets the sort read straight through the borrowed `&str`s and
materialise **no key buffer** — which is the whole security point, because record field names are
decrypted plaintext.

The claim has been checked twice by exhaustive sweep (184,041 pairwise comparisons in #560's PR body;
400,000 in an independent Python reproduction during its review, zero mismatches both times) and
**neither sweep is committed**. Both live in prose. There are zero `proptest` uses under
`core/src/vault/canonical/` or `core/src/cbor/`.

`proptest` is already a `secretary-core` dev-dependency. The property:

```
(a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()))  ==  enc_text(&a).cmp(&enc_text(&b))
```

where `enc_text` is a local CBOR text-head encoder written for the test — deliberately **not** reusing
the production encoder, or the test would be circular.

This matters more than a normal property test because the frozen-fixture anchor cannot see the
regression it is cited as covering (#562): every key in `golden_vault_001` is ASCII, so a byte-length →
char-count regression produces byte-identical output for that vault.

### T8 — documentation

- `core/src/cbor/secret_tree/mod.rs`'s *"What this does not claim"* section gains **(i)** the parser's
  4 KiB scratch buffer, now addressed by T1, and **(ii)** the >4 KiB reallocation threshold (#570).
  Today that section names the realloc class in one general clause; it does not say the class is
  **routine for any field over 4 KiB**, which for an attachment, a long note or a stored key file it is.
  A reader currently cannot tell.
- `docs/manual/contributors/memory-hygiene-audit-internal.md` — extend the six-copy trace with what
  this slice closes and what it does not.
- `CLAUDE.md` — the zeroize-discipline section gains the "encoder returns the wrapper" pattern from T4.
- `ffi/secretary-ffi-uniffi/src/wrappers/block.rs` — correct the #519 comment. It currently justifies the
  gap as *"there is no local to wrapper-type"*. That is not the reason: the bridge's `to_vec()` result
  **is** a local we own. The real reason is the `RustBuffer` (§7).

## 4. Sequencing

`T1 → T2 → T4 → T3 → T5 → T6 → T7 → T8`

T1 before T2 (T2 consumes T1's entry point). T4 before T3 because it has the widest ripple and should
surface surprises early, while T3 is the one task that can move on-disk bytes and wants a settled tree
underneath it. T5–T7 are independent. T8 last, so it describes what actually shipped.

Subagent-driven: a fresh implementer per task, an independent review after each, a whole-branch review
at the end — the cadence that worked in #560. TDD throughout; each task's tests land before its
implementation.

## 5. Gates

Every gate in the previous baton's §4 block, plus: `core/tests/data/` diff **EMPTY** and
`ffi/secretary-ffi-uniffi/src/secretary.udl` diff **EMPTY** (nothing in this slice crosses the FFI).

## 6. Risks

1. **T3 byte identity** — the only path that can change on-disk output. Contained by
   `golden_vault_001_pinned`, which rebuilds `identity.bundle.enc` without round-tripping.
2. **T4's reach** — ~30 test call sites plus a KAT generator. Mechanical, but a missed `.expose()` in a
   comparison would compile if both sides changed type together, so each converted assertion is read
   rather than pattern-replaced.
3. **T1 behaviour drift** — mitigated by reading ciborium's source rather than its docs: `from_reader`
   *is* `from_reader_with_buffer` with a 4096-byte buffer and `recurse: 256`.
4. **File growth** — `manifest.rs` (3855) and `block.rs` (2978) are already at issue (#564, #563). T6 adds
   ~40 lines to `manifest.rs`; T1 adds a new small module rather than growing an existing file. No task
   in this slice makes the split harder.

## 7. What this slice deliberately does not close

**#519** — re-audited against uniffi 0.32.0's source on 2026-08-24 and commented on the issue. Two
corrections to its stated fix:

- `uniffi::custom_type!` does **not** help. `uniffi_macros-0.32.0/src/custom.rs:236-247` generates
  `<Vec<u8> as Lower>::write(lower_expr, buf)`, so a custom type must still materialise a real
  `Vec<u8>`/`String` first. Only a hand-authored `unsafe impl Lower` avoids it — an `unsafe trait` in a
  crate that sets `unsafe_code = "deny"`, requiring a hand-written duplicate of uniffi's wire format
  that must stay byte-exact across every uniffi upgrade.
- There are **three** copies per call, and any in-repo fix reaches only the first. The second is the
  `RustBuffer`: `lower_into_rust_buffer` (`uniffi_core-0.32.0/src/ffi_converter_traits.rs:265`) hands it
  to the foreign side, which frees it through uniffi's own generated `rustbuffer_free` →
  `RustBuffer::destroy`. We never see that free. **Unclosable in-repo at any effort level.**

So the maximal in-repo fix closes 1 of 3 copies at a materially worse cost than the issue implies. The
honest next step is an upstream uniffi issue for a zeroize-aware lowering hook — the only thing that can
reach copy 2 — not a large in-repo change. T8 corrects the misleading in-code comment; the rest is a
separate decision.

**#562** — regenerating `golden_vault_001` is a human-reviewed fixture diff that also feeds
`conformance.py`. Its own slice, its own review.
