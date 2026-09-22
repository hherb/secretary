# Token-compare `contact_card` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `contact_card` the fourth token-compared differential-replay
target, so the two implementations are compared on WHICH rule each names, with
zero disagreements over the whole corpus and no tolerance.

**Architecture:** Rule the `display_name` cap normative in `docs/`, then wire
the shared byte-level well-formedness walk into the card path in both
languages, give `CardError` a rule-4 pair and an exhaustive `rule_token()`,
reorder the Python decoder onto Rust's phase order using the entry-span loop
`codec/manifest_decode.py` already uses, and add committed single-fault seeds
through the existing generator.

**Tech Stack:** Rust (stable, `core/`), Python 3.11 via `uv`
(`core/tests/python/conformance_lib/`), `cbor2`, `ciborium`.

**Spec:** `docs/superpowers/specs/2026-09-22-token-compare-contact-card-design.md`

## Global Constraints

- **Working directory is the worktree.** `/Users/hherb/src/secretary/.worktrees/token-compare-card`, branch `feature/token-compare-contact-card`. Shell state does not persist between tool calls; chain or use absolute paths.
- **Never `pip`.** `uv` only.
- **`#![forbid(unsafe_code)]`** is a workspace lint. Do not introduce `unsafe`.
- **Clippy must stay clean** with `-D warnings`, lib *and* test targets.
- **Scratch files go to `$SCRATCH`**, never the source tree (#516). `$SCRATCH` = the session scratchpad directory.
- **`MAX_DISPLAY_NAME_BYTES = 4096`** — `core/src/identity/card.rs:91`. The single source; never write `4096` literally in new code or docs prose without citing the constant.
- **`RuleToken` is at 17 variants** and becomes 18. Its `ALL` slice, `as_str`, `is_phase_dependent` and `core/tests/data/rule_token_vocabulary.json` must move together.
- **`CardError` is at 11 variants** and becomes 13.
- **Every new Python rejection class carries a `token` class attribute** whose value is a vocabulary spelling, and subclasses `ValueError` (or `KeyError` for a missing field) so `conformance_lib.rejection`'s allowlist covers it.
- **Seed file names are DERIVED from their row**, never hand-written.
- **A moved ACCEPTANCE verdict on the fuzz corpus is a STOP condition**, not a finding to write up. Halt and report.

---

### Task 1: The normative `display_name` cap

**Files:**
- Modify: `docs/crypto-design.md` (§6, the Contact Card section)
- Modify: `docs/threat-model.md:176` (the Display-name DoS cap row)

**Interfaces:**
- Consumes: nothing.
- Produces: the normative sentence Task 8 implements in `codec/card.py`. No code symbol.

- [ ] **Step 1: Read the two anchors**

```bash
cd /Users/hherb/src/secretary/.worktrees/token-compare-card
sed -n '/^## 6\./,/^### 6.1/p' docs/crypto-design.md
sed -n '174,178p' docs/threat-model.md
```

- [ ] **Step 2: Add the normative paragraph to `docs/crypto-design.md` §6**

Place it immediately after the §6 field listing, before §6.1. Wording is
modelled on §6.2 rule 6, whose three justifying clauses hold identically here:

```markdown
**`display_name` is at most 4096 bytes of UTF-8.** Writers MUST NOT emit a
longer one and readers MUST reject one. This is a v1 profile bound, not a
canonical-form rule: it bounds the memory a reader commits to attacker-supplied
variable-length text taken from the attacker-writable vault folder, before any
signature over that text can be checked. The reference implementation has
enforced exactly this limit since v1, on parse and on both encode paths, so
stating it narrows nothing a v1 reader accepts and forbids nothing a v1 writer
emits. A reader reports it distinguishably from a fixed-size field arriving at
the wrong length, because the two have different remediations.
```

- [ ] **Step 3: Update the `threat-model.md` row to cite the spec**

The row currently cites Rust test names only. Add the §6 citation so the
control is traceable to a normative sentence rather than to an implementation:

```
- **Display-name DoS cap on parse + encode + signed_bytes** → normative in
  [crypto-design.md](crypto-design.md) §6; `core/src/identity/card.rs` tests
  `from_canonical_cbor_rejects_oversize_display_name`,
  `_accepts_display_name_at_cap`, `to_canonical_cbor_rejects_oversize_display_name`,
  `_accepts_display_name_at_cap`, `signed_bytes_rejects_oversize_display_name`
  (cap enforced symmetrically; PR #11).
```

- [ ] **Step 4: Verify the figure in the doc matches the constant**

The doc now states a number. Confirm it is the constant's value — a mismatch
here is the drift class this repo keeps re-finding:

```bash
grep -n "MAX_DISPLAY_NAME_BYTES: usize" core/src/identity/card.rs
grep -n "4096 bytes of UTF-8" docs/crypto-design.md
```

Expected: `= 4096;` and the prose figure agree.

- [ ] **Step 5: Verify nothing regressed**

```bash
uv run core/tests/python/conformance.py
cargo test --release --locked -p secretary-core --lib identity::card
```

Expected: conformance exit 0, all card unit tests pass. Neither changes —
this task edits only prose.

- [ ] **Step 6: Commit**

```bash
git add docs/crypto-design.md docs/threat-model.md
git commit -m "spec: crypto-design §6 bounds display_name at 4096 bytes (#641)

The cap has been enforced on parse and on both encode paths since PR #11 and
was stated in no normative document, so a clean-room writer could emit a card
this codebase refuses to read back. Binds writers and readers, as §6.2 rule 6
and §4.2's repeated-array-value rule do.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `CardError` gains rule-4 arms

**Files:**
- Modify: `core/src/identity/card.rs` (the `CardError` enum; `canonical_error_to_card_error`; a new `impl From`)

**Interfaces:**
- Consumes: `crate::vault::canonical::CanonicalError` (already imported at `card.rs:61`).
- Produces: `CardError::FloatRejected { field: &'static str }`, `CardError::TagRejected`, and `impl From<CanonicalError> for CardError`. Task 3 needs the `From`; Task 6 classifies the two variants.

Note the shapes: `FloatRejected` carries a `&'static str` field (mirroring
`RecordError::FloatRejected`, and because `CanonicalError::FloatRejected` has
one to forward), `TagRejected` is fieldless (mirroring `RecordError::TagRejected`).

- [ ] **Step 1: Write the failing test**

Add to `card.rs`'s `#[cfg(test)] mod tests`:

```rust
/// The rule-4 arms are their own variants, not folded onto `Malformed`.
///
/// Until #641 both folded onto `CardError::Malformed(&'static str)`, which is
/// fine while nothing reads the distinction and wrong the moment a rule token
/// does: rule 4 would report as `wrong_type` against a `conformance.py` side
/// that names it exactly, manufacturing a divergence out of a mapping choice.
#[test]
fn canonical_rule_four_errors_keep_their_own_card_variants() {
    let float = CardError::from(CanonicalError::FloatRejected { field: "<root>" });
    assert!(
        matches!(float, CardError::FloatRejected { field: "<root>" }),
        "expected FloatRejected, got {float:?}"
    );
    let tag = CardError::from(CanonicalError::TagRejected { field: "<root>" });
    assert!(
        matches!(tag, CardError::TagRejected),
        "expected TagRejected, got {tag:?}"
    );
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test --release --locked -p secretary-core --lib \
  identity::card::tests::canonical_rule_four_errors_keep_their_own_card_variants
```

Expected: FAIL to COMPILE — `no variant named FloatRejected`, and
`the trait From<CanonicalError> is not implemented for CardError`.

- [ ] **Step 3: Add the two variants**

In the `CardError` enum, after `Malformed`:

```rust
    /// A float appeared anywhere in the card body. crypto-design §6.2
    /// rule 4, which §6.2's opening sentence binds the §6 self-signed
    /// message and §6.1 fingerprint input by.
    ///
    /// Its own variant rather than a [`Self::Malformed`] literal because
    /// `rule_token()` must name rule 4 where `conformance.py` names it
    /// (#641). `field` is a `&'static str` hint from
    /// [`CanonicalError::FloatRejected`], never card content.
    #[error("float values are not permitted in canonical CBOR (in field {field})")]
    FloatRejected {
        /// A fixed structural hint, e.g. `"<root>"`.
        field: &'static str,
    },

    /// A CBOR tag appeared anywhere in the card body — §6.2 rule 4.
    ///
    /// Fieldless, mirroring [`crate::vault::record::RecordError::TagRejected`]:
    /// `CanonicalError::TagRejected`'s hint is dropped because no caller
    /// distinguishes tag positions and the token does not either.
    #[error("CBOR tags are not permitted in canonical CBOR")]
    TagRejected,
```

- [ ] **Step 4: Repoint the two folding arms and add the `From`**

In `canonical_error_to_card_error`, replace the two `Malformed(..)` arms:

```rust
        CanonicalError::FloatRejected { field } => CardError::FloatRejected { field },
        CanonicalError::TagRejected { .. } => CardError::TagRejected,
```

Then, immediately below that function:

```rust
/// Required by [`crate::vault::canonical::walk_first_item_checked`], whose
/// bound is `E: From<CanonicalError>` (#641).
///
/// Delegates rather than re-deciding: the mapping stays written in exactly one
/// place, which is the property `canonical_error_to_card_error` exists for.
impl From<CanonicalError> for CardError {
    fn from(e: CanonicalError) -> Self {
        canonical_error_to_card_error(e)
    }
}
```

- [ ] **Step 5: Run the test and the whole card suite**

```bash
cargo test --release --locked -p secretary-core --lib identity::card
cargo test --release --locked -p secretary-core --test identity
```

Expected: PASS. If any test asserts the old `Malformed` message text, it is
asserting the fold this task removes — update it to the new variant and say so
in the commit. (A grep at plan time found none in `core/` or `ffi/`; the
`bundle.rs` hits are `BundleError`'s and are untouched.)

- [ ] **Step 6: Commit**

```bash
git add core/src/identity/card.rs
git commit -m "core: CardError gains FloatRejected and TagRejected (#641)

Both used to fold onto Malformed(&'static str), which reports §6.2 rule 4 as
wrong_type — a divergence manufactured by a mapping choice, against a
conformance.py side that names rule 4 exactly. Adds the From<CanonicalError>
impl walk_first_item_checked's bound needs, delegating so the mapping stays
written once.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: The well-formedness walk runs first, in BOTH languages

**Files:**
- Modify: `core/src/identity/card.rs` (`from_canonical_cbor`'s first statement; new tests)
- Modify: `core/tests/python/conformance_lib/codec/card.py` (the pre-pass call)

**Interfaces:**
- Consumes: `CardError::{FloatRejected, TagRejected}` and `impl From<CanonicalError> for CardError` from Task 2; `crate::vault::canonical::walk_first_item_checked`; `conformance_lib.codec.well_formed.walk_body`.
- Produces: the aligned pre-pass both later tasks assume.

**Both languages in ONE task, deliberately.** Changing only the Rust side makes
Rust reject a 9-byte-bignum `created_at` that Python still accepts, so
`differential_replay` — which compares ACCEPTANCE on every target, compared or
not — reds between the two tasks. Each task must end green.

- [ ] **Step 1: Write the failing Rust tests**

In `card.rs`'s test module:

```rust
/// Build a card body with one known field's value replaced by raw bytes.
///
/// The card schema has no forward-compat `unknown` bag, so a fault can only
/// be planted in a known field's value — unlike the manifest, where #666's
/// probe planted under an unknown key.
fn card_bytes_with_created_at(raw: &[u8]) -> Vec<u8> {
    let card = fixture_card("probe", 1_714_060_800_000, 0x55, 0x66);
    let base = card.to_canonical_cbor().expect("encode");
    let needle = {
        let mut v = vec![0x6a]; // text(10)
        v.extend_from_slice(b"created_at");
        v
    };
    let at = base
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .expect("created_at key present")
        + needle.len();
    // The value that follows is a u64; find its end by re-encoding the same
    // integer the fixture used.
    let old = {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Integer(1_714_060_800_000u64.into()), &mut buf)
            .expect("encode created_at");
        buf
    };
    assert_eq!(&base[at..at + old.len()], old.as_slice(), "value layout moved");
    let mut out = base[..at].to_vec();
    out.extend_from_slice(raw);
    out.extend_from_slice(&base[at + old.len()..]);
    out
}

/// A body that is not well-formed is reported as that, ahead of the shape
/// check — `docs/vault-format.md` §4.2's precondition, which §6.2 rule 6
/// cites and which `record::decode` and `decode_manifest` already honour.
///
/// Before #641 `ciborium` parsed the whole item first and read `undefined`
/// and the two-byte simple form as ordinary simple values, so the card
/// answered `Malformed("expected unsigned integer")` where `conformance.py`
/// answered `malformed_cbor` — a pair that is never tolerated.
#[test]
fn a_malformed_body_outranks_the_shape_check() {
    for (label, raw) in [
        ("undefined", vec![0xf7]),
        ("two-byte simple", vec![0xf8, 0x15]),
        ("nested indefinite chunk", vec![0x7f, 0x7f, 0x61, 0x61, 0xff, 0xff]),
    ] {
        let bytes = card_bytes_with_created_at(&raw);
        let err = ContactCard::from_canonical_cbor(&bytes)
            .expect_err("a non-well-formed body must be rejected");
        assert!(
            matches!(err, CardError::CborDecode(_)),
            "{label}: expected CborDecode, got {err:?}"
        );
    }
}

/// §6.2 rule 4, reported as rule 4 at BOTH bignum widths.
///
/// The narrow one is the sharper row. `ciborium` folds a bignum that fits 64
/// bits into an integer, so before #641 it reached the re-encode comparison
/// and reported `NonCanonicalCbor`; `cbor2` folds it too, so BOTH said
/// "non-canonical" and neither named the tag. Agreement is not conformance.
#[test]
fn a_tag_anywhere_is_reported_as_rule_four() {
    for (label, raw) in [
        ("narrow bignum", vec![0xc2, 0x41, 0x01]),
        ("wide bignum", vec![0xc2, 0x49, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
        ("shareable tag 28", vec![0xd8, 0x1c, 0x00]),
    ] {
        let bytes = card_bytes_with_created_at(&raw);
        let err = ContactCard::from_canonical_cbor(&bytes)
            .expect_err("a tag must be rejected");
        assert!(
            matches!(err, CardError::TagRejected),
            "{label}: expected TagRejected, got {err:?}"
        );
    }
}

/// §6.2 rule 4's other half.
#[test]
fn a_float_anywhere_is_reported_as_rule_four() {
    let bytes = card_bytes_with_created_at(&[0xf9, 0x00, 0x00]);
    let err = ContactCard::from_canonical_cbor(&bytes).expect_err("a float must be rejected");
    assert!(
        matches!(err, CardError::FloatRejected { .. }),
        "expected FloatRejected, got {err:?}"
    );
}

/// The walk answers before `ciborium`, so §6.2 rule 6's limit on this path is
/// the walk's and not `ciborium`'s. 256 levels inside the card map is the
/// card map plus 255 arrays; 257 is one more.
#[test]
fn the_walk_enforces_the_v1_nesting_limit_on_the_card_path() {
    let at_limit = card_bytes_with_created_at(&{
        let mut v = vec![0x81; 255];
        v.push(0x00);
        v
    });
    let err = ContactCard::from_canonical_cbor(&at_limit)
        .expect_err("a nested array is still the wrong type for created_at");
    assert!(
        !matches!(err, CardError::CborDecode(_)),
        "256 levels must not be refused for DEPTH, got {err:?}"
    );

    let past_limit = card_bytes_with_created_at(&{
        let mut v = vec![0x81; 256];
        v.push(0x00);
        v
    });
    let err = ContactCard::from_canonical_cbor(&past_limit).expect_err("257 levels");
    assert!(
        matches!(
            err,
            CardError::CborDecode(CborFault {
                kind: CborErrorKind::RecursionLimit,
                ..
            })
        ),
        "expected RecursionLimit, got {err:?}"
    );
}
```

Add `use crate::cbor::{CborErrorKind, CborFault};` to the test module if not
already in scope.

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test --release --locked -p secretary-core --lib identity::card 2>&1 | tail -20
```

Expected: the four new tests FAIL. `a_malformed_body_outranks_the_shape_check`
reports `Malformed("expected unsigned integer")`;
`a_tag_anywhere_is_reported_as_rule_four` reports `NonCanonicalCbor` for the
narrow bignum and `Malformed(..)` for the wide one.

- [ ] **Step 3: Wire the walk into `from_canonical_cbor`**

Make it the function's FIRST statement, ahead of the `from_reader` call:

```rust
        // crypto-design §6.2's rules 4 and 6 and `docs/vault-format.md` §4.2's
        // well-formedness precondition, before anything is parsed (#641, #691).
        //
        // `ciborium` reads `undefined` and the two-byte simple form as
        // ordinary simple values, folds a bignum that fits 64 bits into an
        // integer, and accepts a nested indefinite chunk — each rejected
        // anyway, but under a later rule than `conformance.py` names. The
        // same walk `record::decode` (#641), `decode_manifest` and
        // `block::decode_plaintext` (#666) run. Its offset is discarded:
        // trailing bytes are judged by the re-encode comparison below, where
        // this decoder has always judged them.
        crate::vault::canonical::walk_first_item_checked(bytes, CardError::CborDecode)?;
```

- [ ] **Step 4: Run the Rust tests**

```bash
cargo test --release --locked -p secretary-core --lib identity::card
cargo test --release --locked -p secretary-core --test identity
```

Expected: PASS, including every pre-existing card test.

- [ ] **Step 5: Move the Python pre-pass onto `walk_body`**

In `core/tests/python/conformance_lib/codec/card.py`, change the import and
the call:

```python
from conformance_lib.codec.well_formed import walk_body
```

```python
    # crypto-design §6.2 rules 4 and 6 before cbor2 parses anything, and
    # `docs/vault-format.md` §4.2's well-formedness precondition ahead of both
    # (#641, #691).  `walk_body`, not the content-BLIND `reject_excessive_nesting`
    # this decoder used until #641: that pass reported no UTF-8, simple-value
    # or rule-4 fault, so `cbor2` folded a bignum to an int and re-emitted it as
    # a bignum, round-tripping the re-encode comparison and ACCEPTING a tag
    # §6.2 rule 4 forbids.
    walk_body(data)
```

- [ ] **Step 6: Verify both sides agree, and that the acceptance set moved together**

```bash
uv run core/tests/python/conformance.py
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

Expected: conformance exit 0, all sections PASS; the replay `ok`. The replay
is the load-bearing gate here — it compares ACCEPTANCE on `contact_card` even
though the target is not yet token-compared, so a one-sided walk reds it.

- [ ] **Step 7: Commit**

```bash
git add core/src/identity/card.rs core/tests/python/conformance_lib/codec/card.py
git commit -m "Walk the card body for well-formedness before parsing (#641, #691)

Both languages in one commit: a one-sided change moves the acceptance set,
because Rust rejects a 9-byte-bignum created_at that cbor2 folds to an int and
re-emits as a bignum — a tag §6.2 rule 4 forbids, invisible end to end.

Closes the three rows where both implementations agreed on an answer §4.2
forbids: undefined, a float and a narrow bignum all reached rejection through
the type check, so neither side named well-formedness or rule 4.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Delete `reject_excessive_nesting`

**Files:**
- Modify: `core/tests/python/conformance_lib/codec/well_formed.py` (delete the function)
- Modify: `core/tests/python/conformance_lib/sections/nesting_depth.py` (any check that drives it)

**Interfaces:**
- Consumes: Task 3 having moved the last caller.
- Produces: `conformance_lib` with one traversal and one entry point.

- [ ] **Step 1: Prove it has no callers left**

```bash
grep -rn "reject_excessive_nesting" core/tests/python/ --include=*.py | grep -v __pycache__
```

Expected: only its own `def` in `well_formed.py`, its docstring, and whatever
`sections/nesting_depth.py` drives it with. **If any `codec/` module still
calls it, STOP** — Task 3 is incomplete.

- [ ] **Step 2: Delete the function and its section coverage**

Remove `def reject_excessive_nesting` and its docstring from
`well_formed.py`. Then remove the Section NDL check that exercises it, and
renumber the remaining checks and their `PASS` lines.

- [ ] **Step 3: Record WHY in `well_formed.py`'s module docstring**

A deletion with no note reads as an oversight to the next author. Add:

```python
# `reject_excessive_nesting` was deleted in #641.  It was a CONTENT-BLIND
# depth pass: it walked item boundaries and reported no UTF-8, simple-value or
# rule-4 fault, because none of those moves a boundary.  #666 moved the
# manifest and the trash entry onto `walk_body`; #641 moved its last caller,
# `codec/card.py`, and deleted it rather than leaving it callerless.
#
# The reason is #689's, one level up: that function's own
# `later_phases_scan_in_byte_order` flag was retired because "a documented
# fail-open defended solely by its own test is how the next decoder gets wired
# onto it on the strength of a caller list that no longer holds".  With zero
# callers the whole function is that hazard.  One traversal, one entry point.
```

- [ ] **Step 4: Verify**

```bash
uv run core/tests/python/conformance.py
```

Expected: exit 0. Section NDL's PASS lines report one fewer check; Section REG
still reports the same driver count (no section was added or removed).

- [ ] **Step 5: Commit**

```bash
git add core/tests/python/conformance_lib/codec/well_formed.py \
        core/tests/python/conformance_lib/sections/nesting_depth.py
git commit -m "Delete reject_excessive_nesting, now callerless (#641, #691)

Task 3 moved codec/card.py, its last caller, onto walk_body. Keeping a
content-blind pass alive with no production caller is #689's retired-flag
hazard restated at function scope.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: The 18th token, `RuleToken::UnknownField`

**Files:**
- Modify: `core/src/vault/manifest/token.rs` (variant, `ALL`, `as_str`, `is_phase_dependent`, the `WrongType` doc)
- Modify: `core/tests/data/rule_token_vocabulary.json`
- Modify: `core/src/vault/manifest/token/tests/vocabulary.rs` (the variant count, if written out)

**Interfaces:**
- Consumes: nothing.
- Produces: `RuleToken::UnknownField`, wire spelling `"unknown_field"`. Task 6 maps `CardError::UnknownField` onto it; Task 7 gives the Python class the same spelling.

- [ ] **Step 1: Write the failing test**

In `core/src/vault/manifest/token/tests/vocabulary.rs`, extend the existing
fixture-comparison test's expectations; then add:

```rust
/// The card is the only decoder in the tree that rejects an unrecognised key
/// outright — the manifest, record and block plaintext all carry
/// forward-compat `unknown` bags — so this token has exactly one producer
/// today (#641).
///
/// It is NOT folded onto `WrongType`: `conformance.py`'s card decoder names
/// an unknown key exactly, and the full-corpus measurement found 39 inputs
/// where Rust said "non-string map key" and Python said "unknown field".
/// Collapsing the two would have scored those as agreement.
#[test]
fn unknown_field_is_its_own_token_and_is_not_phase_dependent() {
    assert_eq!(RuleToken::UnknownField.as_str(), "unknown_field");
    assert!(!RuleToken::UnknownField.is_phase_dependent());
    assert!(RuleToken::ALL.contains(&RuleToken::UnknownField));
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test --release --locked -p secretary-core --lib vault::manifest::token
```

Expected: FAIL to COMPILE — `no variant or associated item named UnknownField`.

- [ ] **Step 3: Add the variant, in declaration order beside its neighbours**

In the `RuleToken` enum, after `MissingField`:

```rust
    /// A map key the schema does not define, on a decoder that has no
    /// forward-compat `unknown` bag to put it in (#641).
    ///
    /// Today's sole producer is `CardError::UnknownField`: the §6 contact
    /// card rejects every unrecognised key outright, where the manifest body,
    /// the record and a block's plaintext all retain one. Distinct from
    /// [`Self::WrongType`] because both implementations name the two apart —
    /// a non-text key is a wrong type, a well-typed key that is not in the
    /// schema is this.
    UnknownField,
```

Add the matching `ALL` entry and `as_str` arm (`"unknown_field"`), then add
`UnknownField` to `is_phase_dependent`'s **`false`** arm.

That function is EXHAUSTIVE — both arms enumerate every variant and there is no
wildcard — so forgetting it is a compile error, not a silent default. That is
the property to preserve: do not "simplify" either arm to a `_ =>`, because a
wildcard on the `false` side would let a future phase-dependent token arrive
classified as ordered, which is the fail-open direction (it narrows the
tolerance and manufactures disagreements) and a wildcard on the `true` side is
worse (it widens the tolerance and hides real ones).

- [ ] **Step 4: Widen `WrongType`'s doc for the length half**

`DisplayNameTooLong` maps to `WrongType` (Task 6), and the doc currently reads
"or a byte string's length". Change to:

```rust
    /// A field's CBOR major type, or a byte string's or text string's length,
    /// is not what §4.2 (the manifest body), §6 (a contact card) or §6.3 (a
    /// block's plaintext, or a record alone or inside it) requires —
    /// including a body that is not a map, and a non-text map key.
```

- [ ] **Step 5: Add the vocabulary row**

In `core/tests/data/rule_token_vocabulary.json`, after `"missing_field"`:

```json
    "unknown_field": {"phase_dependent": false},
```

- [ ] **Step 6: Run the tests**

```bash
cargo test --release --locked -p secretary-core --lib vault::manifest::token
cargo test --release --locked -p secretary-core --test rule_token_seeds
uv run core/tests/python/conformance.py
```

Expected: PASS. `vocabulary_fixture_matches_the_enum` compares `ALL`'s length
against the fixture's row count — 18 on both sides. Section RTV reads the same
fixture; if it asserts a row count, update it.

- [ ] **Step 7: Commit**

```bash
git add core/src/vault/manifest/token.rs \
        core/src/vault/manifest/token/tests/vocabulary.rs \
        core/tests/data/rule_token_vocabulary.json
git commit -m "vocabulary: add RuleToken::UnknownField, the 18th token (#641)

The contact card is the only decoder that rejects an unrecognised key outright.
Folding it onto wrong_type would have scored 39 measured corpus divergences as
agreement. Widens WrongType's doc to cover a text string's length, which is
where DisplayNameTooLong maps.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `CardError::rule_token()`

**Files:**
- Create: `core/src/vault/rule_tokens/card.rs`
- Create: `core/src/vault/rule_tokens/tests/card.rs`
- Modify: `core/src/vault/rule_tokens/mod.rs`, `core/src/vault/rule_tokens/tests/mod.rs`

**Interfaces:**
- Consumes: `CardError`'s 13 variants (Task 2), `RuleToken::UnknownField` (Task 5).
- Produces: `CardError::rule_token(&self) -> RuleToken`. Task 9's `rust_decoder` arm and Task 10's `rust_rejection` arm both call it.

- [ ] **Step 1: Write the failing test**

Create `core/src/vault/rule_tokens/tests/card.rs`, modelled exactly on its
`record.rs` sibling — a second, independent declaration of the mapping, so
repointing one arm in `card.rs` reds a row here:

```rust
//! Which token each `CardError` variant carries.

use crate::cbor::{CborErrorKind, CborFault};
use crate::crypto::sig::SigError;
use crate::identity::card::CardError;
use crate::vault::manifest::RuleToken;

/// `CardError`'s variant count. A new variant is a compile error in the
/// exhaustive match below first, and a failure of this count second.
const CARD_ERROR_VARIANTS: usize = 13;

fn fault(kind: CborErrorKind) -> CborFault {
    CborFault { kind, offset: None }
}

fn every_variant_and_its_token() -> Vec<(CardError, RuleToken)> {
    vec![
        (
            CardError::CborEncode(fault(CborErrorKind::Serialization)),
            RuleToken::InternalError,
        ),
        // Every decode kind is `malformed_cbor`, `RecursionLimit` included:
        // §6.2 rule 6, which the walk reports and `conformance_lib` reports
        // under the same token.
        (
            CardError::CborDecode(fault(CborErrorKind::Io)),
            RuleToken::MalformedCbor,
        ),
        (
            CardError::CborDecode(fault(CborErrorKind::Syntax)),
            RuleToken::MalformedCbor,
        ),
        (
            CardError::CborDecode(fault(CborErrorKind::Semantic)),
            RuleToken::MalformedCbor,
        ),
        (
            CardError::CborDecode(fault(CborErrorKind::RecursionLimit)),
            RuleToken::MalformedCbor,
        ),
        (
            CardError::Malformed("expected top-level CBOR map"),
            RuleToken::WrongType,
        ),
        (
            CardError::MissingField { field: "card_version" },
            RuleToken::MissingField,
        ),
        (
            CardError::DuplicateField { field: "created_at" },
            RuleToken::DuplicateMapKey,
        ),
        (CardError::UnknownField { index: 0 }, RuleToken::UnknownField),
        (
            CardError::NonCanonicalCbor,
            RuleToken::NonCanonicalUnclassified,
        ),
        (CardError::InvalidVersion, RuleToken::UnsupportedVersion),
        (CardError::InvalidFieldLength, RuleToken::WrongType),
        // A length bound, so `wrong_type` — the same token a fixed-size field
        // at the wrong length takes. Deliberately NOT a 19th vocabulary
        // variant: one length bound draws no distinction that carries
        // evidence (design §3.5).
        (CardError::DisplayNameTooLong, RuleToken::WrongType),
        (
            CardError::FloatRejected { field: "<root>" },
            RuleToken::Rule4TagOrFloat,
        ),
        (CardError::TagRejected, RuleToken::Rule4TagOrFloat),
        // Unreachable from the `contact_card` replay target — it calls
        // `from_canonical_cbor`, which does not verify — so this is a
        // diagnostic mapping, exactly as `BlockError`'s AEAD and signature
        // arms are.
        (
            CardError::SigVerifyFailed(SigError::Ed25519VerifyFailed),
            RuleToken::SignatureInvalid,
        ),
    ]
}

#[test]
fn every_card_error_variant_carries_its_declared_token() {
    let rows = every_variant_and_its_token();
    for (err, want) in &rows {
        assert_eq!(err.rule_token(), *want, "variant {err:?}");
    }

    // Exhaustive: a fourteenth variant is a COMPILE error here.
    for (err, _) in &rows {
        match err {
            CardError::CborEncode(_)
            | CardError::CborDecode(_)
            | CardError::Malformed(_)
            | CardError::MissingField { .. }
            | CardError::DuplicateField { .. }
            | CardError::UnknownField { .. }
            | CardError::NonCanonicalCbor
            | CardError::InvalidVersion
            | CardError::InvalidFieldLength
            | CardError::DisplayNameTooLong
            | CardError::FloatRejected { .. }
            | CardError::TagRejected
            | CardError::SigVerifyFailed(_) => (),
        }
    }

    let distinct: std::collections::HashSet<_> = rows
        .iter()
        .map(|(e, _)| std::mem::discriminant(e))
        .collect();
    assert_eq!(
        distinct.len(),
        CARD_ERROR_VARIANTS,
        "the table covers {} of the {CARD_ERROR_VARIANTS} CardError variants",
        distinct.len()
    );
}
```

Register it: add `mod card;` to `core/src/vault/rule_tokens/tests/mod.rs`.

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test --release --locked -p secretary-core --lib vault::rule_tokens
```

Expected: FAIL to COMPILE — `no method named rule_token found for enum CardError`.

Confirm `SigError::Ed25519VerifyFailed` is the real variant name before
running; if it differs, use the actual one rather than adding a variant.

- [ ] **Step 3: Write the implementation**

Create `core/src/vault/rule_tokens/card.rs`:

```rust
//! [`CardError::rule_token`] (#641). The mapping is §3 of the design doc
//! `docs/superpowers/specs/2026-09-22-token-compare-contact-card-design.md`.

use crate::identity::card::CardError;
use crate::vault::manifest::RuleToken;

impl CardError {
    /// Which rule this rejection is reporting, as a language-neutral token
    /// shared with `conformance.py` (#634, #641).
    ///
    /// **Exhaustive by construction.** Adding a `CardError` variant without
    /// classifying it is a compile error; a wildcard arm would let a new
    /// variant fall silently into a neighbour's token and present a
    /// divergence as agreement.
    ///
    /// **Coarse on purpose.** [`CardError::DisplayNameTooLong`] and
    /// [`CardError::InvalidFieldLength`] share [`RuleToken::WrongType`]:
    /// both are length bounds, and a token may only draw distinctions that
    /// carry evidence. [`CardError::Malformed`] carries a closed set of
    /// `&'static str` literals covering a non-map body and a non-text key,
    /// which `RuleToken::WrongType`'s own doc names.
    ///
    /// **Two arms are diagnostics, not coverage.** The `contact_card` replay
    /// target calls `from_canonical_cbor`, which neither verifies signatures
    /// nor encodes, so `SigVerifyFailed` and `CborEncode` are unreachable
    /// from it — classified for completeness, as `BlockError`'s AEAD and
    /// signature arms are.
    ///
    /// **Advisory, never a verdict.** Nothing in the crate consults it to
    /// decide acceptance.
    pub fn rule_token(&self) -> RuleToken {
        match self {
            CardError::CborDecode(_) => RuleToken::MalformedCbor,
            CardError::Malformed(_)
            | CardError::InvalidFieldLength
            | CardError::DisplayNameTooLong => RuleToken::WrongType,
            CardError::MissingField { .. } => RuleToken::MissingField,
            CardError::DuplicateField { .. } => RuleToken::DuplicateMapKey,
            CardError::UnknownField { .. } => RuleToken::UnknownField,
            CardError::NonCanonicalCbor => RuleToken::NonCanonicalUnclassified,
            CardError::InvalidVersion => RuleToken::UnsupportedVersion,
            CardError::FloatRejected { .. } | CardError::TagRejected => {
                RuleToken::Rule4TagOrFloat
            }
            CardError::SigVerifyFailed(_) => RuleToken::SignatureInvalid,
            CardError::CborEncode(_) => RuleToken::InternalError,
        }
    }
}
```

Add `mod card;` to `core/src/vault/rule_tokens/mod.rs` and extend that file's
module doc to name `CardError` alongside `RecordError` and `BlockError`,
including the "both are over 3,000 lines" sentence — `card.rs` is 1264, so
the reason given there must be restated accurately rather than inherited.

- [ ] **Step 4: Run the tests**

```bash
cargo test --release --locked -p secretary-core --lib vault::rule_tokens
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-core
```

Expected: PASS, and the doc gate clean (the new doc comment uses intra-doc
links).

- [ ] **Step 5: Commit**

```bash
git add core/src/vault/rule_tokens/
git commit -m "core: exhaustive CardError::rule_token() (#641)

A second, independent declaration of the mapping lives in tests/card.rs, so
repointing one arm reds a row there. DisplayNameTooLong and InvalidFieldLength
share wrong_type deliberately: both are length bounds.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: `codec/card_rules.py` — typed Python rejections

**Files:**
- Create: `core/tests/python/conformance_lib/codec/card_rules.py`
- Modify: `core/tests/python/conformance_lib/sections/rule_token_seeds.py` (`_TOKENED_CLASSES`, `_TOKENED_MODULES`)

**Interfaces:**
- Consumes: the vocabulary spellings from Task 5.
- Produces: `CardWrongType`, `CardIntegerOutOfRange`, `CardDuplicateKey`, `CardMissingField`, `CardUnknownField`, `CardUnsupportedVersion`, `CardNonCanonical`, `CardDisplayNameTooLong`. Task 8 raises all eight.

- [ ] **Step 1: Write the module**

A sibling of `record_rules.py`, holding classes only — no decoder logic — so
`card.py` and this both stay well under 500 lines:

```python
"""Typed §6 contact-card rejections carrying a rule token (#641).

WHY TYPED.  `differential_replay.rs` compares WHICH rule each implementation
names, and a section that keys on message TEXT is satisfied by any rejection
whose wording happens to overlap -- the substring trap #608's review found.
Each class carries a `token` class attribute whose value is a spelling from
`core/tests/data/rule_token_vocabulary.json`, which both languages read.

COARSE ON PURPOSE.  `CardDisplayNameTooLong` carries `wrong_type`, the same
token a fixed-size field at the wrong length takes, because both are length
bounds and `CardError::rule_token` makes the same call.  `CardNonCanonical`
covers §6.2 rules 1, 2 and 3 and trailing bytes alike, because
`CardError::NonCanonicalCbor` is fieldless and cannot tell them apart.

`CardMissingField` subclasses `KeyError` so `str()` renders exactly as the bare
`KeyError` it replaces; every other class is a `ValueError`.  Both bases are in
`conformance_lib.rejection`'s verdict allowlist.
"""

from __future__ import annotations


class CardWrongType(ValueError):
    """A key or value has the wrong CBOR type, or a fixed-size field the wrong
    length, or the body is not a map."""

    token = "wrong_type"


class CardIntegerOutOfRange(ValueError):
    """An integer that must be a u64 is negative or too wide."""

    token = "integer_out_of_range"


class CardDuplicateKey(ValueError):
    """The card map repeats a key (§6.2 rule 5)."""

    token = "duplicate_map_key"


class CardMissingField(KeyError):
    """A required §6 field is absent."""

    token = "missing_field"


class CardUnknownField(ValueError):
    """A key the §6 schema does not define.

    The card has no forward-compat `unknown` bag, so an unrecognised key is
    rejected outright rather than retained -- the only decoder in this package
    that does so, which is why this token has one producer (#641).
    """

    token = "unknown_field"


class CardUnsupportedVersion(ValueError):
    """`card_version` is an integer that is not 1.

    Split from `CardWrongType` deliberately: a `card_version` of the wrong
    TYPE is a type fault, and folding the two was one of the four measured
    corpus divergences (design §1.1).
    """

    token = "unsupported_version"


class CardNonCanonical(ValueError):
    """The card is not in canonical form: §6.2 rule 1, 2 or 3, or trailing
    bytes."""

    token = "non_canonical_unclassified"


class CardDisplayNameTooLong(ValueError):
    """`display_name` exceeds crypto-design §6's 4096-byte bound."""

    token = "wrong_type"
```

- [ ] **Step 2: Register the classes with Section RTS**

In `sections/rule_token_seeds.py`, import the module and add its eight classes
to `_TOKENED_CLASSES`, and the module to `_TOKENED_MODULES`:

```python
from conformance_lib.codec import card_rules, cbor_faults, record_rules
```

```python
    (card_rules.CardWrongType, "wrong_type"),
    (card_rules.CardIntegerOutOfRange, "integer_out_of_range"),
    (card_rules.CardDuplicateKey, "duplicate_map_key"),
    (card_rules.CardMissingField, "missing_field"),
    (card_rules.CardUnknownField, "unknown_field"),
    (card_rules.CardUnsupportedVersion, "unsupported_version"),
    (card_rules.CardNonCanonical, "non_canonical_unclassified"),
    (card_rules.CardDisplayNameTooLong, "wrong_type"),
```

- [ ] **Step 3: Verify**

```bash
uv run core/tests/python/conformance.py
```

Expected: exit 0. Section RTS's check 1 now iterates eight more classes and
requires each to carry the token written beside it; it fails loudly if any
spelling is not in the vocabulary fixture Task 5 updated.

- [ ] **Step 4: Commit**

```bash
git add core/tests/python/conformance_lib/codec/card_rules.py \
        core/tests/python/conformance_lib/sections/rule_token_seeds.py
git commit -m "conformance: typed contact-card rejections carrying a rule token (#641)

Eight classes mirroring record_rules.py, registered with Section RTS so a
spelling that is not in the shared vocabulary fixture fails loudly.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: `codec/card.py` on Rust's phase order

**Files:**
- Modify: `core/tests/python/conformance_lib/codec/card.py`

**Interfaces:**
- Consumes: Task 7's eight classes; `scanner._scan_map_entries`, `scanner._decode_head`, `scanner.DuplicateMapKey`; `walk_body` (Task 3).
- Produces: a decoder whose report order matches `from_canonical_cbor`'s. Task 9 wires the target on the strength of it.

**The decoder stops iterating a `cbor2` dict.** A dict destroys repeats, so it
cannot see a duplicate key at all; and a duplicate check cannot be a pre-pass,
because Rust interleaves — a wrong-typed key at entry 0 and a repeat at entry 5
is `wrong_type`, and a pre-pass would answer `duplicate_map_key`, a NEW
divergence introduced by the fix. The card adopts `codec/manifest_decode.py`'s
existing entry-span shape verbatim.

- [ ] **Step 1: Write the failing check as a throwaway probe**

The gate for this task is the full-corpus join, which is expensive; write a
small probe first so the loop is fast. To `$SCRATCH/phase.py`:

```python
# /// script
# requires-python = ">=3.11"
# dependencies = ["cbor2"]
# ///
"""Five planted bodies, one per measured divergence class (design §1.1, §1.2)."""
import pathlib, sys
import cbor2
sys.path.insert(0, str(pathlib.Path("core/tests/python").resolve()))
from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.card import py_decode_contact_card

BASE = pathlib.Path("core/fuzz/seeds/contact_card/with_sigs.cbor").read_bytes()
base = py_decode_contact_card(BASE)
ents = [(k, cbor2.dumps(v, canonical=True)) for k, v in base.items()]
U64 = cbor2.dumps(base["created_at"], canonical=True)
TXT = cbor2.dumps("ok", canonical=True)
LONG = "zzzzzzzzzzzzzzzz"  # 16 chars: sorts AFTER every known key (max 12)

def edited(key, raw, extra=(), drop=()):
    rows = [(k, raw if k == key else v) for k, v in ents if k not in drop]
    return encode_canonical_map_raw(rows + list(extra))

CASES = {
    # wrong-typed known key ahead of a late unknown key -> wrong_type, not unknown_field
    "badtype_before_unknown": ("wrong_type", edited("created_at", TXT, [(LONG, U64)])),
    # missing key beside a wrong-typed one -> wrong_type, not missing_field
    "missing_and_badtype":    ("wrong_type", edited("self_sig_pq", TXT, drop={"x25519_pk"})),
    # a non-text map key is a wrong TYPE, not an unknown field
    "non_text_key":           ("wrong_type", b"\xa1\x01" + U64),
    # card_version of the wrong TYPE is not "unsupported version"
    "version_wrong_type":     ("wrong_type", edited("card_version", TXT)),
    # ...but an integer that is not 1 is
    "version_wrong_value":    ("unsupported_version",
                               edited("card_version", cbor2.dumps(2, canonical=True))),
    # the §6 cap
    "display_name_over_cap":  ("wrong_type",
                               edited("display_name", cbor2.dumps("a" * 4097, canonical=True))),
}

def dup_key():
    parts = [cbor2.dumps("created_at", canonical=True) + U64]
    for k, v in sorted(ents, key=lambda kv: (len(kv[0]), kv[0])):
        parts.append(cbor2.dumps(k, canonical=True) + v)
    return b"\xb8\x0b" + b"".join(parts)
CASES["duplicate_known_key"] = ("duplicate_map_key", dup_key())

bad = 0
for name, (want, body) in CASES.items():
    try:
        py_decode_contact_card(body)
        got = "ACCEPT"
    except Exception as e:
        got = getattr(e, "token", f"<untokened {type(e).__name__}>")
    ok = got == want
    bad += not ok
    print(f"{'ok ' if ok else 'FAIL'} {name:<24} want={want:<22} got={got}")
sys.exit(1 if bad else 0)
```

- [ ] **Step 2: Run it to verify it fails**

```bash
uv run "$SCRATCH/phase.py"
```

Expected: exit 1, with `badtype_before_unknown`, `missing_and_badtype`,
`non_text_key` and `version_wrong_type` reporting `<untokened ValueError>`,
`display_name_over_cap` reporting `ACCEPT`, and `duplicate_known_key`
reporting `<untokened ValueError>`.

- [ ] **Step 3: Rewrite `py_decode_contact_card`'s body**

Keep the function's name, signature and docstring contract. Replace
everything between `walk_body(data)` and the re-encode comparison with the
entry-span loop. The shape, with the reason for each phase:

```python
    # WHY SPANS AND NOT A `cbor2` DICT (#641).  A dict destroys repeats, so it
    # cannot see a duplicate key at all; `card.rs::set_once` reports one.  And
    # the duplicate check cannot be a PRE-PASS: `from_canonical_cbor`
    # interleaves, so a wrong-typed key at entry 0 and a repeat at entry 5 is a
    # type fault, and a pre-pass would answer "duplicate" -- a NEW divergence
    # introduced by the fix.  Same shape `codec/manifest_decode.py` uses.
    entries, end = _scan_map_entries(data, 0)
    if end != len(data):
        raise CardNonCanonical(f"trailing bytes after contact_card map: {len(data) - end}")

    decoded: dict[str, Any] = {}
    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        # A non-text key is a wrong TYPE, tested BEFORE the unknown-key test.
        # `card.rs` matches `Value::Text` first; the full-corpus measurement
        # found 39 inputs where this decoder called such a key an unknown
        # field (design §1.1).
        if kmaj != 3:
            raise CardWrongType(f"contact_card map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in decoded:
            raise CardDuplicateKey(f"contact_card repeats key {key!r}")
        if key not in KNOWN_CARD_KEYS:
            raise CardUnknownField(f"contact_card unknown field: {key!r}")
        value = cbor2.loads(data[vs:ve])
        # The value is checked the MOMENT its key is read, in wire order, and
        # a missing key is reported only after the loop -- `parse_card_map`'s
        # order.  Checking presence first made a body carrying both faults
        # name a different rule in each language.
        check_card_value(key, value)
        decoded[key] = value

    absent = first_missing_key_in_sorted_order(decoded, REQUIRED_CARD_FIELDS)
    if absent is not None:
        raise CardMissingField(f"contact_card missing required field: {absent!r}")
```

The names this loop uses come from:

```python
from conformance_lib.codec.card_rules import (
    CardDisplayNameTooLong, CardDuplicateKey, CardIntegerOutOfRange,
    CardMissingField, CardNonCanonical, CardUnknownField, CardUnsupportedVersion,
    CardWrongType,
)
from conformance_lib.codec.scanner import _decode_head, _scan_map_entries
```

`KNOWN_CARD_KEYS` and `REQUIRED_CARD_FIELDS` are function-local today; **hoist
both to module level** so `check_card_value` and the loop share one
declaration rather than two.

`check_card_value(key, value)` is a new module-level function: a total
dispatch over the ten §6 keys whose `else` raises `UncheckedKnownKey`, the
shape `record.py`'s `check_record_value` uses (#641's M8):

```python
# crypto-design §6, the source of this figure. Never a bare literal at a call
# site -- the spec states it and `core/src/identity/card.rs` holds the Rust
# constant, so a third spelling is a third thing to keep in step.
MAX_DISPLAY_NAME_BYTES = 4096

# §6 fixed-size fields, in bytes.
_FIXED_BYTE_LENGTHS = {
    "contact_uuid": 16,
    "x25519_pk": 32,
    "ml_kem_768_pk": 1184,
    "ed25519_pk": 32,
    "ml_dsa_65_pk": 1952,
    "self_sig_ed": 64,
    "self_sig_pq": 3309,
}


def check_card_value(key: str, value: Any) -> None:
    """Type- and range-check ONE §6 value, the moment its key is read.

    Total over `KNOWN_CARD_KEYS`: the fall-through raises `UncheckedKnownKey`,
    a bug in this package and never a verdict, so a key added to the schema
    without a check here fails loudly (#641's M8).  A totality check over the
    keys that exist proves nothing about that fall-through, so Section VT's
    check 4b probes it with an UNDECLARED key too.
    """
    if key in _FIXED_BYTE_LENGTHS:
        want = _FIXED_BYTE_LENGTHS[key]
        if not isinstance(value, bytes) or len(value) != want:
            raise CardWrongType(f"{key} must be {want}-byte bstr")
        return
    if key == "card_version":
        # The SPLIT is the point: a wrong TYPE is not an unsupported version.
        # `card.rs` runs `take_u8` before comparing to CARD_VERSION_V1, and
        # folding the two was one of the four measured corpus divergences.
        if not is_integer(value):
            raise CardWrongType(f"card_version must be a uint, got {value!r}")
        if value != 1:
            raise CardUnsupportedVersion(f"card_version must be 1, got {value!r}")
        return
    if key == "display_name":
        if not isinstance(value, str):
            raise CardWrongType("display_name must be tstr")
        if len(value.encode("utf-8")) > MAX_DISPLAY_NAME_BYTES:
            raise CardDisplayNameTooLong(
                f"display_name exceeds crypto-design §6's "
                f"{MAX_DISPLAY_NAME_BYTES}-byte bound"
            )
        return
    if key == "created_at":
        # `is_integer` excludes `bool`, which subclasses `int` (#669 M1).
        if not is_integer(value):
            raise CardWrongType(f"created_at must be uint, got {value!r}")
        # `card.rs` says Malformed("integer outside u64 range") here, which is
        # `integer_out_of_range` and NOT `wrong_type`. Also a split.
        if value < 0:
            raise CardIntegerOutOfRange(f"created_at must be non-negative, got {value!r}")
        return
    raise UncheckedKnownKey(f"no value check for known card key {key!r}")
```

Import `UncheckedKnownKey` from `conformance_lib.codec.record_rules`, where it
already lives, rather than declaring a second one. The arms, restated as the
contract:

- `card_version`: not an integer → `CardWrongType`; integer and `!= 1` →
  `CardUnsupportedVersion`. **The split is the point** — folding the two was
  one of the four measured corpus divergences.
- `contact_uuid` / `x25519_pk` / `ed25519_pk` / `self_sig_ed`: `bytes` of the
  exact length, else `CardWrongType`.
- `ml_kem_768_pk` (1184) / `ml_dsa_65_pk` (1952) / `self_sig_pq` (3309): same.
- `display_name`: not `str` → `CardWrongType`; longer than
  `MAX_DISPLAY_NAME_BYTES` UTF-8 bytes → `CardDisplayNameTooLong`
  (crypto-design §6, Task 1).
- `created_at`: not an integer (via `is_integer`, which excludes `bool`) →
  `CardWrongType`; negative → `CardIntegerOutOfRange`. **Also a split** —
  `card.rs` says `Malformed("integer outside u64 range")` for a negative,
  which is `integer_out_of_range`.

Define `MAX_DISPLAY_NAME_BYTES = 4096` as a module constant with a comment
citing crypto-design §6 as its source, so the figure is not a bare literal.

Change the final re-encode mismatch to raise `CardNonCanonical`.

- [ ] **Step 4: Run the probe**

```bash
uv run "$SCRATCH/phase.py"
```

Expected: exit 0, all seven `ok`.

- [ ] **Step 5: Run the full-corpus join — the real gate**

Rebuild the two verdict tables and join them, per design §9. Write the probes
to `$SCRATCH`; do not commit them.

Expected: `inputs=6398  agree=6398  DISAGREE=0`, with the same single
ACCEPT on each side. **A changed accept count is a STOP condition.**

- [ ] **Step 6: Run the standing gates**

```bash
uv run core/tests/python/conformance.py
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

Expected: both exit 0. Several sections match on card message fragments; if
one fails, the message text moved — restore the wording rather than editing
the section, unless the section is asserting something this task deliberately
changed, in which case say which in the commit.

- [ ] **Step 7: Commit**

```bash
git add core/tests/python/conformance_lib/codec/card.py
git commit -m "conformance: contact-card decoder on from_canonical_cbor's phase order (#641)

Stops iterating a cbor2 dict: a dict destroys repeats, and a duplicate check
cannot be a pre-pass without introducing a new divergence, so the decoder
adopts manifest_decode.py's entry-span loop. Closes all four measured
divergence classes and the display_name acceptance divergence.

Full corpus: 6,398 inputs, 0 disagreements, acceptance unchanged.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Wire `contact_card` into the token comparison

**Files:**
- Modify: `core/tests/differential_replay_helpers/targets.rs`
- Modify: `core/tests/differential_replay_helpers/rust_decoder.rs`

**Interfaces:**
- Consumes: `CardError::rule_token()` (Task 6), the aligned decoders (Tasks 3, 8).
- Produces: `contact_card` in `TOKEN_COMPARED_TARGETS`. Task 10 raises its floor.

- [ ] **Step 1: Move the target between the two lists**

In `targets.rs`:

```rust
pub const TOKEN_COMPARED_TARGETS: &[&str] =
    &["record", "manifest_body", "block_file", "contact_card"];
```

```rust
pub const NOT_TOKEN_COMPARED_TARGETS: &[&str] = &["vault_toml", "bundle_file", "manifest_file"];
```

Update that constant's doc: four targets, and `contact_card` needed a Rust
taxonomy (`CardError::rule_token`, #641), a byte-level walk ahead of
`ciborium` in both languages (#641/#691), and the Python decoder reordered
onto `from_canonical_cbor`'s phase order. Note explicitly that it is NOT in
`PHASE_DEPENDENT_TOLERANCE_TARGETS`: §4.2's two-reader-design licence is the
manifest body's, and nothing gives a §6 card that freedom, so every compared
pair must be strictly equal.

- [ ] **Step 2: Fill the token in the `contact_card` arm**

In `rust_decoder.rs`:

```rust
        "contact_card" => identity::card::ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .map(SecretBytes::new)
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
```

- [ ] **Step 3: Run the replay**

```bash
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

Expected: `ok`. `every_target_is_classified` requires the two lists to
partition `TARGETS` and `PHASE_DEPENDENT_TOLERANCE_TARGETS` to be a subset of
the compared list — both still hold.

- [ ] **Step 4: Prove the gate is not decorative**

**Controller ruling (pre-flight CONFLICT-1).** The obvious control — repointing
`CardError::UnknownField` at `RuleToken::WrongType` — is VACUOUS here. At this
task the committed `contact_card` corpus is four files: two accepting bases,
`pre_sig.cbor` (`missing_field`) and two `valuetype__` seeds (`wrong_type`).
None reaches `unknown_field`, so that mutation passes and proves nothing. Its
seed lands in Task 10, which now carries that control.

Use a mutation these four seeds DO reach. In
`core/src/vault/rule_tokens/card.rs`, temporarily repoint the
`CardError::Malformed(_)` arm at `RuleToken::MalformedCbor`:

```bash
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
```

Expected: REDS on both `valuetype__` seeds — Rust would name `malformed_cbor`
where `conformance.py` names `wrong_type`, and `contact_card` is not in
`PHASE_DEPENDENT_TOLERANCE_TARGETS`, so nothing excuses the pair. Restore the
arm, re-run, confirm green. A target that is compared and catches nothing is
#546 restated.

- [ ] **Step 5: Commit**

```bash
git add core/tests/differential_replay_helpers/
git commit -m "replay: token-compare contact_card (#641)

Strict equality, not the manifest body's phase-dependent tolerance: §4.2's
two-reader-design licence is that section's, and nothing gives a §6 card it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Committed single-fault seeds

**Files:**
- Create: `core/tests/rule_token_seeds_helpers/contact_card.rs`
- Modify: `core/tests/rule_token_seeds_helpers/mod.rs`, `core/tests/rule_token_seeds.rs`
- Modify: `core/tests/python/conformance_lib/sections/rule_token_seeds.py`
- Modify: `core/tests/differential_replay_helpers/targets.rs` (`MIN_CORPUS_INPUTS`)
- Create: `core/fuzz/seeds/contact_card/cardtoken__*.bin`

**Interfaces:**
- Consumes: `SeedCase`, `RustRejection`, `rust_rejection` from `rule_token_seeds_helpers::mod`; `CardError::rule_token()`.
- Produces: committed seeds CI replays, and the raised `MIN_CORPUS_INPUTS` floor.

**The census must be prefix-scoped.** `contact_card/` already holds
`valuetype__card_version.bin` and `valuetype__created_at.bin` from #669's
generator, and `rule_token_seeds.rs`'s "every file containing `__`" rule
would claim them. Exclude them the way `nesting__` is excluded, through one
constant per language.

- [ ] **Step 1: Write the case table**

Create `core/tests/rule_token_seeds_helpers/contact_card.rs` with a
`pub(super) fn cases() -> Vec<SeedCase>` returning one row per shape below,
`target: "contact_card"`, `shape` naming what is planted, and `variant` the
`CardError` `Debug` name. Rows, drawn from the design's measured classes —
every token the card path can produce, plus the five rows a regression would
otherwise reach silently:

| token | shape | variant | plant |
|---|---|---|---|
| `malformed_cbor` | `undefined` | `CborDecode` | `created_at` = `f7` |
| `malformed_cbor` | `two_byte_simple` | `CborDecode` | `created_at` = `f8 15` |
| `malformed_cbor` | `nested_indefinite_chunk` | `CborDecode` | `display_name` = `7f 7f 61 61 ff ff` |
| `malformed_cbor` | `truncated` | `CborDecode` | base minus its last byte |
| `malformed_cbor` | `depth_257` | `CborDecode` | `created_at` = 256×`81` then `00` |
| `rule4_tag_or_float` | `bignum_narrow` | `TagRejected` | `created_at` = `c2 41 01` |
| `rule4_tag_or_float` | `bignum_wide` | `TagRejected` | `created_at` = `c2 49 01×9` |
| `rule4_tag_or_float` | `float` | `FloatRejected` | `created_at` = `f9 00 00` |
| `wrong_type` | `not_a_map` | `Malformed` | `82 00 00` |
| `wrong_type` | `non_text_key` | `Malformed` | one-entry map keyed `01` |
| `wrong_type` | `created_at_text` | `Malformed` | `created_at` = `"ok"` |
| `wrong_type` | `x25519_pk_short` | `InvalidFieldLength` | 31-byte `x25519_pk` |
| `wrong_type` | `display_name_over_cap` | `DisplayNameTooLong` | 4097-byte `display_name` |
| `wrong_type` | `card_version_text` | `Malformed` | `card_version` = `"ok"` |
| `integer_out_of_range` | `created_at_negative` | `Malformed` | `created_at` = `20` |
| `missing_field` | `no_x25519_pk` | `MissingField` | drop `x25519_pk` |
| `duplicate_map_key` | `repeated_created_at` | `DuplicateField` | `created_at` twice |
| `unknown_field` | `extra_key` | `UnknownField` | add a well-typed unknown key |
| `unsupported_version` | `card_version_two` | `InvalidVersion` | `card_version` = `02` |
| `non_canonical_unclassified` | `trailing_bytes` | `NonCanonicalCbor` | base plus `00` |
| `non_canonical_unclassified` | `non_shortest_created_at` | `NonCanonicalCbor` | `created_at` = `18 05` |

**Every plant is a single fault**, per that module's doc: a planted fault may
have a downstream consequence, but both implementations must meet the planted
one first. `display_name_over_cap` and `bignum_wide` are the two acceptance
divergences of design §1.2; `undefined`, `float` and `bignum_narrow` are §1.3's
three agreed-but-non-conformant rows. Those five are the reason this table is
worth committing.

One worked row, so the literal shape is not left to inference:

```rust
pub(super) fn cases() -> Vec<SeedCase> {
    vec![
        SeedCase {
            target: TARGET,
            token: RuleToken::MalformedCbor,
            shape: "undefined",
            variant: "CborDecode",
            plant: |base| with_created_at(base, &[UNDEFINED]),
        },
        // ... one per row of the table above
    ]
}
```

`TARGET` is a `const TARGET: &str = "contact_card";` in this file, so the
string is written once. `shape` must be unique within its `token` — the file
name is derived as `<token>__<shape>.bin` and
`assert_each_target_plants_distinct_bytes` reds a collision.

Build the plants over the committed accepting base `with_sigs.cbor`, splicing
a known field's value — the card has no `unknown` bag, so there is nowhere
else to plant. Put the splice helpers in the same file; do not reach into
`record/surgery.rs`, whose helpers assume a record's schema.

- [ ] **Step 2: Register the target**

In `rule_token_seeds_helpers/mod.rs`: `pub mod contact_card;`, add its rows to
`all_cases()`, and add the `rust_rejection` arm:

```rust
        "contact_card" => secretary_core::identity::card::ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .err()
            .map(|e| RustRejection {
                token: e.rule_token(),
                variant: variant_name(&e),
            }),
```

In `rule_token_seeds.rs`: add `"contact_card"` to `SEEDED_TARGETS`, and add a
`CONTACT_CARD_FOREIGN_PREFIX: &str = "valuetype__"` constant excluded from the
census, with a comment naming #669 as the other generator that owns those two
files.

- [ ] **Step 3: Run the census before generating — it must FAIL**

```bash
cargo test --release --locked -p secretary-core --test rule_token_seeds
```

Expected: FAIL — the table declares rows whose files do not exist.

- [ ] **Step 4: Generate, then verify regeneration is byte-identical**

```bash
cargo test --release --locked -p secretary-core --test rule_token_seeds -- \
  --ignored generate_rule_token_seeds
cargo test --release --locked -p secretary-core --test rule_token_seeds
git status --short core/fuzz/seeds/
cargo test --release --locked -p secretary-core --test rule_token_seeds -- \
  --ignored generate_rule_token_seeds
git status --short core/fuzz/seeds/
```

Expected: PASS after the first generate; the second generate leaves the tree
identical (only the new files, unchanged). The generator asserts every row
BEFORE writing any file, so a wrong table panics with nothing written.

- [ ] **Step 5: Add the Python half**

In `sections/rule_token_seeds.py`, add the `_TARGETS` row — the committed seed
count and the exact set of tokens those seeds name between them:

```python
    "contact_card": (
        21,
        frozenset(
            {
                "malformed_cbor",
                "rule4_tag_or_float",
                "wrong_type",
                "integer_out_of_range",
                "missing_field",
                "duplicate_map_key",
                "unknown_field",
                "unsupported_version",
                "non_canonical_unclassified",
            }
        ),
    ),
```

21 is the row count of Step 1's table; it is the LABELLED count, not the
directory count (Step 6 explains the difference). Add
the same `valuetype__` exclusion through a `_CONTACT_CARD_FOREIGN_PREFIX`
constant, mirroring the Rust side.

- [ ] **Step 6: Raise the replay floor**

The table above has **21** rows and `contact_card/` already holds 4 files, so
the floor is **25**:

```rust
    ("contact_card", 25),
```

Confirm rather than trust — if the table grew or shrank in review, this figure
moved with it:

```bash
ls core/fuzz/seeds/contact_card/ | wc -l    # must equal the floor
```

The same count goes in Section RTS's `_TARGETS` row (Step 5), where it is the
**labelled** seed count and therefore 21, not 25: the two accepting bases and
#669's two `valuetype__` files are excluded from that census.

- [ ] **Step 7: Verify**

```bash
cargo test --release --locked -p secretary-core --test rule_token_seeds
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py
```

Expected: all three exit 0. The replay now reports `contact_card: N of N
input(s) compared, N committed` with every new seed reaching a STRICT
comparison — none of the nine tokens is phase-dependent.

Then run the control Task 9 could not (controller ruling, pre-flight
CONFLICT-1): temporarily repoint `CardError::UnknownField`'s arm in
`core/src/vault/rule_tokens/card.rs` at `RuleToken::WrongType` and re-run the
replay. It must RED on `unknown_field__extra_key.bin`, the seed this task
commits — that input is what makes the 18th token's wiring observable at all.
Restore the arm and confirm green.

- [ ] **Step 8: Commit**

```bash
git add core/tests/rule_token_seeds.rs core/tests/rule_token_seeds_helpers/ \
        core/tests/python/conformance_lib/sections/rule_token_seeds.py \
        core/tests/differential_replay_helpers/targets.rs \
        core/fuzz/seeds/contact_card/
git commit -m "seeds: committed single-fault contact_card seeds (#641)

CI replays committed inputs only, and contact_card held four, two of them
accepting. Covers all nine tokens the card path produces, including the two
acceptance divergences and the three agreed-but-non-conformant rows the design
measured. Census excludes #669's valuetype__ prefix in both languages.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Evidence

**Files:** none committed. Mutation spec to `$SCRATCH` (#516).

**Interfaces:**
- Consumes: every preceding task.
- Produces: the measurements the handoff cites.

- [ ] **Step 1: Re-run the full-corpus join, post-change**

Design §9's recipe. Expected: `inputs=6398  agree=6398  DISAGREE=0`, one
ACCEPT on each side, the same input.

- [ ] **Step 2: Replay the real fuzz corpus through the harness**

```bash
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core --features differential-replay \
  --test differential_replay -- differential_replay_full_corpus
rm core/fuzz/corpus && git status --short
```

Expected: all seven targets, full agreement, `contact_card` at 6,394 runtime
plus its committed seeds. `git status --short` must show no corpus entry.

- [ ] **Step 3: Run the mutation harness**

`--self-test` first, as a literal command:

```bash
uv run scripts/mutate.py --self-test
```

Then write design §8's six rows to `$SCRATCH/card.toml` and run:

```bash
uv run --with cryptography --with pynacl --with "pqcrypto<1" \
  --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/card.toml"
git status --short
```

Every Rust row with a scoped probe must name its scope in the GATE, or the
spec is refused (exit 2). `git status --short` must be empty before and after.

- [ ] **Step 4: Run the whole gate set**

```bash
cargo test --release --locked --workspace
cargo clippy --release --locked --workspace --tests -- -D warnings
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo fmt --all --check
uv run --with pytest python3 -m pytest scripts/mutation_harness -q -k "not C10 and not N4"
bash ffi/scripts/check-lean-binding.sh --self-test
bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test
bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test
bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test
bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test
uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test
uv run scripts/check-test-support-placement.py
```

Each as a LITERAL command, never a zsh loop — `${PIPESTATUS[0]}` is silently
empty in zsh, so a piped sweep measures nothing. Every `--self-test` runs
before its guard.

Expected: every command `rc=0`.

---

### Task 12: Documentation and handoff

**Files:**
- Modify: `CLAUDE.md`, `README.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-09-22-token-compare-contact-card-shipped.md`
- Modify: `NEXT_SESSION.md` (the symlink)

- [ ] **Step 1: Update `CLAUDE.md`**

Three places, each RE-MEASURED rather than quoted:

- The differential-replay section: four token-compared targets, not three;
  `contact_card` compares strictly (not in `PHASE_DEPENDENT_TOLERANCE_TARGETS`);
  the committed corpus count; the `RuleToken` vocabulary at 18.
- The `conformance_lib` paragraph: the file count and the top-five module
  ranking, **re-measured at the merge** per that paragraph's own standing
  instruction, which three consecutive slices have missed.
- A note that `reject_excessive_nesting` is gone and `walk_body` is the one
  entry point.

- [ ] **Step 2: Update `ROADMAP.md` and `README.md`**

`ROADMAP.md`: #641's per-target state — `contact_card` done, `bundle_file` and
`vault_toml` outstanding, `manifest_file` blocked by #640. `README.md` only if
its project-status wording names a figure this slice moved; per the README
style preference, no test-count walls.

- [ ] **Step 3: File what was found and not fixed**

Anything surfaced in review and out of scope gets a GitHub issue before the
session ends — standing authorization, no OK needed.

- [ ] **Step 4: Write the handoff and retarget the symlink**

```bash
ln -snf docs/handoffs/2026-09-22-token-compare-contact-card-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

It must carry: what shipped with SHAs; what is next with acceptance criteria;
open decisions and risks; and the exact resume commands.

- [ ] **Step 5: Commit both together**

```bash
git add CLAUDE.md README.md ROADMAP.md docs/handoffs/ NEXT_SESSION.md
git commit -m "docs: token-compare contact_card handoff (#641, #691)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Re-check `main`, then push and open the PR**

```bash
git fetch origin && git log --oneline main..origin/main
```

If `main` moved, merge it first — per the fixup-time merge discipline, before
any further edit, so the handoff path is 3-way-mergeable at ship time.
