# Design — manifest module split + decoder/encoder closeout (#564, #571, #569p2, #573, #572, #577)

**Date:** 2026-08-27 · **Branch:** `feature/manifest-closeout` · **Base:** `main` @ `51b3bf5c`

Successor to `2026-08-24-cbor-residue-closeout-design.md` (#575). That slice
closed the parser's scratch buffer and moved three encoders' `SecretBytes`
wrap into their return types. This one closes the manifest-shaped residue it
deliberately left, and pays down the file-size debt in the module all of it
lands in.

---

## 1. Scope

Six issues, in dependency order:

| Task | Issue | One line |
|---|---|---|
| T1 | #564 | Split `core/src/vault/manifest.rs` (4273 lines) into a directory module |
| T2 | #571 | `bundle::to_canonical_cbor` returns `SecretBytes` |
| T3 | #569 path 2 | `manifest_to_entries` migrates to the borrowing `CanonicalMap` |
| T4 | #573 | Duplicate-key rejection in the four nested manifest parsers |
| T5 | #572 | Re-encode-and-compare canonicality check in `decode_manifest` |
| T6 | #577 | Persist the one format-freezing proptest's counterexamples |

**Out of scope, and filed:** #576 (a guard pinning `from_secret_reader` as the
sanctioned parse entry point), #570 (`ciborium`'s decode-side realloc), #519
(uniffi secret accessors), #563 / #556 (the `block.rs` / `record.rs` splits),
#569 path 3 (`card.rs`).

**No on-disk format change.** `core/tests/data/` and `secretary.udl` must both
diff EMPTY against `main` at the end of the slice.

---

## 2. T1 — split `manifest.rs` (#564)

A pure mechanical move. Behaviour change: none.

`core/src/vault/manifest.rs` → `core/src/vault/manifest/`:

| File | Contents (current line span) | ~prod lines |
|---|---|---|
| `mod.rs` | module doc, `pub use` re-exports, §4.2 key constants, version/len constants (1–126) | ~130 |
| `error.rs` | `ManifestError` (127–373) | ~250 |
| `types.rs` | `KdfParamsRef`, `BlockEntry`, `TrashEntry`, `Manifest` (374–472) | ~100 |
| `encode.rs` | `encode_manifest`, `manifest_to_entries`, the five `*_to_value` fns, `record_error_to_cbor_fault`, `unknown_value_inner` (473–806) | ~330 |
| `decode/mod.rs` | `decode_manifest`, `parse_manifest_map` (807–1071) | ~270 |
| `decode/entries.rs` | `parse_vector_clock`, `parse_vector_clock_entry`, `parse_blocks`, `parse_block_entry`, `parse_recipients`, `parse_trash`, `parse_trash_entry`, `parse_kdf_params` (1072–1414) | ~340 |
| `decode/extract.rs` | the nine `take_*` fns, `value_to_unknown` (1415–1570) | ~155 |
| `header.rs` | `ManifestHeader`, `slice_array`, `encrypt_manifest_body`, `decrypt_manifest_body` (1571–1762) | ~190 |
| `file/mod.rs` | `ManifestFile`, `encode_manifest_file`, `decode_manifest_file` (1763–2109) | ~330 |
| `file/sign.rs` | `signed_message_bytes`, `sign_manifest`, `verify_manifest`, `is_rollback` (2110–2273) | ~180 |

Tests (~2000 lines) move to sibling `tests.rs` files per module, following the
existing `core/src/cbor/secret_tree/tests.rs` precedent. A test moves to the
module holding the function it exercises; a test spanning several modules stays
with its primary subject and says so in a comment.

**Visibility.** Items currently private to one 4273-line file become
`pub(crate)` or `pub(super)` only where a sibling module genuinely needs them.
The narrowest visibility that compiles is the right one; a blanket `pub(crate)`
sweep is a finding, not a shortcut.

### T1 acceptance

- `git diff main... --stat` for this commit touches **only** paths under
  `core/src/vault/manifest*`. Any other file in the diff means the public
  surface moved and the split is not pure.
- Every gate in §7 green.
- No production file over 500 lines. `error.rs` at ~250 and `file/mod.rs` at
  ~330 are the two largest; if a file lands over 500 during the work, split it
  further rather than recording an exception.
- Test count unchanged. `cargo test --release -p secretary-core` reports the
  same number of passing tests as `main`, verified by comparison, not by
  assertion.

---

## 3. T2 — `bundle::to_canonical_cbor` returns `SecretBytes` (#571)

`IdentityBundle::to_canonical_cbor` is the last encoder of the #558 class in
`core` still returning `Vec<u8>`, and its output is the cleartext CBOR of all
four long-term secret keys — the most secret of the four. Its caller at
`core/src/unlock/mod.rs:211` applies a `SecretBytes::new(..)` wrap that is
**deletable with the whole suite green**, because `SecretBytes`'s wipe comes
from a `derive` that ticks no counter.

Change the return type to `SecretBytes`, delete the wrap at the call site, and
convert affected tests from `.as_slice()` to `.expose()`.

### T2 acceptance

- `to_canonical_cbor` returns `Result<SecretBytes, BundleError>`.
- `unlock/mod.rs`'s `bundle_plaintext` is wrapped by construction; no
  `SecretBytes::new` call remains at that site for a future edit to drop.
- The `#571` pointer comment on `to_canonical_cbor` is removed (the issue is
  closed by this task), and the surrounding doc states the new guarantee
  without overclaiming: the wrap is compile-enforced; the AEAD call still
  takes `&[u8]` via `.expose()`.
- Gates green.

---

## 4. T3 — `manifest_to_entries` → `CanonicalMap` (#569 path 2)

### What is wrong today

`manifest_to_entries` builds an owned `Vec<(Value, Value)>`. Every block's
`block_name` — user-authored plaintext, the field `BlockEntry::block_name`'s
own doc flags as such — is copied into a `Value::Text(entry.block_name.clone())`
and dropped **unwiped** on every manifest write. All four production
`sign_manifest` sites reach it. Making `encode_manifest` return `SecretBytes`
(#558/#565) covered the OUTPUT and left an equivalent copy on the input side.

It is strictly worse than the bundle state #569 was filed against, which at
least had `SecretEntries` wiping on drop; here there is no wrapper at all.

### The migration

Mirror `bundle.rs`'s path-1 migration and `record.rs`'s existing encoder:

- `manifest_to_entries` → returns `CanonicalMap<'a>` borrowing from `&'a Manifest`.
- `vector_clock_to_value`, `blocks_to_value`, `block_entry_to_value`,
  `trash_to_value`, `trash_entry_to_value`, `kdf_params_to_value` → return
  `CanonicalValue<'a>`.
- `Value::Bytes(x.to_vec())` → `CanonicalValue::Bytes(&x)`.
- `Value::Text(s.clone())` → `CanonicalValue::Text(s)`.
- `Value::Integer(u64::from(x).into())` → `CanonicalValue::Uint(u64::from(x))`.
- `encode_manifest` → `to_canonical_vec(&CanonicalValue::Map(map))`.
- `canonical_sort_entries` / `encode_canonical_map` calls disappear;
  `CanonicalMap::serialize` imposes RFC 8949 §4.2.1 order at serialise time.

**`unknown_value_inner` is deleted entirely.** `UnknownValue::as_value()` is
already `pub(crate)` and `record.rs`'s encoder already uses
`CanonicalValue::Borrowed(v.as_value())`. The current function encodes an
unknown subtree to CBOR and re-parses it — an allocation, a `SecretBytes`, and
a `from_secret_reader` call **per unknown per manifest write**, all of which
vanish.

### The integer-equivalence obligation

`Value::Integer(x.into())` → `CanonicalValue::Uint(x)` is the one genuinely
risky substitution, and it must be justified the way #575's T4 justified it
rather than by a green test. Every manifest integer field is `u8`, `u16`,
`u32` or `u64`, so the `ciborium` big-num arms are structurally unreachable
and equivalence holds over the whole domain. The implementer states this per
field, citing the field's declared type.

### T3 acceptance

- `golden_vault_001_pinned` green — byte-identity of a real manifest, the same
  backstop the bundle migration used.
- `git diff main... --stat -- core/tests/data/` EMPTY.
- No `Value::` constructor remains in the manifest encode path.
- `unknown_value_inner` no longer exists.
- A test pins the **elimination** property, not just the output bytes:
  reverting to an owned-`Value` body must fail a test. (#575's T4 shipped this
  property pinned by nothing; the review caught it. Do not repeat it.)
- Gates green.

---

## 5. T4 — nested duplicate-key rejection (#573)

`parse_manifest_map` rejects a repeated key at the top level (#568).
`parse_vector_clock_entry`, `parse_block_entry`, `parse_trash_entry` and
`parse_kdf_params` still silently last-win on their own nested maps.

`ManifestError::DuplicateKey { field: &'static str, index: usize }` already
exists and is data-free by construction (#474). No new variant.

**`field` names the specific nested key** — `"device_uuid"` for a repeated
`device_uuid` inside a `vector_clock` entry, not the container `"vector_clock"`.
It is a compile-time `KEY_*` constant either way, so the #474 guarantee holds.
A repeated forward-compat unknown key inside a `BlockEntry` / `TrashEntry` gets
the literal `"<unknown>"`, matching what `parse_manifest_map` does — the
repeated key itself is attacker-influenced text and is never carried.

`parse_vector_clock_entry` and `parse_kdf_params` already **reject** unknown
keys outright, so for those two a duplicate of a known key is the only silent
case. `parse_block_entry` and `parse_trash_entry` carry `unknown` bags, so both
cases apply.

### T4 acceptance

- Each of the four parsers rejects a duplicate of each of its own keys, with
  `field` naming that key.
- The two parsers with `unknown` bags reject a duplicate unknown key with
  `field == "<unknown>"`.
- The repeated key's own text appears in no error payload — asserted, not
  assumed.
- Gates green, including the error-payload hygiene guard.

---

## 6. T5 — canonicality re-check in `decode_manifest` (#572)

`record::decode` (`record.rs:684`) and `block::decode_plaintext`
(`block.rs:1075`) each re-encode the parsed struct and compare against the
input, returning `NonCanonicalEncoding` on mismatch. `decode_manifest` has no
such check. #575's design spec asserted it did; that claim travelled spec →
plan → task brief unchecked and was caught by an implementer reading the code.

Add the check, with the variant spelled `ManifestError::NonCanonicalEncoding`
to match its two siblings.

### The forward-compatibility hazard, checked

A strict re-encode-and-compare rejects any manifest the decoder cannot
reproduce exactly. That would be a forward-compatibility regression if any
accepted manifest were lossily decoded. **It is not**, verified by reading all
four nested parsers:

- `parse_vector_clock_entry` and `parse_kdf_params` **reject** unknown keys
  (`WrongType`), so nothing is silently dropped.
- `Manifest`, `BlockEntry` and `TrashEntry` each carry an
  `unknown: BTreeMap<String, UnknownValue>` bag that round-trips verbatim.

Every manifest the decoder accepts is therefore fully representable, and the
re-encode is byte-identical. If an implementer finds a counterexample, that is
a decoder bug to surface — not a reason to weaken the check.

### Ordering against T4

T4 lands first. Its checks fire during parse, before T5's re-encode, so a
nested duplicate yields the precise `DuplicateKey` rather than the generic
`NonCanonicalEncoding`. **A test pins that ordering** — without one, a later
edit reordering the two would silently coarsen every nested duplicate
diagnostic with the suite green.

### The residual, stated rather than papered over

Neither T4 nor T5 closes a duplicate key **inside a forward-compat `unknown`
subtree**. Those round-trip verbatim, so the re-encode compares equal, and no
decoder in the crate walks inside them — `UnknownValue`'s only validation is
`reject_floats_and_tags`. `ManifestError::DuplicateKey`'s doc already records
this; T5 must restate it at the new check rather than let "manifest duplicate
keys are handled" stand anywhere in the tree.

### T5 acceptance

- A non-canonical manifest body (unsorted keys, non-shortest integer,
  indefinite-length item) is rejected with `NonCanonicalEncoding`.
- `golden_vault_001_pinned` and every existing manifest round-trip test stay
  green — the check must reject nothing that is valid today.
- A forward-compat manifest carrying unknown keys at the top level, in a
  `BlockEntry`, and in a `TrashEntry` decodes successfully, proving the
  hazard above is closed.
- The T4-before-T5 ordering is pinned by a test.
- The `unknown`-subtree residual is stated at the check site.
- `cargo build --release --workspace` confirms the new variant costs nothing
  downstream (the enum is deliberately not `#[non_exhaustive]`).

---

## 7. T6 — persist the key-order proptest's counterexamples (#577)

`.gitignore` carries `**/*.proptest-regressions` and `**/proptest-regressions/`.
`len_then_bytes_matches_full_cbor_encoding_order`
(`core/src/vault/canonical/value.rs`) guards `CanonicalMap::serialize`'s
`(byte length, bytes)` comparator, which must equal RFC 8949 §4.2.1 order —
a **format-freezing** property with the thinnest frozen-anchor coverage in the
crate. Mutating the comparator to `chars().count()` leaves `golden_vault_001`,
`golden_vault_002`, `conformance_kat` and `revoke_kat` all passing, because
every key in those fixtures is ASCII (#562).

Add a negated `.gitignore` rule for that one path so a CI counterexample
becomes a committable, replayable seed. The general "do not commit regressions"
policy is untouched.

### T6 acceptance

- The negated rule is verified by execution — `git check-ignore -v` on the
  actual path proptest writes, not on a path assumed from the module name.
- A comment at the test records why this one property is exempt.
- No other proptest path becomes un-ignored.

---

## 8. Gates

Every task runs the full set before its commit:

```
cargo fmt --all -- --check
cargo build --release --workspace           # separate from the test run ON PURPOSE
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo clippy --release --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
git diff main... --stat -- core/tests/data/                    # must be EMPTY
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl  # must be EMPTY
```

Plus, once per slice — **neither is covered by any CI job**, and both broke
undetected on the #575 branch because the sweep was scoped to `--workspace`:

```
cargo check --features differential-replay --tests -p secretary-core
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
```

`core/fuzz` is `exclude`d from the workspace and `differential_replay.rs` is
feature-gated, so `clippy --tests` builds neither.

## 9. Testing discipline

TDD per task: the test that fails without the mechanism is written first.

**Every new mechanism must be pinned by a test that fails when the mechanism
is removed, verified by mutation.** #575 found five mechanisms in its own new
code that shipped correct but unobservable — including one where an
unconditional wipe made two *pre-existing* assertions vacuous. Assertions of
the shape `assert!(counter > before)` are banned: they pass on any wipe, not
the one under test. Assert exact counts with a comment deriving the number.

For T3 specifically, the property to pin is **elimination** (no owned copy is
constructed), not output bytes — `golden_vault_001_pinned` would stay green
against a reverted body.

## 10. Risks

| Risk | Mitigation |
|---|---|
| T1's split silently changes visibility or public API | Diff must touch only `core/src/vault/manifest*`; narrowest visibility that compiles |
| T3's `Uint` substitution differs from `Value::Integer` for some field | Per-field justification citing the declared type; `golden_vault_001_pinned` byte-identity |
| T5 rejects a valid forward-compat manifest | Explicit acceptance test at three nesting levels; the hazard was checked against all four parsers before the spec was written |
| T4/T5 ordering silently inverts later | Pinned by a test |
| A doc claims "manifest duplicate keys are handled" | The `unknown`-subtree residual is restated at the T5 check site and in the memo |
| T1 conflicts with a parallel session | Worktree-local branch; `pwd && git branch --show-current` before every path-sensitive command |

## 11. Documentation

- `docs/manual/contributors/memory-hygiene-audit-internal.md` — a section for
  T2/T3, with an explicit "what this does not claim".
- `CLAUDE.md` — the manifest module layout, and the `unknown`-subtree residual.
- `ROADMAP.md` — the memory-hygiene bullet.
- `README.md` — **only if** something user-visible changes. Nothing here is
  expected to; unchanged is the correct outcome, not an omission.
