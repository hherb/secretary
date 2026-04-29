# secretary — next session entry point

This file is the entry point for the **next** session, in the same role
the previous `secretary_next_session.md` played until 2026-04-29 (closed
on the merge of PR #5 + PR #6 — the manifest / atomic-I/O / orchestrators
slice + review follow-ups).

It captures: phases now closed (kept for context, with PR refs), the two
remaining items in Sub-project A's build sequence, and a small set of
carry-over dribbles.

When the items below are done, delete this file and create the next one.

Sub-project A's design anchor lives at
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md` —
re-read at the start of any session that touches Sub-project A code.
The "Conflict resolution" section (around line 279) and the
"Verification" section (around line 375, especially Definition-of-Done
item #3) are the load-bearing parts for Phase A.6.

PR-A's approved plan with PR-B / PR-C sketches lives at
`/Users/hherb/.claude/plans/please-read-secretary-next-session-md-an-wondrous-cray.md` —
the Phase A.6 scope below extends its PR-C sketch with everything
PR-A's and PR-B's reviews surfaced.

---

## Phases now closed (kept for context)

### Phase A.1 — Cryptographic primitives ✅ — pre-PR #1

NIST KAT-pinned implementations of the v1 cipher suite:
`crypto::{aead, kdf, hash, sig, kem}`. KATs in
[core/tests/data/*.json](core/tests/data/) loaded by the shared
[core/tests/kat_loader.rs](core/tests/kat_loader.rs).

### Phase A.2 — Identity ✅ — pre-PR #1

[core/src/identity/](core/src/identity/): identity seed, role-keyed
derivation (auth, KEM, recovery), Contact Cards, recipient fingerprints.
Position-specific signature roles (`SigRole::Block`, `SigRole::Manifest`,
…) so a signature for one purpose cannot be replayed in another.

### Phase A.3 — Unlock module ✅ — PR #1, 2026-04-27

[core/src/unlock/](core/src/unlock/): BIP-39 24-word mnemonic
generate/parse, identity bundle (master KEK + recovery KEK dual wrap),
`vault.toml` cleartext metadata, three orchestrators (`create_vault`,
`open_with_password`, `open_with_recovery`). Argon2id v1 floor enforced
as a typed error. BIP-39 recovery KAT in
[core/tests/data/bip39_recovery_kat.json](core/tests/data/bip39_recovery_kat.json)
(4 vectors: all-zero, all-FF, two Trezor canonical 24-word).

### Phase A.4 — Vault block file format ✅ — PR #3 (PR-A), 2026-04-28

[core/src/vault/{record,block}.rs](core/src/vault/):

- `Record` types (login, secure note, API key, SSH key, custom) with
  canonical CBOR encode/decode (RFC 8949 §4.2.1) and a forward-compat
  `UnknownValue` opaque wrapper preserving bit-identical round-trips at
  record + field level.
- Binary block file: header (§6.1, 58 B prefix + vector clock), recipient
  table (§6.2, 1208 B/entry, sorted by fingerprint), AEAD body under
  per-block content key (§6.3), trailing hybrid signature suffix (§8).
- `encrypt_block` / `decrypt_block` orchestrators as free `fn`s.
  Verify-before-decap structurally enforced: a forged file never triggers
  a private-key operation.
- §15 block KAT: [core/tests/data/block_kat.json](core/tests/data/block_kat.json)
  parsed wire-format-only (at the time) by
  [core/tests/python/conformance.py](core/tests/python/conformance.py).
- ML-DSA-65 NIST sigGen KAT (`ml_dsa_65_nist_siggen_kat`,
  [core/tests/sig.rs](core/tests/sig.rs)): 5 ACVP-Server vectors
  asserting NIST signatures come out byte-for-byte through our signer.

### Phase A.5 — Manifest layer + atomic I/O + orchestrators ✅ — PR #5 + PR #6, 2026-04-29

[core/src/vault/{manifest,io,canonical,orchestrators}.rs](core/src/vault/):

- **Manifest** ([manifest.rs](core/src/vault/manifest.rs)):
  AEAD-encrypted under Identity Block Key with AAD = manifest header
  bytes (§4.1), hybrid-signed with `SigRole::Manifest`, per-block
  fingerprint table, vault-level vector clock (`tick_clock` errors on
  `u64::MAX` overflow, does not saturate), `kdf_params`,
  `owner_user_uuid`, trash list. `VectorClockEntry` is re-exported from
  the block layer — same shape, same purpose.
- **Atomic I/O** ([io.rs](core/src/vault/io.rs)): write-temp + fsync +
  rename + parent-dir fsync, per ADR-0003. `tempfile` exact-pinned
  (`=3.27.0`) as a security-critical path dependency.
- **Shared canonical-CBOR helpers** ([canonical.rs](core/src/vault/canonical.rs)):
  `canonical_sort_entries`, `encode_canonical_map`, the float/tag
  walker, extracted before the third copy could land.
- **Orchestrators** ([orchestrators.rs](core/src/vault/orchestrators.rs)):
  `create_vault` (atomic four-file initial layout),
  `open_vault` (verify-then-decrypt with `vault_uuid` and `kdf_params`
  cross-checks per §4.3 step 5+6),
  `save_block` (atomic write ordering per §9),
  `share_block` (author-only re-sign with author-equals-identity
  precondition; share-as-fork TODO markers pinned for the v2 follow-up).
- **§15 closure**: [core/tests/data/golden_vault_001/](core/tests/data/golden_vault_001/)
  deterministic full-vault fixture (vault.toml + manifest.cbor.enc +
  identity.bundle.enc + one block + one Contact Card) verified end-to-end
  by [core/tests/python/conformance.py](core/tests/python/conformance.py)
  (full hybrid-decap + AEAD-decrypt + hybrid-verify, stdlib-only,
  `uv run`-compatible). A regression test pins the silent-accept bug
  found and fixed in the Python ML-DSA-65 verifier during this phase
  (PR #6 commit `1c90852`).

After PR #6: 340+ tests pass (`cargo test --release --workspace`),
clippy clean with `-D warnings`, `#![forbid(unsafe_code)]` crate-wide.

---

## Open Item 1 — Phase A.6 / PR-C: vector-clock CRDT merge primitives

The remaining v1 functional piece of Sub-project A. Closes
Definition-of-Done item #3 in
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md` (CRDT
merge is commutative, associative, and idempotent under random
sequences of edits).

**Scope boundary**: this is the *primitive* layer only. Pure functions,
no I/O, no scheduling. Orchestration of when/where the merge runs (file
watching, cloud-folder integration, conflict-detection scheduling) is
explicitly Sub-project C in the current ROADMAP (the sync-orchestration
layer that sits between FFI and the platform UIs). The design anchor at
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md`
(around line 279) labels orchestration as "Sub-project B" under its
older breakdown, but the ROADMAP has since split FFI off as B and
demoted sync orchestration to its own phase C — same scope, different
label. Push back if Phase A.6 scope drifts toward orchestration under
either label.

Estimated shape: ~10–15 commits, ~1,500 lines, one session.

### Files to create

| Path | Purpose |
|---|---|
| `core/src/vault/conflict.rs` | Pure functions:<br>`pub fn merge_vector_clocks(a: &[VectorClockEntry], b: &[VectorClockEntry]) -> Vec<VectorClockEntry>` — component-wise max over `{device_uuid → counter}`, sorted ascending by `device_uuid` per §6.1.<br>`pub fn clock_relation(a, b) -> ClockRelation { Equal, IncomingDominates, IncomingDominated, Concurrent }`.<br>`pub fn merge_record(local: &Record, remote: &Record) -> MergedRecord { Clean(Record), Conflict(Record /* with `_conflicts` shadow */) }` — field-level LWW with `device_uuid` lex tiebreak when `last_mod_ms` ties; tombstone takes precedence iff its `last_mod_ms` is strictly newer; conflicting "real" edits (different values written by both devices since the last common ancestor) preserved in `_conflicts`.<br>`pub fn merge_block(local: &BlockPlaintext, remote: &BlockPlaintext) -> MergedBlock` — record-level union, then per-record merge. |
| `core/tests/data/conflict_kat.json` | §15 cross-language vector. Golden conflict-resolution inputs (two divergent record sets + their vector clocks + the device IDs of the writers) and the expected merged output. Replayable from `conformance.py`. |
| `core/tests/conflict.rs` | Integration tests: hand-built scenarios for each `ClockRelation` outcome, each tombstone-vs-edit case, each `_conflicts` shadow case. Mirror the structure of [core/tests/vault.rs](core/tests/vault.rs). |

### Files to modify

- `core/src/vault/mod.rs` — `pub mod conflict;` and re-export
  `MergedRecord`, `MergedBlock`, `ClockRelation`,
  `merge_vector_clocks`, `merge_record`, `merge_block`. Add
  `Conflict(#[from] ConflictError)` to `VaultError` if
  `ConflictError` ends up needed (likely not — the merge is total over
  well-formed inputs).
- `core/tests/proptest.rs` — extend with three CRDT properties at
  proptest defaults (~256 cases):
  - **Property I — `merge_commutativity`**: `merge_record(a, b)` and
    `merge_record(b, a)` produce the same `MergedRecord` (modulo
    `_conflicts` ordering, which must itself be canonical so the
    equality holds bit-identically).
  - **Property J — `merge_associativity`**:
    `merge_record(merge_record(a, b).into_record(), c) ==
     merge_record(a, merge_record(b, c).into_record())`.
  - **Property K — `merge_idempotence`**: `merge_record(a, a) == a`.

  Reuse / extend the existing `card_strategy` / `build_identity` helpers
  ([proptest.rs:66, 105](core/tests/proptest.rs)). Add a strategy that
  produces random `Record` plus random `device_uuid` / `last_mod_ms`
  mutations simulating concurrent edits.
- `core/tests/python/conformance.py` — add a `conflict_kat.json` path:
  decode, run a Python translation of `merge_block`, assert the merged
  output bit-identically matches the JSON `expected` field.
  This Python merge is the smallest second-implementation that proves
  the spec describes the merge unambiguously.
- `docs/crypto-design.md` §10–§11 — surface the `_conflicts` shadow
  schema: how a field with concurrent real edits is represented in the
  CBOR record so a UI can present both values for user resolution.
  This may turn out to need a small schema addition (a `_conflicts`
  reserved key) — coordinate with the spec section that documents
  reserved field-name prefixes.

### Reusable bits already shipped

- `VectorClockEntry` ([block.rs](core/src/vault/block.rs), re-exported
  from [manifest.rs](core/src/vault/manifest.rs)) — same shape used by
  both block headers and manifest entries.
- `tick_clock` rejects `u64::MAX` overflow as typed error (PR #5
  commit `1608bd9`) — `merge_vector_clocks` should not need to call
  `tick_clock`; it only takes max of existing counters.
- `Record` + `RecordField` types from
  [record.rs](core/src/vault/record.rs) already include the per-field
  `last_mod_ms` and `device_uuid` needed for LWW. Verify before relying:
  the design anchor talks about field-level metadata; confirm what's
  actually present in the type today before designing the merge against
  it.
- `proptest.rs` strategies (`arr16`, `arr32`, `card_strategy`, etc.)
  give a starting point for `Record` strategies.

### Verification (Phase A.6 done when, and Sub-project A v1-feature-done when)

1. `cargo test --release --workspace` green; new test count target ~370
   (was 345 + 6 ignored after PR #6).
2. `cargo clippy --all-targets --workspace -- -D warnings` clean.
3. Three CRDT proptests pass at default proptest cases. None of the
   three is allowed to be tagged `#[ignore]`.
4. `conflict_kat.json` decoded by `conformance.py` and replayed through
   a Python `merge_block` to assert the same merged output
   cross-language. Exit 0 on PASS, 1 on FAIL, 2 on missing fixture
   (matches the existing `conformance.py` exit-code convention).
5. **Sub-project A v1-feature-done test** (per the design anchor's DoD):
   a new contributor can clone the repo, run
   `cargo test --workspace && uv run core/tests/python/conformance.py`,
   see all green, read `docs/crypto-design.md` + `docs/vault-format.md`
   alone, and write an interoperable client in any language without
   reading any Rust source.

### Known risks / things to watch

- **`_conflicts` shadow schema not yet pinned in the spec.** The design
  anchor describes the *behaviour* (both values preserved until UI
  resolves) but not the *byte representation*. PR-C must either pin it
  in `docs/crypto-design.md` §10–§11 *and* the CBOR record schema, or
  defer the schema decision and ship merge primitives that return a
  Rust enum without serialising `_conflicts` to disk. Pick one
  explicitly; do not paper over it.
- **Field-level `last_mod_ms` / `device_uuid` may not yet exist on
  `Record`.** If they don't, adding them is a record-format change and
  needs to be done on disk-compatibly with `golden_vault_001/`. Verify
  the current `Record` shape before designing the merge.
- **`merge_record` totality.** The merge must be total over all
  well-formed `Record` pairs. Don't introduce error cases for
  "incompatible" records — that would let an attacker who can shape
  records cause a denial of merge. If two records collide irreconcilably,
  `_conflicts` is the answer, not an error.

---

## Open Item 2 — Phase A.7: hardening + external audit prep

After Phase A.6 lands, Sub-project A has one phase left before FFI
bindings begin. This is the gate before any Sub-project B work.

- **Independent cryptographic review** (paid, external). Engage early —
  the design has been frozen since the PR #1 / PR #3 / PR #5 cadence,
  so the spec docs are stable enough to send out. Especially valuable:
  reviewer with FIPS 203 / FIPS 204 implementer experience and
  AAD/signed-range eyes.
- **Fuzz harness for the wire-format decoders** (`cargo fuzz`). Targets:
  `decode_block_file`, `decode_manifest`, `decode_identity_bundle`,
  `decode_record`, `decode_contact_card`. Coverage-guided; corpus
  seeded from the §15 KAT fixtures.
- **Side-channel review**. Constant-time critical paths:
  - All AEAD verify-then-decap flows (already structurally verified
    per PR-A; needs constant-time primitive review).
  - `Fingerprint` comparison and recipient-table lookup.
  - Argon2id comparison sites if any (unlock paths).
- **Memory hygiene audit**. `zeroize` coverage on every secret type;
  `secrecy::Secret` typestate where it's load-bearing; drop ordering
  in `IdentityBundle`, `BlockPlaintext`, `Identity`. Especially the
  paths that hold a secret across an `?` propagation site.
- **Documentation pass**.
  `docs/threat-model.md` updated to reference the as-implemented surface
  (currently written from spec, not from code — small gaps will have
  surfaced).
  `docs/vault-format.md` clarifications surfaced during PR-A / PR-B / PR-C.
  Two known docs tickets carried forward: §6.2 wire-form
  clarification (`wrap_ct (32)` and `wrap_tag (16)` adjacent on wire),
  and §6.1 `sig_pq_len = u16, 3309 (suite v1)` annotation.

End of Sub-project A: Rust core is feature-complete for v1, audited,
and ready to be wrapped by FFI in Sub-project B (which then unblocks
Sub-project C — sync orchestration — and Sub-project D — platform UIs).

---

## Carry-over dribbles

Small open items not big enough to merit their own phase. Bundle into
the next PR they touch.

- **`unknown` BTreeMap forward-compat in proptests.** PR-A's
  record-level proptest A uses `BTreeMap::new()` for the unknown bag,
  with the tradeoff documented inline. Add a strategy generating
  bounded `ciborium::Value` trees if future regressions warrant. Not
  urgent. PR-B added a block-cycle integration test for the
  `BlockPlaintext::unknown` path; the proptest strategy gap is
  field-level only.
- **`share-as-fork` v2 follow-up.** PR #5 / PR #6 pinned two TODO
  markers for share-as-fork at the encrypt/decrypt call sites. This is
  a v2 vault-format change (out of scope for Sub-project A), but
  re-validate the markers when Phase A.6 touches `share_block`-adjacent
  code so they don't drift.
- **`records_to_value` / `take_records` byte round-trip.** Defer until
  profiling shows it on a hot path; the manifest workload is the
  earliest realistic profiling target and Phase A.6 doesn't add new
  hot paths.
- **`§6.2 wrap_ct + wrap_tag` and `§6.1 sig_pq_len` annotations** —
  bundled into Phase A.7's documentation pass above; flag here so they
  don't slip if Phase A.7 gets reorganised.

---

## What previous sessions delivered

### PR #5, `feature/vault-manifest` — 2026-04-28 → 2026-04-29

Phase A.5 in one PR. ~30 commits, the full manifest + atomic I/O +
orchestrators + golden-vault scope:

- **`feat(vault)` commits** (`5719277`, `5af1906`, `1e0ff58`, `13ace27`):
  the four orchestrators — `create_vault` (atomic four-file initial
  layout), `save_block` (atomic write ordering per §9), `open_vault`
  (verify-then-decrypt with rollback check), `share_block` (author-only
  re-sign with send-only-mode test).
- **`fix(vault)` commits** (`58cf8de`, `83d2ab9`, `785560e`, `1608bd9`):
  `open_vault` enforces §4.3 step 5 (`vault_uuid` cross-check) and
  step 6 (`kdf_params` cross-check); `share_block` enforces
  author == open.identity precondition; `tick_clock` errors on
  `u64::MAX` overflow instead of saturating.
- **`refactor(vault)` commits** (`70660c5`, `7e0178d`, `d771fc4`):
  `BTreeMap<String, ()>` → `BTreeSet<String>` for `seen_keys`;
  `signed_message_bytes` takes loose fields and drops the sign
  placeholder; `FINGERPRINT_LEN` renamed to disambiguate, `kdf_params`
  check simplified.
- **`test(vault)` commits** (`a66cc5a`, `b7d598b`, `464d6dc`,
  `81935b1`, `815c329`, `b043e9f`, `ccdc11c`, `6e3a64b`, `2b733a4`):
  `golden_vault_001/` deterministic fixture and pin; full
  hybrid-decap + AEAD-decrypt + hybrid-verify in `conformance.py`;
  proptest properties F/G/H for manifest; dedicated negatives for
  `VaultError` and `ManifestError` variants reachable from `open_vault`
  and `share_block`; unit-level tampers for `aead_nonce` / `aead_tag`
  inside the signed range; proptest property G closes the
  `author_fingerprint` hole; tightened broad `except` in
  `conformance.py` CBOR decode sites.

After merge: 345 tests pass + 6 ignored.

### PR #6, `chore/pr-b-review-followups` — 2026-04-29

PR-B review follow-ups, all small but worth pinning:

- `8236ae7` — split orchestrators out of `mod.rs` into
  `orchestrators.rs` (file-size hygiene; `mod.rs` stays a re-export
  hub).
- `069c0ce` — exact-pin `tempfile = "=3.27.0"` for the security-critical
  atomic-write path; documented in `Cargo.toml` why exact pinning here.
- `9fda717` + `1c90852` — fix and regression-test for a silent-accept
  bug in the Python `conformance.py` ML-DSA-65 verifier (it accepted
  invalid signatures). The fix was conformance-only (no Rust change),
  but the regression test now ensures any future verifier rewrite
  doesn't silently re-introduce the same hole.
- `121e7c2` + `75390ac` — share-as-fork TODO markers pinned at the
  encrypt and decrypt call sites for v2 follow-up.
- `68cf44e` — tempfile documented as a security-critical path
  dependency.
- `19604b6` — caller-side nonce generation idiom documented in the
  AEAD module (orientation for future contributors; no API change).

After merge: 345 tests pass + 6 ignored, tree state matches the
"Phases now closed" inventory above.
