# secretary — next session entry point

This file is the entry point for the **next** session, in the same role
the previous `secretary_next_session.md` played until 2026-04-29 (closed
on the merge of PR-C — the CRDT merge primitives, record-level
`tombstoned_at_ms` death-clock, full-domain CRDT proptests, and
nine-vector cross-language KAT). With PR-C, **Sub-project A is feature-
complete for v1**; what remains is the hardening + external-audit phase
(below) before FFI bindings (Sub-project B) can begin.

It captures: phases now closed (kept for context, with PR refs), the
single remaining open item in Sub-project A's build sequence, and a
small set of carry-over dribbles.

When the items below are done, delete this file and create the next one.

Sub-project A's design anchor lives at
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md` —
re-read at the start of any session that touches Sub-project A code.
The "Verification" section (around line 375, especially the §15
cross-language conformance contract) is the load-bearing part for
Phase A.7.

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

### Phase A.6 — Vector-clock CRDT merge primitives ✅ — PR-C, 2026-04-29

[core/src/vault/conflict.rs](core/src/vault/conflict.rs) — pure
functions, no I/O, no scheduling:

- **Vector-clock primitives**: `clock_relation(local, incoming)` →
  `Equal | IncomingDominates | IncomingDominated | Concurrent`
  (anti-symmetric, missing-device-as-zero; the `IncomingDominated`
  variant is the manifest §10 rollback signal).
  `merge_vector_clocks(a, b)` — lattice join (component-wise max,
  sorted ascending by `device_uuid` per §6.1).
- **Per-record merge** with field-level LWW + record-level
  death-clock: `merge_record(local, remote) -> MergedRecord`.
  `device_uuid` lex tiebreak on `last_mod` ties; tombstone-on-tie
  (`T_d ≥ T_l`); `tombstoned_at_ms` propagated via `max`; staleness
  filter drops fields with `last_mod ≤ death_clock`. Concurrent
  value collisions surfaced as `Vec<FieldCollision>` informational
  metadata (no `_conflicts` shadow on disk per §11.4).
- **Per-block merge** dispatching on `clock_relation`:
  `merge_block(local, local_clock, remote, remote_clock,
  merging_device) -> Result<MergedBlock, ConflictError>`. Returns
  the dominant side unchanged for `Equal` /
  `IncomingDominates` / `IncomingDominated`; runs the per-record
  union + per-record merge for `Concurrent` and ticks the merging
  device into the merged clock. `block_uuid` mismatch surfaced as
  a typed error.
- **`tombstoned_at_ms` death-clock** added to `Record` (encoded
  absent-when-zero; backward-compatible with `golden_vault_001`).
  Lattice join via `max`; preserved across resurrection. Drives
  the §11.3 staleness filter that closes the three-way-merge
  associativity gap. Spec at `docs/crypto-design.md` §11.3 +
  `docs/vault-format.md` §6.3.
- **§11.3 identity-metadata override**: on `LocalTombstoneWins` /
  `RemoteTombstoneWins`, the merged record's `tags`,
  `record_type`, and record-level `unknown` come wholesale from
  the tombstoning side — so a UI surfacing a tombstoned record
  reflects the deleter's view, not a concurrent edit they never
  saw.
- **Defensive canonicalisation** in `merge_record`: clamps
  `tombstoned_at_ms` upward to `last_mod_ms` for any input where
  `tombstone == true`, so a malformed peer
  (`tombstone = true, tombstoned_at_ms = 0`) cannot suppress the
  death-clock's advance.
- **CRDT proptests** in [core/tests/proptest.rs](core/tests/proptest.rs)'s
  `mod vault` PR-C section: `crdt_merge_record_commutativity`,
  `_associativity`, `_idempotence` at proptest defaults (~256 cases).
  All three pass on the **full record domain** — arbitrary
  `tombstone`, arbitrary `tombstoned_at_ms`, arbitrary fields
  predating or surviving any tombstone.
- **§15 cross-language KAT**:
  [core/tests/data/conflict_kat.json](core/tests/data/conflict_kat.json) —
  nine vectors covering each `ClockRelation` branch, the death-
  clock staleness filter, the §11.3 identity-metadata override,
  both-tombstoned merges, and resurrection-preserves-death-clock.
  Replayed by both Rust ([core/tests/conflict.rs](core/tests/conflict.rs)
  `kat_replays_match_rust_merge`) and a clean-room Python
  `py_merge_record` written from §11 spec docs only
  ([core/tests/python/conformance.py](core/tests/python/conformance.py)
  Section 4).

After PR-C: 399+ tests pass; clippy clean; `#![forbid(unsafe_code)]`
crate-wide. Sub-project A is feature-complete for v1; Phase A.7
(hardening + external audit) is next.

---

## Open Item 1 — Phase A.7: hardening + external audit prep

With Phase A.6 / PR-C landed, Sub-project A is feature-complete for v1.
Phase A.7 is the gate before any Sub-project B (FFI) work and the
phase that turns "the Rust core implements the v1 design" into "the
Rust core has been independently scrutinised against the v1 design."

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
  with the tradeoff documented inline. PR-C did NOT close this — the
  `crdt_merge_record_*` proptests inherit the same gap (record-level
  unknown is empty in the strategy). Adding a strategy generating
  bounded `ciborium::Value` trees would tighten coverage. Not urgent;
  the integration tests in `core/tests/conflict.rs` exercise non-empty
  record-level `unknown` directly, and the §15 KAT pins the
  tombstone-wins override behavior cross-language.
- **Python `py_merge_record` does not model record-level `unknown`.**
  The Python clean-room merge in `core/tests/python/conformance.py`
  Section 4 currently doesn't carry `unknown` keys through the merged
  record dict (the existing 9 KAT vectors don't exercise it). If a
  future KAT vector adds record-level `unknown`, extend `py_merge_record`
  to handle it (mirror Rust: §11.1 per-key lex-larger CBOR bytes; §11.3
  override on tombstone-wins outcomes).
- **`share-as-fork` v2 follow-up.** PR #5 / PR #6 pinned two TODO
  markers for share-as-fork at the encrypt/decrypt call sites. This is
  a v2 vault-format change (out of scope for Sub-project A); PR-C did
  not touch them. Re-validate when Sub-project C orchestration brings
  the share path back into focus.
- **`records_to_value` / `take_records` byte round-trip.** Defer until
  profiling shows it on a hot path. Phase A.6 did not add any new hot
  paths (the merge primitives operate on already-decoded `Record`s).
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

### PR-C, `feature/vault-conflict` — 2026-04-29

Phase A.6 in one PR, plus the death-clock follow-up after the
review surfaced a three-way-merge associativity gap. ~19 commits
along three axes:

- **Spec first, then code** (`ca74791`, `de91797`, `94afacf`,
  `34a5141`): pinned §11.1–§11.5 metadata rules, tightened tags /
  record_type / unknown tie-breaks for strict commutativity, added
  §11.3 death-clock + staleness filter, extended the §11.3
  identity-metadata override from tags-only to also cover
  `record_type` and record-level `unknown` on tombstone-wins
  outcomes.
- **Implementation in step-by-step slices**:
  `6752701` (vector-clock primitives), `a1e8468` (`merge_record` +
  `MergedRecord` / `FieldCollision`), `7d293fa` (`merge_block`
  dispatching on `clock_relation` + `ConflictError` typed errors
  wired into `VaultError`), `f4f554b` (`tombstoned_at_ms` field on
  `Record` — encode-omit-when-zero, decode-default-zero, all 15
  Record construction sites updated), `2fc7f4e` (death-clock
  staleness filter that closes the three-way associativity gap),
  `65def86` (extended §11.3 override implementation),
  `d058fc9` (defensive clamp against malformed
  `tombstone=true, tombstoned_at_ms=0` inputs).
- **Tests at every layer** (`fbbc307` integration tests via the
  public API, `2348c9d` initial CRDT proptests, `f408ba8` 5-vector
  cross-language KAT + Rust + Python replay, `6463259` proptest
  domain expanded to the full tombstone domain, `82a9375` KAT vector
  for the death-clock staleness filter, `94906c1` test data §11.5
  invariant fixes + collisions × staleness doc, `64f975a` 4
  additional KAT vectors covering IncomingDominated, both-tombstoned,
  identity-metadata override, and resurrection-preserves-death-clock).

Misc: `876e587` untracked `.claude/` user state and
`proptest.proptest-regressions` accidentally swept in by `git add -A`.

After merge: 399+ tests pass + 6 ignored. Three CRDT proptests pass
on the full record domain (arbitrary tombstone histories, arbitrary
`tombstoned_at_ms`) at proptest defaults. Nine-vector
`conflict_kat.json` replayed bit-identically by both Rust and a
clean-room Python `py_merge_record`. clippy clean with `-D warnings`;
`#![forbid(unsafe_code)]` crate-wide. **Sub-project A is feature-
complete for v1**; Phase A.7 (hardening + external audit) is the
next gate.
