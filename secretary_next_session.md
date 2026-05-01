# secretary — next session entry point

This file is the entry point for the **next** session, in the same role
the previous `secretary_next_session.md` played until 2026-05-01 (closed
on the merge of PR #8 — the cargo-fuzz harness, NiceGUI monitor, and
cross-language differential-replay protocol — followed by PR #10's
thirteen-chapter cryptography primer and PR #9's vault-conflict polish:
the bidirectional defensive death-clock clamp, tag-canonicalisation on
the LWW-clone path, and the clean-room Python `py_merge_unknown_map`
covering record-level `unknown` cross-language).

**Sub-project A is feature-complete for v1**; Phase A.7 (hardening +
external audit) is in progress. The most concrete near-term work is
fuzz-finding triage — see [Open Item 1](#open-item-1--fuzz-finding-triage-from-pr-8)
below — followed by a small set of polishing dribbles
([Open Item 2](#open-item-2--polishing-dribbles-from-pr-9-review)) and
the standing Phase A.7 hardening track.

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

### Phase A.6 — Vector-clock CRDT merge primitives ✅ — PR #7 (PR-C), 2026-04-29

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
- **CRDT proptests** in [core/tests/proptest.rs](core/tests/proptest.rs)'s
  `mod vault` PR-C section: `crdt_merge_record_commutativity`,
  `_associativity`, `_idempotence` at proptest defaults (~256 cases).
  All three pass on the **full record domain** — arbitrary
  `tombstone`, arbitrary `tombstoned_at_ms`, arbitrary fields
  predating or surviving any tombstone.
- **§15 cross-language KAT**:
  [core/tests/data/conflict_kat.json](core/tests/data/conflict_kat.json) —
  initially nine vectors covering each `ClockRelation` branch, the
  death-clock staleness filter, the §11.3 identity-metadata override,
  both-tombstoned merges, and resurrection-preserves-death-clock.
  Replayed by both Rust ([core/tests/conflict.rs](core/tests/conflict.rs)
  `kat_replays_match_rust_merge`) and a clean-room Python
  `py_merge_record` written from §11 spec docs only
  ([core/tests/python/conformance.py](core/tests/python/conformance.py)
  Section 4).

After PR #7: 399+ tests pass; clippy clean; `#![forbid(unsafe_code)]`
crate-wide.

### Fuzz harness + NiceGUI monitor + differential-replay protocol ✅ — PR #8, 2026-05-01

[core/fuzz/](core/fuzz/) — coverage-guided `cargo-fuzz` harness on a
path-scoped nightly toolchain. The first concrete output of Phase A.7.

- **Six fuzz targets** ([core/fuzz/fuzz_targets/](core/fuzz/fuzz_targets/)):
  `block_file`, `bundle_file`, `contact_card`, `manifest_file`,
  `record`, `vault_toml`. Each runs the production decoder and asserts
  `Result` rather than panic. Seeded from the §15 KAT fixtures and
  hand-built golden inputs in [core/fuzz/seeds/](core/fuzz/seeds/).
- **NiceGUI monitor** ([core/fuzz/monitor.py](core/fuzz/monitor.py)):
  single-file dashboard (PEP 723 inline deps, `uv run`-compatible) —
  spawns `cargo +<nightly> fuzz run` per target, parses libFuzzer pulse
  lines, detects exec/coverage plateaus and SIGTERMs the run, surfaces
  fresh `crash-*` artifacts. Both-sequential sanitiser mode (ASan, then
  chain UBSan if the ASan run terminated cleanly). Persists last-used
  runs cap per target. Written as pure functions where possible (parse,
  plateau check, env build, runs-cap parse) with the subprocess and UI
  side held at the edges.
- **Differential-replay protocol**: cross-language decoder agreement
  contract documented at
  [docs/manual/contributors/differential-replay-protocol.md](docs/manual/contributors/differential-replay-protocol.md).
  Implemented by
  [core/tests/python/conformance.py](core/tests/python/conformance.py)'s
  `--diff-replay <target> <input-path>` mode (decode + canonical
  re-encode in Python; compare bytes against the Rust side) and the
  Rust harness in
  [core/tests/differential_replay.rs](core/tests/differential_replay.rs).
  Per-input timeout bounds the Python subprocess so a single
  pathological input cannot stall a campaign.
- **Findings carried over** (under triage, see [Open Item 1](#open-item-1--fuzz-finding-triage-from-pr-8)):
  two OOMs (in `contact_card`, `record`), two slow-units (in
  `vault_toml`).
- **Operator docs**: [core/fuzz/README.md](core/fuzz/README.md) — how
  to run targets, how to promote findings into durable regression
  KATs.

### User and contributor manual ✅ — PR #10, 2026-05-01

[docs/manual/](docs/manual/) — informal companion material to the
normative specs.

- **Cryptography primer** ([docs/manual/primer/cryptography/](docs/manual/primer/cryptography/index.md)):
  thirteen chapters in plain language for curious users — symmetric vs
  asymmetric, hashing, KDFs, AEAD, KEM, signatures, the quantum threat,
  the trust problem, randomness, rollback resistance, limits of
  cryptography, glossary. No prior background assumed; analogies used
  pedagogically with their breakdown points called out.
- **Hardening guide** ([docs/manual/hardening-security.md](docs/manual/hardening-security.md)):
  user-facing operational-security advice for pushing beyond Secretary's
  (already strong) defaults.

Bonus material: not strictly Phase A.7, but valuable contributor
onboarding now that the spec has stabilised.

### Vault-conflict polish: bidirectional clamp + tag canonicalisation + record-level `unknown` cross-language ✅ — PR #9, 2026-05-01

Follow-up polish on the PR #7 / PR-C merge layer surfaced during
review. Same module ([core/src/vault/conflict.rs](core/src/vault/conflict.rs)),
same module ownership; closes the two carry-over dribbles from the
previous next-session file.

- **Bidirectional defensive death-clock clamp** ([conflict.rs](core/src/vault/conflict.rs)):
  PR-C clamped `tombstoned_at_ms` upward to `last_mod_ms` on the local
  side only. PR #9 makes it bidirectional — applied to *both* `local`
  and `remote` before the lattice join — so a malformed peer
  (`tombstone = true, tombstoned_at_ms = 0`) cannot suppress the
  death-clock's advance from either side. Plus integration test
  `bidirectional_clamp_handles_malformed_remote` proving the previously
  asymmetric case.
- **Tag canonicalisation on the LWW-clone path** ([conflict.rs](core/src/vault/conflict.rs)):
  `merge_tags` already canonicalised tag multiplicity on the Concurrent
  branch. PR #9 extends this to the LWW-clone path (`IncomingDominates`
  and `IncomingDominated` outcomes), so the `well-formedness` invariant
  holds *bit-identically* on every output, not just on the Concurrent
  branch. Plus a new
  `well_formedness_property_under_arbitrary_inputs` proptest
  (Property L) that exercises the invariant across the entire merge
  surface.
- **§11.3 record-level `unknown` carve-out** removed: PR-C's spec text
  for the §11.3 identity-metadata override on tombstone-wins outcomes
  carved record-level `unknown` out of the wholesale-from-tombstoner
  rule. PR #9 drops that carve-out for symmetry — `unknown` now
  follows the same wholesale rule as `tags` and `record_type` on
  tombstone-wins outcomes. Spec change in
  [docs/crypto-design.md](docs/crypto-design.md) §11.3; implementation
  follows.
- **Clean-room Python `py_merge_unknown_map`** ([core/tests/python/conformance.py](core/tests/python/conformance.py)):
  records the v1 merge rule for record-level `unknown` (per-key
  lex-larger CBOR bytes; tombstone-wins override per §11.3) in a
  Python clean-room implementation written from §11 spec docs only.
  Includes a Section 5 case-insensitivity self-test guarding against
  raw-string-compare drift on hex-encoded blobs (the bug pattern that
  surfaced during review).
- **§15 KAT extended to eleven vectors**: two new vectors added —
  `concurrent_record_unknown_collision_lex_larger_wins` (tests
  per-key lex resolution) and
  `concurrent_tombstone_wins_preserves_live_unknown` (tests the
  §11.3 wholesale override on `unknown`). Replayed bit-identically
  by both Rust and Python.
- **Python proptest record_strategy unified**: a single
  `record_strategy` now generates populated `unknown` for *every*
  CRDT property (commutativity, associativity, idempotence, plus
  the new well-formedness Property L), closing the
  `BTreeMap::new()` forward-compat gap noted in the previous
  next-session file.
- **Conformance-script refactor**: `py_clamp_death_clock` hoisted to
  module scope (was a closure inside `py_merge_record`) so all eleven
  KAT vectors replay through the same clamp logic.

After PR #9: 425+ tests pass; clippy clean; `#![forbid(unsafe_code)]`
crate-wide. **Sub-project A is feature-complete for v1**; Phase A.7
hardening is the active phase.

---

## Open Item 1 — Fuzz-finding triage (from PR #8) ✅ closed

Closed in PR #11 + PR #12. Step 1 (`.gitignore` gap) was already in
place via per-crate [core/fuzz/.gitignore](core/fuzz/.gitignore);
the original ticket missed the per-crate file. Step 2 (triage the
four — actually six — findings) discovered that none reproduced
against current main: 25 minutes × 3 targets of fresh campaigns
yielded 25.7M total executions with zero new findings, and direct
replay at 256 MB rss/malloc returned `Err` in 0 ms. Most plausible
cause: libfuzzer's RSS sampler attributing limit-crossing events to
whichever input was running, so accumulated long-campaign state can
falsely flag innocent inputs.

Outcome (PR #11):

- Six artifacts promoted as committed regression tests under
  [core/tests/data/fuzz_regressions/](core/tests/data/fuzz_regressions/)
  — locked into the existing "must not panic" replay loop in
  [core/tests/fuzz_regressions.rs](core/tests/fuzz_regressions.rs).
- A real peer-supplied DoS surface caught while reading the
  contact-card decoder (`display_name` was unbounded variable-length
  CBOR text and the orchestrator at
  [core/src/vault/orchestrators.rs:509](core/src/vault/orchestrators.rs#L509)
  reads contact-card bytes that may originate from a sync peer) was
  capped at 4 KiB on parse with a new `CardError::DisplayNameTooLong`
  variant.

PR #12 then surfaces live telemetry in the NiceGUI monitor (the gap
that surfaced when running PR #8's scaffold against the real
campaigns above).

---

## Open Item 2 — Polishing dribbles (from PR #9 review)

Captured in [docs/TODO_FINAL_POLISHING.md](docs/TODO_FINAL_POLISHING.md).
None are regressions or correctness issues — deferred polish to be
picked up when adjacent code is next touched:

1. Replace `# type: ignore[arg-type]` in `py_merge_unknown_map` with an
   explicit `assert r_hex is not None`
   ([conformance.py:955](core/tests/python/conformance.py#L955)).
2. Lift the cross-language hex compare pattern into a
   `hex_lex_compare` / `hex_canonicalise` helper *if* a second
   hex-bearing KAT field appears.
3. Extract a `_record_pass_fail()` helper *if* a Section 6 with five+
   sub-tests lands.
4. Confirm at least one `conflict_kat.json` vector exercises
   block-level `unknown_hex` (not just record-level); add one if
   none does.

When the file becomes empty, **delete it** in the same commit.

---

## Open Item 3 — Phase A.7 standing track

The hardening + external-audit gate before Sub-project B (FFI) work
can begin. Items 1 and 2 above are subsets; this is the rest:

- **Independent cryptographic review** (paid, external). Engage early
  — the design has been frozen since the PR #1 / PR #3 / PR #5
  cadence and PR #7 / PR #9 polishing has stabilised the merge layer,
  so the spec docs are stable enough to send out. Especially valuable:
  reviewer with FIPS 203 / FIPS 204 implementer experience and
  AAD/signed-range eyes.
- **Side-channel review**. Constant-time critical paths:
  - All AEAD verify-then-decap flows (already structurally verified
    per PR #3; needs constant-time primitive review).
  - `Fingerprint` comparison and recipient-table lookup.
  - Argon2id comparison sites in unlock paths.
- **Memory hygiene audit**. `zeroize` coverage on every secret type;
  `secrecy::Secret` typestate where it's load-bearing; drop ordering
  in `IdentityBundle`, `BlockPlaintext`, `Identity`. Especially the
  paths that hold a secret across an `?` propagation site.
- **Documentation pass**.
  `docs/threat-model.md` updated to reference the as-implemented
  surface (currently written from spec, not from code — small gaps
  will have surfaced during PR #3 / PR #5 / PR #7 / PR #9).
  `docs/vault-format.md` clarifications surfaced during PR #3 / PR #5
  / PR #7 / PR #9. Two known docs tickets carried forward: §6.2
  wire-form clarification (`wrap_ct (32)` and `wrap_tag (16)`
  adjacent on wire), and §6.1 `sig_pq_len = u16, 3309 (suite v1)`
  annotation.

End of Sub-project A: Rust core is feature-complete for v1, audited,
and ready to be wrapped by FFI in Sub-project B (which then unblocks
Sub-project C — sync orchestration — and Sub-project D — platform UIs).

---

## Carry-over dribbles

Small open items not big enough to merit their own phase. Bundle into
the next PR they touch.

- **`share-as-fork` v2 follow-up.** PR #5 / PR #6 pinned two TODO
  markers for share-as-fork at the encrypt/decrypt call sites. This
  is a v2 vault-format change (out of scope for Sub-project A); PR #7
  / PR #9 did not touch them. Re-validate when Sub-project C
  orchestration brings the share path back into focus.
- **`records_to_value` / `take_records` byte round-trip.** Defer until
  profiling shows it on a hot path. PR #7 / PR #9 did not add any new
  hot paths (the merge primitives operate on already-decoded
  `Record`s).
- **`§6.2 wrap_ct + wrap_tag` and `§6.1 sig_pq_len` annotations** —
  bundled into Open Item 3's documentation pass above; flagged here so
  they don't slip if A.7 gets reorganised.

(Two earlier dribbles — record-level `unknown` in proptests, and
Python `py_merge_record` modelling record-level `unknown` — were
both closed by PR #9.)

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
- **`test(vault)` commits**: `golden_vault_001/` deterministic fixture
  and pin; full hybrid-decap + AEAD-decrypt + hybrid-verify in
  `conformance.py`; proptest properties F/G/H for manifest; dedicated
  negatives for `VaultError` and `ManifestError` variants reachable
  from `open_vault` and `share_block`; unit-level tampers for
  `aead_nonce` / `aead_tag` inside the signed range; proptest
  property G closes the `author_fingerprint` hole; tightened broad
  `except` in `conformance.py` CBOR decode sites.

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
  AEAD module.

After merge: 345 tests pass + 6 ignored.

### PR #7 (PR-C), `feature/vault-conflict` — 2026-04-29

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
  `tombstone=true, tombstoned_at_ms=0` inputs — local side only;
  bidirectional in PR #9).
- **Tests at every layer** (`fbbc307` integration tests, `2348c9d`
  initial CRDT proptests, `f408ba8` 5-vector cross-language KAT,
  `6463259` proptest domain expanded to the full tombstone domain,
  `82a9375` death-clock staleness KAT vector, `94906c1` test data
  §11.5 invariant fixes, `64f975a` 4 additional KAT vectors).

After merge: 399+ tests pass + 6 ignored.

### PR #8, `feature/fuzz-harness` — 2026-04-30 → 2026-05-01

Phase A.7's first concrete output. ~30+ commits along three axes:

- **Fuzz crate scaffold + targets**: cargo-fuzz crate at
  `core/fuzz/`, path-scoped nightly toolchain, six fuzz targets
  (`block_file`, `bundle_file`, `contact_card`, `manifest_file`,
  `record`, `vault_toml`) seeded from §15 KAT fixtures plus
  hand-built golden inputs. Operator README at
  [core/fuzz/README.md](core/fuzz/README.md).
- **NiceGUI monitor**: `a237274` scaffold; `f1da5f3`/`b61bdca`/
  `83aed0a`/`f1058cf`/`8040446`/`ec3c3f9` pure-function building
  blocks (parse pulse, parse targets from Cargo.toml, plateau check,
  nightly toolchain locator, env builder, runs-cap parse);
  `82ec1c4` Status enum + RunState dataclass; `fbef11b` static UI
  scaffold; `3aa137b`/`8a3d149`/`d2a00e3`/`0e86b8e`/`6738b20`
  subprocess management, async stderr reader, plateau-triggered
  SIGTERM, sequential ASan→UBSan chain, crash detection,
  per-target runs-cap persistence; `07fb0a3`/`a23f91f`/
  `f046c68`/`f48451c`/`8f5e624` bug fixes for stdout-pipe drain,
  pulse regex tightness, `default_factory` for `RunState` deques,
  import consolidation, plateau-trigger duplicate-SIGTERM guard.
  Followed by post-merge `9f56b07` page-scoped UI fix on `main`
  (timers were on the auto-index page and outlived client
  disconnects).
- **Differential-replay protocol**: `53bca61` documented the
  cross-language contract at
  [docs/manual/contributors/differential-replay-protocol.md](docs/manual/contributors/differential-replay-protocol.md);
  `--diff-replay` mode added to
  [conformance.py](core/tests/python/conformance.py); Rust harness
  in [core/tests/differential_replay.rs](core/tests/differential_replay.rs)
  with per-input timeout (`6ba1b48`) bounding the Python subprocess.

Findings: 4 (2 OOMs, 2 slow-units) — see
[Open Item 1](#open-item-1--fuzz-finding-triage-from-pr-8).
Also a `.gitignore` gap on the fuzz crate's sub-`target/` and on
`corpus/` / `artifacts/`, captured at `6924404`.

### PR #10, `docs/cryptography-primer` — 2026-05-01

Thirteen-chapter cryptography primer at
[docs/manual/primer/cryptography/](docs/manual/primer/cryptography/index.md)
plus user-facing operational hardening guide at
[docs/manual/hardening-security.md](docs/manual/hardening-security.md).
14 files, +1556 lines, no source changes. Bonus material for
contributor onboarding.

### PR #9, `feature/vault-conflict` (re-used) — 2026-05-01

PR-C polish surfaced during review. Squash-merged into main as
`e8a8d92`; 7 files, +959/-104. Scope along four axes:

- **Spec changes**: drop the §11.3 record-level `unknown` carve-out
  in [docs/crypto-design.md](docs/crypto-design.md), so `unknown`
  follows `tags` / `record_type` in the wholesale-from-tombstoner
  rule.
- **Implementation**: bidirectional defensive clamp on
  `tombstoned_at_ms` in
  [core/src/vault/conflict.rs](core/src/vault/conflict.rs) so a
  malformed peer (`tombstone = true, tombstoned_at_ms = 0`) cannot
  suppress death-clock advance from either side; tag-canonicalisation
  extended to the LWW-clone path.
- **Cross-language closure**: clean-room Python `py_merge_unknown_map`
  in [core/tests/python/conformance.py](core/tests/python/conformance.py)
  for record-level `unknown`; Section 5 case-insensitivity self-test
  guarding raw-string-compare drift on hex blobs; `py_clamp_death_clock`
  hoisted to module scope.
- **Test-domain expansion**: well-formedness proptest Property L on
  arbitrary inputs; `record_strategy` unified with populated
  `unknown` for *every* CRDT property; tenth and eleventh KAT
  vectors in [core/tests/data/conflict_kat.json](core/tests/data/conflict_kat.json)
  (`concurrent_record_unknown_collision_lex_larger_wins`,
  `concurrent_tombstone_wins_preserves_live_unknown`).

Adjacent work on main, not part of the squash:
[docs/TODO_FUZZ_FOLLOWUP.md](docs/TODO_FUZZ_FOLLOWUP.md) at `6924404`
(post-PR-#8 follow-up captured separately); a page-scoped fix to
[core/fuzz/monitor.py](core/fuzz/monitor.py) at `9f56b07` (the
auto-index-page `ui.timer` lifecycle crash that surfaced when running
the monitor against PR #8's harness).
[docs/TODO_FINAL_POLISHING.md](docs/TODO_FINAL_POLISHING.md) ships
inside the PR #9 squash itself.

After merge: 425+ tests pass + 6 ignored. Three pre-existing CRDT
proptests plus the new Property L all pass on the full record domain
(arbitrary tombstone histories, arbitrary `tombstoned_at_ms`,
arbitrary `unknown` keys) at proptest defaults. Eleven-vector
`conflict_kat.json` replayed bit-identically by both Rust and a
clean-room Python `py_merge_record` + `py_merge_unknown_map`.
clippy clean with `-D warnings`; `#![forbid(unsafe_code)]` crate-wide.
**Sub-project A is feature-complete for v1**; Phase A.7 hardening is
the active phase, with fuzz-finding triage as the next concrete unit
of work.
