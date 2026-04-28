# secretary — next session entry point

This file is the entry point for the **next** session, in the same role
[FIXME.md](FIXME.md) played until 2026-04-26 (now closed and removed).
It captures: closed items (kept for context), one open §15 KAT still
blocked on a later module, and the two remaining sub-modules in
Sub-project A's build sequence.

When all the items below are done, delete this file and create the next
one.

Sub-project A's design anchor lives at
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md` —
re-read at the start of any session that touches Sub-project A code.

PR-A's approved plan with PR-B / PR-C sketches lives at
`/Users/hherb/.claude/plans/please-read-secretary-next-session-md-an-wondrous-cray.md` —
the items below extend that plan with everything PR-A's review surfaced.

---

## Item 1 — Finish the §15 KAT contract

Per `docs/crypto-design.md` §15, the §15 list has twelve entries.
Eleven now ship; one remains.

### 1a. ~~`bip39_recovery_kat.json`~~ — DONE 2026-04-27 (PR #1)

Delivered as [core/tests/data/bip39_recovery_kat.json](core/tests/data/bip39_recovery_kat.json)
(4 vectors: all-zero, all-FF, two Trezor canonical 24-word) plus the
`bip39_recovery_kat_vectors` test in [core/tests/unlock.rs](core/tests/unlock.rs),
which pins three relations end-to-end: mnemonic↔entropy, `info_tag` bytes
match `TAG_RECOVERY_KEK`, and entropy→Recovery KEK under HKDF-SHA-256.
Cross-verified against the Trezor `mnemonic` Python package + the
`cryptography` library's HKDF.

### 1b. `golden_vault_001/` — blocked on PR-B's manifest layer

§15 promises a complete v1 vault: `vault.toml`, `manifest.cbor.enc`,
`identity.bundle.enc`, one block, one Contact Card, decryptable from
the spec alone via `core/tests/python/conformance.py`.

PR-A delivered the **block** slice ([core/tests/data/block_kat.json](core/tests/data/block_kat.json)
+ a stdlib-only [core/tests/python/conformance.py](core/tests/python/conformance.py)
that parses the §6.1 wire layout and cross-checks against the JSON
inputs). What still needs to land before §15 is closed:

- `manifest.cbor.enc` envelope and CBOR schema (PR-B Item 5).
- A complete vault folder containing all four file types
  (PR-B Item 5 — `golden_vault_001/`).
- `conformance.py` extension to perform full hybrid-decap +
  AEAD-decrypt + hybrid-verify across both block and manifest
  (currently structural-only at the block level; PR-B Item 5).

---

## ~~Item 2 — Optional: ML-DSA sign-side NIST cross-validation~~ — DONE 2026-04-28 (PR #3)

Closed as `ml_dsa_65_nist_siggen_kat` in [core/tests/sig.rs](core/tests/sig.rs)
(commit `7609b4e`), which feeds NIST's expanded sk (FIPS 204, 4032 bytes)
into our signer and asserts NIST's signature comes out byte-for-byte for
5 ACVP-Server vectors. The deprecated `ExpandedSigningKey::from_expanded`
call is locally `#[allow(deprecated)]` with a 3-bullet rationale +
upgrade path documented inline. Vectors appended to
[core/tests/data/ml_dsa_65_kat.json](core/tests/data/ml_dsa_65_kat.json)
under a new `siggen_vectors` array.

---

## ~~Item 3 — Build-sequence next: `unlock` module~~ — DONE 2026-04-27 (PR #1)

Per `docs/crypto-design.md` §3 + §4 + §5 and `docs/vault-format.md` §2 + §3,
delivered across [core/src/unlock/](core/src/unlock/):

- [mnemonic.rs](core/src/unlock/mnemonic.rs) — BIP-39 24-word generate +
  parse with NFKD normalization, checksum validation, and zeroization on drop.
- [bundle.rs](core/src/unlock/bundle.rs) — `IdentityBundle` plaintext
  type with canonical CBOR encode/decode (RFC 8949 §4.2.1).
- [bundle_file.rs](core/src/unlock/bundle_file.rs) — binary envelope for
  `identity.bundle.enc` (vault-format §3) — encode/decode with strict
  truncation/version/kind/length error variants.
- [vault_toml.rs](core/src/unlock/vault_toml.rs) — `vault.toml` cleartext
  metadata (vault-format §2) — encode/decode with strict v1 KDF param
  enforcement, lowercase-canonical UUID parsing, and typed `MissingField` /
  `FieldOutOfRange` / `TimestampOutOfRange` error variants.
- [mod.rs](core/src/unlock/mod.rs) — `UnlockError` umbrella + the three
  orchestrators: `create_vault`, `open_with_password`, `open_with_recovery`.

Implementation plan and audit trail at
[docs/superpowers/plans/2026-04-27-unlock-module.md](docs/superpowers/plans/2026-04-27-unlock-module.md).

---

## Item 4 — Build-sequence: `vault` module (PARTIAL — block slice DONE in PR-A)

Per `docs/crypto-design.md` §10–§11, the vault module owns:

- ~~Block format: encrypted payload + per-recipient HybridWrap entries~~
  ~~(the ones already produced by `kem::encap`).~~ — **DONE in PR-A**.
- Manifest format: per-block recipient table, vector clocks for CRDT
  merge, atomic writes — **PR-B (Item 5)**.
- On-disk layout: `vault.toml` + `manifest.cbor.enc` +
  `identity.bundle.enc` + per-block files — **PR-B (Item 5)**.
- Conflict resolution: vector-clock-driven merge, since multiple
  devices write through the same cloud-folder transport — **PR-C (Item 6)**.

[core/src/vault/mod.rs](core/src/vault/mod.rs) is no longer a stub:
[`record.rs`](core/src/vault/record.rs) and [`block.rs`](core/src/vault/block.rs)
now hold the §6.3 record CBOR layer and the full §6.1 / §6.2 binary
block file (encode + decode + encrypt_block + decrypt_block, hybrid-signed
with `SigRole::Block`, verify-before-decap discipline pinned by proptest
property E in [core/tests/proptest.rs](core/tests/proptest.rs)).

---

## Item 5 — PR-B: manifest + atomic I/O + orchestrators + golden_vault_001

PR-B is the next piece of Sub-project A and unblocks Item 1b. Estimated
shape: ~25 commits, ~5,000 lines, 2-3 sessions matching PR-A's cadence.

### Files to create

| Path | Purpose |
|---|---|
| `core/src/vault/manifest.rs` | `Manifest` CBOR schema (§4 of vault-format, §10–§11 of crypto-design). AEAD-encrypted under Identity Block Key with AAD = manifest header bytes (§4.1). Hybrid-signed with `SigRole::Manifest`. Per-block fingerprint table, vault-level vector clock, kdf_params, owner_user_uuid, trash list. |
| `core/src/vault/io.rs` | Atomic-write helpers: `write_atomic(path, bytes)` writes to `<path>.tmp.<random>`, fsync, rename. `fsync_dir(parent)` after rename. Used by manifest + block writes. **Pure functions; the only place vault code touches the filesystem.** |
| `core/src/vault/canonical.rs` | Shared canonical-CBOR helpers. **Threshold-crossing extraction**: PR-A's `record.rs` and `block.rs` each carry private copies of `canonical_sort_entries`, `encode_canonical_map`, and `reject_floats_and_tags`. Two copies were defensible; manifest brings a third. Extract a `pub(crate) fn` taking the error type as a generic parameter (or three concrete error types via macro). Reviewer (Task 3 quality review) explicitly flagged this as the trigger point. |
| `core/tests/data/golden_vault_001/` | Full deterministic vault: `vault.toml` + `identity.bundle.enc` + `manifest.cbor.enc` + `blocks/<uuid>.cbor.enc` + `contacts/<uuid>.card`. Fixed seeds, fixed timestamps, regenerable via a `bootstrap_dump`-style ignored test (mirroring PR-A's `block_kat_bootstrap_dump`). |
| `core/tests/python/conformance.py` (extend) | Add full hybrid-decap + AEAD-decrypt + hybrid-verify for both block and manifest. Re-derive identity from a JSON-pinned secret-key set (NOT from a seed — the Rust/Python keygen-from-seed match is too fragile, see PR-A Concern 2). Run via `uv run --with cryptography --with pqcrypto-mlkem --with pqcrypto-mldsa core/tests/python/conformance.py`. Exit 0 on PASS, 1 on FAIL, 2 on missing fixture. |
| `core/tests/vault_e2e.rs` | Rust integration tests mirroring the Python checks plus full create/open/save/share orchestrator round-trips. |

### Files to modify

- `core/src/vault/mod.rs` — orchestrators:
  - `pub fn create_vault(folder, password, mnemonic_seed, identity_seed, owner_card, kdf_params, rng) -> Result<(), VaultError>` produces the four canonical files in an empty directory.
  - `pub fn save_block(folder, identity, manifest, plaintext, vector_clock_tick) -> Result<(), VaultError>` encrypts a new block, atomic-writes, updates manifest fingerprint, atomic-writes the manifest.
  - `pub fn share_block(folder, block_uuid, identity, recipient_card) -> Result<(), VaultError>` adds a recipient wrap and re-writes the block.
  - `pub fn open_vault(folder, unlocker) -> Result<OpenVault, VaultError>` wraps `unlock::open_with_password` / `open_with_recovery`, decrypts manifest, hybrid-verifies, runs rollback check, returns a handle.
- `core/src/vault/block.rs` — switch private CBOR helpers to call into `vault::canonical` (matches the new shared module).
- `core/src/vault/record.rs` — same switch.
- `core/src/identity/card.rs` — add `pub fn pk_bundle_bytes(&self) -> Vec<u8>` (canonical CBOR of the four-pk tuple). Documented in `identity::mod.rs:11` as if it exists; PR-A's smoke tests use ad-hoc concatenation pending this. Adding it lets PR-B's golden_vault_001 use the real bundle bytes everywhere.

### Reusable bits already shipped

- AEAD: `crypto::aead::{encrypt, decrypt}` — manifest body re-uses these with AAD = manifest header bytes.
- Hybrid sig: `crypto::sig::{sign, verify}` with `SigRole::Manifest` — already supported, just call.
- Hybrid KEM: `crypto::kem::{encap, decap}` — manifest doesn't need KEM, but `share_block` does (for adding recipient wraps).
- Identity Block Key + Master KEK derivation: `unlock::{create_vault, open_with_password, open_with_recovery}` — open paths already produce the IBK; manifest decrypts under it.
- `ContactCard` + `Fingerprint`: from PR #1, already canonical.

### Verification (PR-B done when)

1. `cargo test --release --workspace` green; new test count target ~280 (was 230 after PR-A).
2. `cargo clippy --all-targets --workspace -- -D warnings` clean.
3. `uv run core/tests/python/conformance.py` exits 0, parses both block and manifest end-to-end with full crypto verify.
4. `golden_vault_001/` regenerable via `bootstrap_dump`-style ignored test; bytes pinned and stable across machines.
5. `BlockFile` round-trip + manifest round-trip + create_vault → open_vault round-trip all proven by integration tests.
6. `decrypt_manifest` enforces the §10 rollback resistance check (typed `VaultError::Rollback { local_clock, incoming_clock }` variant).

### Spec-doc tickets to fold in

These surfaced during PR-A review and are bundled with PR-B because the
manifest layer is where they materially affect documentation:

- **§6.2 wire-form clarification**: spec presents `wrap_ct (32)` and
  `wrap_tag (16)` as two rows, but they sit adjacent on the wire with no
  separator or length prefix. Add: "wrap_ct and wrap_tag are concatenated
  on disk; the row split is purely presentational."
- **§6.1 sig_pq_len annotation**: spec annotates `sig_ed_len = u16, 64`
  but writes `sig_pq_len = u16` without the value pin. Mirror the Ed25519
  annotation: `sig_pq_len = u16, 3309 (suite v1)`.

Both are documentation-only edits to `docs/vault-format.md`.

### Carry-overs from PR-A reviews

These are tracking notes filed during PR-A; PR-B is the natural place
to act on them:

- ~~Float/tag walker duplication~~ — extracted to `vault/canonical.rs`
  (the threshold-crossing trigger).
- ~~`canonical_sort_entries` / `encode_canonical_map` duplication~~ —
  extracted at the same time.
- `records_to_value` / `take_records` byte round-trip — defer until
  profiling shows it on a hot path; PR-B's manifest workload is the
  first realistic profiling target.

---

## Item 6 — PR-C: vector-clock conflict resolution + CRDT proptests

Closes Sub-project A's CRDT acceptance criterion (point 3 of
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md`
Verification §). Estimated ~10-15 commits, ~1,500 lines, one session.

### Files to create

| Path | Purpose |
|---|---|
| `core/src/vault/conflict.rs` | Pure functions (no state):<br>`pub fn merge_vector_clocks(a, b) -> VectorClock` (component-wise max).<br>`pub fn clock_relation(a, b) -> ClockRelation { Equal, IncomingDominates, IncomingDominated, Concurrent }`.<br>`pub fn merge_record(local, remote) -> MergedRecord { Clean(Record), Conflict(Record /*with _conflicts shadow*/) }` — field-level LWW with `device_uuid` lex tiebreak; tombstone takes precedence if its `last_mod_ms` is strictly newer.<br>`pub fn merge_block(local, remote) -> MergedBlock` — record-level union, then per-record merge. |
| `core/tests/data/conflict_kat.json` | Golden conflict-resolution vectors so the CRDT semantics are pinned cross-language (the §15 vector that future Python/Swift/Kotlin clients must reproduce). |

### Files to modify

- `core/tests/proptest.rs` — extend with three CRDT properties:
  - `merge_commutativity`: `merge(a, b) == merge(b, a)` for arbitrary records with shared / divergent fields.
  - `merge_associativity`: `merge(merge(a, b), c) == merge(a, merge(b, c))`.
  - `merge_idempotence`: `merge(a, a) == a`.

  Use proptest default cases (~256). Strategy: random `Record` from PR-A's
  helper plus random `device_uuid`/`last_mod_ms` mutations that simulate
  concurrent edits.

### Verification (PR-C done when, and Sub-project A done when)

1. `cargo test --release --workspace` green; test count ~310-320.
2. `cargo clippy --all-targets --workspace -- -D warnings` clean.
3. CRDT proptests pass at default proptest cases.
4. `conflict_kat.json` decoded by `conformance.py` and replayed through
   `merge_block` to assert the same merged output cross-language.
5. **Sub-project A definition-of-done** (per the design anchor): a new
   contributor can clone the repo, run
   `cargo test --workspace && uv run core/tests/python/conformance.py`,
   see all green, read `docs/crypto-design.md` + `docs/vault-format.md`
   alone, and write an interoperable client in any language without
   reading any Rust source.

---

## Item 7 — Carry-over notes (small tickets)

Surfaced during PR-A reviews; bundle into PR-B unless noted:

- **`ContactCard::pk_bundle_bytes()` helper** — see Item 5 list above.
  PR-B's natural home; PR-A's smoke tests work around it.
- **`unknown` BTreeMap forward-compat in proptests** — PR-A's record-level
  proptest A uses `BTreeMap::new()` for the unknown bag, with the tradeoff
  documented inline. Add a strategy generating bounded `ciborium::Value`
  trees if future regressions warrant. Not urgent.
- **`bootstrap_inputs` doc-comment correction** — the dumper at
  `core/tests/vault.rs:1342` is hermetic; drift detection comes from the
  assertion test, not the dumper. Wording corrected in PR-A commit
  `84bed1a`. No further action.
- **Cross-cutting cleanup of pre-existing review-fix patterns** — none
  outstanding from PR #1; PR-A's own review-fix commits (`7fa9a7b`,
  `1e85e2b`, `cf42bb5`, `6a19e10`, `84bed1a`, `a5e37ca`, `e971abe`,
  `d1ae5c8`) closed every issue raised during its reviews.

---

## What this session delivered (2026-04-26 → 2026-04-26)

For session-context retention. Five commits on `main`:

1. `1fe9693` — security-review fixes #1–#5, #7–#11, #13 (carried over
   from the previous session, committed at start of this one).
2. `88a1c0b` — proptest file with 6 properties (FIXME #12).
3. `e523f7d` — JSON KAT loader infrastructure (FIXME #6, step 1a).
4. `06c6e1a` — 8 KAT fixtures externalized to JSON (FIXME #6, step 1b).
5. `dcfd1e1` — NIST FIPS 203 / FIPS 204 KAT vectors (FIXME #6, step 1c).

`FIXME.md` is now removed. Test count: 6 proptest properties + 122
unit/integration tests, all passing under `cargo test --release`.

## What the next session delivered (2026-04-27 — PR #1, `feature/unlock-module`)

The unlock module (Item 3) and the BIP-39 recovery KAT (Item 1a),
shipped via subagent-driven TDD against
[docs/superpowers/plans/2026-04-27-unlock-module.md](docs/superpowers/plans/2026-04-27-unlock-module.md).

29 commits on `feature/unlock-module` (PR #1):

- Five from the original Opus run before context compaction
  (`a69c078..c43988a`): `mnemonic.rs` (BIP-39 24-word with checksum +
  zeroize) and `bundle.rs` (IdentityBundle plaintext + canonical CBOR).
- Eighteen from the resumed Opus run (`a1f9add..e79ae2a`): `bundle_file.rs`
  (envelope), `vault_toml.rs` (metadata), `UnlockError`, `create_vault`,
  `open_with_password`, `open_with_recovery`, integration tests, BIP-39
  KAT, proptest, plus a latent-bug fix for `vault_toml::encode` rejecting
  timestamps > i64::MAX as a typed error (caught by proptest).
- One cross-block cleanup (`1a09323`): unlock submodules switched to
  `crate::version::{MAGIC, FORMAT_VERSION, SUITE_ID}` instead of duplicating
  constants; `BundleError::MissingField` typed variant replaced eleven
  CborError(format!("missing field …")) sites.
- Five review-driven fixes (`4ffd388..63cda0f`) addressing every issue the
  PR review surfaced (BIP-39 KAT mixed-byte vectors, `created_at_ms`
  cross-check, Argon2id v1 floor, dead `AeadFailure` variant, `map_bip39_error`
  exhaustiveness comments).

Test count after: 158. All clean under `cargo test --release --workspace`
and `cargo clippy --all-targets --workspace -- -D warnings`.

## What this session delivered (2026-04-28 — PR #3, `feature/vault-block-format`)

PR-A: the block-file slice of the vault module (Item 4 partial), the
§15 block KAT (Item 1b's block half), and Item 2's ML-DSA NIST sigGen
KAT. Shipped via subagent-driven TDD against
[/Users/hherb/.claude/plans/please-read-secretary-next-session-md-an-wondrous-cray.md](/Users/hherb/.claude/plans/please-read-secretary-next-session-md-an-wondrous-cray.md).

22 commits on `feature/vault-block-format` (PR #3):

- **5 feat commits** (`7cf076f`, `e085fa7`, `ae91485`, `9a4d128`, `e4bcdec`):
  record types + canonical CBOR, record CBOR test corpus, block plaintext
  + binary header, block AEAD body + recipient table, block hybrid sign /
  verify wired.
- **5 review-driven fix commits** (`7fa9a7b`, `1e85e2b`, `cf42bb5`,
  `6a19e10`, `a5e37ca`): position-specific error variants restored
  (`RecipientCtWrongLength`, `SigPqWrongLength`); `FloatRejected` doc
  vs code reconciliation; `SIGNATURE_SUFFIX_LEN` derived from
  `ML_DSA_65_SIG_LEN` not hard-coded; `expected.block_file_hex` doc drift.
- **3 refactor commits** (`abfc670`, `182f075`, `0fe15bc`):
  `canonical_sort_entries` propagates errors instead of swallowing;
  `UnknownValue` opaque newtype keeps ciborium out of the public API;
  BTreeMap-vs-canonical-CBOR doc-comment corrected.
- **3 test commits** (`572329c`, `d5d1a20`, `d53ca23`):
  integration tests (round-trip, multi-recipient, every byte field
  flipped), 5 proptest properties (incl. verify-before-decap fuzzing),
  §15 block KAT JSON fixture + Rust pin + Python conformance stub.
- **1 Item 2 commit** (`7609b4e`): ML-DSA-65 NIST sigGen KAT —
  5 NIST ACVP-Server vectors against the deprecated `from_expanded`
  API, locally `#[allow(deprecated)]` with documented upgrade path.
- **5 polish commits** (`48eee89`, `e1cd5ee`, `84bed1a`, `e971abe`,
  `d1ae5c8`): tracking notes from reviews; `forbid(unsafe_code)`
  consistency across integration test files; const-asserts on
  `HEADER_PREFIX_LEN`, `VECTOR_CLOCK_ENTRY_LEN`, `ML_DSA_65_SIG_LEN`.

Test count after: 230 + 1 ignored bootstrap (was 158 + 11 proptest =
169). Breakdown: 81 lib + 33 vault integration + 16 proptest +
16 sig + 16 kem + 17 identity + 8 aead + 11 kdf + 8 secret + 7 hash
+ 16 unlock + 1 ignored bootstrap dump. All clean under
`cargo test --release --workspace` and
`cargo clippy --all-targets --workspace -- -D warnings`. Python
conformance stub (`uv run core/tests/python/conformance.py`) exits 0
on the canonical fixture; verified to exit 1 on flipped magic byte
and on truncation.

### Public API surface added

- `secretary_core::vault::record::{Record, RecordField, RecordFieldValue,
  UnknownValue, RecordError, encode, decode}` — §6.3 record CBOR.
- `secretary_core::vault::block::{BlockHeader, BlockPlaintext, BlockFile,
  RecipientWrap, RecipientPublicKeys, VectorClockEntry, BlockError,
  encode_block_file, decode_block_file, encrypt_block, decrypt_block,
  encode_recipient_table, decode_recipient_table, FILE_KIND_BLOCK,
  RECIPIENT_ENTRY_LEN}` — §6.1 / §6.2 / §8 binary block file.
- `secretary_core::vault::VaultError` — umbrella with
  `Record(#[from] RecordError)` + `Block(#[from] BlockError)`.

### Cross-language conformance scaffold

- `core/tests/data/block_kat.json` — one canonical 5076-byte BlockFile
  with all inputs (RNG seed, identity SKs, vault/block UUIDs, vector
  clock, plaintext records). Drift-pinned by
  `block_kat_self_recipient_one_record` (assertion) and
  `block_kat_bootstrap_dump` (`#[ignore]` regenerator using
  `eprintln!`, NEVER auto-overwrites the JSON).
- `core/tests/python/conformance.py` — UV-runnable, PEP 723, stdlib-only.
  Walks §6.1 byte-by-byte from the spec docs alone, enforces §14
  length constants and the §6.2 sort invariant, cross-checks parsed
  values against JSON inputs. Full crypto verify (decap + AEAD-decrypt
  + hybrid-verify) deferred to PR-B per Item 5.

Branch is awaiting merge of PR #3 to `main`. After merge, Items 1b, 5,
6, and 7 remain open for future sessions.
