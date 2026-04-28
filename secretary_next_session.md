# secretary — next session entry point

This file is the entry point for the **next** session, in the same role
[FIXME.md](FIXME.md) played until 2026-04-26 (now closed and removed).
It captures the §15 KAT items still outstanding, hardening leftovers, the
remaining build-sequence modules, and the medium-rated review items
surfaced on PR #3 that PR-B should fold in.

When all the items below are done, delete this file and create the next
one.

---

## Item 1 — Finish the §15 KAT contract (blocked on later modules)

Per `docs/crypto-design.md` §15, the §15 list has twelve entries. Eleven
are now in `core/tests/data/*.json` (block_kat shipped in PR #3). One
remains, blocked on the manifest layer:

### 1a. ~~`bip39_recovery_kat.json`~~ — DONE 2026-04-27

Delivered as [core/tests/data/bip39_recovery_kat.json](core/tests/data/bip39_recovery_kat.json)
(4 vectors: all-zero, all-FF, two Trezor canonical 24-word) plus the
`bip39_recovery_kat_vectors` test in [core/tests/unlock.rs](core/tests/unlock.rs).

### 1b. `golden_vault_001/` — blocked on the manifest layer (PR-B scope)

§15 promises a complete v1 vault: `vault.toml`, `manifest.cbor.enc`,
`identity.bundle.enc`, one block, one Contact Card, decryptable from
the spec alone via `core/tests/python/conformance.py`.

PR #3 (PR-A) shipped the block file half — `block_kat.json` is pinned
and Python parses it from spec alone. The manifest half lands in PR-B
together with the high-level orchestrators (`create_vault`, `save_block`,
`share_block`, `open_vault`) and the atomic-write helpers in `io.rs`.

---

## ~~Item 2 — Optional: ML-DSA sign-side NIST cross-validation~~ — DONE 2026-04-28

Delivered in PR #3 as `ml_dsa_65_nist_siggen_kat` in [core/tests/sig.rs](core/tests/sig.rs)
plus 5 NIST ACVP-Server sigGen vectors in [core/tests/data/ml_dsa_65_kat.json](core/tests/data/ml_dsa_65_kat.json).
Approach (a) was taken: locally `#[allow(deprecated)]` on the
`ExpandedSigningKey::from_expanded` call with a documented upgrade path
for when the `ml-dsa` crate exposes a non-deprecated loader.

---

## ~~Item 3 — Build-sequence next: `unlock` module~~ — DONE 2026-04-27

Delivered across [core/src/unlock/](core/src/unlock/). See PR #1 summary
at the bottom of this file for detail.

---

## Item 4 — Build-sequence: `vault` module (PR-A done; PR-B remaining)

### 4a. ~~Block file format~~ — DONE 2026-04-28 (PR #3, PR-A)

Delivered across [core/src/vault/](core/src/vault/):

- [record.rs](core/src/vault/record.rs) — `Record` types, canonical CBOR
  encode/decode (RFC 8949 §4.2.1), `RecordError`, forward-compat
  `UnknownValue` opaque wrapper preserving bit-identical round-trips at
  record + field level per §6.3.2.
- [block.rs](core/src/vault/block.rs) — binary header (§6.1), recipient
  table (§6.2, 1208 B/entry), AEAD body (§6.3) under per-block content
  key, trailing hybrid signature suffix (§8). `encode_block_file` /
  `decode_block_file` / `encrypt_block` / `decrypt_block` orchestrators
  as free `fn`s. Verify-before-decap structurally enforced: a forged
  file never triggers a private-key operation.
- [mod.rs](core/src/vault/mod.rs) — `VaultError` umbrella ready to
  absorb future `Recipients` / `Manifest` variants without breaking
  existing call sites.

§15 cross-language KAT pinned: [core/tests/data/block_kat.json](core/tests/data/block_kat.json)
(one canonical 5076-byte BlockFile) parsed wire-format-only by
[core/tests/python/conformance.py](core/tests/python/conformance.py)
(stdlib-only, `uv run`-compatible).

Test count: 230 + 1 ignored bootstrap (was 158). Discipline preserved:
`#![forbid(unsafe_code)]` crate-wide, position-specific Aead/Kem/Sig
errors with separate typed length variants, compile-time const-asserts
on all five wire-format constants, canonical CBOR re-encode-and-compare
gate on every decode.

### 4b. PR-B — manifest layer + orchestrators + golden vault

Per `docs/crypto-design.md` §10–§11 and `docs/vault-format.md` §4:

- **Manifest format**: `vault.toml` + `manifest.cbor.enc` + dual-wrapped
  identity bundle. CRDT vector-clock merge with commutativity /
  associativity / idempotence proptests (Sub-project A step 8).
- **Atomic writes**: `core/src/vault/io.rs` (write-temp + fsync + rename
  + parent-dir fsync, per ADR-0003).
- **High-level orchestrators**: `create_vault`, `save_block`,
  `share_block`, `open_vault` — gluing unlock + record + block + manifest
  into a single API surface for the FFI layer to wrap.
- **§15 closure**: `core/tests/data/golden_vault_001/` end-to-end fixture
  + full Python conformance crypto (Item 1b). Closes Item 1.

### 4c. PR-B follow-ups from PR #3 review (medium-rated, non-blocking on PR-A merge)

Surfaced by parallel reviewers on PR #3; tracked here so they don't slip:

1. **Python conformance must verify, not just parse.** Today
   [conformance.py](core/tests/python/conformance.py) confirms wire-format
   byte layout but runs no crypto: no Ed25519 / ML-DSA-65 verify, no
   X25519 / ML-KEM-768 decap, no AEAD decrypt. A second-language client
   could parse correctly while computing the signed range wrong, getting
   AAD wrong, or reversing hybrid concat order — and conformance would
   still print PASS. Since §15 cross-language conformance is the line of
   defence for the Python/Swift/Kotlin clients, the parse-only stance is
   too weak for PR-B's `golden_vault_001/`. Minimum bar: recompute the
   signed-range bytes from the hex fixture and assert they match what
   the embedded signatures cover. Stretch: full hybrid-decap +
   AEAD-decrypt + hybrid-verify in stdlib (or a documented narrow
   dependency set, since ML-KEM-768 / ML-DSA-65 aren't in stdlib).

2. **Encrypted-for-other-not-self path untested.** Today's tests cover
   owner+alice+bob all decrypting and stranger-rejected. Missing: owner
   encrypts for `{alice, bob}` only (NOT self) → alice decrypts, bob
   decrypts, owner gets `NotARecipient`. This is the send-only-mode
   semantics path. Add to `core/tests/vault.rs` integration suite.

3. **`VectorClockDuplicateDevice` / `VectorClockCountMismatch` lack
   dedicated negative tests.** Both are production rejection sites
   ([block.rs:649,758](core/src/vault/block.rs)) and the proptest at
   [proptest.rs:981-983](core/tests/proptest.rs) lists them as
   *permitted* outcomes — allowed but not asserted to fire. A regression
   that demoted `VectorClockDuplicateDevice` into a generic "ok" path
   would not be caught. `VectorClockNotSorted` already has a dedicated
   test ([vault.rs:1076](core/tests/vault.rs)); these two siblings
   deserve the same.

4. **Plaintext-level `unknown` bag round-trip untested at the
   block-cycle level.** Record-level + field-level forward-compat is
   covered in `record.rs` tests. The `BlockPlaintext::unknown` field is
   always `BTreeMap::new()` in current tests. Add a test that survives
   an encrypt → encode → decode → decrypt cycle bit-identically.

5. **Optional polish (low value, do only if convenient)**:
   - One negative ML-DSA-65 sigGen vector (mutated message) would prove
     the assertion isn't tautological. 5 positive vectors is thin but
     deterministic, so this is a nice-to-have.
   - `seen_keys: BTreeMap<String, ()>` → `BTreeSet<String>` in
     [record.rs:585,686](core/src/vault/record.rs) and
     [block.rs:1043](core/src/vault/block.rs).
   - [block.rs:1317-1319](core/src/vault/block.rs)
     `count_usize.checked_mul(RECIPIENT_ENTRY_LEN)` cannot overflow
     (`u16::MAX × 1208 ≈ 79 MB`); `BlockError::TooManyRecipients` is
     dead. Defensive code is fine; flag only.

### 4d. PR-B candidate refactor: shared canonical-CBOR helpers

`canonical_sort_entries`, `encode_canonical_map`, the float/tag walker
are duplicated between [record.rs](core/src/vault/record.rs) and
[block.rs](core/src/vault/block.rs) (2 copies). Adding the manifest
crosses the rule-of-three threshold — extract to a shared
`core/src/vault/canonical.rs` as part of PR-B before the third copy
appears.

### 4e. Spec-doc clarifications deferred from PR-A review

- `docs/vault-format.md` §6.2: pin that `wrap_ct (32)` and
  `wrap_tag (16)` are concatenated on the wire (already implemented;
  spec phrasing was ambiguous).
- `docs/vault-format.md` §6.1: mirror `sig_ed_len = 64` with a
  `sig_pq_len = 3309` annotation.
- `core/src/identity/mod.rs` doc-comment references
  `ContactCard::pk_bundle_bytes()` which doesn't exist as a method.
  Either implement it (alongside the contact-card encryption work in a
  later sub-project) or fix the doc.

---

## What this session delivered (2026-04-26 → 2026-04-26)

For session-context retention. Five commits on `main`:

1. `1fe9693` — security-review fixes #1–#5, #7–#11, #13.
2. `88a1c0b` — proptest file with 6 properties.
3. `e523f7d` — JSON KAT loader infrastructure.
4. `06c6e1a` — 8 KAT fixtures externalized to JSON.
5. `dcfd1e1` — NIST FIPS 203 / FIPS 204 KAT vectors.

Test count: 6 proptest + 122 unit/integration = 128.

## What the next session delivered (2026-04-27 — PR #1, `feature/unlock-module`)

The unlock module (Item 3) and the BIP-39 recovery KAT (Item 1a),
shipped via subagent-driven TDD. 29 commits on `feature/unlock-module`.

### Public API surface added

- `secretary_core::unlock::{create_vault, create_vault_unchecked,
  open_with_password, open_with_recovery}` — orchestrators.
- `secretary_core::unlock::{CreatedVault, UnlockedIdentity, UnlockError}`
- `secretary_core::unlock::mnemonic::{Mnemonic, MnemonicError, generate, parse}`
- `secretary_core::unlock::bundle::{IdentityBundle, BundleError, generate}`
- `secretary_core::unlock::bundle_file::{BundleFile, BundleFileError, encode, decode}`
- `secretary_core::unlock::vault_toml::{VaultToml, KdfSection, VaultTomlError, encode, decode}`

Test count after PR #1: 158.

## What this session delivered (2026-04-28 — PR #3, `feature/vault-block-format`)

Vault PR-A (Item 4a) and ML-DSA-65 NIST sigGen KAT (Item 2). 22 commits
on `feature/vault-block-format`, scope-limited per the "one issue per
commit" discipline. Each `feat(vault)` is followed by its review-fix
`fix(vault)` commits where applicable.

### Production code

- [core/src/vault/record.rs](core/src/vault/record.rs) — record types +
  canonical CBOR + forward-compat `UnknownValue` (1709 lines).
- [core/src/vault/block.rs](core/src/vault/block.rs) — binary header,
  recipient table, AEAD body, hybrid sig suffix, `encrypt_block` /
  `decrypt_block` (2329 lines).
- [core/src/vault/mod.rs](core/src/vault/mod.rs) — `VaultError`
  umbrella + re-exports.
- [core/src/version.rs](core/src/version.rs) — `FILE_KIND_BLOCK` added.

### Tests

- 81 lib unit tests (was 48) — record + block CBOR/binary primitives.
- 33 vault integration tests (1 ignored bootstrap) — round-trip,
  multi-recipient, every byte field flipped, wire-format strictness.
- 16 sig integration (was 15) — adds `ml_dsa_65_nist_siggen_kat`.
- 16 proptest (was 11) — adds block round-trip, recipient-table sort
  invariant, verify-before-decap fuzzing.
- §15 KAT: [core/tests/data/block_kat.json](core/tests/data/block_kat.json).
- ML-DSA-65 NIST KAT: [core/tests/data/ml_dsa_65_kat.json](core/tests/data/ml_dsa_65_kat.json).
- Cross-language: [core/tests/python/conformance.py](core/tests/python/conformance.py)
  (stdlib-only, `uv run` compatible; parses wire format from spec alone).

Test count after PR #3: 230 + 1 ignored bootstrap (was 158). Clean under
`cargo test --release --workspace`, `cargo clippy --all-targets
--workspace -- -D warnings`, and `uv run core/tests/python/conformance.py`.

### Public API surface added

- `secretary_core::vault::{Record, RecordError, RecordField,
  RecordFieldValue, UnknownValue}`
- `secretary_core::vault::{BlockFile, BlockHeader, BlockPlaintext,
  BlockError, RecipientPublicKeys, RecipientWrap, VectorClockEntry}`
- `secretary_core::vault::{encode_block_file, decode_block_file,
  encrypt_block, decrypt_block}`
- `secretary_core::vault::{FILE_KIND_BLOCK, RECIPIENT_ENTRY_LEN}`
- `secretary_core::vault::VaultError` umbrella.

Branch is awaiting merge of PR #3 to `main`. Items 1b and 4b–4e remain
open for future sessions and are PR-B's scope.
