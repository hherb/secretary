# secretary — next session entry point

This file is the entry point for the **next** session, in the same role
[FIXME.md](FIXME.md) played until 2026-04-26 (now closed and removed).
It captures three things: the two crypto-design §15 KAT files that were
deferred from FIXME §6 because their subjects are stubs; one optional
hardening item left over from the NIST KAT round; and the next two
modules in the build sequence the spec calls for.

When all the items below are done, delete this file and create the next
one.

---

## Item 1 — Finish the §15 KAT contract (blocked on later modules)

Per `docs/crypto-design.md` §15, the §15 list has twelve entries. Ten are
in `core/tests/data/*.json` already. Two remain, both blocked on modules
that are still stubs as of this session:

### 1a. ~~`bip39_recovery_kat.json`~~ — DONE 2026-04-27

Delivered as [core/tests/data/bip39_recovery_kat.json](core/tests/data/bip39_recovery_kat.json)
(4 vectors: all-zero, all-FF, two Trezor canonical 24-word) plus the
`bip39_recovery_kat_vectors` test in [core/tests/unlock.rs](core/tests/unlock.rs),
which pins three relations end-to-end: mnemonic↔entropy, `info_tag` bytes
match `TAG_RECOVERY_KEK`, and entropy→Recovery KEK under HKDF-SHA-256.
Cross-verified against the Trezor `mnemonic` Python package + the
`cryptography` library's HKDF.

### 1b. `golden_vault_001/` — blocked on the `vault` module

§15 promises a complete v1 vault: `vault.toml`, `manifest.cbor.enc`,
`identity.bundle.enc`, one block, one Contact Card, decryptable from
the spec alone via `core/tests/python/conformance.py`.

This needs the [core/src/vault/](core/src/vault/) module (manifest format,
block format, atomic writes) AND the `unlock` module above. It's the
final piece of the cross-language conformance contract — until it
exists, no clean-room implementation can be validated end-to-end.

---

## Item 2 — Optional: ML-DSA sign-side NIST cross-validation

The four NIST KAT tests added in this session
([core/tests/kem.rs](core/tests/kem.rs) and [core/tests/sig.rs](core/tests/sig.rs))
cover ML-KEM-768 keygen + encap, and ML-DSA-65 keygen + sigver. The
ML-DSA-65 *sign-side* — "feeding NIST's `sk` and getting NIST's `sig`
out" — is **not** covered, because:

- NIST sigGen vectors carry the FIPS 204 expanded-form sk (4032 bytes).
- The `ml-dsa` crate exposes the expanded-form sk only via
  `#[deprecated]` `ExpandedSigningKey::from_expanded`; the modern API
  is seed-only.
- Using `from_expanded` would compile-warn (and we run clippy with
  `-D warnings`).

Sign-side correctness is currently anchored by:
- `ml_dsa_65_roundtrip` in [core/tests/sig.rs](core/tests/sig.rs) (same
  seed → same output, verify accepts).
- `hybrid_sig_wire_kat` (pins our wrapper's sign output for a fixed
  identity_seed across all three SigRole variants).

To close the loop properly, take a future opportunity to either:
(a) Wrap the deprecated `from_expanded` call in
    `#[allow(deprecated)]` and add a fourth NIST test
    (`ml_dsa_65_nist_siggen_kat`), or
(b) Wait for the `ml-dsa` crate to expose a non-deprecated way to load
    expanded sks (or to ship its own NIST KAT test harness publicly),
    and reuse that.

Not urgent — the existing coverage is meaningful — but worth noting.

---

## ~~Item 3 — Build-sequence next: `unlock` module~~ — DONE 2026-04-27

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

Sub-project A's design anchor lives at
`/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md` —
re-read at the start of any session that touches Sub-project A code.

---

## Item 4 — Build-sequence next: `vault` module

Per `docs/crypto-design.md` §10–§11, the vault module owns:

- Manifest format: per-block recipient table, vector clocks for CRDT
  merge, atomic writes.
- Block format: encrypted payload + per-recipient HybridWrap entries
  (the ones already produced by `kem::encap`).
- On-disk layout: `vault.toml` + `manifest.cbor.enc` +
  `identity.bundle.enc` + per-block files.
- Conflict resolution: vector-clock-driven merge, since multiple
  devices write through the same cloud-folder transport.

This is the largest remaining piece of Sub-project A and is the final
prerequisite for `golden_vault_001/` (Item 1b). [core/src/vault/mod.rs](core/src/vault/mod.rs)
is the stub to grow.

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

## What the next session delivered (2026-04-27 — `feature/unlock-module`)

The unlock module (Item 3) and the BIP-39 recovery KAT (Item 1a),
shipped via subagent-driven TDD against
[docs/superpowers/plans/2026-04-27-unlock-module.md](docs/superpowers/plans/2026-04-27-unlock-module.md).

Twenty-three commits on `feature/unlock-module` — five from the original
Opus run before context compaction (`a69c078..c43988a`, mnemonic + bundle
plaintext) and eighteen from the resumed run (`a1f9add..3c5e361`,
bundle_file + vault_toml + UnlockError + create_vault + the two open
paths + integration tests + BIP-39 KAT + proptest + one latent-bug fix
for `vault_toml::encode` rejecting timestamps > i64::MAX as a typed
error rather than a panic — caught by proptest).

Test count after: 153 (was 122 + 6 proptest = 128). Breakdown:
46 core unit tests + 4 unlock integration tests + 11 proptest
properties + 92 other crypto/identity integration tests. All clean
under `cargo test --release --workspace` and
`cargo clippy --all-targets --workspace -- -D warnings`.

Branch is on `feature/unlock-module` awaiting merge to `main`. Items 1b,
2, and 4 below remain open for future sessions.
