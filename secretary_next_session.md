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

### 1a. `bip39_recovery_kat.json` — blocked on the `unlock` module

§15 promises a KAT covering "Mnemonic encoding / decoding round-trip and
HKDF derivation." The BIP-39 wordlist itself lives at
[core/src/identity/bip39_wordlist.rs](core/src/identity/bip39_wordlist.rs)
and the inverse (entropy → words) is exercised by `mnemonic_form` in
[core/src/identity/fingerprint.rs](core/src/identity/fingerprint.rs) (used for
fingerprint *presentation*, not recovery — see §6.1 vs §3).

The recovery flow itself — 24-word mnemonic → 256-bit entropy →
HKDF-SHA-256 → Recovery KEK — needs the [core/src/unlock/](core/src/unlock/)
module, currently a stub. Once that module exists, the KAT shape is:

```json
{
  "vectors": [
    {
      "name": "rfc_test_vector_or_reference_impl",
      "mnemonic": "<24 words separated by single spaces>",
      "entropy": "<32-byte hex>",
      "info_tag": "<TAG_RECOVERY_KEK bytes from kdf.rs>",
      "expected_recovery_kek": "<32-byte hex>"
    }
  ]
}
```

Cross-verify against the `bip39` Python package + the existing HKDF
implementation. The `recovery_kek_test_vector_zero_entropy` and
`recovery_kek_uses_recovery_kek_tag` tests in
[core/tests/kdf.rs](core/tests/kdf.rs) already pin the HKDF half; the new
KAT will pin the mnemonic-to-entropy half plus their composition.

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

## Item 3 — Build-sequence next: `unlock` module

Per `docs/crypto-design.md` §3 + §4, the unlock module owns:

- Master-password unlock path: vault.toml → derive Master KEK
  (Argon2id) → unwrap Identity Bundle Key → unwrap identity.bundle.enc.
- Recovery unlock path: 24-word mnemonic → entropy → derive Recovery
  KEK (HKDF-SHA-256) → unwrap the dual-wrapped Identity Block Key.
- BIP-39 mnemonic parsing + checksum validation (this also unblocks
  Item 1a above).

The kdf, aead, kem, sig, identity primitives are all in place.
[core/src/unlock/mod.rs](core/src/unlock/mod.rs) is the stub to grow.

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
