# Side-channel internal audit (precursor to paid review)

This document is the **internal pass** called out in
[secretary_next_session.md](../../../secretary_next_session.md)'s Open
Item 3 → Side-channel review. It is a precursor to the planned external
side-channel review, not a substitute for it. Its purpose is to
enumerate the constant-time-sensitive call sites flagged in
[threat-model.md](../../threat-model.md) §3.2 and §3.3, walk each one
in the current code, and flag gaps for the external reviewer to verify
against side-channel adversaries.

**Scope:** the Rust core (`core/src/{crypto,identity,unlock,vault}/`).
Out of scope: hardware-level side channels (power analysis, EM,
acoustic, thermal — explicitly out of scope per threat-model §2.7) and
platform-UI timing (Sub-project D).

**Methodology:** for each constant-time-sensitive path enumerated in
the threat model, identify the production call sites, the underlying
primitive, and the constant-time-discipline the primitive provides
(directly or via an upstream crate). Flag any path that performs a
plain `==` on a secret-derived value.

**Date:** 2026-05-02 (post-PR-#12 monitor stabilisation; 430 tests +
6 ignored on `main`).

---

## Summary

No bugs found in the internal pass — the four constant-time-sensitive
paths (AEAD verify-then-decap, hybrid signature verify, hybrid KEM
decap, Argon2id-derived KEK use) all delegate the sensitive comparison
to upstream RustCrypto crates that document constant-time discipline.
Direct `==` comparisons in the Rust core are limited to **public**
values: `Fingerprint = [u8; 16]`, `vault_uuid: [u8; 16]`,
`device_uuid: [u8; 16]`, `created_at_ms: u64`, suite IDs, format
versions. None of these constitute a side-channel leak surface because
their values are observable to any adversary that can read the cloud-
folder copy of the vault.

The `subtle` crate is a direct dependency
([core/Cargo.toml:17](../../../core/Cargo.toml#L17)) and surfaces a
`Sensitive<T>::ct_eq` API at
[core/src/crypto/secret.rs:64-67](../../../core/src/crypto/secret.rs#L64-L67).
That API has no production call sites today — by design, because the
verify-then-decap pattern means the codebase never compares two secret
byte strings for equality outside of AEAD MAC verification. The API
exists for future hardening (e.g. if Sub-project C orchestration
introduces a "do these two unwrapped block-content keys agree?" check)
or for FFI consumers (Sub-project B) that need to expose CT-equality
to clients.

The principal items to flag for external review are not bugs in
*our* code but **assumptions we make about upstream crates** — we
trust `chacha20poly1305`, `ed25519-dalek`, `ml-dsa`, and `ml-kem` to
provide constant-time discipline where required, and that trust
should be independently verified by a reviewer with FIPS 203 / 204
implementer experience. `ml-dsa` in particular is at `0.1.0-rc.8`
(release candidate); production hardening expectations on a pre-1.0
crate are weaker than for an established crate, and that's worth
flagging.

---

## 1. AEAD verify-then-decap

**Threat model row:** §3.2 brute-force defense (KDF + AEAD MAC
verifies password); §3.1 "tamper with a block" (AEAD MAC catches
tampered ciphertext on decrypt).

**Production paths:**
- [core/src/crypto/aead.rs::decrypt](../../../core/src/crypto/aead.rs#L139) →
  `chacha20poly1305::XChaCha20Poly1305::decrypt` (RustCrypto crate,
  v0.10).
- Used by:
  - `crypto::kem::decap` to unwrap the Block Content Key (BCK) from
    the per-recipient wrap.
  - `vault::block::decrypt_block` to decrypt the block body under
    the recovered BCK.
  - `vault::manifest::open_manifest` to decrypt the manifest body
    under the Identity Block Key (IBK).
  - `unlock::open_with_password` and `open_with_recovery` to decrypt
    `wrap_pw` / `wrap_recovery` (yielding the IBK) and then the
    Identity Bundle plaintext under the IBK.

**Constant-time discipline:** `chacha20poly1305` 0.10 implements MAC
tag verification using `subtle::ConstantTimeEq`; this is documented
RustCrypto policy. The Poly1305 tag is a 16-byte value compared as a
single `subtle` operation.

**Our code's contribution:** none — we treat the crate as a black box.
The single error variant `AeadError::Decryption` deliberately
collapses "wrong key", "wrong nonce", "wrong AAD", "tampered
ciphertext", "truncation" into one outcome
([core/src/crypto/aead.rs:103-107](../../../core/src/crypto/aead.rs#L103-L107)),
matching the AEAD security model.

**Gaps to flag for external review:**
- Confirm `chacha20poly1305` 0.10's tag verify is in fact constant-
  time on every supported target. (RustCrypto's CI tests this on
  x86-64 + aarch64; reviewer should confirm and note any divergent
  paths on other targets.)

---

## 2. Hybrid signature AND-verify (Ed25519 ∧ ML-DSA-65)

**Threat model row:** §3.3 "forge a hybrid signature"; §3.1 "manifest
signature integrity"; §3.4 "fake card insertion" (cards self-sign).

**Production paths:**
- [core/src/crypto/sig.rs::verify](../../../core/src/crypto/sig.rs#L364) →
  `ed25519-dalek::Verifier::verify` then `ml-dsa::Verifier::verify`,
  with `?` propagation between halves.
- Used at every signature-verification call site:
  - `vault::block::decrypt_block` (block signature, before any
    private-key operation runs).
  - `vault::manifest::open_manifest` (manifest signature).
  - `identity::card::ContactCard::verify_self` (card hybrid
    self-signature).

**Early-return-on-Ed25519-fail is intentional**, documented at
[core/src/crypto/sig.rs:14-20](../../../core/src/crypto/sig.rs#L14-L20):
"Failures are surfaced as **distinct** variants
(`SigError::Ed25519VerifyFailed` vs `SigError::MlDsa65VerifyFailed`).
Unlike the AEAD case (where collapsing protects against side
channels), here the caller benefits from knowing which half rejected:
it's diagnostic information about which primitive is broken or being
attacked, not key-recovery information."

The reasoning: signature verification operates on **public values**
(message, signature, public key — all of which an adversary already
sees on the cloud-folder copy), so a timing leak that distinguishes
"Ed25519 rejected" from "ML-DSA rejected" leaks information about
which half a forger broke, not about any secret value.

**Constant-time discipline:** `ed25519-dalek::Verifier` and
`ml-dsa::Verifier` perform group-arithmetic operations on public
data. Constant-time is not a correctness requirement here in the
classical threat model (no secret bits depend on the path taken).

**Gaps to flag for external review:**
- Confirm ML-DSA-65's verify path in `ml-dsa` 0.1.0-rc.8 has no
  unintended observable timing differences for an attacker
  attempting to distinguish "valid sig over message A" from "valid
  sig over message B" via shared cache state. (FIPS 204 verification
  is data-dependent on signature contents; non-CT is acceptable, but
  the pre-1.0 crate version is worth a careful read.)
- Confirm `ed25519-dalek` 2.2's `Verifier::verify` matches the
  RFC 8032 deterministic verification (it does, but worth noting the
  version pin alongside the dalek 2.x stability commitment).

---

## 3. Hybrid KEM decap (X25519 ⊕ ML-KEM-768)

**Threat model row:** §3.3 "decrypt harvested hybrid KEM
ciphertext".

**Production path:**
- [core/src/crypto/kem.rs::decap](../../../core/src/crypto/kem.rs#L408).

**Structural observations:**
1. Both halves run unconditionally — X25519 DH cannot fail (always
   produces 32 bytes), ML-KEM decap returns `Result` but is
   implicit-rejecting per FIPS 203 (a malformed `ct_pq` produces
   "wrong" 32 bytes, not a rejection).
2. The two shared secrets feed HKDF-SHA-256 alongside both
   ciphertexts and both public-key bundles to derive the AEAD wrap
   key.
3. The wrap key then unwraps the Block Content Key via AEAD with
   AAD = `block_uuid || transcript`. **AEAD MAC verify is the
   implicit-rejection check** — an attacker who tampers either
   ciphertext, either public-key bundle, or the transcript inputs
   gets an `AeadFailure` here, not an earlier reveal.
4. Intermediate buffers (`ikm`, `okm`, stack-copy `key`,
   `ss_pq_bytes`, `k`) are explicitly zeroized before drop —
   [core/src/crypto/kem.rs:262-271](../../../core/src/crypto/kem.rs#L262-L271)
   and similar. Defense-in-depth against memory-scraper adversaries
   even though `Sensitive::Drop` already zeroizes the wrapped values.

**Early-return on `MlKemDecapsFailed`:** The `?` propagation at
[core/src/crypto/kem.rs:435](../../../core/src/crypto/kem.rs#L435)
returns before AEAD verify if `dk.decapsulate` errors. In the
implicit-rejection ML-KEM-768 model this should not happen for
well-formed ciphertexts; the only realistic trigger is malformed
inputs that fail length validation upstream. Like the hybrid-sig
case, this is an intentional choice: the ciphertext is **public**
(it sits in the on-disk recipient table), so a timing side channel
that distinguishes "ML-KEM rejected" from "AEAD rejected" leaks no
information that the adversary cannot already obtain by parsing the
file directly.

**Constant-time discipline:** delegated to `x25519-dalek` 2.x
(static-secrets feature, zeroize feature; constant-time arithmetic
per dalek's documented invariants) and `ml-kem` 0.2 (RustCrypto FIPS
203 implementation).

**Gaps to flag for external review:**
- Confirm `ml-kem` 0.2's `decapsulate` is constant-time over the
  decapsulation-key bits. The decap key is a long-term secret;
  timing variation could leak it. RustCrypto's `ml-kem` follows FIPS
  203 algorithm A.21 which has no key-dependent branches; reviewer
  should confirm at the implementation level.
- Confirm `x25519-dalek 2`'s `diffie_hellman` is constant-time over
  the static secret (yes by dalek convention; reviewer to verify
  on the pinned version).
- The HKDF-SHA-256 step in
  [derive_wrap_key](../../../core/src/crypto/kem.rs#L233) operates
  on secret IKM (`ss_x || ss_pq`). The `hkdf` 0.12 crate's
  `extract_and_expand` runs HMAC-SHA-256, which is not branch-
  dependent on key bits in the standard implementation. Reviewer to
  confirm.

---

## 4. Fingerprint comparison and recipient-table lookup

**Threat model row:** §3.4 "card insertion / substitution"; §3.1
"tamper with recipient table" (binds via AEAD AAD on the block).

**Production paths (all `==` on `[u8; 16]`):**
- [core/src/vault/orchestrators.rs:530](../../../core/src/vault/orchestrators.rs#L530) —
  `manifest_file.author_fingerprint != owner_fp`.
- [core/src/vault/orchestrators.rs:1038](../../../core/src/vault/orchestrators.rs#L1038),
  [:1066](../../../core/src/vault/orchestrators.rs#L1066) —
  `author_fp != block_file.author_fingerprint` cross-check.
- [core/src/vault/orchestrators.rs:1089](../../../core/src/vault/orchestrators.rs#L1089),
  [:1121](../../../core/src/vault/orchestrators.rs#L1121) —
  recipient-table lookup `.any(|w| w.recipient_fingerprint == ...)`
  and `.find(|(fp, _)| *fp == wrap.recipient_fingerprint)`.
- [core/src/vault/block.rs:1242](../../../core/src/vault/block.rs#L1242),
  [:1670](../../../core/src/vault/block.rs#L1670) — duplicate-
  fingerprint check on adjacent sorted entries (well-formedness).
- [core/src/vault/block.rs:1751](../../../core/src/vault/block.rs#L1751),
  [:1777](../../../core/src/vault/block.rs#L1777) —
  `block.author_fingerprint != sender_card_fingerprint` cross-check
  + reader entry lookup `.find(|r| &r.recipient_fingerprint == reader_card_fingerprint)`.

**Why `==` is acceptable here:** `Fingerprint = [u8; 16]` is a
**public** value by design. Fingerprints are derived from BLAKE3 of
the canonical Contact Card (which itself is a public artifact —
intended for sharing). They appear cleartext in:
- `vault.toml` (owner fingerprint, sometimes — current v1 does not
  store it there but the cleartext file is reserved for that role).
- The on-disk recipient table at the start of every block file
  (§6.2 of vault-format.md).
- Manifest signed-headers (`author_fingerprint`, §4.1).

A timing leak on a fingerprint comparison reveals at most "which
position in a sorted list the attacker's fingerprint matched" —
information already available to any observer who reads the same
bytes off the cloud-folder copy.

**Conclusion:** no fix needed. The `Fingerprint` type alias is
intentionally a public-value representation, in contrast to
`Sensitive<T>` which wraps secret-value byte strings. Worth
documenting in the type alias — see "Hardening to consider" below.

---

## 5. Argon2id and unlock-path comparisons

**Threat model row:** §3.2 "brute-force the master password";
§3.2 "swap files between two of the user's vaults" (via `vault_uuid`
cross-check).

**Production paths:**
- `unlock::derive_master_kek` uses `argon2 = "0.5"` to derive a 32-
  byte KEK from password + salt + KDF parameters. **No equality
  comparison occurs** — Argon2id is a one-way function and the
  derived KEK is fed straight into `aead::decrypt` of `wrap_pw`.
- The "wrong password" check is **AEAD MAC verify on `wrap_pw`** —
  a wrong KEK produces a MAC mismatch that surfaces as
  `UnlockError::WrongPasswordOrCorrupt`. This collapses "wrong
  password" with "corrupt vault" by design (per
  [core/src/unlock/mod.rs:332-342](../../../core/src/unlock/mod.rs#L332-L342)),
  matching the AEAD model.
- Cross-checks at unlock time
  ([core/src/unlock/mod.rs:323](../../../core/src/unlock/mod.rs#L323)):
  `bf.vault_uuid != vt.vault_uuid || bf.created_at_ms != vt.created_at_ms`
  — both fields are public cleartext metadata; non-CT is fine.
- `Argon2idParams::V1_MIN_MEMORY_KIB` floor is enforced as a
  **typed error** (`UnlockError::WeakKdfParams`,
  [core/src/unlock/mod.rs:46-48](../../../core/src/unlock/mod.rs#L46-L48))
  *before* any Argon2id work runs, so a tampered `vault.toml`
  cannot silently downgrade the cost.

**Constant-time discipline:** delegated to `argon2 = "0.5"` (the
KDF itself); RustCrypto's Argon2 implementation is memory-hard by
construction, with no key-dependent branches in the standard
data-independent Argon2id pass schedule.

**Gaps to flag for external review:**
- Confirm `argon2 0.5`'s data-independent pass schedule is
  preserved on every supported target. (Argon2id has both data-
  independent and data-dependent passes; the data-independent pass
  is the side-channel-relevant one.)
- Confirm the password input is never logged, debug-printed, or
  used as a hash-map key (audited via `Sensitive` wrapping —
  `password: &SecretBytes` is the only API surface, and `SecretBytes`
  has no `Display` impl). One nit to verify: the `SecretBytes`
  `Debug` impl prints `Sensitive<…>` rather than the bytes — see
  `core/src/crypto/secret.rs` for the implementation.

---

## 6. `subtle` crate adoption

`subtle = "2"` is a direct dependency. The single import is at
[core/src/crypto/secret.rs:14](../../../core/src/crypto/secret.rs#L14)
and the only API exposed is `Sensitive<T>::ct_eq`
([:64-67](../../../core/src/crypto/secret.rs#L64-L67)) for byte-
string comparison.

`Sensitive<T>` deliberately does **not** implement `PartialEq` —
documented at
[core/src/crypto/secret.rs:76-78](../../../core/src/crypto/secret.rs#L76-L78):
"`subtle` only provides `ConstantTimeEq` for slices and integer
primitives; an `==` impl bounded on `T: ConstantTimeEq` would
silently fail to apply to `[u8; N]`, the dominant case." This forces
callers to use `ct_eq` explicitly when comparing secrets, rather than
the syntactic `==` which would silently fall back to a non-CT impl.

**Production call sites of `ct_eq`:** zero. By design — see Summary
above. The verify-then-decap pattern means the codebase never has a
"compare two secret byte strings" moment outside of AEAD MAC verify
(where the comparison is inside the upstream crate).

**Gaps to flag for external review:**
- None — the API surface is small, the discipline is documented at
  the type level, and the absence of CT-violating fallbacks is
  enforced by the absence of a `PartialEq` impl on `Sensitive`.

---

## Hardening to consider (small, no-bug fixes)

None of these are bugs. Each is a small documentation or
defensive-discipline improvement that would make the security
boundary even more obvious to future contributors and external
auditors.

1. **`Fingerprint` type-alias doc-comment**: add a short note at
   [core/src/identity/fingerprint.rs:35](../../../core/src/identity/fingerprint.rs#L35)
   explaining that `Fingerprint = [u8; 16]` is a *public* value (in
   contrast to `Sensitive<[u8; 16]>` which would wrap a secret). A
   reader who arrives at a `==` comparison on a `Fingerprint` should
   immediately see that non-CT is intentional.

2. **`SigError::Ed25519VerifyFailed` vs `MlDsa65VerifyFailed`
   distinction**: already documented at the module level
   ([core/src/crypto/sig.rs:14-20](../../../core/src/crypto/sig.rs#L14-L20));
   no change needed. Worth re-reading at every external review to
   re-confirm the threat-model assumption that "which half rejected"
   is non-secret information.

3. **`ml-dsa` version pin**: the crate is at `0.1.0-rc.8` (release
   candidate). Consider switching to a stable 1.x release once
   available, and adding a comment in
   [core/Cargo.toml](../../../core/Cargo.toml) flagging the security-
   critical pin (similar to `tempfile = "=3.27.0"`'s
   exact-pin pattern).

These are not blockers for the external review; they're small
discipline-tightening that the external reviewer might recommend
anyway.

---

## Out of scope for this internal pass

- **Hardware side channels** (power analysis, EM, acoustic, thermal):
  out of scope per threat-model §2.7. An adversary with hardware
  access to an *unlocked* device is in our out-of-scope set.
- **Kernel / firmware compromise**: §2.7.
- **Malware on an unlocked device**: §2.7. `zeroize` reduces the
  window but does not eliminate it.
- **Build / supply-chain side channels** (e.g. a malicious crate that
  exfiltrates keys at compile time): §2.7. Mitigation is reproducible
  builds + dependency review, not internal code audit.
- **Memory-hygiene audit** (zeroize coverage on every secret type,
  drop ordering): tracked separately as the "Memory hygiene audit"
  entry in Open Item 3 of `secretary_next_session.md` — that pass
  produces a per-type coverage table; this side-channel pass focuses
  on timing.

---

## Conclusion

The internal pass found no bugs and no gaps in our own code. The
constant-time-sensitive comparisons all delegate to upstream
RustCrypto crates (`chacha20poly1305`, `ed25519-dalek`, `ml-dsa`,
`ml-kem`, `argon2`, `hkdf`) whose CT discipline is documented but not
independently verified by us. **The principal output of this pass is
a list of upstream-crate assumptions for the external reviewer to
verify**, plus three minor doc-tightening items in "Hardening to
consider".

Direct `==` comparisons in our code are limited to public values
(fingerprints, UUIDs, suite IDs, format versions, timestamps), which
constitute no leak surface because their values are observable to
any adversary that can read the cloud-folder copy of the vault.

The verify-then-decap pattern (signature → AEAD-MAC → decap, in that
order) means the codebase never has a "compare two secret byte
strings for equality" moment outside of AEAD MAC verification —
which is itself constant-time inside the upstream crate. The
`Sensitive::ct_eq` API exists for future callers (Sub-project B FFI,
Sub-project C orchestration) but has no current production use.
