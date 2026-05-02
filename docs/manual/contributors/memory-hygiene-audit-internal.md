# Memory-hygiene internal audit

This document is the **memory-hygiene internal pass** called out in
[secretary_next_session.md](../../../secretary_next_session.md)'s Open
Item 3 → Memory hygiene audit. Companion to the
[side-channel internal audit](side-channel-audit-internal.md). Its
purpose is to walk every type that holds secret material in the Rust
core, verify its zeroize-on-drop discipline, and flag stack-residue
patterns where a secret value sits in a named-but-unzeroized stack
slot after being moved into a `Sensitive` wrapper.

**Scope:** the Rust core (`core/src/{crypto,identity,unlock,vault}/`).
Out of scope: cross-FFI memory hygiene (Sub-project B), platform-UI
clipboard hygiene (Sub-project D), kernel/swap-page memory exposure
(threat-model §2.7).

**Methodology:** for each named struct or type alias that wraps secret
bytes, verify (a) it derives `Zeroize, ZeroizeOnDrop` or composes them
via a wrapped field, (b) its `Debug`/`Clone`/`PartialEq` derives don't
defeat zeroize discipline, (c) the surrounding code zeroizes any
stack-residue copies after the secret is moved into the wrapper.

**Date:** 2026-05-02 (post-side-channel internal audit; 430 tests + 6
ignored on `main`).

---

## Summary

The wrapper discipline (`Sensitive<T>`, `SecretBytes`) is sound and
well-documented:
[core/src/crypto/secret.rs](../../../core/src/crypto/secret.rs)
derives `Zeroize, ZeroizeOnDrop` on both wrappers and intentionally
omits `PartialEq` on `Sensitive<T>` (forcing callers to use
`subtle::ConstantTimeEq` explicitly when they need byte-equality).
`IdentityBundle` wraps all four secret keys in `Sensitive`, has a
custom redacting `Debug`, and does not derive `Clone`.

The audit found **twelve stack-residue gaps** where a secret was
copied into a `Sensitive` wrapper but the original stack slot was not
explicitly zeroized after the move. All twelve are fixed in commits
landing alongside this memo. The pattern was consistent: the
established sites (`crypto::kem::derive_wrap_key`,
`crypto::sig::generate_ed25519`,
`crypto::kdf::derive_recovery_kek`, `vault::block::encrypt_block`'s
BCK construction) had the post-move `.zeroize()` discipline; sister
sites in the same modules had been missed.

The audit originally flagged one **larger design question** as
deferred: `RecordFieldValue::{Text, Bytes}` (the user's actual
passwords / secret notes / API keys) held plain `String` / `Vec<u8>`
that were not zeroized on drop. **This has since been fixed** in a
follow-up pass — both variants now wrap `SecretString` / `SecretBytes`
and inherit `Zeroize, ZeroizeOnDrop`. The wire format is unchanged
(the existing fuzz seeds re-encode bit-identically) and the Python
conformance verifier is unaffected (it compares CBOR bytes, not
in-memory types). See "Resolved: record-content zeroize" below.

---

## Wrapper discipline

[core/src/crypto/secret.rs](../../../core/src/crypto/secret.rs)
defines the two secret-bearing wrappers used throughout the crate:

| Wrapper | Derive | Storage | Custom impls | Notes |
|---|---|---|---|---|
| `SecretBytes` | `Zeroize, ZeroizeOnDrop` | `Vec<u8>` (heap) | `Debug` (redacted, prints len only); `PartialEq, Eq` via `subtle::ConstantTimeEq` | No `Clone` derived; `Display` not implemented. |
| `Sensitive<T: Zeroize>` | `Zeroize, ZeroizeOnDrop` | `T` (typically `[u8; 32]` or `Vec<u8>`) | `Debug` (redacted, prints `<redacted>`) | Intentionally **does not** implement `PartialEq` — see [secret.rs:75-85](../../../core/src/crypto/secret.rs#L75-L85): `subtle` only provides `ConstantTimeEq` for slices and integer primitives, and an `==` impl bounded on `T: ConstantTimeEq` would silently fail to apply to `[u8; N]`. Callers needing byte-equality compare slices via `a.expose()[..].ct_eq(&b.expose()[..])`. |

**Both wrappers are sound.** No changes recommended.

## Top-level secret types

| Type | Module | Wrapping | Drop discipline | Status |
|---|---|---|---|---|
| `AeadKey` | `crypto::aead` | `Sensitive<[u8; 32]>` | inherits | ✓ |
| `Ed25519Secret` | `crypto::sig` | `Sensitive<[u8; 32]>` | inherits | ✓ |
| `MlDsa65Secret` | `crypto::sig` | tuple-struct wrapping `SecretBytes` | derives `Zeroize, ZeroizeOnDrop`; inner field drops + zeroizes (idempotent) | ✓ — derive added in follow-up pass; see "Resolved: newtype `Zeroize` / `ZeroizeOnDrop` derives" below. |
| `X25519Secret` | `crypto::kem` | `Sensitive<[u8; 32]>` | inherits | ✓ |
| `MlKem768Secret` | `crypto::kem` | tuple-struct wrapping `SecretBytes` | derives `Zeroize, ZeroizeOnDrop`; inner field drops + zeroizes (idempotent) | ✓ — same follow-up as `MlDsa65Secret`. |
| `Mnemonic` | `unlock::mnemonic` | `phrase: String` + `entropy: Sensitive<[u8; 32]>` | custom `Drop` zeroizes `phrase`; `entropy` inherits | ✓ |
| `IdentityBundle` | `unlock::bundle` | four secret-key fields wrapped in `Sensitive` | implicit drop drops fields in source order; each `Sensitive` zeroizes | ✓ — custom redacting `Debug` at [bundle.rs:206-222](../../../core/src/unlock/bundle.rs#L206-L222); no `Clone`, no `PartialEq` |
| `UnlockedIdentity` | `unlock::mod` | composes `Sensitive<[u8; 32]>` (IBK) + `IdentityBundle` | implicit drop | ✓ |
| `Fingerprint` | `identity::fingerprint` | `[u8; 16]` (public value, *not* secret) | n/a (public) | ✓ — newly doc-commented in commit `e921e99` to make the public-value status obvious. |

## Drop ordering — composite types holding multiple secrets

`IdentityBundle` ([bundle.rs:167-198](../../../core/src/unlock/bundle.rs#L167-L198))
declares fields in this order:

```rust
user_uuid, display_name,
x25519_sk (Sensitive),     x25519_pk,
ml_kem_768_sk (Sensitive), ml_kem_768_pk,
ed25519_sk (Sensitive),    ed25519_pk,
ml_dsa_65_sk (Sensitive),  ml_dsa_65_pk,
created_at_ms,
```

Rust's drop glue runs each field's destructor in **source order**, so
each `Sensitive` field zeroizes independently. There is no field that
borrows from a sibling secret; no drop-ordering bug.

`UnlockedIdentity` is `(identity_block_key: Sensitive<[u8; 32]>,
identity: IdentityBundle)`. Drop order: IBK first (zeroizes), then
IdentityBundle (which zeroizes its four secret-key fields in turn). ✓

`BlockPlaintext` does *not* hold a key — it holds `Vec<Record>`,
which in turn holds `RecordField`s with `RecordFieldValue::{Text, Bytes}`.
The `Record` contents are now zeroized — `RecordFieldValue::{Text, Bytes}`
wrap `SecretString` / `SecretBytes` since the follow-up pass. See
"Resolved: record-content zeroize" below.

---

## Stack-residue gaps fixed in this pass

Twelve sites where a secret was moved into a `Sensitive` wrapper but
the original stack slot was not zeroized. The fix is the same one-line
pattern used elsewhere in the crate
(`source_var.zeroize()` after `Sensitive::new(source_var)`).

| # | File:line | Site | Fix |
|---|---|---|---|
| 1 | `core/src/crypto/kdf.rs::derive_master_kek` | `out: [u8; 32]` after `Sensitive::new(out)` | `out.zeroize()` |
| 2 | `core/src/unlock/mod.rs::create_vault` | `ibk: [u8; 32]` after `Sensitive::new(ibk)` | `ibk.zeroize()` (replaces a SECURITY note that acknowledged but didn't apply the fix) |
| 3 | `core/src/unlock/mod.rs::open_with_password` | `ibk_arr: [u8; 32]` after `Sensitive::new(ibk_arr)` | `ibk_arr.zeroize()` |
| 4 | `core/src/unlock/mod.rs::open_with_recovery` | `ibk_arr: [u8; 32]` after `Sensitive::new(ibk_arr)` | `ibk_arr.zeroize()` |
| 5 | `core/src/vault/orchestrators.rs::save_block` | author Ed25519 SK temp `*expose()` | bind to `ed_sk_bytes`, zeroize after move |
| 6 | `core/src/vault/orchestrators.rs::open_block` | reader X25519 SK temp `*expose()` | bind to `x_sk_bytes`, zeroize after move |
| 7 | `core/src/vault/block.rs::encrypt_block` | BCK key temp `*bck.expose()` | bind to `bck_key_bytes`, zeroize after move |
| 8 | `core/src/vault/block.rs::decrypt_block` | BCK key temp `*bck.expose()` | bind to `bck_key_bytes`, zeroize after move |
| 9 | `core/src/crypto/kem.rs::encap` | X25519 shared-secret bytes from `ss_x_raw.to_bytes()` | bind to `ss_x_bytes`, zeroize after move |
| 10 | `core/src/crypto/kem.rs::decap` | X25519 shared-secret bytes + recipient SK deref-copy | bind both, zeroize each after move |
| 11 | `core/src/unlock/mnemonic.rs::generate` | `full: [u8; 33]` from `bip.to_entropy_array()` | bind `mut`, `full.zeroize()` after copy |
| 12 | `core/src/unlock/mnemonic.rs::parse` | `full: [u8; 33]` from `bip.to_entropy_array()` | bind `mut`, `full.zeroize()` after copy |

**Note on three SECURITY comments** (in `unlock/mod.rs` at the IBK
construction sites, fixes #2/#3/#4): the comments correctly
identified the residue but suggested it was inherent to Rust ("known
Rust limitation, no MaybeUninit-aware fill_bytes"). The
`fill_bytes`-can't-be-MaybeUninit-aware part is true, but the
*post-move* zeroize is independently doable — and it's the fix the
rest of the crate already used. The new comments make this explicit.

**Note on existing well-disciplined sites** (all already correct, no
fix needed): `crypto::kem::derive_wrap_key`'s `key.zeroize()`,
`crypto::kem::generate_x25519`'s `sk_bytes.zeroize()`,
`crypto::kem::generate_ed25519`'s `sk_bytes.zeroize()`,
`crypto::kdf::derive_recovery_kek`'s `out.zeroize()`,
`crypto::kem::decap`'s `k.zeroize()`,
`crypto::kem::encap+decap`'s `ss_pq_bytes.zeroize()`,
`vault::block::encrypt_block`'s `bck_bytes.zeroize()`. The fixes
above bring the sister sites in those same modules up to the same
discipline.

---

## Resolved: record-content zeroize

The original audit deferred record-content zeroize as a v2 design
discussion. It was picked up in a follow-up pass while the FFI
surface had not yet shipped, which kept the cost of the public-API
change low.

[core/src/vault/record.rs:270-289](../../../core/src/vault/record.rs#L270-L289)
now reads:

```rust
pub enum RecordFieldValue {
    Text(SecretString),
    Bytes(SecretBytes),
}
```

Both wrappers derive `Zeroize, ZeroizeOnDrop`, redacted `Debug`, and
constant-time `PartialEq`. `Clone` is derived on the wrappers (with
a doc note) because conflict resolution legitimately duplicates field
values for collision reporting and proptest shrinking requires it;
the cloned allocation is itself zeroize-on-drop.

What stayed the same:

- **Wire format**: CBOR encode/decode go through `expose()` /
  `SecretBytes::new` / `SecretString::new` at the codec boundary, so
  the canonical byte representation is unchanged. The
  `core/fuzz/seeds/record/*.cbor` files re-encode bit-identically.
- **Python conformance verifier**
  ([core/tests/python/conformance.py](../../../core/tests/python/conformance.py)):
  unaffected. It compares encoded CBOR bytes, not in-memory Rust types.
- **Public API shape**: `RecordFieldValue::Text(_)` and `Bytes(_)` are
  still the two variants; only the inner type changed.

What changed for callers:

- Construction: `RecordFieldValue::Text("alice".into())` /
  `Bytes(payload.into())` continues to work via
  `From<&str> / From<String> for SecretString` and
  `From<Vec<u8>> / From<&[u8]> for SecretBytes`.
- Reading: `match` on the variant yields a `&SecretString` /
  `&SecretBytes`; readers must call `.expose()` to get the underlying
  `&str` / `&[u8]`.
- Equality: `==` still works (constant-time).

What is *not* covered (residual exposure on the codec boundary):

The encode path in
[core/src/vault/record.rs](../../../core/src/vault/record.rs) calls
`s.expose().to_owned()` / `b.expose().to_vec()` to copy the secret
bytes into a `ciborium::Value::{Text, Bytes}` before serialization.
`ciborium::Value` is **not** zeroize-on-drop, and the plaintext CBOR
buffer produced by `encode_canonical_map` is a plain `Vec<u8>`.
Symmetrically, on the decode path the inner `String` / `Vec<u8>`
inside the `ciborium::Value` is not zeroized before being moved
into `SecretString::new` / `SecretBytes::new`. The encrypt/decrypt
step downstream eventually drops these intermediate buffers, but
between the codec call and the AEAD call, the secret material lives
in heap allocations that will not be wiped on drop.

This is unchanged from the pre-`SecretString` situation — the same
exposure existed when the inner type was raw `String` / `Vec<u8>` —
but the resolution above does NOT close it. Tightening the codec
boundary would require either (a) a CBOR encoder that takes a
borrowed `&[u8]` / `&str` and writes directly to a zeroize-typed
output buffer, bypassing `ciborium::Value` for the secret-bearing
fields, or (b) a wrapping pre-pass that zeroizes the
`ciborium::Value` between encode and AEAD. Both are non-trivial
follow-ups; flagged here so the next reviewer doesn't read
"resolved" as stronger than it is.

## Resolved: newtype `Zeroize` / `ZeroizeOnDrop` derives on `MlDsa65Secret` and `MlKem768Secret`

The original audit deferred this as cosmetic: both newtypes wrap
`SecretBytes` (which IS `Zeroize, ZeroizeOnDrop`), so the inner
field's drop already zeroized the bytes. The gap was that neither
newtype implemented `Zeroize` itself, so callers could not call
`secret.zeroize()` on the outer type to wipe a still-live value
before its scope ends.

Resolved by adding `#[derive(Zeroize, ZeroizeOnDrop)]` to both
newtype tuple-structs at
[core/src/crypto/sig.rs](../../../core/src/crypto/sig.rs) and
[core/src/crypto/kem.rs](../../../core/src/crypto/kem.rs). The inner
`SecretBytes` field's drop continues to wipe the bytes on scope-end
(idempotent with the outer derive); the new exposure is purely
additive. Pinned by two integration tests at
[core/tests/sig.rs](../../../core/tests/sig.rs) and
[core/tests/kem.rs](../../../core/tests/kem.rs):
`ml_dsa_65_secret_zeroize_clears_inner_bytes` and
`ml_kem_768_secret_zeroize_clears_inner_bytes`.

## Deferred items (not addressed in this pass)

### 3. HKDF internal state residue

`hkdf = "0.12"` does not zeroize its internal HMAC state on drop.
[core/src/crypto/kdf.rs:216-223](../../../core/src/crypto/kdf.rs#L216-L223)
documents this as a SECURITY note on `derive_recovery_kek`, and the
same applies to `hkdf_sha256_extract_and_expand`. Eliminating the
residue requires either:
- A future `hkdf` release with `ZeroizeOnDrop`-derived internal state
  (upstream change);
- Rolling HMAC-SHA-256 manually with hand-zeroized state (substantial
  change, would deviate from the RFC 5869 KAT-pinned reference
  implementation).

**Why deferred:** out of our control until upstream `hkdf` ships
zeroize support. Watch upstream and re-evaluate when a new release
lands.

### 4. ML-KEM-768 / ML-DSA-65 internal state

`ml-kem = "0.2"` and `ml-dsa = "0.1.0-rc.8"` are RustCrypto crates
that we feed seeds and ciphertexts to. We don't control their
internal scratch memory. The side-channel audit
([side-channel-audit-internal.md](side-channel-audit-internal.md))
flagged `ml-dsa` 0.1.0-rc.8's pre-1.0 status for the paid external
reviewer; the same caveat applies to memory hygiene.

**Why deferred:** upstream-managed. The external reviewer should
verify both crates' drop discipline at their pinned versions.

---

## Out of scope for this internal pass

- **Cross-FFI memory hygiene** (Sub-project B): when the Rust core
  crosses an FFI boundary into Python / Swift / Kotlin, the foreign
  language's allocator and GC own a copy of any secret material
  passed across. The discipline there is Sub-project B's concern; the
  Rust core's job is to make sure its side of the boundary is clean.
- **Clipboard hygiene** (Sub-project D): when a user copies a
  password to the system clipboard, the clipboard daemon owns a copy
  the Rust core has no visibility into. Mitigation is platform-UI
  responsibility (clear-on-timeout, opt-in clipboard managers, etc.).
- **Swap-page exposure**: a system that swaps process memory to disk
  may persist secret bytes onto a non-encrypted swap partition.
  Mitigation is `mlock`/`VirtualLock` at process start, which is a
  platform-UI concern (and threat-model §2.7 puts kernel/OS issues
  out of scope anyway).

---

## Conclusion

The wrapper discipline is sound, the type-level invariants are right,
and twelve concrete stack-residue gaps were fixed by this pass. Each
fix follows a one-line pattern that already had instances in the
codebase — they were sister sites that hadn't yet been brought up to
the established discipline.

The follow-up pass also resolved record-content zeroize at the
in-memory-type level (see "Resolved" above): `RecordFieldValue::
{Text, Bytes}` now wrap `SecretString` / `SecretBytes`, so the
held representation of the most-sensitive data is zeroized on
drop alongside the keys. The wire format and Python conformance
are unchanged. The codec boundary itself still has residual
plaintext lifetime in `ciborium::Value` and the canonical-CBOR
output buffer (see "What is *not* covered" under Resolved); that
narrower gap is flagged for follow-up rather than closed by this
pass.

Memory-hygiene status: **clean for v1's Sub-project A scope at the
type level**, with the codec-boundary residue carved out as a
known-narrow follow-up. The Sub-project D clipboard / mlock
concerns and the upstream-managed crate items remain flagged for
the appropriate later phases.
