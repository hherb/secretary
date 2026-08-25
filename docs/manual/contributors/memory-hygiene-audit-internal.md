# Memory-hygiene internal audit

This document is the **memory-hygiene internal pass** called out in
[secretary_next_session.md](../../../secretary_next_session.md)'s Open
Item 3 → Memory hygiene audit. Companion to the
[side-channel internal audit](side-channel-audit-internal.md). Its
purpose is to walk every type that holds secret material in the Rust
core, verify its zeroize-on-drop discipline, and flag stack-residue
patterns where a secret value sits in a named-but-unzeroized stack
slot after being moved into a `Sensitive` wrapper.

**Scope:** the Rust core (`core/src/{crypto,identity,unlock,vault}/`) —
plus, as of the 2026-05-28 re-verification and the 2026-08-11 #513
panic-safe-secret-slots pass below, the three Rust-authored FFI crates
(`ffi/secretary-ffi-bridge/src`, `ffi/secretary-ffi-uniffi/src`,
`ffi/secretary-ffi-py/src`) to the extent that their own Rust-side stack
and heap slots wipe on every exit path. (An earlier version of this scope
line excluded cross-FFI hygiene outright while the "Cross-sub-project
discipline" section below already covered the bridge — that
inconsistency is fixed here rather than left standing.) Out of scope: the
*foreign runtime's* own copy of a marshalled secret once it crosses the
boundary (Python `bytes`, Swift `Data`/`[UInt8]`, Kotlin `ByteArray`) —
that is [`ffi-secret-handling-internal.md`](ffi-secret-handling-internal.md)'s
subject — platform-UI clipboard hygiene (Sub-project D), and
kernel/swap-page memory exposure (threat-model §2.7).

**Methodology:** for each named struct or type alias that wraps secret
bytes, verify (a) it derives `Zeroize, ZeroizeOnDrop` or composes them
via a wrapped field, (b) its `Debug`/`Clone`/`PartialEq` derives don't
defeat zeroize discipline, (c) the surrounding code zeroizes any
stack-residue copies after the secret is moved into the wrapper.

**Date:** 2026-05-02 (post-side-channel internal audit; 430 tests + 6
ignored on `main`). **Re-verified 2026-05-28** against the post-
Sub-project-B/C codebase — see the "Cross-sub-project discipline" and
"Re-verification" sections below. The line numbers cited in the
stack-residue table and the file-anchor citations have drifted by a few
lines per file as the modules have grown; the symbol-name citations
remain authoritative and, as of the 2026-05-28 re-verification, all
twelve `.zeroize()` post-move calls were confirmed present in the code as
it stood then. **That is no longer true as of this branch's own
2026-08-11 extension, and deliberately so**: two of the twelve — fix #1's
`kdf::derive_master_kek::out.zeroize()` and fix #2's
`unlock::create_vault`/`create_vault_unchecked::ibk.zeroize()` — are
removed below, because both slots are converted to `Sensitive::build` /
`try_build` and `Drop` covers the wipe unconditionally, leaving nothing
for the explicit call to do. Ten of the twelve remain present. **Extended
2026-08-11** (#513/#518/#503) — see "Panic- and error-safe secret slots"
below: the 2026-05-02 pass's own idiom wiped only on a normal-return
exit, its count was one short, and a 101-site census across the Rust core
and all three FFI crates closes both.

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
landing alongside this memo. **Correction (2026-08-11):** that count was
itself incomplete by one, and the fix idiom it used only ever covered a
normal-return exit — see "Panic- and error-safe secret slots" below,
which corrects both. The pattern was consistent: the
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
defines the three secret-bearing wrappers used throughout the crate
(the third, `SecretString`, was introduced by PR #16's
`RecordFieldValue` rewrap — see "Resolved: record-content zeroize"):

| Wrapper | Derive | Storage | Custom impls | Notes |
|---|---|---|---|---|
| `SecretBytes` | `Zeroize, ZeroizeOnDrop, Clone` | `Vec<u8>` (heap) | `Debug` (redacted, prints len only); `PartialEq, Eq` via `subtle::ConstantTimeEq` | `Clone` was added with PR #16 for conflict-resolution duplicate-detection and proptest shrinking; the cloned allocation is itself zeroize-on-drop. `Display` not implemented. |
| `SecretString` | `Zeroize, ZeroizeOnDrop, Clone` | `String` (heap) | `Debug` (redacted, prints len only); `PartialEq, Eq` via byte-slice `subtle::ConstantTimeEq` | Sibling of `SecretBytes` for human-readable secrets (passwords, secret notes, recovery phrases stored in records). |
| `Sensitive<T: Zeroize>` | `Zeroize, ZeroizeOnDrop` | `T` (typically `[u8; 32]` or `Vec<u8>`) | `Debug` (redacted, prints `<redacted>`) | Intentionally **does not** implement `PartialEq` — see the inline comment above the type definition in [secret.rs](../../../core/src/crypto/secret.rs): `subtle` only provides `ConstantTimeEq` for slices and integer primitives, and an `==` impl bounded on `T: ConstantTimeEq` would silently fail to apply to `[u8; N]`. Callers needing byte-equality compare slices via `a.expose()[..].ct_eq(&b.expose()[..])`. |

**All three wrappers are sound.** No changes recommended.

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
| 2 | `core/src/unlock/mod.rs::create_vault` (the `ibk` slot moved to `create_vault_unchecked` when `create_vault` became a floor-check wrapper; converted again in 2026-08-11's Task 6) | `ibk: [u8; 32]` after `Sensitive::new(ibk)` | `ibk.zeroize()` (replaces a SECURITY note that acknowledged but didn't apply the fix) |
| 3 | `core/src/unlock/mod.rs::open_with_password` | `ibk_arr: [u8; 32]` after `Sensitive::new(ibk_arr)` | `ibk_arr.zeroize()` |
| 4 | `core/src/unlock/mod.rs::open_with_recovery` | `ibk_arr: [u8; 32]` after `Sensitive::new(ibk_arr)` | `ibk_arr.zeroize()` |
| 5 | `core/src/vault/orchestrators.rs::save_block` | author Ed25519 SK temp `*expose()` | bind to `ed_sk_bytes`, zeroize after move |
| 6 | `core/src/vault/orchestrators.rs::share_block` | reader X25519 SK temp `*expose()` | bind to `x_sk_bytes`, zeroize after move |
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

> **Historical, as of 2026-08-11: none of those three comments still
> exists.** Two were removed before this pass; the last (the `ibk` block)
> was replaced by `Sensitive::build` in Task 6 — see "A 50th conversion"
> below. `grep -n "MaybeUninit" core/src/unlock/mod.rs` now returns nothing.
> The paragraph is kept because the *reasoning* is what a reviewer needs —
> "inherent to Rust" was the wrong diagnosis then and would be the wrong
> diagnosis again — but do not go looking for the comments it describes.

**Note on existing well-disciplined sites** (all already correct, no
fix needed): `crypto::kem::derive_wrap_key`'s `key.zeroize()`,
`crypto::kem::generate_x25519`'s `sk_bytes.zeroize()`,
`crypto::kem::generate_ed25519`'s `sk_bytes.zeroize()`,
~~`crypto::kdf::derive_recovery_kek`'s `out.zeroize()`~~,
`crypto::kem::decap`'s `k.zeroize()`,
`crypto::kem::encap+decap`'s `ss_pq_bytes.zeroize()`,
`vault::block::encrypt_block`'s `bck_bytes.zeroize()`. The fixes
above bring the sister sites in those same modules up to the same
discipline.

> **`derive_recovery_kek` is struck through as of 2026-08-11.** The 2026-05-02
> pass called it correct, and by that pass's standard it was: the wipe ran on
> every *return*. The 2026-08-11 pass reclassified it as WINDOW row 2 — an
> `.expect()` sits between the fill and the wipe, so an unwinding panic
> skipped it — and the call this entry cites no longer exists. The entry is
> struck rather than deleted because the reclassification is the point: a
> site can be exemplary under one threat model and a window under the next,
> and the six survivors in this list are exemplary only under the narrower
> one. Do not cite this list as evidence that a site needs no work.

---

## Panic- and error-safe secret slots (#513, #518, #503) — 2026-08-11 pass

**Correction to the count above:** the "twelve stack-residue gaps" this
document reported on 2026-05-02 undercounted by one. A thirteenth gap in
the identical shape — `unlock::mnemonic::generate`'s `entropy: [u8; 32]`
slot, moved into `Sensitive::new(entropy)` inside the returned struct
literal and never wiped — was missed in that pass and not found until the
per-slot census this section describes (design spec §3.4). It shares
`generate()` with fix #11 above (`full`) and sits right next to
`generate`'s true sibling function `parse()` — fix #12 above, not fix #5
— whose own `entropy` copy *is* wiped —
`generate`'s own doc comment claimed the same of `entropy` ("the local
32-byte entropy buffer is zeroized," true only of `entropy_buf`). This is
recorded as a correction, not a silent renumbering: the original twelve
fixes were real and remain correct as far as they went; the pass that
found them was not exhaustive, and this document says so rather than
quietly absorbing the fix. The thirteenth gap is closed alongside the
work below (row 5a in the table).

### The idiom above covers a normal return only

Every fix in the table above — and the pattern the "Cross-sub-project
discipline" section below holds Sub-projects B and C to — follows one
shape: fill a stack slot, copy or move it into a wrapper, then call
`.zeroize()` on the source slot to wipe the plaintext duplicate the
wrapper's construction left behind. That source slot is **not** already
empty at the point of that call — for the common `[u8; N]` (`Copy`) case
`Sensitive::new(x)` duplicates the bytes rather than invalidating `x`,
and that live duplicate is exactly the hazard the wipe exists to close;
"now-empty" would only be true immediately *after* the call succeeds.
This idiom wipes on the **happy-path return
only**. A secret slot is dirty between its last write and its wipe, and
there are three distinct ways to leave a function inside that window:

| exit class | description | covered by a trailing `.zeroize()`? |
|---|---|---|
| E1 | an unwinding panic | no |
| E2 | `?` on a fallible call after the fill | no |
| E3 | an explicit `return Err(...)` after the fill | no |

`#513` originally reported only E1 (three `device_secret` sites in
`ffi/secretary-ffi-uniffi`), rated low severity on the reasoning that "a
panic inside the bridge is not an expected path, the process is
typically about to die, and `panic = "abort"` would make it moot." **All
three clauses are wrong**, and this memo records why rather than let the
low-severity label stand uncorrected:

- `panic = "abort"` appears in no `.toml` in the workspace — unwinding is
  the real behaviour in both `dev` and `release`.
- Both FFI boundaries catch the unwind at the crate edge, so the host
  process does **not** die — it survives and reuses the same stack for
  its next call:

  | binding | site | behaviour |
  |---|---|---|
  | uniffi 0.32.0 | `uniffi_core/src/ffi/rustcalls.rs:207` | `panic::catch_unwind(callback)` → an unexpected-error return |
  | pyo3 0.29.0 | `pyo3/src/impl_/trampoline.rs:301` | `catch_unwind` → `PanicException::from_panic_payload` |

- E2 and E3 are not failure modes — they are ordinary, expected control
  flow — and `#513` never named them. The census below found two live
  E2/E3 leaks, filed as **#518**: the full 24-word recovery phrase in
  `unlock::mnemonic::parse` (leaked on the `WrongLength` return and on the
  `UnknownWord`/checksum `?` — the latter is the single most common way
  this function fails, hit repeatedly by a user recovering a vault by
  hand), and the two raw Ed25519/X25519 secret keys decoded mid-parse in
  `unlock::bundle::from_canonical_cbor` (leaked on the `MissingField` `?`
  chain — real but lower severity, since reaching that code means the
  bundle ciphertext was already decrypted).

### The fix: wrap before filling, not fill-then-wipe

`Sensitive<T>` gained two constructors
([`core/src/crypto/secret.rs`](../../../core/src/crypto/secret.rs)):
`build(init, f)` for infallible fills, `try_build(init, f)` for fallible
ones. Both wrap the value **before** `f` runs, so the wrapper — and its
`ZeroizeOnDrop` — is live for the entire fill:

```rust
// before — correct only if control reaches the last statement
let mut secret_arr = [0u8; 32];
array32_from_vec_into(src, &mut secret_arr, "device_secret")?;
let result = bridge::open_with_device_secret(&path, &uuid, &secret_arr);
secret_arr.zeroize();

// after — Drop wipes on every exit: return, `?`, or unwinding panic
let secret = Sensitive::try_build([0u8; 32],
    |slot| array32_from_vec_into(src, slot, "device_secret"))?;
let result = bridge::open_with_device_secret(&path, &uuid, secret.expose());
```

`zeroize::Zeroizing<T>` was considered and **rejected**: it derives
`Debug` (forwarding to the inner value — a stray `{:?}` prints the
secret) and a derived, variable-time `PartialEq`. Both are properties the
wrapper table above records as deliberate omissions on `Sensitive<T>` /
`SecretBytes` / `SecretString`; adopting `Zeroizing` would have added a
fourth secret wrapper that regresses on exactly the two properties this
memo treats as load-bearing. Two other shapes were considered and
rejected before `try_build` — a permanent `expose_mut(&mut self) -> &mut
T` accessor, and a `Scratch<T>` newtype with the same accessor — because
both hand out a standing mutable borrow of a live secret (`mem::swap` the
secret out, and `Sensitive`'s `Drop` wipes whatever was swapped *in*
instead), the same laundering-shape class the `#474`→`#480`→`#486`→`#500`
FFI error-payload work spent four PRs closing, reintroduced here at the
type level. `try_build`'s `&mut` is scoped to one closure written at the
call site instead of a standing capability on the type — reviewable, not
eliminated; see design spec §2.2/§7 for the full comparison and the
residual risk this leaves.

### Census method and reconciliation

Classification is per-site and manual (design spec §3.1): a naive
"is there a call between the fill and the wipe" matcher reports every
site as windowed, because `Sensitive::new(x)` is syntactically a call but
cannot panic — the first automated pass returned `adjacent=0` across all
four scan roots, an artifact rather than a result. Every verdict below
was reached by reading the enclosing function and, where the intervening
call is into a third-party crate (`x25519-dalek`, `ml-kem`, `ml-dsa`,
`pyo3`), that crate's own source. It is a point-in-time claim of exactly
the kind
[`error-payload-hygiene-allowlist.txt`](../../../scripts/error-payload-hygiene-allowlist.txt)
Section 3 holds, recorded as such — no CI guard enforces it (design spec
§6: a per-site judgement of this kind is not something a text matcher can
make; it will drift as `core/` and the FFI crates change).

The raw `grep -rn "\.zeroize()" core/src ffi --include="*.rs"` count
**measured against the pre-conversion tree at merge-base `9c187946`** is
**107**; 6 of those are comment references (doc comments, `//` lines
describing the pattern) rather than calls, leaving **101 real call
sites**, each classified below.

**A prior version of this paragraph said 108 raw / 7 comment-only at the
merge-base, not 107/6 — verified wrong, four independent ways** (a
merge-base worktree checkout, an independent `git archive` extraction,
and by-hand re-classification of every one of the matched lines as
comment-or-real, all agreeing on 107/6/101). The 108th hit the wrong
figure was counting is
`ffi/secretary-ffi-py/tests/test_device_slot.py:122` — a `.py` file,
which the `--include="*.rs"` flag in the command above excludes, so it
cannot appear in that command's own output; the command was quoted
verbatim just above the wrong number. `108`/`7` is real, but it is the
count at a *later*, branch-local point in this pass's own history —
Task 1, which added a `.zeroize()` doc comment at
`core/src/crypto/secret.rs:190` — and got misattributed here to the
merge-base the census in the next section actually started from. (Cited
by task, not commit SHA, for the same reason as the WINDOW table below:
`main` squash-merges, so a branch-local SHA dangles the moment this
branch lands — the exact failure mode H1 exists to eliminate.) The
real-call total, **101**, is unaffected either way; only the raw count
and the comment-only split at the starting point were wrong, by exactly
one each.

**Running the same command against the tree this pass ships in gives
different, smaller numbers — `81` raw / `51` real, re-verified by
execution — and that is expected, not a discrepancy to chase.** The 49
WINDOW conversions below each replaced an explicit `.zeroize()` call with
`Drop`, removing that raw grep hit; several of those same sites gained an
explanatory comment mentioning `#513` or the old idiom, which the same
grep also matches, so the drop in the *real*-call count (101 → 51) is
larger than the drop in the raw count (107 → 81). Per-root, the
post-conversion real-call counts are `core/src` 43,
`ffi/secretary-ffi-bridge/src` 8 (unchanged — this crate needed no
conversion), `ffi/secretary-ffi-uniffi/src` 0, `ffi/secretary-
ffi-py/src` 0 — the last two hitting zero is the expected shape, since
every real call site in those two roots was WINDOW and got converted. If
you run the grep below and get `107`/`101`, you are reading `main`
before this pass landed; `81`/`51` is this tree, after — and that number
moves again with every doc-comment edit this file itself makes to a
`.zeroize()`-adjacent line, which is precisely how it went from `79` to
`81`: two of this file's own review-response comments (in
`core/src/unlock/bundle.rs` and `ffi/secretary-ffi-py/src/errors.rs`)
themselves contain the literal text `` `.zeroize()` ``, and the grep
below does not distinguish prose from code:

| root | real call sites (pre-conversion, at `9c187946`) | WINDOW (converted) | ADJACENT (no window, unchanged) | TEST-ONLY | DROP-IMPL | EARLY-WIPE-OF-WRAPPED |
|---|---|---|---|---|---|---|
| `core/src` | 53 | 9 | 40 | 3 | 1 | 0 |
| `ffi/secretary-ffi-bridge/src` | 8 | 0 | 4 | 0 | 0 | 4 |
| `ffi/secretary-ffi-uniffi/src` | 3 | 3 | 0 | 0 | 0 | 0 |
| `ffi/secretary-ffi-py/src` | 37 | 37 | 0 | 0 | 0 | 0 |
| **Total** | **101** | **49** | **44** | **3** | **1** | **4** |

`49 + 44 + 3 + 1 + 4 = 101`; `101 + 6` (comment-only) `= 107`, matching
the pre-conversion raw grep count at `9c187946`. This table is a
classification of that pre-conversion snapshot — the WINDOW column is
"how many of these 101 got converted," so the table is necessarily
historical; it does not re-measure against the post-conversion tree.
Category definitions:

- **WINDOW** — a real exit (E1, E2, or E3) is reachable between the fill
  and the wipe; converted to `Sensitive::build` / `try_build` (or an
  equivalent wrapper-typed local).
- **ADJACENT** — no fallible or panicking operation intervenes between
  the fill and the wipe (frequently a `?` that belongs to the *fill
  itself*, firing before the slot is even bound); left unconverted, per
  design spec §6 — with one deliberate exception, converted anyway; see
  "A 50th conversion" after the WINDOW table below.
- **TEST-ONLY** — a `.zeroize()` call inside `#[cfg(test)]` exercising a
  type's `Zeroize` derive directly, not the fill-then-wipe idiom.
- **DROP-IMPL** — the call is inside a hand-written `Drop::drop` body,
  which runs on every exit path by language guarantee; there is no
  statement for control flow to skip.
- **EARLY-WIPE-OF-WRAPPED** — an explicit early `.zeroize()` on a field
  whose declared type is already `Sensitive<T>`; the owning struct's own
  `Drop` wipes the same bytes on every exit this call might miss, so it
  is defensive, not load-bearing.

The full per-site table — including the reasoning behind each of the 44
ADJACENT / 3 TEST-ONLY / 1 DROP-IMPL / 4 EARLY-WIPE-OF-WRAPPED rows this
summary doesn't reproduce in full — lives in the tree at
[`docs/superpowers/plans/2026-08-11-513-census.md`](../../superpowers/plans/2026-08-11-513-census.md).
It was deleted once, at the end of implementation, on the theory that git
history was sufficient recovery; it is restored here instead, because
`main` squash-merges (its last several commits are single-parent with a
trailing `(#N)`), so a plan file that exists only in branch history is
gone the moment this branch lands on `main` — `git log --all -- '<path>'`
and `git show <commit>^:<path>` both work in this feature-branch worktree
and both return nothing against a squashed `main`. Keeping the file in
the tree is the actual fix; a recovery recipe for an unreachable commit
is not one. Of that file's rows, **52 are non-WINDOW** (44 ADJACENT + 3
TEST-ONLY + 1 DROP-IMPL + 4 EARLY-WIPE, as enumerated just above) and are
not duplicated here, because 51 of them changed no code and their reasoning
is either trivial ("only `Sensitive::new` intervenes," the dominant shape
below) or already in the design spec's §3.2/§3.3 — this memo's job is to
record what changed and why, and to give a future auditor enough to
re-derive the rest. (That 52 is a **subtotal, not the file's row count**;
the census has considerably more rows than 52, and an earlier version of
this sentence said "the file's 52 rows", which sent a reviewer counting for
a number that appears nowhere in it.) The 52nd non-WINDOW row
— `unlock/mod.rs::create_vault_unchecked`'s `ibk` slot, classified
ADJACENT but converted anyway — is the one exception; see "A 50th
conversion" after the WINDOW table below. Separately, the handful of
ADJACENT judgements that needed third-party source verification are
restored below rather than left to the census file alone, since that
verification is the least re-derivable content the census had.

### The 49 WINDOW sites — fixed by this pass

The last column names the implementation-plan task
([`docs/superpowers/plans/2026-08-11-513-panic-safe-secret-slots.md`](../../superpowers/plans/2026-08-11-513-panic-safe-secret-slots.md))
that converted each site, not a commit SHA: `main` squash-merges (its last
several commits are single-parent with a trailing `(#N)`), so the 8
branch-local SHAs an earlier version of this table cited here go dangling
the moment this branch lands — a reviewer cloning `main` and running
`git show <sha>` gets "bad object." The task headings are a stable pointer
because the plan file itself stays in the tree (unlike the census file
above, which didn't and is restored for the same reason).

| # | File::function | Slot(s) | Exit class | Fixed in (task) |
|---|---|---|---|---|
| 1 | `core/src/crypto/kdf.rs::derive_master_kek` | `out` | E1; E2 only nominally — see note | `try_build` — Task 3 |
| 2 | `core/src/crypto/kdf.rs::derive_recovery_kek` | `out` | E1 (`.expect()` in fill) | `build` — Task 3 |
| 3 | `core/src/crypto/kdf.rs::derive_device_kek` | `out` | E1 | `build` — Task 3 |
| 4 | `core/src/crypto/kem.rs::derive_wrap_key` | `ikm` | E1 (holds *both* KEM shared secrets) | wrapped earlier — `SecretBytes::new` moved before the HKDF call — Task 3 |
| 5 | `core/src/unlock/mnemonic.rs::generate` | `entropy_buf` | E1 | `build` — Task 4 |
| 5a | `core/src/unlock/mnemonic.rs::generate` | `entropy` (§3.4 — the thirteenth gap; never wiped at all, not itself a window) | n/a | built in place via `build`, alongside 5's conversion — Task 4 |
| 6 | `core/src/unlock/mnemonic.rs::parse` | `normalized` | E2 + E3 (#518) | `SecretString::new` — Task 4 |
| 7 | `core/src/unlock/bundle.rs::from_canonical_cbor` | `x25519_sk_bytes` | E2 (#518) | `Option<Sensitive<[u8; N]>>` decode-loop binding — Task 5 |
| 8 | `core/src/unlock/bundle.rs::from_canonical_cbor` | `ed25519_sk_bytes` | E2 (#518) | same shape — Task 5 |
| 8a | `core/src/unlock/bundle.rs::from_canonical_cbor` | `ml_kem_768_sk_bytes`, `ml_dsa_65_sk_bytes` (the FOURTEENTH gap; never wiped at all, like 5a — see the note below this table) | E2 | `Option<Sensitive<Vec<u8>>>` decode-loop binding — review round 2 |
| 9 | `core/src/unlock/mod.rs::create_vault_unchecked` | `bundle_plaintext` | E1 | `SecretBytes::new` — Task 6 |
| 10 | `ffi/secretary-ffi-uniffi/src/namespace/mod.rs::open_with_device_secret` | `secret_arr` | E1 (the site `#513` itself named) | `try_build` — Task 9 |
| 11 | `ffi/secretary-ffi-uniffi/src/namespace/repair.rs::repair_with_device_secret` | `secret_arr` | E1 | `try_build` — Task 9 |
| 12 | `ffi/secretary-ffi-uniffi/src/namespace/repair.rs::preview_repair_with_device_secret` | `secret_arr` | E1 | `try_build` — Task 9 |
| 13 | `ffi/secretary-ffi-py/src/repair_preview.rs::preview_repair_with_password` | `password` | E1 | wrapped before the bridge call — Task 8 |
| 14 | `ffi/secretary-ffi-py/src/repair_preview.rs::preview_repair_with_recovery` | `mnemonic` | E1 | wrapped before the bridge call — Task 8 |
| 15 | `ffi/secretary-ffi-py/src/repair_preview.rs::preview_repair_with_device_secret` | `device_secret`, `secret_arr` | E1 | wrapped before the bridge call — Task 8 |
| 16 | `ffi/secretary-ffi-py/src/device.rs::DeviceSecretOutput::take_secret` | `v` | E1 (fix round 1 — pyo3 `PyBytes::new` panics on OOM) | wrapped before the accessor call — Task 8 |
| 17 | `ffi/secretary-ffi-py/src/device.rs::add_device_slot` | `password` | E1 | wrapped before the bridge call — Task 8 |
| 18 | `ffi/secretary-ffi-py/src/device.rs::open_with_device_secret` | `device_secret`, `secret_arr` | E1 | wrapped before the bridge call — Task 8 |
| 19 | `ffi/secretary-ffi-py/src/repair.rs::repair_with_password` | `password` | E1 | wrapped before the bridge call — Task 8 |
| 20 | `ffi/secretary-ffi-py/src/repair.rs::repair_with_recovery` | `mnemonic` | E1 | wrapped before the bridge call — Task 8 |
| 21 | `ffi/secretary-ffi-py/src/repair.rs::repair_with_device_secret` | `device_secret`, `secret_arr` | E1 | wrapped before the bridge call — Task 8 |
| 22 | `ffi/secretary-ffi-py/src/unlock.rs::MnemonicOutput::take_phrase` | `v` | E1 (fix round 1) | wrapped before the accessor call — Task 8 |
| 23 | `ffi/secretary-ffi-py/src/unlock.rs::open_with_password` | `password` | E1 | wrapped before the bridge call — Task 8 |
| 24 | `ffi/secretary-ffi-py/src/unlock.rs::open_with_recovery` | `mnemonic` | E1 | wrapped before the bridge call — Task 8 |
| 25 | `ffi/secretary-ffi-py/src/unlock.rs::create_vault` | `password` | E1 | wrapped before the bridge call — Task 8 |
| 26 | `ffi/secretary-ffi-py/src/unlock.rs::create_vault_in_folder` | `password` | E1 | wrapped before the bridge call — Task 8 |
| 27 | `ffi/secretary-ffi-py/src/record.rs::FieldHandle::expose_text` | `s` | E1 (fix round 1) | wrapped before the accessor call — Task 8 |
| 28 | `ffi/secretary-ffi-py/src/record.rs::FieldHandle::expose_bytes` | `v` | E1 (fix round 1) | wrapped before the accessor call — Task 8 |
| 29 | `ffi/secretary-ffi-py/src/vault.rs::open_vault_with_password` | `password` | E1 | wrapped before the bridge call — Task 8 |
| 30 | `ffi/secretary-ffi-py/src/vault.rs::open_vault_with_recovery` | `mnemonic` | E1 | wrapped before the bridge call — Task 8 |

Rows 13-30 (18 functions) account for all 37 `ffi/secretary-ffi-py/src`
real call sites — several functions hold more than one windowed slot
(e.g. row 18's `device_secret` **and** `secret_arr`), so the row count is
per-function, not per-line; the census's row-by-row line count sums to
37 exactly. Four of these rows (16, 22, 27, 28) were originally
misclassified during this pass's own census as "accessor hand-out — a
different pattern, not a window," traced to a withdrawn dispatch
instruction rather than a fabricated citation, and corrected before any
code was converted (census "fix round 1"); all four are genuine E1
windows, verified against pyo3 0.29.0 source (`PyBytes::new` /
`PyString::new` → `assume_owned` → `Bound::from_owned_ptr` →
`panic_on_null` on a null pointer, `src/instance.rs:2425-2430`).

**Row 1's exit class, stated precisely.** The `?` on `derive_master_kek`'s
Argon2 fill does skip the pre-#513 trailing wipe, which is why the row was
first recorded as E2. But for that call's concrete shape (`out: [u8; 32]`,
`output_len = Some(32)`) argon2 0.5.3 never writes `out` on an error path:
the two length checks and `verify_inputs` precede any write, `initial_hash`
takes `out` as an immutable `&[u8]`, `fill_blocks` never receives it, and
`finalize`'s only write goes through `blake2b_long`'s `out.len() <= 64`
short path, which writes on success alone. So there was no partially-derived
KEK to leak, and the row's real window is E1. The conversion still earns its
place — it stops the guarantee depending on a reading of a third-party
crate's internal statement ordering — but this table claimed an observed
leak where there was none, and the code comment at `kdf.rs` now records the
distinction. Found in the whole-branch review; the same review found the
FOURTEENTH gap at row 8a.

**Row 8a — the fourteenth gap.** `ml_kem_768_sk_bytes` and
`ml_dsa_65_sk_bytes` were `Option<Vec<u8>>` while their X25519 / Ed25519
siblings (rows 7, 8) became `Sensitive` in Task 5. Being `Vec`, they are
moved rather than copied out — but only on the path that REACHES the move;
on any `?` at an earlier field of the struct literal they were still
`Some(..)`, and a plain `Vec<u8>` frees its heap buffer without zeroizing.
That released a 2400-byte ML-KEM-768 decapsulation key and an ML-DSA-65
secret key to the allocator intact. Like row 5a this was invisible to the
idiom census — the census greps for `.zeroize()` calls and these never had
one — which is now the second time that method has missed a never-wiped
slot. Treat "has no wipe to find" as its own search, not a corollary of the
grep. Pinned by
`from_canonical_cbor_early_return_leaves_both_pq_secret_keys_wrapped`.

**A 50th conversion, outside this table.**
`unlock/mod.rs::create_vault_unchecked`'s `ibk` slot — same function as
row 9's `bundle_plaintext`, same commit, Task 6 — was also converted to
`Sensitive::build`, even though the census classifies it ADJACENT: only
`rng.fill_bytes` intervenes between the fill and the wrap, and that call
cannot fail, so there is no window there to fix. Design spec §3.3
pre-authorised converting it anyway ("adjacent (`fill_bytes`, converted
opportunistically — see plan)"), on the reasoning that `Sensitive::build`
states the invariant in one line where five lines of SECURITY comment
previously explained why the post-move wipe was the best available
discipline — it no longer is, so there was no reason to keep the weaker
idiom on a site this cheap to upgrade. This pass therefore converts
**50** sites total — the 49 WINDOW conversions in the table above, plus
this one opportunistic ADJACENT conversion — not 49. It is also why
"Don't convert a provably-adjacent site … for consistency" (the rule this
pass adds to CLAUDE.md's memory-hygiene section) does not contradict this
site being converted: the rule is about unforced churn on frozen-adjacent
crypto code, and this conversion was forced by nothing but was authorised
in the design spec before it was made, not applied after the fact "for
consistency."

Separately, **#503** (`array32_or_value_error(...) -> PyResult<[u8; 32]>`,
a by-value producer that handed back an unwrapped stack array) is now
closed on its ffi-py half — a prior fix had closed only the uniffi side.
`array32_into_or_value_error` now writes through into an already-wrapped
slot (Task 7), so there is never an unwrapped
`[u8; 32]` holding a secret on the stack at any point in either binding
crate.

### 44 ADJACENT + 3 TEST-ONLY + 1 DROP-IMPL + 4 EARLY-WIPE-OF-WRAPPED — no conversion

Left exactly as-is, per design spec §6 ("no conversion of the no-window
sites" — converting a non-windowed crypto site is churn on
frozen-adjacent code for zero gain) — with one deliberate exception:
`unlock/mod.rs::create_vault_unchecked`'s `ibk` slot is counted among the
44 ADJACENT rows here but was converted anyway; see "A 50th conversion"
above. The dominant ADJACENT shape, seen
repeatedly across `crypto/kem.rs::decap`, `crypto/sig.rs`,
`sync/prepare.rs`, `sync/commit/write.rs`,
`vault/repair/orchestration.rs`, and `vault/device_slot.rs`:

```rust
let mut sk_bytes = sk.to_bytes();
let secret = Sensitive::new(sk_bytes);   // cannot panic, cannot return: no window
sk_bytes.zeroize();
```

Six of the ADJACENT judgements above, across three call sites, needed
more than "only `Sensitive::new` intervenes" — the intervening call was
into a third-party crate, so the "cannot panic" claim rests on having
read that crate's own source at the pinned version. Restored here rather
than left git-history-only, since design spec §3.2/§3.3 covers the
trivial ADJACENT rows but carries none of these three vendor citations,
and a future auditor re-deriving them would otherwise have to redo the
source reading from scratch:

- `crypto/kem.rs::decap`'s `sk_x_bytes` — the intervening
  `XStaticSecret::from(sk_x_bytes)` was checked against `x25519-dalek`
  2.0.1 (`x25519.rs:248`: `StaticSecret(bytes)`, a bare tuple-struct wrap
  — cannot panic).
- `crypto/kem.rs::decap`'s `dk_arr` — the intervening
  `Dk::from_bytes(&dk_arr)` was checked against `ml-kem` 0.2.3
  (`kem.rs:53`, `pke.rs:85`/`138`: fixed-size polynomial decode over
  `hybrid_array::Array<u8, N>`, no fallible ops in the traced path).
- `crypto/sig.rs::generate_ml_dsa_65`'s `seed_bytes`/`seed` (two slots),
  and `crypto/sig.rs::sign`'s `seed_arr`/`seed` (two more) — four slots
  under one citation, since all four call through the identical
  `MlDsa65::from_seed(&seed)` — checked against `ml-dsa` 0.1.0-rc.8
  (`lib.rs:890-943`: the `impl<P> KeyGen for P` block's `from_seed`,
  deterministic XOF-based sampling over fixed-size `B32`/`B64`, no
  `unwrap`/`expect`/`assert` in the traced path).

`ffi/secretary-ffi-bridge/src`'s 4 EARLY-WIPE-OF-WRAPPED sites
(`revoke/orchestration.rs`, `share/orchestration.rs`) are an explicit
early `.zeroize()` on `identity_clone.ed25519_sk` /
`identity_clone.ml_dsa_65_sk` — both already `Sensitive`-typed fields
whose owning struct is dropped (and re-wipes the same bytes) later in
the same function; not a window by construction. The bridge's other 4
real call sites are ordinary ADJACENT `wrap; zeroize;` pairs — this crate
needed no conversion at all.

### Spec §5.4's stated limit

A wipe of freed heap or a dead stack frame is **not observable from safe
Rust** — there is no per-site "assert the bytes are gone" test, and this
pass does not claim one exists. The per-site argument is **type-level**,
not assertion-based: once a local is wrapper-typed, `Drop` is
unconditional and no control-flow path opts out of it. That is strictly
stronger than the idiom it replaces, where every site's correctness was
an independent claim about statement ordering — and, per the E1/E2/E3
table above, two of those claims (`#518`'s two leaks) were false.

What **is** directly tested is the mechanism the type-level argument
rests on:
[`core/tests/secret_panic_safety.rs`](../../../core/tests/secret_panic_safety.rs)
proves `Sensitive`'s `Drop` runs — and wipes — while the stack is
**unwinding**, not merely on a normal return, plus the `try_build` API's
three cases (writes land; a returned `Err` propagates and still wipes; a
panicking fill still wipes). A reviewer mutation-tested the unwind proof:
reverted `try_build` to the old fill-then-wrap shape it replaces, ran the
suite 50 times under parallelism, and it caught the regression 50/50. Do
not overclaim beyond this: the test proves the mechanism fires on every
run it was exercised; it does not and cannot prove the freed memory is
unreadable.

### Open issue: #519 — four secret accessors in `ffi/secretary-ffi-uniffi` have no Rust-side wipe at all

`ffi/secretary-ffi-uniffi/src/wrappers/{device,identity,block}.rs` expose
four one-line forwarders — `take_secret`, `take_phrase`, `expose_text`,
`expose_bytes` — that hand a `Vec<u8>` / `String` back to generated
uniffi scaffolding with **no local `.zeroize()` call at all**; their doc
comments push the obligation across the FFI boundary ("Caller MUST
zeroize after use"). This is deliberately **not** folded into the WINDOW
list above: there is no existing local/zeroize call to wrapper-type,
because this project uses UDL scaffolding
(`uniffi::include_scaffolding!`), so the `lower()` call that serialises
and frees the returned value runs in **generated** code this crate does
not own. Fixing it needs either a custom UDL type with a hand-authored
`Lower`/`Lift` that wipes after serializing, or upstream uniffi support —
a materially different, larger change than this pass's mechanical
`Sensitive::build` conversions, deliberately left for its own design
discussion rather than force-fit here. Tracked as **#519**; not closed by
this pass.

---

## Residual closeout (2026-08-23) — #542, #522, #524, #521

A follow-up slice closing the six residuals PR #520's whole-branch review
and the #526 desktop review left behind, plus the one live remnant of
audit finding C-4. Cited below by issue number, not by any of this
slice's own branch-local commit SHAs: `main` squash-merges, so those SHAs
stop resolving the moment the enclosing PR lands — the same discipline
"The 49 WINDOW sites" section above already applies, for the same reason.

### `take_fixed_bytes` had three residues, not one

This memo never mentioned `take_fixed_bytes` by name (`grep -n
take_fixed_bytes docs/manual/contributors/memory-hygiene-audit-internal.md`
returned nothing before this section). Decoding a fixed-size secret key out
of the §5 CBOR map had **three** unwiped copies, not the one its issue
named:

1. The `[u8; N]` array in `take_fixed_bytes`'s own stack frame, produced
   by `Vec::try_into`.
2. A second copy in the caller's return-value temporary — `Vec::try_into`
   returns by value, so the array is copied again on the way out.
3. The CBOR byte string's **heap** buffer itself. `Vec::try_into` reaches
   its array via `set_len(0)` + `ptr::read` — a copy, not a move-out — so
   the original heap allocation is deallocated with the secret key still
   in it, unwiped. This is the worst of the three: heap residue can
   outlive the stack frame that touched it.

Residue 3 is not a new finding — it is the 2026-07-02 audit's finding
**C-4**: the canonical re-encode buffer was closed by #357, the bundle
plaintext by #513 Task 6 (see "Panic- and error-safe secret slots" above),
and the `Copy`-typed locals by #518.

**C-4 is NOT fully closed, and an earlier version of this paragraph said it
was.** That claim called residue 3 "C-4's last live sub-item"; the #546
review found the audit's own FIRST-named read-side sub-item still open —
`from_canonical_cbor`'s ciborium `Value` tree (`let map = match value {
Value::Map(m) => m, ... }`) is a bare `Vec<(Value, Value)>`, and the loop
that consumes and wipes it does so on the happy path only. Any early `?`
inside that loop — `Malformed`, `DuplicateField`, `WrongKeySize`,
`UnknownField` — drops the iterator with up to **four** long-term secret
keys still populated, not three as an earlier version of this paragraph
said (#547 Task 8 review — corrected here rather than silently reworded).
Canonical RFC 8949 §4.2.1 key order (length-then-bytewise, recomputed by
hand for all eleven §5 fields during Task 7's own review) puts
`user_uuid` and `x25519_pk` first among the bundle's map entries — both
non-secret — so a `Malformed`/`UnknownField` firing on either of those two
leading entries leaves every one of the four secret-key entries
(`x25519_sk`, `ed25519_sk`, `ml_dsa_65_sk`, `ml_kem_768_sk`) still
unconsumed in the remainder of the list. Tracked as **#548**. Read this
section as closing residues 1-3 of the DECODE HELPERS, not C-4 entire.

Fixed by replacing the by-value `take_fixed_bytes` with write-through
`take_fixed_bytes_into<const N: usize>(v: Value, field: &'static str, out:
&mut [u8; N]) -> Result<(), BundleError>`
([`core/src/unlock/bundle.rs`](../../../core/src/unlock/bundle.rs)): the
destination is a caller-owned slot already wrapper-covered by
`Sensitive::try_build` at both secret-key call sites, so no unwrapped
`[u8; N]` is ever materialised in this function's frame or returned by
value (residues 1 and 2 gone by construction), and the source `Vec` is
wrapped in `SecretBytes` before the length check runs, so `Drop` covers
every exit — including the wrong-length `return` — with no trailing
statement for control flow to skip (residue 3 closed). The by-value
producer was **deleted**, not kept alongside the write-through version as
a sibling, per #503's principle: removing the unsafe shape makes it
awkward to write again rather than merely discouraged.

`take_sized_bytes` (the sibling helper for the two `Vec`-typed ML-KEM /
ML-DSA keys) had only the heap-residue half of the same defect: its
success path already moved the `Vec` into `Sensitive::new` untouched, but
its wrong-length **reject** path freed the same secret-key-shaped byte
string unwiped.

Its first fix wrapped in `SecretBytes` before the length check and returned
`Ok(bytes.expose().to_vec())` — which closed the reject path but ADDED a
full extra copy of the 2400-byte ML-KEM-768 decapsulation key on every
successful unlock, under a comment asserting "ownership of the same heap
buffer transfers and no copy is made". `expose()` yields `&[u8]`;
`to_vec()` allocates. The #546 review caught it.

It is now split by intent, and neither half copies:

- `take_sized_secret` returns `Sensitive<Vec<u8>>`. `Sensitive::new` MOVES
  the `Vec`, the length check runs through the wrapper, and the success
  path returns that same wrapper — covered from before the check, zero
  copies, and no claim needed about what the caller does next.
- `take_sized_public` keeps the by-value `Vec<u8>` shape for the two public
  keys, which need no wrapper.

Naming them apart is the point: choosing the by-value shape for a secret is
now a visible decision at the call site rather than the default, the same
reason the by-value `take_fixed_bytes` was deleted rather than kept.

### C-4's write side (#542) — untracked until this slice, now closed

C-4's *read*-side sub-items (above) were all that had issues filed against
them. Its **write** side had none, and was still open: `to_canonical_cbor`
clones every one of the bundle's four long-term secret keys into a
`ciborium::Value::Bytes` before encoding, and `ciborium::Value` has no
zeroizing `Drop` — so all four clones were freed unwiped on every vault
create and every unlock (the canonicality check inside
`from_canonical_cbor` re-encodes, so the read path pays this cost too).
This slice filed and closed it as #542.

The fix is `ZeroizingEntries`, a newtype around the entry list
`to_canonical_cbor` builds
([`core/src/unlock/bundle.rs`](../../../core/src/unlock/bundle.rs)):
`Drop` walks the list and zeroizes every `Value::Bytes` payload, covering
the unwinding-panic and early-return paths a trailing sweep after
`encode_map` would have missed — the same `Drop`-over-trailing-statement
reasoning as `Sensitive::build`/`try_build` above, applied to a type this
crate does not own and therefore cannot give a zeroizing `Drop` of its
own.

**`ZeroizingEntries` covered LESS than this section originally claimed.**
The #546 review found that `encode_map` — called on the very next line —
did `pair.clone()` on every entry. `ciborium::Value` derives `Clone` with
`Bytes(Vec<u8>)`, so that deep-copied all four secret keys into a second
list, moved them into a `Value::Map`, and freed that **unwiped on every
call** — every vault create and, via the canonicality re-encode, every
unlock. The wrapper had moved the leak, not removed it, while this memo and
the type's doc comment both described the write side as closed. That is the
"documentation claiming more coverage than the code delivers" pattern
CLAUDE.md flags as this line of work's most repeated review finding,
committed in the section recording the fix.

Fixed in #546: `encode_map` now takes `&ZeroizingEntries` (so the wrapper
is not optional at its only call site — passing the inner slice made
reverting to a bare `vec![…]` compile and pass the whole suite), sorts
**indices** while the values ride along as borrows, and serialises through
a `BorrowedCanonicalMap` `Serialize` impl instead of building an owning
`Value::Map`. No clone is made at all. Its output buffer is also
pre-reserved against an upper bound so `into_writer` cannot grow it — a
realloc there would free an unwiped block holding the full cleartext CBOR.

**The remaining boundary, stated rather than glossed** (it is recorded in
the type's own doc comment, and repeated here because a handoff memo is
where a future auditor will look first): the `vec![…]`
literal that builds the entry list constructs every clone **before**
`ZeroizingEntries` takes ownership of the resulting `Vec`. If that
literal itself unwinds partway through — after some elements are built,
before the `vec!` expression completes — the already-built elements drop
as bare temporaries, outside the wrapper, unwiped. The only unwind source
inside a `vec![…]` literal of `Value` clones is allocation failure, and
allocation failure **aborts** rather than unwinds in this workspace's
configuration, so the gap is not a live path today — but it is real, and
it is not the "covered on every exit" completeness the wrapper has once
construction finishes. Do not read "`ZeroizingEntries` closes C-4's write
side" as "every intermediate `Value::Bytes` clone is covered from the
instant it exists" — it is covered from the instant the wrapper takes
ownership of the completed `Vec`, one statement later.

### `SecretBytes::concat` — and why it is not `build`/`try_build`

#524 asked for `Sensitive`/`SecretBytes`'s existing `build`/`try_build`
constructor pair, the shape "Memory hygiene: zeroize discipline" above
recommends for any secret-bearing local live across a fallible call. For
`derive_wrap_key`'s `ikm` — six slices concatenated into one HKDF input —
that closes the **panic-during-fill** window but not the hazard #524's own
issue text called out as the sharp edge: **`build`/`try_build` do not
close a reallocation.**

Concretely: wrapping the buffer first (`Sensitive::build(Vec::new(), |v|
{ v.extend_from_slice(a); v.extend_from_slice(b); ... })`) makes the
*wrapper* live for the whole fill, but if the buffer's capacity is ever
under-sized, `extend_from_slice` reallocates — the allocator copies the
current contents into a **new** heap block and frees the **old** one.
`Drop` only ever wipes the buffer the `Vec` *currently* points at when it
drops, which is the new block. The old block — which held a live copy of
the secret for however long it existed — is freed unwiped, and wrapping
the `Vec` earlier does nothing to prevent this, because the reallocation
happens *inside* the wrapper, invisibly to it.

This is the sentence most likely to get lost if a future reader
"simplifies" the call site back to `Sensitive::build`/`try_build`
"for consistency" with the rest of the memory-hygiene discipline: the two
shapes look interchangeable and are not. `try_build` is the right choice
when the fill is a single write (a KDF output, a decode) that cannot
reallocate because it never grows a buffer. It is the *wrong* choice for
an incrementally-**built** secret assembled from multiple pushed slices,
because nothing about `try_build`'s contract prevents the closure from
under-provisioning capacity and triggering exactly the realloc-leak this
paragraph describes.

`SecretBytes::concat(parts: &[&[u8]]) -> Self`
([`core/src/crypto/secret.rs`](../../../core/src/crypto/secret.rs))
closes the hazard structurally instead of by convention: it derives the
total capacity by summing `parts.iter().map(|p| p.len())` and performs
every push from that same `parts` slice, in the same function, so the
reserved capacity and the total pushed length cannot drift and no
reallocation can occur — not "is unlikely to occur," but is
unrepresentable given the function's own logic. The wrapper is still
constructed before the first push (so an unwinding panic mid-loop is also
covered, the same property `build` gives), but that is now the *lesser*
of the two properties `concat` provides. It is also strictly less API
surface than `build`/`try_build`: it lends no `&mut` to caller code,
which matters because #521 (below) exists specifically to police what a
closure holding a live `&mut` into a secret wrapper is allowed to do.

**This property is structural, not tested — and the doc comment says so
rather than implying a test exists.** A reallocation that did not happen
leaves no observable trace from safe Rust: there is no "assert no
realloc occurred" test, the same limitation the "Spec §5.4's stated
limit" note above records for wipe-of-freed-memory claims generally. The
guarantee rests on reading `concat`'s own body, not on a test result.

`derive_wrap_key`'s call site (`core/src/crypto/kem.rs:266`) now reads as
its own normative spec line — `ss_x || ss_pq || ct_x || ct_pq ||
sender_pk_bundle || recipient_pk_bundle`, matching crypto-design.md §7 —
rather than a hand-computed capacity expression that was correct only
because `ct_x` happened to be typed `&[u8; X25519_PK_LEN]` at the time it
was written.

### #521's guard enforces the `&mut` caveat this memo already named — and widens it

"Wrapper discipline" above says flatly: **"All three wrappers are sound.
No changes recommended."** That sentence needs a footnote as of this
slice, not a retraction: the wrappers' *type-level* soundness is
unchanged, but `Sensitive::build`/`try_build`'s own doc comment (added by
#513, see "The fix: wrap before filling" above) has always named a
residual hole honestly — a closure that moves the secret out via
`std::mem::swap`/`std::mem::replace` defeats the wipe, because `Drop`
then zeroizes whatever was swapped **in**, not the secret that was
swapped **out**. Until this slice, "every closure written here is a
review point" was the entire enforcement mechanism for that sentence —
convention, not a check.

`scripts/check-secret-slot-hygiene.sh` (#521) converts it into a CI gate,
the same move #467/#472/#474/#486/#500/#504/#515 each made for their own
sink. It denies two families tree-wide (not scoped to a `build` closure —
see the script's own header for why closure-scoping would both need brace
matching in bash and miss the second family below):

- **S1** — `mem::swap` / `mem::replace` / `mem::take` / `mem::forget`.
- **S2** — `ManuallyDrop`.

The second family is not merely an extension of the first for coverage's
sake: `mem::forget` and `ManuallyDrop` **defeat `ZeroizeOnDrop` on every
wrapper in `secret.rs`** — `SecretBytes`, `SecretString`, and
`Sensitive<T>` alike — not just the two `Sensitive` constructors this
memo's "wrap before filling" section is about. A `ManuallyDrop<SecretBytes>`
or a `mem::forget`-ed `SecretString` never runs its destructor at all, so
the wipe that "All three wrappers are sound" was asserting is silently
**skipped**, not merely made harder to reach. The corrected statement is:
the three wrappers' `Drop` implementations are sound; that soundness is
only as good as the guarantee that `Drop` actually runs, and `mem::forget`
/ `ManuallyDrop` are exactly the two standard-library constructs that make
`Drop` not run, on safe, `#![forbid(unsafe_code)]`-compliant Rust.

It scans test code with no `#[cfg(test)]` carve-out, deliberately: #496
found the error-payload guard's permissive test-code matcher was being used
as a skip list, where an over-match is fail-open.

**The allowlist does not ship empty, and the claim that it did was an
artefact of the root list rather than a fact about the tree.** The guard's
first version hand-named six scan roots and omitted two workspace MEMBERS —
`browser/secretary-browser-host` (which handles the device secret and the
master password through `SecretBytes`) and
`desktop/secretary-desktop-presence`. The browser host holds **two live S1
producers**, its `scrub_string` helper, so the "exactly one hit tree-wide"
census had measured six chosen directories, not the tree. Both members are
scanned now and both sites are reviewed allowlist rows; the duplication and
the hand-rolled zeroization they contain are tracked as **#549**.

That omission is also why the guard now checks its own root list against
the root manifest's `[workspace] members` — a member with a `src/` in
neither `SCAN_ROOTS` nor `UNSCANNED_MEMBERS` is a hard failure, the
treatment #505 gave the payload guard's `DEFAULT_ROOTS`. A self-test cannot
substitute: any assertion written over `SCAN_ROOTS` disappears along with a
deleted entry, which was verified by mutation while writing it.

**The guard also used to fail OPEN on its own wiring**, in four ways the
#546 review found by execution, each of which printed `OK` and exited 0:
a declared scan root that was missing or renamed (`[[ -d ]] || continue` —
a tree with none of the roots reported "OK (6 roots, …)" having read
nothing, i.e. #496's `Path.rglob` fail-open restated in bash); a root whose
`grep` failed with exit >= 2 (`2>/dev/null || true` erased the error
channel — `chmod 000` on a root holding a real violation reported OK); an
unrecognised CLI argument (a typo'd `--self-tets` silently ran the full
guard, whose clean-tree output reads like a passing self-test); and the
success line reporting the DECLARED root count rather than the scanned one.
All four are now fatal, and the self-test drives `run_guard` itself and
asserts its EXIT CODE in both directions — previously it asserted only on
the text `scan_all` returned, so `return 1` could become `return 0` with
both CI steps green (verified by mutation).

**LIMITS.** Naming this only in passing would repeat the exact overclaim
pattern the error-payload guard's own LIMITS register exists to stop
(see CLAUDE.md's "Rust error payloads" section for that register's
scale) — so, matched by an equivalent LIMITS block in the guard's own
script header and in CLAUDE.md's Commands section:

- **Module/item aliasing is not symmetric between the two rules, and
  should not be flattened into one claim.** `use std::mem as m;` followed
  by `m::swap(slot, &mut plain)` evades **S1 entirely** — grepping either
  the `use` line or the call site for `mem::(swap|replace|take|forget)`
  finds nothing, verified by execution against a planted probe (zero hits
  from both the real guard's `scan_rule` and a bare regex check).
  **S2 is different, and better, by accident rather than by design:**
  aliasing `ManuallyDrop` still requires writing that literal identifier
  once, on the `use` line — `use std::mem::ManuallyDrop as MD;` — and S2
  matches *that* line even though it does not match the later `MD::new(...)`
  call site, also verified by execution. An S2 evasion therefore needs the
  name never to appear at all, which is a narrower attack than S1's — but
  NOT one no import syntax achieves, as an earlier version of this bullet
  claimed. That claim is falsified by the scope bullet two items below:
  a `pub use std::mem::ManuallyDrop as MD;` in an unscanned tree, re-imported
  under the alias from a scanned file, never writes the identifier in any
  scanned file at all. Zero live
  producers of either evasion exist in the tree today; this is a
  disclosure of an open door, not a report of exploitation. Tracked as
  **#545**, the same root cause as **#512** (a renaming import defeats the
  `Detail` newtype's E2 credit) and **#517** (E6 and
  `SHADOWABLE_PARAM_IDENTS` carry E4's alias/macro blind spots) —
  text-based identifier matching, matched by spelling, resolving nothing.
- **Macro-generated code.** Every rule here reads TEXT, not expanded
  macros: a `macro_rules!`-generated `mem::swap` or `ManuallyDrop::new`
  is invisible to either rule. Inherent to a text-based guard, the same
  limitation the error-payload guard's own LIMITS section states for its
  own rules.
- **Scope.** The guard reads only `*.rs` files under eight named roots
  (`core/src`, the three `ffi/secretary-ffi-*/src` crates,
  `desktop/src-tauri/src`, `desktop/secretary-desktop-presence/src`,
  `browser/secretary-browser-host/src`, `cli/src`). An earlier version of
  this bullet named six and listed `core/tests/**` and `test-utils/` as the
  unscanned trees — omitting the last two roots above, both workspace
  MEMBERS, one of them secret-bearing with two live S1 producers. That is
  now a hard failure rather than an omission (`check_roots_cover_workspace`
  against `[workspace] members`), but the manifest check bounds only
  MEMBERS with a `src/`. Still unscanned, in full: `core/tests/**`,
  `cli/tests/**`, `ffi/*/tests/**`, `desktop/src-tauri/tests/**`,
  `browser/*/tests/**`, `core/examples/`, `test-utils/` (a member, excluded
  by name because it is dev-only by construction), and `core/fuzz/` (not a
  member at all — the root manifest `exclude`s it). A secret-bearing helper
  added to any of those is invisible to this guard regardless of which
  construct it uses.

Per #545's own suggested-fix note: do not close the aliasing gap by
widening S1's regex (an `S3` rule matching `use (std|core)::mem as ` is
the natural next step, but it is deliberately **out of scope for this
slice** and left for #545 to pick up) — recording the boundary honestly
now is the point, not pre-empting the fix.

---

## Resolved: canonical-CBOR codec-boundary residue (#547, #548)

Closes the exact gap the "What is *not* covered" paragraph under "Resolved:
record-content zeroize" (below) described as an open follow-up, and closes
audit finding **C-4** the rest of the way — see the correction just made to
the "Residual closeout" section above ("up to **four**", not three,
long-term secret keys).

### The six-copy trace, measured rather than described

Tracing one block save of a record carrying a single
`RecordFieldValue::Text` field, the design spec for this slice
(`docs/superpowers/specs/2026-08-23-547-canonical-cbor-plaintext-residue-design.md`
§1) found the same plaintext materialised **six** times before this slice,
every copy in a `ciborium::Value` or a bare `Vec<u8>`, none `ZeroizeOnDrop`:

| # | Site (pre-slice) | What it copied |
|---|---|---|
| 1 | `record.rs` `field_to_entries` | `s.expose().to_owned()` — the copy #547 named |
| 2 | `canonical.rs` `pair.clone()`, via the inner-field sort | deep clone of #1 |
| 3 | `canonical.rs` `pair.clone()`, via the outer sort | deep clone of the whole field map |
| 4 | `canonical.rs` `pair.clone()`, via `encode_canonical_map` | again |
| 5 | `block.rs` `records_to_value` | `record::encode` → plaintext `Vec<u8>`, **re-parsed** into a fresh `Value` tree |
| 6 | `canonical.rs` `pair.clone()`, via `block.rs`'s own outer sort | clone of the records array |

Two mechanisms close this, matching the split the repo already draws between
`SecretBytes::concat` (eliminates a realloc) and `ZeroizingEntries`/its
successors (wipe what remains): **copies we make can be eliminated; copies
`ciborium` makes can only be wiped.**

**Mechanism A — eliminate.** `CanonicalValue` / `CanonicalMap`
([core/src/vault/canonical/value.rs](../../../core/src/vault/canonical/value.rs))
are a borrowing mirror of the CBOR subset the format uses: `Text(&'a str)`,
`Bytes(&'a [u8])`, `Map(CanonicalMap<'a>)`, etc. — every leaf borrows straight
out of a `SecretString`/`SecretBytes` (or a `&Value` for forward-compat
unknowns, via the `Borrowed` arm) instead of copying into an owned
`ciborium::Value`. `CanonicalMap` sorts keys **allocation-free**, on
`(key.len(), key.as_bytes())` — no key is ever materialised into an owned
buffer, which matters because `record.fields`' keys are user-authored field
names, i.e. decrypted plaintext in their own right. Applied at
`record::record_to_canonical` (Task 4, closes copies #1-#4) and
`block.rs`'s `plaintext_to_entries` (Task 5, closes copies #5-#6 by embedding
`record_to_canonical` calls inline and deleting the encode→reparse
round-trip entirely, rather than merely wiping the reparsed tree).

**Mechanism B — wipe.** `SecretValueTree` / `SecretEntries`
([core/src/cbor/secret_tree/](../../../core/src/cbor/secret_tree/), split out
of `cbor.rs` once that file passed the project's 500-line threshold) own a
parsed `Value` (or entry list) and recursively zeroize `Bytes` **and**
`Text` payloads through `Array`, `Map` (keys and values both) and `Tag`, on
`Drop`. This is what `ciborium::de::from_reader` itself allocates while
parsing — that allocation belongs to the parser, not to any caller here, and
cannot be eliminated, only wiped before drop. Two properties carried over
from the retired `ZeroizingEntries` (#542) and sharpened by this slice's own
review: `Value::Text` is wiped here (unlike `ZeroizingEntries`, which
skipped it because the bundle's only text value, `display_name`, was held
unwrapped elsewhere anyway); and the walk is **recursive**, not
top-level-only, because the record shape nests a per-field map inside an
outer map inside the records array.

### Four production `SecretValueTree`/`SecretEntries` roots, not three

An earlier draft of this section's own outline said three. Verified by
grepping every production (non-`#[cfg(test)]`) call site of
`SecretValueTree::new` / `SecretEntries::new`:

| Root | Call site | Direction |
|---|---|---|
| `record.rs` | `record::decode` (`record.rs:635`) | decode |
| `block.rs` | `block::decode_plaintext` (`block.rs:1049`) | decode |
| `unlock/bundle.rs` | `IdentityBundle::from_canonical_cbor` (`bundle.rs:367`, `SecretEntries`) | decode |
| `manifest.rs` | `decode_manifest` (`manifest.rs:810`) | decode |

**This table is narrower than it was, twice over — and the second
correction fixes an error THIS task introduced, not one it inherited.**
First: a follow-up slice (cbor-residue-closeout, #569) migrated
`IdentityBundle::to_canonical_cbor`'s encode side off `SecretEntries` onto
the borrowing `CanonicalMap` — see "Resolved: cbor-residue-closeout
follow-up" below — so the row this table used to carry for it (`bundle.rs`,
then line 296, **encode**) no longer exists: there is nothing left for
that call to wrap.

Second: this table used to carry a fifth row — `manifest.rs` |
`unknown_value_inner` (then cited at line 723, refreshed to 748 during
this same task) | **encode**. **That row was never true.** Independently
re-verified: `grep -rn "SecretValueTree::new\|SecretEntries::new" core/src
| grep -v secret_tree/` returns exactly the four rows above — nothing for
`unknown_value_inner`. Its own doc comment
(`manifest.rs:745-747`) says why: *"The counter-based test Task 7b wrote
for the removed `SecretValueTree` wrap is retired with the wrap it
pinned"* — the wrap was removed before this branch existed, absent at
`main` and at this branch's own pre-Task-8 tip. During this task the row's
CITATION was refreshed (line 723 → 748) without re-verifying the
underlying FACT, which made a stale claim read as freshly confirmed — the
exact defect class this whole slice exists to fight, landed in the one
task whose entire product is prose. `unknown_value_inner` still calls
`from_secret_reader` (see the six-call-site count in "Resolved:
cbor-residue-closeout follow-up" below, which is a
DIFFERENT count — of `from_secret_reader` call sites, not of
`SecretValueTree`/`SecretEntries` construction sites, and stays six); the
`Value` it parses is real and secret-bearing, but nothing wraps it. That
gap is not new, not caused by this slice, and not covered by any of
#561/#565-#570 — it is the same class `unknown_value_inner`'s own comment
already places under **#558** (the AEAD-plaintext-buffer class), stated
outright rather than pretending to a coverage this table used to imply.

Grouped by *file*, this is now **four roots — record, block, bundle,
manifest — and all four are decode-only** for `SecretValueTree`/
`SecretEntries`: **four call sites total**, not five, not six. That
uniformity has two different causes, and conflating them would itself be
an overclaim: `record`, `block` and `bundle` are decode-only because their
encode sides use Mechanism A (elimination) — nothing owned is ever
materialised, so there is nothing to wrap. `manifest.rs` is decode-only
for a different reason — its encode side (`unknown_value_inner`) DOES
materialise an owned, secret-bearing `Value`, and that value is simply
unwrapped, a real residual rather than an eliminated copy. Do not read
"four roots, all decode-only" as "four roots, uniformly covered."

`identity/card.rs`'s own `from_canonical_cbor` (`ContactCard`) and
`sync/state.rs`'s `SyncState::from_canonical_cbor` are deliberately outside
this list: neither carries secret material — the Contact Card is public
key + display-name material meant to be shared, and `SyncState` carries only
`vault_uuid` / `device_uuid` / vector-clock counters.

### What `SecretValueTree`/`SecretEntries` do NOT claim

Stated here because a handoff memo is where a future auditor looks first,
and because this exact overclaim pattern is what CLAUDE.md flags as this
line of work's most repeated review finding:

- **Freed heap is not observable from safe Rust.** There is no "assert the
  old allocation was actually wiped before the allocator reused it" test,
  the same limitation `SecretBytes::concat`'s doc note (above, "why it is
  not `build`/`try_build`") records for its own no-realloc claim. The wipe
  is provable by reading `SecretValueTree::wipe`'s body; that the bytes
  never come back is not independently checkable from outside the process.
- **A reallocation `ciborium`'s parser performed before we ever saw the
  value is not covered.** If `from_reader` internally grew a `String`/`Vec`
  buffer while building the tree, the old (smaller) buffer was freed by the
  allocator before `SecretValueTree::new` is ever called — that happened
  inside a dependency this crate does not control, and no wrapper applied
  afterward can retroactively wipe it.
- **`SecretValueTree` covers the buffer the tree points at when it drops**
  — nothing more. A value cloned OUT of the tree before drop (the
  `UnknownValue` clones both `record.rs`/`block.rs`/`manifest.rs` make for
  forward-compat unknowns, and `manifest.rs`'s `unknown_value_inner` clone
  of its own tree's root — see "Still open," below) is a fresh, ordinary,
  non-zeroizing allocation from that point on. The source is covered; the
  clone is not.

### The one validation-semantics change, and the test that discharges it

`block::take_records` used to re-serialise each record `Value` into a
plaintext `buf` and call `record::decode(&buf)` — a full extra encode/parse
round trip per record, per block open, that also re-ran `record::decode`'s
own byte-level canonicality re-check on that one record. Task 6 replaced it
with `record::decode_value(&Value)`, which borrows the record's subtree
directly out of the block's own `SecretValueTree` and skips that per-record
re-check.

The claim that nothing is lost is that `block::decode_plaintext`'s own
whole-plaintext re-encode-and-compare (`encode_plaintext(&plaintext) !=
bytes` ⇒ `NonCanonicalEncoding`) **subsumes** the deleted per-record check,
because it covers the nested record's bytes as part of the whole block.
That is a claim about frozen-format validation, and per this document's own
standard it needed a test, not an argument: `block.rs`'s
`a_non_canonical_nested_record_is_still_rejected` plants a non-canonical
nested record (out-of-order field keys) inside an otherwise-valid block and
proves `decode_plaintext` still rejects it. Both `decode_value`'s and
`decode_plaintext`'s own doc comments point at this test by name.

### `pt_bytes` / `body_bytes`: the terminal AEAD-input buffer, missed by the six-copy trace and closed in the final fix wave

The six-copy trace above and the Mechanism A/B accounting both stop one step
short of where each save path actually ends: the already-canonical `Vec<u8>`
that `encode_plaintext` (`block.rs`) / `encode_manifest` (`manifest.rs`)
returns, which is handed straight to `aead::encrypt`. Neither mechanism's
grep covered it — it holds no `ciborium::Value`, so `SecretValueTree`
(Mechanism B) has nothing to wrap, and it is the *output* of the borrowing
encoder, not a copy `CanonicalValue`/`CanonicalMap` (Mechanism A) could have
eliminated by construction. Found in the final whole-branch review, not by
either census.

- **`block::encrypt_block`'s `pt_bytes`** was a bare `Vec<u8>` holding the
  canonical-CBOR encoding of the **entire block plaintext** — every record,
  every field, every password/note/TOTP seed in the block — dropped unwiped
  on every save. It is the single largest unwiped plaintext buffer this
  slice's save path produced, larger than any one of the six copies the
  trace above counts, because it is the whole block rather than one field.
- **`manifest::sign_manifest`'s `body_bytes`** is the same shape one layer
  up: the canonical-CBOR encoding of the whole manifest body, including
  every `BlockEntry::block_name` (the plaintext this document's Census
  section, below, already tracks two OTHER unwiped clones of, upstream in
  `canonical_sort_entries`).

Both are now wrapped at construction — `SecretBytes::new(encode_plaintext
(plaintext)?)` / `SecretBytes::new(encode_manifest(body)?)` — with
`.expose()` passed to `aead::encrypt`, matching the `bundle_plaintext`
pattern in `unlock::create_vault_unchecked` (#513, #357): `ZeroizeOnDrop`
then covers every exit path (normal return, an early `?`, an unwinding
panic), not just the happy path a trailing `.zeroize()` would have covered.
Byte-identity is unaffected — `SecretBytes::new` takes ownership of the same
`Vec` and `.expose()` returns `&[u8]` over the same allocation, so this is a
wrapper change, not a data change, and `golden_vault_001_pinned` (which
rebuilds every vault file and byte-compares against the frozen fixture)
confirms it.

**Save-path copy count, re-derived (not adjusted arithmetically) after this
fix:**

- **Block save (`encrypt_block`).** Zero unwiped plaintext copies remain.
  Per-record/per-field copies were already eliminated by Mechanism A (Task
  4/5); `pt_bytes`, the one bare `Vec<u8>` that survived past Mechanism A
  because it isn't a `ciborium::Value` copy, is now wrapped.
- **Manifest save (`sign_manifest`).** Two unwiped plaintext copies remain,
  down from three: the two `block_name` clones inside
  `canonical_sort_entries` this document's Census section already tracks as
  **deliberately** out of scope (manifest.rs's encode side stays on
  `canonical_sort_entries`/`encode_canonical_map` rather than migrating to
  `CanonicalValue` — a churn-avoidance decision recorded in the design
  spec's §6, not an oversight, and not touched by this fix). `body_bytes`,
  the third copy — and the only one this section's mechanisms had not
  already accounted for — is now wrapped.

### Census: what remains, and why each hit is justified

Re-running the grep census this section is built on
(`expose().to_owned()` / `expose().to_vec()` / `.0.clone()`, `pair.clone()`,
`SecretValueTree::new`, `from_reader` outside `#[cfg(test)]`) turns up
several more hits than the "four roots" table above — every one of them was
individually read, not counted from the grep subtotal, per this document's
own repeated warning against exactly that shortcut:

- **Test-only.** The large majority of `.expose().to_vec()` / `.0.clone()`
  hits (`unlock/device.rs`'s three `#[test]`-fn sites, `unlock/bundle.rs`'s
  test-module fixture builders at lines 1585/1601 and its
  `owned_*_for_test` mirrors in `record.rs`) live inside `#[cfg(test)] mod
  tests` and never compile into `cargo build --release`.
- **`unlock/bundle.rs::generate` (`ml_kem_768_sk`/`ml_dsa_65_sk`,
  lines 270-271).** A single, documented copy at key-*generation* time
  (not the encode/decode residue class this section is about): the PQC
  modules wrap their secrets in module-private newtypes, the bundle wants
  a uniform `Sensitive<Vec<u8>>` across all four keys, and the source
  wrapper's `SecretBytes` is dropped (zeroized) at the end of the same
  function. Pre-existing, out of scope for #547/#548.
- **`unlock/bundle.rs::to_canonical_cbor` — CLOSED BY ELIMINATION, not by a
  wrap.** This bullet used to read: "(`x25519_sk`/`ed25519_sk`.
  `.expose().to_vec()`, lines 307/323). This IS a copy of secret-key
  material into a `Value::Bytes`, but it is immediately wrapped in
  `SecretEntries::new(entries)` on the very next statement — this is
  Mechanism B applied to the bundle's own encode side (#542/#548), not an
  uncovered residue." That described Mechanism B (wrap-then-wipe) covering
  a copy that genuinely existed at the time. The cbor-residue-closeout
  follow-up slice (#569) removed the copy itself: `to_canonical_cbor` now
  builds a `CanonicalMap` whose four secret-key entries — X25519,
  ML-KEM-768, Ed25519, ML-DSA-65 — borrow straight out of the bundle's own
  `Sensitive` fields via `.expose()`, with no `.to_vec()` and no
  `SecretEntries` construction on
  this path at all — Mechanism A (elimination), the same mechanism
  `record.rs`'s and `block.rs`'s encode sides already used. See "Resolved:
  cbor-residue-closeout follow-up" below.
- **`vault/device_slot.rs:110`, `unlock/device.rs`'s production
  `secret_bytes` construction pattern.** `SecretBytes::new(device_secret
  .expose().to_vec())` — a single documented boundary copy (device secret
  handed back to the caller as the public `SecretBytes` type), unrelated to
  the CBOR codec boundary this section covers.
- **`identity/card.rs:562` `pair.clone()`, inside `encode_map`.**
  `ContactCard` carries only public key material, a display name, and a
  self-signature — no secret keys, by construction (see the type's own
  field list). Out of scope: there is no secret content to leak.
- **`vault/canonical/legacy.rs:32` `pair.clone()`, inside
  `canonical_sort_entries`.** This is the ONE deliberately-retained clone
  the design spec calls out by name (§3.3, "What is NOT in scope"):
  `manifest.rs`'s own *encode* side stays on `canonical_sort_entries` /
  `encode_canonical_map` rather than migrating to `CanonicalValue`, a
  churn-avoidance decision, not an oversight. Its only plaintext-bearing
  caller through this function is `block_entry_to_value`'s `block_name`
  field (`manifest.rs`) — genuinely user-visible plaintext within the
  encrypted manifest, cloned once via `.clone()` into the entry list and
  again via `canonical_sort_entries`'s `pair.clone()`. Two clones of a
  block name per manifest save; not wiped, not eliminated, and
  **deliberately** left that way by this slice's own scope decision — see
  "Still open," below, for why this is not silently accepted as fine
  either.
- **`sync/state.rs`'s `canonical_sort_entries` / `from_reader` calls.**
  `SyncState` carries `vault_uuid`, `device_uuid`, and vector-clock
  counters — no secret material. Out of scope.
- **The remaining `from_reader` sites.** This bullet claimed they were
  "either the four production roots already tabulated above,
  `identity/card.rs`'s two sites, or `#[cfg(test)]`-gated". **That
  three-bucket claim is false, and is corrected rather than reworded**
  (#560 review). Two production sites fall in none of the three buckets:
  - `record.rs`'s `UnknownValue::from_canonical_cbor` — and it is
    **reachable from block decode**, not an isolated public entry point:
    `block::value_to_unknown` re-serialises a decrypted block subtree into
    a bare `Vec<u8>` and parses it back with no `SecretValueTree` wrap,
    into an `UnknownValue` this memo separately notes has no `Zeroize`
    impl. (`value_to_unknown`'s output buffer is at least pre-reserved as
    of the #560 review, closing the realloc half; the parse itself is
    still unwrapped.)
  - `sync/state.rs` — discussed elsewhere in this memo, but not by this
    sentence, and `SyncState` carrying no secret material is a property of
    that type, not of the bucket list.

  The lesson is the one this memo keeps re-learning: an exhaustiveness
  claim stated as a closed list of buckets needs the census that produced
  it re-run, or it silently narrows to "the sites I happened to tabulate".

### Still open — recorded so it is tracked, not merely discovered later

Found during this slice and deliberately **not** fixed, each because fixing
it was judged out of this slice's scope rather than because it was missed:

- **~~`re_encoded` is an unwiped plaintext buffer~~ — CLOSED by the
  cbor-residue-closeout follow-up slice, not by this one.** This bullet
  used to read: "on both `record::decode` and `block::decode_plaintext` —
  the output of the canonicality re-check's own re-encode (`encode(&record)`
  / `encode_plaintext(&plaintext)`), compared against the input and then
  dropped as a plain `Vec<u8>`. Task 6 took this from ~2N+1 unwiped buffers
  per block open (N records) down to this **one** survivor; it is neither
  eliminated (the re-encode is a correctness gate this slice deliberately
  keeps, per the design spec §6) nor wrapped." That was accurate for this
  slice's own scope, which stopped at reducing the count. The follow-up
  slice closed the survivor itself (#558, #565): `encode` / `encode_plaintext`
  now return `SecretBytes` directly, so the survivor buffer is wrapped **by
  construction** at both call sites — there is no longer a bare `Vec<u8>`
  moment for it to occupy. See "Resolved: cbor-residue-closeout follow-up"
  below for the mechanism and why a structural return-type wrap is stronger
  than a caller-side one.
- **Non-canonical key order inside a forward-compat `unknown` subtree**
  escapes both the old per-record canonicality check and the new
  whole-plaintext one: `CanonicalValue::Borrowed` emits an unknown subtree
  verbatim on encode, and `UnknownValue::from_canonical_cbor` validates
  only the no-float / no-tag rules on decode, not full canonical key
  order. Pre-existing, identical before and after this slice — not a
  regression, but also not closed by it.
- **`block::decode_plaintext` has no fuzz target**, while the per-record
  gate it partly replaced does (`core/fuzz/fuzz_targets/record.rs`).
  Tracked as **#557**, alongside the observation that deleting the
  `decode_plaintext` wrap leaves every existing test green — i.e. nothing
  in the current suite pins that specific wrap's presence.
- **~~The `take_*` helper family's shape-mismatch branches~~ — CLOSED in
  the #560 review.** This bullet read: "(a field present but the wrong CBOR
  major type) drop their `Value` unwiped on the error return. Pre-existing,
  and lower severity than it looks: by the time any of these run, the
  content has passed AEAD authentication…". The severity argument was and
  remains sound. Two things about the DESCRIPTION were not:
  - It said "the `take_*` helper family", unqualified. That is true only of
    `unlock/bundle.rs`, whose five helpers took `v: Value` **by value**.
    Every `take_*` in `record.rs`, `block.rs` and `manifest.rs` takes
    `&Value` and therefore cannot drop it at all. As written the bullet
    overstated the residual across three files that never had it.
  - It named only *shape-mismatch* branches. The wrong-**LENGTH** branches
    of `take_uuid` and `take_sized_public` were the same leak and are not
    shape mismatches — `take_sized_public` freed a `Vec<u8>` intact on a
    length reject, which is where a 2400-byte ML-KEM-768 SECRET key stored
    under `ml_kem_768_pk` (expects 1184) would land.

  All six `bundle.rs` helpers now wipe the rejected value (or wrap it
  before the length check, the pattern `take_fixed_bytes_into` already
  used). The non-string-key arm also now wipes the map **KEY**, which it
  did not: it wiped `v` and dropped `k` intact, in the one arm whose shape
  check guarantees `k` is some non-text `Value` — `Value::Bytes` among
  them. One arm of the class was filed as **#566** and read as open here:
  "`set_once`'s `DuplicateField` return drops an already-extracted
  `String`/`Vec<u8>` temp unwiped, which needs a different mechanism
  (`set_once` is generic over `T`) rather than the uniform `mut other =>
  wipe` shape the rest took." **CLOSED by the cbor-residue-closeout
  follow-up slice**: `set_once` now takes a `T: Zeroize` bound and calls
  `v.zeroize()` on the rejected duplicate before returning
  `DuplicateField`, the different-mechanism fix this bullet said the
  generic signature needed. See "Resolved: cbor-residue-closeout
  follow-up" below.
- **`UnknownValue` has no `Zeroize` impl**
  (`#[derive(Debug, Clone, PartialEq)]` only). Every clone made of a
  `Value` before wrapping it in `UnknownValue` — `record.rs`'s direct
  `UnknownValue(v.clone())` (it owns the type, so it constructs directly;
  `record.rs:753`, `:878`), and `block.rs`'s / `manifest.rs`'s
  serialise-then-reparse round trip through `value_to_unknown` /
  `unknown_value_inner` (neither owns `UnknownValue`'s private field) —
  escapes the enclosing `SecretValueTree` uncovered, by design of the
  type: the SOURCE stays covered until the tree drops; the CLONE never
  was. No regression relative to pre-slice behaviour (the clone was
  exactly as uncovered before this slice existed), but the type itself is
  the residual gap, not any one call site.
- **Issues filed during this slice:** **#555** (closed by Task 7),
  **#556** (`record.rs` is over the project's 500-line split guideline;
  the count has moved every task and #556's own TITLE is now stale, so
  run `wc -l` rather than citing any snapshot — this bullet has carried
  three different numbers), **#557** (`block::decode_plaintext`'s
  `SecretValueTree` wrap was unpinned — **closed in the #560 review** by
  `decode_plaintext_wipes_its_parsed_tree_on_an_early_return`, an
  exact-count assertion measured at exactly one
  `SecretValueTree::drop`), **#558**, **#559** (**closed in the #560
  review**: `CanonicalValue`/`CanonicalMap` and `CanonicalMap`'s
  `with_capacity`/`push` now DECLARE `pub(crate)` instead of relying on a
  private `mod value;` two files away).

- **Filed by the #560 review**, all from the same slice's code:
  **#561** (`ciborium`'s `from_reader` 4 KiB stack scratch buffer holds
  decrypted plaintext and is never wiped — verified by execution, and
  fixable via the public `from_reader_with_buffer`; not named in this
  memo's "still open" list before now), **#562** (`golden_vault_001` is
  pure ASCII with zero `unknown` keys, so the frozen-fixture anchor cannot
  see a byte-length-vs-char-count comparator regression and never
  constructs `CanonicalValue::Borrowed`), **#563**/**#564** (`block.rs` at
  2895 lines and `manifest.rs` at 3844 lines, the two largest files in the
  tree, both grown by this slice and neither previously filed alongside
  #556), **#565** (`re_encoded`, promoted from this list's own prose to a
  tracked issue — **closed by the cbor-residue-closeout follow-up slice**:
  `encode`/`encode_plaintext` now return `SecretBytes`, wrapping it by
  construction), **#566** (the `set_once` residual described above —
  **closed by the same follow-up slice**: `set_once` gained a `T: Zeroize`
  bound and wipes the rejected duplicate), **#567** (the `(len, bytes)` ==
  RFC 8949 §4.2.1 sweep exists only in prose — no committed proptest — as
  filed; **closed by the same follow-up slice**, which added
  `len_then_bytes_matches_full_cbor_encoding_order` as a committed
  proptest),
  **#568** (`parse_manifest_map` is the one decoder of four with no
  duplicate-key detection, and it silently last-wins — as filed. That
  "four" counts the four `SecretValueTree`/`SecretEntries` top-level
  decode roots this memo tracks above (`record`, `block`, `bundle`,
  `manifest`); it is a DIFFERENT group from the nested parsers named next,
  and a prior version of this entry conflated the two — reading the four
  nested parsers as the same "four" the filing counted, which does not add
  up (one-of-four plus four-nested is five). **Closed by the same
  follow-up slice** at the top level: `parse_manifest_map` now rejects a
  repeated key via `ManifestError::DuplicateKey`. That leaves
  `manifest.rs`'s own four NESTED parsers — `parse_vector_clock_entry`,
  `parse_block_entry`, `parse_trash_entry`, `parse_kdf_params` — with no
  equivalent check of their own; unchanged by this slice, tracked
  separately as #573),
  **#569** (`bundle.rs`, `manifest.rs` and `card.rs` encode paths still
  copy secrets into an owned `ciborium::Value` rather than borrowing
  through `CanonicalMap` — bundle's copies all four long-term secret keys
  per encode, as filed; **partially closed by the same follow-up slice**:
  `bundle.rs`'s copies of the four long-term secret keys are gone —
  `to_canonical_cbor` borrows through `CanonicalMap` now. `manifest.rs`'s
  user-visible block-name clone and `card.rs`'s public-key-only encode are unchanged;
  neither carries the secret-key material #569 was filed over), **#570**
  (`ciborium`'s decode side grows payload buffers from capacity 0, so any
  field over 4 KiB reallocs repeatedly and frees unwiped prefixes —
  measured, by execution, at 6 allocation events / 5 reallocations for a
  100,000-byte `bstr`, final capacity 131072. This entry originally read
  "~14 reallocations" — wrong by roughly 3x, corrected here rather than
  carried forward a third time; see "Resolved: cbor-residue-closeout
  follow-up" below for the reproduction).

---

## Resolved: cbor-residue-closeout follow-up (#561, #565–#569)

A follow-up slice (branch `feature/cbor-residue-closeout`) picking up six
of the seven issues the #560 review filed against the section above.
Cited by issue number, for the same reason the #542/#522/#524/#521
section gives: `main` squash-merges, so a branch-local commit SHA stops
resolving the moment the enclosing PR lands. **#570 is deliberately not
closed by this slice** — it is the one item in that list this section
documents rather than fixes; see "What this does not claim" below.

### The parser's scratch buffer (#561)

`ciborium::de::from_reader` stages every payload of 4096 bytes or fewer
through a `[0; 4096]` in its own stack frame and leaves it intact when the
parser returns — a decrypted record field, block plaintext, a manifest's
user-visible block name, or one of the identity bundle's four long-term
secret keys could sit there after any secret-bearing parse. Closed by
[`core/src/cbor/scratch.rs`](../../../core/src/cbor/scratch.rs)'s
`CborScratch` (a zeroize-on-drop wrapper around the same 4096-byte buffer)
and `from_secret_reader`, which calls `ciborium::de::from_reader_with_buffer`
with that owned buffer instead — behaviour-identical to plain
`ciborium::de::from_reader` (verified against the vendored `ciborium-0.2.2`
source, not inferred from its docs), differing only in who owns, and
wipes, the scratch space.

Every secret-bearing decode in the crate now routes through it: six
production call sites — `unlock/bundle.rs` (1), `vault/block.rs` (1),
`vault/manifest.rs` (2, one of them `unknown_value_inner`'s encode-side
re-parse), `vault/record.rs` (2). Two call sites deliberately stay on
plain `ciborium::de::from_reader`, each with a comment stating why its
input provably holds no secret: `identity/card.rs`'s `ContactCard` decode
(public key material + a display name, meant to be shared) and
`sync/state.rs`'s `SyncState` decode (`vault_uuid` / `device_uuid` /
vector-clock counters only).

### The bundle's encode side: elimination, not a wrap (#569, partial)

`IdentityBundle::to_canonical_cbor` used to clone all four long-term
secret keys — X25519, the 2400-byte ML-KEM-768 decapsulation key,
Ed25519, and the ML-DSA-65 seed — out of their `Sensitive` wrappers via
`.expose().to_vec()` into an owned `ciborium::Value::Bytes`, on *every*
encode, then relied on `SecretEntries::drop` to wipe the copy. This slice
removes the copy instead of covering it: `to_canonical_cbor` now builds a
`CanonicalMap` whose secret-key entries are `CanonicalValue::Bytes(self.
x25519_sk.expose())` and its three siblings — borrows, not clones. A copy
that never exists needs no wipe and cannot be missed by a future caller;
`to_canonical_cbor_touches_no_wipe_counter` pins this by asserting the
shared wipe counter does not move across an encode call. The decode side
(`from_canonical_cbor`) is unchanged and still wraps its parsed entries in
`SecretEntries` — `ciborium`'s parser owns that allocation, so elimination
is not available there. #569 also named `manifest.rs`'s user-visible
block-name clone and `card.rs`'s public-key-only encode; neither carries the four
long-term secret keys #569 was filed over, and neither is touched by this
slice — #569 stays open for those two, closed only for `bundle.rs`.

### The canonical encoders return the wrapper, instead of a caller applying one (#558, #565)

`record::encode`, `block::encode_plaintext` and `encode_manifest` used to
return a bare `Vec<u8>`, relying on each caller to wrap it —
`SecretBytes::new(encode(&record)?)` and the like. `record.rs` never grew
that caller-side wrap at all (see the correction below); `block.rs`'s
`encrypt_block` and `manifest.rs`'s `sign_manifest` did, and a `SecretBytes::
new(..)` call at a call site is *deletable with the whole test suite still
green* — verified by execution — because a derived `Zeroize`/`ZeroizeOnDrop`
gives no observable signal when its wrap is simply skipped. All three
functions now return `SecretBytes` directly, and `encrypt_manifest_body`
takes `&SecretBytes` rather than `&[u8]`. Moving the wrap into the return
type turns that same deletion into a compile error instead of a silent
gap — a stronger claim than "the value happens to be wrapped today."
`aead::encrypt` is deliberately unchanged (`&[u8]` in, `Vec<u8>` out): its
plaintext genuinely is not always secret — the RFC-vector KATs encrypt
public test literals — so the "output is always secret" precondition this
pattern needs does not hold there.

One consequence worth naming explicitly: the canonicality re-check's
re-encode buffer — the survivor this memo's own "still open" list named
after Task 6 reduced the per-block-open count from ~2N+1 to one — is now
`SecretBytes` **by construction** on both
`record::decode` and `block::decode_plaintext` — there is no longer a
`Vec<u8>` moment for it to occupy between the re-encode and the comparison.
It was closed by removing the opportunity for the gap, not by adding a
wipe to cover it.

### Two smaller closures on the same branch

- **`set_once` wipes the duplicate it rejects (#566).** `unlock/bundle.rs`'s
  `set_once<T: Zeroize>` now calls `v.zeroize()` on the REJECTED value
  before returning `BundleError::DuplicateField` — the one `take_*`-family
  arm the #560 review's own closure pass had left open, because `set_once`
  is generic over `T` rather than shaped like the uniform `mut other =>
  wipe` arm the rest of that pass used.
- **`parse_manifest_map` rejects duplicate top-level keys (#568).** RFC
  8949 §5.4 requires rejecting a repeated map key rather than silently
  taking the last one; `parse_manifest_map` was the one decoder of four
  (the four `SecretValueTree`/`SecretEntries` top-level decode roots —
  `record`, `block`, `bundle`, `manifest` — not the nested parsers below,
  a separate group) that did not. It now tracks the keys seen so far in a
  set and returns `ManifestError::DuplicateKey` on a repeat. Scoped to the
  top level only — `manifest.rs`'s own four NESTED parsers
  (`parse_vector_clock_entry`, `parse_block_entry`, `parse_trash_entry`,
  `parse_kdf_params`) have no equivalent check of their own, tracked
  separately as **#573**.
- **The `(len, bytes)` == RFC 8949 §4.2.1 claim is now a committed
  proptest (#567).** `CanonicalMap::serialize`'s key sort — the mechanism
  that lets its keys stay borrowed `&str`s with no key buffer ever
  materialised — had been checked twice by exhaustive sweep (184,041 and,
  independently, 400,000 pairwise comparisons, zero mismatches both times)
  and neither sweep was committed; both lived in prose in a handoff
  document. `len_then_bytes_matches_full_cbor_encoding_order` in
  [`core/src/vault/canonical/value.rs`](../../../core/src/vault/canonical/value.rs)
  now pins it as a proptest, mutation-checked in both directions.

### What this does not claim

- **The >4 KiB reallocation class is documented, not fixed (#570).**
  `ciborium`'s `serde::Deserialize` visitor for byte strings and text
  builds the final payload with `Vec::new()` / `String::new()` plus a
  per-chunk grow-and-copy, so any field larger than the parser's 4096-byte
  scratch buffer still grows by doubling and frees an unwiped prefix at
  every step, inside the parser's own visitor — before `from_secret_reader`
  or `SecretValueTree` ever sees the value. Measured, by execution
  (`Vec<u8>::extend_from_slice` in 4096-byte chunks to 100,000 bytes
  total): 6 allocation events, 5 of them reallocations, final capacity
  131072 grown from 0. For an attachment, a long note, or a stored key
  file this is the routine case,
  not an edge case, and there is no public `ciborium` hook to reach it.
  Both `core/src/cbor/scratch.rs`'s and `core/src/cbor/secret_tree/mod.rs`'s
  own "What this does not claim" sections now name this threshold
  explicitly.
- **A wipe of freed heap is not observable from safe Rust.** Every claim
  in this section, and in the section above it, is a claim about what code
  runs, not a claim that can be checked against the allocator's own state
  after the fact — the same limit the #547/#548 section already states for
  `SecretValueTree`/`SecretEntries`, restated here because it applies
  equally to `CborScratch`.

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

**This whole "What is *not* covered" block is now stale, and is left in
place — struck through in substance, not in markup — rather than deleted,
per this memo's own discipline of correcting a falsified claim in place.**
#547 built **the first half of option (a)**, not option (a) — this
sentence read "Option (a) above is exactly what #547 built" until the #560
review, which is an overclaim inside the very paragraph whose job is
retiring a stale warning. Option (a) as written above is "a CBOR encoder
that takes a borrowed `&[u8]`/`&str` **and writes directly to a
zeroize-typed output buffer**." `CanonicalValue`/`CanonicalMap` deliver the
borrowing-input half in full. The output half — this paragraph continued —
they did not: `to_canonical_vec` returned a bare `Vec<u8>`, and the
`SecretBytes` wrap happened in the caller afterwards (`block.rs`'s
`encrypt_block`, `manifest.rs`'s `sign_manifest`), which is why this
memo's own "still open" list named `re_encoded` (#565) as exactly the
unwiped output buffer option (a) called for. **That description of the
output half is ITSELF now stale, closed by the cbor-residue-closeout
follow-up slice.** `record::encode` / `block::encode_plaintext` /
`encode_manifest` all now return `SecretBytes` directly — the wrap moved
INTO the encoder, out of the caller. `encrypt_block` and `sign_manifest`
no longer wrap anything: they call `encode_plaintext(plaintext)?` /
`encode_manifest(body)?` and get an already-wrapped `SecretBytes` back.
Option (a) as written above — a borrowing CBOR encoder that writes
directly to a zeroize-typed output buffer — is now built in full, not
just its input half; see "Resolved: cbor-residue-closeout follow-up"
below for why a structural return-type wrap is a stronger claim than a
caller-side one, and "Resolved: canonical-CBOR codec-boundary residue
(#547, #548)" above for the state this paragraph was originally
correcting. In short: the
`s.expose().to_owned()` /
`b.expose().to_vec()` copy this paragraph names by exact call shape no
longer exists in `record.rs`'s production encode path (Task 4 replaced it
with a borrow), and the parsed `ciborium::Value` tree on the decode path
is now wrapped in `SecretValueTree`, which zeroizes it on every exit,
including the early-return paths this paragraph worried about. The
residue is not zero — see that section's own "still open" list — but it
is a different, smaller residue than the one described here, and reading
this paragraph as the current state would overstate what remains.

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

## Cross-sub-project discipline (re-verification, 2026-05-28)

Sub-projects B and C were written **after** the original 2026-05-02
audit. A spot re-verification confirms both new layers follow the
established `bind → wrap → zeroize` pattern at every secret-bearing
site:

- **Sub-project C — sync orchestration**
  ([core/src/sync/](../../../core/src/sync/)). The two new sites that
  copy secret keys out of `Sensitive<...>` wrappers for per-block AEAD
  decryption and signing both follow the pattern verbatim:
  - [sync/prepare.rs#L169](../../../core/src/sync/prepare.rs#L169) —
    `let mut x_sk_bytes = *identity.identity.x25519_sk.expose(); let
    reader_x_sk: X25519Secret = Sensitive::new(x_sk_bytes);
    x_sk_bytes.zeroize();`
  - [sync/commit/write.rs#L237](../../../core/src/sync/commit/write.rs#L237) —
    the parallel `ed_sk_bytes.zeroize()` pattern for the author's
    Ed25519 secret key.

  No new top-level secret types are introduced — the sync layer
  composes `Sensitive`-wrapped values from the existing core types
  rather than declaring its own wrappers.

- **Sub-project B — FFI bridge**
  ([ffi/secretary-ffi-bridge/](../../../ffi/secretary-ffi-bridge/)).
  The bridge re-exposes core types through opaque-handle wrappers
  (`UnlockedIdentity`, `MnemonicOutput`, `OpenVaultManifest`,
  `BlockReadOutput`, `Record`, `FieldHandle`) using the `Mutex<Option
  <Inner>>` (or `Arc<Mutex<Option<Inner>>>` for shared handles)
  pattern. The inner `Inner` types are all built from the established
  `Sensitive` / `SecretBytes` / `SecretString` wrappers, so the
  bridge inherits the drop-cascade zeroize discipline without
  introducing new bytes-handling sites. The dedicated
  [`ffi-secret-handling-internal.md`](ffi-secret-handling-internal.md)
  memo walks the bridge layer in detail and covers the foreign-
  runtime heap-copy caveat that the bridge cannot close from the
  Rust side.

- **CLI (`cli/`)** — the `secretary-sync` binary consumes the sync
  layer through its library surface; it does not introduce new
  secret-bearing types. The TTY / stdin password-sourcing path in
  [cli/src/unlock.rs](../../../cli/src/unlock.rs) reads the password
  into a `SecretBytes` and feeds it directly to the core unlock
  entry points without intermediate plaintext.

The pattern from this memo's "Stack-residue gaps fixed" table is now
the cross-codebase expectation. New work that introduces a fresh
`Sensitive::new(stack_var)` site without the accompanying
`stack_var.zeroize()` will fail the FFI memo's "Adding a new bridge
handle" checklist and should fail review here too.

**This section predates, and is narrower than, the rule that supersedes
it.** The trailing-wipe pattern above is correct only when the fill is
provably adjacent to the wrap — see "Panic- and error-safe secret slots"
above and CLAUDE.md's memory-hygiene section for the full E1/E2/E3
analysis. A fresh site with a fallible or panicking call between the fill
and the wrap needs `Sensitive::build` / `try_build` instead, not the
`Sensitive::new(stack_var); stack_var.zeroize();` idiom this paragraph
was written around.

## Deferred items (not addressed in this pass)

The two type-level deferred items from the original audit (record-content
`SecretString` / `SecretBytes` rewrap, and the cosmetic newtype-`Zeroize`
gap) have both been resolved by follow-up passes — see the two "Resolved"
sections above. The remaining deferred items are upstream-managed and
re-numbered §1 / §2 below.

### 1. HKDF internal state residue

`hkdf = "0.12"` does not zeroize its internal HMAC state on drop.
[core/src/crypto/kdf.rs:258-265](../../../core/src/crypto/kdf.rs#L258-L265)
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

### 2. ML-KEM-768 / ML-DSA-65 internal state

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
  As of the 2026-05-28 re-verification, the bridge-side discipline is
  covered by a dedicated companion memo
  ([`ffi-secret-handling-internal.md`](ffi-secret-handling-internal.md));
  the foreign-runtime heap-copy caveat (Python `bytes`, Swift `String`,
  Kotlin `ByteArray` not being authoritatively zeroizable from the
  bridge) remains an inherent property of the FFI boundary and is
  documented per-accessor on the bridge side. The symmetric *inbound*
  residue — uniffi's generated value-marshalling buffers for a
  user-entered password / recovery phrase (#299) — is likewise an
  accepted, in-scope-unfixable FFI-boundary limitation; see
  [`ffi-secret-handling-internal.md`](ffi-secret-handling-internal.md)
  → "Accepted limitation: uniffi value-marshalling secret residue".
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
the established discipline. **That pattern itself only ever covered a
normal-return exit, and the count was one short — see "Panic- and
error-safe secret slots" above** (2026-08-11, #513/#518/#503): a
thirteenth stack-residue gap this pass missed entirely, plus 49 windowed
sites in a class this pass never looked for (an unwinding panic or an
early `?`/`return Err` between the fill and the wipe), are closed by
converting the affected locals to
`Sensitive::build` / `try_build`, which wipes unconditionally via `Drop`
regardless of how the function exits.

The follow-up pass also resolved record-content zeroize at the
in-memory-type level (see "Resolved" above): `RecordFieldValue::
{Text, Bytes}` now wrap `SecretString` / `SecretBytes`, so the
held representation of the most-sensitive data is zeroized on
drop alongside the keys. The wire format and Python conformance
are unchanged. ~~The codec boundary itself still has residual
plaintext lifetime in `ciborium::Value` and the canonical-CBOR
output buffer (see "What is *not* covered" under Resolved); that
narrower gap is flagged for follow-up rather than closed by this
pass.~~ **That codec-boundary gap is what #547/#548 closed** — see
"Resolved: canonical-CBOR codec-boundary residue (#547, #548)" above.
The struck-through sentence described the state as of this
(2026-05-28-era) pass; it is no longer the current state and is kept,
not deleted, so a reader following the document's history can see what
changed and why, per this memo's own correction discipline.

Memory-hygiene status: **clean for v1's Sub-project A scope at the
type level**, with the codec-boundary residue closed to the extent
described in "Resolved: canonical-CBOR codec-boundary residue (#547,
#548)" above — read that section's own "still open" list before calling
this boundary fully clean. The Sub-project D clipboard / mlock
concerns and the upstream-managed crate items remain flagged for
the appropriate later phases.
