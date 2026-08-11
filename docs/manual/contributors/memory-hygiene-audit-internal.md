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
| 2 | `core/src/unlock/mod.rs::create_vault` | `ibk: [u8; 32]` after `Sensitive::new(ibk)` | `ibk.zeroize()` (replaces a SECURITY note that acknowledged but didn't apply the fix) |
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
is not one. Most of the file's 52 rows aren't duplicated here because 51
of them changed no code, and their reasoning is either trivial ("only
`Sensitive::new` intervenes," the dominant shape below) or already in the
design spec's §3.2/§3.3 — this memo's job is to record what changed and
why, and to give a future auditor enough to re-derive the rest. The 52nd
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
| 1 | `core/src/crypto/kdf.rs::derive_master_kek` | `out` | E2 (`?` on the Argon2 fill) | `try_build` — Task 3 |
| 2 | `core/src/crypto/kdf.rs::derive_recovery_kek` | `out` | E1 (`.expect()` in fill) | `build` — Task 3 |
| 3 | `core/src/crypto/kdf.rs::derive_device_kek` | `out` | E1 | `build` — Task 3 |
| 4 | `core/src/crypto/kem.rs::derive_wrap_key` | `ikm` | E1 (holds *both* KEM shared secrets) | wrapped earlier — `SecretBytes::new` moved before the HKDF call — Task 3 |
| 5 | `core/src/unlock/mnemonic.rs::generate` | `entropy_buf` | E1 | `build` — Task 4 |
| 5a | `core/src/unlock/mnemonic.rs::generate` | `entropy` (§3.4 — the thirteenth gap; never wiped at all, not itself a window) | n/a | built in place via `build`, alongside 5's conversion — Task 4 |
| 6 | `core/src/unlock/mnemonic.rs::parse` | `normalized` | E2 + E3 (#518) | `SecretString::new` — Task 4 |
| 7 | `core/src/unlock/bundle.rs::from_canonical_cbor` | `x25519_sk_bytes` | E2 (#518) | `Option<Sensitive<[u8; N]>>` decode-loop binding — Task 5 |
| 8 | `core/src/unlock/bundle.rs::from_canonical_cbor` | `ed25519_sk_bytes` | E2 (#518) | same shape — Task 5 |
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
