# FFI secret-handling internal audit

This document is the **FFI-boundary secret-handling memo**. Companion to the
[memory-hygiene audit](memory-hygiene-audit-internal.md) and the
[side-channel audit](side-channel-audit-internal.md), both of which
explicitly carved cross-FFI memory hygiene out of their scope. Sub-project B
is now feature-complete through B.6 v2 (Rust core ↔ Python via PyO3, Rust
core ↔ Swift / Kotlin via uniffi), so the cross-FFI surface that those
earlier memos deferred is real code now and needs its own contributor-
facing audit trail.

**Scope:** the bridge crate
[`ffi/secretary-ffi-bridge`](../../../ffi/secretary-ffi-bridge/) plus the
two binding-flavor projection crates `secretary-ffi-py` and
`secretary-ffi-uniffi`, specifically the discipline by which secret bytes
cross the Rust → foreign-language boundary and the lifecycle of
caller-owned secret copies on the foreign side.

Out of scope: the Rust-core discipline that the bridge inherits (covered
by the memory-hygiene and side-channel memos), the wire-format / on-disk
discipline (covered by `docs/crypto-design.md` and `docs/vault-format.md`),
and Sub-project D platform clipboard/UI hygiene.

**Methodology:** for each opaque handle exposed across the FFI, identify
(a) what secret-bearing state it wraps Rust-side, (b) how that state is
projected through the foreign-language boundary (cloned, exposed, or
left opaque), (c) the wipe discipline (idempotency, cascade, drop chain),
(d) the residual exposure on the foreign side that the bridge cannot
control.

**Date:** 2026-05-28 (post-B.6 v2; post-C.2 ✅).

---

## Summary

The bridge layer establishes a **uniform opaque-handle pattern** for
every secret-bearing FFI handle (`UnlockedIdentity`, `MnemonicOutput`,
`OpenVaultManifest`, `BlockReadOutput`, `Record`, `FieldHandle`). The
pattern: `Arc<Mutex<Option<Inner>>>` (or `Mutex<Option<...>>` where
shared-clone semantics aren't needed) so accessors are thread-safe and
non-throwing, wipe is idempotent via `Option::take()`, and the inner
secret-bearing state inherits the Rust-core's `Zeroize, ZeroizeOnDrop`
discipline on drop.

**The bridge handles wipe correctly.** The unfixable residual gap is on
the foreign-runtime side: once a secret is copied out via
`expose_text` / `expose_bytes` / `take_phrase`, it lives in
caller-runtime heap (Python `bytes` / `str`, Swift `String` / `Data`,
Kotlin `ByteArray` / `String`) which the bridge has no authority over.
The accessors are documented as **one-shot read-out boundaries, not
recoverable copies**, and the bridge-side `SecretString` / `SecretBytes`
remains the only authoritative wipe target.

The principal items contributors must hold in mind when modifying the
bridge surface are:

1. **The wipe cascade must remain intact.** Any new handle that wraps
   secret-bearing state must implement `wipe()` (idempotent) and, if
   it owns child handles, cascade `wipe()` to them. Adding a handle
   that wraps a `SecretString` / `SecretBytes` without a corresponding
   `wipe()` method is a regression even though `Drop` would still
   eventually fire — the contract is that the foreign caller can force
   the wipe at a known point.
2. **The opaque-handle pattern is the FFI's `Sensitive<T>` analog.**
   None of Python / Swift / Kotlin has a Rust-style generic
   `Sensitive<T>` wrapper. The opaque handle plus `wipe()` is the
   only authoritative-wipe primitive the bridge can offer. Returning
   a raw `Vec<u8>` / `String` of secret bytes from a new method
   without going through a handle is a foreign-API smell — review.
3. **Read-out methods name the cost.** `expose_*` is the established
   prefix for accessors that copy secret bytes out into caller-owned
   heap; `take_*` is the established prefix for one-shot accessors
   that consume the inner secret and zeroize it as a side effect.
   Don't introduce a `get_*` / `read_*` accessor on a secret field —
   the prefix loses the foreign reader's only signal that this
   call has a residue-on-foreign-heap cost.

---

## Handle inventory

The bridge surface (post-B.6 v2) exposes six handles that wrap
secret-bearing state. Each is `Send + Sync` (via the `Mutex`),
non-throwing on use-after-wipe, and zeroizes its inner state on drop or
explicit `wipe()`.

| Handle | File | Wraps | Cascade | Shared? |
|---|---|---|---|---|
| `UnlockedIdentity` | [`identity.rs`](../../../ffi/secretary-ffi-bridge/src/identity.rs) | `core::UnlockedIdentity` (IBK + 4 secret keys in `Sensitive`) | leaf | no (`Mutex<Option<...>>`) |
| `MnemonicOutput` | [`create.rs`](../../../ffi/secretary-ffi-bridge/src/create.rs) | `core::unlock::mnemonic::Mnemonic` (phrase `String` + entropy `Sensitive<[u8; 32]>`) | leaf | no (`Mutex<Option<...>>`) |
| `OpenVaultManifest` | [`vault.rs`](../../../ffi/secretary-ffi-bridge/src/vault.rs) | IBK `Sensitive<[u8; 32]>` + manifest + envelope + owner card | leaf (cascade-to-Record is via separate `read_block` call, not retained state) | no (`Mutex<Option<...>>`) |
| `BlockReadOutput` | [`record/output.rs`](../../../ffi/secretary-ffi-bridge/src/record/output.rs) | `Vec<Record>` | cascades `wipe()` to each `Record` before clearing the vec | no (`Mutex<Option<...>>`) |
| `Record` | [`record/handle.rs`](../../../ffi/secretary-ffi-bridge/src/record/handle.rs) | non-secret metadata + `Vec<FieldHandle>` | cascades `wipe()` to each `FieldHandle` | **yes** (`Arc<Mutex<Option<...>>>`) |
| `FieldHandle` | [`record/field.rs`](../../../ffi/secretary-ffi-bridge/src/record/field.rs) | `RecordFieldValue` = `Text(SecretString)` or `Bytes(SecretBytes)` | leaf | **yes** (`Arc<Mutex<Option<...>>>`) |

The `Arc<Mutex<Option<...>>>` shape on `Record` and `FieldHandle` is
load-bearing for foreign-side ergonomics: foreign callers can hold a
clone of a `Record` for the lifetime of one screen and the parent
`BlockReadOutput` is free to be wiped independently. A `wipe()` on
either clone wipes the shared underlying state — the inner
`Option::take()` is shared across all `Arc` clones, so every other
clone sees `None` on its next accessor call and falls through to the
non-throwing default. **This is intentional** — the alternative
(per-clone state) would let one Rust-side wipe leave a stale plaintext
copy live behind a foreign clone the bridge no longer tracks.

---

## Wipe discipline

### Idempotency

Every `wipe()` method on every handle uses
`*guard = None` (or `let _ = guard.take()`) so a second `wipe()` call
is a no-op rather than a panic. This is observable in the test suites
under each module (`wipe_then_wipe_is_idempotent` is the canonical
test name; see `record/field.rs:218–222` as the prototype).

### Cascade ordering

`BlockReadOutput::wipe` walks its `records: Vec<Record>` and calls
`wipe()` on each before clearing the vec
([output.rs:90](../../../ffi/secretary-ffi-bridge/src/record/output.rs#L90)).
Each `Record::wipe` in turn walks its `fields: Vec<FieldHandle>` and
calls `wipe()` on each. Each `FieldHandle::wipe` takes the inner
`Option<...>`, which triggers the `RecordFieldValue` drop chain that
zeroizes the wrapped `SecretString` / `SecretBytes`.

The Rust `Drop` chain would also produce this cascade automatically;
the explicit cascade is defense-in-depth and gives foreign callers a
deterministic-time wipe primitive. Both paths converge on the same
`Sensitive`-wrapper drop.

### Use-after-wipe semantics

Accessors on a wiped handle return zero / empty / `None` (whichever
makes sense for the return type) rather than panicking or surfacing a
typed error. The pattern is uniform across modules — see
`lock_or_recover` in
[`sync_helpers.rs`](../../../ffi/secretary-ffi-bridge/src/sync_helpers.rs)
for the Mutex-poison-recovery helper that every accessor uses.

The rationale: foreign-side callers routinely have lingering
references after a programmatic `wipe()` (a UI screen still in scope, a
debounced re-render, etc.). Surfacing a `WipedHandle` error variant on
every accessor would force every foreign call site to wrap in a
`try`/`catch` purely for a no-op-on-wipe path. Returning the
zero-equivalent default lets the foreign caller observe "I'm wiped"
via the value (empty string, all-zero UUID) without exception
handling.

This is one of the few places where the bridge's API deliberately
deviates from "errors are typed; absence is `Option`". The reason is
foreign-ergonomic, not Rust-idiomatic; document it in any new accessor
you add.

---

## Cross-boundary secret-copy accessors

Three accessor families produce foreign-runtime heap copies of secret
bytes. Each one's caveat applies uniformly: **the bridge cannot
zeroize the returned value once it crosses the FFI boundary**. The
only authoritative wipe is `handle.wipe()` on the Rust-side handle.

### `FieldHandle::expose_text` / `expose_bytes`

[`record/field.rs:125`](../../../ffi/secretary-ffi-bridge/src/record/field.rs#L125)
and
[`record/field.rs:152`](../../../ffi/secretary-ffi-bridge/src/record/field.rs#L152).

`FieldHandle::expose_text` returns `Option<String>` (clone of the
inner `SecretString::expose()` via std `to_owned`).
`FieldHandle::expose_bytes` returns `Option<Vec<u8>>` (clone of the
inner `SecretBytes::expose()` via std `to_vec`). `None` is returned
if the field is the other variant or the handle has been wiped.

The clones cross the FFI as the foreign-language's natural string /
byte-array type:

- **Python**: `str` / `bytes`. `str` is interned + immutable; `bytes`
  is immutable. Neither can be authoritatively zeroized from Python
  alone. Foreign callers wanting best-effort cleanup convert
  immediately to `bytearray` and overwrite with zeros, then `del`. The
  immutable interned `str` is the harder case — see the foreign-side
  doc in `secretary-ffi-py/README.md` for the idioms.
- **Swift**: `String` (UTF-8) / `Data`. Both are value types but the
  allocator is not zeroize-aware. The standard idiom is to scope the
  use tightly (`do { let s = handle.exposeText(); use(s); }` so the
  deinit fires at end of block).
- **Kotlin**: `String` / `ByteArray`. `ByteArray` supports `.fill(0)`
  (best-effort); `String` is interned + immutable and cannot be
  authoritatively wiped without going through `CharArray` plumbing,
  which the foreign-side smoke runners don't exercise.

The repeated message in the inline rustdoc on these methods is
"foreign-runtime heap-copy caveat: the [String/Vec] handed back is
*functionally* un-zeroizable in most foreign runtimes." That sentence
is load-bearing — it warns foreign-side reviewers that the only
authoritative wipe is the bridge-side `wipe()`, not whatever the
foreign caller does with the returned value.

### `MnemonicOutput::take_phrase`

[`create.rs`](../../../ffi/secretary-ffi-bridge/src/create.rs)
(see the `take_phrase` impl after the type definition).

Returns `Option<Vec<u8>>` containing the UTF-8 bytes of the 24-word
BIP-39 mnemonic. **One-shot** — the inner `Mnemonic` is consumed and
dropped on the first successful call (which zeroizes the inner
`String` phrase + `Sensitive<[u8; 32]>` entropy); subsequent calls
return `None` rather than an error.

The one-shot semantics are the bridge's discipline equivalent of "the
mnemonic is intended for the user to write down once and never to be
retrieved again". A foreign caller that wants to display the mnemonic
twice (e.g. "confirm your written copy") must hold the bytes
themselves between displays — and zeroize them between displays —
because the bridge will not re-emit them.

### `UnlockedIdentity::display_name` / `user_uuid`

[`identity.rs`](../../../ffi/secretary-ffi-bridge/src/identity.rs).

These are **non-secret** accessors. `display_name` is user-chosen
metadata; `user_uuid` is a public derived identifier. They are listed
here because they share the opaque-handle infrastructure and
contributors might assume the secret-copy caveat applies. It does not.

---

## Bridge-side `Sensitive`-wrapper discipline

The bridge does not introduce new `Sensitive` wrappers — it inherits
the core's. The places where the bridge handles raw `[u8; 32]` /
`Vec<u8>` of secret material follow the established stack-residue
discipline from the memory-hygiene memo.

Three sites worth flagging for contributors modifying the bridge:

1. [`sync/prepare.rs:169`](../../../core/src/sync/prepare.rs#L169) —
   not bridge code, but the sync layer (Sub-project C) was written
   after the memory-hygiene audit and follows the exact pattern:
   ```rust
   let mut x_sk_bytes = *identity.identity.x25519_sk.expose();
   let reader_x_sk: X25519Secret = Sensitive::new(x_sk_bytes);
   x_sk_bytes.zeroize();
   ```
   Mentioned here because contributors evaluating bridge-side secret
   handling should also read the sync-layer call sites to see the
   pattern enforced cross-module.

2. [`sync/commit/write.rs:237`](../../../core/src/sync/commit/write.rs#L237) —
   the parallel `ed_sk_bytes.zeroize()` pattern for the author's
   Ed25519 secret key.

3. The bridge crate itself does **not** expose secret bytes from a
   handle as a raw `*expose()` slice — it always either copies-out
   (via std `to_owned` / `to_vec` for the foreign caller, who then
   owns the residual) or passes through to a Rust-side
   `Sensitive::new(...)` construction. Sites where future bridge work
   might need to copy secret bytes between the inner `Sensitive` and
   a new Rust-side `Sensitive` should follow the
   `bind → wrap → zeroize` pattern verbatim.

---

## Anti-oracle conflation across the FFI

The §13 anti-oracle property
([`docs/threat-model.md`](../../threat-model.md) §13) requires that
"wrong key" and "vault corruption" be indistinguishable to the
adversary on the unlock path. The bridge preserves this via the
`FfiUnlockError::WrongPasswordOrCorrupt` and
`FfiUnlockError::WrongMnemonicOrCorrupt` variants, which are the
**deliberately conflated** terminal classes for the password and
mnemonic unlock paths respectively.

The conflation MUST NOT be split on the foreign side. Splitting
"WrongPassword" from "Corrupt" in a foreign UI would re-introduce the
oracle that the bridge variant collapses. The rustdoc on the
`FfiUnlockError` enum variant pins this; the Python / Swift / Kotlin
projections preserve it (single exception class
`WrongPasswordOrCorrupt`, single Swift / Kotlin enum case).

`InvalidMnemonic { detail }` is a separate variant because it fires
**before** any vault byte is touched (BIP-39 validation) — surfacing
the specific failure mode (wrong word count, unknown word, bad
checksum, invalid UTF-8) gives the user a clear UX path with zero
oracle cost. The detail string is intentionally informational and
should be displayed to the user.

---

## What is *not* covered

The bridge inherits, doesn't fix, the following residual exposures
already flagged in the prerequisite memos:

- **Codec-boundary plaintext residue** (memory-hygiene memo →
  "What is *not* covered" under Resolved). The CBOR encode/decode
  path goes through `ciborium::Value` and a plain `Vec<u8>` canonical
  buffer between the `SecretString` / `SecretBytes` and the AEAD
  call. This applies equally on the bridge side: when
  `read_block` constructs a `FieldHandle`, the secret bytes have
  already been zeroize-typed before reaching the bridge, but the
  intermediate decode buffer between AEAD-decrypt and `SecretString::
  new` is not zeroized. Same exposure window as core; same
  follow-up.
- **Upstream `hkdf` / `ml-kem` / `ml-dsa` internal state**
  (memory-hygiene memo → Deferred items §1, §2). The bridge
  surfaces these primitives via the core API; if upstream zeroize
  support lands, the bridge inherits it without bridge-side work.

The bridge introduces no *new* residual exposures beyond these. The
foreign-runtime heap-copy caveat documented per accessor is not a
"residual exposure" in the memo sense — it's a fundamental property
of the FFI boundary that the bridge documents and works around with
the opaque-handle + `wipe()` primitive.

### Accepted limitation: uniffi value-marshalling secret residue (#299)

The per-accessor foreign-runtime caveat above concerns the **outbound**
direction (`expose_*` / `take_*` returns: Rust → foreign). The
**inbound** direction — a user-entered master password or 24-word
recovery phrase travelling foreign → Rust (`open_vault_with_password` /
`open_vault_with_recovery` / `create_vault_in_folder` / sync) — has a
*distinct*, symmetric residue that no side can scrub. #229 / #298 added
`withZeroizingData` to scrub the iOS adapter-owned `Data` copy, and the
uniffi namespace wrappers (`ffi/secretary-ffi-uniffi/src/namespace/
mod.rs`) `zeroize()` the `Vec<u8>` parameter on both success and error
paths — but **uniffi's generated value-marshalling allocates two further
intermediate copies that neither scrub reaches.**

Confirmed against the actual generated `secretary.swift` (uniffi 0.31,
regenerated via `ios/scripts/build-xcframework.sh`'s bindgen step) and
`uniffi_core` @ `v0.31.0`. For `bytes` arguments, `FfiConverterData.lower`
→ `FfiConverterRustBuffer.lower` does:

```swift
var writer = createWriter()        // [UInt8]  ← residue copy #1 (Swift-side)
write(value, into: &writer)        // appends the plaintext secret bytes
return RustBuffer(bytes: writer)   // memcpy into a Rust-allocated RustBuffer ← copy #2
```

1. **Copy #1 — the Swift `writer: [UInt8]`** holds the plaintext and is
   freed (out of scope at the end of `lower`) **without** zeroize. It is a
   *different* allocation from the adapter `Data` that `withZeroizingData`
   scrubs (`write` only reads *from* the `Data`), so #298 cannot reach it.
2. **Copy #2 — the Rust-allocated `RustBuffer`** is lifted into the
   `Vec<u8>` parameter (which the namespace wrapper *does* `zeroize()`),
   then freed by `uniffi_rustbuffer_free` → `RustBuffer::destroy` →
   `drop(self.destroy_into_vec())`: a **plain `drop` of a `Vec<u8>` with no
   overwrite before `dealloc`.** This free runs in generated scaffolding
   **before** our wrapper body executes, so the wrapper's `password.
   zeroize()` cannot reach copy #2 either.

**Android has the identical residue.** The generated Kotlin
`FfiConverterByteArray.lower` writes the secret into a `ByteBuffer` /
`RustBuffer` with the same lifecycle. This is *distinct* from the #229
finding that Android has no *adapter-owned* copy to scrub (Kotlin forwards
the `ByteArray` directly): the adapter copy and the generated-marshalling
copy are different allocations; the marshalling residue applies to both
bindings.

**Not closeable in any *released* uniffi (as of 0.31.2, 2026-06-16).**
The latest release exposes no config flag, attribute, trait, custom-type
mechanism, or "sensitive"/"secret" wire type that scrubs marshalling
buffers — `custom_type!` only maps to an existing bridge type and then
runs the *standard* `FfiConverter`, producing the same un-scrubbed
copies. The RustBuffer allocator is only the cdylib's global
`#[global_allocator]`; a zeroizing allocator would zero-on-free for the
*entire* crate's heap traffic (heavyweight) and still would not touch
copy #1. Upstream
[mozilla/uniffi-rs#2080](https://github.com/mozilla/uniffi-rs/issues/2080)
(zeroize-on-drop) is **closed** with maintainers explicitly declining
zeroize ("uniffi makes many copies … zeroize seems, frankly,
pointless"); an opt-in `#[uniffi(zeroize)]` was floated but met "probably
no appetite". We have registered the specific secrets-manager consumer
ask on #2080.

**Remediation on the horizon — zero-copy `[ByRef] bytes` (uniffi
[#2864](https://github.com/mozilla/uniffi-rs/issues/2864) /
[#2878](https://github.com/mozilla/uniffi-rs/pull/2878)).** Rather than
scrubbing the marshalling copies, upstream chose to *avoid* them:
[#2878](https://github.com/mozilla/uniffi-rs/pull/2878) (merged to
`main` 2026-05-10, **unreleased** as of 0.31.2) lets an inbound `bytes`
argument declared `[ByRef] bytes` (UDL) / `&[u8]` (proc-macro) travel as
a `ForeignBytes` (pointer + length) — a borrow of foreign memory —
**instead of being copied through a `RustBuffer`.** For synchronous
calls (which all our unlock entry points are) this eliminates *both*
residue copies above: copy #2 (the Rust `RustBuffer`) never exists, and
on Swift the `Data` is passed by pointer with no `createWriter` /
`RustBuffer(bytes:)` dance, so copy #1 never exists either. The foreign
side retains ownership of its buffer, which makes #298's
`withZeroizingData` scrub of the adapter `Data` the *complete* scrub.
(Async args still revert to copying; not applicable here. Kotlin
call sites must pass a *direct* `java.nio.ByteBuffer` rather than a
`ByteArray`.) Once a uniffi release ships #2878, migrating the inbound
secret args (`open_vault_with_password` / `open_vault_with_recovery` /
`create_vault_in_folder`, currently `Vec<u8>`) to `&[u8]` closes this
limitation. Tracked as #307.

**Threat framing.** Worst case is a residency window for one secret copy
in freed-but-not-yet-reused heap — not a logic bug. The core
`Sensitive<T>` / `SecretBytes` discipline is unaffected, and the
idiomatic mitigation (keep secret material behind Rust-owned `Arc`
handles, as the device-unlock path already does) is applied wherever the
secret is *not* user-entered. For inbound user-entered password / phrase
there is no avoidance path in any *released* uniffi as of 0.31.2, so this
is accepted as a limitation of the released value-marshalling model —
**not** an inherent one: the unreleased `[ByRef] bytes` zero-copy path
above is the remediation once it ships. See
[`docs/superpowers/specs/2026-06-25-uniffi-secret-residue-investigation-design.md`](../../superpowers/specs/2026-06-25-uniffi-secret-residue-investigation-design.md)
for the full investigation record.

### Sub-project D platform concerns (carved out)

When the platform UI (Sub-project D, currently in flight as the
Tauri 2 desktop walking skeleton — ADR 0007 + `desktop/`) copies a
secret to the system clipboard, that's a Sub-project D concern that
the bridge cannot reach. The bridge gives the UI the **secret bytes**
via `expose_text` / `expose_bytes`; what the UI does with them
between read and clipboard-clear is Sub-project D's responsibility.

The Tauri 2 desktop scaffold's IPC layer (`desktop/src-tauri/src/`)
re-bridges through `secretary-ffi-py` for the live UI; the same
`expose_*` discipline applies at every IPC `tauri::command` boundary
that returns secret bytes. Contributors adding such commands should
default to opaque-handle equivalents (e.g. return a handle ID and
have the foreground process re-expose on demand) rather than passing
plaintext through IPC.

---

## Adding a new bridge handle

The checklist that follows is the contract a new handle must meet to
preserve the discipline documented above. None of this is enforced by
the compiler; it's enforced by review.

1. **Wrap the secret-bearing inner type in `Mutex<Option<Inner>>`**
   (`Arc<Mutex<Option<Inner>>>` if foreign callers need to hold
   independent clones). `Inner` should not implement `Clone`
   — clones must go through `Arc::clone` on the outer handle.
2. **Make all accessors non-throwing.** Use `lock_or_recover` from
   `sync_helpers.rs` to absorb mutex poison. Return zero /
   empty / `None` for the wiped case.
3. **Implement `wipe()` as `*guard = None`.** Idempotent by
   construction. Add a `wipe_then_wipe_is_idempotent` test.
4. **Cascade `wipe()` to any child handles** the new handle owns.
   See `BlockReadOutput::wipe` and `Record::wipe` for the prototype.
5. **Document the foreign-runtime heap-copy caveat** on any accessor
   that returns secret bytes (`expose_*` / `take_*` prefix). The
   inline rustdoc is the audit trail.
6. **Project through both PyO3 and uniffi.** Method names follow the
   vocabulary in the bridge README ("Foreign-side projection notes"):
   `wipe()` Rust-side; `close()` Python-side; `wipe()` uniffi-side.
7. **Add an integration test under
   `ffi/secretary-ffi-bridge/tests/`** that exercises the
   wipe + use-after-wipe path against `golden_vault_001` (or
   `golden_vault_002`).

---

## Conclusion

The FFI surface inherits the Rust core's secret-handling discipline
(via `SecretString` / `SecretBytes` / `Sensitive<T>`) and adds a
uniform opaque-handle layer on top. The handle layer's contract is
small and consistent: `Arc<Mutex<Option<Inner>>>`, idempotent
`wipe()`, cascade-to-children, non-throwing use-after-wipe.

The unfixable residual is the foreign-runtime heap-copy caveat. The
bridge documents it per accessor and offers `wipe()` on the Rust-side
handle as the only authoritative cleanup primitive. Sub-project D
platform UIs will need to make their own decisions about clipboard
lifetime and IPC plaintext handling; the bridge gives them the raw
material plus the contract, not the policy.

FFI secret-handling status: **clean for v1's Sub-project B scope at
the bridge level**, with the foreign-runtime heap-copy caveat carved
out per-accessor and the Sub-project D platform-policy concerns
flagged for the appropriate later phase.
