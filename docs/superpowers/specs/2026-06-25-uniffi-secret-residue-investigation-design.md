# Design: uniffi value-marshalling secret residue — investigation & disposition (#299)

**Date:** 2026-06-25
**Issue:** #299 (`security`) — "Scrub uniffi-generated lowering buffer for password/phrase
(full FFI-boundary scrub, #229 follow-up)"
**Type:** Investigation + documentation + issue disposition. **No production code change.**

## Problem

PR #298 (#229) added `withZeroizingData` and scrubs the **adapter-owned** `Data` copy at the
iOS password/phrase FFI sites in `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/`. The
Rust namespace wrappers (`ffi/secretary-ffi-uniffi/src/namespace/mod.rs`) additionally
`zeroize()` the `Vec<u8>` parameter on both success and error paths.

Neither scrub reaches the **uniffi-generated marshalling buffers** that the secret transits on
its way across the FFI boundary. A copy of the password / recovery phrase therefore lingers in
generated-code-owned heap after the call returns, beyond what either side can scrub. #299 asks
whether that gap can be closed — the chosen appetite (this session) is to **investigate
upstream uniffi** and document findings, commenting upstream if warranted.

## Investigation findings (grounded)

### The residue path — two uncontrolled copies

Confirmed by reading the **actual** generated `secretary.swift` (uniffi 0.31, regenerated from
the host cdylib via `ios/scripts/build-xcframework.sh`'s bindgen step) and `uniffi_core`
@ `v0.31.0`:

Inbound secret, Swift → Rust (e.g. `openVaultWithPassword(folderPath:password:)`):

1. `FfiConverterData.lower(password)` → `FfiConverterRustBuffer.lower` (generated
   `secretary.swift`):
   ```swift
   public static func lower(_ value: SwiftType) -> RustBuffer {
       var writer = createWriter()        // [UInt8]  ← residue copy #1
       write(value, into: &writer)        // appends the plaintext secret bytes
       return RustBuffer(bytes: writer)   // copies into a Rust-allocated RustBuffer ← residue copy #2
   }
   ```
   - **Copy #1 — Swift `writer: [UInt8]`:** holds the plaintext; goes out of scope at the end
     of `lower` and is freed **without** zeroize. Not reachable from `withZeroizingData` (that
     scrubs the adapter `Data`, a *different* allocation that `write` reads *from*).
   - **Copy #2 — the Rust-allocated `RustBuffer`:** `RustBuffer(bytes:)` →
     `RustBuffer.from(ptr)` → `ffi_secretary_ffi_uniffi_rustbuffer_from_bytes(ForeignBytes(...))`
     memcpys the bytes into a buffer allocated by Rust's global allocator.

2. On the Rust side, the uniffi scaffolding lifts copy #2 into the `Vec<u8>` parameter (which
   our namespace wrapper *does* `zeroize()`), then frees the `RustBuffer` via
   `uniffi_rustbuffer_free` → `RustBuffer::destroy` → `drop(self.destroy_into_vec())`. That is a
   **plain `drop` of a `Vec<u8>` — no overwrite before `dealloc`.** Critically, this free runs
   in generated scaffolding **before** our `open_vault_with_password` body executes, so our
   `password.zeroize()` cannot reach copy #2 either.

Net: a plaintext copy survives in (a) the freed Swift `writer` array and (b) the freed Rust
`RustBuffer` allocation, until each heap region is reused. Both are in code we do not author.

### Is it closeable in-scope? No.

- **No hook in uniffi 0.31.** uniffi 0.31 (current head 0.31.2, released 2026-06-16) exposes no
  config flag, attribute, trait, custom-type mechanism, or "sensitive"/"secret" wire type that
  scrubs marshalling buffers. `custom_type!` / `custom_newtype!` only transform a Rust type into
  an existing bridge type (e.g. `Vec<u8>`); the lift/lower then runs the *standard*
  `FfiConverter`, producing the **same** un-scrubbed copies. The CHANGELOG through `Unreleased`
  has zero entries mentioning zeroize / secret / sensitive / scrub.
- **The allocator is a coarse global knob, not a per-type hook.** RustBuffer alloc/free are
  monomorphized per component, but the only override point is the cdylib's
  `#[global_allocator]`. A zeroizing `GlobalAlloc` would zero-on-free for the *entire* crate's
  heap traffic (heavyweight) and **still would not touch copy #1** (the Swift-side array). Not
  proportionate to "one secret copy in freed heap".
- **Upstream has already declined.** Issue
  [mozilla/uniffi-rs#2080](https://github.com/mozilla/uniffi-rs/issues/2080) ("Deriving
  `uniffi::Record` together with `ZeroizeOnDrop` does not compile. Solvable?") is **closed**.
  Maintainer position: @jplatte — "for zeroize in particular I think you'd be defeating the
  purpose of that derive since UniFFI would be creating copies of the bytes that don't get
  zeroized on drop"; he floated an opt-in `#[uniffi(zeroize)]` but added "probably no appetite
  for it by the maintainers." @mhammond — "uniffi makes *many* copies … zeroize seems, frankly,
  pointless." This treats the residue as an **inherent property of the value-marshalling
  model**, not a bug.
- **No newer release helps.** There is no uniffi > 0.31.2 as of 2026-06; no migration closes
  the gap.

### Android has the identical residue

The generated Kotlin `FfiConverterByteArray.lower` writes the secret into a `ByteBuffer` /
`RustBuffer` with the same lifecycle (lifted into `Vec<u8>` Rust-side, then freed unscrubbed).
Note this is **distinct** from the #229 finding that Android has *no adapter-owned copy* to
scrub (Kotlin forwards the `ByteArray` directly): the adapter copy and the
generated-marshalling copy are different allocations. The marshalling residue applies equally
to both bindings.

### Threat framing

Worst case is a **residency window for one secret copy in freed-but-not-yet-reused heap** —
not a logic bug, and the core `Sensitive<T>` / `SecretBytes` zeroize discipline is unaffected.
An attacker would need to read process heap (a core-dump / live-memory capture) in the window
between the call returning and the allocator reusing those regions. This is the same residual
class the issue itself anticipated and labelled lower-priority than the core discipline.

### Idiomatic mitigation (already in use where applicable)

The uniffi-blessed way to minimize residue is to keep secret material **behind Rust-owned
`Arc` handles** rather than ferrying raw bytes across the boundary — exactly the existing
device-unlock shape (the secret goes in, the work happens behind the FFI, no raw key material
is returned). For **inbound user-entered** secrets (master password / 24-word recovery phrase)
there is no way to avoid the marshalling copies in any released uniffi; this is the unavoidable
case and is accepted.

## Disposition (the deliverables)

1. **Memo section** — add an "Accepted limitation: uniffi value-marshalling secret residue
   (#299)" subsection to `docs/manual/contributors/memory-hygiene-audit-internal.md` capturing
   the residue path, the two copies, the in-scope-unfixable evidence (uniffi 0.31.2 + #2080),
   the Android-equivalent note, threat framing, and the idiomatic mitigation. This is the
   durable home (the memo is the principal handoff doc for the paid external review and already
   has a "Deferred items" / "Out of scope" structure for exactly this kind of accepted
   residual).

2. **Upstream comment on #2080** — a constructive comment from a real secrets-manager consumer:
   precise residue locations (the two copies above) + the specific opt-in `#[uniffi(zeroize)]`
   ask that @jplatte himself floated. No new issue (the question was already asked and declined;
   a duplicate would be unwelcome). The comment text is reviewed before posting.

3. **Close #299** referencing the memo section + #2080 with the documented rationale.

## Out of scope

- Any change to generated code, the uniffi version, or a custom FFI shim (the residue is
  inherent to value marshalling; a non-uniffi raw-pointer shim collides with the workspace
  `#![forbid(unsafe_code)]` invariant and is disproportionate to the threat).
- VM-owned input-array scrubbing (separate concern, already documented under #229).
- The outbound (Rust → Swift) secret-return path (`take_phrase` / `take_secret`): it has the
  *mirror* residue, but #299 is scoped to the inbound password/phrase path. Noted in the memo
  for completeness, not addressed here.

## Testing

None. There is no code or observable behavior change to test. Verification is:
- the generated-code residue path is grounded in the actual regenerated `secretary.swift`
  (re-checkable via the bindgen step) and `uniffi_core` v0.31.0 source;
- `cargo`/`clippy`/conformance/Swift+Kotlin-conformance gates are unaffected (zero `core/` and
  zero FFI-crate source files touched);
- the memo edit is prose-only.

## README / ROADMAP

Unchanged. Documentation of an accepted FFI-boundary limitation introduces no capability and
ticks no milestone — matching the pure-hardening precedent (#210 / #251 / #229 / #300).
