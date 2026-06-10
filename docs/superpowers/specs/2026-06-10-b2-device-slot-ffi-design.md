# B.2 — FFI projection of the per-device wrap slot (design)

**Date:** 2026-06-10
**Status:** Approved (brainstorm) — pending implementation plan
**Sub-project:** D.3 (native mobile via uniffi, ADR 0008), Option-B credential model
**Scope:** project the B.1 device-slot folder operations across the FFI surface
(uniffi + pyo3). No Secure Enclave, no biometrics (that is B.3 / #202).
**Issue:** #201

## 1. Context & motivation

B.1 (#211, ADR 0009) landed the per-device wrap-slot **core**: the on-disk format
(`devices/<uuid>.wrap`, `file_kind 0x0004`), the pure crypto (`core/src/unlock/device.rs`:
`wrap_device_slot` / `unwrap_device_slot` / `open_with_device_secret`), and the folder ops
(`core/src/vault/device_slot.rs`: `add_device_slot` / `open_identity_with_device_secret` /
`remove_device_slot`). All headless Rust + a Python clean-room conformance proof.

B.2 makes those operations reachable from the binding languages so a later slice (B.3, the
Secure Enclave / biometric headline) and the automation path can enrol a device, open a vault
from a device secret, and revoke a device. It is an **FFI projection** — no new cryptography.

### The bridge has a folder-in family; B.2 joins it

The bridge exposes **two** families:

- **Pure-bytes** (`create_vault`, `open_with_password`, `open_with_recovery`): bytes in/out,
  the foreign side owns file I/O. Used for vault *creation* (no folder exists yet) and the
  lightweight "just unlock the identity bundle" path. Exercised by the `SmokeBytesIn` tests.
- **Folder-in** (B.4a–d: `open_vault_with_password`, `open_vault_with_recovery`, `read_block`,
  `save_block`, `share_block`, `trash_block`, `restore_block`): take a **folder path**, do
  their own file I/O (including atomic writes via core `write_atomic`), return rich handles
  (`OpenVaultOutput` = identity + manifest). **This is the family the conformance KAT replays**
  — `run_open_password` calls `bridge::vault::open_vault_with_password(&vault_dir, …)` against
  fixture directories.

The device slot is inherently folder-shaped (one file per device under `devices/`), its core
API is already the folder ops, and revoke is a file delete. **B.2 projects the folder-in
layer**, joining the B.4 family. This:

- matches issue #201 (add / open / remove + `DeviceSlotNotFound`),
- preserves the §9 atomic-write guarantee (enrol writes through core `write_atomic`),
- lands the new errors on `FfiVaultError` — matching the B.1 handoff's exact words
  ("promoted to dedicated `FfiVaultError` variants") and the `ConformanceErrors.{swift,kt}`
  harnesses the handoff repeatedly flagged (they enumerate `VaultError`/`VaultException`), and
- reuses the existing `vault_dir` conformance-replay path instead of inventing a bytes-in one.

A pure-bytes projection was considered and rejected: it would be inconsistent with the
folder-in B.4 family, would need a brand-new (non-`vault_dir`) conformance replay path, would
push atomic-write responsibility onto the foreign side, and would not match #201. (An earlier
draft of this spec mistakenly assumed the bridge was pure-bytes-only; the folder-in family
exists and is the right home for these ops.)

## 2. The FFI surface (three folder-in operations + one handle)

All three take a `folder_path` (`bytes`, UTF-8) and mirror the B.4 folder-in conventions.

### `add_device_slot` (enrol)

```
add_device_slot(folder_path, password) -> DeviceEnrollOutput
```

Mirrors core `add_device_slot`: read `vault.toml` + `identity.bundle.enc` from the folder →
`open_with_password` to recover (and validate) the IBK → mint a fresh 16-byte `device_uuid` +
32-byte `device_secret` (OsRng, bridge-internal) → `wrap_device_slot` → **atomically write**
`devices/<uuid>.wrap`. A wrong password errors before any file is written. Returns:

```
DeviceEnrollOutput {
    device_uuid:   Vec<u8>,             // 16 bytes, non-secret
    device_secret: DeviceSecretOutput,  // opaque one-shot handle (below)
}
```

### `open_with_device_secret` (open)

```
open_with_device_secret(folder_path, device_uuid, device_secret) -> OpenVaultOutput
```

Returns the **same `OpenVaultOutput`** (identity + manifest) as `open_vault_with_password`, so
the device path is a first-class vault open ready for B.3's biometric unlock. Implemented by
adding a third arm to the core `Unlocker` enum (see §3); the bridge fn is a sibling of
`open_vault_with_password`.

**Fixed-array bridge signatures (length-validation lives at the binding layer).** Mirroring the
established `block_uuid` pattern, the bridge fns take fixed arrays — `device_uuid: &[u8; 16]`
and `device_secret: &[u8; 32]` — so a wrong-length input is *unrepresentable* at the bridge.
The uniffi/pyo3 namespace fns take `bytes`/`Vec<u8>`, pre-check the length, and raise
`VaultError::InvalidArgument` (uniffi) / `ValueError` (pyo3) on mismatch — exactly as
`save_block` does for `block_uuid`. This keeps wrong-length → `InvalidArgument` **identical
across all bindings** (the bridge never sees a wrong length). The binding zeroizes its transient
`Vec<u8>` and the intermediate `[u8; 32]` after the call.

### `remove_device_slot` (revoke)

```
remove_device_slot(folder_path, device_uuid) -> void
```

Mirrors core `remove_device_slot`: delete `devices/<uuid>.wrap`; a missing file is
`DeviceSlotNotFound`. `device_uuid` bridge-typed `&[u8; 16]`; length validated at the binding
layer as above.

### `DeviceSecretOutput` — one-shot secret handle

The 32-byte device secret is the only secret that exits the boundary. Returned as an opaque
handle copied verbatim from `MnemonicOutput` (the recovery-phrase pattern):

```
DeviceSecretOutput {
    take_secret() -> Option<Vec<u8>>   // Some once, then None (one-shot)
    wipe()                             // idempotent; zeroizes any still-resident secret
}
```

pyo3 surfaces it as `take_secret()` + `close()` + the context-manager protocol, exactly like
pyo3 `MnemonicOutput`. The returned `Vec<u8>`/`bytes` is caller-owned heap; the foreign side
hands it to the Secure Enclave (B.3) and zeroizes its copy.

## 3. Core addition — `Unlocker::DeviceSecret`

`core::vault::orchestrators::open_vault` currently dispatches `Unlocker::Password` and
`Unlocker::Recovery` through its read → unlock → manifest-verify → decrypt sequence. B.2 adds:

```rust
Unlocker::DeviceSecret { device_uuid: &'a [u8; 16], secret: &'a SecretBytes }
```

Its step-2 arm reads `devices/<uuid>.wrap` (absent → `VaultError::DeviceSlotNotFound`) and
routes through the existing `unlock::device::open_with_device_secret`; steps 3–8 (manifest
read, owner-card verify, verify-before-decrypt, rollback check) are unchanged and shared. This
is the only core change — small, additive, and reusing B.1 crypto verbatim. `core::vault::
open_identity_with_device_secret` (identity-only, no manifest) remains for callers that do not
need the manifest; the bridge's `open_with_device_secret` uses the new `Unlocker` arm so it
returns the full `OpenVaultOutput`.

## 4. Error model (3 new `FfiVaultError` variants)

The folder-in ops return `VaultError` → `FfiVaultError`. Mapping (policy matches the existing
`save_block`/`share_block` use of `InvalidArgument` for caller-contract violations, and the
`MalformedBundleFile → CorruptVault` fold precedent):

The bridge's `FfiVaultError` has **no `InvalidArgument` variant** — that is a *uniffi-side*
concept produced by binding-layer length pre-checks (§2). So B.2 adds exactly **3** new
`FfiVaultError` variants; the length-violation cases never reach the bridge.

| Source | FFI mapping | Rationale |
|---|---|---|
| `VaultError::DeviceSlotNotFound` | **NEW** `DeviceSlotNotFound` | Currently folded to `CorruptVault` (vault/mod.rs); promote to honest variant. Returned by open/remove when `devices/<uuid>.wrap` is absent. |
| `Unlock(WrongDeviceSecretOrCorrupt)` | **NEW** `WrongDeviceSecretOrCorrupt` | Parallel to `WrongPassword`/`WrongMnemonic`; anti-oracle (wrong secret vs tamper indistinguishable). App: "device unlock failed → fall back to password". Intercepted in the `VE::Unlock(...)` arm before the `FfiUnlockError` fold. |
| `Unlock(DeviceUuidMismatch)` | **NEW** `DeviceUuidMismatch{detail}` | Structural relabel-integrity signal (header `device_uuid` ≠ filename); B.1 handoff wanted it kept distinct. Intercepted in `VE::Unlock(...)`. |
| `Unlock(MalformedDeviceFile(_))` | fold → `CorruptVault{detail}` | A corrupt wrap file is the same "cannot decode a well-formed v1 file" class as `MalformedBundleFile`. Reaches `CorruptVault` via the existing `VE::Unlock → FfiUnlockError → FfiVaultError` path (the `FfiUnlockError` device fold); pinned by a tripwire. |
| `Unlock(MalformedDeviceSecret{len})` | fold → `CorruptVault{detail}`, **structurally unreachable** | The bridge fn takes `&[u8; 32]`, so core never sees a non-32-byte secret through any FFI surface; the binding raised `InvalidArgument` first. Folded + pinned exactly like `WeakKdfParams` (defensive forward-compat for a direct-bridge caller). |
| wrong-length `device_uuid` / `device_secret` | `InvalidArgument` at the **binding layer** | Bridge takes fixed arrays; the uniffi/pyo3 namespace fns length-check and raise `InvalidArgument`/`ValueError`. Identical across bindings; never a bridge variant. |

**Tripwire inversion.** B.1 added tests pinning the device variants to the defensive
`CorruptVault` fold (one on the `FfiUnlockError` side, one on the `VaultError::DeviceSlotNotFound`
fold). B.2 **inverts** the `DeviceSlotNotFound` one: the test now asserts the promotion. The
`FfiUnlockError` device-fold stays as-is (the pure-bytes `open_with_device_secret` is still not
FFI-surfaced; its variants remain defensively folded) — that tripwire is unchanged. New pin
tests on the `FfiVaultError` side cover: `Unlock(WrongDeviceSecretOrCorrupt)` →
`WrongDeviceSecretOrCorrupt`, `Unlock(DeviceUuidMismatch)` → `DeviceUuidMismatch`,
`Unlock(MalformedDeviceFile)` → `CorruptVault`, and `Unlock(MalformedDeviceSecret)` →
`CorruptVault` (unreachable-fold pin).

## 5. Layering & exhaustive-match sites

`secretary-ffi-bridge` is the single source of truth; uniffi and pyo3 are thin projections.
Adding the three `FfiVaultError` variants ripples through every exhaustive match — Rust sites
are compiler-enforced; the Swift/Kotlin harnesses are **not** (only `run_conformance.sh` sees
them — [[project_secretary_ffivaulterror_workspace_match]]).

**Core (`core/`)**
- `src/vault/orchestrators.rs` — add `Unlocker::DeviceSecret` + its `open_vault` arm (+ unit tests).

**Bridge (`ffi/secretary-ffi-bridge/`)**
- `src/error/vault/mod.rs` — promote `DeviceSlotNotFound`; map the nested `Unlock(...)` device
  errors; invert the B.1 `DeviceSlotNotFound→CorruptVault` tripwire.
- `src/device.rs` (NEW, <500 lines) — `add_device_slot`, `open_with_device_secret`,
  `remove_device_slot`, `DeviceEnrollOutput`, `DeviceSecretOutput`. lib.rs re-exports.

**uniffi (`ffi/secretary-ffi-uniffi/`)**
- `src/secretary.udl` — 3 new `VaultError` variants; 3 namespace functions;
  `DeviceEnrollOutput` dictionary + `DeviceSecretOutput` interface.
- `src/errors/vault.rs` — 3 `From<FfiVaultError>` arms + 1:1 tripwire tests.
- `src/namespace/mod.rs` — the 3 functions (UTF-8 path validation, zeroize the password Vec).
- `src/wrappers/` — `DeviceSecretOutput` object + `DeviceEnrollOutput` dictionary.

**pyo3 (`ffi/secretary-ffi-py/`)**
- `src/device.rs` (NEW) — 3 `#[pyfunction]` + `DeviceSecretOutput` (`take_secret`/`close`/CM
  protocol) + `DeviceEnrollOutput` pyclass.
- `src/errors.rs` — 3 new exception classes (`VaultDeviceSlotNotFound`,
  `VaultWrongDeviceSecretOrCorrupt`, `VaultDeviceUuidMismatch`) + translator arms.
- `src/lib.rs` — register classes + functions.

**Swift / Kotlin harnesses (cargo CANNOT see these)**
- `tests/{swift,kotlin}/ConformanceErrors.{swift,kt}` — add the 3 `VaultError`/`VaultException`
  variant cases (exhaustive-switch / `when` tripwire) + detail extraction.

## 6. Conformance (full cross-language proof)

Extends the existing `vault_dir`-based replay — no new infrastructure shape.

**`conformance_kat.json` (human-reviewed, scoped diff)** — new
`Operation::OpenWithDeviceSecret`, dispatch arm in `core/tests/conformance_kat.rs` **and** the
Swift + Kotlin runners, replaying through `bridge::device::open_with_device_secret(&vault_dir,
…)` exactly like `OpenVaultWithPassword`. Vectors (inputs read from `golden_vault_001_inputs.json`):
- **happy:** open against the B.1 fixture `golden_vault_001/devices/d0d0…d0.wrap` with the
  pinned `device_uuid` + `device_secret` → asserts the same `display_name` / `block_uuid` as
  `open_password_happy` (deterministic, fixed-output).
- **errors:** wrong secret (32 bytes, wrong value) → `WrongDeviceSecretOrCorrupt`; relabeled
  uuid → `DeviceUuidMismatch`; absent slot → `DeviceSlotNotFound` (all three are real bridge
  errors). Short secret (≠32 bytes) → `InvalidArgument` via the existing **synthetic** path
  (`BridgeOrSyntheticErr::Synthetic { variant: "InvalidArgument" }`) — the bridge `&[u8; 32]`
  signature makes a wrong length unrepresentable, so the Rust replay + Swift/Kotlin runners each
  do the length pre-check and synthesize the variant name, exactly as they already do for
  wrong-length `block_uuid`.

**Enrol round-trip (not a fixed-output KAT).** `add_device_slot` uses OsRng, so it has no fixed
output and does **not** fit the fixed-input/fixed-output vector schema. It is proven by
round-trip against a **writable temp copy** of the fixture (the established
`open_vault_with_password_writable` tempdir pattern): `add_device_slot` → `take_secret` →
`open_with_device_secret` with the returned uuid+secret → assert the identity matches the
password path. Covered in:
- Rust bridge integration test, and
- pyo3 pytest, and
- `conformance.py` clean-room (reusing its B.1 `verify_device_slot` primitives), and
- a dedicated **round-trip assertion in the Swift + Kotlin runners** (copies the fixture to a
  temp dir, enrols, opens). This is the only check that exercises the one-shot
  `DeviceSecretOutput` handle end-to-end across the language boundary — a standalone runner
  assertion, **not** a JSON vector.

**`conformance.py`** gains `add_device_slot` (round-trip) + `open_with_device_secret` clean-room
checks reusing the existing `verify_device_slot` primitives.

## 7. Testing & file discipline

- **TDD, spec-first.** Each op is test-driven; new `FfiVaultError` variants land with their
  tripwire/mapping tests in the same step.
- **No hardcoded crypto literals** — pinned `device_uuid` / `device_secret` test inputs come
  from `golden_vault_001_inputs.json` (already holds the B.1 device-slot inputs), per the
  standing rule that literal nonces/keys trip CodeQL.
- **Files <500 lines** — new `bridge/src/device.rs` and `ffi-py/src/device.rs`.
- **Zeroize discipline** — transient foreign-input `password` `Vec<u8>` zeroized after each
  call; `DeviceSecretOutput` is `ZeroizeOnDrop` like `MnemonicOutput`; the minted secret is
  zeroized at the stack source per CLAUDE.md.
- **Smoke parity** — add Swift/Kotlin/pyo3 smoke coverage alongside the existing
  `SmokeFolderIn` device-free folder ops.

## 8. Out of scope

- Secure Enclave / Android StrongBox / biometric key release — **B.3 / #202** (the headline).
- A pure-bytes `open_with_device_secret` (bytes-in) projection — B.3 can add it if the Secure
  Enclave flow needs raw bytes; YAGNI for B.2.
- New cryptography or format change — B.2 is projection + one additive `Unlocker` arm; the
  frozen on-disk format is untouched.

## 9. Acceptance criteria

- `add_device_slot` / `open_with_device_secret` / `remove_device_slot` callable from Swift,
  Kotlin, and Python.
- `DeviceSlotNotFound` / `WrongDeviceSecretOrCorrupt` / `DeviceUuidMismatch` are dedicated
  `FfiVaultError` variants; `MalformedDeviceFile` + (unreachable) `MalformedDeviceSecret` fold to
  `CorruptVault`; wrong-length `device_uuid`/`device_secret` raise `InvalidArgument` at the
  binding layer (bridge takes `&[u8;16]`/`&[u8;32]`); B.1 `DeviceSlotNotFound` tripwire inverted.
- `DeviceSecretOutput` is one-shot (second `take_secret` → None) and `ZeroizeOnDrop`, proven
  across all three bindings.
- `Unlocker::DeviceSecret` added to core with unit tests; `open_with_device_secret` returns a
  full `OpenVaultOutput`.
- `conformance_kat.json` regenerated (scoped diff) with the device-slot happy + 4 error vectors;
  enrol round-trip asserted in the Rust / Python / Swift / Kotlin paths.
- `ConformanceErrors.{swift,kt}` updated for the 3 new variants.
- Full gauntlet green: `cargo clippy --release --workspace --tests -- -D warnings`,
  `cargo test --release --workspace`, `uv run core/tests/python/conformance.py`,
  `uv run core/tests/python/spec_test_name_freshness.py`,
  `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh`,
  `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh`.
