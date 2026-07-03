# repair_vault FFI projection + desktop "repair now?" UX — design (#374, Slice A)

**Date:** 2026-07-03
**Issue:** [#374](https://github.com/hherb/secretary/issues/374) (follow-up to #350)
**Scope:** Slice A — make the *existing* fail-closed `repair_vault` reachable end-to-end.
Parts 1 (bridge projection + typed errors), 2 (desktop reference UX), and 4
(device-secret-arm test). **Part 3 (informed-consent adoption of a recipient-
*widening* residue) is explicitly deferred** to its own spec/issue because it
changes `repair_vault`'s core security semantics.

## Problem

#350 shipped the `repair_vault` orchestrator and made `open_vault` fail with
typed recoverable errors on crash residue (`BlockFingerprintMismatch` /
`BlockFileMissing`). But both fold to `FfiVaultError::CorruptVault` at the bridge
([`error/vault/mod.rs`](../../../ffi/secretary-ffi-bridge/src/error/vault/mod.rs)
lines ~530–538), so every downstream app shows a generic corrupt-vault error and
**cannot offer repair**. `repair_vault` itself is not projected onto the FFI at
all. This slice closes both gaps for the safe (fail-closed) cases.

## Non-goals (deferred)

- **Part 3 — informed-consent superset adoption.** `repair_vault` today hard-
  refuses any recipient *widening* regardless of clock relation (the fail-closed
  guard the #350 review hardened; see `repair.rs` Gate 3b and vault-format §6.5).
  A consent flow that shows the recipient delta and adopts a crashed-*share*
  superset requires a new core opt-in policy surface and its own threat
  reasoning. Until it ships, the widening case continues to fail-closed as
  `RepairRejected` with a message that names the added recipients. **No change to
  `repair_vault`'s security semantics in this slice.**
- Recovery/device-secret *desktop* UX. The bridge exposes all three repair arms
  (parity with the three open arms), but the desktop reference UX only wires the
  password arm — the only unlock arm the desktop currently exposes.

## Typed error surface (decided)

Two new `FfiVaultError` variants, projected through every binding + the
Swift/Kotlin conformance harnesses:

| Core `VaultError` | New `FfiVaultError` | Meaning / UX |
| --- | --- | --- |
| `BlockFingerprintMismatch { block_uuid }` (from `open_vault`) | **`VaultNeedsRepair { block_uuid_hex }`** | "This vault has an interrupted write — offer Repair." |
| `RepairRejected { block_uuid, detail }` (from `repair_vault`) | **`RepairRejected { block_uuid_hex, detail }`** | Repair was attempted and refused; `detail` names the recipient delta for equal-clock rejections. Show it; no auto-fix. |
| `BlockFileMissing { block_uuid }` | *unchanged* → `CorruptVault` | Bytes are gone; repair cannot invent them. Genuinely unrepairable — honest as `CorruptVault`. |

Rationale for two variants (not one, not three): the two-signal model lets the UI
structurally distinguish "you may repair" from "repair was refused" without
parsing detail strings, while keeping the unrepairable `BlockFileMissing` folded
to the existing `CorruptVault` (the app's only action there is restore/re-sync,
same as any corruption).

**Obligation:** each new variant adds a workspace-wide exhaustive-match site
(bridge conversion, desktop `AppError` map, uniffi + pyo3 error surfaces) **and**
the Swift/Kotlin `ConformanceErrors.{swift,kt}` harnesses — which `cargo`/`clippy`
cannot see; only `run_conformance.sh` catches a gap. See
[[project_secretary_ffivaulterror_workspace_match]].

## Components

### Core — part 4 only (no semantic change)

Add to [`core/tests/crash_recovery.rs`](../../../core/tests/crash_recovery.rs):

- `repair_vault_adopts_interrupted_save_via_device_secret` — stage a crashed
  `save_block` residue (reuse the existing staging helpers), enroll a device slot,
  then drive `repair_vault` through `Unlocker::DeviceSecret` and assert the block
  is adopted (same gated adoption as the password arm). Proves the device arm is
  not a weaker open, closing the whole-branch-review gap that it was covered only
  transitively via the shared `unlock_vault_identity`.

`repair_vault` itself is untouched.

### Bridge — `secretary-ffi-bridge`

New module `src/repair/` (mirror the `save/` split; keep files < 500 lines). Three
pure fns, each returning `OpenVaultOutput` via the existing
`vault::orchestration::split_core_open_vault`, internally using `&mut OsRng` and
`local_highest_clock: None` (single-device convention, matching
`open_vault_with_password`):

```rust
pub fn repair_vault_with_password(
    folder: &Path, password: &[u8], device_uuid: &[u8; 16], now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError>;

pub fn repair_vault_with_recovery(
    folder: &Path, phrase: &str, device_uuid: &[u8; 16], now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError>;

pub fn repair_vault_with_device_secret(
    folder: &Path, device_uuid: &[u8; 16], device_secret: &[u8; 32], now_ms: u64,
) -> Result<OpenVaultOutput, FfiVaultError>;
```

Notes:
- For the password/recovery arms the unlocking credential does not identify a
  device, so `device_uuid` (the manifest-clock tick key — `repair_vault` calls
  `tick_clock(&mut manifest.vector_clock, &device_uuid)`) is an explicit caller-
  supplied param, exactly like `save_block`.
- For the device-secret arm the **one** `device_uuid` serves both roles: it
  selects the `devices/<uuid>.wrap` slot (`Unlocker::DeviceSecret`) **and** keys
  the manifest tick — the unlocking device *is* the slot's device.
- Credential byte-length validation (`&[u8; 16]` / `&[u8; 32]`) stays at the
  binding wrapper (`InvalidArgument`), per
  [[project_secretary_input_validation_at_binding_wrapper]] — the bridge takes
  fixed-size arrays and trusts its caller.

Error mapping (`error/vault/mod.rs`):
- Add `VaultNeedsRepair { block_uuid_hex: String }` and
  `RepairRejected { block_uuid_hex: String, detail: String }` to `FfiVaultError`.
- Route `VE::BlockFingerprintMismatch { block_uuid }` → `VaultNeedsRepair` (hex-
  encode the uuid); `VE::RepairRejected { block_uuid, detail }` → `RepairRejected`.
  Pull both out of the current catch-all `CorruptVault` fold; leave
  `VE::BlockFileMissing` in it. Update the fold comment.
- `error/vault/tests.rs`: flip the two existing "folds to CorruptVault"
  assertions for these inputs to assert the new typed variants; keep
  `BlockFileMissing` asserting `CorruptVault`.

### uniffi — `secretary-ffi-uniffi`

- `secretary.udl`: two new error variants on the vault-error enum; three new
  namespace functions (`repair_with_password` / `repair_with_recovery` /
  `repair_with_device_secret`) returning `OpenVaultOutput`, taking `bytes
  device_uuid`, `u64 now_ms`, and the credential — mirroring the shape of the
  existing `open_with_*` + `save_block` signatures.
- `namespace/` + `wrappers/`: repair wrappers that validate credential lengths
  (`InvalidArgument`), copy+zeroize the credential like the open wrappers, and
  delegate to the bridge. Value types crossing `runOffMainActor` stay `Sendable`;
  repair runs Argon2id so mobile callers offload (per
  [[project_secretary_ios_value_types_sendable_offload]] — informational; this
  slice adds no iOS UI).
- `tests/swift/ConformanceErrors.swift` + `tests/kotlin/ConformanceErrors.kt`:
  add exhaustive arms for the two new variants. **Run both
  `run_conformance.sh` scripts** — the only check that sees these files.

### pyo3 — `secretary-ffi-py`

- New `src/repair.rs` with the three fns (follow the `device.rs` stack-copy +
  zeroize discipline for the credential arrays; `from_py_object`/`skip_from_py_object`
  discipline per [[project_secretary_pyo3_028_fromtopyobject_deprecation]]).
- `errors.rs`: surface the two new variants.
- pytest: repair happy-adopt (interrupted save) + `RepairRejected` (widening).

### Desktop — reference UX (password arm)

Backend:
- New `read_vault_uuid_from_toml(folder: &Path) -> Result<[u8; 16], AppError>` —
  reads the plaintext `vault_uuid` field from `vault.toml`. Small, pure, TDD'd.
  (vault.toml is a frozen format; `vault_uuid` is a plaintext TOML string.) Needed
  because repair runs *before* a successful open, so the session isn't unlocked
  and `device_uuid` (loaded per-`vault_uuid`) isn't available yet.
- New `commands/repair.rs`: `repair_vault` command + testable `repair_vault_impl`:
  1. gate `folder` against the `VaultFolder` approval slot (identical to
     `unlock_with_password_impl`, `MatchMode::Exact`) → `PathNotApproved` on miss;
  2. `validate_vault_path` (reuse);
  3. `read_vault_uuid_from_toml` → `load_or_create_device_uuid_in`;
  4. `repair_vault_with_password(folder, password, &device_uuid, now_ms())`;
  5. on success, populate the session (mirror `session.unlock`'s post-open block:
     set `inner`, `device_uuid`, idle tracker) and return `ManifestDto` with
     `pending_warnings`.
- Register `repair_vault` in `generate_handler!`; classify it as a **write** in
  `writeCommands.ts` (repair rewrites the signed manifest — the #280 coverage
  test fails otherwise; see [[project_secretary_desktop_generate_handler_writecommands_coverage]]).
- `AppError`: two new variants `VaultNeedsRepair { block_uuid_hex }` +
  `RepairRejected { block_uuid_hex, detail }`, mapped from the new `FfiVaultError`
  variants in the existing `From<FfiVaultError>` match.

Frontend:
- `errors.ts`: two new codes `vault_needs_repair` (`{ blockUuidHex }`) and
  `repair_rejected` (`{ blockUuidHex, detail }`), added to the union + the
  discriminated map.
- ipc wrapper for `repair_vault`.
- Unlock flow: on a `vault_needs_repair` error, render a "This vault has an
  interrupted write. Repair now?" affordance instead of a hard error. On confirm,
  re-invoke `repair_vault` with the same folder + the password **still in the
  form field** (no re-prompt; the password was not yet zeroized — the unlock
  attempt returned an error, the form still holds it). Success → proceed exactly
  as a normal unlock (show manifest + warnings). `repair_rejected` → show
  `detail` (names the recipient delta) with no auto-fix affordance.

### Docs

README/ROADMAP: note repair is now reachable via FFI (all three arms) + the
desktop "repair now?" reference UX; #374 parts 1/2/4 done, part 3 deferred.

## Data flow

```
unlock_with_password
      │  Err(VaultNeedsRepair { block_uuid })
      ▼
UI: "Interrupted write — Repair now?"  ──confirm──▶  repair_vault(folder, pw)
                                                          │
                                    ┌─────────────────────┴─────────────────────┐
                                    ▼                                           ▼
                            Ok(ManifestDto)                          Err(RepairRejected { detail })
                        proceed as normal unlock                  show detail (recipient delta); no auto-fix
```

## Testing

| Layer | Tests |
| --- | --- |
| core | `repair_vault_adopts_interrupted_save_via_device_secret` (part 4) |
| bridge | error-mapping units for the two new variants (flip the CorruptVault assertions; keep `BlockFileMissing`→`CorruptVault`); repair-fn integration over a staged residue vault — happy-adopt + `RepairRejected`(widening) + idempotent healthy-open, password + device-secret arms |
| uniffi | Swift + Kotlin `ConformanceErrors` compile+pass with both new arms (`run_conformance.sh`) |
| pyo3 | pytest: repair happy-adopt + `RepairRejected` |
| desktop backend | `repair_vault_impl` (unapproved-folder rejection); `read_vault_uuid_from_toml` (happy + malformed/missing field) |
| desktop frontend | vitest: needs-repair → confirm → success; rejected → shows detail; `writeCommands.ts` classification |

## Build/verify gates

```bash
# in .worktrees/repair-vault-ffi-374
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py           # desktop/FFI-only; no format drift expected
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
cd desktop && pnpm svelte-check && pnpm test
```

## Risks / open items

- **Two new `FfiVaultError` variants → wide exhaustive-match blast radius.** The
  Swift/Kotlin conformance harnesses are invisible to cargo/clippy; the
  conformance scripts are the only guard. Thread every site in one pass.
- **`read_vault_uuid_from_toml` duplicates a slice of vault.toml knowledge in the
  desktop crate.** Accepted (the desktop already duplicates the canonical
  filenames to avoid a circular dep); the format is frozen. Alternative — a
  bridge `read_vault_uuid(folder)` helper — is deferred as unneeded for one field.
- **Password re-use for the repair confirm depends on the form still holding the
  password.** If the UX zeroizes on error, the confirm must re-prompt. The plan
  must confirm the unlock form retains the password across an error return.
- **Part 3 stays deferred** — the widening case is still `RepairRejected`. This is
  a documented limitation, not a regression.
