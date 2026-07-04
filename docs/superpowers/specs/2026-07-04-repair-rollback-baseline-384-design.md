# Design: repair_vault §10 rollback baseline — verified-uuid keying + fail-closed posture (#384)

**Date:** 2026-07-04
**Issue:** [#384](https://github.com/hherb/secretary/issues/384) — follow-up from the #382 review.
**Branch:** `feature/repair-baseline-384` (worktree `.worktrees/repair-baseline-384`, cut from `main` @ `fc8a53a`).

## Problem

The bridge repair path (`ffi/secretary-ffi-bridge/src/repair/orchestration.rs::load_rollback_baseline`)
loads the §10 rollback baseline **before** core `repair_vault` runs, which forces two compromises
relative to the read-only open path (`enforce_rollback_resistance_in`):

1. **Unverified keying.** The baseline lookup is keyed by the *plaintext* `vault.toml`
   `vault_uuid`, not the verified `manifest.vault_uuid` the open path uses. Sound today only
   because the unlock-time AEAD AAD binds the same `vault_uuid` — an out-of-band guard the
   repair path itself never re-checks.
2. **Fail-open on baseline-load failure.** *Any* failure — including a **present but
   unreadable/undecodable** state file — collapses to `None` → §10 check skipped. Copied from
   the open path, where a skipped check leaks one read and self-heals on the next open. On the
   **mutating** repair path a skipped check lets adoption tick + re-sign the manifest,
   permanently laundering a strictly-dominated (rolled-back) clock into a "concurrent" one no
   future open flags.

Both are latent fragility, not live vulnerabilities (see #384's "why it's safe today").

## Decisions (user-approved 2026-07-04)

- **Posture:** fail **closed on repair only** when the baseline state file is *present but
  unreadable/undecodable/uuid-mismatched*. The never-synced case (missing state file, empty
  clock, or no resolvable state dir) still skips — no false positive. The read-only open path
  keeps its skip posture unchanged (asymmetry is deliberate: read self-heals, mutation launders).
- **Mechanism:** approach A — a **baseline-provider closure** injected into core
  `repair_vault`, invoked with the **verified** `manifest.vault_uuid` in the pre-write window.
  (Rejected: B — uuid-tagged baseline + core cross-check — keeps the plaintext parse and adds an
  unreachable-in-practice mismatch arm; C — core loads the state file itself — couples the
  frozen core to the sync-layer `SyncState` CBOR format, a layering violation.)
- **Error surface:** **no new `VaultError` / `FfiVaultError` variant.** The fail-closed refusal
  is manufactured as an existing `VaultError::Io` and folds through the existing
  `CorruptVault { detail }` conversion arm.

## 1. Core API — `core/src/vault/repair.rs`

`repair_vault` signature change (core-internal API; consumed only by the bridge and core tests):

```rust
pub fn repair_vault(
    folder: &Path,
    unlocker: Unlocker<'_>,
    load_baseline: impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<OpenVault, VaultError>
```

replacing `local_highest_clock: Option<&[VectorClockEntry]>`.

Flow inside `repair_vault`:

1. `unlock_vault_identity` (unchanged).
2. `read_and_verify_manifest(folder, &vault_toml_bytes, &unlocked, None)` — the `None` is
   deliberate; step 8 inside that helper stays untouched for the open/sync callers.
3. **Immediately after** the manifest is verified + decrypted, and **before Pass-1
   classification** (strictly pre-write — nothing staged, nothing ticked):
   ```rust
   let baseline = load_baseline(&manifest.vault_uuid)?; // Err ⇒ abort fail-closed
   if let Some(local) = baseline {
       if manifest::is_rollback(&local, &manifest.vector_clock) {
           return Err(VaultError::Rollback { local_clock: local, incoming_clock: … });
       }
   }
   ```
4. Everything after (classification gates, adoption, tick, atomic manifest rewrite) unchanged.

Guard comment at the call site: the §10 check for repair lives **here**, not in
`read_and_verify_manifest`, because its baseline key is the verified `manifest.vault_uuid`,
which does not exist until after hybrid-verify + AEAD decrypt; and it must run before any
write because a post-write check evaluates the post-tick clock (the #374 lesson: a mutating op
checks §10 **before** it writes).

## 2. Bridge — `ffi/secretary-ffi-bridge/src/repair/orchestration.rs`

- **Delete `load_rollback_baseline`** — including the plaintext `vault.toml` read + decode.
  Asymmetry (1) is removed structurally: no code path keys the baseline by an unverified uuid.
- Add one provider builder shared by all three arms (password / recovery / device-secret; the
  `_in` seams keep their `state_dir: Option<&Path>` parameter):

  | `state::load(state_dir, *verified_uuid)` outcome | Provider returns |
  |---|---|
  | no resolvable `state_dir` (`None`) | `Ok(None)` — no baseline infrastructure = no history |
  | `Ok(state)`, empty `highest_vector_clock_seen` (missing file → `SyncState::empty`, or never-synced) | `Ok(None)` — skip, no false positive |
  | `Ok(state)`, non-empty clock | `Ok(Some(clock))` |
  | `Err(_)` — file present but unreadable (`StateError::Io`), undecodable (`Decode`), or internal-uuid mismatch (`VaultUuidMismatch`) | `Err(VaultError::Io { … })` — **fail-closed** |

- The manufactured error: `context` = a static str naming the failure class
  (e.g. `"§10 rollback baseline state file exists but could not be read"`); `source` =
  `std::io::Error::new(ErrorKind::InvalidData, "<original error>; state file: <path>; deleting it resets this device's rollback history (crypto-design §10) — then retry the repair")`.
  `ErrorKind::InvalidData` is **deliberate**: the `FfiVaultError` `From` impl routes
  `NotFound`/`PermissionDenied`/`NotADirectory` to `FolderInvalid` ("vault path is wrong" — a
  misdiagnosis here) and `AlreadyExists` to `VaultFolderNotEmpty`; `InvalidData` falls to the
  `CorruptVault { detail }` fold, which carries the full context + remedy text. This kind is
  used for **all** load-failure causes, even an underlying `PermissionDenied` on the state file.
- Rewrite the module docs: keying is now structurally verified (the provider receives the
  verified uuid from core); the fail-closed posture is a deliberate divergence from the
  read-only open path, documented with the mutating-vs-read rationale. Drop the now-moot
  AAD-binding soundness argument for plaintext keying.

## 3. Error / FFI surface — zero ripple

No new enum variants anywhere. uniffi, pyo3, desktop `AppError`, the core
`conformance_kat_helpers` matcher, and the Swift/Kotlin `ConformanceErrors` harnesses are all
untouched. Bridge public fn signatures unchanged; only core `repair_vault`'s (internal)
signature changes. Desktop needs no change — the refusal renders through the existing
`CorruptVault` detail path.

## 4. Spec updates (docs-first discipline)

- **`docs/vault-format.md`** — the §9 `repair_vault` recovery paragraph: state that the
  repair-time §10 check is keyed by the **verified** manifest `vault_uuid`, runs **pre-write**
  on the committed clock, and that an *existing-but-unreadable* per-device baseline store fails
  the repair closed, while a missing/never-synced baseline skips the check.
- **`docs/crypto-design.md` §10** — one additive normative sentence: a **mutating** operation
  (repair/merge) MUST evaluate the rollback check before any manifest write and MUST fail
  closed if an existing "highest seen" baseline cannot be read; destroying the baseline remains
  the documented explicit reset.

## 5. Tests (TDD; new tests RED-proven before the fix)

Bridge integration (extend the existing repair test file that carries the #382 rollback
regressions from `c7adb5c` / `0fa1f96`):

- **(a) Corrupt state file:** garbage bytes at `<state-dir>/<vault_uuid_hex>.state.cbor` + crash
  residue → repair refuses; error detail names the state file; **manifest bytes byte-identical**
  before/after. Password arm **and** device-secret arm (parity with the #382 regression pattern).
- **(b) Uuid-mismatched state file:** a validly-encoded `SyncState` whose internal `vault_uuid`
  differs → same refusal shape.
- **(c) Never-synced still adopts:** existing missing-file/empty-baseline adopt tests stay green.
- **(d) Rollback still refused:** the existing #382 rollback-refusal regressions stay green —
  they now also prove the verified-uuid keying end-to-end (baseline seeded under the real vault
  uuid is found via the closure).

Core:

- Provider is invoked with **exactly** the manifest's `vault_uuid` (capture + assert).
- Provider `Err` ⇒ `repair_vault` returns that error and the manifest file is unchanged.
- Existing core `repair_vault` callers update mechanically (`|_| Ok(None)`,
  `|_| Ok(Some(clock.clone()))`).

Full acceptance: `cargo test --release --workspace`; clippy `-D warnings`; `cargo fmt --check`;
rustdoc `-D warnings`; `conformance.py`; Swift + Kotlin `run_conformance.sh` (expected
unchanged — no FFI surface delta); `cd desktop && pnpm test && pnpm svelte-check` (expected
unchanged).

## 6. Out of scope / invariants preserved

- Read-only open path untouched: `enforce_rollback_resistance` keeps its skip posture.
- Sync-layer §10 enforcement untouched.
- `repair_vault`'s adoption gates (hybrid verify, header binding, two-tier freshness,
  recipient-widening refusal) untouched.
- No on-disk format change; no binding-surface change; no desktop UI work.
- #374 part 3 (consent-gated widening adoption) remains deferred and independent.
