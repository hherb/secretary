# repair_vault §10 Baseline Hardening (#384) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Key the repair-time §10 rollback baseline off the *verified* manifest `vault_uuid` (not the plaintext `vault.toml` value) and fail the mutating repair closed when an existing baseline state file cannot be read.

**Architecture:** Core `repair_vault` swaps its pre-loaded `local_highest_clock: Option<&[VectorClockEntry]>` parameter for an injected baseline-provider closure invoked with the verified `manifest.vault_uuid` in the pre-write window; the bridge supplies the closure over `secretary_cli::state::load` and maps a present-but-unreadable state file to a fail-closed `VaultError::Io` (folding through the existing `CorruptVault { detail }` FFI arm — **zero new enum variants anywhere**).

**Tech Stack:** Rust (stable, workspace), `secretary-core`, `secretary-ffi-bridge`, `secretary-cli` state store. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-04-repair-rollback-baseline-384-design.md` (committed as `625d409`). Issue: #384.

## Global Constraints

- Work in `/Users/hherb/src/secretary/.worktrees/repair-baseline-384` on branch `feature/repair-baseline-384`. Every command below runs from that directory (absolute paths in `cd` chains; shell state does not persist between Bash calls).
- Always build/test `--release` (crypto crates are unusably slow in debug): `cargo test --release --workspace`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`. Format with `cargo fmt --all`.
- `#![forbid(unsafe_code)]` workspace-wide. No new dependencies. **No new `VaultError` or `FfiVaultError` variants** (the whole design avoids the workspace-wide exhaustive-match ripple).
- The read-only open path (`enforce_rollback_resistance` in `ffi/secretary-ffi-bridge/src/vault/orchestration.rs`) is **out of scope — do not touch it**. Same for the sync layer and `repair_vault`'s adoption gates (recipient-widening refusal etc.).
- Test crypto values are RNG-derived (`ChaCha20Rng::from_seed`), never hardcoded key/nonce literals (CodeQL gate). Test seeds used below (`0x71/0x72` core, `0x98/0x99/0x9a` bridge) are chosen disjoint from existing seeds in their files and from the golden-vault mint seeds `0xA0/0xA1/0xA2`.
- Commit after every task; end commit messages with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Core — verified-uuid baseline provider + pre-write §10 gate

The core mechanism: `repair_vault` takes a provider closure, invokes it with the verified manifest uuid strictly before any staging/tick/write, propagates provider errors fail-closed, and runs `is_rollback` itself. The bridge is mechanically adapted in the same task (its old signature won't compile otherwise) but keeps its current *fail-open* posture on state-load errors — Task 2 flips that with its own RED cycle.

**Files:**
- Modify: `core/src/vault/repair.rs` (signature at line ~173, gate insertion after line ~184, doc comment)
- Modify: `core/tests/crash_recovery.rs` (2 new tests; 12 mechanical call-site updates at lines 442, 530, 615, 716, 854, 939, 1056, 1185, 1274, 1353, 1397, 1435)
- Modify: `ffi/secretary-ffi-bridge/src/repair/orchestration.rs` (delete `load_rollback_baseline`, add `baseline_provider`, rewire 3 arms, rewrite module-doc keying text)

**Interfaces:**
- Consumes: `secretary_core::vault::manifest::is_rollback(local: &[VectorClockEntry], incoming: &[VectorClockEntry]) -> bool` (pub, `core/src/vault/manifest.rs:1814`); `secretary_cli::state::load(state_dir: &Path, vault_uuid: [u8; 16]) -> Result<SyncState, StateError>` (missing file ⇒ `Ok(SyncState::empty(...))`, present-but-bad ⇒ `Err`).
- Produces (Task 2 and all later tasks rely on these exact shapes):
  - `pub fn repair_vault(folder: &Path, unlocker: Unlocker<'_>, load_baseline: impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError>, device_uuid: [u8; 16], now_ms: u64, rng: &mut (impl RngCore + CryptoRng)) -> Result<OpenVault, VaultError>`
  - bridge-private `fn baseline_provider(state_dir: Option<&Path>) -> impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError> + '_`

- [ ] **Step 1: Write the two failing core tests**

Append to `core/tests/crash_recovery.rs` (conventions mirror `repair_vault_adopts_interrupted_save` at line 403; `make_fast_vault` / `make_simple_plaintext` / `fs` / `VaultError` are already in scope):

```rust
/// #384: the §10 baseline provider must be invoked with the VERIFIED
/// manifest `vault_uuid` (available only after hybrid-verify + AEAD
/// decrypt) — never a plaintext-derived value. Pins the keying half of
/// the #384 hardening at the core seam.
#[test]
fn repair_passes_verified_manifest_uuid_to_baseline_provider() {
    let (dir, _mnemonic, pw) = make_fast_vault(71, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let expected_uuid = open.manifest.vault_uuid;
    let (device_uuid, block_uuid) = ([0xd1; 16], [0xb1; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    // Crash simulation: the v2 block hit disk, the v2 manifest didn't.
    fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    let mut seen: Option<[u8; 16]> = None;
    let repaired = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |uuid: &[u8; 16]| {
            seen = Some(*uuid);
            Ok(None)
        },
        device_uuid,
        3_000,
        &mut rng,
    )
    .expect("adoptable residue with an empty baseline must repair");
    drop(repaired);
    assert_eq!(
        seen,
        Some(expected_uuid),
        "provider must be keyed by the verified manifest vault_uuid"
    );
}

/// #384: a baseline-provider error must abort the repair FAIL-CLOSED —
/// propagated before anything is staged or written. Pins the posture
/// half of the #384 hardening at the core seam (the bridge maps its
/// state-store failures onto exactly this contract).
#[test]
fn repair_aborts_when_baseline_provider_errors() {
    let (dir, _mnemonic, pw) = make_fast_vault(72, "Owner");
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    let mut open = open_vault(folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xd2; 16], [0xb2; 16]);
    let recipients = vec![open.owner_card.clone()];
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    let before = fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let err = secretary_core::vault::repair_vault(
        folder,
        Unlocker::Password(&pw),
        |_: &[u8; 16]| {
            Err(VaultError::Io {
                context: "test: baseline store unreadable",
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "seeded failure"),
            })
        },
        device_uuid,
        3_000,
        &mut rng,
    )
    .expect_err("a provider error must refuse the repair");
    assert!(
        matches!(err, VaultError::Io { context, .. } if context == "test: baseline store unreadable"),
        "the provider's own error must propagate, got {err:?}"
    );
    assert_eq!(
        fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "refused repair must not mutate the manifest"
    );
}
```

- [ ] **Step 2: Run to verify RED**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && cargo test --release --workspace --test crash_recovery 2>&1 | tail -20`
Expected: **compile error** on the two new tests — `expected Option<&[VectorClockEntry]>, found closure` (the new provider signature does not exist yet). This is the RED for an API-introduction change; the *behavioral* RED for the posture lives in Task 2.

- [ ] **Step 3: Change the core signature + insert the pre-write gate**

In `core/src/vault/repair.rs`:

(a) Extend the manifest import (line 24):

```rust
use super::manifest::{is_rollback, BlockEntry, Manifest};
```

(b) Replace the signature (lines ~173-180) — `local_highest_clock: Option<&[VectorClockEntry]>` becomes the provider:

```rust
pub fn repair_vault(
    folder: &Path,
    unlocker: Unlocker<'_>,
    load_baseline: impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<OpenVault, VaultError> {
```

(c) Replace the first two statements of the body (lines ~181-184). The old comment said "Same unlock + §10-checked manifest verify as open_vault"; §10 now runs explicitly below, so `read_and_verify_manifest` gets `None`:

```rust
    // Same unlock + §1 verify-before-decrypt manifest sequence as
    // open_vault. §10 runs explicitly below (not inside
    // read_and_verify_manifest) — see the gate comment.
    let (vault_toml_bytes, unlocked) = unlock_vault_identity(folder, unlocker)?;
    let (owner_card, mut manifest, manifest_file, _envelope_bytes) =
        read_and_verify_manifest(folder, &vault_toml_bytes, &unlocked, None)?;

    // §10 pre-write gate (#384): keyed by the VERIFIED manifest
    // `vault_uuid` — available only now, after hybrid-verify + AEAD
    // decrypt — never by the plaintext `vault.toml` value. It must run
    // HERE, before Pass 1 stages anything and before the adopt/tick/
    // manifest rewrite below: a post-write check would evaluate the
    // post-tick clock, where the local tick flips a strictly-dominated
    // (rollback) committed clock into an unflagged "concurrent" one,
    // masking the rollback permanently. A provider error propagates
    // fail-closed — nothing has been staged or written yet.
    if let Some(local) = load_baseline(&manifest.vault_uuid)? {
        if is_rollback(&local, &manifest.vector_clock) {
            return Err(VaultError::Rollback {
                local_clock: local,
                incoming_clock: manifest.vector_clock.clone(),
            });
        }
    }
```

(d) In the `repair_vault` doc comment, find the paragraph beginning `/// Goes through the same `unlock_vault_identity` +` (line ~158) and replace its first sentence so the §10 wording matches the new mechanism:

```rust
/// Goes through the same `unlock_vault_identity` +
/// `read_and_verify_manifest` §1 verify-before-decrypt sequence as
/// `open_vault`, then evaluates the §10 rollback check itself — keyed by
/// the **verified** `manifest.vault_uuid` handed to `load_baseline`, on
/// the committed (pre-tick) clock, strictly before any write; a
/// `load_baseline` error refuses the repair fail-closed (#384). The
/// repair path is never a weaker open than a normal
/// one; it only widens what happens *after* the manifest is
/// authenticated.
```

- [ ] **Step 4: Update the 12 existing core call sites**

In `core/tests/crash_recovery.rs`, every existing `repair_vault(` call (lines 442, 530, 615, 716, 854, 939, 1056, 1185, 1274, 1353, 1397, 1435 pre-edit) passes `None,` as the third argument. Replace that third argument with `|_| Ok(None),` at all 12 sites. Verify none were missed:

Run: `grep -n "repair_vault(" -A 3 core/tests/crash_recovery.rs | grep -c "|_| Ok(None)"`
Expected: `12`

- [ ] **Step 5: Adapt the bridge (mechanical; posture unchanged until Task 2)**

In `ffi/secretary-ffi-bridge/src/repair/orchestration.rs`:

(a) Extend the core import (line 43):

```rust
use secretary_core::vault::{repair_vault, Unlocker, VaultError, VectorClockEntry};
```

(b) Delete `load_rollback_baseline` (lines 48-85) **including its doc comment**, and add in its place:

```rust
/// Build the §10 rollback-baseline provider shared by the three repair
/// arms. Core `repair_vault` invokes the returned closure with the
/// **verified** `manifest.vault_uuid` (post hybrid-verify + AEAD
/// decrypt), so the state lookup can never be keyed by an
/// attacker-controlled plaintext value (#384). A `None` state dir (no
/// resolvable OS state dir) and an empty baseline (missing state file /
/// never-synced device) both yield `Ok(None)` — §10 is skipped with no
/// false positive on a fresh device.
fn baseline_provider(
    state_dir: Option<&Path>,
) -> impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError> + '_ {
    move |vault_uuid: &[u8; 16]| {
        let Some(state_dir) = state_dir else {
            return Ok(None);
        };
        match secretary_cli::state::load(state_dir, *vault_uuid) {
            Ok(state) => {
                let clock = state.highest_vector_clock_seen;
                // Empty baseline (never-synced) is indistinguishable from
                // no baseline for §10 purposes; skip (no false positive).
                Ok((!clock.is_empty()).then_some(clock))
            }
            // Interim fail-open posture — flipped to fail-closed in the
            // next commit (#384 posture half, RED-proven there).
            Err(_) => Ok(None),
        }
    }
}
```

(c) In each of the three `_in` fns, delete the `let baseline = load_rollback_baseline(state_dir, folder);` line and the `// Pass the baseline as \`local_highest_clock\`…` comment block above the `repair_vault(` call, and change the third argument from `baseline.as_deref(),` to `baseline_provider(state_dir),`. Example (password arm; recovery and device-secret arms are identical in shape):

```rust
    let pw = SecretBytes::new(password.to_vec());
    // Core invokes the provider with the VERIFIED manifest vault_uuid and
    // runs the §10 check on the COMMITTED clock before it ticks/rewrites
    // the manifest — the pre-write gate for this mutating path (module docs).
    let core_out = repair_vault(
        folder,
        Unlocker::Password(&pw),
        baseline_provider(state_dir),
        *device_uuid,
        now_ms,
        &mut OsRng,
    )?;
```

(d) Rewrite the module-doc paragraph about keying (lines ~25-37, from `The baseline is keyed by the `vault_uuid` from the` through `…which is no longer made here.`) to:

```rust
//! So we hand core `repair_vault` a baseline *provider* instead of a
//! pre-loaded clock. Core invokes it with the **verified**
//! `manifest.vault_uuid` — available only after hybrid-verify + AEAD
//! decrypt — inside the pre-write window, so the baseline lookup can
//! never be keyed by an attacker-controlled plaintext value. (The
//! previous design keyed it off the plaintext `vault.toml` `vault_uuid`
//! and relied on the unlock-time AEAD AAD binding as an out-of-band
//! guard; #384 removed that reliance.) A provider error propagates
//! fail-closed before anything is staged or written. This replaces the
//! original (buggy) post-write `enforce_rollback_resistance` call.
```

- [ ] **Step 6: Run the workspace tests + clippy**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && cargo test --release --workspace 2>&1 | tail -5 && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3 && cargo fmt --all`
Expected: all tests pass — including the 2 new core tests, the existing 12 core repair tests, and the bridge `repair/tests.rs` Cases 1-6 (Case 5/6 seed a valid dominating baseline under the real vault uuid; they now prove the verified-uuid keying end-to-end). Clippy clean.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && git add core/src/vault/repair.rs core/tests/crash_recovery.rs ffi/secretary-ffi-bridge/src/repair/orchestration.rs && git commit -m "core+bridge: key repair §10 baseline off the verified manifest uuid (#384)

repair_vault now takes a baseline-provider closure invoked with the
verified manifest.vault_uuid in the pre-write window; the bridge's
plaintext-vault.toml keying (and its reliance on the unlock AAD as an
out-of-band guard) is deleted. Provider errors propagate fail-closed at
the core seam; the bridge still maps state-load errors fail-open until
the posture flip lands (next commit, RED-proven).

Refs #384

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Bridge — fail closed on an existing-but-unreadable §10 baseline

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/repair/tests.rs` (3 new tests, appended after Case 6)
- Modify: `ffi/secretary-ffi-bridge/src/repair/orchestration.rs` (flip the provider's `Err` arm; extend module doc + provider doc)

**Interfaces:**
- Consumes: `baseline_provider` from Task 1; `secretary_cli::state::{save, state_file_path}` (both pub); `secretary_core::sync::SyncState::new(vault_uuid, clock)` (already used by Case 5/6); `FfiVaultError::CorruptVault { detail }` where `detail = format!("{VaultError}")` and `VaultError::Io` displays as `"vault I/O error ({context}): {source}"` — so both the context and the remedy text inside `source` surface in `detail`.
- Produces: the final provider `Err` arm (below); tests asserting `detail` contains `"rollback baseline"` and `"resets this device's rollback history"`.

- [ ] **Step 1: Write the three failing tests**

Append to `ffi/secretary-ffi-bridge/src/repair/tests.rs` (all fixture helpers already in the file; `VectorClockEntry` and `secretary_cli::state` paths already used by Case 5/6):

```rust
/// #384 posture (password arm): an EXISTING but unreadable/undecodable
/// §10 baseline state file must refuse the MUTATING repair fail-closed —
/// a skipped check here would let adoption tick + re-sign the manifest,
/// permanently laundering a rolled-back clock. The refusal surfaces as
/// `CorruptVault` whose detail names the state file and the documented
/// remedy (delete it = the crypto-design §10 reset); the manifest must be
/// byte-for-byte untouched. Missing-file/never-synced keeps adopting
/// (Cases 1/2 pin that branch).
#[test]
fn repair_refuses_unreadable_rollback_baseline_and_leaves_manifest_untouched() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x98; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe7; 16], [0xf7; 16]);
    let recipients = vec![open.owner_card.clone()];
    let vault_uuid = open.manifest.vault_uuid;

    // Stage genuine adoptable crash residue (crashed save, v2 on disk).
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    // Sanity: adoptable residue, not pre-existing corruption.
    assert!(
        matches!(
            open_vault_with_password(&folder, &pw),
            Err(FfiVaultError::VaultNeedsRepair { .. })
        ),
        "residue must be adoptable crash residue",
    );

    // A PRESENT but garbage state file at the exact path load() reads.
    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let before = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let err =
        repair_vault_with_password_in(Some(state_dir.path()), &folder, &pw, &device_uuid, 3_000)
            .expect_err("existing-but-unreadable baseline must refuse the mutating repair");
    match err {
        FfiVaultError::CorruptVault { detail } => {
            assert!(
                detail.contains("rollback baseline"),
                "detail must name the failing store: {detail}"
            );
            assert!(
                detail.contains("resets this device's rollback history"),
                "detail must carry the documented remedy: {detail}"
            );
        }
        other => panic!("expected CorruptVault, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

/// #384 posture (device-secret arm): same contract as the password-arm
/// test above, proven end-to-end through the device-secret unlock path
/// (arm parity — mirrors how Case 5/6 pin the rollback gate on both arms).
#[test]
fn repair_device_secret_refuses_unreadable_rollback_baseline() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let mut rng = ChaCha20Rng::from_seed([0x99; 32]);

    let enrolled = add_device_slot(&folder, &pw).expect("add_device_slot must succeed");
    let device_uuid: [u8; 16] = enrolled
        .device_uuid
        .as_slice()
        .try_into()
        .expect("device_uuid must be 16 bytes");
    let device_secret_bytes = enrolled
        .device_secret
        .take_secret()
        .expect("first take_secret must return Some");
    let device_secret: [u8; 32] = device_secret_bytes
        .as_slice()
        .try_into()
        .expect("device secret must be 32 bytes");

    let device_secret_sb = SecretBytes::new(device_secret.to_vec());
    let dev_unlocker = || Unlocker::DeviceSecret {
        device_uuid: &device_uuid,
        secret: &device_secret_sb,
    };
    let mut open = open_vault(&folder, dev_unlocker(), None).unwrap();
    let block_uuid = [0xf8; 16];
    let recipients = vec![open.owner_card.clone()];
    let vault_uuid = open.manifest.vault_uuid;
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    std::fs::write(
        secretary_cli::state::state_file_path(state_dir.path(), vault_uuid),
        b"not a canonical SyncState",
    )
    .unwrap();

    let before = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let err = repair_vault_with_device_secret_in(
        Some(state_dir.path()),
        &folder,
        &device_uuid,
        &device_secret,
        3_000,
    )
    .expect_err("existing-but-unreadable baseline must refuse the mutating repair");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}

/// #384 posture: a validly-encoded SyncState whose INTERNAL vault_uuid
/// differs from the file's path key (`StateError::VaultUuidMismatch`) is
/// "present but not usable" — same fail-closed refusal as garbage bytes,
/// NOT a silent skip (a skip would let a planted/mislabelled state file
/// neutralize §10 on the mutating path).
#[test]
fn repair_refuses_uuid_mismatched_rollback_baseline() {
    let (_tmp, folder) = tmp_golden_vault();
    let state_dir = tempfile::tempdir().unwrap();
    let pw = golden_password();
    let pw_secret = SecretBytes::new(pw.clone());
    let mut rng = ChaCha20Rng::from_seed([0x9a; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw_secret), None).unwrap();
    let (device_uuid, block_uuid) = ([0xe9; 16], [0xf9; 16]);
    let recipients = vec![open.owner_card.clone()];
    let vault_uuid = open.manifest.vault_uuid;
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v1"),
        &recipients,
        device_uuid,
        1_000,
        &mut rng,
    )
    .unwrap();
    let manifest_v1 = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    save_block(
        &folder,
        &mut open,
        make_simple_plaintext(block_uuid, "v2"),
        &recipients,
        device_uuid,
        2_000,
        &mut rng,
    )
    .unwrap();
    drop(open);
    std::fs::write(folder.join("manifest.cbor.enc"), &manifest_v1).unwrap();

    // A validly-encoded SyncState under a DIFFERENT internal uuid, planted
    // at the path keyed by the real vault uuid.
    let other_uuid = [0x5a; 16];
    assert_ne!(other_uuid, vault_uuid);
    let clock = vec![VectorClockEntry {
        device_uuid: [0x0e; 16],
        counter: 1,
    }];
    let mismatched = secretary_core::sync::SyncState::new(other_uuid, clock).unwrap();
    secretary_cli::state::save(state_dir.path(), &mismatched).unwrap();
    std::fs::rename(
        secretary_cli::state::state_file_path(state_dir.path(), other_uuid),
        secretary_cli::state::state_file_path(state_dir.path(), vault_uuid),
    )
    .unwrap();

    let before = std::fs::read(folder.join("manifest.cbor.enc")).unwrap();
    let err =
        repair_vault_with_password_in(Some(state_dir.path()), &folder, &pw, &device_uuid, 3_000)
            .expect_err("uuid-mismatched baseline must refuse the mutating repair");
    assert!(
        matches!(err, FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}",
    );
    assert_eq!(
        std::fs::read(folder.join("manifest.cbor.enc")).unwrap(),
        before,
        "refused repair must not mutate the manifest (fail-closed pre-write)",
    );
}
```

- [ ] **Step 2: Run to verify RED**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && cargo test --release -p secretary-ffi-bridge repair 2>&1 | tail -15`
Expected: the 3 new tests **FAIL** at `expect_err` — the repair *succeeds* despite the bad state file (current interim fail-open posture). All pre-existing repair tests still pass.

- [ ] **Step 3: Flip the provider's `Err` arm to fail-closed**

In `ffi/secretary-ffi-bridge/src/repair/orchestration.rs`, replace the interim arm

```rust
            // Interim fail-open posture — flipped to fail-closed in the
            // next commit (#384 posture half, RED-proven there).
            Err(_) => Ok(None),
```

with:

```rust
            // #384 fail-closed: an EXISTING but unreadable/undecodable/
            // uuid-mismatched baseline refuses the MUTATING repair — a
            // skipped check here would let adoption tick + re-sign the
            // manifest, permanently laundering a rolled-back clock (unlike
            // the read-only open path, which self-heals on the next open).
            // Deleting the named state file is the documented §10 reset
            // (crypto-design §10) and unblocks the repair.
            // ErrorKind::InvalidData is deliberate: the FfiVaultError
            // conversion routes it to the `CorruptVault { detail }` fold
            // (which carries this full message), never to `FolderInvalid`
            // ("vault path wrong" — a misdiagnosis here), even when the
            // underlying cause was e.g. PermissionDenied on the state file.
            Err(e) => {
                let path = secretary_cli::state::state_file_path(state_dir, *vault_uuid);
                Err(VaultError::Io {
                    context: "§10 rollback baseline state file exists but could not be read",
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "{e}; state file: {}; deleting it resets this device's rollback history (crypto-design §10) — then retry the repair",
                            path.display()
                        ),
                    ),
                })
            }
```

Also update the provider's doc comment: replace its last sentence (`… §10 is skipped with no false positive on a fresh device.`) with:

```rust
/// false positive on a fresh device. A state file that EXISTS but cannot
/// be used (unreadable, undecodable, internal-uuid mismatch) fails the
/// repair CLOSED — on this mutating path a skipped check would launder a
/// rollback permanently, whereas the read-only open path's skip posture
/// self-heals on the next open (#384; deliberate asymmetry).
```

And append one paragraph to the module doc (after the paragraph added in Task 1):

```rust
//!
//! ## Fail-closed on an existing-but-unreadable baseline (#384)
//!
//! The read-only open path skips §10 when the local baseline cannot be
//! read (availability posture: a rolled-back READ leaks once and
//! self-heals on the next open, which re-checks the persisted baseline).
//! Repair is NOT symmetric: it rewrites the manifest, so a skipped check
//! is permanent laundering. Hence: missing/never-synced baseline → skip
//! (no false positive); EXISTING but unusable state file → refuse, with
//! the deletion remedy in the error detail. Deleting the state file is
//! the crypto-design §10 documented reset to a "no history" device.
```

- [ ] **Step 4: Run to verify GREEN**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && cargo test --release --workspace 2>&1 | tail -5 && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3 && cargo fmt --all`
Expected: all pass (the 3 new tests now GREEN; Cases 1-6 untouched), clippy clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && git add ffi/secretary-ffi-bridge/src/repair/ && git commit -m "bridge: fail closed on existing-but-unreadable §10 baseline at repair (#384)

A present state file that cannot be loaded (garbage bytes, decode
failure, internal-uuid mismatch) now refuses the mutating repair with
the deletion remedy in the CorruptVault detail; missing/never-synced
baselines keep skipping (no false positive). RED-proven on the password
and device-secret arms with manifest-bytes-unchanged assertions.

Refs #384

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Normative docs — vault-format §9 repair paragraph + crypto-design §10

**Files:**
- Modify: `docs/vault-format.md` (the `repair_vault` recovery paragraph, line ~436)
- Modify: `docs/crypto-design.md` (§10, after the "highest seen" paragraph, line ~466)

**Interfaces:**
- Consumes: the two Task 1 core test names cited below (`repair_passes_verified_manifest_uuid_to_baseline_provider`, `repair_aborts_when_baseline_provider_errors`) — they must exist verbatim in `core/tests/crash_recovery.rs` or `spec_test_name_freshness.py` flags drift.
- Produces: normative language Task 4's conformance/freshness checks run against.

- [ ] **Step 1: Amend `docs/vault-format.md`**

In the paragraph at line ~436, replace the fragment

```
it re-runs the §1 open sequence (same credentials, same verify-before-decrypt, same §10 rollback check), then
```

with

```
it re-runs the §1 open sequence (same credentials, same verify-before-decrypt), then evaluates the §10 rollback check on the committed (pre-adoption) manifest clock — keyed by the **verified** manifest `vault_uuid`, never the plaintext `vault.toml` value, and strictly **before** any manifest write (after repair's own clock tick a strictly-dominated clock would read as concurrent and the rollback would be laundered permanently); because repair mutates the manifest, an *existing but unreadable* per-device §10 baseline store MUST fail the repair closed, while a genuinely absent / never-synced baseline skips the check (destroying the baseline store remains §10's documented explicit reset) — then
```

In the same paragraph's `Conformance:` list (ends with `repair_rejects_equal_set_different_bytes`), extend it to

```
… / `repair_rejects_equal_set_different_bytes` / `repair_passes_verified_manifest_uuid_to_baseline_provider` / `repair_aborts_when_baseline_provider_errors` pin this contract.
```

- [ ] **Step 2: Amend `docs/crypto-design.md` §10**

After the paragraph ending `…and rollback resistance is reset on that device.` (line ~466), insert a new paragraph:

```
A read-only load MAY evaluate this check after decoding the manifest — nothing has been written, and a skipped or late check self-heals on the next load against the persisted baseline. Any operation that **rewrites the manifest as part of loading it** (e.g. crash repair, vault-format.md §9) MUST evaluate the check on the committed (pre-tick) clock *before* its first write, keyed by the verified manifest `vault_uuid`, and MUST fail closed if an existing "highest seen" baseline cannot be read: after the operation's own clock tick, a strictly-dominated clock becomes concurrent and the rollback is laundered permanently. A genuinely absent baseline (never-synced device, deliberate reset) skips the check as above.
```

- [ ] **Step 3: Verify doc/test-name freshness + conformance + rustdoc**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && uv run core/tests/python/spec_test_name_freshness.py && uv run core/tests/python/conformance.py 2>&1 | tail -3 && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -3`
Expected: freshness script passes (the two new cited test names resolve in `core/tests/crash_recovery.rs`); conformance passes (no byte-format change); rustdoc warning-clean.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && git add docs/vault-format.md docs/crypto-design.md && git commit -m "docs: normative §10 pre-write + fail-closed language for mutating loads (#384)

Refs #384

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Full acceptance sweep

No new code — the branch-wide gate. Fix anything that surfaces (each fix = its own commit).

**Files:** none planned (fix-ups only if a check fails).

- [ ] **Step 1: Rust gates**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && cargo fmt --all --check && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3 && cargo test --release --workspace 2>&1 | tail -5`
Expected: fmt clean, clippy clean, 0 test failures.

- [ ] **Step 2: Cross-language conformance (expected unchanged — no FFI surface delta)**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3 && bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3`
Expected: 27/27 each. (These compile the generated harnesses; they are the only check that would catch an accidental binding-surface change.)

- [ ] **Step 3: Desktop (expected unchanged — no desktop file touched)**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384/desktop && pnpm svelte-check 2>&1 | tail -3 && pnpm test 2>&1 | tail -3`
Expected: 0 errors; full suite passes (577+).

- [ ] **Step 4: Lean-binding guard (unchanged deps, cheap belt-and-braces)**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384 && bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh`
Expected: self-test fires on the control; guard passes.

---

## Self-Review Notes

- **Spec coverage:** §1 core API → Task 1; §2 bridge → Tasks 1+2; §3 zero error ripple → enforced by Global Constraints (no variant added anywhere); §4 docs → Task 3; §5 tests → Tasks 1 (core pair), 2 (bridge trio + existing Cases 1/2 pin never-synced, Cases 5/6 pin keying end-to-end); §6 out-of-scope → Global Constraints.
- **Posture asymmetry is deliberate and documented twice** (bridge module doc, crypto-design §10) — reviewers should check the open path was NOT touched.
- The `seen` capture closure in the Task 1 uuid test is `FnMut`-shaped; it coerces into the `impl FnOnce` parameter and the mutable borrow of `seen` ends when `repair_vault` returns — no borrow gymnastics needed.
