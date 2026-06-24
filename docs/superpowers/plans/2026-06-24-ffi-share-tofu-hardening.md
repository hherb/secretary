# FFI TOFU-Substitution Hardening (#206) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the FFI TOFU-substitution gap (#206) by hardening the raw `share_block` bridge primitive (verify every card + refuse byte-different overwrite of a trusted contact) and projecting the verified `import_contact_card` / `share_block_to` primitives to PyO3 and uniffi.

**Architecture:** Three layers. (1) Bridge `share::share_block` gains three gates — verify_self the new card, verify_self every existing card, and a TOFU non-overwrite guard — plus a doc-contract comment in core. (2) PyO3 projects `import_contact_card` / `share_block_to` + a `ContactSummary` pyclass. (3) uniffi projects the same two fns + a `ContactSummary` dictionary, with Swift/Kotlin smoke assertions. The safe `share_block_to` already flows through the hardened `share::share_block`, so the bridge fix and the projection reinforce each other.

**Tech Stack:** Rust (stable), PyO3 0.28, uniffi 0.31, pytest (via `uv`/`maturin`), Swift/Kotlin smoke runners.

## Global Constraints

- `#![forbid(unsafe_code)]` workspace-wide — no `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`.
- Format clean: `cargo fmt --all -- --check`.
- Always build/test `--release` (crypto crates are slow in debug).
- **No new `FfiVaultError` / `VaultError` variant.** The non-overwrite refusal reuses `ContactAlreadyExists`; `share_block_to`'s missing-card surfaces `ContactNotFound`. Both are already projected across UDL / uniffi `From` / pyo3 exception classes / Swift+Kotlin `ConformanceErrors` — do not add a variant (would trigger the workspace-wide exhaustive-match obligation).
- **No on-disk format change, no `core` behavior change** (core edit is a doc comment only) → `conformance.py` and the conformance KAT are untouched.
- Python: `uv` only — never `pip`.
- Worktree: all commands run from `/Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening`. Verify with `pwd && git branch --show-current` before path-sensitive commands.
- New code files target < 500 lines; create focused modules rather than growing `share.rs` / `mod.rs`.

---

## File Structure

- **Modify** `ffi/secretary-ffi-bridge/src/share/orchestration.rs` — three gates in `share_block` + a pure non-overwrite guard helper + demote-rustdoc.
- **Modify** `core/src/vault/orchestrators.rs` (Step 12 of `share_block`) — doc-contract comment only.
- **Modify** `ffi/secretary-ffi-bridge/tests/share_block_helpers/mod.rs` — add `mint_forged_card`.
- **Modify** `ffi/secretary-ffi-bridge/tests/share_block.rs` — hardening tests (teeth + verify gates + allow cases).
- **Create** `ffi/secretary-ffi-py/src/contacts.rs` — `ContactSummary` pyclass + `import_contact_card` / `share_block_to` pyfunctions.
- **Modify** `ffi/secretary-ffi-py/src/lib.rs` — `mod contacts;` + register class + 2 functions; demote-docstring note on `share_block`.
- **Modify** `ffi/secretary-ffi-py/src/share.rs` — demote-docstring on `share_block`.
- **Create** `ffi/secretary-ffi-py/tests/test_contacts.py` — pytest for the two new functions.
- **Create** `ffi/secretary-ffi-uniffi/src/wrappers/contacts.rs` — `ContactSummary` record + `From<bridge::ContactSummary>`.
- **Create** `ffi/secretary-ffi-uniffi/src/namespace/contacts.rs` — `import_contact_card` / `share_block_to` namespace fns.
- **Modify** `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs`, `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` — module wiring + re-exports.
- **Modify** `ffi/secretary-ffi-uniffi/src/secretary.udl` — `ContactSummary` dictionary + two namespace fns + demote-docstring on `share_block`.
- **Modify** `ffi/secretary-ffi-uniffi/tests/swift/SmokeShareBlock.swift`, `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeShareBlock.kt` — safe-path asserts.

---

## Task 1: Bridge hardening + core doc-contract

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/share/orchestration.rs`
- Modify: `core/src/vault/orchestrators.rs` (Step 12 comment)
- Modify: `ffi/secretary-ffi-bridge/tests/share_block_helpers/mod.rs`
- Test: `ffi/secretary-ffi-bridge/tests/share_block.rs`

**Interfaces:**
- Consumes: `crate::contacts::read_verified_card(&[u8]) -> Result<ContactCard, FfiVaultError>` (already `pub(crate)`); `secretary_core::vault::format_uuid_hyphenated(&[u8;16]) -> String`; `FfiVaultError::{ContactAlreadyExists{uuid_hex}, FolderInvalid{detail}, CardDecodeFailure{detail}}`.
- Produces: the hardened `secretary_ffi_bridge::share_block` (signature unchanged) and a test-only `mint_forged_card(seed, name, victim_uuid) -> (IdentityBundle, Vec<u8>)`.

- [ ] **Step 1: Add the `mint_forged_card` test helper**

In `ffi/secretary-ffi-bridge/tests/share_block_helpers/mod.rs`, after `mint_external_card`, add a helper that mints an attacker identity but stamps a *victim's* `contact_uuid` onto the self-signed card (so it `verify_self`s under the attacker's own keys yet impersonates the victim's UUID):

```rust
/// Mint a FORGED card: attacker keys (from `seed`) but a chosen
/// `contact_uuid` (the victim's). The card still self-verifies — it is
/// signed by its own embedded attacker keys — so `verify_self` alone does
/// NOT catch it; only the TOFU non-overwrite guard does. Used by the
/// #206 substitution teeth test.
#[allow(dead_code)]
pub fn mint_forged_card(seed: u8, display_name: &str, victim_uuid: [u8; 16]) -> (IdentityBundle, Vec<u8>) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let bundle = generate_bundle(display_name, 1_714_060_800_000, &mut rng);
    let pq_sk = MlDsa65Secret::from_bytes(bundle.ml_dsa_65_sk.expose()).unwrap();
    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: victim_uuid, // impersonated UUID, attacker keys below
        display_name: bundle.display_name.clone(),
        x25519_pk: bundle.x25519_pk,
        ml_kem_768_pk: bundle.ml_kem_768_pk.clone(),
        ed25519_pk: bundle.ed25519_pk,
        ml_dsa_65_pk: bundle.ml_dsa_65_pk.clone(),
        created_at_ms: bundle.created_at_ms,
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    card.sign(&bundle.ed25519_sk, &pq_sk).unwrap();
    let bytes = card.to_canonical_cbor().unwrap();
    (bundle, bytes)
}
```

- [ ] **Step 2: Write the failing teeth test (substitution rejected, disk + manifest unchanged)**

In `ffi/secretary-ffi-bridge/tests/share_block.rs`, update the imports line to pull the new helper and `mint_external_card` is already imported. Add `mint_forged_card` to the `use share_block_helpers::{...}` list and `use secretary_core::vault::format_uuid_hyphenated;` + `use std::fs;`. Then add:

```rust
#[test]
fn share_block_raw_rejects_substituting_a_trusted_card() {
    // #206: a forged card carrying a TRUSTED contact's uuid but attacker
    // keys must not (a) overwrite the on-disk trusted card nor (b) re-key
    // the block. The hardened raw share_block rejects it as
    // ContactAlreadyExists before core runs.
    let (tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity, &manifest, NEW_BLOCK_UUID, NEW_RECORD_UUID, "p", "v", NOW_MS_BASE,
    );
    // Genuine Alice on disk (TOFU import via raw share to a fresh block path
    // would also write her, but place the card directly for clarity).
    let (alice_bundle, alice_genuine) = mint_external_card(0xB1, "Alice");
    let alice_uuid = alice_bundle.user_uuid;
    let card_path = tmp.path().join("contacts").join(format!(
        "{}.card", format_uuid_hyphenated(&alice_uuid)
    ));
    fs::write(&card_path, &alice_genuine).expect("place genuine alice card");

    // Forged card: Alice's uuid, attacker keys, self-consistent.
    let (_eve, forged) = mint_forged_card(0xE5, "Eve-as-Alice", alice_uuid);
    assert_ne!(forged, alice_genuine, "forged bytes differ from genuine");

    let owner_card_bytes = manifest.owner_card_bytes().unwrap().unwrap();
    let err = share_block(
        &identity, &manifest, NEW_BLOCK_UUID,
        std::slice::from_ref(&owner_card_bytes),
        &forged, DEVICE_UUID, NOW_MS_BASE + 1_000,
    )
    .expect_err("substituting a trusted card must be rejected");
    assert!(matches!(err, FfiVaultError::ContactAlreadyExists { .. }), "got {err:?}");

    // On-disk card unchanged.
    let on_disk = fs::read(&card_path).unwrap();
    assert_eq!(on_disk, alice_genuine, "trusted card must not be overwritten");

    // Block not re-keyed: still owner-only.
    let entry = manifest.find_block(&NEW_BLOCK_UUID).expect("block findable");
    assert_eq!(entry.recipient_uuids.len(), 1, "owner only; no re-key");
    assert!(!entry.recipient_uuids.contains(&alice_uuid));
}
```

- [ ] **Step 3: Run the teeth test — verify it FAILS on pre-fix code**

Run: `cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening && cargo test --release -p secretary-ffi-bridge --test share_block share_block_raw_rejects_substituting_a_trusted_card`
Expected: FAIL — pre-fix `share_block` overwrites the card and re-keys (the `expect_err` panics or the disk/manifest assertions fail).

- [ ] **Step 4: Implement the three gates + the pure guard helper**

In `ffi/secretary-ffi-bridge/src/share/orchestration.rs`:

Add imports near the top:
```rust
use secretary_core::vault::format_uuid_hyphenated;
```

Replace the Step 0 decode block (the `existing_decoded` + `new_decoded` lets) with verify-gated versions:
```rust
    // Step 0: decode AND self-verify every input card (both Ed25519 ∧
    // ML-DSA-65 halves) via the shared contacts gate. #206: raw share_block
    // must not trust an unverified card for re-keying. Any parse/verify
    // failure surfaces as CardDecodeFailure (bridge-internal).
    let existing_decoded: Vec<ContactCard> = existing_recipient_cards
        .iter()
        .map(|b| crate::contacts::read_verified_card(b))
        .collect::<Result<_, _>>()?;
    let new_decoded = crate::contacts::read_verified_card(new_recipient)?;
```
(Remove the now-unused `use secretary_core::identity::card::ContactCard;`? No — `ContactCard` is still the element type of `existing_decoded`; keep it.)

After the Step 1 manifest snapshot (which binds `vault_folder`), before Step 2, add the TOFU non-overwrite guard:
```rust
    // Step 1.5 (#206): TOFU non-overwrite guard. If a card for this
    // contact_uuid already exists on disk and differs from the bytes the
    // caller supplied, refuse — overwriting it would substitute a trusted
    // contact's keys (silent TOFU substitution). Byte-identical (legit
    // re-share / the share_block_to path) and absent (first-contact TOFU)
    // both pass.
    guard_new_recipient_no_substitution(&vault_folder, &new_decoded.contact_uuid, new_recipient)?;
```

Add the pure helper at the bottom of the file (above or below `map_core_vault_error_share`):
```rust
/// Refuse to overwrite an existing, byte-different `contacts/<uuid>.card`.
///
/// - file exists, bytes differ → `ContactAlreadyExists` (the #206 guard);
/// - file exists, byte-identical → `Ok` (legit re-share);
/// - file absent → `Ok` (trust-on-first-use of a brand-new contact);
/// - read error other than not-found → `FolderInvalid`.
fn guard_new_recipient_no_substitution(
    vault_folder: &std::path::Path,
    card_uuid: &[u8; 16],
    new_bytes: &[u8],
) -> Result<(), FfiVaultError> {
    let path = vault_folder
        .join("contacts")
        .join(format!("{}.card", format_uuid_hyphenated(card_uuid)));
    match std::fs::read(&path) {
        Ok(on_disk) if on_disk != new_bytes => Err(FfiVaultError::ContactAlreadyExists {
            uuid_hex: hex::encode(card_uuid),
        }),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(FfiVaultError::FolderInvalid {
            detail: format!("read existing contact card for overwrite check: {e}"),
        }),
    }
}
```

Update the `share_block` rustdoc: add a `# Errors` line for `ContactAlreadyExists` ("an existing trusted card for `new_recipient`'s uuid would be overwritten with different bytes") and a paragraph marking the function **discouraged / bridge-internal** — FFI consumers should prefer `share_block_to` + `import_contact_card`, which never trust caller-supplied card bytes for the recipient key.

- [ ] **Step 5: Add the verify-gate + allow-case tests**

Append to `ffi/secretary-ffi-bridge/tests/share_block.rs`:

```rust
#[test]
fn share_block_raw_rejects_unsigned_new_card() {
    // New card parses but fails verify_self → CardDecodeFailure (gate 1).
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(&identity, &manifest, NEW_BLOCK_UUID, NEW_RECORD_UUID, "p", "v", NOW_MS_BASE);
    let owner = manifest.owner_card_bytes().unwrap().unwrap();
    let (_b, mut alice) = mint_external_card(0xB1, "Alice");
    let n = alice.len();
    alice[n - 1] ^= 0xFF; // still parses; self-sig now invalid
    let err = share_block(
        &identity, &manifest, NEW_BLOCK_UUID,
        std::slice::from_ref(&owner), &alice, DEVICE_UUID, NOW_MS_BASE + 1,
    ).expect_err("unsigned new card must reject");
    assert!(matches!(err, FfiVaultError::CardDecodeFailure { .. }), "got {err:?}");
}

#[test]
fn share_block_raw_rejects_unsigned_existing_card() {
    // An existing card that parses but fails verify_self → CardDecodeFailure
    // (gate 3), surfaced earlier than core's MissingRecipientCard.
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(&identity, &manifest, NEW_BLOCK_UUID, NEW_RECORD_UUID, "p", "v", NOW_MS_BASE);
    let mut owner = manifest.owner_card_bytes().unwrap().unwrap();
    let n = owner.len();
    owner[n - 1] ^= 0xFF; // tampered owner card in the existing list
    let (_b, alice) = mint_external_card(0xB1, "Alice");
    let err = share_block(
        &identity, &manifest, NEW_BLOCK_UUID,
        std::slice::from_ref(&owner), &alice, DEVICE_UUID, NOW_MS_BASE + 1,
    ).expect_err("unsigned existing card must reject");
    assert!(matches!(err, FfiVaultError::CardDecodeFailure { .. }), "got {err:?}");
}

#[test]
fn share_block_raw_allows_byte_identical_existing_card_on_disk() {
    // Sharing a brand-new recipient whose genuine card is already on disk
    // with IDENTICAL bytes must succeed (guard allows identical).
    let (tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(&identity, &manifest, NEW_BLOCK_UUID, NEW_RECORD_UUID, "p", "v", NOW_MS_BASE);
    let (alice_bundle, alice) = mint_external_card(0xB1, "Alice");
    let path = tmp.path().join("contacts").join(format!(
        "{}.card", format_uuid_hyphenated(&alice_bundle.user_uuid)
    ));
    fs::write(&path, &alice).unwrap();
    let owner = manifest.owner_card_bytes().unwrap().unwrap();
    share_block(
        &identity, &manifest, NEW_BLOCK_UUID,
        std::slice::from_ref(&owner), &alice, DEVICE_UUID, NOW_MS_BASE + 1,
    ).expect("identical on-disk card → allowed");
    let entry = manifest.find_block(&NEW_BLOCK_UUID).unwrap();
    assert_eq!(entry.recipient_uuids.len(), 2);
    assert!(entry.recipient_uuids.contains(&alice_bundle.user_uuid));
}
```

The pre-existing `share_block_owner_to_alice_appends_recipient_to_manifest` (absent → TOFU allow) and the `tests/contacts.rs` suite (`share_block_to` happy / tampered-card-rejected) cover the remaining allow/verify cases — no new tests needed there.

- [ ] **Step 6: Add the core doc-contract comment**

In `core/src/vault/orchestrators.rs`, Step 12 of `share_block` (the `if let Some((card_bytes, card_uuid)) = card_to_persist {` block, ~line 1254), extend the existing comment with the trust contract:

```rust
    // Step 12: optionally persist a recipient's contact card to
    // `contacts/<uuid>.card` ...
    //
    // Trust contract (#206): callers MUST supply already-verified,
    // non-substituting card bytes. This orchestrator writes `card_bytes`
    // verbatim and does NOT itself guard against overwriting a trusted
    // card with attacker-controlled keys. The FFI projection enforces this
    // in `secretary-ffi-bridge`'s `share::share_block` (verify_self every
    // card + a TOFU non-overwrite guard); in-repo Rust callers must uphold
    // the same contract or route through the bridge / `share_block_to`.
```
No behavioral change.

- [ ] **Step 7: Run the full bridge test suite + clippy + fmt**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening
cargo test --release -p secretary-ffi-bridge
cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings
cargo fmt --all -- --check
```
Expected: all PASS (the teeth test now passes; `contacts.rs` + `share_block.rs` suites green; clippy + fmt clean).

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening
git add ffi/secretary-ffi-bridge/src/share/orchestration.rs \
        ffi/secretary-ffi-bridge/tests/share_block.rs \
        ffi/secretary-ffi-bridge/tests/share_block_helpers/mod.rs \
        core/src/vault/orchestrators.rs
git commit -m "fix(ffi): harden raw share_block against TOFU substitution (#206)

Verify_self every existing + new card and refuse to overwrite a
byte-different trusted contacts/<uuid>.card (ContactAlreadyExists).
Core share_block Step 12 documents the trust contract the bridge
enforces. No new error variant; no core behavior change.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: PyO3 projection (`import_contact_card` / `share_block_to` + `ContactSummary`)

**Files:**
- Create: `ffi/secretary-ffi-py/src/contacts.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs`
- Modify: `ffi/secretary-ffi-py/src/share.rs` (demote-docstring)
- Test: `ffi/secretary-ffi-py/tests/test_contacts.py`

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{import_contact_card, share_block_to, ContactSummary}`; `crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error}`; `crate::identity::UnlockedIdentity`; `crate::vault::OpenVaultManifest`.
- Produces: Python module functions `import_contact_card(manifest, card_bytes) -> ContactSummary`, `share_block_to(identity, manifest, block_uuid, new_recipient_uuid, device_uuid, now_ms)`, and pyclass `ContactSummary` with getters `contact_uuid: bytes`, `display_name: str`, `shared_block_count: int`.

- [ ] **Step 1: Write the failing pytest**

Create `ffi/secretary-ffi-py/tests/test_contacts.py`:

```python
"""D.1.6 contacts pytest — verified share path (#206).

Exercises the projected import_contact_card / share_block_to. Each test
gets its own writable copy of golden_vault_001 in tmp_path.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py


def _golden(n: int = 1) -> Path:
    return Path(__file__).resolve().parents[3] / "core" / "tests" / "data" / f"golden_vault_{n:03d}"


def _password(n: int = 1) -> bytes:
    import json
    p = Path(__file__).resolve().parents[3] / "core" / "tests" / "data" / f"golden_vault_{n:03d}_inputs.json"
    return json.loads(p.read_text())["password"].encode()


def _fresh(tmp_path: Path, n: int = 1) -> Path:
    dst = tmp_path / f"vault{n:03d}"
    shutil.copytree(_golden(n), dst)
    return dst


def _uuid_from_card_filename(name: str) -> bytes:
    # "<hyphenated-uuid>.card" → 16 raw bytes
    return bytes.fromhex(name[: -len(".card")].replace("-", ""))


def _open(vault: Path):
    return secretary_ffi_py.open_vault_with_password(str(vault).encode(), _password())


def _a_peer_card(vault: Path, owner_uuid: bytes) -> tuple[bytes, bytes]:
    """Return (card_bytes, contact_uuid) for a non-owner card shipped in the
    fixture's contacts/ dir."""
    for f in sorted((vault / "contacts").glob("*.card")):
        uuid = _uuid_from_card_filename(f.name)
        if uuid != owner_uuid:
            return f.read_bytes(), uuid
    raise AssertionError("fixture has no non-owner contact card")


def test_import_contact_card_round_trip_and_duplicate(tmp_path: Path) -> None:
    vault = _fresh(tmp_path)
    out = _open(vault)
    with out.identity as identity, out.manifest as manifest:
        owner_uuid = identity.user_uuid()
        card_bytes, peer_uuid = _a_peer_card(vault, owner_uuid)
        # Card is already on disk → duplicate import rejected.
        with pytest.raises(secretary_ffi_py.VaultContactAlreadyExists):
            secretary_ffi_py.import_contact_card(manifest, card_bytes)
        # Delete and re-import → ContactSummary echoes the uuid.
        (vault / "contacts" / f"{_hyphen(peer_uuid)}.card").unlink()
        summary = secretary_ffi_py.import_contact_card(manifest, card_bytes)
        assert bytes(summary.contact_uuid) == peer_uuid
        assert isinstance(summary.display_name, str)
        assert summary.shared_block_count == 0


def test_import_rejects_tampered_card(tmp_path: Path) -> None:
    vault = _fresh(tmp_path)
    out = _open(vault)
    with out.identity as identity, out.manifest as manifest:
        owner_uuid = identity.user_uuid()
        card_bytes, peer_uuid = _a_peer_card(vault, owner_uuid)
        (vault / "contacts" / f"{_hyphen(peer_uuid)}.card").unlink()
        tampered = bytearray(card_bytes)
        tampered[-1] ^= 0xFF
        with pytest.raises(secretary_ffi_py.VaultCardDecodeFailure):
            secretary_ffi_py.import_contact_card(manifest, bytes(tampered))


def _hyphen(u: bytes) -> str:
    h = u.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
```

(The `share_block_to` happy path is exercised at the bridge + uniffi smoke layers; the Python tests pin import semantics + the duplicate/tampered guards, which is where the #206 projection value is.)

- [ ] **Step 2: Run the pytest — verify it FAILS (functions not yet projected)**

Run (per the maturin/uv discipline):
```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening/ffi/secretary-ffi-py
uv run maturin develop --release
uv run pytest tests/test_contacts.py -v
```
Expected: FAIL — `AttributeError: module 'secretary_ffi_py' has no attribute 'import_contact_card'`.

- [ ] **Step 3: Create the PyO3 contacts module**

Create `ffi/secretary-ffi-py/src/contacts.rs`:

```rust
//! D.1.6 contacts surface (#206): the verified `import_contact_card` /
//! `share_block_to` primitives + the `ContactSummary` projection.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Secret-free projection of one contact card (uuid + label + share count).
#[pyclass]
pub(crate) struct ContactSummary {
    pub(crate) contact_uuid: [u8; 16],
    pub(crate) display_name: String,
    pub(crate) shared_block_count: u32,
}

#[pymethods]
impl ContactSummary {
    /// 16-byte contact UUID as fresh `bytes`.
    #[getter]
    fn contact_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.contact_uuid)
    }
    /// User-facing label.
    #[getter]
    fn display_name(&self) -> &str {
        &self.display_name
    }
    /// Number of the owner's blocks listing this contact as a recipient.
    #[getter]
    fn shared_block_count(&self) -> u32 {
        self.shared_block_count
    }
}

impl From<secretary_ffi_bridge::ContactSummary> for ContactSummary {
    fn from(s: secretary_ffi_bridge::ContactSummary) -> Self {
        Self {
            contact_uuid: s.contact_uuid,
            display_name: s.display_name,
            shared_block_count: s.shared_block_count,
        }
    }
}

/// TOFU import of one contact card. Verifies both self-signature halves and
/// refuses to overwrite an existing card (`VaultContactAlreadyExists`).
/// Tampered/unsigned bytes raise `VaultCardDecodeFailure`.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn import_contact_card(
    manifest: &OpenVaultManifest,
    card_bytes: Vec<u8>,
) -> PyResult<ContactSummary> {
    secretary_ffi_bridge::import_contact_card(&manifest.0, &card_bytes)
        .map(ContactSummary::from)
        .map_err(ffi_vault_error_to_pyerr)
}

/// Share a block with a recipient identified by `new_recipient_uuid`. The
/// recipient's card (and every existing recipient's card) is loaded from
/// `contacts/` and re-verified before re-keying — no caller-supplied card
/// bytes enter the trust path. Prefer this over raw `share_block`.
///
/// `block_uuid`, `new_recipient_uuid`, `device_uuid` must each be 16 bytes
/// (`ValueError` otherwise).
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn share_block_to(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    new_recipient_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let new_recipient_uuid = uuid_array_or_value_error(&new_recipient_uuid, "new_recipient_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::share_block_to(
        &identity.0,
        &manifest.0,
        block_uuid,
        new_recipient_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}
```

- [ ] **Step 4: Register the module, class, and functions in `lib.rs`**

In `ffi/secretary-ffi-py/src/lib.rs`: add `mod contacts;` to the module list; add `use contacts::{import_contact_card, share_block_to, ContactSummary};` near the other `use` imports; and in the module-init fn (after the `share_block` registration block) add:

```rust
    // D.1.6 contacts surface (#206) — verified share path. The
    // ContactAlreadyExists / ContactNotFound exception classes are already
    // registered above.
    m.add_class::<ContactSummary>()?;
    m.add_function(wrap_pyfunction!(import_contact_card, m)?)?;
    m.add_function(wrap_pyfunction!(share_block_to, m)?)?;
```

Also add a one-line note to the existing `share_block` registration comment: "raw `share_block` is discouraged for FFI consumers; prefer `share_block_to` + `import_contact_card` (#206)."

- [ ] **Step 5: Demote-docstring on the raw `share_block` pyfunction**

In `ffi/secretary-ffi-py/src/share.rs`, prepend a paragraph to the `share_block` docstring: it is **discouraged** — it trusts caller-supplied recipient card bytes. FFI consumers should `import_contact_card` the peer once, then `share_block_to` by UUID.

- [ ] **Step 6: Rebuild and run the pytest — verify PASS**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening/ffi/secretary-ffi-py
uv run maturin develop --release
uv run pytest tests/test_contacts.py -v
```
Expected: PASS. (If pytest sees a stale `.so`, nuke the venv + uv cache per the known maturin/uv stickiness trap, then re-run.)

- [ ] **Step 7: clippy + fmt on the py crate**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening
cargo clippy --release -p secretary-ffi-py --tests -- -D warnings
cargo fmt --all -- --check
```
Expected: clean.

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening
git add ffi/secretary-ffi-py/src/contacts.rs ffi/secretary-ffi-py/src/lib.rs \
        ffi/secretary-ffi-py/src/share.rs ffi/secretary-ffi-py/tests/test_contacts.py
git commit -m "feat(ffi-py): project import_contact_card / share_block_to (#206)

Expose the verified TOFU import + share-by-uuid primitives and a
ContactSummary pyclass; mark raw share_block discouraged. Error classes
already registered. Pytest pins import round-trip + duplicate/tampered.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: uniffi projection (`import_contact_card` / `share_block_to` + `ContactSummary`)

**Files:**
- Create: `ffi/secretary-ffi-uniffi/src/wrappers/contacts.rs`
- Create: `ffi/secretary-ffi-uniffi/src/namespace/contacts.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs`, `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Test: `ffi/secretary-ffi-uniffi/tests/swift/SmokeShareBlock.swift`, `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeShareBlock.kt`

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{import_contact_card, share_block_to, ContactSummary}`; `crate::wrappers::{UnlockedIdentity, OpenVaultManifest}`; `crate::errors::VaultError`; `crate::namespace::uuid_from_vec`.
- Produces: uniffi namespace fns `import_contact_card(manifest) -> ContactSummary`, `share_block_to(...)`; uniffi dictionary `ContactSummary { bytes contact_uuid; string display_name; u32 shared_block_count; }`.

- [ ] **Step 1: Add the `ContactSummary` wrapper record + round-trip test**

Create `ffi/secretary-ffi-uniffi/src/wrappers/contacts.rs`:

```rust
//! D.1.6 contacts wrappers (#206): the `ContactSummary` dictionary
//! projection of `secretary_ffi_bridge::ContactSummary`.

/// uniffi dictionary projection of `secretary_ffi_bridge::ContactSummary`.
/// All fields are non-secret public metadata.
pub struct ContactSummary {
    pub contact_uuid: Vec<u8>,
    pub display_name: String,
    pub shared_block_count: u32,
}

impl From<secretary_ffi_bridge::ContactSummary> for ContactSummary {
    fn from(s: secretary_ffi_bridge::ContactSummary) -> Self {
        Self {
            contact_uuid: s.contact_uuid.to_vec(),
            display_name: s.display_name,
            shared_block_count: s.shared_block_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_summary_projection_round_trip() {
        let bridge = secretary_ffi_bridge::ContactSummary {
            contact_uuid: [9u8; 16],
            display_name: "Carol".to_string(),
            shared_block_count: 3,
        };
        let p = ContactSummary::from(bridge);
        assert_eq!(p.contact_uuid, vec![9u8; 16]);
        assert_eq!(p.display_name, "Carol");
        assert_eq!(p.shared_block_count, 3);
    }
}
```

In `ffi/secretary-ffi-uniffi/src/wrappers/mod.rs`, add `mod contacts;` and `pub use contacts::ContactSummary;` (mirror how `vault::BlockSummary` is re-exported).

- [ ] **Step 2: Run the wrapper round-trip test — verify it FAILS to compile / then passes**

Run: `cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening && cargo test --release -p secretary-ffi-uniffi contact_summary_projection_round_trip`
Expected at this point: the wrapper test PASSES (it doesn't depend on the UDL yet). This step verifies the `From` + re-export compile cleanly before the UDL ties them to the binding.

- [ ] **Step 3: Add the namespace fns**

Create `ffi/secretary-ffi-uniffi/src/namespace/contacts.rs`:

```rust
//! D.1.6 contacts namespace fns (#206): verified `import_contact_card` /
//! `share_block_to`.

use crate::errors::VaultError;
use crate::namespace::uuid_from_vec;
use crate::wrappers::{ContactSummary, OpenVaultManifest, UnlockedIdentity};

/// TOFU import of one contact card. Verifies both self-signature halves and
/// refuses to overwrite an existing card (`VaultError::ContactAlreadyExists`).
#[allow(clippy::needless_pass_by_value)]
pub fn import_contact_card(
    manifest: std::sync::Arc<OpenVaultManifest>,
    card_bytes: Vec<u8>,
) -> Result<ContactSummary, VaultError> {
    secretary_ffi_bridge::import_contact_card(&manifest.0, &card_bytes)
        .map(ContactSummary::from)
        .map_err(VaultError::from)
}

/// Share a block with a recipient by `new_recipient_uuid`. All cards are
/// loaded from `contacts/` and re-verified before re-keying — no
/// caller-supplied card bytes enter the trust path. Prefer over `share_block`.
#[allow(clippy::too_many_arguments)]
pub fn share_block_to(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    new_recipient_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let new_recipient_uuid = uuid_from_vec(&new_recipient_uuid, "new_recipient_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::share_block_to(
        &identity.0,
        &manifest.0,
        block_uuid,
        new_recipient_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}
```

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`: add `mod contacts;` and `pub use contacts::{import_contact_card, share_block_to};` (mirror the existing `pub use` of namespace submodule fns). Confirm `uuid_from_vec` and the wrapper re-exports are reachable (`pub(crate)` as used by the sibling fns); if `uuid_from_vec` is private to `mod.rs`, make it `pub(crate)`.

- [ ] **Step 4: Declare the dictionary + fns in the UDL + demote-docstring**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`:

Add to the `namespace secretary { ... }` block (near `share_block`):
```
    /// TOFU import of one contact card (#206). Verifies both self-signature
    /// halves; refuses to overwrite an existing card
    /// (`VaultError::ContactAlreadyExists`).
    [Throws=VaultError]
    ContactSummary import_contact_card(
        OpenVaultManifest manifest,
        bytes card_bytes
    );

    /// Share a block with a recipient by UUID (#206). Every card is loaded
    /// from `contacts/` and re-verified before re-keying — no caller card
    /// bytes enter the trust path. Prefer over `share_block`.
    [Throws=VaultError]
    void share_block_to(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        bytes new_recipient_uuid,
        bytes device_uuid,
        u64 now_ms
    );
```

Add the dictionary (near `BlockSummary`):
```
/// Secret-free projection of one contact card (#206). Non-secret metadata.
dictionary ContactSummary {
    /// 16-byte contact UUID.
    bytes contact_uuid;
    /// User-facing label.
    string display_name;
    /// Count of owner blocks listing this contact as a recipient.
    u32 shared_block_count;
};
```

Prepend to the existing `share_block` UDL docstring a sentence marking it **discouraged** (trusts caller card bytes; prefer `share_block_to` + `import_contact_card`).

- [ ] **Step 5: Build the uniffi crate (scaffolding picks up the UDL)**

Run: `cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening && cargo test --release -p secretary-ffi-uniffi`
Expected: PASS — `build.rs` regenerates scaffolding from the UDL; the namespace fn signatures must match the UDL exactly (a mismatch is a compile error). Round-trip wrapper test green.

- [ ] **Step 6: Add the Swift smoke safe-path asserts**

Append to `runShareBlockAsserts(env:)` in `ffi/secretary-ffi-uniffi/tests/swift/SmokeShareBlock.swift` (before the closing brace):

```swift
    // Assert 31 (#206): verified safe path — import Alice, then
    // share_block_to by UUID; manifest grows to 2 recipients. A second
    // import of the same card → ContactAlreadyExists.
    do {
        let aliceBytes = try _aliceCardBytes(env: env)
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe() }
        defer { manifest.wipe() }
        defer { try? FileManager.default.removeItem(at: tmp) }

        try saveBlock(
            identity: identity, manifest: manifest,
            input: BlockInput(blockUuid: shareBlockBlockUuid, blockName: "shared", records: []),
            deviceUuid: shareBlockDeviceUuid, nowMs: 1_000
        )
        let summary = try importContactCard(manifest: manifest, cardBytes: aliceBytes)
        check(summary.contactUuid.count == 16, "import_contact_card → 16-byte uuid")

        try shareBlockTo(
            identity: identity, manifest: manifest,
            blockUuid: shareBlockBlockUuid,
            newRecipientUuid: summary.contactUuid,
            deviceUuid: shareBlockDeviceUuid, nowMs: 2_000
        )
        let entry = manifest.findBlock(blockUuid: shareBlockBlockUuid)
        check(entry?.recipientUuids.count == 2, "share_block_to → 2 recipients")

        do {
            _ = try importContactCard(manifest: manifest, cardBytes: aliceBytes)
            check(false, "duplicate import should throw ContactAlreadyExists")
        } catch let e as VaultError {
            if case .ContactAlreadyExists = e {
                check(true, "duplicate import → ContactAlreadyExists")
            } else {
                check(false, "duplicate import wrong variant: \(e)")
            }
        }
    } catch {
        check(false, "#206 safe-path smoke threw \(error)")
    }
```

- [ ] **Step 7: Add the Kotlin smoke safe-path asserts**

Append the mirror to `runShareBlockAsserts(env)` in `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeShareBlock.kt` (match the existing Kotlin assert style — `importContactCard`, `shareBlockTo`, `VaultException.ContactAlreadyExists`, `findBlock(...)?.recipientUuids?.size == 2`). Use the same staging helpers the file already uses for the other asserts.

```kotlin
    // Assert 31 (#206): verified safe path + duplicate import guard.
    run {
        val aliceBytes = aliceCardBytes(env)
        val (identity, manifest, tmp) = freshWritableVault(env)
        try {
            saveBlock(identity, manifest,
                BlockInput(shareBlockBlockUuid, "shared", emptyList()),
                shareBlockDeviceUuid, 1_000uL)
            val summary = importContactCard(manifest, aliceBytes)
            check(summary.contactUuid.size == 16, "import_contact_card -> 16-byte uuid")
            shareBlockTo(identity, manifest, shareBlockBlockUuid,
                summary.contactUuid, shareBlockDeviceUuid, 2_000uL)
            val entry = manifest.findBlock(shareBlockBlockUuid)
            check(entry?.recipientUuids?.size == 2, "share_block_to -> 2 recipients")
            try {
                importContactCard(manifest, aliceBytes)
                check(false, "duplicate import should throw ContactAlreadyExists")
            } catch (e: VaultException.ContactAlreadyExists) {
                check(true, "duplicate import -> ContactAlreadyExists")
            }
        } finally {
            identity.wipe(); manifest.wipe(); tmp.toFile().deleteRecursively()
        }
    }
```
(Adjust helper names — `aliceCardBytes` / `freshWritableVault` / `BlockInput` ctor / `uL` suffixes — to whatever `SmokeShareBlock.kt` + `SmokeHelpers.kt` already use; match the existing asserts in the same file exactly.)

- [ ] **Step 8: Run the uniffi crate test + Swift + Kotlin smoke runners**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening
cargo test --release -p secretary-ffi-uniffi
cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh   # needs kotlinc + JDK; CI is the backstop if absent locally
```
Expected: cargo + clippy PASS; Swift smoke PASS; Kotlin smoke PASS (if `kotlinc` installed — otherwise note it and rely on CI). If a toolchain is missing locally, record that the cargo-level scaffolding build + Swift smoke validated the binding and CI's `test.yml` runs the Kotlin layer.

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening
git add ffi/secretary-ffi-uniffi/src/wrappers/contacts.rs \
        ffi/secretary-ffi-uniffi/src/namespace/contacts.rs \
        ffi/secretary-ffi-uniffi/src/wrappers/mod.rs \
        ffi/secretary-ffi-uniffi/src/namespace/mod.rs \
        ffi/secretary-ffi-uniffi/src/secretary.udl \
        ffi/secretary-ffi-uniffi/tests/swift/SmokeShareBlock.swift \
        ffi/secretary-ffi-uniffi/tests/kotlin/SmokeShareBlock.kt
git commit -m "feat(ffi-uniffi): project import_contact_card / share_block_to (#206)

Add the verified TOFU import + share-by-uuid namespace fns and a
ContactSummary dictionary; mark raw share_block discouraged. Swift +
Kotlin smoke exercise the safe path + duplicate-import guard. Error
variants already in the UDL/ConformanceErrors.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification (after all tasks)

Run the full workspace gates:
```bash
cd /Users/hherb/src/secretary/.worktrees/ffi-share-tofu-hardening
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py            # unchanged — must still PASS
```
Then the foreign layers: pytest (`ffi/secretary-ffi-py`) + Swift/Kotlin smoke. CI (`test.yml` + `rust-lint.yml` + CodeQL) is the real gate on push.

---

## Self-Review

**Spec coverage:**
- §3.A gate 1 (verify_self new card) → Task 1 Step 4 (`read_verified_card(new_recipient)`), Step 5 unsigned-new test. ✓
- §3.A gate 2 (TOFU non-overwrite) → Task 1 Step 4 guard helper, Step 2 teeth test, Step 5 identical-allow test. ✓
- §3.A gate 3 (verify existing cards) → Task 1 Step 4 (`read_verified_card` map over existing), Step 5 unsigned-existing test. ✓
- §3.B core doc-contract → Task 1 Step 6. ✓
- §3.C PyO3 projection → Task 2. ✓
- §3.D uniffi projection → Task 3. ✓
- §3.E demote raw share_block → Task 1 Step 4 (bridge rustdoc), Task 2 Step 5 (pyo3), Task 3 Step 4 (UDL). ✓
- §4 no new error variant → Global Constraints + reuse of `ContactAlreadyExists`/`ContactNotFound`. ✓
- §5 teeth test + TDD → Task 1 Steps 2–3 (fails pre-fix), Task 2 Steps 1–2, Task 3 round-trip. ✓
- §7 file-size discipline → new focused modules (`contacts.rs` in each layer). ✓

**Placeholder scan:** No TBD/TODO. The only deliberately-deferred detail is the Kotlin helper *names* in Task 3 Step 7 (the file's own existing helpers), explicitly flagged to match the sibling asserts — the structure and assertions are concrete.

**Type consistency:** `ContactSummary` fields (`contact_uuid: [u8;16]`/`Vec<u8>`, `display_name: String`, `shared_block_count: u32`) consistent across bridge → pyo3 pyclass → uniffi dictionary. `share_block_to` arg order (`identity, manifest, block_uuid, new_recipient_uuid, device_uuid, now_ms`) matches the bridge fn (verified against `tests/contacts.rs` call sites) across PyO3 + uniffi + UDL. Error reuse (`ContactAlreadyExists` / `ContactNotFound` / `CardDecodeFailure`) matches the already-projected variants.
