# Design: close the FFI TOFU-substitution gap (#206)

**Date:** 2026-06-24
**Issue:** #206 — *FFI `share_block` accepts unverified contact card and overwrites trusted card (TOFU substitution); verified primitives not projected to PyO3/uniffi*
**Severity:** Medium (bug, security). Verified confidence: high.
**Scope:** FFI surface only (`ffi/secretary-ffi-bridge`, `ffi/secretary-ffi-py`, `ffi/secretary-ffi-uniffi`) plus a documentation-only comment in `core`. **No on-disk vault/manifest/block format change, no new `FfiVaultError`/`VaultError` variant** → `conformance.py` and the Swift/Kotlin conformance harnesses' error surface are unaffected.

## 1. The vulnerability

The only recipient-sharing primitive projected through PyO3 and uniffi today is the **raw `share_block`**, which decodes caller-supplied contact-card bytes (`new_recipient`) and hands them to `core::vault::share_block`. Core then:

1. **Re-keys the block** to every recipient's KEM keys taken *directly from the caller-supplied decoded cards* (`core/src/vault/orchestrators.rs`), and
2. **Unconditionally overwrites** `contacts/<uuid>.card` with the caller bytes (Step 12, `orchestrators.rs:1261-1273`).

An FFI consumer (a host app passing attacker-influenced bytes) can therefore supply a forged card carrying an **existing trusted contact's `contact_uuid` but attacker-controlled keys**. Two distinct harms result:

- **Immediate confidentiality breach** — the block is re-encrypted so the attacker's KEM key can decrypt it. This happens from the caller's bytes, independent of the card-file write.
- **Persistent substitution (TOFU)** — the trusted on-disk card is replaced with attacker keys, so every *future* share / sync / recipient-resolution silently uses them.

The step-5 duplicate check is a fingerprint over full canonical bytes, so a forged card with a different key set has a *different* fingerprint, passes the dedup gate, and replaces the on-disk card. **`verify_self()` alone does not fix this** — it checks the card's self-signature against its own embedded keys, so a fully attacker-generated card (attacker keys + victim UUID, attacker-signed) passes. The load-bearing control is the **TOFU "never overwrite a byte-different trusted card" guard**.

The safe primitives already exist in the bridge but are **not projected** to Python or mobile:

- `contacts::import_contact_card` — TOFU import: `read_verified_card` (both halves) + dedup-reject (`ContactAlreadyExists`), never overwrites (`contacts/import.rs`).
- `contacts::share_block_to` — share by recipient **UUID**: loads every existing card *and* the new card from `contacts/` and re-verifies both self-signature halves before re-keying (`contacts/share.rs`). The caller supplies only a UUID — no card bytes enter the trust path.

So the gap is specifically the **PyO3/uniffi projection surface**: Rust consumers linking the bridge directly can already use the safe wrappers.

## 2. Threat model and residual risk

**In scope:** an FFI consumer / host app passing attacker-influenced card bytes through the projected `share_block`.

**Who can reach unguarded `core::share_block`?** PyO3, uniffi, *and the desktop Tauri app* all call the **bridge** facade; none link `secretary-core` directly. The only callers reaching the core orchestrator without the bridge are in-repo Rust (core's own tests + the bridge itself).

**Decision (guard placement):** the defense-in-depth guard lives in the **bridge** `share::share_block`, with a **doc-contract** comment at core Step 12. Rationale:

- The bridge guard closes the reported vulnerability completely. If the victim's genuine card is already on disk (the realistic "share with an existing trusted contact" case), the guard rejects the call *before core runs*, closing **both** the immediate re-key and the persistence. If no card exists yet, there is no trusted card to substitute — that is normal trust-on-first-use.
- The only residual surface is a hypothetical *future in-repo Rust caller* that feeds `core::share_block` untrusted bytes while bypassing the bridge. That surface does not exist today, is compile-time visible and code-review-catchable, and is **not** the threat model's adversary (a runtime attacker arriving through FFI). The core doc-contract warns that author at the source.
- A core-level guard would buy belt-and-suspenders against that future in-repo misuse at the cost of a new `VaultError` variant, bridge exhaustive-match mapping, a frozen-v1 spec change (the documented Step 12 "idempotent overwrite" behavior), and a `conformance.py` re-run. Rejected as disproportionate to a non-attacker-reachable surface.

## 3. Components

### A. Bridge — harden `share::share_block` (the security fix)

File: `ffi/secretary-ffi-bridge/src/share/orchestration.rs`. Before calling `core::share_block`, gate the **new** recipient card:

1. **verify_self** — route `new_recipient` through the existing `crate::contacts::read_verified_card` (both Ed25519 ∧ ML-DSA-65 self-signature halves) instead of decode-only. Malformed/unsigned → `FfiVaultError::CardDecodeFailure` (unchanged variant; `read_verified_card` already maps both parse and verify failures to it).
2. **TOFU non-overwrite guard** — derive the path `contacts/<format_uuid_hyphenated(new_card.contact_uuid)>.card` under the snapshot's `vault_folder`:
   - file exists with **byte-different** content → reject `FfiVaultError::ContactAlreadyExists { uuid_hex }`;
   - file exists, **byte-identical** → allow (legit re-share; the `share_block_to` path lands here);
   - file absent → allow (first-contact TOFU).

The guard is a pure helper (`fn new_recipient_overwrite_ok(vault_folder, card_uuid, new_bytes) -> Result<(), FfiVaultError>` or similar) so it is unit-testable. `share_block_to` flows through this same hardened `share::share_block` with disk-loaded, already-verified, byte-identical bytes → never false-rejects.

The existing `existing_recipient_cards` handling is unchanged (see §6 non-goals).

### B. Core — doc-contract only

File: `core/src/vault/orchestrators.rs`, Step 12 of `share_block`. Add a comment stating the trust contract: *callers must supply already-verified, non-substituting card bytes; the FFI projection enforces this in the bridge `share::share_block` (verify_self + TOFU non-overwrite). Direct in-repo callers must uphold the same contract.* No code/behavior/format change.

### C. PyO3 projection — `ffi/secretary-ffi-py/`

- New module `src/contacts.rs` (keeps `share.rs` and `lib.rs` small):
  - `#[pyfunction] import_contact_card(manifest, card_bytes: &[u8]) -> PyResult<ContactSummary>`
  - `#[pyfunction] share_block_to(identity, manifest, block_uuid, new_recipient_uuid, device_uuid, now_ms)`
  - `#[pyclass] ContactSummary` projecting the bridge's 3 non-secret fields (`contact_uuid: [u8;16]` → bytes, `display_name: String`, `shared_block_count: u32`) with read-only getters, mirroring the existing DTO pyclass pattern (`sync.rs`).
- Register both pyfunctions + the pyclass in `lib.rs`. The error classes `VaultContactAlreadyExists` / `VaultContactNotFound` are **already registered**; no error-surface change.
- Argument-validation discipline per [[project_secretary_input_validation_at_binding_wrapper]]: wrong-length `block_uuid` / `new_recipient_uuid` / `device_uuid` validated at the binding wrapper (→ `ValueError`), consistent with the existing `share_block` pyfunction.
- pytest under the existing Python test layer.

### D. uniffi projection — `ffi/secretary-ffi-uniffi/`

- UDL (`src/secretary.udl`): add a `dictionary ContactSummary { ... }` and two namespace functions — `import_contact_card(...) -> ContactSummary` and `void share_block_to(...)` — mirroring the existing `share_block` declaration style.
- New `src/namespace/contacts.rs` with the wrapper fns + a `ContactSummary` record type (or `From` conversion from the bridge type), keeping `namespace/mod.rs` focused.
- Swift/Kotlin bindings regenerate automatically via `tests/swift/run.sh` / `tests/kotlin/run.sh` (gitignored, per the crate README) — **no committed-binding churn**.
- Add safe-path assertions to the Swift + Kotlin smoke runners (`SmokeShareBlock.{swift,kt}` or a sibling): `import_contact_card` then `share_block_to` succeeds; `import_contact_card` of a duplicate UUID → `ContactAlreadyExists`. No new `ConformanceErrors` arm (no new error variant).

### E. Demote raw `share_block`

Rustdoc on `share::share_block` (bridge) + the PyO3/UDL docstrings: mark it **discouraged / bridge-internal**, document the hardening, and point consumers at `share_block_to` + `import_contact_card`. It is retained — the Swift/Kotlin smoke harness and the pinned uniffi checksum depend on it.

## 4. Error surface

**No new `FfiVaultError` or `VaultError` variant.**

- The non-overwrite refusal reuses `FfiVaultError::ContactAlreadyExists { uuid_hex }` — already projected (PyO3 `VaultContactAlreadyExists`, uniffi error enum).
- `share_block_to`'s card-load surfaces `ContactNotFound` — already present.

Per [[project_secretary_ffivaulterror_workspace_match]], adding a variant would force threading uniffi/pyo3 + the Swift/Kotlin `ConformanceErrors.{swift,kt}` harnesses; reusing existing variants avoids that churn entirely.

## 5. Testing (TDD)

Write tests first; each reproduces a gap or pins a behavior.

**Teeth test (reproduces the vuln on pre-fix code):** stage a vault with a trusted contact card on disk; call raw `share_block` with a forged card carrying that contact's `contact_uuid` but different key bytes. Pre-fix: the on-disk card is overwritten. Post-fix: the call returns `ContactAlreadyExists` and the on-disk card is **byte-unchanged**.

**Bridge unit/integration:**
- new card identical to the on-disk card → allowed (no false reject);
- new card UUID absent from `contacts/` → allowed (TOFU first contact);
- unsigned/malformed new card → `CardDecodeFailure`;
- `share_block_to` happy path (import then share-by-uuid) succeeds;
- `import_contact_card` duplicate UUID → `ContactAlreadyExists`.

**PyO3 pytest:** both new functions importable from the module and exercised (import → share_block_to happy path; duplicate import → `VaultContactAlreadyExists`).

**uniffi Swift + Kotlin smoke:** the safe-path assertions in §3.D.

**Gates (all must be green):**
```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py            # unchanged — sanity
# Python FFI tests (per maturin/uv discipline), and:
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```

## 6. Explicit non-goals

- **Not** verifying the *existing* recipient cards inside raw `share_block`. The cited vulnerability is the new-recipient overwrite; existing cards are fingerprint-matched against the on-disk recipient set (`MissingRecipientCard`), and `share_block_to` verifies all cards from disk anyway. Noted as a possible follow-up.
- **Not** projecting the other already-built contact primitives (`enumerate_contact_cards`, `delete_contact_card`, `block_recipients`, `owner_card_export`, `revoke_block_from`, `contact_blocks`) — out of scope for the security fix.
- **Not** removing raw `share_block` from the FFI surface — it is load-bearing for the smoke/conformance harness and the pinned uniffi checksum.

## 7. File-size discipline

New small modules (`ffi/secretary-ffi-py/src/contacts.rs`, `ffi/secretary-ffi-uniffi/src/namespace/contacts.rs`) rather than growing `share.rs` / `mod.rs` past their current size, per the project's 500-line guideline.
