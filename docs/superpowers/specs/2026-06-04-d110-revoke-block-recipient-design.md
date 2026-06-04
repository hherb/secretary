# D.1.10 — `revoke_block_recipient` (frozen-core revoke / unshare primitive)

**Date:** 2026-06-04
**Sub-project:** A/B (Rust crypto core + bridge), the revoke primitive deferred out of D.1.7–D.1.9.
**Status:** design approved; ready for implementation plan.
**Issue:** [#177](https://github.com/hherb/secretary/issues/177).

## 1. Problem

`share_block` is **append-only** in v1: a recipient can be added to a block but never removed.
Deleting a contact's card from `contacts/` is **not** revocation — the former recipient still
holds the block content key (BCK) from the prior `share_block` and can still decrypt every
version it ever saw and any future version (the BCK is unchanged on append). D.1.7's contacts
pane states this boundary and a test pins it (a deleted contact can still decrypt a previously
shared block). `core` has no primitive to actually revoke, and `core` is frozen for v1, so this
must be a deliberate, fully-reviewed frozen-core change — not a D-phase UI task.

## 2. Goal

Add a frozen-core primitive `revoke_block_recipient` (and a bridge wrapper `revoke_block_from`)
that removes a recipient from a block via a **true content-key rotation**: a fresh BCK, the body
re-encrypted under it, fresh per-recipient hybrid-KEM wraps for the **remaining** recipients
only, the manifest `BlockEntry.recipients` shrunk, the manifest clock ticked and re-signed
(Ed25519 ∧ ML-DSA-65), all written atomically (block first, manifest second). After revoke, the
revoked party's old wrap can no longer recover the new body.

This is the inverse of `share_block`. Because `share_block` already generates a fresh BCK and
re-wraps for **all** current recipients on every call, revoke reuses that exact machinery with
the recipient set reduced by one — it introduces **no new crypto**, only a new validation surface
and a new manifest mutation.

## 3. Scope

**In scope**
- A private core helper `rewrite_block_with_recipients` extracted from `share_block`, holding the
  shared re-key engine (decrypt-as-author → fresh BCK → re-encrypt → re-wrap a given recipient
  set → re-sign → atomic block write → manifest update/tick/re-sign/write).
- A new core primitive `revoke_block_recipient` that validates and calls the helper with the
  reduced set.
- A new typed error `RecipientNotPresent` on both `VaultError` and `FfiVaultError` (+ UDL),
  threaded through every exhaustive match in the workspace.
- A bridge wrapper `revoke_block_from(block_uuid, revoked_recipient_uuid)` mirroring
  `share_block_to`, assembling remaining recipient cards from `contacts/`.
- Spec updates (`vault-format.md` §6.5, `crypto-design.md` §7) documenting revocation semantics
  and the forward-secrecy boundary.
- A revoke KAT + a `conformance.py` clean-room path proving the re-key.

**Out of scope (deferred)**
- **Desktop "Revoke" UI** — a separate D.1.11 slice hanging off the D.1.8 "Shared with" banner
  and the D.1.9 `ContactRow`, both already revoke-ready surfaces.
- **uniffi/pyo3 exposure of the revoke *function*** — stays under
  [#167](https://github.com/hherb/secretary/issues/167); revoke is bridge + (future) desktop only.
  (The new *error variant* still touches the binding surface — see §8.)
- Revocation audit log, re-share/rotation policies, batch revoke.
- Deleting the revoked contact's card from `contacts/` — the contact may receive **other** blocks;
  card deletion remains the separate "delete a contact" concern, orthogonal to revoke.

## 4. Architecture

Four layers, bottom-up.

### 4.1 Shared re-key helper (refactor of `share_block`)

`share_block` (`core/src/vault/orchestrators.rs:1189-1518`) performs an 18-step sequence; steps
7–17 are the re-key engine and are recipient-set-agnostic:

7. decrypt the block under the author's reader identity (§6.4);
8. materialise the **final** recipient set (pk-bundles, ML-KEM PKs, fingerprints);
9. rebuild the §6.1 header (preserve `block_uuid`, `created_at_ms`, block `vector_clock`);
10. re-encrypt under a **fresh BCK** with fresh per-recipient wraps (§6.5);
11. atomic-write the block to `blocks/<uuid>.cbor.enc`;
13. update `BlockEntry.recipients` + `fingerprint`, advance `last_mod_ms`;
14. tick the manifest vault-clock for `device_uuid`;
15–16. refresh + re-sign the manifest (Ed25519 ∧ ML-DSA-65);
17. atomic-write the manifest (block-first → manifest-second, §9).

Extract these into a private helper:

```rust
fn rewrite_block_with_recipients(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    author_card: &ContactCard,
    author_sk_ed: &Ed25519Secret,
    author_sk_pq: &MlDsa65Secret,
    final_recipient_cards: &[ContactCard],   // who can decrypt AFTER (the new wrap set)
    final_recipient_uuids: Vec<[u8; 16]>,    // manifest BlockEntry.recipients AFTER
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError>
```

After extraction:
- `share_block` = validate(author single-owner; new recipient **not** already present) →
  `final = existing ++ [new]` → `rewrite_block_with_recipients(...)` → persist the new
  recipient's card to `contacts/` (the one share-specific step, kept in the caller).
- `revoke_block_recipient` = validate(author single-owner; target **is** present) →
  `final = existing \ {target}` → `rewrite_block_with_recipients(...)`. No card is written or
  deleted.

The helper is the **single source of crypto truth**: the "both halves sign / both halves wrap"
property is implemented once and proven once.

If extraction pushes `orchestrators.rs` past the 500-line guidance, split it into an
`orchestrators/` module directory (`share.rs`, `revoke.rs`, `rekey.rs`, `mod.rs`) — one concept
per file. The decision is made during implementation based on the resulting line count.

### 4.2 Core primitive `revoke_block_recipient`

```rust
pub fn revoke_block_recipient(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    author_card: &ContactCard,
    author_sk_ed: &Ed25519Secret,
    author_sk_pq: &MlDsa65Secret,
    existing_recipient_cards: &[ContactCard],  // ALL current recipients (resolve wire table + find target)
    revoked_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError>
```

Sequence:
1. Locate the manifest `BlockEntry` by `block_uuid` → `BlockNotFound` if absent.
2. Read + decode the on-disk block (§6.1) → `CorruptVault` on decode failure.
3. Verify author: `fingerprint(author_card) == block_file.author_fingerprint` **and** the PR-B
   single-owner restriction (`author_card.contact_uuid == open.identity.user_uuid`) → `NotAuthor`.
4. **Owner-revoke guard:** `revoked_recipient_uuid != open.identity.user_uuid` → else
   **`VaultError::CannotRevokeOwner`**. The owner/author is **always** a recipient of any
   shareable block — `share_block` decrypts the block under the author's reader identity (§6.4)
   and fails with `NotARecipient` if the author is absent from the §6.2 table (orchestrators.rs:
   "The author MUST be a current recipient"). Re-keying a block *without* the owner would
   therefore brick it: the owner could never again decrypt it to re-key/re-share, and a transient
   `Ok` would mask a permanent loss of control. Reject up-front. (Because the owner can never be
   revoked, the final recipient set is **never empty** — there is no `EmptyRecipientList` path to
   worry about, and "revoke the last recipient" means the last *non-owner* recipient.)
5. Resolve every wire-level recipient (§6.2) to a supplying card in `existing_recipient_cards` →
   `MissingRecipientCard` if any is unresolved.
6. **Target-present check:** `revoked_recipient_uuid` must correspond to a current recipient
   (present in `BlockEntry.recipients` **and** the §6.2 wire table) → else
   **`VaultError::RecipientNotPresent`**.
7. Build `final_recipient_cards` = existing minus the target; `final_recipient_uuids` =
   `BlockEntry.recipients` minus the target.
8. `rewrite_block_with_recipients(...)`.

The manifest `recipients` shrinks → `shared_block_count` falls → the D.1.9 reverse map reflects
the change with no UI work. The contact card is left untouched.

### 4.3 Typed errors `RecipientNotPresent` and `CannotRevokeOwner`

Two new unit variants, each mirroring `RecipientAlreadyPresent`'s wiring across every layer:

- `core/src/vault/mod.rs`: add `VaultError::RecipientNotPresent` and `VaultError::CannotRevokeOwner`
  (unit variants, mirroring `RecipientAlreadyPresent` at mod.rs:232).
- `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`: add the matching `FfiVaultError` variants
  (mirroring `RecipientAlreadyPresent` at error/vault/mod.rs:195).
- `ffi/secretary-ffi-uniffi/src/secretary.udl`: add `RecipientNotPresent();` and
  `CannotRevokeOwner();` (mirroring `RecipientAlreadyPresent()` at udl:174).
- `From<VaultError> for FfiVaultError` and every exhaustive `match VaultError { … }` /
  `match FfiVaultError { … }` site in the workspace (share, trash, save, restore orchestrations;
  pyo3, uniffi, desktop tauri `map_ffi_error`, conformance helpers) must gain both new arms.

`CannotRevokeOwner` is **not** `RecipientNotPresent` (the owner *is* present) and **not**
`NotAuthor` (the caller *is* the author) — it is a distinct "you may not revoke the one recipient
that must remain" condition, so it earns its own typed variant rather than overloading either.

⚠️ **This error variant is the one binding-surface change** even though the revoke *function*
stays bridge-only: adding a `FfiVaultError`/UDL variant regenerates the Swift/Kotlin bindings and
imposes the workspace-wide exhaustive-match obligation. The build is validated with
`cargo clippy --release --workspace --tests -- -D warnings`, and Swift + Kotlin conformance are
re-run, before the slice is considered green.

### 4.4 Bridge wrapper `revoke_block_from`

Mirror `share_block_to` (`ffi/secretary-ffi-bridge/src/contacts/share.rs` +
`share/orchestration.rs`):

```rust
pub fn revoke_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    existing_recipient_cards: &[Vec<u8>],   // canonical-CBOR; ALL current recipients
    revoked_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError>
```

A `contacts/`-level wrapper `revoke_block_from(block_uuid, revoked_recipient_uuid)` assembles
`existing_recipient_cards` from the persisted `contacts/*.card` set (the union needed to resolve
the wire table, including the target's card), then calls the orchestration wrapper, mapping
`VaultError → FfiVaultError` exactly as `share` does (IO → `FolderInvalid`; decode →
`CorruptVault`; `NotAuthor` / `MissingRecipientCard` / `RecipientNotPresent` / `CannotRevokeOwner`
/ `BlockNotFound` → typed; residual crypto failures on validated inputs → `SaveCryptoFailure`). On success it
writes the refreshed manifest back into the in-memory handle.

**Mutation-path strictness (carried from the D.1.9 review):** the revoke path must **not** adopt
any of the read-only display leniency. A transient I/O fault folding to "no recipients" is fine
for a *display* but fatal for a *mutation* — every failure surfaces as a typed error; nothing is
swallowed.

## 5. Semantics / edge cases

| Situation | Behaviour |
|---|---|
| Revoke one of N recipients | Remaining N−1 re-wrapped under a fresh BCK; revoked old wrap fails on the new body. |
| Revoke the **last non-owner** recipient | `recipients` shrinks to the owner only; the block is owner-only again (never empty — the owner always remains). **Allowed.** |
| Revoke a **non-recipient** uuid | `RecipientNotPresent` (typed). No write. |
| Caller is **not** the owner/author | `NotAuthor`. No write. |
| A **remaining** recipient's card missing from `contacts/` | `MissingRecipientCard` — cannot re-wrap. No write. |
| Revoke the **author/owner** | `CannotRevokeOwner` (typed). The owner is *always* a recipient (must be, to decrypt + re-key); re-keying without them would brick the block, so this is rejected up-front (§4.2 step 4). No write. |
| `block_uuid` not in manifest | `BlockNotFound`. |

**Atomicity:** block-first → manifest-second (§9). A crash between leaves a re-keyed block + a
stale manifest still listing the old recipient — recoverable, and the conservative direction (the
revoked recipient appears *still present* until the manifest write lands, never *spuriously
removed* before the block is re-keyed).

## 6. Forward-secrecy boundary (must be documented)

Revocation protects **future** block-versions only. The revoked party may retain plaintext it
already decrypted, and the old BCK it already unwrapped — neither is recoverable by `core`.
Concretely: after revoke, the revoked party cannot decrypt the **new** on-disk body (fresh BCK,
no wrap for them), but nothing un-sees what they already saw. This is a property boundary, not a
bug; it is documented in `crypto-design.md` §7 and `vault-format.md` §6.5 so a future reader does
not assume revoke is retroactive.

## 7. Spec + conformance

- **`vault-format.md` §6.5** (Writing a block) + **`crypto-design.md` §7** (KEM wrap): add a
  "revocation = re-key + drop recipient (re-wrap remaining only)" paragraph and the §6 forward-
  secrecy caveat. **The on-disk format is unchanged** — a revoke emits the same §6.1/§6.2 bytes as
  a share to a smaller set — so this is clarifying prose, not a wire-format change. No format
  version bump.
- **New revoke KAT** under `core/tests/data/` + a **`conformance.py`** clean-room path:
  share-to-two → revoke-one, asserting
  (a) the revoked recipient's wrap is **gone** from the §6.2 table,
  (b) the remaining recipient decrypts the new body under the **new** BCK,
  (c) the revoked party's **old** wrap no longer decrypts the new body,
  (d) the manifest `recipients` shrank by exactly the revoked uuid.
- **`spec_test_name_freshness.py`**: register the new revoke test-name citations.

## 8. Tests (TDD)

Author tests first, mirroring `core/tests/share_block.rs`.

**Core — `core/tests/revoke_block.rs`:**
- `revoke_block_round_trip` — revoke one of two; remaining decrypts under the new BCK; the
  revoked party's pre-revoke wrap fails on the new body.
- `revoke_block_last_recipient_returns_owner_only` — revoking the last *non-owner* recipient
  leaves the owner-only set; author still decrypts.
- `revoke_block_non_author_rejected` — `NotAuthor`.
- `revoke_block_non_recipient_rejected` — `RecipientNotPresent`.
- `revoke_block_owner_rejected` — revoking the owner/author uuid → `CannotRevokeOwner`; the block
  is left untouched (no re-key, no write).
- `revoke_block_missing_remaining_card_rejected` — `MissingRecipientCard`.
- `revoke_block_not_found_rejected` — `BlockNotFound`.
- `revoke_block_re_sign_verifies` — manifest + block signatures verify post-revoke.
- `revoke_block_manifest_recipients_shrink` — `BlockEntry.recipients` drops exactly the target;
  `shared_block_count` integrity preserved.

**Refactor guard — `share_block` unchanged:**
- A test proving `share_block`'s on-disk output is byte-equivalent pre/post the helper extraction
  (re-run the existing `share_block.rs` suite; add an explicit output-shape assertion if the
  existing suite does not already pin the bytes). The refactor must not alter share's behaviour.

**Bridge:**
- An integration test for `revoke_block`/`revoke_block_from`: share to a recipient, revoke, assert
  the recipient is gone from the manifest and a typed error surfaces for a non-recipient.

**Crypto values:** generate nonces/keys at test runtime via `OsRng`; KAT vectors only via the
JSON fixture (no hardcoded cryptographic literals).

The CRDT merge proptests are **unaffected** — revoke changes no merge semantics (it ticks the
existing clock and shrinks a set under the existing canonical encoding). No proptest change.

## 9. Risks

1. **Editing the frozen, heavily-reviewed `share_block` path** (the helper extraction). Mitigation:
   the byte-equivalence guard test (§8) + a full security re-review of `share_block` in the
   whole-branch review. The extraction is mechanical (move steps 7–17 into a helper, parameterise
   the recipient set); `share_block`'s validation and card-persistence stay in place.
2. **`FfiVaultError` variant churn** — a workspace-wide exhaustive-match obligation + Swift/Kotlin
   binding regeneration, even though the revoke function is not FFI-exposed. Mitigation:
   `--workspace` clippy with `-D warnings`, thread every match site, re-run Swift + Kotlin + pyo3
   conformance.
3. **Forward-secrecy misreading** — a future contributor could assume revoke is retroactive.
   Mitigation: the §6 boundary is documented in both normative specs.

## 10. Acceptance criteria

- `revoke_block_recipient` in `core` with the §4.2 validation surface and the `rewrite_block_with_
  recipients` helper; `share_block` refactored onto the helper with byte-equivalent output.
- `VaultError::RecipientNotPresent` + `VaultError::CannotRevokeOwner` (+ their `FfiVaultError` +
  UDL variants), threaded through every workspace match site. The owner-revoke guard is enforced
  in `revoke_block_recipient` (§4.2 step 4) and pinned by `revoke_block_owner_rejected`.
- `revoke_block` / `revoke_block_from` bridge wrappers mirroring `share`.
- `vault-format.md` §6.5 + `crypto-design.md` §7 updated (revocation + forward-secrecy); no format
  version bump.
- A revoke KAT + a `conformance.py` path asserting (a)–(d) of §7; `spec_test_name_freshness`
  registered.
- The full automated gauntlet green: `cargo test --release --workspace`,
  `cargo clippy --release --workspace --tests -- -D warnings`, `cargo fmt --all -- --check`,
  `conformance.py`, `spec_test_name_freshness.py`, Swift + Kotlin conformance.
- No desktop change; no uniffi/pyo3 revoke *function*.
