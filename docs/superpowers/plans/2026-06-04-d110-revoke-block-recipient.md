# D.1.10 — `revoke_block_recipient` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a frozen-core `revoke_block_recipient` primitive (+ bridge wrapper `revoke_block`/`revoke_block_from`) that removes a recipient from a shared block by rotating the block content key and re-wrapping for the remaining recipients only — the inverse of `share_block`.

**Architecture:** Extract `share_block`'s re-key engine (decrypt → fresh BCK → re-wrap → re-sign → atomic block+manifest write, current `orchestrators.rs:1318-1518`) into a private `rewrite_block_with_recipients` helper parameterised by the *final* recipient set, then build `revoke_block_recipient` on top of it with a reduced set. Add a typed `RecipientNotPresent` error across core + FFI + UDL. Mirror the bridge `share` wrapper. Update both normative specs and add a clean-room revoke KAT.

**Tech Stack:** Rust (stable, `secretary-core` + `secretary-ffi-bridge`), uniffi UDL, Python stdlib (`conformance.py`), `uv`.

**Spec:** [docs/superpowers/specs/2026-06-04-d110-revoke-block-recipient-design.md](../specs/2026-06-04-d110-revoke-block-recipient-design.md)

**Working directory:** `/Users/hherb/src/secretary/.worktrees/d110-revoke` on branch `feature/d110-revoke`. All `cargo`/`git` commands run from there (verify with `pwd && git branch --show-current` first).

**Per-task gate (run before every commit):**
```bash
cargo fmt --all -- --check && \
cargo clippy --release --workspace --tests -- -D warnings && \
cargo test --release --workspace
```

---

## Task 1: Extract `rewrite_block_with_recipients` helper (behavior-preserving refactor)

This is a pure refactor: move `share_block`'s steps 7–18 into a private helper and have `share_block` call it. No behavior change — the existing `share_block.rs` suite is the guard.

**Files:**
- Modify: `core/src/vault/orchestrators.rs` (extract helper from `share_block` body `1189-1518`)
- Test (guard, already exists): `core/tests/share_block.rs`

- [ ] **Step 1: Confirm the guard suite is green before touching anything**

Run: `cargo test --release --workspace --test share_block`
Expected: PASS (all existing `share_block_*` tests). This is the baseline the refactor must preserve.

- [ ] **Step 2: Add the private helper holding steps 7–18**

In `core/src/vault/orchestrators.rs`, add a private function. Its body is the **current `share_block` code at lines 1318-1518 (steps 7 through 18), copied verbatim**, with exactly three parameterisations:

1. Step 8 builds the recipient set from the `final_recipient_cards` parameter (in wire order) instead of `existing_cards_in_order` + `new_recipient`.
2. Step 12 (persist contact card) becomes conditional on the `card_to_persist` parameter — `Some((bytes, uuid))` writes the card exactly as today; `None` skips it. This preserves share's block→card→manifest write ordering.
3. Step 13 sets `recipients: final_recipient_uuids` instead of `old.recipients.clone()` + push.

Signature:

```rust
/// Re-key a block for a given final recipient set and re-sign the manifest.
///
/// This is the shared crypto engine behind both `share_block` (final set =
/// existing ++ new) and `revoke_block_recipient` (final set = existing \ target).
/// It performs §6.4 decrypt-as-author → fresh-BCK §6.5 re-encrypt → atomic block
/// write → optional recipient-card persist → manifest BlockEntry update → vault
/// clock tick → manifest re-sign (Ed25519 ∧ ML-DSA-65) → atomic manifest write,
/// preserving the block-first → manifest-second ordering of §9.
///
/// Callers perform steps 1–6 (locate entry, read+decode block, author check,
/// single-owner check, wire-table resolution) and pass the results in.
#[allow(clippy::too_many_arguments)]
fn rewrite_block_with_recipients(
    folder: &Path,
    open: &mut OpenVault,
    block_file: &block::BlockFile,
    entry_idx: usize,
    author_card: &ContactCard,
    author_fp: crate::identity::fingerprint::Fingerprint,
    author_sk_ed: &Ed25519Secret,
    author_sk_pq: &MlDsa65Secret,
    final_recipient_cards: &[&ContactCard],
    final_recipient_uuids: Vec<[u8; 16]>,
    card_to_persist: Option<(&[u8], [u8; 16])>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError> {
    // ... steps 7–18 from the current share_block body, parameterised as above ...
}
```

Notes for the implementer:
- Step 8's loop iterates `final_recipient_cards` (already `&ContactCard` in wire order).
- The `blocks_dir` / `block_path` are recomputed inside the helper from `folder` + `block_file.header.block_uuid` (or pass them in — pick one and keep it consistent; recomputing from `block_file.header.block_uuid` is simplest since the helper already has `block_file`).
- Step 12: when `card_to_persist` is `Some((bytes, uuid))`, write `contacts/<hyphenated-uuid>.card` exactly as the current code does with `new_recipient_card_bytes` / `new_recipient.contact_uuid`.

- [ ] **Step 3: Rewrite `share_block` to call the helper**

Keep `share_block`'s steps 1–6 **unchanged** (lines 1202-1316). Replace steps 7–18 (lines 1318-1518) with:

```rust
    // Steps 7–18: build the final recipient set (existing in wire order +
    // the new recipient appended) and delegate to the shared re-key engine.
    let mut final_cards: Vec<&ContactCard> = existing_cards_in_order;
    final_cards.push(new_recipient);

    let mut final_uuids = open.manifest.blocks[entry_idx].recipients.clone();
    final_uuids.push(new_recipient.contact_uuid);

    rewrite_block_with_recipients(
        folder,
        open,
        &block_file,
        entry_idx,
        author_card,
        author_fp,
        author_sk_ed,
        author_sk_pq,
        &final_cards,
        final_uuids,
        Some((&new_recipient_card_bytes, new_recipient.contact_uuid)),
        device_uuid,
        now_ms,
        rng,
    )
```

(Confirm `new_recipient_card_bytes` from step 5 is still in scope; if the borrow checker objects to `existing_cards_in_order` being moved into `final_cards` while `block_file` is borrowed, the existing code already holds these references in the same scope — preserve their lifetimes.)

- [ ] **Step 4: Run the per-task gate**

Run: `cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings && cargo test --release --workspace --test share_block`
Expected: fmt clean, clippy clean, **all `share_block_*` tests still PASS** (the refactor preserved behavior).

- [ ] **Step 5: Run the full workspace suite (no regressions elsewhere)**

Run: `cargo test --release --workspace`
Expected: PASS, same totals as the D.1.9 baseline (1172/0/10).

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/orchestrators.rs
git commit -m "refactor(core): extract rewrite_block_with_recipients from share_block

Pulls share_block's re-key engine (steps 7-18: decrypt -> fresh BCK ->
re-wrap -> re-sign -> atomic block+manifest write) into a private helper
parameterised by the final recipient set, so revoke_block_recipient can reuse
it. share_block's validation (steps 1-6) and write ordering (block -> card ->
manifest) are unchanged; the existing share_block suite is the behavior guard.

Refs #177.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Typed error `RecipientNotPresent` (core + FFI + UDL + all match sites)

**Files:**
- Modify: `core/src/vault/mod.rs` (add `VaultError::RecipientNotPresent` near `RecipientAlreadyPresent` at line 232)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (add `FfiVaultError::RecipientNotPresent` near line 195)
- Modify: `ffi/secretary-ffi-bridge/src/error/conversions.rs` (the `From<VaultError>` mapping)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (add `RecipientNotPresent();` near line 174)
- Modify: any other exhaustive `match VaultError`/`match FfiVaultError` site flagged by the compiler (e.g. `trash/orchestration.rs:127-129`)
- Test: `ffi/secretary-ffi-bridge/src/error/conversions.rs` (or its test module) — a mapping unit test

- [ ] **Step 1: Write the failing mapping test**

In the bridge error-conversions test module, add:

```rust
#[test]
fn recipient_not_present_maps_to_ffi_variant() {
    let ffi: FfiVaultError = VaultError::RecipientNotPresent.into();
    assert!(matches!(ffi, FfiVaultError::RecipientNotPresent));
}
```

- [ ] **Step 2: Run it to verify it fails to compile**

Run: `cargo test --release -p secretary-ffi-bridge recipient_not_present_maps_to_ffi_variant`
Expected: compile error — `VaultError::RecipientNotPresent` and `FfiVaultError::RecipientNotPresent` do not exist yet.

- [ ] **Step 3: Add the core variant**

In `core/src/vault/mod.rs`, immediately after the `RecipientAlreadyPresent` variant (line 232), add a doc-commented unit variant:

```rust
    /// The caller asked to revoke a recipient that is not currently a
    /// recipient of the block (absent from the §6.2 wire table / the
    /// manifest `BlockEntry.recipients`). Symmetric with
    /// [`Self::RecipientAlreadyPresent`]. Surfaced by `revoke_block_recipient`.
    RecipientNotPresent,
```

Add a `Display` arm if `VaultError`'s `Display`/`thiserror` derivation requires one (mirror `RecipientAlreadyPresent`'s message: e.g. `"recipient is not present on the block"`).

- [ ] **Step 4: Add the FFI variant + mapping + UDL**

In `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, after `RecipientAlreadyPresent` (line 195), add:

```rust
    /// Revoke target is not a current recipient of the block. Mirrors
    /// [`Self::RecipientAlreadyPresent`]; surfaced by the revoke path.
    RecipientNotPresent,
```

In `ffi/secretary-ffi-bridge/src/error/conversions.rs`, add the arm to the `From<VaultError>` match:

```rust
        VaultError::RecipientNotPresent => FfiVaultError::RecipientNotPresent,
```

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, after `RecipientAlreadyPresent();` (line 174), add:

```
  RecipientNotPresent();
```

- [ ] **Step 5: Thread every other exhaustive match the compiler flags**

Run: `cargo build --release --workspace --tests`
For each `non-exhaustive` / `unreachable`-style error, add a `VaultError::RecipientNotPresent` (or `FfiVaultError::RecipientNotPresent`) arm. Known site: `ffi/secretary-ffi-bridge/src/trash/orchestration.rs:127-129` groups `NotAuthor | RecipientAlreadyPresent | MissingRecipientCard` — add `| VaultError::RecipientNotPresent` to that group (it is an unreachable "crypto/validated" residual there, mapped to whatever that arm maps to — match the existing grouping's intent). Repeat for any save/restore/share match the compiler points at.

- [ ] **Step 6: Run the mapping test + gate**

Run: `cargo test --release -p secretary-ffi-bridge recipient_not_present_maps_to_ffi_variant`
Expected: PASS.
Run: `cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings && cargo test --release --workspace`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add core/src/vault/mod.rs ffi/secretary-ffi-bridge/src/error/ ffi/secretary-ffi-uniffi/src/secretary.udl
git add -u
git commit -m "feat(core,ffi): add typed RecipientNotPresent error

VaultError::RecipientNotPresent + FfiVaultError::RecipientNotPresent + UDL
variant + From mapping, threaded through every workspace exhaustive match.
Symmetric with RecipientAlreadyPresent; surfaced by the revoke path. Adding
the FfiVaultError/UDL variant regenerates Swift/Kotlin bindings even though
the revoke function stays bridge-only.

Refs #177.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Core `revoke_block_recipient` — happy paths

**Files:**
- Modify: `core/src/vault/orchestrators.rs` (add `pub fn revoke_block_recipient`)
- Modify: `core/src/vault/mod.rs` (re-export `revoke_block_recipient` alongside `share_block`)
- Test: `core/tests/revoke_block.rs` (new; copy `share_block.rs`'s fixture helpers verbatim)

- [ ] **Step 1: Scaffold the test file with the shared fixtures**

Create `core/tests/revoke_block.rs`. Copy the fixture helpers from `core/tests/share_block.rs` lines 16-~250 (`fast_kdf`, `make_fast_vault`, `format_uuid_hyphenated`, any `make_recipient_card` / `save_initial_block` helpers, and the imports at lines 16-41). Add `revoke_block_recipient` to the `use secretary_core::vault::{…}` import list. These helpers create a vault, mint recipient cards, and save+share an initial block — the revoke tests need a block already shared with two recipients.

- [ ] **Step 2: Write the round-trip happy-path test (failing)**

```rust
#[test]
fn revoke_block_round_trip() {
    // Arrange: owner vault + two imported recipients (alice, bob); save a
    // block and share it to both, so the wire table has {owner?, alice, bob}.
    let (dir, owner_card, owner_sk_ed, owner_sk_pq, open, block_uuid,
         alice_card, bob_card) = setup_block_shared_to_two();

    // Snapshot: alice can decrypt the pre-revoke block.
    // (assert via decrypt_block as alice — proves the baseline)

    // Act: revoke bob.
    let mut open = open;
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    revoke_block_recipient(
        dir.path(), &mut open, block_uuid,
        &owner_card, &owner_sk_ed, &owner_sk_pq,
        &[alice_card.clone(), bob_card.clone()], // existing recipient cards (all current)
        bob_card.contact_uuid,                   // revoked uuid
        [7u8; 16], 1_714_060_900_000, &mut rng,
    ).expect("revoke should succeed");

    // Assert (a): bob's fingerprint is gone from the §6.2 wire table.
    let after = decode_block_file(&fs::read(block_path(&dir, block_uuid)).unwrap()).unwrap();
    let bob_fp = fingerprint(&bob_card.to_canonical_cbor().unwrap());
    assert!(!after.recipients.iter().any(|w| w.recipient_fingerprint == bob_fp),
            "bob's wrap must be removed");

    // Assert (b): alice still decrypts under the NEW BCK.
    // (decrypt_block as alice on `after` → Ok, plaintext == original)

    // Assert (c): the manifest BlockEntry.recipients dropped exactly bob.
    let entry = open.manifest.blocks.iter().find(|b| b.block_uuid == block_uuid).unwrap();
    assert!(!entry.recipients.contains(&bob_card.contact_uuid));
    assert!(entry.recipients.contains(&alice_card.contact_uuid));
}
```

Implement `setup_block_shared_to_two()` and `block_path()` as local helpers (mirror `share_block.rs`'s arrangement; `setup` calls `save_block` then `share_block` twice or `share_block` once per recipient). Keep crypto values random/seeded (no hardcoded keys).

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test --release --workspace --test revoke_block revoke_block_round_trip`
Expected: compile error / FAIL — `revoke_block_recipient` not defined.

- [ ] **Step 4: Implement `revoke_block_recipient`**

In `core/src/vault/orchestrators.rs`, add (mirrors `share_block` steps 1–6, with step 5 inverted to require-present, then delegates to the Task 1 helper):

```rust
/// Revoke a recipient from a shared block (§6 revoke / unshare primitive).
///
/// The inverse of [`share_block`]: rotates the block content key, re-wraps for
/// the remaining recipients only, drops `revoked_recipient_uuid` from the
/// manifest `BlockEntry.recipients`, ticks the manifest clock, re-signs
/// (Ed25519 ∧ ML-DSA-65) and writes atomically (block then manifest).
///
/// Author-only (single-owner, like `share_block`). `existing_recipient_cards`
/// must cover every recipient currently in the §6.2 wire table, INCLUDING the
/// revoke target (needed to resolve the table). The revoked contact's card is
/// left in `contacts/` untouched — card deletion is a separate concern.
///
/// # Errors
/// - [`VaultError::BlockNotFound`] — `block_uuid` absent from the manifest.
/// - [`VaultError::NotAuthor`] — caller is not the block's single-owner author.
/// - [`VaultError::MissingRecipientCard`] — a current wrap has no supplying card.
/// - [`VaultError::RecipientNotPresent`] — `revoked_recipient_uuid` is not a
///   current recipient.
///
/// # Forward secrecy
/// Revocation protects FUTURE block-versions only. The revoked party may retain
/// plaintext/keys already seen; `core` cannot un-see them. See `docs/`.
#[allow(clippy::too_many_arguments)]
pub fn revoke_block_recipient(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    author_card: &ContactCard,
    author_sk_ed: &Ed25519Secret,
    author_sk_pq: &MlDsa65Secret,
    existing_recipient_cards: &[ContactCard],
    revoked_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError> {
    // Step 1: locate the manifest BlockEntry.
    let entry_idx = open
        .manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .ok_or(VaultError::BlockNotFound { block_uuid })?;

    // Step 2: read + decode the §6.1 block envelope.
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = blocks_dir.join(format!("{block_uuid_hex}.cbor.enc"));
    let block_file_bytes = std::fs::read(&block_path).map_err(|e| VaultError::Io {
        context: "failed to read block file for revoke_block_recipient",
        source: e,
    })?;
    let block_file = block::decode_block_file(&block_file_bytes)?;

    // Step 3: author check (re-derive fingerprint, compare to on-disk).
    let author_card_bytes = author_card.to_canonical_cbor()?;
    let author_fp = fingerprint(&author_card_bytes);
    if author_fp != block_file.author_fingerprint {
        return Err(VaultError::NotAuthor {
            expected: block_file.author_fingerprint,
            got: author_fp,
        });
    }

    // Step 4: PR-B single-owner restriction (same as share_block).
    if author_card.contact_uuid != open.identity.user_uuid {
        return Err(VaultError::NotAuthor {
            expected: block_file.author_fingerprint,
            got: author_fp,
        });
    }

    // Step 5 (inverted vs share): resolve every wrap to a supplying card AND
    // locate the revoke target. Build the fingerprint->card lookup, walk the
    // wire table, and split the resolved cards into "keep" (final set) vs the
    // single revoked card. The target must be present.
    let mut card_lookup: Vec<(crate::identity::fingerprint::Fingerprint, &ContactCard)> =
        Vec::with_capacity(existing_recipient_cards.len());
    for c in existing_recipient_cards {
        card_lookup.push((fingerprint(&c.to_canonical_cbor()?), c));
    }
    let mut final_cards: Vec<&ContactCard> = Vec::with_capacity(block_file.recipients.len());
    let mut found_target = false;
    for wrap in &block_file.recipients {
        let card = card_lookup
            .iter()
            .find(|(fp, _)| *fp == wrap.recipient_fingerprint)
            .map(|(_, c)| *c)
            .ok_or(VaultError::MissingRecipientCard {
                fingerprint: wrap.recipient_fingerprint,
            })?;
        if card.contact_uuid == revoked_recipient_uuid {
            found_target = true; // drop from the final set
        } else {
            final_cards.push(card);
        }
    }
    if !found_target {
        return Err(VaultError::RecipientNotPresent);
    }

    // Step 6: final manifest recipient uuids = current minus the target.
    let final_uuids: Vec<[u8; 16]> = open.manifest.blocks[entry_idx]
        .recipients
        .iter()
        .copied()
        .filter(|u| *u != revoked_recipient_uuid)
        .collect();

    // Steps 7–18: delegate to the shared re-key engine. No card is persisted
    // or deleted on revoke (card_to_persist = None).
    rewrite_block_with_recipients(
        folder,
        open,
        &block_file,
        entry_idx,
        author_card,
        author_fp,
        author_sk_ed,
        author_sk_pq,
        &final_cards,
        final_uuids,
        None,
        device_uuid,
        now_ms,
        rng,
    )
}
```

Re-export it from `core/src/vault/mod.rs` wherever `share_block` is re-exported.

- [ ] **Step 5: Run the round-trip test**

Run: `cargo test --release --workspace --test revoke_block revoke_block_round_trip`
Expected: PASS.

- [ ] **Step 6: Add the remaining happy-path tests**

Add to `core/tests/revoke_block.rs`:

```rust
#[test]
fn revoke_block_last_recipient_returns_owner_only() {
    // Share to exactly one recipient, revoke it: recipients becomes empty,
    // the block is owner-only, and the owner/author still decrypts.
    // assert: after.recipients is empty (or just the owner if owner is a
    // recipient — match what save_block puts in the wire table), and
    // manifest entry.recipients is empty.
}

#[test]
fn revoke_block_re_sign_verifies() {
    // After revoke, re-open the vault (open_vault) and decrypt the block:
    // the manifest hybrid signature and the block hybrid signature both verify.
    // open_vault already enforces Ed25519 ∧ ML-DSA-65 on the manifest.
}

#[test]
fn revoke_block_manifest_recipients_shrink() {
    // Share to alice + bob, revoke bob, assert entry.recipients == [alice]
    // (exact set equality), proving shared_block_count integrity.
}
```

Fill in each body using the same arrangement helpers. For `re_sign_verifies`, call `open_vault(...)` on `dir.path()` after revoke and assert it returns `Ok` (open_vault verifies the manifest signature), then `decrypt_block` the block as alice.

- [ ] **Step 7: Run all happy-path tests + gate**

Run: `cargo test --release --workspace --test revoke_block`
Expected: all 4 happy-path tests PASS.
Run: `cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add core/src/vault/orchestrators.rs core/src/vault/mod.rs core/tests/revoke_block.rs
git commit -m "feat(core): revoke_block_recipient happy paths

Inverse of share_block: re-key the block, re-wrap remaining recipients only,
drop the target from manifest BlockEntry.recipients, re-sign, atomic write.
Built on rewrite_block_with_recipients. Tests: round-trip (remaining decrypts
under new BCK, revoked wrap gone), last-recipient -> owner-only, re-sign
verifies via open_vault, manifest recipients shrink.

Refs #177.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Core `revoke_block_recipient` — error paths

**Files:**
- Test: `core/tests/revoke_block.rs` (extend)

- [ ] **Step 1: Write the error-path tests (failing only if a guard is wrong)**

Add:

```rust
#[test]
fn revoke_block_not_found_rejected() {
    // revoke against a random block_uuid not in the manifest -> BlockNotFound.
    let err = revoke_block_recipient(/* ..., */ [0xAB; 16] /* bogus block */, /* ... */).unwrap_err();
    assert!(matches!(err, VaultError::BlockNotFound { .. }));
}

#[test]
fn revoke_block_non_author_rejected() {
    // A non-owner identity attempts revoke -> NotAuthor.
    // (build a second vault/identity as the caller; or pass a foreign
    // author_card whose contact_uuid != open.identity.user_uuid)
    assert!(matches!(err, VaultError::NotAuthor { .. }));
}

#[test]
fn revoke_block_non_recipient_rejected() {
    // Share to alice only; attempt to revoke bob (never a recipient) ->
    // RecipientNotPresent. Pass bob's card in existing_recipient_cards so the
    // failure is specifically "not in the wire table", not MissingRecipientCard.
    assert!(matches!(err, VaultError::RecipientNotPresent));
}

#[test]
fn revoke_block_missing_remaining_card_rejected() {
    // Share to alice + bob; revoke bob but pass existing_recipient_cards =
    // [bob] only (alice's card withheld) -> MissingRecipientCard (alice's wrap
    // can't be resolved to re-wrap).
    assert!(matches!(err, VaultError::MissingRecipientCard { .. }));
}
```

Fill in the arranges with the local helpers. For `non_recipient_rejected`, ensure bob's card IS supplied (so the lookup resolves but no wrap matches bob → `found_target` stays false → `RecipientNotPresent`). For `missing_remaining_card_rejected`, withhold alice's card so her wrap can't resolve.

- [ ] **Step 2: Run them**

Run: `cargo test --release --workspace --test revoke_block`
Expected: PASS (the guards from Task 3 already enforce these; if any fail, fix the guard ordering in `revoke_block_recipient`). Confirm `revoke_block_non_recipient_rejected` in particular returns `RecipientNotPresent` and NOT `MissingRecipientCard` — this pins the §4.2 step-5 ordering.

- [ ] **Step 3: Run the gate**

Run: `cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings && cargo test --release --workspace`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add core/tests/revoke_block.rs
git commit -m "test(core): revoke_block_recipient error paths

BlockNotFound, NotAuthor, RecipientNotPresent (target supplied but not a
recipient), MissingRecipientCard (a remaining wrap has no card). Pins the
step-5 ordering: a non-recipient with a supplied card is RecipientNotPresent,
not MissingRecipientCard.

Refs #177.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Bridge `revoke_block` + `revoke_block_from` wrappers

Mirror the `share` bridge surface (`ffi/secretary-ffi-bridge/src/share/orchestration.rs` + `contacts/share.rs`).

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/revoke/orchestration.rs` (mirror `share/orchestration.rs`)
- Create: `ffi/secretary-ffi-bridge/src/revoke/mod.rs` (or add a `revoke` module declaration)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (declare `mod revoke;` + re-export `revoke_block`)
- Create/Modify: `ffi/secretary-ffi-bridge/src/contacts/revoke.rs` (mirror `contacts/share.rs`'s `share_block_from`) + register in `contacts/mod.rs`
- Test: a bridge integration test (mirror the existing share bridge test location — e.g. `ffi/secretary-ffi-bridge/tests/` or the in-crate test module used by `share`)

- [ ] **Step 1: Write the failing bridge integration test**

Mirror the share bridge test: open a vault handle, save a block, share to a recipient, then revoke and assert the recipient is gone + a non-recipient revoke surfaces `FfiVaultError::RecipientNotPresent`.

```rust
#[test]
fn revoke_block_removes_recipient_and_typed_errors() {
    // Arrange a handle with a block shared to alice (reuse the share test's setup).
    // Act: revoke_block(identity, manifest, block_uuid, &[alice_card_bytes],
    //                   alice_uuid, device_uuid, now_ms) -> Ok.
    // Assert: the in-memory manifest's BlockEntry.recipients no longer contains alice.
    // Act 2: revoke a uuid that isn't a recipient -> Err(FfiVaultError::RecipientNotPresent).
}
```

- [ ] **Step 2: Run it to verify failure**

Run: `cargo test --release -p secretary-ffi-bridge revoke_block_removes_recipient`
Expected: compile error — `revoke_block` not defined.

- [ ] **Step 3: Implement the orchestration wrapper**

Create `ffi/secretary-ffi-bridge/src/revoke/orchestration.rs` mirroring `share/orchestration.rs:56-200`. Same shape: decode the existing recipient cards from canonical-CBOR bytes, snapshot the manifest, clone+extract+zeroize the signing keys, build a temporary `OpenVault`, call `secretary_core::vault::revoke_block_recipient`, and on success write the manifest back via the same handle method `share` uses. Reuse `share`'s `map_revoke_error` equivalent (copy `share`'s VaultError→FfiVaultError mapping and add the `RecipientNotPresent` arm — it maps to `FfiVaultError::RecipientNotPresent`).

```rust
pub fn revoke_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    existing_recipient_cards: &[Vec<u8>],
    revoked_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // mirror share_block's body; call revoke_block_recipient instead.
}
```

- [ ] **Step 4: Implement the `contacts/`-level wrapper**

Create `ffi/secretary-ffi-bridge/src/contacts/revoke.rs` mirroring `contacts/share.rs`. `revoke_block_from(block_uuid, revoked_recipient_uuid)` looks up the manifest BlockEntry, assembles the current recipient cards from `contacts/*.card` (the union covering the wire table, including the target), and calls `revoke::orchestration::revoke_block`. Map a missing manifest entry to `FfiVaultError::BlockNotFound` (mirror `share.rs:54`).

Wire both into `lib.rs` (`mod revoke;`, re-export `revoke_block`) and `contacts/mod.rs`.

- [ ] **Step 5: Run the integration test**

Run: `cargo test --release -p secretary-ffi-bridge revoke_block_removes_recipient`
Expected: PASS.

- [ ] **Step 6: Run the gate (workspace — catches uniffi/pyo3 fallout)**

Run: `cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings && cargo test --release --workspace`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/revoke/ ffi/secretary-ffi-bridge/src/contacts/ ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/ 2>/dev/null; git add -u
git commit -m "feat(bridge): revoke_block / revoke_block_from wrappers

Mirror share's bridge surface: decode current recipient cards, call core
revoke_block_recipient, write the refreshed manifest back to the handle.
contacts::revoke_block_from assembles cards from contacts/. The mutation path
keeps no read-only display leniency — every failure is a typed FfiVaultError.
Bridge-only (no uniffi/pyo3 function) per #167.

Refs #177.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Spec docs — revocation semantics + forward-secrecy

**Files:**
- Modify: `docs/vault-format.md` (§6.5 "Writing a block")
- Modify: `docs/crypto-design.md` (§7 KEM wrap + a forward-secrecy note)

- [ ] **Step 1: Update `vault-format.md` §6.5**

Add a subsection under §6.5 (Writing a block) describing revocation. Exact prose to add (adjust section numbering to match the file):

```markdown
#### Revocation (removing a recipient)

Revoking a recipient re-keys the block: a fresh block content key (BCK) is
generated, the body is re-encrypted under it, and fresh §6.2 recipient wraps are
produced for the **remaining** recipients only. The revoked recipient's wrap is
absent from the new §6.2 table, and the manifest `BlockEntry.recipients` drops
the revoked contact UUID. The block is written first, then the manifest (§9), and
both are re-signed (Ed25519 ∧ ML-DSA-65). The on-disk *format* is identical to a
write to a smaller recipient set — there is no new field and no format-version
bump. Revoking the last recipient yields an empty recipient set (owner-only).

**Forward-secrecy boundary.** Revocation protects only block-versions written
*after* it. The revoked party may retain plaintext it already decrypted and the
prior BCK it already unwrapped; nothing in this format makes those unrecoverable.
A conforming reader holding only the *new* on-disk bytes cannot decrypt as the
revoked recipient (no wrap exists for them under the new BCK).
```

- [ ] **Step 2: Update `crypto-design.md` §7**

Add a short paragraph to §7 (Hybrid KEM / block-key wrap) cross-referencing the boundary:

```markdown
**Re-keying on share/revoke.** Both `share_block` and `revoke_block_recipient`
generate a fresh BCK and re-wrap for the full *post-operation* recipient set
(existing ± one). This means every share/revoke rotates the content key; an
attacker who recorded a prior on-disk version still holds wraps to the prior BCK,
so revocation is forward-only (see vault-format.md §6.5). The hybrid wrap itself
(X25519 ⊕ ML-KEM-768 → HKDF-SHA256 → XChaCha20-Poly1305) is unchanged.
```

- [ ] **Step 3: Verify the conformance/spec scripts still pass (no code change, doc-only)**

Run: `uv run core/tests/python/conformance.py`
Expected: PASS (unchanged — docs prose doesn't affect the golden-vault decrypt).
Run: `uv run core/tests/python/spec_test_name_freshness.py`
Expected: PASS (no new test-name citations in the docs yet — those come in Task 8).

- [ ] **Step 4: Commit**

```bash
git add docs/vault-format.md docs/crypto-design.md
git commit -m "docs: revocation semantics + forward-secrecy boundary

vault-format.md §6.5 documents revoke = re-key + drop recipient (same on-disk
format, no version bump, last-recipient -> owner-only) and the forward-secrecy
boundary; crypto-design.md §7 notes that share AND revoke rotate the BCK and
why revocation is forward-only.

Refs #177.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Revoke KAT fixture + deterministic generator

A clean-room fixture: a 2-recipient block plus the same block after revoking one recipient, with the remaining recipient's keys so `conformance.py` can prove the re-key.

**Files:**
- Create: `core/tests/data/revoke_kat/before_block.cbor.enc`, `after_block.cbor.enc`, `inputs.json` (generated, committed)
- Create: `core/tests/revoke_kat.rs` (a `#[ignore]` generator `generate_revoke_kat` + a non-ignored replay test that re-derives and asserts equality)

- [ ] **Step 1: Write the replay test (the always-run guard)**

Create `core/tests/revoke_kat.rs`. The non-ignored test loads `revoke_kat/inputs.json`, reads `after_block.cbor.enc`, decodes it, and asserts:

```rust
#[test]
fn revoke_kat_after_block_matches_inputs() {
    let inputs = load_inputs(); // serde from inputs.json
    let after = decode_block_file(&fs::read(data("revoke_kat/after_block.cbor.enc")).unwrap()).unwrap();
    // (a) revoked fingerprint absent, remaining present, exactly 1 recipient (+owner if applicable)
    assert!(!after.recipients.iter().any(|w| w.recipient_fingerprint == inputs.revoked_fp));
    assert!(after.recipients.iter().any(|w| w.recipient_fingerprint == inputs.remaining_fp));
    // (b) remaining recipient decrypts under the new BCK -> plaintext == inputs.expected_plaintext
    let pt = decrypt_block(&after, /* author + remaining-reader args from inputs */).unwrap();
    assert_eq!(pt.canonical_cbor_or_field_repr(), inputs.expected_plaintext);
    // (c) before_block had the revoked recipient; its AEAD body ct differs from after (re-key happened)
    let before = decode_block_file(&fs::read(data("revoke_kat/before_block.cbor.enc")).unwrap()).unwrap();
    assert!(before.recipients.iter().any(|w| w.recipient_fingerprint == inputs.revoked_fp));
    assert_ne!(before.aead_ct, after.aead_ct, "fresh BCK must change the body ciphertext");
}
```

Define `inputs.json`'s schema (mirror `golden_vault_001_inputs.json`): hex-encoded `remaining_x25519_sk`, `remaining_ml_kem_768_sk`, `remaining_pk_bundle`, `remaining_fp`, `revoked_fp`, `author_fp`, `author_pk_bundle`, `author_ed25519_pk`, `author_ml_dsa_65_pk`, and `expected_plaintext` (the canonical-CBOR hex of the `BlockPlaintext`). Read `golden_vault_001_inputs.json` first to match field conventions.

- [ ] **Step 2: Write the `#[ignore]` generator**

```rust
/// Regenerate core/tests/data/revoke_kat/ deterministically.
///   cargo test --release --workspace -- --ignored generate_revoke_kat --nocapture
/// Human-review the diff before commit (expected: the three revoke_kat files).
#[test]
#[ignore]
fn generate_revoke_kat() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]); // fixed seed -> deterministic
    // Build an owner vault, two recipients (remaining, revoked), save a block,
    // share to both -> write before_block.cbor.enc. Then revoke the "revoked"
    // recipient -> write after_block.cbor.enc. Serialize inputs.json with the
    // remaining recipient's keys + fingerprints + expected plaintext.
}
```

Use the seeded RNG so re-running is byte-stable. The generator reuses the Task 3 fixture helpers (factor them into a shared `mod` or copy).

- [ ] **Step 3: Generate the fixtures**

Run: `cargo test --release --workspace --test revoke_kat -- --ignored generate_revoke_kat --nocapture`
Expected: writes `core/tests/data/revoke_kat/{before_block.cbor.enc,after_block.cbor.enc,inputs.json}`.

- [ ] **Step 4: Run the replay guard against the generated fixtures**

Run: `cargo test --release --workspace --test revoke_kat revoke_kat_after_block_matches_inputs`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `cargo fmt --all -- --check && cargo clippy --release --workspace --tests -- -D warnings`

```bash
git add core/tests/revoke_kat.rs core/tests/data/revoke_kat/
git commit -m "test(core): revoke KAT fixture + deterministic generator

core/tests/data/revoke_kat/ holds a 2-recipient before-block, the after-block
post-revoke, and inputs.json (remaining recipient keys + fingerprints +
expected plaintext). The always-run replay guard asserts the revoked wrap is
gone, the remaining recipient decrypts under the new BCK, and the body
ciphertext changed (re-key). generate_revoke_kat (#[ignore]) regenerates it.

Refs #177.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: `conformance.py` revoke section + freshness registration

Prove the revoke re-key is verifiable from `docs/` alone, stdlib-only.

**Files:**
- Modify: `core/tests/python/conformance.py` (add a `section_revoke_kat()` and call it from `main`)
- Modify: `docs/vault-format.md` and/or `docs/crypto-design.md` (cite the new test names so `spec_test_name_freshness` tracks them)

- [ ] **Step 1: Add the conformance section**

In `conformance.py`, add (reusing the existing `parse_block_file`, `aead_decrypt`, `x25519_dh`, `ml_kem_768_decap`, `hkdf_sha256` helpers):

```python
def revoke_kat_dir() -> Path:
    here = Path(__file__).resolve()
    return here.parent / "data" / "revoke_kat"


def section_revoke_kat() -> tuple[bool, list[str]]:
    """Clean-room verification of the revoke re-key (vault-format.md §6.5).

    Loads core/tests/data/revoke_kat/, parses the after-block, and proves:
    (a) the revoked fingerprint is absent from the §6.2 recipient table and the
        remaining fingerprint is present;
    (b) the remaining recipient decaps + AEAD-decrypts the body under the NEW
        BCK to the expected plaintext;
    (c) the revoked party's old wrap is gone and the body ciphertext changed
        vs the before-block (a real re-key, not just a list edit).
    """
    lines: list[str] = []
    inputs = load_json_fixture(revoke_kat_dir() / "inputs.json", "revoke_kat/inputs.json")
    after = parse_block_file((revoke_kat_dir() / "after_block.cbor.enc").read_bytes())
    before = parse_block_file((revoke_kat_dir() / "before_block.cbor.enc").read_bytes())

    revoked_fp = bytes.fromhex(inputs["revoked_fp"])
    remaining_fp = bytes.fromhex(inputs["remaining_fp"])

    ok = True
    if any(r.recipient_fingerprint == revoked_fp for r in after.recipients):
        ok = False; lines.append("FAIL revoke_kat: revoked wrap still present")
    if not any(r.recipient_fingerprint == remaining_fp for r in after.recipients):
        ok = False; lines.append("FAIL revoke_kat: remaining wrap missing")
    if before.aead.ct == after.aead.ct:
        ok = False; lines.append("FAIL revoke_kat: body ciphertext unchanged (no re-key)")

    # (b) decap+decrypt the new BCK as the remaining recipient, then the body.
    # Mirror the golden-vault decrypt path: find the remaining recipient's wrap,
    # X25519+ML-KEM decap, HKDF the wrap key, AEAD-open the BCK, AEAD-open body.
    plaintext = decrypt_as_remaining(after, inputs)  # helper built from existing primitives
    if plaintext.hex() != inputs["expected_plaintext"]:
        ok = False; lines.append("FAIL revoke_kat: plaintext mismatch under new BCK")

    lines.append("PASS  revoke_kat::after_block_rekeyed" if ok else "FAIL  revoke_kat")
    return ok, lines
```

Wire `section_revoke_kat()` into `main()` alongside the existing section calls, folding its `ok` into the overall exit status. Implement `decrypt_as_remaining` from the existing `x25519_dh` / `ml_kem_768_decap` / `hkdf_sha256` / `aead_decrypt` helpers and the §7 wrap construction (mirror how the golden-vault path unwraps a recipient).

- [ ] **Step 2: Run conformance**

Run: `uv run core/tests/python/conformance.py`
Expected: PASS, including a `PASS  revoke_kat::after_block_rekeyed` line.

- [ ] **Step 3: Cite the test names in the spec so freshness tracks them**

In `docs/vault-format.md` §6.5 (the revocation subsection from Task 6), add a normative-test citation line, e.g.:

```markdown
> Conformance: `revoke_kat::after_block_rekeyed` (conformance.py) and
> `revoke_block_round_trip` / `revoke_block_non_recipient_rejected`
> (core/tests/revoke_block.rs) pin this behavior.
```

- [ ] **Step 4: Run the freshness checker**

Run: `uv run core/tests/python/spec_test_name_freshness.py`
Expected: PASS — the cited test names resolve to real tests. If it flags any, fix the citation (exact test-fn names) or add to the allowlist only if genuinely external.

- [ ] **Step 5: Full gauntlet**

Run:
```bash
cargo test --release --workspace && \
cargo clippy --release --workspace --tests -- -D warnings && \
cargo fmt --all -- --check && \
uv run core/tests/python/conformance.py && \
uv run core/tests/python/spec_test_name_freshness.py && \
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3 && \
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
```
Expected: all green; Swift 22/22, Kotlin 22/22 (the UDL variant regenerated bindings but added no new function — conformance counts unchanged).

- [ ] **Step 6: Commit**

```bash
git add core/tests/python/conformance.py docs/vault-format.md docs/crypto-design.md
git commit -m "test(conformance): clean-room revoke re-key verification

conformance.py section_revoke_kat parses the after-block, asserts the revoked
wrap is gone + the remaining recipient decrypts under the new BCK + the body
ciphertext changed (real re-key), all stdlib-only. Spec cites the new test
names so spec_test_name_freshness tracks them.

Refs #177.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final verification (after all tasks)

- [ ] Full automated gauntlet (the Task 8 Step 5 block) green.
- [ ] `git diff main..HEAD --stat` touches only: `core/src/vault/{orchestrators.rs,mod.rs}`, `core/tests/{revoke_block.rs,revoke_kat.rs}`, `core/tests/data/revoke_kat/`, `core/tests/python/conformance.py`, `ffi/secretary-ffi-bridge/src/{revoke/,contacts/,error/,lib.rs}`, `ffi/secretary-ffi-uniffi/src/secretary.udl`, `docs/{vault-format.md,crypto-design.md}`, and the spec/plan. **No desktop change.**
- [ ] Whole-branch security review (requesting-code-review skill) focused on: the `share_block` refactor preserved behavior (the byte/behavior guard); the "both halves sign / both halves wrap" property is implemented once in the helper and proven; the revoke mutation path swallows nothing; forward-secrecy documented.
- [ ] Update `README.md` / `ROADMAP.md`: mark D.1.10 ✅ (core revoke primitive), advance the "next" pointer to the D.1.11 revoke UI.
- [ ] Author the handoff `docs/handoffs/2026-06-04-d110-revoke-block-recipient-shipped.md` + retarget `NEXT_SESSION.md`.
