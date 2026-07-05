# Informed-Consent Widening Adoption (#374 part 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the informed-consent adoption path for crashed-`share_block` widening residue: a `RepairPolicy`-gated core path with delta-bound approvals, a read-only preview surface (names + fingerprints), FFI projection on all three unlock arms, and the desktop reference consent UX. Default stays fail-closed everywhere.

**Architecture:** Two-phase, delta-bound consent per the approved spec (`docs/superpowers/specs/2026-07-05-repair-consent-widening-374-design.md`): `preview_repair` (read-only) reports consent-eligible widenings; `repair_vault` gains `RepairPolicy` where an `ApprovedWidening` must match the on-disk file fingerprint AND the exact added-recipient set. Consent-eligible shape is exactly `Equal` clock ∧ strict superset; everything else keeps unconditional refusal. Per-block gate logic is extracted once (`classify_block`) and consumed by both repair and preview.

**Tech Stack:** Rust (stable, `--release`), uniffi 0.31 + pyo3 bindings, Tauri 2 + Svelte 5 desktop, vitest.

## Global Constraints

- Worktree: ALL commands run from `/Users/hherb/src/secretary/.worktrees/repair-consent-374` (branch `feature/repair-consent-374`). Bash cwd persists between calls but `cd` explicitly in every compound command. Edit/Write/Read tool paths MUST spell out `/Users/hherb/src/secretary/.worktrees/repair-consent-374/...` — a bare `/Users/hherb/src/secretary/...` path silently edits the MAIN checkout.
- `cargo test --release --workspace` (crypto crates too slow in debug); clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`; rustdoc: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`.
- `#![forbid(unsafe_code)]` workspace-wide. No new dependencies.
- Python: `uv` only (never pip).
- Zero new `FfiVaultError` variants (spec §5). Zero on-disk format change.
- Test crypto values: generate at runtime (OsRng / seeded ChaCha20Rng), never literal secret byte arrays (CodeQL); fixture seeds like `[0x66; 32]` for ChaCha20Rng follow the existing crash_recovery.rs pattern and are fine.
- Desktop: `pnpm` (never npm); run `pnpm svelte-check` after any `.svelte` attribute edit.
- Files heading past ~500 lines get split (Task 1 does this for `repair.rs` up front).
- Commit messages end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Split `core/src/vault/repair.rs` into a directory module (mechanical, zero behavior change)

`repair.rs` is 449 lines; Tasks 2–4 add ~250 more. Split first so later diffs land in focused files.

**Files:**
- Create: `core/src/vault/repair/mod.rs`, `core/src/vault/repair/sweep.rs`, `core/src/vault/repair/orchestration.rs`
- Delete: `core/src/vault/repair.rs` (contents move verbatim)

**Interfaces:**
- Produces: unchanged public surface — `crate::vault::repair_vault` and `pub(crate) complete_pending_trash_renames` resolve exactly as before via `mod.rs` re-exports. `core/src/vault/mod.rs:32,57` (`mod repair;` / `pub use repair::repair_vault;`) needs NO edit.

- [ ] **Step 1: Create the directory module**

`core/src/vault/repair/mod.rs` — move the module doc comment (repair.rs lines 1–7) here, then:

```rust
mod orchestration;
mod sweep;

pub use orchestration::repair_vault;
pub(crate) use sweep::complete_pending_trash_renames;
```

- [ ] **Step 2: Move code verbatim**

- `sweep.rs`: `complete_pending_trash_renames` (repair.rs lines 32–81) plus exactly the imports it needs (`std::path::Path`, `blake3_hash`, `format_uuid_hyphenated`, `Manifest`, `BLOCKS_SUBDIR`, `BLOCK_FILE_EXTENSION`, `TRASH_SUBDIR`).
- `orchestration.rs`: everything else (the `repair_vault` doc comment + fn, lines 83–449) plus its imports. Inside the subdirectory, `use super::block;`-style paths become `use crate::vault::block;` etc. (one level deeper); `use super::sweep::complete_pending_trash_renames;` for the sweep call at the two call sites (lines 411, 441).
- Check the one external caller of the sweep: `grep -n "complete_pending_trash_renames" core/src/vault/orchestrators.rs` — its `super::repair::complete_pending_trash_renames` path is unchanged by the re-export.

- [ ] **Step 3: Verify zero behavior change**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-consent-374 && cargo test --release -p secretary-core --test crash_recovery && cargo clippy --release --workspace --tests -- -D warnings && cargo fmt --all --check`
Expected: all pass, no new warnings.

- [ ] **Step 4: Commit**

```bash
git add -A core/src/vault && git commit -m "refactor(core): split repair.rs into repair/ directory module (no behavior change)"
```

---

### Task 2: Core `RepairPolicy` + consent arm in Gate 3b (RED first)

**Files:**
- Create: `core/src/vault/repair/policy.rs` (the two new types)
- Modify: `core/src/vault/repair/mod.rs` (declare + re-export), `core/src/vault/repair/orchestration.rs` (signature + Gate 3b), `core/src/vault/mod.rs` (re-export types)
- Modify (mechanical callers, same commit — the workspace won't compile otherwise): `ffi/secretary-ffi-bridge/src/repair/orchestration.rs` (3 arms pass `RepairPolicy::FailClosed`), every `repair_vault(` call in `core/tests/crash_recovery.rs` (append `RepairPolicy::FailClosed` — note the param order below)
- Test: `core/tests/crash_recovery.rs`

**Interfaces:**
- Produces: `pub enum RepairPolicy { FailClosed, AdoptApproved(Vec<ApprovedWidening>) }`; `pub struct ApprovedWidening { pub block_uuid: [u8; 16], pub file_fingerprint: [u8; 32], pub added_recipients: BTreeSet<[u8; 16]> }`; new signature `repair_vault(folder, unlocker, load_baseline, device_uuid, now_ms, rng, policy: RepairPolicy)` (policy LAST). Re-exported from `crate::vault`.

- [ ] **Step 1: Write the failing tests** (append to `core/tests/crash_recovery.rs`; staging copied from `repair_rejects_crashed_share_superset` at line 888 — same save→snapshot-manifest→share→restore-manifest sequence)

```rust
/// Shared stager: a crashed-share superset residue (block on disk is
/// {owner, C}, committed manifest says {owner}). Returns everything a
/// consent test needs. Mirrors repair_rejects_crashed_share_superset.
fn stage_crashed_share(
    seed: u8,
) -> (
    tempfile::TempDir,
    SecretBytes,        // password
    [u8; 16],           // device_uuid
    [u8; 16],           // block_uuid
    [u8; 16],           // C's contact_uuid (the added recipient)
    [u8; 32],           // on-disk file fingerprint (blake3 of block bytes)
    Vec<u8>,            // pre-repair manifest bytes
) {
    let (dir, _mnemonic, pw) = make_fast_vault(seed, "Owner");
    let folder = dir.path().to_path_buf();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let mut open = open_vault(&folder, Unlocker::Password(&pw), None).unwrap();
    let (device_uuid, block_uuid) = ([0xde; 16], [0xbe; 16]);

    let mut rng_c = ChaCha20Rng::from_seed([seed.wrapping_add(1); 32]);
    let id_c = secretary_core::unlock::bundle::generate("Cee", 1_714_060_800_000, &mut rng_c);
    let card_c = make_signed_card(&id_c);
    let c_uuid = card_c.contact_uuid;

    let recipients = vec![open.owner_card.clone()];
    save_block(&folder, &mut open, make_simple_plaintext(block_uuid, "mine"),
        &recipients, device_uuid, 1_000, &mut rng).unwrap();
    let manifest_pre_share = fs::read(folder.join("manifest.cbor.enc")).unwrap();

    let author_card = open.owner_card.clone();
    let author_sk_ed: secretary_core::crypto::sig::Ed25519Secret =
        secretary_core::crypto::secret::Sensitive::new(*open.identity.ed25519_sk.expose());
    let author_sk_pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    share_block(&folder, &mut open, secretary_core::vault::BlockUuid::new(block_uuid),
        &author_card, &author_sk_ed, &author_sk_pq, &recipients, &card_c,
        secretary_core::vault::DeviceUuid::new(device_uuid), 2_000, &mut rng).unwrap();
    drop(open);
    fs::write(folder.join("manifest.cbor.enc"), &manifest_pre_share).unwrap();

    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_bytes = fs::read(folder.join("blocks").join(format!("{uuid_hex}.cbor.enc"))).unwrap();
    let file_fp = *blake3::hash(&block_bytes).as_bytes();
    (dir, pw, device_uuid, block_uuid, c_uuid, file_fp, manifest_pre_share)
}

#[test]
fn repair_adopts_crashed_share_with_matching_approval() {
    let (dir, pw, device_uuid, block_uuid, c_uuid, file_fp, _) = stage_crashed_share(0x90);
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
    let approval = secretary_core::vault::ApprovedWidening {
        block_uuid,
        file_fingerprint: file_fp,
        added_recipients: [c_uuid].into_iter().collect(),
    };
    let open = secretary_core::vault::repair_vault(
        folder, Unlocker::Password(&pw), |_| Ok(None), device_uuid, 3_000, &mut rng,
        secretary_core::vault::RepairPolicy::AdoptApproved(vec![approval]),
    )
    .expect("exact approval must adopt the crashed-share superset");
    let entry = open.manifest.blocks.iter().find(|b| b.block_uuid == block_uuid).unwrap();
    assert_eq!(entry.recipients.len(), 2, "widened set committed");
    assert!(entry.recipients.contains(&c_uuid));
    drop(open);
    // Vault opens clean afterwards (residue fully adopted).
    open_vault(folder, Unlocker::Password(&pw), None).expect("post-repair open must succeed");
}

#[test]
fn repair_rejects_approval_with_stale_fingerprint() {
    let (dir, pw, device_uuid, block_uuid, c_uuid, mut file_fp, manifest_before) =
        stage_crashed_share(0x92);
    let folder = dir.path();
    let mut rng = ChaCha20Rng::from_seed([0x93; 32]);
    file_fp[0] ^= 0x01; // consent bound to different bytes than on disk
    let approval = secretary_core::vault::ApprovedWidening {
        block_uuid, file_fingerprint: file_fp,
        added_recipients: [c_uuid].into_iter().collect(),
    };
    let err = secretary_core::vault::repair_vault(
        folder, Unlocker::Password(&pw), |_| Ok(None), device_uuid, 3_000, &mut rng,
        secretary_core::vault::RepairPolicy::AdoptApproved(vec![approval]),
    )
    .expect_err("stale consent must refuse");
    assert!(matches!(&err, VaultError::RepairRejected { block_uuid: b, .. } if *b == block_uuid));
    assert!(err.to_string().contains("consent"), "detail names the consent mismatch: {err}");
    // Nothing written.
    assert_eq!(fs::read(folder.join("manifest.cbor.enc")).unwrap(), manifest_before);
}

#[test]
fn repair_rejects_approval_with_wrong_added_set() {
    // Three wrong shapes: empty set, superset-of-actual, disjoint. Exact
    // equality is required — subset/superset of the real delta all refuse.
    let (dir, pw, device_uuid, block_uuid, c_uuid, file_fp, manifest_before) =
        stage_crashed_share(0x94);
    let folder = dir.path();
    for wrong in [
        std::collections::BTreeSet::new(),
        [c_uuid, [0x11; 16]].into_iter().collect(),
        [[0x22; 16]].into_iter().collect::<std::collections::BTreeSet<_>>(),
    ] {
        let mut rng = ChaCha20Rng::from_seed([0x95; 32]);
        let approval = secretary_core::vault::ApprovedWidening {
            block_uuid, file_fingerprint: file_fp, added_recipients: wrong,
        };
        let err = secretary_core::vault::repair_vault(
            folder, Unlocker::Password(&pw), |_| Ok(None), device_uuid, 3_000, &mut rng,
            secretary_core::vault::RepairPolicy::AdoptApproved(vec![approval]),
        )
        .expect_err("non-exact added set must refuse");
        assert!(matches!(&err, VaultError::RepairRejected { .. }), "got {err:?}");
        assert_eq!(fs::read(folder.join("manifest.cbor.enc")).unwrap(), manifest_before);
    }
}
```

- [ ] **Step 2: Run to verify RED**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-consent-374 && cargo test --release -p secretary-core --test crash_recovery repair_adopts_crashed_share 2>&1 | tail -20`
Expected: compile FAILURE (`RepairPolicy` / `ApprovedWidening` not found; `repair_vault` takes 6 args). That is the RED state for a signature change.

- [ ] **Step 3: Implement**

`core/src/vault/repair/policy.rs`:

```rust
//! Consent policy for the repair path (#374 part 3). The default is
//! fail-closed; `AdoptApproved` licenses ONLY the crashed-share shape
//! (`Equal` clock ∧ strict superset) and only where the approval matches
//! the on-disk file fingerprint AND the exact added-recipient set —
//! consent is bound to exactly what the user was shown (spec §3.1–3.3).

use std::collections::BTreeSet;

/// How `repair_vault` treats a consent-eligible recipient widening.
#[derive(Debug, Clone)]
pub enum RepairPolicy {
    /// Any recipient widening refuses the repair (pre-#374-part-3 behavior).
    FailClosed,
    /// Adopt a widening ONLY if it matches one of these approvals exactly;
    /// any mismatch (or any non-consent-eligible widening shape) still
    /// refuses. An empty vec behaves like `FailClosed`.
    AdoptApproved(Vec<ApprovedWidening>),
}

/// One user-approved widening, bound to exactly what the preview showed.
#[derive(Debug, Clone)]
pub struct ApprovedWidening {
    /// The block whose widening the user approved.
    pub block_uuid: [u8; 16],
    /// BLAKE3-256 of the on-disk block file the user was shown. A file
    /// swapped between preview and repair fails this bind (stale consent).
    pub file_fingerprint: [u8; 32],
    /// The exact added-recipient set (contact UUIDs) the user approved.
    /// Compared with set equality — never subset/superset.
    pub added_recipients: BTreeSet<[u8; 16]>,
}
```

`repair/mod.rs`: add `mod policy;` + `pub use policy::{ApprovedWidening, RepairPolicy};`. `core/src/vault/mod.rs`: extend the repair re-export line to `pub use repair::{repair_vault, ApprovedWidening, RepairPolicy};`.

`orchestration.rs` — add `policy: RepairPolicy` as the LAST parameter of `repair_vault` (7 params total — at clippy's `too_many_arguments` limit, not over it). Replace the Gate 3b block (the `if !added.is_empty()` refusal, currently orchestration.rs near the `added: Vec<String>` construction) with:

```rust
        let on_disk: BTreeSet<[u8; 16]> = recipients.iter().copied().collect();
        let committed: BTreeSet<[u8; 16]> = entry.recipients.iter().copied().collect();
        let added: BTreeSet<[u8; 16]> = on_disk.difference(&committed).copied().collect();
        if !added.is_empty() {
            let added_hex: Vec<String> = added.iter().map(format_uuid_hyphenated).collect();
            // Consent-eligible = the crashed-share residue shape and ONLY
            // that shape: Equal clock ∧ pure adds (strict superset). A
            // dominating widening is the planted-content-save re-grant
            // exploit; a mixed add+remove delta is no single crashed op.
            // Neither is EVER licensed by an approval — the shape check
            // deliberately precedes the approval lookup (spec §3.3).
            let removed_any = committed.difference(&on_disk).next().is_some();
            let consent_eligible = matches!(relation, ClockRelation::Equal) && !removed_any;
            let approval = match (&policy, consent_eligible) {
                (RepairPolicy::AdoptApproved(approvals), true) => {
                    approvals.iter().find(|a| a.block_uuid == entry.block_uuid)
                }
                _ => None,
            };
            match approval {
                // Exact bind: the previewed bytes AND the previewed delta.
                Some(a) if a.file_fingerprint == got && a.added_recipients == added => {
                    // consented crashed-share adoption — fall through
                }
                Some(_) => {
                    return Err(VaultError::RepairRejected {
                        block_uuid: entry.block_uuid,
                        detail: format!(
                            "approval does not match the on-disk residue (stale \
                             consent — the block file or recipient delta changed \
                             after preview; re-run the preview): residue would ADD \
                             recipients {{{}}}",
                            added_hex.join(", ")
                        ),
                    });
                }
                None => {
                    return Err(VaultError::RepairRejected {
                        block_uuid: entry.block_uuid,
                        detail: format!(
                            "re-key residue would ADD recipients {{{}}}: refusing \
                             automatic adoption; adopting requires explicit consent \
                             (preview_repair + RepairPolicy::AdoptApproved){}",
                            added_hex.join(", "),
                            if consent_eligible { "" } else {
                                " — and this residue is not the crashed-share shape, \
                                 so it is never adoptable"
                            }
                        ),
                    });
                }
            }
        }
```

Keep the equal-clock/equal-set-different-bytes refusal AFTER this block unchanged. Update the `repair_vault` doc comment's Equal-tier paragraph: the crashed-share consequence sentence now describes the consent path (was "NOT auto-adopted — a documented limitation until an informed-consent adoption path ships"; becomes: not auto-adopted; adoptable only via `RepairPolicy::AdoptApproved` with a preview-bound approval).

Mechanical caller updates (same commit): the 3 bridge arms append `secretary_core::vault::RepairPolicy::FailClosed` (import it); every existing `repair_vault(` call in `crash_recovery.rs` appends `RepairPolicy::FailClosed` (add to the existing `secretary_core::vault::{...}` import list). Check whether `repair_rejects_crashed_share_superset` / `repair_rejects_dominating_clock_recipient_widening` assert on the old "explicit consent path not yet implemented" text and update those assertions to the new wording.

- [ ] **Step 4: Verify GREEN**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-consent-374 && cargo test --release --workspace 2>&1 | grep -E "test result|FAILED" | tail -10 && cargo clippy --release --workspace --tests -- -D warnings && cargo fmt --all`
Expected: 0 failures (new tests pass, all regressions green), clippy clean.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): RepairPolicy::AdoptApproved — delta-bound consent adoption of crashed-share widening (#374)"
```

---

### Task 3: Core adversarial shape-guard pinning tests

These pin that an approval can NEVER license a non-eligible shape and that all-or-nothing survives partial approvals. They should pass immediately after Task 2 (the shape check precedes the approval lookup) — they exist to FAIL if anyone ever reorders the gate. Verify each runs green; if any fails, Task 2's gate order is wrong — fix that, not the test.

**Files:**
- Test: `core/tests/crash_recovery.rs`

**Interfaces:**
- Consumes: `stage_crashed_share` (Task 2), staging patterns from `repair_rejects_dominating_clock_recipient_widening` (line ~1092) and `repair_rejects_stale_equal_clock_replay` (line ~642).

- [ ] **Step 1: Write the tests**

```rust
#[test]
fn repair_approval_does_not_license_dominating_widening() {
    // Reuse repair_rejects_dominating_clock_recipient_widening's staging
    // verbatim (planted owner-signed content-save whose clock dominates,
    // carrying a widened recipient set), then attempt repair with an
    // approval matching that residue's block/fingerprint/delta exactly.
    // Copy the staging body from that test (line ~1092) up to the point
    // where it calls repair_vault; compute file_fp + added uuid the same
    // way stage_crashed_share does. Then:
    let approval = secretary_core::vault::ApprovedWidening {
        block_uuid, file_fingerprint: file_fp,
        added_recipients: [revoked_uuid].into_iter().collect(),
    };
    let err = secretary_core::vault::repair_vault(
        folder, Unlocker::Password(&pw), |_| Ok(None), device_uuid, 9_000, &mut rng,
        secretary_core::vault::RepairPolicy::AdoptApproved(vec![approval]),
    )
    .expect_err("a dominating widening is a plant shape — no approval may license it");
    assert!(matches!(&err, VaultError::RepairRejected { .. }));
    assert_eq!(fs::read(folder.join("manifest.cbor.enc")).unwrap(), manifest_before);
}

#[test]
fn repair_all_or_nothing_with_partial_approvals() {
    // Two blocks, both with crashed-share residue; approval only for the
    // first. Whole repair must refuse; manifest byte-identical. Stage by
    // extending stage_crashed_share's pattern to two blocks in one vault
    // (two save_block + snapshot + two share_block + restore snapshot),
    // then approve only block A. Assert RepairRejected names block B and
    // the manifest bytes are unchanged. Then approve BOTH and assert Ok —
    // proving the refusal was the missing consent, not the staging.
}
```

Write `repair_all_or_nothing_with_partial_approvals` in full (the comment above describes the staging; the assertions mirror Task 2's tests). Also add the mixed-delta guard: stage per `repair_rejects_stale_equal_clock_replay`'s equal-clock replay pattern where the on-disk set both adds and removes relative to committed (share C then revoke owner→ no; simplest staging: save with {owner, B}, snapshot manifest, revoke B and share C via two re-keys, restore snapshot — on-disk is {owner, C} vs committed {owner, B}: adds C, removes B, Equal clock) and assert refusal even with an exactly-matching approval for {C}.

```rust
#[test]
fn repair_approval_does_not_license_mixed_delta() { /* staging above; expect RepairRejected + manifest unchanged */ }
```

- [ ] **Step 2: Run — expect immediate GREEN (pinning tests)**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-consent-374 && cargo test --release -p secretary-core --test crash_recovery repair_approval -- --nocapture && cargo test --release -p secretary-core --test crash_recovery repair_all_or_nothing`
Expected: PASS. (A failure here means Task 2's shape-check-before-approval order is broken.)

- [ ] **Step 3: Commit**

```bash
git add core/tests/crash_recovery.rs && git commit -m "test(core): pin consent cannot license dominating/mixed widenings; all-or-nothing under partial approvals (#374)"
```

---

### Task 4: Core `preview_repair` + single-source classification

**Files:**
- Create: `core/src/vault/repair/classify.rs`
- Modify: `core/src/vault/repair/orchestration.rs` (consume classifier; add `preview_repair`), `core/src/vault/repair/mod.rs`, `core/src/vault/mod.rs` (re-exports), `core/src/vault/orchestrators.rs` (extract `scan_verified_contact_cards`)
- Test: `core/tests/crash_recovery.rs`

**Interfaces:**
- Produces:
  - `pub struct RepairPreview { pub widenings: Vec<WideningReport> }`
  - `pub struct WideningReport { pub block_uuid: [u8; 16], pub block_name: String, pub file_fingerprint: [u8; 32], pub added: Vec<AddedRecipient> }`
  - `pub struct AddedRecipient { pub uuid: [u8; 16], pub display_name: String, pub card_fingerprint: [u8; 16] }` — NOTE: 16 bytes, the identity `fingerprint()` used as `recipient_fingerprint` in §6.2 wraps (the spec doc says 32; Task 11 amends the spec).
  - `pub fn preview_repair(folder: &Path, unlocker: Unlocker<'_>, load_baseline: impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError>) -> Result<RepairPreview, VaultError>`
  - `pub(crate) enum BlockClassification { Healthy, Adopt(BlockEntry), ConsentEligibleWidening { staged: BlockEntry, added: BTreeSet<[u8; 16]>, file_fingerprint: [u8; 32], block_name: String } }` and `pub(crate) fn classify_block(...) -> Result<BlockClassification, VaultError>` in `classify.rs`.
  - In `orchestrators.rs`: `pub(crate) fn scan_verified_contact_cards(folder: &Path) -> Result<Vec<ContactCard>, VaultError>` — extracted verbatim from `resolve_recipient_uuids`'s read_dir + parse + `verify_self` + continue-past loop (line ~2183–2230), consumed by both `resolve_recipient_uuids` and the preview's name lookup. Existing share/revoke/repair tests keep the extraction honest.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn preview_reports_widening_with_names_and_fingerprints() {
    let (dir, pw, _device_uuid, block_uuid, c_uuid, file_fp, manifest_before) =
        stage_crashed_share(0x96);
    let folder = dir.path();
    let preview =
        secretary_core::vault::preview_repair(folder, Unlocker::Password(&pw), |_| Ok(None))
            .expect("preview of a consent-eligible residue succeeds");
    assert_eq!(preview.widenings.len(), 1);
    let w = &preview.widenings[0];
    assert_eq!(w.block_uuid, block_uuid);
    assert_eq!(w.block_name, "mine");
    assert_eq!(w.file_fingerprint, file_fp);
    assert_eq!(w.added.len(), 1);
    assert_eq!(w.added[0].uuid, c_uuid);
    assert_eq!(w.added[0].display_name, "Cee");
    // card_fingerprint = identity fingerprint of C's card (16 bytes).
    // Recompute from the staged card to pin it: fingerprint(&card_c.to_canonical_cbor()?)
    // — return card_c from stage_crashed_share (extend its tuple) or re-mint
    // id_c deterministically from the same seed and re-derive.
    // Read-only: manifest bytes untouched.
    assert_eq!(fs::read(folder.join("manifest.cbor.enc")).unwrap(), manifest_before);
}

#[test]
fn preview_is_empty_for_plainly_adoptable_residue() {
    // stage_crashed_save (existing helper, line 188) → preview returns
    // zero widenings (an interrupted save adopts without consent).
}

#[test]
fn preview_propagates_hard_rejections() {
    // Rollback-plant staging from repair_vault_rejects_rollback_plant
    // (line ~1236) → preview_repair returns Err(RepairRejected) — there
    // is nothing to consent to on an unrepairable vault.
}
```

Write all three in full (the comments name the staging source to copy). Extend `stage_crashed_share` to also return `card_c`'s 16-byte fingerprint so the first test can assert `w.added[0].card_fingerprint` exactly.

- [ ] **Step 2: Run to verify RED**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-consent-374 && cargo test --release -p secretary-core --test crash_recovery preview_ 2>&1 | tail -5`
Expected: compile failure (`preview_repair` not found).

- [ ] **Step 3: Implement**

1. Extract `scan_verified_contact_cards` in `orchestrators.rs`; rewrite `resolve_recipient_uuids` to consume it (identical observable behavior: build the fp→uuid map from the returned cards; keep the owner-card fast path and the `needs_scan` guard).
2. `classify.rs`: move the per-block gate body (everything from `let bytes = std::fs::read(...)` through the widening/equal-set checks and `BlockEntry` construction) out of `repair_vault`'s loop into `classify_block`. Owner key material travels in a small context struct built once per repair/preview run:

```rust
pub(crate) struct OwnerVerifyCtx<'a> {
    pub owner_card: &'a ContactCard,
    pub owner_fp: [u8; 16],
    pub owner_pk_bundle: Vec<u8>,
    pub owner_pq_pk: MlDsa65Public,
    pub owner_x_sk: kem::X25519Secret,
    pub owner_pq_sk_reader: MlKem768Secret,
}

pub(crate) fn classify_block(
    folder: &Path,
    blocks_dir: &Path,
    vault_uuid: [u8; 16],
    entry: &BlockEntry,
    ctx: &OwnerVerifyCtx<'_>,
) -> Result<BlockClassification, VaultError>
```

Behavior is a pure move of Task 2's logic MINUS the policy decision: `Healthy` for fingerprint match; every existing hard rejection returns `Err` unchanged (including non-eligible widenings — dominating widening and mixed delta reject INSIDE classify with the Task 2 "never adoptable" detail); the eligible widening returns `ConsentEligibleWidening { staged, added, file_fingerprint: got, block_name }` where `staged` is the fully-built adopted-shape `BlockEntry` (recipients = on-disk set). The plain adoptable path returns `Adopt(entry)`.
3. `repair_vault`'s loop becomes: `Healthy` → continue; `Adopt(e)` → push; `ConsentEligibleWidening { .. }` → the Task 2 approval match (exact fingerprint + set) → push staged or the two `RepairRejected` arms. (The "stale consent" / "explicit consent required" details stay in orchestration — they are policy wording, not classification.)
4. `preview_repair` in `orchestration.rs`: same unlock + `read_and_verify_manifest` + `load_baseline(&manifest.vault_uuid)?` + `ensure_not_rollback` sequence as `repair_vault` (fail-closed §10 posture lives in the provider — same rationale comment as the repair path, citing spec §3.4), then builds the same `OwnerVerifyCtx`, loops `classify_block`, collects `ConsentEligibleWidening` arms into `WideningReport`s. Name lookup: `scan_verified_contact_cards(folder)` once, build `uuid → (display_name, fingerprint(&card.to_canonical_cbor()?))`; a missing added uuid → `RepairRejected` (defensive; Gate 3 resolution normally guarantees presence). Writes nothing; drops the unlocked identity (ZeroizeOnDrop cleans up).
5. Re-exports: `repair/mod.rs` gains `mod classify;` + `pub use classify::{AddedRecipient, RepairPreview, WideningReport};` (types can live in classify.rs) + `pub use orchestration::preview_repair;`; `vault/mod.rs` re-export line extends accordingly.

- [ ] **Step 4: Verify GREEN + full core regression**

Run: `cd /Users/hherb/src/secretary/.worktrees/repair-consent-374 && cargo test --release --workspace 2>&1 | grep -E "test result|FAILED" | tail -10 && cargo clippy --release --workspace --tests -- -D warnings && cargo fmt --all && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -3`
Expected: 0 failures; clippy + rustdoc clean.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): preview_repair + single-source block classification (#374)"
```

---

### Task 5: Bridge — approvals on the three repair arms

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/repair/types.rs` (`FfiApprovedWidening`)
- Modify: `ffi/secretary-ffi-bridge/src/repair/orchestration.rs` (3 arms + `_in` seams gain `approvals: &[FfiApprovedWidening]`), `ffi/secretary-ffi-bridge/src/repair/mod.rs`, `ffi/secretary-ffi-bridge/src/lib.rs` (re-export)
- Modify (mechanical callers, same commit): `ffi/secretary-ffi-uniffi/src/namespace/repair.rs` and `ffi/secretary-ffi-py/src/repair.rs` (pass `&[]` for now — their public APIs grow in Tasks 7–8), `desktop/src-tauri/src/session.rs::repair` (pass `&[]` for now — approvals plumb through in Task 9)
- Test: `ffi/secretary-ffi-bridge/src/repair/tests.rs`

**Interfaces:**
- Produces: `pub struct FfiApprovedWidening { pub block_uuid: [u8; 16], pub file_fingerprint: [u8; 32], pub added_recipients: Vec<[u8; 16]> }` (Vec at the FFI seam; the arm converts to `BTreeSet` when building `RepairPolicy`). New signatures: `repair_vault_with_password(folder, password, device_uuid, now_ms, approvals: &[FfiApprovedWidening])` (and recovery / device-secret alike).
- Consumes: `RepairPolicy` / `ApprovedWidening` from `secretary_core::vault`.

- [ ] **Step 1: Write the failing bridge tests** (in `repair/tests.rs`, reusing its existing vault-staging helpers — read the file's helper section first and mirror how the existing per-arm adoption tests stage residue; add a crashed-share stager mirroring core's `stage_crashed_share` using bridge-visible APIs, or stage via `secretary_core` directly as the existing bridge tests do)

Four tests: `repair_with_password_adopts_with_exact_approval` (approval built from on-disk blake3 + added uuid → Ok, manifest advanced, reopen clean), `repair_with_recovery_adopts_with_exact_approval` (same through the mnemonic arm — the staging helper returns the vault's mnemonic), `repair_with_device_secret_adopts_with_exact_approval` (same through the device-secret arm — enroll a slot first via the pattern the existing device-arm test uses), `repair_refuses_stale_approval_as_repair_rejected` (flipped fingerprint byte → `FfiVaultError::RepairRejected` with `detail` containing "consent", manifest bytes unchanged). Plus one §10 regression: the existing garbage-state-file test gains a variant passing a valid approval — fail-closed §10 must still win (`CorruptVault` before any consent logic).

- [ ] **Step 2: RED** — `cargo test --release -p secretary-ffi-bridge 2>&1 | tail -5` → compile failure (no `approvals` param / no `FfiApprovedWidening`).

- [ ] **Step 3: Implement**

`types.rs` as in Interfaces (with doc comments: Vec-not-set at the seam; length-validated arrays are the BINDING layer's job — the bridge trusts its caller per the established rule). Each `_in` seam builds the policy:

```rust
    let policy = if approvals.is_empty() {
        RepairPolicy::FailClosed
    } else {
        RepairPolicy::AdoptApproved(
            approvals.iter().map(|a| ApprovedWidening {
                block_uuid: a.block_uuid,
                file_fingerprint: a.file_fingerprint,
                added_recipients: a.added_recipients.iter().copied().collect(),
            }).collect(),
        )
    };
```

and passes `policy` as `repair_vault`'s last arg (replacing Task 2's hardcoded `FailClosed`). Empty→FailClosed is the documented safe-zero-value (doc comment on the param). Mechanical callers pass `&[]`.

- [ ] **Step 4: GREEN** — `cargo test --release --workspace 2>&1 | grep -E "test result|FAILED" | tail -8 && cargo clippy --release --workspace --tests -- -D warnings`

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(bridge): approvals parameter on the three repair arms (#374)"`

---

### Task 6: Bridge — preview arms

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/repair/preview.rs`
- Modify: `ffi/secretary-ffi-bridge/src/repair/mod.rs`, `ffi/secretary-ffi-bridge/src/lib.rs` (re-exports)
- Test: `ffi/secretary-ffi-bridge/src/repair/tests.rs`

**Interfaces:**
- Produces (display-oriented hex output, mirroring the `FfiVaultError` hex convention):

```rust
pub struct FfiRepairPreview { pub widenings: Vec<FfiWideningReport> }
pub struct FfiWideningReport {
    pub block_uuid_hex: String,        // lowercase hyphenated UUID
    pub block_name: String,
    pub file_fingerprint_hex: String,  // 64 lowercase hex chars
    pub added: Vec<FfiAddedRecipient>,
}
pub struct FfiAddedRecipient {
    pub uuid_hex: String,              // lowercase hyphenated UUID
    pub display_name: String,
    pub card_fingerprint_hex: String,  // 32 lowercase hex chars (16-byte identity fingerprint)
}
pub fn preview_repair_with_password(folder: &Path, password: &[u8]) -> Result<FfiRepairPreview, FfiVaultError>
pub fn preview_repair_with_recovery(folder: &Path, mnemonic_bytes: &[u8]) -> Result<FfiRepairPreview, FfiVaultError>
pub fn preview_repair_with_device_secret(folder: &Path, device_uuid: &[u8; 16], device_secret: &[u8; 32]) -> Result<FfiRepairPreview, FfiVaultError>
```

Each has a `pub(crate) ..._in(state_dir, ...)` seam and passes the SAME `baseline_provider(state_dir)` as the repair arms (spec §3.4: fail-closed §10 surfaces at preview time, before any dialog). Hex helpers: reuse the crate's existing uuid-hyphenation helper (grep `format_uuid_hyphenated` / the helper the error conversion uses at `error/vault/mod.rs:537`); plain-hex via the same mechanism the crate already formats fingerprints with (grep `hex` in the bridge; if none exists, a 6-line local `fn to_hex(bytes: &[u8]) -> String` with a unit test — no new dependency).

- [ ] **Step 1: RED tests** — `preview_with_password_reports_widening` (staged crashed share → one report; assert block name, 64-char fingerprint hex round-trips to the on-disk blake3, display_name "Cee", uuid hex matches; manifest bytes unchanged), `preview_with_password_empty_for_crashed_save` (zero widenings), `preview_fails_closed_on_garbage_baseline_state` (reuse the §10 garbage-file staging → `CorruptVault` naming the state file).
- [ ] **Step 2: RED run** — compile failure.
- [ ] **Step 3: Implement** per Interfaces (unlock arm mapping identical to the repair arms: password → `Unlocker::Password`, recovery → UTF-8 check then `Unlocker::Recovery`, device-secret → `Unlocker::DeviceSecret`).
- [ ] **Step 4: GREEN** — workspace test + clippy as in Task 5.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(bridge): preview_repair arms with names + fingerprints (#374)"`

---

### Task 7: uniffi projection + conformance + Android builds

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (repair section at lines ~289–297 + new dictionaries next to the existing ones ~485+), `ffi/secretary-ffi-uniffi/src/namespace/repair.rs`, `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (32-byte helper), `ffi/secretary-ffi-uniffi/src/lib.rs` (exports)

**Interfaces:**
- Produces (UDL):

```
dictionary ApprovedWidening { bytes block_uuid; bytes file_fingerprint; sequence<bytes> added_recipients; };
dictionary AddedRecipient { string uuid_hex; string display_name; string card_fingerprint_hex; };
dictionary WideningReport { string block_uuid_hex; string block_name; string file_fingerprint_hex; sequence<AddedRecipient> added; };
dictionary RepairPreview { sequence<WideningReport> widenings; };
```

plus `sequence<ApprovedWidening> approvals` appended to all three `repair_with_*` fns and three new `RepairPreview preview_repair_with_*` fns (password: `bytes folder_path, bytes password`; recovery: `bytes folder_path, bytes mnemonic`; device-secret: `bytes folder_path, bytes device_uuid, bytes device_secret`).

- [ ] **Step 1:** UDL edits + Rust wrappers. Validation at the wrapper per the established rule: every `bytes` field of every `ApprovedWidening` is length-checked BEFORE the bridge call — `uuid_from_vec` (existing, `namespace/mod.rs`) for 16-byte fields; add `array32_from_vec` beside it mirroring `uuid_from_vec` exactly but for `[u8; 32]`, returning the same `VaultError::InvalidArgument` shape with the field name in the detail. Wrapper structs mirror the UDL dictionaries (uniffi 0.31 derives from the UDL; follow how `ContactSummary` is wired). Zeroize discipline for password/mnemonic identical to the existing `repair_with_password` wrapper (validate approvals FIRST, before the fallible chain, zeroizing the credential on the early-return arm — same pattern as the existing `uuid_from_vec` early return). Preview wrappers mirror `open_*` counterparts minus device/now params.
- [ ] **Step 2:** `cargo test --release --workspace` + clippy → green (uniffi scaffolding tests compile the UDL).
- [ ] **Step 3:** Conformance harnesses (compile the regenerated Swift/Kotlin bindings — cargo CANNOT see breakage there): `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh && bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` → 27/27 each. No harness edits expected (nothing in `ffi/secretary-ffi-uniffi/tests/` references repair — verified during planning); if either fails to compile, fix the harness in this task, not later.
- [ ] **Step 4:** Android builds in the SAME task (`:kit` maps repair errors; signature changes are additive for it, but prove it): `cd android && ./gradlew :kit:build :app:assembleDebug 2>&1 | tail -5` → BUILD SUCCESSFUL. (iOS SecretaryKit does not call the repair fns — additive API changes cannot break its compile; the heavy xcframework build is deliberately skipped here.)
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(uniffi): approvals + preview_repair projection (#374)"`

---

### Task 8: pyo3 projection + pytest

**Files:**
- Modify: `ffi/secretary-ffi-py/src/repair.rs`, `ffi/secretary-ffi-py/src/lib.rs` (register new classes/fns)
- Test: `ffi/secretary-ffi-py/tests/test_repair.py`

**Interfaces:**
- Produces (Python): `repair_with_password(folder_path, password, device_uuid, now_ms, approvals=None)` (same for recovery / device_secret; `approvals: Optional[list[ApprovedWidening]]`, `None`/`[]` → fail-closed); `preview_repair_with_password(folder_path, password) -> RepairPreview`; classes `ApprovedWidening` (input: `#[new]` constructor taking `block_uuid: Vec<u8>, file_fingerprint: Vec<u8>, added_recipients: Vec<Vec<u8>>`, length-validated in the constructor → `ValueError`, following the input-record discipline in `save.rs` — check its `from_py_object`/`skip_from_py_object` usage and mirror it), `RepairPreview` / `WideningReport` / `AddedRecipient` (output-only: `#[pyclass(get_all)]` String/list fields, `From<secretary_ffi_bridge::Ffi...>` impls like `contacts.rs::ContactSummary`; remember `get_all` does not combine with `from_py_object` — output records skip it).

- [ ] **Step 1:** RED — extend `test_repair.py`: a crashed-share fixture (stage via the Python API the file already uses for staging residue — read its existing fixture first), then: refusal without approvals mentions "consent"; `preview_repair_with_password` returns the widening with `display_name`; passing the preview-derived approval adopts; a wrong-length `block_uuid` in `ApprovedWidening` raises `ValueError`. Run per the maturin/uv discipline the other py tests use (check `ffi/secretary-ffi-py/README` or how CI invokes them; if the venv shows stale symbols, nuke venv + uv cache per the known maturin/uv stickiness).
- [ ] **Step 2:** Implement per Interfaces.
- [ ] **Step 3:** GREEN — py tests + `cargo clippy --release --workspace --tests -- -D warnings` (pyo3 0.28 deprecation discipline).
- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(py): approvals + preview_repair projection (#374)"`

---

### Task 9: Desktop backend — preview command + approvals plumbing

**Files:**
- Create: `desktop/src-tauri/src/dtos/repair.rs` (`RepairPreviewDto`, `WideningReportDto`, `AddedRecipientDto`, `ApprovedWideningArg` — serde `rename_all = "camelCase"` like the other dtos)
- Modify: `desktop/src-tauri/src/commands/repair.rs` (new `preview_repair` command + `repair_vault` gains `approvals: Vec<ApprovedWideningArg>`), `desktop/src-tauri/src/session.rs` (`repair` gains approvals; new `preview` method that does NOT populate the session), `desktop/src-tauri/src/main.rs` (register `repair::preview_repair`), `desktop/src-tauri/src/dtos/mod.rs`
- Modify (frontend seam): `desktop/src/lib/ipc.ts` (`previewRepair` + `repairVault` third arg + DTO interfaces), `desktop/src/lib/writeCommands.ts`
- Test: command-level Rust tests in `commands/repair.rs` `#[cfg(test)]` (gate rejection for preview, hex validation), `desktop/tests/writeCommands.test.ts` (coverage test forces the classification)

**Interfaces:**
- Produces: `ApprovedWideningArg { block_uuid_hex: String, file_fingerprint_hex: String, added_uuids_hex: Vec<String> }` → converted in `commands/repair.rs` to `FfiApprovedWidening` (hex-decode + length checks → `AppError::InvalidArgument` on failure — decode helper local to the command module, unit-tested); `previewRepair(folderPath, password): Promise<RepairPreviewDto>`; `repairVault(folderPath, password, approvals: ApprovedWideningDto[])`.
- `preview_repair` command: same `PathPurpose::VaultFolder` approval gate + `validate_vault_path` + `AlreadyUnlocked` guard as `repair_vault_impl`; calls `secretary_ffi_bridge::preview_repair_with_password`; returns the DTO (hex strings pass through from the bridge verbatim — no reformatting).
- `writeCommands.ts`: `preview_repair: { kind: 'write', gate: 'exempt', wrapper: 'previewRepair', reason: 'pre-unlock read-only consent preview invoked from the locked Unlock screen (mirrors repair_vault) — takes the vault password directly, performs no vault mutation' }` (precedent: `pick_export_dir` is write/exempt with a no-mutation reason).

- [ ] **Step 1:** RED — `cd desktop && pnpm test -- writeCommands` fails once `preview_repair` is registered in `generate_handler!` without classification (the #280 coverage test); Rust command tests for the approval gate + a `repair_vault` hex-validation test (`"zz"` fingerprint → `InvalidArgument`).
- [ ] **Step 2:** Implement per Interfaces. `session.repair` passes the converted approvals slice to the bridge (replacing Task 5's `&[]`); `session.preview` mirrors `repair`'s vault-uuid/device-uuid-free shape (preview needs neither) — it only guards `AlreadyUnlocked` and calls the bridge.
- [ ] **Step 3:** GREEN — `cargo test --release -p secretary-desktop 2>&1 | tail -5` (or the desktop crate's actual name from its Cargo.toml) + `cd desktop && pnpm test 2>&1 | tail -5`.
- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(desktop): preview_repair command + approvals plumbing (#374)"`

---

### Task 10: Desktop consent dialog + Unlock flow

**Files:**
- Create: `desktop/src/components/RepairConsentDialog.svelte`, `desktop/tests/RepairConsentDialog.test.ts`
- Modify: `desktop/src/routes/Unlock.svelte` (`confirmRepair` becomes preview-then-repair), `desktop/src/theme.css` (dialog styles — component `<style>` blocks trip the Vite-6 preprocessCSS bug under Vitest), `desktop/tests/Unlock.test.ts`

**Interfaces:**
- Consumes: `previewRepair` / `repairVault` from Task 9.
- `RepairConsentDialog` props: `{ widenings: WideningReportDto[], onCancel: () => void, onGrant: () => void }`. Renders per widened block: block name, then each added recipient as `display_name` + card fingerprint hex grouped in 4s (e.g. `a1b2 c3d4 …` — a tiny exported `groupHex(hex: string): string` helper in the component module or `lib/`, unit-tested). Copy (verbatim from spec §7): title "An interrupted share was found."; body "Adopting this repair will give these contacts access to this block. If you don't recognize this, choose Cancel — the vault stays unchanged."; buttons Cancel (default-focused, `autofocus`) and "Grant access and repair". One Grant covers all listed widenings; no per-block checkboxes.

- [ ] **Step 1:** RED — vitest first:
  - `RepairConsentDialog.test.ts`: renders block name + display names + grouped fingerprint; Cancel button has initial focus; clicking Grant/Cancel fires the callbacks.
  - `Unlock.test.ts` additions (existing hoisted-mock pattern; add `previewMock` to the `vi.hoisted` block and the `vi.mock` factory; remember `mockRejectedValueOnce`, never persistent `mockRejectedValue`): (a) empty-widenings path: preview resolves `{ widenings: [] }` → `repairVault` called once with `[]` approvals — flow identical to today; (b) consent path: preview resolves one widening → dialog rendered with "Cee" → Grant → `repairVault` called with approvals built verbatim from the preview (assert exact arg); (c) cancel path: Cancel → `repairVault` NOT called, back to locked with the repair affordance still rendered; (d) stale-consent path: `repairVault` rejects `{ code: 'repair_rejected', detail: '...consent...' }` → detail shown, state locked.
- [ ] **Step 2:** Implement `confirmRepair` restructure: capture `const priorError = $sessionState.lastError` (the `vault_needs_repair` error) before `beginUnlock()`; `previewRepair(folderPath, password)`; empty → `repairVault(folderPath, password, [])` (rest of the flow unchanged); non-empty → set `consentWidenings = preview.widenings` (dialog renders while session state is `unlocking`; `repairing` keeps the block mounted); Grant → `repairVault(folderPath, password, consentWidenings.map(w => ({ blockUuidHex: w.blockUuidHex, fileFingerprintHex: w.fileFingerprintHex, addedUuidsHex: w.added.map(a => a.uuidHex) })))` — built verbatim from the preview, never recomputed; Cancel → `unlockFailed(priorError)` (returns to locked + affordance), clear `consentWidenings`, KEEP the password bound (the affordance stays usable; it clears on any terminal outcome as today). Preview/ repair errors → `unlockFailed(err)` as today.
- [ ] **Step 3:** GREEN — `cd desktop && pnpm test 2>&1 | tail -5 && pnpm svelte-check 2>&1 | tail -3` (svelte-check mandatory: .svelte attribute edits + smart-quote risk).
- [ ] **Step 4: Commit** — `git add -A && git commit -m "feat(desktop): repair consent dialog — preview-then-repair flow (#374)"`

---

### Task 11: Normative docs + spec amendment

**Files:**
- Modify: `docs/vault-format.md` (§9 repair paragraph, line ~436; §6.5.1 cross-reference, line ~444), `docs/crypto-design.md` (§10, line ~468), `docs/superpowers/specs/2026-07-05-repair-consent-widening-374-design.md` (16-byte card-fingerprint amendment)

- [ ] **Step 1:** vault-format.md §9 — inside the existing repair paragraph, replace the sentence fragment "that residue is a documented limitation, not auto-repairable, until an explicit informed-consent adoption path exists" with the normative consent contract (MUST-level, one flowing addition to the same paragraph): the crashed-share residue (`Equal` clock ∧ strict recipient superset — adds only, no removals) MAY be adopted **only** through an explicit informed-consent path in which the client first runs a read-only preview that renders, for every recipient who would gain access, a human-recognizable identity (display name and card fingerprint from the verified contact card); consent MUST be bound to both the BLAKE3-256 fingerprint of the exact on-disk block file previewed and the exact added-recipient set shown, and any mismatch at adoption time MUST refuse; every other widening shape (a dominating clock with any added recipient, an equal-clock mixed add/remove delta) MUST be refused regardless of consent; absent an exactly-matching approval the default MUST remain the fail-closed refusal; the all-or-nothing rule and the §10 pre-write fail-closed gate apply unchanged, and the preview MUST apply the same fail-closed §10 baseline posture as the mutating repair. Append to the paragraph's conformance citation list: `repair_adopts_crashed_share_with_matching_approval` / `repair_rejects_approval_with_stale_fingerprint` / `repair_rejects_approval_with_wrong_added_set` / `repair_approval_does_not_license_dominating_widening` / `repair_approval_does_not_license_mixed_delta` / `repair_all_or_nothing_with_partial_approvals` / `preview_reports_widening_with_names_and_fingerprints` / `preview_propagates_hard_rejections` (exact Rust test names — the freshness checker resolves them against `core/`).
- [ ] **Step 2:** vault-format.md §6.5.1 — update its "documented limitation" cross-reference sentence to point at the §9 consent contract instead of calling it non-adoptable.
- [ ] **Step 3:** crypto-design.md §10 (line ~468) — append one sentence after the fail-closed MUST: "A read-only *preview* of such a rewriting operation (enumerating what a subsequent repair would need consent for) SHOULD apply the same fail-closed posture, so an unusable baseline surfaces before the user is asked to approve anything."
- [ ] **Step 4:** Spec amendment: in the design doc's §3.4, change `card_fingerprint: [u8; 32]` to `[u8; 16]` with a parenthetical "(identity `fingerprint()` output — the same 16-byte value §6.2 wraps use as `recipient_fingerprint`)"; same for the §5 hex-length mention (32 hex chars).
- [ ] **Step 5:** Verify citations resolve: `cd /Users/hherb/src/secretary/.worktrees/repair-consent-374 && uv run core/tests/python/spec_test_name_freshness.py; echo "exit=$?"` — expected: the 3 pre-existing threat-model.md L234 false-positives (#290, pre-existing on main) and NOTHING new. Any new flag = a typo in a cited test name; fix it.
- [ ] **Step 6:** `uv run core/tests/python/conformance.py` — PASS (no byte-format change; this is a regression guard).
- [ ] **Step 7: Commit** — `git add docs && git commit -m "docs: normative consent-adoption contract for crashed-share residue (#374)"`

---

### Task 12: Full gate battery

- [ ] **Step 1:** From the worktree (verify `pwd` FIRST — Bash cwd drifts between parallel sessions):

```bash
cd /Users/hherb/src/secretary/.worktrees/repair-consent-374 && pwd && git branch --show-current
cargo fmt --all --check
cargo clippy --release --workspace --tests -- -D warnings
cargo test --release --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
cd desktop && pnpm test && pnpm svelte-check
```

Expected: everything green (conformance 27/27 each; desktop suite fully passing; svelte-check 0 errors).

- [ ] **Step 2:** Fix anything red (one issue per commit), re-run the affected gate.
- [ ] **Step 3:** No commit if all green (this task produces no changes on success).

---

## Self-review notes (spec → plan)

- Spec §3.1–3.3 → Tasks 2–3; §3.4 → Task 4; §5 → Tasks 5–6; §6 → Tasks 7–8; §7 → Tasks 9–10; §8 → Task 11; §9 gates → per-task steps + Task 12. Acceptance §10.1 (end-to-end desktop) is covered by Task 10's vitest flow tests; the *manual* GUI smoke (native app, human click) stays a post-merge baton item as with Slice A.
- Type consistency: `ApprovedWidening.added_recipients: BTreeSet<[u8;16]>` (core) ↔ `Vec<[u8;16]>` (bridge seam) ↔ `sequence<bytes>` (UDL) ↔ `addedUuidsHex: string[]` (desktop) — conversions specified at each seam. `card_fingerprint` is 16 bytes everywhere (spec amended in Task 11).
- Known-risk callouts for implementers: gate ORDER (shape check before approval lookup) is security-load-bearing — Task 3 pins it; preview/repair share `classify_block` — do not fork the gate logic; `writeCommands.ts` coverage test will fail the build if the new command is unclassified (that is the mechanism working, not a flake).
