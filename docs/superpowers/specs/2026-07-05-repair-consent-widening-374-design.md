# Informed-consent adoption of crashed-share widening residue (#374 part 3)

**Date:** 2026-07-05
**Issue:** [#374](https://github.com/hherb/secretary/issues/374) scope item 3 (final part; parts 1–2 shipped in PR #382, hardened in #386)
**Branch:** `feature/repair-consent-374` (worktree `.worktrees/repair-consent-374`, cut from `main` @ `d5edfdf`)
**Status:** approved design (brainstorm 2026-07-05); supersedes nothing — extends `docs/superpowers/specs/2026-07-02-vault-crash-recovery-350-design.md` and `2026-07-03-repair-vault-ffi-desktop-374-design.md`

## 1. Problem

`repair_vault` refuses to adopt any crash residue that would ADD a recipient, on every clock relation (Gate 3b, cross-cutting). That refusal is correct for every widening shape except one: the genuine residue of a crashed `share_block`. A share re-keys the block to the committed recipient set **plus** the new recipients and — like every re-key — preserves the block vector clock, so its residue lands as `Equal` clock ∧ strict recipient **superset**. Today that residue is a documented limitation (vault-format.md §6.5): the user's only recovery is to lose the share and redo it, and the rejection `detail` names the would-be-added recipients only as UUID strings.

Part 3 ships the explicit informed-consent adoption path: the user sees exactly *who* would gain access, in human-recognizable form, and can approve adoption of exactly *that* delta. The default remains fail-closed everywhere.

## 2. Goals and non-goals

**Goals**

- A `RepairPolicy`-gated core path that can adopt a consent-eligible widening, where consent is cryptographically bound to what the user was shown (TOCTOU-proof).
- A read-only preview surface returning the widening delta with resolved contact display names + card fingerprints, suitable for a consent dialog.
- Desktop reference consent UX (preview → dialog → approved repair).
- Zero new `FfiVaultError` variants; zero change to the on-disk format; §10 (#384) and all-or-nothing contracts unchanged.

**Non-goals**

- Mobile consent UX (the uniffi surface ships; iOS/Android dialogs are follow-up work — `:kit`/`:app` and both conformance harnesses must merely keep compiling/passing).
- Partial adoption (approve some widened blocks, repair the rest) — ruled out in brainstorm; all-or-nothing stands.
- Any relaxation for widening shapes other than the crashed-share residue (see §4).

## 3. Core surface (`core/src/vault/repair.rs`)

### 3.1 New types

```rust
pub enum RepairPolicy {
    /// Default: any recipient widening refuses the repair (today's behavior).
    FailClosed,
    /// Adopt widenings that match an approval EXACTLY; everything else still refuses.
    AdoptApproved(Vec<ApprovedWidening>),
}

pub struct ApprovedWidening {
    pub block_uuid: [u8; 16],
    /// BLAKE3 fingerprint of the on-disk block file the user was shown —
    /// binds consent to the exact previewed bytes.
    pub file_fingerprint: [u8; 32],
    /// The exact added-recipient set (contact UUIDs) the user approved.
    pub added_recipients: BTreeSet<[u8; 16]>,
}
```

`repair_vault` gains a trailing `policy: RepairPolicy` parameter. All existing callers (bridge arms, tests) pass `RepairPolicy::FailClosed`.

### 3.2 Consent-eligible shape — deliberately minimal

An approval can license **only** the crashed-`share_block` residue shape:

> clock relation `Equal` ∧ on-disk recipient set is a **strict superset** of the committed set (adds ≥ 1, removes 0).

Everything else keeps today's unconditional refusal even under `AdoptApproved`:

| Shape | Disposition | Why |
|---|---|---|
| `IncomingDominates` + any added recipient | refused, always | planted owner-signed content-save carrying a pre-revocation set (the #350 review exploit); a real share preserves the clock, so its residue can never dominate |
| `Equal` + mixed delta (adds AND removes) | refused, always | no single crashed operation produces it (a share re-keys from the committed table); stale-replay shape |
| `Equal` + equal set, different bytes | refused, always | unchanged (forgery shape) |
| `IncomingDominated` / `Concurrent` | refused, always | unchanged (rollback plant / torn multi-device state) |
| unresolvable added recipient card | refused, always | unchanged Gate 3 (cannot render a name for an unknown card → nothing to consent to) |

### 3.3 Gate 3b under `AdoptApproved`

Order is load-bearing: the **shape check precedes the approval lookup**. Only after establishing `Equal` ∧ strict superset does the gate consult approvals:

1. Find the approval with matching `block_uuid`. None → `RepairRejected` (detail: consent required, names the delta as today).
2. Require `approval.file_fingerprint == got` (the manifest-mismatch fingerprint of the on-disk file) **and** `approval.added_recipients == added` (exact set equality — not subset, not superset). Any mismatch → `RepairRejected` (detail: stale consent — the disk changed after preview; re-preview).
3. Match → adopt. The rebuilt `BlockEntry` follows the existing adoption path verbatim (recipients from the on-disk §6.2 table, `vector_clock_summary` verbatim, `last_mod_ms` from the file header, committed `unknown` map carried forward).

All other gates run unchanged and **before** Gate 3b: §1 unlock + verify-before-decrypt, the §10 pre-write fail-closed gate (#384 — including its provider fail-closed contract), hybrid verify ∧ header binding, clock-relation sanity, recipient resolution. **All-or-nothing is preserved**: one unapproved or mismatched widening refuses the whole repair before anything is staged or written.

### 3.4 Read-only preview

```rust
pub struct RepairPreview {
    /// Consent-eligible widenings. Empty ⇒ a FailClosed repair will succeed
    /// (or the vault is already healthy).
    pub widenings: Vec<WideningReport>,
}
pub struct WideningReport {
    pub block_uuid: [u8; 16],
    pub block_name: String,             // from the decrypted on-disk block
    pub file_fingerprint: [u8; 32],     // feed back verbatim into ApprovedWidening
    pub added: Vec<AddedRecipient>,
}
pub struct AddedRecipient {
    pub uuid: [u8; 16],
    pub display_name: String,           // from the resolved contact card
    pub card_fingerprint: [u8; 32],     // fingerprint(card canonical CBOR)
}
```

`preview_repair(folder, unlocker, load_baseline, ...) -> Result<RepairPreview, VaultError>` runs the identical unlock + §1 sequence and per-block gates but **writes nothing**:

- Consent-eligible widenings are collected into the report instead of erroring.
- Hard-refused shapes (every row of the §3.2 table except the eligible one) still propagate as `RepairRejected` — repair can never succeed there, so there is nothing to consent to and the app shows the failure detail as today.
- Healthy / plainly-adoptable blocks contribute nothing to the report.
- §10 posture: preview evaluates the rollback check through the same `load_baseline` closure and `ensure_not_rollback` call as `repair_vault` — the posture lives in the *provider* (#384). The bridge passes the same fail-closed `baseline_provider` to both, so a broken §10 baseline store surfaces at **preview** time, before any consent dialog, rather than after the user has approved. This is deliberately the mutating posture, not `open_vault`'s skip posture: preview's sole purpose is to precede a mutating repair, and failing closed earlier is never weaker. The mutating `repair_vault` call keeps the #384 pre-write fail-closed gate unconditionally.

**Single source of gate truth:** Pass-1 per-block classification is factored into one shared helper returning a classification (adopt / consent-eligible-widening / reject-with-detail). `repair_vault` consumes it honoring `policy`; `preview_repair` consumes it collecting reports. The gate logic must not be duplicated. If `repair.rs` approaches the 500-line threshold as a result, split into a `repair/` directory module (classification, preview, orchestration) rather than growing one file.

## 4. Threat reasoning (recorded normatively, vault-format.md §9)

- **What changes for an attacker:** planted owner-signed re-key bytes carrying a superset previously produced a refusal; now they can at most produce a **consent dialog**. The dialog is therefore part of the security boundary: it renders identities (display name + card fingerprint), defaults to Cancel, and consent binds to exact bytes. A user who does not recognize the recipients cancels and is exactly where they are today.
- **What consent can never do:** resurrect a recipient invisibly (the delta renders exhaustively); adopt bytes other than those previewed (fingerprint binding — a swap between dialog and click is refused as stale consent); license a dominating plant or any non-eligible shape (shape check precedes approval lookup); weaken §10 (the pre-write gate runs before Gate 3b); widen beyond the approved set (exact set equality).
- **Approval replay:** an approval is only ever constructed by the caller from a fresh preview and only matches while the on-disk file still has the previewed fingerprint. Approvals are not persisted anywhere by core, the bridge, or the desktop app; they live for one preview→repair round-trip in memory.
- **Residual risk, stated honestly:** a user can be socially engineered into clicking Grant. That is irreducible in any informed-consent design; the mitigation is the dialog's explicitness (who gains access, alarming copy, Cancel as default), not a mechanism.

## 5. FFI bridge (`ffi/secretary-ffi-bridge/src/repair/`)

- The three arms `repair_vault_with_{password,recovery,device_secret}` gain `approvals: Vec<FfiApprovedWidening>`. Mapping: **empty → `RepairPolicy::FailClosed`**, non-empty → `AdoptApproved`. The zero value is the safe direction — forgetting approvals can only fail closed. All three keep the #384 `baseline_provider` unchanged.
- Three new arms `preview_repair_with_{password,recovery,device_secret}` return `FfiRepairPreview` (`block_uuid_hex`, `block_name`, `file_fingerprint_hex`, per-recipient `{uuid_hex, display_name, card_fingerprint_hex}`). Preview arms pass the same fail-closed `baseline_provider` as the mutating arms (§3.4).
- **Zero new `FfiVaultError` variants.** Consent-missing/stale surfaces through the existing `RepairRejected { block_uuid_hex, detail }`; preview returns data, not errors. (Avoids the workspace-wide exhaustive-match + Swift/Kotlin `ConformanceErrors` obligation.)
- Bridge fns take fixed-size byte arrays (`[u8; 16]` / `[u8; 32]`) inside `FfiApprovedWidening`; hex parsing/length validation lives at the binding wrappers per the established rule (bridge trusts its caller).

## 6. Bindings (uniffi + pyo3)

- New records on both bindings: `ApprovedWidening`, `RepairPreview`, `WideningReport`, `AddedRecipient` — UUIDs/fingerprints as hex strings at the binding layer, validated (length + hex) in the wrapper, surfacing the existing `InvalidArgument` before the bridge is touched.
- pyo3 records follow the `from_py_object` / `skip_from_py_object` discipline (input records need `from_py_object`; output-only records skip it).
- Known ripple obligations, scheduled in-plan (not discovered late): run **both** `ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/run_conformance.sh`; build Android `:kit` **and** `:app` in the same task; `cargo`/clippy cannot see those breakages.

## 7. Desktop reference UX (Tauri backend + `Unlock.svelte`)

Backend: the existing `repair_vault` command gains an approvals argument (empty array = today's behavior); new `preview_repair` command. Both classified in `writeCommands.ts` (`repair_vault` stays a write command; `preview_repair` classified per the #280 coverage test's taxonomy — the test forces the decision).

Frontend flow (restructures "Repair now" from call-repair-directly to preview-then-repair):

1. Unlock fails `vault_needs_repair` → existing "This vault has an interrupted write. Repair now?" affordance, unchanged.
2. "Repair now" click → `preview_repair` (reusing the retained password with the existing cleared-password guard).
   - Preview error (hard shape, wrong password, …) → shown as today's failure detail; no dialog.
   - `widenings` empty → immediately `repair_vault` with no approvals (common case: crashed save/revoke — one click, UX identical to today).
   - `widenings` non-empty → consent dialog.
3. **Consent dialog** — alarming, not routine. Per widened block: block name, then each recipient who would **gain access** as display name + card fingerprint (short-form hex, rendered as the contacts UI renders fingerprints). Copy: *"An interrupted share was found. Adopting this repair will give these contacts access to this block. If you don't recognize this, choose Cancel — the vault stays unchanged."* Buttons: **Cancel** (default/focused) and **Grant access and repair** (explicit consequence). One Grant covers everything shown — no per-block checkboxes (all-or-nothing; if unsure about any line, Cancel).
4. Approve → `repair_vault` with approvals built **verbatim** from the preview's `file_fingerprint` + added sets — the frontend never recomputes or edits the delta. Disk changed in between → core refuses (stale consent) → detail surfaces, state returns to locked; re-clicking "Repair now" re-previews fresh.
5. Cancel → dialog closes; vault locked and untouched; affordance remains.

## 8. Spec updates (normative)

- **vault-format.md** (§9 repair paragraph + §6.5/§6.5.1 cross-references): replace "documented limitation … until an explicit informed-consent adoption path exists" with the normative consent contract — eligible shape exactly `Equal` ∧ strict superset; MUST-refuse for every other widening shape regardless of consent; consent MUST bind to the on-disk file fingerprint and the exact added set shown to the user, any mismatch MUST refuse; default MUST be fail-closed; all-or-nothing and the §10 pre-write gate unchanged. Append the new conformance test citations.
- **crypto-design.md §10:** one sentence — the repair *preview* shares the mutating path's fail-closed baseline posture (it exists only to precede a mutating repair); the mutating adopt keeps the pre-write fail-closed gate. No contract change.
- Doc changes land together with the code change per the "spec is normative" discipline; `conformance.py` is unaffected (no byte-format or merge-semantics change) but the citation-freshness expectations of `spec_test_name_freshness.py` apply to the new test names.

## 9. Testing (TDD, RED first)

**Core (`core/tests/crash_recovery.rs`):**

- `repair_adopts_crashed_share_with_matching_approval` — staged crashed-share superset + exact approval → adopted entry carries the widened set, clock verbatim; vault opens clean afterwards.
- `repair_rejects_approval_with_stale_fingerprint` — approval carries a different `file_fingerprint` → refused, manifest bytes unchanged.
- `repair_rejects_approval_with_wrong_added_set` — subset/superset/disjoint approved sets all refused (exact equality required).
- `repair_approval_does_not_license_dominating_widening` — planted dominating content-save + matching-looking approval → still refused.
- `repair_approval_does_not_license_mixed_delta` — Equal-clock add+remove residue + approval → still refused.
- `repair_all_or_nothing_with_partial_approvals` — two widened blocks, one approval → whole repair refused, manifest bytes byte-identical.
- `preview_reports_widening_with_names_and_fingerprints` — report contains block name, file fingerprint, and resolved display name + card fingerprint per added recipient; manifest bytes unchanged (read-only).
- `preview_propagates_hard_rejections` — rollback-plant residue → preview errs `RepairRejected`.
- Existing FailClosed tests unchanged (regression: default behavior identical).

**Bridge:** per-arm (password / recovery / device-secret) approved-adopt happy path; stale-fingerprint refusal surfaces as `RepairRejected`; preview projection includes display names; §10 fail-closed regression (garbage state file) still refuses with approvals present.

**Bindings / desktop:** wrapper hex/length validation → `InvalidArgument`; Swift + Kotlin conformance harnesses recompile against the new records and stay green (extending the KAT itself is not in scope — no observable-output change to existing entries); `:kit` + `:app` Gradle builds; desktop vitest covering the four flow paths (empty-widenings, consent-approve, stale-consent, cancel); `writeCommands.ts` classification; `pnpm svelte-check`.

**Gates (all, from the worktree):** `cargo fmt --all --check`; `cargo clippy --release --workspace --tests -- -D warnings`; `cargo test --release --workspace`; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`; `uv run core/tests/python/conformance.py`; both `run_conformance.sh`; lean-binding guard; `cd desktop && pnpm test && pnpm svelte-check`.

## 10. Acceptance criteria

1. A staged crashed-share residue is adoptable end-to-end on desktop: unlock → "Repair now?" → consent dialog showing the added recipients by name + fingerprint → Grant → vault opens with the widened recipient set committed.
2. With no approvals (or Cancel), behavior is byte-for-byte today's: refusal naming the delta, nothing written.
3. No approval can adopt: a dominating widening, a mixed delta, a swapped file (stale fingerprint), or a different added set than shown.
4. §10 (#384) fail-closed posture and the provider contract are untouched; the whole gate battery in §9 is green.
