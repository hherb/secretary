# NEXT_SESSION.md — Vault crash-recovery-on-open (#350) ✅ SHIPPED (PR opening)

**Session dates:** 2026-07-02 → 2026-07-03. Shipped the larger of the two architectural deferrals from the 2026-07-02 pre-release audit (PR #371): [#350](https://github.com/hherb/secretary/issues/350) — a crash between a block-file op and its manifest write left the vault **unopenable** (`trash_block` residue → `Io(NotFound)`; `save_block`/re-key residue → `BlockFingerprintMismatch` → "corrupt vault"), and the spec's §6.5 recovery promise had no implementation. Worktree `.worktrees/vault-crash-recovery-350`, branch `feature/vault-crash-recovery-350` (cut from `main` @ `a5d1b04`). **Core + normative spec only — no byte-format, KAT, conformance, or FFI-surface change** (the two new `VaultError` variants fold to `CorruptVault` across the existing bridge mappers). FFI/app projection deferred to [#374](https://github.com/hherb/secretary/issues/374).

Also at session start: the #347 baton was retired (PR #372 confirmed merged; worktree + branch cleaned up), and the 20 audit issues fixed by merged PR #371 were closed with pointers (user-approved), leaving #350 + #353 as the open deferrals.

## (1) What we shipped this session

Built via **subagent-driven development** (fresh implementer + task reviewer per task; opus for the security-critical Task 6 review and the whole-branch review).

- **Typed errors** (`5334b0e`, `c039e30`): `VaultError::BlockFileMissing { block_uuid }` (replaces the anonymous `Io(NotFound)` in `verify_block_fingerprints`; closes the missing-file half of #88) and `VaultError::RepairRejected { block_uuid, detail }`; both added to all six bridge fold arms (→ `CorruptVault` / `SaveCryptoFailure`). One bridge integration test pin flipped (`FolderInvalid` → `CorruptVault` for a missing block file — semantically correct bucket).
- **Manifest-first `trash_block`** (`8bc95dc`, + FFI doc-comment fix `9500e52`): the signed-manifest write is the **commit point**; state is staged on clones (the previously-false "on Err, in-memory state untouched" doc contract is now true); the physical `blocks/ → trash/` rename is best-effort (crash/EXDEV/permissions degrade to a benign unlisted orphan; EXDEV no longer aborts).
- **Open-time trash-completion sweep** (`bfa23fe`): new `core/src/vault/repair.rs`; `complete_pending_trash_renames` relocates the orphan to its §7 trash path — rename-only, idempotent, gated on the *signed* `TrashEntry.fingerprint` + not-live + not-already-moved; runs in `open_vault` after manifest + fingerprint verification.
- **`repair_vault` orchestrator** (`b422954` extraction, `c430227`, security fix `b3ac55d`): same `unlock_vault_identity` + `read_and_verify_manifest` (incl. §10 rollback check) as `open_vault` — never a weaker open. Per mismatched block, all-or-nothing gated adoption: full hybrid verify (Ed25519 ∧ ML-DSA-65) under the owner card ∧ header `vault_uuid`/`block_uuid` binding ∧ **two-tier clock freshness** ∧ recipient resolution via self-verified cards. Healthy vault ⇒ plain open, zero writes (idempotent).
- **The Task-6 security story (important precedent):** the plan's strict-dominance-only clock gate proved wrong — re-keys (share/revoke) deliberately do NOT tick the block clock, so crashed revocations land as `Equal`. The implementer's interim fix (`Equal` + newer signed `last_mod_ms`) was **found exploitable by the opus task review** (empirically: backward-clock revoke + retained share bytes ⇒ revoked-recipient re-grant — `last_mod_ms` is caller wall-clock, no monotonicity). User-adjudicated replacement (`b3ac55d`): **Equal adopts only a strict-subset recipient reduction** — sound because equal clock ⇒ identical plaintext (re-keys re-encrypt unchanged plaintext; invariant now guard-commented at `rewrite_block_with_recipients` and normative in §6.5.1), so adoption can only narrow access. Crashed-**share** superset residue is a documented fail-closed limitation pending #374's informed-consent path. Timestamps decide nothing.
- **Tests** (`95a8c73` + per-task): `core/tests/crash_recovery.rs` (14 tests) + 2 in `trash_restore.rs` — crash simulations by state surgery, sweep gates, adoption happy paths (save + revocation), and the reject gates (rollback plant, concurrent transplant, backward-clock share replay, crashed-share superset, equal-set forgery, missing file, idempotence). Task 7's reviewer proved the four gate tests **non-vacuous by mutation**.
- **Spec** (`246e779`, `483bfc9`): vault-format.md §6.5 (typed repair contract, two-tier rule, all-or-nothing), §6.5.1 (widening re-key documented + **normative clock preservation**), §7 (manifest-first deletion + sweep), §9 (invariant: *never persist a manifest referencing block bytes not on disk*). Fixed a §8 mis-citation found in review.
- **Docs** (this commit): README audit-remediation row, ROADMAP Phase-A.7 entry, CLAUDE.md "Crash recovery" section (the equal-clock invariant), this handoff.

**Verification.** `cargo test --release --workspace` green (84 targets, 0 failures); clippy `-D warnings`, `cargo fmt`, `cargo doc -D warnings` clean; `conformance.py` PASS (no observable-format drift); `check-lean-binding.sh` clean; `spec_test_name_freshness.py` fails only on the 3 pre-existing #290 threat-model false-positives (identical on `main`). **Whole-branch opus review: Ready to merge = YES** — 0 Critical/Important; 2 informational Minors (device-secret-arm repair test → folded into #374; missing-file error precedence confirmed intentional).

### Branch commits (off `main` @ `a5d1b04`)
| SHA | What |
|---|---|
| `b44d3a2` / `1795bf5` | docs: design / implementation plan |
| `5334b0e` | feat — typed `BlockFileMissing` + `RepairRejected` + bridge fold sweep |
| `c039e30` | feat — `verify_block_fingerprints` types missing files (#88) |
| `8bc95dc` / `9500e52` | feat — manifest-first `trash_block` / stale FFI doc comments |
| `bfa23fe` | feat — `repair.rs` + open-time trash-completion sweep |
| `b422954` | refactor — extract `resolve_recipient_uuids` |
| `c430227` | feat — `repair_vault` orchestrator |
| `b3ac55d` | **fix — Equal-clock gate is subset-only (closed the review Critical)** |
| `4f9000e` / `1edc65b` | docs — design/plan amendments + citation reconcile |
| `95a8c73` | test — gate pins (rollback / concurrent / missing / idempotence) |
| `246e779` / `483bfc9` | docs(spec) — §6.5/§7/§9 + §6.5.1 widening-re-key fix |
| (+ this commit) | README + ROADMAP + CLAUDE.md + handoff + symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/vault-crash-recovery-350
cargo test --release --workspace                                  # 0 failures — GREEN
cargo test --release --workspace --test crash_recovery           # 14/14
cargo clippy --release --workspace --tests -- -D warnings        # clean
uv run core/tests/python/conformance.py                          # PASS
```

## (2) What's next
#350 is complete. Follow-ups, roughly in priority order:

1. **[#353](https://github.com/hherb/secretary/issues/353) desktop dialog path binding** — the LAST open audit deferral. Move dialog invocation into backend-mediated commands so path args bind to dialog-approved paths (new pick commands + approved-path state + `PathPicker` refactor + capability changes). Design-first; the issue comment carries the scoping (incl. the correction that share/import already route through the guarded bridge — the residual is create/probe/import path args, esp. the `probe_create_target` while-locked filesystem oracle).
2. **[#374](https://github.com/hherb/secretary/issues/374) FFI projection of `repair_vault` + platform "repair now?" UX** — bridge fn + typed-error surfacing (workspace exhaustive-match + Swift/Kotlin conformance-harness obligation), desktop reference UX, the informed-consent path for crashed-share superset residue, and a device-secret-arm repair test.
3. **iOS on-device Face ID acceptance (#284/#347)** — still pending the physical iPhone 13 Pro Max manual walkthrough (no code); should also spot-check the multi-vault case (button absent for un-enrolled vault B). If it passes, flip the "pending" note in README/ROADMAP.
4. **Carried Android items:** instrumented UI assertions for #341/#342 (optional); #338 on-device biometric cloud-open proof; #331 SAF picker on custom ROMs; #334 native cloud-provider epic (ADR + threat-model first).

## (3) Open decisions and risks
- **Crashed-share superset residue is fail-closed but unrepairable** until #374's informed-consent path: an interrupted in-place share leaves the vault failing open with `BlockFingerprintMismatch`, and `repair_vault` refuses (detail names the would-be-added recipients). Deliberate, user-approved trade-off — never auto-widen access. Documented in §6.5 + repair.rs.
- **The equal-clock ⇒ identical-plaintext invariant is load-bearing** for repair's Equal tier. Any future change making a clock-preserving path mutate plaintext MUST tick the block clock instead — guard comments at `rewrite_block_with_recipients`, normative in §6.5.1, CLAUDE.md section added. **Never reintroduce a wall-clock (`last_mod_ms`) freshness gate** — the exploit is documented in the Task-6 review history and pinned by `repair_rejects_backward_clock_share_replay`.
- **Post-review remediation (PR #375 review, 2026-07-03):** the review found the recipient-widening refusal was gated **Equal-only**, leaving the `IncomingDominates` arm able to re-grant a clock-invisible revoke via a planted owner-signed content-save (a dominating block carrying a pre-revocation recipient set). Fixed: the widening refusal is now **cross-cutting** (applies on every clock relation) — a legitimate crashed `save_block` never widens (it re-encrypts to the existing set), so no valid residue is rejected. Pinned by `repair_rejects_dominating_clock_recipient_widening` (proven non-vacuous by mutation). Also fixed: repair's recipient-resolution `MissingRecipientCard` now remaps to `RepairRejected` (keeps the outcome set `{RepairRejected, BlockFileMissing}`; environmental `Io` stays `Io`), and the adopted-entry `unknown`-map comment corrected. Spec §6.5/§6.5.1 + CLAUDE.md updated. Filed follow-ups: **[#376](https://github.com/hherb/secretary/issues/376)** (trash best-effort rename: lingering decryptable ciphertext + lost EXDEV signal), **[#377](https://github.com/hherb/secretary/issues/377)** (extract shared manifest re-sign+zeroize helper).
- **`spec_test_name_freshness.py` fails on `main` too** (3 pre-existing #290 threat-model false-positives). Not introduced here; #290 tracks it.
- **Retention purge (§7 step 5) remains unimplemented** — unchanged scope; the sweep keeps its future input well-formed.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/vault-crash-recovery-350 && \
#   git branch -D feature/vault-crash-recovery-350
git worktree list && git status -s
# Core acceptance: cargo test --release --workspace   (and --test crash_recovery for the #350 suite)
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/vault-crash-recovery-350` (15 commits + this docs/handoff commit). Worktree `.worktrees/vault-crash-recovery-350`. #350 resolved (PR carries `Fixes #350` so the issue closes on merge — #371's lesson).
- **Acceptance:** full workspace green; conformance PASS; opus whole-branch review "Ready to merge: YES" (0 Critical/Important; all security invariants source-verified; Task-6 Critical found, fixed, re-review CLOSED).
- **README / ROADMAP / CLAUDE.md:** updated (audit-remediation row; Phase-A.7 audit entry; crash-recovery invariant section).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-03-vault-crash-recovery-350-shipped.md`.
