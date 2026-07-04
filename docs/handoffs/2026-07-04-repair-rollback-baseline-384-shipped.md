# NEXT_SESSION.md — repair_vault §10 baseline hardening (#384) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-04 (afternoon; same-day follow-up to the #374 Slice A session). Shipped **[#384](https://github.com/hherb/secretary/issues/384)** — closed the two latent asymmetries the #382 review found in the repair-time §10 rollback gate. Worktree `.worktrees/repair-baseline-384`, branch `feature/repair-baseline-384` (cut from `main` @ `fc8a53a`). Built via brainstorm → spec → plan → subagent-driven development (fresh implementer + reviewer per task; opus whole-branch review at the end: **0 Critical / 0 Important**, 3 editorial items fixed).

## (1) What we shipped this session

Two changes to how the mutating repair path enforces §10 rollback resistance, with **zero new error variants** and zero binding-surface change:

- **Verified-uuid keying** (`1623223` core+bridge, `d2365e3` desktop comment): core `repair_vault` no longer takes a pre-loaded `local_highest_clock` — it takes a **baseline-provider closure** (`impl FnOnce(&[u8; 16]) -> Result<Option<Vec<VectorClockEntry>>, VaultError>`) and invokes it with the **verified** `manifest.vault_uuid` (post hybrid-verify + AEAD decrypt + body-vs-header cross-check), strictly **pre-write** (before Pass-1 classification), running `is_rollback` itself on the committed clock. The bridge's `load_rollback_baseline` (plaintext `vault.toml` keying + reliance on the unlock AAD as an out-of-band guard) is **deleted**; `baseline_provider(state_dir)` in `ffi/secretary-ffi-bridge/src/repair/orchestration.rs` replaces it across all three arms. Two new core tests pin the keying (provider receives exactly the manifest uuid) and Err-propagation (manifest bytes unchanged).
- **Fail-closed posture** (`2f35ca7`): an **existing-but-unreadable** baseline state file (garbage bytes / decode failure / internal-uuid mismatch — every `secretary_cli::state::load` `Err`) now refuses the mutating repair, surfacing as `CorruptVault { detail }` naming the state file and the deletion-reset remedy; missing/never-synced/no-state-dir still skip (no false positive). Mechanism: `VaultError::Io` manufactured with `ErrorKind::InvalidData` — the kind is load-bearing (routes past `FolderInvalid`/`VaultFolderNotEmpty` to the `CorruptVault` fold). RED-proven: 3 bridge tests (password garbage-file, device-secret garbage-file, uuid-mismatch) failed at `expect_err` pre-flip, all asserting manifest-bytes-unchanged. The read-only open path deliberately keeps its skip posture (self-heals; asymmetry documented).
- **Normative docs** (`2a005eb`): vault-format.md §9 repair paragraph (verified-uuid keying, pre-write, fail-closed MUST + two new conformance test citations) and crypto-design.md §10 (mutating loads MUST check pre-tick and fail closed on an unreadable baseline).
- **Editorial from the whole-branch review** (`34570d4`): vault-format splice seam, orchestration.rs "buggy" wording disambiguated from the live open-path fn, and a `repair_vault` doc caution that the fail-closed posture lives in the *provider* — future callers must use/mirror `baseline_provider`, `|_| Ok(None)` is test-only.
- **Spec + plan** (`625d409`, `dee2935`): `docs/superpowers/specs/2026-07-04-repair-rollback-baseline-384-design.md`, `docs/superpowers/plans/2026-07-04-repair-rollback-baseline-384.md`.

**Verification (final state, all re-verified FROM THE WORKTREE):** `cargo fmt --all --check`; `cargo clippy --release --workspace --tests -- -D warnings`; `cargo test --release --workspace` (0 failures); `RUSTDOCFLAGS="-D warnings" cargo doc`; `conformance.py` PASS; Swift + Kotlin `run_conformance.sh` 27/27 each; desktop `pnpm svelte-check` 0 errors + `pnpm test` 581/581; lean-binding guard green. (Process note: a mid-session Bash-cwd drift to the main checkout was caught and every ambiguous gate re-run with explicit `cd` — see [[feedback_bash_cwd_persists_verify_before_killing]].)

### Branch commits (off `main` @ `fc8a53a`)
`625d409` (spec) → `dee2935` (plan) → `1623223` (core+bridge keying) → `d2365e3` (desktop comment) → `2f35ca7` (fail-closed posture) → `2a005eb` (normative docs) → `34570d4` (editorial) → this docs/handoff commit.

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/repair-baseline-384
cargo test --release --workspace                                  # 0 failures
cargo clippy --release --workspace --tests -- -D warnings         # clean
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh      # 27/27
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh     # 27/27
cd desktop && pnpm svelte-check && pnpm test                      # 0 errors; 581 pass
```

## (2) What's next
Carried forward (this session inserted #384 ahead of the inherited list; the rest is unchanged in priority):

1. **#374 part 3 — informed-consent adoption of a crashed-*share* recipient-*widening* residue.** Needs its own brainstorm + spec + threat reasoning (it deliberately relaxes the fail-closed widening refusal). Now builds on the corrected §10 gate — the part-3 design must keep the provider fail-closed contract (see the `repair_vault` doc caution) and re-check §10 pre-write on any new mutating path. Acceptance: a `RepairPolicy`-gated core path + consent UX (desktop reference) rendering the added-recipient set; default stays fail-closed.
2. **Manual GUI smoke of the desktop repair flow** (only a human can click the native confirm): `pnpm tauri dev` against a **temp copy** of a vault with staged crash residue; confirm unlock → "Repair now?" → adopt; and a widening residue → refusal detail. Optionally also: corrupt the §10 state file and confirm the new fail-closed message renders with the remedy text.
3. **#383** — quick-xml RUSTSEC-2026-0194/0195 via tauri→plist (dependency triage); **#376 remainder** — secure-overwrite fallback + legacy `fingerprint == None` trash-entry migration decisions.
4. **Recovery/device-secret desktop repair UX** when the desktop grows those unlock arms; optional Cancel affordance clearing the retained password on the repair prompt.
5. **Carried mobile:** iOS on-device Face ID spot-check; Android #338 on-device biometric cloud-open, #331 SAF custom-ROM, #334 native cloud-provider epic (ADR + threat-model first).
6. **Housekeeping:** #290 — `spec_test_name_freshness.py` fails on main (3 pre-existing threat-model.md L234 false-positives; unrelated to this branch, already filed).

## (3) Open decisions and risks
- **Layering guard is documentation, not types** (final-review observation, non-blocking): core `repair_vault` accepts any provider, so a future second production caller (e.g. a CLI `repair` subcommand) could pass `|_| Ok(None)` and silently reconstruct fail-open behavior without a compile error. Mitigated by the doc caution on `repair_vault` naming `baseline_provider` as the canonical fail-closed provider. If a second production caller ever appears, consider promoting a shared fail-closed constructor instead of relying on the doc.
- **The read-only open path keeps its skip posture on purpose** — a rolled-back *read* leaks once and self-heals on the next open; only the *mutating* path launders permanently. Documented in crypto-design §10; don't "fix" the asymmetry.
- **`ErrorKind::InvalidData` is load-bearing** in `baseline_provider`'s Err arm: it steers the FFI fold to `CorruptVault { detail }`. If the `FfiVaultError` Io-routing arms ever change, re-check this mapping (the bridge test asserting the remedy text in `detail` will catch it).
- **#384 closes with this PR** (both observations addressed: keying via the closure variant — chosen over the issue's core-loads-state sketch on layering grounds, same security property — and the posture split exactly as the issue's alternative proposed).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/repair-baseline-384 && \
#   git branch -D feature/repair-baseline-384
git worktree list && git status -s
# Full acceptance: cargo test --release --workspace ; cd desktop && pnpm test && pnpm svelte-check
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink is retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/repair-baseline-384` (8 commits incl. this docs/handoff commit). Worktree `.worktrees/repair-baseline-384`. #384 resolved (PR carries `Closes #384`).
- **Acceptance:** full workspace green; both conformance harnesses 27/27; desktop 581/581 + svelte-check clean; lean-binding green; opus whole-branch review 0 Critical / 0 Important, 3 editorial items fixed in `34570d4`.
- **README / ROADMAP:** updated (one-sentence README note in the audit row; ROADMAP gains the #384 hardening entry in the audit bullet).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-04-repair-rollback-baseline-384-shipped.md`.
