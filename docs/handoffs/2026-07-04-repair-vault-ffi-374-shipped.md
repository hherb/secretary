# NEXT_SESSION.md — repair_vault FFI projection + desktop "repair now?" UX (#374 Slice A) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-04. Shipped **Slice A of [#374](https://github.com/hherb/secretary/issues/374)** — made the existing fail-closed `repair_vault` crash-recovery orchestrator (from #350) reachable end-to-end: projected onto all three FFI unlock arms with two new typed errors, plus a desktop "repair now?" reference flow and a device-secret-arm core test. Worktree `.worktrees/repair-vault-ffi-374`, branch `feature/repair-vault-ffi-374` (cut from `main` @ `d3a1ee6`). **No change to `repair_vault`'s core security semantics** — the fail-closed recipient-widening refusal is untouched. Built via subagent-driven development (fresh implementer + task reviewer per task; opus whole-branch review at the end).

## (1) What we shipped this session

`repair_vault` is now callable from every binding and offered by the desktop app. On a crash-residue open the user sees an actionable "Repair now?" affordance instead of a generic "corrupt vault"; on confirm the app adopts the residue (or shows a typed refusal detail).

- **Two typed errors** (`a5eb69e`): `FfiVaultError::VaultNeedsRepair { block_uuid_hex }` (promoted from open's `BlockFingerprintMismatch`, out of the generic `CorruptVault` fold) and `RepairRejected { block_uuid_hex, detail }` (repair refused; `detail` names the recipient delta). `BlockFileMissing` stays folded to `CorruptVault` (unrepairable). Threaded through **every** exhaustive consumer — bridge conversion + tests, uniffi `VaultError` (From + udl), pyo3 exception classes + mapping, desktop `AppError` (+ From), the core `conformance_kat_helpers` matcher, the `read_block` integration test, and both Swift + Kotlin `ConformanceErrors` harnesses. No `_ =>` catch-all (the #40 anti-drift invariant).
- **Bridge projection** (`2c8bb1c`): `repair_vault_with_{password,recovery,device_secret}` in `ffi/secretary-ffi-bridge/src/repair/` (three arms, parity with the three `open_vault_with_*` arms) + integration tests (happy-adopt / widening-reject / idempotent-healthy). The device-secret arm's single `device_uuid` serves both the slot lookup and the manifest-clock tick.
- **uniffi** (`1db0a9d`): `repair_with_*` namespace fns + wrappers (length-validated `InvalidArgument`, zeroize discipline) + udl.
- **pyo3** (`d4a5983`): `repair_with_*` + pytest (crash-residue adopt + widening-reject + input-validation).
- **Desktop backend** (`d8d14dd`): `repair_vault` Tauri command + `VaultSession::repair` (+ a shared `populate_unlocked` helper DRY'd out of `unlock`) + `read_vault_uuid_from_toml` (needed because repair resolves `device_uuid` before the open). Classified `repair_vault` as `write+exempt` in `writeCommands.ts` (#280 gate).
- **Desktop frontend** (`08ad37d`): the "repair now?" affordance in `Unlock.svelte` — reuses the password still in the form (scoped `keepPassword` on `vault_needs_repair`, cleared on every other outcome and after the repair resolves), renders `RepairRejected.detail`.
- **Core test** (`b463e7f`): `repair_vault` via `Unlocker::DeviceSecret` (part 4 — closes the whole-branch-review coverage gap).
- **Security fix from the whole-branch review** (`c7adb5c`, `0fa1f96`): see (3) — the §10 rollback check now runs **before** repair's manifest write.
- **Docs** (`f93aab5`): README + ROADMAP updated (#374 Slice A shipped; part 3 deferred).

**Verification (final state, all green):** `cargo test --release --workspace`; `cargo clippy --release --workspace --tests -- -D warnings`; `cargo fmt --all --check`; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`; `conformance.py`; Swift + Kotlin `run_conformance.sh` (27/27 each); `pnpm svelte-check`; `pnpm test` (577/577). Opus whole-branch review: **1 Critical + 2 Minor, all fixed**; re-review of the Critical fix **Approved** (reviewer independently RED/GREEN-proved the regression test).

### Branch commits (off `main` @ `d3a1ee6`)
12 commits: `c713dc9`/`430859b` (design + plan) → `b463e7f`…`08ad37d` (impl) → `f93aab5` (docs) → `c7adb5c` (security fix) → `0fa1f96` (fix follow-ups). See `git log main..HEAD`.

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/repair-vault-ffi-374
cargo test --release --workspace                                  # 0 failures
cargo clippy --release --workspace --tests -- -D warnings         # clean
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh      # 27/27
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh     # 27/27
cd desktop && pnpm svelte-check && pnpm test                      # 0 errors; 577 pass
```

## (2) What's next
#374 Slice A is complete. Follow-ups, roughly in priority order:

1. **#374 part 3 — informed-consent adoption of a crashed-*share* recipient-*widening* residue.** The one deferred slice: today `repair_vault` hard-refuses any recipient widening (fail-closed → `RepairRejected`). Part 3 adds a **new core opt-in policy surface** that, on explicit user consent showing the recipient delta, adopts a crashed-share superset. This changes `repair_vault`'s security semantics — give it its own brainstorm + spec + threat reasoning (the #350 review hardened the widening refusal; relaxing it is load-bearing). Acceptance: a `RepairPolicy`-gated core path + a consent UX (desktop reference) that renders the added-recipient set before adopting; the default path stays fail-closed.
2. **Manual GUI smoke of the desktop repair flow** (automated tests can't drive the native repair confirm). `pnpm tauri dev` against a **temp copy** of a vault with staged crash residue (`cp -R` a golden vault, corrupt one block file's bytes); confirm: unlock → "Repair now?" appears → confirm → vault opens; and a widening residue → shows the refusal detail.
3. **Recovery/device-secret desktop repair UX** — the bridge exposes all three repair arms, but the desktop reference UX wires only the password arm (the only unlock arm the desktop exposes). Wire the others when the desktop grows recovery/device unlock.
4. **Optional frontend hardening (Task 7 note):** a "Cancel" affordance on the repair prompt that clears the retained password (today it lingers in the Unlock component's reactive state until the user acts/unmounts — the approved password-reuse tradeoff).
5. **Carried:** iOS on-device Face ID acceptance (#284/#347 now closed — spot-check remains); Android instrumented UI (#341/#342), #338 on-device biometric cloud-open, #331 SAF custom-ROM, #334 native cloud-provider epic (ADR + threat-model first).

## (3) Open decisions and risks
- **The whole-branch review caught a Critical rollback-resistance gap — fixed this session.** The bridge repair fns originally passed `None` for core `repair_vault`'s `local_highest_clock`, so the §10 rollback check (`enforce_rollback_resistance`) ran **after** `repair_vault` had already ticked + persisted the manifest, on the *post-tick* clock — the local tick flipped `is_rollback` (`any_strictly_less && !any_strictly_more`) from true to false, masking a rollback permanently (a foreign-device rollback laundered through a "repair now?" confirm). Fix (`c7adb5c`): the bridge repair fns load the local baseline (keyed by the vault.toml `vault_uuid`) and pass it as `Some(&baseline)` to core `repair_vault`, so `read_and_verify_manifest` gates the rollback on the **committed** clock before any adopt/tick/write — fail-closed, nothing mutated. Availability posture preserved (never-synced device → empty baseline → skip, no false positive). Regression tests (`c7adb5c` password arm, `0fa1f96` device-secret arm) assert **refuse-with-`CorruptVault` AND manifest bytes unchanged**, both RED-proven. **Lesson for part 3 and any future mutating open:** a read-only open can check §10 after core returns; a *mutating* op must check **before** it writes.
- **`toml = "0.8"` caret dep added to the desktop** (`read_vault_uuid_from_toml`). Reviewer-adjudicated acceptable: matches core's existing `toml = "0.8"` caret precedent (core parses the crypto-critical KDF params with the same crate/pin), parses only the non-secret plaintext `vault_uuid`, returns `Result` (no panic on tampered input). Whether to exact-pin `toml` repo-wide per the `tempfile = "=3.27.0"` precedent is a **pre-existing** policy question, not introduced here.
- **pyo3 `RepairRejected`** collapses `block_uuid_hex` + `detail` into one message string (documented contract `"<uuid>: <detail>"`) — consistent with the pyo3 module's `create_exception!` convention; uniffi/desktop keep them structured.
- **Part 3 stays deferred** — the recipient-widening case remains fail-closed as `RepairRejected`. This is a documented limitation, not a regression.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/repair-vault-ffi-374 && \
#   git branch -D feature/repair-vault-ffi-374
git worktree list && git status -s
# Full acceptance: cargo test --release --workspace ; cd desktop && pnpm test && pnpm svelte-check
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink is retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/repair-vault-ffi-374` (12 commits incl. this docs/handoff commit). Worktree `.worktrees/repair-vault-ffi-374`. #374 Slice A resolved (PR carries `Refs #374`; part 3 remains open under #374).
- **Acceptance:** full workspace green; both conformance harnesses 27/27; frontend 577/577; opus whole-branch review 1 Critical + 2 Minor all fixed; Critical fix re-reviewed Approved.
- **README / ROADMAP:** updated (#374 Slice A shipped; part 3 = sole remaining deferral).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-04-repair-vault-ffi-374-shipped.md`.
