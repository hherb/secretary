# NEXT_SESSION.md — Desktop: hide per-record Move button when no other blocks (#273) ✅ SHIPPED (PR #430)

**Session date:** 2026-07-14, resuming from `main` @ `f03f931f` after #428 (the #427 CI hardening) merged. This session did **two things**: (a) a **stale-issue sweep** — three candidates carried in the prior baton were already shipped by earlier PRs but never closed, so they were verified-then-closed; and (b) shipped **#273**, a small desktop UX polish. Branch `feature/hide-move-button-273` off `main` @ `f03f931f`; worktree `.worktrees/hide-move-button-273/`. Executed brainstorm → spec → plan → inline TDD → code review → ship. Spec: [docs/superpowers/specs/2026-07-14-hide-move-button-273-design.md](../superpowers/specs/2026-07-14-hide-move-button-273-design.md). Plan: [docs/superpowers/plans/2026-07-14-hide-move-button-273.md](../superpowers/plans/2026-07-14-hide-move-button-273.md).

**Desktop frontend only (Svelte 5 + TS). Files: [desktop/src/lib/blockCrud.ts](../../desktop/src/lib/blockCrud.ts), [desktop/src/components/RecordList.svelte](../../desktop/src/components/RecordList.svelte), [desktop/src/routes/Vault.svelte](../../desktop/src/routes/Vault.svelte), + 4 test files. No `core` / crypto / FFI / on-disk-format change; no new error variant; `#![forbid(unsafe_code)]` untouched (no Rust touched at all).**

## (1) What we shipped this session

### Stale-issue sweep (the prior baton's candidate list was substantially out of date)
The #427 handoff's "what's next" list was carried forward from an older baton; **verifying liveness before starting** (per [[feedback_verify_carryover_todos]]) found three of its candidates already done and merged, just never closed:
- **#408** (write-gate scanner comment-naive) — resolved by PR #415 (`4de849e2`): `maskNonCode` comment/string masking + the full #408 test block + RetentionDialog workaround removed. **Closed** with evidence.
- **#421** (Settings banner "save"-worded copy on load failure) — resolved by PR #422 (`4ade2bd4`): host-tested neutral `settingsErrorMessage` on both Android + iOS; banner calls it. **Closed** with evidence.
- **#280** (centralized write-gate coverage test) — resolved by PR #285 (`968dd28e`): `writeGateCoverage.test.ts` (3-layer registry/wrapper/scanner enforcement) already satisfies "adding a mutating write without a gate decision is a failing test." **Closed** with evidence.

All three closes were **verify-then-close**: confirmed the fix is still on `main` (`f03f931f`) and green before commenting + closing. **Lesson for next session: do not trust a carried-forward candidate list — grep/git-log each item first.** (#417 is genuinely still open — its Android render tests shipped in #422 but the *iOS literal-render sliver* was deliberately deferred; #277 is genuinely open.)

### #273 — hide the per-record Move button when the vault has ≤1 live block
In a single-block vault the Move button opened `MoveTargetPicker` only to dead-end at "No other blocks to move into." Now hidden. **Approach (per the issue's preferred option):** thread the authoritative `manifest.blockCount` from `Vault.svelte` into `RecordList` — **no extra IPC** — and gate `onMove` with a pure `hasMoveTargets(blockCount)` helper, reusing `RecordRow`'s existing `{#if onMove}` (no `RecordRow` change).

- `blockCrud.ts`: pure `hasMoveTargets(blockCount): boolean` = `blockCount >= MIN_BLOCKS_TO_MOVE` (named const = 2; no magic number). Unit-tested (0,1→false; 2,3→true).
- `RecordList.svelte`: new **required** `blockCount: number` prop; `canMove = $derived(hasMoveTargets(blockCount))`; `onMove={canMove ? onMove : undefined}`.
- `Vault.svelte`: `<RecordList block={$browseNav.block} blockCount={manifest.blockCount} />`.
- The `blockCount >= 2` threshold is **exact**, not approximate: code review traced `block_count() = manifest.blocks.len()` and `block_summaries()` over the same set, and `MoveTargetPicker` candidates = `listBlocks()` minus source, so `candidates.length === blockCount - 1`. The button is hidden on exactly the range the picker would show its empty state. Still a **UX layer** on top of the picker empty-state + `move_record_impl` same-block guard (both unchanged) — correctness never depended on it.
- **Mobile parity filed as #429** (Android + iOS also always show Move today; split out so the desktop slice shipped contained).

### Branch commits (off `main` @ `f03f931f`, in order)
- `28ee759a` design doc (spec)
- `ce450651` implementation plan
- `c5f0d89a` **Task 1** — `hasMoveTargets` pure guard + unit tests
- `cad331e0` **Task 2** — wire `RecordList` + `Vault` + render tests + 15 existing render-site prop updates
- _(this commit)_ handoff doc + symlink retarget

### Acceptance (all met)
```bash
# From the worktree desktop/ dir — all green this session:
cd desktop
pnpm test              # 79 files / 648 tests pass
pnpm run svelte-check  # 0 errors, 0 warnings (required-prop enforcement)
pnpm run lint          # clean
```
Code review (pr-review-toolkit:code-reviewer over the diff): **clean, no findings at confidence ≥ 80** — threshold logic (verified against the Rust `block_count()` source), `onMove={… : undefined}` idiom, reactivity chain, test soundness (no race — Delete renders in the same synchronous pass as Move), and edge cases (blockCount is a `u64`, always ≥0) all confirmed.

## (2) What's next — pick a new slice

**Verify liveness first** (this session's lesson). Genuinely-open candidates as of this handoff:

- **#429 — mobile Move-button parity (Android + iOS)**, filed this session. Mirror #273 on mobile: hide the per-record Move action when block count ≤ 1. **Acceptance:** Android Compose render/instrumented test (single-block → no `move-<uuid>`; 2+ → present) + iOS host-testable VM gating + render pattern; picker empty-state + `move_record_impl` guard stay. Small–medium; needs emulator (Android instrumented) + iOS host. Natural direct follow-on to this session.
- **#277 — desktop OS-biometric write re-auth (macOS Touch ID)** — the biggest-remaining D.1 item; desktop still re-auths by password only. `authorizeWrite` is the single injection point. Meaty, multi-session, hardware-verification heavy.
- **#417 — iOS render-assertion sliver** — the one deferred piece: a literal SwiftUI render assertion for `settings-error` / `purge-notice`. Needs a test-infra decision (ViewInspector host dep vs a SecretaryApp XCUITest target).
- **Rust test-helper dedup #90** — ~13 files each define their own `fn copy_dir_recursive`; consolidate into one shared helper. Low-risk, good Rust-module practice.
- **#269 Android duplicate-name guard on block create/rename** — small Kotlin feature.
- **Security #383** — still upstream-blocked (`quick-xml 0.39` via `plist` → `tauri`); re-check on the next Tauri bump; do not start.
- Any user-prioritized slice.

## (3) Open decisions and risks
- **`blockCount` is a required prop (accepted).** Chosen over an optional default so `svelte-check` enforces every call site supplies it (there is one production caller, `Vault.svelte`, plus 15 test render sites — all updated). A future second caller that forgets it fails the type gate, not silently the wrong affordance.
- **The `blockCount >= 2` guard is a UX layer, not a safety boundary.** The `MoveTargetPicker` empty-state and `move_record_impl` same-block rejection remain the authoritative guards. If `listBlocks()` and `manifest.blockCount` ever diverged (they do not today — both project `manifest.blocks`), the worst case is a momentarily-shown button that dead-ends into the existing empty state, never an incorrect move. **Do not** remove the picker empty-state or the Rust guard on the theory that the button is now hidden.
- **Desktop-only scope (deliberate).** Mobile parity is #429; the issue explicitly permitted either. Don't treat #273 as incomplete — it is desktop-scoped and closed by PR #430.
- **README/ROADMAP: no change** — cosmetic polish on an already-documented feature (`move_record` affordance already shipped ✅ on all three platforms); consistent with prior cosmetic-slice precedent (#422 added no entry either). Verified neither file needs an edit.
- **Other in-flight worktrees exist** (parallel sessions — do not touch): `.worktrees/d4-browser-autofill`, `.worktrees/desktop-block-crud-ui`, `.worktrees/timer-poison-147`, plus two detached `.claude/worktrees/*`. This session only removed the merged `ci-hardening-427` worktree.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After PR #430 merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/hide-move-button-273 && git branch -D feature/hide-move-button-273
git worktree list && git status -s
# If resuming THIS branch for fixups (bind histories first — closes the add/add gap on the handoff doc):
#   cd .worktrees/hide-move-button-273 && git fetch origin && git merge origin/main
# Re-run this branch's local gates any time it is live (from the worktree):
#   cd desktop && pnpm test && pnpm run svelte-check && pnpm run lint
# CI status for the PR:
#   gh pr checks 430
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside PR #430 — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, first `git fetch origin && git merge origin/main` (branch version wins on this doc) before editing.

## Closing inventory
- **State on close:** PR #430 open on `feature/hide-move-button-273` (worktree `.worktrees/hide-move-button-273`). Branch commits: spec + plan + 2 task commits + handoff. Code review clean.
- **Also closed this session (stale-but-done):** #408, #421, #280 (evidence comments + verify-then-close). **Filed:** #429 (mobile Move-button parity).
- **Acceptance:** all desktop gates green (648 tests, svelte-check 0 errors, lint clean); code review no findings; `blockCount >= 2` threshold proven exact against the Rust source.
- **Next:** pick a new slice — #429 (direct mobile follow-on), #277 (biggest D.1), #417 iOS sliver, #90 Rust dedup, or user priority. **Verify liveness first.**
- **README / ROADMAP:** no change (cosmetic polish on an already-documented feature).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-14-hide-move-button-273-shipped.md`.
