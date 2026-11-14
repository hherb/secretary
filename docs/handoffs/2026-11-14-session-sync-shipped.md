# NEXT_SESSION.md: session sync and the stale-write guard (#101)

Branch `feature/session-sync`, worktree `.worktrees/session-sync`, base
`13ce2ef8` (`main`; `main` has not moved since). The PR is open; see
`gh pr list --head feature/session-sync`.

Design: `docs/superpowers/specs/2026-11-14-session-sync-design.md`. Plan:
`docs/superpowers/plans/2026-11-14-session-sync.md`. The ledger, per-task
reviews and gate logs are in `.superpowers/sdd/2026-11-14-session-sync/`
(gitignored, local only).

---

## (1) What shipped

**What it does.** A manifest write over a vault that changed on another
device is now refused, where it used to silently revert that change. Sync no
longer needs the password on a session that is already open.

| SHA | What |
|---|---|
| `d3585d8f`, `19f68f2f` | Design spec, plan |
| `97be58fc`, `2cbe8a80` | `FfiVaultError::VaultChangedOnDisk` across bindings and platforms |
| `883f6461` | Core: every manifest writer working from an open session (five block writers, two purge commits, `repair_vault`) refuses with `ManifestChangedOnDisk` when the on-disk manifest differs from the session's copy |
| `9a2eb963` | `verify_vault_state`, shared by open, the merge commit and the bridge refresh |
| `011c942f`, `b5f06714` | Merge commit uses the unlocked identity (no password, no second Argon2id); CLI drops the password after unlock |
| `0e8f71c4`, `4eea33d6` | Bridge: `sync_vault_with_session`, `sync_commit_decisions_with_session`, `refresh_manifest`; SilentMerge refreshes against the pre-pass clock |
| `f9f0d8be` | Desktop and Android: password pass plus refresh (skipped on SilentMerge) |
| `6bc2775e` | iOS: sync through the session behind the re-auth gate; password sheet removed |
| `d5d22fb5` | macOS: Reload on `vaultChangedOnDisk` |
| `9dc40b2b` | Docs |
| `3386ecef`..`48cb9fa9` | Final-review fix wave, part 1: I1 (Android B1 guard), M1 (refresh fails closed on an unreadable state), M2, I2 (Mac Reload from every sheet), I4 (settings copy), T5/T7/T8 minors |
| `fe6a3252`..`b2eff31b` | Fix wave, part 2: M4 (CLAUDE.md invariant), I3(a) (the SilentMerge dead end stated in code and ROADMAP), M3, T1/T2/T3/T4/T6 tests and docs, and one out-of-brief bug: desktop record edit/delete mappers folded `VaultChangedOnDisk` into a generic `RecordSaveFailed` (`b2eff31b`) |
| (this commit) | This handoff + symlink retarget |
| `/finalcheck` wave | Mac Reload keeps the sheet on a failed reload; iOS shows a `RollbackRejected` pass; desktop SilentMerge is a warning, not "Synced"; Android refresh decision exhaustive; bridge tests for the per-arm rollback baseline, a tampered-block refresh and every writer's `VaultChangedOnDisk` fold (each mutation-proven with `scripts/mutate.py`); a foreign-identity `verify_vault_state` test; doc scope corrections; #740-#742 filed |

**Gates at HEAD (`b2eff31b`), every one exit 0:**
- `cargo fmt --all --check`
- `cargo clippy --release --workspace --tests -D warnings`
- `cargo test --release --workspace`
- rustdoc `-D warnings`
- `pnpm test` (789 tests since the `/finalcheck` wave)
- Gradle `:kit:testDebugUnitTest :vault-access:test :browse-ui/:app compile`
- Android log hygiene, plus its self-test
- payload hygiene, plus its self-test
- iOS public-log hygiene, plus its self-test
- lean binding
- test-support placement
- secret-slot hygiene
- ci wiring
- `swift test` SecretaryVaultAccess (182 + 195 in its two bundles since the `/finalcheck` wave) and SecretaryKit (59)
- `ios/scripts/build-app.sh` and `build-macos-app.sh`

Every test added in fix wave part 2 was shown to red under a temporary
mutation, then the mutation was reverted.

**Not run / known red:**
- Swift and Kotlin conformance runners: they fail on Xcode 27.2's `ld`
  everywhere (#728). A typecheck stood in for them.
- `spec_test_name_freshness.py` reports 100 unresolved, identical at the
  merge-base (#642).
- pyo3 `test_retention.py::test_commit_purges_expired_block` fails on `main`
  too (#738). The suite is not in CI (#501); the other 134 tests pass.
- No manual GUI pass on any platform.

## (2) What is next

1. **Merge this PR.** Acceptance: all 25 required checks green. If CI is red
   only on a gate that cannot run locally, investigate before re-running.
2. **#730, then #732 / #733 (recommended next slice).** After a desktop or
   Android SilentMerge pass the handle stays stale, so the next write is
   refused. A repeat sync is `RollbackRejected`, and a lock-and-reopen is
   refused as a rollback, so the user is stuck. iOS is unaffected.
   Acceptance:
   - #732: desktop calls `sync_vault_with_session_in` /
     `sync_commit_decisions_with_session_in` with the identity it holds.
   - #733: Android's `UniffiVaultSyncPort` calls `syncVaultWithSession`.
   - Both: a SilentMerge pass followed by a write succeeds, pinned by a test
     on each platform. The `needs_refresh` / `refreshIfNeeded` copies are
     deleted.
   - Fixing #730 itself (the persisted LUB clock dominating disk) is a sync
     state-model decision, so ask the user before choosing a design.
3. **#736**: iOS browse VM calls the session synchronously on the main actor.
   The Mac Reload and `refreshFromDisk` are listed there too. Acceptance:
   those calls are offloaded, with the session lock still held across a pass.
4. **#734**: a rollback-specific refresh message, instead of `CorruptVault`.
   (A `RollbackRejected` PASS now shows a neutral notice on iOS; a refused
   REFRESH still reads as corruption.)
5. **#737 / #729**: four files that were already over the size cap grew;
   bridge `error/vault` needs a split.
6. **#738**: fix the pyo3 retention test window (above the #606 floor).
7. **#731**: auto-sync on folder change.
8. **#740** (refresh failure after a merged pass reads as "Sync failed"),
   **#741** (Android refresh wiring untested), **#742** (pyo3 stale-write
   test). Filed by the `/finalcheck` review.
9. From the previous baton, still open: #649, #683, the nested non-map sweep,
   #677, #668 / #693 (spec questions, ask the user), and #699 / #701-#705.

## (3) Open decisions / risks

- **The desktop/Android SilentMerge dead end ships with this PR.** It was
  ruled acceptable (option (a), documented) because moving those platforms
  onto session sync was an explicit spec non-goal. Code comments, the
  ROADMAP row and #730/#732/#733 all say so. Desktop now tells the user (a
  SilentMerge is a warning saying edits may be refused); Android still shows
  nothing for it. If that is not acceptable for a release, #732/#733 must
  land first.
- The check-then-write window in `ensure_manifest_unchanged_on_disk` is not
  atomic. It is an accepted residual (spec §5.2), documented in the helper.
- The guard is enforced by convention: one call per writer. The CLAUDE.md
  bullet names every current caller. A new writer must add it.
- Worktrees: `.worktrees/session-sync` holds an untracked `target-fixwave/`
  (a fix-wave build cache, safe to delete). The other merged worktrees, the
  two detached `.claude/worktrees/` checkouts and the branch
  `backup-pre-reword-1787543234` are carried over. Ask before deleting any
  of them.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/session-sync
pwd && git branch --show-current     # feature/session-sync
git fetch origin && git log --oneline HEAD..origin/main
gh pr checks "$(gh pr list --head feature/session-sync --json number -q '.[0].number')"
cargo test --release --workspace
(cd desktop && pnpm test)
(cd ios/SecretaryVaultAccess && swift test)
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
