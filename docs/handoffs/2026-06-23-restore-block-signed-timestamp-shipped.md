# NEXT_SESSION.md — restore_block signed-timestamp selection (#205) ✅ SHIPPED (PR to open)

**Session date:** 2026-06-23. Started from a clean baton — PR #291 (#204 Argon2 floor docs) had merged to `main` (`61043fb2`); the prior `.worktrees/argon2-floor-docs` was cleaned up. Picked **#205** from the sync/daemon-security cluster (you chose it over #206 / #207-209 / #210). Brainstormed → spec → plan → executed inline (TDD) → reviewed → opened PR.

**Status:** ✅ **SHIPPED — branch `feature/restore-block-signed-timestamp`, PR opening.** Security fix + 2 regression tests; fresh-eyes security review found **no material bugs** (all six target properties proven to hold).

## (1) What we shipped this session

**The vuln (#205, Medium/security):** `restore_block` selected which trashed block file to restore by **largest filename suffix** — and the suffix is *unauthenticated* filename metadata in an attacker-writable synced folder (threat-model §2.1). A malicious cloud host could plant a previously-retained, genuinely owner-signed *older* copy of a block at a *larger* suffix; the next user-initiated restore would resurrect that **authentic-but-stale** block (e.g. a rotated password), then purge the legitimate copy — an undetectable rollback that no later CRDT merge could self-heal. Violated threat-model.md:60 ("a restore must be authentic **and current**").

**The fix (Approach A — bind selection to the signed value):** `trash_block` writes the file `trash/<uuid>.cbor.enc.<now_ms>` **and** the signed `TrashEntry{tombstoned_at_ms: now_ms}` in one operation, so the authentic file's suffix **equals** the signed timestamp by construction. `restore_block` now selects the file whose canonical u64 suffix **equals** `TrashEntry.tombstoned_at_ms` (equality, not `>=`), reading the timestamp from the verified manifest — not from the filename. Purge targets = every other match (older stale copies AND larger-suffix plants).

**New typed error:** `VaultError::RestoreTargetMissing { block_uuid, expected_tombstoned_at_ms }` fires when a signed `TrashEntry` exists and trash files are present but none matches the signed timestamp (authentic file removed/renamed; only stale/forged copies remain). It **folds to the existing `FfiVaultError::CorruptVault`** (the "signed-data ↔ on-disk-bytes" integrity bucket, exactly like `RestoreVerificationFailed`) → **no new `FfiVaultError` variant**, so **no `.udl`/pyo3/Swift/Kotlin conformance churn**. The bridge's five per-path `VaultError` matchers have no `_` catchall (issue #40 invariant), so all five were threaded (reachable arm in `restore/`, unreachable-but-listed in `save`/`share`/`trash`/`revoke`).

**Branch commits** (off `main` @ `61043fb2`):
| SHA | What |
|---|---|
| `8181dc89` | design doc (`docs/superpowers/specs/2026-06-23-restore-block-signed-timestamp-design.md`) |
| `cd44bb90` | implementation plan (`docs/superpowers/plans/2026-06-23-restore-block-signed-timestamp.md`) |
| `e3afbb94` | **fix**: core equality selection + `RestoreTargetMissing` variant + FFI arms (6 bridge files) + 2 TDD tests + FFI mapping tripwire |
| `9f1d6f7c` | **docs**: `vault-format.md` §7.1 steps 1-2 — select signed `tombstoned_at_ms`, not largest suffix |
| `67906b48` | **docs**: README B.5 row — corrected the now-false "reads the largest-timestamp file" clause |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

**Tests added** (`core/tests/trash_restore.rs`):
- `restore_block_ignores_larger_suffix_forgery` — authentic file at suffix=`tombstoned_at_ms`, **corrupt** forgery at a larger suffix; restore succeeds by selecting the authentic file (asserted byte-identical), forgery purged. *Fails on `main`* (largest-suffix picks the corrupt file → `RestoreVerificationFailed`).
- `restore_block_missing_signed_target_rejected` — authentic file renamed to a larger suffix (a genuinely owner-signed "stale" plant); restore returns `RestoreTargetMissing { expected_tombstoned_at_ms }`, manifest/trash untouched. *Would succeed (the rollback) on `main`.*

### Acceptance (all GREEN locally on the branch)
```bash
cd /Users/hherb/src/secretary/.worktrees/restore-signed-ts
cargo test --release --workspace                                   # 82 binaries OK, 0 FAILED
cargo clippy --release --workspace --tests -- -D warnings          # clean
uv run core/tests/python/conformance.py                            # PASS (restore not exercised; golden vault still decrypts)
uv run core/tests/python/spec_test_name_freshness.py               # 108 resolved; only the 3 pre-existing #290 false-positives (no NEW drift)
```
**CI is the real gate once pushed** — `test.yml` (rust ×2 OS + desktop vitest + swift/kotlin conformance) + `rust-lint.yml` (fmt/clippy) + CodeQL. No new `FfiVaultError` variant means the Swift/Kotlin conformance harnesses are unaffected; freshness checker is not a CI gate.

## (2) What's next
**#205 done (PR open). Pick a fresh item.** Remaining sync/daemon-security cluster (core Rust, no desktop/D.4 worktree conflict):
- **#206** — FFI `share_block` accepts an unverified contact card and overwrites a trusted one (TOFU substitution); verified primitives not projected to PyO3/uniffi. *Larger — touches FFI surface; if it needs a new `FfiVaultError` variant, thread uniffi/pyo3 + Swift/Kotlin `ConformanceErrors.{swift,kt}` and run both `run_conformance.sh` scripts (see [[project_secretary_ffivaulterror_workspace_match]]).*
- **#207/#208/#209** — daemon rollback-detection gaps (discards `Ok(RunOutcome)`; `SyncState` persisted only on clean exit; state-dir `.` fallback misplaces state). Related; can bundle or sequence.
- **#210** — fuzz monitor dashboard binds `0.0.0.0` with no auth (Python; small, quick win).
- **#251** (`openBlocks` accumulates plaintext until lock) / **#229** (passwords as plain `[UInt8]`/`Data` not zeroized across Swift FFI) — memory hygiene.
- **#290** — allowlist the 3 D.4 freshness false-positives once the `d4-browser-autofill` session settles.

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* (not assumed — security paths), full `cargo test --workspace` + clippy `-D warnings` green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #251 / #247 / #246 / #234 / #232 / #231 / #229 / #224 / #218 / #210 / #209 / #208 / #207 / #206 / #205(merging) / #193 / #192 / #190 / #189 / #186 / #183.

## (3) Open decisions and risks
- **Deliberate scope:** the fix stays inside the frozen v1 format — it binds selection to the existing signed `TrashEntry.tombstoned_at_ms` rather than re-signing the trash filename into the block payload (a heavier format change). If a future change ever needs the trash *time* cryptographically bound into the block envelope itself, that's a v2 format discussion, not this fix.
- **Equality, not `>=`:** the manifest carries only the most-recent `tombstoned_at_ms`; a multi-cycle trash→restore→re-trash history with the legit copy purged could mis-select under `>=`. Don't relax to `>=` in a future refactor.
- **FFI fold to `CorruptVault`:** deliberate (the §13 anti-oracle policy conflates integrity failures at the FFI boundary; the distinct signal lives at the core layer + in tests). If a future caller needs to distinguish "stale-target rollback" from generic corruption at the FFI surface, that would mean a *new* `FfiVaultError` variant + full conformance-harness threading — weigh the churn.
- **Risk:** none introduced — honest-vault restore is byte-identical to before (the authentic file's suffix already equalled `tombstoned_at_ms`); the new behaviour only bites when extra files are present. Full suite + security review clean.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/restore-signed-ts can be removed:
#   git worktree remove .worktrees/restore-signed-ts && git branch -D feature/restore-block-signed-timestamp
git worktree list && git status -s

# Run any gate locally:
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `origin/main` (`61043fb2`, no divergence), so no history-binding merge was needed this session.

## Closing inventory
- **State on close:** PR opening on `feature/restore-block-signed-timestamp` (5 code/doc commits + handoff). Worktree `.worktrees/restore-signed-ts`.
- **Acceptance:** local GREEN — full suite (82 binaries, 0 fail), 2 new teeth-verified tests, clippy clean, conformance PASS, freshness adds no new drift. Security review: no material bugs. CI pending on push.
- **README.md:** B.5 restore row clause corrected. **ROADMAP.md:** unchanged (high-level; doesn't describe restore selection mechanism). **CLAUDE.md:** unchanged (no restore-selection invariant documented there).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-23-restore-block-signed-timestamp-shipped.md`.
