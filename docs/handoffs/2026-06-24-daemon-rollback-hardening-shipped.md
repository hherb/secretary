# NEXT_SESSION.md — daemon rollback-detection hardening (#207/#208/#209) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-24. Started from a clean baton — PR #294 (#293 restore content-commitment) had merged to `main` (`1b18b6b4`); cleaned up the prior `.worktrees/trash-content-commitment` worktree + deleted branch. Picked the **#207/#208/#209 daemon-security cluster** (you chose it over #206 / #210 / #251+#229). Brainstormed → spec → plan → executed via **subagent-driven development** (fresh implementer + spec/quality reviewer per task, final whole-branch review on opus) → fixed review Minors → opened PR.

**Status:** ✅ **SHIPPED — branch `feature/daemon-rollback-hardening`, PR opening.** 3 security fixes + 12 new tests; final whole-branch review (opus): **Ready to merge, 0 Critical / 0 Important**; 5 Minors fixed in one wave, 1 filed as #295, 1 dismissed.

## (1) What we shipped this session

All three are confirmed spec/code divergences against the C.2 design (`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`); each fix code-aligns to the existing spec (the spec stays the source of truth). **`cli/` only** — no `core/` crypto change, no FFI surface, no on-disk vault/manifest/`SyncState` format change → `conformance.py` + Swift/Kotlin harnesses unaffected.

**#207 (Medium, observability):** the daemon loop discarded every `Ok(RunOutcome)`, so `RollbackRejected` (the threat-model §3.1 attack indicator) and auto-resolved tombstone vetoes were never logged at any verbosity — a malicious cloud host could probe the daemon with replayed manifests at zero alerting cost. **Fix:** enriched `RunOutcome::RollbackRejected(RollbackEvidence)` (the type already derives the needed traits; `once` mode ignores the payload → still exit 10), added a pure `daemon::outcome_log` classifier + `daemon::log_outcome` emitter, and the loop now logs rollback (with disk+local vector clocks) at `warn!` and the auto-resolved-veto count. Logging stays at the daemon edge — `pipeline.rs` has zero `tracing` calls.

**#208 (Medium, defense voided on crash):** `SyncState` (the sole rollback anchor) was persisted only once after the loop exits, so an unclean exit (SIGKILL/OOM/panic/power-loss) discarded the whole session's clock advances → on restart a stale clock let the host replay any manifest from the elapsed window as a forward update (silent rollback). **Fix:** pure `RunOutcome::advanced_state()` (true for AppliedAutomatically | SilentMerge | MergedAndCommitted), `daemon::after_sync(result, state, &mut save_sink)` that logs + persists via an **injected sink** (unit-testable without a watcher/FS) whenever the outcome advanced; threaded `state_dir` into `run_against_vault`; in-loop save failure is logged + swallowed (daemon survives transient FS errors); the final-save failure now escalates a `Success` exit to `GenericError` without overriding a more specific non-success code.

**#209 (Low–Medium, state could land in the attacker's folder):** when `dirs::data_dir()` returns `None` (headless, no `$HOME` — a stated systemd/Docker target) the state dir silently fell back to `"."` (cwd); if WorkingDirectory was the vault folder, rollback state landed inside the attacker-controlled synced folder where the cloud host deletes it → detection disabled. Plus a `0700` spec/code divergence. **Fix (decisions from brainstorming):** **hard error** on implicit cwd fallback (`StateDirError::Unresolvable`; explicit `--state-dir .` still allowed) **and** on a state dir resolving inside the vault (`StateDirError::InsideVault`), both → exit 2 (UsageError); a **lexical** (intentionally symlink-unaware) `normalize_abs`/`is_within` containment guard; `create_dir_secure` applies `STATE_DIR_MODE = 0o700` on Unix. Deleted the old `STATE_DIR_FALLBACK` const + infallible resolver.

**Branch commits** (off `main` @ `1b18b6b4`):
| SHA | What |
|---|---|
| `cee9f4c0` | design doc (`docs/superpowers/specs/2026-06-24-daemon-rollback-hardening-design.md`) |
| `9f63d564` | implementation plan (`docs/superpowers/plans/2026-06-24-daemon-rollback-hardening.md`) |
| `82b25072` | **fix(#207)**: log RollbackRejected + auto-resolved vetoes in daemon loop |
| `f398bd57` | **fix(#208)**: persist SyncState after every advancing sync (+ spec persist-list extended for SilentMerge) |
| `ef2dcf46` | **fix(#209)**: state-dir safety — no cwd fallback, never inside vault, 0700 (+ spec no-fallback note) |
| `203c09b2` | **fix**: final-review Minors — exit-code + save-swallow regression tests, comment/doc tidy |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

**Tests added (~18 test fns):** `outcome_log` ×3, `advanced_state` ×2, `after_sync` ×4 (incl. the save-error-swallow teeth test), `outcome_to_exit_code` ×2, and the #209 path-helper set ×7 — `is_within` ×2, `resolve_state_dir` ×4, `create_dir_secure(0700)` ×1. The teeth tests (assert the gap is closed, fail on pre-fix code): `after_sync_skips_save_on_non_advancing_arms` (#208), `resolve_rejects_state_dir_inside_vault` + `is_within_folds_parent_dir_escape` (#209), and the daemon-loop logging path (#207).

### Acceptance (all GREEN locally on the branch, verified by the controller, not assumed)
```bash
cd /Users/hherb/src/secretary/.worktrees/daemon-rollback-hardening
cargo test --release --workspace                             # 0 FAILED across all binaries
cargo clippy --release --workspace --tests -- -D warnings    # clean
cargo fmt --all -- --check                                   # clean
uv run core/tests/python/conformance.py                      # PASS (no format/semantics change)
```
**CI is the real gate once pushed** — `test.yml` (rust ×2 OS + desktop vitest + swift/kotlin conformance) + `rust-lint.yml` (fmt/clippy) + CodeQL. No new `FfiVaultError`/format surface → Swift/Kotlin conformance harnesses unaffected.

## (2) What's next
**Cluster done (PR open). Pick a fresh item.** Remaining sync/daemon + memory-hygiene security backlog:
- **#206** — FFI `share_block` accepts an unverified contact card and overwrites a trusted one (TOFU substitution); verified primitives not projected to PyO3/uniffi. *Larger — touches FFI surface; if it needs a new `FfiVaultError` variant, thread uniffi/pyo3 + Swift/Kotlin `ConformanceErrors.{swift,kt}` and run both `run_conformance.sh` scripts (see [[project_secretary_ffivaulterror_workspace_match]]).*
- **#210** — fuzz monitor dashboard binds `0.0.0.0` with no auth (Python; small, quick win).
- **#251** (`openBlocks` accumulates plaintext until lock) / **#229** (passwords as plain `[UInt8]`/`Data` not zeroized across Swift FFI) — memory hygiene.
- **#295** (NEW, filed this session) — `once` mode doesn't `log_outcome` (rollback/veto surfaced only via exit code, no forensic clocks). Small; just call `daemon::log_outcome` on the `Ok` arm of `dispatch_once_subcommand`.
- **#290** — allowlist the 3 D.4 freshness false-positives once the `d4-browser-autofill` session settles.

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* (not assumed — security paths), full `cargo test --workspace` + clippy `-D warnings` green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #295 / #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #251 / #247 / #246 / #234 / #232 / #231 / #229 / #224 / #218 / #210 / #206 / #193 / #192 / #190 / #189 / #186 / #183. (#207 / #208 / #209 now closed by this PR; #205 + #293 closed earlier.)

## (3) Open decisions and risks
- **Deliberate scope (frozen v1):** all three are observability/durability/config fixes to the existing daemon — no `SyncState` CBOR change, no manifest/vault format bump.
- **Lexical (not canonical) containment guard:** `is_within` is symlink-unaware **by design** — the in-scope adversary (malicious cloud host) controls the synced folder's *contents*, not the operator's local-FS symlink layout. Documented at the call site; the final review confirmed it can't produce a false-negative (both sides route through the same `normalize_abs`). Don't "harden" it into a `canonicalize` that requires the path to exist — that would break the not-yet-created-state-dir case.
- **`advanced_state()` arms are load-bearing:** true for exactly {AppliedAutomatically, SilentMerge, MergedAndCommitted}, false for {NothingToDo, RollbackRejected}. A wrong arm either loses rollback durability (missing save) or persists a non-advancing clock. Verified ⇔ the actual `run_one` mutation sites. Don't relax.
- **Final-save escalation must not override a specific code:** `Success → GenericError` only; `RollbackRejected`/`EvidenceStale`/etc. are preserved. (`LockfileHeld` returns earlier and never reaches that block — the comment was corrected in `203c09b`.)
- **0700 is leaf-only:** `create_dir_secure` sets 0700 on the created leaf; intermediate parents are umask-governed and an already-existing dir is not chmod'd — matches the spec wording "created on first run with mode 0700". Acknowledged, not a defect.
- **Risk:** none introduced — honest-vault behavior is unchanged (the new checks only bite on misconfiguration or an actual rollback/crash). Full suite + final security review clean.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/daemon-rollback-hardening can be removed:
#   git worktree remove .worktrees/daemon-rollback-hardening && git branch -D feature/daemon-rollback-hardening
git worktree list && git status -s

# Run any gate locally (from the worktree if the PR is still open):
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `origin/main` (`1b18b6b4`) and `origin/main` had **not** advanced at handoff time (verified: `origin/main` == merge-base), so no history-binding merge was needed this session.

## Closing inventory
- **State on close:** PR opening on `feature/daemon-rollback-hardening` (6 code/doc commits + handoff). Worktree `.worktrees/daemon-rollback-hardening`.
- **Acceptance:** local GREEN — full workspace suite (0 fail), ~18 new tests incl. teeth tests for each gap, clippy clean, fmt clean, conformance PASS. Final whole-branch review (opus): Ready to merge, 0 Critical/Important; 5 Minors fixed (`203c09b`), 1 filed (#295), 1 dismissed. CI pending on push.
- **README.md / ROADMAP.md:** unchanged — these describe capabilities/milestones; #207/#208/#209 are bugfixes to the already-shipped C.2 daemon (capability-level unchanged), and per the brief-status README style three internal fixes would be minutiae.
- **CLAUDE.md:** unchanged (no daemon-loop invariant documented there; the "both halves" hybrid-verify property it documents is untouched).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-24-daemon-rollback-hardening-shipped.md`.
