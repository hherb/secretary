# NEXT_SESSION.md — Reconcile Argon2id v1-floor docs with code (#204) ✅ SHIPPED (PR open, awaiting merge)

**Session date:** 2026-06-23. Started from a clean baton (PR #289 test-CI already merged, no in-flight work). Picked **#204** from the open-issue list (you chose it over #277 desktop-biometric / sync-security cluster / memory-hygiene). Brainstormed the design fork → wrote spec + plan → executed inline (TDD) → opened PR.

**Status:** ✅ **SHIPPED — PR open on `feature/argon2-floor-doc-reconcile`, awaiting your merge.** Docs-correctness + one regression test; **zero production source touched** (`core/src/`, `ffi/` bridge/uniffi, `*.udl`, `ios/`, `android/`, `desktop/` all untouched — guardrail verified empty).

## (1) What we shipped this session

**The problem (#204):** `docs/threat-model.md` (a *normative*, source-of-truth doc + principal external-review handoff) falsely claimed the Argon2id v1 memory floor is enforced as a typed error at `open_with_password` time, and cited a test (`core/tests/unlock.rs` open-side rejection) that **does not exist**. The same false claim was repeated in `side-channel-audit-internal.md` and `CLAUDE.md`. The code (and the approved B.2 design) only enforce the floor at **`create_vault`**.

**The decision (Approach A — correct docs to match code + prove the real defense):** Enforcing at open buys **zero** security (downgrade is cryptographically refuted) and would break the fast-KDF test fixtures, so we did **not** add an open-time check. Instead we corrected the docs and backed the *true* defense with a regression test.

**Why the missing open-time check is not a vuln (now documented + tested):**
1. Changing `memory_kib` in the cleartext `vault.toml` → different Master KEK → `wrap_pw` AEAD fails → `WrongPasswordOrCorrupt`. The strong Argon2 cost is bound into the ciphertext; an offline thief still pays it.
2. The orchestrator `open_vault` cross-checks `vault.toml [kdf]` against the **signed** manifest → `KdfParamsMismatch` ([orchestrators.rs:829](../../core/src/vault/orchestrators.rs#L829), tested by `open_vault_kdf_params_mismatch_rejected`).

**Branch commits** (off `main` @ `b9adb642`):
| SHA | What |
|---|---|
| `289d7eb2` | design doc (`docs/superpowers/specs/2026-06-23-argon2-floor-doc-reconcile-design.md`) |
| `072b5b28` | implementation plan (`docs/superpowers/plans/2026-06-23-argon2-floor-doc-reconcile.md`) |
| `a42e65a9` | **test**: `core/tests/unlock.rs::open_with_password_downgraded_kdf_params_fails` — downgraded `vault.toml` → `WrongPasswordOrCorrupt` (proves the refutation at the pure unlock layer; verified to have teeth) |
| `f8e7a527` | **docs**: corrected the false floor claim in `threat-model.md` (×2: §3.2 row + test-citation bullet), `side-channel-audit-internal.md`, `CLAUDE.md` |
| `5a1c2934` | **docs**: clarified ROADMAP A.3 line (floor is creation-time-only) |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

**Files changed vs main:** `CLAUDE.md`, `ROADMAP.md`, `core/tests/unlock.rs`, `docs/threat-model.md`, `docs/manual/contributors/side-channel-audit-internal.md`, `docs/superpowers/{specs,plans}/2026-06-23-*`. **No `core/src/` or `ffi/` source.**

### Incidental issue filed (not fixed — out of scope, active parallel session)
- **#290** — `spec_test_name_freshness.py` false-positives on 3 D.4 design concepts (`origin_binding`/`registrable_domain`/`exact_origin`, threat-model.md:234, ADR 0010 §6). **Pre-existing on `main`** (pristine main fails with the exact same 3; our change *added* 6 resolved citations, 102→108). Not in CI (`test.yml` runs `cargo test`, not this script). Filed rather than fixed because the D.4 area has an active `d4-browser-autofill` worktree — coordinate before editing its allowlist.

### Acceptance (all verified GREEN locally on the branch)
```bash
cd /Users/hherb/src/secretary/.worktrees/argon2-floor-docs
cargo test --release --workspace                                    # 82 test binaries OK, 0 FAILED
cargo test --release --workspace --test unlock \
  open_with_password_downgraded_kdf_params_fails                    # PASS (and FAILs when assertion inverted → has teeth)
cargo clippy --release --workspace --tests -- -D warnings           # clean
uv run core/tests/python/spec_test_name_freshness.py                # 108 resolved; only the 3 pre-existing #290 failures remain (no NEW drift)
git diff main...HEAD --name-only | grep -E '^(core/src/|ffi/.*/src/)' # EMPTY (no production source)
```
**CI will be the real acceptance** once pushed — `test.yml` (rust ×2 OS + desktop vitest + swift/kotlin conformance) + `rust-lint.yml` (fmt/clippy) + CodeQL. This PR is docs + one test, so all should pass; the freshness checker is not a CI gate.

## (2) What's next
**#204 done (pending merge). Pick a fresh item.** Candidates from the open list:
- **#277** — desktop OS biometric (Touch ID/Hello), largest open write-reauth piece. **Heads-up:** `d4-browser-autofill` + `desktop-block-crud-ui` worktrees are still active — coordinate before a desktop-heavy pick.
- **Sync/daemon security cluster** (core Rust, no desktop conflict): #205 (restore_block trash-suffix rollback), #206 (share_block TOFU substitution), #207/#208/#209 (daemon SyncState rollback-detection gaps), #210 (fuzz dashboard binds 0.0.0.0).
- **Memory hygiene:** #251 (openBlocks accumulates plaintext until lock), #229 (passwords as plain [UInt8]/Data not zeroized across Swift FFI).
- **#290** (just filed) — allowlist the 3 D.4 freshness false-positives once the d4 session settles.

**Open follow-up issues (carried):** #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #251 / #247 / #246 / #234 / #232 / #231 / #229 / #224 / #218 / #210 / #209 / #208 / #207 / #206 / #205 / #204(merging) / #193 / #192 / #190 / #189 / #186 / #183 / **#290(new)**.

## (3) Open decisions and risks
- **Deliberate non-fix:** we chose NOT to enforce the floor at open. If a future change-password/re-wrap flow re-derives the KEK from `vault.toml` params, the floor becomes load-bearing there — that flow **must** route through `try_new_v1`. This requirement is now documented in `CLAUDE.md` (Crypto layering bullet) and the design doc. Don't let a future re-key flow read params via the non-validating `Argon2idParams::new`.
- **Risk:** none introduced — docs + one test, no behavior change, guardrail empty.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/argon2-floor-docs can be removed.
git worktree list && git status -s

# Run any gate locally:
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `main` (`b9adb642`, no divergence), so no history-binding merge was needed this session.

## Closing inventory
- **State on close:** PR open on `feature/argon2-floor-doc-reconcile` (5 code/doc commits + handoff). Worktree `.worktrees/argon2-floor-docs`.
- **Acceptance:** local GREEN — full suite (82 binaries, 0 fail), new test passes (+ teeth-verified), clippy clean, freshness adds no new drift. CI pending on push.
- **README.md:** unchanged (its Argon2 mentions are accurate creation-side defaults). **ROADMAP.md:** A.3 line tightened to creation-time-only. **CLAUDE.md:** Crypto-layering floor bullet corrected.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-23-argon2-floor-doc-reconcile-shipped.md`.
