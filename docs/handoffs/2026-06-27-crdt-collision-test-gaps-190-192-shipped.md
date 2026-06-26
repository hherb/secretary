# NEXT_SESSION.md — #190 + #192 CRDT collision test gaps ✅ SHIPPED (PR opening)

**Session date:** 2026-06-27 (started 2026-06-26). Started from a clean baton — PR #311 (the #189 lean mobile-binding CI guard) had merged to `main` as `28e48ef7`; removed the merged worktree/branch (`.worktrees/lean-binding-guard-189` / `feature/lean-binding-guard-189`). User picked **#190 + #192** (paired bridge/CRDT test gaps). Executed in project-local worktree `.worktrees/crdt-test-gaps-190-192`, branch `feature/crdt-test-gaps-190-192`.

**Status:** ✅ **SHIPPED — branch `feature/crdt-test-gaps-190-192`, PR opening.** Pure test-coverage / regression-insurance change. **No `core`/FFI-surface/on-disk-format/`conformance.py`/crypto change; no Cargo manifest change.** `Closes #190` + `Closes #192` ride in the commit + PR body.

## (1) What we shipped this session

**The shared insight.** Both issues need one fixture shape the existing tombstone-veto fixture provably cannot produce: a **non-tombstone concurrent field edit** (two devices keep the same record LIVE and edit the same field). `merge_record`'s tombstone arm returns an empty collision set ([core/src/vault/conflict.rs:326](core/src/vault/conflict.rs#L326)), so a veto and a field collision can't coexist on the same record. The classification gate in `sync_pass_inspect` keys **only on `draft.vetoes`** ([cli/src/pipeline/passes.rs:234](cli/src/pipeline/passes.rs#L234)), so a zero-veto + non-empty-collision merge is `MergedClean` with the collisions carried as informational metadata. That single fixture is asserted at two layers:
- **#192** at `prepare_merge`: `draft.vetoes` empty (the clean-merge discriminator) **AND** `draft.collisions` populated with the exact `record_id` + field name. Previously verified only by compilation.
- **#190** at the bridge `sync_vault_in`: `MergedClean` + state advanced/persisted + block rewritten on disk — the one dispatch seam the existing bridge tests (`AppliedAutomatically` / lock-held / wrong-password) don't exercise.

**Design (settled with the user via options).** For #190 the bridge crate has **no** divergence-staging machinery (only flat golden-vault copy); the ~250-line crypto staging lives in `cli/tests`. Options weighed: (A) committed binary fixture mirroring the existing #187 `sync_conflict_fixture` precedent, (B) a `secretary-cli` `test-support` feature, (C) duplicate the staging. **Chose (A).** Rationale: (B) reintroduces feature-unification reasoning into the exact binding crates #189 *just* hardened and moves fixture-*forging* crypto into a shipped lib; the committed fixture's only real cost — regeneration on format change — is near-moot because the on-disk format is **frozen for v1**. (C) is the duplication #190 was deferred to avoid.

**Mechanics:**
- Refactor `stage_concurrent_veto_vault` → parameterized `stage_concurrent_vault_with_sibling(sibling_records)` + two thin wrappers (`stage_concurrent_veto_vault` / `stage_concurrent_collision_vault`); the sibling record is the only varying axis. Renamed `VETO_RECORD_UUID` → `CONFLICT_RECORD_UUID` (shared by both fixtures). The 5 veto-path tests are behaviorally unchanged (all green).
- New `#[ignore] generate_sync_collision_fixture` generator (mirrors `generate_sync_conflict_fixture`). **Key difference:** it self-validates with the **non-writing** `sync_once` + `prepare_merge` — NOT `sync_pass_inspect`, which on the clean arm commits and would consume the divergence before the copy. It copies the still-pre-merge vault + a seeded concurrent `SyncState` into `core/tests/data/sync_collision_fixture/`.
- Bridge test `sync_vault_in_clean_concurrent_merge_commits_and_advances` consumes that committed fixture → asserts `MergedClean`, `highest_vector_clock_seen` advanced (stronger than `has_state`, which is true regardless since the fixture pre-seeds a state file), and the canonical block bytes changed.

**Branch commits** (off `main` @ `28e48ef7`):
| SHA | What |
|---|---|
| `0feb38d5` | **test(#190,#192)**: refactor + `prepare_merge` collision test + `#[ignore]` generator + committed `sync_collision_fixture/` + bridge `MergedClean` test |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/crdt-test-gaps-190-192
cargo test --release -p secretary-cli --test sync_pass_integration   # 8 pass (incl. new #192 test) + 2 ignored
cargo test --release -p secretary-ffi-bridge --lib sync_vault_in      # 4 pass (incl. new #190 test)
cargo test --release --workspace                                     # all 82 test-result lines ok, 0 failed
cargo clippy --release --workspace --tests -- -D warnings            # clean
cargo fmt --all -- --check                                          # clean
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh  # #189 guard still green
```
- **Non-vacuousness proven:** #192's `vetoes.is_empty()` + `collisions.len()==1` discriminator would fail (to 0) if the fixture silently regressed to a tombstone/dominance shape — independently traced + confirmed in code review.
- **Code review** (pr-review-toolkit code-reviewer) on the full diff: **no issues ≥80 confidence**. It independently verified the refactor preserves the 5 veto-path tests, the generator's non-writing-validation reasoning, `blocks[0]` is unambiguously the divergent block, and the state-advance check is sound. One cosmetic nit (fully-qualified `Unlocker::Password`) fixed.

## (2) What's next
**#190 + #192 done (PR open). Pick a fresh item.** Collision-free candidates (parallel worktrees this session: `.worktrees/d4-browser-autofill` on D.4, `.worktrees/desktop-block-crud-ui`, `.claude/worktrees/hardcore-robinson-373901` — avoid D.4 docs):
- **#92** (docs) — clean up the 28 pre-existing `cargo doc` warnings (14 in `secretary-cli`); `cargo doc -D warnings` is **not** a CI gate today (could add it as teeth). No collision.
- **#183** — reduce positional-arg count on the `rewrite_block_with_recipients` re-key engine. Rust refactor on a crypto-adjacent path — needs care to preserve the hybrid both-halves property.
- **SecretaryApp Swift 6 follow-up** (optional, no issue) — the XcodeGen `ios/SecretaryApp/` app target was out of #231's "SwiftPM targets" scope and still builds in Swift 5 mode; promoting it extends the strict-concurrency bar to the app shell.
- **#290** — allowlist the 3 D.4 freshness false-positives in `threat-model.md`. **Still collision-risky** while `.worktrees/d4-browser-autofill` is active — coordinate before touching D.4 docs.

**Acceptance criteria template:** a failing test/build reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #269 / #255 / #247 / #246 / #234 / #232 / #224 / #218 / #186 / #183 / #92. (#190 + #192 closing via this PR.)

## (3) Open decisions and risks
- **Committed fixture over a `test-support` feature (resolved with user).** Detailed rationale in §1 — the deciding factors were the frozen on-disk format (regeneration cost ≈ 0) and not re-widening the #189-hardened binding-crate feature boundary. The clean-but-heavier alternative (a dedicated dev-only `secretary-test-support` crate) was noted and declined as over-engineering for two low-priority tests.
- **The generator must validate with `sync_once` + `prepare_merge`, never `sync_pass_inspect`.** On the clean-collision path `sync_pass_inspect` COMMITS (rewrites the block, advances state) and would consume the divergence before the copy — leaving a committed fixture that no longer diverges. This is load-bearing; the generator's doc comment spells it out.
- **`sync_collision_fixture` doubles the #187 regeneration surface — but only theoretically.** Both fixtures only need regenerating if `golden_vault_001` or the block/manifest format changes, and the format is frozen for v1. Each is reproduced byte-faithfully by its `#[ignore]` generator (deterministic seeds/nonces).
- **README / ROADMAP / CLAUDE.md unchanged (deliberate).** No public interface / behavior / on-disk-format / milestone change — matches the #189/#252/#231 pure-test/hardening precedent. The README sync-surface row already names `CollisionDto` (the binding surface predates this; we only added tests). The analogous #187 generator command is not documented in CLAUDE.md, so the #190 one isn't either (consistency).
- **Risk:** none to product behavior — only new tests + a committed test fixture. Worst case is a future format change silently invalidating the fixture; mitigated by the self-validating generator (regenerate + human-review the scoped diff).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree can be removed:
#   git worktree remove .worktrees/crdt-test-gaps-190-192 && git branch -D feature/crdt-test-gaps-190-192
git worktree list && git status -s

# Re-verify this session's tests (from the worktree if the PR is still open):
cd .worktrees/crdt-test-gaps-190-192
cargo test --release -p secretary-cli --test sync_pass_integration
cargo test --release -p secretary-ffi-bridge --lib sync_vault_in
# Regenerate the committed fixture only after an intentional format change (human-review the scoped diff):
#   cargo test --release -p secretary-cli --test sync_pass_integration -- --ignored generate_sync_collision_fixture --nocapture
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`28e48ef7`); at handoff time `origin/main` is an ancestor of `HEAD` (verified), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `feature/crdt-test-gaps-190-192` (`0feb38d5` tests+fixture + handoff). Worktree `.worktrees/crdt-test-gaps-190-192`.
- **Acceptance:** full workspace green (82/82 result lines ok); new #192 `prepare_merge` collision test + new #190 bridge `MergedClean` test pass; clippy `-D warnings` clean; fmt clean; #189 lean-binding guard still green; code review clean (one cosmetic nit fixed). No `core`/FFI-surface/on-disk-format/`conformance.py`/manifest touched → all language gates unaffected. `#190` + `#192` close via the PR.
- **README.md / ROADMAP.md / CLAUDE.md:** unchanged (rationale in §3).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-27-crdt-collision-test-gaps-190-192-shipped.md`.
