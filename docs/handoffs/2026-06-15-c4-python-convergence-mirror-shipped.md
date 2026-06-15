# NEXT_SESSION.md — C.4 Python clean-room convergence mirror ✅

**Session date:** 2026-06-15. Flow: `/nextsession` → confirmed C.4 Rust convergence (#235, `226e6a2`) was squash-merged to `main` + removed its stale worktree/branch → chose **C.4 Python clean-room convergence mirror** → brainstormed (veto-scope + fixture-source decisions) → spec → 5-task TDD plan → **subagent-driven execution** (fresh implementer + two-stage spec/quality review per task; final whole-branch review on Opus = **READY TO MERGE**) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c4-python-convergence-mirror`. PR: see §4. The stdlib-only clean-room verifier (`core/tests/python/conformance.py`) now **replays the four C.4 convergence scenarios in both merge orderings** and asserts they converge to identical logical state (order-independence) **and** match a Rust-generated golden — extending the repo's core "docs alone are sufficient" property from single-vault decryption + pairwise merge to **two-client convergence**. **Additive test-only — no `core/src`, FFI, on-disk-format, crypto, CRDT, or existing-KAT change.** `git diff main...HEAD --name-only` touches only `core/tests/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty).

## (1) What we shipped this session

**The central idea:** convergence is *self-checking and triple-derived*. The committed golden is produced by the real Rust `merge_block`; the **Rust always-run guard** re-derives both orderings via real `merge_block` and asserts equality + golden-match; the **Python clean-room section** independently re-merges from the spec-derived engine (`py_merge_block`, no `secretary-core` import) and asserts the same. A wrong golden cannot pass all three. Convergence is asserted on the **clock-free block** (`block_to_json` / `_normalise_block`) — the only legitimate cross-ordering difference is the merger's own clock tick, exactly as the Rust harness's `LogicalRecord` excludes clocks. The four scenarios stay as plain data so each ordering exercises *asymmetric* merge paths (e.g. `tombstone_accept` hits `LocalTombstoneWins` in AB and `RemoteTombstoneWins` in BA), so order-independence is a genuine CRDT-commutativity result, not an artifact of identical construction.

| Layer | What landed | Commit (pre-squash) |
|---|---|---|
| **Spec + plan** | design doc + 5-task TDD plan | `f86fa43` `3c77592` |
| **Task 1 — serializers** | `Record`/`BlockPlaintext`/clock → JSON serializers (inverse of `conflict.rs` parsers) + scenario builders + `unknown_to_json` fail-loud extension point | `b3bfa86` `d4aad61` |
| **Task 2 — generator + guard** | 4-scenario table, `merge_ordering`, `#[ignore] generate_convergence_kat`, always-run `convergence_kat_replays_are_order_independent` guard, the generated fixture | `2634c60` `3ff8d81` |
| **Task 3 — Python section** | `section_convergence_kat()` reusing `py_merge_block`/`_normalise_block`; both orderings; order-independence + golden-match | `2286552` `e4804d8` |
| **Task 4 — docs** | README + ROADMAP: Python clean-room convergence mirror ✅ | `edc9cd3` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `226e6a2`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live)
- `core/tests/convergence_kat_gen.rs` — builders + serializers + 4-scenario table + `merge_ordering` + `#[ignore]` generator + always-run guard.
- `core/tests/data/convergence_kat.json` — the 4 scenario vectors (two concurrent device sides + golden converged block; golden carries **no** vector clock by design).
- `core/tests/python/conformance.py` — new `section_convergence_kat()` / `_converged_block()` / `convergence_kat_path()`, wired into `main()`'s aggregate pass/fail gate.

### The four scenarios (all single-record on record X; CRDT-pure)
1. **auto_apply** — A live, B behind (empty) → dominated clock (`IncomingDominates`/`IncomingDominated`, **not** Concurrent); converges to A's record.
2. **concurrent_disjoint** — A edits f1, B edits f2 → field union; order-independent.
3. **lww_collision** — A and B edit field `k`, later `last_mod` (101>100) wins → `bob-wins`.
4. **tombstone_accept** — B tombstones X with death clock 200 > A's edit 100 → death clock auto-resolves to tombstoned in both orderings.

### Acceptance (green — full gauntlet this session)
```
cargo test --release --workspace --test convergence_kat_gen                       → 2 passed, 1 ignored (generator)
cargo test --release --workspace                                                  → all suites pass, 0 failures
cargo clippy --release --workspace --tests -- -D warnings                         → clean
cargo fmt --all --check                                                           → clean
uv run core/tests/python/conformance.py                                           → all sections PASS incl. 4 Section C scenarios
uv run core/tests/python/spec_test_name_freshness.py                              → 101 resolved, 0 unresolved, 0 flagged
git diff main...HEAD --name-only | grep -vE '^(core/tests/|docs/|README.md|ROADMAP.md)'                                            → empty
git diff main...HEAD --name-only | grep -E 'core/src|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data/(conflict_kat|conformance_kat)'  → empty
```
Mutation check (done in Task 3): corrupting the `lww_collision` golden → `FAIL … converged block != Rust golden`, exit 1; fixture reverted. Fixture regenerates **byte-for-byte** from the generator (final review verified).

## (2) What's next — candidate directions

- **C.4 next rung — KeepLocal veto in the clean-room (the one acknowledged gap).** This slice deliberately covered only the **CRDT-pure** convergence (scenarios 1–3 + the `AcceptTombstone`/death-clock arm). The Rust harness's `KeepLocal` veto arm is **out of scope** because the veto (`prepare_merge` veto pass / `commit_with_decisions` / `MergeDecision`) lives in `core/src/sync/` and is **not in the frozen spec docs**. The user explicitly flagged: "eventually we have to catch up with features (such as the veto)." **Acceptance for that rung:** first promote the veto semantics into `docs/` (so the clean-room can implement them from the spec), then mirror the `KeepLocal` arm — asserting per-replica override convergence *within an ordering* (NOT order-independence, which would be false; see §3).
- **C.3 Android** — folder-change detection + sync UI (SAF + `WorkManager`); greenfield platform scaffold mirroring the iOS pure-core/real-adapter split over the same uniffi sync surface.
- **3+ device topologies** — extend the convergence harness/fixture beyond two devices (N-way). Note the Rust harness's `reconcile` conflict-copy suffix keys on `device_uuid[0]` only — widen if devices collide in byte 0.
- **Durability / partition / clock-skew scenarios** — power-cut mid-commit, partitioned reconciles, adversarial clock-skew (the original C.4 sketch's operational failure modes; this and #235 prove *logical* convergence + order-independence, not those).
- **iOS biometric re-auth before a write** — self-contained follow-up over existing B.3 DeviceUnlock infra.
- Rust-core backlog: **#193 / #192 / #190 / #189**.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session — the veto gap is documented design scope, not a bug.)

## (3) Open decisions and risks

- **Veto is intentionally out of clean-room scope (the session's scope decision).** The clean-room contract is "implementable from `docs/` alone." The veto is undocumented sync-orchestration in `core/src/sync/`, so mirroring it would couple `conformance.py` to `core/src` internals and weaken the property. Documented in three places: design doc §2, the `section_convergence_kat` docstring, and ROADMAP. If you add the veto later, **do NOT assert order-independence for `KeepLocal`** — it is a per-replica user override that converges *within* an ordering but is intentionally order-dependent (only the replica offered the veto can override the death clock; see #235's handoff §3).
- **Convergence is logical, not byte-level (deliberate).** The golden carries **no vector clock** — the merged clock differs by which device was the merger (the merge tick). Convergence is asserted on records (`block_to_json` / `_normalise_block`), mirroring the Rust `LogicalRecord`. If you add a new mergeable `Record` field, ensure both the Rust serializer (`record_to_json`) and the Python `_normalise_block` include it, or a divergence there could be missed.
- **Scenarios are single-record (record X) by design** to avoid record-list-ordering concerns (Rust `Vec` equality is order-dependent; `py_merge_block` sorts records by uuid). A future multi-record scenario must ensure both sides emit records in a stable (uuid-sorted) order.
- **Field order parity is load-bearing.** The golden's field order comes from a `BTreeMap` (sorted by name); `py_merge_record` builds merged fields via `sorted(set(...))`. These must stay in lockstep — if either changes its field ordering, the golden-match comparison (`_normalise_block` compares fields as an ordered list) would spuriously fail.
- **`unknown_to_json` is a fail-loud stub.** Scenarios carry no forward-compat `unknown` keys; the serializer asserts empty. The first scenario that needs unknown keys must implement the hex-CBOR mapping there (single documented extension point) rather than bypassing the assert.
- **No production-code change.** Purely additive test code; it *characterizes* and cross-checks existing merge behavior.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/c4-python-convergence-mirror

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c4-python-convergence-mirror && git branch -D feature/c4-python-convergence-mirror
git worktree prune && git worktree list

# 3) Next direction (veto rung, C.3 Android, or N-device): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/c4-python-convergence-mirror
cargo test --release --workspace --test convergence_kat_gen     # 2 passed, 1 ignored
cargo test --release --workspace                                # whole suite
cargo clippy --release --workspace --tests -- -D warnings       # clean
uv run core/tests/python/conformance.py                         # all PASS incl. Section C
git diff main...HEAD --name-only | grep -vE '^(core/tests/|docs/|README.md|ROADMAP.md)'   # expect empty

# Regenerate the fixture after an intentional merge-semantics change (human-review the diff):
cargo test --release --workspace -- --ignored generate_convergence_kat --nocapture
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `226e6a2` == current `origin/main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `226e6a2`; `feature/c4-python-convergence-mirror` carries spec + plan + serializers/builders + generator + always-run guard + fixture + Python section + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — see §1. No `core`-format / crypto / CRDT / existing-KAT change.
- **Process note:** subagent-driven (fresh implementer + two-stage spec/quality review per task; final whole-branch review on Opus = **READY TO MERGE**, no Critical/Important issues, adversarial divergence attempt failed). Reviews caught + fixed real items each task — the `unknown_to_json` extension-point consolidation (T1), `merge_ordering`/`auto_apply` comment precision (T2), and a redundant `# noqa: BLE001` made consistent with `section4_conflict_kat` (T3).
- **README.md / ROADMAP.md:** updated — C.4 Python clean-room convergence mirror ✅.
- **NEXT_SESSION.md:** symlink retargeted to this file.
