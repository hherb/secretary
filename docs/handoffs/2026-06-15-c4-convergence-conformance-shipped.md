# NEXT_SESSION.md — C.4 cross-device convergence conformance ✅

**Session date:** 2026-06-15. Flow: `/nextsession` → confirmed C.3 slice 3 (#233, iOS sync UI) was squash-merged to `main` (`33a08d3`) + removed its stale worktree/branch → chose **C.4 cross-device convergence conformance** → brainstormed (fidelity + coverage decisions) → spec → 10-task TDD plan → **subagent-driven execution** (fresh implementer + two-stage spec/quality review per task; final whole-branch review on Opus) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c4-convergence-conformance`. PR: see §4. A new Rust integration test proves **two real device identities** (one shared vault identity, distinct `device_uuid`s) editing through a shared folder **converge to identical logical state, order-independent**, driving the **real** `sync_once`/`prepare_merge`/`commit_with_decisions` pipeline (no synthetic block rewriting). **Additive Rust test-only — no `core/src`, FFI, on-disk-format, crypto, or CRDT change** — `git diff main...HEAD --name-only` touches only `core/tests/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty).

## (1) What we shipped this session

**The central idea:** convergence is asserted on **decrypted logical state**, never on ciphertext bytes (random nonces + randomized ML-DSA make bytes differ by construction). The two devices and the two sync orderings check *each other* — so convergence is **self-checking**, with no frozen golden vault. Identities and AEAD nonces come from per-device **deterministic ChaCha20 seeds** (mirroring `save_block.rs`'s fixture convention — reproducible failures, distinct seeds per device so two devices never share a nonce); the "no hardcoded crypto values" property still holds because every nonce/key is drawn from the CSPRNG via `fill_bytes`, never a literal byte array. (An earlier draft of this handoff said "fresh `OsRng`-seeded each run" — that was inaccurate; the harness is deterministic by design, like the `save_block.rs` template it mirrors.) Genuine two-device concurrency is staged via a faithful **cloud-sync reconcile** (one device's files become canonical, the other's become conflict-copy siblings — the exact filenames `ingest_conflict_copies` scans). The conflict-copy holder syncs first (the **merger**: `ConcurrentDetected` → `prepare_merge` → `commit_with_decisions`); the canonical holder syncs second (the **adopter**: `AppliedAutomatically`).

| Layer | What landed | Commit(s) (pre-squash) |
|---|---|---|
| **Spec + plan** | design doc + 10-task TDD plan | `91e95df` `b465b6d` |
| **Task 1 — baseline** | `Baseline` fast-KDF (8 KiB) empty on-disk vault | `3ea2543` `75b22be` |
| **Task 2 — device** | `Device` (working-copy fork + real `save_block` edit/tombstone) | `11437fc` `a6beeff` |
| **Task 3 — reconcile** | cloud-sync `reconcile` → canonical + conflict-copy sibling layout | `164714f` `f9fb26c` |
| **Task 4 — sync drivers** | merger/adopter drivers + quiescence (**load-bearing**: convergence model proven empirically) | `03b8c88` `abedf73` |
| **Task 5 — contract** | `LogicalRecord` secret-free projection + `decrypt_state` + `assert_converged` | `5c23738` `ff09126` |
| **Task 6 — scenario 1** | auto-apply (one editor; the other adopts) | `20517ab` `88c639b` |
| **Task 7 — scenario 2** | concurrent disjoint-field auto-merge + reusable `run_both_edit_ordering` + seeded-baseline helper | `2130fab` `1b03c0a` |
| **Task 8 — scenario 3** | LWW field collision (later value wins) | `90182c6` `8afda01` |
| **Task 9 — scenario 4** | tombstone-veto, both decisions (asymmetry-honest) | `9907952` `ed88ed3` |
| **Task 10 — docs** | README + ROADMAP C.4 ✅ | `1b46665` `5fd4c19` |
| **Final cleanup** | drop task-scaffolding lint allows after suite completion | `5d8501f` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `33a08d3`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live)
- `core/tests/convergence.rs` — the 4 scenario tests (15 test fns) + the `run_both_edit_ordering` order-independence runner.
- `core/tests/convergence_helpers/` — `baseline.rs` (fast vault + `from_folder`), `device.rs` (`Device` + `copy_dir_all`), `reconcile.rs` (cloud-sync conflict-copy layout), `sync_drive.rs` (merger/adopter drivers + `VetoPolicy`), `assert.rs` (`LogicalRecord` + `decrypt_state` + `assert_converged`), `mod.rs`.

### The four scenarios (what each proves)
1. **auto-apply** — A edits, B (behind) adopts → both reach A's record; re-sync is a no-op.
2. **concurrent disjoint** — A edits X.f1, B edits X.f2 → CRDT unions both fields; order-independent.
3. **LWW collision** — A and B edit the same field with different `last_mod` → later value wins; order-independent.
4. **tombstone-veto** — A keeps X live, B tombstones X. **`AcceptTombstone` is order-independent** (death clock wins both ways). **`KeepLocal` is a per-replica user override** that converges *within* an ordering but is **not** order-independent — the veto is offered only to the replica whose sync sees the canonical *live* record about to be deleted (see §3).

### Acceptance (green — full gauntlet this session)
```
cargo test --release --workspace --test convergence                              → 15 passed, 0 failed
cargo test --release --workspace                                                  → all suites pass, 0 failures
cargo clippy --release --workspace --tests -- -D warnings                         → clean
cargo fmt --all --check                                                           → clean
git diff main...HEAD --name-only | grep -vE '^(core/tests/|docs/|README.md|ROADMAP.md)'                            → empty
git diff main...HEAD --name-only | grep -E 'core/src|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'  → empty
```

## (2) What's next — candidate directions

The natural continuations after proving in-process convergence:
- **C.4 next rung — Python clean-room convergence mirror.** Replay these same scenarios in `core/tests/python/conformance.py` (stdlib-only, no Rust imports) and assert identical convergence — the repo's core "docs alone are sufficient" property, extended from single-vault to two-client convergence. **Acceptance:** a `conformance.py` section drives the same 4 scenarios from a committed scenario fixture and asserts the Python merge converges identically to the Rust golden, with no `secretary-core` import. (The Rust scenario definitions were deliberately kept as plain data to enable this.)
- **C.3 Android** — folder-change detection + sync UI on Android (SAF + `WorkManager`); greenfield platform scaffold mirroring the iOS pure-core/real-adapter split over the same uniffi sync surface.
- **3+ device topologies** — extend the harness beyond two devices (N-way convergence).
- **Durability / partition / clock-skew scenarios** — the original C.4 sketch named "no data loss across power-cycle, network-partition, and clock-skew." This slice proves *logical convergence + order-independence*, not those operational failure modes (power-cycle crash-recovery is already characterized by C.1.1b's idempotent recovery; `now_ms` is caller-controlled but not adversarially skewed). Deferred — extend the harness with mid-commit power-cut, partial/partitioned reconciles, and adversarial clock-skew if/when we want C.4 to also cover durability.
- **iOS biometric re-auth before a write** — self-contained follow-up over existing B.3 DeviceUnlock infra.
- Rust-core backlog: **#193 / #192 / #190 / #189**.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session — the one notable finding, the asymmetric tombstone-veto, is *intentional documented behavior* of `prepare.rs`, captured in the scenario-4 test, not a bug.)

## (3) Open decisions and risks

- **The tombstone-veto is asymmetric by design (the session's key finding).** `prepare_merge`'s veto pass (`core/src/sync/prepare.rs` ~L498–510) iterates **only canonical pre-merge records and skips already-tombstoned ones** — so a `RecordTombstoneVeto` fires only when the *live* record is the canonical-on-disk one. When the tombstone is canonical, the death clock auto-resolves to tombstone with **no veto**. Consequence: `AcceptTombstone` converges order-independently (death clock symmetric), but `KeepLocal` is a per-replica user override that overrides the death clock only on the replica offered the veto. The scenario-4 tests reflect this **honestly** (KeepLocal asserts single-ordering convergence + documents why; it does **not** claim order-independence). If you extend veto handling, preserve this honesty — do not write a KeepLocal test that asserts order-independence (it would be false).
- **Convergence is logical, not byte-level (deliberate).** Each device re-encrypts with fresh nonces; after convergence there is one shared folder anyway. `LogicalRecord` projects `record_uuid`, `tombstone`, `tombstoned_at_ms`, `last_mod_ms`, `record_type`, sorted `tags`, and per-field value **digests** (blake3 of plaintext, secret-free). `created_at_ms` is excluded (min-merged → order-independent by construction). The final review could not construct two divergent states that project equal — but if you add a new mergeable `Record` field, **add it to `LogicalRecord`** or convergence could silently miss a divergence there.
- **Harness `save_block` is a whole-record overwrite (not read-modify-write).** `Device::edit_text_field` writes a record containing only the new field, so a single-field edit drops the record's other fields locally *before* any sync. This is why scenario 2's seed field `f0` is absent from the converged result (the disjoint union is still genuinely proven via f1⊎f2). Any future scenario needing a record to retain pre-existing sibling fields across an edit must NOT rely on a single-field edit.
- **`reconcile` conflict-copy suffix keys on `device_uuid[0]` only** (`.sync-conflict-from-device-XX`). Fine while device UUIDs differ in byte 0 (`[0x0A;16]`/`[0x0B;16]`); the assumption is commented. Widen to more bytes if the harness gains devices colliding in byte 0 (e.g. an N-device topology).
- **No production-code change.** This branch is purely additive test code; it does not alter the sync engine, crypto, format, or CRDT. It *characterizes* existing behavior.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/c4-convergence-conformance

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c4-convergence-conformance && git branch -D feature/c4-convergence-conformance
git worktree prune && git worktree list

# 3) Next direction (Python clean-room mirror, or C.3 Android): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/c4-convergence-conformance
cargo test --release --workspace --test convergence                 # 15 tests
cargo test --release --workspace                                    # whole suite
cargo clippy --release --workspace --tests -- -D warnings           # clean
git diff main...HEAD --name-only | grep -vE '^(core/tests/|docs/|README.md|ROADMAP.md)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `33a08d3` == current `origin/main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `33a08d3`; `feature/c4-convergence-conformance` carries spec + plan + the 10-task harness (baseline → device → reconcile → sync-drivers → contract → 4 scenarios) + the final allow-cleanup + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — see §1. No `core`-format / crypto / CRDT change.
- **Process note:** subagent-driven (fresh implementer + combined spec/quality review per task; final whole-branch review on Opus = **READY TO MERGE**, no Critical/Important issues). Reviews caught + fixed real issues each task — notably: the adopter's silent `NothingToDo` fallthrough (made strict, T4); an incomplete `LogicalRecord` projection missing the death clock (T5); a latent password-forwarding trap in `baseline_from_seeded` + missing symmetric field assertions (T7); and the **asymmetric tombstone-veto** investigated and handled honestly (T9). The load-bearing convergence model (merger sees `Concurrent`, adopter auto-applies) was proven empirically at T4 with no model adjustment.
- **README.md / ROADMAP.md:** updated — C.4 convergence conformance ✅.
- **NEXT_SESSION.md:** symlink retargeted to this file.
