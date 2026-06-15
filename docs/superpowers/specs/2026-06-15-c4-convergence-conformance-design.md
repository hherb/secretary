# C.4 — Cross-Device Convergence Conformance (design)

**Date:** 2026-06-15
**Phase:** Sub-project C (sync), milestone C.4
**Status:** approved design — ready for implementation plan
**Scope:** additive Rust test code only. No `core/src` change, no FFI, no on-disk
format / crypto / CRDT change.

## 1. Problem & goal

Sub-project C's sync engine is mature: `core/src/sync/{once,prepare,commit}.rs`
implements the three-step pass (`sync_once` → `prepare_merge` →
`commit_with_decisions`) over the CRDT merge primitives in
`core/src/vault/conflict.rs`. The merge *function* is proven commutative,
associative, and idempotent by record-level proptests, and several KATs
(`sync_kat.json`, `conflict_kat.json`, `sync_pass_kat`) pin its classification
and per-block math.

**The gap.** Every existing sync test constructs divergence *synthetically* —
the `sync_helpers` primitives (`fresh_vault_two_concurrent_manifests`,
`fresh_vault_two_concurrent_blocks`, `rewrite_block_with_records`) hand-write
two conflicting manifests/blocks and then test *one* device's reaction to a
single `sync_once`. No test runs **two real device identities**, each through
the **real edit + full sync round-trip**, against **one shared folder**, and
proves they **converge** to the same logical state — independent of who synced
first.

**C.4's goal.** Prove, end-to-end at the folder + sync-pass level, that two
independently-editing clients sharing a folder converge. This validates the
*orchestration* (real `save_block` writes, `sync_once`/`prepare`/`commit`,
atomic writes, manifest signing, per-device `SyncState` advancement) — not just
the pure merge function the record-level proptests already cover.

## 2. The "device" model

This is one user's vault replicated across that user's own devices. The two
devices therefore **share one `UnlockedIdentity`** (same IBK, same Ed25519 ∧
ML-DSA signing keys — both produce valid manifest signatures) and differ only
in:

- a distinct **`device_uuid`** — their vector-clock identity, stamped into every
  edit, and
- a distinct **`SyncState` directory** — each device's independently-persisted
  "highest vector clock seen" + vault UUID.

The **shared folder** is the single on-disk vault both devices sync through.

The edit seam already exists: `vault::orchestrators::save_block` takes
`device_uuid: [u8; 16]` and `now_ms: u64` as explicit parameters. The harness
gives each `Device` its own `device_uuid` and passes a controlled `now_ms`, so
no `core` API change is needed and C.4 stays purely additive.

## 3. What "convergence" means here (and what it does NOT)

Convergence is a **logical** property, asserted on decrypted state — *not* a
byte-level comparison of ciphertext. Three reasons byte-identity is the wrong
assertion:

1. Each device re-encrypts with fresh random nonces; ML-DSA-65 signing is
   randomized. Identical plaintext therefore yields different bytes.
2. After convergence there is *one* shared folder — both devices point at the
   same physical merged files, so there is no "device A copy vs device B copy"
   to diff.
3. Across the two sync *orderings* (run in independent temp folders), ciphertext
   differs by construction (random nonces), so only the decrypted logical state
   is comparable.

Forcing byte-identity would require deterministic keys/nonces, which is both
unrealistic and trips the project's "tests use random crypto values, not
hardcoded" rule. Instead convergence is **self-checking**: the two devices (and
the two orderings) check *each other*, so no frozen golden vault is needed and
identities are generated fresh from `OsRng` each run.

### The convergence contract (three assertions)

For each scenario, after both devices have fully synced:

1. **Logical equality.** `decrypt_state()` on each device yields identical
   records — `record_uuid`, field names + values, `tombstone` flag,
   `last_mod_ms` — and identical vector clocks, matching the scenario's
   `expected` outcome.
2. **Quiescence.** A follow-up `sync_once` on *each* device returns
   `NothingToDo` (both `SyncState`s advanced to the merged LUB; no residual
   pending divergence).
3. **Order-independence.** The scenario is run twice in independent temp folders
   — once with device A syncing first, once with device B first — and both runs
   produce the same decrypted logical state.

## 4. Scenario set (v1)

Four named scenarios, one per distinct merge arm. Each is a small data-driven
definition: an edit script, a veto policy, and the expected converged logical
outcome.

| # | Scenario | Setup | Merge arm | Expected converged state |
|---|----------|-------|-----------|--------------------------|
| 1 | **auto-apply** | A edits record X; B is behind, no local edit | `IncomingDominates` → `AppliedAutomatically` | B adopts A's record X; clock = A's |
| 2 | **concurrent disjoint** | A edits X.field1; B concurrently edits X.field2 | `Concurrent`, no field collision → silent auto-merge | both fields present; clock = LUB(A,B) |
| 3 | **LWW collision** | A and B both edit X's **same** field, different values | `Concurrent`, field collision → LWW by `last_mod_ms` | later-`now_ms` value wins; collision surfaced; clock = LUB |
| 4 | **tombstone-veto** | A edits X; B tombstones X concurrently | `Concurrent` → `ConflictsPending` veto | asserted for **both** decisions: keep-mine (X survives, edited) **and** accept-delete (X stays tombstoned) |

Notes:

- Scenario 3 controls LWW ordering through the explicit `now_ms` parameter the
  sync/save APIs already accept — deterministic ordering **without**
  deterministic crypto.
- Scenario 4 runs the convergence contract twice, once per veto decision, so
  both arms of the death-clock tie-break are proven.

## 5. Module structure & file discipline

```
core/tests/convergence.rs               — integration test: 4 scenarios × the contract
core/tests/convergence_helpers/mod.rs   — reusable harness
```

Harness surface (public fns / types):

- `Device::new(shared_identity, device_uuid, folder)` with `edit(...)`,
  `sync(veto_policy)`, `decrypt_state()` — every op goes through the real public
  API (`save_block`, `sync_once`/`prepare_merge`/`commit_with_decisions`,
  `open_vault`); no synthetic block rewriting.
- `run_scenario(scenario, order)` → drives both devices in the given sync order,
  returns the final decrypted state.
- `assert_converged(a, b, expected)` → logical-equality + quiescence assertions;
  order-independence is asserted by the caller comparing the two orders' results.

If `convergence_helpers/mod.rs` grows past ~400 lines it splits by concern
behind `mod.rs` (`device.rs` = the handle + ops; `scenario.rs` = scenario
definitions + the run-both-orderings driver; `assert.rs` = the contract
assertions), per the project's 500-line discipline. The harness reuses existing
`sync_helpers` primitives (e.g. `decrypt_block_using_open`, block-path helpers)
where they already fit rather than duplicating them.

## 6. Testing approach (TDD)

This is test code, so TDD applies to the harness itself — build it
scenario-by-scenario, each red→green:

1. **Scenario 1 (auto-apply)** first — the simplest arm forces the
   `Device`/`edit`/`sync`/`decrypt_state` plumbing into existence.
2. **Scenario 2 (concurrent disjoint)** — adds the `Concurrent` auto-merge path.
3. **Scenario 3 (LWW collision)** — adds `now_ms`-ordered field collision.
4. **Scenario 4 (tombstone-veto)** — adds the `prepare`/`commit` veto path, both
   decisions.

Each scenario lands as its own commit (one-issue-per-commit). Acceptance gate:

```
cargo test --release --workspace --test convergence        # green
cargo clippy --release --workspace --tests -- -D warnings   # clean
```

## 7. Out of scope (YAGNI — recorded for the handoff)

- **Python clean-room mirror** of these convergence scenarios (the "Rust +
  Python clean-room" conformance rung). Scenario definitions stay as plain Rust
  data so a future slice *could* serialize them to a KAT for cross-language
  replay — but that format is not built now.
- **3+ device topologies.** v1 is exactly two devices.
- **Property-based folder convergence** (random edit/sync interleavings). The
  record-level merge proptests already cover the algebraic properties; folder
  convergence here is the canonical named-scenario set, not a generator.

## 8. Risks

- **Vector-clock device-id stamping.** The harness assumes `save_block` is the
  only place a device ticks the clock for an edit; if any other write path
  stamps a device id, the two-device model must route through it too. To verify
  at plan time by tracing every `tick_clock` call site.
- **Veto API shape.** Scenario 4 depends on `prepare_merge` surfacing the
  tombstone-veto and `commit_with_decisions` accepting a keep-local/accept-peer
  decision per record. Confirm the exact `VetoDecision` shape against
  `core/src/sync/prepare.rs` + `commit/` during planning.
- **`now_ms` monotonicity expectations.** Some sync paths reject disk older than
  seen (rollback). The scenario scripts must advance `now_ms` consistently so a
  legitimate concurrent edit is never misclassified as a rollback.
