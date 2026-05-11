# NEXT_SESSION.md

**Session date:** 2026-05-11 (B.5 design + implementation plan session on `feat/ffi-b5-trash-restore-block`)
**Status:** Spec and plan committed; no implementation yet. Brainstorming → spec → plan workflow complete. Next session executes Task 1 of the plan and onwards.

## (1) What we shipped this session

Three commits on `feat/ffi-b5-trash-restore-block`:

| Commit | Type | What landed |
|---|---|---|
| `11dde89` | spec | Approved design doc [`docs/superpowers/specs/2026-05-11-ffi-b5-trash-restore-block-design.md`](docs/superpowers/specs/2026-05-11-ffi-b5-trash-restore-block-design.md) (470 lines). 6 architectural decisions settled in brainstorming (scope = trash + restore both; multi-copy restore policy = newest + purge older; live-collision = reject with `BlockUuidAlreadyLive`; full decrypt + hybrid-verify on restore; recipient resolution via `contacts/*.card` scan; per-orchestrator module shape mirroring `bridge/share/`). 3 new `core::vault::VaultError` variants — `BlockUuidAlreadyLive`, `BlockNotInTrash`, `RestoreVerificationFailed` — trigger compile errors at 3 mapper sites (issue #40 tripwire firing as designed). New `docs/vault-format.md` §7.1 sub-section verbatim included in the spec doc. **Spec self-review caught a real correctness issue inline**: the original Section 4.2 step 8 assumed the block file's recipient table carries `contact_uuid`s, but it's keyed by `recipient_fingerprint` — fixed before commit by adding a contacts/-scanning sub-step and reordering so the failure path leaves the trash file untouched. |
| `2278439` | plan | Step-by-step implementation plan [`docs/superpowers/plans/2026-05-11-ffi-b5-trash-restore-block.md`](docs/superpowers/plans/2026-05-11-ffi-b5-trash-restore-block.md) (2451 lines). Nine TDD-shaped tasks, each ending in one logical commit: atomic error-variant addition across all 4 layers (Task 1) → core `trash_block` + §7 grammar tightening (Task 2) → core `restore_block` + §7.1 spec section (Task 3) → bridge trash + restore modules (Tasks 4-5) → PyO3 layer (Task 6) → uniffi UDL + namespace fns (Task 7) → Swift + Kotlin smoke runner additions (Task 8) → workspace verification + README/ROADMAP/NEXT_SESSION docs pass (Task 9). |
| `4b828bf` | chore | Salvaged the prior session's untracked verification handoff (`docs/handoffs/2026-05-11-verify-smoke-runners-macos.md`) onto this branch so the historical record rides inside the PR rather than slipping through main uncommitted. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **603 passed + 9 ignored, 0 failed** (baseline unchanged — no code shipped this session). |
| `cargo clippy --release --workspace -- -D warnings` | clean (baseline). |
| `cargo fmt --all -- --check` | OK (baseline). |
| `uv run core/tests/python/conformance.py` | PASS (baseline). |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS (baseline). |

This session intentionally did not run any verification heavier than the cargo/cargo-fmt/cargo-clippy/conformance/freshness gate — there was nothing to verify beyond "branch state matches main + spec/plan docs added".

## (2) What's next — execute the plan

**Workflow:** `superpowers:subagent-driven-development` recommended. One subagent per task; review the diff between tasks; nine commits land in order. Aligns with the user's "stay in the inner loop — learning over throughput" feedback and "fix every review issue before merging" discipline (between-task review catches issues at the boundary they were introduced).

Acceptance criteria for the full B.5 PR (derived from the plan's §9 verification gauntlet):

- `cargo test --release --workspace --no-fail-fast` → 630-635 passed, 0 failed, 9 ignored (was 603).
- `cargo clippy --release --workspace -- -D warnings` → clean.
- `cargo fmt --all -- --check` → OK.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS.
- `uv run --directory ffi/secretary-ffi-py pytest` → 67 passed (was 57; +10).
- `ffi/secretary-ffi-uniffi/tests/swift/run.sh` → 34/34 PASS (was 30; +4).
- `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` → 35/35 PASS (was 31; +4).

Per-task acceptance criteria are inline in the plan doc as the "Expected: ..." annotations after each `cargo test` / `pytest` / smoke-runner invocation.

## (3) Open decisions and risks

### Design-side decisions left explicit in the spec (already settled)

- Restore-and-purge for the multi-copy case (chosen over reject-on-ambiguity and over keep-old-versions). Users can't currently recover an older trashed version through the retention window; a future `list_trashed_versions(uuid)` API can lift this.
- Restore halts BEFORE filesystem mutation on every failure mode except step 7's rename. The ordering rationale paragraph in §4.2 of the spec is normative.

### Process-side risks for the implementation session

- **`error/vault.rs` will grow another ~60 LOC** during Task 1 (3 new `From` arms + 5 pin tests + 2 new variants). File is currently 524 LOC; after B.5 it will be ~584. Per the project memory and the B.4d posture, the per-variant explicit matching is intrinsic; splitting tests would over-deepen the directory. **Decision deferred until B.5 lands, then re-evaluate as one cleanup pass.** Issue #44 already tracks this.
- **PyO3 `ContactCard` boundary**: the share-then-trash-then-restore round-trip pytest in Task 6 requires a `mint_recipient` fixture that creates a second `ContactCard` on a fresh identity, writes it to `contacts/`, and feeds it to `share_block`. The existing pytest helpers may not expose card-minting directly — if they don't, the fixture has to call into core via the bridge's `create_vault` path on a sibling tempdir. Estimate: ~20 LOC of fixture plumbing. Mention it explicitly when picking up Task 6 so it doesn't surprise the next agent.
- **Two manifest snapshots use `snapshot_for_save_block`**: this accessor's name was chosen for save_block but its 5-tuple shape is exactly what trash/restore also need. The plan reuses it as-is; a future cleanup pass could rename it to `snapshot_for_mutating_orchestrator`. Not in scope this PR.
- **`.claude/worktrees/` directory exists** — git status flags it as untracked (`chore+b4d-deferred-cleanup` from a prior session). Not touched this session. Safe to leave or `rm -rf` if you want a clean tree. Same posture as the prior session.

### Issues still open from PR #46 (carried forward)

- **Stale `signer_secret_keys()` accessor on `UnlockedIdentity`** — PR #46's #42 fix removed its only caller. Accessor still exists with `#[allow(dead_code)]`. *No GitHub issue filed yet.* Could be closed in a cleanup pass after B.5.
- **Issue #38 still open** — `share_block` and `save_block` proptests pinned at 16 cases. B.5's `trash_restore_round_trip_preserves_plaintext` proptest also pins at 16 per the same Argon2id cost rationale. The umbrella fix (shared writable-vault fixture) waits for Sub-project C-era infrastructure.
- **Issue #44 still open** — `error/vault.rs` 500-line policy threshold; see §(3) above for the B.5 impact and deferred-cleanup posture.
- **Issue #45 still open** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. Forward-compat with Sub-project C; revisit when C's surface stabilizes.
- **Issue #37 still open** — design discipline reminder for Sub-project C: preserve the manifest-only-read invariant for the sync layer.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout feat/ffi-b5-trash-restore-block
git status --short                                     # expect: clean (or just .claude/worktrees/ untracked)
git log --oneline -3
# Expect:
#   4b828bf chore: salvage prior session's verification handoff onto B.5 branch
#   2278439 plan(ffi-b5): step-by-step implementation plan for trash_block / restore_block
#   11dde89 spec(ffi-b5): approved design for trash_block / restore_block lifecycle pair

# Verify baseline (should match prior session's numbers exactly — no code shipped this session):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
# Expect: TOTAL: 603 passed; 0 failed; 9 ignored

cargo clippy --release --workspace -- -D warnings      # Expect: clean
cargo fmt --all -- --check                              # Expect: OK
uv run core/tests/python/conformance.py                 # Expect: PASS
uv run core/tests/python/spec_test_name_freshness.py    # Expect: PASS

# Begin implementation — Task 1 of the plan (atomic error-variant addition across 4 layers):
#
#   cat docs/superpowers/plans/2026-05-11-ffi-b5-trash-restore-block.md | less
#
# Recommended workflow: superpowers:subagent-driven-development.
# Dispatch one fresh subagent per task with the plan as input; review the
# diff between tasks; nine commits land in order; final commit is the
# README/ROADMAP/NEXT_SESSION docs pass (Task 9) and the gh pr create
# command lives inside Task 9 step 9.7.
```

---

## Closing inventory

- **Branch:** `feat/ffi-b5-trash-restore-block` (created this session; 3 commits ahead of main).
- **Total commits this session:** 3 (`11dde89` spec, `2278439` plan, `4b828bf` chore).
- **Workspace tests:** 603 + 9 ignored (unchanged from prior session — no code shipped).
- **README / ROADMAP:** unchanged (test counts haven't moved; B.5 isn't shipped yet — Task 9.2/9.3 of the plan covers the ship-time README/ROADMAP delta).
- **Files modified:** [`NEXT_SESSION.md`](NEXT_SESSION.md) (this file).
- **Files created:** [`docs/superpowers/specs/2026-05-11-ffi-b5-trash-restore-block-design.md`](docs/superpowers/specs/2026-05-11-ffi-b5-trash-restore-block-design.md), [`docs/superpowers/plans/2026-05-11-ffi-b5-trash-restore-block.md`](docs/superpowers/plans/2026-05-11-ffi-b5-trash-restore-block.md), [`docs/handoffs/2026-05-11-ffi-b5-design-and-plan.md`](docs/handoffs/2026-05-11-ffi-b5-design-and-plan.md) (this file's frozen archive).
- **Files inherited from prior session:** [`docs/handoffs/2026-05-11-verify-smoke-runners-macos.md`](docs/handoffs/2026-05-11-verify-smoke-runners-macos.md) (committed onto this branch as `4b828bf` for branch-PR ride-along).
