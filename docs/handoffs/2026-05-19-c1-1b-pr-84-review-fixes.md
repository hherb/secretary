# Handoff: 2026-05-19 — C.1.1b PR #84 review fix-ups

**Session date:** 2026-05-19 (review-fix cycle on top of Tasks 1-3)
**Branch:** `feature/c1-1b-sync-merge`
**Status:** three review-fix commits landed on top of the Tasks 1-3 work and pushed to PR #84. Gauntlet green. No PR-state change other than the new commits — the PR remains open against `main` for the rest of the C.1.1b plan (Tasks 4-17).

This is the contemporaneous frozen-in-time handoff. The live equivalent at the time of writing is `NEXT_SESSION.md` on the feature branch; this file is preserved unmodified for historical traceability.

---

## Why this session existed

PR #84 carried the first three tasks of the C.1.1b sync-merge plan (scaffolding: helpers + error variants). A `/review` pass on the open PR surfaced five observations — three actionable in-scope, two deliberately deferred. The actionable items were addressed one-commit-each per the project's `feedback_fix_all_review_issues` rule (no technical debt, no batching). The deferred items are filed below with their rationale.

## Issues raised and disposition

| # | Issue | Disposition | Commit / link |
|---|---|---|---|
| 1 | Track `#[allow(dead_code)]` removal across Tasks 1-3 (BLOCK_NONCE_E/F/G, four new SyncError variants, several helpers) so the final PR carries zero stale markers. | **Fixed in-scope** — added a Task-17 pre-merge checklist item to `NEXT_SESSION.md` enumerating every `#[allow(dead_code)]` that must be cleared before the C.1.1b PR is mergeable. | [`9997fa6`](https://github.com/hherb/secretary/commit/9997fa6) |
| 2 | `core/tests/sync_helpers/mod.rs` duplicates `vault::orchestrators::format_uuid_hyphenated` (13 lines of body copy) because the original is `pub(crate)`. Two formatters for one on-disk filename shape is one too many. | **Fixed in-scope** — promoted the function to `#[doc(hidden)] pub` and re-exported from `vault/mod.rs`, mirroring the established `__test_dispatch` cross-target test-hook pattern in `crate::sync::once`. Test-side copy deleted; `block_file_path` now calls the canonical helper. | [`acc5085`](https://github.com/hherb/secretary/commit/acc5085) |
| 3 | `ChaCha20Rng::from_seed` seed construction in `rewrite_block_with_records` leaves the last 8 bytes zero (the BLOCK_NONCE_* constants are 24-byte AEAD nonces being used as 32-byte seeds). Not a bug — distinct nonces in the first 24 bytes yield distinct seeds — but worth a comment so a future "harden it by randomizing the tail" change doesn't break the determinism the `distinct_seeds_produce_distinct_ciphertexts` invariant depends on. | **Fixed in-scope** — added a comment block at the seed-construction site explaining the rationale and warning against the "obvious-looking but wrong" fix. | [`7633deb`](https://github.com/hherb/secretary/commit/7633deb) |
| 4 | `rewrite_block_with_records` opens the vault and the helper test then opens it again — two Argon2id-at-V1-default runs (~2-3s each in release). Acceptable for two tests; could become a hotspot if Task 15's property tests multiply fixtures. | **Deferred — preventive advice, not a defect.** Not file-worthy as a GitHub issue because the current cost is acceptable. Re-evaluated at Task 15 when proptest case counts are set; if `prepare_merge` shows up in property-test hotpaths the implementer's-call decision in `NEXT_SESSION.md` §3 (Path A vs Path B for owner-card caching) covers the same surface. | — |
| 5 | When Task 4 wires `verify_block_fingerprints` into `open_vault`, `docs/vault-format.md` (or §10) MUST be updated in the same commit per CLAUDE.md "Spec is normative". | **Deferred to Task 4** — the variant added in Task 3 has no observable behavior yet; the spec update belongs in the commit that makes the check observable. Already implicit in the plan's Task 4 acceptance criteria; not file-worthy as a separate issue. | — |

## What landed

Three task commits + one baton + one main-side sync.

| # | Commit SHA | Subject |
|---|---|---|
| 1 | [`7633deb`](https://github.com/hherb/secretary/commit/7633deb) | docs(sync-helpers): annotate ChaCha20Rng seed-zero-padding rationale |
| 2 | [`acc5085`](https://github.com/hherb/secretary/commit/acc5085) | refactor(vault): expose format_uuid_hyphenated as #[doc(hidden)] pub |
| 3 | [`9997fa6`](https://github.com/hherb/secretary/commit/9997fa6) | docs(c1-1b): NEXT_SESSION.md baton — record two PR-review fix-ups |
| — | `777e150` (on main) | docs: sync NEXT_SESSION.md baton on main with feature/c1-1b-sync-merge |

### Verification at session close (on the feature branch)

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **724 passed + 10 ignored, 0 failed** (unchanged from pre-review state; the fixes are non-test refactors). |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean. |
| `cargo fmt --all -- --check` | OK. |
| `uv run core/tests/python/conformance.py` | PASS. |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS (96 resolved, 0 unresolved, 2 suppressed by allowlist). |
| `git diff --stat origin/main..feature/c1-1b-sync-merge -- core/` (code-only) | `core/src/vault/mod.rs | 9 +++++++++ `<br/>`core/src/vault/orchestrators.rs | 22 ++++++++++++++++------ `<br/>`core/tests/sync_helpers/mod.rs | 31 +++++++++++++------------------ ` |

## Significant findings

### `#[doc(hidden)] pub` as the established cross-target test-hook pattern

The pattern is already in use for `__test_dispatch` in `crate::sync::once` (re-exported `#[doc(hidden)] pub use` from `crate::sync`). The same shape was right for `format_uuid_hyphenated` — production code, the sync layer, and integration tests now all flow through one formatter, and the `#[doc(hidden)]` keeps the helper out of the rendered public API surface. The memory at `project_secretary_cfg_test_not_propagated` records this pattern for future cross-target hook decisions.

The cost of widening a `pub(crate)` to `pub` (even `#[doc(hidden)]`) is real — downstream crates can technically depend on the helper — but it's the explicit "this is a test hook, not API" signal `#[doc(hidden)]` exists to carry. Worth it when the alternative is keeping two copies of a normative format helper in lock-step manually.

### Seed-padding rationale belongs in source

Issue 3 was caught not by code being wrong but by code looking wrong — a 32-byte seed half-filled from a 24-byte constant invites a future "harden it" change that would break determinism. The fix was a comment block, not a code change. This is consistent with the project's broader stance that the right place for "why this looks weird but is right" is a tight inline comment — not a separate doc, not a PR description that disappears with the merge.

### `#[allow(dead_code)]` is a per-task TDD shim, not a permanent state

Tasks 1-3 deliberately introduced `#[allow(dead_code)]` on constants and helpers whose first real consumers don't land until Tasks 8-13. This is fine inside an in-flight branch — it keeps each per-task commit clippy-clean without forcing tasks into different orderings — but a stale marker at PR-close time would be a real defect (the helper might never have been wired and nobody would know). Adding the Task-17 pre-merge enumeration to `NEXT_SESSION.md` makes the cleanup obligation explicit and grep-able.

## What did NOT happen this session

- **No new Rust feature work.** Tasks 4-17 of the C.1.1b plan remain untouched.
- **No changes to the spec docs** (`docs/crypto-design.md`, `docs/vault-format.md`, `docs/threat-model.md`). The variant added in Task 3 is not yet observable; the spec update belongs in Task 4's commit.
- **No new dependencies.** All three fixes are pure refactors / comments.
- **No new tests.** The fixes are non-test changes; test count is unchanged at 724.
- **No FFI runner re-runs.** The `core/src/vault/{mod,orchestrators}.rs` changes are visibility-only (`pub(crate)` → `#[doc(hidden)] pub`) — no observable behavior change in the bridge or uniffi surface, so the Swift / Kotlin runner state from the Tasks 1-3 session carries over unchanged.

## Resume instructions

The live `NEXT_SESSION.md` baton on the feature branch has the full resume sequence. Short version:

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
cd .worktrees/c1-1b-sync-merge
git status --short                                              # expect clean
git log --oneline -10                                           # last 6 commits: this baton, 9997fa6, acc5085, 7633deb, prior-baton, dcaed3a, ...

# Baseline gauntlet (expect 724 / 0 / 10 on this branch):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"

# Resume Task 4 of the C.1.1b plan:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md
```

Per `feedback_stay_in_inner_loop`, the one-task-one-commit-one-review cadence continues. The next milestone-level handoff snapshot is the Task 4/5 close (when `verify_block_fingerprints` becomes observable in `open_vault`).
