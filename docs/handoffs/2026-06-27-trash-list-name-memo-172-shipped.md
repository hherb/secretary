# NEXT_SESSION.md — #172 trash-list name memo ✅ SHIPPED (PR opening)

**Session date:** 2026-06-27 (third session of the day). Started from a clean baton — PR #314 (#92 cargo-doc warning cleanup + workspace `-D warnings` doc gate) had merged to `main` as `d0613622`; removed the merged worktree/branch (`.worktrees/docs-warnings-92` / `feature/docs-warnings-92`; remote already pruned). User picked **#172** (Trash view `list_trashed_blocks` does a full decrypt per trashed block on every open). Executed in project-local worktree `.worktrees/trash-list-memo-172`, branch `feature/trash-list-memo-172`.

**Status:** ✅ **SHIPPED — branch `feature/trash-list-memo-172`, PR opening.** `secretary-ffi-bridge`-only change. **No `core` / on-disk-format / spec / `conformance.py` / KAT-JSON / FFI-surface (uniffi/pyo3/Swift/Kotlin) change; no public-signature change.** `Closes #172` rides in the commit + PR body.

## (1) What we shipped this session

**The hazard (#172).** [`list_trashed_blocks`](../../ffi/secretary-ffi-bridge/src/trash/list.rs) recovered each trashed block's `block_name` by **fully AEAD-decrypting + hybrid-verifying** the newest `trash/<uuid>.cbor.enc.<ts>` file for every entry in `manifest.trash`, every call. AEAD is all-or-nothing, so there's no "decrypt just the name" — the whole block plaintext is decrypted then dropped. Repeat opens/refreshes of the desktop Trash view re-paid the full O(n) decrypt.

**The fix — a self-invalidating in-memory memo on the handle.** `block_uuid → (ts, block_name)` in a new `Mutex<HashMap>` field on `OpenVaultManifest`, keyed by the on-disk `<ts>` filename suffix (already parsed for free by `newest_trash_file`). Hit on `(uuid, ts)` → skip the decrypt; miss → decrypt + cache. Pruned to the live-`manifest.trash` set each call; cleared on `wipe`.

**Why it needs no explicit invalidation:** the `(uuid, ts)` pair *is* the file version. Re-trash writes a strictly-higher `ts` → automatic miss → re-decrypt. Restore removes the entry from `manifest.trash` → pruned. **Why it's secure:** block names are non-secret in the bridge (already plaintext in `BlockSummary`, returned as a plain FFI `String`), so the cache holds plain `String` (not `Sensitive`) — no weaker than active blocks — and is still cleared on `wipe`. Record plaintext never escapes the function. **Format-change alternative (put `block_name` in `TrashEntry`) was ruled out** — touches the frozen on-disk format.

**Spec + plan (committed on-branch):** [`docs/superpowers/specs/2026-06-27-trash-list-name-memo-design.md`](../superpowers/specs/2026-06-27-trash-list-name-memo-design.md), [`docs/superpowers/plans/2026-06-27-trash-list-name-memo.md`](../superpowers/plans/2026-06-27-trash-list-name-memo.md). Built TDD, inline execution, four tasks.

**Branch commits** (off `main` @ `d0613622`):
| SHA | What |
|---|---|
| `0180f929` | **docs(#172)**: design doc |
| `45b7b11e` | **docs(#172)**: implementation plan |
| `63328972` | **refactor(#172)**: `newest_trash_file` returns `(path, ts)` (pure refactor, no behavior change) |
| `b1696a61` | **feat(#172)**: `name_cache` field + `trash_name_cache_get` / `trash_name_cache_put_and_prune` accessors on `OpenVaultManifest`; cleared on `wipe`; 3 unit tests |
| `66854dbb` | **feat(#172)**: memoize names in `list_trashed_blocks`; 2 behavioral tests; **Closes #172** |
| (+ ROADMAP + handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink + ROADMAP D.1.5 accuracy touch |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/trash-list-memo-172
cargo test --release --workspace                             # 1461 passed, 0 failed (was 1456 + 5 new bridge tests)
cargo clippy --release --workspace --tests -- -D warnings    # clean (exit 0)
cargo fmt --all --check                                      # clean (exit 0)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace   # clean (exit 0) — the #92 gate caught a redundant-link target, fixed
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh  # #189 green
```
- **Diff scope (`git diff --stat main...HEAD`):** only `ffi/secretary-ffi-bridge/src/{trash/list.rs,vault/manifest.rs}`, `ffi/secretary-ffi-bridge/tests/trash_list.rs`, `ROADMAP.md`, and the two `docs/superpowers/` design+plan docs (+ this handoff/symlink). No `core/`, no spec docs, no `conformance.py`, no `*.json` KAT, no uniffi/pyo3 `.rs`, no Swift/Kotlin.
- **The two behavioral memo tests** (no test-only instrumentation): `cache_hit_serves_name_without_redecrypt` (corrupt the ciphertext in place, same `ts` → second list still returns the name → proves no re-decrypt) and `newer_ts_forces_redecrypt_not_stale_cache` (drop a corrupt higher-`ts` file → second list keys on the new `ts` → miss → re-decrypt → typed error, not the stale name). Plus 3 accessor unit tests in `manifest.rs`.

## (2) What's next
**#172 done (PR open). Pick a fresh item.** Active parallel worktrees this session (avoid collisions): `.worktrees/d4-browser-autofill` (D.4), `.worktrees/desktop-block-crud-ui`, `.claude/worktrees/hardcore-robinson-373901`. Collision-free candidates:
- **#105** — group multi-arg test helper signatures (`sync_helpers` + `sync_merge_vetoes`) into small param structs — continues #183's transposition-safety theme; test-only, low risk.
- **SecretaryApp Swift 6 follow-up** (optional, no issue) — promote the XcodeGen `ios/SecretaryApp/` target (still Swift 5, was out of #231's SwiftPM scope) to Swift 6 strict concurrency. iOS toolchain is available on this machine ([[project_secretary_ios_toolchain_available]]).
- **#290** — allowlist the 3 D.4 freshness false-positives in `threat-model.md`. **Still collision-risky** while `.worktrees/d4-browser-autofill` is active — coordinate before touching D.4 docs.
- Any from the carried backlog below.

**Possible follow-up from this work (optional, no issue yet):** the memo only helps *repeat* opens within a session — the first open of a fresh handle is still O(n) decrypts (the name genuinely only exists in ciphertext on first sight). If first-open latency on a large trash ever matters, the only further win without a frozen-format change would be a background pre-warm of the memo at open time; deliberately not taken on (premature — v1 trash is small).

**Acceptance criteria template:** a failing test/build reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #269 / #255 / #247 / #246 / #234 / #232 / #224 / #218 / #186 / #167 / #105. (#172 closing via this PR; #92 closed last session.)

## (3) Open decisions and risks
- **Memo holds plain `String`, not `Sensitive` (deliberate).** Block names are non-secret in the bridge — already plaintext in `BlockSummary` and returned as a plain FFI `String`. Caching them in memory is no weaker than what active blocks already do. The memo is still cleared on `wipe` to match the handle's secret-lifecycle. (The memory-hygiene memo's "don't widen secret-field lifetimes into caches" caveat was weighed — it does not apply, names are not secret-bearing.)
- **Stale-name-at-same-`ts` is an accepted property, not a bug.** The one case the memo serves a cached name without re-verify is a trash file whose ciphertext is mutated *without* advancing the `ts` suffix — which no vault operation produces (re-trash always advances `ts`). It can only arise from out-of-band tampering, where serving a non-secret cached name is harmless and **restore still re-verifies on disk independently** (§6.1 + the signed `TrashEntry.fingerprint`, #293/#205). Trust for restoring content is never sourced from this memo.
- **Keyed on `ts`, not `TrashEntry.fingerprint` (deliberate).** `fingerprint` is `Option` (`None` for legacy vaults) and the signed-fingerprint freshness guarantee is load-bearing for *restore*, not for a name-projection memo; `ts` is present for every file, free to read, and tied to the exact file decrypted.
- **README unchanged (deliberate); ROADMAP got a one-clause accuracy touch.** #172 is an internal perf optimization — no new capability/architecture/milestone — so README (product/architecture, [[feedback_readme_style]]) needs nothing, mirroring the #92 precedent. ROADMAP's D.1.5 historical entry said `list_trashed_blocks` "(decrypts each trashed block for its name)", now subtly stale; per [[feedback_act_on_issues_dont_mention]] it got a single forward-referencing clause noting the per-handle `(uuid, ts)` memo rather than leaving a now-false assertion.
- **Risk:** none to product behavior or on-disk bytes — a `secretary-ffi-bridge` in-memory optimization + two new tests. Output of `list_trashed_blocks` is byte-identical to before (same names, same order); only the cost of repeat calls changes.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree can be removed:
#   git worktree remove .worktrees/trash-list-memo-172 && git branch -D feature/trash-list-memo-172
git worktree list && git status -s

# Re-verify this session's work (from the worktree if the PR is still open):
cd .worktrees/trash-list-memo-172
cargo test --release -p secretary-ffi-bridge --test trash_list   # 5 passed (3 original + 2 memo)
cargo test --release --workspace                                 # 1461 passed, 0 failed
cargo clippy --release --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`d0613622`); at handoff time `origin/main` is an ancestor of `HEAD` (verified), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `feature/trash-list-memo-172` (`0180f929` design + `45b7b11e` plan + `63328972` refactor + `b1696a61` accessors + `66854dbb` memo + ROADMAP/handoff commit). Worktree `.worktrees/trash-list-memo-172`.
- **Acceptance:** full workspace green (1461 passed, 0 failed); clippy `-D warnings` clean; fmt clean; doc `-D warnings` clean; #189 lean-binding guard green. Diff provably bridge-internal + docs only → all language/FFI gates unaffected (no `run_conformance.sh` needed). `#172` closes via the PR.
- **README.md:** unchanged (rationale §3). **ROADMAP.md:** one-clause accuracy touch on the D.1.5 `list_trashed_blocks` entry. **CLAUDE.md:** unchanged (no new gate/command).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-27-trash-list-name-memo-172-shipped.md`.
