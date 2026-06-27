# NEXT_SESSION.md — #183 re-key signature hardening ✅ SHIPPED (PR opening)

**Session date:** 2026-06-27. Started from a clean baton — PR #312 (the #190+#192 CRDT collision test gaps) had merged to `main` as `836f8be1`; removed the merged worktree/branch (`.worktrees/crdt-test-gaps-190-192` / `feature/crdt-test-gaps-190-192`). User picked **#183** (reduce positional-arg count + transposition-safety on the `rewrite_block_with_recipients` re-key engine). Executed in project-local worktree `.worktrees/rekey-newtypes-183`, branch `feature/rekey-newtypes-183`.

**Status:** ✅ **SHIPPED — branch `feature/rekey-newtypes-183`, PR opening.** Pure internal-API-shape refactor. **No on-disk format / spec / `conformance.py` / KAT-JSON / FFI-surface / Cargo-manifest change; no behavior change** (verified field-by-field in review). `Closes #183` rides in the commit + PR body.

## (1) What we shipped this session

**The hazard (from #183).** The shared re-key engine `rewrite_block_with_recipients` took **14 positional args** behind `#[allow(clippy::too_many_arguments)]`, and its public callers threaded several adjacent same-typed `[u8; 16]` UUIDs — `revoke_block_recipient` carries **three** (`block_uuid`, `revoked_recipient_uuid`, `device_uuid`), the last two **adjacent**. A transposition compiled silently on a security-critical path (BCK rotation + Ed25519∧ML-DSA hybrid re-sign). The existing `Fingerprint = [u8;16]` is only a *type alias* → no transposition safety, no usable precedent.

**Design (settled with the user via the options format).** Chose **true UUID newtypes through the public API + a parameter object for the engine** over (B) named param-structs without newtypes (still type-check on a wrong-value-in-right-field) and (C) engine-only struct (leaves the public-API transposition risk). Only true newtypes make a transposition *fail to compile* — the issue's literal goal. Spec: [docs/superpowers/specs/2026-06-27-rekey-newtypes-183-design.md](docs/superpowers/specs/2026-06-27-rekey-newtypes-183-design.md).

**Mechanics:**
- **New `core/src/vault/ids.rs`** — `BlockUuid` / `RecipientUuid` / `DeviceUuid` true newtypes (one `uuid_newtype!` macro; `new`/`as_bytes`/`into_inner`/bidirectional `From`; `Copy` + value equality). 4 unit tests + a **`compile_fail` doctest** on the module doc (NOT inside `#[cfg(test)]` — rustdoc skips those) that pins "passing a `DeviceUuid` where a `BlockUuid` is expected does not compile." Re-exported from `core/src/vault/mod.rs`.
- **Engine** collapses its 14 args into a `BlockRekey<'_>` parameter object (nested `AuthorSigner<'_>` for the author card+fp+sk_ed+sk_pq cluster) → **4 args; `#[allow(clippy::too_many_arguments)]` removed**. Field-name construction is inherently transposition-proof. `entry_idx` stays caller-supplied (no behavior change).
- **Public `share_block` / `revoke_block_recipient`** keep flat arg lists (user-facing API) but their UUID params are newtypes — swapping the adjacent `revoked_recipient_uuid`/`device_uuid` now fails to compile. They `.into_inner()` the scalar ids at the top (body unchanged) and build a `BlockRekey`. They keep their own `#[allow]` (inherent API arg count; the issue's complaint *there* was transposition, now fixed).
- **Scalar-role only:** `Vec<[u8;16]>` recipient lists and the on-disk `BlockEntry.recipients` type stay raw → frozen v1 format untouched.
- **Call sites:** 2 bridge sites (`ffi/secretary-ffi-bridge/src/{share,revoke}/orchestration.rs`) wrap raw bytes via `::new` — bridge/FFI public signatures stay `[u8;16]`, so **no `.udl` / conformance change**. ~21 core test sites (share_block.rs, revoke_block.rs, revoke_kat.rs) wrapped via a validated line-number-driven script (`::new`, not `.into()`, to keep tests transposition-honest).

**Branch commits** (off `main` @ `836f8be1`):
| SHA | What |
|---|---|
| `6af85e32` | **docs(#183)**: design spec |
| `79a70a37` | **refactor(#183)**: UUID role newtypes + `BlockRekey` param object + bridge/test call-site updates |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/rekey-newtypes-183
cargo test --release --workspace                          # 1456 passed, 0 failed
cargo test --release -p secretary-core --doc             # compile_fail doctest passes (transposition rejected)
cargo clippy --release --workspace --tests -- -D warnings # clean (exit 0)
cargo fmt --all -- --check                               # clean (exit 0)
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh  # #189 guard green
```
- **Non-vacuousness proven:** the reviewer compiled the doctest body standalone against the built rlib → fails with `E0308: mismatched types, expected BlockUuid, found DeviceUuid` (the exact guarantee, not an unresolved-import/private-item artifact).
- **Code review** (pr-review-toolkit code-reviewer) on the full diff: **no issues ≥80 confidence**. It independently verified the engine destructuring maps every field to the same value the old positional arg carried (no swaps), the same bytes reach crypto/manifest/disk (`device_uuid.as_bytes()`→`tick_clock`, `card_uuid.as_bytes()`→`format_uuid_hyphenated`, raw `Vec` → `BlockEntry.recipients`), and every bridge/test wrap uses the correct role newtype.

## (2) What's next
**#183 done (PR open). Pick a fresh item.** Active parallel worktrees this session (avoid collisions): `.worktrees/d4-browser-autofill` (D.4), `.worktrees/desktop-block-crud-ui`, `.claude/worktrees/hardcore-robinson-373901`. Collision-free candidates:
- **#92** (docs) — clean up the 28 pre-existing `cargo doc` warnings (14 in `secretary-cli`); `cargo doc -D warnings` is **not** a CI gate today (could add it as teeth). No collision.
- **SecretaryApp Swift 6 follow-up** (optional, no issue) — the XcodeGen `ios/SecretaryApp/` app target was out of #231's "SwiftPM targets" scope and still builds in Swift 5 mode; promoting it extends the strict-concurrency bar to the app shell.
- **#290** — allowlist the 3 D.4 freshness false-positives in `threat-model.md`. **Still collision-risky** while `.worktrees/d4-browser-autofill` is active — coordinate before touching D.4 docs.

**Possible follow-up from this work (optional, no issue yet):** the UUID newtypes live only on the re-key path; the rest of `core` (save_block, trash/restore, sync, device_slot) still threads raw `[u8;16]`. Codebase-wide adoption was explicitly out of #183's scope, but if the transposition pattern is judged worth generalizing, that's a natural follow-up (would also let `Fingerprint` graduate from alias to newtype).

**Acceptance criteria template:** a failing test/build reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #269 / #255 / #247 / #246 / #234 / #232 / #224 / #218 / #186 / #92. (#183 closing via this PR.)

## (3) Open decisions and risks
- **Newtypes scoped to the re-key path (resolved with user).** `BlockUuid`/`RecipientUuid`/`DeviceUuid` exist only on `share_block`/`revoke_block_recipient`/engine; the rest of `core` keeps raw `[u8;16]`. Accepted local inconsistency — expanding the convention codebase-wide is a separate, larger change.
- **Public fns keep `#[allow(clippy::too_many_arguments)]` (deliberate).** Their arg count is inherent user-facing API surface; the issue's complaint *there* was transposition (now a compile error), not arg count. Only the internal engine's allow was removed.
- **`compile_fail` doctest must live on a public item, NOT in `#[cfg(test)]`.** rustdoc doesn't enable `cfg(test)`, so a doctest inside the tests module would be silently skipped (a green-but-vacuous trap). It's on the module-level `//!` doc; `cargo test --doc` runs it.
- **README / ROADMAP / CLAUDE.md unchanged (deliberate).** No public-interface / behavior / on-disk-format / milestone change — matches the #190/#192/#189/#252/#231 pure-refactor/test precedent. README's sync-surface row is about the bridge DTOs (unchanged: bridge still takes `[u8;16]`).
- **Risk:** none to product behavior — compile-time-only wrappers; serialized bytes, manifest types, and the FFI surface are untouched. Worst case would be a behavior-changing field swap in the refactor; ruled out by the field-by-field review + the unchanged 1456-test suite (incl. share/revoke/revoke-KAT/conformance-KAT).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree can be removed:
#   git worktree remove .worktrees/rekey-newtypes-183 && git branch -D feature/rekey-newtypes-183
git worktree list && git status -s

# Re-verify this session's work (from the worktree if the PR is still open):
cd .worktrees/rekey-newtypes-183
cargo test --release --workspace
cargo test --release -p secretary-core --doc          # the transposition compile_fail doctest
cargo clippy --release --workspace --tests -- -D warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`836f8be1`); at handoff time `origin/main` is an ancestor of `HEAD` (verified), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `feature/rekey-newtypes-183` (`6af85e32` spec + `79a70a37` refactor + handoff). Worktree `.worktrees/rekey-newtypes-183`.
- **Acceptance:** full workspace green (1456 passed, 0 failed); `compile_fail` doctest proves transposition is a type error (verified non-vacuous); clippy `-D warnings` clean; fmt clean; #189 lean-binding guard green; code review clean (no issues ≥80). No `core` on-disk-format/FFI-surface/`conformance.py`/manifest touched → all language gates unaffected. `#183` closes via the PR.
- **README.md / ROADMAP.md / CLAUDE.md:** unchanged (rationale in §3).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-27-rekey-newtypes-183-shipped.md`.
