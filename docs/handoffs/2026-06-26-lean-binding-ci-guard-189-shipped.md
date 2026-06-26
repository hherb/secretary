# NEXT_SESSION.md — #189 lean mobile-binding CI guard ✅ SHIPPED (PR opening)

**Session date:** 2026-06-26. Started from a clean baton — PR #310 (the #231 iOS Swift 6 strict-concurrency work) had merged to `main` as `99e3fcd9`; removed the merged worktree/branch (`.worktrees/ios-strict-concurrency-231` / `feature/ios-strict-concurrency-231`). User picked **#189** (CI guard asserting the lean mobile-binding feature boundary). Executed in project-local worktree `.worktrees/lean-binding-guard-189`, branch `feature/lean-binding-guard-189`.

**Status:** ✅ **SHIPPED — branch `feature/lean-binding-guard-189`, PR opening.** Pure CI-posture / regression-insurance change. **No `core`/FFI/on-disk-format/`conformance.py`/crypto change; no Cargo manifest change.** `Closes #189` rides in the PR body.

## (1) What we shipped this session

**The gap (#189).** `secretary-cli`'s `daemon` feature gates `notify`/`clap`; `secretary-ffi-bridge` depends on `secretary-cli` with `default-features = false` to keep them out of the bridge and the mobile bindings (`secretary-ffi-uniffi`, `secretary-ffi-py`). This "lean binding" property is **build-context-dependent** — under `cargo test --workspace` Cargo unifies `daemon` ON (the `secretary-sync` bin requires it); the guarantee only holds for the `-p`-scoped `--no-default-features` resolution that is the real shipping context. Nothing in-repo prevented a future dependency edit from silently re-pulling `notify`/`clap` into the binding tree. The issue was filed before any CI workflows existed; they exist now (`rust-lint.yml`, `test.yml`, `ios-tsan.yml`), so it became actionable.

**Design (settled with the user via brainstorming + options):** *Script + CI step*.
- `ffi/scripts/check-lean-binding.sh` (new `ffi/scripts/` dir; mirrors the `run_conformance.sh` pattern — locally runnable, CI-invoked, self-documenting). One forbidden-deps matcher `FORBIDDEN_RE='^(clap|notify) '`, one guarded-crate list. For each crate: `cargo tree -p <crate> --no-default-features -e normal --prefix none` → grep the anchor → fail with the offending lines. `--prefix none` strips box-drawing chars so the line-anchor is robust (the issue's proposed `^\S*…` anchor was buggy). **Fail-closed**: a `cargo tree` error aborts via `set -euo pipefail` rather than passing as "lean" (the `{ grep || true; }` only neutralizes grep's exit-1-on-no-match).
- **`--self-test` mode (positive control):** asserts the matcher *does* flag `clap`+`notify` in `secretary-cli` built with default features (daemon ON). If the control fails to trip, the script exits non-zero — proving the guard is never vacuous (**the #231 lesson:** a "zero warnings" bar that checked nothing).
- CI: new ubuntu-only `lean-binding` job in `rust-lint.yml` (it's a static dependency-boundary lint; `cargo tree` only *resolves* — never compiles — so no GTK/WebKit/Tauri apt deps, fast). Runs `--self-test` first, then the guard.
- CLAUDE.md Commands section documents both local invocations.

**Branch commits** (off `main` @ `99e3fcd9`):
| SHA | What |
|---|---|
| `55bb1281` | **docs(#189)**: design spec (`docs/superpowers/specs/2026-06-26-lean-binding-ci-guard-189-design.md`) |
| `8417de4c` | **ci(#189)**: the guard script + `rust-lint.yml` `lean-binding` job + CLAUDE.md command |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session, in the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/lean-binding-guard-189
bash ffi/scripts/check-lean-binding.sh --self-test   # → matcher fires on secretary-cli (control)
bash ffi/scripts/check-lean-binding.sh               # → all 3 binding crates lean, exit 0
shellcheck ffi/scripts/check-lean-binding.sh         # → clean
```
- **Genuine red→green:** temporarily flipped the bridge's `secretary-cli` dep back to default-features (daemon on) — the exact regression class the guard targets — and the guard correctly **FAILED** (exit 1) flagging `clap v4.6.1` + `notify v6.1.1` on **all three** binding crates; reverted clean (no residual diff), guard green again. Self-test fires independently.
- **Code-review pass** (pr-review-toolkit code-reviewer) on the full staged diff: **no material issues**. Independently verified the fail-closed direction (pipefail aborts before the "lean" branch on a `cargo tree` error), the matcher anchoring (`clap_builder`/`clap_lex`/`clap_derive` do NOT false-positive; `clap `/`notify ` do), that the bridge genuinely reaches `secretary-cli` daemon-off on the guarded path (green ≠ no-op), and CI-toolchain consistency with the existing clippy job (no missing setup; `Cargo.lock` is committed so `cargo tree` resolves without mutation).

## (2) What's next
**#189 done (PR open). Pick a fresh item.** Carried collision-free candidates (from this session's backlog sweep):
- **#190 / #192** — bridge/CRDT test gaps: assert `sync_vault`'s `MergedClean` arm under the held lockfile (#190) and that `prepare_merge` populates `DraftMerge.collisions` on a non-tombstone concurrent-edit fixture (#192). Pure Rust TDD; strengthens the merge-correctness net. No collision.
- **#92** (docs) — clean up the 28 pre-existing `cargo doc` warnings (14 in `secretary-cli`); `cargo doc -D warnings` is **not** a CI gate today (could add it as teeth). No collision.
- **#183** — reduce positional-arg count on the `rewrite_block_with_recipients` re-key engine. Rust refactor on a crypto-adjacent path — needs care.
- **#290** — allowlist the 3 D.4 freshness false-positives in `threat-model.md`. **Still collision-risky:** `.worktrees/d4-browser-autofill` (`claude/intelligent-davinci-hriple`) was active this session — coordinate before touching D.4 docs.
- **SecretaryApp Swift 6 follow-up** (optional, no issue) — the XcodeGen `ios/SecretaryApp/` app target was out of #231's "SwiftPM targets" scope and still builds in Swift 5 mode; promoting it would extend the strict-concurrency bar to the app shell.

**Acceptance criteria template:** a failing test/build reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #269 / #255 / #247 / #246 / #234 / #232 / #224 / #218 / #192 / #190 / #186 / #183 / #92. (#189 closing via this PR.)

## (3) Open decisions and risks
- **Script + CI step over a Rust test or inline CI YAML (resolved with user via brainstorming).** A runnable script keeps the logic locally reproducible + documented (matches `run_conformance.sh`), avoids the awkwardness of spawning `cargo tree` from inside `cargo test`, and keeps the matcher robust (`--prefix none` + line anchor) rather than the issue's buggy `^\S*` proposal.
- **Self-test positive control is load-bearing, not decoration.** It uses `secretary-cli` (daemon on by default) as a known-positive tree; if the matcher ever stops detecting `clap`/`notify` the CI job fails on the self-test step *before* it can vouch for a vacuous green. This is the direct application of [[feedback_security_no_assumptions]] / the #231 vacuous-bar lesson.
- **Guard scope = normal edges, `--no-default-features`.** `-e normal` is the deps that actually land in the shipped artifact (excludes build/dev deps); `--no-default-features` matches the real cdylib/.so build context *and* guards against a future move of the opt-in `cli` feature into `default`. Build-dep clap (e.g. via uniffi-bindgen's `cli` feature) is intentionally **not** flagged — it never links into the artifact.
- **README / ROADMAP unchanged (deliberate).** No public interface / behavior / on-disk-format / milestone change — matches the #231/#252 pure-hardening precedent. Verified neither doc references `#189` or the notify/clap boundary or makes a now-inaccurate claim.
- **Risk:** none to product behavior — no code/manifest touched, only a new CI tripwire + a script + a doc line. Worst case is a *false CI failure* on an air-gapped runner with no cached registry index (`cargo tree` could try an index update and fail) — fail-closed, never a silent pass; not a practical concern on GitHub-hosted ubuntu.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree can be removed:
#   git worktree remove .worktrees/lean-binding-guard-189 && git branch -D feature/lean-binding-guard-189
git worktree list && git status -s

# Re-verify this session's guard (from the worktree if the PR is still open):
cd .worktrees/lean-binding-guard-189
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`99e3fcd9`); at handoff time `origin/main` == merge-base == `99e3fcd9` (verified), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `feature/lean-binding-guard-189` (`55bb1281` spec + `8417de4c` guard/CI/docs + handoff). Worktree `.worktrees/lean-binding-guard-189`.
- **Acceptance:** `--self-test` fires; guard green over all 3 binding crates; shellcheck clean; genuine red→green proven via an injected default-features regression (exit 1 on all 3 crates, clean after revert); code-review clean. No `core`/FFI/on-disk-format/`conformance.py`/manifest touched → all language gates unaffected. `#189` closes via the PR.
- **README.md / ROADMAP.md:** unchanged (rationale in §3).
- **CLAUDE.md:** updated — documents the new local guard command in the Commands section.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-26-lean-binding-ci-guard-189-shipped.md`.
