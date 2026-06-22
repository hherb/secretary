# NEXT_SESSION.md — Add test CI (rust + desktop + swift/kotlin conformance) (#279 follow-up) ✅ SHIPPED + MERGED (PR #289)

**Session date:** 2026-06-22. Flow: continuation of the same session that shipped **#279** (ffi rustfmt drift + the repo's first committed CI, the fmt/clippy `rust-lint.yml` gate — PR #288, **MERGED** @ `f498206c`). You approved the follow-up: a behaviour-test CI gate. Picked **all three** candidate job groups (rust workspace tests, desktop vitest, Swift+Kotlin uniffi conformance).

**Status:** ✅ **SHIPPED + MERGED.** PR #289 squash-merged to `main` @ `ef005160` (all CI green). **No in-flight work — this baton describes what's next (§2).** The merge was CI workflow + handoff only — no source code touched (`core/`, spec, `*.udl`, `ffi/` bridge/uniffi API, `ios/`, `android/`, `desktop/` source all untouched).

## (1) What we shipped this session

**`.github/workflows/test.yml`** — the repo's second committed workflow (after `rust-lint.yml` from #288). A behaviour gate; complements the lint gate, does not overlap CodeQL (security-only). Triggers on `pull_request` + push to `main`, cancel-in-progress concurrency group. Four jobs:

| Job | Command | Runner(s) | Notes |
|---|---|---|---|
| `rust-test` | `cargo test --release --workspace` | matrix ubuntu + macOS | Linux leg installs Tauri GTK/WebKit deps (`libwebkit2gtk-4.1-dev` etc.) — same step as `rust-lint.yml`, because `--workspace` pulls in `secretary-desktop`. `Swatinem/rust-cache`. |
| `desktop-test` | `pnpm test` (vitest) | ubuntu | `pnpm/action-setup@v4` with `package_json_file: desktop/package.json` (version = pnpm 11.3.0; see first-run fixes below), `actions/setup-node@v4` **Node 22** (pnpm 11.3.0 needs Node ≥22.13) + pnpm cache, `pnpm install --frozen-lockfile`. `working-directory: desktop` (applies to `run:` steps only). |
| `swift-conformance` | `bash …/tests/swift/run_conformance.sh` | macOS | swiftc ships with the runner's Xcode. Builds only the uniffi cdylib (no Tauri crate → no GUI deps). Script hard-requires Darwin by design. |
| `kotlin-conformance` | `bash …/tests/kotlin/run_conformance.sh` | ubuntu | `actions/setup-java@v4` Temurin JDK 17 + `sudo snap install --classic kotlin` (JetBrains-published snap — avoids unpinned third-party actions). Script fetches JNA + org.json (pinned, SHA-256 verified inside the script). Builds only the uniffi cdylib (no GUI deps). |

**Key design decisions (so a future reader doesn't "fix" them):**
- **`differential-replay` stays OFF.** Those tests (`core/tests/differential_replay.rs`) shell out to `uv run conformance.py` and are behind the opt-in `differential-replay` Cargo feature (`#![cfg(feature = "differential-replay")]` gates the whole file). Plain `cargo test --release --workspace` is therefore Rust-only — no `uv`/Python needed in CI. If you ever add `--features differential-replay` to CI, you must also set up `uv` on that runner.
- **`core/fuzz` is excluded from the workspace** (separate nightly toolchain) → not run here.
- **Tauri Linux deps are load-bearing on any Linux job that compiles the workspace.** `rust-test`'s ubuntu leg needs them (it builds `secretary-desktop`). The conformance jobs build only `-p secretary-ffi-uniffi` (no Tauri dep) so they do NOT need GUI deps. See [[project_secretary_ci_codeql_default_setup]].
- **Separate file from `rust-lint.yml`** — lint (fast) vs behaviour (slow) are distinct check groups; cleaner signal.

**Docs:** README + ROADMAP **not** touched (internal CI tooling, zero behaviour change). Only this handoff + the retargeted `NEXT_SESSION.md` symlink.

**Squash-merged to `main` @ `ef005160`.** Branch commits that went in:
- `95186afa` ci: add test workflow (rust workspace, desktop vitest, swift+kotlin conformance) (#279 follow-up)
- `baae3f3a` docs: session handoff for test CI + retarget NEXT_SESSION symlink
- `308b92f9` ci: fix pnpm action version resolution in desktop-test job (first-run fix #1)
- `0243951e` ci: bump desktop-test Node to 22 (pnpm 11.3.0 needs Node ≥22.13) (first-run fix #2)
- (post-merge: this handoff was corrected directly on `main` — it had been squashed in stale because the merge landed before the "CI-green" handoff edit.)

**First-run CI fixes (`desktop vitest`, the only failing job — both predicted in §2 as likely friction):**
1. **`308b92f9`** — first run 9/10 green; `desktop vitest` failed in 8s. `pnpm/action-setup` reads `packageManager` from `package.json` at the **repo root**, but `defaults.run.working-directory: desktop` applies only to `run:` steps, NOT `uses:` actions — no root `package.json` → "No pnpm version is specified." Fix: `package_json_file: desktop/package.json` on the action.
2. **`0243951e`** — next run surfaced the real version constraint: pnpm 11.3.0 requires Node ≥22.13, so `actions/setup-node` `node-version: 20` failed. Fix: bump to `node-version: 22`. After this, all green. (This is the #288 "local-green ≠ CI-green" precedent twice over — local pnpm/node already satisfied these.)

### Acceptance (all four baselines verified green LOCALLY before commit)
```bash
cd /Users/hherb/src/secretary/.worktrees/test-ci
cargo test --release --workspace                                         # 1411 pass / 0 fail (82 binaries)
( cd desktop && pnpm install --frozen-lockfile && pnpm test )            # 569 pass / 75 files
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh            # 27/27 vectors
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh           # 27/27 vectors
```
**CI verified GREEN on PR #289** (the real acceptance) after the `308b92f9` pnpm fix — all jobs pass, status CLEAN: `cargo test` ubuntu 3m46s / macOS 3m46s, `desktop vitest` 45s, `swift conformance` 1m25s, `kotlin conformance` 1m34s, plus fmt/clippy/CodeQL. (Cold first run: cargo legs were ~7m; warm rust-cache halved them.)

Guardrail — CI + handoff only:
```bash
git diff main...HEAD --name-only | grep -vE '^(\.github/|docs/handoffs/|NEXT_SESSION.md)'   # EMPTY
```

## (2) What's next
**#279 and its two CI follow-ups (`rust-lint.yml` + `test.yml`) are DONE and merged. No in-flight work — pick a fresh item.**
- **Top candidate: #277** — desktop OS biometric (Touch ID / Windows Hello), the largest open write-reauth piece, mirroring the mobile presence-proof model. **Heads-up:** parallel desktop sessions were live (`d4-browser-autofill`, `desktop-block-crud-ui`) — coordinate before a desktop-heavy pick.
- **If a CI job proves flaky/expensive** down the line: cheapest trims are dropping the macOS `rust-test` leg (ubuntu still covers the suite) or moving `kotlin-conformance` to a less-frequent trigger. Don't trim Swift (only macOS-binding coverage). A `cargo test --features differential-replay` job (needs `uv` on the runner) is a possible future addition.

**Open follow-up issues (carried):** #277 (desktop OS biometric — largest open write-reauth piece) / #255 / #252 / #251 / #234 / #224 / #193 / #192 / #190 / #189 / #186 / #167 / #162 / #161.

## (3) Open decisions and risks
- **CI cost** — this roughly triples CI minutes per PR (rust ×2 OS + desktop + swift + kotlin, on top of fmt + clippy ×2). Acceptable for a security-critical crypto repo. If it bites, cheapest trims: drop the macOS `rust-test` leg (ubuntu still covers the suite) or move `kotlin-conformance` to a less-frequent trigger. Don't trim Swift (only macOS-binding coverage).
- **CI + handoff only** — guardrail empty by construction (verified); no source change, no cross-language regression risk introduced by this PR itself.

## (4) Exact commands to resume
```bash
# PR #289 is already merged to main @ ef005160. Just sync + start the next item.
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git status -s && git worktree list      # confirm clean; .worktrees/test-ci should be gone (cleaned up this session)

# Run any gate locally (now also enforced in CI by rust-lint.yml + test.yml):
cargo test --release --workspace        # or: ( cd desktop && pnpm test )
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). **Lesson from this session:** PR #289 was merged before the final "CI-green" handoff edit was pushed, so `main` got a *stale* baton (it still said "PR to open" / "awaiting your merge"). The correction was applied **directly on `main`** afterward (the work is merged, no open PR to ride — [[feedback_next_session_main_authoritative]]). Takeaway: when a PR is squash-merged, immediately verify `NEXT_SESSION.md` on `main` reflects the merged reality and fix it on `main` if not; the in-PR handoff only covers state up to the last pushed commit before merge.

## Closing inventory
- **State on close:** **PR #289 MERGED to `main` @ `ef005160`** (commits `95186afa`, `baae3f3a`, `308b92f9`, `0243951e`). This handoff corrected directly on `main` post-merge. Worktree `.worktrees/test-ci` + branch `feature/test-ci` cleaned up.
- **Acceptance:** GREEN on CI (PR #289) — `cargo test` ubuntu 3m46s + macOS 3m46s, desktop vitest 45s, swift 27/27 (1m25s), kotlin 27/27 (1m34s), plus fmt/clippy/CodeQL. Local baselines first: rust 1411 pass/0 fail; desktop vitest 569 pass; swift 27/27; kotlin 27/27.
- **README.md / ROADMAP.md:** both intentionally unchanged (internal CI tooling, behaviour identical).
- **NEXT_SESSION.md:** symlink points to this file (`docs/handoffs/2026-06-22-test-ci-shipped.md`).
