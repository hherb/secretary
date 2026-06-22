# NEXT_SESSION.md — Add test CI (rust + desktop + swift/kotlin conformance) (#279 follow-up) ✅ (code-complete; PR to open)

**Session date:** 2026-06-22. Flow: continuation of the same session that shipped **#279** (ffi rustfmt drift + the repo's first committed CI, the fmt/clippy `rust-lint.yml` gate — PR #288, **MERGED** @ `f498206c`). You approved the follow-up: a behaviour-test CI gate. Picked **all three** candidate job groups (rust workspace tests, desktop vitest, Swift+Kotlin uniffi conformance).

**Status:** ✅ **code-complete; all four CI jobs verified green locally.** Branch `feature/test-ci` (worktree `.worktrees/test-ci`), branched from `main` @ `f498206c`. **CI workflow + handoff only** — no source code touched (`core/`, spec, `*.udl`, `ffi/` bridge/uniffi API, `ios/`, `android/`, `desktop/` source all untouched). **PR not yet open** — push + open it (see §4).

## (1) What we shipped this session

**`.github/workflows/test.yml`** — the repo's second committed workflow (after `rust-lint.yml` from #288). A behaviour gate; complements the lint gate, does not overlap CodeQL (security-only). Triggers on `pull_request` + push to `main`, cancel-in-progress concurrency group. Four jobs:

| Job | Command | Runner(s) | Notes |
|---|---|---|---|
| `rust-test` | `cargo test --release --workspace` | matrix ubuntu + macOS | Linux leg installs Tauri GTK/WebKit deps (`libwebkit2gtk-4.1-dev` etc.) — same step as `rust-lint.yml`, because `--workspace` pulls in `secretary-desktop`. `Swatinem/rust-cache`. |
| `desktop-test` | `pnpm test` (vitest) | ubuntu | `pnpm/action-setup@v4` (version from `desktop/package.json` `packageManager` = pnpm 11.3.0), `actions/setup-node@v4` Node 20 + pnpm cache, `pnpm install --frozen-lockfile`. `working-directory: desktop`. |
| `swift-conformance` | `bash …/tests/swift/run_conformance.sh` | macOS | swiftc ships with the runner's Xcode. Builds only the uniffi cdylib (no Tauri crate → no GUI deps). Script hard-requires Darwin by design. |
| `kotlin-conformance` | `bash …/tests/kotlin/run_conformance.sh` | ubuntu | `actions/setup-java@v4` Temurin JDK 17 + `sudo snap install --classic kotlin` (JetBrains-published snap — avoids unpinned third-party actions). Script fetches JNA + org.json (pinned, SHA-256 verified inside the script). Builds only the uniffi cdylib (no GUI deps). |

**Key design decisions (so a future reader doesn't "fix" them):**
- **`differential-replay` stays OFF.** Those tests (`core/tests/differential_replay.rs`) shell out to `uv run conformance.py` and are behind the opt-in `differential-replay` Cargo feature (`#![cfg(feature = "differential-replay")]` gates the whole file). Plain `cargo test --release --workspace` is therefore Rust-only — no `uv`/Python needed in CI. If you ever add `--features differential-replay` to CI, you must also set up `uv` on that runner.
- **`core/fuzz` is excluded from the workspace** (separate nightly toolchain) → not run here.
- **Tauri Linux deps are load-bearing on any Linux job that compiles the workspace.** `rust-test`'s ubuntu leg needs them (it builds `secretary-desktop`). The conformance jobs build only `-p secretary-ffi-uniffi` (no Tauri dep) so they do NOT need GUI deps. See [[project_secretary_ci_codeql_default_setup]].
- **Separate file from `rust-lint.yml`** — lint (fast) vs behaviour (slow) are distinct check groups; cleaner signal.

**Docs:** README + ROADMAP **not** touched (internal CI tooling, zero behaviour change). Only this handoff + the retargeted `NEXT_SESSION.md` symlink.

**Branch commit:**
- `95186afa` ci: add test workflow (rust workspace, desktop vitest, swift+kotlin conformance) (#279 follow-up)
- (+ this handoff + the retargeted `NEXT_SESSION.md` symlink — one more commit)

### Acceptance (all four baselines verified green LOCALLY before commit)
```bash
cd /Users/hherb/src/secretary/.worktrees/test-ci
cargo test --release --workspace                                         # 1411 pass / 0 fail (82 binaries)
( cd desktop && pnpm install --frozen-lockfile && pnpm test )            # 569 pass / 75 files
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh            # 27/27 vectors
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh           # 27/27 vectors
```
YAML validated (`yaml.safe_load`). **CI not yet observed** — the workflow runs on the PR once pushed (same-repo branch → `pull_request` reads it from the PR head, as #288 confirmed). Watch the first run (§2).

Guardrail — CI + handoff only:
```bash
git diff main...HEAD --name-only | grep -vE '^(\.github/|docs/handoffs/|NEXT_SESSION.md)'   # EMPTY
```

## (2) What's next
- **Push + open the PR** (§4). **Watch the first CI run carefully** — this is the first time these jobs run on GitHub's runners, so CI-environment surprises are possible (the #288 ubuntu-clippy Tauri-deps failure is the precedent). Most likely friction points, in order: (a) `snap install kotlin` slowness/availability on the runner; (b) macOS Swift job cargo build time (cold cache, no rust-cache hit on first run); (c) a platform-gated test that passes on macOS but not Linux (or vice-versa). Local baselines are all green, so any failure should be environmental, not a real regression.
- After merge: housekeeping (remove this worktree + branch — §4).
- **If a job proves flaky/expensive:** the cheapest trims are dropping the macOS `rust-test` leg (ubuntu still covers the suite) or moving `kotlin-conformance` to its own less-frequent trigger. Don't trim Swift (it's the only macOS-binding coverage).

**Open follow-up issues (carried):** #277 (desktop OS biometric — largest open write-reauth piece) / #255 / #252 / #251 / #234 / #224 / #193 / #192 / #190 / #189 / #186 / #167 / #162 / #161. **Heads-up:** parallel desktop sessions were live (`d4-browser-autofill`, `desktop-block-crud-ui`) — coordinate before a desktop-heavy pick.

## (3) Open decisions and risks
- **First-run CI risk** — local green ≠ CI green (precedent: #288). Verify the PR checks before merging; treat the first run as the real acceptance.
- **CI cost** — this roughly triples CI minutes per PR (rust ×2 OS + desktop + swift + kotlin, on top of fmt + clippy ×2). Acceptable for a security-critical crypto repo; trims noted in §2 if it bites.
- **CI + handoff only** — guardrail empty by construction (verified); no source change, no cross-language regression risk introduced by this PR itself.

## (4) Exact commands to resume
```bash
# 0) Push the branch + open the PR (worktree kept alive for PR iteration):
cd /Users/hherb/src/secretary/.worktrees/test-ci
git push -u origin feature/test-ci
gh pr create --base main --head feature/test-ci \
  --title "Add test CI: rust workspace + desktop vitest + swift/kotlin conformance (#279 follow-up)" --body "<summary>"

# Then WATCH the first CI run (the real acceptance):
gh pr checks <PR#> --watch

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/test-ci && git branch -D feature/test-ci
git worktree prune && git worktree list
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing ([[feedback_next_session_main_authoritative]]). `origin/main` was at `f498206c` (the branch point) at close.

## Closing inventory
- **Branch on close:** `feature/test-ci` @ `95186afa` + the handoff commit; `main`/`origin/main` @ `f498206c`. PR to open. Squash-merge → one commit on `main`.
- **Acceptance:** all four jobs green LOCALLY — rust 1411 pass/0 fail; desktop vitest 569 pass; swift 27/27; kotlin 27/27; YAML validated. CI run pending on the PR (the real acceptance — watch it).
- **README.md / ROADMAP.md:** both intentionally unchanged (internal CI tooling, behaviour identical).
- **NEXT_SESSION.md:** symlink retargeted to this file.
