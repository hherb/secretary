# NEXT_SESSION.md — C.2 design (spec + plan) shipped

**Session date:** 2026-05-23 (C.2 design slice — spec + implementation plan for the headless `secretary-sync` CLI).
**Status:** C.2 design ✅ (spec + plan committed on `feature/c2-task-1-spec`; PR pending). Implementation tasks 1-10 queued.

## (1) What we shipped this session

A single PR (to be opened on `feature/c2-task-1-spec`) carrying the **design contract for Sub-project C phase C.2** — the headless `secretary-sync` desktop CLI. Two artifacts:

| Artifact | Path | Commit |
|---|---|---|
| Design spec | [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md) | `96dd3fd` (initial) + `5bc9536` (clean-room conformance reframe) + `03d919f` (commit_with_decisions signature correction) |
| Implementation plan | [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) | `d89dcc9` |
| This handoff + symlink retarget | this file + `NEXT_SESSION.md` | (pending — final commit on the PR) |

### Spec highlights (10 design decisions D1–D10)

| | Decision | Why it matters |
|---|---|---|
| D1 | Single binary with `--non-interactive` flag | One executable covers both desktop terminal + NAS / supervisor deployments. |
| D2 | `--password-stdin` only for headless unlock | Composes with systemd `LoadCredential=`, `pass`, `op run --env-file` — no env-var leak in `/proc/<pid>/environ`. |
| D3 | `notify` events + debounce + optional periodic poll | Belt-and-suspenders against flaky cloud-folder mounts (Dropbox, iCloud, WebDAV). |
| D4 | Default `KeepLocal` veto in non-interactive mode | Honours C.1.1b D2 "no silent data loss"; daemon makes forward progress. |
| D5 | `SyncState` in OS data dir, vault-UUID-keyed filename | Multi-vault coexistence; host-local placement (not in vault folder). |
| D6 | Provider-name filter + size-stability window (2000 ms default, mobile-network-aware) | ADR-0003 partial-download requirement. 10-pattern canonical table in the spec. |
| D7 | Single-process-per-vault via host-local `fs2` lockfile | Closes the race in `commit_with_decisions` between two CLIs on the same vault. |
| D8 | Two subcommands: `run` + `once` | `once` is testable without signal handling; `run` is the operational mode. |
| D9 | New `cli/` workspace member (not `core/src/bin/`) | `core` stays library-only with minimal dep surface. |
| D10 | Windows is best-effort, not a primary target | Per [[feedback_windows_not_primary]] — user considers Windows insecure by design. |

### Plan highlights (10 tasks, brick-by-brick)

1. Scaffold `cli/` workspace member + exit codes (~12 unit tests).
2. State persistence + lockfile (~9 unit tests).
3. Unlock module (~7 unit tests).
4. Veto trait + AutoKeepLocal + TtyVetoUx (~7 unit tests).
5. Pipeline (one sync attempt) + lib/bin split (~2 integration tests).
6. Watcher submodule: ready + debounce, pure (~17 unit tests).
7. notify driver + daemon event loop (~2 unit tests).
8. Logging + signal handling (~1 unit test; signal-hook gated to `cfg(unix)`).
9. Wire `main.rs` end-to-end + 11 `assert_cmd` integration tests on `once`.
10. Two-instance convergence test + `notify` quirk pinned test + README + ROADMAP + handoff.

Workspace target growth: **800 (current) → ~875** new tests across Tasks 1-10. No `core/` changes; all new code under `cli/`.

### One signature alignment captured during plan authoring

`commit_with_decisions(folder, password: &SecretBytes, draft, decisions, now_ms)` — the function takes the **password**, not the IBK, and re-opens the vault internally via `Unlocker::Password(password)`. The CLI retains `password: SecretBytes` for the daemon's lifetime in addition to `identity: UnlockedIdentity`. Spec §"Identity lifecycle" corrected in `03d919f`; plan §"Spec adjustments" records this as the single deviation.

## (2) What's next — start C.2 Task 1

After the C.2 design PR (this branch) merges, the next slice is **C.2 Task 1: scaffold `cli/` workspace member + exit codes**.

### Acceptance criteria for Task 1

- [ ] New `cli/` workspace member with `[[bin]] name = "secretary-sync"`.
- [ ] `cli/Cargo.toml` lists all 11 runtime deps + 2 dev deps from spec §"External dependencies". `tempfile` exact-pinned at `=3.27.0` with a cross-reference comment.
- [ ] `cli/src/main.rs` — skeleton entry point using `clap::Parser::parse()` + stub dispatch returning `ExitCode::GenericError`.
- [ ] `cli/src/args.rs` — clap derive types for `Cli`, `Command::{Once, Run}`, `CommonArgs`, `RunArgs`, `LogFormat`. Four unit tests covering parse paths + the 2000 ms `--ready-window-ms` default.
- [ ] `cli/src/exit.rs` — `ExitCode` enum with documented discriminants 0/1/2/10/11/12/13/14 + `From<SyncError>` mapping. 9 unit tests.
- [ ] Workspace `Cargo.toml` updated: `cli` added to `[workspace] members`.
- [ ] Gauntlet stays green: **PASSED: 812 FAILED: 0 IGNORED: 10** (800 base + 12 new cli tests).
- [ ] Clippy clean with `-D warnings`; fmt clean; Python conformance + spec freshness PASS.

### Plan handoff

The full Task 1 instructions are in [`docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md`](../superpowers/plans/2026-05-23-c2-headless-sync-cli.md) §"Task 1". Each subsequent task likewise has its own worktree setup, TDD steps with complete code, gauntlet checks, and PR command.

## (3) Open decisions and risks

### Decisions settled during the C.2 brainstorm (carried forward)

All 10 D-numbered decisions in the spec are settled and frozen for v1. No outstanding design questions before Task 1 begins.

### Decisions deferred (won't block Task 1)

- `--veto-policy=fail` and `--decisions-file` flags — deferred to a future C.2.x slice once a real deployment asks.
- `--exit-on-error` for systemd-restart semantics — deferred; daemon's "log + continue on non-fatal errors" stance is the explicit choice per the brainstorm.
- Windows CI runner — per D10, Windows is best-effort.
- `status` and `init` subcommands — YAGNI per D8.
- Clean-room conformance harness for `cli/` — surfaces frozen by this spec; harness deferred to a future C.2.x slice or absorbed into C.4 (per [[user feedback during brainstorm]]).

### Risks carried into the C.2 implementation phase

- **CRDT proptests must not weaken.** Same as C.1.1b. C.2 implementation does NOT touch `core/src/vault/conflict.rs`.
- **`tempfile = "=3.27.0"` exact pin propagates** from `core/Cargo.toml` to `cli/Cargo.toml`. Bump only via deliberate changelog review.
- **`#![forbid(unsafe_code)]`** workspace-wide. `cli/` must be pure-safe Rust.
- **`notify` cross-platform drift risk.** Mitigation: pin to `notify` 6.x with caret range; the notify-quirk integration test in Task 10 is the regression backstop.
- **Single-process-per-vault is advisory.** `flock` doesn't prevent an operator deleting the lockfile under a running daemon. Documented in the spec as a footgun.

### Issues currently open (re-checked at C.2 design close)

- [**#37**](https://github.com/hherb/secretary/issues/37) — Sub-project C umbrella. C.2 is the next slice.
- [**#38**](https://github.com/hherb/secretary/issues/38) — `save_block` proptest case-count budget.
- [**#45**](https://github.com/hherb/secretary/issues/45) — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`.
- [**#75**](https://github.com/hherb/secretary/issues/75) — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests.
- [**#76**](https://github.com/hherb/secretary/issues/76) — Python clean-room replay of `sync_kat.json`.
- [**#78**](https://github.com/hherb/secretary/issues/78) — C.1.1a integration-test gaps.
- [**#79**](https://github.com/hherb/secretary/issues/79) — sync_kat.json ingestion vectors.
- [**#81**](https://github.com/hherb/secretary/issues/81) — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table.
- [**#87**](https://github.com/hherb/secretary/issues/87) — dedup `golden_vault_001_password` reader.
- [**#88**](https://github.com/hherb/secretary/issues/88) — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures.
- [**#90**](https://github.com/hherb/secretary/issues/90) — consolidate four `copy_dir_recursive` test-helper copies.
- [**#95**](https://github.com/hherb/secretary/issues/95) — split `core/tests/sync_helpers/mod.rs`.
- [**#98**](https://github.com/hherb/secretary/issues/98) — `apply_decisions` duplicate-decision tightening.

None block C.2 Task 1.

### Housekeeping note (stale worktree on disk)

The `.worktrees/c1-1b-sync-merge` worktree (branch `feature/c1-1b-task-17`) is still on disk locally; the upstream remote branch was deleted by the PR #110 squash merge. It is safe to clean up via `git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17` whenever convenient — does NOT block C.2 work.

## (4) Exact commands to resume

```bash
# After this C.2 design PR (feature/c2-task-1-spec) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 800 / 0 / 10, unchanged — design PR adds no tests):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Start Task 1:
git worktree add .worktrees/c2-task-1 -b feature/c2-task-1 main
cd .worktrees/c2-task-1

# Open the plan and follow Task 1 line-by-line:
#   docs/superpowers/plans/2026-05-23-c2-headless-sync-cli.md §"Task 1"
# Steps 1-11 cover the full scaffold + commit + PR.
```

## Closing inventory

- **Branch state on close:** `main` at `f0e5de5` (PR #110 squash-merged). `feature/c2-task-1-spec` carries 4 commits on top: `96dd3fd` (spec), `5bc9536` (spec-review reframe), `03d919f` (signature correction), `d89dcc9` (plan).
- **Workspace tests on `feature/c2-task-1-spec`:** 800 passed + 10 ignored (unchanged from `main` — this PR is docs-only). Clippy + fmt + Python conformance + spec freshness all clean.
- **README.md:** unchanged this session — C.2 is design-only; README updates with implementation.
- **ROADMAP.md:** unchanged this session — same reason.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** see §(3) — none block Task 1.
- **Open PRs:** one to be opened at end of this session (C.2 design — spec + plan).
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge` (stale, safe to remove) + `.worktrees/c2-task-1-spec` (this session's work).
- **Frozen baton snapshots:** all prior 17 C.1.1b handoffs at [`docs/handoffs/2026-05-{19..23}-c1-1b-*-shipped.md`](.) — preserved unchanged.
- **This file:** the live baton for C.2 design close.
