# NEXT_SESSION.md — fuzz monitor loopback bind (#210) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-25. Started from a clean baton — PR #298 (#251 + #229 iOS/Android memory-hygiene) had merged to `main` (`cc7b21c9`), and PR #301 (`602b3af0`) was the new tip. Removed the two merged worktrees/branches (`ios-android-memory-hygiene`, `fix-share-proptest-seed-collision`). User picked **#210** (fuzz dashboard auth, the only `security`-labelled quick win) over #295 / #290 (#290 still blocked by the active `d4-browser-autofill` worktree). Executed via **TDD** (red→green) in the project-local worktree.

**Status:** ✅ **SHIPPED — branch `fix/fuzz-monitor-loopback-bind`, PR opening.** Single focused commit; 142/142 monitor tests green; runtime bind verified.

## (1) What we shipped this session

One pre-existing security gap in the **dev-only fuzz dashboard** — no Rust-core / on-disk-format / spec change; `conformance.py` + the Swift/Kotlin conformance harnesses untouched; zero Rust files touched.

**#210 — NiceGUI fuzz dashboard bound `0.0.0.0` with no auth.** `core/fuzz/monitor.py` called `ui.run(port=8080, show=False, reload=False, title=...)` with **no `host=`**, so in non-native mode NiceGUI defaults to `0.0.0.0` (all interfaces). The Start/Stop button handlers `asyncio.create_subprocess_exec("cargo", "fuzz", "run", ...)` and `os.killpg(...)` **with no authentication**, so anyone on the same LAN got an unauthenticated start/kill panel for full-CPU `cargo build` + libFuzzer campaigns, plus disclosure of local paths / crash filenames in the live log tails — while CLAUDE.md and `core/fuzz/README.md` both describe it as a `localhost:8080` dashboard. Blast radius was already bounded (fixed argv, no command injection, stderr `html.escape`d), hence the issue's Low–Medium severity.

**Fix.** Bind `127.0.0.1` explicitly. Rather than burying a literal in `ui.run`, the bind host + port are now named constants (`_BIND_HOST = "127.0.0.1"`, `_DASHBOARD_PORT = 8080` — no magic numbers) and the entire `ui.run` argument set is isolated in a pure `run_kwargs() -> dict`, so the loopback bind is **unit-assertable without launching the server**. `main()` now calls `ui.run(**run_kwargs())`. The fix makes the code match its own docs (loopback bind makes the no-auth posture acceptable for a dev-only tool).

**Incidental fix (surfaced during the task):** the documented test command in CLAUDE.md (`uv run --with pytest pytest test_monitor.py -v`) omitted `--with nicegui` and therefore **failed in a clean env** — `test_monitor` imports `monitor.py`, which imports `nicegui` at module load. Corrected to `uv run --with pytest --with "nicegui>=2" pytest test_monitor.py -v` (verified verbatim).

**Branch commit** (off `main` @ `602b3af0`):
| SHA | What |
|---|---|
| `d72846a9` | **fix(fuzz)**: bind monitor dashboard to loopback only (#210) — `run_kwargs()` + named consts + 3 tests + CLAUDE.md test-cmd fix |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

**Tests added (TDD red→green):** `TestRunKwargs` in `core/fuzz/test_monitor.py` (3 cases):
- `test_binds_loopback_not_all_interfaces` — `run_kwargs()["host"] == "127.0.0.1"` and `!= "0.0.0.0"` (the teeth assertion; fails on the pre-fix no-`host=` code, which had no `run_kwargs` at all).
- `test_port_matches_documented_dashboard_port` — port stays the documented `8080`.
- `test_no_dev_server_reload_or_browser_autolaunch` — `reload`/`show` stay `False` (regression guard on the call shape).

### Acceptance (verified by the controller this session, not assumed)
```bash
cd /Users/hherb/src/secretary/.worktrees/fuzz-monitor-loopback/core/fuzz
uv run --with pytest --with "nicegui>=2" pytest test_monitor.py -v    # 142 passed (3 new)
# Runtime bind proof (stronger than the kwarg assertion):
uv run monitor.py &                                                   # then:
lsof -nP -iTCP:8080 -sTCP:LISTEN                                       # -> TCP 127.0.0.1:8080 (LISTEN), NOT 0.0.0.0
```
**CI note:** the workflows do **not** run the monitor pytest suite (grep-clean in `.github/workflows/`), so this fix is gated by local runs + the runtime `lsof` proof above, not CI. No Rust / format / conformance surface changed → `test.yml` + `rust-lint.yml` + CodeQL unaffected.

## (2) What's next
**#210 done (PR open). Pick a fresh item.** Remaining backlog (carried):
- **#295** — `once` mode doesn't `log_outcome` (rollback/veto surfaced only via exit code, no forensic clocks). Small, pure-Rust/cli; spinoff of the daemon cluster. Call `daemon::log_outcome` on the `Ok` arm of `dispatch_once_subcommand`.
- **#290** — allowlist the 3 D.4 freshness false-positives (`origin_binding`/`registrable_domain`/`exact_origin`) once the `d4-browser-autofill` session settles (worktree `.worktrees/d4-browser-autofill` was still active at handoff — check before picking).
- Larger sync/daemon + tooling backlog otherwise unchanged (see carried-issues list below).

**Acceptance criteria template for the next pick:** a failing test that reproduces the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths), full `cargo test --workspace` + clippy `-D warnings` green, and spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #295 / #290 / #284 / #280 / #277 / #273 / #272 / #269 / #255 / #252 / #247 / #246 / #234 / #232 / #231 / #224 / #218 / #193 / #192 / #190 / #189 / #186 / #183. (#210 now closed by this PR; #251 / #229 closed by #298; #206–#209 / #205 / #293 / #301 closed earlier.)

## (3) Open decisions and risks
- **#210: explicit `127.0.0.1`, not `localhost` (deliberate).** Binding the IPv4 loopback literal is strictly more restrictive than `0.0.0.0` and matches the issue's exact recommendation; `localhost` could resolve to `::1` and muddies the assertion. Don't "generalise" it back to a hostname.
- **#210: `run_kwargs()` pure-split is what makes the bind testable.** `ui.run` actually launches the server, so a literal `host=` arg buried in `main` couldn't be asserted without standing up a socket. The pure `dict`-returning helper is the seam; the runtime `lsof` check is the belt-and-braces proof that NiceGUI honours the kwarg. Don't inline it back into `main`.
- **No auth added (scope).** The fix is loopback-bind only; it does **not** add a `storage_secret`/auth middleware. That's the correct, proportionate fix for a dev-only single-operator tool per the issue — loopback makes no-auth acceptable. Adding auth would be over-engineering; file a follow-up only if the dashboard ever needs to be reachable off-host.
- **README / ROADMAP unchanged (deliberate).** #210 adds **no new capability** — pure security hardening of already-shipped dev tooling. The README dashboard mention (`core/fuzz/monitor.py`, "running and watching campaigns") makes no bind/network claim, so it stays accurate; ROADMAP has no #210 reference and no milestone moved. (Matches the prior session's pure-hardening rationale for #251/#229.)
- **Risk:** none to honest single-operator use. Loopback bind only removes off-host reachability; a developer browsing `http://localhost:8080` on their own machine is unaffected (full 142-test suite green; runtime socket confirmed `127.0.0.1:8080`).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree .worktrees/fuzz-monitor-loopback can be removed:
#   git worktree remove .worktrees/fuzz-monitor-loopback && git branch -D fix/fuzz-monitor-loopback-bind
git worktree list && git status -s

# Re-run this fix's gate locally (from the worktree if the PR is still open):
cd core/fuzz && uv run --with pytest --with "nicegui>=2" pytest test_monitor.py -v
# Runtime bind proof:
uv run monitor.py & sleep 3; lsof -nP -iTCP:8080 -sTCP:LISTEN; kill %1
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch was cut from current `origin/main` (`602b3af0`) and `origin/main` had **not** advanced at handoff time (verified: `origin/main` == merge-base), so no history-binding merge was needed this session.

## Closing inventory
- **State on close:** PR opening on `fix/fuzz-monitor-loopback-bind` (1 code commit + handoff). Worktree `.worktrees/fuzz-monitor-loopback`.
- **Acceptance:** local GREEN — 142/142 monitor tests (3 new), runtime socket confirmed `127.0.0.1:8080` (not `0.0.0.0`), documented test command fixed + verified verbatim. Zero Rust touched → cargo/clippy/conformance unaffected; CI does not run the monitor suite (local + lsof proof is the gate).
- **README.md / ROADMAP.md:** unchanged (rationale in §3 — internal hardening, no capability/milestone change).
- **CLAUDE.md:** updated — the documented fuzz-monitor test command now includes `--with nicegui` (was broken in a clean env); no architectural guidance changed.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-25-fuzz-monitor-loopback-bind-shipped.md`.
