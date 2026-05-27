# NEXT_SESSION.md — D.1.1 Tauri spec + plan shipped, implementation downstream

**Session date:** 2026-05-27 (D.1.1 spec + plan + ADR 0007 + D-row pivot from NiceGUI to Tauri — design + implementation plan; per-task implementation PRs come next.)
**Status:** D.1.1 spec + plan authored on branch `feature/d11-tauri-spec`; PR pending. C.2 closed in the previous session (commit `433393d`, PR #128).

## (1) What we shipped this session

A single design-only PR with no code, opening Sub-project D under its new Tauri-based shape:

| Artifact | Path | Notes |
|---|---|---|
| D.1.1 design spec | [`docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`](../superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md) | New (~790 LOC, 16 sections). Covers: project layout under `desktop/`, module decomposition + responsibilities (backend + frontend), vault session lifecycle with state-machine diagram, settings record schema (reserved block `__secretary_app_settings__` with deterministic SHA-256-derived UUID, record_type `secretary.settings.v1`, single field `auto_lock_timeout_ms`), constants table (8 named values with rationale + magnitude), AppError + AppWarning enums with `#[serde(tag = "code")]` discrimination, four-layer test strategy (cargo unit + Vitest + cargo integration + tauri-driver/WDIO e2e), prerequisites + dev loop with pnpm, Content Security Policy lockdown, page routes + Svelte stores, UX details from brainstorming wireframes, out-of-scope enumeration, acceptance criteria. |
| D.1.1 implementation plan | [`docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md`](../superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md) | New (~5070 LOC, 12 tasks). Each task is self-contained with worktree setup, file paths, complete code blocks, TDD step sequences, gauntlet checks, expected test counts, and PR template. Gauntlet trajectory: 960 → 987 (Task 2) → 999 (Task 3) → 1002 (Task 4) → 1005 (Task 5) → unchanged through Tasks 6-11. Tasks: (1) Tauri 2 scaffold + workspace integration, (2) backend pure modules (constants/errors/auto_lock/settings parse), (3) VaultSession + settings vault I/O + device-UUID persistence, (4) IPC commands + DTOs, (5) auto-lock timer + vault-locked event, (6) frontend pure modules + Vitest, (7) Unlock route + PathPicker + theme.css, (8) Vault route + BlockCard + LockButton, (9) Settings dialog, (10) App.svelte orchestration + Toast + activity tracking, (11) L4 e2e (tauri-driver + WDIO), (12) acceptance criteria sweep + ship. |
| ADR 0007 — D-row pivots to Tauri | [`docs/adr/0007-d-row-tauri.md`](../adr/0007-d-row-tauri.md) | New. Supersedes the desktop/mobile UI portion of ADR 0001 (the Rust-core decision stands). Context: 8 months of Rust accumulated, Tauri 2 mature. Decision: Tauri 2 + Svelte + TS replaces NiceGUI + SwiftUI + Compose. Consequences enumerate security wins (no localhost HTTP, secrets-in-Rust), codebase-consolidation wins (one UI codebase across 5 platforms), costs (+30-50% upfront for D.1.1, learning curve, Tauri 2 mobile younger than uniffi). Alternatives considered: stay-with-NiceGUI (rejected), hybrid (rejected — defers cost without reducing it), all-Rust-UI without WebView (rejected — Slint/iced/Dioxus mobile story weaker), native-everywhere (rejected — three-frontend maintenance cost not justified). |
| README D-row update | [`README.md`](../../README.md) | One row rewritten: "Platform UIs (NiceGUI desktop/web, SwiftUI iOS, Compose Android) | ⏳ Sub-project D" → Tauri-based universal client description + ADR 0007 link + clarification that `secretary-ffi-py` and `secretary-ffi-uniffi` stay as third-party-consumer paths (scripts, Shortcuts, AutoFill) but are no longer the UI path. Per [[feedback_readme_style]] brief and audience-aware. |
| ROADMAP D-section rewrite | [`ROADMAP.md`](../../ROADMAP.md) | Two edits: (1) Sub-project D section header text restructured to "Tauri 2 codebase (Rust + Svelte/TS) targeting all platforms from a single source tree", with reference to ADR 0007 and a brief explanation of why the FFI bindings stay around. (2) D.1 / D.2 / D.3 / D.4 phase rows rewritten to reflect the new shape: D.1 = Tauri walking skeleton macOS/Linux desktop with five sub-slices D.1.1 → D.1.5 enumerated, D.2 = Linux + Windows desktop maturation (CI / packaging / signing), D.3 = Tauri 2 mobile (iOS + Android with platform shims), D.4 = browser autofill (unchanged from original). (3) Order-of-magnitude estimates section bumped to match the new D.1 / D.2 / D.3 phase structure. |
| `desktop/` README rewrite | [`desktop/README.md`](../../desktop/README.md) | Was a one-line placeholder for "Python + NiceGUI desktop and web client". Now a proper layout + prerequisites + dev-loop quick-start file describing the (yet-to-be-scaffolded) Tauri project structure. Points at the spec doc as the source of truth. |
| Handoff baton | This file ([`docs/handoffs/2026-05-27-d11-tauri-spec-shipped.md`](.)) | New. Captures the spec-only delivery and frames the next session's job (plan + first task). |
| Symlink retarget | [`NEXT_SESSION.md`](../../NEXT_SESSION.md) | Bumped from `docs/handoffs/2026-05-26-c2-shipped.md` to this file. |

**Commit:** `D.1.1 spec + plan + ADR 0007 + D-row pivot from NiceGUI to Tauri` (single commit on `feature/d11-tauri-spec`; the post-squash-merge SHA on `main` will differ). No code; only design + plan docs + README/ROADMAP/desktop-README updates.

### Why this is a separate PR from the implementation

Per the precedent set by C.2 (spec PR #111 landed before implementation PRs #112, #114, ...): a sizeable design with a project-wide architectural pivot — superseding ADR 0001's UI-layer decision — deserves its own review cycle before code starts being written. The reviewer should be able to argue with the spec and the ADR independently of the implementation choices.

### Brainstorming highlights (for the reviewer's context)

The session's brainstorming surfaced several decisions worth flagging:

1. **Vault-stored auto-lock timeout** (user pushback during brainstorming): the user pointed out — correctly — that storing the timeout in the vault rather than in a plaintext config file is the security-aware default. Persistence in the vault means the timeout is encrypted at rest and only readable post-unlock. The spec implements this via a reserved block `__secretary_app_settings__` with deterministic SHA-256-derived UUID for CRDT-clean concurrent creation across multiple devices.
2. **Tauri vs NiceGUI** (user-initiated reconsideration): the user surfaced their growing Tauri experience mid-brainstorming, leading to a re-evaluation of the original ADR 0001 UI-layer decision. The analysis (security + codebase-consolidation + costs) is recorded in ADR 0007.
3. **Frontend framework = plain Svelte + Vite** (no SvelteKit): the user noted prior experience with plain Svelte + Vite on a more complex UI in another project; this carried over.
4. **No magic numbers** (user reminder during Section 3 review): the constants table (8 named values with rationale and magnitude) in §8 of the spec is the canonical source; code references the names verbatim with doc-comments quoting the same rationale.
5. **Sub-projects B and B-uniffi stay**: the pivot doesn't deprecate the Python / Swift / Kotlin FFI work — they keep their value as third-party-consumer paths (scripts, automation, Shortcuts integration, AutoFill Service). Only the *UI path* moves to Tauri.

## (2) What's next — D.1.1 implementation tasks 1-12

Plan is authored in this PR. The next session's job is to **start executing Task 1**:

1. **Task 1 — Project scaffolding** (~30 min). Manual scaffold per spec §11.3: `package.json`, `vite.config.ts`, `svelte.config.js`, `tsconfig.json`, `tauri.conf.json`, root `Cargo.toml` workspace integration. Ends with `pnpm tauri dev` launching a "hello world" Tauri window. One PR.
2. **Tasks 2-11** — feature slices per the plan. Each task = one PR, one Claude session. The plan is fully detailed (5070 LOC, 12 tasks) with worktree setup, file paths, complete code, TDD step sequences, and expected gauntlet counts at each step. No mid-stream design decisions required.
3. **Task 12 — Acceptance criteria sweep + ship**. Validates the §15 criteria, files any deferred follow-up issues, updates README + ROADMAP + handoff, retargets the symlink. One PR.

Total estimate: 12-15 sessions. The plan is structured for `superpowers:subagent-driven-development` execution — each task is bite-sized and self-contained.

### Acceptance criteria for D.1.1 implementation (from spec §15)

When all of the following hold, D.1.1 is shippable:

- **Manual smoke** (from `cd desktop && pnpm install && pnpm tauri build --debug`): launch binary → Unlock screen → folder picker selects `core/tests/data/golden_vault_001/` → enter known password → Vault screen with block cards → open Settings → change auto-lock 10 min → 1 min → save → idle >1 min → vault auto-locks with toast → re-unlock → 1-min value persisted → Lock click → Unlock screen.
- **Gauntlet** clean: cargo test workspace, clippy `-D warnings`, cargo fmt, `uv run conformance.py`, `uv run spec_test_name_freshness.py`, `pnpm test`, `pnpm tsc --noEmit`, `pnpm svelte-check`, `pnpm lint`.
- **L4 e2e (manual)**: `pnpm e2e` runs cleanly against the debug binary.
- **Documentation**: README + ROADMAP + ADR 0007 + desktop/README updated (all in this spec PR).
- **Process discipline**: every file under 500 LOC, no magic numbers, pure functions in their own modules, tests use random crypto values where applicable.

## (3) Open decisions and risks

### Decisions settled during this session

- **D-row pivots to Tauri** — see ADR 0007 for the full rationale, alternatives considered, and consequences.
- **Frontend framework = plain Svelte + Vite + TypeScript** (not SvelteKit, not React, not Solid).
- **Backend state model = `tauri::State<Mutex<VaultSession>>`** — Mutex (not RwLock) because nearly every read-side command mutates `idle.last_activity_ms`.
- **Auto-lock settings live in the vault**, not plaintext config — reserved block `__secretary_app_settings__`, deterministic UUID, record_type `secretary.settings.v1`, single field `auto_lock_timeout_ms`. Lazy creation (block not created until user explicitly changes the default).
- **AppError + AppWarning are serde-tagged discriminated unions** — `#[serde(tag = "code", rename_all = "snake_case")]`. Frontend TS discriminates on `code`. Developer-facing `detail` fields are `#[serde(skip_serializing)]` so they're logged via `tracing` but never cross IPC.
- **Single secret crosses IPC in D.1.1**: only the password during unlock. Record-field secrets defer to D.1.2.
- **Native window only**, no browser mode. CSP locked to `default-src 'self'; script-src 'self'; connect-src 'self' ipc: tauri:`.
- **Test pyramid**: cargo unit + Vitest + cargo integration + tauri-driver/WDIO e2e. E2E not in CI for D.1.1 (deferred to dedicated CI-infra slice).
- **CSS = plain custom properties**, no Tailwind, no component library. ~8 components is small enough that utility-first CSS is overkill.
- **Manual scaffold over `pnpm create tauri-app`** — non-interactive task execution + zero scaffolding cruft from example content.

### Decisions deferred to the plan or implementation

- **Exact Tauri 2.x patch version pin** — picked at scaffold time (task 1).
- **Exact Svelte version** (Svelte 5 vs Svelte 4) — picked at scaffold time. Probable: Svelte 5 (stable since late 2024).
- **Exact Vite version** — picked at scaffold time.
- **Tauri plugin list** — `@tauri-apps/plugin-dialog` is needed for the native folder picker; others (`-fs`, `-shell`, etc.) are evaluated per-task.
- **Bundle identifier** — currently `org.secretary.desktop` in the spec; can be adjusted when distribution / signing is set up (post-D.1.1).
- **Frontend lockfile policy** — `pnpm-lock.yaml` committed; the spec doesn't pin exact transitive versions.

### Risks carried into the implementation

- **Tauri 2 + Linux WebKitGTK rendering edge cases.** Different distros ship different webkit2gtk versions. The L4 e2e test catches regressions on the dev machine; CI catch is deferred. If a contributor reports a Linux-only rendering bug, the spec's "WebKitGTK 2.40+" constraint is the floor — anything older is unsupported.
- **First-time scaffolding friction.** Manual scaffold means task 1 has to assemble several config files in lockstep (Vite config + Svelte config + TSConfig + Tauri config + Cargo.toml + workspace integration). The plan should call out which file leads which (Tauri's `tauri.conf.json` defines the build hook that drives Vite).
- **Settings record corruption recovery.** §8 says "settings corrupt → defaults + warning" but the dialog UX for "your settings record was corrupted; we're using defaults — fix by saving here" needs concrete wireframes during D.1.4 (when save UX is in scope).
- **Tauri-driver setup on Linux CI**. Out of D.1.1 scope, but a known cliff for whenever CI integration of L4 is picked up.
- **Mobile (D.3) Tauri 2 maturity**. Acknowledged in ADR 0007 — desktop is rock-solid, mobile likely has rougher edges. Detailed risk assessment deferred to when D.3 is planned.

### Issues currently open (carried from C.2 close, not affected by this session)

- #37 — Sub-project C umbrella. C.1 / C.1.1a / C.1.1b / C.2 ✅ complete; C.3 + C.4 still pending.
- #117 — `TtyVetoUx` re-prompt loop has no max-attempts cap. Low-priority.
- #120 — `matches_partial_pattern` allocates per call. Perf-only.
- #122 — `cli/src/daemon.rs` at ~777 LOC over the 500-LOC threshold. Should fold into whoever picks up C.3 next.
- #123 — daemon behavioural tests use 50-200 ms wall-clock windows. Speculative flake risk.
- #38, #45, #75, #76, #78, #79, #81, #87, #88, #90, #95, #98 — none affected by this session.

None of these block the D.1.1 plan or implementation.

### Housekeeping note (stale worktrees on disk)

After this PR merges, the C.2 task worktrees can be removed:

```bash
# From /Users/hherb/src/secretary, after this PR merges:
git worktree remove .worktrees/c1-1b-sync-merge && git branch -D feature/c1-1b-task-17
git worktree remove .worktrees/c2-task-1-spec   && git branch -D feature/c2-task-1-spec
for n in 1 2 3 4 5 6 7 8 9 10; do
  git worktree remove .worktrees/c2-task-$n     && git branch -D feature/c2-task-$n
done
# Keep `.worktrees/d11-tauri-spec` until this PR merges; remove after.
```

## (4) Exact commands to resume

```bash
# After this D.1.1 spec PR (feature/d11-tauri-spec) merges:
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                       # expect: clean
git checkout main
git pull --ff-only origin main

# Verify gauntlet on fresh main (expect 960 / 0 / 10 — no code added in this session,
# only docs):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check

# Next session: start D.1.1 Task 1.
# Reference: docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md
# The plan's Task 1 contains the worktree setup, file scaffolding, exact code blocks,
# and TDD step sequences. Just follow it.
#
# Alternatively, dispatch via superpowers:subagent-driven-development to execute
# Tasks 1-12 with a fresh subagent per task + review between.
```

## Closing inventory

- **Branch state on close:** `main` at `433393d` (C.2 Task 10 PR #128 merged). `feature/d11-tauri-spec` carries one commit on top (this spec + ADR + README/ROADMAP/desktop-README + handoff + symlink retarget).
- **Workspace tests on `feature/d11-tauri-spec`:** unchanged from main — **960 passed + 10 ignored** (no code added in this session).
- **README.md:** Sub-project D row rewritten for Tauri.
- **ROADMAP.md:** Sub-project D section restructured; "Where we are" bullet unchanged (D.1 still ⏳ — flips when implementation lands).
- **CLAUDE.md:** unchanged this session.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **`docs/adr/`:** ADR 0007 new, supersedes UI portion of ADR 0001.
- **`desktop/README.md`:** rewritten from one-line stub to proper layout + dev-loop quick-start.
- **Open issues:** see §(3) — none close with this PR.
- **Open PRs:** one to be opened at end of this session (D.1.1 spec).
- **Worktrees on disk:** stale C.2 task worktrees can be cleaned up (see §(3)); `feature/d11-tauri-spec` keeps until merge.
- **This file:** the live baton for the D.1.1 spec close. The next slice opens with a fresh handoff (`docs/handoffs/<date>-d11-plan-shipped.md` or similar).
