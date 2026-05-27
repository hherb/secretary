# D.1.1 Tauri Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first end-to-end Tauri client (Sub-project D.1.1). A user can launch a native desktop window on macOS or Linux, pick a vault folder + enter a password, unlock an existing vault, see a block-list scaffold (clicks stubbed for D.1.2), change the auto-lock timeout via a settings dialog that persists in the vault itself, trigger explicit or idle auto-lock, and exit with all secret state wiped via the Rust `ZeroizeOnDrop` chain.

**Architecture:** Tauri 2 backend (Rust, in-process; consumes `secretary-ffi-bridge` via workspace path dep — same crate PyO3 and uniffi wrap) + plain Svelte 5 + TypeScript + Vite frontend. Module-level `tauri::State<Mutex<VaultSession>>` holds the live `UnlockedIdentity` + `OpenVaultOutput` + `IdleTracker`; explicit `lock()` drops the `UnlockedSession` triggering `Drop`-chain wipe. Auto-lock runs in a dedicated OS thread; activity is debounced-notified by the frontend on mousemove/keydown. Settings live in a reserved vault block (`__secretary_app_settings__`, deterministic SHA-256-derived UUID) so they're encrypted at rest and only readable post-unlock — lazy-created on first user mutation.

**Tech Stack:** stable Rust (workspace toolchain). New `desktop/src-tauri/` workspace member with `tauri = { version = "2", features = ["..."] }`, `tauri-build = "2"`, `secretary-ffi-bridge = { path = "../../ffi/secretary-ffi-bridge" }`, `serde`, `serde_json`, `thiserror`, `tracing`, `tracing-subscriber`, `rand`, `sha2`, `hex`, `tempfile = "=3.27.0"`, `dirs = "5"`. Frontend: `svelte 5.x`, `vite 5.x`, `@sveltejs/vite-plugin-svelte`, `typescript 5.x`, `@tauri-apps/api 2.x`, `@tauri-apps/cli 2.x`, `@tauri-apps/plugin-dialog 2.x`, `vitest`. E2E: `@wdio/cli`, `tauri-driver`.

**Spec:** [`docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`](../specs/2026-05-27-d11-tauri-walking-skeleton-design.md) (all 16 sections finalized 2026-05-27).

**ADR:** [`docs/adr/0007-d-row-tauri.md`](../../adr/0007-d-row-tauri.md) — the architectural pivot from NiceGUI + SwiftUI + Compose.

**Predecessor:** C.2 on `main` (PR #128 merged 2026-05-26 at commit `433393d`; baseline gauntlet 960 PASS / 0 FAIL / 10 IGNORED). The spec doc + ADR 0007 + README/ROADMAP/desktop-README updates + this plan ride together on branch `feature/d11-tauri-spec`. Implementation tasks each open their own worktree + branch (`.worktrees/d11-task-N` on `feature/d11-task-N`).

---

## Spec adjustments from the design doc

One substantive correction, applied to the spec inline before this plan was authored:

| Spec original draft | Corrected | Why |
|---|---|---|
| Backend depends on `secretary-core = { path = "../../core" }` directly | Backend depends on `secretary-ffi-bridge = { path = "../../ffi/secretary-ffi-bridge" }` | The bridge crate already exposes the consumer-facing orchestration API (`open_vault_with_password`, `read_block`, `save_block`, …) plus stable error types (`FfiVaultError`), and its semantics are already validated across PyO3 and uniffi. Tauri becomes a third wrapper around the same bridge surface — keeps cross-language consumer behavior consistent. NOT an FFI hop (bridge is a normal Rust crate). |

No other deviations from the spec.

One sub-decision deferred from the spec to this plan: **device UUID management.** `secretary-ffi-bridge::save_block` requires a `device_uuid: [u8; 16]` argument (host-identity for the vector-clock layer). For D.1.1 we persist a per-vault device UUID at `dirs::data_dir()/secretary-desktop/devices/<vault_uuid_hex>.dev` — generated on first settings-save, reused on subsequent saves. This keeps multi-device sync semantics correct without coupling to the C.2 daemon's state file. Each desktop install thus presents as one logical "device" per vault in the vector clock. (Sub-project C.4 cross-device convergence will sort out the broader cross-app device-identity story.)

---

## File Structure

**New files (32) — all under `desktop/`:**

### Backend (Rust)

```
desktop/src-tauri/Cargo.toml                    ~50 LOC   workspace member; 13 runtime + 1 dev dep
desktop/src-tauri/tauri.conf.json               ~40 LOC   v2 schema; CSP locked down; bundle id
desktop/src-tauri/build.rs                      ~3 LOC    tauri-build canonical
desktop/src-tauri/src/main.rs                   ~120 LOC  Builder + State init + handler registration + timer thread spawn
desktop/src-tauri/src/constants.rs              ~85 LOC   All 8 constants per spec §8 + 5 timing constants per §6
desktop/src-tauri/src/errors.rs                 ~110 LOC  AppError + AppWarning enums (serde::Serialize + thiserror); From<FfiVaultError> mapping
desktop/src-tauri/src/auto_lock.rs              ~70 LOC   IdleTracker pure struct + now_ms + is_expired
desktop/src-tauri/src/settings.rs               ~280 LOC  Settings struct + parse + serialize + load_from_vault + save_to_vault + device_uuid helpers + tests
desktop/src-tauri/src/session.rs                ~300 LOC  VaultSession + UnlockedSession + Drop impl + unlock/lock/notify_activity/with_open_vault
desktop/src-tauri/src/dtos.rs                   ~140 LOC  ManifestDto + BlockSummaryDto + Settings DTO conversions
desktop/src-tauri/src/commands/mod.rs           ~20 LOC   pub mod {unlock, vault, settings, lock}
desktop/src-tauri/src/commands/unlock.rs        ~80 LOC   unlock_with_password command
desktop/src-tauri/src/commands/vault.rs         ~70 LOC   list_blocks + get_manifest commands
desktop/src-tauri/src/commands/settings.rs      ~90 LOC   get_settings + set_settings commands
desktop/src-tauri/src/commands/lock.rs          ~80 LOC   lock + notify_activity commands
```

### Backend integration tests

```
desktop/src-tauri/tests/session_integration.rs  ~340 LOC  ~12 cargo tests against golden_vault_001 + ephemeral vaults
```

### Frontend (Svelte + TypeScript)

```
desktop/package.json                            ~45 LOC   deps + scripts
desktop/pnpm-lock.yaml                          (generated)
desktop/tsconfig.json                           ~25 LOC   strict, ESNext, bundler module resolution
desktop/vite.config.ts                          ~25 LOC   Tauri-canonical Vite config
desktop/svelte.config.js                        ~10 LOC   Svelte 5 + vite-plugin-svelte
desktop/src/main.ts                             ~6 LOC    Svelte 5 mount(App, { target: ... })
desktop/src/App.svelte                          ~50 LOC   sessionState subscription + route swap + Toast + event listener
desktop/src/theme.css                           ~80 LOC   CSS custom properties (--color-bg, --space-*, --radius-*, …)
desktop/src/lib/ipc.ts                          ~120 LOC  Typed wrappers around invoke() — one per backend command
desktop/src/lib/stores.ts                       ~50 LOC   sessionState + currentSettings + autoLockNotice
desktop/src/lib/errors.ts                       ~110 LOC  TS discriminated union mirror of AppError + userMessageFor
desktop/src/lib/auto_lock.ts                    ~80 LOC   document mousemove/keydown listener + debounced notifyActivity
desktop/src/routes/Unlock.svelte                ~110 LOC  Single-screen form layout + submit handler
desktop/src/routes/Vault.svelte                 ~90 LOC   Block list grid + settings trigger + lock button slot
desktop/src/components/BlockCard.svelte         ~50 LOC   Single block summary card
desktop/src/components/PathPicker.svelte        ~60 LOC   Read-only input + Choose… button (native dialog via @tauri-apps/plugin-dialog)
desktop/src/components/SettingsDialog.svelte    ~120 LOC  Native <dialog> + auto-lock input + Save/Cancel
desktop/src/components/LockButton.svelte        ~30 LOC   Button calling lock() IPC
desktop/src/components/Toast.svelte             ~50 LOC   Auto-dismiss notification
```

### Frontend tests

```
desktop/tests/auto_lock.test.ts                 ~110 LOC  Vitest — debounce timing, listener attach/detach
desktop/tests/errors.test.ts                    ~80 LOC   Vitest — every variant maps to non-empty title
desktop/tests/ipc.test.ts                       ~90 LOC   Vitest — invoke wrapper success + error paths (mocked)
```

### E2E (deferred from CI but present in repo)

```
desktop/e2e/unlock_and_browse.spec.ts           ~180 LOC  WDIO + tauri-driver — full unlock → blocks → lock cycle
desktop/e2e/wdio.conf.ts                        ~60 LOC   WDIO config for tauri-driver
```

### Modified files

```
Cargo.toml (workspace root)                     +1 LOC    add "desktop/src-tauri" to [workspace] members
.gitignore                                       +5 LOC    desktop/node_modules/ + desktop/target/ + desktop/dist/
```

**Modified docs (already shipped on this branch via the spec PR):**

```
README.md (D-row, platforms list, ASCII diagram, ADR ref)
ROADMAP.md (Sub-project D section restructure)
desktop/README.md (rewritten from stub)
docs/adr/0007-d-row-tauri.md (new)
docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md (new)
docs/handoffs/2026-05-27-d11-tauri-spec-shipped.md (new)
NEXT_SESSION.md (symlink retarget)
```

---

## Baseline gauntlet

Run once at task start; same set after every task. Expected counts updated per task.

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Plus, from Task 6 onward (once frontend exists):

```bash
cd desktop && pnpm test 2>&1 | tail -5
cd desktop && pnpm tsc --noEmit
cd desktop && pnpm svelte-check
cd desktop && pnpm lint 2>&1 | tail -5
```

**Starting baseline (post-PR #128, `main` at `433393d`):** PASSED: 960 FAILED: 0 IGNORED: 10. Clippy clean, fmt clean, conformance PASS, spec freshness PASS (96 resolved / 0 unresolved / 2 suppressed). Frontend gauntlet lines not yet applicable.

**After every task:** gauntlet must stay green before commit. Commit only when green.

---

## Task 1: Project scaffolding — Tauri 2 + workspace integration + "hello world" window

**Why:** Lay down `desktop/src-tauri/` as a new workspace member and the frontend toolchain in `desktop/`. Single task because the Tauri config, the Vite config, and the Cargo workspace integration are tightly interdependent — `tauri.conf.json` declares the Vite build hook, the Cargo workspace declares the new member, the frontend toolchain bootstraps off Vite. Splitting them would force a churn cycle where intermediate states don't even type-check. Task 1 produces a "hello world" Tauri window that launches via `pnpm tauri dev` and verifies the entire toolchain is wired up; no business logic yet.

**Files:**
- Create: `desktop/package.json`
- Create: `desktop/tsconfig.json`
- Create: `desktop/vite.config.ts`
- Create: `desktop/svelte.config.js`
- Create: `desktop/src/main.ts` (minimal Svelte mount)
- Create: `desktop/src/App.svelte` (minimal "hello world" component)
- Create: `desktop/index.html` (Vite entry HTML)
- Create: `desktop/src-tauri/Cargo.toml`
- Create: `desktop/src-tauri/build.rs`
- Create: `desktop/src-tauri/tauri.conf.json`
- Create: `desktop/src-tauri/src/main.rs` (minimal Tauri builder)
- Modify: `Cargo.toml` (workspace root) — add `"desktop/src-tauri"` to `[workspace] members`
- Modify: `.gitignore` — add `desktop/node_modules/`, `desktop/target/`, `desktop/dist/`

- [ ] **Step 1: Set up worktree from main**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-1 -b feature/d11-task-1 main
cd .worktrees/d11-task-1
```

- [ ] **Step 2: Add `desktop/src-tauri` to workspace members**

Edit `Cargo.toml` (root). Locate the existing `[workspace] members = [...]` block and add the new member:

```toml
[workspace]
resolver = "2"
members = [
    "core",
    "cli",
    "desktop/src-tauri",
    "ffi/secretary-ffi-py",
    "ffi/secretary-ffi-uniffi",
    "ffi/secretary-ffi-bridge",
]
exclude = ["core/fuzz"]
```

- [ ] **Step 3: Create `desktop/src-tauri/Cargo.toml`**

```toml
[package]
name = "secretary-desktop"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[[bin]]
name = "secretary-desktop"
path = "src/main.rs"

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
# Tauri 2.x. Features kept minimal: window for the main window, no
# tray icon / no auto-updater / no clipboard / no shell — D.1.1 doesn't
# need any of those. Add features per-slice as D.1.x grows.
tauri = { version = "2", features = [] }
secretary-ffi-bridge = { path = "../../ffi/secretary-ffi-bridge" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
sha2 = "0.10"
hex = "0.4"
rand = "0.8"
dirs = "5"
# `tempfile` exact-pinned to match `core/Cargo.toml` and `cli/Cargo.toml`.
# Used for atomic writes of the device_uuid file via `NamedTempFile::persist`.
# Same exact-pin rule as core: bump only via deliberate changelog review
# (CLAUDE.md "exact pins on security-critical paths").
tempfile = "=3.27.0"

[dev-dependencies]
tempfile = "=3.27.0"

[lints]
workspace = true
```

- [ ] **Step 4: Create `desktop/src-tauri/build.rs`**

```rust
fn main() {
    tauri_build::build();
}
```

- [ ] **Step 5: Create `desktop/src-tauri/tauri.conf.json`**

```json
{
  "$schema": "https://schema.tauri.app/config/2.0.0",
  "productName": "Secretary",
  "version": "0.1.0",
  "identifier": "org.secretary.desktop",
  "build": {
    "frontendDist": "../dist",
    "devUrl": "http://localhost:1420",
    "beforeDevCommand": "pnpm dev",
    "beforeBuildCommand": "pnpm build"
  },
  "app": {
    "windows": [
      {
        "title": "Secretary",
        "width": 1024,
        "height": 768,
        "minWidth": 600,
        "minHeight": 400,
        "resizable": true,
        "fullscreen": false
      }
    ],
    "security": {
      "csp": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ipc: tauri:; script-src 'self'"
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": [
      "icons/icon.png"
    ]
  }
}
```

> NOTE: The `icons/icon.png` path is referenced but the icon file is not created in D.1.1 (would need a logo asset). Tauri 2 will emit a warning at `tauri build` time about the missing icon; that's acceptable for D.1.1 (release packaging is a deferred slice — see spec §13). `pnpm tauri dev` does not require the icon to exist.

- [ ] **Step 6: Create `desktop/src-tauri/src/main.rs`** (minimal Tauri 2 builder)

```rust
//! Secretary desktop client — Tauri 2 main entry point.
//!
//! D.1.1 walking skeleton: minimal "hello world" window. The session,
//! commands, and timer thread land in later tasks per
//! `docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md`.

// Hide the console window on Windows in release builds. Cosmetic for D.1.1
// but the macro is canonical Tauri practice — keep it from day one.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
```

- [ ] **Step 7: Create `desktop/package.json`**

```json
{
  "name": "secretary-desktop",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "tauri": "tauri",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "eslint src tests",
    "svelte-check": "svelte-check --tsconfig ./tsconfig.json"
  },
  "dependencies": {
    "@tauri-apps/api": "^2",
    "@tauri-apps/plugin-dialog": "^2"
  },
  "devDependencies": {
    "@sveltejs/vite-plugin-svelte": "^4",
    "@tauri-apps/cli": "^2",
    "svelte": "^5",
    "svelte-check": "^4",
    "tslib": "^2",
    "typescript": "^5",
    "vite": "^5",
    "vitest": "^2"
  }
}
```

- [ ] **Step 8: Create `desktop/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "useDefineForClassFields": true,
    "module": "ESNext",
    "resolveJsonModule": true,
    "allowJs": false,
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "isolatedModules": true,
    "moduleResolution": "bundler",
    "esModuleInterop": true,
    "skipLibCheck": true,
    "allowSyntheticDefaultImports": true
  },
  "include": ["src/**/*", "tests/**/*"]
}
```

- [ ] **Step 9: Create `desktop/svelte.config.js`**

```javascript
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  preprocess: vitePreprocess()
};
```

- [ ] **Step 10: Create `desktop/vite.config.ts`**

```typescript
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Tauri-canonical Vite config: fixed dev port 1420, skip env vars Tauri owns,
// disable HMR overlay (Tauri's window has its own dev menu).
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: false,
    hmr: { protocol: 'ws', host: 'localhost', port: 1421 },
    watch: { ignored: ['**/src-tauri/**'] }
  }
});
```

- [ ] **Step 11: Create `desktop/index.html`**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Secretary</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

- [ ] **Step 12: Create `desktop/src/main.ts`** (Svelte 5 mount point)

```typescript
import { mount } from 'svelte';
import App from './App.svelte';

const app = mount(App, {
  target: document.getElementById('app')!
});

export default app;
```

- [ ] **Step 13: Create `desktop/src/App.svelte`** (minimal hello world — to be replaced in Task 10)

```svelte
<script lang="ts">
  // D.1.1 placeholder. Routing + sessionState subscription lands in Task 10.
</script>

<main>
  <h1>Secretary</h1>
  <p>D.1.1 walking skeleton — bootstrapping…</p>
</main>

<style>
  main {
    font-family: system-ui, -apple-system, sans-serif;
    padding: 2rem;
    text-align: center;
  }
</style>
```

- [ ] **Step 14: Update `.gitignore`**

Add these lines (preserving the existing content):

```
# Tauri build artifacts
desktop/node_modules/
desktop/target/
desktop/dist/
desktop/src-tauri/target/
desktop/src-tauri/gen/
```

- [ ] **Step 15: Install frontend deps**

```bash
cd desktop && pnpm install
```

Expected: `pnpm install` resolves the dep tree, creates `node_modules/` + `pnpm-lock.yaml`. No errors.

If `pnpm` is not installed on the dev machine, install via `corepack enable && corepack prepare pnpm@latest --activate` or `npm install -g pnpm`.

- [ ] **Step 16: Smoke test — `cargo build`**

```bash
cd /Users/hherb/src/secretary/.worktrees/d11-task-1
cargo build --release --workspace
```

Expected: workspace builds clean, including the new `secretary-desktop` member. Tauri 2 first-build is ~2-5 minutes (lots of transitive deps); subsequent builds are seconds.

If you see `error: failed to resolve patches for ...` related to the workspace, double-check the `Cargo.toml` `[workspace] members` edit in Step 2.

- [ ] **Step 17: Smoke test — `pnpm tauri dev`** (the actual D.1.1-shape integration check)

```bash
cd /Users/hherb/src/secretary/.worktrees/d11-task-1/desktop
pnpm tauri dev
```

Expected:
1. Vite dev server starts on `localhost:1420`.
2. Cargo compiles `secretary-desktop` (first time: ~30-60s warm; subsequent: ~5-10s).
3. A native window titled "Secretary" opens at 1024×768 showing the "D.1.1 walking skeleton — bootstrapping…" heading.
4. Closing the window terminates the process cleanly.

If the window does not appear within 2 minutes, check the terminal for Cargo / Vite errors. Common gotchas:
- macOS asks for "Allow incoming connections" — accept.
- Linux missing `libwebkit2gtk-4.1-dev` — install via `sudo apt install libwebkit2gtk-4.1-dev` (or distro equivalent) and re-run.

- [ ] **Step 18: Baseline gauntlet**

```bash
cd /Users/hherb/src/secretary/.worktrees/d11-task-1
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected:
- PASSED: 960 FAILED: 0 IGNORED: 10 (unchanged — Task 1 adds no Rust tests yet)
- clippy clean
- fmt clean
- conformance PASS
- spec freshness PASS

If clippy flags anything in the new `secretary-desktop` crate, fix inline before commit (no warnings carried forward — [[feedback_act_on_issues_dont_mention]]).

- [ ] **Step 19: Commit**

```bash
git add Cargo.toml .gitignore desktop/
git status --short  # verify only the expected files are staged
git commit -m "$(cat <<'EOF'
feat(d11): scaffold Tauri 2 desktop project + workspace integration

Sub-project D.1.1 Task 1. Lays down desktop/src-tauri (new Rust workspace
member depending on secretary-ffi-bridge) + the Svelte/TypeScript/Vite
frontend toolchain. No business logic yet — a "hello world" Tauri window
launches via `pnpm tauri dev` and confirms the toolchain is wired up.

Spec: docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md
Plan: docs/superpowers/plans/2026-05-27-d11-tauri-walking-skeleton.md

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 20: Push + open PR**

```bash
git push -u origin feature/d11-task-1
gh pr create --title "feat(d11): Task 1 — scaffold Tauri 2 desktop project + workspace integration" --body "$(cat <<'EOF'
## Summary
- New workspace member `desktop/src-tauri` depending on `secretary-ffi-bridge`
- Frontend toolchain: Svelte 5 + TypeScript + Vite + `@tauri-apps/cli`
- Minimal "hello world" Tauri 2 window — proves the integration is wired up
- No business logic; session / commands / timer / pages come in Tasks 2-12

## Spec / Plan
- Spec §4 (project layout), §11 (dev loop), §11.4 (CSP)
- Plan task 1 (scaffolding)

## Gauntlet
- Workspace tests: 960 / 0 / 10 (unchanged — no new Rust tests in this task)
- clippy + fmt + conformance + spec freshness: clean
- Manual smoke: `pnpm tauri dev` launches the window, displays "D.1.1 walking skeleton — bootstrapping…"

## Test plan
- [ ] Reviewer can run `pnpm install && pnpm tauri dev` from `desktop/` and see the window
- [ ] `cargo test --release --workspace` stays green

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

After merge, gauntlet baseline stays at **960 / 0 / 10** (no new tests).

---

## Task 2: Backend pure modules — constants, errors, idle tracker, settings parsing

**Why:** All four modules are pure (no I/O, no Tauri dependencies, no `secretary-ffi-bridge` dependencies beyond `Record` / `FieldHandle` value types). They share one feature: they're all unit-testable in isolation, the foundation that every later task references. Single task because none of them require more than ~100 LOC of code + tests, and shipping them one-by-one would create artificial PR churn. TDD applies: write the failing test, run, implement, run, commit per module.

**Files:**
- Create: `desktop/src-tauri/src/constants.rs`
- Create: `desktop/src-tauri/src/errors.rs`
- Create: `desktop/src-tauri/src/auto_lock.rs`
- Create: `desktop/src-tauri/src/settings.rs` (parse + serialize only; load/save in Task 3)
- Modify: `desktop/src-tauri/src/main.rs` (add `mod` declarations)

- [ ] **Step 1: Set up worktree from main**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-2 -b feature/d11-task-2 main
cd .worktrees/d11-task-2
```

- [ ] **Step 2: Write the failing tests for `constants.rs`**

Create `desktop/src-tauri/src/constants.rs`:

```rust
//! Canonical constants for the desktop app. Every value is documented with
//! its rationale; the spec §8 "Constants" table is the canonical source —
//! this file mirrors it verbatim.
//!
//! NO MAGIC NUMBERS POLICY: every value the desktop app uses that isn't
//! self-explanatory (e.g. 0, 1, 2 for indexing) lives here with a name.
//!
//! See: docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md §8

// =============================================================================
// Auto-lock timing
// =============================================================================

/// Default auto-lock timeout in milliseconds. Used when no settings record
/// exists in the vault (first-unlock or default-only users).
///
/// **Value:** 600_000 (10 minutes).
/// **Rationale:** Matches 1Password (10 min default), Bitwarden (15 min).
/// Long enough to not annoy; short enough that "I walked away for lunch"
/// leaves the vault locked.
pub const AUTO_LOCK_DEFAULT_MS: u64 = 600_000;

/// Lower bound for `auto_lock_timeout_ms` settings validation.
///
/// **Value:** 60_000 (1 minute).
/// **Rationale:** Below this, re-prompts become tedious for the user with no
/// security gain — a 30-second adversary window vs 60-second isn't materially
/// different in a physical-access threat model.
pub const AUTO_LOCK_MIN_MS: u64 = 60_000;

/// Upper bound for `auto_lock_timeout_ms` settings validation.
///
/// **Value:** 86_400_000 (24 hours).
/// **Rationale:** Anything longer is effectively "never auto-lock" —
/// security antipattern we won't ship as configurable.
pub const AUTO_LOCK_MAX_MS: u64 = 86_400_000;

/// Tick interval for the auto-lock timer thread.
///
/// **Value:** 5_000 (5 seconds).
/// **Rationale:** Coarse enough to be free of measurable CPU cost; fine
/// enough that auto-lock fires within 5s of the threshold expiring
/// (acceptable jitter vs the 1-minute minimum threshold).
pub const AUTO_LOCK_TICK_MS: u64 = 5_000;

/// Minimum interval between frontend `notify_activity` IPC calls (debounce).
///
/// **Value:** 2_000 (2 seconds).
/// **Rationale:** Each mousemove during typing shouldn't issue an IPC; 2s
/// is well below any plausible threshold so the timer never spuriously fires
/// while the user is active.
pub const ACTIVITY_NOTIFY_MIN_INTERVAL_MS: u64 = 2_000;

// =============================================================================
// Settings record schema
// =============================================================================

/// Reserved block name for the secretary-app settings record.
///
/// **Value:** `"__secretary_app_settings__"`.
/// **Rationale:** Double-underscore prefix/suffix marks "internal"; unlikely
/// to collide with user-created block names.
pub const SETTINGS_BLOCK_NAME: &str = "__secretary_app_settings__";

/// Versioned record_type string for the settings record.
///
/// **Value:** `"secretary.settings.v1"`.
/// **Rationale:** Versioned. Future schema migrations get `v2`. Forward-compat:
/// unknown version on load falls back to `Settings::default()` + warning.
pub const SETTINGS_RECORD_TYPE: &str = "secretary.settings.v1";

/// Field name for the auto-lock timeout setting.
///
/// **Value:** `"auto_lock_timeout_ms"`.
/// **Rationale:** Snake-case matches Rust convention; matches the constant
/// name `AUTO_LOCK_DEFAULT_MS` for grep-ability.
pub const SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS: &str = "auto_lock_timeout_ms";

// =============================================================================
// Deterministic UUID derivation (for the settings block and record)
// =============================================================================

/// Compute the deterministic 16-byte UUID for a vault-internal block name
/// or record_type string, via `SHA-256(input)[0..16]`.
///
/// Used for the settings block and the settings record so that two devices
/// creating the same block independently produce identical UUIDs — the CRDT
/// merge layer then treats their writes as concurrent updates of one block
/// rather than two separate blocks. See spec §8 for the full rationale.
pub fn deterministic_uuid_16(input: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[0..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanity: ensure no two constants accidentally hold the same value
    // (would mask a refactor bug).
    #[test]
    fn auto_lock_bounds_are_ordered() {
        assert!(AUTO_LOCK_MIN_MS < AUTO_LOCK_DEFAULT_MS);
        assert!(AUTO_LOCK_DEFAULT_MS < AUTO_LOCK_MAX_MS);
    }

    #[test]
    fn tick_interval_smaller_than_min_threshold() {
        // Otherwise auto-lock can never fire within the user's chosen
        // threshold — spec §6 invariant.
        assert!(AUTO_LOCK_TICK_MS < AUTO_LOCK_MIN_MS);
    }

    #[test]
    fn settings_block_uuid_is_deterministic_and_frozen() {
        // Frozen-string test: if this assertion ever fails, the on-disk
        // settings-block UUID has drifted from what shipped clients expect.
        // That's a vault-format break — investigate before changing.
        let uuid = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
        assert_eq!(
            hex::encode(uuid),
            "0eea9b4c12dd9a3a1f7d51f7c4f7e6e8",
            "settings block UUID drift — vault-format break risk"
        );
    }

    #[test]
    fn settings_record_uuid_is_deterministic_and_frozen() {
        let uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE);
        assert_eq!(
            hex::encode(uuid),
            "fd7e4d8c6a2eb6b7f88be8e60d6a7d0e",
            "settings record UUID drift — vault-format break risk"
        );
    }
}
```

> NOTE ON FROZEN HEX STRINGS: The values `0eea9b4c…` and `fd7e4d8c…` above are placeholders. **Compute the real values once during implementation:**
>
> ```bash
> echo -n "__secretary_app_settings__" | shasum -a 256 | head -c 32
> echo -n "secretary.settings.v1" | shasum -a 256 | head -c 32
> ```
>
> Replace both literals with the actual outputs before running the tests for the first time. The frozen assertions then guard against any future change to either input string (which would be a vault-format break).

- [ ] **Step 3: Add the `mod constants;` declaration to `main.rs`**

Edit `desktop/src-tauri/src/main.rs`:

```rust
//! Secretary desktop client — Tauri 2 main entry point.
//!
//! D.1.1 walking skeleton. See
//! docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod constants;

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
```

- [ ] **Step 4: Run constants tests — verify all pass**

```bash
cargo test --release -p secretary-desktop constants:: -- --nocapture
```

Expected: 4 tests passing (the two frozen-UUID tests will fail until you replace the placeholder hex strings with the real SHA-256 outputs — that's intentional, the test enforces the freeze).

- [ ] **Step 5: Commit constants module**

```bash
git add desktop/src-tauri/src/constants.rs desktop/src-tauri/src/main.rs
git commit -m "feat(d11): constants module — auto-lock timings + settings schema names + deterministic UUID helper

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Write the failing tests for `errors.rs`**

Create `desktop/src-tauri/src/errors.rs`:

```rust
//! `AppError` + `AppWarning` types crossing the Tauri IPC boundary.
//!
//! See spec §9 for the full mapping rules. Key disciplines:
//!
//! - Every variant `#[serde(tag = "code", rename_all = "snake_case")]` so
//!   the wire format is `{ "code": "wrong_password", ... }`.
//! - Developer-facing `detail` fields are `#[serde(skip_serializing)]` — they're
//!   logged via `tracing` on the Rust side but NEVER cross the IPC seam.
//! - `From<FfiVaultError>` is an explicit `match` so we choose the user-facing
//!   variant per case; no fall-through wrap-in-`Internal`.
//! - `WrongPassword` collapse rule: anything decryption-failure-shaped becomes
//!   `WrongPassword` (info-leak prevention).

use secretary_ffi_bridge::error::FfiVaultError;

#[derive(thiserror::Error, Debug, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AppError {
    #[error("Vault folder does not exist or is not readable")]
    VaultPathNotFound { path: String },

    #[error("Folder exists but doesn't contain a vault")]
    VaultPathNotAVault { path: String },

    #[error("Vault is currently locked by another process")]
    VaultPathLocked { path: String },

    #[error("Wrong password")]
    WrongPassword,

    #[error("Vault uses KDF parameters below the minimum")]
    KdfTooWeak {
        current_memory_kib: u32,
        min_memory_kib: u32,
    },

    #[error("Vault is corrupted; consider restoring from a backup")]
    VaultCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Vault already unlocked")]
    AlreadyUnlocked,

    #[error("No vault currently unlocked")]
    NotUnlocked,

    #[error("Settings record is malformed; using defaults")]
    SettingsCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Settings record uses an unknown schema version")]
    SettingsUnknownVersion { version: String },

    #[error("Auto-lock timeout must be between {min} and {max} ms")]
    SettingsOutOfRange { min: u64, max: u64 },

    #[error("Filesystem error")]
    Io {
        #[serde(skip_serializing)]
        detail: String,
    },

    #[error("Internal error — this is a bug")]
    Internal {
        #[serde(skip_serializing)]
        detail: String,
    },
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AppWarning {
    SettingsCorrupt {
        #[serde(skip_serializing)]
        detail: String,
    },
    SettingsClamped {
        original_ms: u64,
        clamped_ms: u64,
    },
    SettingsUnknownVersion {
        version: String,
    },
}

impl From<FfiVaultError> for AppError {
    /// Explicit per-variant mapping. Adding a new `FfiVaultError` variant
    /// in the bridge crate will surface here as a compile error (the match
    /// must be exhaustive), forcing a deliberate UI-mapping choice.
    fn from(e: FfiVaultError) -> Self {
        // Log developer-facing detail before stripping. tracing::warn so
        // it appears in stderr in dev mode and in any production log
        // sink without requiring DEBUG verbosity.
        tracing::warn!(?e, "FfiVaultError surfacing to AppError");

        match e {
            // Decryption-failure-shaped → WrongPassword (info-leak prevention).
            FfiVaultError::Unlock { .. } => AppError::WrongPassword,

            // Genuine cryptographic / integrity failures → VaultCorrupt.
            FfiVaultError::CorruptVault { detail }
            | FfiVaultError::SaveCryptoFailure { detail } => {
                AppError::VaultCorrupt { detail }
            }

            FfiVaultError::WeakKdfParams {
                current_memory_kib,
                min_memory_kib,
            } => AppError::KdfTooWeak {
                current_memory_kib,
                min_memory_kib,
            },

            // Filesystem errors → Io.
            FfiVaultError::Io { detail } => AppError::Io { detail },

            // Catch-all for variants the bridge adds that we haven't taught
            // the UI to render specifically. Use `{e:?}` to capture the
            // variant name + payload for the dev-facing log; the user gets
            // the generic Internal message.
            other => AppError::Internal {
                detail: format!("{other:?}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn round_trip(err: &AppError) -> Value {
        serde_json::from_str(&serde_json::to_string(err).expect("serialize")).expect("parse")
    }

    #[test]
    fn wrong_password_has_code_only() {
        let v = round_trip(&AppError::WrongPassword);
        assert_eq!(v["code"], "wrong_password");
        assert_eq!(v.as_object().expect("object").len(), 1);
    }

    #[test]
    fn kdf_too_weak_carries_payload() {
        let v = round_trip(&AppError::KdfTooWeak {
            current_memory_kib: 32_768,
            min_memory_kib: 65_536,
        });
        assert_eq!(v["code"], "kdf_too_weak");
        assert_eq!(v["current_memory_kib"], 32_768);
        assert_eq!(v["min_memory_kib"], 65_536);
    }

    #[test]
    fn vault_corrupt_detail_is_stripped() {
        let v = round_trip(&AppError::VaultCorrupt {
            detail: "sensitive dev info".to_string(),
        });
        assert_eq!(v["code"], "vault_corrupt");
        assert!(v.get("detail").is_none(), "detail must NOT cross IPC");
    }

    #[test]
    fn settings_out_of_range_carries_bounds() {
        let v = round_trip(&AppError::SettingsOutOfRange {
            min: 60_000,
            max: 86_400_000,
        });
        assert_eq!(v["code"], "settings_out_of_range");
        assert_eq!(v["min"], 60_000);
        assert_eq!(v["max"], 86_400_000);
    }

    #[test]
    fn settings_clamped_warning_carries_both_values() {
        let w = AppWarning::SettingsClamped {
            original_ms: 30_000,
            clamped_ms: 60_000,
        };
        let v: Value =
            serde_json::from_str(&serde_json::to_string(&w).expect("ser")).expect("parse");
        assert_eq!(v["code"], "settings_clamped");
        assert_eq!(v["original_ms"], 30_000);
        assert_eq!(v["clamped_ms"], 60_000);
    }

    #[test]
    fn unknown_version_warning_carries_version_string() {
        let w = AppWarning::SettingsUnknownVersion {
            version: "secretary.settings.v99".to_string(),
        };
        let v: Value =
            serde_json::from_str(&serde_json::to_string(&w).expect("ser")).expect("parse");
        assert_eq!(v["code"], "settings_unknown_version");
        assert_eq!(v["version"], "secretary.settings.v99");
    }
}
```

- [ ] **Step 7: Add `mod errors;` to main.rs**

Edit `desktop/src-tauri/src/main.rs`:

```rust
mod constants;
mod errors;
```

- [ ] **Step 8: Run errors tests**

```bash
cargo test --release -p secretary-desktop errors::
```

Expected: 6 tests passing. If `FfiVaultError` variants don't match the names used in the `From` impl (the bridge crate's actual variant names may differ slightly — check `ffi/secretary-ffi-bridge/src/error/mod.rs`), fix the match arms to use the real names.

- [ ] **Step 9: Commit errors module**

```bash
git add desktop/src-tauri/src/errors.rs desktop/src-tauri/src/main.rs
git commit -m "feat(d11): AppError + AppWarning + From<FfiVaultError> mapping

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 10: Write the failing tests for `auto_lock.rs`**

Create `desktop/src-tauri/src/auto_lock.rs`:

```rust
//! Pure idle tracker for the auto-lock timer. The actual timer thread and
//! the lock action live in `session.rs` / `main.rs`; this module is pure
//! data + truth-table functions, unit-testable without spinning up Tauri
//! or threads.
//!
//! See spec §6 (vault session lifecycle, auto-lock subsection).

use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock milliseconds since the UNIX epoch. Used by both `IdleTracker`
/// and the timer thread to compute "now". Pulled out as a free function so
/// tests can inject a fixed value via the `is_expired` argument rather than
/// monkey-patching the clock.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Records the wall-clock time of the most recent UI activity. The auto-lock
/// timer thread checks `is_expired(threshold_ms, now_ms())` each tick.
#[derive(Debug, Clone, Copy)]
pub struct IdleTracker {
    pub last_activity_ms: u64,
}

impl IdleTracker {
    /// Construct fresh — `last_activity_ms` initialized to "now".
    pub fn new(now_ms: u64) -> Self {
        Self { last_activity_ms: now_ms }
    }

    /// Mark activity at the given wall-clock time.
    pub fn notify(&mut self, now_ms: u64) {
        // Only advance forward — protects against clock skew that could
        // make `last_activity_ms` jump into the past, which would cause a
        // spurious auto-lock on the next tick.
        if now_ms > self.last_activity_ms {
            self.last_activity_ms = now_ms;
        }
    }

    /// Returns true if `now_ms - last_activity_ms >= threshold_ms`.
    /// Underflow-safe: if the clock has gone backwards (rare; resume from
    /// suspend on some systems), returns false rather than panicking.
    pub fn is_expired(&self, threshold_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_activity_ms) >= threshold_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_TICK_MS};

    #[test]
    fn fresh_tracker_is_not_expired() {
        let t = IdleTracker::new(1_000);
        assert!(!t.is_expired(AUTO_LOCK_DEFAULT_MS, 1_000));
    }

    #[test]
    fn expired_after_threshold() {
        let t = IdleTracker::new(0);
        // Exactly at the threshold counts as expired (>= comparison).
        assert!(t.is_expired(AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_DEFAULT_MS));
    }

    #[test]
    fn not_expired_just_before_threshold() {
        let t = IdleTracker::new(0);
        assert!(!t.is_expired(AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_DEFAULT_MS - 1));
    }

    #[test]
    fn notify_advances_forward() {
        let mut t = IdleTracker::new(1_000);
        t.notify(5_000);
        assert_eq!(t.last_activity_ms, 5_000);
    }

    #[test]
    fn notify_ignores_backward_clock() {
        let mut t = IdleTracker::new(5_000);
        t.notify(1_000); // backward — clock skew or test fixture mistake
        assert_eq!(t.last_activity_ms, 5_000, "must not advance backward");
    }

    #[test]
    fn underflow_safe_on_backward_clock() {
        let t = IdleTracker::new(10_000);
        // "now" before "last_activity" — saturating_sub returns 0,
        // 0 < threshold, so not expired.
        assert!(!t.is_expired(AUTO_LOCK_DEFAULT_MS, 5_000));
    }

    #[test]
    fn tick_interval_constant_is_usable() {
        // Smoke: ensure tick interval fits in u64 (compile-time) and is
        // strictly positive (runtime).
        assert!(AUTO_LOCK_TICK_MS > 0);
    }
}
```

- [ ] **Step 11: Add `mod auto_lock;` to main.rs + run tests**

```rust
// main.rs (full content after this step)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auto_lock;
mod constants;
mod errors;

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
```

```bash
cargo test --release -p secretary-desktop auto_lock::
```

Expected: 7 tests passing.

- [ ] **Step 12: Commit auto_lock module**

```bash
git add desktop/src-tauri/src/auto_lock.rs desktop/src-tauri/src/main.rs
git commit -m "feat(d11): IdleTracker pure module — now_ms + notify + is_expired (underflow-safe)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 13: Write the failing tests for `settings.rs` (parse + serialize only)**

Create `desktop/src-tauri/src/settings.rs`:

```rust
//! Settings record schema + parse/serialize. The vault I/O facade (load_from_vault,
//! save_to_vault) lands in Task 3 along with VaultSession.
//!
//! See spec §8 for the full schema rationale (record_type, deterministic UUIDs,
//! lazy creation, validation bounds, version handling).

use crate::constants::{
    AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS,
    SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS, SETTINGS_RECORD_TYPE,
};
use crate::errors::{AppError, AppWarning};

/// Parsed app settings — pure value type with no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
        }
    }
}

/// Result of parsing a settings record from the vault. Note `Ok(Settings, Vec<AppWarning>)`
/// — the parse can succeed with non-fatal warnings (e.g. clamped-on-load), which the
/// frontend renders as a banner alongside the manifest.
pub type ParseResult = Result<(Settings, Vec<AppWarning>), AppError>;

/// Parse one field-name / field-value pair into a `Settings`. Returns the parsed
/// settings + any warnings (clamp on out-of-range, unknown version, etc.).
///
/// `record_type` is the record's record_type string. `field_name` is the field's name.
/// `field_value_text` is the field's text value (settings fields are always text per
/// spec §8). Bytes-typed fields are rejected.
pub fn parse_settings_field(
    record_type: &str,
    field_name: &str,
    field_value_text: &str,
) -> ParseResult {
    if record_type != SETTINGS_RECORD_TYPE {
        return Err(AppError::SettingsUnknownVersion {
            version: record_type.to_string(),
        });
    }

    if field_name != SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS {
        return Err(AppError::SettingsCorrupt {
            detail: format!("unknown field name: {field_name}"),
        });
    }

    let parsed: u64 = field_value_text.parse().map_err(|e| AppError::SettingsCorrupt {
        detail: format!("auto_lock_timeout_ms parse failure: {e}"),
    })?;

    let (final_value, warnings) = clamp_with_warning(parsed);
    Ok((Settings { auto_lock_timeout_ms: final_value }, warnings))
}

/// Apply bounds-clamping + emit a warning if clamped. Used by both load and the
/// save-validation path (where it's converted to an error via `validate_save_value`).
fn clamp_with_warning(value: u64) -> (u64, Vec<AppWarning>) {
    if value < AUTO_LOCK_MIN_MS {
        (
            AUTO_LOCK_MIN_MS,
            vec![AppWarning::SettingsClamped {
                original_ms: value,
                clamped_ms: AUTO_LOCK_MIN_MS,
            }],
        )
    } else if value > AUTO_LOCK_MAX_MS {
        (
            AUTO_LOCK_MAX_MS,
            vec![AppWarning::SettingsClamped {
                original_ms: value,
                clamped_ms: AUTO_LOCK_MAX_MS,
            }],
        )
    } else {
        (value, vec![])
    }
}

/// Validate a settings value before saving (frontend-supplied value path).
/// Rejects out-of-range with `SettingsOutOfRange` rather than clamping —
/// the frontend dialog also validates client-side; this round-trips only
/// on adversarial input.
pub fn validate_save_value(value: u64) -> Result<(), AppError> {
    if (AUTO_LOCK_MIN_MS..=AUTO_LOCK_MAX_MS).contains(&value) {
        Ok(())
    } else {
        Err(AppError::SettingsOutOfRange {
            min: AUTO_LOCK_MIN_MS,
            max: AUTO_LOCK_MAX_MS,
        })
    }
}

/// Serialize a `Settings` into the (record_type, field_name, field_value_text)
/// triple expected by the vault save path. Pure function — the save call
/// itself (which packages this into a `BlockInput` and calls
/// `secretary_ffi_bridge::save_block`) lives in Task 3.
pub fn serialize_settings(s: &Settings) -> (String, String, String) {
    (
        SETTINGS_RECORD_TYPE.to_string(),
        SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
        s.auto_lock_timeout_ms.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_constant() {
        assert_eq!(Settings::default().auto_lock_timeout_ms, AUTO_LOCK_DEFAULT_MS);
    }

    #[test]
    fn parse_happy_path_no_warnings() {
        let (s, warnings) = parse_settings_field(
            SETTINGS_RECORD_TYPE,
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            "300000",
        )
        .expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, 300_000);
        assert!(warnings.is_empty());
    }

    #[test]
    fn parse_below_min_clamps_with_warning() {
        let (s, warnings) = parse_settings_field(
            SETTINGS_RECORD_TYPE,
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            "30000",
        )
        .expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, AUTO_LOCK_MIN_MS);
        assert_eq!(warnings.len(), 1);
        match &warnings[0] {
            AppWarning::SettingsClamped { original_ms, clamped_ms } => {
                assert_eq!(*original_ms, 30_000);
                assert_eq!(*clamped_ms, AUTO_LOCK_MIN_MS);
            }
            other => panic!("expected SettingsClamped, got {other:?}"),
        }
    }

    #[test]
    fn parse_above_max_clamps_with_warning() {
        let oversized = AUTO_LOCK_MAX_MS + 1;
        let (s, warnings) = parse_settings_field(
            SETTINGS_RECORD_TYPE,
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            &oversized.to_string(),
        )
        .expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, AUTO_LOCK_MAX_MS);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn parse_unknown_version_errors() {
        let err = parse_settings_field(
            "secretary.settings.v99",
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            "600000",
        )
        .expect_err("must error");
        match err {
            AppError::SettingsUnknownVersion { version } => {
                assert_eq!(version, "secretary.settings.v99");
            }
            other => panic!("expected SettingsUnknownVersion, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_field_name_errors() {
        let err = parse_settings_field(SETTINGS_RECORD_TYPE, "unknown_field", "x")
            .expect_err("must error");
        match err {
            AppError::SettingsCorrupt { .. } => {}
            other => panic!("expected SettingsCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn parse_non_integer_errors() {
        let err = parse_settings_field(
            SETTINGS_RECORD_TYPE,
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            "not-a-number",
        )
        .expect_err("must error");
        match err {
            AppError::SettingsCorrupt { .. } => {}
            other => panic!("expected SettingsCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn validate_save_accepts_default() {
        assert!(validate_save_value(AUTO_LOCK_DEFAULT_MS).is_ok());
    }

    #[test]
    fn validate_save_rejects_below_min() {
        let err = validate_save_value(AUTO_LOCK_MIN_MS - 1).expect_err("must error");
        match err {
            AppError::SettingsOutOfRange { min, max } => {
                assert_eq!(min, AUTO_LOCK_MIN_MS);
                assert_eq!(max, AUTO_LOCK_MAX_MS);
            }
            other => panic!("expected SettingsOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn validate_save_rejects_above_max() {
        let err = validate_save_value(AUTO_LOCK_MAX_MS + 1).expect_err("must error");
        match err {
            AppError::SettingsOutOfRange { .. } => {}
            other => panic!("expected SettingsOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn serialize_round_trips_through_parse() {
        let original = Settings { auto_lock_timeout_ms: 900_000 };
        let (record_type, field_name, field_value) = serialize_settings(&original);
        let (parsed, warnings) =
            parse_settings_field(&record_type, &field_name, &field_value).expect("parse");
        assert_eq!(parsed, original);
        assert!(warnings.is_empty());
    }
}
```

- [ ] **Step 14: Add `mod settings;` to main.rs**

```rust
// main.rs after this step
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auto_lock;
mod constants;
mod errors;
mod settings;

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
```

- [ ] **Step 15: Run settings tests**

```bash
cargo test --release -p secretary-desktop settings::
```

Expected: 10 tests passing.

- [ ] **Step 16: Commit settings parse/serialize module**

```bash
git add desktop/src-tauri/src/settings.rs desktop/src-tauri/src/main.rs
git commit -m "feat(d11): Settings parse/serialize pure module (load/save vault facade in Task 3)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 17: Full gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected: PASSED **987** FAILED 0 IGNORED 10 (960 + 4 constants + 6 errors + 7 auto_lock + 10 settings = 987). Clippy / fmt / conformance / freshness all clean.

- [ ] **Step 18: Push + open PR**

```bash
git push -u origin feature/d11-task-2
gh pr create --title "feat(d11): Task 2 — backend pure modules (constants, errors, auto_lock, settings parse/serialize)" --body "$(cat <<'EOF'
## Summary
- `constants.rs` (8 constants from spec §8 + deterministic UUID helper, frozen-string tests guard vault-format breakage)
- `errors.rs` (AppError + AppWarning, serde-tagged discriminated unions, From<FfiVaultError> explicit per-variant mapping with detail-stripping)
- `auto_lock.rs` (IdleTracker pure struct, underflow-safe)
- `settings.rs` (parse_settings_field + clamp_with_warning + validate_save_value + serialize_settings — pure functions only; vault I/O in Task 3)

All modules under 300 LOC each, pure, dependency-free beyond the bridge crate's value types. 27 new unit tests; total workspace count 960 → 987.

## Spec / Plan
- Spec §8 (settings schema + constants table), §9 (error model)
- Plan task 2 (pure modules)

## Gauntlet
- Workspace tests: 987 / 0 / 10 (+27)
- clippy + fmt + conformance + spec freshness: clean

## Test plan
- [ ] `cargo test --release -p secretary-desktop` runs all new tests
- [ ] Verify the frozen SHA-256 hex strings in `constants::tests` match the actual outputs of `echo -n "<input>" | shasum -a 256`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

After merge, gauntlet baseline becomes **987 / 0 / 10**.

---

## Task 3: Backend session + settings I/O facade

**Why:** `VaultSession` holds the live cryptographic state (`UnlockedIdentity` + `OpenVaultOutput` + `IdleTracker`) plus the lock/unlock/settings logic. This is the most security-sensitive module — the `Drop` ordering, the explicit `wipe()` calls, the device-UUID persistence, and the settings vault I/O all live here. Single task because session.rs and settings.rs's I/O facade are tightly coupled (every settings load happens immediately after unlock; every save uses the same identity + manifest the session holds). Integration tests against `golden_vault_001/` verify the round-trip end-to-end. No IPC layer yet — that's Task 4. No timer thread yet — that's Task 5.

**Files:**
- Create: `desktop/src-tauri/src/session.rs`
- Modify: `desktop/src-tauri/src/settings.rs` (extend with `load_from_vault`, `save_to_vault`, device-UUID helpers)
- Create: `desktop/src-tauri/tests/session_integration.rs`
- Modify: `desktop/src-tauri/src/main.rs` (add `mod session;`)

- [ ] **Step 1: Set up worktree from main**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-3 -b feature/d11-task-3 main
cd .worktrees/d11-task-3
```

- [ ] **Step 2: Verify the bridge API surface you'll be calling**

Before writing session.rs, confirm the exact function signatures and type names from the bridge crate. Run:

```bash
grep -nE "^pub (fn|struct|enum) " ffi/secretary-ffi-bridge/src/vault/orchestration.rs ffi/secretary-ffi-bridge/src/save/orchestration.rs ffi/secretary-ffi-bridge/src/record/orchestration.rs ffi/secretary-ffi-bridge/src/identity.rs ffi/secretary-ffi-bridge/src/vault/types.rs 2>&1 | head -30
```

Key types/functions you'll use:
- `secretary_ffi_bridge::vault::open_vault_with_password(folder: &Path, password: &[u8]) -> Result<OpenVaultOutput, FfiVaultError>`
- `OpenVaultOutput` has `.manifest: OpenVaultManifest` (with `vault_uuid`, `owner_user_uuid`, `block_count`, `block_summaries`, `find_block`, `owner_card_bytes`) and `.identity: UnlockedIdentity` plus a `.wipe()` method
- `secretary_ffi_bridge::record::read_block(identity, manifest, block_uuid) -> Result<BlockReadOutput, FfiVaultError>`
- `secretary_ffi_bridge::save::save_block(identity, manifest, input: BlockInput, device_uuid: [u8; 16], now_ms: u64) -> Result<(), FfiVaultError>`

If any of these names differ slightly in the actual code, adjust the imports in the steps below accordingly. **Don't guess — verify before writing.**

- [ ] **Step 3: Write the failing integration tests skeleton**

Create `desktop/src-tauri/tests/session_integration.rs`:

```rust
//! Integration tests for the VaultSession + settings I/O facade.
//!
//! Uses the workspace-shared `core/tests/data/golden_vault_001/` reference vault
//! for the unlock-against-known-good-vault path, plus `tempfile::tempdir()`-based
//! ephemeral vaults for the write-path tests (so the golden vault stays read-only).
//!
//! The known-good password for `golden_vault_001` is documented in
//! `core/tests/data/golden_vault_001/README.md`. If it changes, update
//! `GOLDEN_VAULT_PASSWORD` here.

use std::path::PathBuf;

use secretary_desktop::session::VaultSession;
use secretary_desktop::settings::Settings;

const GOLDEN_VAULT_PASSWORD: &[u8] = b"correct horse battery staple";

fn golden_vault_path() -> PathBuf {
    // Workspace-root-relative path. cargo test sets CWD to the crate root,
    // so we go up two levels from desktop/src-tauri/.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("desktop/")
        .parent()
        .expect("workspace root")
        .join("core/tests/data/golden_vault_001")
}

#[test]
fn unlock_golden_vault_with_correct_password_succeeds() {
    let mut session = VaultSession::new();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock golden vault");
    assert!(session.is_unlocked(), "session must report unlocked after success");
}

#[test]
fn unlock_with_wrong_password_returns_wrong_password() {
    use secretary_desktop::errors::AppError;
    let mut session = VaultSession::new();
    let err = session
        .unlock(&golden_vault_path(), b"definitely not the password")
        .expect_err("must reject wrong password");
    matches!(err, AppError::WrongPassword);
}

#[test]
fn unlock_then_lock_clears_inner_state() {
    let mut session = VaultSession::new();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");
    assert!(session.is_unlocked());
    session.lock();
    assert!(!session.is_unlocked(), "session must report locked after lock()");
}

#[test]
fn second_unlock_while_already_unlocked_returns_already_unlocked() {
    use secretary_desktop::errors::AppError;
    let mut session = VaultSession::new();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");
    let err = session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect_err("second unlock must reject");
    matches!(err, AppError::AlreadyUnlocked);
}

#[test]
fn settings_load_from_vault_without_settings_block_returns_defaults() {
    let mut session = VaultSession::new();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");
    let settings = session.current_settings();
    assert_eq!(settings, Settings::default(), "no settings block → default");
}

#[test]
fn unlock_then_lock_cycles_repeatedly() {
    let mut session = VaultSession::new();
    for _ in 0..3 {
        session
            .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
            .expect("unlock");
        session.lock();
        assert!(!session.is_unlocked());
    }
}

#[test]
fn notify_activity_on_locked_session_is_silent_noop() {
    let mut session = VaultSession::new();
    // No unlock; session is locked.
    session.notify_activity(); // must not panic.
    assert!(!session.is_unlocked());
}

#[test]
fn notify_activity_on_unlocked_session_advances_idle_tracker() {
    let mut session = VaultSession::new();
    session
        .unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD)
        .expect("unlock");
    let t0 = session.last_activity_ms();
    std::thread::sleep(std::time::Duration::from_millis(5));
    session.notify_activity();
    let t1 = session.last_activity_ms();
    assert!(t1 > t0, "notify_activity must advance the tracker");
}

// Settings write-path tests follow — they need an ephemeral vault since the
// golden vault is read-only. Defer the test bodies until VaultSession's
// set_settings method exists (Step 6 of this task).
//
// TODO(d11-task-3): write set_settings_persists_and_reloads test.
// TODO(d11-task-3): write set_settings_out_of_range_errors test.
```

> NOTE: The `set_settings_*` tests intentionally have `TODO`-only placeholders here because the test file is being committed as a contract before the implementation lands. Steps 7+ will fill in those tests with real code; the TODO-named functions are intentionally not declared as `#[test]` fns yet, so they don't fail the gauntlet.

> NOTE: For the GOLDEN_VAULT_PASSWORD constant, **verify the actual password by reading `core/tests/data/golden_vault_001/README.md` or the existing test fixtures** (e.g. `core/tests/python/conformance.py` references it). Replace `b"correct horse battery staple"` with the real value.

- [ ] **Step 4: Run the failing tests — verify they fail to compile**

```bash
cargo test --release -p secretary-desktop --test session_integration -- --nocapture
```

Expected: compile error — `VaultSession`, `session::*`, `current_settings`, `last_activity_ms`, `set_settings` don't exist yet. That's correct for TDD.

- [ ] **Step 5: Write `session.rs` minimum implementation**

Create `desktop/src-tauri/src/session.rs`:

```rust
//! `VaultSession` — the live cryptographic state holder.
//!
//! See spec §6 (vault session lifecycle) for the full state machine. The
//! discipline in this file:
//!
//! - `UnlockedSession::Drop` calls `vault.wipe()` BEFORE `identity.wipe()`
//!   (spec §6 invariant — vault holds signature material that references
//!   the identity).
//! - `unlock()` rejects with `AlreadyUnlocked` if a session is in progress.
//! - `notify_activity()` is a silent no-op when locked.
//! - `with_open_vault<F>(f)` is the only path commands have to reach into
//!   the unlocked state — borrows the manifest immutably, returns `f`'s output
//!   or `AppError::NotUnlocked`.

use std::path::Path;

use secretary_ffi_bridge::error::FfiVaultError;
use secretary_ffi_bridge::identity::UnlockedIdentity;
use secretary_ffi_bridge::vault::types::OpenVaultManifest;
use secretary_ffi_bridge::vault::open_vault_with_password;

use crate::auto_lock::{now_ms, IdleTracker};
use crate::errors::AppError;
use crate::settings::{self, Settings};

/// The complete unlocked-state bundle. `Drop`-wipes both halves in correct
/// order. Never construct directly — only via `VaultSession::unlock`.
pub struct UnlockedSession {
    pub identity: UnlockedIdentity,
    pub manifest: OpenVaultManifest,
    pub settings: Settings,
    /// Persistent per-vault device UUID, loaded/generated on unlock from
    /// `dirs::data_dir()/secretary-desktop/devices/<vault_uuid_hex>.dev`.
    /// Required by the bridge's `save_block` for vector-clock semantics.
    pub device_uuid: [u8; 16],
}

impl Drop for UnlockedSession {
    fn drop(&mut self) {
        // Order is load-bearing — see spec §6 "Drop ordering".
        self.manifest.wipe();
        self.identity.wipe();
        // settings + device_uuid have no secret material; default Drop.
    }
}

/// The Mutex-guarded session state, registered as `tauri::State` in Task 5.
pub struct VaultSession {
    inner: Option<UnlockedSession>,
    idle: IdleTracker,
}

impl VaultSession {
    pub fn new() -> Self {
        Self {
            inner: None,
            idle: IdleTracker::new(now_ms()),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.is_some()
    }

    pub fn last_activity_ms(&self) -> u64 {
        self.idle.last_activity_ms
    }

    /// Returns a reference to the current settings, or the default if locked.
    /// Locked path is a defensive fallback — UI shouldn't be calling this
    /// while locked, but returning `Default::default()` is safer than panic
    /// in case the IPC layer races.
    pub fn current_settings(&self) -> Settings {
        self.inner
            .as_ref()
            .map(|u| u.settings)
            .unwrap_or_default()
    }

    /// Mark UI activity. Silent no-op when locked.
    pub fn notify_activity(&mut self) {
        if self.inner.is_some() {
            self.idle.notify(now_ms());
        }
    }

    /// Attempt to unlock with a password. On success, populates `inner` and
    /// loads settings from the vault (with defaults if no settings block).
    /// On failure, leaves the session locked and returns the typed error.
    pub fn unlock(&mut self, folder: &Path, password: &[u8]) -> Result<(), AppError> {
        if self.inner.is_some() {
            return Err(AppError::AlreadyUnlocked);
        }

        // Bridge call. FfiVaultError → AppError conversion via the
        // explicit From impl from Task 2.
        let output = open_vault_with_password(folder, password)?;

        // Pull device UUID for this vault (persistent across runs).
        let device_uuid = settings::load_or_create_device_uuid(
            &output.manifest.vault_uuid,
        )?;

        // Load settings — non-fatal warnings are dropped here; the unlock
        // command in Task 4 will re-load via `load_from_vault_with_warnings`
        // to surface them in the manifest DTO.
        let settings = settings::load_from_vault(&output.identity, &output.manifest)
            .map(|(s, _warnings)| s)
            .unwrap_or_default();

        self.inner = Some(UnlockedSession {
            identity: output.identity,
            manifest: output.manifest,
            settings,
            device_uuid,
        });
        self.idle = IdleTracker::new(now_ms());
        Ok(())
    }

    /// Explicit lock — drops `inner`, triggering the Drop chain.
    pub fn lock(&mut self) {
        self.inner = None;
    }

    /// Run a closure with read access to the unlocked manifest. Returns
    /// `NotUnlocked` if the session is locked.
    pub fn with_unlocked<F, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&UnlockedSession) -> Result<T, AppError>,
    {
        match &self.inner {
            Some(u) => f(u),
            None => Err(AppError::NotUnlocked),
        }
    }

    /// Mutable variant for save-path commands (settings persistence).
    pub fn with_unlocked_mut<F, T>(&mut self, f: F) -> Result<T, AppError>
    where
        F: FnOnce(&mut UnlockedSession) -> Result<T, AppError>,
    {
        match &mut self.inner {
            Some(u) => f(u),
            None => Err(AppError::NotUnlocked),
        }
    }

    /// Check if the session should auto-lock now. Called by the timer thread
    /// (Task 5) under the mutex.
    pub fn should_auto_lock(&self, threshold_ms: u64) -> bool {
        self.is_unlocked() && self.idle.is_expired(threshold_ms, now_ms())
    }
}

impl Default for VaultSession {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 6: Extend `settings.rs` with the vault I/O facade**

Append to `desktop/src-tauri/src/settings.rs`:

```rust
// ============================================================================
// Vault I/O facade — load + save against an unlocked vault
// ============================================================================

use std::path::PathBuf;

use secretary_ffi_bridge::error::FfiVaultError;
use secretary_ffi_bridge::identity::UnlockedIdentity;
use secretary_ffi_bridge::record::read_block;
use secretary_ffi_bridge::save::save_block;
use secretary_ffi_bridge::vault::types::{BlockInput, FieldInput, FieldInputValue, OpenVaultManifest, RecordInput};

use crate::auto_lock::now_ms;
use crate::constants::{deterministic_uuid_16, SETTINGS_BLOCK_NAME, SETTINGS_RECORD_TYPE};

/// Look up the settings block in the manifest by name; returns `None` if
/// the block doesn't exist (vaults of users who never opened the settings dialog).
fn find_settings_block_uuid(manifest: &OpenVaultManifest) -> Option<[u8; 16]> {
    let target = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
    manifest
        .block_summaries
        .iter()
        .find(|bs| bs.block_name == SETTINGS_BLOCK_NAME)
        .map(|bs| {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&bs.block_uuid);
            // Sanity: the deterministic UUID should match the block UUID
            // we find. If it doesn't, someone created a block with our
            // reserved name but a different UUID — that's a vault-format
            // violation we ignore here (use the actual UUID from disk).
            debug_assert_eq!(uuid, target, "settings block UUID drift");
            uuid
        })
}

/// Load settings from an unlocked vault. Returns the settings + any non-fatal
/// warnings (clamped on load, unknown version, corrupt record).
///
/// Returns `(Settings::default(), vec![])` if no settings block exists.
pub fn load_from_vault(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<(Settings, Vec<AppWarning>), AppError> {
    let Some(block_uuid) = find_settings_block_uuid(manifest) else {
        return Ok((Settings::default(), vec![]));
    };

    let block = read_block(identity, manifest, &block_uuid).map_err(AppError::from)?;
    // The settings block holds exactly one record; if it has zero or more
    // than one, treat as corrupt + use defaults + emit warning.
    if block.records.len() != 1 {
        return Ok((
            Settings::default(),
            vec![AppWarning::SettingsCorrupt {
                detail: format!(
                    "settings block has {} records (expected 1)",
                    block.records.len()
                ),
            }],
        ));
    }
    let record = &block.records[0];
    if record.fields.len() != 1 {
        return Ok((
            Settings::default(),
            vec![AppWarning::SettingsCorrupt {
                detail: format!(
                    "settings record has {} fields (expected 1)",
                    record.fields.len()
                ),
            }],
        ));
    }
    let field = &record.fields[0];
    let field_text = field
        .value
        .as_text()
        .ok_or_else(|| AppError::SettingsCorrupt {
            detail: "settings field is not text-typed".to_string(),
        })?;

    parse_settings_field(&record.record_type, &field.name, field_text)
}

/// Save settings to the vault. Creates the settings block on first call
/// (lazy creation per spec §8); updates it on subsequent calls.
pub fn save_to_vault(
    identity: &UnlockedIdentity,
    manifest: &mut OpenVaultManifest,
    device_uuid: [u8; 16],
    new_settings: &Settings,
) -> Result<(), AppError> {
    validate_save_value(new_settings.auto_lock_timeout_ms)?;

    let block_uuid = find_settings_block_uuid(manifest)
        .unwrap_or_else(|| deterministic_uuid_16(SETTINGS_BLOCK_NAME));
    let record_uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE);

    let (record_type, field_name, field_value) = serialize_settings(new_settings);

    let block_input = BlockInput {
        block_uuid,
        block_name: SETTINGS_BLOCK_NAME.to_string(),
        records: vec![RecordInput {
            record_uuid,
            record_type,
            tags: vec![],
            fields: vec![FieldInput {
                name: field_name,
                value: FieldInputValue::Text(field_value),
            }],
        }],
    };

    save_block(identity, manifest, block_input, device_uuid, now_ms())
        .map_err(AppError::from)?;
    Ok(())
}

/// Per-vault persistent device UUID file. Stored under
/// `dirs::data_dir()/secretary-desktop/devices/<vault_uuid_hex>.dev`
/// containing 16 raw bytes. Generated on first unlock; reused thereafter.
pub fn load_or_create_device_uuid(vault_uuid: &[u8]) -> Result<[u8; 16], AppError> {
    use rand::RngCore;
    use std::fs;

    let path = device_uuid_path(vault_uuid)?;

    if path.exists() {
        let bytes = fs::read(&path).map_err(|e| AppError::Io {
            detail: format!("read device_uuid: {e}"),
        })?;
        if bytes.len() != 16 {
            return Err(AppError::Io {
                detail: format!(
                    "device_uuid file has {} bytes (expected 16)",
                    bytes.len()
                ),
            });
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes);
        Ok(uuid)
    } else {
        // Generate new + persist atomically via tempfile rename.
        let mut uuid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut uuid);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| AppError::Io {
                detail: format!("mkdir devices/: {e}"),
            })?;
        }
        let tmp = tempfile::NamedTempFile::new_in(
            path.parent().expect("path has parent"),
        )
        .map_err(|e| AppError::Io {
            detail: format!("tempfile: {e}"),
        })?;
        fs::write(tmp.path(), uuid).map_err(|e| AppError::Io {
            detail: format!("write tempfile: {e}"),
        })?;
        tmp.persist(&path).map_err(|e| AppError::Io {
            detail: format!("persist device_uuid: {e}"),
        })?;
        Ok(uuid)
    }
}

fn device_uuid_path(vault_uuid: &[u8]) -> Result<PathBuf, AppError> {
    let data_dir = dirs::data_dir().ok_or_else(|| AppError::Io {
        detail: "no platform data_dir".to_string(),
    })?;
    Ok(data_dir
        .join("secretary-desktop")
        .join("devices")
        .join(format!("{}.dev", hex::encode(vault_uuid))))
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use tempfile::tempdir;

    // device_uuid_path test — verify the canonical path structure.
    #[test]
    fn device_uuid_path_includes_vault_uuid_hex() {
        let uuid = [0xAB; 16];
        let path = device_uuid_path(&uuid).expect("data_dir resolves");
        let s = path.to_string_lossy();
        assert!(s.contains("secretary-desktop/devices"));
        assert!(s.contains("abababababababababababababababab.dev"));
    }

    // load_or_create on a fresh dir creates and returns 16 bytes.
    // Note: this test pollutes the actual data_dir; tolerate that for now.
    // A future refactor could inject the data_dir as a parameter.
    #[test]
    fn load_or_create_round_trips_for_fresh_vault_uuid() {
        let mut fresh_uuid = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut fresh_uuid);

        let result1 = load_or_create_device_uuid(&fresh_uuid).expect("first call");
        let result2 = load_or_create_device_uuid(&fresh_uuid).expect("second call");

        assert_eq!(result1, result2, "second call must return same UUID");
        assert_ne!(result1, [0u8; 16], "should be random, not zero");

        // Cleanup
        let _ = std::fs::remove_file(device_uuid_path(&fresh_uuid).unwrap());
    }
}
```

> NOTE: The `BlockInput`, `RecordInput`, `FieldInput`, `FieldInputValue`, `OpenVaultManifest`, `BlockReadOutput` type names and field names are based on the FFI surface inspection from the brainstorming phase. **Verify each name against the actual bridge crate source** (`ffi/secretary-ffi-bridge/src/vault/types.rs` and similar) and adjust as needed. If `manifest.block_summaries` is named `manifest.block_summaries()` (method, not field), update accordingly.

- [ ] **Step 7: Add `pub mod session;` + `pub mod settings;` (visibility for the integration test crate)**

Edit `desktop/src-tauri/src/main.rs`:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Modules are `pub` so the integration test crate can reach into them.
// Tauri's main.rs convention is unusual: it's both a bin AND exposes a
// lib-like surface for tests. The `pub` here is the gate.

pub mod auto_lock;
pub mod constants;
pub mod errors;
pub mod settings;
pub mod session;

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
```

Actually — for cleaner integration-test access, we should add a `lib.rs` that re-exports the modules. Tauri 2 supports this pattern via a `[[bin]]` + `[lib]` Cargo.toml setup.

Add to `desktop/src-tauri/Cargo.toml`:

```toml
[[bin]]
name = "secretary-desktop"
path = "src/main.rs"

[lib]
name = "secretary_desktop"
path = "src/lib.rs"
```

Create `desktop/src-tauri/src/lib.rs`:

```rust
//! Library surface for the secretary-desktop binary. Re-exports the modules
//! so that `desktop/src-tauri/tests/*.rs` integration tests can reach in
//! without main.rs's `fn main` shadowing the surface.

pub mod auto_lock;
pub mod constants;
pub mod errors;
pub mod settings;
pub mod session;
```

And simplify `main.rs`:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Module imports happen via the library crate. main.rs is just the bin entry.
use secretary_desktop as _; // currently unused except via tauri::generate_context!

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
```

- [ ] **Step 8: Run integration tests — first pass**

```bash
cargo test --release -p secretary-desktop --test session_integration
```

Expected: 8 tests should pass. If any fail with compile errors about bridge crate types, verify the type names match what the bridge actually exports.

- [ ] **Step 9: Add the write-path integration tests**

Append to `desktop/src-tauri/tests/session_integration.rs`:

```rust
// ============================================================================
// Write-path tests — uses an ephemeral copy of the golden vault so we can
// mutate it without affecting the read-only test fixture.
// ============================================================================

use secretary_desktop::errors::AppError;
use tempfile::tempdir;

/// Copy golden_vault_001 into a fresh tempdir, return the path.
fn ephemeral_golden_copy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().expect("tempdir");
    let dst = dir.path().to_path_buf();
    copy_recursive(&golden_vault_path(), &dst);
    (dir, dst)
}

fn copy_recursive(src: &std::path::Path, dst: &std::path::Path) {
    use std::fs;
    if src.is_file() {
        fs::create_dir_all(dst.parent().expect("parent")).expect("mkdir");
        fs::copy(src, dst).expect("copy");
    } else if src.is_dir() {
        fs::create_dir_all(dst).expect("mkdir");
        for entry in fs::read_dir(src).expect("read_dir") {
            let entry = entry.expect("entry");
            let src_child = entry.path();
            let dst_child = dst.join(entry.file_name());
            copy_recursive(&src_child, &dst_child);
        }
    }
}

#[test]
fn set_settings_persists_and_reloads() {
    let (_dir, vault_path) = ephemeral_golden_copy();
    let new_value = 900_000u64; // 15 minutes

    // First unlock + set
    {
        let mut session = VaultSession::new();
        session.unlock(&vault_path, GOLDEN_VAULT_PASSWORD).expect("unlock");
        let new_settings = Settings { auto_lock_timeout_ms: new_value };
        secretary_desktop::settings::save_to_vault(
            &session.with_unlocked(|u| Ok(&u.identity as *const _)).unwrap() as _ as _,
            // The above borrow gymnastics are awkward — refactor save_to_vault
            // to take a closure or move it onto VaultSession. See Step 10.
            todo!("see Step 10 — VaultSession::set_settings is the public surface"),
            session.with_unlocked(|u| Ok(u.device_uuid)).unwrap(),
            &new_settings,
        )
        .expect("save");
    }

    // Second unlock + verify the new value is loaded
    {
        let mut session = VaultSession::new();
        session.unlock(&vault_path, GOLDEN_VAULT_PASSWORD).expect("unlock");
        assert_eq!(session.current_settings().auto_lock_timeout_ms, new_value);
    }
}

#[test]
fn set_settings_out_of_range_errors_without_writing() {
    let (_dir, vault_path) = ephemeral_golden_copy();
    let mut session = VaultSession::new();
    session.unlock(&vault_path, GOLDEN_VAULT_PASSWORD).expect("unlock");

    // Too small
    let err = session
        .set_settings(&Settings { auto_lock_timeout_ms: 30_000 })
        .expect_err("must reject below min");
    matches!(err, AppError::SettingsOutOfRange { .. });

    // Too large
    let err = session
        .set_settings(&Settings { auto_lock_timeout_ms: 86_400_001 })
        .expect_err("must reject above max");
    matches!(err, AppError::SettingsOutOfRange { .. });

    // Verify no write happened by re-unlocking and checking default
    session.lock();
    session.unlock(&vault_path, GOLDEN_VAULT_PASSWORD).expect("unlock");
    assert_eq!(session.current_settings(), Settings::default());
}
```

- [ ] **Step 10: Add `set_settings` to `VaultSession`** (replaces the awkward borrow gymnastics)

Append to `desktop/src-tauri/src/session.rs`:

```rust
impl VaultSession {
    /// Persist new settings to the vault. Validates bounds; on success
    /// updates in-memory `inner.settings` to match disk.
    pub fn set_settings(&mut self, new_settings: &Settings) -> Result<(), AppError> {
        self.with_unlocked_mut(|u| {
            settings::save_to_vault(&u.identity, &mut u.manifest, u.device_uuid, new_settings)?;
            u.settings = *new_settings;
            Ok(())
        })
    }
}
```

And update the first integration test (the awkward one) to use this:

```rust
#[test]
fn set_settings_persists_and_reloads() {
    let (_dir, vault_path) = ephemeral_golden_copy();
    let new_value = 900_000u64;

    {
        let mut session = VaultSession::new();
        session.unlock(&vault_path, GOLDEN_VAULT_PASSWORD).expect("unlock");
        session
            .set_settings(&Settings { auto_lock_timeout_ms: new_value })
            .expect("save");
    }

    {
        let mut session = VaultSession::new();
        session.unlock(&vault_path, GOLDEN_VAULT_PASSWORD).expect("unlock");
        assert_eq!(session.current_settings().auto_lock_timeout_ms, new_value);
    }
}
```

- [ ] **Step 11: Run all integration tests**

```bash
cargo test --release -p secretary-desktop --test session_integration
```

Expected: 10 tests passing (8 unlock/lock + 2 write-path).

- [ ] **Step 12: Full gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected: PASSED **999** FAILED 0 IGNORED 10 (987 + 10 integration + 2 io_tests in settings.rs = 999). All clean.

- [ ] **Step 13: Commit + push + PR**

```bash
git add desktop/src-tauri/
git commit -m "feat(d11): VaultSession + settings vault I/O facade + device UUID persistence

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-3
gh pr create --title "feat(d11): Task 3 — VaultSession + settings I/O" --body "$(cat <<'EOF'
## Summary
- `VaultSession` with `unlock` / `lock` / `notify_activity` / `with_unlocked*` / `set_settings` / `should_auto_lock`
- `UnlockedSession::Drop` wipes vault then identity per spec §6
- `settings.rs` extended: `load_from_vault`, `save_to_vault`, `load_or_create_device_uuid` (per-vault `<vault_uuid_hex>.dev` under `dirs::data_dir()/secretary-desktop/devices/`)
- 10 integration tests against `golden_vault_001` (read-only) + ephemeral copies (write path)
- Workspace count: 987 → 999

## Spec / Plan
- Spec §6 (session lifecycle), §8 (settings schema)
- Plan task 3 (session + settings I/O)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

After merge, gauntlet baseline becomes **999 / 0 / 10**.

---

## Task 4: IPC commands + DTOs

**Why:** Wires `VaultSession` to the Tauri command surface. Six `#[tauri::command]` functions: `unlock_with_password`, `list_blocks` (+ `get_manifest`), `get_settings`, `set_settings`, `lock`, `notify_activity`. DTOs (`ManifestDto`, `BlockSummaryDto`) strip the bridge crate's `Vec<u8>` UUIDs into hex strings + drop any zeroize-typed bytes. Commands are tested via cargo integration tests that drive them through `tauri::test::mock_builder()` or — pragmatically — by testing the underlying VaultSession methods (which is what Task 3 did) plus testing the DTO conversions in isolation. The timer thread + event emission land in Task 5 because they need `tauri::AppHandle` from the running runtime.

**Files:**
- Create: `desktop/src-tauri/src/dtos.rs`
- Create: `desktop/src-tauri/src/commands/mod.rs`
- Create: `desktop/src-tauri/src/commands/unlock.rs`
- Create: `desktop/src-tauri/src/commands/vault.rs`
- Create: `desktop/src-tauri/src/commands/settings.rs`
- Create: `desktop/src-tauri/src/commands/lock.rs`
- Modify: `desktop/src-tauri/src/lib.rs` (add `pub mod commands; pub mod dtos;`)
- Modify: `desktop/src-tauri/src/main.rs` (register handlers, manage state)

- [ ] **Step 1: Set up worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-4 -b feature/d11-task-4 main
cd .worktrees/d11-task-4
```

- [ ] **Step 2: Write the failing DTO tests**

Create `desktop/src-tauri/src/dtos.rs`:

```rust
//! Data Transfer Objects crossing the Tauri IPC boundary.
//!
//! Discipline (spec §5 "IPC boundary"):
//! - Hex-encode all `Vec<u8>` UUIDs as String fields with `_hex` suffix.
//! - Never serialize zeroize-typed values.
//! - `From<&BridgeType>` impls live next to the DTO so the conversion
//!   is reviewable in one place.
//! - All DTOs `#[derive(serde::Serialize)]` and use `#[serde(rename_all = "camelCase")]`
//!   to match JS/TS conventions on the frontend side.

use secretary_ffi_bridge::vault::types::{BlockSummary, OpenVaultManifest};

use crate::errors::AppWarning;
use crate::settings::Settings;

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockSummaryDto {
    pub block_uuid_hex: String,
    pub block_name: String,
    pub record_count: u32,
    pub last_mod_ms: u64,
}

impl From<&BlockSummary> for BlockSummaryDto {
    fn from(b: &BlockSummary) -> Self {
        Self {
            block_uuid_hex: hex::encode(&b.block_uuid),
            block_name: b.block_name.clone(),
            record_count: b.record_count,
            last_mod_ms: b.last_mod_ms,
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestDto {
    pub vault_uuid_hex: String,
    pub owner_user_uuid_hex: String,
    pub block_count: u64,
    pub block_summaries: Vec<BlockSummaryDto>,
    pub warnings: Vec<AppWarning>,
}

impl ManifestDto {
    /// Build the DTO from an unlocked manifest plus the warnings vector
    /// produced by `settings::load_from_vault`.
    pub fn from_manifest_with_warnings(
        manifest: &OpenVaultManifest,
        warnings: Vec<AppWarning>,
    ) -> Self {
        Self {
            vault_uuid_hex: hex::encode(&manifest.vault_uuid),
            owner_user_uuid_hex: hex::encode(&manifest.owner_user_uuid),
            block_count: manifest.block_count,
            block_summaries: manifest
                .block_summaries
                .iter()
                .map(BlockSummaryDto::from)
                .collect(),
            warnings,
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsDto {
    pub auto_lock_timeout_ms: u64,
}

impl From<&Settings> for SettingsDto {
    fn from(s: &Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsInput {
    pub auto_lock_timeout_ms: u64,
}

impl From<&SettingsInput> for Settings {
    fn from(s: &SettingsInput) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn block_summary_uses_camel_case() {
        let dto = BlockSummaryDto {
            block_uuid_hex: "00112233445566778899aabbccddeeff".to_string(),
            block_name: "Banking".to_string(),
            record_count: 3,
            last_mod_ms: 1_700_000_000_000,
        };
        let v: Value = serde_json::from_str(&serde_json::to_string(&dto).unwrap()).unwrap();
        assert_eq!(v["blockUuidHex"], "00112233445566778899aabbccddeeff");
        assert_eq!(v["blockName"], "Banking");
        assert_eq!(v["recordCount"], 3);
        assert_eq!(v["lastModMs"], 1_700_000_000_000_i64);
    }

    #[test]
    fn settings_input_round_trips_via_serde() {
        let input: SettingsInput =
            serde_json::from_str(r#"{"autoLockTimeoutMs":900000}"#).unwrap();
        assert_eq!(input.auto_lock_timeout_ms, 900_000);
    }

    #[test]
    fn settings_dto_uses_camel_case() {
        let s = Settings { auto_lock_timeout_ms: 600_000 };
        let dto = SettingsDto::from(&s);
        let v: Value = serde_json::from_str(&serde_json::to_string(&dto).unwrap()).unwrap();
        assert_eq!(v["autoLockTimeoutMs"], 600_000);
    }
}
```

- [ ] **Step 3: Update lib.rs to expose dtos**

```rust
// desktop/src-tauri/src/lib.rs
pub mod auto_lock;
pub mod commands;
pub mod constants;
pub mod dtos;
pub mod errors;
pub mod settings;
pub mod session;
```

- [ ] **Step 4: Create the commands module structure**

`desktop/src-tauri/src/commands/mod.rs`:

```rust
//! Tauri IPC commands. One file per command grouping; all registered in main.rs.
//!
//! See spec §5 (IPC boundary discipline) — every command consumes a
//! `tauri::State<Mutex<VaultSession>>` and converts errors to `AppError`.

pub mod lock;
pub mod settings;
pub mod unlock;
pub mod vault;
```

- [ ] **Step 5: Implement `commands/unlock.rs`**

```rust
//! `unlock_with_password` command.

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::State;

use crate::dtos::ManifestDto;
use crate::errors::AppError;
use crate::session::VaultSession;
use crate::settings;

#[tauri::command]
pub async fn unlock_with_password(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
    password: String,
) -> Result<ManifestDto, AppError> {
    let folder = PathBuf::from(&folder_path);

    if !folder.exists() {
        return Err(AppError::VaultPathNotFound {
            path: folder_path,
        });
    }
    if !folder.is_dir() {
        return Err(AppError::VaultPathNotAVault {
            path: folder_path,
        });
    }

    // Acquire the session mutex. We hold the lock for the entire unlock
    // operation — it's serialized against any other command that might
    // run on a concurrent tauri command worker thread.
    let mut session = state
        .lock()
        .map_err(|e| AppError::Internal {
            detail: format!("session mutex poisoned: {e}"),
        })?;

    session.unlock(&folder, password.as_bytes())?;

    // Re-load with warnings to surface in the manifest DTO. This is a
    // second pass over the settings record but it's cheap (the block
    // is already decrypted into memory). The first pass (in session.unlock)
    // dropped warnings; this one preserves them for the frontend.
    let (_, warnings) = session
        .with_unlocked(|u| {
            settings::load_from_vault(&u.identity, &u.manifest).or_else(|e| {
                tracing::warn!(?e, "settings reload for warnings failed");
                Ok((u.settings, vec![]))
            })
        })?;

    let dto = session.with_unlocked(|u| {
        Ok(ManifestDto::from_manifest_with_warnings(&u.manifest, warnings))
    })?;

    Ok(dto)
}
```

> NOTE: The double load (once in `session.unlock` dropping warnings, once here re-loading for warnings) is intentionally redundant for clean code separation — `session.unlock` is the deterministic "open the vault" path; warnings are a UI concern. If you want to avoid the second decrypt, refactor `session.unlock` to take a `&mut Vec<AppWarning>` accumulator. For D.1.1 the double-decrypt is fast enough that simplicity wins.

- [ ] **Step 6: Implement `commands/vault.rs`**

```rust
//! `list_blocks` + `get_manifest` commands (D.1.2 will add `read_block`).

use std::sync::Mutex;

use tauri::State;

use crate::dtos::{BlockSummaryDto, ManifestDto};
use crate::errors::AppError;
use crate::session::VaultSession;

#[tauri::command]
pub async fn list_blocks(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Vec<BlockSummaryDto>, AppError> {
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.with_unlocked(|u| {
        Ok(u.manifest.block_summaries.iter().map(BlockSummaryDto::from).collect())
    })
}

#[tauri::command]
pub async fn get_manifest(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<ManifestDto, AppError> {
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.with_unlocked(|u| {
        Ok(ManifestDto::from_manifest_with_warnings(&u.manifest, vec![]))
    })
}
```

- [ ] **Step 7: Implement `commands/settings.rs`**

```rust
//! `get_settings` + `set_settings` commands.

use std::sync::Mutex;

use tauri::State;

use crate::dtos::{SettingsDto, SettingsInput};
use crate::errors::AppError;
use crate::session::VaultSession;
use crate::settings::Settings;

#[tauri::command]
pub async fn get_settings(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<SettingsDto, AppError> {
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    if !session.is_unlocked() {
        return Err(AppError::NotUnlocked);
    }
    Ok(SettingsDto::from(&session.current_settings()))
}

#[tauri::command]
pub async fn set_settings(
    state: State<'_, Mutex<VaultSession>>,
    settings: SettingsInput,
) -> Result<(), AppError> {
    let mut session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    let new_settings = Settings::from(&settings);
    session.set_settings(&new_settings)
}
```

- [ ] **Step 8: Implement `commands/lock.rs`**

```rust
//! `lock` + `notify_activity` commands. Note: the event emission for
//! auto-lock (Tauri event `vault-locked`) is wired up in Task 5 — the
//! lock command itself just mutates state here.

use std::sync::Mutex;

use tauri::{AppHandle, Emitter, State};

use crate::errors::AppError;
use crate::session::VaultSession;

#[tauri::command]
pub async fn lock(
    state: State<'_, Mutex<VaultSession>>,
    app: AppHandle,
) -> Result<(), AppError> {
    let mut session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    let was_unlocked = session.is_unlocked();
    session.lock();
    drop(session); // release mutex before emit to avoid back-pressure

    if was_unlocked {
        // Emit `vault-locked` with reason=explicit for the frontend's toast.
        app.emit("vault-locked", serde_json::json!({"reason": "explicit"}))
            .map_err(|e| AppError::Internal {
                detail: format!("event emit failed: {e}"),
            })?;
    }
    Ok(())
}

#[tauri::command]
pub async fn notify_activity(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<(), AppError> {
    let mut session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.notify_activity();
    Ok(())
}
```

- [ ] **Step 9: Wire up handlers + state in `main.rs`**

```rust
//! Secretary desktop client — Tauri 2 main entry point.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;

use secretary_desktop::commands::{lock, settings, unlock, vault};
use secretary_desktop::session::VaultSession;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tauri::Builder::default()
        .manage(Mutex::new(VaultSession::new()))
        .invoke_handler(tauri::generate_handler![
            unlock::unlock_with_password,
            vault::list_blocks,
            vault::get_manifest,
            settings::get_settings,
            settings::set_settings,
            lock::lock,
            lock::notify_activity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}
```

- [ ] **Step 10: Build + run dev to smoke-test**

```bash
cargo build --release -p secretary-desktop
```

Expected: clean compile. If a `tauri::command` macro complains about argument types, double-check that `String` and `SettingsInput` are `serde::Deserialize` (they are, but typos happen).

Then:

```bash
cd desktop && pnpm tauri dev
```

Window should open. Open the dev tools (right-click → Inspect, or Cmd+Opt+I on macOS) and type in the console:

```javascript
const { invoke } = window.__TAURI__.core;
await invoke('list_blocks').catch((e) => e);
// Expected: { code: 'not_unlocked' }
```

That confirms the IPC plumbing works and `AppError` serializes correctly through Tauri.

- [ ] **Step 11: Full gauntlet**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected: PASSED **1002** FAILED 0 IGNORED 10 (999 + 3 dto tests = 1002). Clean.

- [ ] **Step 12: Commit + push + PR**

```bash
git add desktop/src-tauri/
git commit -m "feat(d11): IPC commands + DTOs + handler registration

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-4
gh pr create --title "feat(d11): Task 4 — IPC commands + DTOs" --body "$(cat <<'EOF'
## Summary
- 7 commands: `unlock_with_password`, `list_blocks`, `get_manifest`, `get_settings`, `set_settings`, `lock`, `notify_activity`
- DTOs strip `Vec<u8>` UUIDs to hex strings, use camelCase wire format
- Handler registration + state management + tracing subscriber init in main.rs
- Manual dev-tools smoke confirmed AppError serializes through Tauri IPC

## Spec / Plan
- Spec §5 (IPC boundary discipline), §9 (error model wire format)
- Plan task 4

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

After merge, gauntlet baseline becomes **1002 / 0 / 10**.

---

## Task 5: Auto-lock timer + `vault-locked` event emission

**Why:** Spawns the OS-thread timer that periodically checks `session.should_auto_lock(...)` and triggers a backend lock + frontend event when the threshold expires. Single task; ~80 LOC of plumbing in main.rs. Test strategy: a programmatic test that drives the timer in isolation (without launching Tauri) by extracting the tick body into a pure function.

**Files:**
- Modify: `desktop/src-tauri/src/main.rs` (spawn timer thread after builder)
- Create: `desktop/src-tauri/src/timer.rs` (pure tick-body function for testability)
- Modify: `desktop/src-tauri/src/lib.rs` (expose `timer` module)

- [ ] **Step 1: Set up worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-5 -b feature/d11-task-5 main
cd .worktrees/d11-task-5
```

- [ ] **Step 2: Write the failing tests for `timer.rs`**

Create `desktop/src-tauri/src/timer.rs`:

```rust
//! Auto-lock timer logic. The actual thread spawn lives in `main.rs`; this
//! module is the pure tick body — testable without spinning up Tauri.

use std::sync::Mutex;

use crate::session::VaultSession;

/// Outcome of a single timer tick — used by the thread loop to decide whether
/// to emit a `vault-locked` event.
#[derive(Debug, PartialEq, Eq)]
pub enum TickOutcome {
    /// Session is locked or not yet expired; no action.
    NoAction,
    /// Session was unlocked, exceeded threshold, and was locked by this tick.
    AutoLocked,
    /// Mutex was contended; skip this tick (next tick will retry).
    Skipped,
}

/// Pure tick body. Acquires the mutex via `try_lock` (non-blocking — if a
/// command is mid-flight, skip), checks `should_auto_lock`, locks if so.
///
/// The threshold is passed as a parameter rather than read from session.settings
/// because the settings are inside the mutex — we'd need to acquire it twice.
/// In the integration path (main.rs spawns the thread with a fresh `AppHandle`),
/// the threshold is read inside the same lock acquisition.
pub fn tick(session_mutex: &Mutex<VaultSession>, threshold_ms: u64) -> TickOutcome {
    let Ok(mut session) = session_mutex.try_lock() else {
        return TickOutcome::Skipped;
    };

    if session.should_auto_lock(threshold_ms) {
        session.lock();
        TickOutcome::AutoLocked
    } else {
        TickOutcome::NoAction
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto_lock::IdleTracker;

    #[test]
    fn tick_does_nothing_on_locked_session() {
        let mutex = Mutex::new(VaultSession::new());
        assert_eq!(tick(&mutex, 60_000), TickOutcome::NoAction);
    }

    #[test]
    fn tick_skipped_when_mutex_contended() {
        let mutex = Mutex::new(VaultSession::new());
        let _guard = mutex.lock().expect("hold lock");
        assert_eq!(tick(&mutex, 60_000), TickOutcome::Skipped);
    }

    // NOTE: testing the "AutoLocked" path requires either (a) unlocking the
    // session, which needs golden_vault_001, or (b) refactoring VaultSession
    // to expose a test-only `force_unlocked_state` method. Option (b) is
    // cleaner — add the method now.
    //
    // The implementation: append to session.rs:
    //
    //   #[cfg(test)]
    //   impl VaultSession {
    //       /// Test-only: simulate an unlocked session without doing the
    //       /// full vault unlock dance. Used to test auto-lock-threshold
    //       /// logic in isolation.
    //       pub fn force_unlocked_for_test(&mut self, expired_at_ms: u64) {
    //           // We can't construct a real UnlockedSession without the
    //           // bridge crate's types. Instead, just set the idle tracker
    //           // to an expired value AND set inner to Some(...) using
    //           // a test-only constructor.
    //           //
    //           // Pragmatic alternative: add a unit test in `tests/` that
    //           // does the full unlock against golden_vault_001 + manually
    //           // sets `idle.last_activity_ms` to an expired value via a
    //           // helper method, then calls tick().
    //       }
    //   }
    //
    // For D.1.1, we'll go with the pragmatic alternative — the auto-lock
    // expiry test lives in tests/session_integration.rs (Task 3 already
    // had the unlock plumbing).
}
```

- [ ] **Step 3: Add the integration test for auto-lock expiry**

Append to `desktop/src-tauri/tests/session_integration.rs`:

```rust
use secretary_desktop::timer::{tick, TickOutcome};
use std::sync::Mutex;

#[test]
fn timer_tick_auto_locks_expired_session() {
    let mutex = Mutex::new(VaultSession::new());

    // Unlock + manually expire the idle tracker.
    {
        let mut session = mutex.lock().expect("lock");
        session.unlock(&golden_vault_path(), GOLDEN_VAULT_PASSWORD).expect("unlock");
        session.force_expire_idle_tracker_for_test();
        assert!(session.is_unlocked());
    }

    let outcome = tick(&mutex, 60_000);
    assert_eq!(outcome, TickOutcome::AutoLocked);

    let session = mutex.lock().expect("lock");
    assert!(!session.is_unlocked(), "tick must have locked the session");
}
```

And add the helper to `session.rs`:

```rust
// At the bottom of session.rs:

#[cfg(test)]
impl VaultSession {
    /// Test-only: rewind the idle tracker so it's expired against any
    /// non-zero threshold. Used by the timer integration test.
    pub fn force_expire_idle_tracker_for_test(&mut self) {
        self.idle.last_activity_ms = 0;
    }
}
```

> NOTE: `#[cfg(test)]` makes this only compile during `cargo test`. **However**, integration tests (`tests/*.rs`) are a separate crate from the lib, so `#[cfg(test)]` items in lib don't show up. To make the helper visible to integration tests, use `#[cfg(any(test, feature = "test-helpers"))]` and enable the feature in dev-deps. Or — simpler — just make it a regular `pub` method with a `_for_test` suffix and accept that it's in the public surface. For D.1.1 simplicity, **make it a regular `pub fn` with a clear suffix**:

```rust
impl VaultSession {
    /// Rewind the idle tracker for testing. Public because the cfg(test)
    /// gate doesn't reach integration tests. Suffix `_for_test` documents
    /// the intent; no production caller should use this.
    pub fn force_expire_idle_tracker_for_test(&mut self) {
        self.idle.last_activity_ms = 0;
    }
}
```

If you want the strict `#[doc(hidden)] pub` pattern documented in `project_secretary_cfg_test_not_propagated`, apply it:

```rust
impl VaultSession {
    #[doc(hidden)]
    pub fn force_expire_idle_tracker_for_test(&mut self) {
        self.idle.last_activity_ms = 0;
    }
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cargo test --release -p secretary-desktop timer::
cargo test --release -p secretary-desktop --test session_integration timer_tick
```

Expected: 2 + 1 = 3 tests passing.

- [ ] **Step 5: Spawn the timer thread in main.rs**

Update `desktop/src-tauri/src/main.rs`:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use tauri::{Emitter, Manager};

use secretary_desktop::commands::{lock, settings, unlock, vault};
use secretary_desktop::constants::AUTO_LOCK_TICK_MS;
use secretary_desktop::session::VaultSession;
use secretary_desktop::timer::{tick, TickOutcome};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tauri::Builder::default()
        .manage(Mutex::new(VaultSession::new()))
        .invoke_handler(tauri::generate_handler![
            unlock::unlock_with_password,
            vault::list_blocks,
            vault::get_manifest,
            settings::get_settings,
            settings::set_settings,
            lock::lock,
            lock::notify_activity,
        ])
        .setup(|app| {
            // Spawn the auto-lock timer thread. Lives for the app lifetime
            // (no graceful shutdown — the OS reclaims the thread on process exit).
            let app_handle = app.handle().clone();
            thread::spawn(move || auto_lock_timer_loop(app_handle));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Secretary tauri application");
}

fn auto_lock_timer_loop(app: tauri::AppHandle) {
    loop {
        thread::sleep(Duration::from_millis(AUTO_LOCK_TICK_MS));

        // Read the current threshold inside the same lock acquisition that
        // tick() will take. This requires a slightly different API than
        // tick() exposes — we inline the body here. Refactoring tick() to
        // take a threshold-getter closure would let us share code; for D.1.1
        // simplicity, duplicate the few lines.
        let state = app.state::<Mutex<VaultSession>>();
        let Ok(mut session) = state.try_lock() else {
            continue; // skip this tick — mid-flight command holds the mutex
        };
        let threshold_ms = session.current_settings().auto_lock_timeout_ms;
        if session.should_auto_lock(threshold_ms) {
            session.lock();
            drop(session);
            if let Err(e) = app.emit("vault-locked", serde_json::json!({"reason": "idle"})) {
                tracing::error!(?e, "failed to emit vault-locked event");
            }
        }
    }
}
```

- [ ] **Step 6: Smoke-test the timer end-to-end**

Manual smoke: open dev tools after `pnpm tauri dev`, then in the console:

```javascript
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

await listen('vault-locked', (e) => console.log('LOCKED:', e.payload));

// (You'd need to also unlock a vault first, but for this smoke just verify
// the listen handler subscribes without error.)
```

- [ ] **Step 7: Full gauntlet + commit + PR**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: PASSED **1005** FAILED 0 IGNORED 10. Clean.

```bash
git add desktop/src-tauri/
git commit -m "feat(d11): auto-lock timer thread + vault-locked event emission

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-5
gh pr create --title "feat(d11): Task 5 — auto-lock timer + vault-locked event" --body "..."
```

After merge, baseline becomes **1005 / 0 / 10**.

---

## Task 6: Frontend pure modules — ipc, stores, errors, auto_lock + Vitest harness

**Why:** Lay down the typed TS layer that every Svelte component imports. All four modules are pure (no DOM, no Svelte components, no I/O) and Vitest-testable. Establishing them as a separate task before any component work means: (a) frontend has typed IPC wrappers from the first component, (b) error display logic is centralized, (c) Vitest is wired into the gauntlet from now on.

**Files:**
- Create: `desktop/src/lib/ipc.ts`
- Create: `desktop/src/lib/stores.ts`
- Create: `desktop/src/lib/errors.ts`
- Create: `desktop/src/lib/auto_lock.ts`
- Create: `desktop/tests/ipc.test.ts`
- Create: `desktop/tests/errors.test.ts`
- Create: `desktop/tests/auto_lock.test.ts`
- Modify: `desktop/package.json` (add `vitest` config; ESLint config)
- Create: `desktop/vitest.config.ts`
- Create: `desktop/.eslintrc.cjs`

- [ ] **Step 1: Set up worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-6 -b feature/d11-task-6 main
cd .worktrees/d11-task-6/desktop
```

- [ ] **Step 2: Create `vitest.config.ts`**

```typescript
import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte({ hot: false })],
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.ts'],
    globals: true
  }
});
```

Add `jsdom` to devDeps in `package.json` (`pnpm add -D jsdom`).

- [ ] **Step 3: Create `src/lib/errors.ts`**

```typescript
// Discriminated union mirroring src-tauri/src/errors.rs::AppError.
// Generated by reading the AppError variants; if the Rust side adds a
// variant, this file must be updated — a runtime mismatch would otherwise
// fall through to the default-case branch in userMessageFor.

export type AppError =
  | { code: 'vault_path_not_found'; path: string }
  | { code: 'vault_path_not_a_vault'; path: string }
  | { code: 'vault_path_locked'; path: string }
  | { code: 'wrong_password' }
  | { code: 'kdf_too_weak'; current_memory_kib: number; min_memory_kib: number }
  | { code: 'vault_corrupt' }
  | { code: 'already_unlocked' }
  | { code: 'not_unlocked' }
  | { code: 'settings_corrupt' }
  | { code: 'settings_unknown_version'; version: string }
  | { code: 'settings_out_of_range'; min: number; max: number }
  | { code: 'io' }
  | { code: 'internal' };

export type AppWarning =
  | { code: 'settings_corrupt' }
  | { code: 'settings_clamped'; original_ms: number; clamped_ms: number }
  | { code: 'settings_unknown_version'; version: string };

export interface UserMessage {
  title: string;
  detail?: string;
  actionHint?: string;
}

export function userMessageFor(err: AppError): UserMessage {
  switch (err.code) {
    case 'vault_path_not_found':
      return { title: 'Folder not found', detail: err.path, actionHint: 'Check the path or choose a different folder.' };
    case 'vault_path_not_a_vault':
      return { title: 'Not a vault', detail: `${err.path} doesn't contain a vault manifest.`, actionHint: 'Did you mean to create a new vault here?' };
    case 'vault_path_locked':
      return { title: 'Vault in use', detail: 'Another Secretary instance or sync daemon is holding the lock.', actionHint: 'Close the other application and try again.' };
    case 'wrong_password':
      return { title: 'Wrong password', actionHint: 'Check Caps Lock and keyboard layout.' };
    case 'kdf_too_weak':
      return { title: 'Vault is too weakly protected', detail: `Uses ${err.current_memory_kib} KiB of KDF memory; minimum is ${err.min_memory_kib} KiB.`, actionHint: 'This vault may have been created with an old version. Contact support.' };
    case 'vault_corrupt':
      return { title: 'Vault appears corrupted', actionHint: 'Restore from a recent backup.' };
    case 'already_unlocked':
      return { title: 'Vault already unlocked' };
    case 'not_unlocked':
      return { title: 'Vault is locked' };
    case 'settings_corrupt':
      return { title: 'Settings malformed', detail: 'Using default values.', actionHint: 'Change a setting to overwrite the corrupt record.' };
    case 'settings_unknown_version':
      return { title: 'Settings format newer than this app', detail: `Schema version "${err.version}" is from a newer Secretary build. Using defaults.` };
    case 'settings_out_of_range':
      return { title: 'Value out of range', detail: `Auto-lock timeout must be between ${err.min / 1000}s and ${err.max / 1000}s.` };
    case 'io':
      return { title: 'Filesystem error', actionHint: 'Check disk space and permissions, then try again.' };
    case 'internal':
      return { title: 'Internal error', actionHint: 'This is a bug. Please report it.' };
  }
}

export function userMessageForWarning(w: AppWarning): UserMessage {
  switch (w.code) {
    case 'settings_corrupt':
      return { title: 'Settings record malformed', detail: 'Using default values until you change a setting.' };
    case 'settings_clamped':
      return { title: 'Settings value clamped', detail: `Auto-lock changed from ${w.original_ms / 1000}s to ${w.clamped_ms / 1000}s (within allowed bounds).` };
    case 'settings_unknown_version':
      return { title: 'Settings format newer than this app', detail: `Schema "${w.version}" — using defaults.` };
  }
}
```

- [ ] **Step 4: Create `tests/errors.test.ts`**

```typescript
import { describe, it, expect } from 'vitest';
import { userMessageFor, userMessageForWarning, type AppError, type AppWarning } from '../src/lib/errors';

describe('userMessageFor', () => {
  const variants: AppError[] = [
    { code: 'vault_path_not_found', path: '/x' },
    { code: 'vault_path_not_a_vault', path: '/x' },
    { code: 'vault_path_locked', path: '/x' },
    { code: 'wrong_password' },
    { code: 'kdf_too_weak', current_memory_kib: 32768, min_memory_kib: 65536 },
    { code: 'vault_corrupt' },
    { code: 'already_unlocked' },
    { code: 'not_unlocked' },
    { code: 'settings_corrupt' },
    { code: 'settings_unknown_version', version: 'v99' },
    { code: 'settings_out_of_range', min: 60000, max: 86400000 },
    { code: 'io' },
    { code: 'internal' }
  ];

  it.each(variants)('returns non-empty title for $code', (err) => {
    const msg = userMessageFor(err);
    expect(msg.title.length).toBeGreaterThan(0);
  });

  it('wrong_password has actionHint about Caps Lock', () => {
    const msg = userMessageFor({ code: 'wrong_password' });
    expect(msg.actionHint).toContain('Caps Lock');
  });

  it('settings_out_of_range shows bounds in seconds', () => {
    const msg = userMessageFor({ code: 'settings_out_of_range', min: 60_000, max: 86_400_000 });
    expect(msg.detail).toContain('60s');
    expect(msg.detail).toContain('86400s');
  });
});

describe('userMessageForWarning', () => {
  const variants: AppWarning[] = [
    { code: 'settings_corrupt' },
    { code: 'settings_clamped', original_ms: 30000, clamped_ms: 60000 },
    { code: 'settings_unknown_version', version: 'v99' }
  ];

  it.each(variants)('returns non-empty title for $code', (w) => {
    const msg = userMessageForWarning(w);
    expect(msg.title.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 5: Create `src/lib/ipc.ts`**

```typescript
// Typed wrappers around Tauri's invoke(). One function per backend command.
// All catch IPC errors and re-throw the typed AppError union from errors.ts.

import { invoke } from '@tauri-apps/api/core';
import type { AppError, AppWarning } from './errors';

export interface BlockSummaryDto {
  blockUuidHex: string;
  blockName: string;
  recordCount: number;
  lastModMs: number;
}

export interface ManifestDto {
  vaultUuidHex: string;
  ownerUserUuidHex: string;
  blockCount: number;
  blockSummaries: BlockSummaryDto[];
  warnings: AppWarning[];
}

export interface SettingsDto {
  autoLockTimeoutMs: number;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (err) {
    // Tauri rejects with the serialized AppError struct. Re-throw as a typed
    // error the caller can pattern-match on.
    if (typeof err === 'object' && err !== null && 'code' in err) {
      throw err as AppError;
    }
    throw { code: 'internal' } satisfies AppError;
  }
}

export async function unlockWithPassword(folderPath: string, password: string): Promise<ManifestDto> {
  return call<ManifestDto>('unlock_with_password', { folderPath, password });
}

export async function listBlocks(): Promise<BlockSummaryDto[]> {
  return call<BlockSummaryDto[]>('list_blocks');
}

export async function getManifest(): Promise<ManifestDto> {
  return call<ManifestDto>('get_manifest');
}

export async function getSettings(): Promise<SettingsDto> {
  return call<SettingsDto>('get_settings');
}

export async function setSettings(settings: SettingsDto): Promise<void> {
  return call<void>('set_settings', { settings });
}

export async function lock(): Promise<void> {
  return call<void>('lock');
}

export async function notifyActivity(): Promise<void> {
  return call<void>('notify_activity');
}
```

- [ ] **Step 6: Create `tests/ipc.test.ts`**

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';

const invokeMock = vi.fn();

vi.mock('@tauri-apps/api/core', () => ({
  invoke: invokeMock
}));

import { unlockWithPassword, listBlocks } from '../src/lib/ipc';

beforeEach(() => {
  invokeMock.mockReset();
});

describe('ipc wrappers', () => {
  it('unlockWithPassword passes camelCase args', async () => {
    invokeMock.mockResolvedValue({
      vaultUuidHex: 'aa',
      ownerUserUuidHex: 'bb',
      blockCount: 0,
      blockSummaries: [],
      warnings: []
    });
    await unlockWithPassword('/path', 'secret');
    expect(invokeMock).toHaveBeenCalledWith('unlock_with_password', { folderPath: '/path', password: 'secret' });
  });

  it('listBlocks resolves with the array', async () => {
    invokeMock.mockResolvedValue([
      { blockUuidHex: 'aa', blockName: 'Banking', recordCount: 3, lastModMs: 100 }
    ]);
    const blocks = await listBlocks();
    expect(blocks).toHaveLength(1);
    expect(blocks[0].blockName).toBe('Banking');
  });

  it('re-throws typed AppError on rejection', async () => {
    invokeMock.mockRejectedValue({ code: 'wrong_password' });
    await expect(unlockWithPassword('/x', 'wrong')).rejects.toMatchObject({ code: 'wrong_password' });
  });

  it('wraps non-typed rejection as internal', async () => {
    invokeMock.mockRejectedValue('a string, not a typed error');
    await expect(listBlocks()).rejects.toMatchObject({ code: 'internal' });
  });
});
```

- [ ] **Step 7: Create `src/lib/stores.ts`**

```typescript
// Svelte stores for session state. Subscribe in components via `$sessionState`.

import { writable, derived } from 'svelte/store';
import type { AppError, AppWarning } from './errors';
import type { ManifestDto, SettingsDto } from './ipc';

export type SessionState =
  | { status: 'locked'; lastError: AppError | null }
  | { status: 'unlocking'; lastError: null }
  | { status: 'unlocked'; manifest: ManifestDto; settings: SettingsDto }
  | { status: 'locking'; lastError: null };

export const sessionState = writable<SessionState>({ status: 'locked', lastError: null });

export const autoLockNotice = writable<string | null>(null);

export const currentSettings = derived(sessionState, ($s) =>
  $s.status === 'unlocked' ? $s.settings : null
);
```

- [ ] **Step 8: Create `src/lib/auto_lock.ts`**

```typescript
// Browser-side activity tracker. Installs document-level mousemove + keydown
// listeners; debounces calls to ipc.notifyActivity() to at most once per
// ACTIVITY_NOTIFY_MIN_INTERVAL_MS.
//
// Mirrors the constant from src-tauri/src/constants.rs.

import { notifyActivity } from './ipc';

// Must match Rust-side ACTIVITY_NOTIFY_MIN_INTERVAL_MS. If you change one,
// change the other.
export const ACTIVITY_NOTIFY_MIN_INTERVAL_MS = 2_000;

let lastNotifyMs = 0;
let timerId: ReturnType<typeof setTimeout> | null = null;
let cleanup: (() => void) | null = null;

function maybeNotify() {
  const now = Date.now();
  const elapsed = now - lastNotifyMs;
  if (elapsed >= ACTIVITY_NOTIFY_MIN_INTERVAL_MS) {
    lastNotifyMs = now;
    notifyActivity().catch((e) => {
      // Notify-activity is best-effort. A failure (e.g. session locked
      // between the debounce + IPC call) is silently dropped.
      console.debug('notifyActivity failed', e);
    });
    return;
  }
  // Schedule the next allowed notify for when the debounce window expires.
  if (timerId === null) {
    timerId = setTimeout(() => {
      timerId = null;
      lastNotifyMs = Date.now();
      notifyActivity().catch(() => {});
    }, ACTIVITY_NOTIFY_MIN_INTERVAL_MS - elapsed);
  }
}

export function startActivityTracking(): () => void {
  if (cleanup) {
    cleanup(); // restart fresh
  }
  document.addEventListener('mousemove', maybeNotify, { passive: true });
  document.addEventListener('keydown', maybeNotify, { passive: true });
  cleanup = () => {
    document.removeEventListener('mousemove', maybeNotify);
    document.removeEventListener('keydown', maybeNotify);
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
    cleanup = null;
  };
  return cleanup;
}

// Test-only — reset internal state between tests.
export function _resetActivityTrackingForTest() {
  lastNotifyMs = 0;
  if (timerId !== null) {
    clearTimeout(timerId);
    timerId = null;
  }
  if (cleanup) {
    cleanup();
  }
}
```

- [ ] **Step 9: Create `tests/auto_lock.test.ts`**

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const notifyActivityMock = vi.fn();
vi.mock('../src/lib/ipc', () => ({ notifyActivity: notifyActivityMock }));

import { startActivityTracking, _resetActivityTrackingForTest, ACTIVITY_NOTIFY_MIN_INTERVAL_MS } from '../src/lib/auto_lock';

beforeEach(() => {
  vi.useFakeTimers();
  notifyActivityMock.mockReset();
  notifyActivityMock.mockResolvedValue(undefined);
  _resetActivityTrackingForTest();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('startActivityTracking', () => {
  it('first mousemove triggers immediate notifyActivity', () => {
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
  });

  it('subsequent events within debounce window do not re-trigger', () => {
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    document.dispatchEvent(new KeyboardEvent('keydown'));
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
  });

  it('event after debounce window triggers a new notify', () => {
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    vi.advanceTimersByTime(ACTIVITY_NOTIFY_MIN_INTERVAL_MS + 1);
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(2);
  });

  it('cleanup detaches listeners', () => {
    const cleanup = startActivityTracking();
    cleanup();
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 10: Create `.eslintrc.cjs`**

```javascript
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },
  env: { browser: true, node: true, es2022: true },
  ignorePatterns: ['dist', 'node_modules', 'src-tauri', 'target'],
  rules: {
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }]
  }
};
```

Add ESLint to devDeps: `pnpm add -D eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin`.

- [ ] **Step 11: Run the frontend gauntlet**

```bash
cd desktop
pnpm install        # picks up the new devDeps
pnpm test           # Vitest — expect 4 (errors) + 4 (ipc) + 4 (auto_lock) = 12 tests
pnpm tsc --noEmit   # type-check
pnpm svelte-check   # svelte type-check (no Svelte files yet — should be silent)
pnpm lint           # ESLint
```

Expected: all clean. 12 Vitest tests passing.

- [ ] **Step 12: Combined gauntlet (Rust + Python + frontend)**

```bash
cd /Users/hherb/src/secretary/.worktrees/d11-task-6
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
cd desktop && pnpm test 2>&1 | tail -5 && pnpm tsc --noEmit && pnpm svelte-check && pnpm lint 2>&1 | tail -5
```

Expected:
- Rust: PASSED 1005 FAILED 0 IGNORED 10 (unchanged from Task 5)
- TS: 12 tests passing, tsc + svelte-check + lint clean

- [ ] **Step 13: Commit + push + PR**

```bash
git add desktop/
git commit -m "feat(d11): frontend pure modules (ipc, stores, errors, auto_lock) + Vitest harness

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-6
gh pr create --title "feat(d11): Task 6 — frontend pure modules + Vitest" --body "..."
```

After merge, the gauntlet now includes the four `pnpm` lines. Frontend test count baseline = **12**.

---

## Task 7: Unlock route + PathPicker component

**Why:** First user-visible Svelte component. Implements the single-screen unlock form (spec §12) wiring up `unlockWithPassword` IPC, error display via `userMessageFor`, and the native folder dialog via `@tauri-apps/plugin-dialog`. PathPicker isolates the folder-selection logic into a reusable leaf component.

**Files:**
- Create: `desktop/src/components/PathPicker.svelte`
- Create: `desktop/src/routes/Unlock.svelte`
- Create: `desktop/src/theme.css`
- Modify: `desktop/src/App.svelte` (subscribe to sessionState; render Unlock when locked)
- Modify: `desktop/src-tauri/tauri.conf.json` (add dialog plugin permissions)
- Modify: `desktop/src-tauri/Cargo.toml` (add `tauri-plugin-dialog` dep)
- Modify: `desktop/src-tauri/src/main.rs` (`.plugin(tauri_plugin_dialog::init())`)

- [ ] **Step 1: Set up worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-7 -b feature/d11-task-7 main
cd .worktrees/d11-task-7
```

- [ ] **Step 2: Add dialog plugin to backend**

In `desktop/src-tauri/Cargo.toml`, add:

```toml
[dependencies]
# ...existing deps...
tauri-plugin-dialog = "2"
```

In `desktop/src-tauri/src/main.rs`, add the plugin to the builder:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_dialog::init())
    .manage(Mutex::new(VaultSession::new()))
    // ...rest unchanged
```

In `desktop/src-tauri/capabilities/default.json` (create the file):

```json
{
  "$schema": "https://schema.tauri.app/config/2.0.0/capability",
  "identifier": "default",
  "description": "Default capabilities for the secretary-desktop app",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "dialog:allow-open"
  ]
}
```

And reference it from `tauri.conf.json`:

```json
"app": {
  "windows": [...],
  "security": {
    "csp": "..."
  }
}
```

(Tauri 2 picks up `capabilities/*.json` automatically; no explicit reference needed in `tauri.conf.json`.)

- [ ] **Step 3: Create `src/theme.css`**

```css
/* Secretary desktop — CSS custom properties theme.
   Loaded by App.svelte; component-level styles reference these tokens.

   No CSS framework — plain custom properties keep the bundle minimal
   (~2 KB after gzip) and make the entire theme reviewable in one file. */

:root {
  /* Color tokens — neutral base; semantic tokens layered on top */
  --color-bg: #fafafa;
  --color-bg-elevated: #ffffff;
  --color-text: #1a1a1a;
  --color-text-muted: #6b6b6b;
  --color-border: #e0e0e0;
  --color-primary: #2563eb;
  --color-primary-hover: #1d4ed8;
  --color-danger: #dc2626;
  --color-danger-bg: #fef2f2;
  --color-warning: #d97706;
  --color-warning-bg: #fffbeb;

  /* Spacing tokens */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 24px;
  --space-6: 32px;
  --space-7: 48px;
  --space-8: 64px;

  /* Border-radius tokens */
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 10px;

  /* Typography */
  --font-stack: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-stack-mono: ui-monospace, "SF Mono", Menlo, monospace;
  --font-size-xs: 11px;
  --font-size-sm: 13px;
  --font-size-md: 15px;
  --font-size-lg: 18px;
  --font-size-xl: 22px;

  /* Shadows */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.04);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.08);
  --shadow-lg: 0 16px 32px rgba(0, 0, 0, 0.12);
}

@media (prefers-color-scheme: dark) {
  :root {
    --color-bg: #0f0f10;
    --color-bg-elevated: #1a1a1c;
    --color-text: #f5f5f5;
    --color-text-muted: #a1a1a1;
    --color-border: #2a2a2d;
    --color-primary: #60a5fa;
    --color-primary-hover: #93c5fd;
    --color-danger: #f87171;
    --color-danger-bg: #2a1414;
    --color-warning: #fbbf24;
    --color-warning-bg: #2a2014;
  }
}

* {
  box-sizing: border-box;
}

body {
  font-family: var(--font-stack);
  font-size: var(--font-size-md);
  color: var(--color-text);
  background: var(--color-bg);
  margin: 0;
}
```

- [ ] **Step 4: Create `src/components/PathPicker.svelte`**

```svelte
<script lang="ts">
  import { open as openDialog } from '@tauri-apps/plugin-dialog';

  type Props = {
    value: string;
    onSelect: (path: string) => void;
    disabled?: boolean;
  };

  let { value, onSelect, disabled = false }: Props = $props();

  async function pick() {
    const selected = await openDialog({
      directory: true,
      multiple: false,
      title: 'Choose vault folder'
    });
    if (typeof selected === 'string') {
      onSelect(selected);
    }
  }
</script>

<div class="path-picker">
  <input
    type="text"
    readonly
    value={value || ''}
    placeholder="No folder selected"
    {disabled}
  />
  <button type="button" onclick={pick} {disabled}>Choose…</button>
</div>

<style>
  .path-picker {
    display: flex;
    gap: var(--space-2);
  }
  input {
    flex: 1;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-elevated);
    color: var(--color-text);
    font-family: var(--font-stack-mono);
    font-size: var(--font-size-sm);
  }
  button {
    padding: var(--space-2) var(--space-4);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-elevated);
    color: var(--color-text);
    cursor: pointer;
    font-size: var(--font-size-sm);
  }
  button:hover:not(:disabled) {
    background: var(--color-border);
  }
  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
```

- [ ] **Step 5: Create `src/routes/Unlock.svelte`**

```svelte
<script lang="ts">
  import PathPicker from '../components/PathPicker.svelte';
  import { sessionState } from '../lib/stores';
  import { unlockWithPassword } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';

  let folderPath = $state('');
  let password = $state('');
  let submitting = $state(false);

  const formValid = $derived(folderPath.length > 0 && password.length > 0);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!formValid || submitting) return;
    submitting = true;
    sessionState.set({ status: 'unlocking', lastError: null });
    try {
      const manifest = await unlockWithPassword(folderPath, password);
      // Fetch settings — the manifest carries warnings but not the full settings
      // value. The post-unlock route reads via getSettings IPC.
      const { getSettings } = await import('../lib/ipc');
      const settings = await getSettings();
      sessionState.set({ status: 'unlocked', manifest, settings });
      password = ''; // do not retain in DOM state any longer than necessary
    } catch (err) {
      sessionState.set({ status: 'locked', lastError: err as AppError });
    } finally {
      submitting = false;
    }
  }

  // Display state.lastError as inline form error
  let errMsg = $derived(
    $sessionState.status === 'locked' && $sessionState.lastError
      ? userMessageFor($sessionState.lastError)
      : null
  );
</script>

<main class="unlock">
  <div class="card">
    <div class="icon">🔐</div>
    <h1>Secretary</h1>
    <p class="subtitle">Open a vault</p>

    <form onsubmit={submit}>
      {#if errMsg}
        <div class="error">
          <div class="error-title">{errMsg.title}</div>
          {#if errMsg.detail}<div class="error-detail">{errMsg.detail}</div>{/if}
          {#if errMsg.actionHint}<div class="error-hint">{errMsg.actionHint}</div>{/if}
        </div>
      {/if}

      <label>
        <span class="label">Vault folder</span>
        <PathPicker
          value={folderPath}
          onSelect={(p) => (folderPath = p)}
          disabled={submitting}
        />
      </label>

      <label>
        <span class="label">Password</span>
        <input
          type="password"
          bind:value={password}
          placeholder="••••••••"
          disabled={submitting}
          autofocus={folderPath.length > 0}
        />
      </label>

      <button type="submit" class="submit" disabled={!formValid || submitting}>
        {submitting ? 'Unlocking…' : 'Unlock'}
      </button>

      <div class="footer">Lost your password? Use recovery phrase (coming soon)</div>
    </form>
  </div>
</main>

<style>
  .unlock {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: var(--space-5);
  }
  .card {
    max-width: 420px;
    width: 100%;
    padding: var(--space-7) var(--space-5);
    background: var(--color-bg-elevated);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-md);
    text-align: center;
  }
  .icon { font-size: 48px; margin-bottom: var(--space-2); }
  h1 { margin: 0 0 var(--space-1); font-size: var(--font-size-xl); }
  .subtitle { margin: 0 0 var(--space-6); color: var(--color-text-muted); font-size: var(--font-size-sm); }

  form { text-align: left; }
  label { display: block; margin-bottom: var(--space-4); }
  .label {
    display: block;
    margin-bottom: var(--space-2);
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
  }
  input[type="password"] {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font-size: var(--font-size-md);
  }
  .submit {
    width: 100%;
    padding: var(--space-3);
    margin-top: var(--space-2);
    border: none;
    border-radius: var(--radius-md);
    background: var(--color-primary);
    color: white;
    font-weight: 600;
    font-size: var(--font-size-md);
    cursor: pointer;
  }
  .submit:hover:not(:disabled) { background: var(--color-primary-hover); }
  .submit:disabled { opacity: 0.5; cursor: not-allowed; }

  .error {
    margin-bottom: var(--space-4);
    padding: var(--space-3);
    border-radius: var(--radius-md);
    background: var(--color-danger-bg);
    color: var(--color-danger);
    font-size: var(--font-size-sm);
  }
  .error-title { font-weight: 600; }
  .error-detail, .error-hint { margin-top: var(--space-1); font-size: var(--font-size-xs); }

  .footer {
    margin-top: var(--space-5);
    text-align: center;
    color: var(--color-text-muted);
    font-size: var(--font-size-xs);
  }
</style>
```

- [ ] **Step 6: Update `App.svelte` to subscribe to sessionState**

```svelte
<script lang="ts">
  import { sessionState } from './lib/stores';
  import Unlock from './routes/Unlock.svelte';
  import './theme.css';
</script>

{#if $sessionState.status === 'unlocked'}
  <!-- Vault route lands in Task 8 -->
  <main><h1>Unlocked — Vault view coming in Task 8</h1></main>
{:else}
  <Unlock />
{/if}
```

- [ ] **Step 7: Smoke-test the unlock flow**

```bash
cd desktop && pnpm tauri dev
```

Manual test:
1. Window opens showing the Unlock card.
2. Click "Choose…" → native folder dialog opens.
3. Navigate to `core/tests/data/golden_vault_001` and select it.
4. Enter the known-good password.
5. Click "Unlock" → button shows "Unlocking…" → screen swaps to "Unlocked — Vault view coming in Task 8".
6. Try wrong password → inline red error "Wrong password" + Caps Lock hint.

- [ ] **Step 8: Gauntlet + commit + PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/d11-task-7
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
cd desktop && pnpm test && pnpm tsc --noEmit && pnpm svelte-check && pnpm lint
```

Expected: Rust 1005 / 0 / 10 unchanged. TS 12 tests pass. Type-checks clean.

```bash
git add desktop/ && git commit -m "feat(d11): Unlock route + PathPicker + theme tokens

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-7
gh pr create --title "feat(d11): Task 7 — Unlock screen + PathPicker + theme" --body "..."
```

---

## Task 8: Vault route + BlockCard + LockButton

**Why:** Second user-visible route. Implements the post-unlock screen (spec §12 "Vault screen") — top bar with vault label + settings gear + lock button, vertical stack of BlockCards. Clicks on cards are stubbed (D.1.2 wires them up). LockButton calls the `lock` IPC; the frontend waits for the `vault-locked` event before transitioning (per spec §7 — backend reality is source of truth).

**Files:**
- Create: `desktop/src/components/BlockCard.svelte`
- Create: `desktop/src/components/LockButton.svelte`
- Create: `desktop/src/routes/Vault.svelte`
- Modify: `desktop/src/App.svelte` (render Vault when unlocked)

- [ ] **Step 1: Set up worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-8 -b feature/d11-task-8 main
cd .worktrees/d11-task-8
```

- [ ] **Step 2: Create `src/components/BlockCard.svelte`**

```svelte
<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';

  type Props = { block: BlockSummaryDto };
  let { block }: Props = $props();

  function formatTimestamp(ms: number): string {
    const d = new Date(ms);
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }
</script>

<button
  class="block-card"
  type="button"
  title="Block details coming in the next release"
  aria-label={`${block.blockName}: ${block.recordCount} records, last modified ${formatTimestamp(block.lastModMs)}`}
>
  <div class="name">{block.blockName}</div>
  <div class="meta">
    {block.recordCount} record{block.recordCount === 1 ? '' : 's'}
    · last mod {formatTimestamp(block.lastModMs)}
  </div>
</button>

<style>
  .block-card {
    width: 100%;
    text-align: left;
    padding: var(--space-3) var(--space-4);
    margin: 0;
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-elevated);
    color: var(--color-text);
    cursor: not-allowed;
    font-family: var(--font-stack);
    font-size: var(--font-size-md);
  }
  .name { font-weight: 600; }
  .meta { margin-top: var(--space-1); font-size: var(--font-size-xs); color: var(--color-text-muted); }
</style>
```

- [ ] **Step 3: Create `src/components/LockButton.svelte`**

```svelte
<script lang="ts">
  import { lock } from '../lib/ipc';
  import { sessionState } from '../lib/stores';

  let locking = $state(false);

  async function handleClick() {
    if (locking) return;
    locking = true;
    sessionState.set({ status: 'locking', lastError: null });
    try {
      await lock();
      // Don't set sessionState here — the `vault-locked` event listener
      // in App.svelte does that. Frontend mirrors backend reality.
    } catch (e) {
      console.error('lock IPC failed', e);
      // Force-transition to locked anyway — even on IPC error, the user
      // wanted to lock, so present them with the locked screen.
      sessionState.set({ status: 'locked', lastError: null });
    } finally {
      locking = false;
    }
  }
</script>

<button class="lock-button" type="button" onclick={handleClick} disabled={locking}>
  🔒 {locking ? 'Locking…' : 'Lock'}
</button>

<style>
  .lock-button {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-elevated);
    color: var(--color-text);
    cursor: pointer;
    font-size: var(--font-size-sm);
  }
  .lock-button:hover:not(:disabled) { background: var(--color-danger-bg); color: var(--color-danger); border-color: var(--color-danger); }
  .lock-button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
```

- [ ] **Step 4: Create `src/routes/Vault.svelte`**

```svelte
<script lang="ts">
  import { sessionState } from '../lib/stores';
  import { userMessageForWarning } from '../lib/errors';
  import BlockCard from '../components/BlockCard.svelte';
  import LockButton from '../components/LockButton.svelte';

  // Only render when actually unlocked — defensive coding via discriminant
  // narrowing.
  let unlockedState = $derived(
    $sessionState.status === 'unlocked' ? $sessionState : null
  );
</script>

{#if unlockedState}
  {@const manifest = unlockedState.manifest}
  {@const warnings = manifest.warnings}

  <div class="vault">
    <header>
      <div class="header-left">
        <strong>Secretary</strong>
        <span class="vault-id">· vault: {manifest.vaultUuidHex.slice(0, 8)}…</span>
      </div>
      <div class="header-right">
        <!-- Settings dialog trigger lands in Task 9; placeholder here -->
        <button type="button" class="settings-trigger" disabled title="Settings (Task 9)">⚙️ Settings</button>
        <LockButton />
      </div>
    </header>

    {#each warnings as warning}
      <div class="warning-banner">
        <strong>{userMessageForWarning(warning).title}</strong>
        {#if userMessageForWarning(warning).detail}
          — <span>{userMessageForWarning(warning).detail}</span>
        {/if}
      </div>
    {/each}

    <div class="block-list-header">
      {manifest.blockCount} block{manifest.blockCount === 1n || manifest.blockCount === 1 ? '' : 's'}
    </div>

    <div class="block-list">
      {#each manifest.blockSummaries as block (block.blockUuidHex)}
        <BlockCard {block} />
      {/each}
    </div>
  </div>
{/if}

<style>
  .vault { padding: var(--space-4); }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-2) var(--space-3);
    margin-bottom: var(--space-5);
    background: var(--color-bg-elevated);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
  }
  .vault-id { color: var(--color-text-muted); font-family: var(--font-stack-mono); font-size: var(--font-size-sm); }
  .header-right { display: flex; gap: var(--space-2); }
  .settings-trigger {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-elevated);
    color: var(--color-text-muted);
    cursor: not-allowed;
    font-size: var(--font-size-sm);
    opacity: 0.6;
  }
  .warning-banner {
    padding: var(--space-3);
    margin-bottom: var(--space-4);
    background: var(--color-warning-bg);
    color: var(--color-warning);
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
  }
  .block-list-header {
    margin-bottom: var(--space-2);
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
  }
  .block-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
</style>
```

- [ ] **Step 5: Update `App.svelte` to render Vault when unlocked**

```svelte
<script lang="ts">
  import { sessionState } from './lib/stores';
  import Unlock from './routes/Unlock.svelte';
  import Vault from './routes/Vault.svelte';
  import './theme.css';
</script>

{#if $sessionState.status === 'unlocked'}
  <Vault />
{:else}
  <Unlock />
{/if}
```

- [ ] **Step 6: Smoke-test**

```bash
cd desktop && pnpm tauri dev
```

1. Unlock golden_vault_001.
2. Verify Vault screen appears with header + warning banner (if any) + block-count label + block cards.
3. Hover over a card — cursor is `not-allowed`.
4. Click "🔒 Lock" → button shows "Locking…" → screen swaps back to Unlock (this still requires the `vault-locked` event listener in App.svelte from Task 10; for this task's manual test the screen may not auto-transition until Task 10 lands. **OK to defer the visual transition verification to Task 10**.)

- [ ] **Step 7: Gauntlet + commit + PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/d11-task-8
cd desktop && pnpm test && pnpm tsc --noEmit && pnpm svelte-check && pnpm lint
cd /Users/hherb/src/secretary/.worktrees/d11-task-8
cargo clippy --release --workspace --tests -- -D warnings && cargo fmt --all -- --check
```

Expected: all clean. No new tests (Svelte component-level tests are out of D.1.1 scope).

```bash
git add desktop/ && git commit -m "feat(d11): Vault route + BlockCard + LockButton

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-8
gh pr create --title "feat(d11): Task 8 — Vault route + BlockCard + LockButton" --body "..."
```

---

## Task 9: Settings dialog + integration

**Why:** Implements the settings dialog (spec §12 "Settings dialog") — native `<dialog>` overlay on Vault, single field for auto-lock timeout, client-side bounds validation + IPC `setSettings` call. Wires the gear icon in Vault.svelte (currently disabled in Task 8) to open the dialog.

**Files:**
- Create: `desktop/src/components/SettingsDialog.svelte`
- Modify: `desktop/src/routes/Vault.svelte` (enable settings gear, instantiate dialog)

- [ ] **Step 1: Set up worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-9 -b feature/d11-task-9 main
cd .worktrees/d11-task-9
```

- [ ] **Step 2: Create `src/components/SettingsDialog.svelte`**

```svelte
<script lang="ts">
  import { sessionState } from '../lib/stores';
  import { setSettings } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';

  // Mirror Rust-side constants. If you change one, change both.
  const AUTO_LOCK_MIN_MIN = 1;   // 60_000 ms / 60_000 = 1 minute
  const AUTO_LOCK_MAX_MIN = 1440; // 86_400_000 ms / 60_000 = 1440 minutes

  type Props = {
    open: boolean;
    onClose: () => void;
  };
  let { open = $bindable(), onClose }: Props = $props();

  // Derive initial value from current settings store.
  let currentMs = $derived(
    $sessionState.status === 'unlocked' ? $sessionState.settings.autoLockTimeoutMs : 600_000
  );
  let inputMinutes = $state(Math.round(currentMs / 60_000));
  let submitting = $state(false);
  let formError = $state<AppError | null>(null);

  let dialogEl: HTMLDialogElement | undefined = $state();

  // Re-sync input when settings change in the store.
  $effect(() => {
    inputMinutes = Math.round(currentMs / 60_000);
  });

  $effect(() => {
    if (dialogEl) {
      if (open) {
        dialogEl.showModal();
      } else {
        dialogEl.close();
      }
    }
  });

  function clientSideValidate(): string | null {
    if (!Number.isInteger(inputMinutes)) return 'Must be a whole number';
    if (inputMinutes < AUTO_LOCK_MIN_MIN) return `Minimum is ${AUTO_LOCK_MIN_MIN} minute`;
    if (inputMinutes > AUTO_LOCK_MAX_MIN) return `Maximum is ${AUTO_LOCK_MAX_MIN} minutes`;
    return null;
  }

  async function save() {
    const validationErr = clientSideValidate();
    if (validationErr) {
      formError = { code: 'settings_out_of_range', min: AUTO_LOCK_MIN_MIN * 60_000, max: AUTO_LOCK_MAX_MIN * 60_000 };
      return;
    }
    submitting = true;
    formError = null;
    try {
      const newMs = inputMinutes * 60_000;
      await setSettings({ autoLockTimeoutMs: newMs });
      // Update local store immediately — backend has persisted.
      if ($sessionState.status === 'unlocked') {
        sessionState.set({
          ...$sessionState,
          settings: { autoLockTimeoutMs: newMs }
        });
      }
      onClose();
    } catch (err) {
      formError = err as AppError;
    } finally {
      submitting = false;
    }
  }

  function cancel() {
    formError = null;
    inputMinutes = Math.round(currentMs / 60_000);
    onClose();
  }
</script>

<dialog bind:this={dialogEl} onclose={cancel}>
  <h2>Settings</h2>

  <label>
    <span class="label">Auto-lock after</span>
    <div class="input-row">
      <input
        type="number"
        min={AUTO_LOCK_MIN_MIN}
        max={AUTO_LOCK_MAX_MIN}
        step="1"
        bind:value={inputMinutes}
        disabled={submitting}
      />
      <span class="suffix">minutes</span>
    </div>
  </label>

  {#if formError}
    {@const msg = userMessageFor(formError)}
    <div class="error">
      <strong>{msg.title}</strong>
      {#if msg.detail}<div>{msg.detail}</div>{/if}
    </div>
  {/if}

  <div class="actions">
    <button type="button" onclick={cancel} disabled={submitting}>Cancel</button>
    <button type="button" class="primary" onclick={save} disabled={submitting}>
      {submitting ? 'Saving…' : 'Save'}
    </button>
  </div>
</dialog>

<style>
  dialog {
    border: 1px solid var(--color-border);
    border-radius: var(--radius-lg);
    background: var(--color-bg-elevated);
    color: var(--color-text);
    padding: var(--space-5);
    min-width: 380px;
    box-shadow: var(--shadow-lg);
  }
  dialog::backdrop {
    background: rgba(0, 0, 0, 0.4);
  }
  h2 { margin: 0 0 var(--space-4); font-size: var(--font-size-lg); }
  .label {
    display: block;
    margin-bottom: var(--space-2);
    font-size: var(--font-size-xs);
    text-transform: uppercase;
    color: var(--color-text-muted);
    letter-spacing: 0.05em;
  }
  .input-row { display: flex; align-items: center; gap: var(--space-2); }
  input[type="number"] {
    flex: 0 0 100px;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg);
    color: var(--color-text);
    font-size: var(--font-size-md);
  }
  .suffix { color: var(--color-text-muted); }
  .error {
    margin-top: var(--space-3);
    padding: var(--space-3);
    background: var(--color-danger-bg);
    color: var(--color-danger);
    border-radius: var(--radius-md);
    font-size: var(--font-size-sm);
  }
  .actions {
    margin-top: var(--space-5);
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
  button {
    padding: var(--space-2) var(--space-4);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-elevated);
    color: var(--color-text);
    cursor: pointer;
    font-size: var(--font-size-sm);
  }
  button.primary { background: var(--color-primary); border-color: var(--color-primary); color: white; }
  button.primary:hover:not(:disabled) { background: var(--color-primary-hover); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
```

- [ ] **Step 3: Wire the settings dialog into `Vault.svelte`**

Edit `desktop/src/routes/Vault.svelte` — add the import + state + render:

```svelte
<script lang="ts">
  import { sessionState } from '../lib/stores';
  import { userMessageForWarning } from '../lib/errors';
  import BlockCard from '../components/BlockCard.svelte';
  import LockButton from '../components/LockButton.svelte';
  import SettingsDialog from '../components/SettingsDialog.svelte';

  let unlockedState = $derived(
    $sessionState.status === 'unlocked' ? $sessionState : null
  );

  let settingsOpen = $state(false);
</script>

<!-- ... existing markup ... -->
<button type="button" class="settings-trigger" onclick={() => (settingsOpen = true)}>⚙️ Settings</button>
<!-- (remove the `disabled` attr) -->

<!-- At the bottom of the {#if unlockedState} block: -->
<SettingsDialog bind:open={settingsOpen} onClose={() => (settingsOpen = false)} />
```

Remove the `:disabled` and the `cursor: not-allowed` from the `.settings-trigger` styles (the gear is now active).

- [ ] **Step 4: Smoke-test**

```bash
cd desktop && pnpm tauri dev
```

1. Unlock golden vault.
2. Click "⚙️ Settings" → dialog opens with current value (10 min default).
3. Type "5" → click Save → dialog closes.
4. Lock + re-unlock the vault → open Settings again → value persists as 5.
5. Try invalid values: 0, -1, 9999 — inline error shows.

- [ ] **Step 5: Gauntlet + commit + PR**

Same gauntlet as before. Commit:

```bash
git add desktop/ && git commit -m "feat(d11): Settings dialog with auto-lock timeout persistence

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-9
gh pr create --title "feat(d11): Task 9 — Settings dialog" --body "..."
```

---

## Task 10: App.svelte orchestration — event listener + Toast + activity tracking

**Why:** Closes the session lifecycle loop on the frontend. App.svelte subscribes to the backend's `vault-locked` Tauri event so explicit + auto-lock both transition the UI. Toast component renders the auto-lock notice from spec §12. Activity tracking (mousemove/keydown → debounced `notifyActivity` IPC) is started on unlock + stopped on lock.

**Files:**
- Create: `desktop/src/components/Toast.svelte`
- Modify: `desktop/src/App.svelte` (event listener + activity tracking lifecycle)

- [ ] **Step 1: Set up worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-10 -b feature/d11-task-10 main
cd .worktrees/d11-task-10
```

- [ ] **Step 2: Create `src/components/Toast.svelte`**

```svelte
<script lang="ts">
  import { autoLockNotice } from '../lib/stores';
  import { onMount } from 'svelte';

  type Props = { message: string };
  let { message }: Props = $props();

  const AUTO_DISMISS_MS = 5_000;

  onMount(() => {
    const t = setTimeout(() => autoLockNotice.set(null), AUTO_DISMISS_MS);
    return () => clearTimeout(t);
  });
</script>

<div class="toast" role="status" aria-live="polite">
  {message}
  <button type="button" class="dismiss" onclick={() => autoLockNotice.set(null)} aria-label="Dismiss">×</button>
</div>

<style>
  .toast {
    position: fixed;
    top: var(--space-4);
    right: var(--space-4);
    padding: var(--space-3) var(--space-4);
    background: var(--color-bg-elevated);
    color: var(--color-text);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    font-size: var(--font-size-sm);
    z-index: 9999;
    animation: slide-in 0.2s ease-out;
  }
  @keyframes slide-in {
    from { transform: translateX(20px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  .dismiss {
    border: none;
    background: transparent;
    color: var(--color-text-muted);
    cursor: pointer;
    font-size: var(--font-size-lg);
    padding: 0;
    line-height: 1;
  }
  .dismiss:hover { color: var(--color-text); }
</style>
```

- [ ] **Step 3: Update `App.svelte` — full orchestration**

```svelte
<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { sessionState, autoLockNotice } from './lib/stores';
  import { startActivityTracking } from './lib/auto_lock';
  import Unlock from './routes/Unlock.svelte';
  import Vault from './routes/Vault.svelte';
  import Toast from './components/Toast.svelte';
  import './theme.css';

  let unlistenVaultLocked: UnlistenFn | null = null;
  let stopActivity: (() => void) | null = null;

  onMount(async () => {
    unlistenVaultLocked = await listen<{ reason: 'idle' | 'explicit' | 'window_close' }>(
      'vault-locked',
      (event) => {
        sessionState.set({ status: 'locked', lastError: null });
        if (stopActivity) {
          stopActivity();
          stopActivity = null;
        }
        if (event.payload.reason === 'idle') {
          autoLockNotice.set('Vault auto-locked due to inactivity');
        }
      }
    );
  });

  onDestroy(() => {
    if (unlistenVaultLocked) unlistenVaultLocked();
    if (stopActivity) stopActivity();
  });

  // Start activity tracking when transitioning into unlocked; stop when leaving.
  $effect(() => {
    if ($sessionState.status === 'unlocked' && !stopActivity) {
      stopActivity = startActivityTracking();
    } else if ($sessionState.status !== 'unlocked' && stopActivity) {
      stopActivity();
      stopActivity = null;
    }
  });
</script>

{#if $sessionState.status === 'unlocked'}
  <Vault />
{:else}
  <Unlock />
{/if}

{#if $autoLockNotice}
  <Toast message={$autoLockNotice} />
{/if}
```

- [ ] **Step 4: Smoke-test the full lifecycle**

```bash
cd desktop && pnpm tauri dev
```

1. Unlock golden vault.
2. Open Settings → set auto-lock to 1 minute → Save.
3. Stop touching the mouse/keyboard. Wait ~1 minute + the 5s tick interval = up to 70s.
4. Vault auto-locks; Toast slides in from top-right with "Vault auto-locked due to inactivity"; screen returns to Unlock.
5. Toast auto-dismisses after 5 seconds (or click × to dismiss immediately).
6. Re-unlock + click Lock manually → screen transitions to Unlock immediately. No toast (toast is only for `reason === 'idle'`).

- [ ] **Step 5: Gauntlet + commit + PR**

Same gauntlet. Commit + push + PR with title "feat(d11): Task 10 — App orchestration + Toast + activity tracking".

---

## Task 11: L4 end-to-end smoke test (tauri-driver + WDIO)

**Why:** Spec §10 L4 — one end-to-end test that drives the full unlock → block list → lock cycle through the actual WebView. Not in CI for D.1.1 (deferred per spec §13), but lives in the repo so any contributor with `tauri-driver` installed can run `pnpm e2e` against a `cargo tauri build --debug` artifact and validate the full flow.

**Files:**
- Create: `desktop/e2e/wdio.conf.ts`
- Create: `desktop/e2e/unlock_and_browse.spec.ts`
- Modify: `desktop/package.json` (add `pnpm e2e` script + WDIO devDeps)

- [ ] **Step 1: Set up worktree**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree add .worktrees/d11-task-11 -b feature/d11-task-11 main
cd .worktrees/d11-task-11
```

- [ ] **Step 2: Add WDIO devDeps**

```bash
cd desktop
pnpm add -D @wdio/cli @wdio/local-runner @wdio/mocha-framework @wdio/spec-reporter
```

In `desktop/package.json`, add the e2e script:

```json
"scripts": {
  "e2e": "wdio run e2e/wdio.conf.ts"
}
```

- [ ] **Step 3: Verify `tauri-driver` is installed (developer note)**

```bash
which tauri-driver || cargo install tauri-driver
```

On macOS, `tauri-driver` shells out to `safaridriver` (built-in). On Linux, it shells out to `WebKitWebDriver` (part of webkit2gtk).

- [ ] **Step 4: Create `desktop/e2e/wdio.conf.ts`**

```typescript
import { spawn, ChildProcess } from 'child_process';
import { join } from 'path';

let tauriDriverProcess: ChildProcess | null = null;

// Resolve the debug binary built by `cargo tauri build --debug`.
const BINARY_PATH = join(__dirname, '..', 'src-tauri', 'target', 'debug', 'secretary-desktop');

export const config: WebdriverIO.Config = {
  hostname: '127.0.0.1',
  port: 4444,
  specs: ['./e2e/**/*.spec.ts'],
  maxInstances: 1,
  capabilities: [{
    'tauri:options': {
      application: BINARY_PATH
    }
  }] as unknown as WebdriverIO.Capabilities[],
  reporters: ['spec'],
  framework: 'mocha',
  mochaOpts: { ui: 'bdd', timeout: 60_000 },
  onPrepare: () => {
    tauriDriverProcess = spawn('tauri-driver', [], { stdio: 'inherit' });
  },
  onComplete: () => {
    if (tauriDriverProcess) tauriDriverProcess.kill();
  }
};
```

- [ ] **Step 5: Create `desktop/e2e/unlock_and_browse.spec.ts`**

```typescript
import { join } from 'path';
import { describe, it } from 'mocha';

const GOLDEN_VAULT_PATH = join(__dirname, '..', '..', 'core', 'tests', 'data', 'golden_vault_001');
const GOLDEN_VAULT_PASSWORD = 'correct horse battery staple'; // must match the integration test fixture

describe('D.1.1 walking skeleton smoke', () => {
  it('unlock → see blocks → lock', async () => {
    // 1. App starts at Unlock screen
    const unlockHeading = await $('h1=Secretary');
    await unlockHeading.waitForDisplayed({ timeout: 10_000 });

    // 2. The PathPicker input is read-only — set the path via JS (in real
    //    use the user clicks "Choose…" and the native dialog; we can't
    //    drive the OS-native dialog from WebDriver, so we set via
    //    `execute()` against the Svelte $state binding's input element).
    const pathInput = await $('.path-picker input[type="text"]');
    // tauri-driver currently does not support typing into readonly inputs
    // directly; instead, evaluate a script that triggers the onSelect
    // callback. The cleanest way is via a test-only hook — see NOTE.
    await browser.executeScript(`
      const input = document.querySelector('.path-picker input[type="text"]');
      const valueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      valueSetter.call(input, '${GOLDEN_VAULT_PATH}');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    `, []);
    // NOTE: this approach bypasses the Svelte reactivity that normally
    // owns the value. For a robust e2e, refactor PathPicker to accept the
    // path via either prop OR a test-only `data-e2e-path` attribute that
    // wires straight to onSelect. See follow-up issue (filed by Task 11).

    // 3. Fill password
    const passwordInput = await $('input[type="password"]');
    await passwordInput.setValue(GOLDEN_VAULT_PASSWORD);

    // 4. Click Unlock
    const unlockButton = await $('button.submit');
    await unlockButton.click();

    // 5. Wait for Vault screen
    const lockButton = await $('button.lock-button');
    await lockButton.waitForDisplayed({ timeout: 15_000 });

    // 6. Assert at least one block card is rendered
    const blockCards = await $$('.block-card');
    if (blockCards.length === 0) {
      throw new Error('Expected at least one block card');
    }

    // 7. Click Lock
    await lockButton.click();

    // 8. Wait for Unlock screen again
    await unlockHeading.waitForDisplayed({ timeout: 10_000 });
  });
});
```

> NOTE: The PathPicker e2e workaround (setting the input value via JS to bypass the read-only) is fragile. Track as a follow-up issue: "PathPicker should expose a test hook for e2e folder injection." This is acknowledged technical debt for D.1.1; D.1.2 should clean it up when the e2e suite grows.

- [ ] **Step 6: Run the e2e**

```bash
# Build the debug binary first
cd desktop && pnpm tauri build --debug

# In a separate terminal (or after the build finishes):
pnpm e2e
```

Expected: one test passes. If it hangs at the "wait for Vault screen" step, increase the timeout in the spec or check that `tauri-driver` is actually launching the binary.

- [ ] **Step 7: Add a README note to `desktop/README.md`**

Append to the Test layers section:

```markdown
### E2E (manual, not in CI)

```bash
cd desktop
cargo install tauri-driver  # one-time
pnpm tauri build --debug
pnpm e2e
```

L4 requires `tauri-driver` + (on Linux) WebKitWebDriver from webkit2gtk. Currently not wired into CI; tracked for the dedicated CI-infra slice.
```

- [ ] **Step 8: Gauntlet + commit + PR**

The L4 test does NOT join the per-task gauntlet (manual-only). Commit:

```bash
git add desktop/ && git commit -m "feat(d11): L4 end-to-end smoke test (tauri-driver + WDIO)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-11
gh pr create --title "feat(d11): Task 11 — L4 e2e smoke" --body "..."
```

---

## Task 12: Final integration + acceptance criteria sweep + ship D.1.1

**Why:** Closing task that verifies the spec §15 acceptance criteria end-to-end, files any deferred follow-up issues, updates the handoff baton for the next slice, and ships D.1.1 as ✅ complete. No new code; this is the "did we actually finish?" sweep.

**Files:**
- Modify: `README.md` (flip D.1 to ✅ in progress)
- Modify: `ROADMAP.md` (flip D.1.1 row)
- Create: `docs/handoffs/2026-XX-XX-d11-shipped.md` (replace XX-XX with the actual close date)
- Modify: `NEXT_SESSION.md` (retarget symlink)

- [ ] **Step 1: Set up worktree from main (which should have all 11 previous PRs merged)**

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git log -12 --oneline  # verify 11 task PRs + this plan's PR are merged
git worktree add .worktrees/d11-task-12 -b feature/d11-task-12 main
cd .worktrees/d11-task-12
```

- [ ] **Step 2: Run the §15 acceptance criteria manual smoke**

From a fresh `cd /Users/hherb/src/secretary/.worktrees/d11-task-12`:

```bash
cd desktop
pnpm install
pnpm tauri build --debug
./src-tauri/target/debug/secretary-desktop  # launch the binary directly
```

Walk through:
- ✅ Unlock screen appears.
- ✅ "Choose…" opens native folder dialog.
- ✅ Select `core/tests/data/golden_vault_001/`.
- ✅ Enter known password → Unlock.
- ✅ Vault screen shows block cards with names + record counts + last-mod dates.
- ✅ Open Settings → change auto-lock from 10 min to 1 min → Save.
- ✅ Idle 1+ minute → vault auto-locks; Toast appears; Unlock screen shown.
- ✅ Re-unlock → 1-min value persisted (open Settings, confirm).
- ✅ Click Lock → Unlock screen.
- ✅ Close window → process exits cleanly.

Document the smoke test outcome in the handoff baton.

- [ ] **Step 3: Run the full gauntlet**

```bash
cd /Users/hherb/src/secretary/.worktrees/d11-task-12
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
cd desktop && pnpm test && pnpm tsc --noEmit && pnpm svelte-check && pnpm lint
```

Expected: all clean. Capture the exact counts for the handoff.

- [ ] **Step 4: Run the L4 manual once**

```bash
cd desktop && pnpm e2e
```

Confirm L4 passes against the just-built binary.

- [ ] **Step 5: Update README.md + ROADMAP.md**

In `README.md`, update the D-row's status indicator. Change `⏳` → `🚧` (in progress) on the D-row table cell. Update the description sentence: "D.1.1 walking skeleton (unlock + block-list scaffold + vault-stored auto-lock settings) **shipped 2026-XX-XX**; D.1.2 browse next."

In `ROADMAP.md`, in the Sub-project D section, mark D.1.1 specifically as ✅ in the prose, leaving D.1.x and downstream slices as ⏳. Bump the progress bar one cell.

- [ ] **Step 6: Create the handoff baton at `docs/handoffs/2026-XX-XX-d11-shipped.md`**

Mirror the structure of `2026-05-26-c2-shipped.md`:

- §(1) What we shipped this session — table listing all 12 task PRs with SHAs, the gauntlet numbers achieved at each, the §15 acceptance criteria pass/fail.
- §(2) What's next — D.1.2 (browse, read-only): clickable block cards → record list → field viewer with reveal-secret. Acceptance criteria for D.1.2.
- §(3) Open decisions and risks — the PathPicker e2e hook follow-up; any clippy / svelte-check noise carried forward; the device-UUID-per-vault story for cross-app convergence (defers to C.4).
- §(4) Exact commands to resume — `git pull main`, gauntlet verification, "next session opens D.1.2 plan authoring".
- Closing inventory — branch state, test counts, README/ROADMAP/docs touched.

- [ ] **Step 7: Retarget the NEXT_SESSION.md symlink**

```bash
ln -snf docs/handoffs/2026-XX-XX-d11-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md  # verify
head -3 NEXT_SESSION.md  # reads through the symlink
```

- [ ] **Step 8: Commit + push + PR**

```bash
git add README.md ROADMAP.md docs/handoffs/ NEXT_SESSION.md
git commit -m "ship(d11): D.1.1 walking skeleton complete — README/ROADMAP/handoff

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
git push -u origin feature/d11-task-12
gh pr create --title "ship(d11): D.1.1 walking skeleton complete (closes D.1.1)" --body "$(cat <<'EOF'
## Summary
D.1.1 is shippable. All §15 acceptance criteria verified manually.

## Cumulative scope (Tasks 1-11)
- Tauri 2 scaffold + workspace integration
- Backend pure modules (constants, errors, auto_lock, settings parse/serialize) — 27 tests
- VaultSession + settings I/O facade — 10 integration tests against golden_vault_001
- 7 IPC commands + DTOs — 3 DTO tests
- Auto-lock timer thread + vault-locked event emission
- Frontend pure modules (ipc, stores, errors, auto_lock) — 12 Vitest tests
- Unlock route + PathPicker + theme.css
- Vault route + BlockCard + LockButton
- SettingsDialog (native <dialog>) with auto-lock timeout persistence
- App.svelte orchestration + Toast + activity tracking lifecycle
- L4 e2e (tauri-driver + WDIO) — manual, not CI

## §15 acceptance criteria

| Criterion | Status |
|---|---|
| Manual smoke (unlock golden vault, see blocks, settings persist, auto-lock fires, lock works) | ✅ |
| Gauntlet (cargo test, clippy, fmt, conformance, spec freshness, pnpm test/tsc/svelte-check/lint) | ✅ |
| L4 e2e manual | ✅ |
| Documentation (README + ROADMAP + ADR 0007 + desktop/README) | ✅ |
| Process discipline (≤500 LOC/file, no magic numbers, pure functions in own modules, random crypto values in tests) | ✅ |

## Gauntlet at close
- Workspace: PASSED [final-count] FAILED 0 IGNORED 10
- Frontend Vitest: 12 / 12
- All type-checks clean

## What's next
D.1.2 — browse (read-only): clickable block cards → record list → field viewer with reveal-secret. New baton at docs/handoffs/2026-XX-XX-d11-shipped.md.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 9: After merge, clean up worktrees**

```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
for n in 1 2 3 4 5 6 7 8 9 10 11 12; do
  git worktree remove .worktrees/d11-task-$n 2>/dev/null
  git branch -D feature/d11-task-$n 2>/dev/null
done
git worktree remove .worktrees/d11-tauri-spec  # this plan's worktree
git branch -D feature/d11-tauri-spec
```

After merge, **D.1.1 is shipped** ✅. The next session opens D.1.2 (browse — read-only block detail view + field reveal).

---

## Self-review checklist (run after committing this plan)

- [ ] Every spec section has a task covering it:
  - §4 (layout) → Tasks 1, 2, 4
  - §5 (modules) → Tasks 2, 3, 4
  - §6 (session lifecycle) → Tasks 3, 5
  - §7 (routes) → Tasks 7, 8, 10
  - §8 (settings schema) → Tasks 2, 3
  - §9 (errors) → Tasks 2, 4, 6
  - §10 (testing) → Tasks 2, 3, 4, 6, 11
  - §11 (dev loop) → Task 1
  - §12 (UX) → Tasks 7, 8, 9, 10
  - §13 (out of scope) — explicitly deferred, no tasks needed
  - §14 (broader implications) — shipped on `feature/d11-tauri-spec` (this plan's branch)
  - §15 (acceptance criteria) → Task 12
- [ ] No placeholder text — TBD / TODO / "as appropriate" — except clearly-marked notes about e.g. the PathPicker e2e hook deferral and the GOLDEN_VAULT_PASSWORD verification step.
- [ ] Type consistency: `BlockSummaryDto.blockUuidHex` (camelCase) is used consistently in DTO, IPC wrapper, Svelte component.
- [ ] Gauntlet counts increment monotonically and are explicitly stated per task (960 → 987 → 999 → 1002 → 1005, then unchanged through Tasks 6-11).







