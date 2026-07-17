# desktop/

Sub-project D — Tauri 2 universal client for Secretary (Rust backend + Svelte/TypeScript frontend). Currently being scaffolded for the D.1.1 walking skeleton — see [`docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`](../docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md) for the design and [ADR-0007](../docs/adr/0007-d-row-tauri.md) for the rationale behind the Tauri pivot from the original NiceGUI plan.

This directory will contain a single Tauri app targeting macOS, Linux, Windows desktop and (in D.3) iOS and Android. The Python (`ffi/secretary-ffi-py`) and uniffi-Swift/Kotlin (`ffi/secretary-ffi-uniffi`) bindings stay in the project as third-party-consumer paths but are no longer the UI path.

## Layout (post-scaffold)

```
desktop/
├── package.json                # frontend deps (Svelte, TS, Vite)
├── pnpm-lock.yaml
├── tsconfig.json
├── vite.config.ts
├── svelte.config.js
├── src/                        # Frontend (Svelte + TS, runs in WebView)
│   ├── main.ts                 # Svelte mount point
│   ├── App.svelte              # root — routes between Unlock and Vault
│   ├── lib/                    # pure TS modules (auto_lock, errors, ipc, stores)
│   ├── routes/                 # Unlock.svelte, Vault.svelte
│   ├── components/             # leaf components (BlockCard, PathPicker, …)
│   └── theme.css               # CSS custom properties
├── src-tauri/                  # Backend (Rust, in-process; consumes secretary-core directly)
│   ├── Cargo.toml              # workspace member
│   ├── tauri.conf.json
│   └── src/                    # main.rs + session.rs + settings.rs + auto_lock.rs + errors.rs + commands/
├── tests/                      # Vitest unit tests for pure TS modules
└── e2e/                        # tauri-driver + WDIO end-to-end smoke
```

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Rust toolchain | Stable (per repo `rust-toolchain.toml`) | rustup |
| Node.js | LTS (≥ 20.x) | nvm/fnm/system |
| pnpm | ≥ 9.x | `npm install -g pnpm` or corepack |
| WebKitGTK (Linux) | `2.40+` | `apt install libwebkit2gtk-4.1-dev` or distro equivalent |
| `tauri-driver` (for E2E only) | latest | `cargo install tauri-driver` |

macOS needs only the first three; Linux adds webkit2gtk. Windows is not a primary target.

## Dev loop (once D.1.1 task 1 has scaffolded the project)

```bash
cd desktop
pnpm install                           # installs frontend deps + tauri CLI
pnpm tauri dev                          # launches Vite dev server + Tauri window
# Frontend changes (Svelte/TS): Vite hot-reload, no restart.
# Backend changes (Rust): tauri dev auto-rebuilds + restarts (~5-10 s).
```

## macOS signed build (Touch ID)

The write re-auth Touch ID sheet (#277) is presented by `LocalAuthentication`,
which only serves interactive biometric prompts to properly signed processes.
Practical consequences, proven on hardware 2026-07-17
([#442](https://github.com/hherb/secretary/issues/442)):

- **A Developer-ID-signed release build presents the sheet.** Build one with:

  ```bash
  # Pick an identity from: security find-identity -v -p codesigning
  cd desktop
  APPLE_SIGNING_IDENTITY="Developer ID Application: <name> (<team>)" pnpm tauri build
  # → target/release/bundle/macos/Secretary.app (signed, hardened runtime)
  ```

  Tauri applies the hardened runtime automatically. **No entitlement and no
  Info.plist usage-description key is needed** for Touch ID on macOS (unlike
  Face ID on iOS) — the proof ran with none.

- **Unsigned / `pnpm tauri dev` builds may not present the sheet** — Apple
  documents unentitled/non-interactive processes failing `evaluatePolicy`
  (`LAErrorNotInteractive`-class). This is fail-safe by design: every
  unusable-biometry outcome classifies to `Unavailable` and the write re-auth
  falls back to the password dialog, so a dev build still works — it just
  never shows Touch ID. (Documented from Apple's docs; not re-proven
  empirically.)

- **Watch the presence outcomes live** by launching the bundle with stderr
  attached: `Secretary.app/Contents/MacOS/secretary-desktop` from a terminal,
  or `open -a <path/to/Secretary.app> --stderr <logfile>`.

- **Stale-copy gotcha:** Dock/Spotlight/`open -b` resolve the bundle
  *identifier* (`org.secretary.desktop`), which prefers an installed copy in
  `/Applications` over the one you just built. If a freshly built feature is
  mysteriously missing, check which binary is actually running
  (`ps -o command -p $(pgrep secretary-desktop)`).

- **Reproducing the re-auth prompts:** the gate is silent inside the grace
  window (seeded at every unlock, default 2 min) — set the Settings grace
  window to 0 minutes to make every write prompt.

## Test layers

```bash
pnpm test                               # Vitest — pure TS module unit tests
pnpm svelte-check                       # Type-check (Svelte + .ts); understands component module exports
pnpm lint                               # ESLint
# From repo root:
cargo test --release --workspace        # Rust backend unit + integration tests
# Locally only (not CI):
pnpm e2e                                # tauri-driver + WDIO end-to-end smoke
```

## Where to start

Read the design spec for D.1.1: [`docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`](../docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md). It's the source of truth for the layout, IPC contracts, session lifecycle, settings schema, error model, and test plan.
