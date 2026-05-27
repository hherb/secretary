# ADR 0007 — Sub-project D pivots to Tauri-based universal client

**Status:** Accepted (2026-05-27)
**Supersedes:** ADR 0001 (Sub-project D portion only — desktop / mobile UI choices; the Rust-core decision in ADR 0001 stands unchanged)
**Superseded by:** none

## Context

ADR 0001 (April 2026) committed Sub-project D to three separate UI codebases consuming `secretary-core` through three separate FFI bindings:

- Desktop / web — Python + NiceGUI via PyO3 bindings (`ffi/secretary-ffi-py`).
- iOS — Swift + SwiftUI via uniffi (`ffi/secretary-ffi-uniffi` → `.framework`).
- Android — Kotlin + Jetpack Compose via uniffi (`ffi/secretary-ffi-uniffi` → `.aar`).

That decision was made when the author was a Rust novice and Tauri 2 (October 2024 stable) had not yet been widely evaluated. Eight months later (May 2026), enough Rust has been written through Sub-projects A and C that the learning-curve gap to a Rust-fronted desktop client has narrowed, and Tauri 2 has matured enough that mobile-from-the-same-codebase is feasible.

This ADR records the pivot of Sub-project D's UI layer from "three native UI codebases" to "one Tauri-based codebase across desktop and mobile".

The pivot does NOT touch the Rust core, the Python FFI (`secretary-ffi-py`), or the uniffi-based Swift/Kotlin bindings (`secretary-ffi-uniffi`). All three remain in the project as third-party-consumer paths.

## Decision

Sub-project D's UI layer is implemented in Tauri 2:

- **Backend** — Rust, consuming `secretary-core` as a direct workspace dep (no FFI hop).
- **Frontend** — Svelte + TypeScript + Vite, running in the platform-native WebView (WKWebView on macOS, WebKitGTK on Linux, WebView2 on Windows, system WebView on iOS/Android).
- **IPC** — Tauri's command/event system over the `tauri://` custom URL scheme. No localhost HTTP server.

Sub-project D's slicing is restructured:

- **D.1** — Tauri walking skeleton on macOS + Linux (current slice; design in `docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`).
- **D.1.x** — feature breadth: browse (D.1.2), create vault (D.1.3), edit (D.1.4), share / trash / restore (D.1.5).
- **D.2** — Linux + Windows desktop maturation (CI matrix, distribution packaging, code signing).
- **D.3** — Tauri 2 mobile (iOS + Android) using the same Rust + TypeScript codebase. Replaces the original D.2 (SwiftUI) + D.3 (Compose) plan.

The original D.4 (browser autofill extensions) remains unchanged in scope — separate slice, post-D.3.

## Consequences

### Security wins

- **No localhost HTTP server.** NiceGUI ran uvicorn/FastAPI on `127.0.0.1:<port>` even in native mode; any other localhost process or browser extension could probe it. Tauri's IPC is in-process via custom URL scheme — that attack surface closes entirely.
- **Secrets stay in Rust address space.** NiceGUI marshalled secret material into a Python process; Python's allocator (small-object cache, string intern table) is opaque enough that some bytes may linger longer than the Rust `ZeroizeOnDrop` chain guarantees. Tauri keeps secrets in the same Rust address space they were generated in — `ZeroizeOnDrop` is deterministic.
- **Tighter Content Security Policy.** Tauri's WebView allows a strict CSP (`default-src 'self'; script-src 'self'; connect-src 'self' ipc: tauri:`) with no external load surfaces. NiceGUI's Quasar-based UI has runtime asset-loading patterns harder to lock down equivalently.

### Codebase-consolidation wins

- Three UI codebases (NiceGUI + SwiftUI + Compose) collapse to one (Tauri Rust + Svelte/TS), modulo platform-specific deployment shims.
- Feature work in D.1.2 / D.1.3 / etc. ships to all five platforms by default, not three times in three idioms.

### Costs

- **+30–50% upfront effort for D.1.1** vs the original NiceGUI plan. The PyO3 work in `ffi/secretary-ffi-py` is no longer the UI path; it stays as the scripting / automation consumer path. The work isn't lost but the UI walking-skeleton has to be built from scratch on the Tauri side.
- **Learning-curve cost.** Tauri requires Rust depth and a frontend framework (Svelte chosen — smallest concept-vocabulary cost). The 8+ months of Rust experience from Sub-projects A and C mitigate this; Svelte is the smallest learning surface among framework options.
- **Tauri 2 mobile is younger than uniffi-based native UI.** Desktop is rock-solid. Mobile will likely encounter rougher edges in D.3 — Apple Shortcuts integration and Android AutoFill Service may still benefit from the uniffi bindings as a fallback.
- **Frontend dependency hygiene becomes a project concern.** Tauri brings a Node/pnpm toolchain alongside the existing Rust + Python tooling. The repo's "lockfiles religiously" discipline (Cargo.lock, uv.lock) extends to `pnpm-lock.yaml`.

### What stays unchanged

- The Rust core (`secretary-core`) — design, format, security review path all unaffected.
- The Python FFI (`ffi/secretary-ffi-py`) — stays as the path for scripting / automation / Python consumers / Jupyter notebooks / CI integration tests. Not deprecated.
- The uniffi bindings (`ffi/secretary-ffi-uniffi`) — stay as the path for third-party Swift/Kotlin code consuming the vault format directly (Apple Shortcuts, Android AutoFill Service). Not deprecated.
- Sub-project C (sync orchestration). C.3 (mobile sync adapters) and C.4 (cross-device convergence) remain. C.3's per-OS file-watcher work via uniffi-Swift/Kotlin may end up scope-narrowed if Tauri 2's mobile plugins handle the case — that's a decision for whenever C.3 is picked up next, not for this ADR.

## Alternatives considered

### Stay with NiceGUI

Continue the original plan. Three UI codebases, Python iteration speed for desktop, established native UI idioms for mobile.

**Rejected** because the security tradeoffs (localhost HTTP + secrets-in-Python) and codebase-fragmentation costs (three frontends to maintain) outweigh the iteration-speed advantage. The walking-skeleton-stage iteration-speed gap closes by D.1.4 (when feature work dominates scaffolding).

### Hybrid — NiceGUI for D.1 desktop, Tauri later if needed

Ship D.1 with NiceGUI now (fastest path to a usable client), revisit Tauri after D.1 has been used in anger and friction points are concrete.

**Rejected** because it defers cost without reducing it. Migrating an established NiceGUI codebase to Tauri would be more expensive than starting on Tauri now — the surface area only grows. The "is NiceGUI's security profile acceptable for a long-lived secrets manager?" question doesn't get easier to answer by deferring it.

### All-Rust UI (Slint / iced / egui / Dioxus)

Same Rust-everywhere narrative as Tauri but without the WebView. ADR 0001 considered this and rejected it for v1 due to mixed Rust GUI maturity and a weaker web/mobile story.

**Still rejected** for the same reasons in 2026. Slint and iced are more mature than 18 months ago but neither has a clean iOS+Android story comparable to Tauri 2's mobile support. Dioxus has mobile via Dioxus Mobile but the ecosystem is smaller than Tauri's.

### Native everywhere with no shared UI

What ADR 0001 chose. Maximum native fidelity per platform, zero shared UI code.

**Rejected for this revision** because the maintenance cost of three frontends — when one Tauri codebase can serve all five platforms — does not justify the marginal native-fidelity gain for v1. Native polish can be added back per-platform via Tauri's native plugins or per-platform CSS overrides if specific UX needs emerge.

## Related

- `docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md` — the D.1.1 design spec that implements this ADR.
- ADR 0001 — Rust core with Python / Swift / Kotlin clients via FFI (superseded for the UI portion only).
