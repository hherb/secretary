# `browser/` — Secretary browser autofill (D.4)

Browser-autofill track for Secretary: a WebExtension that asks a small native
host whether anything is available for the current page, and (in later slices)
fills credentials after an explicit native confirmation. It runs **parallel** to
the other Secretary sub-projects.

> **Status: D.4.1 — native-messaging walking skeleton (shipped).** This is the
> transport shell only: one `query → available{count:0}` **no-op** round trip.
> **No crypto, no vault, no `secretary-core` dependency, no fill, no secrets.**
> It exists to prove the channel, the manifest binding, and the framing codec in
> isolation — exactly as D.1.1 proved the Tauri IPC shell before any feature
> work. Real candidate counts, the per-fill vault open, and credential injection
> arrive in D.4.2–D.4.4.

## Why native messaging (the architecture in one paragraph)

The extension is a **thin courier**: it never sees plaintext secrets and holds
no key material. It talks over the browser's **native-messaging** stdio channel
to a local host process — **there is no listening socket**, which is the
structural property the whole design hangs on (threat-model §6 invariant 3). The
host is the only component that touches the vault, and only behind the same
`open_with_device_secret` verify-before-decrypt path used everywhere else. See
[ADR 0010](../docs/adr/0010-browser-autofill-native-messaging.md) for the
decision and **§2 "Architecture & trust boundary"** of the
[D.4 design](../docs/superpowers/specs/2026-06-15-d4-browser-autofill-design.md)
for the trust boundary in full.

## Layout

```
browser/
  secretary-browser-host/   Rust native-messaging host (a workspace member)
    src/frame.rs            length-prefix framing codec (1 MiB cap, never panics)
    src/protocol.rs         serde query / available / error message types
    src/lib.rs              run(): the read→dispatch→write loop
    src/main.rs             wires run() to locked stdin/stdout
    tests/echo.rs           in-process query→available round-trip test (no browser)
  extension/                Chromium MV3 extension (Firefox shares it in D.4.6)
    manifest.json           MV3, nativeMessaging permission, scoped to a test page
    src/background.ts       service worker: connectNative → send query → log available
    src/content.ts          content script: collect {top_origin, frame_origin, https}
  host-manifest/            dev native-messaging manifest + macOS/Linux install notes
    com.secretary.browser_host.json
    README.md
```

The host is a **full workspace member** (not excluded like `core/fuzz`): it is
production code and holds the workspace lints — `#![forbid(unsafe_code)]` and
clippy `-D warnings`. In D.4.1 it has **no `secretary-core` dependency**; it is
pure transport. D.4.2 adds that dependency behind the per-fill vault open.

## The D.4.1 protocol subset

Two message types (the full set is in design §3):

```jsonc
// extension → host
{ "type": "query", "top_origin": "https://example.com",
  "frame_origin": "https://example.com", "https": true }

// host → extension
{ "type": "available", "request_id": "<uuid>", "count": 0 }
```

The host **always** answers `count: 0` in this slice — no matching exists yet
(that is D.4.3). Each reply mints a fresh `request_id` UUID so D.4.4's
`request_fill` correlation is already threaded through the channel. An
unrecognized `type` is answered with a typed `error` frame, never a panic.

**Framing** (`frame.rs`): each message is UTF-8 JSON prefixed by a **4-byte
length in native byte order**, capped at **1 MiB**. The codec never panics on
malformed input — a bad length, truncated frame, or non-JSON body is a typed
`FrameError`, mirroring the fuzz-harness "assert `Result`, not panic" contract
(CLAUDE.md). A clean EOF at a frame boundary is the host's normal shutdown.

## Dev run

### Host (Rust, CI-gated)

```bash
# from the repo root
cargo build --release -p secretary-browser-host        # → target/release/secretary-browser-host
cargo test  --release -p secretary-browser-host        # frame.rs unit tests + tests/echo.rs
cargo clippy --release -p secretary-browser-host --tests -- -D warnings
```

### Extension (TypeScript)

```bash
cd browser/extension
pnpm install
pnpm run typecheck      # tsc --noEmit
pnpm run lint           # eslint src
pnpm run build          # emits dist/background.js + dist/content.js
```

### Manual browser smoke (the round trip)

The end-to-end browser round trip is a **documented manual smoke** at this stage
(the same posture as the iOS on-device proof in CLAUDE.md; an automated
browser-driver e2e is a later, optional add). Build the host, load the unpacked
extension, install the host manifest with the extension's ID, then visit
`https://example.com/` and watch the service-worker console log
`available{count:0}`. Full step-by-step instructions, the per-OS
NativeMessagingHosts install locations, and a troubleshooting table are in
[`host-manifest/README.md`](host-manifest/README.md).

## What's deferred (later slices)

| Slice | Adds |
|---|---|
| D.4.2 | `secretary-core` dep; casual-vault per-fill `open_with_device_secret`; device-slot enrollment; real candidate count |
| D.4.3 | Real origin matching (PSL, bindings, iframe rules) |
| D.4.4 | Click-to-fill, native confirmation dialog, credential injection |
| D.4.5 | `origin_binding` record metadata + tiering guard-rails |
| D.4.6 | Firefox + Safari + Windows registry + signing/packaging |
| D.4.7 | Write/capture path |

## Pointers

- [ADR 0010](../docs/adr/0010-browser-autofill-native-messaging.md) — the decision.
- [D.4 design](../docs/superpowers/specs/2026-06-15-d4-browser-autofill-design.md) — §2 boundary, §3 protocol, §9 slicing, §10 resolved decisions.
- [D.4.1 plan](../docs/superpowers/specs/2026-06-16-d41-native-messaging-skeleton-plan.md) — this slice's task breakdown + DoD.
- [threat-model §6](../docs/threat-model.md) — the browser-extension adversary model + structural invariants.
