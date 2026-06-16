# D.4.1 — Native-messaging walking skeleton (implementation plan)

**Date:** 2026-06-16
**Status:** Plan (pending implementation)
**Sub-project:** D.4 (browser autofill), first slice
**Design:** [2026-06-15-d4-browser-autofill-design.md](2026-06-15-d4-browser-autofill-design.md)
**Scope:** the transport skeleton **only** — a browser extension and a native-messaging host
that complete one `query → available` round trip as a **no-op** ("no match"). **No crypto, no
vault, no `secretary-core` dependency, no fill.** This slice exists to prove the channel, the
manifest binding, and the framing codec in isolation, exactly as D.1.1 proved the Tauri IPC
shell before any feature work.

## 1. What this slice ships

- A **native-messaging host** binary that reads length-prefixed JSON frames from stdin, and for
  a `query` message replies with `available { count: 0 }` on stdout. Nothing else.
- A **Chromium (Manifest V3) extension** that, on a page, calls `runtime.connectNative`, sends a
  `query` carrying the page's origins, and logs the `available` reply.
- A dev-time **host manifest** + install notes registering the host for the extension ID on
  macOS/Linux.
- Host **unit + integration tests** that exercise the framing codec and the `query→available`
  handler over an in-process pipe — **no browser required in CI**.

### Explicit non-goals (later slices)

| Deferred | Slice |
|---|---|
| Opening any vault / device-slot enrollment | D.4.2 |
| Real origin matching (PSL, bindings, iframe rules) | D.4.3 |
| Click-to-fill, native confirmation dialog, credential injection | D.4.4 |
| `origin_binding` record metadata, guard-rails | D.4.5 |
| Firefox + Safari + signing/packaging | D.4.6 |
| Any write/capture path | D.4.7 |

This slice deliberately carries **no secret material**, so the §6 invariants it can prove are
the *structural* ones (no socket, manifest-bound IDs, no-panic framing), not the crypto ones.

## 2. Layout

A new top-level `browser/` home (sibling of `desktop/`, `ios/`, `android/`):

```
browser/
  extension/                     WebExtension (Chromium first; Firefox shares it in D.4.6)
    manifest.json                MV3: nativeMessaging permission, no host_permissions beyond test page
    src/background.ts            service worker: connectNative, send query, log available
    src/content.ts               content script: collect {top_origin, frame_origin, https}, post to bg
    package.json / tsconfig      reuse desktop/ pnpm toolchain conventions
  secretary-browser-host/        native-messaging host — a Rust crate, NEW workspace member
    Cargo.toml                   no secretary-core dep yet (added in D.4.2)
    src/main.rs                  stdin/stdout framed read→handle→write loop
    src/frame.rs                 length-prefix codec (encode/decode), the testable core
    src/protocol.rs              serde message types for the D.4.1 subset
    tests/echo.rs                pipe a query frame in, assert an available frame out
  host-manifest/                 dev manifest + per-OS install notes
    com.secretary.browser_host.json
    README.md
```

The host is a **workspace member** (not excluded like `core/fuzz`): it is production code and
must hold the workspace lints — `#![forbid(unsafe_code)]`, clippy `-D warnings`. It depends on
`secretary-core` only from D.4.2 onward; in D.4.1 it is pure transport.

## 3. Native-messaging mechanics

Native messaging is the browser spawning the host as a subprocess and exchanging messages over
the host's stdin/stdout. **There is no socket** — that is the property this slice locks in.

**Framing** (`frame.rs`): each message is UTF-8 JSON prefixed by a **4-byte length in the
host's native byte order**. Per the platform contract, a host→extension message is capped at
1 MiB; we additionally cap extension→host at **1 MiB** and reject anything larger as a typed
error rather than allocating. The codec:

- `decode`: read 4 length bytes → validate `len ≤ 1 MiB` (else `FrameError::TooLarge`) → read
  exactly `len` bytes → `serde_json` parse. EOF on the length read = clean shutdown.
- `encode`: `serde_json` to bytes → write 4-byte native-endian length → write body.
- **Never panics** on malformed input — returns `Result`, mirroring the fuzz-harness
  "assert `Result`, not panic" contract (CLAUDE.md). A short read, a bad length, or non-JSON
  body is a typed error, not a crash.

**The loop** (`main.rs`): read frame → dispatch → write frame, until stdin EOF. Single-threaded,
synchronous; no global state.

## 4. Walking-skeleton protocol subset

Only two message types in D.4.1 (the full set is in the design §3):

```jsonc
// extension → host
{ "type": "query", "top_origin": "https://example.com",
  "frame_origin": "https://example.com", "https": true }

// host → extension
{ "type": "available", "request_id": "<uuid>", "count": 0 }
```

The host **always** replies `count: 0` in this slice (no matching exists yet). `request_id` is a
fresh UUID the host generates per query, so the D.4.4 `request_fill` correlation is already
threaded. Unknown `type` values are answered with a typed `error` frame, never a panic.

## 5. Host manifest

`com.secretary.browser_host.json` (dev form):

```jsonc
{
  "name": "com.secretary.browser_host",
  "description": "Secretary native-messaging host (D.4.1 skeleton)",
  "path": "/abs/path/to/secretary-browser-host",      // built binary, abs path
  "type": "stdio",
  "allowed_origins": ["chrome-extension://<EXTENSION_ID>/"]  // binds host ↔ extension ID
}
```

`allowed_origins` is the **manifest binding**: only the named extension may launch this host.
Install location is per-OS (dev notes in `host-manifest/README.md`): the user-scoped
NativeMessagingHosts directory for the target Chromium channel on macOS/Linux. Windows registry
registration is a D.4.6 concern.

## 6. Task breakdown

| Task | Deliverable | Test gate |
|---|---|---|
| **1** | Scaffold `browser/secretary-browser-host` crate; add to workspace members; `frame.rs` length-prefix codec. | `frame.rs` unit tests: round-trip, oversize→`TooLarge`, truncated length→error, non-JSON body→error, EOF→clean. |
| **2** | `protocol.rs` serde types (`query`, `available`, `error`); `main.rs` read→dispatch→write loop; no-op handler returning `count:0` + fresh `request_id`. | `tests/echo.rs`: feed a `query` frame to a `Cursor`/pipe, assert an `available{count:0}` frame out; unknown-type→`error`. |
| **3** | Scaffold `browser/extension` MV3 (manifest, background SW, content script); `connectNative` → send `query` → log `available`. | `tsc` builds clean; lint clean under desktop/ conventions. |
| **4** | `host-manifest/` dev manifest + per-OS install README (macOS/Linux). | Manual: install manifest, load unpacked extension, visit a test page, observe the round trip in the extension console. |
| **5** | Wire host crate into `cargo test --release --workspace`; clippy `-D warnings`; confirm `#![forbid(unsafe_code)]` holds. | `cargo test --release --workspace` green incl. new crate; `cargo clippy --release --workspace --tests -- -D warnings` clean. |
| **6** | `browser/README.md` (architecture pointer to design §2, dev-run steps) + a `2026-..-d41-shipped.md` handoff. | Docs reviewed; handoff lists what D.4.2 picks up. |

Tasks 1–2 are the load-bearing slice (the host codec + loop); 3–4 are the browser scaffold; 5–6
are integration + handoff. Tasks 1, 2, 5 are fully CI-gated in Rust; tasks 3–4 carry a
**documented manual smoke** (the browser e2e is manual at this stage, the same posture as the
iOS on-device proof in CLAUDE.md — automated browser-driver e2e is a later, optional add).

## 7. Testing strategy

- **Host codec (L1, CI).** `frame.rs` unit tests cover encode/decode round-trip and every
  malformed-input branch (oversize, truncated, non-JSON, EOF). The no-panic contract is
  asserted, not assumed.
- **Host handler (L2, CI).** `tests/echo.rs` drives the loop over an in-memory pipe: a `query`
  frame in → an `available{count:0}` frame out; an unknown type → an `error` frame; a truncated
  stream → clean shutdown. No browser, no network.
- **Browser round trip (L3, manual).** Load-unpacked extension + installed manifest; a test page
  triggers a `query` and the console shows the `available` reply. Documented in
  `host-manifest/README.md`; promoted to an automated driver test only if a later slice needs it.

## 8. Definition of Done

The slice is done when, with **no crypto and no secrets in play**, these hold:

1. `cargo test --release --workspace` (incl. the new host crate) and
   `cargo clippy --release --workspace --tests -- -D warnings` are green.
2. The host completes a `query → available{count:0}` round trip both in `tests/echo.rs` and in a
   manual browser load-unpacked smoke.
3. **No listening socket exists** — the host communicates only over the browser-provided stdio
   (structural §6 invariant 3).
4. The manifest's `allowed_origins` binds the host to the extension ID (§6 invariant 3).
5. The framing codec **never panics** on malformed input and caps message size at 1 MiB
   (DoS bound; fuzz-discipline parity).
6. The host holds **no key material and opens no vault** (§6 invariant 1) — trivially true here
   because it has no `secretary-core` dependency yet, which D.4.2 will add behind the same
   verify-before-decrypt open path.
7. `#![forbid(unsafe_code)]` holds in the new crate.

## 9. What D.4.2 picks up

The handoff (task 6) hands D.4.2 a working channel to attach crypto to: add the `secretary-core`
dependency, the casual-vault `open_with_device_secret` per-fill open, native-app device-slot
enrollment, and replace the `count: 0` no-op with a real candidate count (still no secrets
crossing — that waits for D.4.4's native-confirmation gate).

## 10. Related

- D.4 design — [2026-06-15-d4-browser-autofill-design.md](2026-06-15-d4-browser-autofill-design.md) (this plan implements §3 transport + §2 boundary).
- ADR 0010 — browser autofill via native messaging.
- D.1.1 — Tauri walking-skeleton spec (the precedent for "prove the shell before features").
- `threat-model.md §6` — the structural invariants (3) this slice locks in.
