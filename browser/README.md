# `browser/` — Secretary browser autofill (D.4)

Browser-autofill track for Secretary: a WebExtension that asks a small native
host whether anything is available for the current page, and (in later slices)
fills credentials after an explicit native confirmation. It runs **parallel** to
the other Secretary sub-projects.

> **Status: D.4.2 — per-fill open (shipped).** On a `query`, the host now opens
> the **casual** vault per fill via the existing `open_with_device_secret`
> (B.2 / ADR 0009) verify-before-decrypt path and replies `available { count }`
> with the real candidate count. **Still no secrets cross the channel** — the
> reply is an integer. The host holds no key material between fills and opens
> only the casual vault. Real origin matching (PSL, bindings, iframe rules) is
> D.4.3; credential injection + the native confirmation dialog are D.4.4.
>
> D.4.1 (the underlying native-messaging walking skeleton — framing codec,
> `query → available` no-op, manifest binding, no socket) shipped first.

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
    src/config.rs           helper-local config (vault path, device_uuid, secret source)
    src/secret_source.rs    DeviceSecretSource port + DevFileSecretSource (dev only)
    src/vault.rs            per_fill_count(): open_with_device_secret → block count
    src/enroll.rs           enroll(): mint a device slot + write config/secret
    src/lib.rs              Context + run(): the read→dispatch→write loop
    src/main.rs             builds Context from config; wires run() to stdin/stdout
    src/bin/enroll.rs       secretary-browser-enroll: DEV-only enrollment CLI
    tests/echo.rs           in-process channel round-trip test (no browser)
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
clippy `-D warnings`. As of D.4.2 it depends on **`secretary-core`** and reuses
the **exact** B.2 / ADR 0009 `open_vault(Unlocker::DeviceSecret { .. })` path —
no crypto is reimplemented and the browser open is never a weaker open.

### Per-fill open (D.4.2)

On a `query`, the host:

1. Loads the helper-local config (`config.rs`) — vault path, device UUID, and
   where to fetch the secret. **No config = not enrolled** → it replies
   `count: 0` (no affordance), never an error.
2. Fetches the 32-byte device secret from the [`DeviceSecretSource`] port
   (`secret_source.rs`) as a zeroize-on-drop `SecretBytes`.
3. Opens the casual vault via `open_vault(Unlocker::DeviceSecret { .. })`
   (`vault.rs`) — the same manifest verify-before-decrypt as every other path —
   counts the live blocks, and drops the secret + identity (zeroizing).

The host holds **no key material between fills** and **no secrets cross the
channel** — only the integer count.

> #### ⚠️ Dev-only secret source
>
> D.4.2 ships **one** `DeviceSecretSource`: `DevFileSecretSource`, which reads
> the device secret from a **cleartext file**. It exists so the per-fill open is
> CI-testable without a platform keystore — **never use it in production.** Real
> OS-keystore adapters (macOS Keychain, Linux Secret Service), optionally
> biometric-gated, land behind the same port in a follow-up (the iOS B.3
> pure-core-port / real-adapter pattern).

## The protocol subset

Two message types (the full set is in design §3):

```jsonc
// extension → host
{ "type": "query", "top_origin": "https://example.com",
  "frame_origin": "https://example.com", "https": true }

// host → extension
{ "type": "available", "request_id": "<uuid>", "count": 2 }
```

`count` is the number of candidate records in the enrolled casual vault
(D.4.2); an un-enrolled host replies `count: 0`. Real **origin matching** (so
the count reflects the page, not the whole vault) is D.4.3. Each reply mints a
fresh `request_id` UUID so D.4.4's `request_fill` correlation is already
threaded through the channel. An unrecognized `type` is answered with a typed
`error` frame, never a panic.

**Framing** (`frame.rs`): each message is UTF-8 JSON prefixed by a **4-byte
length in native byte order**, capped at **1 MiB**. The codec never panics on
malformed input — a bad length, truncated frame, or non-JSON body is a typed
`FrameError`, mirroring the fuzz-harness "assert `Result`, not panic" contract
(CLAUDE.md). A clean EOF at a frame boundary is the host's normal shutdown.

## Dev run

### Host (Rust, CI-gated)

```bash
# from the repo root
cargo build --release -p secretary-browser-host        # → target/release/{secretary-browser-host,secretary-browser-enroll}
cargo test  --release -p secretary-browser-host        # codec + config + per-fill open + enroll
cargo clippy --release -p secretary-browser-host --tests --bins -- -D warnings
```

### Enroll a casual vault (DEV-only)

`secretary-browser-enroll` mints a browser-helper device slot on a casual vault
and writes the helper config + the dev secret file. It is a stand-in for the
design's native-app enrollment until the desktop UI lands — and it writes the
device secret to a **cleartext file** (see the dev-only warning above), so it is
for development only.

```bash
# password from an env var (or it prompts on stdin, echoing — dev tool)
SECRETARY_VAULT_PASSWORD='…' \
  target/release/secretary-browser-enroll \
    --vault /path/to/casual-vault \
    --config /path/to/browser-host.json \
    --secret /path/to/browser-host-secret.hex

# then point the host at that config (the host reads $SECRETARY_BROWSER_HOST_CONFIG,
# else dirs::config_dir()/secretary/browser-host.json):
export SECRETARY_BROWSER_HOST_CONFIG=/path/to/browser-host.json
```

With the config in place a `query` returns `available { count: N }` for the
vault's live records; without it (un-enrolled) it returns `count: 0`.

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
| D.4.3 | Real origin matching (PSL, bindings, iframe rules) — so the count reflects the page; + the real OS-keystore `DeviceSecretSource` adapters and the desktop enrollment UI |
| D.4.4 | Click-to-fill, native confirmation dialog, credential injection |
| D.4.5 | `origin_binding` record metadata + tiering guard-rails |
| D.4.6 | Firefox + Safari + Windows registry + signing/packaging |
| D.4.7 | Write/capture path |

## Pointers

- [ADR 0010](../docs/adr/0010-browser-autofill-native-messaging.md) — the decision.
- [D.4 design](../docs/superpowers/specs/2026-06-15-d4-browser-autofill-design.md) — §2 boundary, §3 protocol, §4 per-fill open, §9 slicing, §10 resolved decisions, §12 invariants.
- [D.4.1 plan](../docs/superpowers/specs/2026-06-16-d41-native-messaging-skeleton-plan.md) + [D.4.2 plan](../docs/superpowers/specs/2026-06-16-d42-per-fill-open-plan.md) — the slice task breakdowns + DoDs.
- [threat-model §6](../docs/threat-model.md) — the browser-extension adversary model + structural invariants.
