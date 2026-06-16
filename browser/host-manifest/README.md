# Native-messaging host manifest — dev install (D.4.1)

This directory holds the **dev-time** native-messaging host manifest that binds
the Secretary host (`secretary-browser-host`) to the Chromium MV3 extension in
[`../extension/`](../extension/). It is the piece that makes
`chrome.runtime.connectNative("com.secretary.browser_host")` actually spawn our
host.

> **Scope:** macOS + Linux, Chromium/Chrome dev channels only. Windows registry
> registration and Firefox/Safari are **D.4.6**. Packaging/signing is later too.
> This is a manual developer smoke, the same posture as the iOS on-device proof
> (CLAUDE.md) — there is no automated browser-driver test in D.4.1.

## What the manifest binds

[`com.secretary.browser_host.json`](com.secretary.browser_host.json):

```jsonc
{
  "name": "com.secretary.browser_host",   // must equal the connectNative() name
  "description": "Secretary native-messaging host (D.4.1 skeleton)",
  "path": "/abs/path/to/target/release/secretary-browser-host", // built binary, ABSOLUTE
  "type": "stdio",                          // stdin/stdout framing — no socket
  "allowed_origins": ["chrome-extension://<EXTENSION_ID>/"]  // ONLY this extension may launch the host
}
```

Two fields are the security-relevant bindings:

- **`path`** must be an **absolute** path to the compiled host binary. The
  browser launches exactly this executable; a relative path is rejected.
- **`allowed_origins`** is the **manifest binding** (threat-model §6 invariant
  3): only the listed extension ID may start this host. Chromium ignores a
  `connectNative` from any other extension.

`"type": "stdio"` is the whole point of the slice — the host speaks only over
the browser-provided stdin/stdout. **There is no listening socket.**

## One-time setup

### 1. Build the host binary

From the repo root:

```bash
cargo build --release -p secretary-browser-host
# binary lands at: target/release/secretary-browser-host
```

### 2. Build + load the extension, and copy its ID

```bash
cd browser/extension
pnpm install
pnpm run build          # emits dist/background.js + dist/content.js
```

Then in Chrome/Chromium:

1. Go to `chrome://extensions`.
2. Enable **Developer mode** (top-right).
3. Click **Load unpacked** and select `browser/extension/` (the dir with
   `manifest.json`).
4. Copy the extension's **ID** (a 32-char string shown on its card).

### 3. Fill in and install the manifest

Edit a copy of `com.secretary.browser_host.json`, replacing:

- `path` → the absolute path printed by step 1 (e.g.
  `/Users/you/secretary/target/release/secretary-browser-host`).
- the `<EXTENSION_ID>` in `allowed_origins` → the ID from step 2, keeping the
  `chrome-extension://` prefix and trailing `/`.

Copy it into the per-OS **NativeMessagingHosts** directory for your browser. The
file name **must** be `com.secretary.browser_host.json` (it must match the
`name` field).

#### macOS

| Browser | Directory |
|---|---|
| Google Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |
| Chromium | `~/Library/Application Support/Chromium/NativeMessagingHosts/` |
| Microsoft Edge | `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/` |

```bash
DEST="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
mkdir -p "$DEST"
cp com.secretary.browser_host.json "$DEST/"
```

#### Linux

| Browser | Directory |
|---|---|
| Google Chrome | `~/.config/google-chrome/NativeMessagingHosts/` |
| Chromium | `~/.config/chromium/NativeMessagingHosts/` |
| Microsoft Edge | `~/.config/microsoft-edge/NativeMessagingHosts/` |

```bash
DEST="$HOME/.config/google-chrome/NativeMessagingHosts"
mkdir -p "$DEST"
cp com.secretary.browser_host.json "$DEST/"
```

> Use the **user-scoped** directory above (per-user install). The system-wide
> locations (`/Library/Google/...`, `/etc/opt/chrome/...`) work too but need
> elevated permissions and are unnecessary for a dev smoke.

## Manual smoke test (the D.4.1 round trip)

With the host built, the extension loaded, and the manifest installed:

1. Open a new tab and visit **`https://example.com/`** (the content script's
   matched test page).
2. Open the extension's service-worker console: `chrome://extensions` → the
   Secretary card → **service worker** ("Inspect views").
3. You should see the round trip logged:

   ```text
   [secretary] available reply: { type: "available", request_id: "…", count: 0 }
   ```

4. The page console (regular DevTools on `example.com`) shows the content-script
   side:

   ```text
   [secretary] host responded: { type: "available", request_id: "…", count: 0 }
   ```

`count: 0` is expected **until the browser is enrolled.** As of D.4.2 the host
opens the casual vault per fill and returns a real candidate count — but only if
a helper-local config points it at an enrolled casual vault. To see a non-zero
count in the smoke, first enroll with `secretary-browser-enroll` and set
`$SECRETARY_BROWSER_HOST_CONFIG` (see ["Enroll a casual vault" in
`browser/README.md`](../README.md#enroll-a-casual-vault-dev-only)). Without a
config the host stays at `count: 0` — the un-enrolled, no-affordance posture.
Real **origin matching** (count reflecting the page, not the whole vault) is
D.4.3.

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Specified native messaging host not found` | Manifest not in the right NativeMessagingHosts dir, or filename ≠ `com.secretary.browser_host.json`. |
| `Access to the specified native messaging host is forbidden` | `allowed_origins` extension ID doesn't match the loaded extension. |
| `Native host has exited` immediately | `path` is wrong/relative, or the binary isn't built (`cargo build --release -p secretary-browser-host`). |
| No log at all | Content script didn't run — confirm you're on `https://example.com/` and reload the tab after loading the extension. |

## What changes in later slices

- **D.4.2 (done)** replaced `count: 0` with a real candidate count from a
  per-fill `open_with_device_secret` open of the enrolled casual vault (still no
  secrets crossing).
- **D.4.3** makes the count reflect the page via real origin matching, and adds
  the real OS-keystore secret source + desktop enrollment UI (replacing the
  dev-only file secret + `secretary-browser-enroll`).
- **D.4.6** adds Windows registry registration, Firefox (`allowed_extensions`
  by add-on ID), Safari (App Extension), and a packaged installer so this manual
  copy step goes away.
