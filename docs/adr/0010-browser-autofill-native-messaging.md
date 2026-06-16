# ADR 0010 — Browser autofill via native messaging, scoped to a casual vault

**Status:** Proposed (2026-06-15)
**Supersedes:** none
**Superseded by:** none

Refines the **D.4** slice reserved in ADR 0007 ("The original D.4 (browser autofill
extensions) remains unchanged in scope — separate slice, post-D.3"). This ADR fixes the
security architecture of that slice before any code is written; the on-disk format and the
core crypto are untouched.

## Context

Sub-project D.4 lets the user fill saved credentials into web pages from a browser
extension. Autofill is valuable but it deliberately moves a subset of secrets into the
browser — a far larger and more hostile trusted computing base than the native Tauri app
(ADR 0007) or the native mobile apps (ADR 0008). The browser carries a constant stream of
renderer RCEs, a JIT, a coarse extension-permission model with auto-updating supply chain,
and the page content itself is adversarial (`threat-model.md §6`).

Users are not a monolith. Three postures must all be served by one design:

- **Convenience-first** — wants frictionless fill everywhere.
- **Paranoid** — would rather autofill never touched a browser at all.
- **Grayscale (the canonical case)** — "I don't care if a hobby-mailing-list password leaks,
  but my email is an auth backchannel for password resets across dozens of sites and must
  *never* be reachable from a browser extension."

The grayscale user is the design driver. The requirement is not merely "let the user choose
what to expose" but "make it *cryptographically impossible* for the extension to reach the
high-value secrets, regardless of how thoroughly the browser or the extension is
compromised." A UI toggle is not sufficient; the wall must be the absence of key material.

The vault concept already supports more than one vault, and ADR 0009 already gives us a
third, additive unlock path — the per-device wrap slot (`devices/<uuid>.wrap`,
`file_kind 0x0004`) that releases the Identity Block Key under a `device_kek` derived from a
device secret held in the OS keystore. Those two facts make the wall expressible in the
existing model rather than as a new mechanism.

## Decision

### 1. Two-tier (N-tier) vaults; the wall is cryptographic

A user runs at least two vaults: a **high-value** vault and a **casual** vault. The casual
vault is enrolled with a browser **device slot** (ADR 0009); the high-value vault is
**never** enrolled with one. The browser helper therefore holds no key material capable of
opening the high-value vault — the separation is the *absence of a wrap file*, not a flag
that code could be tricked into ignoring. Revoking the browser is `remove_device_slot` on
the casual vault and leaves the master password, the recovery mnemonic, and every other
device untouched.

### 2. Thin-courier extension; native messaging over stdio

The extension holds **no IBK, no master password, no vault, and no plaintext at rest**. It
sends `{top-frame origin, field descriptor}` to a native helper and renders the result; all
cryptography and all policy run in the helper. Transport is **native messaging** — the
browser spawns the helper as a subprocess and talks over stdin/stdout. There is **no
localhost socket**, preserving the closed-surface property ADR 0007 valued when it removed
NiceGUI's `127.0.0.1` server. The per-OS native-messaging manifest binds the extension ID
to the helper path on both ends.

### 3. Per-fill open via the device slot; no long-running daemon

On a fill request the helper opens the casual vault with `open_with_device_secret`, the
device secret released from the OS keystore (optionally behind a biometric gate), serves the
single requested credential, then re-locks. Because the device slot derives its KEK with
HKDF rather than Argon2id (ADR 0009), a per-fill open is cheap, so no unlocked vault and no
daemon needs to persist between fills. The open goes through the **same B.2 manifest
verify-before-decrypt** as every other path — the browser path is not a weaker open.

### 4. Click-to-fill only

There is **no autofill on page load**. A fill requires a genuine (`isTrusted`) user gesture;
scripted/synthetic events do not trigger a fill.

### 5. Confirmation in a native OS dialog

The click-to-fill confirmation is presented by the helper in **native UI, outside web
content** — not a page-injected overlay and not a web-rendered surface. It is therefore not
clickjackable by the page and not reachable by a co-resident extension. The dialog names the
de-confused destination origin (see §6) so the user authorizes a specific target.

### 6. Origin matching in the helper, per-credential binding

All origin matching runs in the helper, never in a content script. Each stored credential
carries an **`origin_binding`** field chosen by the user, with a user-settable default
(honoring the grayscale philosophy — the user picks per item according to that item's value):

- **`registrable_domain`** — match on eTLD+1 via the Public Suffix List. Fills across
  subdomains of the same site. The PSL is essential, not a string-suffix shortcut: it
  correctly makes `foo.github.io` its own registrable domain, defeating shared-suffix
  hosting confusion.
- **`exact_origin`** — match on scheme + host + port. Tighter; more "why won't it fill?"
  friction on multi-subdomain sites, which is the paranoid user's accepted trade.

Cross-cutting rules that hold under **both** bindings:

- **Top-frame origin governs.** Never fill into a cross-origin iframe. If the form's frame
  origin differs from the credential's origin, refuse — or require an explicit per-fill
  confirmation that names the iframe origin.
- **HTTPS required.** Refuse `http:`, `file:`, `data:`, `blob:`, `about:`, and
  extension-internal pages.
- **De-confused origin display** in the confirmation: render punycode/ASCII form and flag
  mixed-script IDN.
- The page never learns the credential list — only whether a fill occurred.

### 7. Tiering guard-rails

The casual vault warns when the user files a recovery-channel domain (email, SSO, or
financial) into it, and discourages reuse of a password across the tier boundary — a reused
password makes the cryptographic wall illusory.

## Consequences

- **High-value secrets are unreachable from the browser by construction.** Full compromise
  of the renderer *and* the extension *and* the helper yields, at worst, casual-vault items
  one fill at a time — never the IBK, the master password, or the high-value vault.
- **No new always-listening local surface.** Native-messaging stdio + per-fill open means no
  daemon and no socket; the ADR 0007 win is preserved.
- **Revocation is a folder op.** Lose a laptop or retire a browser → `remove_device_slot`.
- **The format stays frozen.** D.4 reuses ADR 0009's `file_kind 0x0004`; no new on-disk
  structure and no change to `identity.bundle.enc` or `golden_vault_001`.
- **Costs.** A native helper + native confirmation dialog must be built per desktop OS
  (macOS / Linux / Windows), and the extension must ship for each browser engine. `origin_binding`
  is new per-credential metadata to thread through the record model and the UI. The Public
  Suffix List becomes a maintained, versioned data dependency.
- **Residual, eyes-open.** Once a credential is filled it lives in page DOM; a compromised
  renderer or a malicious co-extension can read it. Tiering bounds this to casual items. The
  user, not the tool, classifies value — guard-rails mitigate but cannot remove
  misclassification risk.

## Alternatives considered

- **Extension-resident vault (keys in the browser).** Rejected: puts the IBK and bulk
  plaintext inside the browser TCB; a single renderer/extension compromise exposes a whole
  vault rather than one credential, and there is no cryptographic wall to a high-value tier.
- **Long-running app + local IPC for the helper.** A thin stdio shim forwarding to an
  always-running desktop app over a separate authenticated local IPC. Rejected: lower
  per-fill latency but reintroduces exactly the local listening surface ADR 0007 removed,
  for a latency win the cheap HKDF per-fill open already makes unnecessary.
- **Web-rendered / page-injected confirmation UI.** Rejected: lives in the browser TCB and
  is exposed to clickjacking and co-extension interference; the native dialog moves the trust
  decision out of web content.
- **Autofill on page load with heuristics.** Rejected: silent fill is the single most
  exploited password-manager surface (lookalike origins, injected forms). Click-to-fill with
  a genuine gesture removes the class.
- **Single vault with a per-item "browser-allowed" flag.** Rejected: a flag is enforced by
  code that a compromise could bypass; only the absence of a device wrap is a real wall.

## Related

- ADR 0009 — per-device wrap slot (the key-release foundation for the casual-vault device
  enrollment).
- ADR 0007 — Tauri universal client; reserves D.4 and establishes the "no localhost server"
  posture this ADR preserves. The native helper may reuse `secretary-core` directly or the
  uniffi bindings (ADR 0007 notes "Android AutoFill Service" as a uniffi consumer).
- ADR 0008 — native mobile via uniffi; mobile autofill (iOS AutoFill credential provider /
  Android AutoFill Service) is a sibling of this slice and should follow the same
  thin-courier + per-fill-open + tiering shape.
- ADR 0006 — mandatory recovery key (an unrelated wrap slot; named for completeness).
- `threat-model.md §6` — the browser-extension adversary model this ADR defends against.
