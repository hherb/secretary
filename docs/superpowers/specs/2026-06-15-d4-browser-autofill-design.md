# D.4 — Browser autofill (design)

**Date:** 2026-06-15
**Status:** Draft (brainstorm) — pending review of ADR 0010
**Sub-project:** D.4 (browser autofill extensions), reserved in ADR 0007, architected in ADR 0010
**Scope:** the browser extension + native helper + the security-critical origin-matching
engine + the `origin_binding` record metadata. Reuses `secretary-core` and the ADR 0009
device slot; **no on-disk format change** and no new core crypto.

## 1. Context & motivation

ADR 0010 froze the security architecture of browser autofill: a thin-courier extension over
native-messaging stdio, per-fill open of a *casual* vault via the ADR 0009 device slot (no
daemon), click-to-fill only, a native OS confirmation dialog, and helper-side origin matching
with a per-credential `origin_binding`. The high-value vault is never enrolled with a browser
device slot, so the separation is the **absence of key material**, not a UI toggle. The
adversary model is `threat-model.md §6`.

This spec turns that ADR into a buildable shape: the trust boundary, the extension↔helper
protocol, where `origin_binding` lives, the origin-matching rules (the security core), and a
walking-skeleton-first slicing.

The design driver remains the **grayscale user**: "I don't care if a hobby-mailing-list
password leaks, but my email is an auth backchannel and must never be reachable from a
browser." Everything below serves making that wall real and the casual path ergonomic.

## 2. Architecture & trust boundary

```
  ┌─ browser process (HOSTILE TCB, threat-model §6) ──────────────┐
  │  web page (adversary §6.1.1)                                  │
  │      ▲ inject single approved credential into DOM (residual)  │
  │  content script ──────────┐                                   │
  │  extension service worker │  thin courier: NO keys, NO vault, │
  │      ▲                     │  NO plaintext at rest             │
  └──────┼─────────────────────┼──────────────────────────────────┘
         │ native messaging (stdio; NO socket)
  ┌──────▼─────────────────────▼──────── native helper (trusted) ─┐
  │  origin-matching engine (PSL, §5)                             │
  │  per-fill open: open_with_device_secret (ADR 0009)           │
  │      → casual vault only; device secret from OS keystore      │
  │  NATIVE confirmation dialog (outside web content, §7)        │
  └───────────────────────────────────────────────────────────────┘
                  high-value vault: NO device slot → unreachable
```

The helper is the trust boundary. Everything browser-side is treated as the §6 hostile TCB:
the extension is a courier that learns *whether* a fill is available and, only after native
approval, receives *one* credential to inject. It never holds keys, never holds the vault,
and never sees the credential list.

## 3. Extension ↔ helper protocol

Transport is **native messaging**: the browser spawns the helper as a subprocess and exchanges
length-prefixed JSON over stdin/stdout. There is **no listening socket** (preserves the
ADR 0007 "no localhost server" posture). The per-OS native-messaging manifest binds the
extension ID to the helper executable path; only the named extension can launch the named
helper, and the helper speaks only over the browser-provided pipe.

Message flow for one fill (secrets minimized to a single credential, crossing only post-approval):

| # | Direction | Message | Carries |
|---|---|---|---|
| 1 | ext → helper | `query` | `{ top_origin, frame_origin, https }` — **no secrets** |
| 2 | helper → ext | `available` | `{ request_id, count }` — whether to show the affordance; **no secrets, no labels** |
| 3 | ext → helper | `request_fill` | `{ request_id }` — sent only from a genuine (`isTrusted`) user gesture |
| 4 | helper (local) | — | open casual vault, run §5 match, show **native** picker+confirm dialog naming the de-confused origin |
| 5 | helper → ext | `fill` | `{ request_id, fields:[{field_hint, value}] }` — **one** credential, only on approval |
| 6 | ext (content script) | — | inject into DOM, then drop/overwrite the message buffer |

Design points:

- **The native dialog (step 4) is the authoritative security gate, not the `isTrusted` check.**
  Even if a hostile page synthesizes a `request_fill`, nothing is released without the user
  approving in native UI. The `isTrusted` gating in step 3 only reduces prompt-spam; it is
  defense-in-depth UX, not the boundary. State this explicitly so no reviewer mistakes the
  gesture check for the control.
- **Disambiguation is native.** If `count > 1`, the picker (labels, username previews) lives in
  the native dialog, so usernames are not bulk-streamed into the browser. Only the chosen
  credential's fillable fields cross back in step 5.
- **One credential per approval.** The list never crosses; `query` returns only a count.
- **Residual, acknowledged (§6.3.1):** the injected credential lands in page DOM, where a
  compromised renderer or co-extension can read it. Tiering bounds this to casual items; it is
  the inherent cost of autofill, not a defect.

## 4. Per-fill open & device-slot enrollment

The helper holds no unlocked vault between fills. On `request_fill` it calls
`open_with_device_secret` (B.2) with the casual vault's device secret, released from the OS
keystore (optionally behind a biometric gate), serves the approved credential, then re-locks.
HKDF-derived `device_kek` (not Argon2id) makes per-fill opens cheap (ADR 0009), so no daemon
is needed. The open goes through the **same manifest verify-before-decrypt** as every other
path — the browser open is not a weaker open.

**Enrollment** ("let this browser fill from my casual vault") is a native-app action, not an
extension action: the desktop app (ADR 0007) mints a device slot on the *casual* vault
(`add_device_slot`), stores the device secret in the OS keystore scoped to the helper, and
records that this is the browser-helper device. **Revocation** is `remove_device_slot` on the
casual vault — master password, recovery mnemonic, and all other devices untouched. The
high-value vault is simply never offered for browser enrollment.

## 5. Origin-matching engine (security core)

All matching runs in the helper, never in a content script. This is the most exploited surface
in password managers, so it gets the project's KAT discipline: a pinned
`origin_match_kat.json` corpus of `(top_origin, frame_origin, stored_origin, binding) →
{fill | refuse}` vectors, replayed in Rust and (since the helper reuses `secretary-core` /
generic logic) ideally cross-checked clean-room, mirroring the §5-verification-trace pattern.

Per-credential `origin_binding` (stored per §6), user-chosen with a user-settable default:

- **`registrable_domain`** — match on eTLD+1 via the **Public Suffix List**. Fills across
  subdomains of one site. PSL is mandatory, not a string-suffix shortcut: it correctly makes
  `foo.github.io` its own registrable domain, defeating shared-suffix hosting confusion.
- **`exact_origin`** — match on scheme + host + port. Tighter; more "why won't it fill?"
  friction, which is the paranoid user's accepted trade.

Rules holding under **both** bindings (each a KAT vector):

1. **Top-frame origin governs.** Never fill into a cross-origin iframe. If `frame_origin ≠`
   the credential's origin under the active binding, **refuse** (or require an explicit per-fill
   confirmation that *names the iframe origin* — a separate, louder dialog).
2. **HTTPS required.** Refuse `http:`, `file:`, `data:`, `blob:`, `about:`, and
   extension-internal pages.
3. **De-confused origin display.** The dialog renders punycode/ASCII form and flags
   mixed-script IDN, so the user authorizes a target they can actually read.
4. **No credential-list leak.** The page learns only whether a fill occurred.

The PSL becomes a **versioned, security-critical data dependency** — pin it exactly with a
rationale comment and a deliberate-bump review, mirroring the `tempfile =3.27.0` discipline
(CLAUDE.md "Atomic-write contract"). A stale PSL silently changes match boundaries.

## 6. `origin_binding` record metadata (zero format change)

`origin_binding` is **non-secret policy**, so it must *not* go into `RecordFieldValue` (which is
secret-only: `Text(SecretString)`/`Bytes(SecretBytes)` per CLAUDE.md "zeroize discipline"). Its
home is the **record-level `unknown` map** under a reserved key (e.g. `d4_origin_binding`):

- **No on-disk format change** — the `unknown` map is the existing §6.3.2 forward-compat
  channel; `golden_vault_001` and every v1 vault stay byte-identical.
- **Syncs with the credential** — it travels in the record across devices.
- **Correct merge semantics for free** — unknown keys are LWW-merged by `py_merge_unknown_map`
  / `merge_record`, so a policy change is last-writer-wins, which is the right semantic for a
  per-item setting.

The credential's URL/origin itself is an ordinary login-record field (already present); the
engine reads that field plus the `d4_origin_binding` policy. The **global default** binding
(used when a record has no `d4_origin_binding`) is a D.4-layer setting; whether it lives in
`vault.toml` or in helper-local config is an open question (§10).

> Alternative considered: a first-class typed `origin_binding` field on `Record`. Rejected for
> v1 — it mutates the frozen record struct for a D.4-only concern the `unknown` map already
> carries safely. Revisit only if a v2 format opens for other reasons.

## 7. Click-to-fill & native confirmation

No autofill on page load. A fill requires a genuine user gesture in the extension (§3 step 3),
and the **native OS dialog** (§3 step 4) is the authoritative gate: it lives outside web
content, so it is not clickjackable by the page and not reachable by a co-resident extension.
The dialog names the de-confused destination origin (§5 rule 3) and, when `count > 1`, hosts the
picker. Per-desktop-OS native dialog implementations are required (macOS / Linux / Windows).

## 8. Tiering guard-rails

Advisory, in the native app / helper, not enforced by the core:

- **Recovery-channel warning** — warn when filing an email / SSO / financial domain into the
  *casual* vault (these are auth backchannels; §1).
- **Cross-tier reuse warning** — a password present in both vaults makes the cryptographic wall
  illusory for that secret; flag it. (`threat-model.md §6.3` limitations 2–3.)

## 9. Proposed slicing (walking-skeleton first)

| Slice | Deliverable | Crypto? |
|---|---|---|
| **D.4.0** | This design doc → approved; ADR 0010 accepted. | — |
| **D.4.1** | **Native-messaging walking skeleton.** One engine (Chromium MV3) + helper that round-trips `query`→`available` as a no-op ("no match"). Proves the stdio channel, manifest install, no socket. | none |
| **D.4.2** | **Per-fill open.** Helper opens the casual vault via `open_with_device_secret`; native-app enrollment mints the browser device slot; helper returns a *count* of candidate records (still no secrets cross). | reuses B.2 |
| **D.4.3** | **Origin-matching engine + KAT corpus.** PSL integration, `registrable_domain` / `exact_origin`, top-frame-governs, iframe refusal, HTTPS-only, IDN de-confusion. Pure, host-tested, pinned `origin_match_kat.json`. **The security-critical slice.** | none |
| **D.4.4** | **Click-to-fill + native confirmation dialog.** Genuine gesture → native picker+confirm → single credential injected. macOS first, then Linux/Windows. | none |
| **D.4.5** | **`origin_binding` metadata + guard-rails.** Read/write `d4_origin_binding` in the record `unknown` map; global-default setting; recovery-channel + reuse warnings. | none |
| **D.4.6** | **Browser & OS breadth.** Firefox (native messaging), Safari (App-Extension model — different, §11), extension signing/store submission, packaging. | none |

D.4.3 is the slice that earns the most review; D.4.1/D.4.2 are scaffolding; D.4.4 is per-OS UI.

## 10. Open questions

1. **Global-default `origin_binding` location** — `vault.toml` (syncs, but widens a frozen-ish
   cleartext file) vs helper-local config (per-install, doesn't sync). Leaning helper-local +
   per-record override, since the binding default is a user-posture choice, not vault data.
2. **Safari** — Safari Web Extensions do not use classic stdio native messaging; they ship
   inside a containing macOS/iOS app and message it. D.4.6 likely routes Safari through the
   native app directly rather than a separate helper. Confirm before committing the abstraction.
3. **TOTP autofill** — login records can carry a TOTP seed (`Bytes` field). Filling a *generated
   code* (not the seed) is in natural scope for D.4.4/D.4.5; decide whether v1 includes it.
4. **Mobile autofill** — iOS AutoFill credential provider / Android AutoFill Service are
   *siblings*, not part of D.4 (different OS frameworks, ADR 0008 native apps). Same
   thin-courier + per-fill-open + tiering shape; likely a separate sub-project. Flag, don't
   absorb.
5. **WebAuthn / passkeys** — the phishing-resistant long-term answer for "casual web login,"
   and the browser is its natural home. Explicitly out of D.4 v1 scope; noted so the autofill
   abstraction doesn't foreclose it.

## 11. Cross-platform notes

- **Chromium (MV3) + Firefox** — classic native messaging over stdio; the §3 protocol applies
  directly. Firefox uses the same model with a different manifest location.
- **Safari** — App-Extension model (see §10.2); different transport, same trust boundary and
  same origin-matching engine.
- **Mobile** — sibling sub-project (§10.4); reuses §5 and §6, different host integration.

## 12. Security invariants (D.4 Definition-of-Done checklist)

Each must be demonstrable before D.4 ships, and each maps to a `threat-model.md §6` row:

1. The extension holds no IBK, no master password, no vault, and no plaintext at rest.
2. The helper opens only the casual vault; the high-value vault has no browser device slot, so
   no key material capable of opening it ever exists browser-side.
3. No listening socket anywhere; transport is browser-spawned stdio with manifest-bound IDs.
4. No fill without a native-dialog approval; the `isTrusted` gesture check is not relied on as
   the boundary.
5. Origin matching runs only in the helper, passes the pinned `origin_match_kat.json`, never
   fills a cross-origin iframe, and is HTTPS-only.
6. Only one credential crosses per approval; the credential list never crosses.
7. The per-fill open uses the same manifest verify-before-decrypt as every other open path.
8. PSL is exact-pinned with a deliberate-bump review.

## 13. Related

- ADR 0010 — browser autofill via native messaging (the decision this spec implements).
- ADR 0009 — per-device wrap slot (the casual-vault enrollment foundation).
- ADR 0007 — Tauri universal client; reserves D.4, establishes the no-localhost-server posture.
- ADR 0008 — native mobile via uniffi (the mobile-autofill sibling's foundation).
- `threat-model.md §6` — browser-extension adversary model and defense matrix.
