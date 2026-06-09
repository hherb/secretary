# ADR 0008 — Mobile reverts to native apps via uniffi; desktop stays Tauri

**Status:** Accepted (2026-06-09)
**Supersedes:** ADR 0007 (mobile portion only — the D.3 "Tauri 2 mobile" decision). ADR 0007's desktop decision (D.1 / D.2 — the Tauri universal client for macOS / Linux / Windows) **stands unchanged**. This ADR re-instates ADR 0001's native-mobile choice for iOS / Android.
**Superseded by:** none

## Context

ADR 0007 (May 2026) pivoted **all** of Sub-project D's UI — desktop *and* mobile — to a single Tauri 2 codebase, with D.3 slated as "Tauri 2 mobile (iOS + Android) using the same Rust + TypeScript codebase," explicitly replacing ADR 0001's native SwiftUI + Jetpack Compose plan. The desktop half of that pivot has since shipped and proven out (D.1.1 → D.1.15, 2026-05 → 2026-06).

Before any mobile (D.3) work began, the Tauri-2-mobile story was evaluated specifically against this project's threat model — a client-only secrets manager whose vaults must remain decryptable for decades, with hardware-backed key protection and biometric-bound key release as first-class requirements. That evaluation (2026-06) surfaced drawbacks serious enough to disqualify Tauri for the *mobile* UI:

- **No first-party hardware-backed key storage.** There is no official Tauri plugin for iOS Secure Enclave, Android StrongBox, or the Keychain/Keystore. The community options are single-maintainer, sub-10-star, v0.1/alpha crates — the opposite of the exact-pin, enforce-don't-assume posture this project applies to security-critical dependencies (e.g. `tempfile`). The official `tauri-plugin-stronghold` is software-encrypted, not hardware-backed.
- **Biometric plugin is a gate, not a key binding.** The official `tauri-plugin-biometric` returns a yes/no auth result; it does not bind a wrapping key to a Keystore/Enclave key. Correct biometric-bound key release loops back to the missing hardware-key plugins.
- **"All-Tauri" would still require native code on the most security-critical path.** To reach Secure Enclave / StrongBox / biometric-bound key release without trusting an alpha plugin, we would hand-write a Swift + Kotlin plugin shim — the *most* security-critical code in the app. So the "one codebase" benefit is largely lost on mobile precisely where it matters most, while still inheriting Tauri's mobile IPC attack surface (a mobile-relevant origin-confusion CVE was fixed in Tauri 2.11.1) and immature mobile e2e tooling.

Desktop has none of these problems: `dirs::data_dir()` + OS file permissions are an appropriate at-rest story for a desktop client, there is no hardware-enclave requirement at the desktop tier, and the desktop Tauri client is already shipped and stable. So the reversal is scoped to mobile only.

The Rust core (`secretary-core`) and the existing `ffi/secretary-ffi-uniffi` bindings — built and conformance-tested across Sub-projects A and B — make a native-mobile path immediately viable: native apps consume the same audited core through uniffi, with direct access to the platform security frameworks.

## Decision

**Mobile (iOS + Android) is built as native apps consuming `secretary-core` via uniffi:**

- **iOS** — Swift + SwiftUI, consuming `ffi/secretary-ffi-uniffi` as a `.framework`/XCFramework. Direct use of Keychain + Secure Enclave + LocalAuthentication (Face ID / Touch ID) for hardware-backed, biometric-bound key release.
- **Android** — Kotlin + Jetpack Compose, consuming `ffi/secretary-ffi-uniffi` as an `.aar`. Direct use of Android Keystore / StrongBox + BiometricPrompt.

**Desktop (macOS / Linux / Windows) remains the Tauri universal client** exactly as ADR 0007 decided and D.1.x implemented. No desktop change.

**The uniffi (and pyo3) bindings are promoted back to first-class consumer paths:**

- `ffi/secretary-ffi-uniffi` is the **mobile UI path** (not merely a third-party-consumer path as ADR 0007 framed it).
- `ffi/secretary-ffi-py` remains the automation / scripting / CI path.

Sub-project D's mobile slicing reverts toward the ADR 0001 shape:

- **D.3 → native iOS (SwiftUI via uniffi).**
- **D.4 (or a sibling) → native Android (Compose via uniffi).**

(Renumbering is a roadmap detail, not part of this decision; the binding architecture is what this ADR fixes.)

## Consequences

### Security wins (the decisive ones)

- **Hardware-backed key protection, off the shelf.** Native iOS/Android reach mature, first-party Keychain / Secure Enclave / Keystore / StrongBox APIs directly — no dependency on alpha plugins or a bespoke shim we would have to own and audit.
- **Real biometric-bound key release.** LocalAuthentication / BiometricPrompt gate access to a Keystore/Enclave-held key, not a bypassable boolean.
- **Smaller mobile attack surface.** No WebView IPC bridge on mobile, so the class of origin-confusion / IPC bugs that has recurred in Tauri does not apply to the mobile clients.

### Binding-investment is re-justified

- The cross-language binding work — the `FfiVaultError`-threaded-through-every-binding discipline, the Swift/Kotlin conformance harnesses, and the #187 sync projection onto uniffi + pyo3 — is now **core mobile-UI infrastructure**, not optional third-party parity. The uniffi surface must stay at parity with the bridge; the existing conformance gauntlet enforces that.
- Secrets *do* cross the uniffi boundary into Swift/Kotlin (GC'd, non-zeroizable runtimes) on mobile — the same in-UI-runtime exposure a Tauri WebView would have had with JS. This is inherent to any non-Rust UI and is accepted at the UI tier; the key material that matters (the wrapping key) stays hardware-protected via the native enclave APIs, which the Tauri path could not match.

### Costs

- **Two mobile UI codebases (SwiftUI + Compose)** instead of one Tauri mobile target. But the security-critical key-management code on mobile has to be native and individually audited regardless (even all-Tauri needed a hand-written Swift + Kotlin shim for the hardware-key path) — so the marginal cost over "Tauri mobile + a native key shim" is the UI surface, not the security surface.
- **Desktop and mobile UIs diverge** (Tauri/Svelte vs SwiftUI/Compose). Mitigated by the Rust core remaining the single source of truth for all crypto, format, and sync semantics — UI codebases hold only presentation + platform-security glue.
- **uniffi tooling cost returns** (XCFramework / `.aar` packaging, App Store / Play Store native pipelines) — but this is well-trodden, mature ground, unlike Tauri-2-mobile.

### What stays unchanged

- The Rust core (`secretary-core`) — design, frozen format, security-review path.
- **Desktop** — the Tauri universal client (ADR 0007's desktop decision and all of D.1.x).
- `ffi/secretary-ffi-py` — automation / scripting consumer path.
- Sub-project C (sync orchestration). C.3 (mobile sync adapters) already exposes the C.1 state machine via uniffi — consistent with native mobile.

## Alternatives considered

### Keep Tauri 2 mobile (ADR 0007 as written)

One codebase across all five platforms.

**Rejected** because the mobile security foundation is unacceptable for this threat model: no first-party hardware-backed key storage, biometric-as-a-gate rather than a key binding, and a recurring mobile IPC attack surface — with the "one codebase" benefit largely cancelled by the native key shim mobile would need anyway.

### All-Tauri with a hand-written native key shim behind a Tauri plugin

Keep the Tauri mobile UI, but write a small Swift + Kotlin plugin for the hardware-key + biometric path.

**Rejected** because you still author and audit native Swift/Kotlin for the most security-critical code, while inheriting Tauri's mobile IPC surface and the immature mobile plugin/e2e ecosystem. If native security code is unavoidable on mobile, native UIs that reach the platform frameworks directly are the cleaner, more auditable boundary.

### Abandon Tauri entirely (desktop too) and go native everywhere

**Rejected** — desktop has none of the mobile drawbacks, the Tauri desktop client is already shipped and stable through D.1.15, and discarding it would forfeit a large amount of working, reviewed work for no security gain at the desktop tier.

## Related

- ADR 0007 — Sub-project D pivots to Tauri (superseded for the mobile/D.3 portion only; desktop retained).
- ADR 0001 — Rust core with native Swift / Kotlin clients via FFI (this ADR re-instates its mobile decision).
- `docs/superpowers/specs/2026-06-09-sync-ffi-projection-design.md` — #187, the sync projection onto uniffi + pyo3, now first-class mobile-UI infrastructure under this ADR.
