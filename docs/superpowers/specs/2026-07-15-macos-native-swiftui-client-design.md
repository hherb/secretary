# Design — Native SwiftUI macOS client (sub-project **D.5**)

**Date:** 2026-07-15
**Status:** Approved (design); implementation not started
**Related:** ADR 0007 (desktop = Tauri), ADR 0008 (mobile = native via uniffi), ADR 0009 (per-device wrap slot), #201/#202 (iOS device-unlock B.2/B.3)
**Scope of this document:** the macOS-client architecture + slice decomposition, with **D.5.1 (enclave walking skeleton)** detailed in full. D.5.1 is the sole target of the implementation plan that follows this spec. All later slices are named but deferred.

---

## 1. Context & decision

Secretary already ships a working macOS client: the **Tauri 2 desktop app** (`desktop/`, D.1.1→D.1.15), which runs on macOS via WKWebView and treats macOS as the same "desktop tier" as Linux/Windows — password/recovery unlock, `dirs::data_dir()` + OS file permissions at rest, no hardware enclave.

The question this design answers: **for a Mac App Store / installable Mac app that offers Touch ID / Secure Enclave unlock, do we extend the Tauri app or build a native SwiftUI app branched from iOS?**

Modern Macs (Apple Silicon, T2 Intel) have a Secure Enclave and Touch ID. The moment enclave-backed, biometric-bound key release is a requirement, the reasoning of **ADR 0008 transfers verbatim from mobile to Mac**: Tauri has no first-party hardware-backed key storage, and its biometric plugin is a yes/no gate rather than a key binding — so Tauri would need the same disqualified alpha-plugin-or-bespoke-shim path on the *most* security-critical code. Meanwhile the native path already exists: the iOS B.3 work (`SecretaryDeviceUnlock` + the Secure-Enclave conformer) implements exactly this and is host-tested.

**Decision:** macOS gets a **native SwiftUI client, branched from the iOS app**, consuming `secretary-core` through a **macOS slice of the uniffi XCFramework**, using the Secure Enclave + Touch ID for hardware-backed, biometric-bound key release. This extends the ADR 0007 → 0008 lineage: Mac is enough of a hardware-enclave tier to follow the *mobile* reasoning rather than the *desktop* reasoning.

**Coexistence:** the native SwiftUI Mac app **coexists** with the shipped Tauri macOS build (which stays on the password/recovery desktop tier) until the native app reaches feature parity plus an on-device biometric proof, at which point macOS **cuts over** to native and Tauri narrows to Linux + Windows. The coexistence-then-cutover posture is deliberate risk management; the cutover itself is a later gated slice, **not** part of D.5.1. This decision is recorded as **ADR 0011**, drafted as part of the D.5.1 implementation (see §9).

### Alternatives considered

- **Extend the Tauri app to the Mac App Store.** Rejected for the enclave requirement: Tauri cannot deliver Touch-ID-bound key release without the same alpha-plugin/bespoke-shim path ADR 0008 disqualified for mobile, and App Store sandboxing is less trodden for Tauri. It remains the correct choice for the *desktop tier* (Linux/Windows, and macOS until cutover).
- **Mac Catalyst (bring the iOS app to Mac).** Not chosen as the primary path: Catalyst carries iOS UIKit idioms and windowing constraints; a native SwiftUI macOS target reusing the shared packages gives a cleaner Mac app and the same enclave access. (Not re-evaluated in depth here; can be revisited if the SwiftUI-Mac shell proves costly.)

---

## 2. Scope & decomposition

The whole macOS app is too large for one spec, so D.5 is sliced the way D.1.x was, with a walking-skeleton-first ordering that mirrors iOS #202 (prove the risky hardware path on real devices before building breadth).

- **D.5.1 — enclave walking skeleton (THIS spec's implementation target).** A minimal SwiftUI Mac app that enrolls a device slot and, on relaunch, opens a **staged** vault via Touch ID / Secure Enclave on real Mac hardware, through the same B.2 `open_with_device_secret` path.
- **D.5.2+ — feature breadth (deferred).** Vault selection/create-vault wizard, browse, record-edit, block CRUD, share/trash/restore, settings, sync UI — paralleling the iOS `SecretaryApp/Sources/*` screens.
- **D.5.N — distribution hardening (deferred).** Covers **both** distribution modes: direct-install (Developer-ID-signed, hardened-runtime, notarized `.dmg`/`.pkg`) and Mac App Store (App Sandbox entitlements, security-scoped bookmarks for cloud-folder vault access, App Store pipeline). Direct-install is the lighter target; the App Sandbox is the stricter one and drives the bookmark/keychain-access-group work.
- **D.5.cutover — cutover gate (deferred).** Parity checklist + on-device biometric acceptance; retire the Tauri macOS build.

**Everything past D.5.1 is out of scope for the implementation plan** and listed here only to frame the coexistence.

---

## 3. Architecture & reuse map

The Rust core is untouched. This is additive UI + build-arch work only.

| Component | Current state | D.5.1 action |
|---|---|---|
| `secretary-core`, `secretary.udl`, `FfiVaultError` | frozen | **Untouched.** No FFI-surface change ⇒ the Swift/Kotlin conformance gauntlet is **not** in the blast radius. |
| `SecretaryDeviceUnlock` (coordinator, ports, `DeviceUnlockError`) | already `.macOS(.v13), .iOS(.v17)`; pure/FFI-free | Reuse as-is. |
| `SecretaryDeviceUnlockUI` (`DeviceUnlockViewModel`) | already macOS; host-tested (drove #202) | Reuse as-is. |
| `SecretaryVaultAccess` (bookmark/provisioning ports) | already `.macOS(.v13), .iOS(.v17)` | Reuse as-is. |
| `Secretary.xcframework` (built by `ios/scripts/build-xcframework.sh`) | iOS device + simulator arches only | **Add the `aarch64-apple-darwin` (Apple Silicon) macOS slice.** Intel (`x86_64-apple-darwin`) is deferred — see §8. |
| `SecretaryKit` + `SecretaryKit/DeviceUnlock/*` adapters | `.iOS(.v17)` only; links the XCFramework | **Generalize to `.macOS(.v13)`** — the core engineering of this slice. |
| `SecretaryApp` (XcodeGen project, iOS SwiftUI views) | iOS | New **macOS app target** with a minimal window (not the iOS views). |

Two of the three shared Swift packages are already macOS-declared and pure, so the reuse is real, not aspirational. The engineering concentrates in the XCFramework build and `SecretaryKit`.

---

## 4. The real work — generalizing `SecretaryKit` to macOS

`SecretaryKit` links the XCFramework binary target and holds the platform adapters. Generalizing it means adding `.macOS(.v13)` to its `platforms` and making each adapter compile and behave correctly on macOS, guarding platform-divergent behaviour behind `#if os(macOS)` / `#if os(iOS)` so the iOS build stays green.

Adapter-by-adapter:

- **`SecureEnclaveDeviceSecretStore`** — SE P-256 key via `kSecAttrTokenIDSecureEnclave` works on Apple Silicon / T2 Macs. Must add a **Secure-Enclave availability check with graceful fallback** to the password/recovery path on Macs without an enclave. (For D.5.1, a stub that treats SE as *required* and surfaces a typed "no enclave" error is acceptable; the full fallback UX is a later slice.)
- **`EnclaveBiometricAuthorizer`** — `LAContext` on macOS gates on Touch ID (plus Apple Watch / password fallback per policy). Review biometric-policy flags and `SecAccessControl` creation for macOS availability. The cancel/non-match funnel must map to the same typed cancel path as iOS (mirroring the iOS lesson that biometric eval cancel surfaces as `LAError.userCancel`, and no failure mislabels as `wrappedSecretCorrupt`).
- **`KeychainEnrollmentMetadataStore`** — the default (unsandboxed) keychain works for D.5.1. Keychain access-group / data-protection nuances under App Sandbox are a **later (D.5.N) concern**, not D.5.1.
- **uniffi ports (`UniffiVaultSession`, `UniffiVaultDeviceSlotPort`, open/create/sync/settings/trash ports)** — pure binding calls; they compile for macOS once the XCFramework carries a macOS slice. No signature changes.

**Bonus outcome:** once `SecretaryKit` is macOS-capable and the XCFramework has a macOS slice, `SecretaryKit` becomes **host-buildable via `swift build` / `swift test` on the macOS host** — no simulator destination required. This retires, for the Mac leg specifically, the "SecretaryKit can't `swift build` on host" constraint that holds for iOS, and gives a faster host-test loop.

---

## 5. D.5.1 end-to-end flow

The walking skeleton proves the hardware path end to end and nothing more.

1. **Stage a vault.** The app operates on a **temp copy** of a demo vault (`cp -R` of the tracked fixture to a working dir) — never the frozen `golden_vault_001` in place (settings/device-slot writes would mutate a KAT).
2. **Enroll a device slot.** `add_device_slot` creates a per-device `devices/<uuid>.wrap` (ADR 0009); the `device_secret` is wrapped by a Secure-Enclave-held key gated by a biometric `SecAccessControl`; enrollment metadata (device UUID) is written to the Keychain.
3. **Relaunch → biometric open.** On next launch, the app finds the enrolled slot, triggers `SecKeyCreateDecryptedData` (which prompts Touch ID), releases the `device_secret`, and calls **`open_with_device_secret`** — the same B.2 orchestrator arm that runs manifest verify-before-decrypt. The device path is **not** a weaker open.
4. **Observe success.** The window shows the vault opened (e.g. vault UUID + a record count) — enough to prove decryption succeeded via the enclave.

No App Sandbox, no security-scoped bookmarks, no browse/edit. Dev-signed, direct filesystem path.

---

## 6. Testing strategy

Add a `run-macos-tests.sh` mirroring `ios/scripts/run-ios-tests.sh`, layering fast→slow:

1. **Host, fast (pre-XCFramework):** `swift test` on `SecretaryDeviceUnlock` (+ `SecretaryDeviceUnlockUI`) and `SecretaryVaultAccess`. These are pure and already macOS-declared, so a logic regression fails here in seconds before any slow native build. This reuses the exact packages that host-test on iOS.
2. **Build the XCFramework incl. the macOS slice.** This build is multi-minute and silent — run it **backgrounded with log polling** (the known xcframework-build watchdog trap), not inline under a short timeout.
3. **`swift build` / `swift test` `SecretaryKit` on the macOS host.** Newly possible once macOS-capable; catches adapter compile/behaviour regressions without a simulator.
4. **Manual on-Mac Touch ID proof — the D.5.1 acceptance milestone.** Equivalent to the iOS #202 Face ID proof. Requires a real Mac with Touch ID; the developer machine has working Xcode + code signing.

**Conformance:** D.5.1 changes no FFI surface (no `.udl`, no `FfiVaultError` variant, no bridge signature), so the Swift/Kotlin conformance runners and the Rust KAT replay are unaffected. If any later slice touches the FFI surface, the full conformance gauntlet re-enters scope.

---

## 7. Acceptance criteria (D.5.1)

D.5.1 is done when **all** hold:

1. `build-xcframework.sh` produces a `Secretary.xcframework` containing a macOS slice, and the existing iOS device + simulator slices still build.
2. `SecretaryKit` declares `.macOS(.v13)` and builds for macOS; the iOS build remains green (verified via `run-ios-tests.sh`).
3. `SecretaryKit` host-builds via `swift test` on macOS.
4. `run-macos-tests.sh` exists and runs steps 1–3 green.
5. On a real Apple Silicon (M1+) Touch-ID Mac: enroll a device slot on a staged vault, relaunch, and open it via Touch ID through `open_with_device_secret`. Cancelling Touch ID surfaces the typed cancel path (no `wrappedSecretCorrupt` mislabel).
6. No change to `secretary-core`, the `.udl`, or `FfiVaultError`.
7. ADR 0011 is written (macOS-native decision + coexistence/cutover posture) and cross-links this spec.

---

## 8. Non-goals (D.5.1) & risks

**Hardware floor:** D.5.1 targets **Apple Silicon (M1 and later) only** — the `aarch64-apple-darwin` slice, matching the development machine. Intel Macs (the `x86_64-apple-darwin` slice) are **deferred**: the developer has several generations of Intel Macs for real-world testing in a later pass, but they are out of scope for the skeleton.

**Non-goals (deferred to later D.5 slices):**
- Intel Mac support (`x86_64-apple-darwin` slice) and its T2-vs-no-enclave testing.
- App Sandbox, security-scoped bookmarks, hardened runtime, notarization, Mac App Store submission.
- Browse / record-edit / block CRUD / share / trash / settings / sync UI / create-vault wizard.
- Full non-SE-Mac fallback UX (D.5.1 may stub SE as required).
- Retiring the Tauri macOS build (cutover gate).

**Risks:**
- **Secure-Enclave availability variance.** Apple Silicon / T2 have it; older Intel Macs do not. The fallback path exists (password/recovery) but its Mac UX is a later slice; D.5.1 must at least fail *typed* on non-SE hardware, not crash or mislabel.
- **Keeping iOS green while adding `#if os(macOS)` branches.** Every adapter change must be verified against `run-ios-tests.sh`, not just the macOS build.
- **App Sandbox rework later.** The bookmark/keychain-access-group/codesign work (including the `Resources/`-folder-breaks-codesign class of gotcha the iOS app hit — staged under `Fixtures/` there) lands in D.5.N, not now; D.5.1 stays dev-signed and unsandboxed to keep the skeleton thin.
- **XCFramework build cost.** Adding a macOS slice lengthens an already-slow build; the test scripts must background-and-poll it.

---

## 9. Deliverables summary

- `ios/scripts/build-xcframework.sh` — add macOS target(s) + package the macOS slice.
- `ios/SecretaryKit/Package.swift` — add `.macOS(.v13)`; adapters gain `#if os(macOS)` branches where needed.
- `SecretaryKit/DeviceUnlock/*` — macOS availability + SE-availability handling.
- New macOS app target (XcodeGen) with a minimal enclave-unlock window, reusing `DeviceUnlockViewModel`.
- `ios/scripts/run-macos-tests.sh` — layered host → XCFramework → SecretaryKit → manual-proof runner.
- ADR 0011 recording the macOS-native decision + coexistence/cutover posture.
