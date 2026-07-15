# ADR 0011 — macOS gets a native SwiftUI client; Tauri macOS coexists then cuts over

**Status:** Accepted (2026-07-15)
**Supersedes:** none (extends ADR 0007 / 0008)
**Superseded by:** none

## Context

ADR 0007 made desktop (macOS/Linux/Windows) a Tauri universal client; ADR 0008
reverted *mobile* to native SwiftUI/Compose via uniffi because Tauri had no
first-party hardware-backed key storage and its biometric plugin is a gate, not
a key binding. Modern Macs (Apple Silicon, T2 Intel) have a Secure Enclave and
Touch ID, so the moment enclave-backed, biometric-bound key release is a macOS
requirement, ADR 0008's reasoning transfers from mobile to Mac verbatim.

## Decision

macOS gets a **native SwiftUI client**, branched from the iOS app, consuming
`secretary-core` through a macOS slice of the uniffi XCFramework, using the
Secure Enclave + Touch ID for hardware-backed, biometric-bound key release.

It **coexists** with the shipped Tauri macOS build (which stays on the
password/recovery desktop tier) until the native app reaches feature parity plus
an on-device biometric proof, at which point macOS **cuts over** to native and
Tauri narrows to Linux + Windows.

## Consequences

- The iOS device-unlock work (`SecretaryDeviceUnlock`, the SE conformer) is
  reused on Mac; only the XCFramework arch, `SecretaryKit` platform, and a Mac
  SwiftUI shell are net-new.
- A native Mac UI diverges from the Tauri Linux/Windows UI; mitigated by the
  Rust core remaining the single source of truth.
- Secrets cross the uniffi boundary into Swift on Mac (as on mobile); the
  wrapping key stays hardware-protected in the enclave — which Tauri could not
  match. Accepted at the UI tier.

## Alternatives considered

- **Extend the Tauri app to the Mac App Store.** Rejected for the enclave
  requirement (same alpha-plugin/bespoke-shim problem as ADR 0008); remains the
  right choice for the desktop tier and macOS until cutover.
- **Mac Catalyst.** Not chosen: carries iOS UIKit idioms; a native SwiftUI macOS
  target reusing the shared packages is cleaner with the same enclave access.
