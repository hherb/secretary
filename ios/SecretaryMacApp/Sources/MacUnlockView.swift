import SwiftUI
import os
import SecretaryDeviceUnlock
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

private let macUnlockLog = Logger(subsystem: "com.secretary.macapp", category: "unlock")

/// Password + Touch ID unlock (macOS). Owns gate construction so `MacRootView`
/// receives a fully-opened `(session, gate)` regardless of which tier was used.
@MainActor
struct MacUnlockView: View {
    @StateObject private var viewModel: UnlockViewModel
    let vaultPath: Data
    let biometricEnrolled: Bool
    @Binding var biometricError: String?
    @Binding var rememberDevice: Bool
    let onOpened: (VaultSession, RetargetableReauthGate) -> Void

    @State private var password: String = ""
    @State private var lastPasswordSecret: [UInt8]?
    // Guards against a concurrent double-open across BOTH unlock tiers. Set
    // synchronously at the tap — before either the password Argon2id or the
    // biometric prompt begins — so a second tap on EITHER button is rejected
    // here rather than racing into a second open that would strand an orphan
    // VaultSession. `isBusy` (derived from `viewModel.state`) only turns true
    // AFTER the async password open starts, leaving a pre-busy gap this flag
    // closes; the biometric path never touches `viewModel.state` at all, so it
    // relies on this flag entirely.
    @State private var isOpening = false

    init(viewModel: UnlockViewModel, vaultPath: Data, biometricEnrolled: Bool,
         biometricError: Binding<String?>, rememberDevice: Binding<Bool>,
         onOpened: @escaping (VaultSession, RetargetableReauthGate) -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.vaultPath = vaultPath
        self.biometricEnrolled = biometricEnrolled
        _biometricError = biometricError
        _rememberDevice = rememberDevice
        self.onOpened = onOpened
    }

    private var isBusy: Bool { if case .busy = viewModel.state { return true } else { return false } }
    private var stateIsUnlocked: Bool { if case .unlocked = viewModel.state { return true } else { return false } }

    var body: some View {
        Form {
            if biometricEnrolled {
                Section("Touch ID") {
                    Button("Unlock with Touch ID") { biometricUnlock() }
                        .disabled(isBusy || isOpening)
                }
            }
            Section("Master password") {
                SecureField("Password", text: $password)
                // Only offered when not already enrolled (mirrors iOS): toggling
                // while enrolled would trigger a redundant re-enroll.
                if !biometricEnrolled {
                    Toggle("Remember this Mac with Touch ID", isOn: $rememberDevice)
                }
            }
            Section {
                Button("Unlock") { passwordUnlock() }
                    .disabled(isBusy || isOpening || password.isEmpty)
            }
            if case .failed(let err) = viewModel.state {
                Section("Error") { Text(String(describing: err)).foregroundStyle(.red) }
            }
            if let biometricError {
                Section("Couldn’t unlock") { Text(biometricError).foregroundStyle(.red) }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 460, minHeight: 320)
        .overlay { if isBusy { ProgressView() } }
        // Single-param overload (macOS 11+): the app's deploymentTarget is
        // macOS 13.0, below the macOS 14.0 floor for the two-param
        // `onChange(of:initial:_:)` used elsewhere on iOS 17+.
        .onChange(of: stateIsUnlocked) { unlocked in
            guard unlocked, case .unlocked(let session) = viewModel.state else { return }
            let password = lastPasswordSecret
            lastPasswordSecret = nil
            let gate = makeRetargetableReauthGate(session: session, vaultPath: vaultPath,
                                                  biometricUnlock: false)
            if rememberDevice, let password { enrollDevice(session: session, secret: password) }
            onOpened(session, gate)
        }
    }

    private func passwordUnlock() {
        guard !isOpening else { return }
        isOpening = true
        viewModel.mode = .password
        var secret = Array(password.utf8)
        lastPasswordSecret = secret
        Task {
            await viewModel.unlock(secret: secret)
            isOpening = false
            // On failure the secret is never handed off (no `onOpened` / enroll),
            // so drop + wipe our retained copy now instead of holding it until the
            // next attempt or teardown. Nil the `@State` reference FIRST so `secret`
            // becomes uniquely referenced, then `zeroize` overwrites the real
            // backing buffer — a still-shared `[UInt8]` would only COW-clear a
            // throwaway copy. Best-effort: the SwiftUI `password` String and any
            // bytes already copied across the FFI are out of reach (see `zeroize`).
            // On success the buffer is deliberately kept for enroll and released by
            // `onChange`.
            if case .failed = viewModel.state {
                lastPasswordSecret = nil
                zeroize(&secret)
            }
        }
    }

    private func biometricUnlock() {
        guard !isOpening else { return }
        biometricError = nil
        isOpening = true
        let coordinator = makePerVaultDeviceUnlock(vaultPath: vaultPath).coordinator
        Task {
            let result = await DeviceUnlockOpen.open(
                coordinator: coordinator, openPort: UniffiVaultOpenPort(),
                vaultPath: vaultPath, reason: "Unlock your Secretary vault")
            switch result {
            case .cancelled:
                isOpening = false                               // stay on unlock, quietly
            case .failed(let message):
                isOpening = false
                biometricError = message
            case .opened(let session, let gate):
                isOpening = false
                onOpened(session, gate)
            }
        }
    }

    /// Best-effort device-slot enrollment on password unlock (mirrors iOS): a second
    /// Argon2id open, hopped onto a background queue so the route transition is never
    /// blocked. Non-fatal — the password open already succeeded.
    ///
    /// This writes an additive `devices/<uuid>.wrap` slot (ADR 0009) — the one
    /// intentional vault write in the otherwise read-only D.5.2 slice. It adds an
    /// unlock credential only; it never touches vault content (blocks / records /
    /// manifest), so the "read-only browse" invariant is unaffected.
    private func enrollDevice(session: VaultSession, secret: [UInt8]) {
        let coordinator = makePerVaultDeviceUnlock(vaultPath: vaultPath).coordinator
        let vaultPath = self.vaultPath
        let vaultId = session.vaultUuidHex
        Task {
            do {
                try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                    DispatchQueue.global(qos: .userInitiated).async {
                        var secret = secret
                        // Best-effort wipe of our copy once enroll has consumed it
                        // (#453). Genuine best-effort, NOT a guarantee: this `var`
                        // shadow (needed so `zeroize` has an `inout`) COW-shares the
                        // captured buffer, so while any other reference is live
                        // `zeroize` COW-copies and clears only a throwaway — it bites
                        // the real bytes only in the window where this task uniquely
                        // owns them (see `testZeroizeOnlyClearsAUniquelyOwnedBuffer`).
                        // The SwiftUI `password` String and the FFI-crossing bytes
                        // (zeroized Rust-side) are out of reach regardless — Swift
                        // value semantics preclude a full wipe. Local `var` inside
                        // this `@Sendable` closure — no mutable capture across domains.
                        defer { zeroize(&secret) }
                        do { try coordinator.enroll(vaultPath: vaultPath, vaultId: vaultId, password: secret); c.resume() }
                        catch { c.resume(throwing: error) }
                    }
                }
            } catch {
                macUnlockLog.error("device enroll failed: \(error.localizedDescription, privacy: .public)")
                await MainActor.run { biometricError = "Couldn’t enable Touch ID unlock. You can try again later." }
            }
        }
    }
}
