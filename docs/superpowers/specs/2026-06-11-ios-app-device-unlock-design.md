# iOS app walking-skeleton + on-device #202 biometric proof

**Date:** 2026-06-11
**Issue:** #202 (closes — on-device biometric proof) + establishes the D-phase iOS app shell
**Depends on:** B.3 (Secure-Enclave device unlock, #214 — the real conformer + coordinator), B.2 (device-slot FFI), D.3 slice 1 (iOS XCFramework)
**ADRs:** 0008 (native mobile via uniffi), 0009 (per-device wrap slot)

## 1. Purpose & scope

B.3 (#214) shipped the device-unlock protocol layer plus a **real but device-unverified**
Secure-Enclave conformer (`SecureEnclaveDeviceSecretStore`). This slice does two things at
once:

1. **Build the first runnable iOS app** — a minimal SwiftUI "walking skeleton" that drives
   the real device-unlock flow (enroll / unlock / disenroll / status). This is the app-shell
   foundation the rest of Sub-project D needs.
2. **Close #202** — deploy that app to a **physical iPhone 13 Pro Max** and prove the real
   Secure Enclave + real Face ID release the `device_secret` and open the vault, and that the
   failure modes (cancel / no-match / lockout) surface as the typed `DeviceUnlockError` cases.
   The proof records the **real** Security-framework error `domain`+`code` for each failure,
   so the `mapDecryptError` mapping (hardened in #214 `751d542`) is *verified against device
   evidence* rather than assumed.

### Scoped IN (this slice)

- A new Xcode **app target** (`Secretary`) managed declaratively via **XcodeGen** (`project.yml`
  checked in; the generated `.xcodeproj` is gitignored). Depends on the two existing SPM
  packages.
- A pure, **host-testable** `DeviceUnlockViewModel` (a new `SecretaryDeviceUnlockUI` product in
  the existing `SecretaryDeviceUnlock` package), TDD-covered with the in-memory fakes already
  shipped in `SecretaryDeviceUnlockTesting`.
- A thin SwiftUI screen bound to the ViewModel; the **real** coordinator (real SE store + real
  uniffi port + real Keychain metadata) constructed at the `@main` entry point.
- First-launch staging of a **writable copy** of `golden_vault_001` into the app sandbox (the
  tracked fixture is never mutated).
- A small enhancement to `SecureEnclaveDeviceSecretStore` so its error payloads carry the raw
  `domain`+`code` (the #202 taxonomy-capture deliverable).
- `scripts/build-app.sh` (XcodeGen generate + simulator build — a CI-able compile proof) and a
  `run-ios-tests.sh` extension that also builds the app.
- A documented on-device manual proof script + the captured taxonomy, recorded in the handoff.

### Scoped OUT (deferred — YAGNI / later D-phase)

- Any password-unlock / recovery-unlock UI, vault creation/import UI, record browsing, or sync
  surface. The skeleton is **device-unlock-only**; the password is used solely at enroll time.
- Multi-vault enrollment registry (single vault-keyed enrollment, inherited from B.3 §4).
- A UI test target / automated biometric driving (no `simctl` biometric CLI exists; the proof
  is manual on-device).
- App Store / TestFlight packaging, app icon/launch-screen polish, localization.
- Any change to the frozen on-disk format, the B.2 FFI surface, or any Rust code.

## 2. Background: what this consumes

From B.3 (#214), unchanged:

- `DeviceUnlockCoordinator` (in the FFI-free `SecretaryDeviceUnlock` package) — `enroll`,
  `unlock`, `disenroll`, `isEnrolled`, over three injected ports.
- Real adapters in `SecretaryKit/DeviceUnlock/`: `UniffiVaultDeviceSlotPort`,
  `SecureEnclaveDeviceSecretStore` (non-exportable SE P-256 + `SecAccessControl([.privateKeyUsage,
  .biometryCurrentSet])` + ECIES), `KeychainEnrollmentMetadataStore`.
- In-memory fakes in `SecretaryDeviceUnlockTesting` (`FakeVaultDeviceSlotPort`,
  `InMemoryDeviceSecretEnclave`, `InMemoryEnrollmentMetadataStore`) — reused by the ViewModel
  host tests.

The coordinator's `unlock` funnels through the same B.2 `open_with_device_secret` (hence the
same manifest verify-before-decrypt, Ed25519 ∧ ML-DSA-65) — this slice adds **no** new open path.

## 3. Architecture

**Pattern: pure ViewModel + thin SwiftUI shell + real wiring at the entry point.**

```
ios/SecretaryApp/
  project.yml                         # XcodeGen manifest — app target "Secretary"
  .gitignore                          # ignores the generated Secretary.xcodeproj
  Sources/
    SecretaryApp.swift                # @main App — stages the vault copy, builds the REAL coordinator + VM
    DeviceUnlockScreen.swift          # thin SwiftUI View bound to the ViewModel
    AppVaultProvisioning.swift        # pure-ish helper: stage golden_vault_001 → writable sandbox dir
  Resources/
    golden_vault_001/                 # bundled read-only fixture copy (staged by build-app.sh, like build-xcframework.sh)
    golden_vault_001_inputs.json      # pinned vault_uuid for the on-screen assertion

ios/SecretaryDeviceUnlock/            # EXISTING pure package — add a UI product:
  Sources/SecretaryDeviceUnlockUI/
    DeviceUnlockViewModel.swift       # @MainActor ObservableObject state machine over the coordinator
    DeviceUnlockState.swift           # the pure state enum (one concept per file)
  Tests/SecretaryDeviceUnlockUITests/
    DeviceUnlockViewModelTests.swift  # host swift test — drives the VM with the in-memory fakes

ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/
  SecureEnclaveDeviceSecretStore.swift   # ENHANCE: error payloads carry raw domain+code (taxonomy capture)

ios/scripts/
  build-app.sh                        # xcodegen generate + xcodebuild build -sdk iphonesimulator (CI compile proof)
  run-ios-tests.sh                    # EXTEND: also run build-app.sh
```

### 3.1 The testable core — `DeviceUnlockViewModel`

A `@MainActor` `ObservableObject` (host-testable: `ObservableObject`/Combine and the async
coordinator all run on the macOS host). It owns the injected `DeviceUnlockCoordinator`, the
`vaultPath: Data`, and the `vaultId: String`, and publishes a single `state`:

```
enum DeviceUnlockState: Equatable {
    case idle                                   // before first status refresh
    case notEnrolled
    case enrolled                               // enrolled, not yet unlocked this session
    case busy(Activity)                         // enrolling / unlocking / disenrolling — drives the spinner
    case unlocked(vaultUuidHex: String)         // happy path — shows the opened vault uuid
    case failed(DeviceUnlockError, detail: String?)  // typed error + raw domain+code for the taxonomy
}
enum Activity: Equatable { case enrolling, unlocking, disenrolling }
```

Methods (all `async`, each: set `.busy`, call the coordinator, map result/throw into `state`):
`refreshStatus()`, `enroll(password: [UInt8])`, `unlock(reason: String)`, `disenroll()`.

On a caught failure the ViewModel records `.failed(error, detail:)` where `detail` is read from
the enclave's `lastReleaseDiagnostic` (see §3.4) — so even the *typed* auth cases
(`.userCancelled`, `.biometryLockout`, …), which carry no associated string, still surface the
raw `domain`+`code` for the taxonomy readout. The ViewModel stays protocol-only (no `SecKey`):
`lastReleaseDiagnostic` is a member of the `DeviceSecretEnclave` protocol, so the fakes supply it
(nil, or an injected value in tests) and the host tests cover the detail-capture path.

The ViewModel is **pure of platform UI** beyond `ObservableObject` — no `SecKey`, no uniffi
type. It depends only on the `SecretaryDeviceUnlock` public surface, so it is exercised on the
host with the existing fakes.

### 3.2 The shell — `DeviceUnlockScreen`

A single SwiftUI `View`:

- a **status line** rendered from `viewModel.state`;
- a `SecureField` prefilled with the golden demo password (`"correct horse battery staple"`),
  editable so the screen is reusable for a non-golden vault later;
- **Enroll / Unlock / Disenroll** buttons (each calls the matching `async` VM method in a `Task`),
  disabled while `.busy`;
- a **busy spinner** during `.busy`;
- a **"last result / error detail" area**: on `.unlocked` shows the vault UUID and whether it
  matches the pinned fixture; on `.failed` shows the typed case **and** the raw `domain`+`code`
  detail — this is the on-device taxonomy readout.

No business logic in the View; it only renders state and forwards button taps.

### 3.3 Real wiring — `SecretaryApp` (`@main`)

On launch:

1. `AppVaultProvisioning.stageGoldenVault()` — if absent, copy the bundled `golden_vault_001`
   into a writable Application Support subdir; return its path. (Idempotent; never touches the
   bundled read-only copy.)
2. Construct the real coordinator:
   `DeviceUnlockCoordinator(slotPort: UniffiVaultDeviceSlotPort(), enclave: SecureEnclaveDeviceSecretStore(), metadata: KeychainEnrollmentMetadataStore())`.
3. Construct `DeviceUnlockViewModel(coordinator:, vaultPath:, vaultId: "golden")`, inject into
   `DeviceUnlockScreen`, `refreshStatus()` on appear.

### 3.4 Taxonomy-capture enhancement to `SecureEnclaveDeviceSecretStore`

The #202 deliverable from the #214 re-review fixup note. Today the typed auth cases
(`.userCancelled`, `.biometryLockout`, …) carry no associated string, so the real domain/code is
lost. Add a read-only diagnostic to the **`DeviceSecretEnclave` protocol**:

```
var lastReleaseDiagnostic: String? { get }   // "domain=<…> code=<…> mappedTo=<case>", set on every release failure, nil on success
```

`SecureEnclaveDeviceSecretStore` populates it inside `mapDecryptError` for **every** branch (the
LAError branch, the `NSOSStatusErrorDomain` branch, and the final fallback) and for the
store/clear `OSStatus` errors; the in-memory fakes return nil (or an injected value in tests).
The ViewModel reads it into `.failed(error, detail:)` (§3.1). This changes only the *diagnostic
string* — **not** the typed-case mapping — so no existing test or invariant moves; it just lets
the device run **observe** the real domain/code instead of guessing.

> The mapping logic itself (which case each maps to) stays as hardened in #214. The on-device
> run either confirms the `NSOSStatusErrorDomain` codes chosen in `751d542` are right, or gives
> us the exact codes to tighten them to — that tightening, if any, is a one-line follow-up, not
> part of this slice's acceptance.

## 4. Code-signing & deployment

- `project.yml` configures **automatic** signing (`CODE_SIGN_STYLE = Automatic`); the
  `DEVELOPMENT_TEAM` is supplied at generate/build time (an env var consumed by `build-app.sh`,
  or filled in locally) so the team id is not hard-committed.
- **Simulator build** (CI/compile proof) needs no signing.
- **Device deploy** uses the already-registered iPhone 13 Pro Max:
  `xcodebuild -scheme Secretary -destination 'platform=iOS,id=<udid>' -allowProvisioningUpdates`.
  If automatic signing cannot resolve the team, the Development Team ID is required at that step
  (flagged as a deploy-time dependency, not a spec blocker).

## 5. Error handling

- The ViewModel never throws to the View; every coordinator error becomes `.failed(error, detail)`.
- The View renders `.failed` distinctly per typed case (auth-failed / cancelled / lockout /
  not-enrolled / wrong-secret / corrupt / vault / enclave) so the manual proof can read them off.
- Vault staging failures (bundle missing, copy error) surface as an explicit on-screen error
  state, never a silent fallback to an empty/zeroed path.
- `disenroll` tolerates an already-gone slot (B.3 semantics, unchanged).

## 6. Testing & acceptance

**Automated (CI / repeatable):**
1. `cd ios/SecretaryDeviceUnlock && swift test` — host: existing 24 **plus** the new
   `DeviceUnlockViewModel` state-machine tests (enroll success/failure, unlock success/failure
   via injected release error, disenroll, status refresh, the `.busy`→terminal transitions).
   TDD: the ViewModel tests are written first.
2. `bash ios/scripts/build-app.sh` — XcodeGen generates the project and `xcodebuild` builds the
   `Secretary` app for the simulator → `** BUILD SUCCEEDED **`.
3. The existing `run-ios-tests.sh` simulator integration test (real FFI round-trip) still passes.

**Manual on-device proof (closes #202):**
4. Deploy `Secretary.app` to the iPhone 13 Pro Max.
5. **Happy path:** Enroll (password) → Unlock → real Face ID → screen shows the opened vault
   UUID **and** confirms it equals the pinned `golden_vault_001` UUID.
6. **Failure modes:** trigger **Cancel**, **no-match** (wrong face/passcode-fallback declined),
   and **lockout** (repeated failures) → each shows the expected typed `DeviceUnlockError` case;
   **record the raw `domain`+`code`** the screen reports for each.
7. Confirm `SecKeyCopyExternalRepresentation` / export of the SE private key is refused
   (non-exportability) — by inspection of the conformer + the device behaviour.
8. **Capture** the observed taxonomy table into the handoff (and, if it contradicts `751d542`,
   open a one-line follow-up to tighten `mapDecryptError`).

**Acceptance summary:** automated items 1–3 green in CI; manual items 4–8 performed on-device
and documented. #202 closes on successful on-device proof.

## 7. Risks & open items

- **Code-signing** may need the Development Team ID at device-deploy time (see §4). Mitigated by
  automatic signing; surfaced early.
- **XcodeGen as a new dependency** — `brew install xcodegen`. The `project.yml` is small and
  reviewable; the generated `.xcodeproj` is gitignored, keeping worktree/parallel-session hygiene
  (the reason hand-checked-in pbxproj was rejected).
- **Best-effort zeroization** is unchanged from B.3 — Swift value/COW semantics mean secret
  `[UInt8]`/`Data` can't be guaranteed wiped; minimised lifetime + `memset_s` on our own copies.
- **The on-device taxonomy may differ from the codes chosen in `751d542`.** That is the *point*
  of the proof; the safety default (never label an unidentified failure as tamper) already holds
  regardless, so any difference is a low-risk one-line tightening, not a redesign.
- **No Rust / format / FFI-surface change** — verified by construction (`git diff main..HEAD`
  touches only `ios/` + docs).
