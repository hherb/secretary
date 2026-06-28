# Android cloud-drive provisioning — Slice 4: provisioning view models + screens + AppRoot routing

- **Date:** 2026-06-28
- **Status:** Approved design (pre-implementation)
- **Epic:** [#321](https://github.com/hherb/secretary/issues/321) — Android cloud-drive vault provisioning
- **Epic design:** [`2026-06-27-android-cloud-drive-provisioning-design.md`](./2026-06-27-android-cloud-drive-provisioning-design.md) (component rows **#4 + #5**)
- **Branch:** `feature/android-cloud-drive-provisioning-ui` (cut from `main` @ `07f58b1f`)
- **Modules touched:** `:vault-access` (pure view models, host-tested), `:app` (screens + routing). No `:kit` change. **No core `src/`, no FFI surface, no on-disk-format / spec / `conformance.py` / KAT change.**

## Goal

Bring the provisioning **UI and routing** to Android: the two view models (rows #4),
the two screens + SAF folder-picker launchers + `AppRoot` routing (row #5). After
this slice the app presents a **vault-selection entry screen** and a **create-vault
wizard**, both driven by host-tested pure view models over the Slice-1 `VaultCreatePort`
and Slice-2 `VaultLocationStore`.

This slice deliberately **does not** wire the SAF working-copy lifecycle
(materialize / flush) — that is Slice 5. Consequently the only fully-functional *open*
paths this slice are **Create** (creates into a local working subdir, opens it, browses
— everything except the cloud flush) and the existing **golden-vault demo**. Opening a
*remembered cloud location* is routed through an explicit, named **materialize-then-unlock
seam** that Slice 5 completes.

## Why this boundary

The Rust core operates on a real POSIX path. A cloud-drive folder is reachable only via
SAF `content://`, so opening a remembered cloud vault requires *materializing* a working
copy first — that is the whole point of Slice 5 (`VaultMirror.materialize`, shipped as a
mechanism in Slice 3). Slice 4 builds and host-tests the observable UI + state machines
so Slice 5 only has to *call* `materialize`/`flush` at the right lifecycle moments. Create
needs only a real local working dir, so it round-trips end-to-end this slice (minus the
cloud flush).

## Components

Following the existing `:vault-access` (pure, host-tested) / `:app` (Compose, real
Android) split. Each file is a focused unit; split toward a directory module before any
file nears ~500 lines.

### A. Pure layer — `:vault-access`, package `org.secretary.browse`

Plain classes with a mutable `state`/`step` field mutated by `suspend` methods, mirroring
the existing `DeviceUnlockViewModel` / `DeviceSettingsViewModel`. `AppRoot` bridges the
field into Compose `mutableStateOf` (the established pattern — no Android/Compose
dependency leaks into `:vault-access`).

| File | Contents |
|---|---|
| `VaultSelectionState.kt` | `sealed VaultSelectionState`: `Empty` / `Located(displayName)` / `Unavailable(reason)`. |
| `VaultSelectionViewModel.kt` | `VaultSelectionViewModel(store: VaultLocationStore)` with `var state`. |
| `VaultName.kt` | `validateVaultName(name): VaultNameValidation` (`Valid(name)` / `Invalid(VaultNameError)`); `sealed VaultNameError`. Pure. |
| `VaultProvisioningStep.kt` | `sealed VaultProvisioningStep`: `Folder` / `Credentials(treeUri, vaultName)` / `Mnemonic` / `Done(location)`. |
| `VaultProvisioningViewModel.kt` | `VaultProvisioningViewModel(createPort: VaultCreatePort, store: VaultLocationStore)` with `var step`, `var nameError`, `var error`, `var isCreating`, `var mnemonicRows`. |
| `MnemonicDisplay.kt` | `data class MnemonicWord(index, word)`; `groupMnemonic(phrase: ByteArray): List<MnemonicWord>`. Pure. |

(`VaultProvisioningError`, `CreatedVault`, `VaultLocation`, `VaultLocationStore`,
`VaultCreatePort` already exist from Slices 1–2.)

**`VaultSelectionViewModel` behaviour** (mirror of iOS `VaultSelectionViewModel`, minus
`beginAccess`/`probe` — those need SAF, deferred to Slice 5):

- `loadPersisted()` — if `state` is already `Unavailable`, preserve it (a failed open's
  reason must survive a screen re-appear; the user clears it explicitly via
  `chooseDifferent()` or a fresh `recordSelection`). Otherwise `store.load()`: a present
  location that **is not** `store.isAvailable(loc)` → `Unavailable(reason)` (mirrors iOS
  stale-bookmark `.unavailable`); a present-and-available location → `Located(name)`;
  none → `Empty`.
- `recordSelection(location: VaultLocation)` — `store.persist(location)` → `Located(name)`.
- `markUnavailable(reason)` — → `Unavailable(reason)`. The remembered location is
  **retained, not cleared** (losing the user's selection silently would be wrong). Called
  by the Slice-5 open path when materialize/permission fails.
- `chooseDifferent()` — `store.clear()` → `Empty`.

**`VaultProvisioningViewModel` behaviour** (mirror of iOS `VaultProvisioningViewModel`,
adapted to the Android `createInFolder(folderPath, password, displayName)` port):

- `chooseFolder(treeUri: String, vaultName: String)` — clear `error`; `validateVaultName`:
  `Invalid` → publish `nameError`, stay on `Folder`; `Valid(name)` → clear `nameError`,
  `step = Credentials(treeUri, name)`.
- `create(folderPath: String, password: ByteArray, confirm: ByteArray)` — guard
  re-entrancy (`if (isCreating) return`) and `step is Credentials`. Password match
  (`passwordsMatch`, constant-time-ish over equal length — reuse if a helper exists, else
  a length-then-byte compare) else `error = PasswordMismatch`. Set `isCreating = true`
  before the first suspension (so the button disables before `await` yields); reset in a
  `finally`. Then:
  1. `created = createPort.createInFolder(folderPath, password, vaultName)`
  2. `store.persist(VaultLocation(vaultName, treeUri))` — **before** revealing the phrase,
     so a crash mid-flow leaves an openable + remembered vault.
  3. `phrase = created.phrase`; `mnemonicRows = groupMnemonic(created.phrase)`;
     `step = Mnemonic`.
  - `catch (e: VaultProvisioningError)` → `error = e`; other throw → `error =
    CreateFailed(detail)`. The **caller** owns the `folderPath` directory creation (port
    contract: an existing **empty** dir) and zeroizing its own `password`/`confirm` copies.
- `acknowledgeMnemonic()` — guard `step is Mnemonic`; zeroize the retained `phrase`
  `ByteArray` and drop `mnemonicRows`; `step = Done(store.load() ?: …)`. A `null` load here
  is a real store fault → `error = CreateFailed("vault location unavailable after create")`
  rather than stranding the user (no silent failure).
- `cancel()` — zeroize `phrase`, drop `mnemonicRows`. Safe from any step.

**Secret hygiene.** The recovery `phrase` is a zeroize-owned `ByteArray`, scrubbed in
`acknowledgeMnemonic` / `cancel`. The display `MnemonicWord.word` `String`s are
un-zeroizable — the accepted best-effort tradeoff for showing a phrase the user must read
(documented, same as iOS). `create` never retains `password`/`confirm`.

### B. Screens + SAF launchers — `:app`, package `org.secretary.app`

Pure-ish composables taking state + callbacks (no business logic in the composable),
mirroring the existing `UnlockScreen` / `DeviceSettingsScreen`.

| File | Contents |
|---|---|
| `VaultSelectionScreen.kt` | Renders `VaultSelectionState`. `Empty` → **[Create new vault]** + **[Open the demo vault]**. `Located(name)` → name + **[Open]** + **[Choose different]**. `Unavailable(reason)` → reason + **[Re-pick folder]** + **[Open the demo vault]**. Callbacks: `onCreate`, `onOpen`, `onChooseDifferent`, `onDemo`, `onPickFolder`. |
| `CreateVaultWizardScreen.kt` | Renders `VaultProvisioningStep`: `Folder` (pick-parent button + name field + `nameError`), `Credentials` (password + confirm + `isCreating` disable/spinner), `Mnemonic` (numbered 24-word grid + **[I've written it down]**), Cancel throughout; `Done` signalled up. |

**SAF launchers.** `rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree)`
in `AppRoot`. On a non-null result `treeUri`:

- Hand `treeUri` to `SafVaultLocationStore` so it `takePersistableUriPermission`s (Slice 2
  owns that call).
- Derive the display name from `DocumentFile.fromTreeUri(context, treeUri)?.name`.
- For **select existing** → `selectionVm.recordSelection(VaultLocation(name, treeUri))`.
- For **create** → `provisioningVm.chooseFolder(treeUri.toString(), typedName)`.

### C. Routing — `:app`, `AppRoot.kt`

- New start route **`Route.Selection`** (replaces `Unlock` as the entry).
- The golden-vault **demo path is preserved unchanged** — "Open the demo vault" →
  existing `unlockAndOpen(stageGoldenVault…)` → Browse.
- **Create** (functional this slice, locally): `onCreate` → `Route.CreateWizard`. The
  wizard resolves an **empty working subdir** in app-private storage
  (`File(filesDir, "working/<vaultName>")`, created fresh), passes it to `create(...)`; on
  `acknowledgeMnemonic` → `Done(location)` → route into the existing `Unlock`/Browse flow
  against that real working path. Round-trips end-to-end **minus the cloud flush** (Slice 5).
- **Open a remembered cloud location** — routed through an explicit, named
  **`materialize-then-unlock` seam**. Slice 5 implements it (`VaultMirror.materialize` →
  working copy → unlock). This slice presents the remembered vault with a clear
  *"cloud sync arrives in the next update"* affordance — not a dead button — so the screen
  never lies about being able to open a cloud vault yet.

## Data flows (this slice)

- **Create new (works locally):** `onCreate` → wizard → pick parent tree (SAF) + name →
  `chooseFolder` → credentials → `create(workingSubdir, …)` → `persist(location)` →
  reveal phrase → `acknowledgeMnemonic` → open `workingSubdir` → Browse. *(Cloud flush of
  the working subdir = Slice 5.)*
- **Open demo (works):** `onDemo` → existing `unlockAndOpen(stageGoldenVault)` → Browse.
- **Open remembered cloud vault (Slice-5 seam):** `onOpen` → materialize-then-unlock seam
  (not backed by materialize this slice) → screen shows the deferred affordance.
- **Stale permission:** `loadPersisted` sees `!store.isAvailable(loc)` → `Unavailable` →
  screen prompts re-pick.

## Error handling

- Invalid vault name → `nameError`, stay on `Folder` (no port call).
- Password mismatch → `error = PasswordMismatch`, stay on `Credentials`.
- `createInFolder` → `FolderNotEmpty` / `CreateFailed(detail)` surfaced as `error`.
- Store load returns null after a successful create → `CreateFailed(...)` (no silent
  failure).
- Revoked / stale SAF permission → `Unavailable(reason)` → re-pick prompt.

## Testing

- **Host (`:vault-access:test`, no device):**
  - `validateVaultName` — blank, path separators, `.`/`..`, over-length, valid.
  - `groupMnemonic` — 24 words numbered 1..24; phrase `ByteArray` untouched by grouping.
  - `VaultSelectionViewModel` — `Empty`/`Located`/`Unavailable` transitions; `Unavailable`
    preserved across `loadPersisted`; stale (`isAvailable == false`) → `Unavailable`;
    `chooseDifferent` clears; `markUnavailable` retains the location.
  - `VaultProvisioningViewModel` (fake `VaultCreatePort` + fake `VaultLocationStore`) —
    name-validation gate; password mismatch; **persist-before-mnemonic** (assert persist
    call ordered before `step == Mnemonic`); re-entrancy guard (`isCreating` blocks a
    second `create`); `FolderNotEmpty` / `CreateFailed` mapping; **zeroize-on-ack** (the
    retained phrase buffer is all-zero after `acknowledgeMnemonic`); null-load-after-create
    → `CreateFailed`; `cancel` zeroizes.
- **Instrumented / screen (`:app`, deferred to the existing UI-test pattern where it needs
  a device):** wizard step rendering, Selection state rendering, SAF launcher result →
  `recordSelection`. The full create→flush→materialize→open round-trip is **Slice 6**'s
  instrumented E2E.

## Out of scope (this slice)

- Materialize / flush wiring and the working-copy lifecycle (Slice 5).
- Cloud open of a remembered location (Slice 5).
- Instrumented create→flush→materialize→open E2E + conflict-copy ingest (Slice 6).
- The real-SAF `takePersistableUriPermission` round-trip on a device (Slice 6).

## README / ROADMAP

Add an Android **vault provisioning UI** capability entry now (per the session decision),
worded to state plainly that the **cloud working-copy round-trip lands in the following
slice** — accurate, not overclaiming. Consistent with [[feedback_readme_style]] (brief,
audience-aware).

## Key references

- Epic design: `docs/superpowers/specs/2026-06-27-android-cloud-drive-provisioning-design.md` (rows #4, #5).
- iOS analogues: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/{VaultSelectionViewModel,VaultProvisioningViewModel}.swift`; `ios/SecretaryApp/Sources/{VaultSelectionScreen,CreateVaultWizardView}.swift`.
- Slice 1/2 ports: `android/vault-access/src/main/kotlin/org/secretary/browse/{VaultCreatePort,VaultLocationStore,VaultLocation,VaultProvisioningError}.kt`.
- Android UI pattern to mirror: `android/app/src/main/kotlin/org/secretary/app/{AppRoot,UnlockScreen,DeviceSettingsScreen}.kt`; `android/vault-access/src/main/kotlin/org/secretary/browse/{DeviceUnlockViewModel,DeviceSettingsViewModel}.kt`.
