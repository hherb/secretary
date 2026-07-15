# D.5.1 manual proof — Touch ID / Secure Enclave on macOS

Proves `open_with_device_secret` on a real Apple Silicon Mac with Touch ID.
Equivalent to the iOS #202 proof.

## Prereqs
- Apple Silicon Mac (M1+) with Touch ID, macOS 13+.
- Xcode signed in to an Apple Developer team.
- `brew install xcodegen`.

## Steps
1. Build the framework + generate the project:
   ```bash
   DEVELOPMENT_TEAM=<YOUR_TEAM_ID> bash ios/scripts/build-macos-app.sh
   ```
2. Open `ios/SecretaryMacApp/SecretaryMac.xcodeproj` in Xcode.
3. Select the `SecretaryMac` scheme, destination **My Mac**. Under
   Signing & Capabilities, confirm your team is selected (Automatic signing).
4. Run (⌘R).
5. In the window, type the **golden_vault_001 test password** (see
   `core/tests/data/golden_vault_001_inputs.json`) and click **Enroll device slot**.
   Expect `State: enrolled`.
6. Quit and relaunch the app (⌘R again) — do NOT re-enroll.
7. Click **Unlock with Touch ID**. Authenticate at the Touch ID prompt.
   Expect `State: unlocked(vaultUuidHex: "<pinned uuid>")`.
8. Re-run, click Unlock, and **cancel** the Touch ID prompt. Expect the state to
   return to a `failed(userCancelled, …)` / silent case — **never**
   `wrappedSecretCorrupt`.

Note: the staged vault under Application Support is cached idempotently across
runs. If you change the fixture and need to re-run this proof, delete the
staged copy first, e.g. `rm -rf "$HOME/Library/Application Support/golden_vault_001"`.

## PASS criteria
- [ ] Enroll → `enrolled`.
- [ ] Relaunch + Touch ID → `unlocked(vaultUuidHex:)` matching the pinned uuid.
- [ ] Cancel maps to the cancel path, not `wrappedSecretCorrupt`.

## Known pitfall — `errSecMissingEntitlement` (-34018)
If enroll fails with OSStatus **-34018**, the app is not signed with an
application-identifier the data-protection Keychain / Secure Enclave accepts.
Fix: ensure Automatic signing with a real team is selected (step 3) and that
`SecretaryMac.entitlements` (keychain-access-groups) is attached to the target.
This is expected on the first unsigned run and is why the manual proof runs from
Xcode with a team, not via the `CODE_SIGNING_ALLOWED=NO` CI compile proof.
