# NEXT_SESSION.md — B.1 ✅ per-device wrap slot (core for hardware-backed/biometric unlock)

**Session date:** 2026-06-10 (D.3 Option-B, slice B.1 — the FIRST piece of ADR 0008's hardware-backed, biometric-bound key release: a third, per-device credential that recovers the Identity Block Key via its own wrap file `devices/<uuid>.wrap` (`file_kind 0x0004`), so a device can later unlock after a biometric check **without storing the human master password** and can be **revoked independently**). Flow: settled the credential model (chose Option B — per-device wrap slot — over caching the master password, after a threat-model tradeoff discussion) → `superpowers:brainstorming` (decomposed B into B.1 core / B.2 FFI / B.3 iOS; scoped this session to **B.1 core only**) → `superpowers:writing-plans` (7-task TDD plan, spec-first) → `superpowers:subagent-driven-development` (fresh implementer per task + spec & code-quality review after each + final whole-branch review).
**Status:** ✅ code-complete on branch `feature/b1-device-wrap-slot`. **PR: see §4.** Full gauntlet **green** at HEAD `9403685`: clippy `-D warnings` clean, full workspace tests 0-failed, `conformance.py` PASS (incl. the new device-slot §3a/§5a clean-room replay), `spec_test_name_freshness.py` PASS, and **Swift + Kotlin conformance 22/22 both** (the cross-language harnesses cargo can't see — re-run green after every FFI-bridge touch). Final whole-branch review (Opus): **APPROVE WITH MINOR** — the one Important finding (a spec/code divergence) and the one Minor were both fixed and re-verified.
**No app/GUI gate** — B.1 is headless Rust core + a Python clean-room conformance proof. The conformance gate IS the verification; it is scripted and runs every CI.

## (1) What we shipped this session

**B.1 — per-device wrap-slot format & crypto** (the core foundation; FFI + iOS are deferred follow-ups #201/#202). Frozen-format-safe: `identity.bundle.enc` and every existing `golden_vault_001/` file are **byte-unchanged** — the device slot is a NEW separate file kind.

| Layer | What landed |
|---|---|
| **Spec (normative, first)** | ADR `docs/adr/0009-per-device-wrap-slot.md`; `docs/crypto-design.md` §5a (`device_kek = HKDF-SHA-256(device_secret)`, deliberately not Argon2id — mirrors recovery KEK) + §1.3 tag table; `docs/vault-format.md` §3a (`devices/<uuid>.wrap`, `file_kind 0x0004`, byte layout) + §1 folder line; glossary. |
| **Crypto** | `crypto::kdf::derive_device_kek` + tags `TAG_DEVICE_KEK` / `TAG_ID_WRAP_DEV` (verbatim `derive_recovery_kek` sibling; zeroize discipline). |
| **Codec** | `core/src/unlock/device_file.rs` — `DeviceWrapFile` encode/decode (sibling of `bundle_file.rs`) + a new `core/fuzz` target `device_file`. |
| **Pure ops** | `core/src/unlock/device.rs` — `wrap_device_slot` / `unwrap_device_slot` / `open_with_device_secret`; typed errors `WrongDeviceSecretOrCorrupt` / `MalformedDeviceFile` / `MalformedDeviceSecret` / `DeviceUuidMismatch`; shared `decrypt_bundle_to_identity` tail now used by all three open paths. |
| **Folder ops** | `core/src/vault/device_slot.rs` — `add_device_slot` (enroll: validate password → mint secret+uuid → atomic write), `open_identity_with_device_secret`, `remove_device_slot` (revoke); `VaultError::DeviceSlotNotFound`; new variants threaded through all FFI-bridge exhaustive matches. |
| **Conformance / KAT** | `conformance.py::verify_device_slot` (stdlib clean-room: derives `device_kek`, unwraps the IBK, cross-checks it against the password-path IBK, and asserts §3a `device_uuid` header==filename); golden fixture `golden_vault_001/devices/d0d0…d0.wrap` + pinned inputs; always-run Rust KAT guard. |
| **Docs** | README status row, ROADMAP B.1 ✅, CLAUDE.md crypto-layering bullet + "Seven targets" fuzz line. |

**Branch `feature/b1-device-wrap-slot`** (from `main` @ `4cb4392`): 17 commits — spec + plan + 7 task implementations, each with its review-fix commit, + 2 final-review fixes (`c115aed` device_uuid enforcement, `9403685` bridge tripwire) + this handoff. Squash-merge collapses to one commit on `main`.

**Process notes / things future sessions should know:**
- **Adding a `VaultError` or `UnlockError` variant ripples to the FFI bridge** ([[project_secretary_ffivaulterror_workspace_match]]). B.1 added variants but mapped them to **existing** `FfiVaultError`/`FfiUnlockError` variants (fold to `CorruptVault`) — so **no new FFI variant**, and the Swift/Kotlin `ConformanceErrors.{swift,kt}` did NOT need changes. We still re-ran both conformance scripts (22/22) to confirm. B.2 WILL add real FFI variants and MUST update those `.swift`/`.kt` harnesses (cargo/clippy can't see them).
- **The plan had a bug the implementer caught:** the folder `create_vault` enforces the v1 Argon2id floor (64 MiB), so the test helper uses `create_vault_unchecked` + manual file writes (the established test pattern).
- **The final review caught a real spec/code divergence** the per-task reviews missed: §3a + `conformance.py` require the wrap file's header `device_uuid` to equal the filename UUID, but the Rust open path didn't enforce it (`device_uuid` is NOT in the AEAD AAD). Fixed in `c115aed`: `open_with_device_secret` now takes the expected `device_uuid` and rejects a mismatch (`UnlockError::DeviceUuidMismatch`). Lesson: the conformance script and the Rust must agree — when one enforces an invariant, the other must too.
- Filed/closed issues: **#201** (B.2 FFI projection), **#202** (B.3 iOS Secure Enclave) opened; **#203** (pre-existing §13→§5 comment mis-citations in `open_with_password`/`open_with_recovery`) found during review and **fixed + closed** on this branch.

### Acceptance (re-run clean @ HEAD `9403685`)
```
cargo clippy --release --workspace --tests -- -D warnings        → clean
cargo test --release --workspace                                 → 0 failed (74 ok-result lines)
uv run core/tests/python/conformance.py                          → PASS (device-slot §3a/§5a: OK)
uv run core/tests/python/spec_test_name_freshness.py             → PASS
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh     → 22/22
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh    → 22/22
```

## (2) What's next

Natural next-deferred (pick one → brainstorm → plan → execute). The dependency chain is **B.2 → B.3**:

- **B.2 — FFI projection of the device slot (#201).** Expose `add_device_slot` / `open_with_device_secret` / `remove_device_slot` across uniffi (+ pyo3 parity), threading real `FfiVaultError` variants. **Acceptance:** the three ops callable from Swift/Kotlin/Python; `WrongDeviceSecretOrCorrupt` / `DeviceSlotNotFound` / `DeviceUuidMismatch` promoted to dedicated `FfiVaultError` variants (currently folded to `CorruptVault`); `conformance_kat.json` regenerated (human-reviewed, scoped diff); **the Swift/Kotlin `ConformanceErrors.{swift,kt}` updated for the new variants** (cargo CANNOT see those — only `run_conformance.sh` does); full gauntlet + both conformance scripts green. The `device_secret` exits the boundary as a one-shot `SecretBytes` (like the recovery phrase's `take_phrase`).
- **B.3 — iOS Secure Enclave / biometric release (#202).** The ADR 0008 headline. A non-exportable SE P-256 key (biometric access control) wraps the `device_secret`; biometric/`LAContext` success → SE decrypts → `device_secret` → `open_with_device_secret`. **Acceptance:** SE private key never leaves the enclave; clear failure modes when biometry unavailable/locked out; protocol-boundary unit tests (fake enclave) + a manual/simulator biometric proof. Likely pairs with a small SwiftUI host (the deferred app-skeleton slice). Security-critical — enforce-don't-assume on the key-release path.
- **iOS slice-2 alternatives still open from the prior handoff:** the SwiftUI walking-skeleton app; CI wiring for the iOS XCTest.
- **Desktop / sync deferred (carried):** background auto-sync (Tauri), reveal-to-decide, **#192** (collision-population test), **#193** (pipeline.rs refactor).

**Open follow-up issues:** **#201 / #202** (this slice's children) + carried **#192/#193/#186/#189/#190/#161/#162/#167**. #203 closed this session.

## (3) Open decisions and risks

- **`device_uuid` is bound structurally, not cryptographically.** It is NOT in the AEAD AAD (only `vault_uuid` is — that's the frozen §3a format). The header-`device_uuid`==filename check (`DeviceUuidMismatch`) is a structural integrity check rejecting a relabeled wrap file within a vault. Confidentiality still rests on the device secret + the `vault_uuid` AAD binding. If a future threat model wants `device_uuid` cryptographically authenticated, that is a **format change** (new file kind / AAD change) + golden-KAT regen — out of scope for v1.
- **Interim FFI error mapping.** B.1's device errors fold to `CorruptVault` in the bridge (unreachable today — no FFI surface opens via device secret). B.2 must promote them to honest variants; tripwire tests pin the current folds so that promotion is deliberate.
- **The Secure Enclave work is the unproven frontier.** B.1 keeps the device secret in-memory in tests; the hard, must-be-right hardware-key-binding + biometric-release work is entirely B.3.
- **App project structure still unsettled** (xcodeproj vs XcodeGen vs SPM-app) — decide when the iOS app/UI slice starts.

### Verified non-issues (don't re-investigate)
- **Frozen-format additivity (HIGH confidence):** `git diff main..HEAD -- core/tests/data/golden_vault_001/` is exactly ONE new file (`devices/…​.wrap`); `identity.bundle.enc` and `bundle_file.rs`/`create_vault` are untouched.
- **No new FFI variant → Swift/Kotlin harnesses unaffected:** confirmed by reading the bridge diff AND re-running both conformance scripts 22/22.
- **Zeroize + typed-error invariants:** verified at every secret site (`derive_device_kek`, `wrap`/`unwrap`/`secret_to_array`, `add_device_slot`) by spec + quality + final review; the minted secret is zeroized immediately after the `Sensitive::new` copy.
- **Conformance independence:** `verify_device_slot` cross-checks against an IBK independently re-derived from the password path (not a tautology).

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — confirm / review):
cd /Users/hherb/src/secretary && gh pr list --head feature/b1-device-wrap-slot

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/b1-device-wrap-slot && git branch -D feature/b1-device-wrap-slot
git worktree prune && git worktree list

# 3) Next slice (likely B.2 — FFI projection, #201): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the B.1 gauntlet on the branch (from the worktree):
cd /Users/hherb/src/secretary/.worktrees/b1-device-wrap-slot
cargo test --release --workspace && uv run core/tests/python/conformance.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. `main` did NOT move during this session (branch point == `origin/main` == `4cb4392`), so the symlink retarget merges cleanly (no fixup-merge needed). Next slice: author `docs/handoffs/<date>-<slug>-shipped.md` + `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, both committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `4cb4392`; `feature/b1-device-wrap-slot` carries spec + plan + 7 tasks (each with review-fix) + 2 final-review fixes + this handoff. Squash-merge collapses to one commit on `main`.
- **Acceptance:** green — clippy / full workspace tests / conformance.py / spec-freshness / Swift 22/22 / Kotlin 22/22 (see §1).
- **Final whole-branch review:** APPROVE WITH MINOR — both findings fixed (`c115aed`, `9403685`) and re-verified.
- **README.md / ROADMAP.md:** B.1 ✅ 2026-06-10. **CLAUDE.md:** crypto-layering bullet + "Seven targets" fuzz line. **docs/adr:** ADR 0009 added.
- **Open decision for next session:** B.2 (FFI projection, #201) is the natural next step; it MUST update the Swift/Kotlin `ConformanceErrors.{swift,kt}` when it adds real FFI variants. B.3 (Secure Enclave, #202) is the security-critical headline.
- **NEXT_SESSION.md:** symlink retargeted to this file.
