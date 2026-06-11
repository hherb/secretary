# NEXT_SESSION.md — B.2 ✅ FFI projection of the per-device wrap slot (#201)

**Session date:** 2026-06-11 (B.2 — projecting the B.1 per-device wrap slot across the FFI so a device can enrol / open-from-secret / revoke through PyO3 + uniffi; the FFI groundwork the iOS Secure-Enclave slice B.3/#202 builds on). Flow: `/nextsession` → cleaned up the merged B.1 worktree → **chose B.2** (the B.2→B.3 chain's natural next) → `superpowers:brainstorming` (settled the surface; **corrected a mistaken premise mid-brainstorm** — the bridge is NOT pure-bytes-only, it has a folder-in B.4 family that the conformance KAT actually replays, which flipped the design to folder-in) → `superpowers:writing-plans` (12-task TDD plan) → `superpowers:subagent-driven-development` (fresh implementer per task + spec & code-quality review after each + final whole-branch review).

**Status:** ✅ code-complete on branch `feature/b2-device-slot-ffi`. **PR: see §4.** Full gauntlet **green** at HEAD (see §1): clippy `-D warnings`, full workspace tests 0-failed, `conformance.py` PASS (incl. the new device-slot B.2 clean-room), `spec_test_name_freshness.py` PASS, **Swift + Kotlin conformance 27/27 both**, pyo3 **78 pytest** pass, `cargo fmt --check` clean. Final whole-branch review (Opus): **APPROVE-WITH-MINOR** — the one Minor (a stale spec §6 sentence) was fixed and re-verified; all 8 cross-cutting security/integration properties hold.

**No app/GUI gate** — B.2 is headless Rust + bindings + the cross-language conformance proof. The conformance gauntlet IS the verification.

## (1) What we shipped this session

**B.2 — FFI projection of the device slot** as **folder-in** ops joining the B.4a–d family (NOT pure-bytes — see the design-pivot note below). Frozen-format-safe: `git diff fb53b10..HEAD -- core/tests/data/golden_vault_001/` is **empty** (no fixture byte changed); `conformance_kat.json` changed only by appending 4 vectors.

| Layer | What landed |
|---|---|
| **Core** | `Unlocker::DeviceSecret { device_uuid, secret }` arm in `core/src/vault/orchestrators.rs::open_vault` — the device open is a **first-class full vault open** (identity + manifest), reusing the SAME manifest verify-before-decrypt (Ed25519 ∧ ML-DSA-65) as password/recovery. Shared `device_slot::read_device_wrap_bytes` helper (DRY with the folder-op layer). |
| **Bridge** | `ffi/secretary-ffi-bridge/src/device.rs` — `add_device_slot` / `open_with_device_secret` / `remove_device_slot` (fixed-array sigs `&[u8;16]`/`&[u8;32]`) + one-shot `DeviceSecretOutput` (Mutex<Option<SecretBytes>>, copy-out-before-drop, mirrors `MnemonicOutput`) + `DeviceEnrollOutput`. 3 new `FfiVaultError` variants promoted from the B.1 `CorruptVault` fold (`DeviceSlotNotFound` / `WrongDeviceSecretOrCorrupt` / `DeviceUuidMismatch`); the B.1 tripwire was **inverted** to pin the promotion. `MalformedDeviceFile` + (structurally-unreachable) `MalformedDeviceSecret` still fold to `CorruptVault`, pinned. |
| **uniffi** | `secretary.udl` + `namespace/mod.rs` + `wrappers/device.rs`: 3 namespace fns, `DeviceSecretOutput` interface (`take_secret`/`wipe`), `DeviceEnrollOutput` dict. Wrong-length `device_uuid`/`device_secret` → `VaultError::InvalidArgument` at the binding layer; password + secret Vec + the `[u8;32]` array zeroized on every return path. |
| **pyo3** | `ffi/secretary-ffi-py/src/device.rs`: 3 `#[pyfunction]` + `DeviceSecretOutput` (`take_secret`/`close`/context-manager) + `DeviceEnrollOutput` (destructive take-once getter). 3 `Vault*` exception classes + translator arms. Wrong-length → `ValueError`. `OpenVaultOutput::from_bridge` ctor (now used by all three folder-in opens). pytest `tests/test_device_slot.py`. |
| **Conformance** | Rust KAT: `Operation::OpenWithDeviceSecret` + 4 vectors (happy / wrong_secret→WrongDeviceSecretOrCorrupt / absent→DeviceSlotNotFound / short_secret→synthetic InvalidArgument). Swift+Kotlin runners: dispatch arm + an enrol round-trip exercising the one-shot handle (27/27 each). `conformance.py`: a refactored-shared `unwrap_device_slot` open cross-check (device IBK == password IBK) + a stdlib enrol round-trip (encrypt→encode §3a→decode→unwrap). Smoke: Swift+Kotlin `SmokeDeviceSlot` covering add/open/**remove**→DeviceSlotNotFound (the revoke gap the KAT doesn't cover). |
| **Docs** | README device-slot row, ROADMAP B.2 ✅ + B.6 count 22→26 / 27/27, CLAUDE.md crypto-layering bullet (`Unlocker::DeviceSecret` + the FFI projection), ADR 0009 unchanged. |

**Branch `feature/b2-device-slot-ffi`** (from `main` @ `fb53b10`): spec + plan + the task implementations (each with its review-fix folded in) + the final-review spec fix + this handoff/docs commit. **Squash-merge collapses to one commit on `main`.**

**Process notes / things future sessions should know:**
- **Design pivot (logged honestly):** the brainstorm first assumed the FFI was "pure-bytes only" and chose a bytes-in surface. Digging into the conformance harness revealed the bridge already has a **folder-in family** (B.4a–d: `open_vault_with_password`, `read_block`, …) which is what `conformance_kat.rs` actually replays. That flipped the design to folder-in (matches #201, preserves atomic-write, reuses the `vault_dir` replay). Lesson: **map the whole bridge surface before framing the FFI shape** — the two families coexist (`open_with_password` bytes-in vs `open_vault_with_password` folder-in).
- **The `FfiVaultError` workspace ripple is real** ([[project_secretary_ffivaulterror_workspace_match]]): adding the 3 variants forced edits to uniffi `From` + UDL, pyo3 translator, **desktop `map_ffi_error`**, the conformance error helper, AND the Swift/Kotlin `ConformanceErrors.{swift,kt}` (cargo/clippy CANNOT see the last two — only `run_conformance.sh` does). One implementer did the whole ripple in the Task-2 commit to keep the workspace compiling; that's why Tasks 4 & 6 were already done.
- **DeviceUuidMismatch is intentionally NOT a cross-language JSON KAT vector** — exercising it needs a relabeled-wrap fixture that would pollute the frozen golden vault. It's covered by the core unit test + the bridge mapping test + `conformance.py` instead. Documented in the spec §6 (the final review caught a stale sentence implying otherwise; fixed).
- **maturin/uv stale-`.so` trap** bit Task 7 ([[project_secretary_maturin_uv_cache]]): pytest imported a stale `.so` after a successful `maturin develop`; fixed by `uv cache clean` + nuking `.venv`. `maturin` isn't on bare PATH — invoke via `uv run --with maturin`.
- **Two spend-limit interruptions** hit mid-run (Task 5 implementer + the final-review subagent were cut off). Both resumed cleanly after the limit was raised; no work lost (Task 5's edits were verified + committed by the controller; the final review was re-dispatched).

### Post-review fixup (folded into this PR)
- **CodeQL `rust/hard-coded-cryptographic-value` (alert #130):** the `enroll_wrong_password_is_wrong_password_or_corrupt` test used a literal `b"wrong-password"` as the password arg, which CodeQL flags as a hard-coded cryptographic value. Replaced with 24 `OsRng`-generated bytes (never collides with the fixed golden password) per [[feedback_test_crypto_random_not_hardcoded]]. Test-only change; no spec/format/binding impact, conformance gauntlet unaffected.

### Open follow-up filed/observed
- **Pre-existing doc inaccuracy (NOT fixed here — your call):** CLAUDE.md + `conformance.py`'s own header advertise it as **"stdlib-only"**, but it actually uses third-party crypto primitives (`cryptography` HKDF, `pynacl` XChaCha20-Poly1305, `pqcrypto`) via PEP 723 inline deps. The clean-room property that matters still holds (it re-implements the protocol from generic primitives, independent of `secretary-core`), but the "stdlib-only" wording is wrong. **Decide:** (a) it was always aspirational/loose → reword CLAUDE.md + the file header to "clean-room (generic crypto primitives via PEP 723; no dependency on `secretary-core`)", or (b) you intend literal stdlib-only and the script drifted → that's a Python cleanup, not a doc edit. Worth a one-line issue.

### Acceptance (re-run clean @ HEAD)
```
cargo clippy --release --workspace --tests -- -D warnings        → clean
cargo test --release --workspace                                 → 0 failed
uv run core/tests/python/conformance.py                          → PASS (device-slot B.2 ops: OK)
uv run core/tests/python/spec_test_name_freshness.py             → PASS
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh     → 27/27
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh    → 27/27
cd ffi/secretary-ffi-py && uv run --with maturin maturin develop --release && uv run --with pytest pytest -q   → 78 passed
cargo fmt --all --check                                          → clean
```

## (2) What's next

The B-chain headline: **B.3 — iOS Secure Enclave / biometric release of the device secret (#202).** B.2 delivered the FFI surface it needs (`add_device_slot` hands back the one-shot `DeviceSecretOutput`; `open_with_device_secret` takes the secret bytes back). **Acceptance:** a non-exportable SE P-256 key (biometric access control) wraps the `device_secret`; biometric/`LAContext` success → SE decrypts → `device_secret` → `open_with_device_secret`; SE private key never leaves the enclave; clear failure modes when biometry is unavailable / locked out; protocol-boundary unit tests (fake enclave) + a manual/simulator biometric proof. Likely pairs with a small SwiftUI host (the deferred app-skeleton slice). Security-critical — enforce-don't-assume on the key-release path. Depends conceptually on D.3 slice 1 (the iOS XCFramework, shipped 2026-06-10).

**Other open work (carried):** the SwiftUI walking-skeleton app + iOS XCTest CI wiring; desktop/sync deferred — background auto-sync (Tauri), reveal-to-decide, **#192** (collision-population test), **#193** (`pipeline.rs` refactor); manual GUI smoke **#161**.

**Open follow-up issues:** **#202** (B.3, the next slice) + carried **#192/#193/#186/#189/#190/#161/#162/#167**. Plus the new "stdlib-only" wording observation above (file it). #201 closes when this PR merges.

## (3) Open decisions and risks

- **`device_uuid` is bound structurally, not cryptographically** (carried from B.1): it is NOT in the AEAD AAD (only `vault_uuid` is — frozen §3a). The header-`device_uuid`==filename check (`DeviceUuidMismatch`) is a structural integrity check; confidentiality rests on the device secret + the `vault_uuid` AAD binding. Cryptographically authenticating `device_uuid` would be a format change — out of scope for v1.
- **Anti-rollback is `None` on the device path — same as password.** The bridge passes `local_highest_clock = None` to `open_vault` for every unlocker (the OS-keystore layer is meant to track it; pre-existing, out of B.2 scope). B.2 keeps the device path at parity, it does NOT close this gap. If B.3 wires a real highest-clock for the SE path, do it for all paths.
- **Interim → real FFI error mapping is DONE for the folder-in path.** The B.1 `CorruptVault` folds for the folder-in device ops are now promoted to honest `FfiVaultError` variants. The **bytes-in** `FfiUnlockError` device fold is intentionally LEFT (the pure-bytes `open_with_device_secret` is still not FFI-surfaced; B.3 can add it if the SE flow needs raw bytes — YAGNI for now).
- **The Secure Enclave work is the unproven frontier.** B.2 keeps the device secret in-memory; the hardware-key-binding + biometric-release work is entirely B.3.

### Verified non-issues (don't re-investigate)
- **Frozen-format additivity (HIGH confidence):** golden_vault_001 is byte-unchanged; conformance_kat.json is +4 vectors only; `identity.bundle.enc` handling untouched.
- **Verify-before-decrypt parity:** the final whole-branch review proved the `Unlocker::DeviceSecret` arm funnels through the SAME `read_and_verify_manifest` (Ed25519 ∧ ML-DSA-65) as password/recovery — no identity-only shortcut at any layer; core test `open_vault_with_device_secret_matches_password_open` pins IBK + user_uuid + vector_clock parity.
- **Zeroize on every path, both directions:** proven across core → bridge one-shot handle → binding, AND foreign bytes → uniffi/pyo3 `Vec`+`[u8;32]` → bridge, including every early `InvalidArgument`/`ValueError` return.
- **Error-variant consistency across all 6 exhaustive surfaces** (bridge / uniffi / UDL / pyo3 / Swift / Kotlin) confirmed by the final review + green Swift/Kotlin conformance.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — confirm / review):
cd /Users/hherb/src/secretary && gh pr list --head feature/b2-device-slot-ffi

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/b2-device-slot-ffi && git branch -D feature/b2-device-slot-ffi
git worktree prune && git worktree list

# 3) Next slice (B.3 — iOS Secure Enclave, #202): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the B.2 gauntlet on the branch (from the worktree):
cd /Users/hherb/src/secretary/.worktrees/b2-device-slot-ffi
cargo test --release --workspace && uv run core/tests/python/conformance.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
cd ffi/secretary-ffi-py && uv run --with maturin maturin develop --release && uv run --with pytest pytest -q
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. `main` did NOT move during this session (branch point == `origin/main` == `fb53b10`), so the symlink retarget merges cleanly (no fixup-merge needed). Next slice: author `docs/handoffs/<date>-<slug>-shipped.md` + `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, both committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `fb53b10`; `feature/b2-device-slot-ffi` carries spec + plan + the B.2 implementation + this handoff/docs commit. Squash-merge collapses to one commit on `main`.
- **Acceptance:** green — clippy / full workspace tests / conformance.py / spec-freshness / Swift 27/27 / Kotlin 27/27 / pyo3 78 pytest / fmt (see §1).
- **Final whole-branch review:** APPROVE-WITH-MINOR — the one stale-spec-sentence Minor fixed + re-verified; all 8 cross-cutting properties hold.
- **README.md / ROADMAP.md:** B.2 ✅ 2026-06-11. **CLAUDE.md:** crypto-layering `Unlocker::DeviceSecret` + FFI-projection note. **docs/adr:** unchanged (ADR 0009 already covers the slot).
- **Open decision for next session:** B.3 (iOS Secure Enclave, #202) is the headline next step. Plus the "stdlib-only" `conformance.py` wording observation (§1) to file/decide.
- **NEXT_SESSION.md:** symlink retargeted to this file.
