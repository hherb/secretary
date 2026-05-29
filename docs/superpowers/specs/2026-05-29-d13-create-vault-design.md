# D.1.3 — Create: desktop vault create wizard (design spec)

**Status:** approved design, pre-plan. Follows D.1.2 (`2026-05-29-d12-browse-design.md`), which shipped read-only browse (block detail + field reveal). D.1.3 is the next slice in Sub-project D's feature breadth (browse → **create** → edit → share/trash; see ADR 0007) and the **first write path** in Sub-project D.

This spec mirrors the D.1.1 / D.1.2 section structure so the three read as a series. Where a prior section has no D.1.3 analogue it is omitted rather than padded.

## 1. What this slice ships

D.1.2 reads an existing vault. D.1.3 lets the user **create a brand-new vault** from the desktop app:

- A guided wizard: **choose a folder** → **set a display name + password (with confirm)** → **create** → **surface the 24-word recovery mnemonic** → acknowledge → land on Unlock with the new path pre-filled.
- The create call writes a complete, re-openable v1 vault — `vault.toml`, `identity.bundle.enc`, `contacts/<owner>.card`, and an empty `manifest.cbor.enc` — **atomically** (core's `io::write_atomic` per file).
- The D.1.1 "Not a vault" picker hint becomes **actionable**: it offers to open the create wizard pre-filled with the chosen folder.
- This slice also **closes the D.1.1 password carry-forward**: the IPC password boundary becomes zeroize-typed for both `create_vault` and (retrofit) `unlock_with_password`.

Still no edit/save (D.1.4) and no share/trash/restore (D.1.5). After create, the app does **not** auto-open — the user opens the new vault through the normal unlock flow.

## 2. Why this ordering (create after browse)

Browse (D.1.2) proved the read path and the secret-widening discipline before any write existed. Create is the smallest write slice: it produces a fresh vault from scratch with **no merge, no manifest mutation, no block writes** — it exercises the atomic-write contract and a second secret-widening point (the recovery mnemonic) in isolation, before the riskier edit/save path (which mutates an existing manifest and writes blocks) builds on it. It also unblocks the most basic first-run flow: a user with no vault can now make one.

## 3. Architecture approach

Core already exposes the complete create entry point: `secretary_core::vault::orchestrators::create_vault(folder, &SecretBytes, display_name, Argon2idParams, created_at_ms, &mut rng)` writes all four files atomically and returns the `Mnemonic`. The desktop crate **already links `secretary-core` directly** (`desktop/src-tauri/Cargo.toml`), so D.1.3 wraps that core orchestrator behind one IPC command — it does **not** use the bridge's `create_vault`.

| Decision | Choice | Rationale |
|---|---|---|
| Disk-write surface | Wrap **`core::vault::orchestrators::create_vault`** (writes 4 files atomically, returns `Mnemonic`) | The §9 atomic-write guarantee lives in core. The **bridge** `create_vault` is bytes-only and returns just `vault.toml` + `identity.bundle.enc` bytes — **not** the empty manifest or owner card — so it cannot produce a complete on-disk vault without bridge changes (a separate FFI PR + uniffi regen). Wrong tool for a desktop slice. |
| Post-create flow | **Return to Unlock, path pre-filled** (no auto-open) | One Argon2id derivation total (the create). Password is dropped immediately after create — never held to auto-open. The subsequent unlock is a separate, user-initiated action they would take anyway. (Rejected: auto-open via a second derivation — holds the password longer for marginal convenience.) |
| KDF params | Hardcoded **`Argon2idParams::V1_DEFAULT`** (256 MiB / 3 / 1) | Matches the bridge's design (no foreign-callable KDF knob). The desktop never supplies custom params, so `UnlockError::WeakKdfParams` is **unreachable** here (see §13). No "strength" UI built around an error that cannot fire. |
| Empty-folder handling | **Client probe + offer subfolder**, plus a Rust-side empty-check producing a typed error | Core requires the target dir to **exist and be empty** (`ensure_empty_directory`); a non-empty dir yields a coarse `VaultError::Io`, not a dedicated variant. The desktop does its own check and surfaces a typed `AppError::VaultFolderNotEmpty` — never string-matching core's `Io`. |
| Mnemonic confirmation | **Display + "I have written it down" checkbox** gating Continue | Low friction; the phrase is the only recovery path, so it is shown clearly with a copy button. (Rejected for v1: verify-by-re-entry — more friction/UI; promote later if desired.) |
| Password input | **Confirm-password field** + zeroize-typed IPC boundary | The password is unrecoverable except via the mnemonic, so a confirm field guards typos. The boundary type closes the D.1.1 carry-forward (see §6). |

## 4. Project layout (additions)

```
desktop/src-tauri/src/
  commands/
    create.rs            NEW — create_vault + probe_create_target command impls
  secret_arg.rs          NEW — Password newtype (zeroize-typed IPC boundary)
  dtos/
    create.rs            NEW — CreateVaultDto, CreateTargetProbeDto
    mod.rs               MODIFIED — re-export create DTOs
  commands/unlock.rs     MODIFIED — password: String → password: Password (retrofit)
  errors.rs              MODIFIED — VaultFolderNotEmpty, VaultCreateFailed
  main.rs                MODIFIED — register the two new commands
desktop/src/
  lib/
    create.ts            NEW — pure wizard step state machine + transitions
    ipc.ts               MODIFIED — createVault, probeCreateTarget
    errors.ts            MODIFIED — new codes + actionable "Not a vault" hint
    constants.ts         MODIFIED — wizard-related constants if any
  components/
    create/              NEW dir — one component per wizard step
      FolderStep.svelte      choose folder + empty-probe + subfolder offer
      CredentialsStep.svelte display name + password + confirm
      MnemonicStep.svelte    24-word display + copy + acknowledge gate
  routes/
    CreateVault.svelte   NEW — wizard host (switches on step)
    Unlock.svelte        MODIFIED — "Not a vault" hint → open wizard pre-filled;
                                    accept a pre-fill path + "created" banner
  App.svelte             MODIFIED — route between Unlock and CreateVault
```

The `create/` component dir keeps each wizard step a small, single-purpose file (< 500 LOC); the wizard host only routes between steps.

## 5. Module decomposition + responsibilities

### Backend (`src-tauri/src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `commands/create.rs` | Thin `#[tauri::command]` wrappers + `*_impl` for `create_vault` and `probe_create_target`. `create_vault_impl`: `create_dir_all` the target, own empty-check → typed error, call core orchestrator, copy mnemonic into DTO, drop (zeroize). Session-stateless. | No (file I/O + core call) |
| `secret_arg.rs` | `Password` newtype wrapping `SecretString`, with a custom `Deserialize` that wraps the incoming JSON string and zeroizes its own intermediate buffer. Exposes `as_bytes()` for the core call. | Data (zeroizing) |
| `dtos/create.rs` | `Serialize`-only `CreateVaultDto { mnemonic }` (the one widening point) and `CreateTargetProbeDto { exists, is_empty }`. `#[serde(rename_all = "camelCase")]`. | Data only |
| `errors.rs` (mod) | Add `VaultFolderNotEmpty { path }` and `VaultCreateFailed { detail #[serde skip] }` (maps any `core::VaultError` from the orchestrator; `detail` logged via `tracing`, never serialized). | Pure |

### Frontend (`src/`)

| Module | Responsibility | Pure? |
|---|---|---|
| `lib/create.ts` | Wizard step state machine: `{step:'folder'} \| {step:'credentials',folder} \| {step:'mnemonic',mnemonic} \| {step:'done',folder}` + transition helpers. No IPC, no DOM. Pure helpers: password-match check, subfolder-path join, mnemonic word-grouping for display. | Yes |
| `lib/ipc.ts` (mod) | `createVault(folderPath, displayName, password)`, `probeCreateTarget(folderPath)` + DTO interfaces. | Wrapper |
| `lib/errors.ts` (mod) | Add `vault_folder_not_empty`, `vault_create_failed` to the code union + messages; make the existing `vault_path_not_a_vault` action hint navigate into the wizard. | Pure |
| `components/create/*` | Render + dispatch only. The mnemonic display holds the phrase **only** in local `$state`; clipboard/DOM writes live at the component edge. | No |
| `routes/CreateVault.svelte` | Host: switch on `lib/create.ts` step; call `ipc.createVault` on submit; on success advance to the mnemonic step; on acknowledge route to Unlock pre-filled. | No |

### IPC boundary discipline

`probe_create_target` returns only booleans (no secrets, no path echo beyond what the caller sent). `create_vault` returns metadata-free `CreateVaultDto` whose **only** field is the recovery `mnemonic` — the single secret crossing the boundary in this slice, produced once on an explicit create and displayed once.

## 6. Create path lifecycle

### `probe_create_target(folderPath) -> CreateTargetProbeDto`

1. `exists` = `folder.exists()`.
2. `is_empty` = exists ∧ is a directory ∧ `read_dir` yields no entry (a non-existent path is reported `exists:false, is_empty:false`; the wizard treats "will be created fresh" separately).
3. Read-only; no writes, no secrets.

### `create_vault(folderPath, displayName, password) -> CreateVaultDto`

1. `fs::create_dir_all(folder)` (idempotent; supports both "user-picked empty dir" and "create a named subfolder").
2. **Own empty-check** (`read_dir`): non-empty → `AppError::VaultFolderNotEmpty { path }`, returned **before** any core call (never string-match core's `Io`).
3. `now_ms()` for `created_at_ms`.
4. `core::vault::orchestrators::create_vault(&folder, password.as_bytes(), &display_name, Argon2idParams::V1_DEFAULT, created_at_ms, &mut OsRng)` — writes the four files atomically, returns `Mnemonic`. Any `VaultError` → `AppError::VaultCreateFailed { detail }` (detail logged, not serialized).
5. Copy the 24-word phrase into `CreateVaultDto { mnemonic }`. The `Mnemonic` then drops (zeroizes phrase + entropy). The `Password` drops (zeroizes) on every return path including errors.

### Backend data shape

```rust
// dtos/create.rs  (Serialize-only, camelCase wire)
struct CreateVaultDto { mnemonic: String }                 // the recovery phrase — widening point
struct CreateTargetProbeDto { exists: bool, is_empty: bool }
```

## 7. Page routes & navigation

`App.svelte` gains a `create` route alongside `unlock` / `unlocked`. The wizard is a small linear stepper within it:

```
folder ──next──▶ credentials ──create()──▶ mnemonic ──acknowledge──▶ Unlock (pre-filled + banner)
   ◀────back────      ◀──(no back past create; vault already written)──
```

- **folder** — `PathPicker` → `probeCreateTarget`. If the picked dir is non-empty, reveal a subfolder-name input ("Create vault in a new subfolder") and compute the final empty target path.
- **credentials** — display name, password, confirm-password (match-gated Continue).
- **mnemonic** — shown only after a successful create (the vault is already on disk). 24 words + copy + "I have written down my recovery phrase" checkbox gating Continue. No "back" past this point — the vault exists.
- **done** — route to `Unlock` with the new path pre-filled and a "Vault created — enter your password to open" banner.

Entry points into `create`: the first-run/empty state, and the actionable "Not a vault" hint from `Unlock` (carries the offending folder as the wizard's initial pick).

## 8. Recovery mnemonic & secret-handling behaviour

| Behaviour | Rule |
|---|---|
| Generation | Inside core (`mnemonic::generate`, 256-bit `OsRng` → 24-word BIP-39); the desktop never generates entropy itself. |
| Display | Shown once on the mnemonic step, in `MnemonicStep.svelte` local `$state` only. Copy button writes to the clipboard (reuses the D.1.2 write-only clipboard capability + the existing auto-clear). |
| Acknowledge gate | Continue is disabled until the "written it down" checkbox is ticked. |
| Drop | On leaving the mnemonic step (acknowledge → route away, or component unmount), the `$state` holding the phrase is dropped; never stored, cached, logged, or placed in any store. |
| Backend wipe | The core `Mnemonic` zeroizes (phrase + entropy) when it drops after the phrase is copied into the DTO. |

## 9. Error model

New `AppError` variants (`#[serde(tag = "code", rename_all = "snake_case")]`, mirroring D.1.1/D.1.2):

| Variant | Wire `code` | When | Frontend message |
|---|---|---|---|
| `VaultFolderNotEmpty { path }` | `vault_folder_not_empty` | `create_vault` target is non-empty (own check, pre-core) | "That folder isn't empty. Choose an empty folder or create a new subfolder." |
| `VaultCreateFailed { detail (skip) }` | `vault_create_failed` | core orchestrator returned a `VaultError` (rare: KDF/serialize/IO) | "Couldn't create the vault. Please try again." |

Typed errors, not silent `None`s — consistent with the no-silent-failure discipline. `detail` stays `#[serde(skip_serializing)]` (logged via `tracing` only). `frontend/errors.ts` adds the two codes to its exhaustive union + `APP_ERROR_CODES`.

## 10. Testing strategy

| Layer | Tool | D.1.3 coverage |
|---|---|---|
| L1 Rust unit | `cargo test` | `secret_arg.rs` `Password` deserialize + zeroize-on-drop; `dtos/create.rs` serde round-trips (camelCase); new error wire codes. |
| L2 TS unit | Vitest | `lib/create.ts` step transitions + pure helpers (password-match, subfolder-join, mnemonic grouping); `FolderStep`/`CredentialsStep`/`MnemonicStep` interaction (probe-driven subfolder offer, confirm-match gating, acknowledge gating); `errors.ts` new codes; `ipc.ts` mocks. |
| L3 Rust integration | `cargo test` (`tests/ipc_integration.rs`) | Over **ephemeral tempdirs** with a **runtime-random password** (`OsRng`): `create_vault_impl` writes the four files; the created vault **re-opens** via `open_vault_with_password` with the same password; `VaultFolderNotEmpty` fires on a non-empty dir; the target dir is created when missing; retrofit `unlock_with_password` still round-trips. |
| L4 e2e | (deferred) | No new e2e; rides on the deferred macOS WebDriver decision (#161). |

Any new test that needs crypto material generates it at runtime (`OsRng`); no hardcoded keys/passwords (CodeQL). No reliance on the golden fixture for create (a created vault is asserted by round-tripping its own freshly-chosen password).

### Expanded gauntlet at D.1.3 close

Same commands as D.1.2's close (`cargo test --release --workspace`, clippy `-D warnings`, fmt, `conformance.py`, `spec_test_name_freshness.py`, `pnpm test / typecheck / svelte-check / lint`). Rust count rises by the new unit + integration tests; Vitest by the new step/logic tests. Counts recorded in the ship handoff.

## 11. Dependencies (additions)

No new Cargo or npm dependencies are anticipated:

- `zeroize` (already a `desktop/src-tauri` dep) backs the `Password` newtype.
- `secretary-core` (already linked) provides the orchestrator, `Argon2idParams`, and `Mnemonic`.
- The clipboard plugin from D.1.2 (write-only) is reused for the mnemonic copy button.

If the `Password` `Deserialize` needs a `serde` helper not already present, it will be a workspace-vetted addition called out in the plan; none is expected.

## 12. UX details

- **Folder step:** `PathPicker` row; after a pick, a probe-driven hint. If empty → "Ready to create here." If non-empty → a subfolder name field + "Create vault in a new subfolder `<name>/`." If non-existent → treated as a fresh path to create.
- **Credentials step:** display-name field; password + confirm-password with an inline "passwords don't match" state; Continue disabled until non-empty + matching.
- **Mnemonic step:** the 24 words in a numbered grid, a copy button (toast "Copied", reusing D.1.1 `Toast`), and a prominent warning that this is the only recovery path; an "I have written down my recovery phrase" checkbox gates Continue.
- **Done → Unlock:** the new path is pre-filled and a "Vault created — enter your password to open" banner shows above the unlock form.
- **Styling:** new classes (`.wizard`, `.wizard-step`, `.mnemonic-grid`, …) in `theme.css` (Vite 6 `preprocessCSS` workaround, #153), reusing existing tokens; dark mode inherits.

## 13. Out of scope for D.1.3

| Deferred | To | Why |
|---|---|---|
| Add/edit records, `save_block` write path | D.1.4 | Mutates an existing manifest + writes blocks; bridge `RecordInput.record_type` gap (#141) matters there. |
| Share / trash / restore | D.1.5 | Needs ContactCard exchange + lifecycle semantics. |
| Auto-open after create | (declined) | Would hold the password for a second derivation; the user opens via the normal flow. |
| Verify-by-re-entry mnemonic confirmation | later | v1 ships display + acknowledge; promote if assurance demands it. |
| Configurable KDF strength / a "strength" UI | (declined) | KDF is hardcoded `V1_DEFAULT`; `WeakKdfParams` is unreachable from the desktop (see Verified non-issue below). |
| Importing / restoring a vault from a mnemonic | later | A distinct recovery flow, not first-run create. |

### Verified non-issue (recorded, won't build for it)

`UnlockError::WeakKdfParams` is **unreachable** from the desktop create path: both core's orchestrator (as called here) and the bridge hardcode `Argon2idParams::V1_DEFAULT` (256 MiB, far above the 64 MiB `V1_MIN_MEMORY_KIB` floor), and the desktop never supplies custom KDF params. No UX or test is built around an error that cannot fire.

### Honest limitation (documented, not silently overclaimed)

The zeroize-typed `Password` boundary guarantees that **our** copy of the password zeroizes on drop. It does **not** guarantee every byte the underlying JSON deserializer touched is wiped — `serde_json`'s internal parse buffer is outside our control. This is a real, bounded improvement over `password: String` (which left a plain heap `String` un-zeroized), not a perfect end-to-end guarantee; the spec records it so the security reviewer isn't misled.

## 14. Broader project implications

- **README.md:** D-row note advances from "D.1.2 (browse) shipped" to "D.1.3 (create) shipped; D.1.4 (edit) next" at ship (brief, per the README style).
- **ROADMAP.md:** mark D.1.3 ✅ at ship; D.1.4 ⏳ next.
- **Security review surface:** the recovery-mnemonic widening point and the zeroize-typed password boundary (incl. the documented limitation) are the items warranting explicit attention in the ship PR.
- **No spec/format change:** D.1.3 consumes the frozen vault format and the existing core create orchestrator unchanged. `crypto-design.md` / `vault-format.md` / `conformance.py` are untouched.
- **Carry-forward closed:** the D.1.1 plain-`String` password boundary is retired in both `create_vault` and `unlock_with_password`.
- **NEXT_SESSION handoff:** authored on the feature branch per the handoff-symlink workflow.

## 15. Acceptance criteria

Mirrors D.1.1 / D.1.2's five categories.

1. **Manual smoke (user, pre-merge gate)** — against a **tempdir** (never the tracked golden fixture): launch → from the empty state (or via the "Not a vault" hint) open the wizard → pick an empty folder (or a non-empty one and accept the subfolder offer) → set display name + password + matching confirm → create → see the 24-word mnemonic → copy + paste elsewhere (matches) → tick acknowledge → land on Unlock with the path pre-filled → unlock with the same password → empty browse view. A second create into the same non-empty folder shows the typed "not empty" message.
2. **Automated gauntlet** — all green: `cargo test --release --workspace`, clippy `-D warnings`, fmt, `conformance.py`, `spec_test_name_freshness.py`, `pnpm test / typecheck / svelte-check / lint`.
3. **L4 e2e** — none added (deferred, #161).
4. **Docs** — README + ROADMAP updated; this spec + the implementation plan committed.
5. **Process** — files < 500 LOC (split where heading over), pure functions in `lib/create.ts` + Rust helpers, no magic numbers (24 / `V1_DEFAULT` come from core), random crypto in any new tests, handoff baton rides inside the ship PR.

## 16. References

- D.1.2 spec — `docs/superpowers/specs/2026-05-29-d12-browse-design.md`
- D.1.1 spec — `docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md`
- ADR 0007 — `docs/adr/0007-d-row-tauri.md` (Sub-project D → Tauri 2)
- Core create orchestrator — `core/src/vault/orchestrators.rs::create_vault` (+ `ensure_empty_directory`)
- Core mnemonic / KDF — `core/src/unlock/mnemonic.rs`, `core/src/crypto/kdf.rs` (`Argon2idParams::V1_DEFAULT`, `V1_MIN_MEMORY_KIB`)
- Bridge create surface (not used here; bytes-only) — `ffi/secretary-ffi-bridge/src/create.rs`
- D.1.1/D.1.2 IPC/DTO/error patterns — `desktop/src-tauri/src/{commands,dtos,errors.rs,session.rs}`
- "Not a vault" hint hook — `desktop/src/lib/errors.ts` (`vault_path_not_a_vault`), `desktop/src/routes/Unlock.svelte`
