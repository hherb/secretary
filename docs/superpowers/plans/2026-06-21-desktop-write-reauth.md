# Desktop password re-auth before a write — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate every mutating desktop vault write behind a password re-entry, throttled by a user-configurable grace window, opt-in (default on).

**Architecture:** A pure `needsReauth` policy function + an injected frontend `writeGuard` drive a shared password-prompt modal; the modal's submitted password is verified by a new Rust `verify_password` command that re-runs `open_vault_with_password` and discards the handle. Two new persisted settings (`require_password_before_edits`, `reauth_grace_window_ms`) control the gate. The gate lives in the host-testable frontend layer, mirroring the iOS VM-level injection (#275).

**Tech Stack:** Rust (Tauri 2 backend, `cargo test`), TypeScript/Svelte 5 (frontend, `vitest`), `pnpm` (NOT npm), `secretary-ffi-bridge` (`open_vault_with_password`).

## Global Constraints

- **No `core/`, crypto-design, vault-format, `*.udl`, `secretary-ffi-py`, `ios/`, or `android/` changes.** This slice is `desktop/`-only. `desktop/src-tauri/*.rs` changes ARE expected (verify command + settings schema) — guardrails are NOT empty here, unlike the iOS slices.
- **No new crypto.** Password verification reuses `secretary_ffi_bridge::vault::open_vault_with_password` verbatim and drops the handle.
- **No magic numbers.** Every timeout/bound/default is a named constant in `desktop/src-tauri/src/constants.rs` (Rust) and `desktop/src/lib/constants.ts` (TS); Rust↔TS shared values are changed together (existing convention, see `ACTIVITY_NOTIFY_MIN_INTERVAL_MS`).
- **Reuse existing `AppError` variants.** Wrong re-auth password → `AppError::WrongPassword` (decryption-failure collapse already does this in `From<FfiVaultError>`); verify-while-locked → `AppError::NotUnlocked`. **No new `AppError` variant, no `errors.ts` change** ([[project_secretary_ffivaulterror_workspace_match]] does not apply).
- **Settings record stays `secretary.settings.v1`.** Extended to multi-field; missing new fields default; unknown extra fields warn (not error) for forward-compat.
- **pnpm only** for the desktop frontend ([[project_secretary_desktop_uses_pnpm]]). Run `pnpm svelte-check` after editing any `.svelte` ([[project_secretary_svelte_smartquote_svelte_check]]).
- **Tests use random crypto values, never hardcoded** ([[feedback_test_crypto_random_not_hardcoded]]); KAT-style fixtures only via JSON. Vault tests run against a `cp -R` **temp copy** of `core/tests/data/golden_vault_001/`, never the tracked fixture ([[feedback_smoke_test_temp_copy_golden_vault]]).
- **Files under ~500 lines**; split when a module grows past that ([[feedback_split_files_proactively]]).
- **Commit after every green step.** TDD: failing test → minimal impl → green → commit.

**Working directory:** `/Users/hherb/src/secretary/.worktrees/desktop-write-reauth` on branch `feature/desktop-write-reauth`. Verify with `pwd && git branch --show-current` before any `cargo`/`git`/`pnpm` call.

**Test commands:**
- Rust: `cargo test --release --workspace` ; lint `cargo clippy --release --workspace --tests -- -D warnings` ; format `cargo fmt --all`.
- Frontend: `cd desktop && pnpm test` (vitest) ; `pnpm lint` ; `pnpm svelte-check`.

---

## File Structure

**Rust (`desktop/src-tauri/src/`):**
- `constants.rs` — MODIFY: add reauth constants + 2 settings field-name constants.
- `settings/parse.rs` — MODIFY: extend `Settings`, multi-field parse/serialize/validate.
- `settings/io.rs` — MODIFY: `load_from_vault` reads multi-field record; `save_to_vault` writes 3 fields.
- `dtos/manifest.rs` — MODIFY: add 2 fields to `SettingsDto` + `SettingsInput` + `From` impls + serde tests.
- `commands/reauth.rs` — CREATE: `verify_password` command + `verify_password_impl`.
- `commands/mod.rs` — MODIFY: `pub mod reauth;`.
- `lib.rs` — MODIFY: register `verify_password` in the invoke handler.
- `session.rs` — MODIFY: add a `vault_folder()` accessor (read-only) used by `verify_password_impl`.
- `tests/ipc_integration.rs` — MODIFY: add verify_password integration tests.

**Frontend (`desktop/src/`):**
- `lib/constants.ts` — MODIFY: add `REAUTH_*` + reuse `MS_PER_MINUTE`.
- `lib/reauth.ts` — CREATE: pure `needsReauth`.
- `lib/writeGuard.ts` — CREATE: `authorizeWrite`, guard state, `ReauthCancelled`, `resetReauthGuard`.
- `lib/stores.ts` — MODIFY: add the `reauthPrompt` writable + helpers.
- `lib/ipc.ts` — MODIFY: extend `SettingsDto`/`SettingsInput` TS types + `verifyPassword` wrapper.
- `components/ReauthPasswordDialog.svelte` — CREATE: the prompt modal.
- `components/SettingsDialog.svelte` — MODIFY: add toggle + grace-window field.
- `routes/Vault.svelte` (+ write handler components) — MODIFY: insert `await authorizeWrite(reason)` before each gated write; mount `ReauthPasswordDialog`.

**Tests (`desktop/tests/`):** new `reauth.test.ts`, `writeGuard.test.ts`, `ReauthPasswordDialog.test.ts`; modify `SettingsDialog.test.ts`, `ipc.test.ts`, and each gated handler's existing test.

---

## Task 1: Reauth + settings-field constants (Rust)

**Files:**
- Modify: `desktop/src-tauri/src/constants.rs`
- Test: same file (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `REAUTH_WINDOW_DEFAULT_MS: u64`, `REAUTH_WINDOW_MIN_MS: u64`, `REAUTH_WINDOW_MAX_MS: u64`, `REQUIRE_PASSWORD_DEFAULT: bool`, `SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS: &str`, `SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS: &str`.

- [ ] **Step 1: Write the failing test** — append to `constants.rs` `mod tests`:

```rust
#[test]
fn reauth_window_bounds_are_ordered() {
    const _: () = assert!(REAUTH_WINDOW_MIN_MS < REAUTH_WINDOW_DEFAULT_MS);
    const _: () = assert!(REAUTH_WINDOW_DEFAULT_MS < REAUTH_WINDOW_MAX_MS);
}

#[test]
fn reauth_default_is_two_minutes() {
    const TWO_MINUTES_MS: u64 = 2 * 60 * 1_000;
    assert_eq!(REAUTH_WINDOW_DEFAULT_MS, TWO_MINUTES_MS);
}

#[test]
fn reauth_field_names_are_snake_case_and_distinct() {
    assert_eq!(SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS, "require_password_before_edits");
    assert_eq!(SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS, "reauth_grace_window_ms");
    assert_ne!(
        SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
        SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-desktop constants:: 2>&1 | tail -20`
(If the desktop crate name differs, use `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml constants::`.)
Expected: FAIL — `cannot find value REAUTH_WINDOW_DEFAULT_MS`.

- [ ] **Step 3: Write minimal implementation** — add to `constants.rs` after the auto-lock section:

```rust
// =============================================================================
// Write re-auth (password re-entry before a mutating write)
// =============================================================================

/// Default grace window for write re-auth, in milliseconds. One successful
/// password re-entry covers all mutating writes within this window before the
/// next prompt.
///
/// **Value:** 120_000 (2 minutes).
/// **Rationale:** Long enough that a normal editing burst costs one prompt,
/// short enough to bound exposure on an unattended-but-unlocked machine. The
/// verify runs a full Argon2id (m=256 MiB, t=3); this window amortises it.
/// User-configurable (Settings dialog) — "Secretary enables maximum security;
/// the user decides what is necessary."
pub const REAUTH_WINDOW_DEFAULT_MS: u64 = 120_000;

/// Lower bound for `reauth_grace_window_ms` validation.
///
/// **Value:** 0. Zero means "re-auth before EVERY mutating write" — a valid
/// maximum-security choice. The frontend offers it explicitly.
pub const REAUTH_WINDOW_MIN_MS: u64 = 0;

/// Upper bound for `reauth_grace_window_ms` validation.
///
/// **Value:** 3_600_000 (1 hour). Beyond an hour the gate adds little over
/// auto-lock; we won't ship a larger configurable value.
pub const REAUTH_WINDOW_MAX_MS: u64 = 3_600_000;

/// Default for `require_password_before_edits`.
///
/// **Value:** true (secure by default; user may disable).
pub const REQUIRE_PASSWORD_DEFAULT: bool = true;

/// Settings field name: the on/off toggle for write re-auth.
pub const SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS: &str = "require_password_before_edits";

/// Settings field name: the grace window in milliseconds.
pub const SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS: &str = "reauth_grace_window_ms";
```

> Note: `REAUTH_WINDOW_MIN_MS == 0` means `reauth_window_bounds_are_ordered`'s first `assert!` (`MIN < DEFAULT`) holds (`0 < 120_000`). Good.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml constants:: 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri/src/constants.rs
git commit -m "feat(desktop): reauth + settings-field constants"
```

---

## Task 2: Multi-field settings schema (`parse.rs`)

**Files:**
- Modify: `desktop/src-tauri/src/settings/parse.rs`
- Test: same file (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: Task 1 constants.
- Produces:
  - `Settings { auto_lock_timeout_ms: u64, require_password_before_edits: bool, reauth_grace_window_ms: u64 }`.
  - `parse_settings_fields(record_type: &str, fields: &[(String, String)]) -> ParseResult` (replaces the single-field `parse_settings_field`).
  - `serialize_settings(&Settings) -> Vec<(String, String, String)>` returning `(record_type, field_name, field_value_text)` triples — one per field; the record_type is identical across triples (the first element of each is `SETTINGS_RECORD_TYPE`). *(Signature change from the old single-triple return.)*
  - `validate_save_settings(&Settings) -> Result<(), AppError>` (replaces the value-only `validate_save_value`; validates auto-lock AND window bounds).

> **Design note (record_type stays v1):** A record missing the two new fields (older client) loads them as defaults with no error. An unknown *extra* field name produces a `SettingsClamped`-style warning, NOT an error, so a future-client write doesn't break this client. The auto-lock clamp-on-load behaviour is preserved per-field.

- [ ] **Step 1: Write the failing tests** — replace the existing `mod tests` body's relevant cases and ADD these (keep the auto-lock clamp/parse tests, updating call sites to the new `parse_settings_fields`/`serialize_settings` signatures):

```rust
use crate::constants::{
    REAUTH_WINDOW_DEFAULT_MS, REAUTH_WINDOW_MAX_MS, REQUIRE_PASSWORD_DEFAULT,
    SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS, SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS,
    SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS, SETTINGS_RECORD_TYPE,
};

#[test]
fn default_includes_reauth_fields() {
    let d = Settings::default();
    assert_eq!(d.require_password_before_edits, REQUIRE_PASSWORD_DEFAULT);
    assert_eq!(d.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
}

#[test]
fn parse_all_three_fields_round_trips() {
    let original = Settings {
        auto_lock_timeout_ms: 900_000,
        require_password_before_edits: false,
        reauth_grace_window_ms: 30_000,
    };
    let triples = serialize_settings(&original);
    let fields: Vec<(String, String)> = triples
        .iter()
        .map(|(_, name, value)| (name.clone(), value.clone()))
        .collect();
    let record_type = &triples[0].0;
    let (parsed, warnings) = parse_settings_fields(record_type, &fields).expect("parse");
    assert_eq!(parsed, original);
    assert!(warnings.is_empty());
}

#[test]
fn parse_missing_new_fields_defaults_them_no_warning() {
    // Older-client record: only the auto-lock field present.
    let fields = vec![(
        SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
        "600000".to_string(),
    )];
    let (parsed, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
    assert_eq!(parsed.auto_lock_timeout_ms, 600_000);
    assert_eq!(parsed.require_password_before_edits, REQUIRE_PASSWORD_DEFAULT);
    assert_eq!(parsed.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
    assert!(warnings.is_empty(), "missing-but-defaulted fields are not a warning");
}

#[test]
fn parse_unknown_extra_field_warns_not_errors() {
    let fields = vec![
        (SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(), "600000".to_string()),
        ("some_future_field".to_string(), "x".to_string()),
    ];
    let (parsed, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields)
        .expect("unknown field must not be a hard error");
    assert_eq!(parsed.auto_lock_timeout_ms, 600_000);
    assert_eq!(warnings.len(), 1);
    matches!(warnings[0], AppWarning::SettingsCorrupt { .. });
}

#[test]
fn parse_window_above_max_clamps_with_warning() {
    let fields = vec![
        (SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(), "600000".to_string()),
        (
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS.to_string(),
            (REAUTH_WINDOW_MAX_MS + 1).to_string(),
        ),
    ];
    let (parsed, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
    assert_eq!(parsed.reauth_grace_window_ms, REAUTH_WINDOW_MAX_MS);
    assert_eq!(warnings.len(), 1);
}

#[test]
fn parse_require_password_accepts_bool_text() {
    for (text, expected) in [("true", true), ("false", false)] {
        let fields = vec![
            (SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(), "600000".to_string()),
            (
                SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS.to_string(),
                text.to_string(),
            ),
        ];
        let (parsed, _) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(parsed.require_password_before_edits, expected);
    }
}

#[test]
fn validate_save_rejects_window_above_max() {
    let s = Settings {
        auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
        require_password_before_edits: true,
        reauth_grace_window_ms: REAUTH_WINDOW_MAX_MS + 1,
    };
    let err = validate_save_settings(&s).expect_err("must reject");
    matches!(err, AppError::SettingsOutOfRange { .. });
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml settings::parse 2>&1 | tail -30`
Expected: FAIL — struct field/function-signature mismatch.

- [ ] **Step 3: Write the implementation** — rewrite `parse.rs`'s non-test body:

```rust
use crate::constants::{
    AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS, REAUTH_WINDOW_DEFAULT_MS,
    REAUTH_WINDOW_MAX_MS, REAUTH_WINDOW_MIN_MS, REQUIRE_PASSWORD_DEFAULT,
    SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS, SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS,
    SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS, SETTINGS_RECORD_TYPE,
};
use crate::errors::{AppError, AppWarning};

/// Parsed app settings — pure value type, no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
            require_password_before_edits: REQUIRE_PASSWORD_DEFAULT,
            reauth_grace_window_ms: REAUTH_WINDOW_DEFAULT_MS,
        }
    }
}

pub type ParseResult = Result<(Settings, Vec<AppWarning>), AppError>;

/// Parse a settings record's `(field_name, field_value_text)` list into a
/// `Settings`. Unknown record_type → `SettingsUnknownVersion`. Missing known
/// fields fall back to `Settings::default()` values with no warning. An
/// unknown *extra* field name produces a non-fatal `SettingsCorrupt` warning
/// (forward-compat: a newer client's extra field must not break this client).
/// Numeric fields clamp-on-load with a `SettingsClamped` warning.
pub fn parse_settings_fields(record_type: &str, fields: &[(String, String)]) -> ParseResult {
    if record_type != SETTINGS_RECORD_TYPE {
        return Err(AppError::SettingsUnknownVersion {
            version: record_type.to_string(),
        });
    }

    let mut settings = Settings::default();
    let mut warnings = Vec::new();

    for (name, value) in fields {
        match name.as_str() {
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS => {
                let raw: u64 = value.parse().map_err(|e| AppError::SettingsCorrupt {
                    detail: format!("auto_lock_timeout_ms parse failure: {e}"),
                })?;
                let (v, mut w) = clamp_ms_with_warning(raw, AUTO_LOCK_MIN_MS, AUTO_LOCK_MAX_MS);
                settings.auto_lock_timeout_ms = v;
                warnings.append(&mut w);
            }
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS => {
                let raw: u64 = value.parse().map_err(|e| AppError::SettingsCorrupt {
                    detail: format!("reauth_grace_window_ms parse failure: {e}"),
                })?;
                let (v, mut w) =
                    clamp_ms_with_warning(raw, REAUTH_WINDOW_MIN_MS, REAUTH_WINDOW_MAX_MS);
                settings.reauth_grace_window_ms = v;
                warnings.append(&mut w);
            }
            SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS => {
                settings.require_password_before_edits =
                    value.parse().map_err(|e| AppError::SettingsCorrupt {
                        detail: format!("require_password_before_edits parse failure: {e}"),
                    })?;
            }
            other => {
                // Forward-compat: a field this build doesn't know about is a
                // warning, not a hard error — a newer client may have written
                // it, and we must still load the fields we DO understand.
                warnings.push(AppWarning::SettingsCorrupt {
                    detail: format!("unknown settings field ignored: {other}"),
                });
            }
        }
    }

    Ok((settings, warnings))
}

/// Clamp a millisecond value into `[min, max]`, emitting a `SettingsClamped`
/// warning when clamped. Load-path only — the save path rejects out-of-range
/// rather than clamping (see `validate_save_settings`).
fn clamp_ms_with_warning(value: u64, min: u64, max: u64) -> (u64, Vec<AppWarning>) {
    if value < min {
        (min, vec![AppWarning::SettingsClamped { original_ms: value, clamped_ms: min }])
    } else if value > max {
        (max, vec![AppWarning::SettingsClamped { original_ms: value, clamped_ms: max }])
    } else {
        (value, vec![])
    }
}

/// Validate settings before saving (frontend-supplied path). Rejects
/// out-of-range numeric values with `SettingsOutOfRange` rather than clamping
/// — the dialog also validates client-side; this catches adversarial IPC.
pub fn validate_save_settings(s: &Settings) -> Result<(), AppError> {
    if !(AUTO_LOCK_MIN_MS..=AUTO_LOCK_MAX_MS).contains(&s.auto_lock_timeout_ms) {
        return Err(AppError::SettingsOutOfRange { min: AUTO_LOCK_MIN_MS, max: AUTO_LOCK_MAX_MS });
    }
    if !(REAUTH_WINDOW_MIN_MS..=REAUTH_WINDOW_MAX_MS).contains(&s.reauth_grace_window_ms) {
        return Err(AppError::SettingsOutOfRange {
            min: REAUTH_WINDOW_MIN_MS,
            max: REAUTH_WINDOW_MAX_MS,
        });
    }
    Ok(())
}

/// Serialize a `Settings` into one `(record_type, field_name, field_value_text)`
/// triple per field. All triples share `SETTINGS_RECORD_TYPE` as element 0.
pub fn serialize_settings(s: &Settings) -> Vec<(String, String, String)> {
    vec![
        (
            SETTINGS_RECORD_TYPE.to_string(),
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            s.auto_lock_timeout_ms.to_string(),
        ),
        (
            SETTINGS_RECORD_TYPE.to_string(),
            SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS.to_string(),
            s.require_password_before_edits.to_string(),
        ),
        (
            SETTINGS_RECORD_TYPE.to_string(),
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS.to_string(),
            s.reauth_grace_window_ms.to_string(),
        ),
    ]
}
```

> Update the pre-existing auto-lock tests in this file to the new signatures: `parse_settings_field(rt, name, value)` → `parse_settings_fields(rt, &[(name.into(), value.into())])`; `serialize_settings` now returns a `Vec` (index `[0]` for the auto-lock triple in round-trip assertions). `validate_save_value(v)` → `validate_save_settings(&Settings { auto_lock_timeout_ms: v, ..Default::default() })`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml settings::parse 2>&1 | tail -30`
Expected: PASS (all old + new).

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri/src/settings/parse.rs
git commit -m "feat(desktop): multi-field settings schema (reauth toggle + window)"
```

---

## Task 3: Settings vault I/O for the multi-field record (`io.rs`)

**Files:**
- Modify: `desktop/src-tauri/src/settings/io.rs`
- Test: same file + existing integration coverage

**Interfaces:**
- Consumes: Task 2 `parse_settings_fields`, `serialize_settings`, `validate_save_settings`.
- Produces: unchanged public signatures `load_from_vault`, `save_to_vault`.

- [ ] **Step 1: Write the failing test** — add to `io.rs` `mod tests` (uses the bridge + a temp golden-vault copy via a helper; if the file already has an integration-style helper, reuse it; otherwise this lives in `tests/ipc_integration.rs` — see note):

```rust
// In tests/ipc_integration.rs (has access to the golden vault + an unlocked
// session helper). Pseudocode shape — adapt to the file's existing harness:
//
// 1. cp -R golden_vault into a tempdir; unlock it.
// 2. save_to_vault(identity, manifest, device_uuid, &Settings {
//        auto_lock_timeout_ms: 600_000,
//        require_password_before_edits: false,
//        reauth_grace_window_ms: 30_000,
//    }).unwrap();
// 3. let (loaded, warnings) = load_from_vault(identity, manifest).unwrap();
// 4. assert_eq!(loaded.require_password_before_edits, false);
//    assert_eq!(loaded.reauth_grace_window_ms, 30_000);
//    assert!(warnings.is_empty());
```

> If `io.rs` has no live-vault unit tests today (it doesn't — its tests cover device-UUID only), put the round-trip in `tests/ipc_integration.rs` next to the existing settings integration tests. Find them with `grep -n "load_from_vault\|save_to_vault\|set_settings_impl" desktop/src-tauri/tests/ipc_integration.rs`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml --test ipc_integration settings 2>&1 | tail -30`
Expected: FAIL — compile error (multi-field record not written/read yet) or assertion failure.

- [ ] **Step 3: Implement** — update `load_from_vault` and `save_to_vault`:

In `load_from_vault`, replace the rigid `field_count() != 1` single-field block with a loop that collects **all** text fields into a `Vec<(String, String)>`, then calls `parse_settings_fields`:

```rust
    // Collect every text field of the (single) settings record into
    // (name, text) pairs. A non-text or payload-missing field is skipped
    // with a warning (same lenient posture as the old single-field path).
    let mut field_pairs: Vec<(String, String)> = Vec::new();
    let mut shape_warnings: Vec<AppWarning> = Vec::new();
    for i in 0..record.field_count() {
        let field = record.field_at(i).expect("i < field_count ⇒ Some");
        if !field.is_text() {
            shape_warnings.push(AppWarning::SettingsCorrupt {
                detail: format!("settings field '{}' is not text-typed", field.name()),
            });
            continue;
        }
        let Some(text) = field.expose_text() else {
            shape_warnings.push(AppWarning::SettingsCorrupt {
                detail: "settings field text payload missing".to_string(),
            });
            continue;
        };
        field_pairs.push((field.name(), text));
    }

    let effective_record_type = if record.record_type().is_empty() {
        SETTINGS_RECORD_TYPE
    } else {
        record.record_type()
    };
    // record_type() returns String; bind to a local to satisfy the borrow.
    let rt = effective_record_type.to_string();

    let (settings, mut parse_warnings) = parse_settings_fields(&rt, &field_pairs)?;
    let mut warnings = shape_warnings;
    warnings.append(&mut parse_warnings);
    Ok((settings, warnings))
```

> Keep the `record_count() != 1` guard (a settings block still holds exactly one record). Remove only the `field_count() != 1` rigid check. Update the `use` to import `parse_settings_fields` instead of `parse_settings_field`.

In `save_to_vault`, replace the single-`FieldInput` construction with one per serialized triple, and swap the validator:

```rust
    validate_save_settings(new_settings)?;

    let block_uuid = find_settings_block_uuid(manifest)
        .unwrap_or_else(|| deterministic_uuid_16(SETTINGS_BLOCK_NAME));
    let record_uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE);

    let triples = serialize_settings(new_settings);
    let record_type = triples[0].0.clone();
    let fields: Vec<FieldInput> = triples
        .into_iter()
        .map(|(_, name, value_text)| FieldInput {
            name,
            value: FieldInputValue::Text(SecretString::from(value_text)),
        })
        .collect();

    let block_input = BlockInput {
        block_uuid,
        block_name: SETTINGS_BLOCK_NAME.to_string(),
        records: vec![RecordInput {
            record_uuid,
            record_type,
            tags: Vec::new(),
            fields,
        }],
    };

    save_block(identity, manifest, block_input, device_uuid, now_ms()).map_err(AppError::from)?;
    Ok(())
```

Update imports: `use super::parse::{parse_settings_fields, serialize_settings, validate_save_settings, Settings};`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml --test ipc_integration settings 2>&1 | tail -30`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri/src/settings/io.rs desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(desktop): round-trip multi-field settings through the vault"
```

---

## Task 4: Settings DTO fields (`dtos/manifest.rs`)

**Files:**
- Modify: `desktop/src-tauri/src/dtos/manifest.rs`
- Test: same file (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `SettingsDto` + `SettingsInput` each gain `require_password_before_edits: bool` and `reauth_grace_window_ms: u64`; serde camelCase (`requirePasswordBeforeEdits`, `reauthGraceWindowMs`).

- [ ] **Step 1: Write the failing test** — add to `dtos/manifest.rs` `mod tests`:

```rust
#[test]
fn settings_dto_serializes_reauth_fields_camel_case() {
    let dto = SettingsDto::from(&Settings {
        auto_lock_timeout_ms: 600_000,
        require_password_before_edits: true,
        reauth_grace_window_ms: 120_000,
    });
    let v = serde_json::to_value(&dto).expect("serialize");
    assert_eq!(v["requirePasswordBeforeEdits"], true);
    assert_eq!(v["reauthGraceWindowMs"], 120_000_u64);
}

#[test]
fn settings_input_deserializes_reauth_fields() {
    let input: SettingsInput = serde_json::from_str(
        r#"{"autoLockTimeoutMs":600000,"requirePasswordBeforeEdits":false,"reauthGraceWindowMs":30000}"#,
    )
    .expect("deserialize");
    let settings = Settings::from(&input);
    assert!(!settings.require_password_before_edits);
    assert_eq!(settings.reauth_grace_window_ms, 30_000);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml dtos::manifest 2>&1 | tail -20`
Expected: FAIL — unknown field / missing struct member.

- [ ] **Step 3: Implement** — add the two fields to both structs and their `From` impls (mirror the existing `auto_lock_timeout_ms` lines at `manifest.rs:76`, `:82`, `:97`, `:103`). Both structs already use `#[serde(rename_all = "camelCase")]`; just add:

```rust
// in struct SettingsDto:
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
// in impl From<&Settings> for SettingsDto:
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
// in struct SettingsInput:
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
// in impl From<&SettingsInput> for Settings:
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml dtos::manifest 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri/src/dtos/manifest.rs
git commit -m "feat(desktop): SettingsDto/SettingsInput carry reauth fields"
```

---

## Task 5: `verify_password` command (`commands/reauth.rs`)

**Files:**
- Create: `desktop/src-tauri/src/commands/reauth.rs`
- Modify: `desktop/src-tauri/src/commands/mod.rs` (add `pub mod reauth;`), `desktop/src-tauri/src/lib.rs` (register in `tauri::generate_handler!`), `desktop/src-tauri/src/session.rs` (add `vault_folder()` accessor)
- Test: `commands/reauth.rs` `mod tests` + `tests/ipc_integration.rs`

**Interfaces:**
- Consumes: `secretary_ffi_bridge::vault::open_vault_with_password`, `VaultSession`, `crate::secret_arg::Password`, `crate::commands::shared::lock_session`.
- Produces: `#[tauri::command] async fn verify_password(state, password: Password) -> Result<(), AppError>`; `fn verify_password_impl(state: &Mutex<VaultSession>, password: &[u8]) -> Result<(), AppError>`; `VaultSession::vault_folder(&self) -> Option<PathBuf>`.

> **Verified:** `open_vault` takes NO exclusive file lock (the only `LockfileGuard` is in the sync path), so a second open against the same folder while a session is live is an independent read+decrypt — no lock conflict. The integration test below pins this by verifying while a session is unlocked.

- [ ] **Step 1: Add the `vault_folder()` accessor to `session.rs`** (no test of its own; covered by Task 5's impl test). After `current_settings`:

```rust
    /// Absolute folder the current vault was opened from, or `None` if locked.
    /// Used by `verify_password` to re-run `open_vault_with_password` against
    /// the same folder for write re-auth.
    pub fn vault_folder(&self) -> Option<std::path::PathBuf> {
        self.inner.as_ref().map(|u| u.vault_folder.clone())
    }
```

- [ ] **Step 2: Write the failing test** — create `commands/reauth.rs` with only the test module first (so it fails to compile against the missing impl):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::VaultSession;
    use std::sync::Mutex;

    /// cp -R the golden vault into a tempdir and return (tempdir, folder).
    /// Mirrors the helper used in tests/ipc_integration.rs; if a shared
    /// helper exists there, prefer exposing/reusing it.
    fn temp_golden_vault() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let dst = dir.path().join("vault");
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/../../core/tests/data/golden_vault_001");
        // Recursive copy (small fixture). Use a tiny copy helper or fs walk.
        copy_dir_recursive(std::path::Path::new(src), &dst).expect("copy golden vault");
        (dir, dst)
    }

    fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let path = entry.path();
            let target = dst.join(entry.file_name());
            if path.is_dir() {
                copy_dir_recursive(&path, &target)?;
            } else {
                std::fs::copy(&path, &target)?;
            }
        }
        Ok(())
    }

    // The golden vault's password — sourced the SAME way the existing
    // ipc_integration tests source it (grep for GOLDEN_VAULT_PASSWORD or a
    // similar const in tests/ipc_integration.rs and reuse it).
    const GOLDEN_PASSWORD: &str = "correct horse battery staple"; // PLACEHOLDER — replace with the real fixture password constant found in tests/ipc_integration.rs

    fn unlocked_session(folder: &std::path::Path) -> Mutex<VaultSession> {
        let data_dir = tempfile::tempdir().expect("data dir").keep();
        let session = VaultSession::new(data_dir);
        let mutex = Mutex::new(session);
        mutex
            .lock()
            .unwrap()
            .unlock(folder, GOLDEN_PASSWORD.as_bytes())
            .expect("unlock golden vault");
        mutex
    }

    #[test]
    fn verify_correct_password_while_unlocked_ok() {
        let (_dir, folder) = temp_golden_vault();
        let state = unlocked_session(&folder);
        // A second open against the same folder while the session is live
        // must succeed — proves there is no exclusive-lock conflict.
        verify_password_impl(&state, GOLDEN_PASSWORD.as_bytes()).expect("correct password verifies");
    }

    #[test]
    fn verify_wrong_password_is_wrong_password_error() {
        let (_dir, folder) = temp_golden_vault();
        let state = unlocked_session(&folder);
        let err = verify_password_impl(&state, b"not the password").expect_err("must reject");
        assert!(matches!(err, AppError::WrongPassword), "got {err:?}");
    }

    #[test]
    fn verify_while_locked_is_not_unlocked() {
        let data_dir = tempfile::tempdir().expect("data dir").keep();
        let state = Mutex::new(VaultSession::new(data_dir));
        let err = verify_password_impl(&state, b"whatever").expect_err("locked must reject");
        assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
    }
}
```

> **Before running:** replace `GOLDEN_PASSWORD` with the real constant. Run `grep -rn "password\|PASSWORD" desktop/src-tauri/tests/ipc_integration.rs | head` to find how the existing tests unlock the golden vault, and reuse that exact value/constant.

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml commands::reauth 2>&1 | tail -30`
Expected: FAIL — `verify_password_impl` not found.

- [ ] **Step 4: Implement** — prepend the non-test body to `commands/reauth.rs`:

```rust
//! `verify_password` command — write re-auth presence proof.
//!
//! Re-runs `open_vault_with_password` against the currently-open vault's
//! folder and immediately drops the handle. Returns `Ok(())` if the password
//! opens the vault, `AppError::WrongPassword` if not (the bridge's
//! decryption-failure collapse already maps to that), `AppError::NotUnlocked`
//! if no vault is open. No new crypto: this is the same authoritative check
//! the unlock path performs. The transient handle's `Drop` runs the bridge's
//! zeroize-on-drop discipline.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::vault::open_vault_with_password;

use crate::commands::shared::lock_session;
use crate::errors::AppError;
use crate::secret_arg::Password;
use crate::session::VaultSession;

/// Tauri entry point. Thin shell; logic in [`verify_password_impl`].
/// `password.expose()` feeds the `&[u8]` impl; `Password` zeroizes on return.
#[tauri::command]
pub async fn verify_password(
    state: State<'_, Mutex<VaultSession>>,
    password: Password,
) -> Result<(), AppError> {
    verify_password_impl(state.inner(), password.expose())
}

/// Testable core. Resolves the open vault's folder (NotUnlocked if locked),
/// then re-opens it with the supplied password and drops the handle.
pub fn verify_password_impl(
    state: &Mutex<VaultSession>,
    password: &[u8],
) -> Result<(), AppError> {
    let folder = {
        let session = lock_session(state)?;
        session.vault_folder().ok_or(AppError::NotUnlocked)?
    }; // release the session mutex BEFORE the ~1-2s Argon2id, so a write/lock
       // on another thread isn't blocked for the duration of the verify.

    // open_vault_with_password performs the full Argon2id + unlock + manifest
    // verify. We discard the handles — a successful open IS the proof. The
    // bridge's From<FfiVaultError> collapses any decryption failure to
    // AppError::WrongPassword (threat-model §13 info-leak prevention).
    let _handle = open_vault_with_password(&folder, password).map_err(AppError::from)?;
    Ok(())
    // _handle drops here → bridge zeroize-on-drop wipes identity + manifest.
}
```

- [ ] **Step 5: Register the command** — in `commands/mod.rs` add `pub mod reauth;` (alphabetical, before `settings`). In `lib.rs`, add `commands::reauth::verify_password` to the `tauri::generate_handler![...]` list (find it: `grep -n "generate_handler" desktop/src-tauri/src/lib.rs`).

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test --release --manifest-path desktop/src-tauri/Cargo.toml commands::reauth 2>&1 | tail -30`
Expected: PASS (3 tests).

- [ ] **Step 7: Full backend gate**

Run: `cargo test --release --workspace 2>&1 | tail -15 && cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5 && cargo fmt --all`
Expected: all green, no warnings.

- [ ] **Step 8: Commit**

```bash
git add desktop/src-tauri/src/commands/reauth.rs desktop/src-tauri/src/commands/mod.rs \
        desktop/src-tauri/src/lib.rs desktop/src-tauri/src/session.rs \
        desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(desktop): verify_password command for write re-auth"
```

---

## Task 6: Pure `needsReauth` + TS constants

**Files:**
- Modify: `desktop/src/lib/constants.ts`
- Create: `desktop/src/lib/reauth.ts`
- Test: `desktop/tests/reauth.test.ts`

**Interfaces:**
- Produces: `REAUTH_WINDOW_DEFAULT_MS`, `REAUTH_WINDOW_MIN_MS`, `REAUTH_WINDOW_MAX_MS` (TS, matching the Rust constants); `needsReauth(opts: { enabled: boolean; lastAuthAtMs: number | null; nowMs: number; windowMs: number }): boolean`.

- [ ] **Step 1: Write the failing test** — `desktop/tests/reauth.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { needsReauth } from '../src/lib/reauth';

describe('needsReauth', () => {
  it('returns false when disabled regardless of clock', () => {
    expect(needsReauth({ enabled: false, lastAuthAtMs: null, nowMs: 0, windowMs: 0 })).toBe(false);
    expect(needsReauth({ enabled: false, lastAuthAtMs: 0, nowMs: 9e9, windowMs: 1000 })).toBe(false);
  });

  it('returns true when never authed this session', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: null, nowMs: 5000, windowMs: 1000 })).toBe(true);
  });

  it('returns false within the grace window', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: 1000, nowMs: 1500, windowMs: 1000 })).toBe(false);
  });

  it('returns true at exactly the window boundary (>=)', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: 1000, nowMs: 2000, windowMs: 1000 })).toBe(true);
  });

  it('returns true past the window', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: 1000, nowMs: 5000, windowMs: 1000 })).toBe(true);
  });

  it('windowMs of 0 always prompts when enabled (every write)', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: 1000, nowMs: 1000, windowMs: 0 })).toBe(true);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test reauth 2>&1 | tail -20`
Expected: FAIL — cannot resolve `../src/lib/reauth`.

- [ ] **Step 3: Implement** — add to `desktop/src/lib/constants.ts` (mirror the Rust values; add the cross-ref comment):

```ts
// Write re-auth grace window (password re-entry before a mutating write).
// Mirror of desktop/src-tauri/src/constants.rs REAUTH_WINDOW_* — change both.
export const REAUTH_WINDOW_DEFAULT_MS = 120_000;
export const REAUTH_WINDOW_MIN_MS = 0;
export const REAUTH_WINDOW_MAX_MS = 3_600_000;
```

Create `desktop/src/lib/reauth.ts`:

```ts
// Pure write-reauth policy. The ENTIRE grace-window decision lives here so it
// is host-testable (vitest) with zero I/O — mirrors the iOS `needsReauth`
// pure function (#275). The stateful gate (lastAuthAt, the prompt, the verify
// IPC) lives in writeGuard.ts; this module decides only "prompt or not".

export interface NeedsReauthOpts {
  /** The `require_password_before_edits` setting. */
  enabled: boolean;
  /** Wall-clock ms of the last successful auth this session, or null if none. */
  lastAuthAtMs: number | null;
  /** Current wall-clock ms. */
  nowMs: number;
  /** The configured grace window in ms. */
  windowMs: number;
}

/**
 * True when a mutating write must prompt for the password first.
 *
 * - disabled            → false (gate off)
 * - never authed (null) → true
 * - elapsed >= window   → true  (boundary inclusive)
 * - else                → false (inside grace)
 */
export function needsReauth(opts: NeedsReauthOpts): boolean {
  if (!opts.enabled) return false;
  if (opts.lastAuthAtMs === null) return true;
  return opts.nowMs - opts.lastAuthAtMs >= opts.windowMs;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm test reauth 2>&1 | tail -20`
Expected: PASS (6).

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/constants.ts desktop/src/lib/reauth.ts desktop/tests/reauth.test.ts
git commit -m "feat(desktop): pure needsReauth policy + reauth window constants"
```

---

## Task 7: TS `SettingsDto` fields + `verifyPassword` IPC wrapper

**Files:**
- Modify: `desktop/src/lib/ipc.ts`
- Test: `desktop/tests/ipc.test.ts`

**Interfaces:**
- Consumes: the `verify_password` command (Task 5).
- Produces: `SettingsDto` / `SettingsInput` TS interfaces gain `requirePasswordBeforeEdits: boolean` + `reauthGraceWindowMs: number`; `verifyPassword(password: string): Promise<void>`.

- [ ] **Step 1: Write the failing test** — add to `desktop/tests/ipc.test.ts` (it mocks `@tauri-apps/api/core`'s `invoke`; follow the file's existing mock pattern — `grep -n "vi.mock\|invoke" desktop/tests/ipc.test.ts`):

```ts
it('verifyPassword invokes verify_password with the password arg', async () => {
  invokeMock.mockResolvedValueOnce(undefined);
  const { verifyPassword } = await import('../src/lib/ipc');
  await verifyPassword('hunter2');
  expect(invokeMock).toHaveBeenCalledWith('verify_password', { password: 'hunter2' });
});

it('verifyPassword surfaces a wrong_password AppError', async () => {
  invokeMock.mockRejectedValueOnce({ code: 'wrong_password' });
  const { verifyPassword } = await import('../src/lib/ipc');
  await expect(verifyPassword('bad')).rejects.toEqual({ code: 'wrong_password' });
});
```

> Match the existing test's mock variable name (it may be `invoke` not `invokeMock`). Use `mockRejectedValueOnce` per [[project_secretary_vitest_mockrejectedvalue_quirk]].

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test ipc 2>&1 | tail -20`
Expected: FAIL — `verifyPassword` is not exported.

- [ ] **Step 3: Implement** — in `ipc.ts`, extend the `SettingsDto` interface and add the wrapper:

```ts
// in interface SettingsDto:
  requirePasswordBeforeEdits: boolean;
  reauthGraceWindowMs: number;
```

```ts
/**
 * Verify the vault password for a write re-auth. Resolves on a correct
 * password; rejects with `wrong_password` on a bad one, `not_unlocked` if
 * the session has been locked meanwhile. Runs a full Argon2id on the backend
 * (~1-2s) — callers await it behind the grace window.
 */
export async function verifyPassword(password: string): Promise<void> {
  return call<void>('verify_password', { password });
}
```

> If `SettingsInput` has a TS counterpart in this file (used by `setSettings`), add the two fields there too. `grep -n "setSettings\|SettingsInput\|autoLockTimeoutMs" desktop/src/lib/ipc.ts`.

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm test ipc 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/ipc.ts desktop/tests/ipc.test.ts
git commit -m "feat(desktop): verifyPassword IPC wrapper + SettingsDto reauth fields"
```

---

## Task 8: `writeGuard` + reauth-prompt store

**Files:**
- Modify: `desktop/src/lib/stores.ts`
- Create: `desktop/src/lib/writeGuard.ts`
- Test: `desktop/tests/writeGuard.test.ts`

**Interfaces:**
- Consumes: `needsReauth` (Task 6), `verifyPassword` (Task 7), `sessionState` (for settings).
- Produces:
  - `stores.ts`: `reauthPrompt: Readable<{ reason: string } | null>`; internal `openReauthPrompt`, `closeReauthPrompt` driven by the guard.
  - `writeGuard.ts`: `ReauthCancelled` (a unique sentinel), `authorizeWrite(reason: string): Promise<void>`, `resetReauthGuard(): void`, and a test seam to inject `now`, `verify`, and the prompt driver.

**Design:** `authorizeWrite` is the single chokepoint. It reads the current settings from `sessionState`, calls `needsReauth`; if no prompt is needed it resolves immediately. Otherwise it opens the prompt (publishing `{ reason }` to the store) and returns a promise the dialog resolves/rejects: the dialog calls back with the typed password, the guard runs `verify`; a wrong password keeps the prompt open (the dialog shows the inline error); a correct password advances `lastAuthAtMs` and resolves; Cancel rejects with `ReauthCancelled`.

To keep this host-testable without a DOM, the guard exposes an injectable driver:

- [ ] **Step 1: Write the failing test** — `desktop/tests/writeGuard.test.ts`:

```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  authorizeWrite,
  resetReauthGuard,
  ReauthCancelled,
  __setWriteGuardTestSeam
} from '../src/lib/writeGuard';

// A controllable settings source + clock + verify + prompt driver.
function seam(opts: {
  enabled: boolean;
  windowMs: number;
  now: () => number;
  // prompt resolves with a password (submit) or rejects (cancel)
  prompt: (reason: string) => Promise<string>;
  verify: (pw: string) => Promise<void>;
}) {
  __setWriteGuardTestSeam({
    readSettings: () => ({ enabled: opts.enabled, windowMs: opts.windowMs }),
    now: opts.now,
    prompt: opts.prompt,
    verify: opts.verify
  });
}

beforeEach(() => resetReauthGuard());

describe('authorizeWrite', () => {
  it('resolves without prompting when disabled', async () => {
    const prompt = vi.fn();
    seam({ enabled: false, windowMs: 1000, now: () => 0, prompt, verify: vi.fn() });
    await authorizeWrite('Confirm deleting this entry');
    expect(prompt).not.toHaveBeenCalled();
  });

  it('prompts once when enabled and never authed; verify ok advances the clock', async () => {
    let t = 1000;
    const prompt = vi.fn().mockResolvedValue('pw');
    const verify = vi.fn().mockResolvedValue(undefined);
    seam({ enabled: true, windowMs: 1000, now: () => t, prompt, verify });

    await authorizeWrite('Confirm saving this entry');
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(verify).toHaveBeenCalledWith('pw');

    // Immediately again, within the window → no prompt.
    t = 1500;
    await authorizeWrite('Confirm saving this entry');
    expect(prompt).toHaveBeenCalledTimes(1);

    // Past the window → prompt again.
    t = 2000;
    await authorizeWrite('Confirm saving this entry');
    expect(prompt).toHaveBeenCalledTimes(2);
  });

  it('rejects with ReauthCancelled on cancel and does not advance the clock', async () => {
    const prompt = vi.fn().mockRejectedValue(ReauthCancelled);
    const verify = vi.fn();
    seam({ enabled: true, windowMs: 1000, now: () => 5000, prompt, verify });

    await expect(authorizeWrite('Confirm moving this entry')).rejects.toBe(ReauthCancelled);
    expect(verify).not.toHaveBeenCalled();

    // Still needs a prompt next time (clock not advanced).
    prompt.mockResolvedValueOnce('pw');
    verify.mockResolvedValueOnce(undefined);
    await authorizeWrite('Confirm moving this entry');
    expect(prompt).toHaveBeenCalledTimes(2);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test writeGuard 2>&1 | tail -20`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the store** — add to `desktop/src/lib/stores.ts`:

```ts
// --- Write re-auth prompt --------------------------------------------------
// A single shared modal driven by writeGuard.authorizeWrite. The payload is
// just the reason string; the resolve/reject handlers live in the guard, not
// the store, so the store stays a plain view-model the dialog subscribes to.
const _reauthPrompt = writable<{ reason: string } | null>(null);
export const reauthPrompt: Readable<{ reason: string } | null> = {
  subscribe: _reauthPrompt.subscribe
};
export function openReauthPrompt(reason: string): void {
  _reauthPrompt.set({ reason });
}
export function closeReauthPrompt(): void {
  _reauthPrompt.set(null);
}
```

Create `desktop/src/lib/writeGuard.ts`:

```ts
// Stateful write re-auth gate. Holds `lastAuthAtMs`, decides via the pure
// `needsReauth`, and on a needed prompt drives the shared reauth modal +
// `verifyPassword`. Mirrors the iOS GraceWindowReauthGate (#275): the policy
// is pure, the gate is injected, and a refusal throws so the caller leaves
// its dialog open and runs no write.

import { get } from 'svelte/store';
import { needsReauth } from './reauth';
import { verifyPassword } from './ipc';
import { sessionState, openReauthPrompt, closeReauthPrompt } from './stores';
import { REAUTH_WINDOW_DEFAULT_MS } from './constants';

/** Thrown (rejected) when the user cancels the re-auth prompt. Identity-compared. */
export const ReauthCancelled = Symbol('ReauthCancelled');

interface WriteGuardSeam {
  readSettings: () => { enabled: boolean; windowMs: number };
  now: () => number;
  /** Resolve with the typed password (submit) or reject with ReauthCancelled. */
  prompt: (reason: string) => Promise<string>;
  verify: (password: string) => Promise<void>;
}

// Default production seam. The prompt opens the shared store and returns a
// promise the ReauthPasswordDialog settles via the module callbacks below.
let pendingSubmit: ((pw: string) => void) | null = null;
let pendingReject: ((reason: unknown) => void) | null = null;

function productionSeam(): WriteGuardSeam {
  return {
    readSettings: () => {
      const s = get(sessionState);
      if (s.status !== 'unlocked') {
        // Locked: no settings → treat as disabled (writes will fail at the
        // backend with NotUnlocked anyway; we don't prompt on a dead session).
        return { enabled: false, windowMs: REAUTH_WINDOW_DEFAULT_MS };
      }
      return {
        enabled: s.settings.requirePasswordBeforeEdits,
        windowMs: s.settings.reauthGraceWindowMs
      };
    },
    now: () => Date.now(),
    prompt: (reason: string) =>
      new Promise<string>((resolve, reject) => {
        pendingSubmit = resolve;
        pendingReject = reject;
        openReauthPrompt(reason);
      }),
    verify: verifyPassword
  };
}

let seam: WriteGuardSeam = productionSeam();
let lastAuthAtMs: number | null = null;

/** Test-only seam injection. */
export function __setWriteGuardTestSeam(s: WriteGuardSeam): void {
  seam = s;
}

/** Reset guard state — call on lock/unlock so a new session re-prompts. */
export function resetReauthGuard(): void {
  lastAuthAtMs = null;
  seam = productionSeam();
  pendingSubmit = null;
  pendingReject = null;
}

/** Seed the clock at unlock (the unlock password proves presence). */
export function seedReauthClock(nowMs: number): void {
  lastAuthAtMs = nowMs;
}

/**
 * The chokepoint. Resolves when the write may proceed; rejects with
 * `ReauthCancelled` (user cancelled) or a verify AppError. Re-prompts on a
 * wrong password until success or cancel.
 */
export async function authorizeWrite(reason: string): Promise<void> {
  const { enabled, windowMs } = seam.readSettings();
  if (!needsReauth({ enabled, lastAuthAtMs, nowMs: seam.now(), windowMs })) {
    return;
  }
  // Loop so a wrong password keeps the prompt open (the dialog reopens the
  // prompt; here we just re-await a fresh prompt round).
  for (;;) {
    const password = await seam.prompt(reason); // rejects with ReauthCancelled on cancel
    try {
      await seam.verify(password);
    } catch (err) {
      // Wrong password (or transient): surface to the dialog by rejecting the
      // round; the dialog shows the inline error and the user retries/cancels.
      // We rethrow so the caller's catch can distinguish; the dialog itself
      // owns the retry UX in the production seam (see ReauthPasswordDialog).
      throw err;
    }
    lastAuthAtMs = seam.now();
    closeReauthPrompt();
    return;
  }
}

/** Called by ReauthPasswordDialog on submit/cancel (production seam). */
export function __submitReauthPassword(password: string): void {
  pendingSubmit?.(password);
  pendingSubmit = null;
  pendingReject = null;
}
export function __cancelReauthPrompt(): void {
  closeReauthPrompt();
  pendingReject?.(ReauthCancelled);
  pendingSubmit = null;
  pendingReject = null;
}
```

> **Note on the retry loop:** in the production seam the dialog stays mounted and re-submits, so the `for(;;)` re-awaits a fresh `prompt` call only if the dialog drives multiple rounds. To keep Task 8 host-testable AND the dialog simple, the dialog (Task 9) owns the retry by calling `verifyPassword` itself and only calling `__submitReauthPassword` once verification *succeeds*; on a wrong password it shows the inline error and stays open. That means the production `seam.verify` is effectively a no-op-success by the time `prompt` resolves. **Simplify accordingly:** if the dialog verifies, `authorizeWrite`'s `verify` for the production seam can be `() => Promise.resolve()`. The test seam still exercises the verify branch directly. Implement whichever split keeps both the unit tests and the dialog green; document the chosen split in a comment. (Recommended: dialog verifies; guard's production `verify` is identity-success; the test seam injects a real verify to cover the policy. Adjust the test's "verify ok" expectation to assert on `prompt`/clock advance, not on `verify`, if you take this route.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd desktop && pnpm test writeGuard 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/stores.ts desktop/src/lib/writeGuard.ts desktop/tests/writeGuard.test.ts
git commit -m "feat(desktop): writeGuard + reauth-prompt store"
```

---

## Task 9: `ReauthPasswordDialog.svelte` + mount + clock seeding

**Files:**
- Create: `desktop/src/components/ReauthPasswordDialog.svelte`
- Modify: `desktop/src/routes/Vault.svelte` (mount the dialog once) and the unlock success path (call `seedReauthClock(Date.now())` + `resetReauthGuard()` on lock — find the unlock/lock transitions in `App.svelte`/`routes/Unlock.svelte`/`stores.ts`)
- Test: `desktop/tests/ReauthPasswordDialog.test.ts`

**Interfaces:**
- Consumes: `reauthPrompt` store, `verifyPassword`, `__submitReauthPassword`, `__cancelReauthPrompt`, `isAppError`, `userMessageFor`.

- [ ] **Step 1: Write the failing test** — `desktop/tests/ReauthPasswordDialog.test.ts` (follow `SettingsDialog.test.ts`'s render harness — `@testing-library/svelte` + the native `<dialog>` mock pattern that file uses):

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import ReauthPasswordDialog from '../src/components/ReauthPasswordDialog.svelte';
import { openReauthPrompt } from '../src/lib/stores';

vi.mock('../src/lib/ipc', () => ({
  verifyPassword: vi.fn(),
  isAppError: (e: unknown) => typeof e === 'object' && e !== null && 'code' in e
}));
import { verifyPassword } from '../src/lib/ipc';

beforeEach(() => vi.clearAllMocks());

it('shows the reason and verifies on confirm', async () => {
  (verifyPassword as any).mockResolvedValueOnce(undefined);
  const { getByText, getByLabelText } = render(ReauthPasswordDialog);
  openReauthPrompt('Confirm deleting this entry');
  expect(getByText('Confirm deleting this entry')).toBeTruthy();
  await fireEvent.input(getByLabelText(/password/i), { target: { value: 'pw' } });
  await fireEvent.click(getByText('Confirm'));
  expect(verifyPassword).toHaveBeenCalledWith('pw');
});

it('shows an inline error on wrong password and stays open', async () => {
  (verifyPassword as any).mockRejectedValueOnce({ code: 'wrong_password' });
  const { getByText, getByLabelText, queryByRole } = render(ReauthPasswordDialog);
  openReauthPrompt('Confirm saving this entry');
  await fireEvent.input(getByLabelText(/password/i), { target: { value: 'bad' } });
  await fireEvent.click(getByText('Confirm'));
  expect(queryByRole('alert')).toBeTruthy(); // Wrong password message rendered
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test ReauthPasswordDialog 2>&1 | tail -20`
Expected: FAIL — component not found.

- [ ] **Step 3: Implement** — `desktop/src/components/ReauthPasswordDialog.svelte` (model the `<dialog>` + `$effect` showModal pattern on `SettingsDialog.svelte`; the dialog verifies and only settles the guard on success):

```svelte
<script lang="ts">
  // Write re-auth prompt. Subscribes to the shared `reauthPrompt` store;
  // mounts modally whenever a write needs the password. The dialog OWNS the
  // verify + retry UX: a wrong password shows an inline error and keeps the
  // prompt open; a correct password settles the guard via __submitReauthPassword.
  import { reauthPrompt } from '../lib/stores';
  import { verifyPassword, isAppError } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';
  import { __submitReauthPassword, __cancelReauthPrompt } from '../lib/writeGuard';

  let dialogEl: HTMLDialogElement | undefined = $state();
  let password = $state('');
  let formError = $state<AppError | null>(null);
  let submitting = $state(false);

  let prompt = $derived($reauthPrompt);

  $effect(() => {
    if (!dialogEl) return;
    if (prompt && !dialogEl.hasAttribute('open')) {
      password = '';
      formError = null;
      dialogEl.showModal();
    } else if (!prompt && dialogEl.hasAttribute('open')) {
      dialogEl.close();
    }
  });

  async function confirm() {
    submitting = true;
    formError = null;
    try {
      await verifyPassword(password);
      const pw = password;
      password = '';
      __submitReauthPassword(pw); // settles the guard's pending prompt
    } catch (err) {
      formError = isAppError(err) ? err : { code: 'internal' };
    } finally {
      submitting = false;
    }
  }

  function cancel() {
    password = '';
    formError = null;
    __cancelReauthPrompt();
  }

  function onNativeClose() {
    if (prompt) cancel();
  }
</script>

<dialog bind:this={dialogEl} class="reauth-dialog" onclose={onNativeClose}>
  {#if prompt}
    <h2 class="reauth-dialog__title">Confirm with your password</h2>
    <p class="reauth-dialog__reason">{prompt.reason}</p>
    <label class="reauth-dialog__field">
      <span class="reauth-dialog__label">Password</span>
      <input
        type="password"
        class="reauth-dialog__input"
        bind:value={password}
        disabled={submitting}
        autocomplete="current-password"
      />
    </label>
    {#if formError}
      {@const msg = userMessageFor(formError)}
      <div class="reauth-dialog__error" role="alert">
        <strong>{msg.title}</strong>
        {#if msg.actionHint}<div class="reauth-dialog__hint">{msg.actionHint}</div>{/if}
      </div>
    {/if}
    <div class="reauth-dialog__actions">
      <button type="button" onclick={cancel} disabled={submitting}>Cancel</button>
      <button type="button" class="reauth-dialog__button--primary" onclick={confirm} disabled={submitting}>
        {submitting ? 'Verifying…' : 'Confirm'}
      </button>
    </div>
  {/if}
</dialog>
```

> Because the dialog verifies, set the **production** `writeGuard` seam's `verify` to identity-success (per the Task 8 note) so verification isn't double-run. The guard's `prompt` promise resolves via `__submitReauthPassword` only after a successful verify.

- [ ] **Step 4: Mount + seed/reset the guard.** In `routes/Vault.svelte`, add `<ReauthPasswordDialog />` alongside the other top-level dialogs (near `ConfirmDialog`). Wire clock lifecycle: on a successful unlock call `seedReauthClock(Date.now())`; on lock/auto-lock call `resetReauthGuard()`. Locate the transitions: `grep -rn "unlockSucceeded\|vaultLocked\|beginLock" desktop/src/lib/stores.ts desktop/src/App.svelte desktop/src/routes`. Add the calls at those sites (import from `../lib/writeGuard`).

- [ ] **Step 5: Run to verify it passes + svelte-check**

Run: `cd desktop && pnpm test ReauthPasswordDialog 2>&1 | tail -20 && pnpm svelte-check 2>&1 | tail -10`
Expected: tests PASS; svelte-check clean.

- [ ] **Step 6: Commit**

```bash
git add desktop/src/components/ReauthPasswordDialog.svelte desktop/src/routes/Vault.svelte \
        desktop/src/lib/stores.ts desktop/src/App.svelte
git commit -m "feat(desktop): ReauthPasswordDialog + mount + clock seeding"
```

---

## Task 10: Gate the record + block write handlers

**Files (modify each handler + its test):**
- `desktop/src/routes/Vault.svelte` (`confirmTrash` → `trashBlock`)
- `desktop/src/components/edit/RecordEditor.svelte` (save → `saveRecord`/`saveRecordEdit`)
- `desktop/src/components/edit/BlockNameDialog.svelte` (create/rename → `createBlock`/`renameBlock`)
- `desktop/src/components/edit/MoveTargetPicker.svelte` (confirm move → `moveRecord`)
- `desktop/src/components/delete/ConfirmDialog.svelte` caller / `RecordRow`/`RecordList` (delete → `tombstoneRecord`)
- `desktop/src/components/delete/TrashView.svelte` + `TrashedBlockRow` (restore record/block → `resurrectRecord`/`restoreBlock`)

> Exact call sites vary; **locate every gated write** with:
> `grep -rn "tombstoneRecord\|resurrectRecord\|saveRecord\|saveRecordEdit\|moveRecord\|createBlock\|renameBlock\|trashBlock\|restoreBlock" desktop/src --include=*.svelte`

**The mechanical transformation (identical at every site):** inside the handler, AFTER input validation and BEFORE the `await ipc.<write>(...)`, insert `await authorizeWrite('<reason>')`. Wrap so a cancel is a soft no-op and other errors surface as today:

```ts
import { authorizeWrite, ReauthCancelled } from '../lib/writeGuard'; // adjust relative path

async function doDelete() {
  // ...existing input validation stays ABOVE this line...
  try {
    await authorizeWrite('Confirm deleting this entry');
  } catch (err) {
    if (err === ReauthCancelled) return; // user cancelled — leave dialog open, no toast
    formError = isAppError(err) ? err : { code: 'internal' }; // verify failure path
    return;
  }
  // ...existing write proceeds unchanged...
  await tombstoneRecord(blockUuidHex, recordUuidHex);
  // ...existing reload/close...
}
```

**Reason strings (use verbatim):**

| Write | Reason |
|---|---|
| `tombstoneRecord` | `Confirm deleting this entry` |
| `resurrectRecord` | `Confirm restoring this entry` |
| `moveRecord` | `Confirm moving this entry` |
| `saveRecord` (new) | `Confirm saving this entry` |
| `saveRecordEdit` | `Confirm saving your changes` |
| `createBlock` | `Confirm creating this block` |
| `renameBlock` | `Confirm renaming this block` |
| `trashBlock` | `Confirm trashing this block` |
| `restoreBlock` | `Confirm restoring this block` |

- [ ] **Step 1: For EACH handler, write/extend the failing test** — in that component's existing test file, add a test using the writeGuard test seam to force a cancel and assert zero ipc write + dialog stays open, plus a happy-path test. Example for delete (`RecordListDelete.test.ts` or the relevant file):

```ts
import { __setWriteGuardTestSeam, ReauthCancelled, resetReauthGuard } from '../src/lib/writeGuard';
// cancel path:
__setWriteGuardTestSeam({
  readSettings: () => ({ enabled: true, windowMs: 0 }),
  now: () => 0,
  prompt: () => Promise.reject(ReauthCancelled),
  verify: () => Promise.resolve()
});
// ...trigger delete... then:
expect(tombstoneRecordMock).not.toHaveBeenCalled();
// happy path: prompt resolves, verify resolves → tombstoneRecord called once.
// resetReauthGuard() in afterEach.
```

- [ ] **Step 2: Run to verify each fails**

Run: `cd desktop && pnpm test 2>&1 | tail -30`
Expected: the new cancel/happy assertions FAIL (write still called on cancel).

- [ ] **Step 3: Apply the transformation** at every located site with the verbatim reason string. Keep input validation above the `authorizeWrite` call.

- [ ] **Step 4: Run the full frontend suite**

Run: `cd desktop && pnpm test 2>&1 | tail -20 && pnpm svelte-check 2>&1 | tail -10 && pnpm lint 2>&1 | tail -5`
Expected: all PASS / clean. (Existing write-path tests that didn't set a seam now hit the production seam → ensure those tests either set a disabled seam in `beforeEach` or call `resetReauthGuard()`; default the seam to `enabled:false` is NOT safe for prod, so update those tests to inject a pass-through seam.)

- [ ] **Step 5: Commit**

```bash
git add desktop/src
git commit -m "feat(desktop): gate record + block writes behind authorizeWrite"
```

---

## Task 11: Gate the sharing + contacts write handlers

**Files:**
- `desktop/src/components/share/ShareDialog.svelte` (`shareBlock`)
- `desktop/src/lib/revoke.ts` caller / `BlockRecipients.svelte` (`revokeBlockFrom`)
- `desktop/src/components/contacts/ContactsPane.svelte` / `ContactRow.svelte` (`deleteContactCard`)

> Locate: `grep -rn "shareBlock\|revokeBlockFrom\|deleteContactCard" desktop/src --include=*.svelte --include=*.ts`

**Reason strings:**

| Write | Reason |
|---|---|
| `shareBlock` | `Confirm sharing this block` |
| `revokeBlockFrom` | `Confirm revoking access` |
| `deleteContactCard` | `Confirm deleting this contact` |

- [ ] **Step 1: Write the failing cancel + happy tests** for each (same shape as Task 10 Step 1, in the relevant existing test files: `ShareDialog.test.ts`, `revoke.test.ts`/`BlockRecipients` test, `contacts.test.ts`/`ContactRow.test.ts`).

- [ ] **Step 2: Run to verify they fail**

Run: `cd desktop && pnpm test 2>&1 | tail -30`
Expected: new assertions FAIL.

- [ ] **Step 3: Apply the same `authorizeWrite` transformation** (Task 10 pattern) at each site with the verbatim reason.

- [ ] **Step 4: Run full suite**

Run: `cd desktop && pnpm test 2>&1 | tail -20 && pnpm svelte-check 2>&1 | tail -10`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add desktop/src
git commit -m "feat(desktop): gate sharing + contact writes behind authorizeWrite"
```

---

## Task 12: Settings dialog — toggle + grace-window field

**Files:**
- Modify: `desktop/src/components/SettingsDialog.svelte`
- Modify: `desktop/src/lib/constants.ts` (reuse `MS_PER_MINUTE`; add minute-bounds derived from `REAUTH_WINDOW_*`)
- Test: `desktop/tests/SettingsDialog.test.ts`

**Interfaces:** the dialog now reads/writes all three settings; `setSettings` payload includes `requirePasswordBeforeEdits` + `reauthGraceWindowMs`.

- [ ] **Step 1: Write the failing test** — add to `SettingsDialog.test.ts`:

```ts
it('saves the reauth toggle and window', async () => {
  // store seeded unlocked with all three settings; render; toggle off the
  // checkbox; set the window minutes; click Save.
  setSettingsMock.mockResolvedValueOnce(undefined);
  // ...render with sessionState unlocked { autoLockTimeoutMs, requirePasswordBeforeEdits:true, reauthGraceWindowMs:120000 }...
  await fireEvent.click(getByLabelText(/require password before edits/i)); // → false
  await fireEvent.input(getByLabelText(/re-?auth.*minutes|grace/i), { target: { value: '1' } });
  await fireEvent.click(getByText('Save'));
  expect(setSettingsMock).toHaveBeenCalledWith(
    expect.objectContaining({ requirePasswordBeforeEdits: false, reauthGraceWindowMs: 60_000 })
  );
});
```

> Update the existing SettingsDialog tests' seeded `sessionState` and `setSettings` expectations to include the two new fields (they now travel in every payload).

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test SettingsDialog 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Implement** — in `SettingsDialog.svelte`: add `requirePasswordBeforeEdits` (checkbox) and `reauthGraceWindowMs` (number input in minutes, bounds from `REAUTH_WINDOW_MIN_MS`/`MAX_MS`) to the `$derived` current values, the `$effect` re-seed, `validateOrError` (window range), and the `setSettings({ autoLockTimeoutMs, requirePasswordBeforeEdits, reauthGraceWindowMs })` payload. Window of 0 minutes is valid ("every write"); allow `min={0}`.

- [ ] **Step 4: Run to verify it passes + svelte-check**

Run: `cd desktop && pnpm test SettingsDialog 2>&1 | tail -20 && pnpm svelte-check 2>&1 | tail -10`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/components/SettingsDialog.svelte desktop/src/lib/constants.ts desktop/tests/SettingsDialog.test.ts
git commit -m "feat(desktop): settings dialog controls for write re-auth"
```

---

## Task 13: Full gate, docs, follow-up issue

**Files:**
- Modify: `README.md`, `ROADMAP.md`
- Create: the OS-biometric follow-up GitHub issue

- [ ] **Step 1: Full green gate (both stacks)**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-write-reauth
cargo test --release --workspace 2>&1 | tail -15
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all --check
cd desktop && pnpm test 2>&1 | tail -15 && pnpm lint 2>&1 | tail -5 && pnpm svelte-check 2>&1 | tail -10
```
Expected: all green.

- [ ] **Step 2: Guardrails**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-write-reauth
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format|\.udl|secretary-ffi-py|ios/|android/'   # MUST be empty
git diff main...HEAD --name-only | grep -E '^desktop/'   # expected: non-empty
```

- [ ] **Step 3: README + ROADMAP** — add a brief status row (dot-point style per [[feedback_readme_style]]): desktop write re-auth (password re-entry, opt-in default on, configurable grace window). Update the relevant ROADMAP D-row / cross-platform parity note (write-reauth now iOS + desktop; Android + OS-biometric pending). Keep it terse.

- [ ] **Step 4: File the follow-up issue**

```bash
gh issue create --title "Desktop write re-auth via OS biometric (macOS Touch ID / Linux / Windows)" \
  --body "$(cat <<'EOF'
Follow-up to the desktop password re-entry write-reauth (this PR). Add an OS-biometric presence proof on desktop:
- macOS: likely a minor expansion of the existing SwiftUI/iOS Secure-Enclave work (Touch ID via LocalAuthentication).
- Linux: polkit / fprintd.
- Windows: Windows Hello (Windows is not a primary target — [[feedback_windows_not_primary]]).
The frontend writeGuard + grace-window policy already abstract the presence proof; this swaps/augments `verifyPassword` with a biometric path. Password re-entry remains the cross-platform fallback.
EOF
)"
```

- [ ] **Step 5: Commit docs**

```bash
git add README.md ROADMAP.md
git commit -m "docs(desktop): note write re-auth; link OS-biometric follow-up"
```

---

## Self-Review (completed during planning)

**Spec coverage:** primitive (Task 5), grace window + pure policy (Task 6), opt-in default-on setting + configurable window (Tasks 1–4, 12), frontend-injected gate (Task 8), prompt UX + cancel-keeps-open (Tasks 9–11), gated write set incl. share/revoke/contacts (Tasks 10–11), settings-save un-gated (not gated — `set_settings` deliberately omitted from Tasks 10–11), backward-compat defaults (Task 2/3), verify cost + no-lock-conflict (Task 5, verified), follow-up issue (Task 13). All covered.

**Placeholder scan:** the only literal placeholder is `GOLDEN_PASSWORD` in Task 5 Step 2, explicitly flagged with the exact `grep` to resolve it before running — this is unavoidable without hardcoding a fixture secret in the plan and is called out as a required substitution, not a silent gap.

**Type consistency:** `Settings` (3 fields) consistent across Tasks 2/3/4; `needsReauth` opts shape consistent Tasks 6/8; `authorizeWrite`/`ReauthCancelled`/`__setWriteGuardTestSeam` consistent Tasks 8/9/10/11; `SettingsDto`/`SettingsInput` camelCase fields consistent Rust (Task 4) ↔ TS (Task 7) ↔ dialog (Task 12).

**Open implementation choice (flagged for the executor):** Task 8's verify split — production dialog verifies (guard's prod `verify` is identity-success) vs guard verifies. The plan recommends "dialog verifies" and tells the executor to keep both unit tests and the dialog green; this is a deliberate, documented degree of freedom, not a gap.
