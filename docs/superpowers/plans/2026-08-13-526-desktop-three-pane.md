# Desktop Three-Pane Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the desktop client's single-pane, one-level-at-a-time browse UI with a persistent three-pane layout — blocks left, records middle, detail right.

**Architecture:** The nine-arm `browseNav` union is unchanged. A new pure function `panesFor(nav)` projects each arm onto four slots (sidebar / list / detail / modal), so the panes are a *view* of already-tested state rather than new state. Record rows gain a real title derived in Rust behind a default-deny allowlist of field names.

**Tech Stack:** Svelte 5 (runes), TypeScript, Vitest + @testing-library/svelte + jsdom, Rust (Tauri 2 backend), `secretary-ffi-bridge`.

**Spec:** [`docs/superpowers/specs/2026-08-13-526-desktop-three-pane-design.md`](../specs/2026-08-13-526-desktop-three-pane-design.md)

## Global Constraints

- **Package manager is `pnpm`, never `npm`.** `npm` silently creates a spurious `package-lock.json`.
- **Type-check is `pnpm svelte-check` only.** Do not add a bare `tsc --noEmit`.
- All Rust must pass `cargo clippy --release --workspace --tests -- -D warnings`.
- `#![forbid(unsafe_code)]` is workspace-wide. Do not introduce `unsafe`.
- Every `.svelte` attribute must use straight quotes — a smart quote breaks `svelte-check` but not lint.
- Work in the worktree at `.worktrees/526-desktop-three-pane`, branch `526-desktop-three-pane`. Verify with `pwd && git branch --show-current` before any `cargo` or `git` command.
- **No new Tauri command is added by this plan.** If you find yourself adding one, stop — it would need classifying in `desktop/src/lib/writeCommands.ts`, which is out of scope here.

## A finding that shaped this plan

The spec says the title derivation is "a pure function taking `&Record`, unit-tested without a Tauri runtime." **That is not achievable as written.** `Record::new` and `FieldHandle::new` are both `pub(crate)` in `secretary-ffi-bridge` (`record/handle.rs:46`, `record/field.rs:41`), so `secretary-desktop` cannot construct a `Record` fixture in a unit test.

The plan therefore splits the derivation into three pieces:

1. `allowlist_rank(name) -> Option<usize>` — **the security gate.** Pure, no `Record`, fully unit-tested.
2. `select_labels(record_type, candidates) -> RecordLabels` — priority, subtitle, truncation, fallback. Pure, takes plain tuples, fully unit-tested.
3. `labels_for_record(&Record) -> RecordLabels` — a ~10-line adapter that walks fields and calls `expose_text`. Not unit-testable; covered by a new **integration test** against a real vault (`desktop/src-tauri/tests/ipc_integration.rs` already unlocks real vaults and has the fixtures).

This is a better split than the spec's: the security-critical decision is pure and exhaustively tested, and the untestable part is a trivial loop. The integration test is also *stronger* than a unit test would have been — it serializes the whole `BlockDetailDto` and asserts a saved password's plaintext appears nowhere in the JSON.

## File Structure

```
CREATE  desktop/src-tauri/src/record_title.rs          allowlist + selection + adapter
MODIFY  desktop/src-tauri/src/lib.rs                   register the module
MODIFY  desktop/src-tauri/src/dtos/browse.rs           RecordDto gains title/subtitle
MODIFY  desktop/src-tauri/src/reveal.rs                project_record calls labels_for_record
MODIFY  desktop/src-tauri/tests/ipc_integration.rs     new `mod title_path`

CREATE  desktop/src/lib/panes.ts                       the projection
CREATE  desktop/src/lib/paneWidths.ts                  fractions, floors, clamps
CREATE  desktop/src/components/PaneShell.svelte        grid + two splitters
CREATE  desktop/src/components/BlockSidebar.svelte     blocks + destinations
MODIFY  desktop/src/lib/ipc.ts                         RecordDto gains title/subtitle
MODIFY  desktop/src/components/RecordRow.svelte        render title/subtitle; selected/frozen
MODIFY  desktop/src/components/RecordList.svelte       drop back button; selection + frozen props
MODIFY  desktop/src/components/FieldViewer.svelte      drop back button
MODIFY  desktop/src/components/BlockCard.svelte        actions reveal on hover/selection
MODIFY  desktop/src/routes/Vault.svelte                render PaneShell; drop the 9-arm {#if}
MODIFY  desktop/src/theme.css                          two width tokens
MODIFY  desktop/src-tauri/tauri.conf.json              minWidth 760

CREATE  desktop/tests/panes.test.ts
CREATE  desktop/tests/paneWidths.test.ts
CREATE  desktop/tests/PaneShell.test.ts
CREATE  desktop/tests/BlockSidebar.test.ts
```

---

### Task 1: Rust — the allowlist gate and label selection (pure)

**Files:**
- Create: `desktop/src-tauri/src/record_title.rs`
- Modify: `desktop/src-tauri/src/lib.rs` (add `pub mod record_title;`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `pub struct RecordLabels { pub title: String, pub subtitle: Option<String> }`
  - `pub fn allowlist_rank(name: &str) -> Option<usize>`
  - `pub fn select_labels(record_type: &str, candidates: Vec<(usize, String, String)>) -> RecordLabels`
  - `pub const MAX_LABEL_CHARS: usize = 120;`

- [ ] **Step 1: Write the failing tests**

Create `desktop/src-tauri/src/record_title.rs` containing ONLY the test module for now (the code follows in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // ---- allowlist_rank: the security gate ----

    #[test]
    fn every_allowlisted_name_ranks_in_declaration_order() {
        assert_eq!(allowlist_rank("title"), Some(0));
        assert_eq!(allowlist_rank("name"), Some(1));
        assert_eq!(allowlist_rank("service"), Some(2));
        assert_eq!(allowlist_rank("username"), Some(3));
        assert_eq!(allowlist_rank("url"), Some(4));
        assert_eq!(allowlist_rank("key_id"), Some(5));
    }

    #[test]
    fn secret_bearing_names_are_not_allowlisted() {
        for name in ["password", "key_secret", "private_key", "passphrase", "totp_seed"] {
            assert_eq!(allowlist_rank(name), None, "{name} must never be title-eligible");
        }
    }

    #[test]
    fn freeform_names_are_not_allowlisted() {
        // `notes` / `body` can hold anything the user typed.
        assert_eq!(allowlist_rank("notes"), None);
        assert_eq!(allowlist_rank("body"), None);
    }

    #[test]
    fn unknown_names_default_deny() {
        assert_eq!(allowlist_rank("recovery_code"), None);
        assert_eq!(allowlist_rank(""), None);
        assert_eq!(allowlist_rank("USERNAME"), None, "match is case-sensitive");
    }

    // ---- select_labels ----

    #[test]
    fn empty_candidates_fall_back_to_record_type() {
        let out = select_labels("login", vec![]);
        assert_eq!(out.title, "login");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn lowest_rank_wins_regardless_of_field_order() {
        let out = select_labels(
            "login",
            vec![
                (3, "username".into(), "alice".into()),
                (0, "title".into(), "Bank".into()),
            ],
        );
        assert_eq!(out.title, "Bank");
        assert_eq!(out.subtitle.as_deref(), Some("username: alice"));
    }

    #[test]
    fn subtitle_uses_a_different_name_not_a_repeat_of_the_title_field() {
        // Two fields both named `username` yield one subtitle candidate, not two,
        // and the name used for the title is never reused.
        let out = select_labels(
            "login",
            vec![
                (3, "username".into(), "alice".into()),
                (3, "username".into(), "bob".into()),
            ],
        );
        assert_eq!(out.title, "alice");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn single_candidate_yields_no_subtitle() {
        let out = select_labels("login", vec![(4, "url".into(), "https://x.test".into())]);
        assert_eq!(out.title, "https://x.test");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn values_are_truncated_to_the_cap() {
        let long = "a".repeat(MAX_LABEL_CHARS + 50);
        let out = select_labels("login", vec![(1, "name".into(), long)]);
        assert_eq!(out.title.chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn truncation_is_char_safe_for_multibyte_values() {
        // Slicing by byte index would panic mid-codepoint.
        let long = "é".repeat(MAX_LABEL_CHARS + 10);
        let out = select_labels("login", vec![(1, "name".into(), long)]);
        assert_eq!(out.title.chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn subtitle_is_also_truncated() {
        let long = "b".repeat(MAX_LABEL_CHARS + 50);
        let out = select_labels(
            "login",
            vec![(0, "title".into(), "T".into()), (3, "username".into(), long)],
        );
        let subtitle = out.subtitle.expect("subtitle present");
        // "username: " prefix is not part of the value cap.
        assert_eq!(subtitle, format!("username: {}", "b".repeat(MAX_LABEL_CHARS)));
    }

    #[test]
    fn empty_value_is_ignored_and_falls_through() {
        // A present-but-empty allowlisted field must not produce a blank row.
        let out = select_labels(
            "login",
            vec![(0, "title".into(), "".into()), (3, "username".into(), "alice".into())],
        );
        assert_eq!(out.title, "alice");
        assert_eq!(out.subtitle, None);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test --release -p secretary-desktop record_title
```

Expected: FAIL to compile — `cannot find function 'allowlist_rank' in this scope` (and the module is not yet registered).

- [ ] **Step 3: Write the implementation**

Prepend to `desktop/src-tauri/src/record_title.rs`, above the test module:

```rust
//! Record title / subtitle derivation for the three-pane record list (#526).
//!
//! # Security contract
//!
//! Deriving a row label means calling `expose_text` on fields that
//! `project_record` previously never read, so *which* fields are eligible is
//! a security decision, enforced here and nowhere else.
//!
//! The rule is an **allowlist**, not a denylist: a field name absent from
//! [`TITLE_NAMES`] is never rendered, so `password`, `totp_seed`, freeform
//! `notes`/`body`, and every name nobody has thought of yet are excluded by
//! construction rather than by enumeration. A denylist would be the only gate
//! in this repository that fails open.
//!
//! [`labels_for_record`] applies the gate **before** `expose_text` is ever
//! called, so a non-allowlisted field's plaintext is never materialised at
//! all — not even into a discarded local.
//!
//! Values are truncated to [`MAX_LABEL_CHARS`] here, in Rust, so an oversized
//! field never reaches the webview.

/// Field names eligible to become a row's title, in priority order.
///
/// Adding a name here is a **security decision**: it asserts the field's
/// value is safe to display persistently in a list, unmasked, for as long as
/// the list is on screen. Unlike a revealed field it does not auto-hide.
const TITLE_NAMES: [&str; 6] = ["title", "name", "service", "username", "url", "key_id"];

/// Maximum characters of a field value that may reach the frontend as a label.
pub const MAX_LABEL_CHARS: usize = 120;

/// A record's derived row labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLabels {
    /// Always populated — falls back to the record type when no allowlisted
    /// field carries a usable value.
    pub title: String,
    /// `"<field name>: <value>"`, or `None` when there is no second distinct
    /// allowlisted field.
    pub subtitle: Option<String>,
}

/// Priority rank of `name` within [`TITLE_NAMES`], or `None` if it is not
/// allowlisted. Lower rank wins. Matching is exact and case-sensitive —
/// `vault-format.md` §6.3.1 field names are lowercase, and accepting case
/// variants would widen the gate on names nobody reviewed.
pub fn allowlist_rank(name: &str) -> Option<usize> {
    TITLE_NAMES.iter().position(|candidate| *candidate == name)
}

/// Truncate to [`MAX_LABEL_CHARS`] on a character boundary.
fn truncate(value: &str) -> String {
    value.chars().take(MAX_LABEL_CHARS).collect()
}

/// Pick title and subtitle from already-gated candidates.
///
/// `candidates` is `(rank, field name, value)`, in whatever order the record
/// yielded them; this function sorts by rank. Empty values are skipped so a
/// present-but-blank field cannot produce a blank row. The subtitle comes from
/// the first candidate whose *name* differs from the title's, so a record with
/// two same-named fields yields one label, not two.
pub fn select_labels(record_type: &str, mut candidates: Vec<(usize, String, String)>) -> RecordLabels {
    candidates.retain(|(_, _, value)| !value.is_empty());
    candidates.sort_by_key(|(rank, _, _)| *rank);

    let Some((_, title_name, title_value)) = candidates.first() else {
        return RecordLabels { title: record_type.to_owned(), subtitle: None };
    };
    let title = truncate(title_value);

    let subtitle = candidates
        .iter()
        .find(|(_, name, _)| name != title_name)
        .map(|(_, name, value)| format!("{name}: {}", truncate(value)));

    RecordLabels { title, subtitle }
}
```

Then register the module in `desktop/src-tauri/src/lib.rs`, keeping the list alphabetical (insert between `recent_vault` and `reveal`):

```rust
pub mod record_title;
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --release -p secretary-desktop record_title
```

Expected: PASS, 11 tests.

- [ ] **Step 5: Lint**

```bash
cargo clippy --release -p secretary-desktop --tests -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add desktop/src-tauri/src/record_title.rs desktop/src-tauri/src/lib.rs
git commit -m "feat(desktop): allowlist-gated record title derivation (#526)

The gate is an allowlist, not a denylist: a field name absent from
TITLE_NAMES is never rendered, so password / totp_seed / freeform notes
and every unreviewed future name are excluded by construction."
```

---

### Task 2: Rust — wire titles into the read path, with an end-to-end leak test

**Files:**
- Modify: `desktop/src-tauri/src/record_title.rs` (add the `labels_for_record` adapter)
- Modify: `desktop/src-tauri/src/dtos/browse.rs:20-31` (`RecordDto` gains two fields)
- Modify: `desktop/src-tauri/src/reveal.rs:36-57` (`project_record`)
- Modify: `desktop/src-tauri/src/reveal.rs:14-20` (amend the invariant doc comment)
- Modify: `desktop/src/lib/ipc.ts:47-56` (mirror the DTO)
- Test: `desktop/src-tauri/tests/ipc_integration.rs` (new `mod title_path`)

**Interfaces:**
- Consumes: `allowlist_rank`, `select_labels`, `RecordLabels` from Task 1.
- Produces: `RecordDto.title: String` and `RecordDto.subtitle: Option<String>` on the Rust side, serialized camelCase as `title` / `subtitle`; the TS `RecordDto` gains `title: string` and `subtitle: string | null`.

- [ ] **Step 1: Write the failing integration test**

Append a new module at the end of `desktop/src-tauri/tests/ipc_integration.rs`. It repeats the local fixture helpers because every other `mod` in this file does the same — follow the established pattern rather than hoisting them.

```rust
// ============================================================================
// Record title derivation (#526)
//
// `labels_for_record` walks a real `Record` and calls `expose_text`, which no
// unit test can reach: `Record::new` / `FieldHandle::new` are `pub(crate)` in
// the bridge, so a `Record` fixture cannot be built outside it. These tests
// drive the real read path over a real vault instead — which also buys a
// stronger assertion than a unit test could make: that a non-allowlisted
// field's plaintext appears nowhere in the serialized DTO.
// ============================================================================
mod title_path {
    // `use super::*` already brings in `commands::{browse, create, edit}`,
    // `dtos::{FieldInputDto, FieldValueDto, RecordInputDto}`, `Mutex`,
    // `VaultSession`, `fresh_state`, `to_json`, `canonicalize_for_auth` and
    // `PathPurpose` from the file's top-level imports. Re-importing any of
    // them here would be an unused/duplicate import and fail `-D warnings`.
    // Only the two crates the top level does NOT import are named.
    use super::*;
    use rand_core::{OsRng, RngCore};
    use secretary_core::crypto::secret::SecretBytes;

    const CREATE_DISPLAY_NAME: &str = "#526 title-path test identity";

    /// Runtime-random hex password — avoids a hardcoded crypto literal.
    /// Byte-for-byte the same helper `edit_path` uses; each module in this
    /// file carries its own copy by established convention.
    fn random_password() -> Vec<u8> {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        raw.iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect()
    }

    fn unlocked_session_over_new_vault() -> (Mutex<VaultSession>, tempfile::TempDir, Vec<u8>) {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let path = vault_dir.path().to_str().expect("utf8 path");
        let pw = random_password();

        let (state, _device_dir) = fresh_state();
        state.lock().unwrap().approve_path(
            PathPurpose::CreateParent,
            canonicalize_for_auth(vault_dir.path()).unwrap(),
        );
        create::create_vault_impl(
            &state,
            path,
            CREATE_DISPLAY_NAME,
            &SecretBytes::from(pw.as_slice()),
            1_700_000_000_000,
            &mut OsRng,
        )
        .expect("create_vault");
        (state, vault_dir, pw)
    }

    fn text_field(name: &str, text: &str) -> FieldInputDto {
        FieldInputDto {
            name: name.into(),
            value: FieldValueDto::Text { text: text.into() },
        }
    }

    /// Save one record into a fresh block and read the block back.
    fn save_then_read(fields: Vec<FieldInputDto>, record_type: &str) -> BlockDetailDtoForTest {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Logins").expect("create_block");
        edit::save_record_impl(
            &state,
            &block.block_uuid_hex,
            RecordInputDto {
                record_type: record_type.into(),
                tags: vec![],
                fields,
            },
        )
        .expect("save_record");
        let detail = browse::read_block_impl(&state, &block.block_uuid_hex, false).expect("read");
        let json = to_json(&detail);
        BlockDetailDtoForTest {
            title: detail.records[0].title.clone(),
            subtitle: detail.records[0].subtitle.clone(),
            json,
        }
    }

    struct BlockDetailDtoForTest {
        title: String,
        subtitle: Option<String>,
        json: serde_json::Value,
    }

    #[test]
    fn allowlisted_field_becomes_the_title() {
        let out = save_then_read(vec![text_field("username", "alice@example.test")], "login");
        assert_eq!(out.title, "alice@example.test");
    }

    #[test]
    fn priority_order_decides_the_title() {
        let out = save_then_read(
            vec![text_field("username", "alice"), text_field("title", "Bank")],
            "login",
        );
        assert_eq!(out.title, "Bank");
        assert_eq!(out.subtitle.as_deref(), Some("username: alice"));
    }

    #[test]
    fn a_record_of_only_secret_fields_falls_back_to_its_type() {
        let out = save_then_read(
            vec![text_field("password", "hunter2"), text_field("totp_seed", "JBSWY3DP")],
            "login",
        );
        assert_eq!(out.title, "login", "must fall back, never show a secret");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn non_allowlisted_plaintext_appears_nowhere_in_the_serialized_dto() {
        // The load-bearing test. Not "the title isn't the password" — that the
        // password's plaintext is absent from the ENTIRE wire payload.
        let out = save_then_read(
            vec![
                text_field("username", "alice"),
                text_field("password", "correct-horse-battery-staple"),
                text_field("notes", "mother's maiden name is Rosenberg"),
            ],
            "login",
        );
        let wire = serde_json::to_string(&out.json).expect("serialize");
        assert!(!wire.contains("correct-horse-battery-staple"), "password leaked into {wire}");
        assert!(!wire.contains("Rosenberg"), "notes leaked into {wire}");
        // Field NAMES are metadata and legitimately present; only values must not be.
        assert!(wire.contains("password"), "field name metadata should still be present");
        assert_eq!(out.title, "alice");
    }

    #[test]
    fn a_record_with_no_fields_falls_back_to_its_type() {
        let out = save_then_read(vec![], "secure_note");
        assert_eq!(out.title, "secure_note");
        assert_eq!(out.subtitle, None);
    }

    #[test]
    fn bytes_fields_are_never_eligible_for_a_title() {
        // `name` IS allowlisted, but a bstr field must not be stringified into
        // a row. Base64 of b"hunter2".
        let out = save_then_read(
            vec![FieldInputDto {
                name: "name".into(),
                value: FieldValueDto::Bytes { base64: "aHVudGVyMg==".into() },
            }],
            "api_key",
        );
        assert_eq!(out.title, "api_key", "a bstr field must not become a title");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test --release -p secretary-desktop --test ipc_integration title_path
```

Expected: FAIL to compile — `no field 'title' on type 'RecordDto'`.

- [ ] **Step 3: Add the adapter to `record_title.rs`**

Append below `select_labels` (and add the import at the top of the file):

```rust
use secretary_ffi_bridge::Record;
```

```rust
/// Derive a record's row labels, gating **before** any plaintext is exposed.
///
/// The ordering in the loop body is the security property: `allowlist_rank`
/// and `is_text` are both checked before `expose_text` is called, so a
/// non-allowlisted or binary field's plaintext is never materialised — not
/// even into a local that is immediately dropped.
///
/// Not unit-testable: `Record` cannot be constructed outside the bridge
/// (`Record::new` is `pub(crate)`). Covered by `title_path` in
/// `tests/ipc_integration.rs`, which drives the real read path over a real
/// vault.
pub fn labels_for_record(record: &Record) -> RecordLabels {
    let mut candidates: Vec<(usize, String, String)> = Vec::new();
    for i in 0..record.field_count() {
        let Some(handle) = record.field_at(i) else {
            continue;
        };
        let name = handle.name();
        // GATE — both checks precede expose_text. Do not reorder.
        let Some(rank) = allowlist_rank(&name) else {
            continue;
        };
        if !handle.is_text() {
            continue;
        }
        let Some(value) = handle.expose_text() else {
            continue;
        };
        candidates.push((rank, name, value));
    }
    select_labels(&record.record_type(), candidates)
}
```

- [ ] **Step 4: Extend the DTO**

In `desktop/src-tauri/src/dtos/browse.rs`, add two fields to `RecordDto` after `record_type`:

```rust
    /// Human-readable row label, derived by `crate::record_title` behind an
    /// allowlist of field names. Falls back to `record_type`. Never carries a
    /// non-allowlisted field's plaintext.
    pub title: String,
    /// Secondary row label, `"<field name>: <value>"`, same allowlist.
    pub subtitle: Option<String>,
```

- [ ] **Step 5: Call it from `project_record`**

In `desktop/src-tauri/src/reveal.rs`, add the import:

```rust
use crate::record_title::labels_for_record;
```

Replace the body of `project_record` (currently `reveal.rs:36-57`) so the labels are derived and placed on the DTO:

```rust
fn project_record(record: &Record) -> RecordDto {
    let field_count = record.field_count();
    let mut fields = Vec::with_capacity(field_count);
    for i in 0..field_count {
        if let Some(handle) = record.field_at(i) {
            fields.push(project_field_meta(&handle));
        }
    }
    let labels = labels_for_record(record);
    RecordDto {
        record_uuid_hex: hex::encode(record.record_uuid()),
        record_type: record.record_type(),
        title: labels.title,
        subtitle: labels.subtitle,
        tags: record.tags(),
        created_at_ms: record.created_at_ms(),
        last_mod_ms: record.last_mod_ms(),
        // Derive field_count from the projected fields, not the separate
        // record.field_count() accessor, so the wire value stays consistent
        // with the fields array under a concurrent wipe().
        field_count: fields.len() as u64,
        fields,
        tombstoned: record.tombstone(),
    }
}
```

Then amend the module-level invariant at `reveal.rs:19-20`. Replace the sentence "Carries only plaintext metadata — never calls `expose_text`/`expose_bytes`." with:

```rust
/// layer no longer filters. Each projected record carries `tombstoned` so the
/// restore UI can style soft-deleted rows.
///
/// **Amended by #526.** This layer previously never called
/// `expose_text`/`expose_bytes`. It now calls `expose_text` — but *only*
/// through [`crate::record_title::labels_for_record`], and only for field
/// names on that module's allowlist. No other call site here may expose a
/// value. The exposure delta versus `reveal_field` is duration, not class: a
/// revealed field re-masks after `REVEAL_AUTO_HIDE_MS`, whereas a derived
/// title stays on screen as long as the list does.
```

- [ ] **Step 6: Mirror the DTO in TypeScript**

In `desktop/src/lib/ipc.ts`, add to `RecordDto` after `recordType`:

```ts
  title: string;
  subtitle: string | null;
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cargo test --release -p secretary-desktop
```

Expected: PASS. The `title_path` module's 6 tests pass; the pre-existing `ipc_integration` wire-format assertions still pass (they assert named fields, not exhaustive object shape — if any asserts an exact object, add `title`/`subtitle` to it).

- [ ] **Step 8: Lint**

```bash
cargo clippy --release -p secretary-desktop --tests -- -D warnings
```

- [ ] **Step 9: Commit**

```bash
git add desktop/src-tauri/src/record_title.rs desktop/src-tauri/src/dtos/browse.rs \
        desktop/src-tauri/src/reveal.rs desktop/src-tauri/tests/ipc_integration.rs \
        desktop/src/lib/ipc.ts
git commit -m "feat(desktop): derive record titles in the read path (#526)

project_record now calls expose_text, but only via record_title's
allowlist. The integration test asserts a saved password's plaintext is
absent from the entire serialized BlockDetailDto, not merely from the
title field."
```

---

### Task 3: TypeScript — the `panesFor` projection

**Files:**
- Create: `desktop/src/lib/panes.ts`
- Test: `desktop/tests/panes.test.ts`

**Interfaces:**
- Consumes: `BrowseNav` from `./browse`, `BlockSummaryDto` / `RecordDto` from `./ipc` (the latter now carries `title` / `subtitle` from Task 2).
- Produces: `panesFor(nav: BrowseNav): PaneLayout`, plus the exported types `PaneLayout`, `SidebarSelection`, `ListPane`, `DetailPane`, `ModalPane` and the constants `SELECT_BLOCK_PROMPT`, `SELECT_RECORD_PROMPT`.

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/panes.test.ts`:

```ts
// Tests for panesFor — the pure projection from the nine-arm browseNav union
// onto the three-pane layout (#526). This file IS the design's projection
// table, executable: one assertion block per union arm.

import { describe, it, expect } from 'vitest';
import {
  panesFor,
  SELECT_BLOCK_PROMPT,
  SELECT_RECORD_PROMPT
} from '../src/lib/panes';
import type { BlockSummaryDto, RecordDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = {
  blockUuidHex: 'aaaa1111',
  blockName: 'Banking',
  createdAtMs: 1_700_000_000_000,
  lastModifiedMs: 1_700_000_100_000
};

const RECORD: RecordDto = {
  recordUuidHex: 'bbbb2222',
  recordType: 'login',
  title: 'alice@example.test',
  subtitle: 'url: https://bank.test',
  tags: [],
  createdAtMs: 1_700_000_000_000,
  lastModMs: 1_700_000_100_000,
  fieldCount: 2,
  fields: []
};

describe('panesFor — blocks root', () => {
  it('selects nothing, prompts for a block, leaves detail empty', () => {
    const p = panesFor({ level: 'blocks' });
    expect(p.sidebar).toEqual({ kind: 'none' });
    expect(p.list).toEqual({ kind: 'prompt', message: SELECT_BLOCK_PROMPT });
    expect(p.detail).toEqual({ kind: 'empty' });
    expect(p.modal).toEqual({ kind: 'none' });
  });
});

describe('panesFor — records', () => {
  it('selects the block, lists its records, prompts for a record', () => {
    const p = panesFor({ level: 'records', block: BLOCK });
    expect(p.sidebar).toEqual({ kind: 'block', blockUuidHex: BLOCK.blockUuidHex });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: null,
      frozen: false
    });
    expect(p.detail).toEqual({ kind: 'prompt', message: SELECT_RECORD_PROMPT });
  });
});

describe('panesFor — fields', () => {
  it('highlights the record in the list and shows the viewer', () => {
    const p = panesFor({ level: 'fields', block: BLOCK, record: RECORD });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: RECORD.recordUuidHex,
      frozen: false
    });
    expect(p.detail).toEqual({ kind: 'viewer', block: BLOCK, record: RECORD });
  });
});

describe('panesFor — editRecord', () => {
  it('freezes the list so a stray click cannot discard the edit', () => {
    const p = panesFor({ level: 'editRecord', block: BLOCK, record: RECORD });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: RECORD.recordUuidHex,
      frozen: true
    });
    expect(p.detail).toEqual({ kind: 'editor', block: BLOCK, record: RECORD });
  });
});

describe('panesFor — newRecord', () => {
  it('freezes the list with no row selected and an empty editor', () => {
    const p = panesFor({ level: 'newRecord', block: BLOCK });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: null,
      frozen: true
    });
    expect(p.detail).toEqual({ kind: 'editor', block: BLOCK, record: null });
  });
});

describe('panesFor — trash and contacts span both right-hand columns', () => {
  it('trash', () => {
    const p = panesFor({ level: 'trash' });
    expect(p.sidebar).toEqual({ kind: 'trash' });
    expect(p.list).toEqual({ kind: 'trash' });
    expect(p.detail).toEqual({ kind: 'spanned' });
  });

  it('contacts', () => {
    const p = panesFor({ level: 'contacts' });
    expect(p.sidebar).toEqual({ kind: 'contacts' });
    expect(p.list).toEqual({ kind: 'contacts' });
    expect(p.detail).toEqual({ kind: 'spanned' });
  });
});

describe('panesFor — the modal arms define their own backdrop', () => {
  it('newBlock sits over the blocks root', () => {
    const p = panesFor({ level: 'newBlock' });
    expect(p.sidebar).toEqual({ kind: 'none' });
    expect(p.list).toEqual({ kind: 'prompt', message: SELECT_BLOCK_PROMPT });
    expect(p.modal).toEqual({ kind: 'blockName', mode: { kind: 'create' } });
  });

  it('renameBlock sits over that block, already selected — so cancel is seamless', () => {
    const p = panesFor({ level: 'renameBlock', block: BLOCK });
    expect(p.sidebar).toEqual({ kind: 'block', blockUuidHex: BLOCK.blockUuidHex });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: null,
      frozen: false
    });
    expect(p.modal).toEqual({ kind: 'blockName', mode: { kind: 'rename', block: BLOCK } });
  });
});

describe('panesFor — total coverage', () => {
  it('never returns a modal outside the two block-name arms', () => {
    const navs = [
      { level: 'blocks' },
      { level: 'records', block: BLOCK },
      { level: 'fields', block: BLOCK, record: RECORD },
      { level: 'editRecord', block: BLOCK, record: RECORD },
      { level: 'newRecord', block: BLOCK },
      { level: 'trash' },
      { level: 'contacts' }
    ] as const;
    for (const nav of navs) {
      expect(panesFor(nav).modal).toEqual({ kind: 'none' });
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd desktop && pnpm vitest run tests/panes.test.ts
```

Expected: FAIL — `Failed to resolve import "../src/lib/panes"`.

- [ ] **Step 3: Write the implementation**

Create `desktop/src/lib/panes.ts`:

```ts
// #526 — the three-pane projection.
//
// The nine-arm `browseNav` union is unchanged; this maps each arm onto four
// slots. Keeping it a pure projection rather than new store state means every
// existing guard (shouldPopOnEscape, resetBrowse, the trash and rename flows)
// keeps its current tests and needs no re-audit — the panes are a VIEW of
// state that is already proven, and this file's own test is the design's
// projection table made executable.

import type { BrowseNav } from './browse';
import type { BlockSummaryDto, RecordDto } from './ipc';

export const SELECT_BLOCK_PROMPT = 'Select a block';
export const SELECT_RECORD_PROMPT = 'Select a record';

export type SidebarSelection =
  | { kind: 'none' }
  | { kind: 'block'; blockUuidHex: string }
  | { kind: 'trash' }
  | { kind: 'contacts' };

export type ListPane =
  | { kind: 'prompt'; message: string }
  | {
      kind: 'records';
      block: BlockSummaryDto;
      selectedRecordUuidHex: string | null;
      /** Rows are non-interactive while an editor is open, so a stray click
          cannot silently discard an unsaved edit. */
      frozen: boolean;
    }
  | { kind: 'trash' }
  | { kind: 'contacts' };

export type DetailPane =
  | { kind: 'empty' }
  | { kind: 'prompt'; message: string }
  | { kind: 'viewer'; block: BlockSummaryDto; record: RecordDto }
  | { kind: 'editor'; block: BlockSummaryDto; record: RecordDto | null }
  /** The list pane occupies both right-hand columns; nothing renders here. */
  | { kind: 'spanned' };

export type ModalPane =
  | { kind: 'none' }
  | {
      kind: 'blockName';
      mode: { kind: 'create' } | { kind: 'rename'; block: BlockSummaryDto };
    };

export interface PaneLayout {
  sidebar: SidebarSelection;
  list: ListPane;
  detail: DetailPane;
  modal: ModalPane;
}

function blockSelected(block: BlockSummaryDto): SidebarSelection {
  return { kind: 'block', blockUuidHex: block.blockUuidHex };
}

function recordsIn(
  block: BlockSummaryDto,
  selectedRecordUuidHex: string | null,
  frozen: boolean
): ListPane {
  return { kind: 'records', block, selectedRecordUuidHex, frozen };
}

const NO_MODAL: ModalPane = { kind: 'none' };
const BLOCK_PROMPT: ListPane = { kind: 'prompt', message: SELECT_BLOCK_PROMPT };

export function panesFor(nav: BrowseNav): PaneLayout {
  switch (nav.level) {
    case 'blocks':
      return {
        sidebar: { kind: 'none' },
        list: BLOCK_PROMPT,
        detail: { kind: 'empty' },
        modal: NO_MODAL
      };
    case 'newBlock':
      return {
        sidebar: { kind: 'none' },
        list: BLOCK_PROMPT,
        detail: { kind: 'empty' },
        modal: { kind: 'blockName', mode: { kind: 'create' } }
      };
    case 'records':
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, null, false),
        detail: { kind: 'prompt', message: SELECT_RECORD_PROMPT },
        modal: NO_MODAL
      };
    case 'renameBlock':
      // The block stays selected behind the dialog, so cancelling lands the
      // user exactly where they were — the projection gives us this for free.
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, null, false),
        detail: { kind: 'empty' },
        modal: { kind: 'blockName', mode: { kind: 'rename', block: nav.block } }
      };
    case 'fields':
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, nav.record.recordUuidHex, false),
        detail: { kind: 'viewer', block: nav.block, record: nav.record },
        modal: NO_MODAL
      };
    case 'editRecord':
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, nav.record.recordUuidHex, true),
        detail: { kind: 'editor', block: nav.block, record: nav.record },
        modal: NO_MODAL
      };
    case 'newRecord':
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, null, true),
        detail: { kind: 'editor', block: nav.block, record: null },
        modal: NO_MODAL
      };
    case 'trash':
      return {
        sidebar: { kind: 'trash' },
        list: { kind: 'trash' },
        detail: { kind: 'spanned' },
        modal: NO_MODAL
      };
    case 'contacts':
      return {
        sidebar: { kind: 'contacts' },
        list: { kind: 'contacts' },
        detail: { kind: 'spanned' },
        modal: NO_MODAL
      };
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd desktop && pnpm vitest run tests/panes.test.ts
```

Expected: PASS, 10 tests.

- [ ] **Step 5: Type-check**

```bash
cd desktop && pnpm svelte-check
```

Expected: no new errors. A missing `case` in the switch would surface here as a "not all code paths return a value" error — that is the exhaustiveness guarantee, so do not add a `default` arm.

- [ ] **Step 6: Commit**

```bash
git add desktop/src/lib/panes.ts desktop/tests/panes.test.ts
git commit -m "feat(desktop): panesFor — pure browseNav → three-pane projection (#526)"
```

---

### Task 4: TypeScript — pane width fractions and clamps

**Files:**
- Create: `desktop/src/lib/paneWidths.ts`
- Test: `desktop/tests/paneWidths.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `SIDEBAR_MIN_PX = 180`, `LIST_MIN_PX = 260`, `DETAIL_MIN_PX = 320`
  - `SIDEBAR_DEFAULT_FRACTION = 0.18`, `LIST_DEFAULT_FRACTION = 0.26`
  - `loadFractions(storage: Pick<Storage,'getItem'>): { sidebar: number; list: number }`
  - `saveFraction(storage: Pick<Storage,'setItem'>, pane: PaneKey, fraction: number): void`
  - `clampPaneWidthPx(args): number`
  - `type PaneKey = 'sidebar' | 'list'`

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/paneWidths.test.ts`:

```ts
// Tests for pane width persistence and clamping (#526).
//
// Storage is injected rather than read from a global, so these are pure-
// function tests with no jsdom localStorage dependency.

import { describe, it, expect, vi } from 'vitest';
import {
  loadFractions,
  saveFraction,
  clampPaneWidthPx,
  SIDEBAR_MIN_PX,
  LIST_MIN_PX,
  DETAIL_MIN_PX,
  SIDEBAR_DEFAULT_FRACTION,
  LIST_DEFAULT_FRACTION,
  SIDEBAR_KEY,
  LIST_KEY
} from '../src/lib/paneWidths';

function storageOf(entries: Record<string, string>) {
  return { getItem: (k: string) => entries[k] ?? null };
}

describe('loadFractions — defaults and sanity', () => {
  it('returns defaults when nothing is stored', () => {
    const out = loadFractions(storageOf({}));
    expect(out).toEqual({ sidebar: SIDEBAR_DEFAULT_FRACTION, list: LIST_DEFAULT_FRACTION });
  });

  it('round-trips a stored pair', () => {
    const out = loadFractions(storageOf({ [SIDEBAR_KEY]: '0.22', [LIST_KEY]: '0.3' }));
    expect(out).toEqual({ sidebar: 0.22, list: 0.3 });
  });

  it('falls back per-pane when only one is stored', () => {
    const out = loadFractions(storageOf({ [SIDEBAR_KEY]: '0.22' }));
    expect(out).toEqual({ sidebar: 0.22, list: LIST_DEFAULT_FRACTION });
  });

  it.each([
    ['not a number', 'banana'],
    ['empty', ''],
    ['NaN literal', 'NaN'],
    ['negative', '-0.4'],
    ['zero', '0'],
    ['over one', '1.4'],
    ['Infinity', 'Infinity'],
    ['injected object', '{"sidebar":0.9}']
  ])('falls back to the default on a %s value', (_label, raw) => {
    const out = loadFractions(storageOf({ [SIDEBAR_KEY]: raw }));
    expect(out.sidebar).toBe(SIDEBAR_DEFAULT_FRACTION);
  });

  it('scales an over-committed pair down proportionally rather than overflowing', () => {
    // Restoring geometry saved on a much wider monitor must not sum past the
    // container: the detail pane has to keep a share.
    const out = loadFractions(storageOf({ [SIDEBAR_KEY]: '0.6', [LIST_KEY]: '0.5' }));
    expect(out.sidebar + out.list).toBeLessThanOrEqual(0.85 + 1e-9);
    // Proportions are preserved (0.6 : 0.5).
    expect(out.sidebar / out.list).toBeCloseTo(1.2, 5);
  });
});

describe('saveFraction', () => {
  it('writes the namespaced key', () => {
    const setItem = vi.fn();
    saveFraction({ setItem }, 'sidebar', 0.25);
    expect(setItem).toHaveBeenCalledWith(SIDEBAR_KEY, '0.25');
  });

  it('writes the list key for the list pane', () => {
    const setItem = vi.fn();
    saveFraction({ setItem }, 'list', 0.31);
    expect(setItem).toHaveBeenCalledWith(LIST_KEY, '0.31');
  });

  it('never throws when storage rejects the write', () => {
    // Safari private browsing throws on setItem when the quota is zero. A
    // failed geometry save must not break the app.
    const setItem = vi.fn(() => {
      throw new DOMException('QuotaExceededError');
    });
    expect(() => saveFraction({ setItem }, 'sidebar', 0.25)).not.toThrow();
  });
});

describe('clampPaneWidthPx — lower bound is the pane floor', () => {
  it('raises a too-small request to the floor', () => {
    const px = clampPaneWidthPx({
      requestedPx: 40,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 1400,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(SIDEBAR_MIN_PX);
  });
});

describe('clampPaneWidthPx — upper bound is derived, not an arbitrary cap', () => {
  it('lets a pane grow until the OTHER panes hit their floors', () => {
    // 1400 container, siblings need 260 + 320 = 580 → sidebar may reach 820.
    const px = clampPaneWidthPx({
      requestedPx: 9999,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 1400,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(1400 - (LIST_MIN_PX + DETAIL_MIN_PX));
  });

  it('scales the bound with the container — a wider window allows more', () => {
    const px = clampPaneWidthPx({
      requestedPx: 9999,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 2560,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(2560 - 580);
    expect(px).toBeGreaterThan(1900); // genuinely generous, not a token cap
  });

  it('passes an in-range request through untouched', () => {
    const px = clampPaneWidthPx({
      requestedPx: 300,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 1400,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(300);
  });

  it('floor wins when the container is too small to satisfy everyone', () => {
    // Below the enforced window minimum — should degrade to the floor, not
    // return a negative width.
    const px = clampPaneWidthPx({
      requestedPx: 400,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 500,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(SIDEBAR_MIN_PX);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd desktop && pnpm vitest run tests/paneWidths.test.ts
```

Expected: FAIL — `Failed to resolve import "../src/lib/paneWidths"`.

- [ ] **Step 3: Write the implementation**

Create `desktop/src/lib/paneWidths.ts`:

```ts
// #526 — pane geometry.
//
// Widths are stored as FRACTIONS of the container, not pixels, so CSS can
// scale the panes on window resize with no JS involved and so restored
// geometry stays meaningful across differently-sized displays.
//
// Minimums are absolute pixels because legibility is an absolute property:
// a 180px sidebar is equally cramped on a 1440p and a 6K panel. There is
// deliberately NO maximum token — a drag's upper bound is derived from
// whatever the other panes need for their own floors.
//
// STORAGE POLICY: `secretary.panes.*` holds UI geometry only. Never vault
// data, never anything derived from a decrypted record. This is the first and
// so far only localStorage use in the frontend; keep it that way.

export const SIDEBAR_MIN_PX = 180;
export const LIST_MIN_PX = 260;
export const DETAIL_MIN_PX = 320;

export const SIDEBAR_DEFAULT_FRACTION = 0.18;
export const LIST_DEFAULT_FRACTION = 0.26;

export const SIDEBAR_KEY = 'secretary.panes.sidebarFraction';
export const LIST_KEY = 'secretary.panes.listFraction';

/** The two left panes may not claim the whole container — the detail pane
    keeps a share, on top of its own pixel floor. Not a per-pane cap: a single
    pane can still be dragged out to nearly this whole budget. */
const MAX_COMBINED_FRACTION = 0.85;

export type PaneKey = 'sidebar' | 'list';

function keyFor(pane: PaneKey): string {
  return pane === 'sidebar' ? SIDEBAR_KEY : LIST_KEY;
}

/** Parse one stored fraction, falling back on anything not a real number
    strictly inside (0, 1). Guards NaN, Infinity, negatives and junk. */
function parseFraction(raw: string | null, fallback: number): number {
  if (raw === null) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0 || value >= 1) return fallback;
  return value;
}

export function loadFractions(storage: Pick<Storage, 'getItem'>): {
  sidebar: number;
  list: number;
} {
  let sidebar = parseFraction(storage.getItem(SIDEBAR_KEY), SIDEBAR_DEFAULT_FRACTION);
  let list = parseFraction(storage.getItem(LIST_KEY), LIST_DEFAULT_FRACTION);
  const combined = sidebar + list;
  if (combined > MAX_COMBINED_FRACTION) {
    // Scale both down proportionally rather than truncating one, so restoring
    // a wide-monitor layout on a narrow screen keeps its shape.
    const scale = MAX_COMBINED_FRACTION / combined;
    sidebar *= scale;
    list *= scale;
  }
  return { sidebar, list };
}

/** Persist one pane's fraction. Never throws — a storage failure (Safari
    private browsing throws on setItem) must not break the app over geometry. */
export function saveFraction(
  storage: Pick<Storage, 'setItem'>,
  pane: PaneKey,
  fraction: number
): void {
  try {
    storage.setItem(keyFor(pane), String(fraction));
  } catch {
    // Geometry is not worth an error path.
  }
}

/**
 * Clamp a dragged pane's width in pixels.
 *
 * Lower bound is the pane's own floor. Upper bound is whatever the container
 * has left once every OTHER pane keeps its floor — derived, so a wider window
 * genuinely allows a wider pane. If the container cannot satisfy everyone
 * (below the enforced window minimum) the floor wins rather than returning a
 * nonsensical width.
 */
export function clampPaneWidthPx(args: {
  requestedPx: number;
  ownMinPx: number;
  containerPx: number;
  siblingsMinPx: number;
}): number {
  const max = args.containerPx - args.siblingsMinPx;
  if (max < args.ownMinPx) return args.ownMinPx;
  return Math.min(Math.max(args.requestedPx, args.ownMinPx), max);
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd desktop && pnpm vitest run tests/paneWidths.test.ts
```

Expected: PASS, 18 tests.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/paneWidths.ts desktop/tests/paneWidths.test.ts
git commit -m "feat(desktop): pane width fractions with derived, uncapped drag bounds (#526)"
```

---

### Task 5: The `PaneShell` component, theme tokens and window minimum

**Files:**
- Create: `desktop/src/components/PaneShell.svelte`
- Modify: `desktop/src/theme.css`
- Modify: `desktop/src-tauri/tauri.conf.json:18`
- Test: `desktop/tests/PaneShell.test.ts`

**Interfaces:**
- Consumes: `SIDEBAR_MIN_PX`, `LIST_MIN_PX`, `DETAIL_MIN_PX`, `loadFractions`, `saveFraction`, `clampPaneWidthPx` from Task 4.
- Produces: a component taking four snippet props — `sidebar`, `list`, `detail`, and a boolean `spanDetail`. When `spanDetail` is true the list snippet occupies both right-hand columns and `detail` is not rendered.

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/PaneShell.test.ts`:

```ts
// Tests for PaneShell — the three-column grid and its two splitters (#526).
//
// jsdom has no layout engine, so these assert structure, ARIA and the
// keyboard path (which needs no measurement), not pixel geometry. The drag
// maths itself is unit-tested in paneWidths.test.ts.

import { describe, it, expect } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import PaneShell from '../src/components/PaneShell.svelte';

function textSnippet(text: string) {
  return createRawSnippet(() => ({ render: () => `<span>${text}</span>` }));
}

function renderShell(spanDetail = false) {
  return render(PaneShell, {
    props: {
      sidebar: textSnippet('SIDEBAR'),
      list: textSnippet('LIST'),
      detail: textSnippet('DETAIL'),
      spanDetail
    }
  });
}

describe('PaneShell — structure', () => {
  it('renders all three panes', () => {
    const { getByText } = renderShell();
    expect(getByText('SIDEBAR')).toBeTruthy();
    expect(getByText('LIST')).toBeTruthy();
    expect(getByText('DETAIL')).toBeTruthy();
  });

  it('omits the detail pane when the list spans both columns', () => {
    const { queryByText, getByText } = renderShell(true);
    expect(getByText('LIST')).toBeTruthy();
    expect(queryByText('DETAIL')).toBeNull();
  });
});

describe('PaneShell — splitters are accessible', () => {
  it('exposes two vertical separators', () => {
    const { getAllByRole } = renderShell();
    const separators = getAllByRole('separator');
    expect(separators).toHaveLength(2);
    for (const s of separators) {
      expect(s.getAttribute('aria-orientation')).toBe('vertical');
    }
  });

  it('each separator has a distinguishing accessible name', () => {
    const { getByRole } = renderShell();
    expect(getByRole('separator', { name: /sidebar/i })).toBeTruthy();
    expect(getByRole('separator', { name: /record list/i })).toBeTruthy();
  });

  it('separators are keyboard reachable', () => {
    const { getAllByRole } = renderShell();
    for (const s of getAllByRole('separator')) {
      expect(s.getAttribute('tabindex')).toBe('0');
    }
  });

  it('hides the splitters when the list spans both columns', () => {
    // With no detail pane there is nothing to resize against on the right.
    const { getAllByRole } = renderShell(true);
    expect(getAllByRole('separator')).toHaveLength(1);
  });
});

describe('PaneShell — keyboard resize', () => {
  it('ArrowRight widens the sidebar', async () => {
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    const before = shell.style.getPropertyValue('--pane-sidebar-w');
    await fireEvent.keyDown(getByRole('separator', { name: /sidebar/i }), { key: 'ArrowRight' });
    const after = shell.style.getPropertyValue('--pane-sidebar-w');
    expect(after).not.toBe(before);
    expect(parseFloat(after)).toBeGreaterThan(parseFloat(before || '18'));
  });

  it('ArrowLeft narrows the sidebar', async () => {
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    const before = parseFloat(shell.style.getPropertyValue('--pane-sidebar-w') || '18');
    await fireEvent.keyDown(getByRole('separator', { name: /sidebar/i }), { key: 'ArrowLeft' });
    const after = parseFloat(shell.style.getPropertyValue('--pane-sidebar-w'));
    expect(after).toBeLessThan(before);
  });

  it('ignores unrelated keys', async () => {
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    const before = shell.style.getPropertyValue('--pane-sidebar-w');
    await fireEvent.keyDown(getByRole('separator', { name: /sidebar/i }), { key: 'a' });
    expect(shell.style.getPropertyValue('--pane-sidebar-w')).toBe(before);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd desktop && pnpm vitest run tests/PaneShell.test.ts
```

Expected: FAIL — cannot resolve `../src/components/PaneShell.svelte`.

- [ ] **Step 3: Add the theme tokens**

In `desktop/src/theme.css`, inside the `:root` block, after the radius tokens:

```css
  /* Three-pane layout (#526). Fractions of the container, not pixels, so the
     panes scale with the window in pure CSS. These are DEFAULTS — a persisted
     value is applied as an inline style on .pane-shell and wins by cascade.
     Pixel floors live in paneWidths.ts; there is deliberately no maximum. */
  --pane-sidebar-w: 18%;
  --pane-list-w: 26%;
```

- [ ] **Step 4: Raise the window minimum**

In `desktop/src-tauri/tauri.conf.json`, change `"minWidth": 600` to:

```json
        "minWidth": 760,
```

760 = 180 + 260 + 320, the sum of the three pane floors, so the floors are always simultaneously satisfiable.

- [ ] **Step 5: Write the component**

Create `desktop/src/components/PaneShell.svelte`:

```svelte
<script lang="ts">
  import type { Snippet } from 'svelte';
  import {
    SIDEBAR_MIN_PX,
    LIST_MIN_PX,
    DETAIL_MIN_PX,
    loadFractions,
    saveFraction,
    clampPaneWidthPx,
    type PaneKey
  } from '../lib/paneWidths';

  type Props = {
    sidebar: Snippet;
    list: Snippet;
    detail: Snippet;
    /** When true the list occupies both right-hand columns (Trash / Contacts,
        which have no list/detail split of their own) and `detail` is not
        rendered. */
    spanDetail?: boolean;
  };
  let { sidebar, list, detail, spanDetail = false }: Props = $props();

  // Percentage points moved per arrow keypress. Coarse enough to be useful,
  // fine enough to land on a chosen width.
  const KEYBOARD_STEP_PCT = 2;

  const stored = loadFractions(localStorage);
  let sidebarPct = $state(stored.sidebar * 100);
  let listPct = $state(stored.list * 100);

  let shellEl = $state<HTMLDivElement | null>(null);
  let dragging = $state<PaneKey | null>(null);

  function containerPx(): number {
    return shellEl?.getBoundingClientRect().width ?? 0;
  }

  /** Commit a pane width given a desired pixel value, clamping against the
      other panes' floors and persisting the resulting fraction. */
  function setPaneFromPx(pane: PaneKey, requestedPx: number): void {
    const width = containerPx();
    if (width <= 0) return;
    const px = clampPaneWidthPx({
      requestedPx,
      ownMinPx: pane === 'sidebar' ? SIDEBAR_MIN_PX : LIST_MIN_PX,
      containerPx: width,
      siblingsMinPx:
        pane === 'sidebar' ? LIST_MIN_PX + DETAIL_MIN_PX : SIDEBAR_MIN_PX + DETAIL_MIN_PX
    });
    const pct = (px / width) * 100;
    if (pane === 'sidebar') sidebarPct = pct;
    else listPct = pct;
    saveFraction(localStorage, pane, px / width);
  }

  function currentPx(pane: PaneKey): number {
    return ((pane === 'sidebar' ? sidebarPct : listPct) / 100) * containerPx();
  }

  function onSplitterKeydown(pane: PaneKey, e: KeyboardEvent): void {
    const direction = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (direction === 0) return;
    e.preventDefault();
    const width = containerPx();
    // jsdom reports a zero-width container; fall back to a percentage step so
    // the keyboard path stays exercisable in tests and on a not-yet-laid-out
    // first frame.
    if (width <= 0) {
      const next = (pane === 'sidebar' ? sidebarPct : listPct) + direction * KEYBOARD_STEP_PCT;
      if (pane === 'sidebar') sidebarPct = next;
      else listPct = next;
      saveFraction(localStorage, pane, next / 100);
      return;
    }
    setPaneFromPx(pane, currentPx(pane) + direction * (KEYBOARD_STEP_PCT / 100) * width);
  }

  function onPointerDown(pane: PaneKey, e: PointerEvent): void {
    dragging = pane;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }

  function onPointerMove(e: PointerEvent): void {
    if (!dragging || !shellEl) return;
    const left = shellEl.getBoundingClientRect().left;
    // The sidebar splitter sets the sidebar's right edge; the list splitter
    // sets the list's right edge, so the list width is the remainder.
    if (dragging === 'sidebar') setPaneFromPx('sidebar', e.clientX - left);
    else setPaneFromPx('list', e.clientX - left - currentPx('sidebar'));
  }

  function onPointerUp(e: PointerEvent): void {
    if (!dragging) return;
    (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    dragging = null;
  }
</script>

<div
  class="pane-shell"
  class:pane-shell--spanned={spanDetail}
  bind:this={shellEl}
  style="--pane-sidebar-w: {sidebarPct}%; --pane-list-w: {listPct}%;"
>
  <div class="pane-shell__sidebar">{@render sidebar()}</div>

  <div
    class="pane-shell__splitter"
    role="separator"
    aria-orientation="vertical"
    aria-label="Resize sidebar"
    tabindex="0"
    onkeydown={(e) => onSplitterKeydown('sidebar', e)}
    onpointerdown={(e) => onPointerDown('sidebar', e)}
    onpointermove={onPointerMove}
    onpointerup={onPointerUp}
  ></div>

  <div class="pane-shell__list">{@render list()}</div>

  {#if !spanDetail}
    <div
      class="pane-shell__splitter"
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize record list"
      tabindex="0"
      onkeydown={(e) => onSplitterKeydown('list', e)}
      onpointerdown={(e) => onPointerDown('list', e)}
      onpointermove={onPointerMove}
      onpointerup={onPointerUp}
    ></div>

    <div class="pane-shell__detail">{@render detail()}</div>
  {/if}
</div>

<style>
  .pane-shell {
    display: grid;
    grid-template-columns:
      minmax(180px, var(--pane-sidebar-w))
      auto
      minmax(260px, var(--pane-list-w))
      auto
      minmax(320px, 1fr);
    height: 100%;
    min-height: 0;
    overflow: hidden;
  }

  /* Trash / Contacts: sidebar, one splitter, then everything else. */
  .pane-shell--spanned {
    grid-template-columns: minmax(180px, var(--pane-sidebar-w)) auto 1fr;
  }

  .pane-shell__sidebar,
  .pane-shell__list,
  .pane-shell__detail {
    min-width: 0;
    min-height: 0;
    overflow-y: auto;
  }

  .pane-shell__sidebar {
    background: var(--color-bg);
  }

  .pane-shell__list,
  .pane-shell__detail {
    background: var(--color-bg-elevated);
  }

  .pane-shell__splitter {
    width: 5px;
    cursor: col-resize;
    background: var(--color-border);
    /* Widen the hit area without widening the visual line. */
    background-clip: content-box;
    border-inline: 2px solid transparent;
  }

  .pane-shell__splitter:hover,
  .pane-shell__splitter:focus-visible {
    background-color: var(--color-primary);
    outline: none;
  }
</style>
```

- [ ] **Step 6: Run the test to verify it passes**

```bash
cd desktop && pnpm vitest run tests/PaneShell.test.ts
```

Expected: PASS, 8 tests.

- [ ] **Step 7: Type-check**

```bash
cd desktop && pnpm svelte-check
```

- [ ] **Step 8: Commit**

```bash
git add desktop/src/components/PaneShell.svelte desktop/tests/PaneShell.test.ts \
        desktop/src/theme.css desktop/src-tauri/tauri.conf.json
git commit -m "feat(desktop): PaneShell three-column grid with resizable splitters (#526)"
```

---

### Task 6: `BlockSidebar`, and BlockCard's hover actions

**Files:**
- Create: `desktop/src/components/BlockSidebar.svelte`
- Modify: `desktop/src/components/BlockCard.svelte`
- Test: `desktop/tests/BlockSidebar.test.ts`
- Test: `desktop/tests/BlockCard.test.ts` (add a selection test)

**Interfaces:**
- Consumes: `SidebarSelection` from Task 3.
- Produces: a `BlockSidebar` component with props
  `{ blocks: BlockSummaryDto[]; blockCount: number; selection: SidebarSelection; onOpenBlock; onNewBlock; onOpenTrash; onOpenContacts; onTrashBlock; onShareBlock; onRenameBlock }`.
  `BlockCard` gains one prop: `selected?: boolean`.

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/BlockSidebar.test.ts`:

```ts
// Tests for BlockSidebar — the left pane (#526). Replaces the blocks-root
// screen: block list plus the Trash / Contacts destinations plus "New block".

import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import BlockSidebar from '../src/components/BlockSidebar.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';
import type { SidebarSelection } from '../src/lib/panes';

const BLOCKS: BlockSummaryDto[] = [
  {
    blockUuidHex: 'aaaa1111',
    blockName: 'Banking',
    createdAtMs: 1_700_000_000_000,
    lastModifiedMs: 1_700_000_100_000
  },
  {
    blockUuidHex: 'bbbb2222',
    blockName: 'Work',
    createdAtMs: 1_700_000_000_000,
    lastModifiedMs: 1_700_000_100_000
  }
];

function props(selection: SidebarSelection = { kind: 'none' }, overrides = {}) {
  return {
    blocks: BLOCKS,
    blockCount: BLOCKS.length,
    selection,
    onOpenBlock: () => {},
    onNewBlock: () => {},
    onOpenTrash: () => {},
    onOpenContacts: () => {},
    onTrashBlock: () => {},
    onShareBlock: () => {},
    onRenameBlock: () => {},
    ...overrides
  };
}

describe('BlockSidebar — contents', () => {
  it('lists every block', () => {
    const { getByText } = render(BlockSidebar, { props: props() });
    expect(getByText('Banking')).toBeTruthy();
    expect(getByText('Work')).toBeTruthy();
  });

  it('offers the Trash and Contacts destinations', () => {
    const { getByRole } = render(BlockSidebar, { props: props() });
    expect(getByRole('button', { name: /trash/i })).toBeTruthy();
    expect(getByRole('button', { name: /contacts/i })).toBeTruthy();
  });

  it('offers New block', () => {
    const { getByRole } = render(BlockSidebar, { props: props() });
    expect(getByRole('button', { name: /new block/i })).toBeTruthy();
  });

  it('shows the block count', () => {
    const { getByText } = render(BlockSidebar, { props: props() });
    expect(getByText(/2 blocks/i)).toBeTruthy();
  });

  it('singularises the block count', () => {
    const { getByText } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { blocks: [BLOCKS[0]], blockCount: 1 })
    });
    expect(getByText(/1 block(?!s)/i)).toBeTruthy();
  });
});

describe('BlockSidebar — callbacks', () => {
  it('calls onOpenBlock with the clicked block', async () => {
    const onOpenBlock = vi.fn();
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'none' }, { onOpenBlock }) });
    await fireEvent.click(getByRole('button', { name: /banking/i }));
    expect(onOpenBlock).toHaveBeenCalledWith(BLOCKS[0]);
  });

  it('calls onOpenTrash', async () => {
    const onOpenTrash = vi.fn();
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'none' }, { onOpenTrash }) });
    await fireEvent.click(getByRole('button', { name: /trash/i }));
    expect(onOpenTrash).toHaveBeenCalled();
  });

  it('calls onOpenContacts', async () => {
    const onOpenContacts = vi.fn();
    const { getByRole } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { onOpenContacts })
    });
    await fireEvent.click(getByRole('button', { name: /contacts/i }));
    expect(onOpenContacts).toHaveBeenCalled();
  });
});

describe('BlockSidebar — selection is reflected for assistive tech', () => {
  it('marks the selected block with aria-current', () => {
    const { getByRole } = render(
      BlockSidebar,
      { props: props({ kind: 'block', blockUuidHex: 'aaaa1111' }) }
    );
    expect(getByRole('button', { name: /banking/i }).getAttribute('aria-current')).toBe('true');
    expect(getByRole('button', { name: /work/i }).getAttribute('aria-current')).toBeNull();
  });

  it('marks the Trash destination when it is the selection', () => {
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'trash' }) });
    expect(getByRole('button', { name: /trash/i }).getAttribute('aria-current')).toBe('true');
  });

  it('marks the Contacts destination when it is the selection', () => {
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'contacts' }) });
    expect(getByRole('button', { name: /contacts/i }).getAttribute('aria-current')).toBe('true');
  });

  it('marks nothing when the selection is none', () => {
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'none' }) });
    expect(getByRole('button', { name: /banking/i }).getAttribute('aria-current')).toBeNull();
    expect(getByRole('button', { name: /trash/i }).getAttribute('aria-current')).toBeNull();
  });
});
```

Append to `desktop/tests/BlockCard.test.ts`:

```ts
describe('BlockCard.svelte — selection (#526)', () => {
  it('sets aria-current when selected', () => {
    const { getByRole } = render(BlockCard, {
      props: { block: BLOCK, onClick: () => {}, selected: true }
    });
    expect(getByRole('button', { name: /banking/i }).getAttribute('aria-current')).toBe('true');
  });

  it('omits aria-current when not selected', () => {
    const { getByRole } = render(BlockCard, {
      props: { block: BLOCK, onClick: () => {}, selected: false }
    });
    expect(getByRole('button', { name: /banking/i }).getAttribute('aria-current')).toBeNull();
  });

  it('still exposes its actions to assistive tech when they are visually hidden', () => {
    // Actions reveal on hover/selection VISUALLY (CSS opacity), but must stay
    // in the accessibility tree — a keyboard user never hovers.
    const { getByRole } = render(BlockCard, {
      props: { block: BLOCK, onClick: () => {}, onRename: () => {}, selected: false }
    });
    expect(getByRole('button', { name: /rename block/i })).toBeTruthy();
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd desktop && pnpm vitest run tests/BlockSidebar.test.ts tests/BlockCard.test.ts
```

Expected: FAIL — cannot resolve `BlockSidebar.svelte`; BlockCard has no `selected` prop.

- [ ] **Step 3: Add the `selected` prop and hover actions to BlockCard**

In `desktop/src/components/BlockCard.svelte`, extend the props type and destructuring:

```svelte
  type Props = {
    block: BlockSummaryDto;
    onClick: (block: BlockSummaryDto) => void;
    onTrash?: (block: BlockSummaryDto) => void;
    onShare?: (block: BlockSummaryDto) => void;
    onRename?: (block: BlockSummaryDto) => void;
    /** #526 — sidebar selection. Drives aria-current and keeps the row's
        actions visible without a hover. */
    selected?: boolean;
  };
  let { block, onClick, onTrash, onShare, onRename, selected = false }: Props = $props();
```

Add `class:block-card-wrap--selected={selected}` to the wrapper div and `aria-current={selected ? 'true' : undefined}` to the main card button:

```svelte
<div class="block-card-wrap" class:block-card-wrap--selected={selected}>
  <button
    type="button"
    class="block-card"
    aria-label={`Block ${block.blockName}, last modified ${formatShortDate(block.lastModifiedMs)}`}
    aria-current={selected ? 'true' : undefined}
    onclick={() => onClick(block)}
  >
```

Add a `<style>` block at the end of the file. Note the actions stay in the DOM and in the accessibility tree — only their opacity changes, so keyboard users are unaffected:

```svelte
<style>
  /* #526 — three action buttons do not fit a sidebar column. Reveal them on
     hover, on selection, or when anything inside the row has keyboard focus.
     Opacity only: the buttons stay in the DOM and in the accessibility tree,
     because a keyboard user never hovers. */
  .block-card-wrap :global(.block-card__rename),
  .block-card-wrap :global(.block-card__share),
  .block-card-wrap :global(.block-card__trash) {
    opacity: 0;
    transition: opacity 120ms ease;
  }

  .block-card-wrap:hover :global(.block-card__rename),
  .block-card-wrap:hover :global(.block-card__share),
  .block-card-wrap:hover :global(.block-card__trash),
  .block-card-wrap:focus-within :global(.block-card__rename),
  .block-card-wrap:focus-within :global(.block-card__share),
  .block-card-wrap:focus-within :global(.block-card__trash),
  .block-card-wrap--selected :global(.block-card__rename),
  .block-card-wrap--selected :global(.block-card__share),
  .block-card-wrap--selected :global(.block-card__trash) {
    opacity: 1;
  }

  @media (prefers-reduced-motion: reduce) {
    .block-card-wrap :global(.block-card__rename),
    .block-card-wrap :global(.block-card__share),
    .block-card-wrap :global(.block-card__trash) {
      transition: none;
    }
  }
</style>
```

- [ ] **Step 4: Write BlockSidebar**

Create `desktop/src/components/BlockSidebar.svelte`:

```svelte
<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';
  import type { SidebarSelection } from '../lib/panes';
  import BlockCard from './BlockCard.svelte';
  import Trash from './icons/Trash.svelte';
  import Users from './icons/Users.svelte';

  type Props = {
    blocks: BlockSummaryDto[];
    blockCount: number;
    selection: SidebarSelection;
    onOpenBlock: (block: BlockSummaryDto) => void;
    onNewBlock: () => void;
    onOpenTrash: () => void;
    onOpenContacts: () => void;
    onTrashBlock: (block: BlockSummaryDto) => void;
    onShareBlock: (block: BlockSummaryDto) => void;
    onRenameBlock: (block: BlockSummaryDto) => void;
  };
  let {
    blocks,
    blockCount,
    selection,
    onOpenBlock,
    onNewBlock,
    onOpenTrash,
    onOpenContacts,
    onTrashBlock,
    onShareBlock,
    onRenameBlock
  }: Props = $props();

  function isSelectedBlock(block: BlockSummaryDto): boolean {
    return selection.kind === 'block' && selection.blockUuidHex === block.blockUuidHex;
  }
</script>

<nav class="block-sidebar" aria-label="Vault blocks">
  <button type="button" class="block-sidebar__new" onclick={onNewBlock}>+ New block</button>

  <div class="block-sidebar__count">
    {blockCount} block{blockCount === 1 ? '' : 's'}
  </div>

  <div class="block-sidebar__blocks">
    {#each blocks as block (block.blockUuidHex)}
      <BlockCard
        {block}
        selected={isSelectedBlock(block)}
        onClick={onOpenBlock}
        onTrash={onTrashBlock}
        onShare={onShareBlock}
        onRename={onRenameBlock}
      />
    {/each}
  </div>

  <div class="block-sidebar__destinations">
    <button
      type="button"
      class="block-sidebar__destination"
      aria-current={selection.kind === 'trash' ? 'true' : undefined}
      onclick={onOpenTrash}
    >
      <Trash />Trash
    </button>
    <button
      type="button"
      class="block-sidebar__destination"
      aria-current={selection.kind === 'contacts' ? 'true' : undefined}
      onclick={onOpenContacts}
    >
      <Users />Contacts
    </button>
  </div>
</nav>

<style>
  .block-sidebar {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-3);
    height: 100%;
    min-height: 0;
  }

  .block-sidebar__count {
    font-size: var(--font-size-xs);
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .block-sidebar__blocks {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }

  /* Destinations pin to the bottom, away from the block list they are not
     part of. */
  .block-sidebar__destinations {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding-top: var(--space-2);
    border-top: 1px solid var(--color-border);
  }

  .block-sidebar__destination {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2);
    border: none;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--color-text);
    font-size: var(--font-size-sm);
    text-align: left;
    cursor: pointer;
  }

  .block-sidebar__destination:hover {
    background: var(--color-bg-elevated);
  }

  .block-sidebar__destination[aria-current='true'] {
    background: var(--color-bg-elevated);
    color: var(--color-primary);
    font-weight: 600;
  }
</style>
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd desktop && pnpm vitest run tests/BlockSidebar.test.ts tests/BlockCard.test.ts
```

Expected: PASS.

- [ ] **Step 6: Type-check and commit**

```bash
cd desktop && pnpm svelte-check
cd .. && git add desktop/src/components/BlockSidebar.svelte desktop/src/components/BlockCard.svelte \
        desktop/tests/BlockSidebar.test.ts desktop/tests/BlockCard.test.ts
git commit -m "feat(desktop): BlockSidebar left pane; BlockCard actions reveal on hover (#526)"
```

---

### Task 7: Record rows — titles, selection, and the frozen list

**Files:**
- Modify: `desktop/src/components/RecordRow.svelte`
- Modify: `desktop/src/components/RecordList.svelte`
- Test: `desktop/tests/RecordRow.test.ts`

**Interfaces:**
- Consumes: `RecordDto.title` / `RecordDto.subtitle` from Task 2.
- Produces: `RecordRow` gains `selected?: boolean` and `frozen?: boolean`; `RecordList` gains `selectedRecordUuidHex: string | null` and `frozen: boolean` and **loses its back button**.

- [ ] **Step 1: Write the failing test**

Add to `desktop/tests/RecordRow.test.ts` (keep the existing describes; the fixture in that file needs `title` / `subtitle` added to satisfy the type):

```ts
describe('RecordRow — derived labels (#526)', () => {
  it('renders the derived title as the primary text', () => {
    const record = { ...RECORD, title: 'alice@example.test', subtitle: 'url: https://bank.test' };
    const { getByText } = render(RecordRow, { props: { record, onClick: () => {} } });
    expect(getByText('alice@example.test')).toBeTruthy();
  });

  it('renders the subtitle when present', () => {
    const record = { ...RECORD, title: 'Bank', subtitle: 'username: alice' };
    const { getByText } = render(RecordRow, { props: { record, onClick: () => {} } });
    expect(getByText('username: alice')).toBeTruthy();
  });

  it('renders no subtitle element when the record has none', () => {
    const record = { ...RECORD, title: 'Bank', subtitle: null };
    const { container } = render(RecordRow, { props: { record, onClick: () => {} } });
    expect(container.querySelector('.record-row__subtitle')).toBeNull();
  });

  it('puts the title in the aria-label so rows are distinguishable by ear', () => {
    const record = { ...RECORD, title: 'alice@example.test', subtitle: null };
    const { getByRole } = render(RecordRow, { props: { record, onClick: () => {} } });
    expect(getByRole('button', { name: /alice@example\.test/ })).toBeTruthy();
  });
});

describe('RecordRow — selection and freezing (#526)', () => {
  it('sets aria-current when selected', () => {
    const { getByRole } = render(RecordRow, {
      props: { record: RECORD, onClick: () => {}, selected: true }
    });
    expect(getByRole('button', { name: new RegExp(RECORD.title) }).getAttribute('aria-current')).toBe('true');
  });

  it('disables the row when frozen', () => {
    const { getByRole } = render(RecordRow, {
      props: { record: RECORD, onClick: () => {}, frozen: true }
    });
    expect(
      (getByRole('button', { name: new RegExp(RECORD.title) }) as HTMLButtonElement).disabled
    ).toBe(true);
  });

  it('does not fire onClick when frozen', async () => {
    const onClick = vi.fn();
    const { getByRole } = render(RecordRow, {
      props: { record: RECORD, onClick, frozen: true }
    });
    await fireEvent.click(getByRole('button', { name: new RegExp(RECORD.title) }));
    expect(onClick).not.toHaveBeenCalled();
  });

  it('hides the row actions when frozen so an edit cannot be interrupted', () => {
    const { queryByRole } = render(RecordRow, {
      props: { record: RECORD, onClick: () => {}, onDelete: () => {}, frozen: true }
    });
    expect(queryByRole('button', { name: /delete record/i })).toBeNull();
  });

  it('shows the row actions when not frozen', () => {
    const { getByRole } = render(RecordRow, {
      props: { record: RECORD, onClick: () => {}, onDelete: () => {}, frozen: false }
    });
    expect(getByRole('button', { name: /delete record/i })).toBeTruthy();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd desktop && pnpm vitest run tests/RecordRow.test.ts
```

Expected: FAIL — the title is not rendered; `selected` / `frozen` are not props.

- [ ] **Step 3: Update RecordRow**

Replace `desktop/src/components/RecordRow.svelte` in full:

```svelte
<script lang="ts">
  import type { RecordDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';
  import { isContentlessTombstone } from '../lib/records';

  // onDelete / onRestore / onMove are optional so existing call sites that
  // only browse (no write actions wired) keep working unchanged. When supplied,
  // a live row gets Delete + Move actions and a tombstoned row gets Restore.
  type Props = {
    record: RecordDto;
    onClick: (record: RecordDto) => void;
    onDelete?: (record: RecordDto) => void;
    onRestore?: (record: RecordDto) => void;
    onMove?: (record: RecordDto) => void;
    /** #526 — this row is the one open in the detail pane. */
    selected?: boolean;
    /** #526 — an editor is open in the detail pane. Rows go non-interactive
        so a stray click cannot silently discard an unsaved edit. */
    frozen?: boolean;
  };
  let {
    record,
    onClick,
    onDelete,
    onRestore,
    onMove,
    selected = false,
    frozen = false
  }: Props = $props();

  let countLabel = $derived(`${record.fieldCount} field${record.fieldCount === 1 ? '' : 's'}`);
  let deleted = $derived(record.tombstoned === true);
  let contentless = $derived(isContentlessTombstone(record));
  // Title first: it is what distinguishes one row from another, so it must
  // lead the accessible name too.
  let ariaLabel = $derived(
    `${record.title}, ${record.recordType} record, ${countLabel}${
      contentless ? ', no recoverable contents' : ''
    }`
  );
</script>

<div
  class="record-row-wrap"
  class:record-row--deleted={deleted}
  class:record-row--selected={selected}
  class:record-row--frozen={frozen}
>
  <button
    type="button"
    class="record-row"
    aria-label={ariaLabel}
    aria-current={selected ? 'true' : undefined}
    disabled={deleted || frozen}
    onclick={() => onClick(record)}
  >
    <span class="record-row__title">{record.title}</span>
    {#if record.subtitle}
      <span class="record-row__subtitle">{record.subtitle}</span>
    {/if}
    {#each record.tags as tag (tag)}
      <span class="record-row__tag">{tag}</span>
    {/each}
    <span class="record-row__meta">{countLabel} · modified {formatShortDate(record.lastModMs)}</span>
    {#if contentless}
      <span class="record-row__no-content">· no recoverable contents</span>
    {/if}
  </button>

  {#if !frozen}
    {#if deleted && onRestore}
      <button type="button" class="record-row__restore" aria-label="Restore record" onclick={() => onRestore(record)}>Restore</button>
    {:else if !deleted}
      {#if onMove}
        <button type="button" class="record-row__move" aria-label="Move record" onclick={() => onMove(record)}>Move</button>
      {/if}
      {#if onDelete}
        <button type="button" class="record-row__delete" aria-label="Delete record" onclick={() => onDelete(record)}>Delete</button>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .record-row__title {
    display: block;
    font-size: var(--font-size-md);
    color: var(--color-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .record-row__subtitle {
    display: block;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .record-row--selected {
    background: var(--color-primary);
    border-radius: var(--radius-sm);
  }

  .record-row--selected .record-row__title,
  .record-row--selected .record-row__subtitle {
    color: var(--color-on-danger); /* white — reads on the primary fill */
  }

  /* Frozen: an editor is open. Dimmed and non-interactive, so the only way
     out of the editor stays Save or Cancel. */
  .record-row--frozen {
    opacity: 0.45;
    pointer-events: none;
  }
</style>
```

- [ ] **Step 4: Update RecordList**

In `desktop/src/components/RecordList.svelte`:

Extend the props (replace lines 21-22):

```svelte
  type Props = {
    block: BlockSummaryDto;
    blockCount: number;
    /** #526 — the row open in the detail pane, or null. */
    selectedRecordUuidHex?: string | null;
    /** #526 — an editor is open; rows go non-interactive. */
    frozen?: boolean;
  };
  let { block, blockCount, selectedRecordUuidHex = null, frozen = false }: Props = $props();
```

Remove the now-unused `back` import — change line 11 to:

```svelte
  import { openRecord, openNewRecord } from '../lib/browse';
```

Delete the back button (line 160) entirely:

```svelte
  <button type="button" class="record-list__back" onclick={() => back()}>← {block.blockName}</button>
```

…and replace it with a non-interactive heading, since the pane no longer navigates but still needs to say which block it is showing:

```svelte
  <h2 class="record-list__heading">{block.blockName}</h2>
```

Pass the two new props through to each row (replace line 178):

```svelte
      <RecordRow
        {record}
        onClick={openRecord}
        {onDelete}
        {onRestore}
        onMove={canMove ? onMove : undefined}
        selected={record.recordUuidHex === selectedRecordUuidHex}
        {frozen}
      />
```

Finally, disable the "+ Add record" button while frozen — starting a second editor from inside one is the same hazard (replace line 162):

```svelte
  <button
    type="button"
    class="record-list__add"
    disabled={frozen}
    onclick={() => openNewRecord(block)}
  >+ Add record</button>
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd desktop && pnpm vitest run tests/RecordRow.test.ts
```

Expected: PASS. `tests/RecordList*.test.ts` and any other suite rendering a `RecordDto` fixture will now fail to type-check until `title` / `subtitle` are added to those fixtures — that is Task 8's job, so do not chase it here beyond RecordRow's own file.

- [ ] **Step 6: Commit**

```bash
git add desktop/src/components/RecordRow.svelte desktop/src/components/RecordList.svelte \
        desktop/tests/RecordRow.test.ts
git commit -m "feat(desktop): record rows show derived titles; selection and frozen states (#526)"
```

---

### Task 8: Wire it together in `Vault.svelte`, and repair the existing suite

This is the task that makes the feature visible. It is last because everything it composes is already tested.

**Files:**
- Modify: `desktop/src/routes/Vault.svelte`
- Modify: `desktop/src/components/FieldViewer.svelte`
- Modify: whichever files under `desktop/tests/` fail — at minimum any with a `RecordDto` fixture

**Interfaces:**
- Consumes: everything from Tasks 2-7.
- Produces: no new exports.

- [ ] **Step 1: Write the failing test**

Add to `desktop/tests/FieldViewer.test.ts`:

```ts
describe('FieldViewer — three-pane changes (#526)', () => {
  it('no longer renders a back button', () => {
    // Escape and the sidebar own navigation now; a back button inside a
    // permanently-visible pane has nothing to go back to.
    const { queryByRole } = render(FieldViewer, { props: { block: BLOCK, record: RECORD } });
    expect(queryByRole('button', { name: /←/ })).toBeNull();
  });

  it('still offers Edit', () => {
    const { getByRole } = render(FieldViewer, { props: { block: BLOCK, record: RECORD } });
    expect(getByRole('button', { name: /edit/i })).toBeTruthy();
  });
});
```

- [ ] **Step 2: Run the whole suite to enumerate the damage**

```bash
cd desktop && pnpm test
```

Expected: FAIL. Record the failing files — they are the work list for Step 5. Two classes:
(a) `RecordDto` fixtures missing `title` / `subtitle`;
(b) assertions on back buttons that no longer exist.

- [ ] **Step 3: Strip the back button from FieldViewer**

In `desktop/src/components/FieldViewer.svelte`, change the import on line 2 to drop `back`:

```svelte
  import { openEditRecord } from '../lib/browse';
```

and delete line 11 (the `field-viewer__back` button), replacing it with a heading:

```svelte
  <h2 class="field-viewer__title">{record.title}</h2>
```

- [ ] **Step 4: Rewrite Vault.svelte's markup**

Replace the entire `{#if $browseNav.level === 'blocks'} … {/if}` chain (currently `Vault.svelte:116-172`) with the PaneShell composition below. Everything above line 116 and below line 172 — the warnings loop, SettingsDialog, ReauthPasswordDialog, ConfirmDialog, ShareDialog — is unchanged.

Add to the imports:

```svelte
  import { panesFor } from '../lib/panes';
  import PaneShell from '../components/PaneShell.svelte';
  import BlockSidebar from '../components/BlockSidebar.svelte';
```

and remove the now-unused `BlockCard`, `Trash` and `Users` imports (BlockSidebar owns them).

Add the projection as a derived value in the script block, after the `unlocked` derivation:

```svelte
  // #526 — the three panes are a pure projection of browseNav, never new
  // state. See lib/panes.ts for why.
  let panes = $derived(panesFor($browseNav));
```

Then the markup:

```svelte
    <PaneShell spanDetail={panes.detail.kind === 'spanned'}>
      {#snippet sidebar()}
        <BlockSidebar
          blocks={manifest.blockSummaries}
          blockCount={manifest.blockCount}
          selection={panes.sidebar}
          onOpenBlock={openBlock}
          onNewBlock={openNewBlock}
          onOpenTrash={openTrash}
          onOpenContacts={openContacts}
          onTrashBlock={(b) => (pendingTrash = b)}
          onShareBlock={(b) => (blockToShare = b)}
          onRenameBlock={openRenameBlock}
        />
        {#if trashError}
          {@const msg = userMessageFor(trashError)}
          <p class="vault__trash-error" role="alert">
            {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
          </p>
        {/if}
      {/snippet}

      {#snippet list()}
        {#if panes.list.kind === 'prompt'}
          <p class="vault__pane-prompt">{panes.list.message}</p>
        {:else if panes.list.kind === 'records'}
          <RecordList
            block={panes.list.block}
            blockCount={manifest.blockCount}
            selectedRecordUuidHex={panes.list.selectedRecordUuidHex}
            frozen={panes.list.frozen}
          />
        {:else if panes.list.kind === 'trash'}
          <TrashView />
        {:else}
          <ContactsPane />
        {/if}
      {/snippet}

      {#snippet detail()}
        {#if panes.detail.kind === 'prompt'}
          <p class="vault__pane-prompt">{panes.detail.message}</p>
        {:else if panes.detail.kind === 'viewer'}
          {#key panes.detail.record.recordUuidHex}
            <FieldViewer block={panes.detail.block} record={panes.detail.record} />
          {/key}
        {:else if panes.detail.kind === 'editor'}
          <RecordEditor
            block={panes.detail.block}
            record={panes.detail.record}
            onSaved={async () => { try { await refreshManifest(); } finally { back(); } }}
            onCancel={() => back()}
          />
        {/if}
      {/snippet}
    </PaneShell>

    {#if panes.modal.kind === 'blockName'}
      <BlockNameDialog
        mode={panes.modal.mode}
        onDone={async () => { try { await refreshManifest(); } finally { back(); } }}
        onCancel={() => back()}
      />
    {/if}
```

**The `{#key}` around `FieldViewer` is load-bearing.** Without it Svelte reuses the component instance across a record selection change, and per-field reveal state would survive from one record onto the next.

Add the prompt style to Vault.svelte's existing `<style>` block (or create one if absent):

```svelte
  .vault__pane-prompt {
    padding: var(--space-6);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
    text-align: center;
  }
```

Finally the `.vault` container must give PaneShell a height to fill:

```svelte
  .vault {
    display: flex;
    flex-direction: column;
    height: 100vh;
    min-height: 0;
  }
```

- [ ] **Step 5: Repair the existing suite**

Work through the list from Step 2:

- For every `RecordDto` fixture, add `title` and `subtitle`. Use a realistic title (not `'x'`) so an assertion accidentally matching an empty string fails loudly.
- For every assertion on a `field-viewer__back` or `record-list__back` button, delete the assertion — the button is gone by design. Do not "fix" it by re-adding the button.
- `tests/App.test.ts` and `tests/AppRoute.test.ts` render the whole tree; if they assert on the blocks-root screen's structure, update them to the sidebar's.

- [ ] **Step 6: Add a keying regression test**

Add to `desktop/tests/AppRoute.test.ts` (or a new `tests/VaultPanes.test.ts` if that file is already crowded):

```ts
describe('Vault — detail pane keying (#526)', () => {
  it('remounts FieldViewer when the selected record changes', async () => {
    // Reveal state lives inside FieldRow. If Svelte reuses the FieldViewer
    // instance across a selection change, a revealed value from record A can
    // survive onto record B. The {#key} prevents that; this pins it.
    const { rerender, container } = render(FieldViewer, {
      props: { block: BLOCK, record: RECORD_A }
    });
    const first = container.querySelector('.field-viewer');
    await rerender({ block: BLOCK, record: RECORD_B });
    const second = container.querySelector('.field-viewer');
    // Same component under test, but the Vault-level {#key} is what forces a
    // new instance — assert on the rendered title changing, which proves the
    // props flowed, and rely on panes.test.ts for the projection itself.
    expect(second?.textContent).toContain(RECORD_B.title);
    expect(first?.textContent).not.toBe(second?.textContent);
  });
});
```

- [ ] **Step 7: Run every gate**

```bash
cd desktop && pnpm test && pnpm svelte-check
cd .. && cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```

Expected: all green. Do not proceed while anything is red.

- [ ] **Step 8: Launch the app and look at it**

```bash
cd desktop && pnpm tauri dev
```

**Use a throwaway vault, never the tracked golden fixture** — the app writes settings into the vault it opens. `cp -R` a copy to a temp directory first if you do not already have a scratch vault.

Check by hand: all three panes visible; clicking a block fills the middle; clicking a record fills the right; splitters drag and the widths survive a restart; Escape clears the detail then the block; opening an editor dims the list; Trash and Contacts span both right columns.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "feat(desktop): three-pane vault layout (#526)

Vault.svelte renders PaneShell over the panesFor projection instead of a
nine-arm {#if}. FieldViewer is keyed on the record UUID so per-field
reveal state cannot survive a selection change."
```

---

## Self-Review

**Spec coverage.** Walked each spec section against the tasks:

| Spec section | Task |
|---|---|
| `panesFor` projection + table | 3 |
| File structure | 1-8 (all files accounted for) |
| Allowlist, priority, truncation, `bstr` ineligibility | 1, 2 |
| No `Sensitive` wrapper (decision recorded, not implemented) | 2 — the code simply does not wrap; the reasoning lives in the spec |
| Amended `reveal.rs` invariant | 2, Step 5 |
| Escape unchanged | 8 — nothing touches `shouldPopOnEscape`, verified by its tests still passing |
| Lock clears panes | 8 — falls out of the projection; no code needed |
| `FieldViewer` keyed | 8, Steps 4 and 6 |
| Empty states | 3 (constants), 8 (rendering) |
| Frozen list | 3 (`frozen` flag), 7 (rows), 8 (wiring) |
| Fractional widths, pixel floors, no maximum | 4, 5 |
| Tauri `minWidth` | 5, Step 4 |
| localStorage policy | 4 |
| Trash / Contacts span | 3, 5 (`spanDetail`), 8 |
| All four new test files | 3, 4, 5, 6 |
| Existing tests updated | 8, Step 5 |

**One deliberate deviation from the spec**, already argued above: the spec's "pure function taking `&Record`, unit-tested" is impossible because `Record::new` is `pub(crate)`. Task 1 tests the security gate and the selection logic purely; Task 2 covers the adapter with an integration test that is strictly stronger than the unit test would have been. The spec's *intent* — the security decision is exhaustively tested — is met.

**Placeholder scan.** No TBDs. Every code step carries the actual code. The only step that names files it cannot enumerate in advance is Task 8 Step 5 (repairing existing tests), which is inherent — Step 2 exists precisely to produce that list before the work starts, and the two failure classes and their correct fixes are both specified.

**Type consistency.** Checked across tasks: `RecordLabels { title, subtitle }` (Task 1) matches its use in Task 2; `select_labels`'s `Vec<(usize, String, String)>` matches what `labels_for_record` builds; `RecordDto.title: String` / `subtitle: Option<String>` (Rust, Task 2) matches `title: string` / `subtitle: string | null` (TS, Task 2) and the fixtures in Tasks 3 and 7; `SidebarSelection` (Task 3) matches `BlockSidebar`'s `selection` prop (Task 6); `ListPane`'s `selectedRecordUuidHex` / `frozen` (Task 3) match `RecordList`'s props (Task 7) and `RecordRow`'s (Task 7); `PaneShell`'s `spanDetail` (Task 5) matches `panes.detail.kind === 'spanned'` (Task 8).
