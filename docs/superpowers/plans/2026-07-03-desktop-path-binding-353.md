# Desktop IPC path-binding (#353) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind every webview-supplied filesystem-path argument to a path the user actually chose in a native, backend-invoked dialog, closing the last open finding (D-2) from the 2026-07-02 pre-release audit.

**Architecture:** New `pick_*` Tauri commands open native dialogs from the Rust backend and record each chosen path (canonicalized) in a per-purpose slot held in `VaultSession`. The five path-taking commands validate their argument against the matching slot before any filesystem work. The webview loses `dialog:allow-open`, so it can no longer open dialogs or name arbitrary paths.

**Tech Stack:** Rust (Tauri 2, `tauri-plugin-dialog` 2.7.1), Svelte 5 + TypeScript frontend, `std::fs` canonicalization.

**Design doc:** `docs/superpowers/specs/2026-07-03-desktop-path-binding-353-design.md`

## Global Constraints

- Stable Rust toolchain; `#![forbid(unsafe_code)]` workspace-wide — no `unsafe`.
- `cargo clippy --release --workspace --tests -- -D warnings` must stay clean.
- Keep source files under ~500 lines; one concept per file.
- Prefer pure free functions in reusable modules; push I/O to the edges.
- TDD: write the failing test first, watch it fail, then implement.
- Tests generate crypto values at runtime (`OsRng`) — never hardcoded byte arrays.
- Frontend uses **pnpm**, never npm (`cd desktop && pnpm …`).
- **Desktop only.** No change to `core/`, `ffi/`, on-disk format, KATs, conformance, or any bridge error variant.
- Manual smoke uses a **temp copy** of the golden vault, never the tracked fixture.
- All work happens in the worktree `.worktrees/desktop-path-binding-353` on branch `feature/desktop-path-binding-353`. Use absolute paths or `cd` in the same Bash call.

**Task ordering rationale:** infrastructure (Tasks 1–4) → frontend switch + capability removal (Task 5, after which the app already sources every path from a backend picker) → enforcement (Tasks 6–8, purely additive checks that legitimately-picked paths satisfy). The app stays runnable after every task.

---

### Task 1: `path_auth` pure module (security core)

**Files:**
- Create: `desktop/src-tauri/src/path_auth.rs`
- Modify: `desktop/src-tauri/src/lib.rs` (add `pub mod path_auth;`)

**Interfaces:**
- Produces:
  - `enum PathPurpose { VaultFolder, ContactCard, ExportDir }` (`Clone, Copy, PartialEq, Eq, Hash, Debug`)
  - `enum MatchMode { Exact, Containment }` (`Clone, Copy, Debug`)
  - `struct PathApprovals` (`Default, Debug`) with `approve(&mut self, PathPurpose, PathBuf)`, `is_authorized(&self, PathPurpose, &Path, MatchMode) -> bool`, `clear(&mut self)`
  - `fn canonicalize_for_auth(&Path) -> Option<PathBuf>`
  - `fn is_contained(&Path, &Path) -> bool`

> Note vs. spec §3.1: the spec sketched `canonicalize_for_auth -> Result<PathBuf, AppError>`. We realize it as `-> Option<PathBuf>` so `path_auth.rs` stays free of the desktop `AppError` type (pure, reusable). Callers map `None` to their own fail-closed outcome.

- [ ] **Step 1: Write the failing tests**

Create `desktop/src-tauri/src/path_auth.rs` with only the test module (types don't exist yet):

```rust
//! Path-authorization core for issue #353: binds webview-supplied path
//! arguments to paths the user chose in a native backend dialog.
//!
//! Pure and free of Tauri / `AppError`. `canonicalize_for_auth` defeats
//! `..` traversal and symlink escapes (resolving symlinks in the existing
//! prefix) while still handling not-yet-created targets; `is_contained`
//! compares on component boundaries. `PathApprovals` holds one approved
//! path per `PathPurpose` (last pick wins) and is consulted with a
//! per-command `MatchMode`.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    #[test]
    fn canonicalize_rejects_parent_dir_component() {
        assert!(canonicalize_for_auth(Path::new("/tmp/../etc/passwd")).is_none());
    }

    #[test]
    fn canonicalize_resolves_existing_path_idempotently() {
        let dir = tempdir().unwrap();
        let once = canonicalize_for_auth(dir.path()).expect("canonicalizes");
        let twice = canonicalize_for_auth(&once).expect("idempotent");
        assert_eq!(once, twice);
    }

    #[test]
    fn canonicalize_handles_nonexistent_tail_under_existing_prefix() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("does-not-exist-yet");
        let canonical = canonicalize_for_auth(&target).expect("prefix exists");
        let canonical_parent = canonicalize_for_auth(dir.path()).unwrap();
        assert_eq!(canonical, canonical_parent.join("does-not-exist-yet"));
    }

    #[test]
    fn is_contained_requires_component_boundary() {
        assert!(is_contained(Path::new("/a/vaults"), Path::new("/a/vaults/x")));
        assert!(is_contained(Path::new("/a/vaults"), Path::new("/a/vaults")));
        // Sibling that merely shares a string prefix must NOT match.
        assert!(!is_contained(Path::new("/a/vaults"), Path::new("/a/vaults-evil")));
    }

    #[test]
    fn exact_mode_rejects_descendant_that_containment_accepts() {
        let dir = tempdir().unwrap();
        let child = dir.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(dir.path()).unwrap(),
        );
        // Descendant: Containment accepts, Exact rejects (least-privilege).
        assert!(approvals.is_authorized(PathPurpose::VaultFolder, &child, MatchMode::Containment));
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, &child, MatchMode::Exact));
    }

    #[test]
    fn unapproved_purpose_is_never_authorized() {
        let dir = tempdir().unwrap();
        let approvals = PathApprovals::default();
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
    }

    #[test]
    fn approval_is_isolated_per_purpose() {
        let dir = tempdir().unwrap();
        let canonical = canonicalize_for_auth(dir.path()).unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(PathPurpose::ContactCard, canonical);
        // A ContactCard approval must not authorize a VaultFolder command.
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
        assert!(approvals.is_authorized(PathPurpose::ContactCard, dir.path(), MatchMode::Exact));
    }

    #[test]
    fn re_pick_overwrites_the_slot() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(PathPurpose::VaultFolder, canonicalize_for_auth(a.path()).unwrap());
        approvals.approve(PathPurpose::VaultFolder, canonicalize_for_auth(b.path()).unwrap());
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, a.path(), MatchMode::Exact));
        assert!(approvals.is_authorized(PathPurpose::VaultFolder, b.path(), MatchMode::Exact));
    }

    #[test]
    fn clear_drops_all_slots() {
        let dir = tempdir().unwrap();
        let mut approvals = PathApprovals::default();
        approvals.approve(PathPurpose::VaultFolder, canonicalize_for_auth(dir.path()).unwrap());
        approvals.clear();
        assert!(!approvals.is_authorized(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
    }

    #[allow(unused_imports)]
    use PathBuf as _EnsurePathBufUsed;
}
```

- [ ] **Step 2: Add `pub mod path_auth;` to `lib.rs`**

In `desktop/src-tauri/src/lib.rs`, insert `pub mod path_auth;` in alphabetical position (after `pub mod dtos;`, before `pub mod reveal;` — the list currently runs `errors` then `reveal`; place it after `errors`):

```rust
pub mod errors;
pub mod path_auth;
pub mod reveal;
```

- [ ] **Step 3: Run tests to verify they fail to compile**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop path_auth 2>&1 | tail -20`
Expected: FAIL — `cannot find type PathApprovals` / `cannot find function canonicalize_for_auth`.

- [ ] **Step 4: Implement the module**

Prepend the implementation above the `#[cfg(test)]` block in `desktop/src-tauri/src/path_auth.rs`:

```rust
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// The kind of path a dialog produced and a command consumes. Part of the
/// approval key so an approval for one purpose never authorizes another.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PathPurpose {
    VaultFolder,
    ContactCard,
    ExportDir,
}

/// How strictly a command's path must match its approved slot. Least-privilege:
/// only the create wizard's "subfolder" offer uses `Containment`.
#[derive(Clone, Copy, Debug)]
pub enum MatchMode {
    Exact,
    Containment,
}

/// Per-purpose last-approved slot. One canonical path per purpose; a new pick
/// overwrites the previous one. Cleared on vault lock.
#[derive(Default, Debug)]
pub struct PathApprovals {
    slots: HashMap<PathPurpose, PathBuf>,
}

impl PathApprovals {
    /// Record `canonical` (already `canonicalize_for_auth` output) as the
    /// approved path for `purpose`, replacing any prior slot value.
    pub fn approve(&mut self, purpose: PathPurpose, canonical: PathBuf) {
        self.slots.insert(purpose, canonical);
    }

    /// True iff `requested` is authorized for `purpose` under `mode`.
    /// Fail-closed: unknown purpose or a path that cannot be canonicalized
    /// (contains `..`, or its existing prefix fails to resolve) is rejected.
    pub fn is_authorized(&self, purpose: PathPurpose, requested: &Path, mode: MatchMode) -> bool {
        let Some(slot) = self.slots.get(&purpose) else {
            return false;
        };
        let Some(canonical) = canonicalize_for_auth(requested) else {
            return false;
        };
        match mode {
            MatchMode::Exact => canonical == *slot,
            MatchMode::Containment => is_contained(slot, &canonical),
        }
    }

    /// Drop every approved slot (called on vault lock).
    pub fn clear(&mut self) {
        self.slots.clear();
    }
}

/// Resolve `path` to a comparison-canonical form that defeats `..` traversal
/// and symlink escapes while still handling not-yet-created targets:
/// 1. reject any `..` component;
/// 2. canonicalize the deepest existing ancestor (resolves symlinks there);
/// 3. re-append the non-existent tail (only `Normal` components remain).
///
/// Returns `None` on a `..` component, an empty path, or a prefix that fails
/// to canonicalize. Deterministic and idempotent on its own output.
pub fn canonicalize_for_auth(path: &Path) -> Option<PathBuf> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    let mut existing = path.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();
    while !existing.exists() {
        let name = existing.file_name()?.to_os_string();
        tail.push(name);
        if !existing.pop() {
            return None; // exhausted ancestors without finding an existing one
        }
    }
    let mut canonical = std::fs::canonicalize(&existing).ok()?;
    for name in tail.iter().rev() {
        canonical.push(name);
    }
    Some(canonical)
}

/// True iff `descendant` is `ancestor` or lies beneath it on a component
/// boundary. Both arguments must already be `canonicalize_for_auth` output.
/// Uses `Path::starts_with` (component-wise) so `/a/vaults` does not match
/// `/a/vaults-evil`.
pub fn is_contained(ancestor: &Path, descendant: &Path) -> bool {
    descendant.starts_with(ancestor)
}
```

Remove the `#[allow(unused_imports)] use PathBuf as _EnsurePathBufUsed;` line from the test module (it was only a scaffolding guard).

- [ ] **Step 5: Run tests to verify they pass + clippy**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop path_auth 2>&1 | tail -20 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -5`
Expected: all `path_auth` tests PASS; clippy clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add desktop/src-tauri/src/path_auth.rs desktop/src-tauri/src/lib.rs
git commit -m "feat(desktop): path_auth core — per-purpose approvals + canonicalize/containment (#353)"
```

---

### Task 2: `PathNotApproved` error variant (Rust)

**Files:**
- Modify: `desktop/src-tauri/src/errors.rs` (add variant + a round-trip test)

**Interfaces:**
- Produces: `AppError::PathNotApproved { path: String }` → wire `{ "code": "path_not_approved", "path": … }`.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `desktop/src-tauri/src/errors.rs` (near the existing `VaultFolderNotEmpty` round-trip test at ~line 516):

```rust
#[test]
fn path_not_approved_round_trips_with_path() {
    let v = round_trip(&AppError::PathNotApproved {
        path: "/some/where".to_string(),
    });
    assert_eq!(v["code"], "path_not_approved");
    assert_eq!(v["path"], "/some/where");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop path_not_approved 2>&1 | tail -15`
Expected: FAIL — `no variant named PathNotApproved`.

- [ ] **Step 3: Add the variant**

In `desktop/src-tauri/src/errors.rs`, add after the `VaultPathNotAVault` variant (~line 58) so it sits with the other path-carrying variants:

```rust
    /// #353: a path argument was not chosen from a backend-invoked dialog.
    /// Produced only at the desktop IPC boundary; carries the offending path
    /// so the UI can prompt the user to re-pick.
    #[error("That path wasn't chosen from a dialog")]
    PathNotApproved { path: String },
```

- [ ] **Step 4: Run test + clippy**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop path_not_approved 2>&1 | tail -10 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -5`
Expected: PASS; clippy clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add desktop/src-tauri/src/errors.rs
git commit -m "feat(desktop): AppError::PathNotApproved variant (#353)"
```

---

### Task 3: `VaultSession` approvals field, methods, clear-on-lock

**Files:**
- Modify: `desktop/src-tauri/src/session.rs`

**Interfaces:**
- Consumes: Task 1 (`PathApprovals`, `PathPurpose`, `MatchMode`).
- Produces on `VaultSession`:
  - `fn approve_path(&mut self, PathPurpose, PathBuf)`
  - `fn is_path_approved(&self, PathPurpose, &Path, MatchMode) -> bool`
  - `lock()` additionally clears approvals.

- [ ] **Step 1: Write the failing test**

Add a `#[cfg(test)] mod tests` block at the end of `desktop/src-tauri/src/session.rs` (the file has none today):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_auth::{canonicalize_for_auth, MatchMode, PathPurpose};
    use tempfile::tempdir;

    #[test]
    fn approved_path_authorizes_then_lock_clears_it() {
        let dir = tempdir().unwrap();
        let mut session = VaultSession::new(std::env::temp_dir());
        session.approve_path(
            PathPurpose::VaultFolder,
            canonicalize_for_auth(dir.path()).unwrap(),
        );
        assert!(session.is_path_approved(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
        session.lock();
        assert!(!session.is_path_approved(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop approved_path_authorizes 2>&1 | tail -15`
Expected: FAIL — `no method named approve_path`.

- [ ] **Step 3: Implement**

In `desktop/src-tauri/src/session.rs`:

(a) Add the import near the other `use crate::…` lines:

```rust
use crate::path_auth::{MatchMode, PathApprovals, PathPurpose};
```

(b) Add a field to `struct VaultSession` (after `device_data_dir: PathBuf,`):

```rust
    /// Paths approved via a backend `pick_*` dialog (#353). Independent of
    /// `inner` so it is reachable while locked (create/probe/unlock and their
    /// pickers all run locked). Cleared on `lock()`.
    approvals: PathApprovals,
```

(c) Initialize it in `VaultSession::new` (add to the struct literal):

```rust
            approvals: PathApprovals::default(),
```

(d) Add the two methods inside `impl VaultSession` (e.g. after `notify_activity`):

```rust
    /// Record a dialog-approved path for `purpose` (#353). `canonical` must be
    /// `path_auth::canonicalize_for_auth` output.
    pub fn approve_path(&mut self, purpose: PathPurpose, canonical: std::path::PathBuf) {
        self.approvals.approve(purpose, canonical);
    }

    /// True iff `requested` is authorized for `purpose` under `mode` (#353).
    pub fn is_path_approved(
        &self,
        purpose: PathPurpose,
        requested: &std::path::Path,
        mode: MatchMode,
    ) -> bool {
        self.approvals.is_authorized(purpose, requested, mode)
    }
```

(e) Extend `lock()` to clear approvals:

```rust
    pub fn lock(&mut self) {
        self.inner = None;
        self.approvals.clear();
    }
```

- [ ] **Step 4: Run test + full crate tests + clippy**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop 2>&1 | tail -15 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -5`
Expected: new test PASS; existing session/command tests still PASS; clippy clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add desktop/src-tauri/src/session.rs
git commit -m "feat(desktop): VaultSession approvals slot + clear-on-lock (#353)"
```

---

### Task 4: `pick_*` backend dialog commands

**Files:**
- Create: `desktop/src-tauri/src/commands/pick.rs`
- Modify: `desktop/src-tauri/src/commands/mod.rs` (add `pub mod pick;`)
- Modify: `desktop/src-tauri/src/main.rs` (import `pick`; register three commands)

**Interfaces:**
- Consumes: Task 1 (`PathPurpose`, `canonicalize_for_auth`), Task 3 (`approve_path`), `commands::shared::lock_session`.
- Produces:
  - `#[tauri::command] pick_vault_folder(app, state) -> Result<Option<String>, AppError>`
  - `#[tauri::command] pick_contact_card(app, state) -> Result<Option<String>, AppError>`
  - `#[tauri::command] pick_export_dir(app, state) -> Result<Option<String>, AppError>`
  - `pub fn pick_into_slot_impl(&Mutex<VaultSession>, PathPurpose, Option<PathBuf>) -> Result<Option<String>, AppError>`

- [ ] **Step 1: Write the failing test + skeleton**

Create `desktop/src-tauri/src/commands/pick.rs`:

```rust
//! Backend-mediated file/folder pickers (#353).
//!
//! The webview no longer opens dialogs (its `dialog:allow-open` capability is
//! removed). Instead it calls these commands; each opens a native dialog from
//! the Rust side, canonicalizes the chosen path, and records it in the
//! matching `PathPurpose` slot on `VaultSession`. The path-taking commands
//! then validate their argument against that slot. The native dialog call is
//! isolated in the thin `#[tauri::command]` shells; the canonicalize-and-store
//! core (`pick_into_slot_impl`) is unit-tested.

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::State;
use tauri_plugin_dialog::DialogExt;

use crate::commands::shared::lock_session;
use crate::errors::AppError;
use crate::path_auth::{canonicalize_for_auth, PathPurpose};
use crate::session::VaultSession;

/// Canonicalize the picked path, store it in `purpose`'s slot, and return the
/// canonical display string. `None` (user cancelled) leaves state untouched.
pub fn pick_into_slot_impl(
    state: &Mutex<VaultSession>,
    purpose: PathPurpose,
    picked: Option<PathBuf>,
) -> Result<Option<String>, AppError> {
    let Some(path) = picked else {
        return Ok(None);
    };
    let canonical = canonicalize_for_auth(&path).ok_or_else(|| AppError::Io {
        detail: format!("could not canonicalize picked path {path:?}"),
    })?;
    let display = canonical.to_string_lossy().into_owned();
    let mut session = lock_session(state)?;
    session.approve_path(purpose, canonical);
    Ok(Some(display))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_auth::MatchMode;
    use tempfile::tempdir;

    #[test]
    fn cancel_returns_none_and_stores_nothing() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let out = pick_into_slot_impl(&state, PathPurpose::VaultFolder, None).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn pick_stores_canonical_path_in_the_slot() {
        let dir = tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let out = pick_into_slot_impl(
            &state,
            PathPurpose::ContactCard,
            Some(dir.path().to_path_buf()),
        )
        .unwrap();
        assert!(out.is_some());
        let session = state.lock().unwrap();
        assert!(session.is_path_approved(PathPurpose::ContactCard, dir.path(), MatchMode::Exact));
        // Isolation: it did not authorize a different purpose.
        assert!(!session.is_path_approved(PathPurpose::VaultFolder, dir.path(), MatchMode::Exact));
    }
}
```

- [ ] **Step 2: Wire the module + run the test to verify it fails to compile**

Add to `desktop/src-tauri/src/commands/mod.rs` (alphabetical — after `pub mod lock;`, before `pub mod reauth;`... place after `pub mod edit;`):

```rust
pub mod pick;
```

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop pick_into_slot 2>&1 | tail -20`
Expected: PASS (the `*_impl` core needs no dialog). If it already passes, that is fine — this task's `*_impl` is testable without the shells. Proceed to add the shells.

- [ ] **Step 3: Add the `#[tauri::command]` shells**

Append to `desktop/src-tauri/src/commands/pick.rs`, before the `#[cfg(test)]` module:

```rust
/// Native folder picker for the vault folder (unlock + create). Stores the
/// choice in the `VaultFolder` slot.
#[tauri::command]
pub async fn pick_vault_folder(
    app: tauri::AppHandle,
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .set_title("Choose vault folder")
        .blocking_pick_folder()
        .and_then(|fp| fp.into_path().ok());
    pick_into_slot_impl(state.inner(), PathPurpose::VaultFolder, picked)
}

/// Native file picker (`.card` filter) for contact-card import. Stores the
/// choice in the `ContactCard` slot.
#[tauri::command]
pub async fn pick_contact_card(
    app: tauri::AppHandle,
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .add_filter("Contact card", &["card"])
        .set_title("Import a contact card")
        .blocking_pick_file()
        .and_then(|fp| fp.into_path().ok());
    pick_into_slot_impl(state.inner(), PathPurpose::ContactCard, picked)
}

/// Native folder picker for owner-card export. Stores the choice in the
/// `ExportDir` slot.
#[tauri::command]
pub async fn pick_export_dir(
    app: tauri::AppHandle,
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .set_title("Choose a folder to export your card to")
        .blocking_pick_folder()
        .and_then(|fp| fp.into_path().ok());
    pick_into_slot_impl(state.inner(), PathPurpose::ExportDir, picked)
}
```

- [ ] **Step 4: Register the commands in `main.rs`**

In `desktop/src-tauri/src/main.rs`, add `pick` to the `commands` import list (line ~23):

```rust
use secretary_desktop::commands::{
    browse, contacts, create, delete, edit, lock, pick, reauth, settings, sync, unlock, vault,
};
```

And add three entries to the `tauri::generate_handler![…]` list (after the `create::…` block):

```rust
            pick::pick_vault_folder,
            pick::pick_contact_card,
            pick::pick_export_dir,
```

- [ ] **Step 5: Build + test + clippy**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo build --release -p secretary-desktop 2>&1 | tail -8 && cargo test --release -p secretary-desktop pick 2>&1 | tail -12 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -5`
Expected: build OK (proves the dialog API + `FilePath::into_path` compile against 2.7.1); tests PASS; clippy clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add desktop/src-tauri/src/commands/pick.rs desktop/src-tauri/src/commands/mod.rs desktop/src-tauri/src/main.rs
git commit -m "feat(desktop): backend pick_* dialog commands populate approval slots (#353)"
```

---

### Task 5: Frontend switch to backend pickers + remove `dialog:allow-open`

**Files:**
- Modify: `desktop/src/components/PathPicker.svelte` (invoke backend picker instead of JS dialog)
- Modify: `desktop/src/lib/ipc.ts` (add `pickVaultFolder` / `pickContactCard` / `pickExportDir`)
- Modify: `desktop/src/lib/errors.ts` (add `path_not_approved` to codes, union, `userMessageFor`)
- Modify call sites: `desktop/src/routes/Unlock.svelte`, `desktop/src/components/create/FolderStep.svelte`, `desktop/src/components/contacts/ContactsPane.svelte`, `desktop/src/components/share/ShareDialog.svelte`
- Modify: `desktop/src-tauri/capabilities/default.json` (remove `dialog:allow-open`)
- Modify: `desktop/package.json` (remove `@tauri-apps/plugin-dialog`)

**Interfaces:**
- Consumes: Task 4 commands `pick_vault_folder` / `pick_contact_card` / `pick_export_dir`.

> After this task the app already sources every path from a backend picker (slots populated), so the enforcement in Tasks 6–8 sees approved paths. No enforcement exists yet, so nothing breaks in between.

- [ ] **Step 1: Rewrite `PathPicker.svelte`**

Replace the entire contents of `desktop/src/components/PathPicker.svelte` with:

```svelte
<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';

  // #353: the picker no longer opens a dialog in the webview. It invokes a
  // backend `pick_*` command, which opens the native dialog, records the
  // chosen path in Rust state, and returns it for display. `command` selects
  // which purpose to pick for.
  type Props = {
    value: string;
    onSelect: (path: string) => void;
    command: 'pick_vault_folder' | 'pick_contact_card' | 'pick_export_dir';
    disabled?: boolean;
    label?: string;
    placeholder?: string;
  };

  let {
    value,
    onSelect,
    command,
    disabled = false,
    label = 'Choose…',
    placeholder = 'No path selected'
  }: Props = $props();

  async function pick(): Promise<void> {
    if (disabled) return;
    const selected = await invoke<string | null>(command);
    if (typeof selected === 'string') {
      onSelect(selected);
    }
  }
</script>

<!-- Styles live in `src/theme.css` as `.path-picker { … }`. -->
<div class="path-picker">
  <input type="text" readonly value={value || ''} {placeholder} {disabled} />
  <button type="button" onclick={pick} {disabled}>{label}</button>
</div>
```

- [ ] **Step 2: Add ipc wrappers**

In `desktop/src/lib/ipc.ts`, add after `probeCreateTarget` (~line 173):

```typescript
export async function pickVaultFolder(): Promise<string | null> {
  return call<string | null>('pick_vault_folder', {});
}

export async function pickContactCard(): Promise<string | null> {
  return call<string | null>('pick_contact_card', {});
}

export async function pickExportDir(): Promise<string | null> {
  return call<string | null>('pick_export_dir', {});
}
```

- [ ] **Step 3: Add `path_not_approved` to the error contract**

In `desktop/src/lib/errors.ts`:

(a) Add to `APP_ERROR_CODES` (after `'vault_path_not_a_vault',`):

```typescript
  'path_not_approved',
```

(b) Add to the `AppError` union (after the `vault_path_not_a_vault` arm):

```typescript
  | { code: 'path_not_approved'; path: string }
```

(c) Add a `case` to `userMessageFor` (after the `vault_path_not_a_vault` case):

```typescript
    case 'path_not_approved':
      return {
        title: 'Path not chosen from a dialog',
        detail: err.path,
        actionHint: 'Use the Choose… button to pick the folder or file again.'
      };
```

- [ ] **Step 4: Update the four call sites**

`desktop/src/routes/Unlock.svelte` — add `command`:

```svelte
        <PathPicker
          value={folderPath}
          command="pick_vault_folder"
          onSelect={(p) => (folderPath = p)}
          disabled={submitting}
        />
```

`desktop/src/components/create/FolderStep.svelte` — add `command`:

```svelte
  <PathPicker value={picked} command="pick_vault_folder" onSelect={onPick} disabled={probing} />
```

`desktop/src/components/contacts/ContactsPane.svelte` — replace `directory`/`title` with `command`:

```svelte
    <PathPicker
      value=""
      command="pick_export_dir"
      label="Export…"
      placeholder="No folder selected"
      onSelect={onExportSelect}
    />
```

`desktop/src/components/share/ShareDialog.svelte` — replace `directory`/`filters`/`title` with `command`:

```svelte
    <PathPicker
      value=""
      command="pick_contact_card"
      onSelect={onImport}
      disabled={busy}
      label="Import a contact…"
      placeholder="No file selected"
    />
```

- [ ] **Step 5: Remove the webview dialog capability + npm dep**

In `desktop/src-tauri/capabilities/default.json`, delete the `"dialog:allow-open",` line and update the `description` to note dialogs are now backend-mediated:

```json
  "description": "Default capabilities for the secretary-desktop main window. Grants Tauri core (event listening, IPC invoke) and clipboard WRITE for the copy-secret affordance. Dialogs are opened by the Rust backend (pick_* commands, #353), so the webview is NOT granted dialog:allow-open. Clipboard read is intentionally NOT granted.",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "clipboard-manager:allow-write-text"
  ]
```

In `desktop/package.json`, remove the `"@tauri-apps/plugin-dialog": "^2"` line (and fix the trailing comma on the preceding line).

- [ ] **Step 6: Verify the frontend**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353/desktop && pnpm install 2>&1 | tail -5 && pnpm svelte-check 2>&1 | tail -15 && pnpm test 2>&1 | tail -15`
Expected: `pnpm install` succeeds after dropping the dep; `svelte-check` 0 errors (proves `path_not_approved` exhaustive switch + PathPicker prop changes compile); `pnpm test` PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add desktop/src/components/PathPicker.svelte desktop/src/lib/ipc.ts desktop/src/lib/errors.ts \
  desktop/src/routes/Unlock.svelte desktop/src/components/create/FolderStep.svelte \
  desktop/src/components/contacts/ContactsPane.svelte desktop/src/components/share/ShareDialog.svelte \
  desktop/src-tauri/capabilities/default.json desktop/package.json desktop/pnpm-lock.yaml
git commit -m "feat(desktop): route pickers through backend commands; drop webview dialog capability (#353)"
```

---

### Task 6: Enforce approval in `unlock_with_password`

**Files:**
- Modify: `desktop/src-tauri/src/commands/unlock.rs`

**Interfaces:**
- Consumes: Task 1 (`PathPurpose`, `MatchMode`), Task 3 (`is_path_approved`).

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `desktop/src-tauri/src/commands/unlock.rs`:

```rust
    #[test]
    fn unapproved_folder_is_rejected_before_validation() {
        let temp = tempdir().expect("tempdir");
        let state = std::sync::Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = unlock_with_password_impl(&state, temp.path().to_str().unwrap(), b"pw")
            .expect_err("unapproved");
        assert!(matches!(err, AppError::PathNotApproved { .. }), "got {err:?}");
    }

    #[test]
    fn approved_folder_passes_the_gate_and_reaches_validation() {
        use crate::path_auth::{canonicalize_for_auth, PathPurpose};
        // An empty temp dir is approved but is not a vault: passing the gate
        // means we reach validate_vault_path, which returns VaultPathNotAVault.
        let temp = tempdir().expect("tempdir");
        let state = std::sync::Mutex::new(VaultSession::new(std::env::temp_dir()));
        state
            .lock()
            .unwrap()
            .approve_path(PathPurpose::VaultFolder, canonicalize_for_auth(temp.path()).unwrap());
        let err = unlock_with_password_impl(&state, temp.path().to_str().unwrap(), b"pw")
            .expect_err("not a vault");
        assert!(matches!(err, AppError::VaultPathNotAVault { .. }), "got {err:?}");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop -- unapproved_folder_is_rejected approved_folder_passes 2>&1 | tail -15`
Expected: FAIL — `unapproved_folder…` currently returns `VaultPathNotAVault` (no gate yet).

- [ ] **Step 3: Add the gate**

In `unlock_with_password_impl` (`desktop/src-tauri/src/commands/unlock.rs`), add the approval check at the top of the body, before `validate_vault_path`, and the imports:

```rust
use crate::path_auth::{MatchMode, PathPurpose};
```

```rust
pub fn unlock_with_password_impl(
    state: &Mutex<VaultSession>,
    folder_path: &str,
    password: &[u8],
) -> Result<ManifestDto, AppError> {
    let folder = PathBuf::from(folder_path);
    // #353: the folder must be one the user picked via pick_vault_folder.
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::VaultFolder, &folder, MatchMode::Exact) {
            return Err(AppError::PathNotApproved {
                path: folder_path.to_string(),
            });
        }
    }
    validate_vault_path(&folder, folder_path)?;

    let mut session = lock_session(state)?;
    session.unlock(&folder, password)?;
    session.with_unlocked(|u| {
        Ok(ManifestDto::from_manifest_with_warnings(
            &u.manifest,
            u.pending_warnings.clone(),
        ))
    })
}
```

- [ ] **Step 4: Run tests + clippy**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop unlock 2>&1 | tail -15 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -5`
Expected: both new tests PASS; existing unlock tests PASS; clippy clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add desktop/src-tauri/src/commands/unlock.rs
git commit -m "feat(desktop): bind unlock_with_password to an approved vault folder (#353)"
```

---

### Task 7: Enforce approval in `create_vault` + `probe_create_target`

**Files:**
- Modify: `desktop/src-tauri/src/commands/create.rs`

**Interfaces:**
- Consumes: Task 1, Task 3. `create_vault_impl` and `probe_create_target_impl` gain a `state: &Mutex<VaultSession>` first parameter; the command shells gain `state: State<'_, Mutex<VaultSession>>`.

- [ ] **Step 1: Write the failing tests**

Add a `#[cfg(test)] mod tests` block to `desktop/src-tauri/src/commands/create.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_auth::{canonicalize_for_auth, PathPurpose};
    use crate::session::VaultSession;
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[test]
    fn probe_rejects_unapproved_path() {
        let temp = tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = probe_create_target_impl(&state, temp.path().to_str().unwrap())
            .expect_err("unapproved");
        assert!(matches!(err, AppError::PathNotApproved { .. }), "got {err:?}");
    }

    #[test]
    fn probe_allows_approved_path() {
        let temp = tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        state
            .lock()
            .unwrap()
            .approve_path(PathPurpose::VaultFolder, canonicalize_for_auth(temp.path()).unwrap());
        let dto = probe_create_target_impl(&state, temp.path().to_str().unwrap()).unwrap();
        assert!(dto.exists && dto.is_empty);
    }

    #[test]
    fn create_rejects_unapproved_path_and_creates_nothing() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("new-vault");
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = create_vault_impl(
            &state,
            target.to_str().unwrap(),
            "My Vault",
            &secretary_core::crypto::secret::SecretBytes::from(b"pw".to_vec()),
            0,
            &mut rand_core::OsRng,
        )
        .expect_err("unapproved");
        assert!(matches!(err, AppError::PathNotApproved { .. }), "got {err:?}");
        assert!(!target.exists(), "must not create the folder for an unapproved path");
    }

    #[test]
    fn create_allows_approved_subfolder_then_reaches_empty_check() {
        // Approve the PARENT; the create target is a subfolder (containment).
        // The parent temp dir is non-empty here (holds the subfolder path's
        // ancestor is the parent itself), so we assert the gate passes by
        // reaching a non-PathNotApproved outcome.
        let temp = tempdir().unwrap();
        // Make the approved parent non-empty so create hits VaultFolderNotEmpty
        // (proving the gate passed) rather than doing slow crypto.
        std::fs::write(temp.path().join("marker"), b"x").unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        state
            .lock()
            .unwrap()
            .approve_path(PathPurpose::VaultFolder, canonicalize_for_auth(temp.path()).unwrap());
        let err = create_vault_impl(
            &state,
            temp.path().to_str().unwrap(),
            "My Vault",
            &secretary_core::crypto::secret::SecretBytes::from(b"pw".to_vec()),
            0,
            &mut rand_core::OsRng,
        )
        .expect_err("parent not empty");
        assert!(matches!(err, AppError::VaultFolderNotEmpty { .. }), "got {err:?}");
    }
}
```

> If `SecretBytes::from(Vec<u8>)` is not the exact constructor, use the same one the existing IPC integration tests use to build a password `SecretBytes` (grep `SecretBytes::` under `desktop/`). The gate assertions do not depend on the crypto succeeding.

- [ ] **Step 2: Run to verify failure**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop -- probe_rejects_unapproved create_rejects_unapproved 2>&1 | tail -20`
Expected: FAIL to compile — `create_vault_impl` / `probe_create_target_impl` take no `state`.

- [ ] **Step 3: Add `state` + the gate to both impls and shells**

In `desktop/src-tauri/src/commands/create.rs`:

(a) Imports:

```rust
use std::sync::Mutex;

use tauri::State;

use crate::commands::shared::lock_session;
use crate::path_auth::{MatchMode, PathPurpose};
use crate::session::VaultSession;
```

(b) `create_vault` shell — add `state` and thread it:

```rust
#[tauri::command]
pub async fn create_vault(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
    display_name: String,
    password: Password,
) -> Result<CreateVaultDto, AppError> {
    create_vault_impl(
        state.inner(),
        &folder_path,
        &display_name,
        password.as_secret_bytes(),
        now_ms(),
        &mut OsRng,
    )
}
```

(c) `create_vault_impl` — new first param + gate at the top:

```rust
pub fn create_vault_impl(
    state: &Mutex<VaultSession>,
    folder_path: &str,
    display_name: &str,
    password: &SecretBytes,
    created_at_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CreateVaultDto, AppError> {
    let folder = Path::new(folder_path);
    // #353: the target must be the approved vault folder or a subfolder of it.
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::VaultFolder, folder, MatchMode::Containment) {
            return Err(AppError::PathNotApproved {
                path: folder_path.to_string(),
            });
        }
    }

    std::fs::create_dir_all(folder).map_err(|e| AppError::Io {
        detail: format!("failed to create vault folder {folder_path}: {e}"),
    })?;
    // …rest of the existing body unchanged…
```

(d) `probe_create_target` shell — add `state`; keep it returning `Result`:

```rust
#[tauri::command]
pub async fn probe_create_target(
    state: State<'_, Mutex<VaultSession>>,
    folder_path: String,
) -> Result<CreateTargetProbeDto, AppError> {
    probe_create_target_impl(state.inner(), &folder_path)
}
```

(e) `probe_create_target_impl` — new first param, becomes fallible, gate at top:

```rust
pub fn probe_create_target_impl(
    state: &Mutex<VaultSession>,
    folder_path: &str,
) -> Result<CreateTargetProbeDto, AppError> {
    let folder = Path::new(folder_path);
    // #353: only probe a path the user picked (or a subfolder of it).
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::VaultFolder, folder, MatchMode::Containment) {
            return Err(AppError::PathNotApproved {
                path: folder_path.to_string(),
            });
        }
    }
    let exists = folder.exists();
    let is_empty = exists
        && folder.is_dir()
        && std::fs::read_dir(folder)
            .map(|mut it| it.next().is_none())
            .unwrap_or(false);
    Ok(CreateTargetProbeDto { exists, is_empty })
}
```

- [ ] **Step 4: Check integration tests for the changed signatures**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && grep -rn 'create_vault_impl\|probe_create_target_impl' desktop/src-tauri/tests 2>/dev/null`
If any integration test calls these `*_impl`s, update those calls to pass a `&Mutex<VaultSession>` with the target folder pre-approved (mirror the unit-test seeding above). Then:

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop create 2>&1 | tail -20 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -5`
Expected: new create/probe tests PASS; existing tests PASS; clippy clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add desktop/src-tauri/src/commands/create.rs desktop/src-tauri/tests
git commit -m "feat(desktop): bind create_vault/probe_create_target to approved folder (containment) (#353)"
```

---

### Task 8: Enforce approval in `import_contact` + `export_contact_card`

**Files:**
- Modify: `desktop/src-tauri/src/commands/contacts.rs`

**Interfaces:**
- Consumes: Task 1, Task 3. Signatures unchanged (both already take `state`).

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `desktop/src-tauri/src/commands/contacts.rs`:

```rust
    #[test]
    fn import_rejects_unapproved_path_before_read() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        // A path that does not exist: if the gate were absent, the fs::read
        // would fail with Io; with the gate it fails with PathNotApproved.
        let err = import_contact_impl(&state, "/no/such/card.card").expect_err("unapproved");
        assert!(matches!(err, AppError::PathNotApproved { .. }), "got {err:?}");
    }

    #[test]
    fn import_approved_path_passes_gate_then_hits_locked_session() {
        use crate::path_auth::{canonicalize_for_auth, PathPurpose};
        let dir = tempfile::tempdir().unwrap();
        let card = dir.path().join("c.card");
        std::fs::write(&card, b"bytes").unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        state
            .lock()
            .unwrap()
            .approve_path(PathPurpose::ContactCard, canonicalize_for_auth(&card).unwrap());
        // Gate passes, read succeeds, then the locked session rejects.
        let err = import_contact_impl(&state, card.to_str().unwrap()).expect_err("locked");
        assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
    }

    #[test]
    fn export_rejects_unapproved_dir() {
        let dir = tempfile::tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = export_contact_card_impl(&state, dir.path().to_str().unwrap())
            .expect_err("unapproved");
        assert!(matches!(err, AppError::PathNotApproved { .. }), "got {err:?}");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop -- import_rejects_unapproved export_rejects_unapproved 2>&1 | tail -15`
Expected: FAIL — `import` currently returns `Io` (read of missing file), `export` returns `NotUnlocked`.

- [ ] **Step 3: Add the gates**

In `desktop/src-tauri/src/commands/contacts.rs`, add imports:

```rust
use std::path::Path;

use crate::path_auth::{MatchMode, PathPurpose};
```

`import_contact_impl` — gate before the `fs::read`:

```rust
pub fn import_contact_impl(
    state: &Mutex<VaultSession>,
    card_path: &str,
) -> Result<ContactSummaryDto, AppError> {
    // #353: the file must be one the user picked via pick_contact_card.
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::ContactCard, Path::new(card_path), MatchMode::Exact)
        {
            return Err(AppError::PathNotApproved {
                path: card_path.to_string(),
            });
        }
    }
    let bytes = std::fs::read(card_path).map_err(|e| AppError::Io {
        detail: format!("read contact card file {card_path:?}: {e}"),
    })?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let summary = bridge_import(&u.manifest, &bytes).map_err(map_ffi_error)?;
        Ok(ContactSummaryDto::from(&summary))
    })
}
```

`export_contact_card_impl` — gate before collecting/writing:

```rust
pub fn export_contact_card_impl(
    state: &Mutex<VaultSession>,
    dest_dir: &str,
) -> Result<ExportedCardDto, AppError> {
    // #353: the destination must be one the user picked via pick_export_dir.
    {
        let session = lock_session(state)?;
        if !session.is_path_approved(PathPurpose::ExportDir, Path::new(dest_dir), MatchMode::Exact) {
            return Err(AppError::PathNotApproved {
                path: dest_dir.to_string(),
            });
        }
    }
    let (file_name, bytes) = {
        let session = lock_session(state)?;
        session.with_unlocked(|u| bridge_owner_card_export(&u.manifest).map_err(map_ffi_error))?
    };
    let path = std::path::Path::new(dest_dir).join(&file_name);
    std::fs::write(&path, &bytes).map_err(|e| AppError::Io {
        detail: format!("write exported card to {path:?}: {e}"),
    })?;
    Ok(ExportedCardDto {
        path: path.to_string_lossy().into_owned(),
    })
}
```

- [ ] **Step 4: Run tests + clippy**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353 && cargo test --release -p secretary-desktop contacts 2>&1 | tail -20 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -5`
Expected: new tests PASS; existing contacts tests PASS; clippy clean.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add desktop/src-tauri/src/commands/contacts.rs
git commit -m "feat(desktop): bind import_contact/export_contact_card to approved paths (#353)"
```

---

### Task 9: Full verification + docs

**Files:**
- Modify: `README.md` (audit-remediation status), `ROADMAP.md` (Phase-A.7 entry)

- [ ] **Step 1: Full Rust workspace gate**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
cargo test --release --workspace 2>&1 | tail -15
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo fmt --all --check 2>&1 | tail -5
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-desktop 2>&1 | tail -5
```
Expected: 0 test failures; clippy clean; fmt clean; doc clean. (Core/FFI unaffected — no format/KAT change, so `conformance.py` needs no run, but it may be run for belt-and-suspenders: `uv run core/tests/python/conformance.py`.)

- [ ] **Step 2: Frontend gate**

Run: `cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353/desktop && pnpm svelte-check 2>&1 | tail -8 && pnpm test 2>&1 | tail -8`
Expected: 0 svelte-check errors; tests PASS.

- [ ] **Step 3: Manual smoke (temp copy of golden vault)**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
cp -R core/tests/data/golden_vault_001 /tmp/smoke_vault_353
cd desktop && pnpm tauri dev   # or the project's usual dev command
```
Verify each dialog flow opens a **native** picker and the action succeeds against `/tmp/smoke_vault_353` (or a fresh temp dir for create):
1. Unlock → pick folder → unlock succeeds.
2. Create → pick folder → "create a subfolder" → create succeeds in the subfolder.
3. Contacts → Export my card → pick folder → card written.
4. Share dialog → Import a contact → pick `.card` file → import succeeds.
Confirm the webview cannot open a dialog on its own (capability removed). Note the result in the commit/PR.

- [ ] **Step 4: Update README + ROADMAP**

In `README.md`, update the audit-remediation status so D-2 / #353 is listed as resolved (both open deferrals from the 2026-07-02 audit are now closed: #350 shipped, #353 here). In `ROADMAP.md`, add a Phase-A.7 line noting the desktop path-binding hardening (#353).

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-path-binding-353
git add README.md ROADMAP.md
git commit -m "docs: record #353 desktop path-binding remediation in README/ROADMAP"
```

---

## Self-Review

**Spec coverage:**
- §2 approach A (backend dialogs + binding) → Tasks 4, 5, 6–8. ✅
- §3.1 pure module → Task 1. ✅
- §3.2 state on `VaultSession` + clear-on-lock → Task 3. ✅
- §3.3 pick commands → Task 4. ✅
- §3.4 five-command binding (Exact/Containment table) → Tasks 6 (unlock/Exact), 7 (create+probe/Containment), 8 (import+export/Exact). ✅
- §3.5 remove `dialog:allow-open` → Task 5 Step 5. ✅
- §3.6 frontend (PathPicker, ipc.ts, 4 call sites, error mapping, npm dep) → Task 5. ✅
- §4 canonicalize/containment/is_authorized + residual comment → Task 1 (residual TOCTOU noted in module doc; add the inline comment at `is_contained`'s definition if not already conveyed). ✅
- §5 `PathNotApproved` → Task 2 (Rust) + Task 5 Step 3 (TS). ✅
- §6 test layers → embedded in Tasks 1, 4, 6, 7, 8. ✅
- §7 verification → Task 9. ✅

**Placeholder scan:** every code step shows complete code; no TBD/TODO. The one conditional (Task 7 `SecretBytes` constructor) names the exact grep to confirm and states the assertions don't depend on it. ✅

**Type consistency:** `PathPurpose` / `MatchMode` / `canonicalize_for_auth` / `is_contained` / `PathApprovals::{approve,is_authorized,clear}` used identically across Tasks 1, 3, 4, 6, 7, 8. `is_path_approved(purpose, &Path, MatchMode)` and `approve_path(purpose, PathBuf)` signatures match between Task 3 (definition) and Tasks 4/6/7/8 (use). Command `*_impl` signature changes (create/probe gain `state` first param) are reflected in both the shell and the tests. ✅
