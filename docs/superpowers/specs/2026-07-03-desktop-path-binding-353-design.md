# Desktop IPC path-binding (#353) — design

**Issue:** [#353](https://github.com/hherb/secretary/issues/353) — `[audit][Medium]` Desktop: IPC
commands accept arbitrary filesystem paths from the webview.
**Source audit:** `docs/security_audits/2026-07-02-full-audit.md` §5 finding D-2.
**Scope:** desktop (`desktop/`) only. Core, FFI, and the on-disk format are untouched.

## 1. Problem

Under the Tauri threat model the webview is potentially compromised (supply-chain on a
frontend dependency, or injection from rendered vault content). Five `#[tauri::command]`s
accept a raw filesystem-path `String` from the webview and act on it with **no binding to a
path the user actually chose**:

| Command | File | Path use | Runs while locked? |
|---|---|---|---|
| `unlock_with_password(folder_path)` | `commands/unlock.rs` | opens the vault at any path (still needs the password); the pre-open `validate_vault_path` leaks *exists* vs *is-a-vault* as distinct errors | yes (it performs the unlock) |
| `create_vault(folder_path)` | `commands/create.rs` | `create_dir_all` + writes the four canonical files at any path | yes (session-stateless) |
| `probe_create_target(folder_path)` | `commands/create.rs` | `exists()` + `read_dir` emptiness — a full-filesystem existence/emptiness **oracle** | yes (session-stateless) — the worst primitive |
| `import_contact(card_path)` | `commands/contacts.rs` | `fs::read` of any file (arbitrary-read; content not returned, but error type/timing is an oracle) | read happens *before* the unlock check |
| `export_contact_card(dest_dir)` | `commands/contacts.rs` | `fs::write` of the (public) owner card into any dir, silently overwriting a same-named file | write happens after the lock is released |

Nothing binds these to a dialog-returned path, so a compromised webview gets a filesystem
probe plus a constrained directory-create / file-write primitive. `sync_*` and
`verify_password` also touch the filesystem but only via `vault_folder` held in the unlocked
session (server-side state, not a webview argument), so they are out of scope.

**Capability context:** the webview has **no `fs:` plugin permission** — all filesystem I/O is
done in Rust `std::fs` inside these commands, which bypasses the capability system. The
path-argument commands are therefore the *only* way the webview reaches the filesystem, and
they are ungated. The webview does hold `dialog:allow-open`, letting its JS open native
dialogs directly (`@tauri-apps/plugin-dialog` in `PathPicker.svelte`).

## 2. Approach

**Chosen: backend-mediated dialogs + per-purpose approved-path binding.**

Move dialog invocation out of the webview into new Rust `pick_*` commands. Each native pick
canonicalizes the chosen path and records it in a **per-purpose slot** in Rust state. The five
path-taking commands validate their path argument against the matching slot (containment)
before any filesystem work. Remove `dialog:allow-open` so the webview can no longer open
dialogs at all. The webview can then never name a path the user did not pick in a native
dialog. `tauri-plugin-dialog` 2.7.1 exposes a backend Rust API
(`app.dialog().file().pick_folder(…)` / `blocking_*`, `.add_filter(…)`, `.set_title(…)`),
and backend calls bypass the (webview-facing) capability system, so removing the JS capability
does not disable the backend picker.

**Rejected — B (partial mitigation, the audit's "at minimum"):** merely require an unlocked
session for `import_contact`/`probe_create_target`. `create_vault`/`probe_create_target`/
`unlock` legitimately run *while locked* (creating/opening a vault has no unlocked session),
so an unlock gate does not apply to the worst oracle. Leaves the probe/create/write primitives
open.

**Rejected — C (frontend registers the picked path):** keep the JS dialog and have the
frontend report the path to a backend `register_approved_path`. Unsound: a compromised webview
just registers the malicious path. Approval **must** originate from a backend-invoked native
dialog — which is exactly A.

**Design decisions (confirmed with the maintainer):**
- **Bind all five** commands, including `unlock_with_password` — one uniform rule with no
  exceptions; also closes the unlock vault-shape oracle.
- **Per-purpose last-approved slot** — one approved path per dialog purpose; each pick
  overwrites its slot. Bounded (3 slots), survives multi-step flows (the wizard probes then
  creates the same folder), cleared on lock.
- **Containment under the approved ancestor** — an approved folder authorizes itself and any
  descendant, preserving the wizard's "create a subfolder" affordance. Exact matches fall out
  of containment naturally.

## 3. Architecture

### 3.1 Pure module `desktop/src-tauri/src/path_auth.rs`

No Tauri dependency; fully unit-testable; target < 300 lines.

```rust
/// The kind of path a dialog produced, and the kind a command consumes.
/// Part of the approval key so a ContactCard approval never authorizes a
/// VaultFolder command (or vice versa), even for the identical path.
enum PathPurpose { VaultFolder, ContactCard, ExportDir }

/// How strictly a command's path must match its approved slot. Least-privilege:
/// only the create wizard (subfolder offer) needs Containment; every other
/// command demands the exact approved path.
enum MatchMode { Exact, Containment }

/// Per-purpose last-approved slot. Bounded to one PathBuf per purpose.
struct PathApprovals { slots: HashMap<PathPurpose, PathBuf> }

impl PathApprovals {
    fn approve(&mut self, purpose: PathPurpose, canonical: PathBuf); // overwrite slot
    fn is_authorized(&self, purpose: PathPurpose, requested: &Path, mode: MatchMode) -> bool;
    fn clear(&mut self); // called on lock
}

// Security-core free functions (see §4):
fn canonicalize_for_auth(path: &Path) -> Result<PathBuf, AppError>;
fn is_contained(ancestor: &Path, descendant: &Path) -> bool;
```

`PathApprovals` stores paths already in `canonicalize_for_auth` form; `is_authorized`
canonicalizes the requested path the same way and compares canonical-to-canonical
(fail-closed on any canonicalization error). `mode` is chosen per command so that
unlock/import/export can never be satisfied by a mere *descendant* of their approved slot —
only create/probe pass `Containment`.

### 3.2 State

`PathApprovals` becomes a field on `VaultSession` (alongside `idle` / `device_data_dir`), i.e.
inside the single existing `Mutex<VaultSession>` managed state. Rationale:

- It must outlive any single `UnlockedSession` and be reachable **while locked**
  (`create`/`probe`/`unlock` and their pickers all run locked) — so it cannot live inside
  `UnlockedSession` (which is `None` when locked).
- Keeping it in `VaultSession` means `VaultSession::lock()` clears it for free (honors
  "clear on lock"), and avoids a second mutex / lock-ordering concern.
- `VaultSession::new` gains `approvals: PathApprovals::default()` — additive; no existing test
  inspects the field, so none break.

New pass-through methods (operate on the `approvals` field, independent of lock state):

```rust
fn approve_path(&mut self, purpose: PathPurpose, canonical: PathBuf);
fn is_path_approved(&self, purpose: PathPurpose, requested: &Path, mode: MatchMode) -> bool;
// lock() additionally calls self.approvals.clear();
```

### 3.3 Backend dialog commands `desktop/src-tauri/src/commands/pick.rs`

Thin `#[tauri::command]` shell + testable `*_impl`, matching the project pattern. The native
dialog call (not driveable headlessly) is isolated in the shell; the `*_impl` does only the
canonicalize-and-store step.

```rust
pub async fn pick_vault_folder(app: AppHandle, state: State<'_, Mutex<VaultSession>>)
    -> Result<Option<String>, AppError>;   // folder dialog → VaultFolder slot
pub async fn pick_contact_card(app, state) -> Result<Option<String>, AppError>;
    // file dialog, `.card` filter → ContactCard slot
pub async fn pick_export_dir(app, state) -> Result<Option<String>, AppError>;
    // folder dialog → ExportDir slot

// Testable core (no Tauri): canonicalize the picked path, store in the slot,
// return the display string. `None` = user cancelled (no state change).
fn pick_into_slot_impl(state, purpose, picked: Option<PathBuf>) -> Result<Option<String>, AppError>;
```

Each returns the display string for the frontend text field, or `None` on cancel.

### 3.4 Command binding

Each of the five commands checks its purpose's slot **before any filesystem work** and returns
`AppError::PathNotApproved { path }` if unauthorized:

| Command | Purpose | `MatchMode` | New signature note |
|---|---|---|---|
| `unlock_with_password` | VaultFolder | `Exact` | already takes state; check before `validate_vault_path` |
| `probe_create_target` | VaultFolder | `Containment` | **gains** `state: State<'_, Mutex<VaultSession>>` |
| `create_vault` | VaultFolder | `Containment` | **gains** `state: State<'_, Mutex<VaultSession>>` |
| `import_contact` | ContactCard | `Exact` | already takes state; check **before** the `fs::read` |
| `export_contact_card` | ExportDir | `Exact` | already takes state; check before the `fs::write` |

`create_vault`/`probe_create_target` are currently session-stateless; adding `state` is
additive (Tauri injects it — the frontend `invoke` argument list is unchanged). They read the
`approvals` field without touching `inner`, so they continue to work while locked. This closes
the while-locked probe oracle: the probe now requires a prior native pick, not just any string.

### 3.5 Capability change

Remove `dialog:allow-open` from `desktop/src-tauri/capabilities/default.json`. The webview
loses JS dialog access entirely; backend Rust dialogs bypass the capability system, so `pick_*`
still works. `dialog:allow-save` was never granted (no change).

### 3.6 Frontend

- `PathPicker.svelte`: drop `import { open } from '@tauri-apps/plugin-dialog'`; take a
  `command: 'pick_vault_folder' | 'pick_contact_card' | 'pick_export_dir'` prop and call
  `invoke(command)`, feeding the returned string to the existing `onSelect` callback. The
  `directory`/`filters`/`title` props (which configured the JS dialog) move into the backend
  commands and are removed; `label`/`value`/`disabled` stay.
- `ipc.ts`: add `pickVaultFolder()`, `pickContactCard()`, `pickExportDir()` wrappers.
- Four call sites pass the right `command`: `routes/Unlock.svelte`,
  `components/create/FolderStep.svelte`, `components/contacts/ContactsPane.svelte` (export),
  `components/share/ShareDialog.svelte` (import).
- Map the new `path_not_approved` error code to a "please choose the folder/file again"
  message.
- Remove the now-unused `@tauri-apps/plugin-dialog` npm dependency from `desktop/package.json`.

## 4. Path-matching & canonicalization (security core)

Two pure functions in `path_auth.rs`, both proven non-vacuous by mutation tests.

### 4.1 `canonicalize_for_auth(path) -> Result<PathBuf, AppError>`

Resolves a path to a comparison-canonical form that defeats symlink/`..` escapes and works for
*not-yet-existing* create targets:

1. **Reject** if the path contains any `..` component (`Component::ParentDir`) — no traversal
   survives into the stored/compared form.
2. Walk from the full path up to the first **existing** ancestor; `std::fs::canonicalize` that
   ancestor (resolves all symlinks in the real prefix).
3. Re-append the non-existent tail (only `Normal` components, guaranteed by step 1) to the
   canonical prefix.

`std::fs::canonicalize` requires existence, but `create_vault`'s target may not exist yet;
canonicalizing the existing prefix resolves symlinks where they can actually exist, and the
`..`-rejection guarantees the tail cannot escape that prefix.

### 4.2 `is_contained(ancestor, descendant) -> bool`

True iff `descendant == ancestor` **or** `descendant` starts with `ancestor` on a **component
boundary** (`Path::starts_with`, not string prefix — so `/vaults` does not authorize
`/vaults-evil`). Both arguments are already `canonicalize_for_auth`-normalized.

### 4.3 `is_authorized(purpose, requested, mode)`

- Slot for `purpose` is `None` (never picked) ⇒ unauthorized.
- `canonicalize_for_auth(requested)`; on error ⇒ unauthorized (fail-closed).
- `MatchMode::Exact` ⇒ authorized iff `canonical_requested == slot`.
- `MatchMode::Containment` ⇒ authorized iff `is_contained(slot, canonical_requested)`.
- Per-purpose isolation: the purpose is part of the key, so a `ContactCard` approval never
  authorizes a `VaultFolder` command.

Least-privilege: unlock/import/export pass `Exact`, so a descendant of their approved slot is
**rejected** even though it shares the ancestor; only create/probe pass `Containment` (for the
wizard's subfolder offer). `Exact` is not merely the `descendant == ancestor` case of
containment falling out — it is enforced as a distinct, stricter comparison.

### 4.4 Residual (documented, not fixed)

A TOCTOU symlink swap *after* the check, by a local attacker who can already write the
filesystem, is out of scope: the #353 threat is a compromised **webview** naming paths, and the
webview has no `fs:` capability to plant symlinks. Noted here and in a code comment at the
check site.

## 5. Error surface

New variant in `desktop/src-tauri/src/errors.rs`, mirroring the existing path-carrying
variants:

```rust
#[error("That path wasn't chosen from a dialog")]
PathNotApproved { path: String },
```

`#[serde(tag = "code")]` ⇒ wire code `path_not_approved`. Produced only at the desktop IPC
boundary (like `VaultFolderNotEmpty`), never from the bridge. The `path` field surfaces the
offending path so the UI can render a precise re-pick affordance.

## 6. Testing (TDD — tests written first)

1. **Pure `path_auth` unit tests** (the security core): `..` rejection; symlink-in-prefix
   resolution; non-existent-tail create target; `/vaults` vs `/vaults-evil` component-boundary;
   **`Exact` rejects a descendant that `Containment` would accept** (least-privilege proof);
   per-purpose isolation; unapproved ⇒ rejected; slot overwrite on re-pick; `clear()` on lock.
   Each gate proven non-vacuous by mutation.
2. **Command `*_impl` tests**: each of the five rejects an unapproved path with
   `PathNotApproved` and accepts a pre-seeded approved path (reusing the `Mutex<VaultSession>`
   test pattern already in `contacts.rs`/`unlock.rs`).
3. **`pick_into_slot_impl` tests**: canonicalizes + stores into the correct slot; `None`
   (cancel) leaves state unchanged. The native dialog itself is isolated in the shell and not
   driven in tests.
4. **Regression**: existing `validate_vault_path`, create empty-check, and IPC-integration
   (golden vault) tests stay green.

## 7. Verification

```bash
# in the worktree
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cd desktop && pnpm test && pnpm svelte-check      # pnpm, not npm
```

Manual smoke of all four dialog flows (unlock, create incl. subfolder, contact-card import,
owner-card export) against a **temp copy** of the golden vault (never the tracked fixture — it
stores settings in the vault and would mutate a frozen KAT).

## 8. Scope boundaries

- **Desktop only.** iOS & Android use OS-native pickers (document picker / SAF) that are
  already backend/OS-mediated; the webview-compromise threat is Tauri-specific.
- **Not folded in:** audit findings D-3 (auto-lock-timeout increase not covered by the
  security-reducing-change re-auth gate) and D-4 (CSP `style-src 'unsafe-inline'`) remain
  separate open items.
- No core / FFI / on-disk-format / KAT / conformance change; no new bridge error variant.
```
