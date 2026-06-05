# D.1.12 — desktop polish batch (design)

**Date:** 2026-06-05
**Track:** D-phase desktop UI (the share/revoke track D.1.6 → D.1.11 is complete; this is a debt-clearing slice, not a new feature track).
**Nature:** pure desktop slice — **no `core` / `ffi` / bridge / `FfiVaultError` / UDL change.** Touches `desktop/src/**` (Svelte/TS) and `desktop/src-tauri/src/commands/**` (Rust) only. No cross-language conformance gauntlet is needed.

## Purpose

Clear four accumulated carry-forward issues as one cohesive pre-external-ship polish slice:

- **#154** — replace emoji-as-icons with a vendored inline-SVG icon convention (quality bar before D.1.1 ships externally; emoji render as color glyphs on macOS/Windows but as tofu on bare Linux).
- **#180** — pair `aria-controls` with the existing `aria-expanded` on the two disclosure buttons (a11y).
- **#164** — implement the `Esc`-pops-a-browse-level keyboard affordance deferred from D.1.2.
- **#170** — hoist the duplicated `lock_session` helper into `commands::shared`.

Each is an independent, self-contained TDD commit; they do not depend on each other and can land in any order. The plan orders them smallest/most-isolated first (#170 → #180 → #154 → #164).

## Part 1 — #154: emoji → vendored inline-SVG icon system

### Decision
There is **no icon infrastructure** in the desktop app today, and emoji are used as icons in eight render sites. We introduce a minimal **vendored** icon convention — one hand-authored Svelte component per icon, inlining a [Lucide](https://lucide.dev) (MIT) `<svg>` with `stroke="currentColor"`. **No new runtime dependency** (matches the repo's minimal-trusted-deps ethos: exact-pinned `tempfile`, `#![forbid(unsafe_code)]`). Per-icon components are tree-shakeable and one-concept-per-file.

### Icon components (new dir `desktop/src/components/icons/`)
Seven components cover all eight color-emoji render sites:

| Component | Lucide source | Replaces | Site(s) |
|---|---|---|---|
| `LockKeyhole.svelte` | `lock-keyhole` | 🔐 | `routes/Unlock.svelte` hero (`size={48}`) |
| `Lock.svelte` | `lock` | 🔒 | `components/LockButton.svelte` |
| `Eye.svelte` | `eye` | 👁 | `components/FieldRow.svelte` (reveal) |
| `EyeOff.svelte` | `eye-off` | 🙈 | `components/FieldRow.svelte` (hide) |
| `Link.svelte` | `link` | 🔗 | `components/BlockCard.svelte` |
| `Trash.svelte` | `trash-2` | 🗑 | `components/BlockCard.svelte` (delete) + `routes/Vault.svelte` (Trash nav) |
| `Users.svelte` | `users` | 👤 | `routes/Vault.svelte` (Contacts nav) |

### Component contract
Each icon component:
- exposes a single prop `size?: number` (default `20`; the Unlock hero passes `48`);
- renders `<svg width={size} height={size} … stroke="currentColor" aria-hidden="true">` so colour is inherited from the surrounding text token (`currentColor`) and light/dark themes work with no extra rules;
- carries a one-line MIT-attribution comment (`<!-- Lucide "<name>" icon — ISC/MIT, https://lucide.dev -->`);
- contains **no** business logic — purely presentational.

### Call-site changes
- Replace each emoji span/glyph with `<Icon … />`.
- `Unlock.svelte`: drop the `.unlock__icon { font-size: 48px }` rule; the size now comes from the `size={48}` prop. Keep the muted colour on the wrapper (`color: var(--color-text-muted)` so `currentColor` resolves muted). `aria-hidden` already satisfied by the icon component.
- Buttons that previously showed only an emoji (FieldRow reveal/hide already carry an `aria-label`; BlockCard, LockButton, Vault nav) keep their accessible name (visible text label or existing `aria-label`); the icon stays `aria-hidden`.

### Deliberate boundary (NOT in scope)
The typographic glyphs **`←`** (back buttons), **`✓`** (MnemonicStep "Copied ✓"), and **`✕`** (D.1.11 revoke controls) are **left as-is**. They are monochrome dingbats/arrows that render consistently cross-platform (they are not color emoji), so they do not exhibit the #154 tofu/inconsistency problem. `✕` in particular shipped in D.1.11 and is not re-touched here.

### Tests
A small Vitest render test per icon family asserting the component renders an `<svg>` with `aria-hidden="true"`, `stroke="currentColor"`, and honours the `size` prop (default + override). Call-site swaps are covered by the existing component tests continuing to pass (the buttons' behaviour and accessible names are unchanged); where a test asserted the emoji text, update it to assert the icon component / its role instead.

## Part 2 — #180: `aria-controls` on the two disclosure buttons

The two disclosure toggles set `aria-expanded` but not `aria-controls`:
- `components/BlockRecipients.svelte` — the "Shared with" toggle (D.1.8).
- `components/contacts/ContactRow.svelte` — the per-contact reverse-map toggle (D.1.9).

### Change
Give each expanded region a **uuid-derived stable id** (unique across sibling rows) and reference it from the toggle's `aria-controls`:
- BlockRecipients: region `id={`recipients-${blockUuidHex}`}`, toggle `aria-controls={`recipients-${blockUuidHex}`}`.
- ContactRow: region `id={`contact-blocks-${contactUuidHex}`}`, toggle `aria-controls={`contact-blocks-${contactUuidHex}`}`.

`aria-controls` should point at the region that is conditionally rendered when expanded; the `id` lives on that region's root element. No behaviour change.

### Tests
Extend each component's existing test to assert the toggle's `aria-controls` equals the rendered region's `id` (and that the id is uuid-derived, hence unique when two instances render).

## Part 3 — #164: `Esc`-pops-a-browse-level

The D.1.2 browse spec (§12) specified `Esc` pops one browse level; only the visible `← <name>` back buttons were implemented. Add the keyboard affordance.

### Mechanism
A `keydown` listener attached in **`routes/Vault.svelte`** (the unlocked container — it is not mounted on the Unlock screen, so "no-op on Unlock" is satisfied structurally) via a Svelte `$effect` that `window.addEventListener('keydown', …)` and returns the matching `removeEventListener` for cleanup.

On `Escape`, call `back()` (from `lib/browse.ts`) **only when** the current `browseNav.level` is `'records'` or `'fields'`. Guards (all must pass):
1. **level guard** — pop only at `'records'` or `'fields'`.
2. **dialog guard** — no-op if `document.querySelector('dialog[open]')` is non-null (the native `<dialog>` SettingsDialog/ConfirmDialog already consume `Esc` via their own `cancel`/`close`; the bubbled `keydown` must not also pop a browse level).
3. **text-entry guard** — no-op if the active element is an `<input>` or `<textarea>` (avoid stealing `Esc` from a focused field).

### Deliberately excluded levels
`'blocks'` (root — nothing to pop), and the **form** levels `'newBlock'` / `'newRecord'` / `'editRecord'` (a global `Esc` there would risk discarding unsaved form input; those screens keep their explicit `← Cancel` button), and `'trash'` / `'contacts'`. Scope is exactly the two read-only browse levels named in #164's acceptance criteria. Widening to other levels is a future affordance, not this slice.

### Revealed-secret state
Popping `'fields'` → `'records'` unmounts the FieldRow subtree; revealed-secret state is cleared by FieldRow's existing `$effect` cleanup (already guaranteed — no new handling needed).

### Tests
Vitest mounts Vault at the `'records'`/`'fields'` level, dispatches a `keydown` `Escape`, and asserts `browseNav.level` popped exactly one level. Separate cases assert: no-op at `'blocks'`; no-op when a `dialog[open]` is present (dialog-open guard); no-op when focus is in an input.

## Part 4 — #170: hoist `lock_session` into `commands::shared`

### Current state
`fn lock_session(state: &Mutex<VaultSession>) -> Result<MutexGuard<'_, VaultSession>, AppError>` (maps a poisoned mutex to `AppError::Internal`) is defined **twice, byte-identically** — in `commands/delete.rs` and `commands/contacts.rs` — and the same `state.lock().map_err(…)` pattern is **open-coded four times** in `commands/edit.rs` (`create_block_impl`, `save_record_impl`, `save_record_edit_impl`, `reveal_record_impl`). (#170 named only edit.rs + delete.rs; contacts.rs is a post-issue third duplicate, folded in here.)

### Change
- Add `pub(crate) fn lock_session(…)` to `commands/shared.rs` beside `parse_uuid_16`, with a doc comment matching that helper's style.
- Adopt it in `delete.rs`, `contacts.rs`, and `edit.rs`; delete both local definitions and replace the four open-coded sites in `edit.rs`.

### Tests
Pure mechanical refactor — the existing per-command tests (`ipc_integration`, the per-module unit tests) cover behaviour. Add a focused unit test in `shared.rs` for the happy path (a non-poisoned mutex yields a guard); the poisoned-mutex branch is exercised indirectly and is awkward to force safely, so it is not separately unit-tested (documented).

## Out of scope / carry-forwards untouched

- **#161** (L4 e2e) — blocked on no tauri-driver for macOS WKWebView.
- **#162** (PathPicker e2e hook) — pairs with #161; deferred.
- **#167** (mirror revoke/edit primitives onto uniffi/pyo3) — no FFI change here.
- The forms' own `Esc`-to-cancel semantics (Part 3 deliberately excludes form levels).

## Verification gauntlet (desktop only)

```
Frontend (desktop/):       pnpm test ; pnpm typecheck ; pnpm svelte-check ; pnpm lint
Rust (desktop/src-tauri):  cargo fmt --check ; cargo clippy --tests -- -D warnings ; cargo test
```

No `cargo test --workspace`, no `conformance.py`, no Swift/Kotlin conformance run — this slice adds no `core`/bridge/`FfiVaultError`/UDL change.

### Manual GUI smoke (pre-merge gate)
Per the temp-copy rule (never open the tracked golden vault — the app writes settings into it, mutating a frozen KAT): `cp -R` the golden vault to a tempdir, `pnpm tauri dev`, and visually confirm: every converted icon renders in light **and** dark theme (currentColor); the Unlock hero lock is correctly sized; `Esc` pops a level from records/fields but not at blocks / with a dialog open / in a focused field; screen-reader `aria-controls` wiring (spot-check via the accessibility inspector). This is a non-functional/visual slice, so the GUI smoke is the gate that the automated suite cannot cover.
