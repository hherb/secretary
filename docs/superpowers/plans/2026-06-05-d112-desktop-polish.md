# D.1.12 Desktop Polish Batch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clear four carry-forward desktop issues as one cohesive pre-external-ship polish slice — a vendored inline-SVG icon system (#154), `aria-controls` on the two disclosure toggles (#180), `Esc`-pops-a-browse-level (#164), and the `lock_session` hoist into `commands::shared` (#170).

**Architecture:** Pure D-phase desktop slice — **no `core` / `ffi` / bridge / `FfiVaultError` / UDL change.** Frontend work is `desktop/src/**` (Svelte 5 runes + TS, Vitest + `@testing-library/svelte`, jsdom). The one Rust change is a mechanical refactor in `desktop/src-tauri/src/commands/**`. Five tasks, each its own TDD commit, ordered most-isolated first: #170 → #180 → icon components (#154a) → call-site migration (#154b) → #164.

**Tech Stack:** Svelte 5 (runes: `$props`, `$state`, `$derived`, `$effect`), TypeScript, Vitest 4, `@testing-library/svelte` 5, jsdom 25; Rust (Tauri command layer). Lucide SVG paths (MIT/ISC) vendored as Svelte components — **no new runtime dependency.**

**Reference spec:** [docs/superpowers/specs/2026-06-05-d112-desktop-polish-design.md](../specs/2026-06-05-d112-desktop-polish-design.md)

---

## Working directory

All commands run from the worktree:

```bash
cd /Users/hherb/src/secretary/.worktrees/d112-desktop-polish
git branch --show-current   # must print: feature/d112-desktop-polish
```

Frontend commands run in `desktop/`; Rust commands in `desktop/src-tauri/`. Shell state does NOT persist between tool calls — chain `cd` in one call or use absolute paths.

## Full verification gauntlet (run before every commit on the relevant side)

Frontend (`desktop/`):
```bash
pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint
```
Rust (`desktop/src-tauri/`):
```bash
cargo fmt --check && cargo clippy --tests -- -D warnings && cargo test
```
A task that touches only one side runs only that side's gauntlet (note per task).

## File structure (what each task creates/modifies)

| Path | Task | Responsibility |
|---|---|---|
| `desktop/src-tauri/src/commands/shared.rs` | T1 | Gains `lock_session` + a unit test module |
| `desktop/src-tauri/src/commands/{edit,delete,contacts}.rs` | T1 | Adopt the hoisted helper; delete local copies |
| `desktop/src/components/BlockRecipients.svelte` | T2 | `aria-controls` ↔ region `id` |
| `desktop/src/components/contacts/ContactRow.svelte` | T2 | `aria-controls` ↔ region `id` |
| `desktop/tests/{BlockRecipients,ContactRow}.test.ts` | T2 | (BlockRecipients.test.ts is new) assert the wiring |
| `desktop/src/components/icons/*.svelte` (7 files) | T3 | One presentational SVG icon component each |
| `desktop/tests/icons.test.ts` | T3 | Render contract for the icon components |
| `desktop/src/theme.css` | T3, T4 | `.icon` baseline rule; `.unlock__icon` cleanup |
| `desktop/src/routes/Unlock.svelte` | T4 | 🔐 → `<LockKeyhole size={48} />` |
| `desktop/src/components/LockButton.svelte` | T4 | 🔒 → `<Lock />` |
| `desktop/src/components/FieldRow.svelte` | T4 | 👁/🙈 → `<Eye />`/`<EyeOff />` |
| `desktop/src/components/BlockCard.svelte` | T4 | 🔗/🗑 → `<Link />`/`<Trash />` |
| `desktop/src/routes/Vault.svelte` | T4, T5 | 🗑/👤 → `<Trash />`/`<Users />` (T4); Esc handler (T5) |
| `desktop/src/lib/browse.ts` | T5 | Pure `shouldPopOnEscape` decision fn |
| `desktop/tests/browse.test.ts` | T5 | (new) `shouldPopOnEscape` truth table |
| `desktop/tests/Vault.test.ts` | T5 | Esc-pop integration cases |

---

## Task 1: #170 — hoist `lock_session` into `commands::shared`

**Files:**
- Modify: `desktop/src-tauri/src/commands/shared.rs` (add helper + test module)
- Modify: `desktop/src-tauri/src/commands/delete.rs` (delete local fn at lines 59-65; import from shared)
- Modify: `desktop/src-tauri/src/commands/contacts.rs` (delete local fn at lines 35-41; import from shared; drop the now-stale #170 doc note)
- Modify: `desktop/src-tauri/src/commands/edit.rs` (replace 4 open-coded `state.lock().map_err(...)` blocks)

**Context:** The helper is currently defined byte-identically in `delete.rs` and `contacts.rs`, and open-coded 4× in `edit.rs` (`create_block_impl`, `save_record_impl`, `save_record_edit_impl`, `reveal_record_impl`). `shared.rs` already hosts `parse_uuid_16` and is `pub(crate) mod shared;` in `mod.rs`.

- [ ] **Step 1: Write the failing test in `shared.rs`**

Append to `desktop/src-tauri/src/commands/shared.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::VaultSession;
    use std::sync::Mutex;

    #[test]
    fn lock_session_yields_a_guard_on_a_healthy_mutex() {
        // A non-poisoned session mutex locks cleanly; the guard derefs to the
        // session (here: the locked default state — no unlocked identity).
        let state = Mutex::new(VaultSession::default());
        let guard = lock_session(&state).expect("healthy mutex must lock");
        // Touching the guard proves we got the real session back, not an error.
        let _ = &*guard;
    }
}
```

> Note: if `VaultSession` has no `Default`, construct it the way the existing `delete.rs`/`contacts.rs` unit tests do (grep `VaultSession::` in `commands/*.rs` tests for the canonical constructor) and use that instead of `::default()`. The assertion is unchanged.

- [ ] **Step 2: Run the test — verify it fails to compile**

Run: `cd desktop/src-tauri && cargo test --lib lock_session_yields_a_guard_on_a_healthy_mutex`
Expected: FAIL — `cannot find function lock_session in this scope` (it is not yet defined in `shared`).

- [ ] **Step 3: Add `lock_session` to `shared.rs`**

Insert above the `#[cfg(test)]` module, after `parse_uuid_16`:

```rust
use std::sync::{Mutex, MutexGuard};

use crate::session::VaultSession;

/// Lock the session mutex, folding a poisoned lock to `Internal`. Shared by
/// every command `*_impl`. A poisoned mutex means a prior handler panicked
/// while holding the session lock — unrecoverable, so it surfaces as a typed
/// `Internal` rather than propagating the panic.
pub(crate) fn lock_session(
    state: &Mutex<VaultSession>,
) -> Result<MutexGuard<'_, VaultSession>, AppError> {
    state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })
}
```

> If `shared.rs` already `use`s `crate::errors::AppError`, keep the single import; only add the `Mutex`/`MutexGuard`/`VaultSession` imports. Adjust the `use` block so `cargo fmt` is satisfied (grouped std imports first).

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd desktop/src-tauri && cargo test --lib lock_session_yields_a_guard_on_a_healthy_mutex`
Expected: PASS.

- [ ] **Step 5: Adopt in `delete.rs`**

Delete the local definition (lines ~59-65):

```rust
fn lock_session(
    state: &Mutex<VaultSession>,
) -> Result<std::sync::MutexGuard<'_, VaultSession>, AppError> {
    state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })
}
```

Add `lock_session` to delete.rs's existing shared import. Find the line `use crate::commands::shared::parse_uuid_16;` and change it to:

```rust
use crate::commands::shared::{lock_session, parse_uuid_16};
```

> If `delete.rs` has no such `use` line yet, add it. The call sites (`let session = lock_session(state)?;`) are unchanged.

- [ ] **Step 6: Adopt in `contacts.rs`**

Delete the local definition (lines ~35-41) AND its doc comment (the block starting `/// Lock the session mutex, folding poison to Internal. Shared by every ... issue #170).`). Update the existing import line `use crate::commands::shared::parse_uuid_16;` to:

```rust
use crate::commands::shared::{lock_session, parse_uuid_16};
```

Also update the module-header doc comment in `contacts.rs` (lines ~7-10) that currently reads *"`lock_session` is defined locally here ... not yet hoisted into `commands::shared`; see issue #170."* — delete that sentence (the hoist is now done).

- [ ] **Step 7: Adopt in `edit.rs` (4 sites)**

Add the import near the top of `edit.rs` (it already imports other `commands::shared` items or `parse_uuid_16`; merge into that line, else add):

```rust
use crate::commands::shared::{lock_session, parse_uuid_16};
```

Replace each of the 4 open-coded blocks of the form:

```rust
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
```

with:

```rust
    let session = lock_session(state)?;
```

in `create_block_impl`, `save_record_impl`, `save_record_edit_impl`, and `reveal_record_impl`. After the edits, grep to confirm none remain:

Run: `cd desktop/src-tauri && grep -rn "session mutex poisoned" src/commands` — expected: exactly ONE hit, in `shared.rs`.

- [ ] **Step 8: Run the Rust gauntlet**

Run: `cd desktop/src-tauri && cargo fmt --check && cargo clippy --tests -- -D warnings && cargo test 2>&1 | grep "^test result:"`
Expected: fmt clean; clippy clean; all test suites pass (lib, `ipc_integration`, `session`). If `cargo fmt --check` fails, run `cargo fmt` and re-check.

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d112-desktop-polish
git add desktop/src-tauri/src/commands/shared.rs desktop/src-tauri/src/commands/edit.rs desktop/src-tauri/src/commands/delete.rs desktop/src-tauri/src/commands/contacts.rs
git commit -m "$(cat <<'EOF'
D.1.12 #170 — hoist lock_session into commands::shared

Single definition beside parse_uuid_16; adopt in edit.rs (4 open-coded
sites), delete.rs, and contacts.rs (a post-issue third duplicate). Pure
mechanical refactor; existing command tests cover behaviour, plus a
happy-path unit test for the hoisted helper.

Closes #170.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: #180 — `aria-controls` on the two disclosure toggles

**Files:**
- Modify: `desktop/src/components/BlockRecipients.svelte`
- Modify: `desktop/src/components/contacts/ContactRow.svelte`
- Create: `desktop/tests/BlockRecipients.test.ts`
- Modify: `desktop/tests/ContactRow.test.ts`

**Context:** Both toggles set `aria-expanded` but no `aria-controls`. Give each expanded region a uuid-derived `id` (unique across sibling rows) and reference it from the toggle. The id only needs to exist when the region renders (expanded) — `aria-controls` may reference a not-yet-rendered region per ARIA.

- [ ] **Step 1: Write the failing test for BlockRecipients**

`BlockRecipients` has no test file yet. Create `desktop/tests/BlockRecipients.test.ts`. It mocks `listBlockRecipients` (so the toggle renders) and asserts the wiring after expanding:

```ts
// Tests for BlockRecipients.svelte's a11y disclosure wiring (#180): the
// "Shared with" toggle's aria-controls must equal the id of the region it
// expands, and that id is uuid-derived (unique across sibling rows).
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import BlockRecipients from '../src/components/BlockRecipients.svelte';
import type { BlockSummaryDto, RecipientDto } from '../src/lib/ipc';

const { listBlockRecipientsMock } = vi.hoisted(() => ({
  listBlockRecipientsMock: vi.fn()
}));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return { ...real, listBlockRecipients: listBlockRecipientsMock };
});

const BLOCK: BlockSummaryDto = {
  blockUuidHex: 'deadbeef',
  blockName: 'Banking',
  createdAtMs: Date.UTC(2024, 0, 1),
  lastModifiedMs: Date.UTC(2024, 5, 15)
};
const OWNER: RecipientDto = { uuidHex: 'owner', kind: 'owner', displayName: 'You' };

beforeEach(() => {
  listBlockRecipientsMock.mockReset();
  listBlockRecipientsMock.mockResolvedValue([OWNER]);
});

describe('BlockRecipients.svelte — #180 aria-controls wiring', () => {
  it('toggle aria-controls equals the expanded region id (uuid-derived)', async () => {
    const { container, getByRole } = render(BlockRecipients, { props: { block: BLOCK } });
    const toggle = await waitFor(() => getByRole('button', { name: /shared with/i }));
    const controls = toggle.getAttribute('aria-controls');
    expect(controls).toBe(`recipients-${BLOCK.blockUuidHex}`);
    await fireEvent.click(toggle); // expand so the region renders
    const region = container.querySelector(`#${controls}`);
    expect(region).not.toBeNull();
  });
});
```

- [ ] **Step 2: Run it — verify it fails**

Run: `cd desktop && pnpm test -- BlockRecipients`
Expected: FAIL — `aria-controls` is currently `null`, so `expect(controls).toBe('recipients-deadbeef')` fails.

- [ ] **Step 3: Wire BlockRecipients**

In `desktop/src/components/BlockRecipients.svelte`, add `aria-controls` to the toggle `<button>` (the one with `class="block-recipients__toggle"`):

```svelte
    <button
      type="button"
      class="block-recipients__toggle"
      aria-expanded={expanded}
      aria-controls={`recipients-${block.blockUuidHex}`}
      onclick={() => (expanded = !expanded)}
    >
      Shared with: {summary} {expanded ? '▴' : '▾'}
    </button>
```

and add the matching `id` to the expanded `<ul>`:

```svelte
      <ul class="block-recipients__list" id={`recipients-${block.blockUuidHex}`}>
```

- [ ] **Step 4: Run it — verify it passes**

Run: `cd desktop && pnpm test -- BlockRecipients`
Expected: PASS.

- [ ] **Step 5: Add the failing test for ContactRow**

Append to `desktop/tests/ContactRow.test.ts` a case mirroring Step 1 (the file already mocks `listContactBlocks`; reuse its fixtures/mocks). The region wraps the conditional content, so the test expands first, then checks the wrapper id:

```ts
  it('#180 — toggle aria-controls equals the expanded region id (uuid-derived)', async () => {
    const { container, getByRole } = render(ContactRow, {
      props: { contact: CONTACT, onDelete: () => {}, onRevoked: () => {} }
    });
    const toggle = getByRole('button', { name: new RegExp(CONTACT.displayName, 'i') });
    expect(toggle.getAttribute('aria-controls')).toBe(`contact-blocks-${CONTACT.contactUuidHex}`);
    await fireEvent.click(toggle);
    expect(container.querySelector(`#contact-blocks-${CONTACT.contactUuidHex}`)).not.toBeNull();
  });
```

> Use the file's existing `CONTACT` fixture name; if it differs, match it. Ensure `render`, `fireEvent` are imported (they already are in this file).

- [ ] **Step 6: Run it — verify it fails**

Run: `cd desktop && pnpm test -- ContactRow`
Expected: FAIL — `aria-controls` is `null`.

- [ ] **Step 7: Wire ContactRow**

In `desktop/src/components/contacts/ContactRow.svelte`, add `aria-controls` to the toggle (`class="contact-card-row__toggle"`):

```svelte
    <button
      type="button"
      class="contact-card-row__toggle"
      aria-expanded={expanded}
      aria-controls={`contact-blocks-${contact.contactUuidHex}`}
      onclick={toggle}
    >
```

and wrap the expanded region in a `<div>` carrying the id. Change the `{#if expanded}` block so its contents are wrapped:

```svelte
  {#if expanded}
    <div id={`contact-blocks-${contact.contactUuidHex}`}>
      {#if error}
        {@const msg = userMessageFor(error)}
        <p class="contact-blocks__error" role="alert">
          {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
        </p>
      {:else if loading || blocks === null}
        <p class="contact-blocks__loading">Loading blocks…</p>
      {:else if blocks.length === 0}
        <p class="contact-blocks__empty">No shared blocks.</p>
      {:else}
        <ul class="contact-blocks__list">
          {#each blocks as b (b.blockUuidHex)}
            <li class="contact-blocks__row">
              <button type="button" class="contact-blocks__item" onclick={() => openBlock(b)}>
                {b.blockName}
              </button>
              <button
                type="button"
                class="contact-blocks__revoke"
                aria-label={`Stop sharing “${b.blockName}” with ${contact.displayName}`}
                onclick={() => (pendingRevoke = b)}
              >
                ✕
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}
```

> The wrapping `<div>` is a plain container; no new CSS needed (the inner elements keep their classes). `svelte-check` must stay at 0 unused selectors.

- [ ] **Step 8: Run the frontend gauntlet**

Run: `cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint`
Expected: all green (407+ tests including the 2 new cases; 0 svelte-check errors/warnings).

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d112-desktop-polish
git add desktop/src/components/BlockRecipients.svelte desktop/src/components/contacts/ContactRow.svelte desktop/tests/BlockRecipients.test.ts desktop/tests/ContactRow.test.ts
git commit -m "$(cat <<'EOF'
D.1.12 #180 — pair aria-controls with aria-expanded on disclosure toggles

BlockRecipients "Shared with" + ContactRow reverse-map toggles now point
aria-controls at a uuid-derived id on the region they expand (unique across
sibling rows). a11y enhancement, no behaviour change.

Closes #180.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: #154a — vendored inline-SVG icon components

**Files:**
- Create: `desktop/src/components/icons/{LockKeyhole,Lock,Eye,EyeOff,Link,Trash,Users}.svelte`
- Create: `desktop/tests/icons.test.ts`
- Modify: `desktop/src/theme.css` (add `.icon` baseline rule)

**Context:** No icon infrastructure exists. Each component is a presentational SVG inlining a Lucide path, `stroke="currentColor"` (inherits the surrounding text colour → light/dark themes work for free), `aria-hidden="true"`, `size` prop (default `20`). One concept per file, tree-shakeable, no runtime dependency.

- [ ] **Step 1: Write the failing render test**

Create `desktop/tests/icons.test.ts`:

```ts
// Render contract for the vendored Lucide icon components (#154). Each is a
// presentational SVG: aria-hidden, currentColor stroke, square, sized by the
// `size` prop (default 20). We assert the contract on a representative pair
// (Lock = default size; LockKeyhole = the hero override) and smoke-render the
// rest so a malformed SVG fails the suite.
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import Lock from '../src/components/icons/Lock.svelte';
import LockKeyhole from '../src/components/icons/LockKeyhole.svelte';
import Eye from '../src/components/icons/Eye.svelte';
import EyeOff from '../src/components/icons/EyeOff.svelte';
import Link from '../src/components/icons/Link.svelte';
import Trash from '../src/components/icons/Trash.svelte';
import Users from '../src/components/icons/Users.svelte';

describe('icons — render contract', () => {
  it('Lock renders a decorative, currentColor SVG at the default size (20)', () => {
    const { container } = render(Lock);
    const svg = container.querySelector('svg');
    expect(svg).not.toBeNull();
    expect(svg!.getAttribute('aria-hidden')).toBe('true');
    expect(svg!.getAttribute('stroke')).toBe('currentColor');
    expect(svg!.getAttribute('width')).toBe('20');
    expect(svg!.getAttribute('height')).toBe('20');
  });

  it('honours the size prop (hero override)', () => {
    const { container } = render(LockKeyhole, { props: { size: 48 } });
    const svg = container.querySelector('svg');
    expect(svg!.getAttribute('width')).toBe('48');
    expect(svg!.getAttribute('height')).toBe('48');
  });

  it('every icon renders a non-empty SVG', () => {
    for (const Icon of [Eye, EyeOff, Link, Trash, Users]) {
      const { container } = render(Icon);
      const svg = container.querySelector('svg');
      expect(svg).not.toBeNull();
      expect(svg!.innerHTML.length).toBeGreaterThan(0);
    }
  });
});
```

- [ ] **Step 2: Run it — verify it fails**

Run: `cd desktop && pnpm test -- icons`
Expected: FAIL — cannot resolve `../src/components/icons/Lock.svelte` (files don't exist).

- [ ] **Step 3: Author the icon components**

Each file follows this exact template — only the inner `<!-- paths -->` change. Example, `desktop/src/components/icons/Lock.svelte`:

```svelte
<script lang="ts">
  // Lucide "lock" icon — ISC/MIT, https://lucide.dev. Vendored (no runtime
  // dep). Presentational: aria-hidden; colour via currentColor (inherits the
  // surrounding text token, so light/dark themes need no extra rules).
  type Props = { size?: number };
  let { size = 20 }: Props = $props();
</script>

<svg
  class="icon"
  xmlns="http://www.w3.org/2000/svg"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
</svg>
```

Create the other six with the same wrapper, swapping the comment's icon name and the inner shapes:

| File | Comment name | Inner SVG shapes |
|---|---|---|
| `LockKeyhole.svelte` | `lock-keyhole` | `<circle cx="12" cy="16" r="1" /><rect width="18" height="12" x="3" y="10" rx="2" /><path d="M7 10V7a5 5 0 0 1 10 0v3" />` |
| `Eye.svelte` | `eye` | `<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" />` |
| `EyeOff.svelte` | `eye-off` | `<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" /><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" /><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" /><line x1="2" x2="22" y1="2" y2="22" />` |
| `Link.svelte` | `link` | `<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" /><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />` |
| `Trash.svelte` | `trash-2` | `<path d="M3 6h18" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" /><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><line x1="10" x2="10" y1="11" y2="17" /><line x1="14" x2="14" y1="11" y2="17" />` |
| `Users.svelte` | `users` | `<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M22 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />` |

- [ ] **Step 4: Run it — verify it passes**

Run: `cd desktop && pnpm test -- icons`
Expected: PASS (all three describe-blocks).

- [ ] **Step 5: Add the `.icon` baseline rule to `theme.css`**

Append to `desktop/src/theme.css` (so icons align with adjacent text and never shrink in flex rows):

```css
/* Vendored inline-SVG icons (#154). currentColor inherits the surrounding
   text token; vertical-align keeps the glyph centred next to text labels. */
.icon {
  display: inline-block;
  vertical-align: middle;
  flex-shrink: 0;
}
```

- [ ] **Step 6: Run the frontend gauntlet**

Run: `cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint`
Expected: all green. (No call sites use the icons yet, so `svelte-check` must not report the new `.icon` rule as unused — it won't, since the components carry `class="icon"`.)

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d112-desktop-polish
git add desktop/src/components/icons desktop/tests/icons.test.ts desktop/src/theme.css
git commit -m "$(cat <<'EOF'
D.1.12 #154a — vendored inline-SVG icon components (Lucide)

Seven presentational icon components (Lock, LockKeyhole, Eye, EyeOff, Link,
Trash, Users), each inlining a Lucide path (ISC/MIT) with currentColor +
aria-hidden + a size prop. No runtime dependency. Call-site migration follows
in #154b.

Refs #154.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: #154b — migrate the emoji call sites to the icon components

**Files:**
- Modify: `desktop/src/routes/Unlock.svelte` (🔐)
- Modify: `desktop/src/components/LockButton.svelte` (🔒)
- Modify: `desktop/src/components/FieldRow.svelte` (👁/🙈)
- Modify: `desktop/src/components/BlockCard.svelte` (🔗/🗑)
- Modify: `desktop/src/routes/Vault.svelte` (🗑/👤)
- Modify: `desktop/src/theme.css` (`.unlock__icon` cleanup)
- Modify: `desktop/tests/Vault.test.ts` (update the stale `🔒 Lock` comment at line ~98)

**Context:** Swap each color-emoji glyph for its icon component. The typographic glyphs `←`, `✓`, `✕`, `⧉` are NOT touched (monochrome, render consistently). No existing test asserts an emoji glyph as text (verified: only comments reference them), so behaviour-by-class/aria-label tests stay green.

- [ ] **Step 1: Migrate the Unlock hero (🔐)**

In `desktop/src/routes/Unlock.svelte`, add the import at the top of `<script>`:

```ts
  import LockKeyhole from '../components/icons/LockKeyhole.svelte';
```

Replace the icon div body:

```svelte
    <div class="unlock__icon" aria-hidden="true"><LockKeyhole size={48} /></div>
```

Then in `desktop/src/theme.css`, change the `.unlock__icon` rule (currently `font-size: 48px; margin-bottom: var(--space-2);`) — drop `font-size` (size now comes from the prop), set the muted colour so `currentColor` resolves, and zero the line box:

```css
.unlock__icon {
  margin-bottom: var(--space-2);
  line-height: 0;
  color: var(--color-text-muted);
}
```

- [ ] **Step 2: Migrate LockButton (🔒)**

In `desktop/src/components/LockButton.svelte`, add:

```ts
  import Lock from './icons/Lock.svelte';
```

Replace the button body `🔒 Lock` with:

```svelte
<button type="button" class="lock-button" onclick={handleClick}>
  <Lock /> Lock
</button>
```

> The accessible name becomes "Lock" (the icon is aria-hidden). `Vault.test.ts` queries `.lock-button` by class (not text), so it stays green. Update its stale comment in Step 7.

- [ ] **Step 3: Migrate FieldRow (👁/🙈)**

In `desktop/src/components/FieldRow.svelte`, add:

```ts
  import Eye from './icons/Eye.svelte';
  import EyeOff from './icons/EyeOff.svelte';
```

Replace the reveal button glyph `👁` and the hide button glyph `🙈` (keep the existing `aria-label`s and the `⧉` copy button unchanged):

```svelte
    <button type="button" class="field-row__btn" aria-label={`reveal ${field.name}`} onclick={reveal} disabled={busy}><Eye /></button>
```
```svelte
    <button type="button" class="field-row__btn" aria-label={`hide ${field.name}`} onclick={mask}><EyeOff /></button>
```

- [ ] **Step 4: Migrate BlockCard (🔗/🗑)**

In `desktop/src/components/BlockCard.svelte`, add:

```ts
  import Link from './icons/Link.svelte';
  import Trash from './icons/Trash.svelte';
```

Replace `🔗` (share button) with `<Link />` and `🗑` (trash button) with `<Trash />`, keeping each button's existing `aria-label`:

```svelte
    <button type="button" class="block-card__share" aria-label="Share block" onclick={() => onShare(block)}><Link /></button>
```
```svelte
    <button type="button" class="block-card__trash" aria-label="Trash block" onclick={() => onTrash(block)}><Trash /></button>
```

- [ ] **Step 5: Migrate the Vault nav (🗑/👤)**

In `desktop/src/routes/Vault.svelte`, add to the existing import block:

```ts
  import Trash from '../components/icons/Trash.svelte';
  import Users from '../components/icons/Users.svelte';
```

Replace the two nav entries' glyphs (keep the text labels):

```svelte
      <button type="button" class="vault__trash-entry" onclick={() => openTrash()}><Trash /> Trash</button>
      <button type="button" class="vault__contacts-entry" onclick={() => openContacts()}><Users /> Contacts</button>
```

- [ ] **Step 6: Verify no color-emoji icon remains**

Run: `cd desktop && grep -rn '🔐\|🔒\|👁\|🙈\|🔗\|🗑\|👤' src`
Expected: NO hits in `src/**` (a hit in a `// comment` is acceptable only if it documents history; prefer none). The `⧉ ✕ ✓ ←` glyphs intentionally remain.

- [ ] **Step 7: Update the stale comment in `Vault.test.ts`**

In `desktop/tests/Vault.test.ts` (~line 98), the comment says ``// `🔒 Lock` button rendered by TopBar. The accessible name is "🔒 Lock"``. Update it to reflect the icon swap:

```ts
    // Lock button rendered by TopBar (icon + "Lock" text; the icon is
    // aria-hidden so the accessible name is "Lock"). Matching the class pins
    // to the correct button and avoids `/lock/i` matching "+ New block".
```

- [ ] **Step 8: Run the frontend gauntlet**

Run: `cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint`
Expected: all green. If any component test fails because it matched a button by emoji text, switch that query to the button's class or `aria-label` (none are expected per the verification grep).

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d112-desktop-polish
git add desktop/src/routes/Unlock.svelte desktop/src/components/LockButton.svelte desktop/src/components/FieldRow.svelte desktop/src/components/BlockCard.svelte desktop/src/routes/Vault.svelte desktop/src/theme.css desktop/tests/Vault.test.ts
git commit -m "$(cat <<'EOF'
D.1.12 #154b — migrate emoji-as-icons to vendored SVG components

Swap the eight color-emoji icon sites (🔐 🔒 👁 🙈 🔗 🗑×2 👤) for the
Lucide components from #154a. Drop .unlock__icon font-size (size now via the
prop; muted via currentColor). Typographic glyphs (← ✓ ✕ ⧉) intentionally
unchanged — they are monochrome and render consistently cross-platform.

Closes #154.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: #164 — `Esc` pops a browse level

**Files:**
- Modify: `desktop/src/lib/browse.ts` (add pure `shouldPopOnEscape`)
- Create: `desktop/tests/browse.test.ts` (truth table for the pure fn)
- Modify: `desktop/src/routes/Vault.svelte` (wire the keydown handler)
- Modify: `desktop/tests/Vault.test.ts` (integration cases)

**Context:** Only the visible `← <name>` back buttons exist. Add the keyboard affordance. The decision logic is a pure function (testable in isolation, per the project's pure-functions preference); Vault wires it to a window `keydown` via `$effect`. Vault is mounted only when unlocked, so "no-op on Unlock screen" is structural.

- [ ] **Step 1: Write the failing test for `shouldPopOnEscape`**

Create `desktop/tests/browse.test.ts`:

```ts
// #164 — Esc pops one browse level, but only at the read-only browse levels
// and only when nothing else owns the Escape key. shouldPopOnEscape is the
// pure decision; Vault wires it to a window keydown. This truth table pins
// every guard so the wiring stays a thin adapter.
import { describe, it, expect } from 'vitest';
import { shouldPopOnEscape } from '../src/lib/browse';
import type { BrowseNav } from '../src/lib/browse';

const LEVELS: BrowseNav['level'][] = [
  'blocks', 'records', 'fields', 'newBlock',
  'newRecord', 'editRecord', 'trash', 'contacts'
];

describe('shouldPopOnEscape', () => {
  it('pops only at records and fields when no dialog/text-field owns Esc', () => {
    for (const level of LEVELS) {
      const expected = level === 'records' || level === 'fields';
      expect(shouldPopOnEscape(level, false, false)).toBe(expected);
    }
  });

  it('never pops while a dialog is open (dialog owns Esc)', () => {
    expect(shouldPopOnEscape('records', true, false)).toBe(false);
    expect(shouldPopOnEscape('fields', true, false)).toBe(false);
  });

  it('never pops while focus is in a text field', () => {
    expect(shouldPopOnEscape('records', false, true)).toBe(false);
    expect(shouldPopOnEscape('fields', false, true)).toBe(false);
  });
});
```

- [ ] **Step 2: Run it — verify it fails**

Run: `cd desktop && pnpm test -- browse`
Expected: FAIL — `shouldPopOnEscape` is not exported from `browse.ts`.

- [ ] **Step 3: Implement `shouldPopOnEscape` in `browse.ts`**

Append to `desktop/src/lib/browse.ts`:

```ts
// #164 — decide whether an Escape keypress should pop one browse level.
// Pure so the guard matrix is unit-tested in isolation; Vault.svelte supplies
// the live level + the two environment booleans. Pops ONLY at the read-only
// browse levels 'records'/'fields' — never at the root, never at a form level
// (Esc there would risk discarding unsaved input; those keep their ← Cancel),
// and never when a dialog or a focused text field already owns Escape.
export function shouldPopOnEscape(
  level: BrowseNav['level'],
  dialogOpen: boolean,
  inTextField: boolean
): boolean {
  if (dialogOpen || inTextField) return false;
  return level === 'records' || level === 'fields';
}
```

- [ ] **Step 4: Run it — verify it passes**

Run: `cd desktop && pnpm test -- browse`
Expected: PASS.

- [ ] **Step 5: Write the failing Vault integration test**

Append to `desktop/tests/Vault.test.ts` a new describe block (the helpers `unlockWith`, `manifestFixture`, `blockFixture`, `openBlock`, `resetBrowse` are already in this file; add `get` from `svelte/store` and `browseNav` to the imports at the top — `import { get } from 'svelte/store';` and add `browseNav` to the `'../src/lib/browse'` import):

```ts
describe('Vault.svelte — #164 Esc pops a browse level', () => {
  it('Escape at records pops to blocks', async () => {
    const block = blockFixture('B', 'ab');
    unlockWith(manifestFixture({ blocks: [block] }));
    render(Vault);
    openBlock(block);
    await waitFor(() => expect(document.querySelector('.record-list')).toBeTruthy());

    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await waitFor(() => expect(get(browseNav).level).toBe('blocks'));
  });

  it('Escape at blocks is a no-op (nothing to pop)', async () => {
    unlockWith(manifestFixture({ blocks: [blockFixture('B', 'ab')] }));
    render(Vault);
    expect(get(browseNav).level).toBe('blocks');
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await new Promise((r) => setTimeout(r, 0));
    expect(get(browseNav).level).toBe('blocks');
  });

  it('Escape with the settings dialog open closes only the dialog (no pop)', async () => {
    const block = blockFixture('B', 'ab');
    unlockWith(manifestFixture({ blocks: [block] }));
    const { getByRole } = render(Vault);
    openBlock(block);
    await waitFor(() => expect(document.querySelector('.record-list')).toBeTruthy());
    // Open settings → a native <dialog open> is present; the guard must hold.
    await fireEvent.click(getByRole('button', { name: /settings/i }));
    await waitFor(() =>
      expect(document.querySelector('dialog[open]')).toBeTruthy()
    );
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await new Promise((r) => setTimeout(r, 0));
    expect(get(browseNav).level).toBe('records'); // did NOT pop
  });
});
```

> `fireEvent` is already imported in `Vault.test.ts`. If the settings dialog's accessible name differs from `/settings/i`, reuse the exact selector the existing "settings gear" test uses (line ~207).

- [ ] **Step 6: Run it — verify it fails**

Run: `cd desktop && pnpm test -- Vault`
Expected: FAIL — the first case fails (`level` stays `records`; no handler yet).

- [ ] **Step 7: Wire the handler in `Vault.svelte`**

Add to the `<script>` imports in `desktop/src/routes/Vault.svelte`:

```ts
  import { get } from 'svelte/store';
  import { shouldPopOnEscape } from '../lib/browse';
```

> `browseNav` and `back` are already imported from `'../lib/browse'`. Merge `shouldPopOnEscape` into that existing import line rather than adding a second.

Add the handler + effect inside `<script>` (after the existing state declarations, e.g. below `confirmTrash`):

```ts
  // #164 — Esc pops one browse level. Window-level so it works regardless of
  // focus; the pure guard decides. Vault mounts only when unlocked, so the
  // Unlock screen is excluded structurally. Native <dialog>s own their own
  // Esc, so we no-op when one is open; likewise when a text field has focus.
  function handleKeydown(e: KeyboardEvent): void {
    if (e.key !== 'Escape') return;
    const dialogOpen = document.querySelector('dialog[open]') !== null;
    const el = document.activeElement;
    const inTextField =
      el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement;
    if (shouldPopOnEscape(get(browseNav).level, dialogOpen, inTextField)) {
      e.preventDefault();
      back();
    }
  }

  $effect(() => {
    window.addEventListener('keydown', handleKeydown);
    return () => window.removeEventListener('keydown', handleKeydown);
  });
```

- [ ] **Step 8: Run it — verify it passes**

Run: `cd desktop && pnpm test -- Vault`
Expected: PASS (all three new cases + the pre-existing Vault suite).

- [ ] **Step 9: Run the full frontend gauntlet**

Run: `cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint`
Expected: all green.

- [ ] **Step 10: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d112-desktop-polish
git add desktop/src/lib/browse.ts desktop/tests/browse.test.ts desktop/src/routes/Vault.svelte desktop/tests/Vault.test.ts
git commit -m "$(cat <<'EOF'
D.1.12 #164 — Esc pops a browse level (records/fields)

Pure shouldPopOnEscape decision (unit-tested truth table) wired to a window
keydown in Vault via $effect. Pops only at the read-only browse levels;
no-op at the root, at form levels (unsaved-input risk), with a dialog open,
or while a text field has focus.

Closes #164.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Final steps (after all five tasks)

- [ ] **Update README.md / ROADMAP.md** — mark D.1.12 ✅ shipped 2026-06-05; advance "next" to D.1.13 (open). Mirror the D.1.11 entry's brevity. Commit on the branch.
- [ ] **Author the handoff** — `docs/handoffs/2026-06-05-d112-desktop-polish-shipped.md` + retarget `NEXT_SESSION.md` symlink (`ln -snf docs/handoffs/2026-06-05-d112-desktop-polish-shipped.md NEXT_SESSION.md`); commit both on the branch.
- [ ] **Whole-branch review** via `superpowers:requesting-code-review` before opening the PR.
- [ ] **Manual GUI smoke (pre-merge gate)** — per the spec's smoke section: `cp -R` the golden vault to a tempdir (NEVER open the tracked fixture), `pnpm tauri dev`, and verify every converted icon renders in light + dark theme, the Unlock hero lock is correctly sized, and `Esc` pops from records/fields but not at blocks / with a dialog open / in a focused field. Record the result in the PR.
- [ ] **Open the PR** against `main`.

## Self-review notes (spec coverage)

- #154 → T3 (components) + T4 (call sites + theme cleanup). All eight color-emoji sites covered; typographic glyphs deliberately excluded per spec.
- #180 → T2. Both disclosure toggles wired; uuid-derived ids unique across rows.
- #164 → T5. Pure guard + Vault wiring; all three guards (level, dialog, text-field) tested; form/trash/contacts levels deliberately excluded per spec.
- #170 → T1. All three modules consolidated (incl. contacts.rs, broader than the issue), single helper in `shared.rs`, happy-path unit test added.
- No `core`/`ffi`/bridge change → no cross-language gauntlet; verified by the absence of any edit under `core/` or `ffi/`.
