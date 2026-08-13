# Desktop three-pane layout (#526)

**Date:** 2026-08-13
**Status:** approved, ready for implementation planning
**Scope:** `desktop/` only — no `core`, no FFI bridge, no mobile.

## Problem

[`desktop/src/routes/Vault.svelte`](../../../desktop/src/routes/Vault.svelte) renders exactly one of nine
`browseNav` levels at a time. Seeing a record's fields hides the record list;
seeing the record list hides the blocks. Every navigation is a full context
swap, and the user must hold the hierarchy in their head instead of seeing it.

The target is the layout mSecure uses: blocks in a left sidebar, records in a
middle column, record detail on the right, all three visible at once.

A second, smaller problem rides along. Record rows currently show
`record_type` as their primary text, so a list of thirty logins reads
"login" thirty times. The middle pane is only useful if rows are
distinguishable.

## Non-goals

- Any change to `browseNav`'s shape, to the Rust core, or to the FFI surface.
- Splitting `TrashView` / `ContactsPane` into their own list+detail panes.
- A responsive collapse mode for narrow windows.
- A dirty-tracking-plus-confirm-dialog editor guard (see "Follow-ups").

## Architecture: the panes are a projection, not new state

The nine `browseNav` arms are kept exactly as they are. A new pure function
maps each arm onto four slots:

```ts
// desktop/src/lib/panes.ts
export interface PaneLayout {
  sidebar: SidebarSelection;   // block uuid | 'trash' | 'contacts' | none
  list:    ListPane;           // records | trash | contacts | empty-prompt
  detail:  DetailPane;         // viewer | editor | empty-prompt | spanned
  modal:   ModalPane;          // block-name dialog | none
}
export function panesFor(nav: BrowseNav): PaneLayout;
```

This is the load-bearing decision of the design. The alternative — teaching
the store about panes — would add navigation states, and every existing
guard (`shouldPopOnEscape`, `resetBrowse`, the trash and rename flows) would
need re-auditing against them. As a projection, the panes are a *view* of
state that is already tested, and the nine-arm mapping is itself a pure
function with a unit test per arm.

### Projection table

| `nav.level` | sidebar | list (middle) | detail (right) | modal |
|---|---|---|---|---|
| `blocks` | nothing selected | *"Select a block"* | *(empty)* | — |
| `records` | `nav.block` | records of block | *"Select a record"* | — |
| `fields` | `nav.block` | records, row selected | `FieldViewer` | — |
| `editRecord` | `nav.block` | records, row selected, **frozen** | `RecordEditor` (edit) | — |
| `newRecord` | `nav.block` | records, **frozen** | `RecordEditor` (new) | — |
| `trash` | Trash | `TrashView` — spans list + detail | | — |
| `contacts` | Contacts | `ContactsPane` — spans list + detail | | — |
| `newBlock` | nothing selected | *"Select a block"* | *(empty)* | `BlockNameDialog` |
| `renameBlock` | `nav.block` | records of block | *(empty)* | `BlockNameDialog` |

`TrashView` and `ContactsPane` span both right-hand columns rather than being
split. Neither has a list/detail division today, and inventing one is new
capability rather than layout; they keep working untouched and a later split
is additive.

The two `BlockNameDialog` arms show the projection paying for itself: the
modal backdrop is well-defined for free. Cancel a rename and the block you
were renaming is already selected behind the dialog, because `nav.block`
drove the sidebar throughout.

### Files

```
desktop/src/lib/panes.ts                    NEW   pure projection
desktop/src/lib/paneWidths.ts               NEW   fraction persistence + floors
desktop/src/components/PaneShell.svelte     NEW   grid + two splitters
desktop/src/components/BlockSidebar.svelte  NEW   blocks + destinations + "New block"
desktop/src/routes/Vault.svelte             EDIT  renders PaneShell; drops the 9-arm {#if}
desktop/src/components/RecordList.svelte    EDIT  loses back button; gains selected-row + frozen states
desktop/src/components/FieldViewer.svelte   EDIT  loses back button
desktop/src/components/BlockCard.svelte     EDIT  actions become reveal-on-hover-or-selection
desktop/src/theme.css                       EDIT  two width tokens
desktop/src-tauri/src/record_title.rs       NEW   pure title/subtitle derivation
desktop/src-tauri/src/reveal.rs             EDIT  project_record calls record_title
```

Block names come from the signed manifest (`BlockSummaryDto.blockName`), so
the sidebar costs no decryption.

[`BlockCard`](../../../desktop/src/components/BlockCard.svelte) currently renders Rename, Share and Trash as three
permanently-visible buttons per row. Three buttons do not fit a sidebar
column, so they collapse to reveal-on-hover-or-selection. This is the one
piece of visual behaviour the slice changes rather than relocates.

## Record titles: an allowlist, default-deny

Rows need a title and subtitle instead of `record_type`. Deriving them means
`project_record` calling `expose_text` on fields it previously never read, so
the rule for *which* fields is a security decision.

**The rule is an allowlist, checked in priority order, applied regardless of
`record_type`, matching `is_text()` fields only:**

```rust
const TITLE_NAMES: [&str; 6] = ["title", "name", "service", "username", "url", "key_id"];
```

Title is the value of the first matching field. Subtitle is the value of the
next match at a *different* allowlisted name — the name used for the title is
never reused, so a record with two `username` fields yields one subtitle
candidate, not two — rendered `name: value`. A record matching no allowlisted
name yields `record_type` as its title and no subtitle, exactly today's
behaviour.

A denylist was considered first and rejected. It ships a title for every
field name nobody thought to exclude, so a `custom` record whose owner named
a field `recovery_code`, or any name a future `vault-format.md` §6.3.1 gains,
would leak by default. Every other gate in this repository default-denies:
`diagnosticDetail` degrades unconformed types, `SecretFreeThrowable` denies
what it does not know, the payload-hygiene guard treats an unrecognised type
as a failure. A denylist here would be the only gate that fails open.

Consequences of the allowlist, stated so a reviewer can check them:

- `password`, `key_secret`, `private_key`, `passphrase` and `totp_seed` are
  excluded **by not being listed**, not by being named.
- `notes` and `body` are also excluded. They are freeform and can hold
  anything.
- A `bstr` field is never eligible, so binary content cannot be stringified
  into a row.
- Values are truncated to 120 characters **in Rust**, so an oversized field
  never reaches the webview at all.

Two further decisions:

**No `Sensitive` wrapper on the derived `String`.** It is destined for
`serde_json` and the webview one line later, so wrapping and unwrapping buys
nothing. This is recorded explicitly rather than left for a reviewer to
wonder whether the memory-hygiene discipline was overlooked; it is the same
reasoning `RevealedFieldDto` already relies on.

**The exposure delta is duration, not class.** `revealField` already ships
field plaintext to the webview, so no new category of data crosses the
boundary. What is new is that a revealed field re-masks after
`REVEAL_AUTO_HIDE_MS` whereas a title stays on screen as long as the list
does. The invariant comment at [`reveal.rs:19-20`](../../../desktop/src-tauri/src/reveal.rs) is amended to say
`project_record` now calls `expose_text` **only** through `record_title`, and
only for allowlisted names; the same statement is repeated at the top of the
new module.

The derivation is pure and takes `&Record`, so it unit-tests without a Tauri
runtime, matching `reveal.rs`'s existing discipline.

## Interaction

Most behaviour falls out of the projection unchanged.

**Escape needs no change at all.** [`shouldPopOnEscape`](../../../desktop/src/lib/browse.ts) already pops only at
`records` / `fields`, never at a form level, never when a dialog or a focused
form control owns the key. Under the projection, popping at `fields` clears
the detail pane and popping at `records` deselects the block — exactly the
right three-pane behaviour. The pure guard and its unit tests carry over
untouched.

**Locking clears all three panes for free**, because every pane is a
projection of `browseNav` and `resetBrowse()` already resets it.

**`FieldViewer` is keyed on the record UUID** (`{#key record.uuidHex}`).
Without the key, Svelte reuses the component instance across a selection
change and per-field reveal state would survive from one record onto the
next. One line, with a security consequence, so it gets its own test.

**Empty states.** Middle pane with no block selected reads *"Select a
block"*; right pane with no record selected reads *"Select a record"*; a
block with no records keeps `RecordList`'s existing empty copy and its "New
record" action.

### The hazard this layout creates

There is no dirty tracking anywhere in the frontend today —
`grep -rln 'dirty|unsaved'` over `desktop/src` matches only `browse.ts`'s
*comment* explaining why Escape refuses to pop at form levels. That is sound
today because the editor is a full-screen level you can only leave through
Save or Cancel. Three panes breaks it: the record list sits beside the open
editor, and one click on another row would silently discard the edit. **The
current design's safety came from the layout, and this layout removes it.**

**Resolution for this slice: freeze the list during edit.** While
`nav.level` is `editRecord` or `newRecord`, the middle pane's rows are
non-interactive and visibly dimmed. You leave the editor through Save or
Cancel, exactly as today.

This *preserves* the existing invariant rather than swapping it for a new
mechanism, needs no dirty-tracking state, and is a few lines. It reads
slightly modal, which is honest — the app does not autosave.

## Layout mechanics

Widths are stored as **fractions of the container**, not pixels:

```css
/* theme.css */
--pane-sidebar-w: 18%;
--pane-list-w: 26%;
```

```css
/* PaneShell */
grid-template-columns:
  minmax(180px, var(--pane-sidebar-w))
  minmax(260px, var(--pane-list-w))
  minmax(320px, 1fr);
```

The `theme.css` values are the **defaults**. A persisted fraction is applied
as an inline `style="--pane-sidebar-w: …%"` on the `PaneShell` root, which
overrides the `:root` default by normal cascade order; a splitter drag writes
the same inline value and then persists it. JS therefore touches the DOM only
on drag, never on window resize.

CSS handles window-resize scaling on its own — widen the window and all three
panes grow proportionally, with no JS involved. Persisting the fraction
rather than a pixel count also keeps the geometry meaningful across
differently-sized displays.

**Minimums are absolute pixels, and only minimums exist.** Legibility is an
absolute property: a 180px sidebar is equally cramped on a 1440p and a 6K
panel, so a percentage floor would be wrong in one direction or the other.
There is deliberately **no maximum token**. A splitter's drag range ends only
where the *other* panes reach their floors, so the sidebar can be dragged out
to `container − 260 − 320` if that is what the user wants. The bound is
derived from the other panes rather than declared as an arbitrary cap.

Tauri's `minWidth` is set to the sum of the three floors, which guarantees
the floors are always simultaneously satisfiable.

Two drag handles sit between the columns, each `role="separator"
aria-orientation="vertical"` and arrow-key adjustable, matching the aria
discipline already present in `BlockCard`.

### Persistence introduces a new storage surface

There is currently **zero** `localStorage` use in the frontend. Pane widths
will be the first, under `secretary.panes.*`, and the convention that comes
with them is explicit:

> **UI geometry only. Never vault data, never anything derived from a
> decrypted record.**

Fractions are clamped on read, so a corrupt or hand-edited value cannot wedge
the layout. Widths deliberately do **not** go into vault settings: that would
write to the vault on every drag and would sync per-device window geometry
between machines.

## Testing

New:

- `desktop/tests/panes.test.ts` — the projection table, one assertion per
  union arm. The highest-value test in the slice: the table *is* the design,
  executable.
- `desktop/tests/paneWidths.test.ts` — clamp-on-read, round-trip, corrupt
  value falls back to default.
- `desktop/tests/PaneShell.test.ts` — rows non-interactive during
  `editRecord` / `newRecord`; `FieldViewer` remounts on record change so
  reveal state cannot carry across.
- `record_title.rs` unit tests — one case per allowlisted name, the priority
  order, the `record_type` fallback, `bstr` ineligibility, 120-char
  truncation, and the case that matters most: a record whose only fields are
  `password` / `totp_seed` yields the fallback and never a value.

Existing tests will need updating in the same commit: `RecordList` and
`FieldViewer` lose their back buttons, and several of the ~20 files under
`desktop/tests/` assert on that navigation.

**No new Tauri command is added** — `record_title` is pure Rust called inside
the existing `project_record` — so the `generate_handler!` /
`writeCommands.ts` classification obligation does not apply to this slice.

### Gates before merge

```bash
cd desktop && pnpm test && pnpm svelte-check
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```

## Follow-ups (deliberately out of scope)

- **Dirty guard + confirm dialog**, replacing the frozen-list resolution with
  a proper unsaved-changes prompt. Additive once the shell is proven.
- **Splitting `TrashView` / `ContactsPane`** into list + detail panes.
- **Responsive collapse** for windows narrower than the floor sum, if the
  minimum-width floor ever proves too restrictive.
