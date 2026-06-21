# Desktop write-gate coverage test (#280) — design

**Date:** 2026-06-21
**Issue:** #280 — *Desktop: centralized gate-coverage test for write re-auth (no ungated mutating IPC)*
**Scope:** `desktop/**` only. Purely additive test + data; **no runtime change** to the shipped #278 write-reauth surface.

## Problem

Write re-auth on desktop (#278) gates mutating vault writes behind `authorizeWrite(reason)`
at **each Svelte call site** ([`desktop/src/lib/writeGuard.ts`](../../../src/lib/writeGuard.ts)).
There is no centralized enforcement: a new mutating IPC wrapper can ship **ungated** if a
contributor forgets the `authorizeWrite` call.

This is not hypothetical. The #278 review caught `importContact` (`ShareDialog.onImport`)
shipping ungated even though the PR claimed coverage. Critically, `ShareDialog` *did* gate a
**different** write (`shareBlock`, in `confirmShare`), so any file-level "does this component
gate anything" check would have **passed** while `importContact` stayed open. The detector must
therefore work at **per-function** granularity, not per-file.

**Goal:** adding a mutating write without a *gate decision* is a failing test, not a silent gap —
covering both classes:
- (a) a brand-new command registered in Rust but never classified in the frontend;
- (b) a second ungated write inside a handler that already gates another write.

## Non-goals

- Not a hard trust boundary. The gate is a presence-assurance UX layer for an
  unlocked-but-unattended session; an attacker with renderer code-exec already holds the
  in-memory plaintext. This issue is about not regressing UX coverage.
- No change to `authorizeWrite`'s signature, the modal UX, or any shipped call site.
- No backend (Rust) enforcement change.

## Approach (chosen)

**Registry + backend-diff + per-call-site source scan — test-only.** Three layers, all robust
string/AST-lite checks over source text, plus one small pure scanner that is itself TDD'd.

### New file: `desktop/src/lib/writeCommands.ts`

Pure data + pure helpers, no I/O. The single source of truth, **keyed by the Tauri command
string** — the one token shared by both the Rust `generate_handler!` registration (ident
`save_record`) and the ipc.ts wrapper (`call<…>('save_record', …)`). Keying on the command
string (not the wrapper name) is what lets layer 1 diff directly against Rust.

```ts
export type CommandKind = 'read' | 'write' | 'session';
export type GateDisposition = 'gated' | 'exempt';

export interface CommandClass {
  kind: CommandKind;
  // present iff kind === 'write':
  gate?: GateDisposition;
  wrapper?: string;   // the exported ipc.ts function name
  reason?: string;    // required iff gate === 'exempt'
}

export const COMMAND_CLASSIFICATION: Record<string, CommandClass> = { /* every registered command */ };
```

Pure helpers (free functions, unit-tested):
- `writeCommands()` → entries with `kind === 'write'`.
- `gatedWrappers()` → wrapper names of `{kind:'write', gate:'gated'}` entries.
- `classifiedCommandNames()` → `Set` of keys (for the backend diff).

### Classification of the 34 registered commands

From [`main.rs:75-110`](../../../src-tauri/src/main.rs) `generate_handler![ … ]`.

**Writes — gated (14)** — each has a live gated call site (#278, verified):
`set_settings` (`setSettings`), `create_block` (`createBlock`), `rename_block` (`renameBlock`),
`save_record` (`saveRecord`), `save_record_edit` (`saveRecordEdit`), `move_record` (`moveRecord`),
`tombstone_record` (`tombstoneRecord`), `resurrect_record` (`resurrectRecord`),
`trash_block` (`trashBlock`), `restore_block` (`restoreBlock`), `import_contact` (`importContact`),
`share_block` (`shareBlock`), `revoke_block_from` (`revokeBlockFrom`),
`delete_contact_card` (`deleteContactCard`).

**Writes — exempt (4)** — each with a recorded `reason`:
- `create_vault` (`createVault`) — *pre-unlock bootstrap; no unlocked session to protect.*
- `probe_create_target` (`probeCreateTarget`) — *pre-unlock probe of a target folder; no vault mutation.*
- `sync_now` (`syncNow`) — *takes the vault password directly; re-auth is intrinsic.*
- `sync_commit_decisions` (`syncCommitDecisions`) — *takes the vault password directly; re-auth is intrinsic.*

> `probe_create_target` is a pre-unlock folder probe. It is classified `write/exempt` (rather than
> `read`) only to keep the create-flow commands grouped with a recorded reason; it performs no vault
> mutation. If a future reader prefers `kind:'read'`, that is an equally valid decision — the test
> only requires *a* decision, not this specific one.

**Session/auth (4):** `unlock_with_password`, `lock`, `notify_activity`, `verify_password`.

**Reads (12):** `list_blocks`, `get_manifest`, `get_settings`, `read_block`, `reveal_field`,
`reveal_record`, `list_trashed_blocks`, `list_contacts`, `export_contact_card`, `block_recipients`,
`list_contact_blocks`, `sync_status`.

Total = 14 + 4 + 4 + 12 = 34. ✓

### New file: `desktop/src/lib/writeGateScanner.ts`

A pure, dependency-free scanner. The crux of layer 3.

```ts
export interface UngatedWrite { wrapper: string; functionName: string; index: number; }

/** Split `source` into top-level function bodies, then for each body that calls one of
 *  `gatedWrappers`, require a `gate(` call textually preceding the first such wrapper call
 *  in the SAME body. Returns one entry per violation. Pure — no I/O. */
export function findUngatedWrites(
  source: string,
  gatedWrappers: readonly string[],
  gate = 'authorizeWrite',
): UngatedWrite[];
```

Algorithm:
1. For `.svelte` input, extract the `<script …>…</script>` block(s); for `.ts`, use the whole file.
2. Enumerate function bodies via brace-matching from each function header:
   `function name(` / `async function name(` / `const name = (… ) =>` / `const name = async (…) =>`.
   Record `functionName` and the matched body span.
3. Within each body, find the first call `wrapper(` for any gated wrapper. If found, require a
   `gate(` occurrence at a lower string index within the same body. Otherwise emit an `UngatedWrite`.
4. Word-boundary matching (`saveRecord` must not match `saveRecordEdit`); ignore matches inside
   string/comment is **not** attempted — over-matching here only ever causes a *stricter* test, and
   the codebase does not embed wrapper-call-looking text in strings. (Documented limitation.)

Brace-matching is sufficient for this codebase's handler style; nested closures fall under the
enclosing named function's body, which is the correct granularity (the gate must precede the write
somewhere in the handler). Edge cases are pinned by fixtures (below).

### Tests

**`desktop/tests/writeGateScanner.test.ts`** (TDD — written first, drives the scanner):
- gated wrapper with a preceding `authorizeWrite` in the same fn → no violation;
- gated wrapper with **no** gate in its fn, while a *sibling* fn gates a different wrapper
  → violation (the `importContact` regression, reproduced synthetically);
- gate appears *after* the write in the same fn → violation (ordering matters);
- arrow-fn handler form and `async function` form both detected;
- `saveRecord` vs `saveRecordEdit` word-boundary discrimination;
- a read-only wrapper call in an ungated fn → no violation (only gated wrappers count).

**`desktop/tests/writeGateCoverage.test.ts`** (the three guard layers):
1. **Backend completeness:** read `src-tauri/src/main.rs`, extract idents inside `generate_handler![ … ]`
   (token after the last `::`, before `,`), assert that set === `classifiedCommandNames()`.
   Asymmetric failure messages name the offending command and the side it is missing from.
2. **ipc.ts consistency:** read `src/lib/ipc.ts`; for each write entry with a `wrapper`, assert
   `export async function <wrapper>` exists and its body contains `call<…>('<command>'`.
3. **Gate coverage:** glob `desktop/src/**/*.{svelte,ts}` minus `lib/ipc.ts`, `lib/writeCommands.ts`,
   `lib/writeGateScanner.ts`, and `tests/**`; run `findUngatedWrites` over each with `gatedWrappers()`;
   assert zero violations (failure lists `file → functionName → wrapper`).
   Also assert every `gate:'exempt'` entry has a non-empty `reason`.

File reads in the coverage test use Node `fs` with paths resolved relative to the repo root
(`new URL(...)` / `import.meta.url`), matching how vitest runs from `desktop/`.

## File inventory

| File | New/changed | Purpose | Approx size |
|---|---|---|---|
| `desktop/src/lib/writeCommands.ts` | new | classification registry + pure helpers | ~120 lines |
| `desktop/src/lib/writeGateScanner.ts` | new | pure `findUngatedWrites` scanner | ~120 lines |
| `desktop/tests/writeGateScanner.test.ts` | new | scanner unit tests (fixtures) | ~140 lines |
| `desktop/tests/writeGateCoverage.test.ts` | new | 3 guard layers over real source | ~120 lines |

All four are well under the 500-line guideline; the scanner and registry are separate modules,
one concept each.

## Testing & acceptance

```bash
cd desktop && pnpm install   # if needed
pnpm test                    # vitest — all green, incl. the 2 new suites
pnpm run check 2>/dev/null || pnpm exec svelte-check   # type/svelte check stays clean
```

- `writeGateScanner.test.ts`: all fixture cases pass (the synthetic `importContact`-class case
  fails *before* the scanner is implemented, passes after — TDD red→green).
- `writeGateCoverage.test.ts`: all three layers green against current `main` (the shipped #278
  surface is fully gated, so layer 3 reports zero violations today).
- **Negative proof (manual, documented in the PR):** temporarily delete one `authorizeWrite`
  line from a handler → layer 3 fails naming that handler; revert. Temporarily add a fake
  `vault::frobnicate` to `generate_handler!` → layer 1 fails; revert.

**Scope guardrail (from worktree root):**
```bash
git diff main...HEAD --name-only | grep -vE '^(desktop/|docs/(superpowers/specs|handoffs)/|NEXT_SESSION.md)'   # EMPTY
```

## Risks / open points

- **Scanner brittleness vs. code style.** Mitigated by: (1) the scanner is pure and fixture-tested;
  (2) over-matching only ever makes the test *stricter* (a false positive is fixed by adding the
  gate or marking exempt, never by weakening the property); (3) the call pattern in this codebase is
  uniform (verified across all 13 current sites).
- **Layer-1 parse of `generate_handler!`** assumes the `module::command,` one-per-line style currently
  in `main.rs`. If that block is ever reflowed, the extractor's line/`::` heuristic must still hold;
  the test reads the whole macro block and splits on `,`, tolerant of whitespace/newlines.
- **`probe_create_target` classification** is a judgement call (write/exempt vs read) — see note above.
  Either is acceptable; the test only enforces that *a* decision exists.
