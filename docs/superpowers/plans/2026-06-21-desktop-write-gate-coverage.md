# Desktop write-gate coverage test (#280) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "a mutating desktop IPC write shipped without a re-auth gate decision" a failing vitest test, covering both a newly-registered command and a second ungated write inside a handler that already gates another.

**Architecture:** A hand-authored classification registry (`writeCommands.ts`) keyed by the Tauri command string is diffed against the Rust `generate_handler!` list and against `ipc.ts`; a pure source scanner (`writeGateScanner.ts`) walks the Svelte/TS source per-function and flags any gated-write wrapper called without a preceding `authorizeWrite` in the same function body. All test-only and additive — no change to the shipped #278 runtime.

**Tech Stack:** TypeScript, vitest (Vite `?raw` + `import.meta.glob` for reading source as strings), Svelte frontend under `desktop/`.

## Global Constraints

- Scope: `desktop/**` and `docs/**` only. No change to `core/`, any `*.udl`, `ffi/`, `android/`, `ios/`, or the Rust backend logic. (Layer 1 only *reads* `main.rs` as text; it does not modify it.)
- Package manager: **pnpm** (`cd desktop && pnpm test`). Never `npm` (it silently writes a spurious `package-lock.json`).
- New code: pure free functions in focused modules, each well under 500 lines. One concept per file.
- TDD: failing test first, watch it fail, minimal implementation, watch it pass, commit.
- No magic numbers; classification lives in data, not control flow.
- README is **not** touched (no user-facing behaviour change). ROADMAP gets a one-line note.
- After editing any `.svelte` file, run `svelte-check` — but this plan adds no `.svelte` files, so only `pnpm test` + type check apply.

---

### Task 1: Pure source scanner (`findUngatedWrites`)

The crux. A dependency-free module that, given a source file's text and the set of gated-write
wrapper names, returns one entry per ungated call. Brace-matched function bodies + innermost-body
attribution give per-function granularity (the `importContact` bug class).

**Files:**
- Create: `desktop/src/lib/writeGateScanner.ts`
- Test: `desktop/tests/writeGateScanner.test.ts`

**Interfaces:**
- Produces:
  - `interface UngatedWrite { wrapper: string; functionName: string; index: number; }`
  - `function findUngatedWrites(source: string, isSvelte: boolean, gatedWrappers: readonly string[], gate?: string): UngatedWrite[]` (default `gate = 'authorizeWrite'`)
- Consumes: nothing from other tasks.

- [ ] **Step 1: Write the failing tests**

Create `desktop/tests/writeGateScanner.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { findUngatedWrites } from '../src/lib/writeGateScanner';

const GATED = ['saveRecord', 'saveRecordEdit', 'shareBlock', 'importContact', 'tombstoneRecord'];
const scan = (src: string, svelte = false) => findUngatedWrites(src, svelte, GATED);

describe('findUngatedWrites', () => {
  it('passes a gated wrapper preceded by authorizeWrite in the same function', () => {
    const src = `
      async function confirmSave() {
        await authorizeWrite('Confirm saving this entry');
        await saveRecord(uuid, rec);
      }`;
    expect(scan(src)).toEqual([]);
  });

  it('flags an ungated handler even when a SIBLING handler gates another write (importContact class)', () => {
    const src = `
      async function confirmShare() {
        await authorizeWrite('Confirm sharing this block');
        await shareBlock(b, r);
      }
      async function onImport() {
        await importContact(path);
      }`;
    const violations = scan(src);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ wrapper: 'importContact', functionName: 'onImport' });
  });

  it('flags a write when the gate appears AFTER it in the same function', () => {
    const src = `
      async function bad() {
        await saveRecord(uuid, rec);
        await authorizeWrite('too late');
      }`;
    expect(scan(src).map((v) => v.wrapper)).toEqual(['saveRecord']);
  });

  it('detects named arrow-function handlers', () => {
    const src = `const onDelete = async () => { await tombstoneRecord(b, r); };`;
    expect(scan(src).map((v) => v.functionName)).toEqual(['<arrow>']);
  });

  it('discriminates saveRecord from saveRecordEdit (word boundary)', () => {
    // gate names saveRecord; saveRecordEdit is a DIFFERENT gated wrapper with no gate here
    const src = `
      async function edit() {
        await saveRecordEdit(b, r, rec);
      }`;
    expect(scan(src).map((v) => v.wrapper)).toEqual(['saveRecordEdit']);
  });

  it('ignores read-only wrapper calls in an ungated function', () => {
    const src = `async function load() { const x = await listBlocks(); await readBlock(b); }`;
    expect(scan(src)).toEqual([]);
  });

  it('extracts the <script> block from a .svelte file', () => {
    const src = `
      <script lang="ts">
        async function confirmSave() {
          await authorizeWrite('ok');
          await saveRecord(b, r);
        }
      </script>
      <div>markup with the word saveRecord( in text should be ignored</div>`;
    expect(findUngatedWrites(src, true, GATED)).toEqual([]);
  });

  it('does not treat braces inside template-literal strings as block boundaries', () => {
    const src = `
      async function confirmSave() {
        const msg = \`hello \${name} { not a block }\`;
        await authorizeWrite('ok');
        await saveRecord(b, r);
      }`;
    expect(scan(src)).toEqual([]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd desktop && pnpm exec vitest run tests/writeGateScanner.test.ts`
Expected: FAIL — `findUngatedWrites` is not exported / module not found.

- [ ] **Step 3: Implement the scanner**

Create `desktop/src/lib/writeGateScanner.ts`:

```ts
/**
 * Pure, dependency-free static scanner backing the desktop write-gate coverage
 * test (#280). It answers one question per source file: is any *gated* write
 * wrapper invoked without an `authorizeWrite(...)` call preceding it in the same
 * enclosing function body?
 *
 * Granularity is per-function (brace-matched bodies, innermost-containing-body
 * attribution) — a sibling handler that gates a different write must NOT mask an
 * ungated one (the historical `importContact` bug, #280).
 *
 * Limitations (documented, deliberate — over-matching only ever makes the guard
 * STRICTER, never weaker): string/comment-aware brace and paren matching is
 * best-effort; a gated write inside an anonymous closure nested in a handler that
 * already gated an *unrelated* write earlier is attributed to the closure body
 * when that closure is itself `=> { ... }` (so it is still checked), but a write
 * in an expression-bodied arrow shares its parent body. This codebase keeps one
 * write per flat handler, so these edge cases do not arise in practice.
 */

export interface UngatedWrite {
  /** The gated-write wrapper that was called without a preceding gate. */
  wrapper: string;
  /** Name of the enclosing function body, or `<top-level>` if outside any. */
  functionName: string;
  /** Index of the wrapper call within the scanned script text. */
  index: number;
}

interface FunctionBody {
  name: string;
  start: number; // index of the opening `{`
  end: number; // index just past the matching `}`
}

const STRING_DELIMS = new Set(['"', "'", '`']);

/** Index just past a string literal that starts at `i` (handles \\ escapes and
 *  `${...}` interpolation in template literals via mutual recursion with matchBrace). */
function skipString(src: string, i: number): number {
  const quote = src[i];
  i += 1;
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') {
      i += 2;
      continue;
    }
    if (quote === '`' && c === '$' && src[i + 1] === '{') {
      i = matchBrace(src, i + 1);
      continue;
    }
    if (c === quote) return i + 1;
    i += 1;
  }
  return src.length;
}

/** Index just past the bracket matching the one at `openIdx`.
 *  `open`/`close` default to braces; pass `(`/`)` for parens. Skips strings + comments. */
function matchBracket(src: string, openIdx: number, open = '{', close = '}'): number {
  let depth = 0;
  let i = openIdx;
  while (i < src.length) {
    const c = src[i];
    if (c === '/' && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i);
      i = nl < 0 ? src.length : nl + 1;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const e = src.indexOf('*/', i + 2);
      i = e < 0 ? src.length : e + 2;
      continue;
    }
    if (STRING_DELIMS.has(c)) {
      i = skipString(src, i);
      continue;
    }
    if (c === open) depth += 1;
    else if (c === close) {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
    i += 1;
  }
  return src.length;
}

function matchBrace(src: string, openIdx: number): number {
  return matchBracket(src, openIdx, '{', '}');
}

/** Concatenate the contents of every `<script>` block (`.svelte`), or return the
 *  whole source for a plain `.ts` file. Markup outside <script> never contains
 *  executable wrapper calls, so dropping it avoids false matches. */
export function extractScript(source: string, isSvelte: boolean): string {
  if (!isSvelte) return source;
  const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  let out = '';
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) out += `${m[1]}\n`;
  return out;
}

/** Look backward from a `=>` token for a `const|let|var NAME =` binding name. */
function arrowName(src: string, arrowIdx: number): string {
  const before = src.slice(Math.max(0, arrowIdx - 200), arrowIdx);
  const m = before.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*(?:async\s+)?\([^)]*\)\s*(?::[^=]*)?$/);
  return m ? m[1] : '<arrow>';
}

/** First `{` at or after `from`, skipping whitespace, strings, comments and a TS
 *  return-type annotation. Returns -1 if none before a `;` or EOF. */
function nextBodyBrace(src: string, from: number): number {
  let i = from;
  while (i < src.length) {
    const c = src[i];
    if (c === '{') return i;
    if (c === ';') return -1;
    if (c === '/' && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i);
      i = nl < 0 ? src.length : nl + 1;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const e = src.indexOf('*/', i + 2);
      i = e < 0 ? src.length : e + 2;
      continue;
    }
    i += 1;
  }
  return -1;
}

/** Enumerate brace-delimited function bodies (declarations, named/anonymous arrows). */
function findFunctionBodies(src: string): FunctionBody[] {
  const bodies: FunctionBody[] = [];

  const arrowRe = /=>\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = arrowRe.exec(src)) !== null) {
    const open = src.indexOf('{', m.index);
    if (open < 0) continue;
    bodies.push({ name: arrowName(src, m.index), start: open, end: matchBrace(src, open) });
  }

  const fnRe = /\bfunction\b\s*([A-Za-z_$][\w$]*)?\s*\(/g;
  while ((m = fnRe.exec(src)) !== null) {
    const parenOpen = src.indexOf('(', m.index);
    if (parenOpen < 0) continue;
    const parenClose = matchBracket(src, parenOpen, '(', ')');
    const open = nextBodyBrace(src, parenClose);
    if (open < 0) continue;
    bodies.push({ name: m[1] ?? '<function>', start: open, end: matchBrace(src, open) });
  }

  return bodies;
}

/** All start indices of `\bname\s*\(` calls in `src`. */
function callIndices(src: string, name: string): number[] {
  const re = new RegExp(`\\b${name}\\s*\\(`, 'g');
  const out: number[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) out.push(m.index);
  return out;
}

/** Innermost body containing `idx`, or null. */
function enclosingBody(bodies: FunctionBody[], idx: number): FunctionBody | null {
  let best: FunctionBody | null = null;
  for (const b of bodies) {
    if (idx > b.start && idx < b.end) {
      if (best === null || b.start > best.start) best = b;
    }
  }
  return best;
}

export function findUngatedWrites(
  source: string,
  isSvelte: boolean,
  gatedWrappers: readonly string[],
  gate = 'authorizeWrite',
): UngatedWrite[] {
  const src = extractScript(source, isSvelte);
  const bodies = findFunctionBodies(src);
  const gateCalls = callIndices(src, gate);
  const violations: UngatedWrite[] = [];

  for (const wrapper of gatedWrappers) {
    for (const callIdx of callIndices(src, wrapper)) {
      const body = enclosingBody(bodies, callIdx);
      const lo = body ? body.start : -1;
      const gated = gateCalls.some((g) => g > lo && g < callIdx && enclosingBody(bodies, g) === body);
      if (!gated) {
        violations.push({ wrapper, functionName: body ? body.name : '<top-level>', index: callIdx });
      }
    }
  }

  violations.sort((a, b) => a.index - b.index);
  return violations;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd desktop && pnpm exec vitest run tests/writeGateScanner.test.ts`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/writeGateScanner.ts desktop/tests/writeGateScanner.test.ts
git commit -m "test(desktop): pure write-gate source scanner (#280)"
```

---

### Task 2: Command classification registry (`writeCommands.ts`)

The single source of truth: every registered Tauri command classified exactly once, keyed by the
command string. Pure data + three free helpers.

**Files:**
- Create: `desktop/src/lib/writeCommands.ts`
- Test: `desktop/tests/writeCommands.test.ts`

**Interfaces:**
- Produces:
  - `type CommandKind = 'read' | 'write' | 'session'`
  - `type GateDisposition = 'gated' | 'exempt'`
  - `interface CommandClass { kind: CommandKind; gate?: GateDisposition; wrapper?: string; reason?: string; }`
  - `const COMMAND_CLASSIFICATION: Record<string, CommandClass>`
  - `function classifiedCommandNames(): Set<string>`
  - `function gatedWrappers(): string[]`
  - `function exemptWritesMissingReason(): string[]`
- Consumes: nothing.

- [ ] **Step 1: Write the failing tests**

Create `desktop/tests/writeCommands.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  COMMAND_CLASSIFICATION,
  classifiedCommandNames,
  gatedWrappers,
  exemptWritesMissingReason,
} from '../src/lib/writeCommands';

describe('writeCommands registry', () => {
  it('classifies exactly the 34 registered commands', () => {
    expect(classifiedCommandNames().size).toBe(34);
  });

  it('lists the gated write wrappers (14)', () => {
    const w = gatedWrappers();
    expect(w).toContain('saveRecord');
    expect(w).toContain('importContact');
    expect(w).not.toContain('createVault'); // exempt
    expect(w).not.toContain('listBlocks'); // read
    expect(w).toHaveLength(14);
  });

  it('requires every exempt write to record a reason', () => {
    expect(exemptWritesMissingReason()).toEqual([]);
  });

  it('marks every gated/exempt entry as kind write with a wrapper', () => {
    for (const [cmd, c] of Object.entries(COMMAND_CLASSIFICATION)) {
      if (c.gate) {
        expect(c.kind, cmd).toBe('write');
        expect(c.wrapper, cmd).toBeTruthy();
      }
    }
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd desktop && pnpm exec vitest run tests/writeCommands.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the registry**

Create `desktop/src/lib/writeCommands.ts`:

```ts
/**
 * Source of truth for the desktop write-reauth gate-coverage test (#280).
 *
 * Every Tauri command registered in `src-tauri/src/main.rs`'s `generate_handler!`
 * is classified here exactly once, keyed by the command string (the token shared
 * by both the Rust ident and the `ipc.ts` `call<…>('cmd', …)` wrapper). Adding a
 * command in Rust without a matching entry here fails the coverage test — forcing
 * a conscious read / write-gated / write-exempt / session decision.
 *
 * The gate is a presence-assurance UX layer for an unlocked-but-unattended session,
 * NOT a hard trust boundary (#278/#280). `exempt` writes record *why* they need no
 * call-site gate.
 */

export type CommandKind = 'read' | 'write' | 'session';
export type GateDisposition = 'gated' | 'exempt';

export interface CommandClass {
  /** Command category. `gate`/`wrapper`/`reason` apply only when `kind === 'write'`. */
  kind: CommandKind;
  /** Whether a mutating write is gated at its call site or explicitly exempt. */
  gate?: GateDisposition;
  /** The exported `ipc.ts` wrapper function name (writes only). */
  wrapper?: string;
  /** Justification — REQUIRED when `gate === 'exempt'`. */
  reason?: string;
}

export const COMMAND_CLASSIFICATION: Record<string, CommandClass> = {
  // --- writes: gated at the Svelte call site (#278) ---
  set_settings: { kind: 'write', gate: 'gated', wrapper: 'setSettings' },
  create_block: { kind: 'write', gate: 'gated', wrapper: 'createBlock' },
  rename_block: { kind: 'write', gate: 'gated', wrapper: 'renameBlock' },
  save_record: { kind: 'write', gate: 'gated', wrapper: 'saveRecord' },
  save_record_edit: { kind: 'write', gate: 'gated', wrapper: 'saveRecordEdit' },
  move_record: { kind: 'write', gate: 'gated', wrapper: 'moveRecord' },
  tombstone_record: { kind: 'write', gate: 'gated', wrapper: 'tombstoneRecord' },
  resurrect_record: { kind: 'write', gate: 'gated', wrapper: 'resurrectRecord' },
  trash_block: { kind: 'write', gate: 'gated', wrapper: 'trashBlock' },
  restore_block: { kind: 'write', gate: 'gated', wrapper: 'restoreBlock' },
  import_contact: { kind: 'write', gate: 'gated', wrapper: 'importContact' },
  share_block: { kind: 'write', gate: 'gated', wrapper: 'shareBlock' },
  revoke_block_from: { kind: 'write', gate: 'gated', wrapper: 'revokeBlockFrom' },
  delete_contact_card: { kind: 'write', gate: 'gated', wrapper: 'deleteContactCard' },

  // --- writes: exempt, with recorded reason ---
  create_vault: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'createVault',
    reason: 'pre-unlock bootstrap — no unlocked session to protect',
  },
  probe_create_target: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'probeCreateTarget',
    reason: 'pre-unlock probe of a target folder; performs no vault mutation',
  },
  sync_now: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'syncNow',
    reason: 'takes the vault password directly — re-auth is intrinsic',
  },
  sync_commit_decisions: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'syncCommitDecisions',
    reason: 'takes the vault password directly — re-auth is intrinsic',
  },

  // --- session / auth ---
  unlock_with_password: { kind: 'session' },
  lock: { kind: 'session' },
  notify_activity: { kind: 'session' },
  verify_password: { kind: 'session' },

  // --- reads ---
  list_blocks: { kind: 'read' },
  get_manifest: { kind: 'read' },
  get_settings: { kind: 'read' },
  read_block: { kind: 'read' },
  reveal_field: { kind: 'read' },
  reveal_record: { kind: 'read' },
  list_trashed_blocks: { kind: 'read' },
  list_contacts: { kind: 'read' },
  export_contact_card: { kind: 'read' },
  block_recipients: { kind: 'read' },
  list_contact_blocks: { kind: 'read' },
  sync_status: { kind: 'read' },
};

/** Set of every classified command string. */
export function classifiedCommandNames(): Set<string> {
  return new Set(Object.keys(COMMAND_CLASSIFICATION));
}

/** Wrapper names of writes that must be gated at their call site. */
export function gatedWrappers(): string[] {
  return Object.values(COMMAND_CLASSIFICATION)
    .filter((c) => c.gate === 'gated' && c.wrapper)
    .map((c) => c.wrapper as string);
}

/** Command strings of exempt writes that fail to record a reason (should be empty). */
export function exemptWritesMissingReason(): string[] {
  return Object.entries(COMMAND_CLASSIFICATION)
    .filter(([, c]) => c.gate === 'exempt' && !c.reason?.trim())
    .map(([cmd]) => cmd);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd desktop && pnpm exec vitest run tests/writeCommands.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/writeCommands.ts desktop/tests/writeCommands.test.ts
git commit -m "feat(desktop): write-command classification registry (#280)"
```

---

### Task 3: Coverage test — the three guard layers

Ties the registry to reality: backend completeness, ipc.ts consistency, and the live source scan.

**Files:**
- Create: `desktop/tests/writeGateCoverage.test.ts`

**Interfaces:**
- Consumes: `COMMAND_CLASSIFICATION`, `classifiedCommandNames`, `gatedWrappers`,
  `exemptWritesMissingReason` (Task 2); `findUngatedWrites` (Task 1).
- Produces: nothing (terminal test).

- [ ] **Step 1: Write the failing test**

Create `desktop/tests/writeGateCoverage.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import mainRs from '../src-tauri/src/main.rs?raw';
import ipcSrc from '../src/lib/ipc.ts?raw';
import {
  COMMAND_CLASSIFICATION,
  classifiedCommandNames,
  gatedWrappers,
  exemptWritesMissingReason,
} from '../src/lib/writeCommands';
import { findUngatedWrites } from '../src/lib/writeGateScanner';

/** Command idents registered in the Rust `generate_handler![ … ]` block. */
function registeredCommands(rust: string): Set<string> {
  const block = rust.match(/generate_handler!\s*\[([\s\S]*?)\]/);
  if (!block) throw new Error('generate_handler! block not found in main.rs');
  const withoutComments = block[1].replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  return new Set(
    withoutComments
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => s.split('::').pop() as string),
  );
}

// All non-test source under src/, as { path: rawText }, minus the registry/scanner/ipc themselves.
const RAW = {
  ...import.meta.glob('../src/**/*.svelte', { query: '?raw', import: 'default', eager: true }),
  ...import.meta.glob('../src/**/*.ts', { query: '?raw', import: 'default', eager: true }),
} as Record<string, string>;
const EXCLUDE = ['/lib/ipc.ts', '/lib/writeCommands.ts', '/lib/writeGateScanner.ts'];
const SCANNED = Object.entries(RAW).filter(
  ([p]) => !p.endsWith('.test.ts') && !EXCLUDE.some((e) => p.endsWith(e)),
);

describe('write-gate coverage (#280)', () => {
  it('layer 1: every registered Tauri command is classified, and vice versa', () => {
    const registered = registeredCommands(mainRs);
    const classified = classifiedCommandNames();
    const unclassified = [...registered].filter((c) => !classified.has(c));
    const stale = [...classified].filter((c) => !registered.has(c));
    expect({ unclassified, stale }).toEqual({ unclassified: [], stale: [] });
  });

  it('layer 2: every write entry maps to a real ipc.ts wrapper bound to its command', () => {
    const problems: string[] = [];
    for (const [cmd, c] of Object.entries(COMMAND_CLASSIFICATION)) {
      if (c.kind !== 'write' || !c.wrapper) continue;
      const fnRe = new RegExp(`export\\s+async\\s+function\\s+${c.wrapper}\\b`);
      if (!fnRe.test(ipcSrc)) problems.push(`${cmd}: missing wrapper ${c.wrapper}`);
      else if (!new RegExp(`call<[^>]*>\\(\\s*'${cmd}'`).test(ipcSrc)) {
        problems.push(`${cmd}: wrapper ${c.wrapper} not bound to command '${cmd}'`);
      }
    }
    expect(problems).toEqual([]);
  });

  it('layer 3: no gated write wrapper is called without a preceding authorizeWrite', () => {
    const gated = gatedWrappers();
    const violations = SCANNED.flatMap(([path, src]) =>
      findUngatedWrites(src, path.endsWith('.svelte'), gated).map(
        (v) => `${path} :: ${v.functionName} → ${v.wrapper}`,
      ),
    );
    expect(violations).toEqual([]);
  });

  it('layer 3b: every exempt write records a reason', () => {
    expect(exemptWritesMissingReason()).toEqual([]);
  });
});
```

- [ ] **Step 2: Run the test**

Run: `cd desktop && pnpm exec vitest run tests/writeGateCoverage.test.ts`
Expected: PASS (4 tests) against current `main` — the shipped #278 surface is fully gated, the registry matches `main.rs`, and `ipc.ts` exports every named wrapper.

If layer 1 fails with a `stale`/`unclassified` mismatch, the count or a command name in Task 2 is wrong — fix the registry (it is the source of truth) and re-run. If layer 3 reports a violation on current `main`, a real call site is ungated — that is a genuine #280 finding; record it and gate that site rather than weakening the test.

- [ ] **Step 3: Verify the guard actually bites (negative proof — temporary, reverted)**

```bash
# (a) ungated-call detection: remove a gate line, expect layer 3 to fail naming the handler
cd desktop
git stash list >/dev/null  # sanity
# Manually delete the `await authorizeWrite(...)` line in src/components/RecordEditor.svelte,
# then:
pnpm exec vitest run tests/writeGateCoverage.test.ts   # EXPECT: layer 3 FAILS, names RecordEditor
git checkout -- src/components/RecordEditor.svelte      # revert

# (b) new-command detection: add a fake `vault::frobnicate,` line inside generate_handler!
#     in src-tauri/src/main.rs, then:
pnpm exec vitest run tests/writeGateCoverage.test.ts   # EXPECT: layer 1 FAILS (unclassified: ['frobnicate'])
git checkout -- src-tauri/src/main.rs                   # revert
```

Expected: each tampering fails the named layer; both reverts restore green. (This step is manual and leaves no committed artifact — the scanner's own fixtures in Task 1 are the durable regression coverage.)

- [ ] **Step 4: Run the full desktop suite**

Run: `cd desktop && pnpm test`
Expected: all suites green, including the three new files. Then `pnpm exec tsc --noEmit` (or `pnpm run check`) stays clean.

- [ ] **Step 5: Commit**

```bash
git add desktop/tests/writeGateCoverage.test.ts
git commit -m "test(desktop): centralized write-gate coverage guard (#280)"
```

---

### Task 4: ROADMAP note

**Files:**
- Modify: `ROADMAP.md` (the desktop write-reauth / #278 area)

**Interfaces:** none.

- [ ] **Step 1: Add the note**

Find the desktop write-reauth (#278) entry in `ROADMAP.md` and append a one-line note, e.g.:

```
  - Gate coverage is enforced by a centralized vitest guard (#280): every mutating IPC
    command is classified (gated/exempt) and diffed against the Rust `generate_handler!`
    list; a per-function source scan rejects any gated write called without `authorizeWrite`.
```

Match the surrounding bullet style exactly (indentation, tense). Do **not** touch README (no
user-facing behaviour change; README stays brief).

- [ ] **Step 2: Verify scope guardrail**

Run (from worktree root):
```bash
git diff main...HEAD --name-only | grep -vE '^(desktop/|docs/(superpowers/(specs|plans)|handoffs)/|ROADMAP.md|NEXT_SESSION.md)'
```
Expected: EMPTY.

- [ ] **Step 3: Commit**

```bash
git add ROADMAP.md
git commit -m "docs: note centralized write-gate coverage guard in ROADMAP (#280)"
```

---

## Self-Review

**Spec coverage:**
- Registry keyed by command string → Task 2. ✓
- 34-command classification (14 gated / 4 exempt / 4 session / 12 read) → Task 2 data + Task 2 count test. ✓
- Layer 1 backend diff → Task 3 test 1. ✓
- Layer 2 ipc.ts consistency → Task 3 test 2. ✓
- Layer 3 per-function scan catching the `importContact` class → Task 1 scanner + fixture, Task 3 test 3. ✓
- Exempt-needs-reason → Task 2 helper + Task 3 test 3b. ✓
- Pure scanner in its own module, TDD'd with fixtures → Task 1. ✓
- Negative proof manual/documented → Task 3 step 3. ✓
- Scope guardrail → Task 4 step 2. ✓
- ROADMAP note, README untouched → Task 4. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step shows complete code. ✓

**Type consistency:** `findUngatedWrites(source, isSvelte, gatedWrappers, gate?)` signature identical in Task 1 definition, Task 1 tests, and Task 3 consumption. `gatedWrappers()`/`classifiedCommandNames()`/`exemptWritesMissingReason()` names match between Task 2 definition and Task 3 use. `CommandClass` fields (`kind`/`gate`/`wrapper`/`reason`) consistent throughout. ✓

**Note on Task ordering:** Task 1 (scanner) and Task 2 (registry) are independent; Task 3 consumes both. Build 1 → 2 → 3 → 4.
