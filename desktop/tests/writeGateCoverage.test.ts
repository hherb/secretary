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
  // Non-greedy capture stops at the first `]`. Safe because the handler list holds
  // only `module::ident` paths (no nested `[...]`); if a generic/array literal is
  // ever added inside the macro this must switch to a brace-balanced parse.
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
  ([p]) => !p.endsWith('.test.ts') && !EXCLUDE.some((e) => p.endsWith(e)), // defensive: no .test.ts files live under src/ today, but guard against future ones
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
      const declRe = new RegExp(`export\\s+async\\s+function\\s+${c.wrapper}\\b`);
      const decl = declRe.exec(ipcSrc);
      if (!decl) {
        problems.push(`${cmd}: missing wrapper ${c.wrapper}`);
        continue;
      }
      // Scope the binding check to THIS wrapper's body (declaration → next function
      // declaration) so a wrapper bound to a different command elsewhere in the file
      // cannot satisfy it.
      const rest = ipcSrc.slice(decl.index + decl[0].length);
      const next = rest.search(/\bexport\s+(?:async\s+)?function\b/);
      const body = next === -1 ? rest : rest.slice(0, next);
      // `[^>]*` matches a single-level generic arg; every command wrapper uses a
      // flat return type today. A nested generic (`call<Foo<Bar>>(...)`) would need
      // a balanced-angle match here.
      if (!new RegExp(`call<[^>]*>\\(\\s*'${cmd}'`).test(body)) {
        problems.push(`${cmd}: wrapper ${c.wrapper} not bound to command '${cmd}'`);
      }
    }
    expect(problems).toEqual([]);
  });

  it('layer 3: no gated write wrapper is called without a preceding authorizeWrite', () => {
    // Anti-vacuous guard: if the glob ever resolves to an empty set (bad path or
    // Vite config drift) layer 3 would pass trivially and silently disable the
    // whole check. Assert the scan actually saw the source tree and a known
    // gated-write call site (RecordEditor.svelte calls the gated saveRecord/saveRecordEdit).
    expect(SCANNED.length).toBeGreaterThan(0);
    expect(SCANNED.some(([p]) => p.includes('RecordEditor.svelte'))).toBe(true);

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
