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
 *
 * KNOWN GAP (#286): only `=> {` arrows and `function ...()` declarations are
 * recognized as function bodies. Object/class method-shorthand handlers
 * (`async confirmSave() { ... }`) are NOT — two such methods in one object share
 * an enclosing scope, so a gate in a sibling method would mask an ungated write
 * (the #280 bug class). No current desktop handler uses method shorthand (all are
 * flat `async function` / `const x = async () =>`), so layer 3 is sound today; a
 * robust matcher is deferred to #286 because it must disambiguate method-def from
 * arrow params / call-then-block and exclude control-flow keywords without
 * false-positiving legitimately-gated code.
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
