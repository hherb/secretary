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
 * Function bodies recognized: `=> {` arrows, `function ...()` declarations, and
 * object/class method shorthand (`(async )?(get|set )?name(...) {`, #286). The
 * method-shorthand matcher excludes control-flow heads (`if`/`for`/`while`/`switch`/
 * `catch`/`with`) so a write nested in such a block is still attributed to its parent
 * handler (and not false-flagged when the parent already gated), and excludes `) =>`
 * arrows (matched separately). A property/method literally *named* after one of those
 * keywords is the one accepted blind spot — see NON_METHOD_KEYWORDS.
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
  // End tag is `<\/script\b[^>]*>`, not just `</script>`: the HTML tokenizer closes
  // a script on any end tag whose name is `script` regardless of trailing whitespace
  // or (ignored) attributes — `</script >`, `</script\n bar>` all count. Matching the
  // bare form would drop the whole block on such a tag and leave its writes UNSCANNED
  // (a false negative, not over-matching). `\b` keeps `</scripted>` from matching.
  const re = /<script\b[^>]*>([\s\S]*?)<\/script\b[^>]*>/gi;
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

/** First non-whitespace, non-comment char index at or after `from` (or src.length). */
function firstNonTrivia(src: string, from: number): number {
  let i = from;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      i += 1;
      continue;
    }
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
    return i;
  }
  return src.length;
}

/** Keywords that read as `name(...) {` but are NOT method bodies. Treating a
 *  control-flow head as a body would attribute a write inside its block to the
 *  wrong scope and FALSE-POSITIVE legitimately-gated code (gate in the parent
 *  handler, write in a nested `if`/`for`/`switch`/`catch` block, #286). `function`
 *  is here because declarations are matched separately by `fnRe`. A handler
 *  literally named after one of these (valid as a property name, e.g. `{ for() {} }`)
 *  is skipped — an accepted, vanishingly-rare limitation. */
const NON_METHOD_KEYWORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'function']);

/** Enumerate brace-delimited function bodies: declarations, named/anonymous arrows,
 *  and object/class method shorthand. */
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

  // Object/class method shorthand: `(async )?(get|set )?name(params) {`. The
  // lookbehind rejects member access / call chains (`.name(`), so a method *call* is
  // never mistaken for a *definition*. NON_METHOD_KEYWORDS excludes control-flow heads;
  // a `) =>` after the param list means an arrow (already found above), not a method.
  // The body `{` must follow the param list (modulo a `:` return-type annotation) before
  // any `;`, so a plain call `name(args);` — which ends in `;` — is correctly not a body.
  const methodRe = /(?<![.\w$])(?:async\s+)?(?:(?:get|set)\s+)?([A-Za-z_$][\w$]*)\s*\(/g;
  while ((m = methodRe.exec(src)) !== null) {
    const name = m[1];
    if (NON_METHOD_KEYWORDS.has(name)) continue;
    const parenOpen = src.indexOf('(', m.index);
    if (parenOpen < 0) continue;
    const parenClose = matchBracket(src, parenOpen, '(', ')');
    const after = firstNonTrivia(src, parenClose);
    if (src[after] === '=' && src[after + 1] === '>') continue; // arrow, not a method
    const open = nextBodyBrace(src, parenClose);
    if (open < 0) continue;
    bodies.push({ name, start: open, end: matchBrace(src, open) });
  }

  // A method shorthand whose name coincides with a `function NAME(` declaration is
  // matched by both loops and yields the same body `{` — dedupe so each body is
  // attributed once. Keep the first (arrow/declaration) occurrence; the names agree.
  const seen = new Set<number>();
  return bodies.filter((b) => (seen.has(b.start) ? false : (seen.add(b.start), true)));
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
