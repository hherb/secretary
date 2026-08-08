from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# ONE lexical pass. Every view below is derived from it.
# ---------------------------------------------------------------------------
#
# Rounds 1-4 grew a family of hand-rolled scanners, each patched for the shape
# that had just defeated it. Round 5's review broke four of them at once, and
# every break was the same bug in a different costume: the scanner did not
# actually know where Rust literals begin and end.
#
#   - `r#"a" const ZZ: usize = 1; "b"#` -- a raw string with an odd number of
#     internal quotes re-exposed its own contents as code, so an author could
#     self-authorise a placeholder from inside a message again (the CRITICAL
#     this branch supposedly closed in round 4).
#   - `let c = '}';` inside a `fn` popped the function's own brace, promoting
#     every following declaration in that body to "module scope".
#   - `fn q() -> char { '"' }` desynced the string scanner across the next
#     `use` statement, which RESTORED a withdrawn credit (see
#     `foreign_use_names` for why that direction is the dangerous one).
#
# So: classify every byte ONCE, correctly, and derive the views from that.
# Anything a future round needs is a new view over the same classification,
# never a fifth bespoke scanner.

KIND_COMMENT = "#"
KIND_DELIM = "d"  # a literal's delimiter bytes (quotes, `r##` prefix, ...)
KIND_LITERAL = "s"  # a literal's CONTENT bytes

# `r"`, `r#"`, `r##"`, and the byte-string forms `br"`, `br#"`, ...
RAW_STRING_START_RE = re.compile(r"(?:b?r)(?P<hashes>#*)\"")
# `'x'`, `'\n'`, `'\''`, `'\\'`, `'\u{1F600}'`, and the byte forms `b'x'`.
# Deliberately NOT matched: `'static` / `'a` / `'outer` -- a `'` that is not
# closed by a matching `'` two-ish characters later is a LIFETIME or a loop
# label, not a char literal. `&'static str` is the shape that makes this
# ambiguity unavoidable, and it is everywhere in this codebase.
CHAR_LITERAL_RE = re.compile(r"b?'(?:\\u\{[0-9a-fA-F_]{1,6}\}|\\.|[^\\'\n])'")


def _ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def lex_spans(src: str) -> list[tuple[int, int, str]]:
    r"""Classify `src` into ordered, non-overlapping, non-CODE spans.

    Returns `(start, end, kind)` for every comment and every string / char
    literal, in source order; anything not covered is code. Handles:

    - line comments, and block comments WITH NESTING (Rust's `/* /* */ */`
      nests, unlike C's -- an inner `/*` that a non-nesting scanner ignores
      makes the outer comment end early);
    - ordinary and byte strings with escapes, including the `\` + newline
      line continuation;
    - RAW strings with a variable `#` run (`r"..."`, `r#"..."#`, `r##"..."##`,
      `br#"..."#`), where `"` inside the body is an ordinary character;
    - char and byte-char literals, including `'"'`, `'{'`, `'}'`, `'\''`,
      `'\\'`;
    - the lifetime-vs-char ambiguity (`&'static str` is code, not a literal).

    Unterminated constructs run to end-of-input, which is the conservative
    reading: the tail is classified as literal/comment rather than code, so
    discovery loses credits (a finding) rather than gaining them.
    """
    spans: list[tuple[int, int, str]] = []
    n = len(src)
    i = 0
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            end = src.find("\n", i)
            end = n if end == -1 else end
            spans.append((i, end, KIND_COMMENT))
            i = end
            continue

        if ch == "/" and nxt == "*":
            depth, j = 0, i
            while j < n:
                if src[j] == "/" and j + 1 < n and src[j + 1] == "*":
                    depth += 1
                    j += 2
                    continue
                if src[j] == "*" and j + 1 < n and src[j + 1] == "/":
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                    continue
                j += 1
            j = min(j, n)
            spans.append((i, j, KIND_COMMENT))
            i = j
            continue

        # `r` / `b` / `br` are literal prefixes only when they are not the
        # tail of a longer identifier (`membr"` is not a thing in valid Rust,
        # but refusing to guess costs nothing).
        if ch in "rb" and (i == 0 or not _ident_char(src[i - 1])):
            m = RAW_STRING_START_RE.match(src, i)
            if m:
                closer = '"' + m.group("hashes")
                body = m.end()
                j = src.find(closer, body)
                if j == -1:
                    spans.append((i, body, KIND_DELIM))
                    spans.append((body, n, KIND_LITERAL))
                    i = n
                    continue
                spans.append((i, body, KIND_DELIM))
                spans.append((body, j, KIND_LITERAL))
                spans.append((j, j + len(closer), KIND_DELIM))
                i = j + len(closer)
                continue
            if ch == "b":
                m = CHAR_LITERAL_RE.match(src, i)
                if m:
                    spans.append((i, i + 2, KIND_DELIM))
                    spans.append((i + 2, m.end() - 1, KIND_LITERAL))
                    spans.append((m.end() - 1, m.end(), KIND_DELIM))
                    i = m.end()
                    continue
                if nxt == '"':
                    i, added = _lex_quoted(src, i, 2, spans)
                    if added:
                        continue

        if ch == '"':
            i, added = _lex_quoted(src, i, 1, spans)
            if added:
                continue

        if ch == "'":
            m = CHAR_LITERAL_RE.match(src, i)
            if m:
                spans.append((i, i + 1, KIND_DELIM))
                spans.append((i + 1, m.end() - 1, KIND_LITERAL))
                spans.append((m.end() - 1, m.end(), KIND_DELIM))
                i = m.end()
                continue
            # A lifetime or a loop label. Code.

        i += 1
    return spans


def _lex_quoted(
    src: str, start: int, prefix_len: int, spans: list[tuple[int, int, str]]
) -> tuple[int, bool]:
    r"""Lex an ordinary (or byte) string literal at `src[start]`, appending its
    spans. `\` consumes the next character whatever it is, which is what makes
    both `\"` and the `\` + newline continuation come out right.
    """
    n = len(src)
    body = start + prefix_len
    j = body
    while j < n:
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == '"':
            break
        j += 1
    body_end = min(j, n)
    spans.append((start, body, KIND_DELIM))
    spans.append((body, body_end, KIND_LITERAL))
    if body_end < n:
        spans.append((body_end, body_end + 1, KIND_DELIM))
        return body_end + 1, True
    return n, True


def render_view(src: str, blank_kinds: str) -> str:
    r"""Blank the requested span kinds, preserving LENGTH and LINE COUNT.

    Every blanked byte becomes a space, except a newline which stays a
    newline. Both invariants are structural here rather than a special case
    that has to be remembered -- an earlier round shipped a `\` + newline
    continuation that emitted a space for the newline and silently shifted
    every subsequent reported line number in the file.
    """
    out: list[str] = []
    pos = 0
    for start, end, kind in lex_spans(src):
        if kind not in blank_kinds:
            continue
        out.append(src[pos:start])
        out.append("".join("\n" if c == "\n" else " " for c in src[start:end]))
        pos = end
    out.append(src[pos:])
    return "".join(out)


def strip_comments(src: str) -> str:
    """Blank `//` and `/* */` comments; leave literals verbatim.

    This is the view `scan_source` reads: locating `#[error(` attributes and
    extracting their message text needs the strings INTACT.
    """
    return render_view(src, KIND_COMMENT)


def discovery_view(raw: str) -> str:
    """The DECLARATION-DISCOVERY view: comments AND literal contents blanked,
    delimiters left in place.

    This is a security control. `find_consts`, `find_type_aliases` and
    `ENUM_RE` all answer "what names may this file vouch for?", and text
    inside an `#[error("...")]` MESSAGE declares nothing. Reading declarations
    from a view with string contents intact let an author self-authorise the
    very placeholder under test:

        #[error("leaked field name: {SELF_AUTH} const SELF_AUTH: usize = 1;")]
        SelfAuthorised,

    passed silently, in one file, with no collision and no file-ordering
    dependence. So did the raw-string form `r#"a" const ... "b"#`, which
    survived round 4 because that round blanked strings with a scanner that
    did not know what a raw string was.

    Char literal CONTENTS are blanked for the same reason braces matter:
    `let c = '}';` inside a `fn` body used to pop that function's own brace in
    `non_module_block_spans`, promoting the rest of the body to module scope.

    FAIL-CLOSED ONLY FOR CREDIT-GRANTING PASSES. Blanking can only ever HIDE
    text. For the three registries this view feeds -- local error enums, type
    aliases, consts -- hiding a declaration LOSES a credit, which produces a
    finding, so a lexer bug there degrades toward noise. That argument does
    NOT transfer to a WITHDRAWAL pass: `foreign_use_names` removes credits, so
    hiding a `use` there would RESTORE one. It therefore does not read this
    view at all -- see its docstring. Getting this backwards is exactly the
    kind of unchecked correctness claim this guard exists to eliminate.
    """
    return render_view(raw, KIND_COMMENT + KIND_LITERAL)


def balanced_slice(src: str, start: int) -> tuple[str, int]:
    """Return the `(...)`-balanced text starting at `src[start] == '('`."""
    depth, i, in_string = 0, start, False
    while i < len(src):
        ch = src[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return src[start : i + 1], i + 1
        i += 1
    return src[start:], len(src)


def string_literal_token_ends(raw: str) -> dict[int, int]:
    r"""Map the START offset of every complete STRING literal token in `raw`
    to the offset just past its closing delimiter.

    Built from `lex_spans`, which emits a terminated literal as exactly three
    contiguous spans — opening `KIND_DELIM`, `KIND_LITERAL` content, closing
    `KIND_DELIM`. Three properties are load-bearing for rule E3:

    - An UNTERMINATED literal emits no closing delimiter span, so it is
      absent from this map and every acceptance test against it fails
      closed.
    - A CHAR literal (`'x'`) has the same three-span shape, so the opening
      delimiter's text must END in `"` — that admits `"`, `r#"`, `b"`,
      `br##"` and rejects `'`.
    - The map is keyed on the literal's own start, so "the expression IS a
      single string literal" is decided by an EXACT offset match, not by a
      prefix test. If a lexer desync ever swallowed half a file into one
      "literal", the expression span would not coincide with that token's
      span and the acceptance would fail rather than widen.
    """
    ends: dict[int, int] = {}
    spans = lex_spans(raw)
    for i in range(len(spans) - 2):
        (s0, e0, k0) = spans[i]
        (s1, e1, k1) = spans[i + 1]
        (s2, e2, k2) = spans[i + 2]
        if (k0, k1, k2) != (KIND_DELIM, KIND_LITERAL, KIND_DELIM):
            continue
        if e0 != s1 or e1 != s2:
            continue
        if not raw[s0:e0].endswith('"'):
            continue
        ends[s0] = e2
    return ends


def balanced_braces(src: str) -> tuple[str, int]:
    """Return the `{...}`-balanced text starting at `src[0] == '{'`."""
    depth, i, in_string = 0, 0, False
    while i < len(src):
        ch = src[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[: i + 1], i + 1
        i += 1
    return src, len(src)


#  A synthetic source carrying every lexical shape the guard has ever been
#  broken by, plus the ones it has not: nested block comments, a `\` + newline
#  continuation, raw strings with a `#` run and internal quotes, byte and raw
#  byte strings, char literals holding a quote / a brace / an escaped quote,
#  and a lifetime. Used by `check_view_invariants` — see there.
LEXER_SAMPLE = (
    '#[error("continued \\\n        message: {a}")]\n'
    "/* block\n   comment /* nested */ still comment */ const A: usize = 1;\n"
    "// line comment\n"
    'let s = "quote \\" inside";\n'
    'let r = r#"raw " with quote and /* not a comment */"#;\n'
    'let r2 = r##"raw "# inner"##;\n'
    'let b = b"bytes \\x00";\n'
    'let br = br#"raw " bytes"#;\n'
    "let q = '\"';\n"
    "let ob = '{';\n"
    "let cb = '}';\n"
    "let esc = '\\'';\n"
    "let bs = '\\\\';\n"
    "let bc = b'x';\n"
    "fn f<'a>(x: &'a str) -> &'static str { x }\n"
)
