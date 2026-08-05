#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fail-closed guard: no `core` error variant may interpolate a runtime String.

WHY THIS EXISTS (#474)
----------------------
`RecordError::DuplicateKey` formatted a decrypted CBOR field name into its
message. That string reached iOS as `VaultAccessError.corruptVault` and Android
as `VaultBrowseError.SaveCryptoFailure`, which is why both platforms redacted
those arms WHOLESALE — losing the detail for every corruption diagnostic, not
just the leaking one.

The payload types are now data-free by construction. This guard keeps them that
way: a new variant carrying a runtime `String` into its `#[error]` message fails
CI in the Rust author's own pull request, rather than silently degrading a
platform two layers away. That drift — a Rust edit with no platform diff and no
failing test anywhere — is exactly how the original leak shipped.

THE RULE
--------
For every `#[error("...")]` attribute under `core/src/`, resolve the field types
of the variant it is attached to. If the message (or a trailing format argument)
interpolates a field whose declared type is not provably data-free, fail —
unless the attribute's exact trimmed source line is allowlisted.

DEFAULT-DENY: an unrecognised type name is a FAILURE, not a pass. A new payload
type cannot slip through by being unfamiliar to this matcher.

LIMITS (stated, not hidden)
---------------------------
- It sees DECLARATIONS, not construction sites. A variant whose payload is
  `&'static str` is provably safe; a variant allowlisted because "its producers
  all pass literals" is a point-in-time claim this guard cannot verify. Those
  entries say so in the allowlist.
- It covers `core/src/**` only. The FFI bridge builds its own detail strings
  (`ffi/secretary-ffi-bridge/**`) and is NOT scanned — see issue #478.
- Rust is parsed by pattern, not by a real parser. The shapes in this codebase
  are regular (thiserror derives); an exotic macro-generated error enum would
  be invisible. `--self-test` pins the shapes that do occur.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "core" / "src"
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "error-payload-hygiene-allowlist.txt"

# Types whose every value is a compile-time constant or a pure number, and so
# cannot carry runtime content. Everything else denies.
DATA_FREE_TYPES: frozenset[str] = frozenset(
    {
        "&'static str",
        "bool",
        "char",
        "usize",
        "isize",
        "u8", "u16", "u32", "u64", "u128",
        "i8", "i16", "i32", "i64", "i128",
        # The #474 classification type: a fieldless kind plus a byte offset.
        "CborFault",
        "crate::cbor::CborFault",
    }
)

# `[u8; 16]`, `[u8; RECORD_UUID_LEN]` — fixed-size numeric arrays.
ARRAY_RE = re.compile(r"^\[[ui](?:8|16|32|64|128|size);[^\]]+\]$")
# `Option<T>` is data-free exactly when `T` is.
OPTION_RE = re.compile(r"^Option<(.+)>$")


def is_data_free(ty: str) -> bool:
    """True when a value of `ty` provably cannot carry runtime content."""
    ty = " ".join(ty.split())
    if ty in DATA_FREE_TYPES:
        return True
    if ARRAY_RE.match(ty.replace(" ", "")):
        return True
    inner = OPTION_RE.match(ty)
    if inner:
        return is_data_free(inner.group(1))
    return False


def strip_comments(src: str) -> str:
    """Blank out `//` and `/* */` comments, preserving line structure.

    Replaces comment bytes with spaces rather than deleting them so that line
    numbers and column offsets stay exact. String literals are respected, so a
    `//` inside `"..."` is not treated as a comment.
    """
    out: list[str] = []
    i, n = 0, len(src)
    in_line_comment = in_block_comment = in_string = False
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(ch)
            else:
                out.append(" ")
            i += 1
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        elif in_string:
            if ch == "\\":
                # A backslash escape consumes 2 source characters (`\` plus
                # whatever follows). Emitting two spaces is right for an
                # ordinary escape like `\"`, but Rust also allows a bare
                # `\` + newline as a string line-continuation. Blanking
                # THAT newline to a space would silently drop it from the
                # line count, desynchronizing every subsequent line number
                # (and hence every subsequent Finding.source_line) for the
                # rest of the file from a single continued string upstream.
                out.append("\n" if nxt == "\n" else " ")
                out.append(" ")
                i += 2
                continue
            if ch == '"':
                in_string = False
            out.append(ch)
            i += 1
        elif ch == "/" and nxt == "/":
            in_line_comment = True
            out.append("  ")
            i += 2
        elif ch == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    source_line: str
    variant: str
    field: str
    field_type: str


ERROR_ATTR_RE = re.compile(r"#\[error\(", re.MULTILINE)
# `{name}` / `{name:?}` / `{0}` — but not `{{` (an escaped brace).
PLACEHOLDER_RE = re.compile(r"(?<!\{)\{([A-Za-z_][A-Za-z0-9_]*|\d+)?[^{}]*\}")
# `.index` in a trailing format argument, e.g. `, .index + 1)`.
ARG_FIELD_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)")
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s*(\{|\(|,|$)")


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


def parse_fields(body: str) -> dict[str, str]:
    """Map field name -> declared type for a variant body.

    Handles both struct variants (`{ field: &'static str, index: usize }`) and
    tuple variants (`(String)` -> `{"0": "String"}`).
    """
    body = body.strip()
    fields: dict[str, str] = {}
    if body.startswith("{"):
        inner = body[1 : body.rindex("}")] if "}" in body else body[1:]
        for part in split_top_level(inner):
            if ":" not in part:
                continue
            name, ty = part.split(":", 1)
            name = name.strip()
            if name.startswith("///") or not name:
                continue
            fields[name] = " ".join(ty.split())
    elif body.startswith("("):
        inner = body[1 : body.rindex(")")] if ")" in body else body[1:]
        for idx, part in enumerate(split_top_level(inner)):
            if part.strip():
                fields[str(idx)] = " ".join(part.split())
    return fields


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not nested inside <>, (), [] or {}."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def scan_source(path_label: str, raw: str) -> list[Finding]:
    """Find every `#[error]` variant that interpolates a non-data-free field."""
    src = strip_comments(raw)
    raw_lines = raw.splitlines()
    findings: list[Finding] = []

    for m in ERROR_ATTR_RE.finditer(src):
        attr_text, after = balanced_slice(src, m.end() - 1)
        attr_line_no = src.count("\n", 0, m.start()) + 1

        # Every placeholder name in the format string, plus every `.field`
        # referenced by a trailing format argument (the mnemonic.rs shape).
        names: set[str] = set()
        positional = 0
        for ph in PLACEHOLDER_RE.finditer(attr_text):
            token = ph.group(1)
            if token is None or token == "":
                names.add(f"__positional_{positional}")
                positional += 1
            else:
                names.add(token)
        arg_split = attr_text.find(",")
        if arg_split != -1:
            for am in ARG_FIELD_RE.finditer(attr_text[arg_split:]):
                names.add(am.group(1))
        if not names:
            continue

        # The variant declaration follows the attribute (possibly after `]`
        # and further doc lines, which strip_comments has already blanked).
        tail = src[after:]
        tail = tail[tail.find("]") + 1 :] if tail.lstrip().startswith("]") else tail
        vm = None
        for line in tail.splitlines():
            if line.strip():
                vm = VARIANT_RE.match(line)
                break
        if not vm:
            continue
        variant = vm.group(1)

        rest = tail[tail.find(variant) + len(variant) :].lstrip()
        if rest.startswith("{"):
            body, _ = balanced_braces(rest)
        elif rest.startswith("("):
            body, _ = balanced_slice(rest, 0)
        else:
            body = ""
        fields = parse_fields(body)

        # Positional `{}` placeholders bind to fields in declaration order.
        ordered = list(fields.items())
        for name in sorted(names):
            if name.startswith("__positional_"):
                idx = int(name.rsplit("_", 1)[1])
                if idx < len(ordered):
                    fname, ftype = ordered[idx]
                else:
                    continue
            elif name in fields:
                fname, ftype = name, fields[name]
            elif name.isdigit() and name in fields:
                fname, ftype = name, fields[name]
            else:
                continue
            if not is_data_free(ftype):
                findings.append(
                    Finding(
                        path=path_label,
                        line=attr_line_no,
                        source_line=raw_lines[attr_line_no - 1].strip(),
                        variant=variant,
                        field=fname,
                        field_type=ftype,
                    )
                )
    return findings


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


# This guard has exactly one rule. The column exists so the file format is
# byte-identical to the two shell guards' allowlists, which lets
# `scripts/lib/hygiene-allowlist.sh::allowlisted` parse this file unchanged —
# which is what the parity test in `core/tests/` actually exercises.
RULE = "E1"


def load_allowlist(path: Path) -> set[str]:
    """Parse the allowlist into a set of `path\\trule\\texact trimmed line` keys.

    Format, one per line, TAB-separated — IDENTICAL to the two shell guards'
    allowlists so that `scripts/lib/hygiene-allowlist.sh::allowlisted` can parse
    this same file:

        <repo-relative-path><TAB><rule><TAB><exact trimmed source line><TAB><reason>

    Matching is on the EXACT trimmed source line, never a substring: a
    substring entry would exempt every future line in the same file that
    happens to contain it, which was demonstrably exploitable on the two
    log-hygiene guards (#467 / #475).
    """
    entries: set[str] = set()
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        entries.add(f"{parts[0].strip()}\t{parts[1].strip()}\t{parts[2].strip()}")
    return entries


def run_real_scan() -> int:
    allowlist = load_allowlist(ALLOWLIST_PATH)
    violations: list[Finding] = []
    for rs in sorted(SCAN_ROOT.rglob("*.rs")):
        label = str(rs.relative_to(REPO_ROOT))
        for f in scan_source(label, rs.read_text(encoding="utf-8")):
            if f"{f.path}\t{RULE}\t{f.source_line}" in allowlist:
                continue
            violations.append(f)

    if violations:
        print("error-payload hygiene: FAIL\n", file=sys.stderr)
        for v in violations:
            print(
                f"  {v.path}:{v.line}\n"
                f"    variant {v.variant} interpolates `{v.field}: {v.field_type}`\n"
                f"    {v.source_line}",
                file=sys.stderr,
            )
        print(
            f"\n{len(violations)} violation(s). A `core` error message must not "
            "interpolate a runtime String — it reaches both platform UIs and "
            "their logs (#474). Carry a &'static str hint plus an ordinal, or "
            "record a reviewed exception in\n  "
            f"{ALLOWLIST_PATH.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1
    print("error-payload hygiene: OK")
    return 0


POSITIVE_CONTROLS: list[tuple[str, str]] = [
    (
        "P1 struct variant with a String payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate map key: {key}")]
            DuplicateKey { key: String },
        }
        ''',
    ),
    (
        "P2 tuple variant with a String payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR decode error: {0}")]
            CborDecode(String),
        }
        ''',
    ),
    (
        "P3 Vec<u8> payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("bad bytes: {raw:?}")]
            BadBytes { raw: Vec<u8> },
        }
        ''',
    ),
    (
        "P4 unrecognised type denies by default",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("wrapped: {inner}")]
            Wrapped { inner: SomeFutureType },
        }
        ''',
    ),
    (
        "P5 trailing format argument (the mnemonic.rs shape)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("word #{} is unknown", .word)]
            UnknownWord { word: String },
        }
        ''',
    ),
    (
        "P6 multi-line attribute",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(
                "a long message that wraps: {detail}"
            )]
            Wrapped { detail: String },
        }
        ''',
    ),
    (
        "P7 PathBuf payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("no such folder: {path}")]
            Missing { path: PathBuf },
        }
        ''',
    ),
]

NEGATIVE_CONTROLS: list[tuple[str, str]] = [
    (
        "N1 &'static str hint plus an ordinal — the #474 fix shape",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate map key at entry #{} of {field}", .index + 1)]
            DuplicateKey { field: &'static str, index: usize },
        }
        ''',
    ),
    (
        "N2 CborFault payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR decode error: {0}")]
            CborDecode(CborFault),
        }
        ''',
    ),
    (
        "N3 fixed-size byte array",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("block {block_uuid:02x?} failed")]
            Failed { block_uuid: [u8; 16] },
        }
        ''',
    ),
    (
        "N4 message interpolates nothing",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected top-level CBOR map")]
            NotAMap,
        }
        ''',
    ),
    (
        "N5 Option<usize>",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("failed at {offset:?}")]
            At { offset: Option<usize> },
        }
        ''',
    ),
    (
        "N6 the whole violation is inside a line comment",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            // #[error("leaky: {key}")]
            // Leaky { key: String },
            #[error("fine")]
            Fine,
        }
        ''',
    ),
    (
        "N7 the whole violation is inside a block comment",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            /* #[error("leaky: {key}")]
               Leaky { key: String }, */
            #[error("fine")]
            Fine,
        }
        ''',
    ),
    (
        "N8 escaped braces are not placeholders",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {{ }} shape")]
            Shape,
        }
        ''',
    ),
]


def run_self_test() -> int:
    failures: list[str] = []
    for label, src in POSITIVE_CONTROLS:
        if not scan_source("<self-test>", src):
            failures.append(f"POSITIVE control did not fire: {label}")
    for label, src in NEGATIVE_CONTROLS:
        found = scan_source("<self-test>", src)
        if found:
            failures.append(
                f"NEGATIVE control fired: {label} -> "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    if failures:
        print("self-test: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"self-test: OK ({len(POSITIVE_CONTROLS)} positive / "
        f"{len(NEGATIVE_CONTROLS)} negative)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(run_self_test())
    sys.exit(run_real_scan())
