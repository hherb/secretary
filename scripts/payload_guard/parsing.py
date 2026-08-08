"""Low-level Rust-text parsing helpers shared by discovery and the rules.

`skip_attributes` and `split_top_level` sit here rather than in `discovery.py`
or in `rules/e1.py` because each has THREE consumers spanning both of those
modules: `discovery.py`'s `discover_error_struct_declarations`
(`skip_attributes`) and `_use_bound_names` (`split_top_level`), plus
`rules/e1.py`'s `scan_source` (both) and `rules/e2.py`'s
`_bridge_plain_enum_variant_findings` (both) (#486 task 4). Neither
`discovery.py` importing from `rules/e1.py` nor the reverse is acceptable —
`discovery.py` sits BELOW `rules/*` in this package's dependency order — so
the shared code has to live in a module below BOTH. This one does, beside
`lexer.py`.
"""

from __future__ import annotations


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not nested inside <>, (), [] or {}."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
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


def skip_attributes(text: str) -> str:
    """Skip leading whitespace and any number of `#[...]`-attribute spans at
    the front of `text`.

    Without this, an intervening attribute between `#[error(...)]` and the
    variant/struct it decorates defeats the guard entirely: `VARIANT_RE`
    cannot match a line starting with `#`, and the old code only ever looked
    at the FIRST non-blank line after the `#[error(...)]` attribute, so

        #[error("leak: {detail}")]
        #[cfg(all())]
        Leaky { detail: String },

    found no variant at all and silently skipped — proven live for
    `#[cfg(...)]`, `#[allow(...)]`, and `#[doc = "..."]`. Brackets are
    balanced so a multi-line or argument-bearing attribute is consumed as a
    unit, not just cut off at its own first `]`.
    """
    i, n = 0, len(text)
    while True:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i + 1 < n and text[i] == "#" and text[i + 1] == "[":
            depth, j, in_string = 0, i + 1, False
            while j < n:
                ch = text[j]
                if in_string:
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == '"':
                        in_string = False
                elif ch == '"':
                    in_string = True
                elif ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                j += 1
            i = j
            continue
        break
    return text[i:]
