"""Allowlist parsing for the error-payload hygiene guard (#474, #480, #486).

Moved out of the former single-file `scripts/check-error-payload-hygiene.py`
in #486 (task 3). Format is documented on `load_allowlist` itself; it is
IDENTICAL to the two shell guards' allowlist format so that
`scripts/lib/hygiene-allowlist.sh::allowlisted` can parse this same file.
"""

from __future__ import annotations

from pathlib import Path


def load_allowlist(path: Path) -> set[str]:
    """Parse the allowlist into a set of `path\\trule\\tnormalized attribute
    text` keys.

    Format, one per line, TAB-separated — IDENTICAL to the two shell guards'
    allowlists so that `scripts/lib/hygiene-allowlist.sh::allowlisted` can parse
    this same file:

        <repo-relative-path><TAB><rule><TAB><normalized #[error(...)] text><TAB><reason>

    The third column is the ENTIRE `#[error(...)]` attribute — not just its
    first source line — whitespace-collapsed to one line (`scan_source`'s
    `key_text`). Keying on just the first line would give a multi-line
    attribute (`sync/error.rs:9`) the literal key `#[error(`, which is not
    unique: any other multi-line attribute in the same file collides on it,
    so one reviewed entry would silently also exempt an unreviewed one. That
    is the exact "substring exempts everything" failure the exact-match
    convention exists to prevent, one level up. Matching is on the EXACT
    normalized text, never a substring, for the same reason #467/#475
    established it for the shell guards.
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

