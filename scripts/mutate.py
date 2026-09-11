#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
r"""A verified mutation harness (#644).

WHY THIS EXISTS
---------------
This repo cites mutation results as load-bearing evidence in CLAUDE.md and in
every handoff, and until now nothing checked that the mutation took effect.
Three distinct mechanisms have produced a GREEN that proved nothing: stale
bytecode on a size-preserving edit, a later class-body assignment silently
overriding an earlier splice, and a mutation left applied by a stalled worker.
A fourth mechanism — a gate that never finishes being credited as a catch
because its 124 exit code looks the same as a real one — was found by review
before this harness shipped and is a control (`C12`) rather than a postmortem.

All three original mechanisms were caught by someone finding a result
surprising. That stops working the moment a mutation is expected to be green
by design, where a false green and a true green are indistinguishable by
inspection.

USAGE
-----
    uv run scripts/mutate.py --self-test
    uv run scripts/mutate.py <spec.toml> [--json] [--journal-dir DIR]
    uv run scripts/mutate.py --drain [--journal-dir DIR]

EXIT CODES for a spec run: 0 every row matched its declaration; 1 a
rendered table with at least one unsuccessful row; 2 refused to start (an
undrained or corrupt journal, or a spec that could not be read or parsed —
including a `path` that is not an existing file); 3 aborted mid-run because
a restore could not be completed or verified (`RestoreFailed`) — THE TREE MAY
BE DIRTY, run `--drain`; 4 aborted mid-run by an error of the harness's own
(a probe interpreter missing, a build tool missing, a `__pycache__` that would
not clear), with the tree restored and the traceback on stderr. Both aborts
render whatever was measured before them. `--self-test` exits 0/1 (1 = at
least one check failed); `--drain` exits 0/2 (2 = the journal could not be
opened or fully restored).

For every non-success row the run also prints a DIAGNOSTIC block to stderr —
why liveness failed, or the tail of the gate's output — so the table can stay
five columns and still be actionable.

Read docs/superpowers/specs/2026-09-11-mutation-harness-design.md first.
Write the spec to the session scratchpad, never into the source tree (#516).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_harness.journal import (  # noqa: E402
    CorruptJournal, Journal, RestoreFailed,
)
from mutation_harness.report import (  # noqa: E402
    render_diagnostics, render_json, render_markdown,
)
from mutation_harness.runner import RunAborted, run_mutations  # noqa: E402
from mutation_harness.selftest import run_self_test  # noqa: E402
from mutation_harness.spec import SpecError, parse_spec  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JOURNAL = Path(tempfile.gettempdir()) / "secretary-mutation-journal"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", nargs="?", help="path to a mutation spec (TOML)")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--drain", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--journal-dir", default=str(DEFAULT_JOURNAL))
    args = parser.parse_args(argv)

    journal_dir = Path(args.journal_dir)

    if args.drain:
        try:
            restored = Journal(journal_dir).drain()
        except (CorruptJournal, RestoreFailed, OSError) as exc:
            # Same ruling as the spec-read handler below: a journal that
            # cannot be opened, parsed or restored is a user-facing failure
            # with a remedy (read the message, inspect the backup blobs by
            # hand), not a traceback. `CorruptJournal` says where the blobs
            # are; swallowing it into a stack trace buries that (final
            # whole-branch review, Finding 5).
            print(f"mutate: {exc}", file=sys.stderr)
            return 2
        for path in restored:
            print(f"restored {path}")
        print(f"{len(restored)} file(s) restored")
        return 0

    if args.self_test:
        return run_self_test()

    if not args.spec:
        parser.error("a spec path is required unless --self-test or --drain is given")

    # Refuse to start on an undrained journal. This is the structural fix for
    # a mutation left applied: it can no longer wait to be noticed by a
    # routine `git status`.
    try:
        journal = Journal(journal_dir)
    except (CorruptJournal, OSError) as exc:
        print(f"mutate: {exc}", file=sys.stderr)
        return 2
    if journal.is_dirty():
        print("mutate: REFUSING TO RUN — an earlier run left files mutated:", file=sys.stderr)
        for path in journal.dirty_paths():
            print(f"  {path}", file=sys.stderr)
        print(f"Run: uv run scripts/mutate.py --drain --journal-dir {journal_dir}",
              file=sys.stderr)
        return 2

    try:
        specs = parse_spec(Path(args.spec).read_text(), REPO_ROOT)
    except (SpecError, OSError) as exc:
        # OSError alongside SpecError: `Path.read_text()` above raises it
        # (FileNotFoundError / PermissionError / ...) for a bad spec PATH,
        # before `parse_spec` ever runs — a missing or unreadable spec is a
        # user-facing usage error, same as a malformed one, not a traceback
        # (fix round 2, Finding 5).
        print(f"mutate: {exc}", file=sys.stderr)
        return 2

    try:
        results = run_mutations(specs, REPO_ROOT, journal_dir)
    except RunAborted as exc:
        # An abort renders the mutations measured before it — they are still
        # real evidence — then says why it stopped. Exit 3 (a restore could
        # not be trusted; the tree may be dirty) and exit 4 (the harness
        # itself failed; the tree was restored) are distinct from 1 (a
        # rendered table with an unsuccessful row) and 2 (refused to start),
        # because each has a different remedy. The traceback is printed for
        # a harness error, where it is the diagnostic; a restore failure's
        # message already names the path and both hashes.
        partial = list(exc.partial_results)
        _render(partial, args.json)
        if not exc.restore_failed and exc.__cause__ is not None:
            traceback.print_exception(exc.__cause__, file=sys.stderr)
        print(f"mutate: ABORTED — {exc}", file=sys.stderr)
        return 3 if exc.restore_failed else 4

    _render(results, args.json)
    return 0 if all(r.outcome.is_success for r in results) else 1


def _render(results, as_json: bool) -> None:
    """The table on stdout; the per-row diagnostics for every non-success
    row on stderr, so the pasted evidence stays five columns."""
    print(render_json(results) if as_json else render_markdown(results))
    diagnostics = render_diagnostics(results)
    if diagnostics:
        print(diagnostics, file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
