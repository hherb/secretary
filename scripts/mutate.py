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

EXIT CODES: 0 every row matched its declaration; 1 a rendered table with at
least one unsuccessful row; 2 refused to start (an undrained journal from an
earlier run, or a spec that could not be read/parsed); 3 aborted mid-run —
a restore could not be completed or verified (`RestoreFailed`), rendering
whatever was measured before the abort.

Read docs/superpowers/specs/2026-09-11-mutation-harness-design.md first.
Write the spec to the session scratchpad, never into the source tree (#516).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mutation_harness.journal import Journal, RestoreFailed  # noqa: E402
from mutation_harness.report import render_json, render_markdown  # noqa: E402
from mutation_harness.runner import run_mutations  # noqa: E402
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
        restored = Journal(journal_dir).drain()
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
    journal = Journal(journal_dir)
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
    except RestoreFailed as exc:
        # A restore failure aborts the run (fail-closed is right — see
        # journal.py), but the mutations measured before the abort are
        # still real evidence. Render them, RESTORE_FAILED row included,
        # rather than only ever printing a traceback (fix round 2,
        # Finding 4). Exit 3 is distinct from 1 (a rendered table with an
        # unsuccessful row) and 2 (refused to start / bad spec) — this is
        # "started, then had to stop".
        partial = getattr(exc, "partial_results", [])
        print(render_json(partial) if args.json else render_markdown(partial))
        print(f"mutate: ABORTED — {exc}", file=sys.stderr)
        return 3

    print(render_json(results) if args.json else render_markdown(results))
    return 0 if all(r.outcome.is_success for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
