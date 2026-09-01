#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "cryptography>=42",
#   "pynacl>=1.5",
#   # UPPER BOUND IS LOAD-BEARING (#544). pqcrypto 1.0.0 is a breaking major
#   # bump: it renamed `generate_keypair` to `keygen`, and — the subtle half —
#   # changed `ml_dsa_65.verify` from returning a bool to RAISING on failure,
#   # so a VALID signature returns `None`. `ml_dsa_65_verify` -- now in
#   # `conformance_lib/primitives.py` (#593) -- returns that value directly,
#   # making every ML-DSA-65 check report "rejected" and
#   # taking the whole §15 gate down. Failure direction was fail-closed (valid
#   # rejected, never invalid accepted), but the gate was non-functional on
#   # `main` until this bound was added. Do not relax to a bare `>=` without
#   # migrating the helper AND giving it a tamper-rejection test that passes on
#   # whichever resolution you allow — `ml_dsa_65_verify`'s own docstring
#   # records that an earlier version of this helper reported "no
#   # exception" as success and silently accepted tampered ML-DSA signatures,
#   # which is exactly the shape pqcrypto 1.x's contract invites back. (That
#   # pointer read "conformance.py:705" and was already stale when written:
#   # the +13-line comment you are reading pushed the docstring down, and
#   # the #593 split then moved the symbol into another file entirely. Cite
#   # the symbol, not the line -- and not "below" either.)
#   "pqcrypto>=0.3,<1",
#   "argon2-cffi>=23",
#   "blake3>=0.4",
#   "cbor2>=5",
# ]
# ///
"""secretary cross-language conformance script (§15).

Run with (PEP 723 inline deps; uv resolves them automatically):

    uv run core/tests/python/conformance.py

Or, equivalently with explicit `--with` flags (matches the harness call
style used by `core/tests/differential_replay.rs`):

    uv run \\
        --with cryptography \\
        --with pynacl \\
        --with pqcrypto \\
        --with argon2-cffi \\
        --with blake3 \\
        --with cbor2 \\
        core/tests/python/conformance.py

This file is a THIN ENTRYPOINT. The verifier itself lives in the sibling
`conformance_lib/` package (#593) -- read `conformance_lib/__init__.py` for
the layout. Two things about this split are load-bearing and must not be
undone:

  1. The PEP 723 header above is the clean-room dependency claim. It is the
     SOLE dependency declaration -- there is no `pyproject.toml`, and the
     package declares nothing of its own. Adding one would let the declared
     set drift from what actually gets installed.

  2. `uv run core/tests/python/conformance.py` must keep working verbatim,
     from any working directory. It is named in `CLAUDE.md`, in the
     `clean-room conformance` CI job in `.github/workflows/test.yml`, and in
     `core/tests/differential_replay.rs`, which shells out to it. The import
     of `conformance_lib` resolves because Python puts THIS FILE's directory
     on `sys.path[0]`, which is a property of the interpreter, not of the
     caller's CWD.

The verifier runs the sections declared in
`conformance_lib.sections.registry.SECTIONS`, then `--diff-replay` mode is
the differential-replay contract with the fuzz harness; see
`conformance_lib/diff_replay.py` and
`docs/manual/contributors/differential-replay-protocol.md`.

The whole verifier is written from `docs/crypto-design.md` and
`docs/vault-format.md` alone -- no `import` of any `secretary` code -- which
is the §15 contract for AGPL clean-room re-implementation rights.

Exit codes:

  0  every section passed.
  1  any section failed; one `FAIL: <reason>` line per failed section is
     written to stderr.
  2  a fixture file was missing or malformed; one-line `MISSING: <which>`
     written to stderr.
  3  `--diff-replay` only: the replay harness itself failed (as distinct
     from the input being rejected, which is a verdict and exits 0).
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--diff-replay",
        nargs=2,
        metavar=("TARGET", "INPUT_PATH"),
        help="differential replay mode: decode one input file for one target, emit JSON",
    )
    args, _ = parser.parse_known_args()
    if args.diff_replay:
        # Imported HERE, not at module scope: `--diff-replay` is invoked once
        # per fuzz input under a timeout, and must not pay to import the
        # section modules (and through them the whole verifier) to decode one
        # file. The section registry is only reachable on the full-run path.
        from conformance_lib.diff_replay import run_diff_replay

        target, input_path = args.diff_replay
        return run_diff_replay(target, input_path)

    from conformance_lib.sections import SECTIONS

    failed: list[str] = []
    for index, section in enumerate(SECTIONS):
        if index:
            print()
        print(section.banner)
        ok, lines = section.run()
        for line in lines:
            print(line)
        if not ok:
            failed.append(section.failure)

    print()
    if not failed:
        print("PASS")
        return 0
    for line in failed:
        print(line, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
