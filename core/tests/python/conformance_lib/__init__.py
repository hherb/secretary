"""Clean-room conformance verifier for the secretary vault format (§15).

This package is the implementation behind `core/tests/python/conformance.py`.
It is written from `docs/crypto-design.md` and `docs/vault-format.md` ALONE --
it imports no `secretary` code, and its only third-party dependencies are the
generic crypto primitives declared in the entrypoint's PEP 723 header. That
property is the §15 contract for AGPL clean-room re-implementation rights, so
adding a `secretary` import here would not merely be a layering violation: it
would void what this code exists to prove.

Layout
------

  constants      §1.0/§14 wire constants, §1.3 tags, §3 file kinds
  cursor         big-endian parsing primitives + `ParseError`
  primitives     §2.1 crypto primitives (thin wrappers over external libs)
  derivations    §2.2 fingerprints, AAD, hybrid KEM/verify
  canonical      §2.3 canonical-CBOR encoding helpers
  fixtures       where the committed test data lives
  rejection      which exception types are rejection VERDICTS
  tamper         the shared byte-flip mutation helper
  diff_replay    `--diff-replay` mode (a CONTRACT -- see the module docstring)

  wire/          §4.1/§6.1 binary envelope parsers + the golden-vault verify
  codec/         the strict decode/encode ROUND-TRIP pairs behind --diff-replay
  merge/         §11 CRDT merge (records, blocks, clocks, trash)
  sections/      the replay drivers, and the registry `main()` iterates

`wire/` vs `codec/` is the distinction the spec itself draws: `wire/` parses a
file in order to INSPECT it (the golden-vault verification path), `codec/`
parses in order to RE-EMIT it byte-identically (the differential-replay path).
Two modules therefore legitimately share a basename -- `wire/vault_toml.py` and
`codec/vault_toml.py`, `wire/block_file.py` and `codec/block_file.py` -- and
each says in its own docstring which side it is on.

Naming
------

A leading underscore means "internal to this package", not "internal to this
module". These names predate the split (#593), when the whole verifier was one
6849-line module and every one of them was genuinely file-local. Renaming the
~30 that now cross a module boundary would have made a mechanical move into a
large semantic diff, so they were left alone deliberately.

Third-party imports are LAZY, inside the functions that need them; the
package's top-level import graph is stdlib-only. `--diff-replay` is invoked
once per fuzz input under a timeout, so it must not pay to import crypto
libraries it never calls.
"""
