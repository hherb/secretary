# Contributor-facing internal documentation

This directory holds the **internal** documentation written for the people
maintaining Secretary's Rust core: wire-protocol contracts that aren't
otherwise visible from the code, and audit memos that recorded the
methodology and findings of Phase A.7's three internal hardening passes.

It is **not** user-facing documentation — for that, see
[../primer/cryptography/index.md](../primer/cryptography/index.md) (the
plain-language cryptography primer) and
[../hardening-security.md](../hardening-security.md) (the user-facing
hardening guide).

## What's in here

### [`differential-replay-protocol.md`](differential-replay-protocol.md)

The wire protocol the Rust integration test
[`core/tests/differential_replay.rs`](../../../core/tests/differential_replay.rs)
expects from each fuzz target's `py_decode` / `py_encode` pair in
[`core/tests/python/conformance.py`](../../../core/tests/python/conformance.py).
Read this **before** adding a new fuzz target, removing one, or changing the
encode/decode behaviour of an existing target. Some of the contract is
machine-checked by `differential_replay.rs`; the rest is convention, easy to
break silently if you don't know it's there.

### [`side-channel-audit-internal.md`](side-channel-audit-internal.md)

Phase A.7's internal pass over constant-time-sensitive call sites in the
Rust core. Walks every CT-sensitive comparison flagged by
[`docs/threat-model.md`](../../threat-model.md) §3.2 / §3.3, identifies the
underlying upstream primitive, and documents what discipline that primitive
provides. **Read the relevant section before changing any signature
verification, AEAD tag check, KEM ciphertext compare, or fingerprint
comparison** — the memo records which guarantees are upstream-provided
versus which are defensive at the call site, and a regression in either
direction is hard to spot from the diff alone.

### [`memory-hygiene-audit-internal.md`](memory-hygiene-audit-internal.md)

Phase A.7's internal pass over zeroize discipline in the Rust core. Walks
every type that wraps secret bytes, verifies its zeroize-on-drop wrapper
discipline, and enumerates the stack-residue patterns where a secret value
could linger in a named-but-unzeroized stack slot. **Read the relevant
section before adding a new secret-bearing field, widening an existing
secret's lifetime, or changing the drop ordering of a composite type
holding multiple secrets.** The "Resolved" section at the bottom is
load-bearing: it records which originally-deferred items have since been
fixed (most recently `RecordFieldValue::{Text, Bytes}` → `SecretString` /
`SecretBytes` and the `MlDsa65Secret` / `MlKem768Secret` newtype-zeroize
follow-up).

## Relationship to the external review

These three memos are the **principal handoff package** for the planned
external paid review of the Rust core. The cryptographic-design and
threat-model documents in [`docs/`](../../) are normative specs (what the
code must implement); these memos are the audit trail (what the code
actually does, and where the discipline holds vs. depends on an upstream
crate's documented behaviour). An external reviewer with FIPS 203 / FIPS
204 implementer experience should read the threat model first, then these
three memos, then the corresponding source files.

The external review is a separate, paid, time-bound engagement and is out
of scope for any in-session pass. See
[`secretary_next_session.md`](../../../secretary_next_session.md) → "External
(paid, time-bound)" for the current status.

## When updating these memos

Each memo's introduction states its **scope** and **methodology**.
Preserve both when extending: a memo that grows to mix ad-hoc additions
with the original audit becomes hard to verify against. New findings that
don't fit an existing memo's scope go into a new memo with its own
methodology statement, not glued onto the side of one that's already
shipped.

If a memo cites a specific function name, file, or constant, the
[`core/tests/python/spec_test_name_freshness.py`](../../../core/tests/python/spec_test_name_freshness.py)
drift check covers it. Run that script (`uv run` from the repo root) before
shipping a memo update; it will flag any citation that no longer resolves
in `core/`.
