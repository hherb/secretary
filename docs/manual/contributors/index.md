# Contributor-facing internal documentation

This directory holds the **internal** documentation written for the people
maintaining Secretary's Rust core and its surrounding sub-projects: wire-
protocol contracts that aren't otherwise visible from the code, and audit
memos that record the methodology and findings of the cross-cutting
hardening passes.

It is **not** user-facing documentation — for that, see
[../primer/cryptography/index.md](../primer/cryptography/index.md) (the
plain-language cryptography primer) and
[../hardening-security.md](../hardening-security.md) (the user-facing
hardening guide).

## What's in here

### Wire-protocol contracts

#### [`differential-replay-protocol.md`](differential-replay-protocol.md)

The wire protocol the Rust integration test
[`core/tests/differential_replay.rs`](../../../core/tests/differential_replay.rs)
expects from each fuzz target's `py_decode` / `py_encode` pair in
[`core/tests/python/conformance.py`](../../../core/tests/python/conformance.py).
Read this **before** adding a new fuzz target, removing one, or changing the
encode/decode behaviour of an existing target. Some of the contract is
machine-checked by `differential_replay.rs`; the rest is convention, easy to
break silently if you don't know it's there.

### Audit memos

The four memos below were originally written as Phase A.7's internal
hardening track (the Rust-core audits, 2026-05-02) and have since grown to
cover the FFI boundary (Sub-project B, 2026-05-28) as the secret-handling
surface expanded across the language boundary.

#### [`side-channel-audit-internal.md`](side-channel-audit-internal.md)

Internal pass over constant-time-sensitive call sites in the Rust core
([`core/src/{crypto,identity,unlock,vault}/`](../../../core/src/)). Walks
every CT-sensitive comparison flagged by
[`docs/threat-model.md`](../../threat-model.md) §3.2 / §3.3, identifies the
underlying upstream primitive, and documents what discipline that primitive
provides. **Read the relevant section before changing any signature
verification, AEAD tag check, KEM ciphertext compare, or fingerprint
comparison** — the memo records which guarantees are upstream-provided
versus which are defensive at the call site, and a regression in either
direction is hard to spot from the diff alone.

#### [`memory-hygiene-audit-internal.md`](memory-hygiene-audit-internal.md)

Internal pass over zeroize discipline in the Rust core. Walks every type
that wraps secret bytes, verifies its zeroize-on-drop wrapper discipline,
and enumerates the stack-residue patterns where a secret value could
linger in a named-but-unzeroized stack slot. **Read the relevant section
before adding a new secret-bearing field, widening an existing secret's
lifetime, or changing the drop ordering of a composite type holding
multiple secrets.** The "Resolved" section is load-bearing: it records
which originally-deferred items have since been fixed.

The memo's discipline has been carried forward into the sync orchestration
layer ([`core/src/sync/`](../../../core/src/sync/), Sub-project C) and the
FFI bridge ([`ffi/secretary-ffi-bridge/`](../../../ffi/secretary-ffi-bridge/),
Sub-project B) — both layers were written after the audit landed and
follow the established `bind → wrap → zeroize` pattern at every secret-
material site. New cross-module sites are expected to keep that pattern.

#### [`ffi-secret-handling-internal.md`](ffi-secret-handling-internal.md)

The cross-FFI memory-hygiene companion that the earlier two audits
explicitly deferred (under "Out of scope: cross-FFI memory hygiene
(Sub-project B)"). Walks the six opaque handles exposed across the
FFI (`UnlockedIdentity`, `MnemonicOutput`, `OpenVaultManifest`,
`BlockReadOutput`, `Record`, `FieldHandle`), the `Arc<Mutex<Option<T>>>`
pattern they share, the wipe-cascade discipline, and the
foreign-runtime heap-copy caveat that the bridge cannot close from the
Rust side. **Read this before adding a new bridge-side handle or
accessor that returns secret bytes** — the "Adding a new bridge handle"
checklist at the bottom is the contract the new code must meet.

## A note on line references

Each memo cites specific Rust file paths plus line numbers (e.g.
[`core/src/crypto/aead.rs#L162`](../../../core/src/crypto/aead.rs#L162))
to anchor its claims. Line numbers drift as the code evolves — the
`#L162` anchor remains a valid hyperlink even when the cited symbol has
moved a few lines, and the
[`core/tests/python/spec_test_name_freshness.py`](../../../core/tests/python/spec_test_name_freshness.py)
drift check covers the **symbol-name** citations (function names, type
names, variant names) that are the load-bearing part of any reference.
Run that script (`uv run` from the repo root) before shipping a memo
update; it will flag any citation that no longer resolves in `core/`.

If you find a citation whose line number is so out of date that the
hyperlink no longer lands near the intended symbol, fix the line number
in passing — but treat the symbol-name claim as the source of truth.

## Relationship to the external review

These memos are the **principal handoff package** for the planned
external paid review of the Rust core. The cryptographic-design and
threat-model documents in [`docs/`](../../) are normative specs (what the
code must implement); these memos are the audit trail (what the code
actually does, and where the discipline holds vs. depends on an upstream
crate's documented behaviour). An external reviewer with FIPS 203 / FIPS
204 implementer experience should read the threat model first, then the
two Rust-core memos (side-channel + memory-hygiene), then the
corresponding source files. The FFI memo is a separate add-on for a
reviewer with FFI-boundary expertise; the FFI's *cryptographic* surface
is the core's (re-exposed verbatim), so cryptographic-discipline review
of the bridge is mostly an exercise in re-verifying that the bridge
doesn't break the discipline the core already established.

The external review is a separate, paid, time-bound engagement and is out
of scope for any in-session pass. See
[`secretary_next_session.md`](../../../secretary_next_session.md) and
[`ROADMAP.md`](../../../ROADMAP.md) for the current status of Phase A.7's
external track.

## Where the project is, vs. where the original memos were written

The four audit memos were written in May 2026 against
Sub-project A (Rust core) only. Since then (state as of 2026-07-01;
[`ROADMAP.md`](../../../ROADMAP.md) and the README "Project status"
table carry the authoritative per-slice detail):

- **Sub-project B** (FFI bindings) — complete through B.6 v2 and
  extended well past it. The bridge crate + PyO3 + uniffi (Swift,
  Kotlin) expose unlock / open / read / save / share / trash /
  restore, plus the per-device wrap-slot ops (B.1 format + crypto,
  B.2 FFI projection — `add_device_slot` / `open_with_device_secret`
  / `remove_device_slot`, [ADR 0009](../../adr/0009-per-device-wrap-slot.md)),
  the folder-writing `create_vault_in_folder`, the record-edit
  primitives (`append` / `edit` / `tombstone` / `resurrect`), the
  block-CRUD tier (`create_block` / `rename_block` / `move_record`),
  and the sync surface (`sync_status` / `sync_vault` /
  `sync_commit_decisions`, [#187](https://github.com/hherb/secretary/issues/187)).
  Cross-language conformance KAT (27/27: 26 vectors + a device-secret
  enrol round-trip) replays Rust ↔ Swift ↔ Kotlin parity. See
  [`ROADMAP.md`](../../../ROADMAP.md) → Sub-project B for the per-
  phase summary.
- **Sub-project C** (sync orchestration) — **all four phases ✅
  complete.** C.1 (sync detection), C.1.1a (conflict-copy ingestion),
  C.1.1b (merge layer), C.2 (the headless `secretary-sync` CLI), C.3
  (mobile adapters — the full iOS *and* Android sync stacks), and C.4
  (cross-device convergence conformance, ✅ 2026-06-15 —
  `core/tests/convergence.rs`, mirrored in the stdlib-only
  clean-room `conformance.py`).
- **Sub-project D** (platform UIs) — **far past the walking-skeleton
  phase; the platform surface where most current work lands.** Desktop
  is a single Tauri 2 codebase ([ADR 0007](../../adr/0007-d-row-tauri.md))
  shipped through D.1.15 (unlock, browse, create, edit, delete/trash,
  share/contacts, per-block + per-contact recipient views, revoke,
  sync UI + interactive conflict resolution) plus a block-CRUD UI and
  password re-auth before writes. Mobile stayed native over uniffi
  ([ADR 0008](../../adr/0008-native-mobile-via-uniffi.md)): the **iOS**
  app does Secure-Enclave/Face-ID device unlock (on-device proof ✅ on
  an iPhone 13 Pro Max, [#202](https://github.com/hherb/secretary/issues/202)),
  password/recovery unlock, vault selection, browse-with-reveal, record
  + block CRUD, vault create/import, sync UI, and biometric write
  re-auth; the **Android** app (Jetpack Compose) does password /
  recovery / biometric-Keystore device unlock (on-device proof ✅ on an
  NX809J), browse-with-reveal, record + block CRUD, sync-on-browse, and
  a full cloud-drive working-copy lifecycle over Storage Access
  Framework (instrumented-proven end-to-end, epic
  [#321](https://github.com/hherb/secretary/issues/321)).

The Rust core's *normative* behaviour is unchanged across these
sub-projects (the spec is frozen for v1, see
[`CLAUDE.md`](../../../CLAUDE.md) → "Spec is normative"). The memos'
findings remain valid for the core; the FFI memo extends the
discipline coverage to the bridge layer; sub-project C's sync code
follows the established patterns. **Sub-project D has now matured well
past the walking-skeleton phase, so its platform-UI secret-hygiene
concerns are live rather than hypothetical** — reveal-on-demand with
auto-hide, copy-with-auto-clear, lock-on-background session wipe, and
re-auth-before-write are already implemented across desktop / iOS /
Android, but a consolidated platform-UI hygiene memo (clipboard
lifetime, reveal lifetime, IPC-plaintext handling) covering all three
platforms is the outstanding contributor-doc gap for this layer. Until
it exists, the per-platform discipline is documented in the shipped
UIs and the FFI memo's "Sub-project D platform concerns (carved out)"
section is the closest standing reference.

## When updating these memos

Each memo's introduction states its **scope** and **methodology**.
Preserve both when extending: a memo that grows to mix ad-hoc additions
with the original audit becomes hard to verify against. New findings that
don't fit an existing memo's scope go into a new memo with its own
methodology statement, not glued onto the side of one that's already
shipped.

A practical heuristic for choosing where new findings go:

- **Bug fix in code already covered by a memo** → update the memo's
  affected section in place, marking the date.
- **New code in the existing scope (e.g. a new `core::crypto` primitive)** →
  extend the relevant memo's coverage table; preserve the original
  scope statement.
- **New code in adjacent scope (e.g. a new FFI handle, a new sync
  layer)** → either extend the cross-sub-project FFI memo (if it's an
  FFI handle) or open a new memo with a clear scope statement (if it's
  a new layer that needs its own treatment).

If a memo cites a specific function name, file, or constant, the
[`core/tests/python/spec_test_name_freshness.py`](../../../core/tests/python/spec_test_name_freshness.py)
drift check covers it. Run that script before shipping a memo update.
