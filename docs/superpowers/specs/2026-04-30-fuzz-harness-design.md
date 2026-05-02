# `core/fuzz/` wire-format fuzz harness — design

**Date:** 2026-04-30
**Scope:** Phase A.7 sub-deliverable (hardening + external-audit prep) of Sub-project A. Delivers item 2 of the five Phase A.7 components named in [secretary_next_session.md §175-208](../../../secretary_next_session.md#L175-L208): a coverage-guided fuzz harness for the wire-format decoders, plus a one-time bug-bash before the external cryptographic review.
**Status:** approved design, awaiting implementation plan.

## Context

Sub-project A is feature-complete for v1 as of PR-C (Phase A.6, 2026-04-29). Five Phase A.7 work items remain before Sub-project B (FFI) can begin: independent crypto review, fuzz harness, side-channel review, memory hygiene audit, and a documentation pass. This document covers only the fuzz harness.

The decoders this harness targets all have the shape `pub fn(&[u8]) -> Result<T, E>` (or `&str` for TOML) and form the wire-format ingest surface for files an attacker can drop into the vault directory. They are:

| Decoder | Source |
|---|---|
| `vault::block::decode_block_file` | [core/src/vault/block.rs:1511](../../../core/src/vault/block.rs#L1511) |
| `vault::manifest::decode_manifest_file` | [core/src/vault/manifest.rs:1515](../../../core/src/vault/manifest.rs#L1515) |
| `unlock::bundle_file::decode` | [core/src/unlock/bundle_file.rs:102](../../../core/src/unlock/bundle_file.rs#L102) |
| `vault::record::Record::decode` | [core/src/vault/record.rs:524](../../../core/src/vault/record.rs#L524) |
| `identity::card::ContactCard::from_canonical_cbor` | [core/src/identity/card.rs:258](../../../core/src/identity/card.rs#L258) |
| `unlock::vault_toml::decode` | [core/src/unlock/vault_toml.rs:141](../../../core/src/unlock/vault_toml.rs#L141) |

Verify-before-decap is a structural property of the design (PR-A), so the decoders parse but do not call into AEAD/KEM/signature primitives. Their immediate transitive surface is `ciborium` for CBOR, the `toml` crate for TOML, plus `blake3` for fingerprinting in some paths.

## Goal

Produce a coverage-guided fuzz harness covering the six decoders above, run a one-time bug-bash before the external cryptographic review, and leave the harness as a durable artifact that auditors can pick up and run.

The harness is the durable deliverable. The bug-bash is a one-time gate for shallow findings; long campaigns are explicitly the external reviewer's domain.

## Targets and oracle shape

Each target is `pub fn(&[u8]) -> Result<T, E>`. All six are crash-checked. Five also have a roundtrip oracle:

| # | Target | Oracle | Encoder for roundtrip |
|---|---|---|---|
| 1 | `block_file` | crash + roundtrip-eq | `encode_block_file` |
| 2 | `manifest_file` | crash + roundtrip-eq | `encode_manifest_file` |
| 3 | `bundle_file` | crash + roundtrip-eq | `bundle_file::encode` |
| 4 | `record` | crash + roundtrip-eq | `record::encode` |
| 5 | `contact_card` | crash + roundtrip-eq | `to_canonical_cbor` |
| 6 | `vault_toml` | **crash only** | — |

**Roundtrip-eq.** For inputs the decoder accepts: `decode(input).ok().map(encode) == Some(input)`. The strict canonical-CBOR posture (per `docs/crypto-design.md` §11.1) means any roundtrip mismatch is by definition a bug — the decoder accepted an input the encoder couldn't have produced, so its grammar is laxer than the spec. This catches the silent-accept class precisely (the bug class that hit the Python ML-DSA-65 verifier, fixed in PR #6 commit `1c90852`).

**Why TOML is crash-only.** The `toml` crate does not preserve whitespace or comment placement across decode→encode, so byte-symmetric roundtrip is not well-defined. A value-equality oracle would still be valuable but is overkill for v1 — crash-only is sufficient to catch parser bugs in the TOML layer.

## Workspace layout and toolchain

```
core/
├── fuzz/                         # cargo-fuzz crate (NOT a workspace member)
│   ├── Cargo.toml                # standalone; not in [workspace.members]
│   ├── rust-toolchain.toml       # path-scoped nightly pin
│   ├── README.md                 # how to run; what each target does
│   ├── .gitignore                # corpus/, artifacts/
│   ├── fuzz_targets/
│   │   ├── block_file.rs
│   │   ├── manifest_file.rs
│   │   ├── bundle_file.rs
│   │   ├── record.rs
│   │   ├── contact_card.rs
│   │   └── vault_toml.rs
│   ├── seeds/                    # committed; small KAT-derived inputs
│   │   ├── block_file/
│   │   ├── manifest_file/
│   │   ├── bundle_file/
│   │   ├── record/
│   │   ├── contact_card/
│   │   └── vault_toml/
│   ├── corpus/                   # GITIGNORED; runtime accumulation
│   └── artifacts/                # GITIGNORED; libFuzzer crash dumps
└── tests/
    └── data/
        ├── fuzz_regressions/     # committed crash repros (durable)
        │   ├── block_file/
        │   ├── manifest_file/
        │   ├── bundle_file/
        │   ├── record/
        │   ├── contact_card/
        │   └── vault_toml/
        └── diff_regressions/     # committed differential disagreements
            └── …                 # one dir per target
```

`core/fuzz/` is intentionally **outside `[workspace.members]`** in the root `Cargo.toml` — cargo-fuzz convention, prevents sanitizer/instrumentation flags from polluting the main build. Toolchain pin is path-scoped, so `cargo test --workspace` at repo root continues to work on stable; `cargo fuzz run <target>` from inside `core/fuzz/` picks up nightly via `core/fuzz/rust-toolchain.toml`.

## Profile flags and sanitizers

```toml
# core/fuzz/Cargo.toml
[profile.release]
debug = true            # symbols for crash backtraces
overflow-checks = true  # arithmetic overflow → panic → fuzzer finding
debug-assertions = true # internal assert!() → panic → fuzzer finding
```

`overflow-checks = true` is the meaningful add over a normal release build — release mode wraps overflows silently by default, which would mask the very class of length-field overflow bugs we are hunting in decoders.

| Sanitizer | Status | Rationale |
|---|---|---|
| AddressSanitizer (ASan) | ON, default | cargo-fuzz default; ~2× throughput cost; catches transitive-`unsafe` bugs in deps (`ciborium`, `blake3`, `chacha20poly1305`, `ml-kem`, `ml-dsa`, dalek family) and gives clean stacks for allocator pathology from attacker-controlled length fields. |
| `cargo fuzz --careful` (Rust analog of UBSan) | ON, separate run per bug-bash | `cargo fuzz run --careful <target>` for ~10 min per target plus a one-time `--build-std` cost on first invocation. Rebuilds `std` with debug-assertions enabled and adds extra const-UB and init checks (per-callsite invariants in `core::ptr`, `MaybeUninit` slot tracking, etc.). Originally specified as `--sanitizer=undefined`, but neither cargo-fuzz nor rustc accept `undefined` as a `-Zsanitizer` value (rustc's set is `address, leak, memory, thread, ...`); UBSan in clang's sense has no Rust analog because Rust enforces UB freedom at the type level. `--careful` is the Rust-fuzz ecosystem's documented "extra UB pass" mode and catches a different class than ASan. |
| MemorySanitizer (MSan) | DEFERRED — Phase A.7 follow-up | Requires rebuilding all deps with MSan instrumentation; fragile in practice; substantial overlap with ASan in pure-Rust contexts. Tracked as a known TODO; revisit after the audit. |
| ThreadSanitizer (TSan) | SKIP | Decoders are single-threaded; no synchronization to race. |

The `#![forbid(unsafe_code)]` lint is crate-wide on `secretary-core`, so the marginal value of sanitizers in our own code is lower than in C/C++ — borrow checking already eliminates UAF / double-free / buffer-overflow at compile time. The value of ASan is concentrated in the transitive `unsafe` surface of dependencies and in turning OOM-shaped findings into clean allocation-site stacks.

## Seed corpus

Seeds are small, valid, and few — libFuzzer expands from them.

| Target | Seed source | Notes |
|---|---|---|
| `block_file` | `core/tests/data/golden_vault_001/blocks/*.bin` | Real on-disk block file from the §15 golden vault. |
| `manifest_file` | `core/tests/data/golden_vault_001/manifest.cbor.enc` | Real manifest. |
| `bundle_file` | `core/tests/data/golden_vault_001/identity.bundle.enc` | Real identity bundle. |
| `record` | hand-extracted, committed | Two or three records canonical-CBOR-encoded once and committed to `seeds/record/`. Avoids inverting the dep graph with a build-script that depends on `secretary-core`. |
| `contact_card` | `core/tests/data/card_kat.cbor`, `card_kat_signed.cbor` | Already committed binary CBOR. |
| `vault_toml` | `core/tests/data/golden_vault_001/vault.toml` + 1–2 minimal hand-written variants | Multiple textual shapes are valid for the same value; seeding two distinct ones gives the fuzzer a starting basin. |

## Regression mechanics

When a crash is found in `core/fuzz/artifacts/<target>/crash-<hash>`:

1. Verify reproducibility: `cargo fuzz run <target> artifacts/<target>/crash-<hash>` panics deterministically.
2. Minimize: `cargo fuzz tmin <target> artifacts/<target>/crash-<hash>` — produces a smaller equivalent.
3. Promote: copy the minimized input to `core/tests/data/fuzz_regressions/<target>/<descriptive-name>.bin`. Optional sibling `<descriptive-name>.md` documents what bug it caught.
4. Fix the bug in `secretary-core`.
5. Verify: `cargo test --release --test fuzz_regressions` is green.

A new integration test [core/tests/fuzz_regressions.rs] reads every file under `core/tests/data/fuzz_regressions/<target>/` and asserts the relevant decoder does not panic on each input. The contract is **must not panic** — an `Err` return is fine, that's the whole point. This is symmetric with the fuzz target's crash oracle.

The integration test runs in plain `cargo test --release --workspace` and survives even if the fuzz harness is removed, refactored, or a future contributor decides not to install nightly. Same posture as the existing §15 KAT regression test for the Python ML-DSA-65 silent-accept bug ([secretary_next_session.md:294-298](../../../secretary_next_session.md#L294-L298)).

## Out-of-loop differential replay

The fuzz harness's runtime corpus is replayed through both Rust and the Python clean-room decoder ([core/tests/python/conformance.py](../../../core/tests/python/conformance.py)) by an opt-in test, gated by a Cargo feature.

**Wire-up:**

`core/Cargo.toml` gets a new feature:
```toml
[features]
differential-replay = []
```

`core/tests/differential_replay.rs` (new, gated by `#[cfg(feature = "differential-replay")]`):
- For each target's runtime corpus directory (`core/fuzz/corpus/<target>/`):
  1. For each input file, run the Rust decoder → get `accept | reject(err_class)`.
  2. Shell out: `uv run --with cryptography --with pqcrypto core/tests/python/conformance.py --diff-replay <target> <input-file>` → get same shape.
  3. Assert agreement on accept/reject. For accepted with a defined roundtrip oracle (targets 1–5): assert re-encoded bytes match. Skip re-encode comparison for `vault_toml`.

`conformance.py` gains a `--diff-replay <target> <input-file>` mode that:
- Dispatches to the existing decoder function for `<target>` (most are already implemented for the §15 conformance check; gaps are filled in this phase).
- Outputs structured JSON to stdout: `{"status": "accept", "reencoded_b64": "..."}` or `{"status": "reject", "error_class": "..."}`.
- Uses only the existing pinned deps (`cryptography`, `pqcrypto`, stdlib) — no new dependencies.

**Run cadence:**
```bash
cargo test --release --workspace                                      # rust-only, default
cargo test --release --workspace --features differential-replay       # with python
```

The differential replay reads whatever local runtime corpus is present. It is not part of `cargo fuzz run`'s inner loop — that's the entire point of "out-of-loop": the fuzzer keeps its 10k–100k execs/sec, and the Python check runs after the fact with replayable, sticky failures.

**Failure triage policy.** A differential disagreement is one of:
- Rust bug → fix Rust.
- Python bug → fix Python.
- Spec ambiguity → docs PR alongside the fix to pick the canonical interpretation.

The first two get committed as differential regressions in `core/tests/data/diff_regressions/<target>/` (separate from `fuzz_regressions/` because the contract is different — agreement, not no-panic).

## Bug-bash plan

Run once after the harness lands. Per target, in this order (cheapest-blast-radius first, so a finding in one target's seed material doesn't cascade):

1. `vault_toml` — text input, smallest decoder, fastest exec rate.
2. `record` — pure CBOR, well-bounded.
3. `contact_card` — CBOR + canonical-form rejection.
4. `bundle_file` — small binary header + CBOR body.
5. `manifest_file` — full binary file format.
6. `block_file` — largest binary file format.

**Stop signal — hardware-independent.** Wall-clock time is the wrong contract for an audit deliverable: 40 min on a fast workstation does an order of magnitude more work than 40 min on a CI runner. The contract is **execution count + coverage plateau**:

- libFuzzer's `-runs=N` caps executions; its live telemetry (`stat: cov: X corp: Y exec/s: Z`) reports new edges and corpus entries.
- A target is "done" for the bug-bash when **both** hold: (a) the run has hit a per-target exec-count floor, and (b) the last `cov` and `corp` deltas are zero across the most recent ≥10% of executions (no new coverage, no new corpus entries) — the standard plateau signal.
- A wall-clock **stop-loss cap** (e.g. 4× the reference wall-clock estimate) terminates a session that genuinely never plateaus on the available hardware; that target is flagged in the bug-bash report rather than blocking the deliverable.

**Reference numbers** for planning, not for the contract — measured on the operator's reference workstation:

| Target | Reference wall-clock (ASan + careful) | Reference exec floor (ASan / careful) |
|---|---|---|
| `vault_toml` | ~30 min + ~10 min | TBD — calibrated empirically (see below) |
| `record` | ~30 min + ~10 min | TBD |
| `contact_card` | ~30 min + ~10 min | TBD |
| `bundle_file` | ~30 min + ~10 min | TBD |
| `manifest_file` | ~30 min + ~10 min | TBD |
| `block_file` | ~30 min + ~10 min | TBD |

**Calibration step.** Before the main bug-bash, one of the smaller targets (`vault_toml` or `record`) is run to plateau on the operator's reference workstation. The exec count at plateau gives the per-target floor (rounded up to a power-of-ten round number for each target). Larger/slower targets get scaled floors. The chosen floors are committed to `core/fuzz/README.md` so any future operator (auditor, CI) can reproduce the same coverage bar regardless of hardware. This is part of the implementation plan, not the spec.

Findings get the regression-mechanics treatment immediately — fix-then-continue, not collect-then-fix, so each subsequent target runs against fixed code.

## Exit criteria

The Phase A.7 fuzz sub-deliverable is done when **all** hold:

1. Six fuzz targets compile and run from `cd core/fuzz && cargo fuzz run <target>`.
2. Seed corpora committed; `cargo fuzz run <target> seeds/<target>/` is green for every target (seeds don't crash).
3. Each target has run with the most recent code under both ASan and `--careful`, has hit its per-target exec-count floor (calibrated per the bug-bash plan, recorded in `core/fuzz/README.md`), and `libFuzzer` has reported zero new coverage and zero new corpus entries across the last ≥10% of executions in each profile (the plateau signal). Targets that hit the wall-clock stop-loss cap without plateauing are flagged in the bug-bash report. No unfixed findings.
4. Any findings fixed; their inputs committed to `core/tests/data/fuzz_regressions/<target>/`; the `fuzz_regressions` integration test green in plain `cargo test --release --workspace`.
5. `core/fuzz/README.md` documents: how to install nightly, how to run a single target, how to run the `--careful` second pass, how to promote a finding, how to run the differential replay, **and the calibrated per-target exec-count floors** (from the calibration step in the bug-bash plan).
6. Differential replay runs cleanly: `cargo test --release --workspace --features differential-replay` is green against the corpus (no disagreements, or all known disagreements pinned as KATs after triage).
7. `cargo test --release --workspace` (default features) stays green throughout.

## Build sequence

Implementation order, each step independently testable before moving on:

1. **Workspace plumbing.** `core/fuzz/Cargo.toml`, `rust-toolchain.toml`, `.gitignore`. Verify `cargo test --workspace` at root still green; verify `cd core/fuzz && cargo fuzz list` works on the path-scoped nightly. Empty harness, just toolchain shaping.
2. **First target (`vault_toml`) end-to-end.** Crash-only by design. Establishes the harness pattern.
3. **First roundtrip target (`record`).** Establishes the assertion shape that the next four copy.
4. **Remaining four targets** (`contact_card`, `bundle_file`, `manifest_file`, `block_file`).
5. **Seeds extracted and committed** for all six targets.
6. **`fuzz_regressions` integration test** wired in, with empty regression dirs (placeholder `.gitkeep`) so the test compiles.
7. **`differential-replay` feature + Python `--diff-replay` mode + `differential_replay.rs` test scaffold.** Runs cleanly against seed corpus before any bug-bash.
8. **Bug-bash session.** Each finding: fix in main code → minimize → promote to regression KAT → continue.
9. **Documentation.** `core/fuzz/README.md` and a brief mention in the root `README.md` testing section. Update [secretary_next_session.md](../../../secretary_next_session.md) to mark this sub-deliverable closed.

## Out of scope

- **MSan.** Tracked above as a deferred Phase A.7 follow-up.
- **In-loop differential fuzzing** (Rust ↔ Python in the fuzz harness's inner loop). The throughput cost is ~10–100×, fault attribution adds significant triage burden, and the work is best left to the external review. Out-of-loop replay above is the in-tree substitute.
- **OSS-Fuzz integration.** Possible follow-up after Sub-project B (FFI) lands and the project surface is more visible.
- **Nightly CI fuzz runs.** v1 is on-demand only; revisit once a baseline of "no findings in 40 min" exists.
- **Sub-decoder isolated targets** (`decode_header`, `decode_recipient_table`, `decode_plaintext`). Reachable via parent decoders. Add later if coverage data shows branches unreached.
- **Phase A.7 items 1, 3, 4, 5** (independent crypto review, side-channel review, memory hygiene audit, docs pass). Separate sub-deliverables; not covered here.
