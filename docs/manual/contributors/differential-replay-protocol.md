# Differential replay protocol (Python clean-room decoder)

This document is for **Python contributors** maintaining
[`core/tests/python/conformance.py`](../../../core/tests/python/conformance.py),
specifically its `--diff-replay` mode. It describes the wire protocol the
Rust integration test
[`core/tests/differential_replay.rs`](../../../core/tests/differential_replay.rs)
expects from each target's `py_decode` / `py_encode` pair, and the
contractual rules that keep the two implementations honest about whether
they agree on a given input.

If you are adding a new fuzz target, removing one, or changing the
encode/decode behaviour of an existing target, **read this whole document
before touching `conformance.py`**. The contract is partly enforced by
`differential_replay.rs` and partly by convention; the parts that aren't
machine-checked are easy to break silently.

## What "differential replay" is

The fuzz harness drives seven Rust decoders (`core/fuzz/fuzz_targets/`) and
differential replay drives seven of its own (`differential_replay.rs`'s
`TARGETS`). **The two sets are not the same set** and neither is "the seven
targets": they overlap in six, `manifest_body` is replay-only and has no
fuzz target, and `device_file` is fuzz-only and is not replayed. The point
of differential replay is to run the corpus through a **completely
independent** Python decoder and assert that the two implementations agree
on:

1. **Whether the input is accepted or rejected.** If Rust accepts and
   Python rejects (or vice versa), one of them has a spec-compliance bug.
2. **What the canonical re-encoded bytes look like, when both accept.**
   Disagreement here means one side has a re-encoding bug that the other
   side's tests didn't catch.
3. **Which rule each names when both reject** — for targets listed in
   `differential_replay.rs::TOKEN_COMPARED_TARGETS`. See §3 below.

The Python decoders live in `core/tests/python/conformance_lib/codec/`
(#593; `conformance.py` is now a thin entrypoint over that package) and
are deliberately written as a separate, "clean-room" implementation: they
read the spec docs, not the Rust source. Two implementations of the
same spec are far less likely to share the same bug than one
implementation tested against itself.

## Invocation

`differential_replay.rs` invokes `conformance.py` once per corpus input,
in a fresh subprocess:

```
uv run [--with <pkg>...] conformance.py --diff-replay <TARGET> <INPUT_PATH>
```

- `TARGET` is one of the seven **differential-replay** target names:
  `vault_toml`, `record`, `contact_card`, `bundle_file`, `manifest_file`,
  `manifest_body`, `block_file`. Not the fuzz target list — see above:
  `manifest_body` is here and not there, `device_file` is there and not
  here.
- `INPUT_PATH` is a single corpus or seed file path.
- The subprocess has a per-input wall-clock budget of 60 seconds. If
  Python takes longer (infinite loop on a malformed input, runaway
  allocation, etc.), the Rust side will SIGKILL it and report a timeout.
  **Don't write Python decoders that scale super-linearly in input
  length** — there is no protective `signal.alarm` inside the Python
  process; the timeout is enforced from Rust.

## Output protocol

`run_diff_replay()` MUST print **exactly one** JSON object to stdout and
**nothing else** (no trailing newline beyond the standard one from
`print`, no log lines, no warnings). The Rust side parses stdout with
`serde_json::from_str(stdout.trim())` and panics if the JSON is malformed.

There are exactly three valid output shapes:

### 1. Accept with re-encoded bytes (most targets)

```json
{"status": "accept", "reencoded_b64": "<standard-base64>"}
```

- `reencoded_b64` is `base64.standard_b64encode(canonical_reencoded).decode("ascii")`.
- Used for `record`, `contact_card`, `bundle_file`, `manifest_file`,
  `manifest_body`, `block_file` — all six "crash + roundtrip-eq" targets.

### 2. Accept with empty re-encoded bytes (`vault_toml` only)

```json
{"status": "accept", "reencoded_b64": ""}
```

- `vault_toml` is a **crash-only** target. We do not assert byte
  equality against Rust's output because the TOML decoder doesn't have
  a canonical re-encode contract — it builds an in-memory `VaultIndex`
  struct and discards the lexical input. Python emits an empty
  `reencoded_b64` and the Rust side
  (`differential_replay.rs::differential_replay_full_corpus`'s
  `if *target == "vault_toml"` arm) short-circuits the byte comparison for
  this target. A line-anchor citation here was tried before and went stale
  across an unrelated edit to the same file (twice, in fact — once before
  #634 and worse afterwards, when splitting the file's helpers into
  `differential_replay_helpers/` shifted the line numbers further); a symbol
  reference doesn't need updating every time this file's line count moves.
- **Do not** invent a re-encode for `vault_toml`. If you do, Rust will
  start comparing bytes and fail because Rust's `rust_decode` arm for
  vault_toml also returns `Vec::new()`. Both sides must stay in sync.

### 3. Reject

```json
{"status": "reject", "error_class": "<class name>", "detail": "<message>", "rule": "<token>"}
```

- `error_class` is `type(e).__name__` and `detail` is `str(e)`. Both are
  informational and neither is compared.
- **`rule` is compared** (#634), for the targets in
  `differential_replay.rs::TOKEN_COMPARED_TARGETS` — today `manifest_body`
  and nothing else. It is one of the tokens in
  `core/tests/data/rule_token_vocabulary.json`, which the Rust enum
  `secretary_core::vault::manifest::RuleToken` and Section RTV both check
  themselves against, so the two languages cannot drift onto different
  spellings.
- `rule` is `null` when the rejection carries no token. For a
  token-compared target that is a **harness failure**, not agreement —
  default-deny, so a new untokened rejection fails loudly rather than
  silently restoring the blindness this field removed.
- A token mismatch is a disagreement **unless either token is
  phase-dependent**, in which case `docs/vault-format.md` §4.2 generally
  declares the order unspecified and both readers are conformant. The
  predicate lives on `RuleToken::is_phase_dependent` and is **derived from**
  §4.2's "deliberately unspecified" paragraphs rather than being them — a
  per-token predicate is strictly BROADER than a per-pair rule, and the two
  families it tolerates that §4.2 does not free are written out in that
  method's own LIMITS block. It is still not a list of tolerated pairs,
  because such a list drifts from §4.2 silently.
- An **unrecognised** token — one absent from the vocabulary — is never
  agreement, but its mechanism is not the missing-token one above: it falls
  through `tokens_agree` to `false` and is reported as an ordinary
  DISAGREEMENT, not as a harness failure. Both red the test, so nothing is
  lost; "unrecognised or missing is a harness failure" is simply wrong about
  the first half.
- **`manifest_file` is deliberately NOT token-compared** (#640): Rust's
  header raises `UnsupportedFormatVersion` where Python raises the same
  `ParseError` it raises for every envelope fault, and no mapping reconciles
  that. The other five targets are #641.

### Exit code

`run_diff_replay()` returns 0 (and the script exits 0) for all three
output shapes — accept, reject, even unknown-target. **Non-zero exit
means an unrecoverable script error** (uncaught exception, syntax error,
import failure) and the Rust side surfaces stderr verbatim.

If you add a new failure mode that should be classified as "the corpus
input is bad" (not "the script is broken"), emit `{"status":"reject", ...}`
and `return 0`. Reserve non-zero exit for "Python itself failed".

## The accept/reject contract — what it really means

Rust accepts an input ⟺ `decoder(input).is_ok()`. Python accepts ⟺ the
`run_diff_replay()` arm for the target completes without raising.

The four-way agreement matrix:

| Rust | Python | Outcome |
|------|--------|---------|
| Accept | Accept | Compare re-encoded bytes (skipped for `vault_toml`). |
| Accept | Reject | **Disagreement** — one of them has a spec bug. |
| Reject | Accept | **Disagreement** — one of them has a spec bug. |
| Reject | Reject | Agreement on the verdict. For a token-compared target the `rule` tokens must also agree, or one must be phase-dependent — see §3. |

When you investigate a disagreement, the rule of thumb:

- **Rust accepts, Python rejects:** Rust may be too permissive
  (canonicality gate is leaking) OR Python may be too strict (Python
  has a parser bug). Read the spec, then both implementations.
- **Python accepts, Rust rejects:** Python may be too permissive OR
  Rust may be too strict. Same procedure.
- **Both accept, bytes differ:** one of the encoders is
  non-canonical for this input. Almost always an encoder bug, not a
  decoder bug.

The fix lands in whichever side is wrong. If the spec is genuinely
ambiguous (it shouldn't be, but it has happened), update
[`docs/vault-format.md`](../../vault-format.md) **first**, then fix
both implementations to match the clarified spec. Do not let the
implementations agree on an under-specified behaviour without writing
it down.

If the disagreement is sticky and you need a long-running regression
artefact, drop the offending input as a file in
`core/tests/data/diff_regressions/<target>/<descriptive-name>.bin`
and commit it. The differential test picks up everything in those
directories on every run.

## Adding a new target

1. Add `py_decode_<target>(data: bytes) -> SomeDataclass` and
   `py_encode_<target>(parsed: SomeDataclass) -> bytes` in a module under
   `core/tests/python/conformance_lib/codec/` — one module per target,
   named after it.
2. Extend the `if target == "<target>":` chain inside `run_diff_replay()`
   (`conformance_lib/diff_replay.py`) with the appropriate accept arm
   (with or without re-encoded bytes, per §1/§2 above), importing the new
   pair at the top of that module.
3. Mirror the change on the Rust side in
   `core/tests/differential_replay.rs::rust_decode` and
   `core/tests/differential_replay.rs::TARGETS`.
4. Add a fuzz target under `core/fuzz/fuzz_targets/<target>.rs` if one
   doesn't exist yet. The differential replay only meaningfully runs
   against inputs the fuzzer has actually mutated — without a
   `cargo-fuzz` target there's no growing corpus.
5. Add seeds in `core/fuzz/seeds/<target>/`, plus the corresponding
   `core/tests/data/fuzz_regressions/<target>/.gitkeep` and
   `core/tests/data/diff_regressions/<target>/.gitkeep`.
6. Run `cargo test --release --workspace --features differential-replay`
   end-to-end at least once before pushing — the Rust side iterates
   over `TARGETS`, so a typo in the new target name there will
   silently skip your work.

## Adding a new accept-shape (don't, unless you must)

The three output shapes above are not arbitrary; they're what
`differential_replay_helpers::python_bridge::python_decode` knows how to
consume (moved out of `differential_replay.rs` itself in #634, to keep that
entry file under the project's 500-LOC guideline — see that file's own
module doc). If you genuinely need a new shape (e.g. "accept with a
structured error class to compare against Rust"), extend **both sides** of
the protocol in the same commit:

1. Update `python_decode` in
   `core/tests/differential_replay_helpers/python_bridge.rs` to recognise
   the new shape.
2. Update `run_diff_replay` in `conformance_lib/diff_replay.py` to emit it.
3. Update this document.

Adding a new shape on only one side will manifest as
`panic!("python output missing status: ...")` from the Rust side, which
is the test failing loudly — not the silent kind of breakage. So the
guard rails are decent, but please update both ends in lockstep anyway.

## Why this exists as a separate doc

The protocol is a contract between two languages and two test layers
(unit-level conformance KAT and corpus-driven differential replay).
Inline comments in either file are easy to miss and harder to diff
against the spec. This doc is the single source of truth; if you
change behaviour, change this file too.
