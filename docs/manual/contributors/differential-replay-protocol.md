# Differential replay protocol (Python clean-room decoder)

This document is for **Python contributors** maintaining
[`core/tests/python/conformance.py`](../../../core/tests/python/conformance.py),
specifically its two replay modes — `--diff-replay-serve`, which the Rust side
uses, and single-shot `--diff-replay`, kept for replaying one input in isolation
(see Invocation). It describes the wire protocol the
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
differential replay drives seven of its own (`TARGETS` in
`differential_replay_helpers/targets.rs`). **The two sets are not the same set** and neither is "the seven
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
   `TOKEN_COMPARED_TARGETS` (`differential_replay_helpers/targets.rs`). See §3
   below.

The Python decoders live in `core/tests/python/conformance_lib/codec/`
(#593; `conformance.py` is now a thin entrypoint over that package) and
are deliberately written as a separate, "clean-room" implementation: they
read the spec docs, not the Rust source. Two implementations of the
same spec are far less likely to share the same bug than one
implementation tested against itself.

## Invocation

There are two modes, and they share one verdict function
(`conformance_lib/diff_replay.py`'s `replay_bytes`), so they cannot answer
differently by construction of the decode — and Section DRS checks that they do
not by execution.

**`differential_replay.rs` uses serve mode (#655): one worker process for the
whole run.**

```
uv run [--with <pkg>...] conformance.py --diff-replay-serve
```

Until #655 it spawned the single-shot mode below once PER corpus input.
Decoding costs 0.2-0.4 ms and the spawn ~0.16 s, so a checkout whose runtime
fuzz corpus held 74,924 inputs took ~3.3 hours and, printing nothing, looked
hung. Through one worker the same corpus — 74,973 inputs with the committed
ones — replays in **27.5 s** (measured 2026-09-13, every input agreeing).

The single-shot mode is kept, unchanged, for replaying one input in isolation:

```
uv run [--with <pkg>...] conformance.py --diff-replay <TARGET> <INPUT_PATH>
```

- `TARGET` is one of the seven **differential-replay** target names:
  `vault_toml`, `record`, `contact_card`, `bundle_file`, `manifest_file`,
  `manifest_body`, `block_file`. Not the fuzz target list — see above:
  `manifest_body` is here and not there, `device_file` is there and not
  here.
- `INPUT_PATH` is a single corpus or seed file path.
- **Each input has a wall-clock budget of 60 seconds** (`PER_INPUT_TIMEOUT` in
  `differential_replay_helpers/python_worker.rs`), in serve mode as it was per
  process. If Python takes longer (infinite loop on a malformed input, runaway
  allocation, etc.), the Rust side kills the worker's whole PROCESS GROUP —
  `uv run` forks the interpreter rather than exec'ing it, so killing `uv` alone
  would orphan a spinning Python — reports a timeout for that input, and starts
  a fresh worker for the next. The kill is `kill(2)` on the negative group id,
  through `rustix`, and **never the `kill` utility**: procps-ng 4.0.4's
  `kill -KILL -<pgid>` (Ubuntu 24.04) reads the group id as an option and
  signals pid -1, every process the user owns. The first version of this
  worker did that on PR #662's CI run and took the runner down with it. **Don't write Python decoders that scale
  super-linearly in input length** — there is no protective `signal.alarm`
  inside the Python process; the timeout is enforced from Rust.

### Serve-mode requests and responses

One request per stdin line, one response per stdout line, flushed, until EOF:

```json
{"target": "<TARGET>", "path": "<INPUT_PATH>"}
```

The response is exactly the single-shot verdict object below **plus**:

- `path` — the request's `path`, echoed. The Rust side rejects a response whose
  echo does not match as a harness failure: trusting line ORDER alone, one
  desynchronised line would score every later input against its neighbour's
  verdict.
- `traceback` — present only on an `error` verdict, carrying what single-shot
  mode writes to stderr. On a shared stderr a traceback cannot be tied to its
  input.

A request the worker cannot interpret is answered, not fatal:
`{"status": "error", "error_class": "BadRequest", "detail": "...", "path": null}`,
and the loop goes on — though on the Rust side that answer's `path: null` fails
the echo check, so the worker is retired and the input is a harness failure.
`sys.stdout` is pointed at stderr while serving, so a decoder that prints
through Python's `sys.stdout` (a `print` left in) cannot put a line on the
response stream. That redirect is Python-level only: native code or a
subprocess writing to file descriptor 1 still reaches the stream, where the
Rust side reads a non-JSON line or a mismatched echo — a harness failure,
never a verdict. The worker exits 0 at EOF.

What a reused interpreter gives up is per-input process isolation: a decoder
that mutated module state on one input could change the verdict on the next.
None does today, and Section DRS replays every committed input through both
modes and requires identical verdicts — each a DECODE (accept or reject), with
the single-shot process exiting 0, since two identical `error` verdicts are
what a broken `replay_bytes` produces in both modes — and requires both
committed roots to contribute an input. See its LIMIT for the fuzz corpus it
does not replay. The Rust side also retires a worker after any transport
failure (timeout, death, non-JSON line, mismatched echo), but NOT after an
`error` verdict. Once **three inputs in a row get no answer from a worker** —
it could not start, or a transport failure — it starts no further worker, and
the rest of the run is reported as one "not replayed" harness failure. Any
answer resets that count, an `error` one included, since the worker that sent
it is up; the input is still a harness failure of its own.

(This paragraph used to say the cap counted workers that "die before answering
a single request". That was an earlier rule, replaced during #655: the
mutation harness showed it could not be told apart from the simpler one, since
a respawned worker has always answered nothing yet.)

## Output protocol

In single-shot mode `run_diff_replay()` MUST print **exactly one** JSON object
to stdout and **nothing else** (no trailing newline beyond the standard one
from `print`, no log lines, no warnings). In serve mode that object is one
response line. Either way a line that is not valid JSON is a HARNESS failure on
the Rust side, never a verdict (#595).

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
  (`differential_replay_helpers/agreement.rs::judge`, via its
  `CRASH_ONLY_TARGET`) short-circuits the byte comparison for this target. A line-anchor citation here was tried before and went stale
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
  informational and neither is compared — but both are REQUIRED, as strings: a
  reject missing either is a harness failure, as an accept missing
  `reencoded_b64` already was (#662 review).
- **`rule` is compared** (#634), for the targets in
  `differential_replay_helpers/targets.rs::TOKEN_COMPARED_TARGETS` — today `manifest_body`,
  `block_file` and `record` (#641). It is one of the tokens in
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
  declares the order unspecified and both readers are conformant. Since #641
  that tolerance applies on manifest_body only
  (`PHASE_DEPENDENT_TOLERANCE_TARGETS`); `block_file` and `record` compare
  strictly. The predicate lives on `RuleToken::is_phase_dependent` and is
  **derived from**
  §4.2's "deliberately unspecified" paragraphs rather than being them — a
  per-token predicate is strictly BROADER than a per-pair rule: it tolerates
  **54 of the 136 unequal token pairs** (58 have a phase-dependent member;
  the four pairing one with `malformed_cbor` are withheld, because §4.2 makes
  well-formedness a precondition that outranks every rule), and the FOUR
  groups it tolerates
  that §4.2 does not license are written out in that method's own LIMITS
  block. Read "generally declares the order unspecified" above with that in
  mind — because all four `NonCanonicalCause` outcomes map to phase-dependent
  tokens, **17 of the 42 rejecting `manifest_body` seeds never compare the
  Python token at all** (the NUMERATOR has not moved since #634; the
  denominator has, twice — "17 of the 24" from #634, re-measured to 32 at
  #667 and to 42 at #666, whose ten new seeds every one reaches a strict
  comparison. Re-measure the denominator, never quote it). It is still not a list of tolerated pairs, because
  such a list drifts from §4.2 silently; #646 tracks replacing it with a
  two-argument relation once §4.2 settles the two groups it leaves open.
- An **unrecognised** token — one absent from the vocabulary — is never
  agreement, but its mechanism is not the missing-token one above: it falls
  through `tokens_agree` to `false` and is reported as an ordinary
  DISAGREEMENT, not as a harness failure. Both red the test, so nothing is
  lost; "unrecognised or missing is a harness failure" is simply wrong about
  the first half.
- A target must be classified: one in neither `TOKEN_COMPARED_TARGETS` nor
  `NOT_TOKEN_COMPARED_TARGETS` is a harness failure in `agreement::judge`,
  never the loose comparison by default (#662 review).
- **`manifest_file` is deliberately NOT token-compared** (#640): Rust's
  header raises `UnsupportedFormatVersion` where Python raises the same
  `ParseError` it raises for every envelope fault, and no mapping reconciles
  that. The other five targets are #641.

### Exit code

Single-shot `run_diff_replay()` exits **0 for accept and reject**, and **3 for
`status: "error"`** — an unknown target, an unreadable input, or any exception
the decoders do not raise deliberately (#595). This section used to say
unknown-target exited 0; it has not since #595 made "error" a harness failure
rather than a verdict. Any other non-zero exit (a syntax error, an import
failure) is equally a harness failure. Serve mode answers all of these as
`error` RESPONSES and exits 0 at EOF; the Rust side scores each one as a
harness failure for its input.

If you add a new failure mode that should be classified as "the corpus
input is bad" (not "the script is broken"), raise one of the exception types
in `conformance_lib/rejection.py`'s `_REJECTION_EXCEPTIONS`, which becomes a
`{"status": "reject", ...}` verdict. Anything else is "Python itself failed".

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
2. Add the pair to the `_ROUND_TRIP` table in
   `conformance_lib/diff_replay.py` (it was an `if target == ...` chain
   until #655), importing it at the top of that module. A crash-only target
   with no re-encode is the one special case, `_CRASH_ONLY_TARGET`, and a
   second one would need `replay_bytes` itself extended. `DIFF_REPLAY_TARGETS`
   is derived from the table, so Section DRS picks the new target up and
   requires a committed input for it.
3. Mirror the change on the Rust side in
   `core/tests/differential_replay_helpers/rust_decoder.rs::rust_decode` and
   `core/tests/differential_replay_helpers/targets.rs::TARGETS` (moved out of
   the entry file in #649), plus a `MIN_CORPUS_INPUTS` row in that same file.
4. Add a fuzz target under `core/fuzz/fuzz_targets/<target>.rs` if one
   doesn't exist yet. The differential replay only meaningfully runs
   against inputs the fuzzer has actually mutated — without a
   `cargo-fuzz` target there's no growing corpus.
5. Add seeds in `core/fuzz/seeds/<target>/`, plus the corresponding
   `core/tests/data/fuzz_regressions/<target>/.gitkeep` and
   `core/tests/data/diff_regressions/<target>/.gitkeep`.
6. Run the replay end-to-end at least once before pushing — the Rust side
   iterates over `TARGETS`, so a typo in the new target name there will
   silently skip your work:

   ```bash
   cargo test --release --locked -p secretary-core \
     --features differential-replay --test differential_replay
   ```

   This is the spelling CI runs (#647). On a checkout that has fuzzed it also
   replays the gitignored `core/fuzz/corpus/`, which is the point of running
   it locally: since #655 that is seconds rather than hours (27.5 s for 74,973
   inputs, measured), and each target prints a start line, a progress line at
   most every 10 s, and a finish line with its input counts — to the process's
   stderr, so they show without `--nocapture`. The `--workspace` spelling this
   step used to recommend additionally rebuilds the desktop and FFI wrapper
   crates for a feature none of them reads.

## Adding a new accept-shape (don't, unless you must)

The three output shapes above are not arbitrary; they're what
`differential_replay_helpers::python_bridge::parse_verdict` knows how to
consume (a pure function since #655, unit-tested without Python; the process
that feeds it is `python_worker.rs`). If you genuinely need a new shape (e.g. "accept with a
structured error class to compare against Rust"), extend **both sides** of
the protocol in the same commit:

1. Update `parse_verdict` in
   `core/tests/differential_replay_helpers/python_bridge.rs` to recognise
   the new shape, with a unit test beside it.
2. Update `replay_bytes` in `conformance_lib/diff_replay.py` to emit it —
   both modes then carry it.
3. Update this document.

Adding a new shape on only one side will manifest as a harness failure
("python output has unrecognised status ...") from the Rust side, which
is the test failing loudly — not the silent kind of breakage. So the
guard rails are decent, but please update both ends in lockstep anyway.

## Why this exists as a separate doc

The protocol is a contract between two languages and two test layers
(unit-level conformance KAT and corpus-driven differential replay).
Inline comments in either file are easy to miss and harder to diff
against the spec. This doc is the single source of truth; if you
change behaviour, change this file too.
