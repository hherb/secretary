"""`--diff-replay` mode: decode one input for one target, emit a JSON verdict.

The CLI shape and the JSON verdict format are a CONTRACT with
`core/tests/differential_replay.rs` and the `cargo-fuzz` harness -- see
`docs/manual/contributors/differential-replay-protocol.md`. Do not change
the argv shape, the JSON keys, or the exit codes without updating both.

"reject" is a VERDICT about the input; "error" is this script failing.
Scoring the second as the first turned an internal bug into a green
differential test (#595).

Two modes share one verdict function (#655):

  * `--diff-replay <target> <path>` -- one input, one process, one JSON line.
  * `--diff-replay-serve` -- one process answering a JSON request per line,
    so a corpus of tens of thousands of inputs pays interpreter start-up once
    instead of once per input. Section DRS checks the two agree.
"""

from __future__ import annotations

import base64
import contextlib
import json
import sys
import traceback
from typing import Callable, NamedTuple, TextIO

from conformance_lib.codec.block_file import py_decode_block_file, py_encode_block_file
from conformance_lib.codec.bundle import py_decode_bundle_file, py_encode_bundle_file
from conformance_lib.codec.card import py_decode_contact_card, py_encode_contact_card
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import py_encode_manifest
from conformance_lib.codec.manifest_file import py_decode_manifest_file, py_encode_manifest_file
from conformance_lib.codec.manifest_rules import token_for
from conformance_lib.codec.record import py_decode_record, py_encode_record
from conformance_lib.codec.vault_toml import py_decode_vault_toml
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

# The exit code for `status: "error"` -- this script failing, as distinct from
# the input being rejected (which is a verdict and exits 0).
EXIT_HARNESS_FAILURE = 3

# Crash-only: decoded, never re-encoded, so its accept carries no bytes.
_CRASH_ONLY_TARGET = "vault_toml"

# Every other target is a strict decode -> encode round trip.
_ROUND_TRIP = {
    "record": (py_decode_record, py_encode_record),
    "contact_card": (py_decode_contact_card, py_encode_contact_card),
    "bundle_file": (py_decode_bundle_file, py_encode_bundle_file),
    "manifest_file": (py_decode_manifest_file, py_encode_manifest_file),
    "manifest_body": (py_decode_manifest, py_encode_manifest),
    "block_file": (py_decode_block_file, py_encode_block_file),
}

# The Python side's target set, in the Rust side's `TARGETS` order. Derived
# from the dispatch table rather than listed a second time.
DIFF_REPLAY_TARGETS: tuple[str, ...] = (_CRASH_ONLY_TARGET, *_ROUND_TRIP)

# `error_class` of a serve request this module could not interpret.
BAD_REQUEST = "BadRequest"

# Keys a serve RESPONSE carries that a single-shot verdict never does.
SERVE_ONLY_KEYS = frozenset({"path", "traceback"})


class Replay(NamedTuple):
    """One input's verdict, plus the traceback of an internal error (if any).

    The traceback is kept OUT of the verdict object so the single-shot JSON
    stays exactly the shape the contract fixes; each mode decides where it
    goes (stderr for single-shot, the response line for serve).
    """

    verdict: dict
    traceback: str | None


def replay_bytes(target: str, data: bytes) -> Replay:
    """Differential replay one input's BYTES through the decoder for `target`.

    Verdict shapes:
      {"status": "accept", "reencoded_b64": "..."}    # for non-TOML targets
      {"status": "accept", "reencoded_b64": ""}       # for vault_toml (no roundtrip)
      {"status": "reject", "error_class": "...", "detail": "...", "rule": "<token>" | null}
      {"status": "error",  "error_class": "...", "detail": "..."}

    **"reject" is a VERDICT; "error" is this script failing (#595).** Until
    that split existed every exception became `{"status": "reject"}` with
    exit 0 -- a `NameError` from a typo, a `RecursionError` on a deeply
    nested subtree, a `cbor2` API break, a missing input file. The Rust
    caller (`core/tests/differential_replay.rs`) scored reject-vs-reject as
    AGREEMENT unconditionally until #634, and 32 of the 47 committed
    `manifest_body` seeds are Rust-reject rows (20 canonicality, 4
    uniqueness, 6 value-type and 2 nesting-depth rejects) -- so an internal
    bug in this script became a green differential test on exactly the inputs
    whose decode paths are most interesting.  #634 narrowed that arm to a
    token comparison for `manifest_body`, and #641 extended it to `record`
    and `block_file`, which does not retire this split: the other four
    targets (`vault_toml`, `contact_card`, `bundle_file`, `manifest_file`)
    are still scored on the fact of rejection alone, and even for
    `manifest_body` a phase-dependent token tolerates whatever the other side
    said (17 of those 32).  Both figures moved with the corpus and were
    re-measured at #667; they were 13 of 27 when this paragraph was written,
    and 24 of 38 until #669. Only the exception types the decoders raise DELIBERATELY
    to signal a wire-format violation are verdicts; everything else is a
    harness failure and must be surfaced, not scored.
    """
    try:
        if target == _CRASH_ONLY_TARGET:
            py_decode_vault_toml(data.decode("utf-8"))
            return Replay({"status": "accept", "reencoded_b64": ""}, None)
        pair = _ROUND_TRIP.get(target)
        if pair is None:
            # An unknown target is a wiring bug between this script and the
            # Rust replay's TARGETS list (`differential_replay_helpers/targets.rs`)
            # -- not a verdict. As a "reject" it read as agreement on every
            # Rust-reject input.
            return Replay(
                {"status": "error", "error_class": "UnknownTarget",
                 "detail": f"unknown target {target}"},
                None,
            )
        decode, encode = pair
        reencoded = encode(decode(data))
        return Replay(
            {"status": "accept",
             "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii")},
            None,
        )
    except _REJECTION_EXCEPTIONS as e:
        # `rule` is the language-neutral token `differential_replay.rs`
        # compares (#634).  `None` when this rejection carries none, which
        # the Rust side treats as a HARNESS FAILURE for a token-compared
        # target rather than as agreement -- default-deny, the same posture
        # `_REJECTION_EXCEPTIONS` itself takes.  `error_class` and `detail`
        # are unchanged, so nothing that reads them moves.
        return Replay(
            {"status": "reject", "error_class": type(e).__name__, "detail": str(e),
             "rule": token_for(e)},
            None,
        )
    except Exception as e:  # noqa: BLE001 - surfaced as a harness failure
        return Replay(
            {"status": "error", "error_class": type(e).__name__, "detail": str(e)},
            traceback.format_exc(),
        )


def replay_path(target: str, input_path: str) -> Replay:
    """Read `input_path` and replay it. An unreadable input is a HARNESS
    failure, never a verdict about the input's conformance."""
    try:
        with open(input_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return Replay(
            {"status": "error", "error_class": f"io: {type(e).__name__}", "detail": str(e)},
            None,
        )
    return replay_bytes(target, data)


def exit_code_for(verdict: dict) -> int:
    """0 for accept|reject, `EXIT_HARNESS_FAILURE` for `status: "error"`."""
    return EXIT_HARNESS_FAILURE if verdict.get("status") == "error" else 0


def run_diff_replay(target: str, input_path: str) -> int:
    """Single-shot mode: print exactly one verdict line to stdout.

    Exit code: 0 for accept|reject; 3 for `status: "error"`, whose traceback
    (if any) goes to stderr first.
    """
    verdict, trace = replay_path(target, input_path)
    if trace is not None:
        sys.stderr.write(trace)
    print(json.dumps(verdict))
    return exit_code_for(verdict)


def _bad_request(detail: str) -> dict:
    return {"status": "error", "error_class": BAD_REQUEST, "detail": detail, "path": None}


def serve_response(line: str, replay: Callable[[str, str], Replay] = replay_path) -> dict:
    """The response object for ONE request line. Pure apart from `replay`.

    A request is `{"target": "<target>", "path": "<input path>"}`. The response
    is that input's verdict plus `path`, echoing the request, so the caller can
    check it is reading the answer to the question it asked rather than
    trusting line ORDER alone. An internal error's traceback rides in the
    response too: on stderr it could not be tied to its input.

    A request that cannot be interpreted is answered, not raised: a
    `BadRequest` error with `path: None`, after which the loop goes on.
    """
    try:
        request = json.loads(line)
    except ValueError as e:
        return _bad_request(f"request is not JSON: {e}")
    if not isinstance(request, dict):
        return _bad_request(f"request is a {type(request).__name__}, not an object")
    target, path = request.get("target"), request.get("path")
    if not isinstance(target, str) or not isinstance(path, str):
        return _bad_request("request needs string `target` and `path`")
    verdict, trace = replay(target, path)
    response = {**verdict, "path": path}
    if trace is not None:
        response["traceback"] = trace
    return response


def serve_diff_replay(
    requests: TextIO,
    responses: TextIO,
    replay: Callable[[str, str], Replay] = replay_path,
) -> int:
    """Answer every request line with one response line, flushed, until EOF.

    `sys.stdout` is pointed at stderr for the duration. The response stream is
    the protocol, and a decoder that PRINTS -- a debugging line left in --
    would otherwise put a non-JSON line on it and desync every answer after
    it. `responses` is bound before the redirect, so it is still the real
    stream. The redirect is Python-level only: native code or a subprocess
    writing to file descriptor 1 bypasses it, and the Rust side then reads a
    non-JSON line or a mismatched echo, which it scores as a harness failure
    rather than a verdict. (This docstring said a printing decoder "cannot"
    corrupt the stream, and gave a library warning as an example; `warnings`
    already writes to stderr, and fd 1 is not covered -- #662 review.)

    Always returns 0: an input this module cannot decode is a verdict or an
    `error` response, never a reason to stop serving the rest.
    """
    with contextlib.redirect_stdout(sys.stderr):
        for line in requests:
            responses.write(json.dumps(serve_response(line, replay)) + "\n")
            responses.flush()
    return 0


def run_diff_replay_serve() -> int:
    """`--diff-replay-serve`: answer requests on stdin until EOF."""
    return serve_diff_replay(sys.stdin, sys.stdout)
