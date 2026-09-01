"""`--diff-replay` mode: decode one input for one target, emit a JSON verdict.

The CLI shape and the JSON verdict format are a CONTRACT with
`core/tests/differential_replay.rs` and the `cargo-fuzz` harness -- see
`docs/manual/contributors/differential-replay-protocol.md`. Do not change
the argv shape, the JSON keys, or the exit codes without updating both.

"reject" is a VERDICT about the input; "error" is this script failing.
Scoring the second as the first turned an internal bug into a green
differential test (#595).
"""

from __future__ import annotations

import base64
import json
import sys
import traceback

from conformance_lib.codec.block_file import py_decode_block_file, py_encode_block_file
from conformance_lib.codec.bundle import py_decode_bundle_file, py_encode_bundle_file
from conformance_lib.codec.card import py_decode_contact_card, py_encode_contact_card
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import py_encode_manifest
from conformance_lib.codec.manifest_file import py_decode_manifest_file, py_encode_manifest_file
from conformance_lib.codec.record import py_decode_record, py_encode_record
from conformance_lib.codec.vault_toml import py_decode_vault_toml
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

def run_diff_replay(target: str, input_path: str) -> int:
    """Differential replay one input through the Python decoder for `target`.

    Output (always to stdout, single line of JSON):
      {"status": "accept", "reencoded_b64": "..."}    # for non-TOML targets
      {"status": "accept", "reencoded_b64": ""}       # for vault_toml (no roundtrip)
      {"status": "reject", "error_class": "...", "detail": "..."}
      {"status": "error",  "error_class": "...", "detail": "..."}

    Exit code: 0 for accept|reject; 3 for `status: "error"`.

    **"reject" is a VERDICT; "error" is this script failing (#595).** Until
    that split existed every exception became `{"status": "reject"}` with
    exit 0 -- a `NameError` from a typo, a `RecursionError` on a deeply
    nested subtree, a `cbor2` API break, a missing input file. The Rust
    caller (`core/tests/differential_replay.rs`) scores reject-vs-reject as
    AGREEMENT, and 9 of the 21 committed `manifest_body` seeds are
    Rust-reject rows -- so an internal bug in this script became a green
    differential test on exactly the inputs whose decode paths are most
    interesting. Only the exception types the decoders raise DELIBERATELY
    to signal a wire-format violation are verdicts; everything else is a
    harness failure and must be surfaced, not scored.
    """
    try:
        with open(input_path, "rb") as f:
            data = f.read()
    except OSError as e:
        # A missing or unreadable input is a HARNESS failure, never a
        # verdict about the input's conformance.
        print(json.dumps({
            "status": "error",
            "error_class": f"io: {type(e).__name__}",
            "detail": str(e),
        }))
        return 3

    try:
        if target == "vault_toml":
            # Crash-only target. Try to UTF-8 decode and parse.
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as e:
                raise e
            py_decode_vault_toml(text)
            print(json.dumps({"status": "accept", "reencoded_b64": ""}))
            return 0
        elif target == "record":
            parsed = py_decode_record(data)
            reencoded = py_encode_record(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "contact_card":
            parsed = py_decode_contact_card(data)
            reencoded = py_encode_contact_card(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "bundle_file":
            parsed = py_decode_bundle_file(data)
            reencoded = py_encode_bundle_file(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "manifest_file":
            parsed = py_decode_manifest_file(data)
            reencoded = py_encode_manifest_file(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "manifest_body":
            parsed = py_decode_manifest(data)
            reencoded = py_encode_manifest(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "block_file":
            parsed = py_decode_block_file(data)
            reencoded = py_encode_block_file(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        else:
            # An unknown target is a wiring bug between this script and
            # `differential_replay.rs`'s TARGETS list -- not a verdict. As a
            # "reject" it read as agreement on every Rust-reject input.
            print(json.dumps({
                "status": "error",
                "error_class": "UnknownTarget",
                "detail": f"unknown target {target}",
            }))
            return 3
    except _REJECTION_EXCEPTIONS as e:
        print(json.dumps({
            "status": "reject",
            "error_class": type(e).__name__,
            "detail": str(e),
        }))
        return 0
    except Exception as e:  # noqa: BLE001 - surfaced as a harness failure
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({
            "status": "error",
            "error_class": type(e).__name__,
            "detail": str(e),
        }))
        return 3
