"""Section DRS -- `--diff-replay-serve` answers exactly as `--diff-replay` does.

WHY THIS EXISTS (#655). `core/tests/differential_replay.rs` used to spawn
`uv run conformance.py --diff-replay <target> <path>` once PER corpus input.
Decoding costs 0.2-0.4 ms; the spawn costs ~0.16 s. On a checkout that has
fuzzed, `core/fuzz/corpus/` held 74,924 inputs, so the replay took ~3.3 hours
and, printing nothing, presented as a hang. Measured in one interpreter, the
same 74,924 inputs decode in about 30 seconds.

`--diff-replay-serve` is that one interpreter: it reads one JSON request per
line and writes one verdict per line. What it gives up is the per-input
PROCESS ISOLATION the old spawn provided for free -- a decoder that mutated
module state on one input could change the verdict on the next. No codec
module holds such state today (audited: no `lru_cache`, no `global`, no
module-level mutable container reachable from `diff_replay`), but "today" is a
property of the call sites, so the equivalence is checked rather than assumed.

Two checks:

  1. PROTOCOL, in-process. One response per request, in request order, each
     echoing its request's `path`; a malformed request is answered with
     `status: error` / `error_class: BadRequest` and the loop goes on; a
     decoder that PRINTS cannot corrupt the response stream; an internal error
     carries its traceback in the response rather than only on stderr, where
     a reader of the stream could attribute it to the wrong input.
  2. EQUIVALENCE, across processes. Every committed input for every target is
     decoded once by a fresh single-shot `--diff-replay` process and once by a
     single `--diff-replay-serve` process fed all of them in sequence. The two
     verdict objects must be identical once the serve-only `path` and
     `traceback` keys are set aside -- and each must be a DECODE (accept or
     reject), with the single-shot process exiting 0, because two identical
     `error` verdicts are what a broken `replay_bytes` produces in both modes.
     Every target must contribute at least one input, so an empty discovery
     cannot pass.

LIMIT. Check 2 replays the COMMITTED inputs only -- the ones CI has. A verdict
that depends on interpreter state could in principle surface only on some
sequence of gitignored fuzz-corpus inputs, which no gate here replays; the
single-shot mode stays available precisely so such an input can be re-run in
isolation.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

from conformance_lib.diff_replay import (
    BAD_REQUEST,
    DIFF_REPLAY_TARGETS,
    SERVE_ONLY_KEYS,
    Replay,
    serve_diff_replay,
)
from conformance_lib.fixtures import test_data_dir

_ENTRYPOINT = Path(__file__).resolve().parents[2] / "conformance.py"
# Generous per spawn: the single-shot side starts a fresh interpreter per input.
_SUBPROCESS_TIMEOUT_SECONDS = 120

# Set in every process this section spawns. `conformance.py` parses with
# `parse_known_args`, so if `--diff-replay-serve` ever stopped being recognised
# the child would silently run the FULL verifier -- this section included,
# which would spawn again, without bound, each level waiting on the next. A
# process that finds this variable set refuses to spawn, so that failure is
# one level deep and reads as a FAIL rather than as a hang. The fall-through
# itself, for every other caller, is #660.
NESTED_ENV = "CONFORMANCE_DRS_SPAWNED"


def committed_inputs() -> list[tuple[str, Path]]:
    """Every committed corpus input, as `(target, path)`, in a stable order.

    The same two directories `differential_replay_helpers/corpus.rs` marks as
    committed: `core/fuzz/seeds/<target>/` and
    `core/tests/data/diff_regressions/<target>/`, skipping `.gitkeep`.
    """
    core = test_data_dir().parents[1]
    roots = (core / "fuzz" / "seeds", test_data_dir() / "diff_regressions")
    found: list[tuple[str, Path]] = []
    for target in DIFF_REPLAY_TARGETS:
        for root in roots:
            directory = root / target
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if path.is_file() and path.name != ".gitkeep":
                    found.append((target, path))
    return found


def _serve_in_process(lines: list[str], replay) -> tuple[list[dict], str]:
    """Drive `serve_diff_replay` over `lines`; return (responses, stray stdout)."""
    requests = io.StringIO("".join(lines))
    responses = io.StringIO()
    stray = io.StringIO()
    with contextlib.redirect_stdout(stray), contextlib.redirect_stderr(io.StringIO()):
        serve_diff_replay(requests, responses, replay=replay)
    parsed = [json.loads(line) for line in responses.getvalue().splitlines()]
    return parsed, stray.getvalue()


def _request(target: str, path: str) -> str:
    return json.dumps({"target": target, "path": path}) + "\n"


def _protocol_issues() -> list[str]:
    issues: list[str] = []

    def noisy_replay(target: str, path: str) -> Replay:
        print("a decoder that prints must not reach the response stream")
        if path == "boom":
            return Replay({"status": "error", "error_class": "E", "detail": "d"}, "TRACE")
        return Replay({"status": "reject", "error_class": "X", "detail": target, "rule": None}, None)

    lines = [
        _request("record", "a"),
        "this is not json\n",
        json.dumps(["not", "an", "object"]) + "\n",
        json.dumps({"target": "record"}) + "\n",
        json.dumps({"target": 7, "path": "x"}) + "\n",
        _request("block_file", "boom"),
        _request("manifest_body", "b"),
    ]
    try:
        responses, stray = _serve_in_process(lines, noisy_replay)
    except Exception as e:  # noqa: BLE001 - a FAIL line, not a traceback out of main()
        # Raised rather than answered: the loop died on a request it should
        # have survived, or wrote a line that is not JSON. Escaping here would
        # abort the verifier with no `FAIL:` line and skip every section after
        # this one, REG included.
        return [f"the serve loop raised instead of answering: {type(e).__name__}: {e}"]

    if len(responses) != len(lines):
        return [f"{len(lines)} requests produced {len(responses)} response lines"]
    if [r.get("path") for r in responses] != ["a", None, None, None, None, "boom", "b"]:
        issues.append(f"responses do not echo their requests' paths in order: {responses}")
    bad = responses[1:5]
    if not all(r.get("status") == "error" and r.get("error_class") == BAD_REQUEST for r in bad):
        issues.append(f"a malformed request was not answered as {BAD_REQUEST}: {bad}")
    if responses[6].get("detail") != "manifest_body":
        issues.append("the loop did not go on answering after a malformed request")
    if responses[5].get("traceback") != "TRACE":
        issues.append(f"an internal error's traceback is not in its response: {responses[5]}")
    if "traceback" in responses[0]:
        issues.append("a verdict with no traceback grew a `traceback` key")
    if stray:
        issues.append(f"a printing decoder leaked into the caller's stdout: {stray!r}")
    return issues


def _run(args: list[str], stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_ENTRYPOINT), *args],
        input=stdin,
        capture_output=True,
        text=True,
        env={**os.environ, NESTED_ENV: "1"},
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )


def _equivalence_issues(inputs: list[tuple[str, Path]]) -> tuple[list[str], int]:
    issues: list[str] = []
    missing = sorted(set(DIFF_REPLAY_TARGETS) - {target for target, _ in inputs})
    if missing:
        issues.append(f"no committed input discovered for target(s) {missing}")

    try:
        served = _run(["--diff-replay-serve"], "".join(_request(t, str(p)) for t, p in inputs))
    except (OSError, subprocess.SubprocessError) as e:
        return issues + [f"--diff-replay-serve could not run: {e}"], 0
    if served.returncode != 0:
        return issues + [f"--diff-replay-serve exited {served.returncode}: {served.stderr.strip()}"], 0
    responses = served.stdout.splitlines()
    if len(responses) != len(inputs):
        return issues + [f"{len(inputs)} requests produced {len(responses)} response lines"], 0

    compared = 0
    for (target, path), line in zip(inputs, responses):
        where = f"[{target}] {path.name}"
        try:
            single = _run(["--diff-replay", target, str(path)])
            want = json.loads(single.stdout)
            got = json.loads(line)
        except subprocess.TimeoutExpired as e:
            # Every later input would wait out the same timeout: were
            # `--diff-replay` ever to fall through to the full verifier, that
            # is 50 x 120 s before this section reported anything.
            issues.append(f"{where}: could not compare, stopping here: {e}")
            break
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            issues.append(f"{where}: could not compare: {e}")
            continue
        if got.get("path") != str(path):
            issues.append(f"{where}: response echoes path {got.get('path')!r}")
        verdict = {k: v for k, v in got.items() if k not in SERVE_ONLY_KEYS}
        if verdict != want:
            issues.append(f"{where}: serve {verdict} != single-shot {want}")
        issues.extend(f"{where}: {issue}" for issue in _decoded_issues(single, want, verdict))
        compared += 1
    return issues, compared


def _decoded_issues(single: subprocess.CompletedProcess, want: dict, got: dict) -> list[str]:
    """Why a pair of IDENTICAL verdicts still compares nothing. Pure.

    Identity alone is not equivalence: if `replay_bytes` were broken -- a
    typo, an import or API break -- BOTH modes return the same `status:
    error` object, and this section printed `PASS 50 committed inputs ...
    serve verdict identical to single-shot` having decoded none of them
    (measured, #662 review). Every committed input is one the Rust replay
    requires a verdict for, so an `error` on either side, or a single-shot
    process that does not exit 0, is a failure here too.
    """
    issues = []
    if single.returncode != 0:
        issues.append(f"single-shot --diff-replay exited {single.returncode}")
    for mode, verdict in (("single-shot", want), ("serve", got)):
        if verdict.get("status") not in ("accept", "reject"):
            issues.append(f"{mode} decoded nothing: {verdict}")
    return issues


def section_diff_replay_serve() -> tuple[bool, list[str]]:
    if os.environ.get(NESTED_ENV):
        return False, [
            f"FAIL refusing to spawn: {NESTED_ENV} is set, so this verifier was itself "
            "started by Section DRS -- the mode it asked for was not recognised"
        ]
    lines: list[str] = []
    protocol = _protocol_issues()
    lines.append(
        "PASS serve protocol: one ordered response per request, malformed requests "
        "answered and survived, stray prints contained, tracebacks carried"
        if not protocol else f"FAIL serve protocol ({len(protocol)} issue(s))"
    )
    lines.extend(f"  {issue}" for issue in protocol)

    inputs = committed_inputs()
    equivalence, compared = _equivalence_issues(inputs)
    lines.append(
        f"PASS {compared} committed inputs over {len(DIFF_REPLAY_TARGETS)} targets: "
        "each decoded, serve verdict identical to single-shot"
        if not equivalence else f"FAIL equivalence ({len(equivalence)} issue(s))"
    )
    lines.extend(f"  {issue}" for issue in equivalence)
    return not (protocol or equivalence), lines
