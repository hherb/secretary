"""The two liveness proofs. Spec §5.1.

**BOTH are before/after COMPARISONS** — each takes one reading on the clean
tree, one after the substitution, and requires the two to DIFFER. That
symmetry is load-bearing and the Python half did not have it until the final
whole-branch review: it checked only a POST-condition (`observed ==
probe.equals`), so a no-op mutation (`TOKEN = "real"` -> `TOKEN = "real"  #
edited`) whose `equals` was copied from the `old` side of the spec reported
`live=True` and then `GREEN_AS_EXPECTED`. That is a false green of #644's own
class, emitted by the harness built to detect them, and it is reachable by one
plausible author error. A row whose observed value did not MOVE measured
nothing and is `NOT_LIVE`.

What the two proofs do NOT share is what a change PROVES, and the harness
reports which mechanism it used rather than implying they are equivalent:

* Python — strong. A fresh interpreter imports the module and evaluates the
  probe expression, before and after. This observes the value the interpreter
  BINDS, not the bytes in the file, which is what false-green mechanism 2
  defeated: a `token = ''` splice after a `class X:` header, silently
  overridden by the real assignment below the docstring.

* Rust — weaker. `cargo build --message-format=json` names the artifacts it
  produced; their CONTENT hash must change. This proves the compiler emitted
  different bytes. It does not prove the mutated expression is reached at
  runtime.

  **A further, structural limit, found while building `controls.py`'s `C10`
  (fix round 1) and independently confirmed and sharpened in fix round 2's
  review with a decisive experiment: two trailing comments of IDENTICAL
  length and line count but different bytes still change the artifact hash;
  two back-to-back builds of an untouched file are bit-identical; reverting
  reproduces the original hash exactly.** `rustc` embeds a whole-file
  content checksum into `.rmeta` for every `SourceFile` that contributes to
  the crate (used to validate debuginfo against source), independent of
  whether any exported item's span moved. Consequently: **no same-file
  textual edit to a file the crate's build graph actually reads can ever be
  `NOT_LIVE` under this liveness proof** — not "a comment placed badly", a
  property of the mechanism itself, since artifact bytes are a content
  function of the whole source file, not of which bytes an item's compiled
  behaviour depends on. This is the SAFE direction to be wrong in (it can
  only over-report liveness, never under-report it — a cosmetic edit reads
  as "live" rather than a semantically dead one reading as "not live"), but
  a reader deciding how much to trust a Rust `live=True` verdict needs to
  know it proves only "the compiler saw a byte change somewhere in this
  file", not "the mutated expression's behaviour changed". The only way to
  test a genuinely compiler-invisible Rust edit under this proof is to
  mutate a file the build graph does not read at all — see `C10`.

Never a source hash and never an mtime. mtime is the mechanism behind
false-green mechanism 1.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from mutation_harness.types import LivenessResult, PythonObservation, PythonProbe

MECHANISM_INTERPRETER = "interpreter"
MECHANISM_ARTIFACT = "artifact"

# Every subprocess this module spawns is bounded, for the same reason
# `run_gate` is: a probe or a build that never finishes must be reported as
# "nothing was measured", not left hanging a run that is otherwise expected
# to terminate. Both expiries are fail-CLOSED (`live=False`).
PROBE_TIMEOUT_SECONDS = 300
BUILD_TIMEOUT_SECONDS = 3600

# Sentinel keys `rust_artifact_hashes` may return INSTEAD of real artifact
# hashes. Both are recognised by `compare_rust_artifacts` before any set
# comparison, because neither is a measurement: a sentinel that merely
# differed from the other side would read as evidence of a change.
BUILD_FAILED = "<build-failed>"
BUILD_TIMED_OUT = "<build-timed-out>"

# Spec §5.2: applied uniformly, never a per-mutation judgement call. The
# mutation whose green must not be believed is precisely the size-preserving
# one that nobody flags as risky.
_NO_BYTECODE = {"PYTHONDONTWRITEBYTECODE": "1"}


class PycacheNotCleared(RuntimeError):
    """A `__pycache__` directory survived its removal attempt.

    This is fatal, not advisory: `clear_pycache` exists solely to defeat
    false-green mechanism 1 (a stale `.pyc` served under a bytecode cache
    whose invalidation key — `(source_mtime, size)` stored to whole SECONDS —
    a size-preserving mutation applied and reverted within one second can
    satisfy). A caller that believes the cache is clear when it is not is
    about to believe a probe or gate result that may have run against
    pre-mutation bytecode. Returning a count that overstates what was
    actually removed would make the one function guarding against this
    mechanism fail OPEN — the exact direction this project exists to avoid.
    """


def python_env() -> dict[str, str]:
    """The environment every Python subprocess runs under."""
    env = dict(os.environ)
    env.update(_NO_BYTECODE)
    return env


def clear_pycache(root: Path) -> int:
    """Remove every `__pycache__` under `root`. Returns how many were removed.

    CPython invalidates a `.pyc` on `(source_mtime, size)` with the mtime
    stored in whole SECONDS, so a size-preserving mutation applied and
    reverted inside one second is served from cache and never runs.
    """
    removed = 0
    for cache in Path(root).rglob("__pycache__"):
        if not cache.is_dir():
            continue
        shutil.rmtree(cache, ignore_errors=True)
        if cache.exists():
            # rmtree's return tells us nothing; the EXISTENCE CHECK is the
            # verdict. A cache that survives removal must not be silently
            # counted as cleared.
            raise PycacheNotCleared(
                f"could not remove {cache}; a stale .pyc could serve a "
                f"pre-mutation value and make a mutation result meaningless"
            )
        removed += 1
    return removed


_PROBE_SOURCE = """\
import sys
sys.path.insert(0, {syspath!r})
import {module} as _m
print(repr(eval({expr!r}, {{"__builtins__": __builtins__}}, vars(_m))))
"""


def observe_python(
    probe: PythonProbe, repo_root: Path, timeout: int = PROBE_TIMEOUT_SECONDS
) -> PythonObservation:
    """Take ONE reading of `probe.expr` in a fresh interpreter.

    The Python analogue of one `rust_artifact_hashes` call: a reading, not a
    verdict. `run_mutations` calls it twice — once on the clean tree, once
    after the substitution — and `compare_python_probe` decides.
    """
    # Defence in depth: `module` is spliced raw into the generated source
    # (unlike `syspath`/`expr`, which land inside `!r`-escaped literals), so
    # a `module` value is required to be a plain dotted identifier sequence
    # before it is ever allowed near the template. Specs are author-
    # controlled files in this repo, so this does not close a real threat
    # surface today (`expr` already reaches `eval`), but there is no reason
    # for `module` to be the one field with a different discipline.
    if not all(part.isidentifier() for part in probe.module.split(".")):
        return PythonObservation(
            ok=False,
            value="",
            error=f"probe module {probe.module!r} is not a dotted identifier",
        )
    syspath = str((Path(repo_root) / probe.syspath).resolve())
    source = _PROBE_SOURCE.format(syspath=syspath, module=probe.module, expr=probe.expr)
    try:
        proc = subprocess.run(
            ["python3", "-c", source],
            capture_output=True,
            text=True,
            cwd=str(repo_root),
            env=python_env(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return PythonObservation(
            ok=False, value="", error=f"probe did not finish within {timeout}s"
        )
    if proc.returncode != 0:
        return PythonObservation(
            ok=False, value="", error=f"probe failed to run: {proc.stderr.strip()[:400]}"
        )
    return PythonObservation(ok=True, value=proc.stdout.strip(), error="")


def compare_python_probe(
    probe: PythonProbe, before: PythonObservation, after: PythonObservation
) -> LivenessResult:
    """The value a fresh interpreter binds must have CHANGED, and changed to
    the value the spec declared.

    Two conditions, and `detail` always says which one failed:

    1. **It moved.** `before.value != after.value`. Checked FIRST, because a
       value that did not move measured nothing regardless of what it equals
       — and the specific way that used to pass is a no-op mutation whose
       `equals` was copied from the spec's `old` side, which satisfies
       condition 2 while proving nothing.
    2. **It moved to the declared value.** `after.value == repr(probe.equals)`.
       Without this, any incidental difference (an unrelated edit, a value
       carrying a timestamp) would read as the mutation having taken effect.

    A reading that could not be taken on EITHER side is `live=False`: a
    missing baseline is not evidence of a change.
    """
    if not before.ok:
        return LivenessResult(
            live=False,
            mechanism=MECHANISM_INTERPRETER,
            detail=f"the pre-mutation probe produced no value ({before.error}); "
                   f"there is no baseline to compare against",
        )
    if not after.ok:
        return LivenessResult(
            live=False,
            mechanism=MECHANISM_INTERPRETER,
            detail=f"the post-mutation probe produced no value ({after.error})",
        )
    if before.value == after.value:
        return LivenessResult(
            live=False,
            mechanism=MECHANISM_INTERPRETER,
            detail=f"the bound value did NOT change: the interpreter observed "
                   f"{after.value} both before and after the substitution, so this "
                   f"mutation measured nothing",
        )
    expected = repr(probe.equals)
    if after.value != expected:
        return LivenessResult(
            live=False,
            mechanism=MECHANISM_INTERPRETER,
            detail=f"the bound value changed {before.value} -> {after.value}, but the "
                   f"spec declared it would become {expected}",
        )
    return LivenessResult(
        True, MECHANISM_INTERPRETER, f"changed {before.value} -> {after.value}"
    )


def rust_artifact_hashes(
    package: str, repo_root: Path, timeout: int = BUILD_TIMEOUT_SECONDS
) -> dict[str, str]:
    """Build `package` and hash the CONTENTS of every artifact cargo names.

    Cargo's JSON gives absolute paths, so no globbing against the ~13,000
    files in `target/release/deps/` is needed. Verified during design: for
    `-p secretary-core` the set is `target/release/libsecretary_core.rlib`
    plus a hash-suffixed `.rmeta`.
    """
    try:
        proc = subprocess.run(
            ["cargo", "build", "--release", "-p", package, "--message-format=json"],
            capture_output=True,
            text=True,
            cwd=str(repo_root),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # A sentinel rather than `{}`: an empty dict is also what "cargo named
        # no artifacts" produces, and the two deserve different diagnostics.
        # Both are fail-CLOSED in `compare_rust_artifacts`.
        return {BUILD_TIMED_OUT: f"build did not finish within {timeout}s"}
    hashes: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        if package not in msg.get("package_id", ""):
            continue
        for filename in msg.get("filenames", []):
            path = Path(filename)
            if path.exists():
                hashes[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not hashes and proc.returncode != 0:
        # A build failure IS a live mutation signal, but a caller cannot tell
        # it apart from "cargo produced nothing", so say which happened.
        hashes[BUILD_FAILED] = hashlib.sha256(proc.stderr.encode()).hexdigest()
    return hashes


def compare_rust_artifacts(before: dict[str, str], after: dict[str, str]) -> LivenessResult:
    """The artifact set must differ. Identical bytes mean the mutation never
    reached the compiler.

    **An ABSENT side is `live=False`, not `live=True`** (final whole-branch
    review, Finding 6). An empty `before` with a non-empty `after` used to
    fall through to the "changed" arm and report the mutation live, which is
    the one fail-OPEN direction in this module: there was no baseline, so the
    difference is between a measurement and the absence of one. Narrow —
    `rust_artifact_hashes` returns a `BUILD_FAILED` sentinel rather than `{}`
    whenever cargo failed, so reaching it needs cargo to exit 0 while naming
    nothing — but the direction is what matters. Over-reporting liveness is
    exactly what #644 exists to stop; under-reporting it costs a re-run.
    """
    for label, side in (("pre-mutation", before), ("post-mutation", after)):
        if BUILD_TIMED_OUT in side:
            return LivenessResult(
                False, MECHANISM_ARTIFACT, f"the {label} cargo build {side[BUILD_TIMED_OUT]}"
            )
    absent = [label for label, side in (("pre-mutation", before), ("post-mutation", after))
              if not side]
    if absent:
        return LivenessResult(
            False,
            MECHANISM_ARTIFACT,
            f"cargo named no artifacts in the {' and '.join(absent)} build; "
            f"there is no baseline to compare against",
        )
    if before == after:
        return LivenessResult(
            False,
            MECHANISM_ARTIFACT,
            f"artifact contents unchanged across {len(after)} file(s)",
        )
    changed = sorted(
        Path(k).name for k in set(before) | set(after) if before.get(k) != after.get(k)
    )
    return LivenessResult(True, MECHANISM_ARTIFACT, f"changed: {', '.join(changed)}")
