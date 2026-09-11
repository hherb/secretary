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

**The two proofs classify a mutation that BREAKS the module oppositely, on
purpose, and both directions are pinned** (PR #652 review). A Python
mutation that makes the module unimportable yields no post-reading, so the
row is `NOT_LIVE`: the proof's contract is "the bound value moved to the
declared value", and with no value there is nothing to compare — under-
reporting costs a re-run, which is the safe direction. A Rust mutation that
makes the crate fail to BUILD is `live=True`: the compiler demonstrably saw
the change, and there is no declared value to miss. A build that fails on
the CLEAN tree is neither — it is an absent baseline, `NOT_LIVE` whatever
the mutated build does.

Never a source hash and never an mtime. mtime is the mechanism behind
false-green mechanism 1.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from mutation_harness.subproc import run_bounded
from mutation_harness.types import (
    LivenessResult, PythonObservation, PythonProbe, RustObservation, RustReadingKind,
)

# Every subprocess this module spawns is bounded, for the same reason
# `run_gate` is: a probe or a build that never finishes must be reported as
# "nothing was measured", not left hanging a run that is otherwise expected
# to terminate. Both expiries are fail-CLOSED (`live=False`).
PROBE_TIMEOUT_SECONDS = 300
BUILD_TIMEOUT_SECONDS = 3600

# Spec §5.2: applied uniformly, never a per-mutation judgement call. The
# mutation whose green must not be believed is precisely the size-preserving
# one that nobody flags as risky. `PYTHONDONTWRITEBYTECODE=1` stops WRITES;
# `PYTHONPYCACHEPREFIX` is REMOVED because with it set CPython reads bytecode
# from a mirror tree OUTSIDE the repo, which `clear_pycache` never sweeps — a
# stale `.pyc` there would survive every sweep and false-green mechanism 1
# would be back for any user who sets that variable (PR #652 review).
_NO_BYTECODE = {"PYTHONDONTWRITEBYTECODE": "1"}
_BYTECODE_RELOCATORS = ("PYTHONPYCACHEPREFIX",)


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
    for key in _BYTECODE_RELOCATORS:
        env.pop(key, None)
    env.update(_NO_BYTECODE)
    return env


def clear_pycache(root: Path) -> int:
    """Remove every `__pycache__` under `root`. Returns how many were removed.

    CPython invalidates a `.pyc` on `(source_mtime, size)` with the mtime
    stored in whole SECONDS, so a size-preserving mutation applied and
    reverted inside one second is served from cache and never runs.

    LIMIT: `Path.rglob` does not descend into symlinked directories and
    silently skips directories it cannot read, so a cache reachable only
    through either is neither removed nor reported (#653; the same `rglob`
    gap `payload_guard` records as #510).
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

    The child is `sys.executable`, the interpreter running the harness, not
    whatever `python3` is first on `PATH`: under `uv run` the two coincide,
    and anywhere else the probe would silently measure a different Python
    from the one the gate runs under.
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
    run = run_bounded(
        [sys.executable, "-c", source], cwd=repo_root, env=python_env(), timeout=timeout
    )
    if run.timed_out:
        return PythonObservation(
            ok=False, value="", error=f"probe did not finish within {timeout}s"
        )
    if run.returncode != 0:
        return PythonObservation(
            ok=False, value="", error=f"probe failed to run: {run.stderr.strip()[:400]}"
        )
    value = run.stdout.strip()
    if not value:
        # A module that swallows stdout, or exits 0 at import time, prints
        # nothing; an empty string is not a reading and must not become a
        # baseline that any later value "moves away from".
        return PythonObservation(ok=False, value="", error="probe printed no value")
    return PythonObservation(ok=True, value=value, error="")


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
    missing baseline is not evidence of a change, and a module the mutation
    made unimportable yields no value to compare (see the module docstring
    for why that is the opposite of the Rust ruling, deliberately).
    """
    if not before.ok:
        return LivenessResult(
            live=False,
            detail=f"the pre-mutation probe produced no value ({before.error}); "
                   f"there is no baseline to compare against",
        )
    if not after.ok:
        return LivenessResult(
            live=False,
            detail=f"the post-mutation probe produced no value ({after.error})",
        )
    if before.value == after.value:
        return LivenessResult(
            live=False,
            detail=f"the bound value did NOT change: the interpreter observed "
                   f"{after.value} both before and after the substitution, so this "
                   f"mutation measured nothing",
        )
    expected = repr(probe.equals)
    if after.value != expected:
        return LivenessResult(
            live=False,
            detail=f"the bound value changed {before.value} -> {after.value}, but the "
                   f"spec declared it would become {expected}",
        )
    return LivenessResult(True, f"changed {before.value} -> {after.value}")


def package_id_names(package_id: str, package: str) -> bool:
    """Does cargo's `package_id` denote exactly `package`?

    The spellings cargo's `PackageIdSpec` documents. Cargo >= 1.77 emits a
    URL-shaped id — `<source>#<name>@<version>`, or `<source>#<version>`
    when the source URL's last path segment IS the name (`path+file:///…/
    mutdemo#0.0.0`, `git+https://…/serde?branch=master#1.0.0`, with the
    segment percent-decoded and a trailing `.git` dropped); older cargo
    emits `<name> <version> (<source>)`. The first version tested
    `package in package_id`, a substring match that `secretary-core-fuzz`
    satisfies for `secretary-core` and `core` satisfies for everything; its
    successor read the last path segment WITH the query string attached. A
    spelling this still misses fails CLOSED — the artifact is simply not
    counted, and an empty reading is `NOT_LIVE`.
    """
    if "#" in package_id:
        source, _, tail = package_id.rpartition("#")
        if "@" in tail:
            name = tail.split("@", 1)[0]
        else:
            segment = urlsplit(source).path.rstrip("/").rsplit("/", 1)[-1]
            name = unquote(segment).removesuffix(".git")
        return name == package
    return package_id.split(" ", 1)[0] == package


def rust_artifact_hashes(
    package: str, repo_root: Path, timeout: int = BUILD_TIMEOUT_SECONDS
) -> RustObservation:
    """Build `package` and hash the CONTENTS of every artifact cargo names.

    Cargo's JSON gives absolute paths, so no globbing against the ~13,000
    files in `target/release/deps/` is needed. Verified during design: for
    `-p secretary-core` the set is `target/release/libsecretary_core.rlib`
    plus a hash-suffixed `.rmeta`.

    Only an exit-0 build whose every named artifact could be read is a
    measurement. A non-zero exit is `BUILD_FAILED` even if cargo named some
    artifacts on the way down (the first version consulted the exit code only
    when the artifact map was EMPTY, so a failed build that had already
    emitted a build-script binary read as a successful measurement); an
    artifact cargo named but that is gone or unreadable when hashed is
    `ARTIFACT_MISSING`, not a silently shorter map (which a parallel cargo run
    rewriting `target/` between the two readings produced, and which the set
    comparison then reported as "changed").
    """
    run = run_bounded(
        ["cargo", "build", "--release", "-p", package, "--message-format=json"],
        cwd=repo_root,
        env=None,
        timeout=timeout,
    )
    if run.timed_out:
        return RustObservation(
            RustReadingKind.BUILD_TIMED_OUT, detail=f"did not finish within {timeout}s"
        )
    if run.returncode != 0:
        stderr_digest = hashlib.sha256(run.stderr.encode()).hexdigest()[:16]
        return RustObservation(
            RustReadingKind.BUILD_FAILED,
            detail=f"failed (cargo exited {run.returncode}; stderr sha256 {stderr_digest}…)",
        )
    hashes: dict[str, str] = {}
    for line in run.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        if not package_id_names(msg.get("package_id", ""), package):
            continue
        for filename in msg.get("filenames", []):
            try:
                data = Path(filename).read_bytes()
            except OSError as exc:
                return RustObservation(
                    RustReadingKind.ARTIFACT_MISSING,
                    detail=f"named {filename} but it could not be read ({exc})",
                )
            hashes[filename] = hashlib.sha256(data).hexdigest()
    return RustObservation(RustReadingKind.ARTIFACTS, hashes)


def compare_rust_artifacts(before: RustObservation, after: RustObservation) -> LivenessResult:
    """The artifact CONTENTS must differ, over the SAME artifact set.

    Dispatch is on `kind` before any hash is looked at (PR #652 review, the
    Critical): the first version recognised `BUILD_TIMED_OUT` and emptiness
    and nothing else, so a `BUILD_FAILED` baseline fell through to the set
    comparison, and two failing builds whose stderr differed — a shifted
    line number in a diagnostic, a "Blocking waiting for file lock" line from
    a parallel session — scored `live=True` with no artifact ever produced.

    * A `before` that is not a measurement is an ABSENT BASELINE: `live=False`
      whatever `after` is. There is nothing to have moved away from.
    * An `after` that FAILED TO BUILD is `live=True` — the compiler saw the
      change (the deliberate asymmetry with the Python proof; see the module
      docstring). An `after` that timed out or lost an artifact is not a
      reading: `live=False`.
    * Two measurements over DIFFERENT artifact sets are not comparable: a
      set change is a build-graph or `target/` event, not this mutation's
      effect, and reporting it as "changed" was the second fail-open.
    """
    if not before.is_measurement:
        return LivenessResult(
            live=False,
            detail=f"the pre-mutation cargo build {before.detail}; "
                   f"there is no baseline to compare against",
        )
    if after.kind is RustReadingKind.BUILD_FAILED:
        return LivenessResult(
            live=True, detail=f"the mutated tree no longer builds: the post-mutation cargo build {after.detail}"
        )
    if not after.is_measurement:
        return LivenessResult(live=False, detail=f"the post-mutation cargo build {after.detail}")
    if not before.hashes:
        return LivenessResult(
            live=False,
            detail="cargo named no artifacts in the pre-mutation build; "
                   "there is no baseline to compare against",
        )
    if not after.hashes:
        return LivenessResult(
            live=False,
            detail="cargo named no artifacts in the post-mutation build; "
                   "nothing was measured after the substitution",
        )
    if set(before.hashes) != set(after.hashes):
        only_before = sorted(Path(k).name for k in set(before.hashes) - set(after.hashes))
        only_after = sorted(Path(k).name for k in set(after.hashes) - set(before.hashes))
        return LivenessResult(
            live=False,
            detail=f"the artifact SET changed rather than artifact contents "
                   f"(only before: {only_before}; only after: {only_after}); that is a "
                   f"build-graph or target/ event, not a measurement of this mutation",
        )
    if before.hashes == after.hashes:
        return LivenessResult(
            live=False,
            detail=f"artifact contents unchanged across {len(after.hashes)} file(s)",
        )
    changed = sorted(
        Path(k).name for k in before.hashes if before.hashes[k] != after.hashes[k]
    )
    return LivenessResult(True, f"changed: {', '.join(changed)}")
