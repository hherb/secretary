"""The two liveness proofs. Spec §5.1.

They are NOT of equal strength and the harness reports which one it used:

* Python — strong. A fresh interpreter imports the module and evaluates the
  probe expression. This observes the value the interpreter BINDS, not the
  bytes in the file, which is what false-green mechanism 2 defeated: a
  `token = ''` splice after a `class X:` header, silently overridden by the
  real assignment below the docstring.

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

from mutation_harness.types import LivenessResult, PythonProbe

MECHANISM_INTERPRETER = "interpreter"
MECHANISM_ARTIFACT = "artifact"

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


def probe_python(probe: PythonProbe, repo_root: Path) -> LivenessResult:
    """Assert a FRESH interpreter observes the mutated value."""
    # Defence in depth: `module` is spliced raw into the generated source
    # (unlike `syspath`/`expr`, which land inside `!r`-escaped literals), so
    # a `module` value is required to be a plain dotted identifier sequence
    # before it is ever allowed near the template. Specs are author-
    # controlled files in this repo, so this does not close a real threat
    # surface today (`expr` already reaches `eval`), but there is no reason
    # for `module` to be the one field with a different discipline.
    if not all(part.isidentifier() for part in probe.module.split(".")):
        return LivenessResult(
            False,
            MECHANISM_INTERPRETER,
            f"probe module {probe.module!r} is not a dotted identifier",
        )
    syspath = str((Path(repo_root) / probe.syspath).resolve())
    source = _PROBE_SOURCE.format(syspath=syspath, module=probe.module, expr=probe.expr)
    proc = subprocess.run(
        ["python3", "-c", source],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
        env=python_env(),
    )
    if proc.returncode != 0:
        return LivenessResult(
            live=False,
            mechanism=MECHANISM_INTERPRETER,
            detail=f"probe failed to run: {proc.stderr.strip()[:400]}",
        )
    observed = proc.stdout.strip()
    if observed == repr(probe.equals):
        return LivenessResult(True, MECHANISM_INTERPRETER, f"observed {observed}")
    return LivenessResult(
        live=False,
        mechanism=MECHANISM_INTERPRETER,
        detail=f"expected {probe.equals!r}, interpreter observed {observed}",
    )


def rust_artifact_hashes(package: str, repo_root: Path) -> dict[str, str]:
    """Build `package` and hash the CONTENTS of every artifact cargo names.

    Cargo's JSON gives absolute paths, so no globbing against the ~13,000
    files in `target/release/deps/` is needed. Verified during design: for
    `-p secretary-core` the set is `target/release/libsecretary_core.rlib`
    plus a hash-suffixed `.rmeta`.
    """
    proc = subprocess.run(
        ["cargo", "build", "--release", "-p", package, "--message-format=json"],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )
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
        hashes["<build-failed>"] = hashlib.sha256(proc.stderr.encode()).hexdigest()
    return hashes


def compare_rust_artifacts(before: dict[str, str], after: dict[str, str]) -> LivenessResult:
    """The artifact set must differ. Identical bytes mean the mutation never
    reached the compiler."""
    if not before and not after:
        return LivenessResult(
            False, MECHANISM_ARTIFACT, "cargo named no artifacts in either build"
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
