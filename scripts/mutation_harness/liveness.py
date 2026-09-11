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

from mutation_harness.types import LivenessResult, PythonProbe, RustProbe

MECHANISM_INTERPRETER = "interpreter"
MECHANISM_ARTIFACT = "artifact"

# Spec §5.2: applied uniformly, never a per-mutation judgement call. The
# mutation whose green must not be believed is precisely the size-preserving
# one that nobody flags as risky.
_NO_BYTECODE = {"PYTHONDONTWRITEBYTECODE": "1"}


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
        if cache.is_dir():
            shutil.rmtree(cache, ignore_errors=True)
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
