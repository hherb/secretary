#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
r"""Assert the bridge's `test-support` feature is enabled ONLY from a
[dev-dependencies] section (#500).

WHY THIS EXISTS
---------------
`Detail::for_test` (`ffi/secretary-ffi-bridge/src/error/detail.rs`) can mint
a `Detail` from a runtime String. It is absent from non-test builds ONLY
because resolver v2 declines to unify a DEV-dependency's requested features
into them. Enabling `test-support` from anywhere else — a normal
`[dependencies]`/`[build-dependencies]` entry, a `[workspace.dependencies]`
entry, or a `[target.*.dependencies]` entry — puts the hatch into the
shipped artifact, and nothing else in CI would notice.

REWRITE HISTORY (#500 fix round 2)
-----------------------------------
The original guard was a line-based `awk` matcher over `find | Cargo.toml`.
An independent reviewer found three Important-severity bypasses, every one
of which still returns "OK" while placing `for_test` in `cargo build
--release`:

  I1 — line-based matching breaks on two valid TOML shapes: a `features`
       array split across multiple lines inside an inline table, and a
       table header (`[dependencies]`) indented with leading whitespace
       (the `/^\[/` anchor never fires, so the violating line gets
       attributed to the PREVIOUS section header instead).
  I2 — the WORST bypass, a single line that defeats the guard entirely:
       `default = ["test-support"]` in `[features]` is never matched
       because the line contains `test-support` but not the literal
       substring `features`. The same blind spot lets a DEPENDENT crate
       forward the feature through Cargo's `"<crate>/<feature>"` syntax
       (`extra = ["secretary-ffi-bridge/test-support"]`) — entirely
       independent of which section the dependency itself is declared in.
  I3 — `done < <(scan ...)` in the old script discarded the scan
       pipeline's exit status despite `set -euo pipefail`, so a
       nonexistent scan root printed a stray `find:` error to stderr and
       then reported "OK" with exit 0 — the exact fail-open class #496
       closed in the sibling error-payload guard ("a scan root whose path
       moved contributed zero files silently").
  M7 — run from the repo root (not a worktree), the old script's `find .`
       swept in every sibling `.worktrees/` and `.claude/worktrees/`
       checkout on disk, attributing another branch's manifest state to
       this one's scan.

This rewrite replaces the line-based matcher with `tomllib` (stdlib,
Python 3.11+) — a REAL TOML parser closes I1 as a class, since a parser has
no concept of "line" to get confused by. It adds an explicit check for
feature-list values (both `default = [...]` and forwarding syntax anywhere
in `[features]`) to close I2. It counts manifests scanned and fails closed
on zero to close I3. And it scans an EXPLICIT, hardcoded list of workspace
directories rather than the ambient repo root, so a sibling worktree's
Cargo.toml is never even opened, closing M7 the same way every other guard
in this repo (`ios/scripts/check-public-log-hygiene.sh`,
`android/scripts/check-log-hygiene.sh`) hardcodes its own scan root instead
of walking from an ambient cwd.

USAGE
-----
    uv run scripts/check-test-support-placement.py              # real scan
    uv run scripts/check-test-support-placement.py --self-test  # controls
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

FEATURE = "test-support"
FORWARD_SUFFIX = f"/{FEATURE}"

# Sections where declaring `features = [..., "test-support", ...]` on a
# dependency puts the hatch into a non-test build. `dev-dependencies` (and
# `target.*.dev-dependencies`) are deliberately ABSENT from this set — that
# is the one sanctioned place to enable the feature.
DENIED_DEP_SECTIONS = ("dependencies", "build-dependencies")

# Explicit, hardcoded scan roots (#500 M7) — never the ambient repo root.
# Every workspace member Cargo.toml lives under one of these directories
# (verified against the `[workspace] members` list in the root Cargo.toml);
# `.worktrees/` and `.claude/worktrees/` are siblings of these, not children,
# so an `rglob` rooted here never reaches them.
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ROOTS = [
    REPO_ROOT / "Cargo.toml",
    REPO_ROOT / "core",
    REPO_ROOT / "cli",
    REPO_ROOT / "desktop",
    REPO_ROOT / "ffi",
    REPO_ROOT / "browser",
    REPO_ROOT / "test-utils",
]


def iter_manifests(roots: list[Path]) -> list[Path]:
    """Every `Cargo.toml` reachable from `roots`, excluding build output.

    A root may be a file (the top-level `Cargo.toml`) or a directory (walked
    recursively). `target/` is excluded because a vendored or cached
    dependency's manifest is not something this repo's own placement policy
    governs.
    """
    manifests: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            manifests.append(root)
            continue
        for path in sorted(root.rglob("Cargo.toml")):
            if "target" in path.relative_to(root).parts:
                continue
            manifests.append(path)
    return manifests


def _feature_hits(spec: object) -> bool:
    """True if a dependency table's `features` list names FEATURE."""
    return isinstance(spec, dict) and FEATURE in (spec.get("features") or [])


def find_dependency_violations(data: dict, label: str) -> list[str]:
    """Direct `features = ["test-support"]` on a non-dev dependency edge.

    Covers top-level `[dependencies]` / `[build-dependencies]`,
    `[workspace.dependencies]`, and `[target.<spec>.dependencies]` /
    `[target.<spec>.build-dependencies]`. `[dev-dependencies]` and
    `[target.<spec>.dev-dependencies]` are intentionally never checked here
    — that is the sanctioned section.
    """
    hits: list[str] = []

    def scan_section(section: object, section_label: str) -> None:
        if not isinstance(section, dict):
            return
        for name, spec in section.items():
            if _feature_hits(spec):
                hits.append(f"{label}: [{section_label}] {name} enables '{FEATURE}'")

    for section_name in DENIED_DEP_SECTIONS:
        scan_section(data.get(section_name), section_name)

    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        scan_section(workspace.get("dependencies"), "workspace.dependencies")

    target = data.get("target")
    if isinstance(target, dict):
        for spec_key, spec_val in target.items():
            if not isinstance(spec_val, dict):
                continue
            for section_name in DENIED_DEP_SECTIONS:
                scan_section(
                    spec_val.get(section_name), f"target.{spec_key}.{section_name}"
                )

    return hits


def find_feature_table_violations(data: dict, label: str) -> list[str]:
    """`[features]` entries that turn `test-support` on without a consumer
    ever writing `[dev-dependencies]` at all (#500 I2).

    Two independent shapes, checked in EVERY feature list (not just
    `default`) because forwarding syntax works the same way regardless of
    which feature carries it — only the FIRST is default-specific:

    1. `default = [..., "test-support", ...]` — this crate defaults its own
       `test-support` feature on. Only meaningful on `secretary-ffi-bridge`
       itself, but checked on every manifest: a same-named feature on an
       unrelated crate is not a real bypass, and flagging it anyway is the
       conservative (fail-closed) choice for a guard whose false-positive
       cost is a one-line allowlist entry, not a shipped secret.
    2. `"<crate>/test-support"` anywhere in ANY feature's value list — the
       forwarding syntax that turns on `test-support` on the NAMED
       dependency whenever the CURRENT crate's feature is active. If that
       feature is reachable from `default`, the dependency's hatch is
       enabled by a plain `cargo build` with no `[dev-dependencies]`
       anywhere in sight.
    """
    hits: list[str] = []
    features = data.get("features")
    if not isinstance(features, dict):
        return hits
    for feature_name, values in features.items():
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str):
                continue
            if feature_name == "default" and value == FEATURE:
                hits.append(
                    f"{label}: [features] default directly includes '{FEATURE}'"
                )
            if value.endswith(FORWARD_SUFFIX):
                hits.append(
                    f"{label}: [features] {feature_name} forwards '{value}'"
                )
    return hits


def scan(roots: list[Path]) -> tuple[list[str], int]:
    """Return (violations, manifest_count) over every manifest under roots."""
    violations: list[str] = []
    manifests = iter_manifests(roots)
    for manifest in manifests:
        try:
            data = tomllib.loads(manifest.read_text())
        except tomllib.TOMLDecodeError as exc:
            violations.append(f"{manifest}: TOML PARSE ERROR — {exc}")
            continue
        label = str(manifest)
        violations.extend(find_dependency_violations(data, label))
        violations.extend(find_feature_table_violations(data, label))
    return violations, len(manifests)


def run_real_scan(roots: list[Path]) -> int:
    violations, count = scan(roots)
    # #500 I3: a scan root that silently contributed zero manifests must
    # FAIL, not report "OK" — the old script's fail-open hole.
    if count == 0:
        print("DENIED: zero Cargo.toml manifests scanned — scan root(s) moved "
              "or are wrong; a guard that finds nothing is indistinguishable "
              "from a guard that isn't running.")
        return 1
    if violations:
        for v in violations:
            print(f"DENIED: {v} — '{FEATURE}' may only be enabled from "
                  f"[dev-dependencies]")
        return 1
    print(f"test-support placement: OK ({count} manifests scanned)")
    return 0


# ---------------------------------------------------------------------------
# --self-test
# ---------------------------------------------------------------------------

# Positive controls: each MUST be denied. One per bypass class found in
# review, plus the original base case (a plain non-dev dependency entry) so
# the rewrite is proven not to have regressed it.
POSITIVE_FIXTURES: dict[str, str] = {
    "base_normal_dependency": """
[dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
    "default_feature_list": """
[features]
default = ["test-support"]
test-support = []
""",
    "crate_forwarded_feature": """
[dependencies]
secretary-ffi-bridge = { path = ".." }

[features]
extra = ["secretary-ffi-bridge/test-support"]
""",
    "multiline_inline_table_array": """
[dependencies]
secretary-ffi-bridge = { path = "..", features = [
  "test-support",
] }
""",
    "indented_table_header": """
  [dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
}

# Negative control: MUST pass. The one sanctioned shape.
NEGATIVE_FIXTURES: dict[str, str] = {
    "legit_dev_dependency": """
[dev-dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
}


def self_test() -> int:
    import tempfile

    fails = 0
    positive_ok = 0
    negative_ok = 0

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        for name, toml_text in POSITIVE_FIXTURES.items():
            case_dir = tmp_path / name
            case_dir.mkdir()
            (case_dir / "Cargo.toml").write_text(toml_text)
            violations, count = scan([case_dir])
            if count == 0:
                print(f"SELF-TEST FAIL: positive control {name!r} contributed "
                      f"zero manifests (fixture bug)")
                fails += 1
            elif not violations:
                print(f"SELF-TEST FAIL: known-positive control {name!r} was "
                      f"NOT denied")
                fails += 1
            else:
                positive_ok += 1

        for name, toml_text in NEGATIVE_FIXTURES.items():
            case_dir = tmp_path / name
            case_dir.mkdir()
            (case_dir / "Cargo.toml").write_text(toml_text)
            violations, count = scan([case_dir])
            if count == 0:
                print(f"SELF-TEST FAIL: negative control {name!r} contributed "
                      f"zero manifests (fixture bug)")
                fails += 1
            elif violations:
                print(f"SELF-TEST FAIL: known-negative control {name!r} was "
                      f"DENIED: {violations}")
                fails += 1
            else:
                negative_ok += 1

        # #500 I3: an empty root must FAIL (zero manifests), not report OK.
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        violations, count = scan([empty_dir])
        if count != 0:
            print("SELF-TEST FAIL: empty-root fixture unexpectedly contributed "
                  "manifests (fixture bug)")
            fails += 1
        elif run_real_scan([empty_dir]) == 0:
            print("SELF-TEST FAIL: zero-manifest root was NOT treated as a "
                  "failure (I3 fail-open regression)")
            fails += 1

    total_controls = len(POSITIVE_FIXTURES) + len(NEGATIVE_FIXTURES)
    if fails:
        print(f"test-support placement self-test: FAILED "
              f"({positive_ok}/{len(POSITIVE_FIXTURES)} positive, "
              f"{negative_ok}/{len(NEGATIVE_FIXTURES)} negative)")
        return 1
    print(f"test-support placement self-test: OK "
          f"({total_controls}/{total_controls} controls: "
          f"{positive_ok} positive, {negative_ok} negative; "
          f"plus 1 zero-manifest fail-closed check)")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    roots = [Path(p) for p in argv] if argv else DEFAULT_ROOTS
    return run_real_scan(roots)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
