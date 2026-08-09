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
entry, a `[target.*.dependencies]` entry, or a Cargo feature ALIAS that
transitively enables it — puts the hatch into the shipped artifact, and
nothing else in CI would notice.

REWRITE HISTORY (#500 fix round 2)
-----------------------------------
The original guard was a line-based `awk` matcher over `find | Cargo.toml`.
An independent reviewer found three Important-severity bypasses, every one
of which still returns "OK" while placing `for_test` in `cargo build
--release`: I1 (line-based matching breaks on a multi-line `features` array
and an indented `[dependencies]` header), I2 (`default = ["test-support"]`
in `[features]` was never matched, and the same blind spot let a dependent
forward the feature via `"<crate>/test-support"`), I3 (a nonexistent scan
root silently contributed zero manifests and the script still printed "OK"
with exit 0), M7 (run from the repo root, `find .` swept in every sibling
`.worktrees/` checkout). Fixed by replacing the line-based matcher with
`tomllib` (I1), adding explicit `[features]`-table checks (I2), counting
manifests and failing closed on zero (I3), and scanning an explicit,
hardcoded root list (M7).

FIX ROUND 3 — two more Important findings, both from the SAME reviewer
------------------------------------------------------------------------
Finding A (I3 was only half closed, and the round-2 rewrite WIDENED it):
`iter_manifests` silently skipped any root that did not exist, and the
zero-manifest check only fired when EVERY root came up empty. The old
single-root script turned a missing root into a hard zero-manifest fail;
the round-2 rewrite's SEVEN hardcoded roots meant six could vanish (e.g. a
directory rename) while the seventh still contributed manifests, so the
guard read "OK" with most of the workspace silently unscanned:

    $ uv run scripts/check-test-support-placement.py ./NO_SUCH_ROOT ./clean
    test-support placement: OK (1 manifests scanned)      rc=0

Fixed: `find_missing_roots` is now checked FIRST and INDEPENDENTLY of the
manifest count — any nonexistent root is named individually and is always a
failure, whether or not other roots still contribute manifests. The
all-roots-zero check is kept as a second, independent failure mode.

Finding B (the guard matched a NAME, so a Cargo feature ALIAS defeated it —
the same root cause as I2, one level up the alias chain): `test-support`
could be re-exposed under any name via Cargo's ordinary feature-alias
mechanism, with the guard never noticing because it only ever compared
literal strings against the literal name `test-support`:

    # (a) one line in the bridge's own manifest, no consumer needed
    [features]
    default = ["hatch"]
    hatch = ["test-support"]

    # (b) a consumer requesting the alias from a normal dependency
    [dependencies]
    secretary-ffi-bridge = { path = "...", features = ["hatch"] }

Fixed: `build_feature_graph` computes, over EVERY scanned manifest
simultaneously, the fixed-point closure of which `[features]` keys
transitively reach `test-support` — via a direct listing, a same-crate
bare-name reference to an already-reached feature, or a `<crate>/<feature>`
forwarding reference into another crate's own closure. The closure is
monotonic (a feature is only ever ADDED to a crate's reachable set, never
removed), so the fixed point always exists and the iteration always
terminates without separate cycle bookkeeping — `a = ["b"], b = ["a"]`
simply never grows past empty unless one of them also reaches
`test-support` some other way. The three call sites that used to compare
against the literal string `"test-support"` (the `default` check, the
dependency-edge `features = [...]` check, and the cross-crate forwarding
check) now consult this closure instead, so an alias is exactly as visible
as the literal name.

Finding C (Minor, fixed): `ffi/secretary-ffi-bridge/Cargo.toml`'s
`[features]` comment pointed at the now-deleted `.sh` script; repointed at
this `.py` file in the same commit as this rewrite.

Finding D (Minor, fixed): `--self-test` used to print the real guard's own
"DENIED: zero Cargo.toml manifests scanned" line to stdout while probing
the I3 sub-check, immediately above its own "self-test: OK" line — in a CI
log that reads as a failure sitting right next to a pass. Internal
self-test probes that expect the guard to FAIL now run with stdout
captured (see `_quiet_scan_rc`), and only replay the capture if the
sub-check's own assertion fails, so a passing self-test's transcript is
just the self-test's own PASS/FAIL lines.

PARKED, NOT FIXED (lower severity, explicitly out of scope this round —
tracked so they are not silently forgotten):
  - `Path.rglob` does not follow directory symlinks, so a symlinked crate
    directory would be invisible to the scan.
  - Any path component literally named `target` is excluded wholesale by
    `iter_manifests`, which would also exclude a hypothetical real crate
    directory that happened to be named `target`.
Neither is touched by this round's changes; `iter_manifests`'s `target`
exclusion and its use of `rglob` are structurally unchanged from round 2.

USAGE
-----
    uv run scripts/check-test-support-placement.py              # real scan
    uv run scripts/check-test-support-placement.py --self-test  # controls
    uv run scripts/check-test-support-placement.py <root> ...   # custom roots
"""

from __future__ import annotations

import contextlib
import io
import sys
import tomllib
from pathlib import Path

FEATURE = "test-support"

# Sections where declaring `features = [..., "test-support", ...]` (or an
# ALIAS that reaches it — see `build_feature_graph`) on a dependency puts
# the hatch into a non-test build. `dev-dependencies` (and
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


def find_missing_roots(roots: list[Path]) -> list[Path]:
    """Roots that do not exist on disk (#500 Finding A).

    Checked independently of manifest count: a root that vanished (renamed
    directory, typo, moved crate) must fail EVEN IF other roots still
    contribute manifests — a partial scan reading "OK" is worse than an
    obviously-broken one, because nothing else in CI would notice the gap.
    """
    return [r for r in roots if not r.exists()]


def iter_manifests(roots: list[Path]) -> list[Path]:
    """Every `Cargo.toml` reachable from `roots`, excluding build output.

    A root may be a file (the top-level `Cargo.toml`) or a directory (walked
    recursively). `target/` is excluded because a vendored or cached
    dependency's manifest is not something this repo's own placement policy
    governs. A missing root silently contributes nothing here — callers
    that need to know WHY must pair this with `find_missing_roots`; `scan`
    below does exactly that.
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


def _crate_name(data: dict, manifest: Path) -> str:
    """The name a dependency edge would use to refer to this manifest's
    crate, i.e. `[package].name`. A manifest with no `[package]` table (a
    virtual workspace-only `Cargo.toml`, or a bare self-test fixture that
    only cares about ITS OWN closure) defines no crate identity that any
    OTHER manifest could depend on; it gets a synthetic, per-path key so it
    still participates in its own same-file closure without ever being
    mistaken for a real crate by a `<crate>/<feature>` forwarding lookup.
    """
    pkg = data.get("package")
    if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
        return pkg["name"]
    return f"<no-package:{manifest}>"


def build_feature_graph(parsed: list[tuple[Path, dict]]) -> dict[str, set[str]]:
    """Fixed-point closure, computed over ALL scanned manifests together:
    for every crate, which of ITS OWN `[features]` keys transitively enable
    `test-support` (#500 Finding B).

    A feature `F` defined in crate `C`'s `[features]` table is added to
    `reaches[C]` if any one of its listed values is:
      - the literal string `test-support` (the base case), or
      - a bare name (no `/`) that is ALREADY in `reaches[C]` — a same-crate
        reference to a feature that itself reaches, or
      - `<other_crate>/<other_feature>` (Cargo's forwarding syntax, `?`
        weak-dependency prefix stripped) where `other_feature` is
        `test-support` itself or is already in `reaches[other_crate]`.

    This only ever ADDS members to a set, never removes one, so repeating
    the pass until nothing changes always reaches a fixed point — a mutual
    reference (`a = ["b"], b = ["a"]`) just never grows past empty unless
    one of them separately reaches `test-support`, with no special cycle
    detection required.
    """
    crate_features: dict[str, dict[str, list[str]]] = {}
    for manifest, data in parsed:
        name = _crate_name(data, manifest)
        features = data.get("features")
        if not isinstance(features, dict):
            continue
        table = crate_features.setdefault(name, {})
        for fname, values in features.items():
            if isinstance(values, list):
                table[fname] = [v for v in values if isinstance(v, str)]

    reaches: dict[str, set[str]] = {name: set() for name in crate_features}
    changed = True
    while changed:
        changed = False
        for crate, feats in crate_features.items():
            for fname, values in feats.items():
                if fname in reaches[crate]:
                    continue
                for value in values:
                    if value == FEATURE:
                        reaches[crate].add(fname)
                        changed = True
                        break
                    if "/" in value:
                        dep_crate, _, dep_feat = value.partition("/")
                        dep_crate = dep_crate.rstrip("?")
                        if dep_feat == FEATURE or dep_feat in reaches.get(dep_crate, set()):
                            reaches[crate].add(fname)
                            changed = True
                            break
                    elif value in reaches[crate]:
                        reaches[crate].add(fname)
                        changed = True
                        break
    return reaches


def _feature_hits(spec: object, reaches: dict[str, set[str]], dep_name: str) -> list[str]:
    """Which of a dependency entry's requested `features` are `test-support`
    itself, or reach it via `dep_name`'s own closure (#500 Finding B)."""
    if not isinstance(spec, dict):
        return []
    requested = spec.get("features")
    if not isinstance(requested, list):
        return []
    dep_reaches = reaches.get(dep_name, set())
    return [
        f for f in requested
        if isinstance(f, str) and (f == FEATURE or f in dep_reaches)
    ]


def find_dependency_violations(
    data: dict, label: str, reaches: dict[str, set[str]]
) -> list[str]:
    """`features = [...]` on a non-dev dependency edge that names
    `test-support` directly OR names an alias whose closure reaches it.

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
            hit_feats = _feature_hits(spec, reaches, name)
            if hit_feats:
                hits.append(
                    f"{label}: [{section_label}] {name} requests {hit_feats!r} "
                    f"(reaches '{FEATURE}')"
                )

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


def find_feature_table_violations(
    data: dict, label: str, crate_name: str, reaches: dict[str, set[str]]
) -> list[str]:
    """`[features]` entries that turn `test-support` on without a consumer
    ever writing `[dev-dependencies]` at all (#500 I2, generalized to
    aliases by Finding B).

    1. `default`'s closure reaching `test-support` — directly or via any
       chain of same-crate / cross-crate aliases. Only load-bearing on
       `secretary-ffi-bridge`'s own manifest, but checked on every manifest
       for the same fail-closed reason as round 2: a coincidentally-named
       feature elsewhere costs a one-line allowlist entry, not a missed
       real bypass.
    2. Any feature list value using `<crate>/<feature>` forwarding syntax
       where `<feature>` is `test-support` itself or reaches it via
       `<crate>`'s own closure — regardless of whether the forwarding
       feature is itself reachable from `default`, matching round 2's
       original scope (a non-default, explicitly-requested forward is
       still a bypass of the "only `[dev-dependencies]`" rule).
    """
    hits: list[str] = []
    features = data.get("features")
    if not isinstance(features, dict):
        return hits

    if "default" in reaches.get(crate_name, set()):
        hits.append(f"{label}: [features] default's closure reaches '{FEATURE}'")

    for feature_name, values in features.items():
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str) or "/" not in value:
                continue
            dep_crate, _, dep_feat = value.partition("/")
            dep_crate = dep_crate.rstrip("?")
            if dep_feat == FEATURE or dep_feat in reaches.get(dep_crate, set()):
                hits.append(
                    f"{label}: [features] {feature_name} forwards '{value}' "
                    f"(reaches '{FEATURE}')"
                )

    return hits


def scan(roots: list[Path]) -> tuple[list[str], int, list[Path]]:
    """Return (violations, manifest_count, missing_roots) over `roots`."""
    missing = find_missing_roots(roots)
    manifest_paths = iter_manifests(roots)

    parsed: list[tuple[Path, dict]] = []
    violations: list[str] = []
    for manifest in manifest_paths:
        try:
            data = tomllib.loads(manifest.read_text())
        except tomllib.TOMLDecodeError as exc:
            violations.append(f"{manifest}: TOML PARSE ERROR — {exc}")
            continue
        parsed.append((manifest, data))

    reaches = build_feature_graph(parsed)

    for manifest, data in parsed:
        label = str(manifest)
        crate_name = _crate_name(data, manifest)
        violations.extend(find_dependency_violations(data, label, reaches))
        violations.extend(
            find_feature_table_violations(data, label, crate_name, reaches)
        )

    return violations, len(manifest_paths), missing


def run_real_scan(roots: list[Path]) -> int:
    violations, count, missing = scan(roots)
    fail = False

    # #500 Finding A: a missing root is ALWAYS a failure, named individually
    # — independent of whether other roots still contributed manifests.
    if missing:
        for m in missing:
            print(f"DENIED: scan root does not exist: {m} — a moved or "
                  f"renamed directory must not silently drop coverage")
        fail = True

    # #500 I3: a scan that contributed zero manifests overall must FAIL,
    # not report "OK" — kept as an independent check from the one above
    # (every root can individually exist yet contain no Cargo.toml).
    if count == 0:
        print("DENIED: zero Cargo.toml manifests scanned — scan root(s) moved "
              "or are wrong; a guard that finds nothing is indistinguishable "
              "from a guard that isn't running.")
        fail = True

    if violations:
        for v in violations:
            print(f"DENIED: {v} — '{FEATURE}' may only be enabled from "
                  f"[dev-dependencies]")
        fail = True

    if fail:
        return 1
    print(f"test-support placement: OK ({count} manifests scanned)")
    return 0


def _quiet_scan_rc(roots: list[Path]) -> tuple[int, str]:
    """Run `run_real_scan` with stdout captured, returning (rc, captured).

    Used by `--self-test`'s sub-checks that deliberately trigger a FAILURE
    to prove the guard notices — their own "DENIED: ..." output is not
    something that should appear in a passing self-test's transcript
    (#500 Finding D). Callers print the capture only when the assertion
    they were probing for itself fails, so a genuine bug is still visible.
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = run_real_scan(roots)
    return rc, buf.getvalue()


# ---------------------------------------------------------------------------
# --self-test
# ---------------------------------------------------------------------------

# Positive controls: each MUST be denied. `dict[case] = {relative_path: toml
# text}` so a case can span more than one manifest (needed for Finding B's
# cross-crate alias controls).
POSITIVE_FIXTURES: dict[str, dict[str, str]] = {
    "base_normal_dependency": {
        "Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
    },
    "default_feature_list": {
        "Cargo.toml": """
[features]
default = ["test-support"]
test-support = []
""",
    },
    "crate_forwarded_feature": {
        "Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = ".." }

[features]
extra = ["secretary-ffi-bridge/test-support"]
""",
    },
    "multiline_inline_table_array": {
        "Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "..", features = [
  "test-support",
] }
""",
    },
    "indented_table_header": {
        "Cargo.toml": """
  [dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
    },
    # --- Finding B: alias-of-test-support bypasses ---
    "alias_default_reaches": {
        # (a) One file, no consumer needed: `default` reaches `test-support`
        # through a same-crate alias hop (`hatch`).
        "Cargo.toml": """
[features]
default = ["hatch"]
hatch = ["test-support"]
test-support = []
""",
    },
    "alias_requested_by_dependent": {
        # (b) A consumer requests the ALIAS (not `test-support` itself) on
        # a plain `[dependencies]` edge; the bridge's own manifest defines
        # the alias. Two files, one shared scan root.
        "bridge/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
hatch = ["test-support"]
test-support = []
""",
        "consumer/Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "../bridge", features = ["hatch"] }
""",
    },
    "alias_forwarded_by_dependent": {
        # Finding B names THREE sites needing the closure treatment: the
        # `default` check, the dependency-edge check (control above), and
        # the cross-crate `<crate>/<feature>` FORWARDING check. This is the
        # dedicated control for the third: a consumer forwards the ALIAS
        # (not `test-support` itself) through its own `[features]` table,
        # never requesting it directly on the dependency edge.
        "bridge/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
hatch = ["test-support"]
test-support = []
""",
        "consumer/Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "../bridge" }

[features]
extra = ["secretary-ffi-bridge/hatch"]
""",
    },
}

# Negative controls: each MUST pass.
NEGATIVE_FIXTURES: dict[str, dict[str, str]] = {
    "legit_dev_dependency": {
        "Cargo.toml": """
[dev-dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
    },
    # Finding B's false-positive guard: an alias chain that does NOT reach
    # `test-support` must not be flagged, even in the same two-file shape
    # as the positive `alias_requested_by_dependent` control above.
    "alias_chain_not_reaching": {
        "bridge/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
unrelated = []
test-support = []
""",
        "consumer/Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "../bridge", features = ["unrelated"] }
""",
    },
}


def _write_fixture(case_dir: Path, files: dict[str, str]) -> None:
    for rel_path, text in files.items():
        target = case_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)


def self_test() -> int:
    import tempfile

    fails = 0
    positive_ok = 0
    negative_ok = 0

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        for name, files in POSITIVE_FIXTURES.items():
            case_dir = tmp_path / name
            case_dir.mkdir()
            _write_fixture(case_dir, files)
            violations, count, missing = scan([case_dir])
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

        for name, files in NEGATIVE_FIXTURES.items():
            case_dir = tmp_path / name
            case_dir.mkdir()
            _write_fixture(case_dir, files)
            violations, count, missing = scan([case_dir])
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

        # #500 I3 (zero-manifest fail-closed): an empty root must FAIL, not
        # report OK. Output captured — this is an EXPECTED failure being
        # probed for, not a self-test failure (#500 Finding D).
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        violations, count, missing = scan([empty_dir])
        if count != 0:
            print("SELF-TEST FAIL: empty-root fixture unexpectedly contributed "
                  "manifests (fixture bug)")
            fails += 1
        else:
            rc, captured = _quiet_scan_rc([empty_dir])
            if rc == 0:
                print("SELF-TEST FAIL: zero-manifest root was NOT treated as a "
                      "failure (I3 fail-open regression)")
                print(captured)
                fails += 1

        # #500 Finding A: a single missing root among several PRESENT,
        # CLEAN ones must still fail the whole scan, and must name the
        # missing root. Output captured for the same reason as above.
        clean_dir = tmp_path / "finding_a_clean"
        clean_dir.mkdir()
        _write_fixture(clean_dir, {"Cargo.toml": "[dev-dependencies]\n"})
        missing_root = tmp_path / "finding_a_DOES_NOT_EXIST"
        rc, captured = _quiet_scan_rc([missing_root, clean_dir])
        if rc == 0:
            print("SELF-TEST FAIL: a missing root among present ones was NOT "
                  "treated as a failure (Finding A regression)")
            print(captured)
            fails += 1
        elif str(missing_root) not in captured:
            print("SELF-TEST FAIL: missing-root failure did not NAME the "
                  "missing root")
            print(captured)
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
          f"plus 1 zero-manifest and 1 missing-root fail-closed check)")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    roots = [Path(p) for p in argv] if argv else DEFAULT_ROOTS
    return run_real_scan(roots)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
