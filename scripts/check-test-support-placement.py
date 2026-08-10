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
monotonic (a feature is only ever ADDED to a reachable set, never removed),
so the fixed point always exists and the iteration always terminates
without separate cycle bookkeeping — `a = ["b"], b = ["a"]` simply never
grows past empty unless one of them also reaches `test-support` some other
way. The three call sites that used to compare against the literal string
`"test-support"` (the `default` check, the dependency-edge `features = [...]`
check, and the cross-crate forwarding check) now consult this closure
instead, so an alias is exactly as visible as the literal name.

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

FIX ROUND 4 — two more Important findings; both are the closure keying on
the WRONG THING, at opposite ends of a dependency edge
------------------------------------------------------------------------
Finding R1 (a REGRESSION round 3 introduced). Round 2 checked
`default = [...]` with a per-manifest literal compare. Round 3 routed that
check through the new GLOBAL closure map, which was keyed on
`[package].name` and merged every same-named manifest's `[features]` table
with last-writer-wins (`table[fname] = ...`). A second scanned manifest
declaring the SAME package name and REDECLARING the feature therefore
ERASED the first one's definition:

    # aa_bridge/Cargo.toml            # zz_shadow/Cargo.toml
    [package]                         [package]
    name = "secretary-ffi-bridge"     name = "secretary-ffi-bridge"
    [features]                        [features]
    default = ["test-support"]        default = []
    test-support = []

    round 3: OK (2 manifests scanned)   rc=0        <-- hatch ships

Order-dependent (denies if the shadow sorts first, passes if it sorts
last), and exploitable in-tree: scan roots are walked in `DEFAULT_ROOTS`
order, non-workspace-members ARE scanned (`core/fuzz` is one), so a shadow
manifest parked under the workspace `exclude` list keeps `cargo build
--release --workspace` green. It also bit as a FALSE POSITIVE — in the
order that did deny, BOTH manifests were flagged, including the innocent
one.

Fixed on two independent axes, deliberately belt-and-braces because either
one alone leaves a residue:

  1. The closure is now keyed by MANIFEST PATH. Nothing merges, so nothing
     can be erased, and the `default` check consults the reaches-set of the
     manifest it is reporting on — which also ends the mis-attribution.
     Cross-crate lookups (a dependency edge, a `<crate>/<feature>` forward)
     resolve a NAME rather than a path, so for those the guard takes the
     UNION over every manifest declaring that name: fail-closed, since a
     shadow that redeclares an alias as empty must not be able to mask a
     sibling that defines it as reaching (that is R1 again, one level out —
     see the `r1_dup_name_shadow_cross_crate` control).
  2. A duplicate `[package].name` among the scanned manifests is ITSELF
     denied. FAIL-CLOSED was chosen over silently unioning: with two
     manifests claiming one crate name the guard cannot tell which of them
     a dependency edge resolves to, and Cargo cannot either within one
     workspace. The real tree has eleven manifests and eleven distinct
     names (one virtual root with no `[package]`), so this denies a shape
     that does not legitimately occur here. Union (1) still runs, so the
     closure stays correct even if a future allowlist ever exempts a
     duplicate.

Finding R2 (dependency RENAMING evades the closure). Cargo dependency
edges and `dep/feat` forwarding strings key on the DEPENDENCY KEY, which
`package = "..."` renames. The closure keyed on `[package].name`, so both
of these passed:

    mybridge = { path = "...", package = "secretary-ffi-bridge",
                 features = ["hatch"] }
    x = ["mybridge/hatch"]        # in a [features] table

Fixed: `build_rename_map` reads `package = "..."` out of EVERY dependency
table in a manifest (dev included — this is name RESOLUTION, not a policy
decision about which section is sanctioned) and `resolve_dep_names`
resolves a dependency key to its candidate package names before any lookup
into the closure. The key itself always stays in the candidate set, so an
alias that shadows a real crate name is checked BOTH ways (fail-closed).

Self-found while fixing R1: making a duplicate `[package].name` a DENIAL
introduced a false positive of its own, because `iter_manifests` had no
reason to de-duplicate before. Two OVERLAPPING scan roots (`… core
core/fuzz`) read one manifest twice, which then read as two manifests
declaring the same package name. `iter_manifests` now de-duplicates by
resolved path; the `overlapping-root` self-test sub-check pins it, and
mutation M17 confirms that sub-check is not vacuous.

LIMITS (round 4 — stated precisely, because the most repeated review
finding on this branch was documentation claiming more than the code does)
------------------------------------------------------------------------
  - `Path.rglob` does not follow directory symlinks, so a symlinked crate
    directory is invisible to the scan. Unchanged since round 2.
  - Any path component literally named `target` is excluded wholesale by
    `iter_manifests`, which would also exclude a hypothetical real crate
    directory named `target`. Unchanged since round 2.
  - The scan reads MANIFESTS, not `cargo metadata`. A feature enabled by a
    manifest OUTSIDE `DEFAULT_ROOTS` (a path dependency pointing out of the
    repo, a `[patch]` redirect, a git dependency) is not seen. The roots
    are the trust boundary; `find_missing_roots` is what keeps them honest.
  - `[workspace.dependencies]` is treated as non-dev. Cargo has no
    `[workspace.dev-dependencies]`, so an entry there that ONLY a
    `[dev-dependencies] foo.workspace = true` inherits would be a false
    positive. Deliberate, fail-closed, unchanged since round 2.
  - Feature values are matched as TEXT. Cargo's `dep:` activation prefix
    carries no feature name and is ignored; a future syntax the guard does
    not know would be read as an ordinary bare name.

USAGE
-----
    uv run scripts/check-test-support-placement.py              # real scan
    uv run scripts/check-test-support-placement.py --self-test  # controls
    uv run scripts/check-test-support-placement.py <root> ...   # custom roots
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

FEATURE = "test-support"

# Appended to every PLACEMENT violation. Structural violations (a TOML parse
# error, a duplicate package name) carry their own explanation instead, so
# the remedy clause is attached at the message site rather than blanket-
# applied when printing.
REMEDY = f"— '{FEATURE}' may only be enabled from [dev-dependencies]"

# Sections where declaring `features = [..., "test-support", ...]` (or an
# ALIAS that reaches it — see `build_feature_graph`) on a dependency puts
# the hatch into a non-test build. `dev-dependencies` (and
# `target.*.dev-dependencies`) are deliberately ABSENT from this set — that
# is the one sanctioned place to enable the feature.
DENIED_DEP_SECTIONS = ("dependencies", "build-dependencies")

# Every dependency-table kind, dev included. Used ONLY for name resolution
# (`build_rename_map`) — reading a `package = "..."` rename out of a
# dev-dependency is not a policy statement about that section, it is how the
# guard learns what `mybridge/hatch` refers to. Violations are still filtered
# to `DENIED_DEP_SECTIONS`.
ALL_DEP_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")

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

    The result is DE-DUPLICATED by resolved path, first occurrence winning.
    `DEFAULT_ROOTS` are disjoint, but a custom invocation can nest one root
    inside another, and since round 4 a manifest seen twice would be read as
    two manifests declaring the same `[package].name` — i.e. an overlapping
    root would manufacture a duplicate-name denial out of one innocent file.
    """
    manifests: dict[Path, Path] = {}

    def add(path: Path) -> None:
        manifests.setdefault(path.resolve(), path)

    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            add(root)
            continue
        for path in sorted(root.rglob("Cargo.toml")):
            if "target" in path.relative_to(root).parts:
                continue
            add(path)
    return list(manifests.values())


def package_name(data: dict) -> str | None:
    """`[package].name`, or None for a manifest that declares no package.

    The name is the ONLY handle another manifest has on this one: a
    dependency edge and a `<crate>/<feature>` forwarding string both name a
    crate, never a path. A manifest with no `[package]` table (a virtual
    workspace-only `Cargo.toml`, or a bare self-test fixture) is therefore
    unreachable from any other manifest — it still gets its own per-manifest
    closure, it just contributes nothing that a cross-crate lookup can find.
    """
    pkg = data.get("package")
    if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
        return pkg["name"]
    return None


def iter_dep_sections(data: dict) -> list[tuple[str, str, dict]]:
    """Every dependency table in a manifest as `(label, kind, table)`.

    `kind` is the bare section kind (`dependencies` / `dev-dependencies` /
    `build-dependencies`) so callers can filter on policy; `label` is the
    human-readable path to it (`target.cfg(unix).dependencies`, …).
    """
    out: list[tuple[str, str, dict]] = []

    def add(label: str, kind: str, table: object) -> None:
        if isinstance(table, dict):
            out.append((label, kind, table))

    for kind in ALL_DEP_SECTIONS:
        add(kind, kind, data.get(kind))

    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        # Cargo has no `[workspace.dev-dependencies]`; the one workspace
        # table feeds both, so it is treated as non-dev (fail-closed).
        add("workspace.dependencies", "dependencies", workspace.get("dependencies"))

    target = data.get("target")
    if isinstance(target, dict):
        for spec_key, spec_val in target.items():
            if not isinstance(spec_val, dict):
                continue
            for kind in ALL_DEP_SECTIONS:
                add(f"target.{spec_key}.{kind}", kind, spec_val.get(kind))

    return out


def build_rename_map(
    data: dict, inherited: dict[str, set[str]] | None = None
) -> dict[str, set[str]]:
    """Dependency KEY -> the package names it can refer to (#500 R2).

    `mybridge = { package = "secretary-ffi-bridge" }` makes `mybridge` the
    name every dependency edge and every `mybridge/feat` forwarding string
    in THIS manifest uses, while the crate it resolves to — the thing the
    feature closure is keyed on — is `secretary-ffi-bridge`. Without this
    map the closure lookup misses entirely.

    The key itself is ALWAYS kept in the candidate set alongside any
    rename: fail-closed, so an alias that happens to shadow a real crate
    name is checked both ways rather than only one.

    `inherited` carries WORKSPACE-LEVEL renames (#515 C2). Cargo lets the
    `package = "..."` rename live in the ROOT manifest's
    `[workspace.dependencies]` while the member writes only
    `mybridge = { workspace = true, features = ["test-support"] }`. Reading
    the member manifest alone, `mybridge` resolves to `{"mybridge"}`, the
    feature-closure lookup misses `secretary-ffi-bridge` entirely, and the
    request is invisible — verified by execution to enable `test-support`
    in a real `cargo build --release` while this guard printed OK. Merging
    the workspace map in is purely ADDITIVE, so it can only ever widen the
    candidate set: fail-closed, same as the key-always-kept rule above.
    """
    renames: dict[str, set[str]] = {}
    if inherited:
        for key, names in inherited.items():
            renames.setdefault(key, set()).update(names)
    for _label, _kind, table in iter_dep_sections(data):
        for key, spec in table.items():
            if not isinstance(key, str):
                continue
            candidates = renames.setdefault(key, {key})
            candidates.add(key)
            if isinstance(spec, dict) and isinstance(spec.get("package"), str):
                candidates.add(spec["package"])
    return renames


def build_workspace_rename_map(
    parsed: list[tuple[Path, dict]],
) -> dict[str, set[str]]:
    """Renames declared in any scanned `[workspace.dependencies]` (#515 C2).

    Workspace inheritance is repo-global, not manifest-local: a member that
    writes `dep = { workspace = true }` picks up whatever the root declared,
    including a `package = "..."` rename. This collects those so
    `build_rename_map` can merge them into every member's local map.

    Collected across ALL scanned manifests rather than only the root, and
    unioned rather than overwritten, because this guard already tolerates
    more than one `[workspace]` in the tree (`core/fuzz` is a second one).
    A key declared by two workspaces contributes both candidates — again
    fail-closed.
    """
    inherited: dict[str, set[str]] = {}
    for _manifest, data in parsed:
        workspace = data.get("workspace")
        if not isinstance(workspace, dict):
            continue
        table = workspace.get("dependencies")
        if not isinstance(table, dict):
            continue
        for key, spec in table.items():
            if not isinstance(key, str):
                continue
            candidates = inherited.setdefault(key, {key})
            if isinstance(spec, dict) and isinstance(spec.get("package"), str):
                candidates.add(spec["package"])
    return inherited


def resolve_dep_names(renames: dict[str, set[str]], key: str) -> set[str]:
    """Candidate package names for a dependency key (see `build_rename_map`).

    A key with no dependency entry in this manifest — a forwarding string
    naming a crate that is not declared here — resolves to itself.
    """
    return renames.get(key, {key})


def build_feature_graph(
    parsed: list[tuple[Path, dict]],
    inherited: dict[str, set[str]] | None = None,
) -> tuple[dict[Path, set[str]], dict[str, set[str]]]:
    """Fixed-point closure of "which `[features]` keys reach `test-support`",
    computed over ALL scanned manifests together (#500 Finding B, R1, R2).

    Returns `(by_manifest, by_name)`:
      - `by_manifest[path]` — that ONE manifest's own reaching features.
        Keyed by PATH, never by package name, so a second manifest claiming
        the same `[package].name` cannot erase this one's `[features]`
        table (#500 R1) and a violation is attributed to the manifest that
        actually declares it.
      - `by_name[crate]` — the UNION of `by_manifest` over every manifest
        declaring `crate`. Cross-crate lookups (a dependency edge, a
        `<crate>/<feature>` forward) have only a name to go on, and a
        shadow manifest redeclaring an alias as empty must not mask a
        sibling that defines it as reaching, so the union is the
        fail-closed resolution of that ambiguity. A duplicate name is
        separately DENIED outright by `find_duplicate_package_names`.

    A feature `F` of manifest `M` is added to `by_manifest[M]` if any listed
    value is:
      - the literal string `test-support` (the base case), or
      - a bare name (no `/`) already in `by_manifest[M]` — a same-manifest
        reference to a feature that itself reaches, or
      - `<dep_key>/<feature>` (Cargo's forwarding syntax, `?` weak-dependency
        prefix stripped) where `<feature>` is `test-support` itself or is
        already reachable under ANY package name `<dep_key>` resolves to.

    This only ever ADDS members to a set, never removes one, so repeating
    the pass until nothing changes always reaches a fixed point — a mutual
    reference (`a = ["b"], b = ["a"]`) just never grows past empty unless
    one of them separately reaches `test-support`, with no special cycle
    detection required. `cycle_reaching` / `cycle_not_reaching` pin both
    directions of that claim.
    """
    nodes: list[Path] = []
    features_of: dict[Path, dict[str, list[str]]] = {}
    renames_of: dict[Path, dict[str, set[str]]] = {}
    nodes_by_name: dict[str, list[Path]] = {}

    for manifest, data in parsed:
        nodes.append(manifest)
        renames_of[manifest] = build_rename_map(data, inherited)
        table: dict[str, list[str]] = {}
        features = data.get("features")
        if isinstance(features, dict):
            for fname, values in features.items():
                if isinstance(fname, str) and isinstance(values, list):
                    table[fname] = [v for v in values if isinstance(v, str)]
        features_of[manifest] = table
        name = package_name(data)
        if name is not None:
            nodes_by_name.setdefault(name, []).append(manifest)

    by_manifest: dict[Path, set[str]] = {m: set() for m in nodes}

    def name_reaches(name: str) -> set[str]:
        """Live union over every manifest declaring `name` — recomputed on
        each lookup so growth propagates within a single pass."""
        out: set[str] = set()
        for m in nodes_by_name.get(name, ()):
            out |= by_manifest[m]
        return out

    changed = True
    while changed:
        changed = False
        for manifest in nodes:
            renames = renames_of[manifest]
            reached = by_manifest[manifest]
            for fname, values in features_of[manifest].items():
                if fname in reached:
                    continue
                for value in values:
                    if value == FEATURE:
                        reached.add(fname)
                        changed = True
                        break
                    if "/" in value:
                        dep_key, _, dep_feat = value.partition("/")
                        dep_key = dep_key.rstrip("?")
                        candidates = resolve_dep_names(renames, dep_key)
                        if dep_feat == FEATURE or any(
                            dep_feat in name_reaches(c) for c in candidates
                        ):
                            reached.add(fname)
                            changed = True
                            break
                    elif value in reached:
                        reached.add(fname)
                        changed = True
                        break

    by_name = {name: name_reaches(name) for name in nodes_by_name}
    return by_manifest, by_name


def find_duplicate_package_names(parsed: list[tuple[Path, dict]]) -> list[str]:
    """Two scanned manifests claiming one `[package].name` (#500 R1).

    FAIL-CLOSED rather than silently tolerated: with two manifests claiming
    one crate name, neither this guard nor Cargo can say which of them a
    dependency edge resolves to, and the shape is exactly the shadowing
    exploit R1 demonstrated. The union in `build_feature_graph` keeps the
    closure correct anyway, so this check is the second of two independent
    defences, not the only one.
    """
    by_name: dict[str, list[Path]] = {}
    for manifest, data in parsed:
        name = package_name(data)
        if name is not None:
            by_name.setdefault(name, []).append(manifest)

    hits: list[str] = []
    for name, paths in sorted(by_name.items()):
        if len(paths) > 1:
            joined = ", ".join(str(p) for p in sorted(paths))
            hits.append(
                f"duplicate [package].name {name!r} declared by {len(paths)} "
                f"scanned manifests ({joined}) — a second manifest claiming an "
                f"existing crate name can shadow the first's [features] table, "
                f"and no dependency edge can be attributed to one of them; give "
                f"every scanned manifest a distinct package name"
            )
    return hits


def find_resolver_violations(parsed: list[tuple[Path, dict]]) -> list[str]:
    """Every scanned `[workspace]` must pin the feature resolver (#515 C1).

    THIS IS THE PRECONDITION OF THE WHOLE GUARD. The `[dev-dependencies]`
    placement this file enforces keeps `Detail::for_test` out of a shipped
    artifact ONLY because resolver v2 declines to unify a dev-dependency's
    requested features into a non-test build. Under resolver **v1** the
    three already-sanctioned dev-dependency lines put the hatch straight
    back into `cargo build --release --workspace`, and every check in this
    file still passes — it is asking the right question of the wrong
    universe.

    A VIRTUAL manifest (no `[package]`) defaults to resolver **1**, and
    Cargo says so with a *warning*, which nothing in CI escalates. The root
    manifest here is virtual, so deleting one line silently converts the
    hatch guarantee to nothing. `edition` inference does NOT rescue it:
    edition-based resolver-2 inference keys off the root `[package].edition`,
    which a virtual manifest does not have.

    Accepts `"2"` and `"3"`: resolver 3 is a strict successor (it adds
    MSRV-aware version selection) and keeps v2's feature-unification rules,
    which are the property this guard depends on.

    EDITION INFERENCE is honoured rather than ignored, because ignoring it
    would fail a manifest that is genuinely safe: a NON-virtual workspace
    root (one that also carries `[package]`) infers resolver 2 from
    `edition >= 2021`. `core/fuzz/Cargo.toml` is exactly that shape — a
    `[workspace]` with no `resolver` key that resolves to v2 anyway — and
    denying it would be a false positive that trains a reader to add an
    allowlist rather than to read the rule.
    """
    hits: list[str] = []
    for manifest, data in parsed:
        workspace = data.get("workspace")
        if not isinstance(workspace, dict):
            continue
        resolver = workspace.get("resolver")
        if resolver is not None:
            if resolver not in ("2", "3"):
                hits.append(
                    f"{manifest}: [workspace] sets resolver = {resolver!r}; only "
                    f'"2" or "3" decline to unify a [dev-dependencies] feature '
                    f"into a non-test build, which is the sole reason "
                    f"`{FEATURE}` is absent from shipped artifacts"
                )
            continue
        # No explicit key: safe ONLY if edition inference gives v2, which
        # needs a root `[package]` (a virtual manifest has no edition to
        # infer from and silently falls back to resolver 1).
        package = data.get("package")
        edition = package.get("edition") if isinstance(package, dict) else None
        if isinstance(edition, str) and edition.isdigit() and int(edition) >= 2021:
            continue
        shape = "VIRTUAL (no [package])" if not isinstance(package, dict) else (
            f"[package].edition = {edition!r}"
        )
        hits.append(
            f"{manifest}: [workspace] does not set `resolver` and {shape}, so "
            f"Cargo falls back to resolver 1 with only a WARNING. Under "
            f"resolver 1 a [dev-dependencies] feature IS unified into `cargo "
            f"build --release`, which puts `{FEATURE}` straight back into a "
            f'shipped artifact and makes every other check in this file '
            f'vacuous. Set `resolver = "2"`'
        )
    return hits


def find_feature_liveness_violations(parsed: list[tuple[Path, dict]]) -> list[str]:
    """The guarded feature must still EXIST and still be requested (#515).

    Every other check in this file is conditional on the string `FEATURE`
    appearing somewhere. Rename the bridge's feature `test-support` ->
    `test-hatch` consistently across all four manifests and this guard keeps
    printing OK forever while policing nothing — a vacuity the project's
    `--self-test`-first convention exists to prevent, and one that
    `--self-test` alone cannot catch because it runs on synthetic fixtures
    that carry their own copy of the name.

    Two independent anchors, so a rename trips at least one even if the
    other is legitimately restructured:

    1. Some scanned manifest DECLARES `[features] test-support`.
    2. Some scanned manifest REQUESTS it from a `[dev-dependencies]` edge.

    Anchor 2 is what makes the whole `[dev-dependencies]`-only rule
    load-bearing rather than hypothetical: if nothing requests the feature,
    nothing is being kept out of a shipped artifact.
    """
    declares = [m for m, d in parsed if FEATURE in (d.get("features") or {})]
    requests: list[Path] = []
    for manifest, data in parsed:
        for _label, kind, table in iter_dep_sections(data):
            if kind != "dev-dependencies":
                continue
            for _key, spec in table.items():
                if isinstance(spec, dict) and FEATURE in (spec.get("features") or []):
                    requests.append(manifest)
    hits: list[str] = []
    if not declares:
        hits.append(
            f"no scanned manifest declares `[features] {FEATURE}` — the guarded "
            f"feature was renamed or removed, so every check in this file is "
            f"now vacuous while still reporting OK. Re-point `FEATURE`, or "
            f"retire this guard deliberately."
        )
    if not requests:
        hits.append(
            f"no scanned manifest requests `{FEATURE}` from a "
            f"[dev-dependencies] edge — the placement rule this guard enforces "
            f"has no subject, so a green run proves nothing. Re-point "
            f"`FEATURE`, or retire this guard deliberately."
        )
    return hits


def find_unscanned_workspace_members(
    parsed: list[tuple[Path, dict]], scanned: list[Path]
) -> list[str]:
    """Workspace members whose manifest no scan root reached (#515, #505).

    `DEFAULT_ROOTS` is hardcoded, and its comment claimed it was "verified
    against the `[workspace] members` list" — a one-time human check that
    nothing re-ran. A new top-level crate directory was therefore silently
    unscanned, with the guard printing OK and the manifest count merely
    changing by an amount nobody pins.

    This derives the claim from the manifest instead of from a comment.
    Glob members (`crates/*`) are expanded with `Path.glob` so the check
    tracks the same set Cargo does. Note the deliberate asymmetry with
    `iter_manifests`: NON-members are still scanned (`core/fuzz` is one),
    because this guard's threat model is "any manifest in the repo that can
    turn the feature on", which is wider than workspace membership.
    """
    scanned_resolved = {p.resolve() for p in scanned}
    hits: list[str] = []
    for manifest, data in parsed:
        workspace = data.get("workspace")
        if not isinstance(workspace, dict):
            continue
        members = workspace.get("members")
        if not isinstance(members, list):
            continue
        base = manifest.parent
        for member in sorted(m for m in members if isinstance(m, str)):
            # A member entry may be a literal path or a glob (`crates/*`).
            matches = sorted(base.glob(member)) if any(
                c in member for c in "*?["
            ) else [base / member]
            if not matches:
                hits.append(
                    f"{manifest}: [workspace] members entry {member!r} matches "
                    f"no directory — a stale member entry means the crate it "
                    f"named is no longer scanned by anything. {REMEDY}"
                )
                continue
            for match in matches:
                member_manifest = (match / "Cargo.toml").resolve()
                if member_manifest not in scanned_resolved:
                    hits.append(
                        f"{manifest}: workspace member {member!r} "
                        f"({member_manifest}) is NOT reached by any scan root — "
                        f"DEFAULT_ROOTS is hardcoded, so a new crate directory "
                        f"is invisible to every check in this file while the "
                        f"scan still reports OK. Add its root. {REMEDY}"
                    )
    return hits


def find_empty_roots(roots: list[Path], scanned: list[Path]) -> list[str]:
    """Directory roots that exist but contributed zero manifests (#515).

    `find_missing_roots` tests `.exists()` only, and the zero-manifest check
    in `run_real_scan` is AGGREGATE — so a root that still exists but has
    been emptied (a crate tree moved one level down, a rename that left the
    parent behind) drops every manifest under it while other roots keep the
    total non-zero and the guard prints OK. `payload_guard/scan.py`'s
    `_check_roots_resolve` already gets this right for the sibling guard
    ("contains no *.rs files"); this is the missing half here.

    A root that is itself a FILE is exempt: it contributes exactly itself,
    and `find_missing_roots` already covers its disappearance.
    """
    scanned_resolved = [p.resolve() for p in scanned]
    hits: list[str] = []
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        resolved = root.resolve()
        if not any(
            p == resolved or resolved in p.parents for p in scanned_resolved
        ):
            hits.append(
                f"scan root {root} exists but contributed ZERO manifests — an "
                f"emptied or moved crate tree drops coverage silently while "
                f"other roots keep the total non-zero. {REMEDY}"
            )
    return hits


def _feature_hits(
    spec: object, reaches_by_name: dict[str, set[str]], candidates: set[str]
) -> list[str]:
    """Which of a dependency entry's requested `features` are `test-support`
    itself, or reach it via the closure of ANY package name the entry
    resolves to (#500 Finding B, R2)."""
    if not isinstance(spec, dict):
        return []
    requested = spec.get("features")
    if not isinstance(requested, list):
        return []
    pool: set[str] = set()
    for candidate in candidates:
        pool |= reaches_by_name.get(candidate, set())
    return [
        f for f in requested
        if isinstance(f, str) and (f == FEATURE or f in pool)
    ]


def find_dependency_violations(
    data: dict,
    label: str,
    reaches_by_name: dict[str, set[str]],
    inherited: dict[str, set[str]] | None = None,
) -> list[str]:
    """`features = [...]` on a non-dev dependency edge that names
    `test-support` directly, names an alias whose closure reaches it, or
    does either through a `package = "..."` RENAME (#500 R2).

    Covers top-level `[dependencies]` / `[build-dependencies]`,
    `[workspace.dependencies]`, and `[target.<spec>.dependencies]` /
    `[target.<spec>.build-dependencies]`. `[dev-dependencies]` and
    `[target.<spec>.dev-dependencies]` are intentionally never reported here
    — that is the sanctioned section — though they DO feed the rename map.
    """
    hits: list[str] = []
    renames = build_rename_map(data, inherited)

    for section_label, kind, table in iter_dep_sections(data):
        if kind not in DENIED_DEP_SECTIONS:
            continue
        for dep_key, spec in table.items():
            if not isinstance(dep_key, str):
                continue
            candidates = resolve_dep_names(renames, dep_key)
            hit_feats = _feature_hits(spec, reaches_by_name, candidates)
            if not hit_feats:
                continue
            alias = (
                ""
                if candidates == {dep_key}
                else f" (resolves to {' / '.join(sorted(candidates))})"
            )
            hits.append(
                f"{label}: [{section_label}] {dep_key}{alias} requests "
                f"{hit_feats!r} (reaches '{FEATURE}') {REMEDY}"
            )

    return hits


def find_feature_table_violations(
    data: dict,
    label: str,
    manifest_reaches: set[str],
    reaches_by_name: dict[str, set[str]],
    inherited: dict[str, set[str]] | None = None,
) -> list[str]:
    """`[features]` entries that turn `test-support` on without a consumer
    ever writing `[dev-dependencies]` at all (#500 I2, generalized to
    aliases by Finding B, to shadowed manifests by R1 and to renamed
    dependencies by R2).

    1. `default`'s closure reaching `test-support` — directly or via any
       chain of same-manifest / cross-crate aliases. Read from THIS
       manifest's own closure (`manifest_reaches`), never a name-keyed one,
       so a same-named sibling can neither erase the finding (#500 R1) nor
       collect the blame for it. Only load-bearing on
       `secretary-ffi-bridge`'s own manifest, but checked on every manifest
       for the same fail-closed reason as round 2: a coincidentally-named
       feature elsewhere costs a one-line allowlist entry, not a missed
       real bypass.
    2. Any feature list value using `<dep>/<feature>` forwarding syntax
       where `<feature>` is `test-support` itself or reaches it via the
       closure of any package name `<dep>` resolves to — regardless of
       whether the forwarding feature is itself reachable from `default`,
       matching round 2's original scope (a non-default, explicitly-
       requested forward is still a bypass of the "only `[dev-dependencies]`"
       rule).
    """
    hits: list[str] = []
    features = data.get("features")
    if not isinstance(features, dict):
        return hits

    if "default" in manifest_reaches:
        hits.append(
            f"{label}: [features] default's closure reaches '{FEATURE}' {REMEDY}"
        )

    renames = build_rename_map(data, inherited)
    for feature_name, values in features.items():
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, str) or "/" not in value:
                continue
            dep_key, _, dep_feat = value.partition("/")
            dep_key = dep_key.rstrip("?")
            candidates = resolve_dep_names(renames, dep_key)
            pool: set[str] = set()
            for candidate in candidates:
                pool |= reaches_by_name.get(candidate, set())
            if dep_feat == FEATURE or dep_feat in pool:
                hits.append(
                    f"{label}: [features] {feature_name} forwards {value!r} "
                    f"(reaches '{FEATURE}') {REMEDY}"
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
            violations.append(
                f"{manifest}: TOML PARSE ERROR — {exc}; an unparseable manifest "
                f"is unscannable, which must never read as clean"
            )
            continue
        parsed.append((manifest, data))

    # #515 C2: workspace-level `package = "..."` renames are repo-global,
    # so they must be resolved BEFORE any per-manifest rename map is built.
    inherited = build_workspace_rename_map(parsed)

    reaches_by_manifest, reaches_by_name = build_feature_graph(parsed, inherited)
    violations.extend(find_duplicate_package_names(parsed))
    violations.extend(find_resolver_violations(parsed))
    violations.extend(find_unscanned_workspace_members(parsed, manifest_paths))

    for manifest, data in parsed:
        label = str(manifest)
        violations.extend(
            find_dependency_violations(data, label, reaches_by_name, inherited)
        )
        violations.extend(
            find_feature_table_violations(
                data, label, reaches_by_manifest[manifest], reaches_by_name, inherited
            )
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

    # #515: two assertions about the REAL TREE rather than about an
    # arbitrary manifest set, so they live here and not in `scan()` — a
    # synthetic control fixture legitimately has neither a live
    # `test-support` feature nor a fully-populated root list, and firing on
    # those would make every control fixture unwritable. Each is pinned by
    # a standalone self-test check instead of by a corpus control.
    parsed_real: list[tuple[Path, dict]] = []
    for manifest in iter_manifests(roots):
        try:
            parsed_real.append((manifest, tomllib.loads(manifest.read_text())))
        except tomllib.TOMLDecodeError:
            continue  # already reported as a violation by `scan`
    real_only = find_feature_liveness_violations(parsed_real)
    real_only += find_empty_roots(roots, iter_manifests(roots))

    if violations or real_only:
        for v in violations + real_only:
            print(f"DENIED: {v}")
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


@dataclass
class Control:
    """One self-test fixture plus what its verdict must SAY.

    `files` maps a relative path to TOML text, so a case can span several
    manifests (needed for every cross-crate control). `expect` / `forbid`
    are substrings matched against the joined violation text.

    A positive control with an EMPTY `expect` is itself a self-test failure:
    asserting only "something fired" is the vacuity #496 found in the
    sibling payload guard, where a mistyped expectation silently degraded a
    control to a presence check. `forbid` is how a control pins the ABSENCE
    of a finding — mis-attribution to an innocent manifest, or a spurious
    denial on a benign shape.
    """

    files: dict[str, str]
    expect: tuple[str, ...] = ()
    forbid: tuple[str, ...] = ()


# Reusable fixture text. A bridge manifest whose `hatch` alias reaches the
# hatch, and one that redeclares `hatch` as empty under the SAME package
# name (the R1 shadow).
_BRIDGE_WITH_HATCH = """
[package]
name = "secretary-ffi-bridge"

[features]
hatch = ["test-support"]
test-support = []
"""

_BRIDGE_SHADOW_EMPTY_HATCH = """
[package]
name = "secretary-ffi-bridge"

[features]
hatch = []
test-support = []
"""

# Positive controls: each MUST be denied, AND must say what `expect` says.
POSITIVE_CONTROLS: dict[str, Control] = {
    "base_normal_dependency": Control(
        files={
            "Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
        },
        expect=("[dependencies] secretary-ffi-bridge requests ['test-support']",),
    ),
    "default_feature_list": Control(
        files={
            "Cargo.toml": """
[features]
default = ["test-support"]
test-support = []
""",
        },
        expect=("[features] default's closure reaches 'test-support'",),
    ),
    "crate_forwarded_feature": Control(
        files={
            "Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = ".." }

[features]
extra = ["secretary-ffi-bridge/test-support"]
""",
        },
        expect=("[features] extra forwards 'secretary-ffi-bridge/test-support'",),
    ),
    "multiline_inline_table_array": Control(
        files={
            "Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "..", features = [
  "test-support",
] }
""",
        },
        expect=("[dependencies] secretary-ffi-bridge requests ['test-support']",),
    ),
    "indented_table_header": Control(
        files={
            "Cargo.toml": """
  [dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
        },
        expect=("[dependencies] secretary-ffi-bridge requests ['test-support']",),
    ),
    # --- Finding B: alias-of-test-support bypasses ---
    "alias_default_reaches": Control(
        # (a) One file, no consumer needed: `default` reaches `test-support`
        # through a same-manifest alias hop (`hatch`).
        files={
            "Cargo.toml": """
[features]
default = ["hatch"]
hatch = ["test-support"]
test-support = []
""",
        },
        expect=("[features] default's closure reaches 'test-support'",),
    ),
    "alias_requested_by_dependent": Control(
        # (b) A consumer requests the ALIAS (not `test-support` itself) on
        # a plain `[dependencies]` edge; the bridge's own manifest defines
        # the alias. Two files, one shared scan root.
        files={
            "bridge/Cargo.toml": _BRIDGE_WITH_HATCH,
            "consumer/Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "../bridge", features = ["hatch"] }
""",
        },
        expect=("[dependencies] secretary-ffi-bridge requests ['hatch']",),
    ),
    "alias_forwarded_by_dependent": Control(
        # Finding B names THREE sites needing the closure treatment: the
        # `default` check, the dependency-edge check (control above), and
        # the cross-crate `<crate>/<feature>` FORWARDING check. This is the
        # dedicated control for the third: a consumer forwards the ALIAS
        # (not `test-support` itself) through its own `[features]` table,
        # never requesting it directly on the dependency edge.
        files={
            "bridge/Cargo.toml": _BRIDGE_WITH_HATCH,
            "consumer/Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "../bridge" }

[features]
extra = ["secretary-ffi-bridge/hatch"]
""",
        },
        expect=("[features] extra forwards 'secretary-ffi-bridge/hatch'",),
    ),
    # --- Round 3 mechanisms, previously verified ad hoc, now pinned ---
    "transitive_chain": Control(
        # `default` reaches only on the THIRD closure pass. Round 3's
        # mutation G5 (single pass instead of a fixed point) was verified by
        # hand; this control makes the iteration permanently load-bearing.
        files={
            "Cargo.toml": """
[features]
default = ["hop_a"]
hop_a = ["hop_b"]
hop_b = ["test-support"]
test-support = []
""",
        },
        expect=("[features] default's closure reaches 'test-support'",),
    ),
    "cycle_reaching": Control(
        # A mutual reference that DOES reach. Must terminate and deny; the
        # closure's monotonicity is what makes cycle bookkeeping unnecessary.
        files={
            "Cargo.toml": """
[features]
default = ["ping"]
ping = ["pong"]
pong = ["ping", "test-support"]
test-support = []
""",
        },
        expect=("[features] default's closure reaches 'test-support'",),
    ),
    "cross_crate_two_hop": Control(
        # bridge -> mid -> consumer, forwarding the alias at each hop.
        files={
            "bridge/Cargo.toml": _BRIDGE_WITH_HATCH,
            "mid/Cargo.toml": """
[package]
name = "mid-crate"

[dependencies]
secretary-ffi-bridge = { path = "../bridge" }

[features]
midfeat = ["secretary-ffi-bridge/hatch"]
""",
            "consumer/Cargo.toml": """
[dependencies]
mid-crate = { path = "../mid", features = ["midfeat"] }
""",
        },
        expect=(
            "mid/Cargo.toml: [features] midfeat forwards "
            "'secretary-ffi-bridge/hatch'",
            "consumer/Cargo.toml: [dependencies] mid-crate requests ['midfeat']",
        ),
    ),
    "weak_dep_forward": Control(
        # Cargo's weak-dependency `?` prefix must not hide the forward.
        files={
            "bridge/Cargo.toml": _BRIDGE_WITH_HATCH,
            "consumer/Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "../bridge", optional = true }

[features]
extra = ["secretary-ffi-bridge?/hatch"]
""",
        },
        expect=("[features] extra forwards 'secretary-ffi-bridge?/hatch'",),
    ),
    # --- R1: a same-named manifest shadowing another's [features] table ---
    "r1_dup_name_shadow_last": Control(
        # The reviewer's exact repro. Round 3 keyed the closure on
        # `[package].name` with last-writer-wins, so the shadow SORTING
        # LAST erased the real declaration and the scan read "OK".
        files={
            "aa_bridge/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
default = ["test-support"]
test-support = []
""",
            "zz_shadow/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
default = []
""",
        },
        expect=(
            "aa_bridge/Cargo.toml: [features] default's closure reaches",
            "duplicate [package].name 'secretary-ffi-bridge'",
        ),
        # The shadow declares `default = []`. Blaming it too was round 3's
        # false-positive half of R1; per-manifest keying is what ends it.
        forbid=("zz_shadow/Cargo.toml: [features] default's closure reaches",),
    ),
    "r1_dup_name_shadow_first": Control(
        # Same exploit, opposite path ordering. Round 3 DENIED this one —
        # but flagged BOTH manifests, the false-positive half of R1.
        files={
            "aa_shadow/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
default = []
""",
            "zz_bridge/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
default = ["test-support"]
test-support = []
""",
        },
        expect=(
            "zz_bridge/Cargo.toml: [features] default's closure reaches",
            "duplicate [package].name 'secretary-ffi-bridge'",
        ),
        forbid=("aa_shadow/Cargo.toml: [features] default's closure reaches",),
    ),
    "r1_dup_name_benign": Control(
        # R1's FALSE-POSITIVE shape: two same-named manifests, NEITHER
        # reaching the hatch. Fail-closed was chosen over union-and-shrug,
        # so this IS denied — but only for the duplicate name. It must not
        # manufacture a placement finding out of two innocent manifests.
        files={
            "a/Cargo.toml": """
[package]
name = "benign-dup"

[features]
foo = []
""",
            "b/Cargo.toml": """
[package]
name = "benign-dup"

[features]
bar = []
""",
        },
        expect=("duplicate [package].name 'benign-dup'",),
        forbid=("reaches 'test-support'", "requests ", "forwards "),
    ),
    "r1_dup_name_shadow_cross_crate": Control(
        # R1 one level out: the shadow redeclares the ALIAS as empty rather
        # than `default`, so a name-keyed last-writer-wins closure loses the
        # reaching definition and the consumer's edge goes unnoticed. Pins
        # the by-name UNION, not just the per-manifest keying.
        files={
            "aa_bridge/Cargo.toml": _BRIDGE_WITH_HATCH,
            "zz_bridge/Cargo.toml": _BRIDGE_SHADOW_EMPTY_HATCH,
            "consumer/Cargo.toml": """
[dependencies]
secretary-ffi-bridge = { path = "../aa_bridge", features = ["hatch"] }
""",
        },
        expect=(
            "consumer/Cargo.toml: [dependencies] secretary-ffi-bridge "
            "requests ['hatch']",
            "duplicate [package].name 'secretary-ffi-bridge'",
        ),
    ),
    # --- R2: `package = "..."` renames the dependency key ---
    "r2_renamed_dep_requests_alias": Control(
        # The edge names `mybridge`; the closure is keyed on the real
        # package name. Without rename resolution the lookup misses and the
        # hatch ships.
        files={
            "bridge/Cargo.toml": _BRIDGE_WITH_HATCH,
            "consumer/Cargo.toml": """
[dependencies]
mybridge = { path = "../bridge", package = "secretary-ffi-bridge", features = ["hatch"] }
""",
        },
        expect=(
            "[dependencies] mybridge (resolves to mybridge / "
            "secretary-ffi-bridge) requests ['hatch']",
        ),
    ),
    "r2_renamed_dep_forwards_alias": Control(
        # Same rename, reached through the consumer's own `[features]`
        # forwarding string instead of the dependency edge.
        files={
            "bridge/Cargo.toml": _BRIDGE_WITH_HATCH,
            "consumer/Cargo.toml": """
[dependencies]
mybridge = { path = "../bridge", package = "secretary-ffi-bridge" }

[features]
x = ["mybridge/hatch"]
""",
        },
        expect=("[features] x forwards 'mybridge/hatch'",),
    ),
    # ---- #515 C1: the resolver pin -------------------------------------
    # Under resolver 1 every OTHER check in this file is asking the right
    # question of the wrong universe, so the precondition gets the same
    # positive-control treatment as the rules it underwrites.
    "resolver_absent_virtual_manifest": Control(
        files={
            "Cargo.toml": """
[workspace]
members = []
""",
        },
        expect=(
            "[workspace] does not set `resolver` and VIRTUAL (no [package])",
        ),
    ),
    "resolver_explicitly_v1": Control(
        files={
            "Cargo.toml": """
[workspace]
resolver = "1"
members = []
""",
        },
        expect=("[workspace] sets resolver = '1'",),
    ),
    "resolver_absent_old_edition": Control(
        files={
            "Cargo.toml": """
[workspace]

[package]
name = "old-edition-root"
edition = "2018"
""",
        },
        expect=("[workspace] does not set `resolver` and [package].edition = '2018'",),
    ),
    # ---- #515 C2: the workspace-inherited `package = "..."` rename ------
    # PROVEN by execution to enable `test-support` in a real `cargo build
    # --release` while this guard printed OK: the rename lives in the ROOT
    # manifest, the member writes only `workspace = true`, and a
    # manifest-local rename map cannot see it.
    "workspace_inherited_rename_on_normal_edge": Control(
        files={
            "Cargo.toml": """
[workspace]
resolver = "2"
members = ["consumer"]

[workspace.dependencies]
mybridge = { path = "bridge", package = "secretary-ffi-bridge" }
""",
            "bridge/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
test-support = []
""",
            "consumer/Cargo.toml": """
[package]
name = "consumer"

[dependencies]
mybridge = { workspace = true, features = ["test-support"] }
""",
        },
        expect=("mybridge (resolves to mybridge / secretary-ffi-bridge) "
                "requests ['test-support']",),
    ),
    # ---- #515 (#505): DEFAULT_ROOTS completeness, derived not asserted ---
    "workspace_member_outside_scan_roots": Control(
        files={
            "Cargo.toml": """
[workspace]
resolver = "2"
members = ["no_such_crate"]
""",
        },
        expect=("workspace member 'no_such_crate'", "is NOT reached by any scan root"),
    ),
    # ---- I4: three denied dependency shapes that had NO positive control -
    # Each denies today, but nothing observed it denying, so each could be
    # switched off with `--self-test` green.
    "build_dependencies_edge": Control(
        files={
            "Cargo.toml": """
[build-dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
        },
        expect=("[build-dependencies] secretary-ffi-bridge requests ['test-support']",),
    ),
    "target_specific_normal_edge": Control(
        files={
            "Cargo.toml": """
[target."cfg(unix)".dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
        },
        expect=("target.cfg(unix).dependencies",),
    ),
    "workspace_dependencies_edge": Control(
        files={
            "Cargo.toml": """
[workspace]
resolver = "2"

[workspace.dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
        },
        expect=("[workspace.dependencies] secretary-ffi-bridge requests ['test-support']",),
    ),
}


# Negative controls: each MUST pass with zero violations.
NEGATIVE_CONTROLS: dict[str, Control] = {
    # #515 C1's false-positive guards. `resolver_inferred_from_edition` is
    # the `core/fuzz/Cargo.toml` shape — a `[workspace]` with no `resolver`
    # key that infers v2 from a root `[package].edition >= 2021`. Denying it
    # would be a false positive that trains a reader to reach for an
    # allowlist instead of reading the rule.
    "resolver_explicitly_v2": Control(
        files={
            "Cargo.toml": """
[workspace]
resolver = "2"
members = []
""",
        },
    ),
    "resolver_inferred_from_edition": Control(
        files={
            "Cargo.toml": """
[workspace]

[package]
name = "fuzz-like-root"
edition = "2021"
""",
        },
    ),
    # #515 C2's false-positive guard: the SAME inherited rename, requested
    # from the sanctioned section. Resolving the workspace rename must not
    # by itself manufacture a finding.
    "workspace_inherited_rename_on_dev_edge": Control(
        files={
            "Cargo.toml": """
[workspace]
resolver = "2"
members = ["consumer"]

[workspace.dependencies]
mybridge = { path = "bridge", package = "secretary-ffi-bridge" }
""",
            "bridge/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
test-support = []
""",
            "consumer/Cargo.toml": """
[package]
name = "consumer"

[dev-dependencies]
mybridge = { workspace = true, features = ["test-support"] }
""",
        },
    ),
    # `[target.<spec>.dev-dependencies]` is the sanctioned section too — the
    # target qualifier must not turn a legitimate dev edge into a finding.
    "target_specific_dev_edge": Control(
        files={
            "Cargo.toml": """
[target."cfg(unix)".dev-dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
        },
    ),
    "legit_dev_dependency": Control(
        files={
            "Cargo.toml": """
[dev-dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
""",
        },
    ),
    # Finding B's false-positive guard: an alias chain that does NOT reach
    # `test-support` must not be flagged, even in the same two-file shape
    # as the positive `alias_requested_by_dependent` control above.
    "alias_chain_not_reaching": Control(
        files={
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
    ),
    # R2's false-positive guard: a LEGITIMATE rename whose requested feature
    # does not reach the hatch. Resolving the rename must not, by itself,
    # manufacture a finding.
    "r2_renamed_dep_not_reaching": Control(
        files={
            "bridge/Cargo.toml": """
[package]
name = "secretary-ffi-bridge"

[features]
unrelated = []
test-support = []
""",
            "consumer/Cargo.toml": """
[dependencies]
mybridge = { path = "../bridge", package = "secretary-ffi-bridge", features = ["unrelated"] }
""",
        },
    ),
    # The closure must TERMINATE on a mutual reference that never reaches —
    # the other half of `cycle_reaching`. A hang here fails the whole run.
    "cycle_not_reaching": Control(
        files={
            "Cargo.toml": """
[features]
default = ["ping"]
ping = ["pong"]
pong = ["ping"]
test-support = []
""",
        },
    ),
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

        for name, control in POSITIVE_CONTROLS.items():
            case_dir = tmp_path / name
            case_dir.mkdir()
            _write_fixture(case_dir, control.files)
            violations, count, _missing = scan([case_dir])
            joined = "\n".join(violations)
            if count == 0:
                print(f"SELF-TEST FAIL: positive control {name!r} contributed "
                      f"zero manifests (fixture bug)")
                fails += 1
            elif not control.expect:
                print(f"SELF-TEST FAIL: positive control {name!r} declares no "
                      f"`expect` — a control asserting only that SOMETHING "
                      f"fired is vacuous")
                fails += 1
            elif not violations:
                print(f"SELF-TEST FAIL: known-positive control {name!r} was "
                      f"NOT denied")
                fails += 1
            else:
                absent = [e for e in control.expect if e not in joined]
                present = [f for f in control.forbid if f in joined]
                if absent or present:
                    print(f"SELF-TEST FAIL: known-positive control {name!r} "
                          f"was denied, but for the wrong reason")
                    for e in absent:
                        print(f"    expected but ABSENT:  {e!r}")
                    for f in present:
                        print(f"    forbidden but PRESENT: {f!r}")
                    print(f"    actual violations: {violations!r}")
                    fails += 1
                else:
                    positive_ok += 1

        for name, control in NEGATIVE_CONTROLS.items():
            case_dir = tmp_path / name
            case_dir.mkdir()
            _write_fixture(case_dir, control.files)
            violations, count, _missing = scan([case_dir])
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
        violations, count, _missing = scan([empty_dir])
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

        # Round 4: OVERLAPPING scan roots must not read one manifest twice.
        # Since duplicate `[package].name` became a denial, a double-read
        # would manufacture a violation out of one innocent file — the
        # false-positive mirror of R1, introduced by R1's own fix.
        overlap_root = tmp_path / "overlap"
        (overlap_root / "inner").mkdir(parents=True)
        _write_fixture(
            overlap_root / "inner",
            {"Cargo.toml": '[package]\nname = "overlap-crate"\n'},
        )
        violations, count, _missing = scan([overlap_root, overlap_root / "inner"])
        if count != 1 or violations:
            print(f"SELF-TEST FAIL: overlapping scan roots read one manifest "
                  f"{count} times and produced {violations!r} — a nested root "
                  f"must not manufacture a duplicate-package-name denial")
            fails += 1

        # #515: the two REAL-TREE-ONLY assertions live in `run_real_scan`,
        # not `scan`, so no corpus control can reach them. Probe them
        # directly, both directions — a check nothing observes firing is
        # the vacuity this whole file exists to prevent.
        live = [
            (Path("bridge/Cargo.toml"), {"features": {FEATURE: []}}),
            (
                Path("consumer/Cargo.toml"),
                {"dev-dependencies": {"b": {"features": [FEATURE]}}},
            ),
        ]
        if find_feature_liveness_violations(live):
            print("SELF-TEST FAIL: feature-liveness check fired on a tree that "
                  "DOES declare and request the feature (false positive)")
            fails += 1
        if not find_feature_liveness_violations([(Path("x/Cargo.toml"), {})]):
            print("SELF-TEST FAIL: feature-liveness check did NOT fire on a "
                  "tree where the guarded feature is absent — a rename would "
                  "silently make every other check in this file vacuous")
            fails += 1
        if not find_feature_liveness_violations(live[:1]):
            print("SELF-TEST FAIL: feature-liveness check did NOT fire when the "
                  "feature is declared but NOTHING requests it from a "
                  "[dev-dependencies] edge — the placement rule then has no "
                  "subject and a green run proves nothing")
            fails += 1

        # An EXISTING root that contributes zero manifests while other roots
        # keep the aggregate non-zero (#515). `find_missing_roots` tests
        # `.exists()` only and the zero-count check is aggregate, so without
        # this an emptied crate tree drops coverage in silence.
        hollow = tmp_path / "hollow_root"
        hollow.mkdir()
        if not find_empty_roots([hollow], []):
            print("SELF-TEST FAIL: an existing-but-empty scan root was NOT "
                  "reported — coverage can be dropped silently")
            fails += 1
        if find_empty_roots([clean_dir], [clean_dir / "Cargo.toml"]):
            print("SELF-TEST FAIL: empty-root check fired on a root that DID "
                  "contribute a manifest (false positive)")
            fails += 1

        # ...and the WIRING of those two into `run_real_scan`. The three
        # probes above call the functions directly, so severing the
        # `violations.extend(...)` line would leave them green. `clean_dir`
        # holds a lone `[dev-dependencies]` manifest that declares no
        # feature at all, so liveness — and only liveness — must red it.
        rc, captured = _quiet_scan_rc([clean_dir])
        if rc == 0 or "guarded feature was renamed or removed" not in captured:
            print("SELF-TEST FAIL: the feature-liveness check is not WIRED "
                  "into run_real_scan — a tree with no `test-support` at all "
                  "scanned clean")
            print(captured)
            fails += 1

        # Same for the empty-root check. `hollow` is paired with a root that
        # DOES contribute, so the aggregate zero-manifest check cannot be
        # what reds it — only `find_empty_roots` can, which is what makes
        # this probe distinguish the wiring from its neighbours.
        _rc, captured = _quiet_scan_rc([clean_dir, hollow])
        if "contributed ZERO manifests" not in captured:
            print("SELF-TEST FAIL: the empty-root check is not WIRED into "
                  "run_real_scan — an existing-but-empty root alongside a "
                  "populated one dropped coverage silently")
            print(captured)
            fails += 1

        # The violations -> exit-1 wiring itself. Every corpus control calls
        # `scan()` directly, so deleting `fail = True` from `run_real_scan`'s
        # `if violations:` block would leave all of them green while the real
        # scan printed DENIED lines and exited 0 — the catastrophic shape.
        wiring = tmp_path / "exit_wiring"
        wiring.mkdir()
        _write_fixture(wiring, POSITIVE_CONTROLS["base_normal_dependency"].files)
        rc, captured = _quiet_scan_rc([wiring])
        if rc == 0:
            print("SELF-TEST FAIL: run_real_scan returned 0 despite violations "
                  "— the DENIED-but-exit-0 shape")
            print(captured)
            fails += 1
        elif "DENIED:" not in captured:
            print("SELF-TEST FAIL: run_real_scan failed without printing a "
                  "DENIED line, so CI would show no reason")
            print(captured)
            fails += 1

    # #511's class, in a file that reproduced it: control tables are dict
    # literals, so a duplicate label is silently last-wins and the printed
    # total simply shrinks. Count the textual entries and compare.
    source = Path(__file__).read_text(encoding="utf-8")
    declared = len(re.findall(r"^    \"[A-Za-z0-9_]+\": Control\(", source, re.M))
    if declared != len(POSITIVE_CONTROLS) + len(NEGATIVE_CONTROLS):
        print(f"SELF-TEST FAIL: {declared} `Control(` entries are declared in "
              f"source but only {len(POSITIVE_CONTROLS) + len(NEGATIVE_CONTROLS)} "
              f"survive in the dicts — a DUPLICATE LABEL was silently "
              f"last-wins, dropping a control with no other signal")
        fails += 1

    total_controls = len(POSITIVE_CONTROLS) + len(NEGATIVE_CONTROLS)
    if fails:
        print(f"test-support placement self-test: FAILED "
              f"({positive_ok}/{len(POSITIVE_CONTROLS)} positive, "
              f"{negative_ok}/{len(NEGATIVE_CONTROLS)} negative)")
        return 1
    print(f"test-support placement self-test: OK "
          f"({positive_ok + negative_ok}/{total_controls} controls: "
          f"{positive_ok} positive, {negative_ok} negative; plus 1 "
          f"zero-manifest, 1 missing-root, 1 overlapping-root, 3 "
          f"feature-liveness, 2 empty-root, 3 wiring and 1 "
          f"label-uniqueness check)")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    roots = [Path(p) for p in argv] if argv else DEFAULT_ROOTS
    return run_real_scan(roots)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
