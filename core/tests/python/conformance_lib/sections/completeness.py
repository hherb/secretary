"""Section REG -- the registry is complete, and the run is not vacuous.

WHY THIS EXISTS. `registry.py` removed one fail-open hazard and created its
dual. Before #593 a section could only run if `main()` named it, so an
unreferenced section module was impossible; a section that FAILED could still
be scored green, by omitting its term from `main()`'s 22-term `and` chain.
The registry makes that second failure unrepresentable -- the exit code is
derived from the same table that runs the sections -- but it makes the first
one possible for the first time: a section module can now exist, be perfectly
correct, and never be reached, because adding it to `SECTIONS` is a separate
edit from writing it.

Nothing but this section would notice. A never-registered section produces no
banner, no output, and no failure -- it is indistinguishable from a section
that does not exist. So the registry is checked against the package it claims
to enumerate, by DISCOVERY rather than by a second hand-maintained list: a
list would have exactly the drift problem it was meant to detect.

Three checks, all fail-closed:

  1. Every `section*` driver defined anywhere in `conformance_lib.sections` is
     in `SECTIONS`. This is the one that catches the new hazard.
  2. Nothing is in `SECTIONS` that discovery did not find -- catches an entry
     whose module was deleted or whose driver was renamed out from under it.
  3. Section ids and banners are unique. A duplicate id is not cosmetic: the
     banner is how a reader attributes output to a section, and two sections
     sharing one makes a failing section's output readable as the other's.

DISCOVERY IS DEFINED BY SHAPE, NOT BY A NAME LIST. A driver is a top-level
function whose name starts with `section`, defined in the module being scanned
(not imported into it). Every one of the 22 drivers returns `(ok, lines)`; if a
future helper adopts the `section` prefix without that shape it will be
reported here as unregistered, which is the fail-CLOSED direction -- noisy
rather than silent.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

# Modules that legitimately define no drivers. Listed for the reader's benefit
# only -- discovery does not consult this, so forgetting to update it cannot
# cause a section to be missed.
_NON_DRIVER_MODULES = ("registry", "completeness", "manifest_body_fixtures")


def discover_drivers() -> dict[str, object]:
    """Every `section*` driver defined in `conformance_lib.sections`.

    Keyed by `"<module>.<function>"` so a duplicate function name in two
    modules stays distinguishable in the report.
    """
    import conformance_lib.sections as pkg

    found: dict[str, object] = {}
    for info in pkgutil.iter_modules(pkg.__path__):
        module = importlib.import_module(f"conformance_lib.sections.{info.name}")
        for name, obj in vars(module).items():
            if not name.startswith("section") or not inspect.isfunction(obj):
                continue
            # `obj.__module__` is where the function was DEFINED. Without this,
            # a driver imported into `registry` would be counted twice -- and,
            # worse, a driver that discovery only ever saw through an import
            # would still look "found" after its defining module was deleted.
            if obj.__module__ != module.__name__:
                continue
            found[f"{info.name}.{name}"] = obj
    return found


def section_registry_completeness() -> tuple[bool, list[str]]:
    # Imported at CALL time, not module scope: `registry` imports this module
    # to put the section in the table, so a module-scope import here is a
    # cycle. Deferring it is not a workaround -- the registry is what this
    # section inspects, so reading it when the section RUNS is also the
    # honest ordering.
    from conformance_lib.sections.registry import SECTIONS

    issues: list[str] = []

    discovered = discover_drivers()
    registered = {section.run for section in SECTIONS}

    for key, fn in sorted(discovered.items()):
        if fn not in registered:
            issues.append(
                f"{key} is a section driver but is NOT in SECTIONS -- it never "
                f"runs, and its absence is silent"
            )

    discovered_fns = set(discovered.values())
    for section in SECTIONS:
        if section.run not in discovered_fns:
            issues.append(
                f"Section {section.id} names {section.run!r}, which discovery "
                f"did not find in conformance_lib.sections"
            )

    for label, values in (
        ("id", [s.id for s in SECTIONS]),
        ("banner", [s.banner for s in SECTIONS]),
    ):
        duplicates = sorted({v for v in values if values.count(v) > 1})
        for dup in duplicates:
            issues.append(f"duplicate section {label}: {dup!r}")

    if issues:
        return False, issues
    return True, [
        f"PASS  section registry: {len(discovered)} drivers discovered, "
        f"{len(SECTIONS)} registered, ids and banners unique"
    ]
