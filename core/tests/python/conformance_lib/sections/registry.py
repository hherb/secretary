"""The ordered table of conformance sections, and how one is run.

WHY A TABLE. Before #593 each section appeared in `main()` THREE times, in
three parallel hand-maintained structures: the call-and-print block, the
banner string, and the `FAIL:` line -- plus a fourth appearance as one term of
a 22-term `and` chain that decided the exit code. Adding a section meant
editing four places, and omitting the `and` term was silent and FAIL-OPEN: the
section's failure lines would print and `main()` would still return 0. The
table below is the single place a section is declared; the banner, the verdict
line and the exit code are all DERIVED from it, so the three cannot drift and
the fourth cannot be forgotten.

Section 1 gained a banner in the same change. It was the only section without
one -- its output appeared at the top of the run with no header at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from conformance_lib.sections.block_kat import section1_block_kat
from conformance_lib.sections.cbor_scanner import section_cbor_scanner_units
from conformance_lib.sections.conflict import (
    section4_conflict_kat,
    section4b_trash_merge_kat,
    section4c_retention_kat,
)
from conformance_lib.sections.completeness import section_registry_completeness
from conformance_lib.sections.convergence import section_convergence_kat
from conformance_lib.sections.golden_vault import section2_golden_vault_001
from conformance_lib.sections.manifest_body_canonicality_guards import (
    section_manifest_body_array_sort_guard,
    section_manifest_body_outer_canonicality_guard,
)
from conformance_lib.sections.manifest_body_schema_guards import (
    section_manifest_body_duplicate_key_guard,
    section_manifest_body_entry_required_fields_guard,
    section_manifest_body_nested_entry_guard,
    section_manifest_body_required_keys_guard,
)
from conformance_lib.sections.manifest_body_shape_guards import (
    section_manifest_body_shape_guard,
    section_manifest_body_strict_subshapes_guard,
)
from conformance_lib.sections.manifest_canonicality_cause import (
    section_manifest_canonicality_cause,
)
from conformance_lib.sections.manifest_canonicality_kat import (
    section_manifest_canonicality_kat,
)
from conformance_lib.sections.manifest_uniqueness_kat import (
    section_manifest_uniqueness_kat,
)
from conformance_lib.sections.ml_dsa_regression import (
    section3_ml_dsa_65_verify_regression,
)
from conformance_lib.sections.purge import section_purge_scenario
from conformance_lib.sections.record_canonicality import (
    section_record_unknown_subtree_canonicality,
)
from conformance_lib.sections.required_key_determinism import (
    section_required_key_determinism,
)
from conformance_lib.sections.revoke import section_revoke_kat
from conformance_lib.sections.sync_pass import section_sync_pass_kat
from conformance_lib.sections.unknown_map import (
    section5_unknown_map_case_insensitivity,
)


@dataclass(frozen=True)
class Section:
    """One conformance section.

    `run` returns `(ok, lines)`. The lines are printed to stdout regardless of
    `ok`, so a CI log keeps the per-row breakdown of a passing run and the
    issue list of a failing one.

    `title` is the human-readable name; `refs` is the trailing spec/issue
    citation shown in the banner but not repeated in the `FAIL:` line. Keeping
    them as separate fields is what lets both strings be derived from one
    declaration without changing either one's text.
    """

    id: str
    title: str
    refs: str
    run: Callable[[], tuple[bool, list[str]]]

    @property
    def banner(self) -> str:
        return f"--- Section {self.id}: {self.title}{self.refs} ---"

    @property
    def failure(self) -> str:
        return f"FAIL: {self.title}"


SECTIONS: tuple[Section, ...] = (
    Section("1", "block_kat.json structural conformance", "", section1_block_kat),
    Section("2", "golden_vault_001 full crypto verify", "", section2_golden_vault_001),
    Section("3", "ml_dsa_65_verify tamper-rejection regression", "",
            section3_ml_dsa_65_verify_regression),
    Section("4", "conflict_kat.json CRDT merge cross-language replay", "",
            section4_conflict_kat),
    Section("4b", "trash_merge_kat.json trash-list merge cross-language replay", "",
            section4b_trash_merge_kat),
    Section("4c", "retention_kat.json trash retention eligibility replay", "",
            section4c_retention_kat),
    Section("5", "py_merge_unknown_map case-insensitivity guard", "",
            section5_unknown_map_case_insensitivity),
    Section("R", "revoke re-key clean-room verification", " (§6.5.1)",
            section_revoke_kat),
    Section("S", "sync-pass classification clean-room replay", " (D.1.13)",
            section_sync_pass_kat),
    Section("C", "convergence_kat.json two-client convergence", " (C.4)",
            section_convergence_kat),
    Section("P", "manifest TrashEntry purge marker", " (§7.2, #399)",
            section_purge_scenario),
    Section("CS", "span-recording CBOR scanner unit coverage", " (§4.2, #592)",
            section_cbor_scanner_units),
    Section("MD", "manifest body duplicate-key-in-nested-map guard", " (#585)",
            section_manifest_body_duplicate_key_guard),
    Section("MDN", "manifest body nested block/trash-entry unknown-bag guard",
            " (#585 fix round 1)", section_manifest_body_nested_entry_guard),
    Section("MRK", "manifest body all-9-required-keys guard", " (#585 fix round 1)",
            section_manifest_body_required_keys_guard),
    Section("MSS", "manifest body strict-subshape (kdf_params/vector_clock) guard",
            " (#585 fix round 2)", section_manifest_body_strict_subshapes_guard),
    Section("MERF", "manifest body entry required-fields guard",
            " (#585 fix round 2)", section_manifest_body_entry_required_fields_guard),
    Section("MSH", "manifest body known-field shape/version guard", " (#595)",
            section_manifest_body_shape_guard),
    Section("MOC", "manifest body outer-map canonicality guard", " (#595)",
            section_manifest_body_outer_canonicality_guard),
    Section("MAS", "manifest body array sort-discipline guard", " (#595)",
            section_manifest_body_array_sort_guard),
    Section("MCK", "manifest_canonicality_kat.json §4.2 per-rule corpus replay",
            " (#583, #592)", section_manifest_canonicality_kat),
    Section("MCC", "manifest_canonicality_kat.json expect_cause cross-language pin",
            " (#590, #604)", section_manifest_canonicality_cause),
    Section("MUQ", "manifest_uniqueness_kat.json §4.2 repeated-value replay",
            " (#594, #600)", section_manifest_uniqueness_kat),
    Section("RC", "record unknown-subtree canonicality, both nesting levels",
            " (#592)", section_record_unknown_subtree_canonicality),
    Section("DET", "required-key rejection determinism across hash seeds",
            " (#597)", section_required_key_determinism),
    # Last on purpose: it reports on the table above, so it reads as a summary
    # of the run rather than as a precondition for it.
    Section("REG", "section registry completeness", " (#593)",
            section_registry_completeness),
)
