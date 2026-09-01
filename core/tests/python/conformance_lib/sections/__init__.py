"""The conformance sections, and the registry that orders them.

Importing this package pulls in every section module, and through them the
whole verifier. `--diff-replay` deliberately does NOT import it -- see
`conformance.py`'s `main()`.
"""

from __future__ import annotations

from conformance_lib.sections.registry import SECTIONS, Section

__all__ = ["SECTIONS", "Section"]
