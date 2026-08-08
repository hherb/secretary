"""The error-payload hygiene guard (#474, #480, #486).

Split out of the former single-file `scripts/check-error-payload-hygiene.py`
in #486. That file remains the ONE documented entry point — CLAUDE.md, CI
(`.github/workflows/test.yml`) and `core/tests/error_payload_hygiene_parity.rs`
all name it, and it keeps the PEP 723 header. This package holds the
implementation.

Read `scripts/check-error-payload-hygiene.py`'s module docstring first: it
carries the WHY and the LIMITS, and points at the module holding each detail.
"""
