"""Section 1 -- `block_kat.json` structural conformance (§6.1 byte layout).

Byte-layout only: no cryptographic verification. Cross-checks decoded
headers, fingerprints, recipient counts and signature lengths against the
pinned JSON inputs.
"""

from __future__ import annotations

from dataclasses import dataclass

from conformance_lib.constants import ED25519_SIG_LEN, ML_DSA_65_SIG_LEN
from conformance_lib.cursor import ParseError
from conformance_lib.fixtures import block_kat_path, load_json_fixture
from conformance_lib.wire.block_file import parse_block_file

# ---------------------------------------------------------------------------
# Vector-level cross-checks
# ---------------------------------------------------------------------------


@dataclass
class VectorReport:
    name: str
    ok: bool
    issues: list[str]


def check_vector(vector: dict) -> VectorReport:
    name = vector["name"]
    issues: list[str] = []

    inputs = vector["inputs"]
    expected = vector["expected"]

    # 1. The hex bytes parse cleanly.
    try:
        block_bytes = bytes.fromhex(expected["block_file"])
    except ValueError as e:
        return VectorReport(name=name, ok=False, issues=[f"block_file hex invalid: {e}"])

    # 2. size_bytes sentinel matches the actual byte count.
    declared_size = expected["size_bytes"]
    if declared_size != len(block_bytes):
        issues.append(
            f"size_bytes sentinel mismatch: declared={declared_size}, "
            f"actual={len(block_bytes)}"
        )

    # 3. Structural parse.
    try:
        parsed = parse_block_file(block_bytes)
    except ParseError as e:
        return VectorReport(
            name=name, ok=False, issues=issues + [f"structural parse failed: {e}"]
        )

    # 4. Cross-check against the JSON inputs.

    if parsed.header.vault_uuid.hex() != inputs["vault_uuid"]:
        issues.append(
            f"vault_uuid mismatch: parsed={parsed.header.vault_uuid.hex()}, "
            f"input={inputs['vault_uuid']}"
        )
    if parsed.header.block_uuid.hex() != inputs["block_uuid"]:
        issues.append(
            f"block_uuid mismatch: parsed={parsed.header.block_uuid.hex()}, "
            f"input={inputs['block_uuid']}"
        )
    if parsed.header.created_at_ms != inputs["created_at_ms"]:
        issues.append(
            f"created_at_ms mismatch: parsed={parsed.header.created_at_ms}, "
            f"input={inputs['created_at_ms']}"
        )
    if parsed.header.last_mod_ms != inputs["last_mod_ms"]:
        issues.append(
            f"last_mod_ms mismatch: parsed={parsed.header.last_mod_ms}, "
            f"input={inputs['last_mod_ms']}"
        )

    # 5. Vector clock: count + each entry.
    expected_vc = inputs["vector_clock"]
    if len(parsed.header.vector_clock) != len(expected_vc):
        issues.append(
            f"vector_clock length mismatch: parsed={len(parsed.header.vector_clock)}, "
            f"input={len(expected_vc)}"
        )
    else:
        # Encoder sorts by device_uuid before emission, so on-disk order may
        # differ from JSON-input order. Compare as sets keyed by device_uuid.
        expected_vc_by_dev = {e["device_uuid"]: e["counter"] for e in expected_vc}
        for entry in parsed.header.vector_clock:
            dev_hex = entry.device_uuid.hex()
            if dev_hex not in expected_vc_by_dev:
                issues.append(f"unexpected vector_clock device_uuid {dev_hex}")
            elif expected_vc_by_dev[dev_hex] != entry.counter:
                issues.append(
                    f"vector_clock[{dev_hex}] counter mismatch: "
                    f"parsed={entry.counter}, input={expected_vc_by_dev[dev_hex]}"
                )

    # 6. Recipient table: count and the (single, in this fixture)
    #    fingerprint matches the JSON's author_fingerprint (the
    #    self-recipient is the author).
    if len(parsed.recipients) != expected["recipients_count"]:
        issues.append(
            f"recipients_count mismatch: parsed={len(parsed.recipients)}, "
            f"expected={expected['recipients_count']}"
        )
    if len(parsed.recipients) >= 1:
        if parsed.recipients[0].fingerprint.hex() != inputs["author_fingerprint"]:
            issues.append(
                f"recipients[0].fingerprint mismatch: "
                f"parsed={parsed.recipients[0].fingerprint.hex()}, "
                f"input.author_fingerprint={inputs['author_fingerprint']}"
            )

    # 7. Author fingerprint in the signature suffix matches the JSON.
    if parsed.signature.author_fingerprint.hex() != inputs["author_fingerprint"]:
        issues.append(
            f"signature.author_fingerprint mismatch: "
            f"parsed={parsed.signature.author_fingerprint.hex()}, "
            f"input.author_fingerprint={inputs['author_fingerprint']}"
        )

    # 8. Signature lengths (both already enforced inside the parser, but
    #    repeat as positive cross-checks for clarity in failure reports).
    if len(parsed.signature.sig_ed) != ED25519_SIG_LEN:
        issues.append(f"sig_ed length: {len(parsed.signature.sig_ed)} (expected {ED25519_SIG_LEN})")
    if len(parsed.signature.sig_pq) != ML_DSA_65_SIG_LEN:
        issues.append(
            f"sig_pq length: {len(parsed.signature.sig_pq)} (expected {ML_DSA_65_SIG_LEN})"
        )

    return VectorReport(name=name, ok=not issues, issues=issues)


# ---------------------------------------------------------------------------
# Section 1 entry point (PR-A): block_kat.json structural conformance
# ---------------------------------------------------------------------------


def section1_block_kat() -> tuple[bool, list[str]]:
    """Run the PR-A block_kat.json structural conformance vectors.

    Returns (ok, lines_to_print). Lines are printed regardless of
    pass/fail so a CI log keeps the per-vector breakdown.
    """
    fixture = load_json_fixture(block_kat_path(), "block_kat.json")

    lines: list[str] = []

    if fixture.get("version") != 1:
        return False, [
            f"FAIL: unsupported block_kat.json version {fixture.get('version')!r}"
        ]

    vectors = fixture.get("vectors", [])
    if not vectors:
        return False, ["FAIL: block_kat.json has no vectors"]

    all_ok = True
    for v in vectors:
        report = check_vector(v)
        if report.ok:
            lines.append(f"PASS  block_kat::{report.name}")
        else:
            all_ok = False
            lines.append(f"FAIL  block_kat::{report.name}")
            for issue in report.issues:
                lines.append(f"      - {issue}")

    if all_ok:
        lines.append(
            f"OK: block_kat.json - {len(vectors)} vector(s) parsed and cross-checked."
        )
    else:
        lines.append("FAIL: one or more block_kat.json vectors did not pass.")

    return all_ok, lines
