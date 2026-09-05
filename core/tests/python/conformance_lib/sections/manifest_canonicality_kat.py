"""Section MCK -- `manifest_canonicality_kat.json` §4.2 per-rule corpus replay.

21 rows against the per-rule table in vault-format.md §4.2, replayed
cross-language. Carries a NAIVE CONTROL: a decoder without the span-scanner
must diverge on rows the real one gets right, or the corpus is not
discriminating.
"""

from __future__ import annotations


from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.fixtures import load_json_fixture, manifest_canonicality_kat_path
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

def section_manifest_canonicality_kat() -> tuple[bool, list[str]]:
    """Replay `manifest_canonicality_kat.json` -- the §4.2 per-rule table,
    at all three nesting levels the corpus carries (#583, #592).

    The corpus is 21 rows: 7 shapes x 3 levels (`top__*`, `block__*`,
    `trash__*`), because `BlockEntry` and `TrashEntry` each carry their own
    forward-compat `unknown` bag and the deepest divergence this slice
    found lives at block-entry level. Two readers, one corpus:

    1. `py_decode_manifest` (byte-retaining) MUST agree with the recorded
       Rust verdict on every row. These 21 rows are EVIDENCE for the "two
       conformant readers accept the same set" property §4.2 states in
       prose (#583), not a proof of it: what this assertion actually
       establishes is that `py_decode_manifest` and `decode_manifest`
       agree on these specific 21 rows, at the three nesting levels the
       corpus carries (top-level, block entry, trash entry).
    2. A deliberately naive `cbor2.loads` reader MUST DIVERGE on all
       THREE `*__rule5_duplicate_key` rows (one per level). This is a
       POSITIVE CONTROL: without it, a corpus that happened to contain no
       discriminating row would pass and prove nothing (#592). The naive
       reader is also expected to diverge on the three `*__rule1_key_order`
       rows (`canonical=True` re-sorts the subtree's keys) -- that is fine;
       the assertion here is membership (rule5 subset of divergences), not
       equality of the divergence set, since a wider divergence set does
       not undermine the control.

       Membership alone is NOT sufficient, though, which is why the control
       is two-sided as of #595: a naive reader returning False for every
       input puts all 12 `expect_accept` rows into `divergences`, of which
       the 3 rule-5 rows are a subset, so the membership check passes on a
       reader that discriminates nothing. The second half asserts the naive
       reader AGREES on the three `*__control_canonical` rows.
    """
    import cbor2

    path = manifest_canonicality_kat_path()
    doc = load_json_fixture(path, "manifest_canonicality_kat.json")
    rows = doc["rows"]
    issues: list[str] = []
    if not rows:
        return False, ["corpus is empty"]

    def naive_accepts(body: bytes) -> bool:
        """The reader crypto-design §6.2 currently points an implementer at.

        Catches only the exception types `cbor2.loads` / `cbor2.dumps` and
        the `==` comparison can legitimately raise -- `cbor2.CBORError`
        (the common base of `CBORDecodeError`/`CBOREncodeError` and its
        two subclasses), plus `ValueError`/`TypeError` -- NOT a bare
        `Exception` (Finding C): a bare catch would silently treat a
        `NameError`/`AttributeError` from a programming error in this
        helper as "rejected", satisfying the divergence assertion below
        for the wrong reason instead of surfacing the bug.
        """
        try:
            decoded = cbor2.loads(body)
            return cbor2.dumps(decoded, canonical=True) == body
        except (cbor2.CBORError, ValueError, TypeError):
            return False

    divergences: list[str] = []
    for row in rows:
        label = row["label"]
        # A malformed fixture must produce a FAIL line, not a traceback out
        # of `main()`. This section runs before MCC, MUQ, RC, DET and REG,
        # so an escaping `ValueError` here silently skips all five --
        # including REG, which is what proves the registry is complete
        # (#614 review; MCC's own copy of this hazard was fixed with it).
        try:
            body = bytes.fromhex(row["manifest_body_hex"])
        except (TypeError, ValueError) as e:
            issues.append(
                f"row {label!r}: manifest_body_hex is not valid hex -- this is a "
                f"FIXTURE defect, not a decoder verdict: {e}"
            )
            continue
        expected = row["expect_accept"]

        try:
            py_decode_manifest(body)
            strict = True
        except _REJECTION_EXCEPTIONS:
            # NARROW, for the reason `naive_accepts` above states about
            # itself and this arm did not apply to the reader actually
            # under test (#595). 9 of the 21 rows expect a REJECT, so a
            # bare `except Exception` let a `NameError`/`AttributeError`
            # inside `py_decode_manifest` satisfy them for the wrong
            # reason -- verified by mutation: making every rejection raise
            # `NameError` instead left this section reporting ok=True.
            strict = False
        if strict != expected:
            issues.append(
                f"row {label!r}: strict reader accept={strict}, Rust recorded {expected}"
            )

        if naive_accepts(body) != expected:
            divergences.append(label)

    expected_rule5_rows = {
        label for label in (r["label"] for r in rows) if label.endswith("__rule5_duplicate_key")
    }
    if len(expected_rule5_rows) != 3:
        issues.append(
            f"expected 3 '*__rule5_duplicate_key' rows in the corpus (one per "
            f"level), found {len(expected_rule5_rows)}: {sorted(expected_rule5_rows)}"
        )
    missing_divergence = expected_rule5_rows - set(divergences)
    if missing_divergence:
        issues.append(
            "positive control failed: the naive cbor2.loads reader did NOT "
            f"diverge on {sorted(missing_divergence)}, so this corpus cannot "
            "distinguish a byte-retaining reader from a dict-based one at "
            "every level (#592)"
        )

    # The KNOWN-NEGATIVE half, without which the control is one-sided
    # (#595). The membership check above is satisfied by a naive reader
    # that returns False for EVERYTHING: all 12 `expect_accept` rows then
    # land in `divergences`, and the 3 rule-5 rows are a subset of them.
    # Verified by execution -- with `naive_accepts` stuck at False the
    # control passed having proven nothing. A reader that is uniformly
    # False now fails here instead, which is the two-sided discipline
    # every `--self-test` guard in this repo already follows: it must fire
    # on a known-positive AND stay silent on a known-negative.
    control_rows = {
        label for label in (r["label"] for r in rows) if label.endswith("__control_canonical")
    }
    if len(control_rows) != 3:
        issues.append(
            f"expected 3 '*__control_canonical' rows (one per level), "
            f"found {len(control_rows)}: {sorted(control_rows)}"
        )
    spurious = control_rows & set(divergences)
    if spurious:
        issues.append(
            "positive control failed: the naive cbor2.loads reader DIVERGED "
            f"on the fully-canonical rows {sorted(spurious)}, so it is not "
            "discriminating between reader strategies -- it is simply broken, "
            "and its agreement above proves nothing (#595)"
        )

    # Corpus floors, mirroring what `manifest_canonicality_kat_replays`
    # asserts on the Rust side against the SAME fixture (#595). Without
    # them a corpus trimmed to 3 rows, or to accept-only rows, passed here
    # -- verified by execution -- leaving this section unable to detect a
    # decoder that accepts everything.
    n_accept = sum(1 for r in rows if r["expect_accept"])
    n_reject = len(rows) - n_accept
    if len(rows) != 21:
        issues.append(f"corpus must carry 7 shapes x 3 levels = 21 rows, found {len(rows)}")
    if n_accept == 0:
        issues.append("corpus has no ACCEPT rows -- it would pass by rejecting everything")
    if n_reject == 0:
        issues.append("corpus has no REJECT rows -- it would pass by accepting everything")

    if issues:
        return False, issues
    return True, [
        f"PASS  manifest canonicality corpus: {len(rows)} rows replayed "
        f"({n_accept} accept / {n_reject} reject), naive control diverged on "
        f"{len(divergences)} rows including all 3 rule-5 rows"
    ]
