"""Section 3 -- `ml_dsa_65_verify` tamper-rejection regression.

Exists because an earlier version of that helper reported "no exception" as
success and silently ACCEPTED tampered ML-DSA-65 signatures. The failure
direction of a broken hybrid-verify is what this section pins.
"""

from __future__ import annotations

from conformance_lib.primitives import ml_dsa_65_verify
from conformance_lib.tamper import _bytes_flip

# ---------------------------------------------------------------------------
# Section 3: ml_dsa_65_verify helper — direct tamper-rejection regression
# ---------------------------------------------------------------------------
#
# `pqcrypto.sign.ml_dsa_65.verify` returns True/False on a well-formed
# input pair (it does NOT raise on a tampered or invalid signature),
# whereas `cryptography`'s Ed25519.verify raises `InvalidSignature`.
# A previous version of `ml_dsa_65_verify` discarded the boolean return
# and reported "no exception" as success, silently accepting tampered
# ML-DSA signatures. The Section 2 tamper cases happen to fail at AEAD
# or Ed25519 verify before reaching ML-DSA verify, so they did not
# detect the bug. This section exercises the helper directly so any
# future regression of the same shape (re-broaden the except, drop the
# `return`, etc.) trips an in-CI failure.


def section3_ml_dsa_65_verify_regression() -> tuple[bool, list[str]]:
    """Direct round-trip + tamper checks against `ml_dsa_65_verify`.

    Locks in the post-fix contract: verify returns True on a clean sig,
    False on a sig whose bytes have been flipped, and False when the
    message has been tampered. No golden fixtures needed -- the
    keypair / signature are generated fresh inside the test so the
    suite stays deterministic against `pqcrypto`'s own keygen.
    """
    from pqcrypto.sign import ml_dsa_65

    lines: list[str] = []
    pk, sk = ml_dsa_65.generate_keypair()
    message = b"secretary-conformance ml_dsa_65 verify regression"
    sig = ml_dsa_65.sign(sk, message)

    if not ml_dsa_65_verify(pk, sig, message):
        lines.append("FAIL  ml_dsa_65_verify rejected a valid signature")
        return False, lines
    lines.append("PASS  ml_dsa_65_verify accepts a valid signature")

    tampered_sig = _bytes_flip(sig, len(sig) // 2)
    if ml_dsa_65_verify(pk, tampered_sig, message):
        lines.append(
            "FAIL  ml_dsa_65_verify accepted a tampered signature "
            "(silent-accept regression)"
        )
        return False, lines
    lines.append("PASS  ml_dsa_65_verify rejects a tampered signature")

    tampered_message = _bytes_flip(message, 0)
    if ml_dsa_65_verify(pk, sig, tampered_message):
        lines.append(
            "FAIL  ml_dsa_65_verify accepted a tampered message "
            "(silent-accept regression)"
        )
        return False, lines
    lines.append("PASS  ml_dsa_65_verify rejects a tampered message")

    return True, lines
