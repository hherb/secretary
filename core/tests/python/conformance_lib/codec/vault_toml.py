"""Strict clean-room `vault.toml` decoder behind `--diff-replay`'s `vault_toml`
target.

Crash-only: there is no re-encode, so the replay contract asserts only that
Rust and Python agree on ACCEPT vs REJECT.
"""

from __future__ import annotations

import base64
import re
import tomllib

# ---------------------------------------------------------------------------
# Differential-replay helpers (--diff-replay mode)
# ---------------------------------------------------------------------------
# Each py_decode_<target> / py_encode_<target> pair implements a strict
# clean-room decoder/encoder that mirrors the Rust side's accept/reject
# behaviour and byte-identical canonical re-encoding output.  They are
# called by run_diff_replay() when the script is invoked as:
#
#   uv run conformance.py --diff-replay <target> <input-path>
#
# and also available as library helpers for future test sections.


def _validate_uuid_canonical(s: str) -> bytes:
    """Parse and validate a canonical RFC 4122 UUID string.

    Requires exactly 36 bytes, hyphens at indices 8/13/18/23, and every
    other character must be a lowercase hex digit (0-9 or a-f).
    Mirrors vault_toml.rs::parse_uuid_canonical.

    Raises ValueError on any violation.
    """
    if len(s) != 36:
        raise ValueError(f"uuid string length {len(s)}, expected 36")
    for i in (8, 13, 18, 23):
        if s[i] != '-':
            raise ValueError(f"uuid missing hyphen at position {i}: {s!r}")
    pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    if not pattern.match(s):
        raise ValueError(f"uuid contains non-lowercase-hex chars: {s!r}")
    return bytes.fromhex(s.replace('-', ''))


def py_decode_vault_toml(text: str) -> dict:
    """Strict §2 vault.toml decoder matching vault_toml.rs::decode.

    Validates:
    - format_version == 1
    - suite_id == 1
    - vault_uuid: canonical lowercase hyphenated RFC 4122 form (rejects
      uppercase and non-standard separators)
    - created_at_ms: non-negative integer
    - [kdf]: algorithm == "argon2id", version == "1.3", no unknown keys,
      salt_b64 decodes to exactly 32 bytes.

    Returns the parsed fields as a dict. Raises on any violation.
    """
    data = tomllib.loads(text)

    # format_version
    fv = data.get("format_version")
    if not isinstance(fv, int) or fv != 1:
        raise ValueError(f"vault.toml format_version {fv!r}")

    # suite_id
    si = data.get("suite_id")
    if not isinstance(si, int) or si != 1:
        raise ValueError(f"vault.toml suite_id {si!r}")

    # vault_uuid — strict canonical form (lowercase hex, exact hyphens)
    vault_uuid_str = data.get("vault_uuid")
    if not isinstance(vault_uuid_str, str):
        raise ValueError("vault.toml vault_uuid missing or wrong type")
    vault_uuid = _validate_uuid_canonical(vault_uuid_str)

    # created_at_ms — must be a non-negative integer
    cat = data.get("created_at_ms")
    if not isinstance(cat, int) or cat < 0:
        raise ValueError(f"vault.toml created_at_ms {cat!r}")

    # [kdf] section — strict: no unknown keys
    kdf = data.get("kdf")
    if not isinstance(kdf, dict):
        raise ValueError("vault.toml missing [kdf] section")

    KNOWN_KDF_KEYS = {"algorithm", "version", "memory_kib", "iterations", "parallelism", "salt_b64"}
    for k in kdf:
        if k not in KNOWN_KDF_KEYS:
            raise ValueError(f"vault.toml unknown kdf key: {k!r}")

    alg = kdf.get("algorithm")
    if alg != "argon2id":
        raise ValueError(f"vault.toml kdf.algorithm {alg!r}")

    ver = kdf.get("version")
    if ver != "1.3":
        raise ValueError(f"vault.toml kdf.version {ver!r}")

    mem_kib = kdf.get("memory_kib")
    if not isinstance(mem_kib, int) or mem_kib < 0 or mem_kib > 0xFFFFFFFF:
        raise ValueError(f"vault.toml kdf.memory_kib {mem_kib!r}")

    iters = kdf.get("iterations")
    if not isinstance(iters, int) or iters < 0 or iters > 0xFFFFFFFF:
        raise ValueError(f"vault.toml kdf.iterations {iters!r}")

    par = kdf.get("parallelism")
    if not isinstance(par, int) or par < 0 or par > 0xFFFFFFFF:
        raise ValueError(f"vault.toml kdf.parallelism {par!r}")

    salt_b64_str = kdf.get("salt_b64")
    if not isinstance(salt_b64_str, str):
        raise ValueError("vault.toml kdf.salt_b64 missing")
    salt = base64.b64decode(salt_b64_str)
    if len(salt) != 32:
        raise ValueError(f"vault.toml kdf salt length {len(salt)} (expected 32)")

    return {
        "format_version": fv,
        "suite_id": si,
        "vault_uuid": vault_uuid,
        "created_at_ms": cat,
        "kdf": {
            "algorithm": alg,
            "version": ver,
            "memory_kib": mem_kib,
            "iterations": iters,
            "parallelism": par,
            "salt": salt,
        },
    }
