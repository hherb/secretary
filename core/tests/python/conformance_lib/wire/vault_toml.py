"""§2 `vault.toml` parse for the golden-vault verification path.

Distinct from `conformance_lib.codec.vault_toml`, which is the strict
clean-room decoder behind `--diff-replay`'s `vault_toml` target. This one
reads the fields the open-vault path needs; that one enforces the full
acceptance set the Rust reader enforces.
"""

from __future__ import annotations

import base64
import tomllib
from dataclasses import dataclass

from conformance_lib.cursor import ParseError

# ---------------------------------------------------------------------------
# §2.4 Binary parsers (vault.toml, identity bundle, manifest)
# ---------------------------------------------------------------------------


@dataclass
class VaultToml:
    format_version: int
    suite_id: int
    vault_uuid: bytes  # 16 bytes
    created_at_ms: int
    kdf_memory_kib: int
    kdf_iterations: int
    kdf_parallelism: int
    kdf_salt: bytes  # 32 bytes


def parse_vault_toml(text: str) -> VaultToml:
    """Parse `vault.toml` per `docs/vault-format.md` §2."""
    data = tomllib.loads(text)
    if data.get("format_version") != 1:
        raise ParseError(f"vault.toml format_version {data.get('format_version')!r}")
    if data.get("suite_id") != 1:
        raise ParseError(f"vault.toml suite_id {data.get('suite_id')!r}")
    vault_uuid_str = data.get("vault_uuid")
    if not isinstance(vault_uuid_str, str):
        raise ParseError("vault.toml missing or wrong-typed vault_uuid")
    vault_uuid = bytes.fromhex(vault_uuid_str.replace("-", ""))
    if len(vault_uuid) != 16:
        raise ParseError(f"vault.toml vault_uuid byte length {len(vault_uuid)}")

    kdf = data.get("kdf") or {}
    if kdf.get("algorithm") != "argon2id":
        raise ParseError(f"vault.toml kdf.algorithm {kdf.get('algorithm')!r}")
    if kdf.get("version") != "1.3":
        raise ParseError(f"vault.toml kdf.version {kdf.get('version')!r}")

    salt_b64 = kdf.get("salt_b64")
    if not isinstance(salt_b64, str):
        raise ParseError("vault.toml kdf.salt_b64 missing")
    salt = base64.b64decode(salt_b64)
    if len(salt) != 32:
        raise ParseError(f"vault.toml kdf salt length {len(salt)} (expected 32)")

    return VaultToml(
        format_version=int(data["format_version"]),
        suite_id=int(data["suite_id"]),
        vault_uuid=vault_uuid,
        created_at_ms=int(data["created_at_ms"]),
        kdf_memory_kib=int(kdf["memory_kib"]),
        kdf_iterations=int(kdf["iterations"]),
        kdf_parallelism=int(kdf["parallelism"]),
        kdf_salt=salt,
    )
