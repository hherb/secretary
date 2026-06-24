"""D.1.6 contacts pytest — verified share path (#206).

Exercises the projected import_contact_card / share_block_to. Each test
gets its own writable copy of golden_vault_001 in tmp_path.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py


def _golden(n: int = 1) -> Path:
    return Path(__file__).resolve().parents[3] / "core" / "tests" / "data" / f"golden_vault_{n:03d}"


def _password(n: int = 1) -> bytes:
    import json
    p = Path(__file__).resolve().parents[3] / "core" / "tests" / "data" / f"golden_vault_{n:03d}_inputs.json"
    return json.loads(p.read_text())["password"].encode()


def _fresh(tmp_path: Path, n: int = 1) -> Path:
    dst = tmp_path / f"vault{n:03d}"
    shutil.copytree(_golden(n), dst)
    return dst


def _uuid_from_card_filename(name: str) -> bytes:
    # "<hyphenated-uuid>.card" → 16 raw bytes
    return bytes.fromhex(name[: -len(".card")].replace("-", ""))


def _open(vault: Path):
    return secretary_ffi_py.open_vault_with_password(str(vault), _password())


def _a_peer_card(vault: Path, owner_uuid: bytes) -> tuple[bytes, bytes]:
    """Return (card_bytes, contact_uuid) for a non-owner card shipped in the
    fixture's contacts/ dir."""
    for f in sorted((vault / "contacts").glob("*.card")):
        uuid = _uuid_from_card_filename(f.name)
        if uuid != owner_uuid:
            return f.read_bytes(), uuid
    raise AssertionError("fixture has no non-owner contact card")


def test_import_contact_card_round_trip_and_duplicate(tmp_path: Path) -> None:
    vault = _fresh(tmp_path)
    out = _open(vault)
    with out.identity as identity, out.manifest as manifest:
        owner_uuid = identity.user_uuid()
        card_bytes, peer_uuid = _a_peer_card(vault, owner_uuid)
        # Card is already on disk → duplicate import rejected.
        with pytest.raises(secretary_ffi_py.VaultContactAlreadyExists):
            secretary_ffi_py.import_contact_card(manifest, card_bytes)
        # Delete and re-import → ContactSummary echoes the uuid.
        (vault / "contacts" / f"{_hyphen(peer_uuid)}.card").unlink()
        summary = secretary_ffi_py.import_contact_card(manifest, card_bytes)
        assert bytes(summary.contact_uuid) == peer_uuid
        assert isinstance(summary.display_name, str)
        assert summary.shared_block_count == 0


def test_import_rejects_tampered_card(tmp_path: Path) -> None:
    vault = _fresh(tmp_path)
    out = _open(vault)
    with out.identity as identity, out.manifest as manifest:
        owner_uuid = identity.user_uuid()
        card_bytes, peer_uuid = _a_peer_card(vault, owner_uuid)
        (vault / "contacts" / f"{_hyphen(peer_uuid)}.card").unlink()
        tampered = bytearray(card_bytes)
        tampered[-1] ^= 0xFF
        with pytest.raises(secretary_ffi_py.VaultCardDecodeFailure):
            secretary_ffi_py.import_contact_card(manifest, bytes(tampered))


def _hyphen(u: bytes) -> str:
    h = u.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
