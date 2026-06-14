"""B.1 round-trip smoke tests for the secretary_ffi_py PyO3 extension.

These tests assert the same surface as the Rust #[cfg(test)] unit tests in
src/lib.rs, exercised through the maturin-built wheel and Python's import
machinery. They prove the binding pipeline (PyO3 + maturin + uv venv +
import) works end-to-end.
"""

import json
import tempfile
from pathlib import Path

import pytest

import secretary_ffi_py


def test_add_returns_arithmetic_sum() -> None:
    assert secretary_ffi_py.add(2, 3) == 5


def test_add_wraps_on_overflow() -> None:
    # Mirror the Rust unit test in src/lib.rs that pins the wrapping
    # contract through the FFI boundary. u32::MAX = 4_294_967_295.
    assert secretary_ffi_py.add(4_294_967_295, 1) == 0


def test_version_matches_format_version() -> None:
    # FORMAT_VERSION is pinned at 1 in core/src/version.rs; if the Rust
    # core bumps the format version this test will fail and demand an
    # explicit update — that's intentional, the wire-format constant is
    # security-critical and shouldn't drift silently.
    assert secretary_ffi_py.version() == 1


# ---------------------------------------------------------------------------
# B.2: open_with_password tests against golden_vault_001 + golden_vault_002.
# ---------------------------------------------------------------------------


def _golden_vault_dir(n: int) -> Path:
    """Resolve `core/tests/data/golden_vault_{n:03d}/` relative to this test
    file. Walks up 3 parents from `ffi/secretary-ffi-py/tests/` to repo root.
    """
    return Path(__file__).resolve().parents[3] / "core" / "tests" / "data" / f"golden_vault_{n:03d}"


def _read_fixture(n: int, name: str) -> bytes:
    return (_golden_vault_dir(n) / name).read_bytes()


@pytest.fixture(scope="module")
def created_vault():
    """Single create_vault invocation reused across read-only B.3b tests
    in this module. Cost: ~1s for V1_DEFAULT Argon2id.

    Tests that consume the one-shot mnemonic use their own fresh
    invocation; the fixture's mnemonic stays untouched so multiple
    read-only tests can share the same identity handle.
    """
    return secretary_ffi_py.create_vault(
        password=b"test-fixture-password",
        display_name="Owner",
        created_at_ms=42_000,
    )


def _golden_vault_phrase(n: int) -> bytes:
    """Read the pinned `recovery_mnemonic_phrase` field from
    `core/tests/data/golden_vault_{n:03d}_inputs.json` and return it as
    UTF-8 bytes ready for `open_with_recovery`. The fixture builder
    asserts the JSON pin matches `bip39::Mnemonic::from_entropy(...)
    .to_string()`, so this stays honest as long as the JSON does."""
    inputs_path = (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}_inputs.json"
    )
    with inputs_path.open() as fh:
        data = json.load(fh)
    return data["recovery_mnemonic_phrase"].encode("utf-8")


def _golden_vault_path(n: int) -> Path:
    """Return the absolute Path to the golden_vault_NNN folder.
    Walks up 3 parents from `ffi/secretary-ffi-py/tests/` to repo root."""
    return (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}"
    )


def _golden_vault_block_summaries(n: int) -> list:
    """Return the pinned block_summaries array for golden_vault_NNN.

    Source: core/tests/data/golden_vault_NNN_inputs.json's `block_summaries`
    field, added in Task 2 Step 3. Each entry has: block_uuid (hex string),
    block_name (string), created_at_ms (int), last_modified_ms (int),
    recipient_uuids (list of hex strings).
    """
    inputs_path = (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}_inputs.json"
    )
    with open(inputs_path) as f:
        return json.load(f)["block_summaries"]


# Pinned KAT values — must match secretary-ffi-bridge's tests and the
# golden_vault_001_inputs.json source of truth. KAT drift cannot land
# silently: bridge tests + this file + Swift/Kotlin smoke runners all
# pin the same values.
VAULT_001_PASSWORD = b"correct horse battery staple"
VAULT_001_OWNER_DISPLAY_NAME = "Owner"
VAULT_001_OWNER_USER_UUID = bytes.fromhex("bf08a3300cd994b877e1a15baa28df35")

# ---------------------------------------------------------------------------
# B.4b: read_block KAT pins (source: golden_vault_001_inputs.json)
# ---------------------------------------------------------------------------
VAULT_001_BLOCK_UUID = bytes.fromhex("112233445566778899aabbccddeeff00")
VAULT_001_BLOCK_NAME = "Personal logins"
VAULT_001_RECORD_UUID = bytes.fromhex("33445566778899aabbccddeeff001122")
VAULT_001_DEVICE_UUID = bytes.fromhex("2233445566778899aabbccddeeff0011")
VAULT_001_TIMESTAMP_MS = 2_000_000_000_000
VAULT_001_PASSWORD_VALUE = "hunter2"
VAULT_001_USERNAME_VALUE = "owner@example.com"

# Number of trailing bytes stripped to corrupt the TOML structurally.
# Empirically large enough to break the document past any tolerant
# parser; mirrors the bridge crate's unlock.rs negative-test value.
#
# Why robust under v1: vault.toml is plain TOML and contains no AEAD-
# framed payloads (those live in identity.bundle.enc), so any
# truncation must fail at TOML parse / required-field-present checks
# long before the AEAD step that produces WrongPasswordOrCorrupt.
# The same constant + reasoning is pinned in the bridge crate's
# unlock.rs and the Swift / Kotlin smoke runners.
_TRUNCATION_SUFFIX_BYTES = 50


def test_open_with_password_success_returns_pinned_identity() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
        assert identity.user_uuid() == VAULT_001_OWNER_USER_UUID


def test_open_with_password_wrong_password_raises_wrong_password_or_corrupt() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.WrongPasswordOrCorrupt):
        secretary_ffi_py.open_with_password(toml, bundle, b"definitely wrong")


def test_open_with_password_swapped_files_raises_vault_mismatch() -> None:
    # vault_001's vault.toml + vault_002's identity.bundle.enc → cross-check
    # at core/src/unlock/mod.rs's vault_uuid + created_at_ms comparison fails.
    toml_001 = _read_fixture(1, "vault.toml")
    bundle_002 = _read_fixture(2, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.VaultMismatch):
        secretary_ffi_py.open_with_password(toml_001, bundle_002, VAULT_001_PASSWORD)


def test_open_with_password_truncated_toml_raises_corrupt_vault() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    truncated = toml[:-_TRUNCATION_SUFFIX_BYTES]
    with pytest.raises(secretary_ffi_py.CorruptVault):
        secretary_ffi_py.open_with_password(truncated, bundle, VAULT_001_PASSWORD)


def test_close_is_idempotent() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    identity = secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD)
    identity.close()
    identity.close()  # second call must not raise
    identity.close()  # third call must not raise


def test_use_after_close_returns_empty_values() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    identity = secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD)
    identity.close()
    assert identity.display_name() == ""
    assert identity.user_uuid() == b"\x00" * 16


def test_open_with_password_accepts_bytearray_for_caller_zeroize_discipline() -> None:
    """Documents the design: passwords accepted as bytes-like; disciplined
    callers can zero a mutable bytearray after the call."""
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    pw = bytearray(VAULT_001_PASSWORD)
    with secretary_ffi_py.open_with_password(toml, bundle, pw) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
    # Caller's zeroize discipline (recommended for first-party clients):
    for i in range(len(pw)):
        pw[i] = 0
    assert all(b == 0 for b in pw)


# ---------------------------------------------------------------------------
# B.3a: open_with_recovery tests against golden_vault_001 + golden_vault_002.
# ---------------------------------------------------------------------------


def test_open_with_recovery_success_returns_pinned_identity() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    phrase = _golden_vault_phrase(1)
    with secretary_ffi_py.open_with_recovery(toml, bundle, phrase) as identity:
        # Same KAT as the open_with_password success path — both unlock
        # paths converge on byte-identical secret state per §3/§4 dual-
        # KEK design.
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
        assert identity.user_uuid() == VAULT_001_OWNER_USER_UUID


def test_open_with_recovery_wrong_mnemonic_raises_wrong_mnemonic_or_corrupt() -> None:
    # vault_002's phrase against vault_001's vault — valid 24-word phrase
    # but wrong vault, so AEAD-decrypt under recovery_kek tag-fails →
    # WrongMnemonicOrCorrupt (anti-oracle preserving).
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    wrong_phrase = _golden_vault_phrase(2)
    with pytest.raises(secretary_ffi_py.WrongMnemonicOrCorrupt):
        secretary_ffi_py.open_with_recovery(toml, bundle, wrong_phrase)


def test_open_with_recovery_wrong_length_raises_invalid_mnemonic() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.InvalidMnemonic) as exc_info:
        secretary_ffi_py.open_with_recovery(toml, bundle, b"only three words")
    assert "got 3" in str(exc_info.value)


def test_open_with_recovery_invalid_utf8_raises_invalid_mnemonic() -> None:
    # 0xFF is not valid UTF-8 in any byte position; the bridge's UTF-8
    # validation seam catches this before the BIP-39 wordlist lookup.
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.InvalidMnemonic) as exc_info:
        secretary_ffi_py.open_with_recovery(toml, bundle, bytes([0xFF] * 32))
    assert "UTF-8" in str(exc_info.value)


def test_open_with_recovery_swapped_files_raises_vault_mismatch() -> None:
    # vault_001 toml + vault_002 bundle + vault_001 phrase. The vault_uuid
    # comparison fires BEFORE mnemonic parsing, so even an "invalid" phrase
    # would still produce VaultMismatch on this input pair.
    toml_001 = _read_fixture(1, "vault.toml")
    bundle_002 = _read_fixture(2, "identity.bundle.enc")
    phrase_001 = _golden_vault_phrase(1)
    with pytest.raises(secretary_ffi_py.VaultMismatch):
        secretary_ffi_py.open_with_recovery(toml_001, bundle_002, phrase_001)


def test_open_with_recovery_accepts_bytearray_for_caller_zeroize_discipline() -> None:
    """Documents the design: mnemonic accepted as bytes-like; disciplined
    callers can zero a mutable bytearray after the call (parallel to the
    password-input pattern from B.2)."""
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    phrase = bytearray(_golden_vault_phrase(1))
    with secretary_ffi_py.open_with_recovery(toml, bundle, phrase) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
    # Caller's zeroize discipline (recommended for first-party clients):
    for i in range(len(phrase)):
        phrase[i] = 0
    assert all(b == 0 for b in phrase)


# ---------------------------------------------------------------------------
# B.3b: create_vault tests against an in-process freshly-built vault.
# Bridge hardcodes OsRng + Argon2idParams::V1_DEFAULT, so each invocation
# costs ~1s (real Argon2id at 256 MiB / 3 iterations / 1 thread).
# ---------------------------------------------------------------------------


def test_create_vault_returns_artifacts_with_expected_shape(created_vault) -> None:
    """The two non-secret CreateVaultOutput byte fields exist with the
    expected types and non-zero lengths. The handle-typed fields
    (`identity`, `mnemonic`) are take-once getters that would clobber
    the fixture; their types are verified by the dedicated tests below
    (`_immediately_live` for identity, `_take_returns_24_words` for
    mnemonic). Uses the module-scoped fixture (no extra Argon2id cost)."""
    assert isinstance(created_vault.vault_toml_bytes, bytes)
    assert len(created_vault.vault_toml_bytes) > 0
    assert isinstance(created_vault.identity_bundle_bytes, bytes)
    assert len(created_vault.identity_bundle_bytes) > 0
    # The identity and mnemonic getters take ownership; assert their types
    # without consuming both — split into separate tests below (which use
    # fresh invocations to avoid clobbering the fixture).


def test_create_vault_identity_is_immediately_live() -> None:
    """The identity returned from create_vault is ready for vault
    operations without a second open_with_password call. Uses a fresh
    invocation since `identity` is take-once."""
    out = secretary_ffi_py.create_vault(
        password=b"x",
        display_name="ImmediateLive",
        created_at_ms=0,
    )
    with out.identity as identity:
        assert identity.display_name() == "ImmediateLive"
    out.mnemonic.close()


def test_create_vault_mnemonic_take_returns_24_words() -> None:
    """The recovery mnemonic exits the FFI as 24 space-separated UTF-8
    words. Pin the contract on the byte shape; the BIP-39 wordlist
    membership is core's responsibility (already covered by core tests)."""
    out = secretary_ffi_py.create_vault(
        password=b"x",
        display_name="X",
        created_at_ms=0,
    )
    with out.mnemonic as mn:
        phrase = mn.take_phrase()
        assert phrase is not None, "first call must return bytes"
        assert isinstance(phrase, bytes)
        assert len(phrase.split(b" ")) == 24, f"expected 24 words, got: {phrase!r}"
    out.identity.close()


def test_create_vault_mnemonic_take_is_one_shot() -> None:
    """Second take_phrase call returns None — documented one-shot
    semantics."""
    out = secretary_ffi_py.create_vault(
        password=b"x",
        display_name="X",
        created_at_ms=0,
    )
    with out.mnemonic as mn:
        first = mn.take_phrase()
        second = mn.take_phrase()
        assert first is not None
        assert second is None, "second take_phrase must return None"
    out.identity.close()


def test_create_vault_round_trip_with_password() -> None:
    """The vault bytes produced by create_vault re-open with the same
    password and yield the same display_name. Pins the dual-KEK
    convergence point: the bridge's create_vault and open_with_password
    agree on identity bytes."""
    pw = b"my-round-trip-password"
    out = secretary_ffi_py.create_vault(
        password=pw,
        display_name="RoundTripBob",
        created_at_ms=42_000,
    )
    out.mnemonic.close()  # not exercising the recovery path here
    with secretary_ffi_py.open_with_password(
        out.vault_toml_bytes,
        out.identity_bundle_bytes,
        pw,
    ) as id2:
        assert id2.display_name() == "RoundTripBob"
    out.identity.close()


def test_create_vault_round_trip_with_recovery() -> None:
    """The vault bytes produced by create_vault re-open via the recovery
    path using the just-taken mnemonic. Pins the create→take→open
    pipeline end-to-end."""
    out = secretary_ffi_py.create_vault(
        password=b"unused",
        display_name="RoundTripCarol",
        created_at_ms=42_000,
    )
    with out.mnemonic as mn:
        phrase = mn.take_phrase()
        assert phrase is not None
        with secretary_ffi_py.open_with_recovery(
            out.vault_toml_bytes,
            out.identity_bundle_bytes,
            phrase,
        ) as id2:
            assert id2.display_name() == "RoundTripCarol"
    out.identity.close()


# =============================================================================
# B.4a — folder-in open_vault tests
# =============================================================================


def test_open_vault_with_password_success() -> None:
    """Open vault from a folder with the correct password; verify both
    handles are populated and produce expected values."""
    folder = _golden_vault_path(1)
    password = bytearray(b"correct horse battery staple")
    out = secretary_ffi_py.open_vault_with_password(str(folder), bytes(password))
    # Wipe the bytearray immediately — caller-zeroize discipline.
    for i in range(len(password)):
        password[i] = 0

    with out as vault:
        with vault.identity as identity:
            assert identity.display_name() == "Owner"
            assert len(identity.user_uuid()) == 16
        with vault.manifest as manifest:
            assert len(manifest.vault_uuid()) == 16
            assert manifest.block_count() >= 0  # could be 0 if fixture has no blocks


def test_open_vault_with_recovery_success() -> None:
    """Same as test_open_vault_with_password_success but via the recovery path."""
    folder = _golden_vault_path(1)
    phrase = bytearray(_golden_vault_phrase(1))
    out = secretary_ffi_py.open_vault_with_recovery(str(folder), bytes(phrase))
    for i in range(len(phrase)):
        phrase[i] = 0

    with out as vault:
        with vault.identity as identity:
            assert identity.display_name() == "Owner"
            assert len(identity.user_uuid()) == 16


def test_open_vault_with_password_wrong_password_raises() -> None:
    """Wrong password → VaultWrongPasswordOrCorrupt."""
    folder = _golden_vault_path(1)
    with pytest.raises(secretary_ffi_py.VaultWrongPasswordOrCorrupt):
        secretary_ffi_py.open_vault_with_password(str(folder), b"definitely wrong")


def test_open_vault_with_recovery_invalid_phrase_raises() -> None:
    """3-word phrase → VaultInvalidMnemonic with detail mentioning word count."""
    folder = _golden_vault_path(1)
    with pytest.raises(secretary_ffi_py.VaultInvalidMnemonic) as exc_info:
        secretary_ffi_py.open_vault_with_recovery(str(folder), b"only three words")
    assert "got 3" in str(exc_info.value)


def test_open_vault_folder_does_not_exist_raises() -> None:
    """Nonexistent folder path → VaultFolderInvalid with detail mentioning the
    missing file."""
    folder = "/tmp/__nonexistent_folder_b4a__"
    with pytest.raises(secretary_ffi_py.VaultFolderInvalid) as exc_info:
        secretary_ffi_py.open_vault_with_password(folder, b"any password")
    detail = str(exc_info.value).lower()
    assert "vault.toml" in detail or "no such file" in detail


def test_block_summaries_round_trip_pinned_against_inputs_json() -> None:
    """Verify block_summaries() returns the JSON-pinned shape exactly."""
    folder = _golden_vault_path(1)
    pinned = _golden_vault_block_summaries(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.manifest as manifest:
            actual = manifest.block_summaries()
            assert manifest.block_count() == len(pinned)
            assert len(actual) == len(pinned)
            for a, p in zip(actual, pinned):
                assert bytes(a.block_uuid).hex() == p["block_uuid"]
                assert a.block_name == p["block_name"]
                assert a.created_at_ms == p["created_at_ms"]
                assert a.last_modified_ms == p["last_modified_ms"]
                actual_recipient_hex = [bytes(r).hex() for r in a.recipient_uuids]
                assert actual_recipient_hex == p["recipient_uuids"]


def test_find_block_returns_some_for_known_uuid_and_none_for_unknown() -> None:
    """Verify find_block() at the Python boundary: returns the matching
    BlockSummary for a known UUID and None for a not-present UUID.

    Also pins both `bytes` and `bytearray` acceptance — PyO3's `Vec<u8>`
    parameter takes either; if the signature were ever tightened to
    `&[u8]` only `bytes` would work, so the bytearray assertion is a
    deliberate tripwire for that regression."""
    folder = _golden_vault_path(1)
    pinned = _golden_vault_block_summaries(1)
    known_uuid_bytes = bytes.fromhex(pinned[0]["block_uuid"])
    unknown_uuid_bytes = bytes(16)  # 16 zero bytes — not present in the vault

    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")
    with out as vault:
        with vault.manifest as manifest:
            # Positive: known UUID returns matching summary.
            summary = manifest.find_block(known_uuid_bytes)
            assert summary is not None
            assert bytes(summary.block_uuid).hex() == pinned[0]["block_uuid"]
            assert summary.block_name == pinned[0]["block_name"]

            # bytearray input also works — PyO3's Vec<u8> conversion
            # accepts both immutable bytes and mutable bytearray.
            summary_ba = manifest.find_block(bytearray(known_uuid_bytes))
            assert summary_ba is not None
            assert bytes(summary_ba.block_uuid).hex() == pinned[0]["block_uuid"]

            # Negative: unknown UUID returns None (not an exception).
            assert manifest.find_block(unknown_uuid_bytes) is None

            # Wrong-length input returns None per the bridge's runtime check.
            assert manifest.find_block(b"\x00" * 15) is None
            assert manifest.find_block(b"\x00" * 17) is None


def test_with_block_double_close_invariants() -> None:
    """Nested context managers wipe each handle on exit; subsequent accessor
    calls return the documented empty defaults rather than raising."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), b"correct horse battery staple")

    # Take the handles out and enter them as context managers; after the
    # inner with-blocks exit, wipe() / close() has run on each handle.
    with out as vault:
        with vault.identity as identity:
            # Still live inside the block.
            assert identity.display_name() == "Owner"
        with vault.manifest as manifest:
            # Still live inside the block.
            assert manifest.block_count() >= 1

    # Both handles' wipe/close ran on with-block exit; accessors return defaults.
    assert identity.display_name() == ""
    assert identity.user_uuid() == bytes(16)
    assert manifest.vault_uuid() == bytes(16)
    assert manifest.block_count() == 0
    assert manifest.block_summaries() == []


# =============================================================================
# B.4b — read_block tests
# =============================================================================


def test_read_block_shape() -> None:
    """Open + read; assert record_count == 1 and field_count == 2."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID, include_deleted=False) as block:
                assert block.record_count() == 1
                assert block.block_name() == VAULT_001_BLOCK_NAME
                assert block.block_uuid() == VAULT_001_BLOCK_UUID
                record = block.record_at(0)
                assert record is not None
                assert record.field_count() == 2


def test_read_block_record_metadata() -> None:
    """Pin record_uuid, record_type, tags, tombstone, timestamps."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID, include_deleted=False) as block:
                record = block.record_at(0)
                assert record.record_uuid() == VAULT_001_RECORD_UUID
                assert record.record_type() == "login"
                assert record.tags() == ["work"]
                assert record.tombstone() is False
                assert record.created_at_ms() == VAULT_001_TIMESTAMP_MS
                assert record.last_mod_ms() == VAULT_001_TIMESTAMP_MS


def test_read_block_field_text_password() -> None:
    """Password field exposes 'hunter2' via expose_text()."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID, include_deleted=False) as block:
                record = block.record_at(0)
                pw_field = record.field_by_name("password")
                assert pw_field is not None
                assert pw_field.is_text()
                assert pw_field.expose_text() == VAULT_001_PASSWORD_VALUE


def test_read_block_field_text_username() -> None:
    """Username field exposes 'owner@example.com' via expose_text()."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID, include_deleted=False) as block:
                record = block.record_at(0)
                user_field = record.field_by_name("username")
                assert user_field is not None
                assert user_field.expose_text() == VAULT_001_USERNAME_VALUE


def test_read_block_field_metadata() -> None:
    """Field-level last_mod_ms + device_uuid match KAT for both fields."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID, include_deleted=False) as block:
                record = block.record_at(0)
                pw_field = record.field_by_name("password")
                user_field = record.field_by_name("username")
                assert pw_field is not None
                assert user_field is not None
                assert pw_field.last_mod_ms() == VAULT_001_TIMESTAMP_MS
                assert user_field.last_mod_ms() == VAULT_001_TIMESTAMP_MS
                assert pw_field.device_uuid() == VAULT_001_DEVICE_UUID
                assert user_field.device_uuid() == VAULT_001_DEVICE_UUID


def test_read_block_unknown_uuid_raises_block_not_found() -> None:
    """16 zero bytes is not a real block UUID → VaultBlockNotFound."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    unknown = bytes(16)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(secretary_ffi_py.VaultBlockNotFound) as exc_info:
                secretary_ffi_py.read_block(identity, manifest, unknown, include_deleted=False)
            # The exception payload carries the uuid_hex string.
            assert "00000000000000000000000000000000" in str(exc_info.value)


def test_read_block_wrong_length_uuid_raises_value_error() -> None:
    """15-byte UUID input → ValueError (NOT VaultBlockNotFound — distinct
    error class for programmer errors vs. data errors)."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError) as exc_info:
                secretary_ffi_py.read_block(identity, manifest, bytes(15), include_deleted=False)
            assert "16 bytes" in str(exc_info.value)
            assert "got 15" in str(exc_info.value)


def test_read_block_field_bytes_is_none_for_text_field() -> None:
    """expose_bytes() on a text field returns None (not raises)."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID, include_deleted=False) as block:
                record = block.record_at(0)
                pw_field = record.field_by_name("password")
                assert pw_field is not None
                assert pw_field.expose_bytes() is None
                assert pw_field.is_bytes() is False


def test_block_read_output_context_manager_wipes() -> None:
    """After exiting `with read_block(...) as block:`, accessors return
    empty defaults (record_count == 0)."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            block = secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID, include_deleted=False)
            assert block.record_count() == 1
            with block:
                pass  # __exit__ runs wipe()
            assert block.record_count() == 0
            assert block.record_at(0) is None


def test_record_field_handles_share_state_after_wipe() -> None:
    """Two foreign-side references to the same field handle: wipe one,
    the other returns None. Pins the Arc<Mutex<Option<...>>> shared-
    wipe contract through the PyO3 boundary."""
    folder = _golden_vault_path(1)
    out = secretary_ffi_py.open_vault_with_password(str(folder), VAULT_001_PASSWORD)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with secretary_ffi_py.read_block(identity, manifest, VAULT_001_BLOCK_UUID, include_deleted=False) as block:
                record_a = block.record_at(0)
                record_b = block.record_at(0)
                field_a = record_a.field_by_name("password")
                field_b = record_b.field_by_name("password")
                assert field_a is not None
                assert field_b is not None
                # Both clones live initially.
                assert field_a.expose_text() == VAULT_001_PASSWORD_VALUE
                assert field_b.expose_text() == VAULT_001_PASSWORD_VALUE
                # Wipe one — the other reflects.
                field_a.wipe()
                assert field_a.expose_text() is None
                assert field_b.expose_text() is None


# ---------------------------------------------------------------------------
# B.4c: save_block tests
#
# save_block mutates the on-disk vault — every test gets its own writable
# copy of golden_vault_001 in pytest's tmp_path so the read-only fixture
# is never touched. Mirrors the bridge crate's `fresh_writable_vault`
# helper and the Swift / Kotlin smoke runners' freshOpenVault helpers.
# ---------------------------------------------------------------------------

# Pinned UUIDs / timestamps for the new save_block tests. Distinct from
# golden_vault_001's existing block (whose uuid is 112233...ff00).
SAVE_BLOCK_NEW_BLOCK_UUID = bytes([0xAB] * 16)
SAVE_BLOCK_NEW_RECORD_UUID = bytes([0xCD] * 16)
SAVE_BLOCK_DEVICE_UUID = bytes([0x07] * 16)
SAVE_BLOCK_NOW_MS_BASE = 1_715_000_000_000


def _fresh_writable_vault(tmp_path: Path) -> tuple:
    """Copy golden_vault_001 into `tmp_path / vault001/` and open it.

    Returns the OpenVaultOutput handle so callers can use it as a context
    manager: `with _fresh_writable_vault(tmp_path) as out: ...`. The
    on-disk copy lives until `tmp_path` is reaped by pytest, so save
    mutations are visible to subsequent re-opens within the same test.
    """
    import shutil
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD), dst


def test_save_block_round_trip_insert(tmp_path: Path) -> None:
    """save_block insert → read_block round-trip preserves text + bytes."""
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            input = secretary_ffi_py.BlockInput(
                block_uuid=SAVE_BLOCK_NEW_BLOCK_UUID,
                block_name="Notes",
                records=[
                    secretary_ffi_py.RecordInput(
                        record_uuid=SAVE_BLOCK_NEW_RECORD_UUID,
                        fields=[
                            secretary_ffi_py.FieldInput(
                                "title",
                                secretary_ffi_py.FieldInputValue.text("wifi password"),
                            ),
                            secretary_ffi_py.FieldInput(
                                "key",
                                secretary_ffi_py.FieldInputValue.bytes(b"\xDE\xAD\xBE\xEF"),
                            ),
                        ],
                    ),
                ],
            )
            secretary_ffi_py.save_block(
                identity, manifest, input, SAVE_BLOCK_DEVICE_UUID, SAVE_BLOCK_NOW_MS_BASE,
            )
            with secretary_ffi_py.read_block(
                identity, manifest, SAVE_BLOCK_NEW_BLOCK_UUID, include_deleted=False,
            ) as block:
                assert block.record_count() == 1
                record = block.record_at(0)
                assert record.field_by_name("title").expose_text() == "wifi password"
                assert record.field_by_name("key").expose_bytes() == b"\xDE\xAD\xBE\xEF"


def test_save_block_update_replaces_existing_entry(tmp_path: Path) -> None:
    """Same block_uuid on second save replaces the manifest entry; the
    block_name advances and block_count stays at the new total (no double-
    counting)."""
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            pre_count = manifest.block_count()
            secretary_ffi_py.save_block(
                identity,
                manifest,
                secretary_ffi_py.BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "v1", []),
                SAVE_BLOCK_DEVICE_UUID,
                SAVE_BLOCK_NOW_MS_BASE,
            )
            secretary_ffi_py.save_block(
                identity,
                manifest,
                secretary_ffi_py.BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "v2", []),
                SAVE_BLOCK_DEVICE_UUID,
                SAVE_BLOCK_NOW_MS_BASE + 1_000,
            )
            assert manifest.block_count() == pre_count + 1
            summary = manifest.find_block(SAVE_BLOCK_NEW_BLOCK_UUID)
            assert summary is not None
            assert summary.block_name == "v2"


def test_save_block_with_empty_records_succeeds(tmp_path: Path) -> None:
    """Empty `records` is allowed (the spec permits empty blocks)."""
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            pre_count = manifest.block_count()
            secretary_ffi_py.save_block(
                identity,
                manifest,
                secretary_ffi_py.BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "empty", []),
                SAVE_BLOCK_DEVICE_UUID,
                SAVE_BLOCK_NOW_MS_BASE,
            )
            assert manifest.block_count() == pre_count + 1


def test_save_block_persists_visible_to_fresh_open(tmp_path: Path) -> None:
    """Save → drop handles → re-open from the same on-disk copy → block
    visible + payload readable. Pins persistence-to-disk + re-open
    agreement end-to-end."""
    out, dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            secretary_ffi_py.save_block(
                identity,
                manifest,
                secretary_ffi_py.BlockInput(
                    SAVE_BLOCK_NEW_BLOCK_UUID,
                    "persisted",
                    [
                        secretary_ffi_py.RecordInput(
                            SAVE_BLOCK_NEW_RECORD_UUID,
                            [
                                secretary_ffi_py.FieldInput(
                                    "k", secretary_ffi_py.FieldInputValue.text("v"),
                                ),
                            ],
                        ),
                    ],
                ),
                SAVE_BLOCK_DEVICE_UUID,
                SAVE_BLOCK_NOW_MS_BASE,
            )

    # Re-open the same on-disk copy in a fresh OpenVaultOutput.
    out2 = secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD)
    with out2 as vault2:
        with vault2.identity as identity2, vault2.manifest as manifest2:
            summary = manifest2.find_block(SAVE_BLOCK_NEW_BLOCK_UUID)
            assert summary is not None
            assert summary.block_name == "persisted"
            with secretary_ffi_py.read_block(
                identity2, manifest2, SAVE_BLOCK_NEW_BLOCK_UUID, include_deleted=False,
            ) as block:
                assert (
                    block.record_at(0).field_by_name("k").expose_text() == "v"
                )


def test_save_block_on_wiped_manifest_raises_corrupt_vault(tmp_path: Path) -> None:
    """Wipe the manifest → save_block raises VaultCorruptVault with
    `manifest` in the detail."""
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        identity = vault.identity
        manifest = vault.manifest
        manifest.wipe()
        with pytest.raises(secretary_ffi_py.VaultCorruptVault) as exc_info:
            secretary_ffi_py.save_block(
                identity,
                manifest,
                secretary_ffi_py.BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "x", []),
                SAVE_BLOCK_DEVICE_UUID,
                SAVE_BLOCK_NOW_MS_BASE,
            )
        assert "manifest" in str(exc_info.value)


def test_save_block_on_wiped_identity_raises_corrupt_vault(tmp_path: Path) -> None:
    """Wipe the identity → save_block raises VaultCorruptVault with
    `identity` in the detail.

    `UnlockedIdentity.close()` is the Python-facing zeroize trigger
    (matches Python's context-manager idiom); it forwards to the bridge
    crate's `wipe()` internally. Other handles expose `wipe()` directly."""
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        identity = vault.identity
        manifest = vault.manifest
        identity.close()
        with pytest.raises(secretary_ffi_py.VaultCorruptVault) as exc_info:
            secretary_ffi_py.save_block(
                identity,
                manifest,
                secretary_ffi_py.BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "x", []),
                SAVE_BLOCK_DEVICE_UUID,
                SAVE_BLOCK_NOW_MS_BASE,
            )
        assert "identity" in str(exc_info.value)


def test_save_block_input_wrong_length_block_uuid_raises_value_error() -> None:
    """`BlockInput(block_uuid=...)` length validation fires inside the
    constructor; no vault open required."""
    with pytest.raises(ValueError) as exc_info:
        secretary_ffi_py.BlockInput(b"\x00" * 5, "x", [])
    assert "16 bytes" in str(exc_info.value)
    assert "got 5" in str(exc_info.value)


def test_save_block_input_wrong_length_record_uuid_raises_value_error() -> None:
    """`RecordInput(record_uuid=...)` length validation fires inside the
    constructor — distinct from BlockInput's check."""
    with pytest.raises(ValueError) as exc_info:
        secretary_ffi_py.RecordInput(b"\x00" * 5, [])
    assert "16 bytes" in str(exc_info.value)
    assert "got 5" in str(exc_info.value)


def test_save_block_wrong_length_device_uuid_raises_value_error(tmp_path: Path) -> None:
    """`save_block(device_uuid=...)` length validation fires at the
    pyfunction boundary (BlockInput already validated block_uuid)."""
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError) as exc_info:
                secretary_ffi_py.save_block(
                    identity,
                    manifest,
                    secretary_ffi_py.BlockInput(SAVE_BLOCK_NEW_BLOCK_UUID, "x", []),
                    bytes(15),
                    SAVE_BLOCK_NOW_MS_BASE,
                )
            assert "device_uuid" in str(exc_info.value)
            assert "16 bytes" in str(exc_info.value)


def test_vault_save_crypto_failure_is_distinct_exception_class() -> None:
    """Smoke: VaultSaveCryptoFailure is importable, distinct from
    VaultCorruptVault, and is a subclass of Exception."""
    assert (
        secretary_ffi_py.VaultSaveCryptoFailure
        is not secretary_ffi_py.VaultCorruptVault
    )
    assert issubclass(secretary_ffi_py.VaultSaveCryptoFailure, Exception)


# ---------------------------------------------------------------------------
# B.4d: share_block tests
#
# share_block extends a block's recipient list. v1 single-author: only the
# vault owner can share blocks they authored. The tests below use
# golden_vault_001 as the owner and golden_vault_002 as the recipient
# ("Alice") — both are pre-built fixtures with distinct identities, which
# avoids the cost of an extra create_vault per test.
# ---------------------------------------------------------------------------

VAULT_002_PASSWORD = b"correct horse battery staple two"

SHARE_BLOCK_BLOCK_UUID = bytes([0xAB] * 16)
SHARE_BLOCK_RECORD_UUID = bytes([0xCD] * 16)
SHARE_BLOCK_DEVICE_UUID = bytes([0x07] * 16)
SHARE_BLOCK_NOW_MS_BASE = 1_715_000_001_000


def _alice_card_bytes(tmp_path: Path) -> bytes:
    """Open a writable copy of golden_vault_002 and return Alice's
    canonical-CBOR-encoded ContactCard bytes. Closes the vault before
    returning so subsequent tests can re-stage golden_vault_002 in
    distinct tmp_paths without contention.
    """
    import shutil
    dst = tmp_path / "vault002_alice"
    shutil.copytree(_golden_vault_path(2), dst)
    out = secretary_ffi_py.open_vault_with_password(str(dst), VAULT_002_PASSWORD)
    with out as vault:
        bytes_ = vault.manifest.owner_card_bytes()
    return bytes_


def _save_one_record_block(
    identity, manifest, block_uuid: bytes, record_uuid: bytes, name: str, value: str
) -> None:
    """Save a one-record block with a single text field. Mirrors save_block
    test patterns; helper to keep share_block tests focused on the share
    surface."""
    secretary_ffi_py.save_block(
        identity,
        manifest,
        secretary_ffi_py.BlockInput(
            block_uuid=block_uuid,
            block_name="shared",
            records=[
                secretary_ffi_py.RecordInput(
                    record_uuid=record_uuid,
                    fields=[
                        secretary_ffi_py.FieldInput(
                            name, secretary_ffi_py.FieldInputValue.text(value),
                        ),
                    ],
                ),
            ],
        ),
        SHARE_BLOCK_DEVICE_UUID,
        SHARE_BLOCK_NOW_MS_BASE,
    )


def test_share_block_owner_to_alice_appends_recipient_to_manifest(tmp_path: Path) -> None:
    """Happy path: owner saves a block, owner shares with Alice, manifest
    entry now lists 2 recipients (owner + Alice). Mirrors the bridge
    integration test's manifest-state assertion at the foreign layer."""
    alice_bytes = _alice_card_bytes(tmp_path)
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(
                identity, manifest, SHARE_BLOCK_BLOCK_UUID, SHARE_BLOCK_RECORD_UUID,
                "password", "hunter2",
            )
            owner_bytes = manifest.owner_card_bytes()
            assert owner_bytes is not None
            secretary_ffi_py.share_block(
                identity,
                manifest,
                SHARE_BLOCK_BLOCK_UUID,
                [owner_bytes],
                alice_bytes,
                SHARE_BLOCK_DEVICE_UUID,
                SHARE_BLOCK_NOW_MS_BASE + 1_000,
            )
            summary = manifest.find_block(SHARE_BLOCK_BLOCK_UUID)
            assert summary is not None
            assert len(summary.recipient_uuids) == 2


def test_share_block_wrong_length_block_uuid_raises_value_error(tmp_path: Path) -> None:
    """`share_block(block_uuid=...)` length validation fires at the
    pyfunction boundary."""
    alice_bytes = _alice_card_bytes(tmp_path)
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            owner_bytes = manifest.owner_card_bytes()
            with pytest.raises(ValueError) as exc_info:
                secretary_ffi_py.share_block(
                    identity, manifest,
                    b"\x00" * 5,  # wrong length
                    [owner_bytes], alice_bytes,
                    SHARE_BLOCK_DEVICE_UUID, SHARE_BLOCK_NOW_MS_BASE + 1_000,
                )
            assert "block_uuid" in str(exc_info.value)
            assert "16 bytes" in str(exc_info.value)


def test_share_block_wrong_length_device_uuid_raises_value_error(tmp_path: Path) -> None:
    """`share_block(device_uuid=...)` length validation fires at the
    pyfunction boundary."""
    alice_bytes = _alice_card_bytes(tmp_path)
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            owner_bytes = manifest.owner_card_bytes()
            with pytest.raises(ValueError) as exc_info:
                secretary_ffi_py.share_block(
                    identity, manifest, SHARE_BLOCK_BLOCK_UUID,
                    [owner_bytes], alice_bytes,
                    bytes(15),  # wrong length
                    SHARE_BLOCK_NOW_MS_BASE + 1_000,
                )
            assert "device_uuid" in str(exc_info.value)
            assert "16 bytes" in str(exc_info.value)


def test_share_block_with_duplicate_recipient_raises_already_present(tmp_path: Path) -> None:
    """Sharing the same recipient twice raises VaultRecipientAlreadyPresent."""
    alice_bytes = _alice_card_bytes(tmp_path)
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(
                identity, manifest, SHARE_BLOCK_BLOCK_UUID, SHARE_BLOCK_RECORD_UUID,
                "k", "v",
            )
            owner_bytes = manifest.owner_card_bytes()
            # First share succeeds.
            secretary_ffi_py.share_block(
                identity, manifest, SHARE_BLOCK_BLOCK_UUID,
                [owner_bytes], alice_bytes,
                SHARE_BLOCK_DEVICE_UUID, SHARE_BLOCK_NOW_MS_BASE + 1_000,
            )
            # Second share with the same alice raises.
            with pytest.raises(secretary_ffi_py.VaultRecipientAlreadyPresent):
                secretary_ffi_py.share_block(
                    identity, manifest, SHARE_BLOCK_BLOCK_UUID,
                    [owner_bytes, alice_bytes], alice_bytes,
                    SHARE_BLOCK_DEVICE_UUID, SHARE_BLOCK_NOW_MS_BASE + 2_000,
                )


def test_share_block_with_missing_existing_card_raises_missing_recipient_card(
    tmp_path: Path,
) -> None:
    """Empty existing_recipient_cards while the block has the owner as a
    recipient raises VaultMissingRecipientCard."""
    alice_bytes = _alice_card_bytes(tmp_path)
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(
                identity, manifest, SHARE_BLOCK_BLOCK_UUID, SHARE_BLOCK_RECORD_UUID,
                "k", "v",
            )
            with pytest.raises(secretary_ffi_py.VaultMissingRecipientCard):
                secretary_ffi_py.share_block(
                    identity, manifest, SHARE_BLOCK_BLOCK_UUID,
                    [],  # missing owner card
                    alice_bytes,
                    SHARE_BLOCK_DEVICE_UUID, SHARE_BLOCK_NOW_MS_BASE + 1_000,
                )


def test_share_block_with_malformed_card_bytes_raises_card_decode_failure(
    tmp_path: Path,
) -> None:
    """Garbage bytes for either existing card or new recipient raises
    VaultCardDecodeFailure."""
    alice_bytes = _alice_card_bytes(tmp_path)
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(
                identity, manifest, SHARE_BLOCK_BLOCK_UUID, SHARE_BLOCK_RECORD_UUID,
                "k", "v",
            )
            owner_bytes = manifest.owner_card_bytes()
            # Garbage in existing list.
            with pytest.raises(secretary_ffi_py.VaultCardDecodeFailure):
                secretary_ffi_py.share_block(
                    identity, manifest, SHARE_BLOCK_BLOCK_UUID,
                    [b"\xff" * 8], alice_bytes,
                    SHARE_BLOCK_DEVICE_UUID, SHARE_BLOCK_NOW_MS_BASE + 1_000,
                )
            # Garbage as new recipient.
            with pytest.raises(secretary_ffi_py.VaultCardDecodeFailure):
                secretary_ffi_py.share_block(
                    identity, manifest, SHARE_BLOCK_BLOCK_UUID,
                    [owner_bytes], b"\xff" * 8,
                    SHARE_BLOCK_DEVICE_UUID, SHARE_BLOCK_NOW_MS_BASE + 2_000,
                )


def test_share_block_typed_exception_classes_are_distinct() -> None:
    """Smoke: the 4 new B.4d typed exception classes are importable and
    pairwise distinct, each subclassing Exception. Mirrors
    test_vault_save_crypto_failure_is_distinct_exception_class.

    NotAuthor at the integration layer requires staging cross-vault
    manifest content; the bridge integration tests skipped this for
    practical reasons (see ffi/secretary-ffi-bridge/tests/share_block.rs's
    closing comment). Here we verify only the exception class is
    importable + distinct, leaving the integration-coverage gap to be
    closed by Sub-project C's sync-layer tests where cross-vault staging
    is the natural topology."""
    classes = [
        secretary_ffi_py.VaultNotAuthor,
        secretary_ffi_py.VaultRecipientAlreadyPresent,
        secretary_ffi_py.VaultMissingRecipientCard,
        secretary_ffi_py.VaultCardDecodeFailure,
    ]
    for cls in classes:
        assert issubclass(cls, Exception), f"{cls} must subclass Exception"
    # Pairwise distinct.
    assert len({id(c) for c in classes}) == len(classes)
    # Distinct from existing variants.
    assert secretary_ffi_py.VaultNotAuthor is not secretary_ffi_py.VaultSaveCryptoFailure
    assert (
        secretary_ffi_py.VaultMissingRecipientCard
        is not secretary_ffi_py.VaultBlockNotFound
    )


# create_vault_in_folder (iOS create/import Slice 1): folder-writing create.


def test_create_vault_in_folder_writes_openable_vault() -> None:
    """create_vault_in_folder writes all four canonical files; the folder
    then opens through open_vault_with_password (which validates the
    manifest + owner card)."""
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp) / "vault"
        folder.mkdir()
        mnem = secretary_ffi_py.create_vault_in_folder(
            str(folder), b"hunter2", "Py-Folder-Bob", 1_700_000_000_000
        )
        phrase = mnem.take_phrase()
        assert phrase is not None
        assert len(bytes(phrase).split(b" ")) == 24

        assert (folder / "vault.toml").is_file()
        assert (folder / "identity.bundle.enc").is_file()
        assert (folder / "manifest.cbor.enc").is_file()
        assert (folder / "contacts").is_dir()

        out = secretary_ffi_py.open_vault_with_password(str(folder), b"hunter2")
        assert out.identity.display_name() == "Py-Folder-Bob"


def test_create_vault_in_folder_rejects_nonempty_folder() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp) / "vault"
        folder.mkdir()
        (folder / "junk").write_bytes(b"x")
        with pytest.raises(secretary_ffi_py.VaultFolderNotEmpty):
            secretary_ffi_py.create_vault_in_folder(
                str(folder), b"pw", "X", 1_700_000_000_000
            )


def test_create_vault_in_folder_rejects_missing_folder() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        missing = Path(tmp) / "does-not-exist"
        with pytest.raises(secretary_ffi_py.VaultFolderInvalid):
            secretary_ffi_py.create_vault_in_folder(
                str(missing), b"pw", "X", 1_700_000_000_000
            )
