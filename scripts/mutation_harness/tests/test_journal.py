import hashlib
import json

import pytest

from mutation_harness.journal import Journal, RestoreFailed


def test_record_then_restore_round_trips(tmp_path):
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    target.write_text("mutated\n")
    j.restore(entry)
    assert target.read_text() == "original\n"
    assert not j.is_dirty()


def test_journal_is_written_before_the_mutation(tmp_path):
    """A kill immediately after record() must leave a recoverable journal."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    j.record(target)
    on_disk = json.loads((tmp_path / "jdir" / "mutation-journal.json").read_text())
    assert on_disk["entries"][0]["path"] == str(target.resolve())
    assert on_disk["entries"][0]["sha256"] == hashlib.sha256(b"original\n").hexdigest()


def test_a_fresh_journal_in_the_same_dir_sees_the_dirty_entry(tmp_path):
    """This is the refusal path: a SIGKILL leaves the journal, and the NEXT
    invocation must see it rather than the run being lost."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    Journal(tmp_path / "jdir").record(target)
    target.write_text("mutated\n")

    reopened = Journal(tmp_path / "jdir")
    assert reopened.is_dirty()
    assert reopened.dirty_paths() == [str(target.resolve())]
    assert reopened.drain() == [str(target.resolve())]
    assert target.read_text() == "original\n"
    assert not reopened.is_dirty()


def test_restore_verifies_sha256_and_raises_on_mismatch(tmp_path, monkeypatch):
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    # Corrupt the backup so the restored bytes will not match the recorded hash.
    (tmp_path / "jdir" / entry.backup_name).write_text("tampered\n")
    target.write_text("mutated\n")
    with pytest.raises(RestoreFailed, match="sha256"):
        j.restore(entry)


def test_drain_on_a_clean_journal_is_a_no_op(tmp_path):
    j = Journal(tmp_path / "jdir")
    assert j.drain() == []
    assert not j.is_dirty()


def test_binary_files_round_trip(tmp_path):
    target = tmp_path / "f.bin"
    target.write_bytes(bytes(range(256)))
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    target.write_bytes(b"\x00")
    j.restore(entry)
    assert target.read_bytes() == bytes(range(256))
