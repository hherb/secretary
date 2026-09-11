import hashlib
import json
import re
import selectors
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from mutation_harness.journal import CorruptJournal, Journal, RestoreFailed


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


# --- Fix round 1 additions ---------------------------------------------


def test_a_corrupt_index_fails_closed_with_a_typed_error(tmp_path):
    """Finding 1 (Critical): a journal whose index cannot be parsed must
    never be silently treated as clean (an empty entries list) — that would
    report a possibly-mutated tree as safe. It must raise a typed,
    directory-naming error instead."""
    journal_dir = tmp_path / "jdir"
    journal_dir.mkdir()
    (journal_dir / "mutation-journal.json").write_text("{not valid json")
    with pytest.raises(CorruptJournal, match=re.escape(str(journal_dir))):
        Journal(journal_dir)


def test_flush_leaves_no_temp_artifacts_behind(tmp_path):
    """Finding 1 (Critical): the index is now written via a temp-file +
    os.replace atomic-rename, not a truncating open(). A successful flush
    must leave no leftover `.tmp` file in the journal directory."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    journal_dir = tmp_path / "jdir"
    Journal(journal_dir).record(target)
    leftover = [p for p in journal_dir.iterdir() if p.name.endswith(".tmp")]
    assert leftover == []


def test_repeated_record_before_drain_restores_the_true_original(tmp_path):
    """Finding 2 (Important): two record() calls on the same path before a
    drain must not leave the file in the intermediate (first-mutation)
    state. drain() must unwind LIFO, restoring the second (most recent)
    entry first and the first (true-original) entry last."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    j.record(target)
    target.write_text("mutated-once\n")
    j.record(target)
    target.write_text("mutated-twice\n")

    restored_paths = j.drain()

    assert restored_paths == [str(target.resolve()), str(target.resolve())]
    assert target.read_text() == "original\n"
    assert not j.is_dirty()


def test_restore_raises_restorefailed_when_the_backup_is_missing(tmp_path):
    """Finding 4 (Minor): a missing backup blob must fail closed as the
    module's own typed RestoreFailed, not a bare FileNotFoundError — same
    failure class as a sha256 mismatch, consistently typed."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    (tmp_path / "jdir" / entry.backup_name).unlink()
    target.write_text("mutated\n")

    with pytest.raises(RestoreFailed, match="backup"):
        j.restore(entry)

    # Fail-closed: the entry must still be there for a future retry.
    assert j.is_dirty()


_SIGNAL_WORKER_SCRIPT = """\
import sys
import time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from mutation_harness.journal import Journal

target = Path(sys.argv[2])
journal_dir = Path(sys.argv[3])

j = Journal(journal_dir)
j.install_handlers()
j.record(target)
target.write_text("mutated-by-subprocess\\n")
print("READY", flush=True)
time.sleep(30)
"""


def _wait_readable(stream, timeout):
    sel = selectors.DefaultSelector()
    sel.register(stream, selectors.EVENT_READ)
    try:
        return bool(sel.select(timeout=timeout))
    finally:
        sel.close()


def test_a_sigterm_mid_mutation_is_restored_by_the_installed_signal_handler(tmp_path):
    """Finding 3 (Minor): this module's whole claim is surviving a kill.
    Prove it by actually sending SIGTERM to a live subprocess mid-mutation
    — not by calling `_on_signal` directly — so `install_handlers()`,
    `_on_signal`, and `_drain_quietly` are exercised for real."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    journal_dir = tmp_path / "jdir"
    scripts_dir = str(Path(__file__).resolve().parents[2])

    proc = subprocess.Popen(
        [sys.executable, "-c", _SIGNAL_WORKER_SCRIPT, scripts_dir, str(target), str(journal_dir)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if not _wait_readable(proc.stdout, timeout=10.0):
            proc.kill()
            proc.wait(timeout=5)
            raise AssertionError(
                f"subprocess never signalled READY; stderr={proc.stderr.read()!r}"
            )
        ready_line = proc.stdout.readline()
        assert ready_line.strip() == "READY", (ready_line, proc.stderr.read())
        assert target.read_text() == "mutated-by-subprocess\n"

        proc.send_signal(signal.SIGTERM)
        returncode = proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

    assert returncode == 128 + signal.SIGTERM
    assert target.read_text() == "original\n"
    assert not Journal(journal_dir).is_dirty()
