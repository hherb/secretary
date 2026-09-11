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
    """A kill immediately after record() must leave a recoverable journal.

    This test's first version never applied a mutation, so it pinned that
    `record()` persists the index, not the ORDERING its name claims (PR #652
    review). The mutation is applied now, and a FRESH journal — what the
    next invocation constructs — must drain back to the original bytes from
    what is on disk alone.
    """
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    j.record(target)
    on_disk = json.loads((tmp_path / "jdir" / "mutation-journal.json").read_text())
    assert on_disk["entries"][0]["path"] == str(target.resolve())
    assert on_disk["entries"][0]["sha256"] == hashlib.sha256(b"original\n").hexdigest()

    target.write_text("mutated\n")
    del j

    assert Journal(tmp_path / "jdir").drain() == [str(target.resolve())]
    assert target.read_text() == "original\n"


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


def test_a_blob_written_but_never_indexed_is_not_a_record(tmp_path):
    """The kill window BETWEEN the blob write and the index replace: the
    orphan blob is inert, the index is clean, and — because the target is
    never mutated before the index is durable — the file is untouched."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    (tmp_path / "jdir" / "mutation-journal.json").unlink()  # the index never landed

    reopened = Journal(tmp_path / "jdir")
    assert not reopened.is_dirty()
    assert reopened.drain() == []
    assert (tmp_path / "jdir" / entry.backup_name).exists()
    assert target.read_text() == "original\n"


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


def test_a_corrupt_blob_is_refused_before_the_target_is_touched(tmp_path):
    """The first version wrote the blob over the target and hashed what it
    had written, so a corrupt-but-readable blob destroyed the mutated file
    as well as failing the restore (PR #652 review)."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    (tmp_path / "jdir" / entry.backup_name).write_text("tampered\n")
    target.write_text("mutated\n")

    with pytest.raises(RestoreFailed, match="left untouched"):
        j.restore(entry)

    assert target.read_text() == "mutated\n"
    assert j.is_dirty()


def test_a_target_that_cannot_be_written_is_a_typed_restore_failure(tmp_path):
    """A write or re-read `OSError` used to escape untyped, past the
    `RESTORE_FAILED` row and the documented exit 3."""
    nested = tmp_path / "gone"
    nested.mkdir()
    target = nested / "f.txt"
    target.write_text("original\n")
    j = Journal(tmp_path / "jdir")
    entry = j.record(target)
    target.unlink()
    nested.rmdir()

    with pytest.raises(RestoreFailed, match="could not be written"):
        j.restore(entry)

    assert j.is_dirty()


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


# --- PR #652 review: entry identity, drain-all, the `entries` key ----------


def test_restoring_one_of_two_same_named_same_content_files_keeps_the_other_recorded(tmp_path):
    """Two paths with the same basename and identical bytes share one
    content-addressed blob; removing entries by BLOB NAME dropped the
    sibling's record while its file stayed mutated — `is_dirty()` False,
    file dirty: false-green mechanism 3 inside the journal."""
    a = tmp_path / "x" / "mod.rs"
    b = tmp_path / "y" / "mod.rs"
    for path in (a, b):
        path.parent.mkdir()
        path.write_text("same\n")
    j = Journal(tmp_path / "jdir")
    entry_a = j.record(a)
    j.record(b)
    a.write_text("mut-a\n")
    b.write_text("mut-b\n")

    j.restore(entry_a)

    assert a.read_text() == "same\n"
    assert b.read_text() == "mut-b\n"
    assert j.is_dirty()
    assert Journal(tmp_path / "jdir").dirty_paths() == [str(b.resolve())]


def test_drain_attempts_every_entry_and_names_what_is_still_mutated(tmp_path):
    """Stopping at the first failure left later entries mutated and unnamed,
    and every subsequent `--drain` re-hit the same entry first."""
    files = {}
    for name in ("a", "b", "c"):
        path = tmp_path / f"{name}.txt"
        path.write_text(f"{name}-original\n")
        files[name] = path
    j = Journal(tmp_path / "jdir")
    entries = {name: j.record(path) for name, path in files.items()}
    for name, path in files.items():
        path.write_text(f"{name}-mutated\n")
    (tmp_path / "jdir" / entries["b"].backup_name).unlink()

    with pytest.raises(RestoreFailed) as info:
        j.drain()

    assert files["a"].read_text() == "a-original\n"
    assert files["c"].read_text() == "c-original\n"
    assert files["b"].read_text() == "b-mutated\n"
    assert j.dirty_paths() == [str(files["b"].resolve())]
    message = str(info.value)
    assert "1 of 3" in message and str(files["b"].resolve()) in message
    assert "still mutated" in message


@pytest.mark.parametrize("body", ["{}", '{"entrys": [{"path": "x", "sha256": "y", "backup_name": "z"}]}'],
                         ids=["empty-object", "misspelt-key"])
def test_an_index_without_an_entries_key_is_corrupt_not_clean(tmp_path, body):
    """`.get("entries", [])` read both of these as a CLEAN journal."""
    journal_dir = tmp_path / "jdir"
    journal_dir.mkdir()
    (journal_dir / "mutation-journal.json").write_text(body)

    with pytest.raises(CorruptJournal, match="no 'entries' key"):
        Journal(journal_dir)


def test_signal_dispositions_are_recorded_and_handed_back(tmp_path):
    before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    j = Journal(tmp_path / "jdir")
    try:
        j.install_handlers()
        assert signal.getsignal(signal.SIGTERM) == j._on_signal
        j.restore_signal_dispositions()
        assert {sig: signal.getsignal(sig) for sig in before} == before
        j.restore_signal_dispositions()  # idempotent
        assert {sig: signal.getsignal(sig) for sig in before} == before
    finally:
        j.uninstall_handlers()


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


# --- Final whole-branch review, Finding 5: structurally-malformed index -----


@pytest.mark.parametrize(
    "body, because",
    [
        ('["not", "an", "object"]', "top-level list -> AttributeError on .get"),
        ('{"entries": 5}', "entries is an int -> TypeError on iteration"),
        ('{"entries": null}', "entries is null -> TypeError on iteration"),
        ('{"entries": [7]}', "entry is not an object -> TypeError on **"),
        ('{"entries": [{"path": "/tmp/x"}]}', "entry missing keys -> TypeError on **"),
        ('{"entries": [{"path": "/tmp/x", "sha256": "d", "backup_name": "b", "x": 1}]}',
         "entry has an extra key -> TypeError on **"),
        ('{"entries": [{"path": 1, "sha256": "d", "backup_name": "b"}]}',
         "entry field is not a string -> silently accepted"),
    ],
    ids=["top-list", "entries-int", "entries-null", "entry-int", "entry-short",
         "entry-extra-key", "entry-wrong-type"],
)
def test_a_structurally_malformed_index_fails_closed_as_corrupt_journal(
    tmp_path, body, because
):
    """`_load` special-cased `JSONDecodeError` only, so an index that was
    valid JSON but the wrong SHAPE escaped as an untyped `AttributeError` or
    `TypeError` — bypassing the one message that tells a reader backup blobs
    remain on disk and a human must decide what to do with them.

    The last row is the quietest: a non-string field was accepted outright
    and became a `JournalEntry` whose `path` is an int, failing much later
    inside a restore.
    """
    journal_dir = tmp_path / "jdir"
    journal_dir.mkdir()
    (journal_dir / "mutation-journal.json").write_text(body)

    with pytest.raises(CorruptJournal, match="do not proceed without manual review") as exc:
        Journal(journal_dir)

    assert str(journal_dir) in str(exc.value), because


def test_a_non_utf8_index_fails_closed_as_corrupt_journal(tmp_path):
    """`read_text()` raises `UnicodeDecodeError` (a ValueError, not a
    JSONDecodeError) before `json.loads` is ever reached."""
    journal_dir = tmp_path / "jdir"
    journal_dir.mkdir()
    (journal_dir / "mutation-journal.json").write_bytes(b"\xff\xfe not utf-8")

    with pytest.raises(CorruptJournal):
        Journal(journal_dir)


def test_a_well_formed_index_still_loads(tmp_path):
    """The negative control: the validation above must not reject the shape
    this module actually writes."""
    target = tmp_path / "f.txt"
    target.write_text("original\n")
    Journal(tmp_path / "jdir").record(target)

    reopened = Journal(tmp_path / "jdir")

    assert reopened.dirty_paths() == [str(target.resolve())]


def test_dispositions_stay_ignored_once_a_signal_has_been_handled(tmp_path):
    """`_on_signal`'s `sys.exit` unwinds through `run_mutations`'s `finally`,
    which used to re-arm the default disposition — so a second Ctrl-C could
    interrupt the `atexit` drain mid-write."""
    j = Journal(tmp_path / "jdir")
    before = signal.getsignal(signal.SIGTERM)
    try:
        j.install_handlers()
        j._signalled = True  # what `_on_signal` records first
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        j.restore_signal_dispositions()
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGTERM, before)
        j.uninstall_handlers()
