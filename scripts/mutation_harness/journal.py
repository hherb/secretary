"""A durable record of original bytes, so a restore survives an abnormal exit.

Spec §5.4. A `finally` block is skipped by a kill; a journal on disk is not.
The ordering is the whole mechanism: the backup and the index are written and
fsynced BEFORE the first byte of the target changes, so there is no window in
which a file is mutated and unrecorded.

The index and the backup blobs use DIFFERENT durability mechanisms, on
purpose (fix round 1, finding 1): a backup is write-once to a fresh,
content-addressed name, so `_fsync_write`'s straightforward
open("wb")+write+fsync is safe — a torn write can only corrupt its OWN
bytes, and `restore()`'s post-write sha256 check catches that. The index
instead accumulates every prior entry in ONE file that gets REWRITTEN on
every `record()`/`restore()`; a naive truncating write there can destroy an
already-durable prior entry if the process dies while writing the new,
larger state — turning a correctly-recorded-and-mutated file into one with
no readable record at all. `_atomic_replace_write` avoids that by never
truncating the live index: write the new content to a temp file in the same
directory, fsync it, `os.replace` it over the index, then fsync the
directory so the rename itself survives a kill.

An undrained journal makes the NEXT invocation refuse to run (see
`selftest`/`mutate`), which is the structural fix for a mutation left applied
by a stalled worker. A journal whose index cannot be parsed fails CLOSED with
a typed `CorruptJournal` rather than silently reporting a possibly-mutated
tree as clean.
"""

from __future__ import annotations

import atexit
import dataclasses
import hashlib
import json
import os
import signal
import sys
import tempfile
from pathlib import Path

JOURNAL_NAME = "mutation-journal.json"


class RestoreFailed(RuntimeError):
    """A restore could not be completed or verified. Always fatal —
    continuing would run the next mutation against a poisoned tree. Raised
    both for a post-write sha256 mismatch and for a backup blob that could
    not even be read (e.g. missing) — both are the same failure class: this
    restore cannot be trusted, so it must not be treated as done."""


class CorruptJournal(RuntimeError):
    """The on-disk journal index could not be parsed. Fails CLOSED,
    deliberately: a target this journal was tracking may already be mutated
    with no readable record of it, so treating this as an empty (clean)
    journal would report a possibly-poisoned tree as safe — the exact
    fail-open direction this project exists to avoid. Backup blobs, if any
    were written, remain on disk beside the index; recovering them is a
    manual, human decision, not something this constructor should guess at."""


@dataclasses.dataclass(frozen=True)
class JournalEntry:
    path: str
    sha256: str
    backup_name: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_write(path: Path, data: bytes) -> None:
    """Write-once-to-a-fresh-name and fsync a backup blob, so a kill
    immediately afterwards cannot lose it. Deliberately NOT used for the
    index — see `_atomic_replace_write` and the module docstring for why
    the two need different durability mechanisms."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _fsync_dir(directory: Path) -> None:
    """fsync a directory so a rename performed inside it is durable, not
    merely visible to a subsequent read in the same process."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_replace_write(path: Path, data: bytes) -> None:
    """Replace `path`'s contents without ever truncating its existing
    durable bytes before the replacement is complete.

    Write `data` to a temp file in the SAME directory (so the later rename
    stays on one filesystem), fsync the temp file, `os.replace` it over
    `path` (atomic on POSIX), then fsync the directory so the rename itself
    survives a kill immediately afterwards. This is what the journal INDEX
    needs and a backup blob does not — see the module docstring.
    """
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    _fsync_dir(directory)


class Journal:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.dir / JOURNAL_NAME
        self._entries: list[JournalEntry] = self._load()

    def _load(self) -> list[JournalEntry]:
        if not self.index_path.exists():
            return []
        try:
            raw = json.loads(self.index_path.read_text())
        except json.JSONDecodeError as exc:
            raise CorruptJournal(
                f"journal index {self.index_path} is corrupt and could not "
                f"be parsed ({exc}); a target this journal was tracking may "
                f"already be mutated with no readable record of it. Backup "
                f"blobs, if any, remain in {self.dir} — do not proceed "
                f"without manual review."
            ) from exc
        return [JournalEntry(**e) for e in raw.get("entries", [])]

    def _flush(self) -> None:
        payload = {"entries": [dataclasses.asdict(e) for e in self._entries]}
        _atomic_replace_write(self.index_path, json.dumps(payload, indent=2).encode())

    def is_dirty(self) -> bool:
        return bool(self._entries)

    def dirty_paths(self) -> list[str]:
        return [e.path for e in self._entries]

    def record(self, target: Path) -> JournalEntry:
        """Copy the original bytes aside and index them, BEFORE any mutation."""
        target = Path(target).resolve()
        data = target.read_bytes()
        digest = _sha256(data)
        backup_name = f"{digest[:16]}-{target.name}.orig"
        _fsync_write(self.dir / backup_name, data)
        entry = JournalEntry(path=str(target), sha256=digest, backup_name=backup_name)
        self._entries.append(entry)
        self._flush()
        return entry

    def restore(self, entry: JournalEntry) -> None:
        """Restore, then VERIFY. A mismatch — or a backup that cannot even
        be read — aborts rather than continuing."""
        backup_path = self.dir / entry.backup_name
        try:
            data = backup_path.read_bytes()
        except OSError as exc:
            raise RestoreFailed(
                f"restore of {entry.path} failed: backup {backup_path} "
                f"could not be read ({exc})"
            ) from exc
        Path(entry.path).write_bytes(data)
        actual = _sha256(Path(entry.path).read_bytes())
        if actual != entry.sha256:
            raise RestoreFailed(
                f"restore of {entry.path} failed sha256 verification: "
                f"expected {entry.sha256}, got {actual}"
            )
        self._entries = [e for e in self._entries if e.backup_name != entry.backup_name]
        self._flush()

    def drain(self) -> list[str]:
        """Restore every outstanding entry, most-recently-recorded first
        (LIFO). Unwinding in the reverse of record order is what makes a
        repeated `record()` on the same path (a second mutation applied
        before the first was restored) correct by construction: restoring
        in insertion order would land the file on the intermediate,
        first-mutation snapshot instead of the true original — draining
        LIFO always peels back to the earliest recorded state, the way
        nested exception handling unwinds. Returns the paths restored, in
        the order restored."""
        restored = []
        for entry in reversed(list(self._entries)):
            self.restore(entry)
            restored.append(entry.path)
        return restored

    def install_handlers(self) -> None:
        """Drain on normal exit AND on SIGINT/SIGTERM. A SIGKILL cannot be
        trapped, which is exactly why the on-disk journal exists."""
        atexit.register(self._drain_quietly)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._on_signal)

    def _drain_quietly(self) -> None:
        try:
            self.drain()
        except Exception as exc:  # noqa: BLE001 - last-ditch; must not mask exit
            print(f"mutate: JOURNAL DRAIN FAILED: {exc}", file=sys.stderr)

    def _on_signal(self, signum, _frame) -> None:
        self._drain_quietly()
        sys.exit(128 + signum)
