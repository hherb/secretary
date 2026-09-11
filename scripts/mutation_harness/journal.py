"""A durable record of original bytes, so a restore survives an abnormal exit.

Spec §5.4. A `finally` block is skipped by a kill; a journal on disk is not.
The ordering is the whole mechanism: the backup and the index are written and
fsynced BEFORE the first byte of the target changes, so there is no window in
which a file is mutated and unrecorded.

An undrained journal makes the NEXT invocation refuse to run (see
`selftest`/`mutate`), which is the structural fix for a mutation left applied
by a stalled worker.
"""

from __future__ import annotations

import atexit
import dataclasses
import hashlib
import json
import os
import signal
import sys
from pathlib import Path

JOURNAL_NAME = "mutation-journal.json"


class RestoreFailed(RuntimeError):
    """A restored file did not match its recorded sha256. Always fatal —
    continuing would run the next mutation against a poisoned tree."""


@dataclasses.dataclass(frozen=True)
class JournalEntry:
    path: str
    sha256: str
    backup_name: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_write(path: Path, data: bytes) -> None:
    """Write and fsync, so a kill immediately afterwards cannot lose it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


class Journal:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.dir / JOURNAL_NAME
        self._entries: list[JournalEntry] = self._load()

    def _load(self) -> list[JournalEntry]:
        if not self.index_path.exists():
            return []
        raw = json.loads(self.index_path.read_text())
        return [JournalEntry(**e) for e in raw.get("entries", [])]

    def _flush(self) -> None:
        payload = {"entries": [dataclasses.asdict(e) for e in self._entries]}
        _fsync_write(self.index_path, json.dumps(payload, indent=2).encode())

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
        """Restore, then VERIFY. A mismatch aborts rather than continuing."""
        data = (self.dir / entry.backup_name).read_bytes()
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
        """Restore every outstanding entry. Returns the paths restored."""
        restored = []
        for entry in list(self._entries):
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
