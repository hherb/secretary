"""A durable record of original bytes, so a restore survives an abnormal exit.

Spec §5.4. A `finally` block is skipped by a kill; a journal on disk is not.
The ordering is the whole mechanism: the backup and the index are written and
fsynced BEFORE the first byte of the target changes, so there is no window in
which a file is mutated and unrecorded.

The index and the backup blobs use DIFFERENT durability mechanisms, on
purpose (fix round 1, finding 1): a backup is write-once to a fresh,
content-addressed name, so `_fsync_write`'s straightforward
open("wb")+write+fsync is safe — a torn write can only corrupt its OWN
bytes, and `restore()`'s sha256 check catches that. The index instead
accumulates every prior entry in ONE file that gets REWRITTEN on every
`record()`/`restore()`; a naive truncating write there can destroy an
already-durable prior entry if the process dies while writing the new,
larger state — turning a correctly-recorded-and-mutated file into one with
no readable record at all. `_atomic_replace_write` avoids that by never
truncating the live index: write the new content to a temp file in the same
directory, fsync it, `os.replace` it over the index, then fsync the
directory so the rename itself survives a kill.

An undrained journal makes the NEXT invocation refuse to run (see
`selftest`/`mutate`), which is the structural fix for a mutation left applied
by a stalled worker. A journal whose index cannot be parsed — or is missing
its `entries` key, which the first version read as an empty list — fails
CLOSED with a typed `CorruptJournal` rather than silently reporting a
possibly-mutated tree as clean.

**`restore()` verifies the blob BEFORE it touches the target** (PR #652
review). The first version wrote the blob over the target and hashed what it
had written, so a corrupt-but-readable blob destroyed the mutated file as
well as failing the restore. And it converted only a blob READ failure to
`RestoreFailed`; a target write or re-read `OSError` escaped untyped, past the
`RESTORE_FAILED` row and the documented exit 3. Both are typed now.

**`drain()` attempts EVERY entry before raising** (PR #652 review). Stopping
at the first failure left later entries mutated and unnamed, and every
subsequent `--drain` re-hit the same entry first, so the rest were
unreachable until that one was repaired by hand.

`install_handlers()` registers a PROCESS-LIFETIME `atexit` hook — by design,
for real usage: a genuinely mutated tree at shutdown must be reported, and
"process lifetime" is what makes that report reliable regardless of which
code path exits. It also records what SIGINT/SIGTERM pointed at before it
ran, and `restore_signal_dispositions()` hands them back — `run_mutations`
calls it in its own `finally`, so the dispositions are process-global state
each run BORROWS rather than overwrites. (The first version left every
run's handler installed: in a pytest process a SIGTERM landed in whichever
`Journal` had installed last, whose temp directory was gone, and became an
in-test `SystemExit` that the runner recorded as an ordinary failure and
kept going past.) `uninstall_handlers()` (fix round 3) undoes the `atexit`
half and exists ONLY for the one self-test control that deliberately
corrupts its own backup to prove `RESTORE_FAILED` is observable
(`selftest.check_restore_failed_is_observable`) — its journal is left
permanently dirty by construction, so the hook fires at INTERPRETER
shutdown, long after that control already made its assertion, printing a
`JOURNAL DRAIN FAILED` line after an otherwise-green summary. Do not call it
from anywhere else: a real `RestoreFailed` legitimately wants that shutdown
message, and suppressing it there would be the exact failure mode this
harness exists to prevent, reproduced in its own output.

LIMIT, documented rather than closed: `_atomic_replace_write` fsyncs the
directory AFTER `os.replace`, and on a filesystem where directory fsync
raises, a `--drain` restores the file, then fails to flush the index, so the
entry never leaves it — every later `--drain` repeats the restore and the
same failure, and the error it prints names the fsync, not the loop.
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
_HANDLED_SIGNALS = (signal.SIGINT, signal.SIGTERM)

# Maps a resolved journal DIRECTORY to the live `Journal` instance whose
# `install_handlers()` registered an atexit hook for it. Exists solely so
# `uninstall_handlers()` is reachable from a caller that does not hold the
# exact instance object `run_mutations()` constructs internally (`mutate.py`
# drives it through a CLI-argv interface with no channel for one) —
# `atexit.unregister` matches a bound method by identity of its `__self__`,
# not by equality of the underlying object, so a FRESH `Journal(same_dir)`
# cannot unregister an EARLIER instance's hook; only the original object can.
_INSTALLED: dict[str, "Journal"] = {}


class RestoreFailed(RuntimeError):
    """A restore could not be completed or verified. Always fatal —
    continuing would run the next mutation against a poisoned tree. Raised
    for a backup blob that cannot be read, a blob whose bytes do not match
    the recorded sha256 (refused BEFORE the target is touched), a target
    that cannot be written or re-read, and a post-write sha256 mismatch —
    all one failure class: this restore cannot be trusted, so it must not
    be treated as done."""


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
        self._previous_dispositions: dict[int, object] = {}
        self._signalled = False

    def _corrupt(self, reason: str) -> CorruptJournal:
        """One message for every way the index can be unusable.

        `CorruptJournal`'s value is the second half of this text — that backup
        blobs remain on disk and a human must decide. Until the final
        whole-branch review only `JSONDecodeError` got it: a structurally
        malformed but syntactically VALID index escaped as an untyped
        `AttributeError` (a top-level JSON list, where `.get` does not exist)
        or `TypeError` (`entries` an int/null, or entry objects with the wrong
        keys reaching `JournalEntry(**e)`), so the one thing a reader needed to
        be told was exactly what they did not get.
        """
        return CorruptJournal(
            f"journal index {self.index_path} {reason}; a target this journal "
            f"was tracking may already be mutated with no readable record of "
            f"it. Backup blobs, if any, remain in {self.dir} — do not proceed "
            f"without manual review."
        )

    def _load(self) -> list[JournalEntry]:
        if not self.index_path.exists():
            return []
        try:
            raw = json.loads(self.index_path.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise self._corrupt(f"is corrupt and could not be parsed ({exc})") from exc
        if not isinstance(raw, dict):
            raise self._corrupt(
                f"is a JSON {type(raw).__name__}, not an object with an 'entries' key"
            )
        if "entries" not in raw:
            # `.get("entries", [])` read `{}` — and `{"entrys": [...]}` — as
            # a CLEAN journal, the one thing this constructor must never do.
            raise self._corrupt(f"has no 'entries' key (keys: {sorted(raw)})")
        entries = raw["entries"]
        if not isinstance(entries, list):
            raise self._corrupt(
                f"has an 'entries' value of type {type(entries).__name__}, not a list"
            )
        return [self._entry_from(item, position) for position, item in enumerate(entries)]

    def _entry_from(self, item: object, position: int) -> JournalEntry:
        """Validate ONE index row before it becomes a `JournalEntry`.

        The field set is read off the dataclass rather than written out again,
        so adding a field cannot leave this check validating the old shape.
        """
        where = f"entry #{position}"
        if not isinstance(item, dict):
            raise self._corrupt(f"has {where} of type {type(item).__name__}, not an object")
        expected = {field.name for field in dataclasses.fields(JournalEntry)}
        if set(item) != expected:
            raise self._corrupt(
                f"has {where} with keys {sorted(item)}, expected exactly {sorted(expected)}"
            )
        wrong = sorted(key for key, value in item.items() if not isinstance(value, str))
        if wrong:
            raise self._corrupt(f"has {where} with non-string value(s) for {wrong}")
        return JournalEntry(**item)

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
        """Verify the blob, restore, then VERIFY the target. Any failure
        aborts as `RestoreFailed` with the entry left in the index."""
        backup_path = self.dir / entry.backup_name
        try:
            data = backup_path.read_bytes()
        except OSError as exc:
            raise RestoreFailed(
                f"restore of {entry.path} failed: backup {backup_path} "
                f"could not be read ({exc})"
            ) from exc
        blob_digest = _sha256(data)
        if blob_digest != entry.sha256:
            raise RestoreFailed(
                f"restore of {entry.path} refused: backup {backup_path} does not match "
                f"the recorded sha256 (expected {entry.sha256}, got {blob_digest}); "
                f"the target was left untouched"
            )
        try:
            Path(entry.path).write_bytes(data)
            actual = _sha256(Path(entry.path).read_bytes())
        except OSError as exc:
            raise RestoreFailed(
                f"restore of {entry.path} failed: the target could not be written "
                f"or re-read ({exc})"
            ) from exc
        if actual != entry.sha256:
            raise RestoreFailed(
                f"restore of {entry.path} failed sha256 verification: "
                f"expected {entry.sha256}, got {actual}"
            )
        # By entry VALUE (path + sha256 + blob name), not by blob name alone:
        # two paths with the same basename and identical bytes share one
        # content-addressed blob, and removing by name dropped the sibling's
        # record while its file stayed mutated — `is_dirty()` False, file
        # dirty (PR #652 review). Two EQUAL entries — the same path recorded
        # twice with the same bytes — both go, correctly: one restore put
        # that file at exactly those bytes.
        self._entries = [e for e in self._entries if e != entry]
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
        the order restored.

        Every entry is ATTEMPTED; failures are collected and raised once,
        naming what was restored, what was not, and what is still mutated.
        """
        restored: list[str] = []
        failures: list[str] = []
        for entry in reversed(list(self._entries)):
            try:
                self.restore(entry)
            except RestoreFailed as exc:
                failures.append(str(exc))
                continue
            restored.append(entry.path)
        if failures:
            raise RestoreFailed(
                f"{len(failures)} of {len(failures) + len(restored)} journal entries could "
                f"not be restored: " + " | ".join(failures)
                + f"; restored: {restored}; still mutated: {self.dirty_paths()}"
            )
        return restored

    def install_handlers(self) -> None:
        """Drain on normal exit AND on SIGINT/SIGTERM. A SIGKILL cannot be
        trapped, which is exactly why the on-disk journal exists. The prior
        signal dispositions are recorded so `restore_signal_dispositions`
        can hand them back."""
        atexit.register(self._drain_quietly)
        for sig in _HANDLED_SIGNALS:
            self._previous_dispositions[sig] = signal.signal(sig, self._on_signal)
        _INSTALLED[str(self.dir.resolve())] = self

    def restore_signal_dispositions(self) -> None:
        """Put SIGINT/SIGTERM back the way `install_handlers` found them.
        Idempotent; a no-op if nothing was installed. The `atexit` hook is
        deliberately untouched — see the module docstring.

        Once `_on_signal` has fired this is ALSO a no-op: the handler's
        `sys.exit` unwinds through `run_mutations`'s `finally`, and re-arming
        the default disposition there would let a second Ctrl-C interrupt
        the `atexit` drain mid-`write_bytes` (fix-wave review). The process
        is exiting; both signals stay ignored until it does."""
        if self._signalled:
            return
        for sig, previous in self._previous_dispositions.items():
            # `signal.signal` reports `None` for a handler installed from C;
            # `SIG_DFL` is the only disposition we can hand back for that.
            signal.signal(sig, signal.SIG_DFL if previous is None else previous)
        self._previous_dispositions = {}

    def uninstall_handlers(self) -> None:
        """Undo the `atexit` half of `install_handlers()`. See the module
        docstring for WHO should call this (only one self-test control) and
        why — a real `RestoreFailed` legitimately wants the shutdown
        message, so this must never run on the general path."""
        atexit.unregister(self._drain_quietly)
        key = str(self.dir.resolve())
        if _INSTALLED.get(key) is self:
            del _INSTALLED[key]

    @classmethod
    def installed_for(cls, directory: Path | str) -> "Journal | None":
        """Return the `Journal` instance whose `install_handlers()` is
        currently live for `directory`, or `None`. The one intended caller
        is `selftest.check_restore_failed_is_observable`, which needs the
        EXACT instance `run_mutations()` constructed internally in order to
        call `uninstall_handlers()` on it."""
        return _INSTALLED.get(str(Path(directory).resolve()))

    def _drain_quietly(self) -> None:
        try:
            self.drain()
        except Exception as exc:  # noqa: BLE001 - last-ditch; must not mask exit
            print(f"mutate: JOURNAL DRAIN FAILED: {exc}", file=sys.stderr)

    def _on_signal(self, signum, _frame) -> None:
        # Re-entrancy guard: a second SIGINT during the drain would re-enter
        # `restore()` mid-write. Ignore both signals for the rest of the
        # process (`restore_signal_dispositions` honours `_signalled`). The
        # cost is stated plainly: a restore hung on a dead mount can then be
        # ended only by SIGKILL — which the on-disk journal survives.
        self._signalled = True
        for sig in _HANDLED_SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        self._drain_quietly()
        sys.exit(128 + signum)
