import type { RecordDto } from './ipc';

/**
 * True iff resurrecting this record would yield an empty shell — a tombstoned
 * record whose fields were dropped. The §11.3 merge-tombstone path empties a
 * record's fields; a local delete preserves them. We key on content-emptiness
 * (not tombstone provenance) because that is exactly the user-facing fact —
 * "there is nothing to restore" — and it needs no provenance flag on the
 * frozen on-disk format.
 */
export function isContentlessTombstone(record: RecordDto): boolean {
  return record.tombstoned === true && record.fieldCount === 0;
}
