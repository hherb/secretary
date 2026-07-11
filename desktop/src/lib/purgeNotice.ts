// desktop/src/lib/purgeNotice.ts
// Pure formatter for the post-op destructive-trash notice (#411). Maps the
// report an op already returns to a user-facing banner string + severity.
// Lives beside the #413 trash helpers; no I/O, no ambient state, so it is
// fully unit-testable and shared identically in logic with the iOS/Android
// mirrors (TrashFormatting.swift / .kt).

export type PurgeSeverity = 'success' | 'warning';

export interface PurgeNotice {
  text: string;
  severity: PurgeSeverity;
}

/** Normalized outcome the caller builds from whichever report DTO it holds.
 * `singlePurge` (delete-forever) carries no count — its DTO has none. */
export type PurgeOutcome =
  | { op: 'emptyTrash'; purgedCount: number; filesFailed: number }
  | { op: 'retention'; purgedCount: number; filesFailed: number }
  | { op: 'singlePurge' };

/** "1 item" / "4 items" — English count noun. */
function plural(n: number, singular: string): string {
  return n === 1 ? `1 ${singular}` : `${n} ${singular}s`;
}

export function formatPurgeNotice(outcome: PurgeOutcome): PurgeNotice {
  if (outcome.op === 'singlePurge') {
    return { text: 'Deleted forever', severity: 'success' };
  }
  const { purgedCount, filesFailed } = outcome;
  if (purgedCount === 0) {
    const text =
      outcome.op === 'retention'
        ? 'No items were past the retention window'
        : 'Trash was already empty';
    return { text, severity: 'success' };
  }
  const base = `Purged ${plural(purgedCount, 'item')}`;
  if (filesFailed > 0) {
    return {
      text: `${base} · ${plural(filesFailed, 'file')} could not be removed`,
      severity: 'warning'
    };
  }
  return { text: base, severity: 'success' };
}
