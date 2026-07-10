// Pure trash-view model helpers (spec D.1.5). No IPC / DOM — IPC wrappers
// live in ipc.ts and feed these. Mirrors browse.ts / editor.ts discipline:
// pure functions, side effects pushed to the edges.

import type { TrashedBlockDto } from './ipc';
import { formatShortDate } from './format';

/** Order trashed blocks newest-first. Pure (returns a new array). */
export function sortTrashed(dtos: TrashedBlockDto[]): TrashedBlockDto[] {
  return [...dtos].sort((a, b) => b.tombstonedAtMs - a.tombstonedAtMs);
}

/** Human label for when a block was trashed (mirrors the app's date format). */
export function formatTrashedWhen(ms: number): string {
  return formatShortDate(ms);
}

/**
 * Body text for the "Empty trash?" confirmation dialog. Pure — no IPC / DOM.
 * `count` is the number of trashed blocks about to be permanently deleted
 * (always ≥ 1 in practice: the button that triggers this only renders when
 * the trash list is non-empty). Pluralized for a clean singular case.
 */
export function emptyTrashConfirmBody(count: number): string {
  const subject = count === 1 ? 'The 1 item' : `All ${count} items`;
  return `${subject} in trash will be permanently deleted. This cannot be undone.`;
}
