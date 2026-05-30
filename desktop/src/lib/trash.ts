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
