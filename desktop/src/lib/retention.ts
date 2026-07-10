// Pure retention helpers — no IPC, no DOM. Convert between the user-visible
// window unit (days) and wire ms, and format the preview summary. Unit-tested
// in isolation (retention.test.ts).

import { MS_PER_DAY } from './constants';
import type { ExpiredEntryDto } from './ipc';

/** Whole days for a ms value, rounded to nearest (settings display). */
export function msToDays(ms: number): number {
  return Math.round(ms / MS_PER_DAY);
}

/** Days → ms (settings save). */
export function daysToMs(days: number): number {
  return days * MS_PER_DAY;
}

/** Largest `ageMs` among entries, or 0 when empty. */
export function oldestAgeMs(entries: ExpiredEntryDto[]): number {
  return entries.reduce((max, e) => (e.ageMs > max ? e.ageMs : max), 0);
}

/** Human summary line for the retention preview dialog. */
export function retentionSummary(entries: ExpiredEntryDto[], windowMs: number): string {
  const days = msToDays(windowMs);
  if (entries.length === 0) {
    return `No trashed items are older than ${days} days.`;
  }
  const n = entries.length;
  const noun = n === 1 ? 'item' : 'items';
  const oldestDays = msToDays(oldestAgeMs(entries));
  return `${n} ${noun} trashed more than ${days} days ago will be permanently ` +
    `deleted (oldest: ${oldestDays} days).`;
}
