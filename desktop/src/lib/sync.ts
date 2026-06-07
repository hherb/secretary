// Pure sync-domain helpers shared by SyncPill + tests. No I/O, no Svelte.
// Outcome/label mapping kept here (not in components) so it is unit-tested
// in isolation and trivially re-split later if the collapsed success copy
// (spec §4.6) ever needs to differentiate the three applied/merged arms.

import { formatRelativeTime } from './format';

/** Read-only sync status from the `sync_status` command (mirrors the Rust
 *  `dtos::SyncStatusDto`; `device_clocks` is intentionally not surfaced). */
export type SyncStatusDto = { hasState: boolean; lastStateWriteMs: number | null };

/** Outcome of a sync pass (mirrors the tagged Rust `dtos::SyncOutcomeDto`). */
export type SyncOutcome =
  | { kind: 'nothingToDo' }
  | { kind: 'appliedAutomatically' }
  | { kind: 'silentMerge' }
  | { kind: 'mergedClean' }
  | { kind: 'conflictsPending'; vetoCount: number }
  | { kind: 'rollbackRejected' };

export type NoticeKind = 'success' | 'warning' | 'error';
export type SyncMessage = { kind: NoticeKind; text: string };

/** Map a sync outcome to its inline notice. The three "changes applied
 *  safely" arms collapse to one success message — the distinction isn't
 *  user-actionable (spec §4.6). */
export function syncOutcomeMessage(outcome: SyncOutcome): SyncMessage {
  switch (outcome.kind) {
    case 'nothingToDo':
      return { kind: 'success', text: 'Already up to date' };
    case 'appliedAutomatically':
    case 'silentMerge':
    case 'mergedClean':
      return { kind: 'success', text: 'Synced — your vault is up to date' };
    case 'conflictsPending': {
      const noun = outcome.vetoCount === 1 ? 'conflict needs' : 'conflicts need';
      return {
        kind: 'warning',
        text: `${outcome.vetoCount} ${noun} resolution — coming soon`
      };
    }
    case 'rollbackRejected':
      return {
        kind: 'error',
        text: 'Sync rejected — a peer tried to roll back protected data'
      };
  }
}

/** Whether an outcome changed vault data, so the records view must refresh.
 *  Exhaustive switch (no default) so a future outcome variant forces a
 *  deliberate classification here rather than silently reading as "false". */
export function syncChangedData(outcome: SyncOutcome): boolean {
  switch (outcome.kind) {
    case 'appliedAutomatically':
    case 'silentMerge':
    case 'mergedClean':
      return true;
    case 'nothingToDo':
    case 'conflictsPending':
    case 'rollbackRejected':
      return false;
  }
}

/** Pill label: "Never synced" / "Synced" / "Synced {relative time}". */
export function lastSyncedLabel(status: SyncStatusDto, nowMs: number): string {
  if (!status.hasState) return 'Never synced';
  if (status.lastStateWriteMs === null) return 'Synced';
  return `Synced ${formatRelativeTime(status.lastStateWriteMs, nowMs)}`;
}
