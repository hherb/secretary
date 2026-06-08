// Pure sync-domain helpers shared by SyncPill + tests. No I/O, no Svelte.
// Outcome/label mapping kept here (not in components) so it is unit-tested
// in isolation and trivially re-split later if the collapsed success copy
// (spec §4.6) ever needs to differentiate the three applied/merged arms.

import { formatRelativeTime } from './format';

/** Read-only sync status from the `sync_status` command (mirrors the Rust
 *  `dtos::SyncStatusDto`; `device_clocks` is intentionally not surfaced). */
export type SyncStatusDto = { hasState: boolean; lastStateWriteMs: number | null };

/** A tombstone-vs-edit dispute the user must resolve (mirrors the Rust
 *  `dtos::VetoDto`). Metadata only — no secret field values cross here. */
export type VetoDto = {
  recordUuidHex: string;
  recordType: string;
  tags: string[];
  fieldNames: string[];
  localLastModMs: number;
  peerTombstonedAtMs: number;
  peerDeviceHex: string;
};

/** A concurrent same-field edit auto-resolved by the merge (mirrors the Rust
 *  `dtos::CollisionDto`); surfaced for after-the-fact disclosure, not a prompt. */
export type CollisionDto = { recordUuidHex: string; fieldNames: string[] };

/** The user's resolution for one veto (mirrors the Rust `dtos::VetoDecisionDto`). */
export type VetoDecisionDto = { recordUuidHex: string; keepLocal: boolean };

/** keepLocal choice keyed by recordUuidHex. */
export type VetoChoices = Record<string, boolean>;

/** Outcome of a sync pass (mirrors the tagged Rust `dtos::SyncOutcomeDto`). */
export type SyncOutcome =
  | { kind: 'nothingToDo' }
  | { kind: 'appliedAutomatically' }
  | { kind: 'silentMerge' }
  | { kind: 'mergedClean' }
  | { kind: 'conflictsPending'; vetoes: VetoDto[]; collisions: CollisionDto[]; manifestHash: number[] }
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
      // Fallback only — the resolution dialog (Task 12) normally handles
      // these; this notice shows just if the dialog can't open.
      const n = outcome.vetoes.length;
      const noun = n === 1 ? 'conflict' : 'conflicts';
      return { kind: 'warning', text: `${n} ${noun} to resolve` };
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

/** Build the decision array for `sync_commit_decisions`, in veto order.
 *  Expects a *total* `choices` map (one entry per veto) — callers must gate on
 *  `decisionsComplete` first; a sparse map would emit `keepLocal: undefined`
 *  for the missing records. (The dialog passes a derived map that defaults
 *  every veto to Keep mine, so it is always total.) */
export function collectDecisions(vetoes: VetoDto[], choices: VetoChoices): VetoDecisionDto[] {
  return vetoes.map((v) => ({ recordUuidHex: v.recordUuidHex, keepLocal: choices[v.recordUuidHex] }));
}

/** True when every veto has an explicit boolean choice. */
export function decisionsComplete(vetoes: VetoDto[], choices: VetoChoices): boolean {
  return vetoes.every((v) => typeof choices[v.recordUuidHex] === 'boolean');
}

/** Human label for a disputed record — metadata only (no secret values).
 *  "recordType" or "recordType · tag1 · tag2". */
export function formatVetoSummary(v: VetoDto): string {
  return v.tags.length > 0 ? `${v.recordType} · ${v.tags.join(' · ')}` : v.recordType;
}
