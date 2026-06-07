import { describe, it, expect } from 'vitest';
import {
  syncOutcomeMessage,
  syncChangedData,
  lastSyncedLabel,
  type SyncOutcome,
  type SyncStatusDto
} from '../src/lib/sync';

describe('syncOutcomeMessage', () => {
  it('maps nothingToDo to a success "already up to date"', () => {
    expect(syncOutcomeMessage({ kind: 'nothingToDo' })).toEqual({
      kind: 'success',
      text: 'Already up to date'
    });
  });

  it('collapses the three applied/merged arms to one success message', () => {
    const arms: SyncOutcome[] = [
      { kind: 'appliedAutomatically' },
      { kind: 'silentMerge' },
      { kind: 'mergedClean' }
    ];
    for (const o of arms) {
      expect(syncOutcomeMessage(o)).toEqual({
        kind: 'success',
        text: 'Synced — your vault is up to date'
      });
    }
  });

  it('maps conflictsPending to a warning with the veto count interpolated', () => {
    expect(syncOutcomeMessage({ kind: 'conflictsPending', vetoCount: 1 })).toEqual({
      kind: 'warning',
      text: '1 conflict needs resolution — coming soon'
    });
    expect(syncOutcomeMessage({ kind: 'conflictsPending', vetoCount: 3 })).toEqual({
      kind: 'warning',
      text: '3 conflicts need resolution — coming soon'
    });
  });

  it('maps rollbackRejected to an error message', () => {
    expect(syncOutcomeMessage({ kind: 'rollbackRejected' })).toEqual({
      kind: 'error',
      text: 'Sync rejected — a peer tried to roll back protected data'
    });
  });
});

describe('syncChangedData', () => {
  it('is true only for the three applied/merged arms', () => {
    expect(syncChangedData({ kind: 'appliedAutomatically' })).toBe(true);
    expect(syncChangedData({ kind: 'silentMerge' })).toBe(true);
    expect(syncChangedData({ kind: 'mergedClean' })).toBe(true);
  });
  it('is false for arms that write nothing', () => {
    expect(syncChangedData({ kind: 'nothingToDo' })).toBe(false);
    expect(syncChangedData({ kind: 'conflictsPending', vetoCount: 2 })).toBe(false);
    expect(syncChangedData({ kind: 'rollbackRejected' })).toBe(false);
  });
});

describe('lastSyncedLabel', () => {
  const now = 1_700_000_000_000;
  it('says "Never synced" when no state exists', () => {
    const s: SyncStatusDto = { hasState: false, lastStateWriteMs: null };
    expect(lastSyncedLabel(s, now)).toBe('Never synced');
  });
  it('says "Synced" with no time when state exists but mtime is unknown', () => {
    const s: SyncStatusDto = { hasState: true, lastStateWriteMs: null };
    expect(lastSyncedLabel(s, now)).toBe('Synced');
  });
  it('says "Synced {relative}" when a write time is known', () => {
    const s: SyncStatusDto = { hasState: true, lastStateWriteMs: now - 120_000 };
    expect(lastSyncedLabel(s, now)).toBe('Synced 2m ago');
  });
});
