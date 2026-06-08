import { describe, it, expect } from 'vitest';
import {
  syncOutcomeMessage,
  syncChangedData,
  lastSyncedLabel,
  collectDecisions,
  decisionsComplete,
  formatVetoSummary,
  type SyncOutcome,
  type SyncStatusDto,
  type VetoDto
} from '../src/lib/sync';

const veto = (id: string): VetoDto => ({
  recordUuidHex: id,
  recordType: 'login',
  tags: ['work'],
  fieldNames: ['username', 'password'],
  localLastModMs: 1000,
  peerTombstonedAtMs: 2000,
  peerDeviceHex: 'ab'.repeat(16)
});

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
    expect(
      syncOutcomeMessage({
        kind: 'conflictsPending',
        vetoes: [veto('0a')],
        collisions: [],
        manifestHash: []
      })
    ).toEqual({
      kind: 'warning',
      text: '1 conflict to resolve'
    });
    expect(
      syncOutcomeMessage({
        kind: 'conflictsPending',
        vetoes: [veto('0a'), veto('0b'), veto('0c')],
        collisions: [],
        manifestHash: []
      })
    ).toEqual({
      kind: 'warning',
      text: '3 conflicts to resolve'
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
    expect(
      syncChangedData({
        kind: 'conflictsPending',
        vetoes: [veto('0a'), veto('0b')],
        collisions: [],
        manifestHash: []
      })
    ).toBe(false);
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

describe('collectDecisions', () => {
  it('maps choices to the DTO array in veto order', () => {
    const vetoes = [veto('0a'), veto('0b')];
    const choices = { '0a': true, '0b': false };
    expect(collectDecisions(vetoes, choices)).toEqual([
      { recordUuidHex: '0a', keepLocal: true },
      { recordUuidHex: '0b', keepLocal: false }
    ]);
  });
});

describe('decisionsComplete', () => {
  it('is true only when every veto has a boolean choice', () => {
    const vetoes = [veto('0a'), veto('0b')];
    expect(decisionsComplete(vetoes, { '0a': true })).toBe(false);
    expect(decisionsComplete(vetoes, { '0a': true, '0b': false })).toBe(true);
  });
  it('is true for an empty veto list', () => {
    expect(decisionsComplete([], {})).toBe(true);
  });
});

describe('formatVetoSummary', () => {
  it('includes record type and tags', () => {
    const s = formatVetoSummary(veto('0a'));
    expect(s).toContain('login');
    expect(s).toContain('work');
  });
  it('omits the tag separator when there are no tags', () => {
    const s = formatVetoSummary({ ...veto('0a'), tags: [] });
    expect(s).toBe('login');
  });
});
