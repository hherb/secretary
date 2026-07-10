import { describe, it, expect } from 'vitest';
import { sortTrashed, formatTrashedWhen, emptyTrashConfirmBody } from '../src/lib/trash';
import type { TrashedBlockDto } from '../src/lib/ipc';

const mk = (blockUuidHex: string, tombstonedAtMs: number): TrashedBlockDto => ({
  blockUuidHex,
  blockName: `Block ${blockUuidHex}`,
  tombstonedAtMs,
  tombstonedByHex: 'deadbeef'
});

describe('sortTrashed', () => {
  it('orders newest-first by tombstonedAtMs', () => {
    const input = [mk('a', 100), mk('b', 300), mk('c', 200)];
    const sorted = sortTrashed(input);
    expect(sorted.map((d) => d.blockUuidHex)).toEqual(['b', 'c', 'a']);
  });

  it('does not mutate the input (returns a new array)', () => {
    const input = [mk('a', 100), mk('b', 300)];
    const before = [...input];
    const sorted = sortTrashed(input);
    expect(sorted).not.toBe(input);
    expect(input).toEqual(before);
  });
});

describe('formatTrashedWhen', () => {
  it('returns a non-empty string', () => {
    expect(formatTrashedWhen(Date.now()).length).toBeGreaterThan(0);
  });
});

describe('emptyTrashConfirmBody', () => {
  it('uses the singular form for one item', () => {
    expect(emptyTrashConfirmBody(1)).toBe(
      'The 1 item in trash will be permanently deleted. This cannot be undone.',
    );
  });

  it('uses the plural form for multiple items', () => {
    expect(emptyTrashConfirmBody(4)).toBe(
      'All 4 items in trash will be permanently deleted. This cannot be undone.',
    );
  });
});
