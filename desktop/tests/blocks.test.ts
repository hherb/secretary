// D.1.9 — pure block-list ordering helper for the per-contact reverse map.
import { describe, it, expect } from 'vitest';
import { sortBlocks } from '../src/lib/blocks';
import type { BlockSummaryDto } from '../src/lib/ipc';

const blk = (name: string, uuid: string): BlockSummaryDto => ({
  blockUuidHex: uuid,
  blockName: name,
  createdAtMs: 0,
  lastModifiedMs: 0
});

describe('sortBlocks', () => {
  it('orders by block name case-insensitively', () => {
    const out = sortBlocks([blk('charlie', '03'), blk('Alpha', '01'), blk('bravo', '02')]);
    expect(out.map((b) => b.blockName)).toEqual(['Alpha', 'bravo', 'charlie']);
  });

  it('breaks name ties deterministically by blockUuidHex', () => {
    const out = sortBlocks([blk('Dup', 'ff'), blk('Dup', '0a'), blk('Dup', '7c')]);
    expect(out.map((b) => b.blockUuidHex)).toEqual(['0a', '7c', 'ff']);
  });

  it('is pure (does not mutate the input array)', () => {
    const a = blk('b', '02');
    const input = [a, blk('a', '01')];
    sortBlocks(input);
    expect(input[0]).toBe(a);
  });
});
