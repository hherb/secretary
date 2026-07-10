import { describe, it, expect } from 'vitest';
import { msToDays, daysToMs, oldestAgeMs, retentionSummary } from '../src/lib/retention';
import { MS_PER_DAY } from '../src/lib/constants';
import type { ExpiredEntryDto } from '../src/lib/ipc';

const entry = (ageMs: number): ExpiredEntryDto => ({
  blockUuidHex: 'aa', tombstonedAtMs: 0, ageMs
});

describe('retention helpers', () => {
  it('converts days <-> ms round trip', () => {
    expect(daysToMs(90)).toBe(90 * MS_PER_DAY);
    expect(msToDays(90 * MS_PER_DAY)).toBe(90);
  });

  it('oldestAgeMs returns the max age, 0 for empty', () => {
    expect(oldestAgeMs([])).toBe(0);
    expect(oldestAgeMs([entry(5), entry(99), entry(2)])).toBe(99);
  });

  it('summary reports count + window days', () => {
    const s = retentionSummary([entry(10 * MS_PER_DAY)], 90 * MS_PER_DAY);
    expect(s).toContain('1');
    expect(s).toContain('90');
  });

  it('summary handles the empty case', () => {
    expect(retentionSummary([], 90 * MS_PER_DAY).toLowerCase()).toContain('no');
  });
});
