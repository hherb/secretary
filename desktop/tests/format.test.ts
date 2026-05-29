import { describe, it, expect } from 'vitest';
import { formatShortDate } from '../src/lib/format';

describe('formatShortDate', () => {
  it('includes the year', () => {
    // 2021-11-14 UTC ~ epoch 1_636_000_000_000; assert the year appears.
    expect(formatShortDate(1_636_000_000_000)).toMatch(/2021/);
  });
});
