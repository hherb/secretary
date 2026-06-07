import { describe, it, expect } from 'vitest';
import { formatShortDate, formatRelativeTime } from '../src/lib/format';

describe('formatShortDate', () => {
  it('includes the year', () => {
    // 2021-11-14 UTC ~ epoch 1_636_000_000_000; assert the year appears.
    expect(formatShortDate(1_636_000_000_000)).toMatch(/2021/);
  });
});

const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

describe('formatRelativeTime', () => {
  const now = 1_700_000_000_000;

  it('shows "just now" under a minute', () => {
    expect(formatRelativeTime(now - 30 * SECOND, now)).toBe('just now');
  });
  it('shows whole minutes', () => {
    expect(formatRelativeTime(now - 2 * MINUTE, now)).toBe('2m ago');
  });
  it('shows whole hours', () => {
    expect(formatRelativeTime(now - 3 * HOUR, now)).toBe('3h ago');
  });
  it('shows whole days up to the cutoff', () => {
    expect(formatRelativeTime(now - 5 * DAY, now)).toBe('5d ago');
  });
  it('falls back to a short date beyond 7 days', () => {
    const past = now - 30 * DAY;
    expect(formatRelativeTime(past, now)).toMatch(/\d{4}/);
  });
  it('treats a future/equal timestamp as "just now" (clock skew safety)', () => {
    expect(formatRelativeTime(now + 5 * SECOND, now)).toBe('just now');
  });
  it('still shows "7d ago" at exactly the 7-day cutoff', () => {
    expect(formatRelativeTime(now - 7 * DAY, now)).toBe('7d ago');
  });
  it('falls back to a short date at 8 days (just past the cutoff)', () => {
    expect(formatRelativeTime(now - 8 * DAY, now)).toMatch(/\d{4}/);
  });
});
