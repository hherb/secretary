import { describe, it, expect } from 'vitest';
import { needsReauth } from '../src/lib/reauth';

describe('needsReauth', () => {
  it('returns false when disabled regardless of clock', () => {
    expect(needsReauth({ enabled: false, lastAuthAtMs: null, nowMs: 0, windowMs: 0 })).toBe(false);
    expect(needsReauth({ enabled: false, lastAuthAtMs: 0, nowMs: 9e9, windowMs: 1000 })).toBe(false);
  });

  it('returns true when never authed this session', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: null, nowMs: 5000, windowMs: 1000 })).toBe(true);
  });

  it('returns false within the grace window', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: 1000, nowMs: 1500, windowMs: 1000 })).toBe(false);
  });

  it('returns true at exactly the window boundary (>=)', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: 1000, nowMs: 2000, windowMs: 1000 })).toBe(true);
  });

  it('returns true past the window', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: 1000, nowMs: 5000, windowMs: 1000 })).toBe(true);
  });

  it('windowMs of 0 always prompts when enabled (every write)', () => {
    expect(needsReauth({ enabled: true, lastAuthAtMs: 1000, nowMs: 1000, windowMs: 0 })).toBe(true);
  });
});
