// D.1.11 — pure confirm-copy helper for the revoke action.
import { describe, it, expect } from 'vitest';
import { revokeConfirmCopy } from '../src/lib/revoke';

describe('revokeConfirmCopy', () => {
  it('interpolates block name and recipient label into the title', () => {
    const copy = revokeConfirmCopy('Logins', 'Alice');
    expect(copy.title).toContain('Logins');
    expect(copy.title).toContain('Alice');
    expect(copy.confirmLabel).toBe('Revoke');
  });

  it('states the forward-secrecy caveat (they keep what they already saw)', () => {
    const copy = revokeConfirmCopy('Logins', 'Alice');
    expect(copy.body).toMatch(/already/i);
    // Pin the load-bearing second clause so a future copy edit can't silently
    // soften the honest "can't recover already-seen data" boundary.
    expect(copy.body).toMatch(/already opened/i);
    expect(copy.body).toContain('Alice');
  });
});
