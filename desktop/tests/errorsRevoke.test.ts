// D.1.11 — the two revoke error variants render typed user messages.
import { describe, it, expect } from 'vitest';
import { userMessageFor, APP_ERROR_CODES } from '../src/lib/errors';

describe('revoke error variants', () => {
  it('recipient_not_present has a refresh-and-retry message', () => {
    const msg = userMessageFor({ code: 'recipient_not_present' });
    expect(msg.title).toBeTruthy();
    expect(msg.actionHint ?? '').toMatch(/refresh/i);
  });

  it('cannot_revoke_owner has a self-removal message', () => {
    const msg = userMessageFor({ code: 'cannot_revoke_owner' });
    expect(msg.title).toBeTruthy();
    expect(msg.actionHint ?? '').toMatch(/owner/i);
  });

  it('both codes are in APP_ERROR_CODES', () => {
    expect(APP_ERROR_CODES).toContain('recipient_not_present');
    expect(APP_ERROR_CODES).toContain('cannot_revoke_owner');
  });
});
