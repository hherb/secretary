import { describe, it, expect } from 'vitest';
import { APP_ERROR_CODES, userMessageFor, type AppError } from '../src/lib/errors';

const SYNC_CODES = [
  'sync_in_progress',
  'sync_evidence_stale',
  'sync_state_vault_mismatch',
  'sync_state_corrupt',
  'sync_failed'
] as const;

describe('errors.ts — D.1.14 sync variants', () => {
  it('registers all five sync codes in APP_ERROR_CODES', () => {
    for (const code of SYNC_CODES) {
      expect(APP_ERROR_CODES).toContain(code);
    }
  });

  it('userMessageFor returns a non-empty title + actionHint for each sync code', () => {
    for (const code of SYNC_CODES) {
      const msg = userMessageFor({ code } as AppError);
      expect(msg.title.length).toBeGreaterThan(0);
      expect(msg.actionHint).toBeTruthy();
      expect(msg.actionHint!.length).toBeGreaterThan(0);
      // must not fall through to the unknown-code fallback
      expect(msg.title).not.toBe('Unknown error');
    }
  });

  it('sync_failed has the real user copy (not the terse Rust placeholder)', () => {
    const msg = userMessageFor({ code: 'sync_failed' } as AppError);
    expect(msg.title).toBe("Sync didn't complete");
    expect(msg.actionHint).toMatch(/try again/i);
  });
});
