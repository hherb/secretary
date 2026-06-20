import { describe, it, expect } from 'vitest';
import { APP_ERROR_CODES, userMessageFor } from '../src/lib/errors';

describe('invalid_argument AppError', () => {
  it('is a known error code', () => {
    expect(APP_ERROR_CODES).toContain('invalid_argument');
  });
  it('maps to a user message', () => {
    const msg = userMessageFor({ code: 'invalid_argument' });
    expect(msg.title).toBeTruthy();
  });
});
