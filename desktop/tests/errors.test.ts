// Pins the user-message surface for every AppError + AppWarning variant.
// A new Rust variant added without a TS-side counterpart breaks the
// discriminated union (`userMessageFor` becomes non-exhaustive at the
// switch and tsc rejects compile). The `it.each` block guarantees every
// known variant produces a non-empty title — silent fall-through to a
// blank toast becomes a test failure.

import { describe, it, expect } from 'vitest';
import {
  userMessageFor,
  userMessageForWarning,
  type AppError,
  type AppWarning
} from '../src/lib/errors';

describe('userMessageFor', () => {
  const variants: AppError[] = [
    { code: 'vault_path_not_found', path: '/x' },
    { code: 'vault_path_not_a_vault', path: '/x' },
    { code: 'vault_path_locked', path: '/x' },
    { code: 'wrong_password' },
    { code: 'kdf_too_weak', current_memory_kib: 32_768, min_memory_kib: 65_536 },
    { code: 'vault_corrupt' },
    { code: 'already_unlocked' },
    { code: 'not_unlocked' },
    { code: 'settings_corrupt' },
    { code: 'settings_unknown_version', version: 'v99' },
    { code: 'settings_out_of_range', min: 60_000, max: 86_400_000 },
    { code: 'io' },
    { code: 'internal' }
  ];

  it.each(variants)('returns non-empty title for $code', (err) => {
    const msg = userMessageFor(err);
    expect(msg.title.length).toBeGreaterThan(0);
  });

  it('vault_path_not_found surfaces the path in detail', () => {
    const msg = userMessageFor({ code: 'vault_path_not_found', path: '/tmp/missing' });
    expect(msg.detail).toBe('/tmp/missing');
  });

  it('wrong_password actionHint mentions Caps Lock', () => {
    const msg = userMessageFor({ code: 'wrong_password' });
    expect(msg.actionHint).toContain('Caps Lock');
  });

  it('kdf_too_weak surfaces both KiB numbers in detail', () => {
    const msg = userMessageFor({
      code: 'kdf_too_weak',
      current_memory_kib: 32_768,
      min_memory_kib: 65_536
    });
    expect(msg.detail).toContain('32768');
    expect(msg.detail).toContain('65536');
  });

  it('settings_out_of_range shows bounds in seconds (not ms)', () => {
    const msg = userMessageFor({
      code: 'settings_out_of_range',
      min: 60_000,
      max: 86_400_000
    });
    expect(msg.detail).toContain('60s');
    expect(msg.detail).toContain('86400s');
  });

  it('settings_unknown_version surfaces the version string', () => {
    const msg = userMessageFor({ code: 'settings_unknown_version', version: 'v99' });
    expect(msg.detail).toContain('v99');
  });
});

describe('userMessageForWarning', () => {
  const variants: AppWarning[] = [
    { code: 'settings_corrupt' },
    { code: 'settings_clamped', original_ms: 30_000, clamped_ms: 60_000 },
    { code: 'settings_unknown_version', version: 'v99' }
  ];

  it.each(variants)('returns non-empty title for $code', (w) => {
    const msg = userMessageForWarning(w);
    expect(msg.title.length).toBeGreaterThan(0);
  });

  it('settings_clamped shows both seconds values in detail', () => {
    const msg = userMessageForWarning({
      code: 'settings_clamped',
      original_ms: 30_000,
      clamped_ms: 60_000
    });
    expect(msg.detail).toContain('30s');
    expect(msg.detail).toContain('60s');
  });
});
